//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  dng.rs
//
// Abstract:
//  ELEGANTBOUNCER DNG scanner for CVE-2025-43300
//
// Author:
//  Matt Suiche (msuiche) 23-Aug-2025
//
use crate::errors::ScanResultStatus;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use log::{error, warn};

const TIFF_LITTLE_ENDIAN: u16 = 0x4949;
const TIFF_BIG_ENDIAN: u16 = 0x4D4D;
const TIFF_MAGIC: u16 = 0x002A;

const TAG_SUBIFD: u16 = 0x014A;
const TAG_SAMPLES_PER_PIXEL: u16 = 0x0115;
const TAG_COMPRESSION: u16 = 0x0103;
const TAG_STRIP_OFFSETS: u16 = 0x0111;
const TAG_JPEG_INTERCHANGE_FORMAT: u16 = 0x0201;

const JPEG_LOSSLESS_COMPRESSION: u16 = 7;
const SOF3_MARKER: u16 = 0xFFC3;

#[derive(Debug, Clone)]
struct IFDEntry {
    tag: u16,
    field_type: u16,
    count: u32,
    value_offset: u32,
}

struct TIFFReader {
    file: File,
    is_little_endian: bool,
}

impl TIFFReader {
    fn new(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        Ok(TIFFReader {
            file,
            is_little_endian: true,
        })
    }

    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0u8; 2];
        self.file.read_exact(&mut buf)?;
        Ok(if self.is_little_endian {
            u16::from_le_bytes(buf)
        } else {
            u16::from_be_bytes(buf)
        })
    }

    fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0u8; 4];
        self.file.read_exact(&mut buf)?;
        Ok(if self.is_little_endian {
            u32::from_le_bytes(buf)
        } else {
            u32::from_be_bytes(buf)
        })
    }

    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0u8; 1];
        self.file.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn seek(&mut self, pos: u64) -> std::io::Result<u64> {
        self.file.seek(SeekFrom::Start(pos))
    }

    fn read_header(&mut self) -> std::io::Result<u32> {
        self.seek(0)?;
        
        let byte_order = self.read_u16()?;
        self.is_little_endian = match byte_order {
            TIFF_LITTLE_ENDIAN => true,
            TIFF_BIG_ENDIAN => false,
            _ => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid TIFF byte order"
            )),
        };

        let magic = self.read_u16()?;
        if magic != TIFF_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid TIFF magic number"
            ));
        }

        self.read_u32()
    }

    fn read_ifd(&mut self, offset: u32) -> std::io::Result<(Vec<IFDEntry>, u32)> {
        self.seek(offset as u64)?;
        
        let num_entries = self.read_u16()?;
        let mut entries = Vec::with_capacity(num_entries as usize);

        for _ in 0..num_entries {
            let tag = self.read_u16()?;
            let field_type = self.read_u16()?;
            let count = self.read_u32()?;
            let value_offset = self.read_u32()?;

            entries.push(IFDEntry {
                tag,
                field_type,
                count,
                value_offset,
            });
        }

        let next_ifd = self.read_u32()?;
        Ok((entries, next_ifd))
    }

    fn get_value_u16(&mut self, entry: &IFDEntry) -> std::io::Result<u16> {
        if entry.count == 1 && entry.field_type == 3 {
            Ok((entry.value_offset & 0xFFFF) as u16)
        } else {
            self.seek(entry.value_offset as u64)?;
            self.read_u16()
        }
    }

    fn get_value_u32(&mut self, entry: &IFDEntry) -> std::io::Result<u32> {
        if entry.count == 1 && (entry.field_type == 4 || entry.field_type == 3) {
            Ok(entry.value_offset)
        } else {
            self.seek(entry.value_offset as u64)?;
            self.read_u32()
        }
    }

    fn check_samples_per_pixel(&mut self, entry: &IFDEntry) -> std::io::Result<(bool, u32)> {
        // For short values (type 3) with count 1, the value is stored in the value_offset field
        let samples = if entry.field_type == 3 && entry.count == 1 {
            (entry.value_offset & 0xFFFF) as u8
        } else {
            let saved_pos = self.file.stream_position()?;
            self.seek(entry.value_offset as u64)?;
            let val = self.read_u8()?;
            self.seek(saved_pos)?;
            val
        };
        
        let is_suspicious = samples == 2;
        Ok((is_suspicious, entry.value_offset))
    }

    fn check_jpeg_lossless(&mut self, offset: u32) -> std::io::Result<bool> {
        let saved_pos = self.file.stream_position()?;
        self.seek(offset as u64)?;
        
        let mut found_sof3 = false;
        let mut suspicious_component_count = false;
        
        for _ in 0..1000 {
            let marker1 = match self.read_u8() {
                Ok(b) => b,
                Err(_) => break,
            };
            
            if marker1 != 0xFF {
                continue;
            }
            
            let marker2 = match self.read_u8() {
                Ok(b) => b,
                Err(_) => break,
            };
            
            let marker = ((marker1 as u16) << 8) | (marker2 as u16);
            
            if marker == SOF3_MARKER {
                found_sof3 = true;
                
                let _length = self.read_u16()?;
                let _precision = self.read_u8()?;
                let _height = self.read_u16()?;
                let _width = self.read_u16()?;
                let component_count = self.read_u8()?;
                
                if component_count == 1 {
                    suspicious_component_count = true;
                }
                break;
            }
            
            if marker >= 0xFFC0 && marker <= 0xFFFE && marker != 0xFFD8 && marker != 0xFFD9 {
                let length = self.read_u16()?;
                if length >= 2 {
                    let current_pos = self.file.stream_position()?;
                    self.seek(current_pos + (length as u64 - 2))?;
                }
            }
        }
        
        self.seek(saved_pos)?;
        Ok(found_sof3 && suspicious_component_count)
    }
}

pub fn scan_dng_file(file_path: &Path) -> ScanResultStatus {
    let mut reader = match TIFFReader::new(file_path) {
        Ok(r) => r,
        Err(_) => return ScanResultStatus::StatusOk,
    };

    let mut ifd_offset = match reader.read_header() {
        Ok(offset) => offset,
        Err(_) => return ScanResultStatus::StatusOk,
    };

    let mut suspicious_samples_per_pixel = false;
    let mut has_jpeg_lossless = false;
    let mut jpeg_offset = 0u32;
    let mut subifd_offsets = Vec::new();
    
    while ifd_offset != 0 {
        let (entries, next_ifd) = match reader.read_ifd(ifd_offset) {
            Ok(data) => data,
            Err(_) => break,
        };

        for entry in &entries {
            match entry.tag {
                TAG_SUBIFD => {
                    if entry.count > 0 {
                        match reader.get_value_u32(entry) {
                            Ok(offset) => subifd_offsets.push(offset),
                            Err(_) => continue,
                        }
                    }
                }
                TAG_COMPRESSION => {
                    if let Ok(compression) = reader.get_value_u16(entry) {
                        if compression == JPEG_LOSSLESS_COMPRESSION {
                            has_jpeg_lossless = true;
                        }
                    }
                }
                TAG_JPEG_INTERCHANGE_FORMAT | TAG_STRIP_OFFSETS => {
                    if let Ok(offset) = reader.get_value_u32(entry) {
                        if offset > 0 {
                            jpeg_offset = offset;
                        }
                    }
                }
                _ => {}
            }
        }

        ifd_offset = next_ifd;
    }

    for subifd_offset in subifd_offsets {
        let (entries, _) = match reader.read_ifd(subifd_offset) {
            Ok(data) => data,
            Err(_) => continue,
        };

        for entry in &entries {
            if entry.tag == TAG_SAMPLES_PER_PIXEL {
                if let Ok((is_suspicious, offset)) = reader.check_samples_per_pixel(&entry) {
                    if is_suspicious {
                        suspicious_samples_per_pixel = true;
                        warn!("[!] Suspicious SamplesPerPixel value (2) found at offset 0x{:X}", offset);
                    }
                }
            }
            
            if entry.tag == TAG_COMPRESSION {
                if let Ok(compression) = reader.get_value_u16(&entry) {
                    if compression == JPEG_LOSSLESS_COMPRESSION {
                        has_jpeg_lossless = true;
                    }
                }
            }
            
            if entry.tag == TAG_JPEG_INTERCHANGE_FORMAT || entry.tag == TAG_STRIP_OFFSETS {
                if let Ok(offset) = reader.get_value_u32(&entry) {
                    if offset > 0 {
                        jpeg_offset = offset;
                    }
                }
            }
        }
    }

    if has_jpeg_lossless && jpeg_offset > 0 {
        if let Ok(has_suspicious_sof3) = reader.check_jpeg_lossless(jpeg_offset) {
            if has_suspicious_sof3 {
                warn!("[!] Suspicious SOF3 component count (1) found in JPEG Lossless data");
                
                if suspicious_samples_per_pixel {
                    error!("[!!!] CVE-2025-43300 detected: Modified SamplesPerPixel + SOF3 component count");
                    return ScanResultStatus::StatusMalicious;
                }
            }
        }
    }

    ScanResultStatus::StatusOk
}