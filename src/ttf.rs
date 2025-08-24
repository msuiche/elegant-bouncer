//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  ttf.rs
//
// Abstract:
//  TRIANGULATION
//
// Author:
//  Matt Suiche (msuiche) 28-Dec-2023
//
use log::{info, debug, warn, error};
use std::path;

use crate::errors::*;

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use byteorder::ReadBytesExt;

#[derive(Debug)]
pub enum TtfError {
    OutOfRangeBytecode,
    InvalidFile,
    TableNotFound
}

impl fmt::Display for TtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TtfError::OutOfRangeBytecode => write!(f, "This bytecode is out of range!"),
            TtfError::InvalidFile => write!(f, "Not a valid file."),
            TtfError::TableNotFound => write!(f, "Table not found")
        }
    }
}

// Define the structures
#[repr(C)]
struct TtfTable {
    // glyf / fpgm / prep
    tag:        [u8; 4],
    checksum:   u32,
    offset:     u32,
    len:        u32
}

#[repr(C)]
struct TtfOffsetTable {
    version:        u32,
    num_tables:     u16,
    search_ranges:  u16,
    entry_selector: u16,
    range_shift:    u16
}

#[repr(C)]
struct TtfHeader {
    offset_table:   TtfOffsetTable,
    tables:         Vec<TtfTable>,
}

impl TtfHeader {
    fn from_reader<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut header = TtfHeader {
            offset_table: TtfOffsetTable {
                version:        0,
                num_tables:     0,
                search_ranges:  0,
                entry_selector: 0,
                range_shift:    0
            },
            tables: Vec::new()
        };

        // Read the fields one by one
        header.offset_table.version = reader.read_u32::<byteorder::BigEndian>()?;
        header.offset_table.num_tables = reader.read_u16::<byteorder::BigEndian>()?;
        header.offset_table.search_ranges = reader.read_u16::<byteorder::BigEndian>()?;
        header.offset_table.entry_selector = reader.read_u16::<byteorder::BigEndian>()?;
        header.offset_table.range_shift = reader.read_u16::<byteorder::BigEndian>()?;

        header.tables.clear();
        for _i in 0..header.offset_table.num_tables {
            let mut entry = TtfTable {
                // glyf / fpgm / prep
                tag:        [0; 4],
                checksum:   0,
                offset:     0,
                len:        0
            };
            reader.read_exact(&mut entry.tag)?;
            entry.checksum = reader.read_u32::<byteorder::BigEndian>()?;
            entry.offset = reader.read_u32::<byteorder::BigEndian>()?;
            entry.len = reader.read_u32::<byteorder::BigEndian>()?;
            header.tables.push(entry);
        }

        Ok(header)
    }

    
    fn is_valid(&self) -> bool {
        self.offset_table.version == 0x00010000
        // &self.riff_sig == b"RIFF" && &self.webp_sig == b"WEBP" && &self.vp8_sig == b"VP8L" // && self.vp8l_ssig[0] == 0x2f
    }

    fn get_table(&self, search: &[u8; 4]) -> Result<&TtfTable> {
        for t in &self.tables {
            if &t.tag == search {
                return Ok(t)
            }
        }

        Err(ElegantError::TtfError(TtfError::TableNotFound))
    }

}

fn is_adjust_inst_present(byte_data: &Vec<u8>) -> Result<bool> {
    let mut off = 0;
    let max_iterations = byte_data.len() * 2; // Prevent infinite loops
    let mut iterations = 0;
    
    while off < byte_data.len() {
        // Safety check for malformed bytecode
        if iterations > max_iterations {
            warn!("Maximum iterations reached in bytecode parsing - possible malformed font");
            return Err(ElegantError::TtfError(TtfError::OutOfRangeBytecode));
        }
        iterations += 1;
        
        let opcode = byte_data[off];
        
        // https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/
        // Undocumented, Apple-only ADJUST TrueType font instruction. This instruction had existed
        // since the early nineties before a patch removed it.
        if opcode == 0x8f || opcode == 0x90 {
            warn!("0x{:04x}: ADJUST /* Undocumented Apple instruction - TRIANGULATION indicator! */", off);
            info!("Found ADJUST instruction at offset 0x{:04x} with opcode 0x{:02x}", off, opcode);
            return Ok(true);
        }
        
        // Variable-length instructions that need special handling
        match opcode {
            // NPUSHB[] - PUSH N Bytes (0x40)
            0x40 => {
                if off + 1 >= byte_data.len() {
                    return Err(ElegantError::TtfError(TtfError::OutOfRangeBytecode));
                }
                let count = byte_data[off + 1] as usize;
                off += 2; // Skip opcode and count byte
                if off + count > byte_data.len() {
                    return Err(ElegantError::TtfError(TtfError::OutOfRangeBytecode));
                }
                debug!("0x{:04x}: NPUSHB[{}] /* {} bytes pushed */", off - 2, count, count);
                off += count;
            }
            
            // NPUSHW[] - PUSH N Words (0x41)
            0x41 => {
                if off + 1 >= byte_data.len() {
                    return Err(ElegantError::TtfError(TtfError::OutOfRangeBytecode));
                }
                let count = byte_data[off + 1] as usize;
                off += 2; // Skip opcode and count byte
                if off + count * 2 > byte_data.len() {
                    return Err(ElegantError::TtfError(TtfError::OutOfRangeBytecode));
                }
                debug!("0x{:04x}: NPUSHW[{}] /* {} words pushed */", off - 2, count, count);
                off += count * 2;
            }
            
            // PUSHB[n] - PUSH Bytes (0xB0-0xB7)
            0xb0..=0xb7 => {
                let count = (opcode - 0xb0 + 1) as usize;
                off += 1; // Skip opcode
                if off + count > byte_data.len() {
                    return Err(ElegantError::TtfError(TtfError::OutOfRangeBytecode));
                }
                debug!("0x{:04x}: PUSHB[{}] /* {} bytes pushed */", off - 1, count - 1, count);
                off += count;
            }
            
            // PUSHW[n] - PUSH Words (0xB8-0xBF)
            0xb8..=0xbf => {
                let count = (opcode - 0xb8 + 1) as usize;
                off += 1; // Skip opcode
                if off + count * 2 > byte_data.len() {
                    return Err(ElegantError::TtfError(TtfError::OutOfRangeBytecode));
                }
                debug!("0x{:04x}: PUSHW[{}] /* {} words pushed */", off - 1, count - 1, count);
                off += count * 2;
            }
            
            // Jump and branch instructions that could affect control flow
            // These don't have inline data but are important for completeness
            0x78 => {
                debug!("0x{:04x}: JROT[] /* Jump Relative On True */", off);
                off += 1;
            }
            0x79 => {
                debug!("0x{:04x}: JROF[] /* Jump Relative On False */", off);
                off += 1;
            }
            0x1c => {
                debug!("0x{:04x}: JMPR[] /* Jump Relative */", off);
                off += 1;
            }
            
            // Function and instruction definitions (variable length)
            0x2c => {
                debug!("0x{:04x}: FDEF[] /* Function Definition */", off);
                // Function definitions continue until ENDF
                // For safety, we'll just increment normally
                off += 1;
            }
            0x2d => {
                debug!("0x{:04x}: ENDF[] /* End Function Definition */", off);
                off += 1;
            }
            0x89 => {
                debug!("0x{:04x}: IDEF[] /* Instruction Definition */", off);
                // Instruction definitions are also variable length
                off += 1;
            }
            
            // IF/ELSE control structures
            0x58 => {
                debug!("0x{:04x}: IF[] /* If test */", off);
                off += 1;
            }
            0x1b => {
                debug!("0x{:04x}: ELSE[] /* Else clause */", off);
                off += 1;
            }
            0x59 => {
                debug!("0x{:04x}: EIF[] /* End if */", off);
                off += 1;
            }
            
            // Regular single-byte instructions
            _ => {
                // Log suspicious or unknown opcodes
                if opcode > 0x91 && opcode < 0xb0 {
                    debug!("0x{:04x}: Unknown/Reserved opcode 0x{:02x}", off, opcode);
                }
                off += 1;
            }
        }
    }
    
    Ok(false)
}

pub fn scan_ttf_file(path: &path::Path) -> Result<ScanResultStatus> {
    info!("Opening {}...", path.display());

    let mut _status = ScanResultStatus::StatusOk;

    let mut file = File::open(path)?;
    // TODO: check magic number
    let header = TtfHeader::from_reader(&file)?;

    debug!("header.ver = {:x}", header.offset_table.version);
    debug!("header.num_tables = {}", header.offset_table.num_tables);

    // fpgm — Font Program
    // This table is similar to the CVT Program, except that it is only run once, when the font is first used. 
    debug!("--- fpgm ---");
    if let Ok(fpgm) = header.get_table(b"fpgm") {
        let mut byte_data = vec![0; fpgm.len as usize];
        file.seek(SeekFrom::Start((fpgm.offset as i64).try_into().unwrap()))?;
        // debug!("go to: 0x{:x}", fpgm.offset);
        file.read_exact(&mut byte_data)?;
        
        if let Ok(status) = is_adjust_inst_present(&byte_data) {
            if status == true {
                info!("Found in the table {:?} with base offset {:x}", fpgm.tag, fpgm.offset);
                return Ok(ScanResultStatus::StatusMalicious);
            }
        }
    }

    // prep — Control Value Program
    // The Control Value Program consists of a set of TrueType instructions that will be executed
    // whenever the font or point size or transformation matrix change and before each glyph is interpreted. 
    debug!("--- prep ---");
    if let Ok(prep) = header.get_table(b"prep") {
        let mut byte_data = vec![0; prep.len as usize];
        file.seek(SeekFrom::Start((prep.offset as i64).try_into().unwrap()))?;
        debug!("go to: 0x{:x}", prep.offset);
        file.read_exact(&mut byte_data)?;
        
        if let Ok(status) = is_adjust_inst_present(&byte_data) {
            if status == true {
                info!("Found in the table {:?} with base offset {:x}", prep.tag, prep.offset);
                return Ok(ScanResultStatus::StatusMalicious);
            }
        }
    }

    // glyf — Glyph Data
    // This table contains information that describes the glyphs in the font in the TrueType outline format.
    if let Ok(maxp) = header.get_table(b"maxp") {
        file.seek(SeekFrom::Start((maxp.offset as i64).try_into().unwrap()))?;
        let _version = file.read_u32::<byteorder::BigEndian>()?;
        let num_glyph = file.read_u16::<byteorder::BigEndian>()?;

        debug!("number of glyf = {}", num_glyph);
        if let Ok(loca) = header.get_table(b"loca") {
            if let Ok(glyf) = header.get_table(b"glyf") {

                for glyf_id in 0..num_glyph {
                    file.seek(SeekFrom::Start(((loca.offset + (glyf_id * 2) as u32) as i64).try_into().unwrap()))?;
                    let glyf_offset = file.read_u16::<byteorder::BigEndian>()? as u32;
                    let glyf_offset = glyf_offset as u32 * 2; // head.indexToLocFormat is assumed to be 0.
                    debug!("{}: glyf offset = {:x} (0x{:x})", glyf_id, glyf_offset, glyf.offset + glyf_offset);

                    file.seek(SeekFrom::Start(((glyf.offset + glyf_offset) as i64).try_into().unwrap()))?;

                    let nb_of_contours = file.read_i16::<byteorder::BigEndian>()?;
                    let _x_min = file.read_u16::<byteorder::BigEndian>()?;
                    let _y_min = file.read_u16::<byteorder::BigEndian>()?;
                    let _x_max = file.read_u16::<byteorder::BigEndian>()?;
                    let _y_max = file.read_u16::<byteorder::BigEndian>()?;

                    // If the number of contours is greater than or equal to zero, this is a simple glyph. 
                    // If negative, this is a composite glyph — the value -1 should be used for composite glyphs.
                    if nb_of_contours < 0 {
                        continue;
                    }

                    // if nb_of_contours != 0xffff {
                    for _i in 0..nb_of_contours { 
                        let _num_points = file.read_u16::<byteorder::BigEndian>()?;
                    }
                    let instructions_len = file.read_u16::<byteorder::BigEndian>()?;
                    // instructions
                    debug!("instruction len = 0x{:x}", instructions_len);
                    let mut byte_data = vec![0; instructions_len as usize];
                    file.read_exact(&mut byte_data)?;

                    if let Ok(status) = is_adjust_inst_present(&byte_data) {
                        if status == true {
                            info!("glyf id = {} and inst len is 0x{:x}", glyf_id, instructions_len);
                            info!("Found in the glyf {:?} with id {} with base offset {:x} (0x{:x})",
                                glyf.tag, glyf_id, glyf.offset, glyf.offset + glyf_offset);
                            return Ok(ScanResultStatus::StatusMalicious);
                        }
                    }

                    // IGNORE: Flags and Points.
                }
            }
        }
    }

    if !header.is_valid() {
        warn!("Not a TTF file. Ignore");
        return Err(ElegantError::TtfError(TtfError::InvalidFile));
    }

    // debug!("get_vp8l_data_size() -> 0x{:x}", header.get_vp8l_data_size());

    Ok(ScanResultStatus::StatusOk)
}