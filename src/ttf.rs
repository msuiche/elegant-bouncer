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
use log::{info, debug, error};
use core::num;
use std::path;

use crate::errors::*;

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use byteorder::ReadBytesExt;

#[derive(Debug)]
pub enum TtfError {
    UnsupportedBehavior,
    InvalidFile,
    TableNotFound
    // UnexpectedEof
}

impl fmt::Display for TtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TtfError::UnsupportedBehavior => write!(f, "Unsupported behavior encountered"),
            // WebpError::UnexpectedEof => write!(f, "Unexpected end of file"),
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

    fn get_tables(&self) -> &Vec<TtfTable> {
        &self.tables
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

fn is_adjust_inst_present(byte_data: &Vec<u8>) -> bool {
    for off in 0..byte_data.len() {
        // https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/
        // Undocumented, Apple-only ADJUST TrueType font instruction. This instruction had existed
        // since the early nineties before a patch removed it.
        if byte_data[off] == 0x8f {
            info!("is_adjust_inst_present() returns to with values: offset {} with byte {:x}", off, byte_data[off]);
            return true;
        }
    }

    false
}

pub fn scan_ttf_file(path: &path::Path) -> Result<ScanResultStatus> {
    info!("Opening {}...", path.display());

    let mut _status = ScanResultStatus::StatusOk;

    let mut file = File::open(path)?;
    let header = TtfHeader::from_reader(&file)?;

    debug!("header.ver = {:x}", header.offset_table.version);
    debug!("header.num_tables = {}", header.offset_table.num_tables);

    // fpgm — Font Program
    // This table is similar to the CVT Program, except that it is only run once, when the font is first used. 
    if let Ok(fpgm) = header.get_table(b"fpgm") {
        let mut byte_data = vec![0; fpgm.len as usize];
        file.seek(SeekFrom::Start((fpgm.offset as i64).try_into().unwrap()))?;
        debug!("go to: 0x{:x}", fpgm.offset);
        file.read_exact(&mut byte_data)?;
        
        if is_adjust_inst_present(&byte_data) {
            info!("Found in the table {:?} with base offset {:x}", fpgm.tag, fpgm.offset);
            return Ok(ScanResultStatus::StatusMalicious);
        }
    }

    // prep — Control Value Program
    // The Control Value Program consists of a set of TrueType instructions that will be executed
    // whenever the font or point size or transformation matrix change and before each glyph is interpreted. 
    if let Ok(_prep) = header.get_table(b"prep") {
        // ignored
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
                    let glyf_offset = file.read_u16::<byteorder::BigEndian>()?;
                    let glyf_offset = glyf_offset * 2; // head.indexToLocFormat is assumed to be 0.
                    debug!("glyf_offset = 0x{:x}", glyf_offset);
                    file.seek(SeekFrom::Start(((glyf.offset + glyf_offset as u32) as i64).try_into().unwrap()))?;

                    let _nb_of_contours = file.read_u16::<byteorder::BigEndian>()?;
                    let _x_min = file.read_u16::<byteorder::BigEndian>()?;
                    let _y_min = file.read_u16::<byteorder::BigEndian>()?;
                    let _x_max = file.read_u16::<byteorder::BigEndian>()?;
                    let _y_max = file.read_u16::<byteorder::BigEndian>()?;
                    let mut num_points = 0;
                    for _i in 0.._nb_of_contours { 
                        num_points = file.read_u16::<byteorder::BigEndian>()?;
                    }
                    let instructions_len = file.read_u16::<byteorder::BigEndian>()?;
                    // instructions
                    let mut byte_data = vec![0; instructions_len as usize];
                    file.read_exact(&mut byte_data)?;
                    if is_adjust_inst_present(&byte_data) {

                        info!("glyf id = {} and inst len is 0x{:x}", glyf_id, instructions_len);
                        info!("Found in the glyf {:?} with id {} with base offset {:x}", glyf.tag, glyf_id, glyf.offset);
                        return Ok(ScanResultStatus::StatusMalicious);
                    }

                    // IGNORE: Flags and Points.
                }
            }
        }
    }

    if !header.is_valid() {
        error!("Not a TTF file. Ignore");
        return Err(ElegantError::TtfError(TtfError::InvalidFile));
    }

    // debug!("get_vp8l_data_size() -> 0x{:x}", header.get_vp8l_data_size());

    Ok(ScanResultStatus::StatusOk)
}