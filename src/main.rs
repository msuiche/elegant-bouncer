

//
//  Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  main.rs
//
// Abstract:
//  JBIG2 PDF scanner
//
// Author:
//  Matthieu Suiche (msuiche) 20-Nov-2022
//

use std::fmt;
use std::path;
use std::io::{Seek, SeekFrom, Read, Cursor};
use lopdf::*;
use colored::*;

use env_logger;
use log::{info, debug, error, LevelFilter};
use clap::Parser;
use byteorder::{ReadBytesExt, BigEndian};

/*
const CRATE_VERSION: &'static str =
    concat!(env!("VERGEN_GIT_SEMVER"),
     " (", env!("VERGEN_GIT_COMMIT_TIMESTAMP"), ")");
*/
const CRATE_VERSION: &'static str = "0.1";

/// A program that analyzes PDF files for malformed JBIG2 objects, such as the ones used in FORCEDENTRY.
#[derive(Parser)]
#[clap(about, long_about = None, author="Copyright (c) 2022, All rights reserved.", version = CRATE_VERSION)]
struct Args {
    /// Print extra output while parsing
    #[clap(short, long)]
    verbose: bool,

    /// Check if there are any exploited known vulnerabilities.
    #[clap(short, long)]
    analyze: bool,

    /// Create a FORCEDENTRY-like PDF.
    #[clap(short, long)]
    create: bool,

    /// Path to the input PDF file.
    #[clap(value_name = "Input file")]
    path: String,
}

#[macro_export]
macro_rules! read_type {
    ($rdr: expr, $ty: ty) => {{
        // `size_of` and `transmute` cannot be easily used with generics.
        let mut buf = [0u8; std::mem::size_of::<$ty>()];
        $rdr.read(&mut buf)?;
        let hdr: $ty = unsafe { std::mem::transmute(buf) };
        let res: Result<$ty> = Ok(hdr);
        res
    }}
}

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

pub struct JBIG2SegInfo {
    pub seg_type:       JBIG2SegmentType,
    pub seg_num:        u32,
    pub seg_flags:      u32,
    pub ref_flags:      u32,
    pub seg_len:        u64,
}

pub struct JBIG2TextRegionInfo {
    pub seg_num:        u32,
    pub bytes:          Vec<u8>
}

pub struct JBIG2SymbolDictionarySegment {
    // Extra Identifier
    pub seg_num:        u32,

    pub flags:          u16,
    pub sd_atx:         [u8; 4],
    pub sd_aty:         [u8; 4],
    pub num_ex_syms:    u64,
    pub num_new_syms:   u64
}

impl JBIG2SymbolDictionarySegment {
    fn new(
        seg_num: u32,
        num_ex_syms: u64,
        num_new_syms: u64) -> Self {

        JBIG2SymbolDictionarySegment {
            seg_num,
            flags: 0,
            sd_atx: [0u8; 4],
            sd_aty: [0u8; 4],
            num_ex_syms,
            num_new_syms
        }
    }

    fn get_seg_num(&self) -> u32 {
        self.seg_num
    }

    fn get_num_ex_syms(&self) -> u64 {
        self.num_ex_syms
    }
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

    pub refs:           Vec<u8>,
    pub num_ex_syms:    u64
}

impl JBIG2Segment { 
    fn new() -> Self {
        JBIG2Segment {
            seg_num: 0,
            seg_flags: 0,
            ref_flags: 0,
            is_large: false,
            ref_count: 0,
            ref_segs_len: 0,
            seg_size: 0,
            page: 0,
            seg_len: 0,
            refs: Vec::new(),
            num_ex_syms: 0
        }
    }

    fn set_header(
        &mut self,
        seg_num: u32,
        seg_flags: u32,
        ref_flags: u32,
        page: u32,
        seg_len: usize) -> Result<()> {

        self.seg_num = seg_num;
        self.seg_flags = seg_flags;
        self.ref_flags = ref_flags;
        self.page = page;
        self.seg_len = seg_len;

        Ok(())
    }

    fn read<R: Read + Seek>(&mut self, rdr: &mut R) -> Result<()> {
        let seg_num = rdr.read_u32::<BigEndian>()?;
        let seg_flags = rdr.read_u8()? as u32;

        let mut ref_flags = rdr.read_u8()? as u32;
        let mut ref_count = 0;
        let is_large = (ref_flags >> 5) == 7;

        let mut ref_segs_len = 0;

        let seg_size = match seg_num {
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
        }

        // TODO: if seg_flags & 0x40 -> rdr.read_u32()
        // TODO: means that get_seg_hdr_len() needs += 3 also
        let page = rdr.read_u8()? as u32;
        let seg_len = rdr.read_u32::<BigEndian>()? as usize;
        
        // JBIG2SymbolDict
        let mut num_ex_syms = 0;
        if seg_flags & 0x3f == 0 {
            rdr.read_u16::<BigEndian>()? as usize; // flags
            rdr.read_u32::<BigEndian>()? as usize;
            rdr.read_u32::<BigEndian>()? as usize;
            num_ex_syms = rdr.read_u32::<BigEndian>()? as u64;
        } 

        self.seg_num = seg_num;
        self.seg_flags = seg_flags;
        self.ref_flags = ref_flags;
        self.is_large = is_large;
        self.ref_count = ref_count;
        self.ref_segs_len = ref_segs_len;
        self.seg_size = seg_size;
        self.page = page;
        self.seg_len = seg_len;
        self.refs = refs;
        self.num_ex_syms = num_ex_syms;

        Ok(())
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

    fn get_refs(&self) -> &Vec<u8> {
        &self.refs
    }

    fn get_num_ex_syms(&self) -> u64 {
        self.num_ex_syms
    }
}

pub struct JBIG2Stream {
    pub syms:       Vec<JBIG2SymbolDictionarySegment>,
    pub regions:    Vec<JBIG2TextRegionInfo>
}

impl JBIG2Stream {
    fn new() -> Self {
        JBIG2Stream {
            syms: Vec::new(),
            regions: Vec::new()
        }
    }

    pub fn get_len_by_seg_num(&self, seg_num: u32) -> u64 {
        for sym in &self.syms {
            if seg_num == sym.get_seg_num() {
                return sym.get_num_ex_syms()
            }
        }
    
        0
    }

    fn parse_jbig2_stream(&mut self, in_buf: &[u8]) -> Result<()> {
        let mut rdr = Cursor::new(in_buf);
        let mut seg_hdr = JBIG2Segment::new();

        loop {
            if let Ok(_) = seg_hdr.read(&mut rdr.clone()) {
                /*
                debug!("segNum = 0x{:x} type: {} seg_len: 0x{:x} ref_count: {:x} is_large: {}",
                    seg_hdr.get_seg_num(), seg_hdr.get_type(), seg_hdr.get_seg_len(),
                    seg_hdr.get_ref_len(), seg_hdr.is_large());
                */

                if seg_hdr.get_type() == JBIG2SegmentType::SymbolDict {
                    let dict_sym = JBIG2SymbolDictionarySegment::new(
                        seg_hdr.get_seg_num(),
                        seg_hdr.get_num_ex_syms(),
                        0
                    );
                    self.syms.push(dict_sym);
                } else if seg_hdr.get_type() == JBIG2SegmentType::TextRegion1 {
                    if seg_hdr.get_seg_num() <= 256 {

                        self.regions.push(JBIG2TextRegionInfo {
                            seg_num: seg_hdr.get_seg_num(),
                            bytes: seg_hdr.get_refs().to_vec()
                        });
                    } else {
                        error!("need to read the text region by blocks of 2 or 4 bytes.");
                    }
                }

                if seg_hdr.get_seg_len() == 0 && seg_hdr.get_seg_num() == 0 {
                    break;
                }

                rdr.seek(SeekFrom::Current(seg_hdr.get_seg_len() as i64))?;
            } else {
                break;
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn display_data(&self) {
        // debug!("number of segments: 0x{:x}", segs.len());
        info!("number of symbols: 0x{:x}", self.syms.len());
        info!("number of regions: 0x{:x}", self.regions.len());

        for sym in &self.syms {
            info!("seg_num: 0x{:x} size: 0x{:x}", sym.seg_num, sym.num_ex_syms);
        }
    }

    fn is_forcedentry(&self) -> bool {
        for region in &self.regions {
            let mut num_syms = 0;
            for ref_seg_num in &region.bytes {
                let sz = self.get_len_by_seg_num(*ref_seg_num as u32);
                num_syms += sz;
                debug!("0x{:x} -> {:x} (0x{:x})", ref_seg_num, sz, num_syms);
            }
            if num_syms > std::u32::MAX as u64 {
                return true;
            }
        }

        false
    }
}

fn analyze(path: &path::Path) {
    let doc = Document::load(path).unwrap();

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
        info!("Checking for JBIG2 presence...          {}", "Present.".white());
    } else {
        info!("Checking for JBIG2 presence...          {}", "Not Present.".white());
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

    let cve_2021_30860 = jbig2_stream.is_forcedentry();

    if cve_2021_30860 { 
        info!("CVE-2021-30860 vulnerability trigger... {}", "Present.".red());
    } else {
        info!("CVE-2021-30860 vulnerability trigger... {}", "Safe.".green());
    }
}

fn create(_path: &path::Path) {

}

fn main() {
    println!("{} v{}", "elegant-bouncer".bold(), CRATE_VERSION);
    println!("A small utility to check the presence of known vulnerabilities in PDF files.");
    println!("At the moment it only searches for the presence of {} (CVE-2021-30860).", "FORCEDENTRY".green());
    println!("");

    let args = Args::parse();

    let level;
    if args.verbose {
        level = LevelFilter::max();
    } else {
        level = LevelFilter::Info;
    }

    env_logger::Builder::new().filter_level(level).init();

    // let mut doc = Document::load("assets/example.pdf").unwrap();

    if !args.analyze && !args.create {
        println!("You need to supply an action. Run with {} for more information.", "--help".green());
        return;
    }

    info!("Opening {}...", args.path);
    let path = path::Path::new(&args.path);

    if args.analyze {
        analyze(&path);
    } else if args.create {
        create(&path);
    }
}
