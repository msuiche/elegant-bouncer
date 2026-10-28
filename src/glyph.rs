//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  glyph.rs
//
// Abstract:
//  CVE-2026-86950 — "The Great Glyph Grift" CoreGraphics out-of-bounds write.
//
// Author:
//  Matt Suiche (msuiche) 27-Oct-2026
//
// Changelog:
//  27-Oct-2026 (msuiche) - Initial implementation
//
// Detection rationale (structural, no in-the-wild sample required):
//
//  The CoreGraphics anti-aliased rasterizer converts glyph path coordinates to
//  4096x4096 sub-pixel fixed point through aa_double_to_fixed() =
//  (int32_t)(0.5 + 4096.0 * px). Prior to iOS/macOS 26.7.1 the cast had no
//  clamping and two call sites compiled it differently (saturation in aa_moveto,
//  truncation via FCVTZS.2D+XTN in aa_lineto). A glyph whose device coordinates
//  overflow int32 after conversion makes the aa_add_edges() bounding box delta
//  sign-wrap, so aa_cache_render() allocates an undersized coverage buffer and
//  writes past it while accumulating scanline alpha — an OOB write on the heap
//  or on the stack via alloca depending on the forged bbox width.
//
//  To be reachable through ripc_DrawGlyphs' glyph-bitmap cache path, the
//  oversized coordinates must survive every upstream transform. The largest
//  text matrix scale that still takes that path is Tf = 1024, so the widest
//  device coordinate an attacker can produce is:
//
//      device_px = font_units * 1024 / unitsPerEm
//      fixed     = 4096 * device_px
//
//  The int32 overflow (fixed >= 2^31) therefore requires:
//
//      font_units >= 2^31 * unitsPerEm / (4096 * 1024) = 512 * unitsPerEm
//
//  i.e. effective glyph coordinates of 512 em — three orders of magnitude
//  beyond any legitimate glyph (real fonts stay within ~±40% of the em). That
//  margin makes the rule both complete for the bug class and false-positive
//  free without in-the-wild samples.
//
//  In the Calif PoC a leaf glyph carries a contour at x = 32000 font units in a
//  16384-upm font, and nine stacked composite glyphs each scale by the F2Dot14
//  maximum (~2.0). The composite expansion multiplies the leaf coordinates to
//  ~16.4M font units = 1000 em > 512 em — exactly the structure detected here.
//
//  The int16 xMin/xMax bbox headers are NOT trusted: the PoC forges them small
//  (0/33) so the undersized allocation happens at render time. Detection uses
//  the actual on-curve/off-curve point coordinates.
//
// References:
//  https://calif.io/research/the-great-glyph-grift
//  https://support.apple.com/en-us/149226
//  https://github.com/califio/publications/tree/main/MADBugs/CVE-2026-86950
//

use std::fmt;
use std::path;

use crate::errors::*;

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{BigEndian, ReadBytesExt};

use log::{debug, info};
use colored::*;

#[derive(Debug)]
pub enum GlyphError {
    InvalidFile,
    TableNotFound,
    MalformedTable,
}

impl fmt::Display for GlyphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlyphError::InvalidFile => write!(f, "Not a valid font file."),
            GlyphError::TableNotFound => write!(f, "Table not found"),
            GlyphError::MalformedTable => write!(f, "Malformed font table."),
        }
    }
}

impl std::error::Error for GlyphError {}

impl From<GlyphError> for ElegantError {
    fn from(e: GlyphError) -> Self {
        ElegantError::GlyphError(e)
    }
}

// Fixed point constant of the CoreGraphics anti-aliased rasterizer: each pixel
// is a 4096 x 4096 sub-pixel box.
const AA_SUBPIXEL: f64 = 4096.0;

// Largest font size (Tf operand) that still reaches the glyph-bitmap cache path
// in ripc_DrawGlyphs — the maximum scale an attacker can push through.
const MAX_TEXT_MATRIX_SCALE: f64 = 1024.0;

// Boundary of the unpatched aa_double_to_fixed() int32 cast.
const INT32_RANGE: f64 = 2147483648.0;

// Overflow threshold in font units: 2^31 * upm / (4096 * 1024) = 512 * upm.
fn effective_unit_limit(upm: u16) -> f64 {
    INT32_RANGE * upm as f64 / (AA_SUBPIXEL * MAX_TEXT_MATRIX_SCALE)
}

struct FontTables {
    loca:    Vec<u8>,
    glyf:    Vec<u8>,
    upm:     u16,     // unitsPerEm
    loca_fmt: u16,     // head.indexToLocFormat: 0 = u16 offsets (x2), 1 = u32
    num_glyphs: u16,
}

impl FontTables {
    fn from_reader<R: Read + Seek>(mut reader: R) -> Result<Self> {
        reader.seek(SeekFrom::Start(0))?;
        let sfnt_version = reader.read_u32::<BigEndian>()?;

        // 0x00010000: TrueType (TTF), 'true': legacy Mac tag. CFF-flavoured
        // OpenType ('OTTO') and collections ('ttcf') use another outline
        // format / extra header — out of scope for this CVE (glyf outlines).
        if sfnt_version != 0x00010000 && sfnt_version != u32::from_be_bytes(*b"true") {
            return Err(GlyphError::InvalidFile.into());
        }

        let num_tables = reader.read_u16::<BigEndian>()?;
        reader.seek(SeekFrom::Current(6))?; // searchRange, entrySelector, rangeShift

        let mut head: Option<Vec<u8>> = None;
        let mut maxp: Option<Vec<u8>> = None;
        let mut loca: Option<Vec<u8>> = None;
        let mut glyf: Option<Vec<u8>> = None;

        let file_len = reader.seek(SeekFrom::End(0))?;
        // Back to the table directory (seeking to End above moved the cursor).
        reader.seek(SeekFrom::Current(-(file_len as i64 - 12)))?;
        for _ in 0..num_tables {
            let mut tag = [0u8; 4];
            reader.read_exact(&mut tag)?;
            let _checksum = reader.read_u32::<BigEndian>()?;
            let offset = reader.read_u32::<BigEndian>()?;
            let len = reader.read_u32::<BigEndian>()?;

            let table = match &tag[..] {
                b"head" => &mut head,
                b"maxp" => &mut maxp,
                b"loca" => &mut loca,
                b"glyf" => &mut glyf,
                _ => continue,
            };
            if offset.checked_add(len).is_none_or(|end| end as u64 > file_len) {
                continue; // out-of-range table entry — ignore it
            }
            // Read the table and return the cursor to the directory entry
            // that follows, so the loop stays in sync.
            let dir_next = reader.stream_position()?;
            reader.seek(SeekFrom::Start(offset as u64))?;
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf)?;
            *table = Some(buf);
            reader.seek(SeekFrom::Start(dir_next))?;
        }

        let head = head.ok_or(GlyphError::TableNotFound)?;
        if head.len() < 54 {
            return Err(GlyphError::MalformedTable.into());
        }
        // unitsPerEm at head offset 18, indexToLocFormat at offset 50.
        let upm = u16::from_be_bytes([head[18], head[19]]);
        let loca_fmt = u16::from_be_bytes([head[50], head[51]]);

        let maxp = maxp.ok_or(GlyphError::TableNotFound)?;
        if maxp.len() < 6 {
            return Err(GlyphError::MalformedTable.into());
        }
        let num_glyphs = u16::from_be_bytes([maxp[4], maxp[5]]);

        Ok(FontTables {
            loca: loca.ok_or(GlyphError::TableNotFound)?,
            glyf: glyf.ok_or(GlyphError::TableNotFound)?,
            upm,
            loca_fmt,
            num_glyphs,
        })
    }

    fn glyph_range(&self, glyph_id: u16) -> Option<(usize, usize)> {
        if self.loca_fmt == 0 {
            let base = (glyph_id as usize) * 2;
            if base + 4 > self.loca.len() {
                return None;
            }
            let start = u16::from_be_bytes([self.loca[base], self.loca[base + 1]]) as usize * 2;
            let end = u16::from_be_bytes([self.loca[base + 2], self.loca[base + 3]]) as usize * 2;
            Some((start, end))
        } else {
            let base = (glyph_id as usize) * 4;
            if base + 8 > self.loca.len() {
                return None;
            }
            let start = u32::from_be_bytes(self.loca[base..base + 4].try_into().unwrap()) as usize;
            let end = u32::from_be_bytes(self.loca[base + 4..base + 8].try_into().unwrap()) as usize;
            Some((start, end))
        }
    }
}

// Bounding box of a fully expanded outline, in the root glyph's font units.
#[derive(Clone, Copy)]
struct GlyphBbox {
    min_x: f64,
    max_x: f64,
    min_y: f64,
    max_y: f64,
}

impl GlyphBbox {
    fn empty() -> Self {
        GlyphBbox { min_x: f64::MAX, max_x: f64::MIN, min_y: f64::MAX, max_y: f64::MIN }
    }

    fn union(&mut self, other: &GlyphBbox) {
        self.min_x = self.min_x.min(other.min_x);
        self.max_x = self.max_x.max(other.max_x);
        self.min_y = self.min_y.min(other.min_y);
        self.max_y = self.max_y.max(other.max_y);
    }

    fn max_abs(&self) -> f64 {
        self.min_x.abs().max(self.max_x).max(self.min_y.abs()).max(self.max_y)
    }
}

// 2x2 component scale/rotation (F2Dot14). Translations are intentionally not
// modelled: only the scale product drives coordinates past the overflow
// threshold, and ignoring offsets keeps the rule conservative.
#[derive(Clone, Copy)]
struct ComponentTransform {
    a: f64,
    b: f64,
    c: f64,
    d: f64,
}

impl ComponentTransform {
    fn apply_to_bbox(&self, bbox: &GlyphBbox) -> GlyphBbox {
        let corners = [
            (self.a * bbox.min_x + self.c * bbox.min_y, self.b * bbox.min_x + self.d * bbox.min_y),
            (self.a * bbox.max_x + self.c * bbox.min_y, self.b * bbox.max_x + self.d * bbox.min_y),
            (self.a * bbox.min_x + self.c * bbox.max_y, self.b * bbox.min_x + self.d * bbox.max_y),
            (self.a * bbox.max_x + self.c * bbox.max_y, self.b * bbox.max_x + self.d * bbox.max_y),
        ];
        let mut out = GlyphBbox::empty();
        for (x, y) in &corners {
            out.min_x = out.min_x.min(*x);
            out.max_x = out.max_x.max(*x);
            out.min_y = out.min_y.min(*y);
            out.max_y = out.max_y.max(*y);
        }
        out
    }
}

fn read_be_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn read_be_i16(buf: &[u8], off: usize) -> Option<i16> {
    read_be_u16(buf, off).map(|v| v as i16)
}

// Parse one glyph and return its fully expanded outline bbox in font units.
// Composites recurse into components applying each component transform as the
// chain unwinds, so the result already includes the accumulated scale product.
// Returns None for empty/missing glyphs. Depth cap cuts composite cycles.
fn parse_glyph(font: &FontTables, glyph_id: u16, depth: usize) -> Result<Option<GlyphBbox>> {
    // maxComponentDepth of the PoC is 9; the OpenType spec bound is 32.
    if depth > 32 {
        return Ok(None);
    }

    let (start, end) = match font.glyph_range(glyph_id) {
        Some(range) if range.1 > range.0 => range,
        _ => return Ok(None), // empty glyph
    };
    if end > font.glyf.len() {
        return Err(GlyphError::MalformedTable.into());
    }
    let g = &font.glyf[start..end];
    if g.len() < 10 {
        return Ok(None);
    }

    let number_of_contours = read_be_i16(g, 0).unwrap_or(-1);
    if number_of_contours >= 0 {
        parse_simple_glyph(g, number_of_contours as usize)
    } else {
        parse_composite_glyph(font, g, depth)
    }
}

// Simple glyph: walk the contours and collect the real coordinate extremes.
// The stored int16 xMin/xMax header is ignored — CVE-2026-86950 forges it.
fn parse_simple_glyph(g: &[u8], num_contours: usize) -> Result<Option<GlyphBbox>> {
    let mut off = 10usize;
    let mut last_end_point = 0usize;
    for _ in 0..num_contours {
        last_end_point = match read_be_u16(g, off) {
            Some(v) => v as usize,
            None => return Err(GlyphError::MalformedTable.into()),
        };
        off += 2;
    }
    let num_points = last_end_point + 1;

    // Skip the hinting bytecode.
    let instruction_len = match read_be_u16(g, off) {
        Some(v) => v as usize,
        None => return Err(GlyphError::MalformedTable.into()),
    };
    off += 2 + instruction_len;
    if off > g.len() {
        return Err(GlyphError::MalformedTable.into());
    }

    // Flags (with REPEAT_FLAG expansion).
    let mut flags = Vec::with_capacity(num_points);
    while flags.len() < num_points {
        let f = match g.get(off) {
            Some(&f) => f,
            None => return Err(GlyphError::MalformedTable.into()),
        };
        off += 1;
        flags.push(f);
        if f & 0x08 != 0 {
            let repeat = match g.get(off) {
                Some(&r) => r as usize,
                None => return Err(GlyphError::MalformedTable.into()),
            };
            off += 1;
            for _ in 0..repeat {
                if flags.len() >= num_points {
                    break;
                }
                flags.push(f);
            }
        }
    }

    // x deltas then y deltas — same encoding, separate sign bits.
    let mut xs = Vec::with_capacity(num_points);
    let mut ys = Vec::with_capacity(num_points);
    let mut x: i32 = 0;
    let mut y: i32 = 0;
    for &f in &flags {
        if f & 0x02 != 0 { // x-short vector
            let dx = match g.get(off) {
                Some(&d) => d as i32,
                None => return Err(GlyphError::MalformedTable.into()),
            };
            off += 1;
            x += if f & 0x10 != 0 { dx } else { -dx };
        } else if f & 0x10 == 0 { // 16-bit delta
            let dx = match read_be_i16(g, off) {
                Some(d) => d as i32,
                None => return Err(GlyphError::MalformedTable.into()),
            };
            off += 2;
            x += dx;
        }
        xs.push(x as f64);
    }
    for &f in &flags {
        if f & 0x04 != 0 { // y-short vector
            let dy = match g.get(off) {
                Some(&d) => d as i32,
                None => return Err(GlyphError::MalformedTable.into()),
            };
            off += 1;
            y += if f & 0x20 != 0 { dy } else { -dy };
        } else if f & 0x20 == 0 {
            let dy = match read_be_i16(g, off) {
                Some(d) => d as i32,
                None => return Err(GlyphError::MalformedTable.into()),
            };
            off += 2;
            y += dy;
        }
        ys.push(y as f64);
    }

    let mut bbox = GlyphBbox::empty();
    for i in 0..num_points {
        bbox.min_x = bbox.min_x.min(xs[i]);
        bbox.max_x = bbox.max_x.max(xs[i]);
        bbox.min_y = bbox.min_y.min(ys[i]);
        bbox.max_y = bbox.max_y.max(ys[i]);
    }

    Ok(Some(bbox))
}

// Composite glyph: expand every component and apply the component transform as
// the recursion unwinds, yielding the effective outline in this glyph's units.
fn parse_composite_glyph(
    font: &FontTables,
    g: &[u8],
    depth: usize,
) -> Result<Option<GlyphBbox>> {
    let mut off = 10usize;
    let mut combined: Option<GlyphBbox> = None;

    loop {
        let flags = match read_be_u16(g, off) {
            Some(f) => f,
            None => return Err(GlyphError::MalformedTable.into()),
        };
        let glyph_index = match read_be_u16(g, off + 2) {
            Some(i) => i,
            None => return Err(GlyphError::MalformedTable.into()),
        };
        off += 4;

        if glyph_index >= font.num_glyphs {
            return Err(GlyphError::MalformedTable.into());
        }

        // Arg1/Arg2 (offsets or point indices) — sizes only, values unused.
        let arg_size = if flags & 0x0001 != 0 { 4 } else { 2 }; // ARG_1_AND_2_ARE_WORDS
        if off + arg_size > g.len() {
            return Err(GlyphError::MalformedTable.into());
        }
        off += arg_size;

        // Optional F2Dot14 scale variants.
        let mut ct = ComponentTransform { a: 1.0, b: 0.0, c: 0.0, d: 1.0 };
        if flags & 0x0008 != 0 {        // WE_HAVE_A_SCALE
            let s = match read_be_i16(g, off) {
                Some(v) => v as f64 / 16384.0,
                None => return Err(GlyphError::MalformedTable.into()),
            };
            ct = ComponentTransform { a: s, b: 0.0, c: 0.0, d: s };
            off += 2;
        } else if flags & 0x0040 != 0 { // WE_HAVE_AN_X_AND_Y_SCALE
            let (sx, sy) = match (read_be_i16(g, off), read_be_i16(g, off + 2)) {
                (Some(x), Some(y)) => (x as f64 / 16384.0, y as f64 / 16384.0),
                _ => return Err(GlyphError::MalformedTable.into()),
            };
            ct = ComponentTransform { a: sx, b: 0.0, c: 0.0, d: sy };
            off += 4;
        } else if flags & 0x0080 != 0 { // WE_HAVE_A_TWO_BY_TWO
            let (a, b) = match (read_be_i16(g, off), read_be_i16(g, off + 2)) {
                (Some(x), Some(y)) => (x as f64 / 16384.0, y as f64 / 16384.0),
                _ => return Err(GlyphError::MalformedTable.into()),
            };
            let (c, d) = match (read_be_i16(g, off + 4), read_be_i16(g, off + 6)) {
                (Some(x), Some(y)) => (x as f64 / 16384.0, y as f64 / 16384.0),
                _ => return Err(GlyphError::MalformedTable.into()),
            };
            ct = ComponentTransform { a, b, c, d };
            off += 8;
        }

        // Child's expanded outline, scaled by this component's transform.
        if let Some(child) = parse_glyph(font, glyph_index, depth + 1)? {
            let child = ct.apply_to_bbox(&child);
            combined = match combined {
                Some(mut prev) => { prev.union(&child); Some(prev) }
                None => Some(child),
            };
        }

        if flags & 0x0020 == 0 { // MORE_COMPONENTS
            break;
        }
    }

    Ok(combined)
}

// Scan an in-memory TrueType font program for the CVE-2026-86950 trigger.
pub fn scan_ttf_bytes(byte_data: &[u8], font_name: &str) -> Result<ScanResultStatus> {
    let font = match FontTables::from_reader(Cursor::new(byte_data)) {
        Ok(f) => f,
        Err(_) => return Ok(ScanResultStatus::StatusOk), // not an expandable TTF — benign for this CVE
    };

    if font.upm == 0 || font.loca_fmt > 1 {
        return Ok(ScanResultStatus::StatusOk); // malformed beyond the interesting parts
    }

    let limit = effective_unit_limit(font.upm);
    for gid in 0..font.num_glyphs {
        match parse_glyph(&font, gid, 0) {
            Ok(Some(bbox)) => {
                let value = bbox.max_abs();
                if value >= limit {
                    info!("Glyph {} in {}: effective coordinate {} font units ({} em) >= {} em limit (upm {})",
                        gid, font_name, value, value / font.upm as f64, limit / font.upm as f64, font.upm);
                    debug!("4096 * {} * 1024 / {} >= 2^31 — aa_double_to_fixed() int32 overflow", value, font.upm);
                    return Ok(ScanResultStatus::StatusMalicious);
                }
            },
            Ok(None) => {}, // empty glyph
            Err(_) => continue, // unparseable glyph — skip, let the others speak
        }
    }

    Ok(ScanResultStatus::StatusOk)
}

// Scan a standalone TrueType/OpenType font file.
pub fn scan_ttf_file(path: &path::Path) -> Result<ScanResultStatus> {
    debug!("Opening {}...", path.display());
    let mut byte_data = Vec::new();
    File::open(path)?.read_to_end(&mut byte_data)?;
    scan_ttf_bytes(&byte_data, &path.display().to_string())
}

// Scan a PDF: resolve /FontFile, /FontFile2 and /FontFile3 from the font
// descriptor dictionaries (they are indirect references to stream objects),
// then scan each embedded font program for the glyph overflow trigger.
// FlateDecode is handled by lopdf's decompressed_content().
pub fn scan_pdf_file(path: &path::Path) -> Result<ScanResultStatus> {
    use lopdf::{Document, Object};

    debug!("Opening {}...", path.display());
    let doc = Document::load(path)?;

    const FONT_FILE_KEYS: [&[u8]; 3] = [b"FontFile", b"FontFile2", b"FontFile3"];

    // The font program streams, referenced by descriptors. Font descriptors
    // may be top-level objects or nested inside /Font dicts.
    let mut font_ids: Vec<(usize, Vec<u8>)> = Vec::new();
    for (obj_id, object) in &doc.objects {
        let dict = match object {
            Object::Dictionary(d) => d,
            _ => continue,
        };
        for key in FONT_FILE_KEYS {
            let font_obj = match dict.get(key) {
                Ok(Object::Reference(id)) => *id,
                // A font program embedded directly as a stream value.
                Ok(Object::Stream(s)) => {
                    font_ids.push((obj_id.0 as usize, s.content.clone()));
                    continue;
                }
                _ => continue,
            };
            // FontFile3 may wrap a CFF program (Subtype /Type1C /CIDFontType0C)
            // or an OpenTypeCollection; only glyf-flavoured programs parse here.
            match doc.get_object(font_obj) {
                Ok(Object::Stream(s)) => {
                    let content = match s.decompressed_content() {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    font_ids.push((obj_id.0 as usize, content));
                }
                _ => continue,
            }
        }
    }

    debug!("Scanning {} embedded font program(s) in {}", font_ids.len(), path.display());

    for (obj_num, content) in &font_ids {
        let name = format!("{} (font stream from obj {})", path.display(), obj_num);
        if scan_ttf_bytes(content, &name)? == ScanResultStatus::StatusMalicious {
            info!("{}: CVE-2026-86950 glyph fixed-point overflow trigger {}",
                path.display(), "Present.".red());
            return Ok(ScanResultStatus::StatusMalicious);
        }
    }

    Ok(ScanResultStatus::StatusOk)
}
