//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  heif.rs
//
// Abstract:
//  ELEGANTBOUNCER HEIF/AVIF scanner for libheif item-graph defects:
//   - CVE-2026-32741, heap buffer overflow in MaskImageCodec::decode_mask_image()
//   - the undocumented 16-bpp mask row underfill that returns uninitialised heap
//     memory as pixel data (same function, both fixed in 1.22.0)
//   - CVE-2026-32882, heap over-read in HeifPixelImage::overlay() when an 'iovl'
//     child has a different bit depth for alpha than for colour (<= 1.21.2)
//   - CVE-2026-84383, heap buffer overflow in scale_nearest_neighbor() reached
//     through a duplicated Alpha channel built with 'iden' items (1.22.0-1.23.1)
//
// Author:
//  Matt Suiche (msuiche) 20-Sep-2026
//
use crate::errors::ScanResultStatus;
use log::{debug, warn};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HeifCve {
    /// Mask item whose declared data extent is larger than the pixel plane the
    /// decoder allocates from 'ispe'. decode_mask_image() memcpy()s the whole
    /// extent into that plane when stride == width, writing past its end.
    Cve202632741,
    /// 16-bpp mask item whose extent satisfies the (unscaled) length guard but
    /// only fills half of every row, so the right half of each row is returned
    /// as uninitialised heap memory. No CVE, fixed silently in libheif 1.22.0.
    MaskUninitDisclosure,
    /// Overlay ('iovl') child whose alpha channel is shallower than its colour
    /// channels. overlay() indexes the alpha plane with the colour plane stride,
    /// reading past the alpha buffer and blending heap bytes into the output.
    Cve202632882,
    /// Item graph that gives one image two Alpha planes (an 'iden' item that is
    /// itself an alpha auxiliary and carries its own alpha). scale_nearest_neighbor()
    /// sizes the destination from the first Alpha and then writes every storage
    /// entry into it, so a deeper second Alpha overflows the allocation.
    Cve202684383,
}

impl HeifCve {
    pub fn name(&self) -> &'static str {
        match self {
            HeifCve::Cve202632741 => "CVE-2026-32741",
            HeifCve::MaskUninitDisclosure => "HEIF-MASK-DISCLOSURE",
            HeifCve::Cve202632882 => "CVE-2026-32882",
            HeifCve::Cve202684383 => "CVE-2026-84383",
        }
    }
}

/// One malicious construction found in a HEIF/AVIF item graph.
#[derive(Debug, Clone)]
pub struct HeifFinding {
    pub cve: HeifCve,
    /// Item the verdict is attached to.
    pub item_id: u32,
    /// Human readable specifics, logged on a verbose scan.
    pub detail: String,
    /// Geometry of the offending mask item, for the two 'mski' defects.
    pub mask: Option<MaskFinding>,
}

/// A mask image item that does not carry the exact amount of data a correct
/// decoder needs for its declared geometry.
#[derive(Debug, Clone)]
pub struct MaskFinding {
    pub item_id: u32,
    pub width: u32,
    pub height: u32,
    pub bits_per_pixel: u8,
    /// Total length of the item's 'iloc' extents.
    pub extent_len: u64,
    /// width * height * bytes_per_pixel - what the plane actually holds.
    pub required_len: u64,
    /// Size of the plane allocation decode_mask_image() writes into.
    pub plane_alloc: u64,
    /// stride == width, the precondition for the single-memcpy overflow branch.
    pub full_copy_branch: bool,
    pub cve: HeifCve,
}

/// Largest 'meta' box we are willing to buffer. Real HEIF metadata is a few
/// kilobytes; the payload lives in 'mdat', which we never read.
const MAX_META_SIZE: u64 = 16 * 1024 * 1024;
const ITEM_TYPE_MASK: [u8; 4] = *b"mski";

#[derive(Debug, Clone)]
enum Property {
    /// ImageSpatialExtentsProperty
    Ispe {
        width: u32,
        height: u32,
    },
    /// MaskConfigurationProperty
    MskC {
        bits_per_pixel: u8,
    },
    /// AuxiliaryTypeProperty - the URN says what the auxiliary image carries.
    AuxC {
        aux_type: String,
    },
    /// PixelInformationProperty - bit depth of each channel.
    Pixi {
        bits: Vec<u8>,
    },
    /// Bit depth taken from a codec configuration ('hvcC', 'av1C').
    CodecDepth {
        bits_per_pixel: u8,
    },
    /// ComponentDefinitionBox - component types of an uncompressed item.
    Cmpd {
        component_types: Vec<u16>,
    },
    /// UncompressedFrameConfigBox - (component index into 'cmpd', bit depth).
    UncC {
        components: Vec<(u16, u8)>,
    },
    Other,
}

/// One 'iref' entry: `from_item` references `to_items` with type `ref_type`.
#[derive(Debug, Clone)]
struct ItemReference {
    ref_type: [u8; 4],
    from_item: u32,
    to_items: Vec<u32>,
}

#[derive(Debug, Default, Clone)]
struct ItemInfo {
    item_type: Option<[u8; 4]>,
    extent_len: u64,
    has_location: bool,
}

#[derive(Debug, Default)]
struct MetaBox {
    items: HashMap<u32, ItemInfo>,
    /// 'ipco' children, in order. 'ipma' indexes them 1-based.
    properties: Vec<Property>,
    /// item ID -> property indices (as stored in 'ipma', 1-based).
    associations: HashMap<u32, Vec<u16>>,
    /// 'iref' entries, in file order.
    references: Vec<ItemReference>,
}

/// Cursor with checked reads over a box payload.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn fourcc(&mut self) -> Option<[u8; 4]> {
        self.take(4).map(|b| [b[0], b[1], b[2], b[3]])
    }

    /// FullBox header: 1 byte version, 3 bytes flags.
    fn full_box_header(&mut self) -> Option<(u8, u32)> {
        let version = self.u8()?;
        let f = self.take(3)?;
        let flags = ((f[0] as u32) << 16) | ((f[1] as u32) << 8) | f[2] as u32;
        Some((version, flags))
    }

    /// Integer of `size` bytes (ISOBMFF uses 0, 4 or 8; 0 means "absent").
    fn sized_int(&mut self, size: u8) -> Option<u64> {
        match size {
            0 => Some(0),
            4 => self.u32().map(|v| v as u64),
            8 => self
                .take(8)
                .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])),
            _ => None,
        }
    }
}

struct BoxHeader {
    typ: [u8; 4],
    /// Offset of the payload, relative to the start of the containing buffer.
    body_start: usize,
    body_len: usize,
    /// Total box size including the header.
    total_len: usize,
}

/// Parse a box header at `off` inside `buf`.
fn read_box(buf: &[u8], off: usize) -> Option<BoxHeader> {
    if off + 8 > buf.len() {
        return None;
    }
    let size32 = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as u64;
    let typ = [buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]];
    let (size, header_len) = if size32 == 1 {
        if off + 16 > buf.len() {
            return None;
        }
        let large = u64::from_be_bytes([
            buf[off + 8],
            buf[off + 9],
            buf[off + 10],
            buf[off + 11],
            buf[off + 12],
            buf[off + 13],
            buf[off + 14],
            buf[off + 15],
        ]);
        (large, 16usize)
    } else if size32 == 0 {
        // Extends to the end of the enclosing buffer.
        ((buf.len() - off) as u64, 8usize)
    } else {
        (size32, 8usize)
    };

    if size < header_len as u64 {
        return None;
    }
    let total_len = size as usize;
    if off.checked_add(total_len)? > buf.len() {
        return None;
    }

    Some(BoxHeader {
        typ,
        body_start: off + header_len,
        body_len: total_len - header_len,
        total_len,
    })
}

/// Iterate the boxes of a buffer, calling `f` for each.
fn for_each_box<F: FnMut(&BoxHeader, &[u8])>(buf: &[u8], mut f: F) {
    let mut off = 0usize;
    while off + 8 <= buf.len() {
        let header = match read_box(buf, off) {
            Some(h) => h,
            None => break,
        };
        let body = &buf[header.body_start..header.body_start + header.body_len];
        f(&header, body);
        off += header.total_len;
    }
}

/// ItemInfoBox - maps item IDs to their four character item type.
fn parse_iinf(body: &[u8], meta: &mut MetaBox) {
    let mut c = Cursor::new(body);
    let (version, _flags) = match c.full_box_header() {
        Some(v) => v,
        None => return,
    };
    let entry_count = if version == 0 {
        match c.u16() {
            Some(v) => v as u32,
            None => return,
        }
    } else {
        match c.u32() {
            Some(v) => v,
            None => return,
        }
    };
    debug!("iinf: {} entries", entry_count);

    for_each_box(&body[c.pos..], |header, infe_body| {
        if &header.typ != b"infe" {
            return;
        }
        let mut e = Cursor::new(infe_body);
        let (infe_version, _) = match e.full_box_header() {
            Some(v) => v,
            None => return,
        };
        // Versions 0 and 1 have no item_type; only 2 and 3 name the codec.
        let item_id = match infe_version {
            2 => match e.u16() {
                Some(v) => v as u32,
                None => return,
            },
            3 => match e.u32() {
                Some(v) => v,
                None => return,
            },
            _ => return,
        };
        if e.u16().is_none() {
            return; // item_protection_index
        }
        let item_type = match e.fourcc() {
            Some(t) => t,
            None => return,
        };
        let entry = meta.items.entry(item_id).or_default();
        entry.item_type = Some(item_type);
    });
}

/// ItemLocationBox - sums the declared extent lengths of every item.
fn parse_iloc(body: &[u8], meta: &mut MetaBox) {
    let mut c = Cursor::new(body);
    let (version, _flags) = match c.full_box_header() {
        Some(v) => v,
        None => return,
    };
    let sizes = match c.u16() {
        Some(v) => v,
        None => return,
    };
    let offset_size = ((sizes >> 12) & 0xF) as u8;
    let length_size = ((sizes >> 8) & 0xF) as u8;
    let base_offset_size = ((sizes >> 4) & 0xF) as u8;
    let index_size = if version == 1 || version == 2 {
        (sizes & 0xF) as u8
    } else {
        0
    };

    let item_count = if version < 2 {
        match c.u16() {
            Some(v) => v as u32,
            None => return,
        }
    } else {
        match c.u32() {
            Some(v) => v,
            None => return,
        }
    };

    for _ in 0..item_count {
        let item_id = if version < 2 {
            match c.u16() {
                Some(v) => v as u32,
                None => return,
            }
        } else {
            match c.u32() {
                Some(v) => v,
                None => return,
            }
        };
        if version == 1 || version == 2 {
            // reserved (12 bits) + construction_method (4 bits)
            if c.u16().is_none() {
                return;
            }
        }
        if c.u16().is_none() {
            return; // data_reference_index
        }
        if c.sized_int(base_offset_size).is_none() {
            return;
        }
        let extent_count = match c.u16() {
            Some(v) => v,
            None => return,
        };

        let mut total: u64 = 0;
        for _ in 0..extent_count {
            if (version == 1 || version == 2) && index_size > 0 && c.sized_int(index_size).is_none()
            {
                return;
            }
            if c.sized_int(offset_size).is_none() {
                return;
            }
            let extent_len = match c.sized_int(length_size) {
                Some(v) => v,
                None => return,
            };
            total = total.saturating_add(extent_len);
        }

        let entry = meta.items.entry(item_id).or_default();
        entry.extent_len = entry.extent_len.saturating_add(total);
        entry.has_location = true;
    }
}

/// ItemPropertyContainerBox - the ordered property list 'ipma' refers to.
fn parse_ipco(body: &[u8], meta: &mut MetaBox) {
    for_each_box(body, |header, prop_body| {
        let property = match &header.typ {
            b"ispe" => {
                let mut c = Cursor::new(prop_body);
                match (c.full_box_header(), c.u32(), c.u32()) {
                    (Some(_), Some(width), Some(height)) => Property::Ispe { width, height },
                    _ => Property::Other,
                }
            }
            b"mskC" => {
                let mut c = Cursor::new(prop_body);
                match (c.full_box_header(), c.u8()) {
                    (Some(_), Some(bits_per_pixel)) => Property::MskC { bits_per_pixel },
                    _ => Property::Other,
                }
            }
            b"auxC" => {
                let mut c = Cursor::new(prop_body);
                match c.full_box_header() {
                    Some(_) => {
                        let rest = &prop_body[c.pos..];
                        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
                        Property::AuxC {
                            aux_type: String::from_utf8_lossy(&rest[..end]).into_owned(),
                        }
                    }
                    None => Property::Other,
                }
            }
            b"pixi" => {
                let mut c = Cursor::new(prop_body);
                match (c.full_box_header(), c.u8()) {
                    (Some(_), Some(num_channels)) => {
                        let mut bits = Vec::with_capacity(num_channels as usize);
                        for _ in 0..num_channels {
                            match c.u8() {
                                Some(b) => bits.push(b),
                                None => break,
                            }
                        }
                        Property::Pixi { bits }
                    }
                    _ => Property::Other,
                }
            }
            // HEVCDecoderConfigurationRecord: bit_depth_luma_minus8 sits in the
            // low 3 bits of byte 17.
            b"hvcC" => {
                if prop_body.len() > 17 {
                    Property::CodecDepth {
                        bits_per_pixel: 8 + (prop_body[17] & 0x07),
                    }
                } else {
                    Property::Other
                }
            }
            // AV1CodecConfigurationRecord: high_bitdepth and twelve_bit are bits
            // 6 and 5 of byte 2.
            b"av1C" => {
                if prop_body.len() > 2 {
                    let high_bitdepth = prop_body[2] & 0x40 != 0;
                    let twelve_bit = prop_body[2] & 0x20 != 0;
                    let bits_per_pixel = match (high_bitdepth, twelve_bit) {
                        (true, true) => 12,
                        (true, false) => 10,
                        _ => 8,
                    };
                    Property::CodecDepth { bits_per_pixel }
                } else {
                    Property::Other
                }
            }
            b"cmpd" => {
                let mut c = Cursor::new(prop_body);
                match c.u32() {
                    Some(count) => {
                        let mut component_types = Vec::new();
                        for _ in 0..count {
                            match c.u16() {
                                Some(t) => {
                                    component_types.push(t);
                                    // A component type >= 0x8000 is followed by
                                    // a null terminated URI.
                                    if t >= 0x8000 {
                                        while let Some(b) = c.u8() {
                                            if b == 0 {
                                                break;
                                            }
                                        }
                                    }
                                }
                                None => break,
                            }
                        }
                        Property::Cmpd { component_types }
                    }
                    None => Property::Other,
                }
            }
            b"uncC" => {
                let mut c = Cursor::new(prop_body);
                match (c.full_box_header(), c.fourcc(), c.u32()) {
                    (Some((0, _)), Some(_profile), Some(count)) => {
                        let mut components = Vec::new();
                        for _ in 0..count {
                            // component_index, component_bit_depth_minus_one,
                            // component_format, component_align_size
                            match (c.u16(), c.u8(), c.u8(), c.u8()) {
                                (Some(index), Some(depth_minus_one), Some(_), Some(_)) => {
                                    components.push((index, depth_minus_one.saturating_add(1)))
                                }
                                _ => break,
                            }
                        }
                        Property::UncC { components }
                    }
                    _ => Property::Other,
                }
            }
            _ => Property::Other,
        };
        meta.properties.push(property);
    });
}

/// ItemPropertyAssociationBox - item ID to property index mapping.
fn parse_ipma(body: &[u8], meta: &mut MetaBox) {
    let mut c = Cursor::new(body);
    let (version, flags) = match c.full_box_header() {
        Some(v) => v,
        None => return,
    };
    let entry_count = match c.u32() {
        Some(v) => v,
        None => return,
    };

    for _ in 0..entry_count {
        let item_id = if version < 1 {
            match c.u16() {
                Some(v) => v as u32,
                None => return,
            }
        } else {
            match c.u32() {
                Some(v) => v,
                None => return,
            }
        };
        let association_count = match c.u8() {
            Some(v) => v,
            None => return,
        };
        let mut indices = Vec::with_capacity(association_count as usize);
        for _ in 0..association_count {
            let index = if flags & 1 != 0 {
                match c.u16() {
                    // essential flag in the top bit, 15-bit property index
                    Some(v) => v & 0x7FFF,
                    None => return,
                }
            } else {
                match c.u8() {
                    Some(v) => (v & 0x7F) as u16,
                    None => return,
                }
            };
            indices.push(index);
        }
        meta.associations
            .entry(item_id)
            .or_default()
            .extend(indices);
    }
}

/// ItemReferenceBox - the 'auxl'/'dimg'/'thmb' edges of the item graph.
fn parse_iref(body: &[u8], meta: &mut MetaBox) {
    let mut c = Cursor::new(body);
    let (version, _flags) = match c.full_box_header() {
        Some(v) => v,
        None => return,
    };

    for_each_box(&body[c.pos..], |header, ref_body| {
        let mut r = Cursor::new(ref_body);
        let from_item = if version == 0 {
            match r.u16() {
                Some(v) => v as u32,
                None => return,
            }
        } else {
            match r.u32() {
                Some(v) => v,
                None => return,
            }
        };
        let count = match r.u16() {
            Some(v) => v,
            None => return,
        };
        let mut to_items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let id = if version == 0 {
                match r.u16() {
                    Some(v) => v as u32,
                    None => break,
                }
            } else {
                match r.u32() {
                    Some(v) => v,
                    None => break,
                }
            };
            to_items.push(id);
        }
        meta.references.push(ItemReference {
            ref_type: header.typ,
            from_item,
            to_items,
        });
    });
}

fn parse_iprp(body: &[u8], meta: &mut MetaBox) {
    for_each_box(body, |header, child| match &header.typ {
        b"ipco" => parse_ipco(child, meta),
        b"ipma" => parse_ipma(child, meta),
        _ => {}
    });
}

fn parse_meta(body: &[u8]) -> MetaBox {
    let mut meta = MetaBox::default();
    // 'meta' is a FullBox: skip version and flags before its children.
    if body.len() < 4 {
        return meta;
    }
    for_each_box(&body[4..], |header, child| match &header.typ {
        b"iinf" => parse_iinf(child, &mut meta),
        b"iloc" => parse_iloc(child, &mut meta),
        b"iprp" => parse_iprp(child, &mut meta),
        b"iref" => parse_iref(child, &mut meta),
        _ => {}
    });
    meta
}

/// Mirror of libheif's ImagePlane::alloc - the size of the buffer
/// decode_mask_image() writes the mask data into.
fn plane_stride(width: u32, bits_per_pixel: u8) -> u64 {
    let bytes_per_pixel = (bits_per_pixel as u64).div_ceil(8);
    let mem_width = std::cmp::max(64u64, (width as u64 + 1) & !1);
    (mem_width * bytes_per_pixel + 15) & !15
}

fn plane_geometry(width: u32, height: u32, bits_per_pixel: u8) -> (u64, u64) {
    let stride = plane_stride(width, bits_per_pixel);
    let mem_height = std::cmp::max(64u64, (height as u64 + 1) & !1);
    let allocation = mem_height * stride + 15;
    (stride, allocation)
}

/// Read the top-level 'meta' box of an ISOBMFF file without buffering 'mdat'.
fn read_meta_box(path: &Path) -> Option<MetaBox> {
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len < 16 {
        return None;
    }

    let mut offset: u64 = 0;

    while offset + 8 <= file_len {
        let mut header = [0u8; 8];
        file.seek(SeekFrom::Start(offset)).ok()?;
        if file.read_exact(&mut header).is_err() {
            return None;
        }
        let size32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let typ = [header[4], header[5], header[6], header[7]];

        let (size, header_len) = if size32 == 1 {
            let mut large = [0u8; 8];
            if file.read_exact(&mut large).is_err() {
                return None;
            }
            (u64::from_be_bytes(large), 16u64)
        } else if size32 == 0 {
            (file_len - offset, 8u64)
        } else {
            (size32, 8u64)
        };

        if size < header_len || offset.saturating_add(size) > file_len {
            // Truncated or malformed container - nothing trustworthy left.
            return None;
        }

        if offset == 0 {
            // ISOBMFF requires 'ftyp' first; anything else is not a HEIF family
            // file and must not be parsed as one.
            if &typ != b"ftyp" {
                return None;
            }
        }

        if &typ == b"meta" {
            let body_len = size - header_len;
            if body_len > MAX_META_SIZE {
                warn!(
                    "meta box of {} bytes exceeds the {} byte scan limit, skipping",
                    body_len, MAX_META_SIZE
                );
                return None;
            }
            let mut body = vec![0u8; body_len as usize];
            file.seek(SeekFrom::Start(offset + header_len)).ok()?;
            if file.read_exact(&mut body).is_err() {
                return None;
            }
            return Some(parse_meta(&body));
        }

        offset += size;
    }

    None
}

/// Component type 7 in a 'cmpd' box is the alpha component.
const COMPONENT_TYPE_ALPHA: u16 = 7;

impl MetaBox {
    fn properties_of(&self, item_id: u32) -> Vec<&Property> {
        let mut out = Vec::new();
        if let Some(indices) = self.associations.get(&item_id) {
            for index in indices {
                if *index == 0 {
                    continue;
                }
                if let Some(property) = self.properties.get((*index - 1) as usize) {
                    out.push(property);
                }
            }
        }
        out
    }

    fn item_type(&self, item_id: u32) -> Option<[u8; 4]> {
        self.items.get(&item_id).and_then(|i| i.item_type)
    }

    fn ispe(&self, item_id: u32) -> Option<(u32, u32)> {
        self.properties_of(item_id)
            .into_iter()
            .find_map(|p| match p {
                Property::Ispe { width, height } => Some((*width, *height)),
                _ => None,
            })
    }

    /// An auxiliary image whose 'auxC' URN marks it as an alpha plane. These are
    /// the three URNs libheif attaches as alpha (context.cc).
    fn is_alpha_auxiliary(&self, item_id: u32) -> bool {
        self.properties_of(item_id).into_iter().any(|p| match p {
            Property::AuxC { aux_type } => matches!(
                aux_type.as_str(),
                "urn:mpeg:avc:2015:auxid:1"
                    | "urn:mpeg:hevc:2015:auxid:1"
                    | "urn:mpeg:mpegB:cicp:systems:auxiliary:alpha"
            ),
            _ => false,
        })
    }

    /// Items referenced by `item_id` with the given reference type.
    fn references_from(&self, item_id: u32, ref_type: &[u8; 4]) -> Vec<u32> {
        self.references
            .iter()
            .filter(|r| r.from_item == item_id && &r.ref_type == ref_type)
            .flat_map(|r| r.to_items.clone())
            .collect()
    }

    /// Alpha auxiliary items attached to `item_id` ('auxl' points from the
    /// auxiliary image to its master).
    fn alpha_auxiliaries_of(&self, item_id: u32) -> Vec<u32> {
        self.references
            .iter()
            .filter(|r| {
                &r.ref_type == b"auxl"
                    && r.to_items.contains(&item_id)
                    && self.is_alpha_auxiliary(r.from_item)
            })
            .map(|r| r.from_item)
            .collect()
    }

    /// Declared bit depth of an item's colour samples, from whichever of 'pixi',
    /// 'hvcC'/'av1C' or 'uncC' the file provides.
    fn colour_depth(&self, item_id: u32) -> Option<u8> {
        let properties = self.properties_of(item_id);
        let mut component_types: Option<&Vec<u16>> = None;
        let mut components: Option<&Vec<(u16, u8)>> = None;
        let mut pixi: Option<&Vec<u8>> = None;
        let mut codec: Option<u8> = None;
        let mut mask: Option<u8> = None;

        for property in properties {
            match property {
                Property::Cmpd { component_types: t } => component_types = Some(t),
                Property::UncC { components: c } => components = Some(c),
                Property::Pixi { bits } => pixi = Some(bits),
                Property::CodecDepth { bits_per_pixel } => codec = Some(*bits_per_pixel),
                Property::MskC { bits_per_pixel } => mask = Some(*bits_per_pixel),
                _ => {}
            }
        }

        // An uncompressed item declares a depth per component and names each
        // component through its index into 'cmpd'. libheif reports the deepest
        // non-alpha component as the image bit depth (unc_dec.cc).
        if let (Some(types), Some(components)) = (component_types, components) {
            let mut deepest: Option<u8> = None;
            for (index, depth) in components {
                match types.get(*index as usize) {
                    Some(kind) if *kind != COMPONENT_TYPE_ALPHA => {
                        deepest = Some(deepest.map_or(*depth, |d: u8| d.max(*depth)));
                    }
                    _ => {}
                }
            }
            if deepest.is_some() {
                return deepest;
            }
        }

        codec
            .or_else(|| pixi.and_then(|bits| bits.first().copied()))
            .or(mask)
            .or_else(|| components.and_then(|c| c.first().map(|(_, d)| *d)))
    }

    /// Bit depth of an uncompressed item's own alpha component, when it has one.
    fn internal_alpha_depth(&self, item_id: u32) -> Option<u8> {
        let properties = self.properties_of(item_id);
        let mut component_types: Option<&Vec<u16>> = None;
        let mut components: Option<&Vec<(u16, u8)>> = None;
        for property in properties {
            match property {
                Property::Cmpd { component_types: t } => component_types = Some(t),
                Property::UncC { components: c } => components = Some(c),
                _ => {}
            }
        }
        let (types, components) = (component_types?, components?);
        components
            .iter()
            .find(|(index, _)| types.get(*index as usize) == Some(&COMPONENT_TYPE_ALPHA))
            .map(|(_, depth)| *depth)
    }

    /// Bit depth of the alpha channel an item's decoded image will carry, either
    /// from its own component list or from its alpha auxiliary item.
    fn alpha_depth(&self, item_id: u32) -> Option<(u8, u32)> {
        if let Some(depth) = self.internal_alpha_depth(item_id) {
            return Some((depth, item_id));
        }
        for alpha in self.alpha_auxiliaries_of(item_id) {
            if let Some(depth) = self.colour_depth(alpha) {
                return Some((depth, alpha));
            }
        }
        None
    }

    /// Every Alpha plane that ends up on `item_id`'s decoded image.
    ///
    /// A derived image hands its source's alpha through: 'iden' returns the
    /// source image unchanged, and a 'grid' canvas is cloned from a tile, alpha
    /// channel included (grid.cc). The item's own alpha auxiliary is then
    /// transferred on top of that. Several 'auxl' edges pointing at the same
    /// master are not duplicates - set_alpha_channel() keeps the last one.
    fn alpha_plane_sources(&self, item_id: u32, depth: usize, seen: &mut Vec<u32>) -> Vec<u32> {
        if depth > MAX_DERIVATION_DEPTH || seen.contains(&item_id) {
            return Vec::new();
        }
        seen.push(item_id);

        let mut planes = Vec::new();
        let item_type = self.item_type(item_id);
        if item_type == Some(*b"iden") || item_type == Some(*b"grid") {
            for source in self.references_from(item_id, b"dimg") {
                planes.extend(self.alpha_plane_sources(source, depth + 1, seen));
            }
        }
        if let Some(own) = self.alpha_auxiliaries_of(item_id).last() {
            planes.push(*own);
        }
        planes
    }
}

/// Guard against cyclic or deeply nested derivation graphs.
const MAX_DERIVATION_DEPTH: usize = 8;

fn bytes_per_sample(bits: u8) -> u8 {
    bits.div_ceil(8)
}

/// Mask items whose declared data length does not match their declared geometry.
fn analyze_mask_items(meta: &MetaBox) -> Vec<MaskFinding> {
    let mut findings = Vec::new();

    for (item_id, item) in &meta.items {
        if item.item_type != Some(ITEM_TYPE_MASK) || !item.has_location {
            continue;
        }

        let mut geometry: Option<(u32, u32)> = None;
        let mut bits_per_pixel: Option<u8> = None;
        for property in meta.properties_of(*item_id) {
            match property {
                Property::Ispe { width, height } => geometry = Some((*width, *height)),
                Property::MskC {
                    bits_per_pixel: bpp,
                } => bits_per_pixel = Some(*bpp),
                _ => {}
            }
        }

        let (width, height) = match geometry {
            Some(g) => g,
            None => continue,
        };
        // decode_mask_image() requires both properties: "Missing required box
        // for mask codec" is returned before any allocation happens.
        let bpp = match bits_per_pixel {
            Some(b) => b,
            None => continue,
        };
        if width == 0 || height == 0 {
            continue;
        }
        if bpp != 8 && bpp != 16 {
            // decode_mask_image() rejects anything else before touching memory.
            continue;
        }

        let pixels = (width as u64).saturating_mul(height as u64);
        let required_len = pixels.saturating_mul(bytes_per_sample(bpp) as u64);
        let (stride, plane_alloc) = plane_geometry(width, height, bpp);
        let extent_len = item.extent_len;

        // The only length check in the vulnerable decoder is `data.size() <
        // width * height` - bytes, never scaled by the bit depth. Short 8-bpp
        // data is rejected there, so it is not a threat.
        let cve = if bpp == 8 && extent_len > pixels {
            Some(HeifCve::Cve202632741)
        } else if bpp == 16 && extent_len >= pixels && extent_len < required_len {
            Some(HeifCve::MaskUninitDisclosure)
        } else {
            None
        };

        if let Some(cve) = cve {
            findings.push(MaskFinding {
                item_id: *item_id,
                width,
                height,
                bits_per_pixel: bpp,
                extent_len,
                required_len,
                plane_alloc,
                full_copy_branch: stride == width as u64,
                cve,
            });
        }
    }

    findings.sort_by_key(|f| f.item_id);
    findings
}

/// CVE-2026-32882 - an 'iovl' child whose alpha channel is shallower than its
/// colour channels. overlay() reads the alpha plane with the colour plane's
/// stride, so a wider colour sample walks the alpha pointer off its buffer.
fn analyze_overlay_items(meta: &MetaBox) -> Vec<HeifFinding> {
    let mut findings = Vec::new();

    for (item_id, item) in &meta.items {
        if item.item_type != Some(*b"iovl") {
            continue;
        }

        for child in meta.references_from(*item_id, b"dimg") {
            // An 'iden' child is decoded as its source image.
            let source = if meta.item_type(child) == Some(*b"iden") {
                meta.references_from(child, b"dimg")
                    .first()
                    .copied()
                    .unwrap_or(child)
            } else {
                child
            };

            let colour_bits = match meta.colour_depth(source) {
                Some(b) => b,
                None => continue,
            };
            let (alpha_bits, alpha_item) = match meta.alpha_depth(source) {
                Some(a) => a,
                None => continue,
            };

            if bytes_per_sample(colour_bits) > bytes_per_sample(alpha_bits) {
                findings.push(HeifFinding {
                    cve: HeifCve::Cve202632882,
                    item_id: *item_id,
                    detail: format!(
                        "overlay item {} composites item {} with {}-bit colour but {}-bit alpha (item {}); overlay() indexes the {} byte per sample alpha plane with the {} byte per sample colour stride",
                        item_id,
                        child,
                        colour_bits,
                        alpha_bits,
                        alpha_item,
                        bytes_per_sample(alpha_bits),
                        bytes_per_sample(colour_bits)
                    ),
                    mask: None,
                });
            }
        }
    }

    findings.sort_by_key(|f| f.item_id);
    findings
}

/// CVE-2026-84383 - an item graph that hands one image two Alpha planes.
/// scale_nearest_neighbor() allocates the destination from the first plane's bit
/// depth and then writes every storage entry into it, so a deeper second Alpha
/// writes past the allocation.
fn analyze_duplicate_alpha(meta: &MetaBox) -> Vec<HeifFinding> {
    let mut findings = Vec::new();

    for item_id in meta.items.keys() {
        let mut seen = Vec::new();
        let planes = meta.alpha_plane_sources(*item_id, 0, &mut seen);
        if planes.len() < 2 {
            continue;
        }

        let depths: Vec<String> = planes
            .iter()
            .map(|p| match meta.colour_depth(*p) {
                Some(bits) => format!("item {} ({}-bit)", p, bits),
                None => format!("item {} (unknown depth)", p),
            })
            .collect();

        // The overflow needs the scaler to run, which happens when the alpha
        // geometry differs from the image it is attached to.
        let mut scaling_note = String::new();
        for master in meta
            .references
            .iter()
            .filter(|r| &r.ref_type == b"auxl" && r.from_item == *item_id)
            .flat_map(|r| r.to_items.clone())
        {
            if let (Some(alpha_dims), Some(master_dims)) = (meta.ispe(*item_id), meta.ispe(master))
            {
                if alpha_dims != master_dims {
                    scaling_note = format!(
                        "; it is the alpha of item {} ({}x{} against {}x{}), so the planes are scaled before use",
                        master, alpha_dims.0, alpha_dims.1, master_dims.0, master_dims.1
                    );
                }
            }
        }

        findings.push(HeifFinding {
            cve: HeifCve::Cve202684383,
            item_id: *item_id,
            detail: format!(
                "item {} carries {} alpha planes - {}{}",
                item_id,
                planes.len(),
                depths.join(", "),
                scaling_note
            ),
            mask: None,
        });
    }

    findings.sort_by_key(|f| f.item_id);
    findings
}

/// Inspect a HEIF/AVIF item graph and return every malicious construction in it.
pub fn analyze_heif_file(path: &Path) -> Vec<HeifFinding> {
    let meta = match read_meta_box(path) {
        Some(m) => m,
        None => return Vec::new(),
    };

    let mut findings = Vec::new();

    for mask in analyze_mask_items(&meta) {
        let detail = match mask.cve {
            HeifCve::MaskUninitDisclosure => format!(
                "mski item {} is {}x{} 16bpp but declares only {} of the {} bytes a full plane needs; {} bytes per row are returned uninitialised",
                mask.item_id, mask.width, mask.height, mask.extent_len, mask.required_len, mask.width
            ),
            _ => {
                let mut detail = format!(
                    "mski item {} is {}x{} {}bpp but declares {} bytes of mask data ({} expected, plane allocation is {} bytes)",
                    mask.item_id,
                    mask.width,
                    mask.height,
                    mask.bits_per_pixel,
                    mask.extent_len,
                    mask.required_len,
                    mask.plane_alloc
                );
                if mask.full_copy_branch {
                    // stride == width, so the decoder copies the whole extent in
                    // one memcpy() instead of row by row.
                    if mask.extent_len > mask.plane_alloc {
                        detail.push_str(&format!(
                            "; {} bytes land past the end of the mask plane",
                            mask.extent_len - mask.plane_alloc
                        ));
                    }
                } else {
                    detail.push_str(&format!(
                        "; stride ({}) differs from the declared width, so the overflowing memcpy() branch is not reached on an unpatched libheif",
                        plane_stride(mask.width, mask.bits_per_pixel)
                    ));
                }
                detail
            }
        };

        findings.push(HeifFinding {
            cve: mask.cve,
            item_id: mask.item_id,
            detail,
            mask: Some(mask),
        });
    }

    findings.extend(analyze_duplicate_alpha(&meta));
    findings.extend(analyze_overlay_items(&meta));
    findings
}

/// Order the defect classes by what an analyst should look at first: the two
/// write primitives, then the two disclosure primitives.
fn severity(cve: HeifCve) -> u8 {
    match cve {
        HeifCve::Cve202632741 => 0,
        HeifCve::Cve202684383 => 1,
        HeifCve::MaskUninitDisclosure => 2,
        HeifCve::Cve202632882 => 3,
    }
}

/// Scan a HEIF/AVIF file and report every defect class its item graph carries.
pub fn scan_heif_file_all(path: &Path) -> (ScanResultStatus, Vec<HeifCve>) {
    let findings = analyze_heif_file(path);
    if findings.is_empty() {
        return (ScanResultStatus::StatusOk, Vec::new());
    }

    let mut classes: Vec<HeifCve> = Vec::new();
    for finding in &findings {
        warn!("{}: {}", finding.cve.name(), finding.detail);
        if !classes.contains(&finding.cve) {
            classes.push(finding.cve);
        }
    }
    classes.sort_by_key(|c| severity(*c));

    (ScanResultStatus::StatusMalicious, classes)
}

/// Scan a HEIF/AVIF file for malicious mask, overlay and alpha constructions.
///
/// Returns the most severe defect class found; use [`scan_heif_file_all`] when a
/// file may carry several.
pub fn scan_heif_file(path: &Path) -> (ScanResultStatus, Option<HeifCve>) {
    let (status, classes) = scan_heif_file_all(path);
    (status, classes.first().copied())
}
