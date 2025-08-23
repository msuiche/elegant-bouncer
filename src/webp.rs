//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  webp.rs
//
// Abstract:
//  BLASTDOOR
//
// Author:
//  Matt Suiche (msuiche) 22-Sep-2023
//
use log::{info, debug, error};
use std::path;

use crate::errors::*;

use std::fmt;
use std::fs::File;
use std::io::{self, Read};

use byteorder::ReadBytesExt;

use crate::huffman::HTree;

// Define the structure
#[repr(C)]
struct WebpHeader {
    riff_sig:   [u8; 4],
    file_size:  u32,
    webp_sig:   [u8; 4],
    vp8_sig:    [u8; 4],
    vp8l_ssig:  [u8; 1],
    data_size:  u32,

    byte_data:  Vec<u8>,
}

impl WebpHeader {
    fn from_reader<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut header = WebpHeader {
            riff_sig: [0; 4],
            file_size: 0,
            webp_sig: [0; 4],
            vp8_sig: [0; 4],
            vp8l_ssig: [0; 1],
            data_size: 0,
            byte_data: Vec::new()
        };

        // Read the fields one by one
        reader.read_exact(&mut header.riff_sig)?;
        header.file_size = reader.read_u32::<byteorder::LittleEndian>()?;
        reader.read_exact(&mut header.webp_sig)?;
        reader.read_exact(&mut header.vp8_sig)?;
        header.data_size = reader.read_u32::<byteorder::LittleEndian>()?;
        // reader.read_exact(&mut header.vp8l_ssig)?;

        header.byte_data.clear();
        header.byte_data.resize((header.data_size) as usize, 0);
        reader.read_exact(&mut header.byte_data)?;
        // debug!("first byte: 0x{:x}", header.byte_data[0]);

        Ok(header)
    }

    fn is_valid(&self) -> bool {
        &self.riff_sig == b"RIFF" && &self.webp_sig == b"WEBP" && &self.vp8_sig == b"VP8L" // && self.vp8l_ssig[0] == 0x2f
    }

    fn get_vp8l_data_size(&self) -> u32 {
        self.data_size
    }

    fn get_vp8l_data(&self) -> &Vec<u8> {
        &self.byte_data
    }
}

pub struct VP8LBitReader<'a> {
    pub data: &'a [u8],       // Reference to the underlying data.
    pub idx: usize,           // Index to the current byte.
    pub bit_offset: usize,    // Offset to the current bit within the current byte.
    pub bits: u32,            // For the lookup table stuff
}

impl<'a> VP8LBitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        VP8LBitReader {
            data,
            idx: 0,
            bit_offset: 0,
            bits: 0
        }
    }

    pub fn read_bit(&mut self) -> Option<u8> {
        if self.idx >= self.data.len() {
            return None;  // No more data to read.
        }

        let byte = self.data[self.idx];
        let bit = (byte >> self.bit_offset) & 1;
        
        self.bit_offset += 1;

        if self.bit_offset >= 8 {
            self.bit_offset = 0;
            self.idx += 1;
        }

        Some(bit)
    }

    pub fn read_bits(&mut self, num_bits: u8) -> Option<u32> {
        if num_bits > 32 {
            return None;  // Can't read more than 32 bits at once.
        }

        let mut value: u32 = 0;
        for n in 0..num_bits as usize {
            match self.read_bit() {
                Some(bit) => {
                    value |= (bit as u32) << n;
                },
                None => return None,
            }
        }

        // info!("read_bit({}) -> {:x}", num_bits, value);

        Some(value)
    }
}

const MAX_ALLOWED_CODE_LENGTH: u32 = 15;

pub const FIXED_TABLE_SIZE: u32 = 630 * 3 + 410;
pub const MAX_RBA_TABLE_SIZE: u32 = 630;
pub const MAX_DISTANCE_TABLE_SIZE: u32 = 410;

pub static K_TABLE_SIZE: [u32; 12] = [
    FIXED_TABLE_SIZE + 654,
    FIXED_TABLE_SIZE + 656,
    FIXED_TABLE_SIZE + 658,
    FIXED_TABLE_SIZE + 662,
    FIXED_TABLE_SIZE + 670,
    FIXED_TABLE_SIZE + 686,
    FIXED_TABLE_SIZE + 718,
    FIXED_TABLE_SIZE + 782,
    FIXED_TABLE_SIZE + 912,
    FIXED_TABLE_SIZE + 1168,
    FIXED_TABLE_SIZE + 1680,
    FIXED_TABLE_SIZE + 2704,
];

const NUM_LITERAL_CODES: u16 = 256;
const NUM_LENGTH_CODES: u16 = 24;
const NUM_DISTANCE_CODES: u16 = 40;

const HUFFMAN_CODES_PER_META_CODE: usize = 5;

const K_ALPHABET_SIZE: [u16; HUFFMAN_CODES_PER_META_CODE] = [
    NUM_LITERAL_CODES + NUM_LENGTH_CODES,
    NUM_LITERAL_CODES,
    NUM_LITERAL_CODES,
    NUM_LITERAL_CODES,
    NUM_DISTANCE_CODES
];

const NUM_CODE_LENGTH_CODES: usize = 19;
static K_CODE_LENGTH_CODE_ORDER: [usize; NUM_CODE_LENGTH_CODES] = [
    17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];

#[derive(Debug)]
pub enum WebpError {
    UnsupportedBehavior,
    InvalidFile,
    // UnexpectedEof
}

impl fmt::Display for WebpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebpError::UnsupportedBehavior => write!(f, "Unsupported behavior encountered"),
            // WebpError::UnexpectedEof => write!(f, "Unexpected end of file"),
            WebpError::InvalidFile => write!(f, "Not a valid file.")
        }
    }
}

/// Returns the table width of the next 2nd level table. count is the histogram
/// of bit lengths for the remaining symbols, len is the code length of the next
/// processed symbol
fn next_table_bit_size(count: &Vec<u32>, mut len: u32, root_bits: u32) -> u32 {
    let mut left = 1 << (len - root_bits);
    while len < MAX_ALLOWED_CODE_LENGTH {
        if count[len as usize] >= left {
            break;
        }
        left -= count[len as usize];
        len += 1;
        left <<= 1;
    }
    len - root_bits
}

/// Returns reverse(reverse(key, len) + 1, len), where reverse(key, len) is the
/// bit-wise reversal of the len least significant bits of key.
fn get_next_key(key: u32, len: u32) -> u32 {
    let mut step = 1 << (len - 1);
    while key & step != 0 {
        step >>= 1;
    }
    if step != 0 {
        (key & (step - 1)) + step
    } else {
        key
    }
}

pub fn is_code_lengths_count_valid(code_lengths_code: &Vec<u32>, max_table_size: u32) -> bool {
    let mut has_overflow = false;
    let mut step = 2;

    let mut key = 0;

    let root_bits = 8;
    let mut table_bits = root_bits;        // key length of current table
    let mut table_size = 1 << table_bits;  // size of current table
    let mut total_size = 1 << root_bits;
    let mut low = 0xffffffff;        // low bits for current root entry
    let mask = total_size - 1;    // mask for low bits

    let mut table_off = 0;

    let mut count = code_lengths_code.to_vec();

    // very likely set to zero but we need to read
    /*
    let color_cache_bits = 0;
    let max_table_size = K_TABLE_SIZE[color_cache_bits];
    info!("max_table_size = 0x{:x}", max_table_size);
    */

    let mut symbols = Vec::new();
    let mut keys = Vec::new();
    symbols.clear();
    symbols.resize(280, 0);

    let mut _num_nodes = 1;   // number of Huffman tree nodes
    let mut num_open = 1;    // number of open branches in current tree level
    // root table
    // This can be ignored because the overflow happens in the second.
    // We run this only to have the latest key.
    for len in 1..=root_bits {
        num_open <<= 1;
        _num_nodes += num_open;

        if count[len as usize] >= num_open {
            debug!("This should not happen. int underflow.");
            return false;
        }
        num_open -= count[len as usize];

        while count[len as usize] > 0 {
            symbols[key as usize] = len;
            keys.push(key);
            key = get_next_key(key, len);
            count[len as usize] -= 1;
        }
        step <<= 1;
    }

    step = 2;
    for len in (root_bits + 1)..=MAX_ALLOWED_CODE_LENGTH {
        num_open <<= 1;
        _num_nodes += num_open;

        if  count[len as usize] >= num_open {
            debug!("This should not happen. int underflow. (count =  {}, len = {})", count[len as usize], len);
            return false;
        }
        num_open -= count[len as usize];

        while count[len as usize] > 0 {

            // debug!("[{}] key = 0x{:x} mask = 0x{:x} low = 0x{:x}", if (key & mask) != low { "true" } else { "false"} , key, mask, low);
            if (key & mask) != low {
                // info!("key = 0x{:x} mask = 0x{:x} low = 0x{:x}", key, mask, low);
                table_off = total_size; // sizeof(HuffmanCode)
                table_bits = next_table_bit_size(&count, len, root_bits);
                table_size = 1 << table_bits;
                total_size += table_size;
                low = key & mask;
                // debug!("key = 0x{:4x} total_size = 0x{:x}, table_size = 0x{:x}", key, total_size, table_size);
            }

            // debug!("WRITE. base off = 0x{:x} OOF = 0x{:x}, key = 0x{:x}, total_size = 0x{:x} table_size = 0x{:x}, step = 0x{:x} // max = 0x{:x}",
            // table_off, (key >> root_bits) + (table_size - step), key, total_size, table_size, step, max_table_size);

            if table_off + (key >> root_bits) + (table_size - step) >= max_table_size {
                debug!("OVERFLOW!!!!!!! (offset = 0x{:x})", table_off + (key >> root_bits) + (table_size - step));
                has_overflow = true;
            }

            // info!("(second table) key = {}\n", key);
            if key < 280 {
                symbols[key as usize] = len;
                keys.push(key);
            }
            key = get_next_key(key, len);
            count[len as usize] -= 1;
        }

        step <<= 1;
    }

    has_overflow
}

fn decode_code_lengths(reader: &mut VP8LBitReader, dst: &mut Vec<u32>, code_length_code_lengths: &Vec<u32>) -> Result<()> {
    let mut tree = HTree::new();
    let _ = tree.build(code_length_code_lengths).unwrap();

    let mut prev_code_length = 8u32;
    let mut symbol = 0;
    let repeat_bits = [2, 3, 7];
    let repeat_offsets = [3, 3, 11];
    let repeats_code_length = 16; // Assuming this value from the context

    let mut max_symbol = dst.len();
    while symbol < dst.len() {
        if max_symbol == 0 {
            break;
        }
        max_symbol -= 1;
        
        let code_length = tree.next(reader).map_err(|err| err).unwrap();
        // println!("code_length: {} (symbol = {}, max_symbol = {})", code_length, symbol, max_symbol);
        if code_length < repeats_code_length {
            dst[symbol] = code_length;
            // println!("dst[{}] = {}", symbol, dst[symbol]);
            symbol += 1;
            if code_length != 0 {
                prev_code_length = code_length;
            }
            continue;
        }
        let repeat = reader.read_bits(repeat_bits[(code_length - repeats_code_length) as usize]).unwrap()
            + repeat_offsets[(code_length - repeats_code_length) as usize] as u32;
        
        if symbol + repeat as usize > dst.len() {
            // return Err("Invalid Code Lengths"); // Or use your custom error type
            error!("Invalid code len");
        }
        
        let mut cl = 0;
        if code_length == 16 {
            cl = prev_code_length;
        }

        // println!("repeat: dst[{}] = {} ({} times)", symbol, dst[symbol], repeat);
        for _ in 0..repeat {
            dst[symbol] = cl;
            symbol += 1;
        }
    }

    // println!("dst: {:?}", dst);

    Ok(())
}

fn get_code_lengths_count(code_lengths: &Vec<u32>) -> Vec<u32> {
    let max_symbol = code_lengths.len();
    let mut count = Vec::new();
    count.clear();
    count.resize((MAX_ALLOWED_CODE_LENGTH + 1) as usize, 0);

    for symbol in 0..max_symbol {
        if code_lengths[symbol] > max_symbol as u32 {
            println!("INVALID");
        }
        count[code_lengths[symbol as usize] as usize] += 1;
    }

    count
}

fn decode_huffman_tree(reader: &mut VP8LBitReader, alphabet_size: usize, max_table_size: u32) -> Result<ScanResultStatus> {

    // info!("alphabet_size -> {}", alphabet_size);

    let mut code_lengths: Vec<u8> = vec![0; alphabet_size];
    // ReadHuffmanCode
    let simple_code = reader.read_bit().unwrap() != 0;
    // info!("simple_code: {}", simple_code);
    if simple_code {
        let num_symbols = reader.read_bit().unwrap() + 1;
        let first_symbol_len_code = reader.read_bit().unwrap();
        // The first code is either 1 bit or 8 bit code.
        let mut symbol;
        if first_symbol_len_code == 0 {
            symbol = reader.read_bit().unwrap();
        } else {
            symbol = reader.read_bits(8).unwrap() as u8;
        }
        code_lengths[symbol as usize] = 1;
        // The second code (if present), is always 8 bits long.
        if num_symbols == 2 {
            symbol = reader.read_bits(8).unwrap() as u8;
            code_lengths[symbol as usize] = 1;
        }

        // TODO:
        return Err(ElegantError::WebpError(WebpError::UnsupportedBehavior));
    } else {  // Decode Huffman-coded code lengths.
        let mut code_length_code_lengths: [u32; NUM_CODE_LENGTH_CODES] = [0; NUM_CODE_LENGTH_CODES];
        let mut count: [u32; (MAX_ALLOWED_CODE_LENGTH + 1) as usize] = [0; (MAX_ALLOWED_CODE_LENGTH + 1) as usize];
        let num_codes = reader.read_bits(4).unwrap() + 4; // lencode_read
        // println!("num_codes = {}", num_codes);
        // assert(num_codes <= NUM_CODE_LENGTH_CODES);
    
        for i in 0..num_codes {
            code_length_code_lengths[K_CODE_LENGTH_CODE_ORDER[i as usize]] = reader.read_bits(3).unwrap() as u32;
        }

        for symbol in 0..NUM_CODE_LENGTH_CODES {
            if code_length_code_lengths[symbol] > MAX_ALLOWED_CODE_LENGTH {
                println!("INVALID");
            }
            count[code_length_code_lengths[symbol as usize] as usize] += 1;
        }

        // println!("count: {:?}", count);

        // Next, if ReadBits(1) == 0, the maximum number of different read symbols is num_code_lengths.
        let use_length = reader.read_bit().unwrap();
        let max_symbol;
        if use_length != 0 {
            let length_nbits = 2 + 2 * reader.read_bits(3).unwrap();
            max_symbol = 2 + reader.read_bits(length_nbits as u8).unwrap();
        } else {
            max_symbol = alphabet_size as u32; 
        }

        let mut code_lengths: Vec<u32> = vec![0; max_symbol as usize];
        let _ = decode_code_lengths(reader, &mut code_lengths, &code_length_code_lengths.to_vec());
        let count = get_code_lengths_count(&code_lengths);
        debug!("count: {:?}", count);

        let blastpass = is_code_lengths_count_valid(&count, max_table_size);
        if blastpass {
            debug!("[_] = {}", blastpass);
            return Ok(ScanResultStatus::StatusMalicious);
        }
        /*
        let mut tree = HTree::new();
        let _ = tree.build(&code_lengths).unwrap();
        */
    }

    Ok(ScanResultStatus::StatusOk)
}

pub fn scan_webp_vp8l_file(path: &path::Path) -> Result<ScanResultStatus> {
    // info!("Opening {}...", path.display());

    let mut status = ScanResultStatus::StatusOk;

    let file = File::open(path)?;
    let header = WebpHeader::from_reader(file)?;

    if !header.is_valid() {
        // error!("Not a WebP file. Ignore");
        return Err(ElegantError::WebpError(WebpError::InvalidFile));
    }

    debug!("get_vp8l_data_size() -> 0x{:x}", header.get_vp8l_data_size());

    let mut reader = VP8LBitReader::new(&header.get_vp8l_data());

    // read header
    let _sig = reader.read_bits(8).unwrap();
    // info!("sig = 0x{:x}", sig);
    let _width = reader.read_bits(14).unwrap() + 1;
    // info!("width = 0x{:x}", width);
    let _height = reader.read_bits(14).unwrap() + 1;
    // info!("height = 0x{:x}", height);
    let _alpha_is_used = reader.read_bits(1).unwrap();
    // info!("alpha = 0x{:x}", alpha_is_used);
    let _version_number = reader.read_bits(3).unwrap();
    // info!("version = 0x{:x}", version_number);

    // DecodeImageStream()
    // ReadTransform
    if reader.read_bit().unwrap() != 0 {
        error!("No support for ReadTransform()");
        return Err(ElegantError::WebpError(WebpError::UnsupportedBehavior));
    }

    // Color Cache
    let mut color_cache_bits = 0;
    if reader.read_bit().unwrap() != 0 {
        color_cache_bits = reader.read_bits(4).unwrap();
        // info!("color_cache_bits = 0x{:x}", color_cache_bits);
    }

    let num_htree_groups_max = 1;
    let use_meta = reader.read_bit().unwrap() != 0; 
    if use_meta {
        error!("Meta code unimplemented.");
        return Err(ElegantError::WebpError(WebpError::UnsupportedBehavior));
    }

    // ReadHuffmanCodes()
    for _i in 0..num_htree_groups_max {
        for j in 0..HUFFMAN_CODES_PER_META_CODE {
            let mut alphabet_size = K_ALPHABET_SIZE[j];
            if j == 0 && color_cache_bits > 0 {
                alphabet_size += 1 << color_cache_bits;
            }

            let max_table_size = match j {
                0 => K_TABLE_SIZE[color_cache_bits as usize] - FIXED_TABLE_SIZE,
                1 | 2 | 3 => MAX_RBA_TABLE_SIZE,
                4 => MAX_DISTANCE_TABLE_SIZE,
                _ => panic!("Unhandled idx value: {}", j),
            };

            // println!("decodeHuffmanTree({}, {})", j, 0);
            status = decode_huffman_tree(&mut reader, alphabet_size as usize, max_table_size)?;
            if status == ScanResultStatus::StatusMalicious {
                break;
            }
        }
    }

    Ok(status)
}