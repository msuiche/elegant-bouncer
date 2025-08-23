//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  huffman.rs
//
// Abstract:
//  Huffman
//
// Author:
//  Matt Suiche (msuiche) 22-Sep-2023
// 
// Changelog:
// 22-Sep-2023 (msuiche) - Initial implementation
//
use std::fmt;
use log::{error, warn, debug, trace};

use crate::webp::VP8LBitReader;

const LEAF_NODE: i32 = -1;
const LUT_SIZE: usize = 7;
const LUT_MASK: usize = (1 << 7) - 1;

#[derive(Debug)]
pub enum HuffmanError {
    InvalidHuffmanTree,
    // UnexpectedEof
}

impl fmt::Display for HuffmanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HuffmanError::InvalidHuffmanTree => write!(f, "Invalid Huffman Tree"),
            // HuffmanError::UnexpectedEof => write!(f, "Unexpected end of file")
        }
    }
}

#[derive(Debug, Clone)]
struct HNode {
    symbol: u32,
    children: i32,
}

#[derive(Debug)]
pub struct HTree {
    nodes: Vec<HNode>,
    lut: [u32; 1 << LUT_SIZE],
}

impl HTree {
    pub fn new() -> Self {
        Self {
            nodes: Vec::with_capacity(1),
            lut: [0; 1 << LUT_SIZE],
        }
    }

    pub fn build(&mut self, code_lengths: &Vec<u32>) -> Result<(), HuffmanError> {
        let mut n_symbols = 0;
        let mut last_symbol = 0;

        for (symbol, &cl) in code_lengths.iter().enumerate() {
            if cl != 0 {
                n_symbols += 1;
                last_symbol = symbol;
            }
        }

        if n_symbols == 0 {
            error!("symbols is zero.");
            return Err(HuffmanError::InvalidHuffmanTree);
        }

        self.nodes = Vec::with_capacity(2 * n_symbols - 1);
        // info!("len(self.nodes) = {} // n_symbols = {}", self.nodes.len(), n_symbols);
        // Create an empty first entry.
        self.nodes.push(HNode {
            symbol: 0,
            children: 0,
        });

        if n_symbols == 1 {
            if code_lengths.len() <= last_symbol {
                error!("code_lengths.len() <= last_symbol");
                return Err(HuffmanError::InvalidHuffmanTree);
            }
            return self.insert(last_symbol as u32, 0, 0);
        }

        let codes = code_lengths_to_codes(&code_lengths)?;
        debug!("code_lengths: {:?}", code_lengths);
        debug!("codes: {:?}", codes);

        for (symbol, &cl) in code_lengths.iter().enumerate() {
            // info!("symbol = {} cl = {}", symbol, cl);
            if cl > 0 {
                // info!("insert({}, {})", symbol, cl);
                // info!("cl = {}, symbol = {}, codes[symbol] = {}", cl, symbol, codes[symbol]);
                self.insert(symbol as u32, codes[symbol], cl)?;
            }
        }

        Ok(())
    }

    fn insert(&mut self, symbol: u32, code: u32, mut code_length: u32) -> Result<(), HuffmanError> {
        // info!("insert() symbol = {} and code_length = {}", symbol, code_length);
        if symbol > 0xffff || code_length > 0xfe {
            error!("symbol id too high.");
            return Err(HuffmanError::InvalidHuffmanTree);
        }
        let base_code: u32;
        if code_length > LUT_SIZE as u32 {
            base_code = (REVERSE_BITS[((code >> (code_length - LUT_SIZE as u32)) & 0xff) as usize] as u32) >> (8 - LUT_SIZE);
        } else {
            base_code = (REVERSE_BITS[(code & 0xff) as usize] as u32) >> (8 - code_length);
            for i in 0..1 << (LUT_SIZE - code_length as usize) {
                self.lut[base_code as usize | ((i as u32) << code_length) as usize] = symbol << 8 | (code_length + 1);
            }
        }
        let mut n = 0;
        let mut jump = LUT_SIZE;
        // info!("start code_length loop");
        while code_length > 0 {
            // info!("start code_length loop. (codeLen = {}, n = {})", code_length, n);
            code_length -= 1;
            if n as usize > self.nodes.len() {
                error!("n too high.");
                return Err(HuffmanError::InvalidHuffmanTree);
            }
            match self.nodes[n].children {
                LEAF_NODE => {
                    error!("unexpected leaf node");
                    return Err(HuffmanError::InvalidHuffmanTree)
                },
                0 => {
                    if n >= self.nodes.len() {
                        error!("too many nodes");
                        return Err(HuffmanError::InvalidHuffmanTree);
                    }
                    self.nodes[n].children = self.nodes.len() as i32;
                    self.nodes.push(HNode { symbol: 0, children: 0 });
                    self.nodes.push(HNode { symbol: 0, children: 0 });
                }
                _ => {}
            }
            // info!("nodes[{}].children ({}) + 1 & ({} >> {})",
            //    n, self.nodes[n].children, code, code_length);
            // info!("self.nodes[n].children = {}", self.nodes[n].children);
            // info!("1 & (code >> code_length) = {}", 1 & (code >> code_length));
            // info!("(code >> code_length) = {}", (code >> code_length));
            let v = self.nodes[n].children as u32 + (1 & (code >> code_length));
            n = v as usize;
            // info!("set n to {} / 1 & (code >> code_length) = {}", n, 1 & (code >> code_length));
            jump -= 1;
            if jump == 1 && self.lut[base_code as usize] == 0 {
                self.lut[base_code as usize] = (n << 8) as u32;
            }
        }

        // info!("Leaf? nodes[{}].children = {}", n, self.nodes[n as usize].children);
        match self.nodes[n as usize].children {
            LEAF_NODE => {}
            0 => self.nodes[n as usize].children = LEAF_NODE,
            e => {
                error!("null type? for n = {} children = {}", n, e);
                return Err(HuffmanError::InvalidHuffmanTree)
            },
        }

        self.nodes[n as usize].symbol = symbol;
        Ok(())
    }

    pub fn next(&self, d: &mut VP8LBitReader) -> Result<u32, HuffmanError> {
        // Read enough bits so that we can use the look-up table.

        let bits = d.read_bits(LUT_SIZE as u8).unwrap();
        // println!("bits = {}", bits);
        // println!("index = {}", bits as usize & LUT_MASK);
        // Use the look-up table.
        let mut n = self.lut[bits as usize & LUT_MASK];
        let mut b = (n & 0xff) as usize;
        // println!("n = {} b = {}", n, b);
        if b != 0 {
            if b > LUT_SIZE {
                trace!("The tree is unbalanced. This is suspicious. (b = {})", b);
                return Ok(n >> 8);
            }
            assert!(b <= LUT_SIZE);
            // println!("(before) b = {} / d.bit_offset = {}", b, d.bit_offset);
            b -= 1;
            if (LUT_SIZE - b) > d.bit_offset {
                d.bit_offset = (8 + d.bit_offset % 8) - (LUT_SIZE - b);
                d.idx -= 1;
            } else {
                d.bit_offset -= LUT_SIZE - b;
            }
            return Ok(n >> 8);
        }
        n >>= 8;
        if LUT_SIZE > d.bit_offset {
            d.bit_offset = (8 + d.bit_offset % 8) - LUT_SIZE;
            d.idx -= 1;
        } else {
            d.bit_offset -= LUT_SIZE;
        }
        self.slow_path(n, d)
    }

    fn slow_path(&self, n: u32, _d: &mut VP8LBitReader) -> Result<u32, HuffmanError> {
        assert!(self.nodes[n as usize].children == LEAF_NODE);
        Ok(self.nodes[n as usize].symbol)
    }
}

// reverse_bits reverses the bits in a byte.
const REVERSE_BITS: [u8; 256] = [
    0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
    0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
    0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
    0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
    0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, 0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
    0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
    0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
    0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
    0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
    0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
    0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
    0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
    0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
    0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
    0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
    0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
];

fn code_lengths_to_codes(code_lengths: &Vec<u32>) -> Result<Vec<u32>, HuffmanError> {
    let max_code_length = code_lengths.iter().max().unwrap_or(&0);
    const MAX_ALLOWED_CODE_LENGTH: u32 = 15;
    if code_lengths.is_empty() || max_code_length > &MAX_ALLOWED_CODE_LENGTH {
        error!("max code len is too high.");
        return Err(HuffmanError::InvalidHuffmanTree);
    }
    let mut histogram = [0; (MAX_ALLOWED_CODE_LENGTH + 1) as usize];
    for &cl in code_lengths {
        histogram[cl as usize] += 1;
    }
    let mut curr_code = 0;
    let mut next_codes = [0; (MAX_ALLOWED_CODE_LENGTH + 1) as usize];
    for cl in 1..=MAX_ALLOWED_CODE_LENGTH {
        curr_code = (curr_code + histogram[(cl - 1) as usize]) << 1;
        next_codes[cl as usize] = curr_code;
    }
    let mut codes = vec![0; code_lengths.len()];
    for (symbol, &cl) in code_lengths.iter().enumerate() {
        if cl > 0 {
            codes[symbol] = next_codes[cl as usize];
            next_codes[cl as usize] += 1;
        }
    }
    Ok(codes)
}


