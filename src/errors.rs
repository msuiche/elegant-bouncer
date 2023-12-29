//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  errors.rs
//
// Abstract:
//  Definitions for errors
//
// Author:
//  Matt Suiche (msuiche) 22-Sep-2023
// 
// Changelog:
// 22-Sep-2023 (msuiche) - Initial implementation
//
use std::io;
use thiserror::Error;

use crate::webp::WebpError;
use crate::ttf::TtfError;
// use crate::huffman::HuffmanError;

#[derive(Debug, Error)]
pub enum ElegantError {
    #[error("lopdf error: {0}")]
    LopdfError(#[from] lopdf::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("WEBP error: {0}")]
    WebpError(WebpError),

    #[error("TTF error: {0}")]
    TtfError(TtfError),

    /*
    #[error("Huffman error: {0}")]
    HuffmanError(HuffmanError),
    */
}

#[derive(Debug, PartialEq)]
pub enum ScanResultStatus {
    StatusOk,
    // StatusSuspicious,
    StatusMalicious
}

pub type Result<T> = std::result::Result<T, ElegantError>;