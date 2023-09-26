//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  main.rs
//
// Abstract:
//  Detection Tool for file-based mobile exploits.
//
// Author:
//  Matt Suiche (msuiche) 20-Nov-2022
// 
// Changelog:
// 22-Sep-2023 (msuiche) - Add support for WEBP VP8L
// 20-Nov-2022 (msuiche) - Initial release with JBIG2 support
//

mod jbig2;
mod webp;
mod errors;
mod huffman;

use std::path;
use colored::*;

use env_logger;
use log::{LevelFilter};
use clap::Parser;

use crate::jbig2 as FORCEDENTRY;
use crate::webp as BLASTPASS;

use crate::errors::*;

use log::{info, debug};

use tabled::{Tabled, Table, settings::{Style}};

use std::{
    fs::File,
    io::{self, Read},
};
use md5;
use sha1::{Sha1, Digest};
use sha3::Sha3_256;

/*
const CRATE_VERSION: &'static str =
    concat!(env!("VERGEN_GIT_SEMVER"),
     " (", env!("VERGEN_GIT_COMMIT_TIMESTAMP"), ")");
*/
const CRATE_VERSION: &'static str = "0.2";

#[derive(Parser)]
#[clap(about, long_about = "A utility designed to detect the presence of known mobile APTs in commonly distributed files.", author="Copyright (c) 2022, All rights reserved.", version = CRATE_VERSION)]
struct Args {
    /// Print extra output while parsing
    #[clap(short, long)]
    verbose: bool,

    /// Assess a given file, checking for known vulnerabilities.
    #[clap(short, long)]
    scan: bool,

    /// Create a FORCEDENTRY-like PDF.
    #[clap(short, long)]
    create_forcedentry: bool,

    /// Path to the input file.
    #[clap(value_name = "Input file")]
    path: String,
}

#[derive(Tabled)]
struct Results {
    name: &'static str,
    cve_ids: &'static str,
    description: &'static str,
    #[tabled(display_with = "display_bool")]
    detected: bool
}

#[derive(Tabled)]
struct KeyValue {
    name: &'static str,
    value: String,
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

fn display_bool(o: &bool) -> String {
    match o {
        true => format!("{}", "Yes".red()),
        false => format!("{}", "No".green()),
    }
}

fn print_hashes(filename: &str) -> io::Result<()> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut values = Vec::new();

    let md5_result = md5::compute(&buffer);
    values.push(KeyValue {name: "MD5", value: format!("{:?}", md5_result)});
    // println!("MD5: {:?}", md5_result);

    let mut hasher = Sha1::new();
    hasher.update(&buffer);
    let sha1_result = hex::encode(hasher.finalize());
    values.push(KeyValue {name: "SHA1", value: sha1_result});
    // println!("SHA1: {:?}", sha1_result);

    let mut hasher = Sha3_256::new();
    hasher.update(&buffer);
    let sha3_result = hex::encode(hasher.finalize());
    values.push(KeyValue {name: "SHA3", value: sha3_result});
    // println!("SHA3: {:?}", sha3_result);

    println!("[+] File Information:");
    let table = Table::new(values).with(Style::rounded()).to_string();
    println!("{}", table);

    Ok(())
}

fn main() -> Result<()> {
    println!("{} v{}", "elegant-bouncer".bold(), CRATE_VERSION);
    println!("{} Detection Tool", "ELEGANTBOUNCER".green());
    println!("Detection tool for file-based mobile exploits.");
    // println!("Supported CVEs: CVE-2021-30860, CVE-2023-4863, CVE-2023-41064");
    println!("");

    let args = Args::parse();

    let level;
    if args.verbose {
        level = LevelFilter::max();
    } else {
        level = LevelFilter::Info;
    }

    env_logger::Builder::new().filter_level(level).init();

    let mut results = Vec::new();

    if !args.scan && !args.create_forcedentry {
        println!("You need to supply an action. Run with {} for more information.", "--help".green());
        return Ok(());
    }

    let path = path::Path::new(&args.path);

    if args.scan {
        let mut forcedentry_detected = false;
        match FORCEDENTRY::scan_pdf_jbig2_file(&path) {
            Ok(status) => {
                info!("PDF JBIG2 file successfully analyzed.");
                if status == ScanResultStatus::StatusMalicious {
                    forcedentry_detected = true;
                }
            },
            Err(_e) => {
                // Handle error
                debug!("JBIG2 analysis failed. Probably not a PDF.");
            }
        }
        results.push(Results {name: "FORCEDENTRY", cve_ids: "CVE-2021-30860", description: "Malicious JBIG2 PDF shared over iMessage", detected: forcedentry_detected});

        let mut blastpass_detected = false;
        match BLASTPASS::scan_webp_vp8l_file(&path) {
            Ok(status) => {
                info!("Webp VP8L file successfully analyzed.");
                if status == ScanResultStatus::StatusMalicious {
                    blastpass_detected = true;
                }
            },
            Err(_e) => {
                // Handle error
                // eprintln!("Analysis failed with error: {}", e);
            }
        }
        results.push(Results {
            name: "BLASTDOOR", 
            cve_ids: "CVE-2023-4863, CVE-2023-41064", 
            description: "Malicious WebP presumably shared over iMessage and other mediums", 
            detected: blastpass_detected});

    } else if args.create_forcedentry {
        FORCEDENTRY::create(&path)?;
    }

    // Display
    println!("");
    let _ = print_hashes(&args.path);

    println!("");
    println!("[+] Results:");
    let table = Table::new(results).with(Style::rounded()).to_string();
    println!("{}", table);
    Ok(())
}
