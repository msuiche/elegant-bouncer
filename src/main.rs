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
mod ttf;
mod dng;
mod errors;
mod huffman;

use std::path::{Path, PathBuf};
use colored::*;
use walkdir::WalkDir;

use env_logger;
use log::LevelFilter;
use clap::Parser;

use crate::jbig2 as FORCEDENTRY;
use crate::webp as BLASTPASS;
use crate::ttf as TRIANGULATION;

use crate::errors::*;

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
#[clap(about, long_about = "A utility designed to detect the presence of known mobile APTs in commonly distributed files.", author="Copyright (c) 2022-2023, Matt Suiche (@msuiche)", version = CRATE_VERSION)]
struct Args {
    /// Print extra output while parsing
    #[clap(short, long)]
    verbose: bool,

    /// Assess a given file or folder, checking for known vulnerabilities.
    #[clap(short, long)]
    scan: bool,

    /// Create a FORCEDENTRY-like PDF.
    #[clap(short, long)]
    create_forcedentry: bool,

    /// Recursively scan subfolders
    #[clap(short, long)]
    recursive: bool,

    /// File extensions to scan (comma-separated, e.g., "pdf,webp,ttf")
    /// Default: pdf,gif,webp,jpg,jpeg,png,tif,tiff,dng,ttf,otf
    #[clap(short, long, value_delimiter = ',')]
    extensions: Option<Vec<String>>,

    /// Path to the input file or folder.
    #[clap(value_name = "Input path")]
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

fn get_default_extensions() -> Vec<String> {
    vec![
        "pdf".to_string(),
        "gif".to_string(),
        "webp".to_string(),
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "tif".to_string(),
        "tiff".to_string(),
        "dng".to_string(),
        "ttf".to_string(),
        "otf".to_string(),
    ]
}

fn should_scan_file(path: &Path, extensions: &[String]) -> bool {
    if let Some(ext) = path.extension() {
        if let Some(ext_str) = ext.to_str() {
            return extensions.iter().any(|e| e.eq_ignore_ascii_case(ext_str));
        }
    }
    false
}

#[derive(Clone)]
struct ScanResult {
    file_path: PathBuf,
    forcedentry: bool,
    blastpass: bool,
    triangulation: bool,
    cve_2025_43300: bool,
}

fn scan_single_file(path: &Path) -> ScanResult {
    let mut result = ScanResult {
        file_path: path.to_path_buf(),
        forcedentry: false,
        blastpass: false,
        triangulation: false,
        cve_2025_43300: false,
    };

    // FORCEDENTRY scan
    match FORCEDENTRY::scan_pdf_jbig2_file(path) {
        Ok(status) => {
            if status == ScanResultStatus::StatusMalicious {
                result.forcedentry = true;
            }
        },
        Err(_) => {}
    }

    // BLASTPASS scan
    match BLASTPASS::scan_webp_vp8l_file(path) {
        Ok(status) => {
            if status == ScanResultStatus::StatusMalicious {
                result.blastpass = true;
            }
        },
        Err(_) => {}
    }

    // TRIANGULATION scan
    match TRIANGULATION::scan_ttf_file(path) {
        Ok(status) => {
            if status == ScanResultStatus::StatusMalicious {
                result.triangulation = true;
            }
        },
        Err(_) => {}
    }

    // CVE-2025-43300 scan
    let dng_status = dng::scan_dng_file(path);
    if dng_status == ScanResultStatus::StatusMalicious {
        result.cve_2025_43300 = true;
    }

    result
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
    println!("{} v{} - Detection tool for file-based mobile exploits.", "ELEGANTBOUNCER".green(), CRATE_VERSION);
    println!("> https://github.com/msuiche/elegant-bouncer");
    println!("Copyright (c) 2022-2023, Matt Suiche (@msuiche)");
    println!("> https://www.msuiche.com");
    println!();

    let args = Args::parse();

    let level = if args.verbose {
        LevelFilter::max()
    } else {
        LevelFilter::Info
    };

    env_logger::Builder::new().filter_level(level).init();

    if !args.scan && !args.create_forcedentry {
        println!("You need to supply an action. Run with {} for more information.", "--help".green());
        return Ok(());
    }

    let path = Path::new(&args.path);

    if args.create_forcedentry {
        return FORCEDENTRY::create(path);
    }

    // Handle scanning
    if args.scan {
        let extensions = args.extensions.unwrap_or_else(get_default_extensions);
        let mut all_scan_results = Vec::new();

        if path.is_file() {
            // Single file scan
            println!("[+] Scanning file: {}", path.display());
            let result = scan_single_file(path);
            all_scan_results.push(result);
            
            // Display file info
            println!();
            let _ = print_hashes(&args.path);
        } else if path.is_dir() {
            // Directory scan
            let mut file_count = 0;
            println!("[+] Scanning directory: {}", path.display());
            if args.recursive {
                println!("[+] Recursive mode enabled");
            }
            println!("[+] Extensions: {}", extensions.join(", "));
            println!();

            let walker = if args.recursive {
                WalkDir::new(path)
            } else {
                WalkDir::new(path).max_depth(1)
            };

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let file_path = entry.path();
                    if should_scan_file(file_path, &extensions) {
                        file_count += 1;
                        println!("[{}] Scanning: {}", file_count, file_path.display());
                        let result = scan_single_file(file_path);
                        
                        // Report if any threats found
                        if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
                            print!("  └─ {} found: ", "THREAT".red());
                            let mut threats = Vec::new();
                            if result.forcedentry { threats.push("FORCEDENTRY"); }
                            if result.blastpass { threats.push("BLASTPASS"); }
                            if result.triangulation { threats.push("TRIANGULATION"); }
                            if result.cve_2025_43300 { threats.push("CVE-2025-43300"); }
                            println!("{}", threats.join(", ").red());
                        }
                        
                        all_scan_results.push(result);
                    }
                }
            }
            
            if file_count == 0 {
                println!("No files found with specified extensions.");
                return Ok(());
            }
            
            println!();
            println!("[+] Scanned {} files", file_count);
        } else {
            eprintln!("Error: Path '{}' does not exist or is not accessible", path.display());
            return Ok(());
        }

        // Aggregate results
        let mut forcedentry_detected = false;
        let mut blastpass_detected = false;
        let mut triangulation_detected = false;
        let mut cve_2025_43300_detected = false;
        let mut infected_files = Vec::new();

        for result in &all_scan_results {
            if result.forcedentry {
                forcedentry_detected = true;
                infected_files.push(result.file_path.clone());
            }
            if result.blastpass {
                blastpass_detected = true;
                infected_files.push(result.file_path.clone());
            }
            if result.triangulation {
                triangulation_detected = true;
                infected_files.push(result.file_path.clone());
            }
            if result.cve_2025_43300 {
                cve_2025_43300_detected = true;
                infected_files.push(result.file_path.clone());
            }
        }

        // Display summary results
        println!();
        println!("[+] Summary Results:");
        let results = vec![
            Results {
                name: "FORCEDENTRY",
                cve_ids: "CVE-2021-30860",
                description: "Malicious JBIG2 PDF shared over iMessage",
                detected: forcedentry_detected,
            },
            Results {
                name: "BLASTDOOR",
                cve_ids: "CVE-2023-4863, CVE-2023-41064",
                description: "Malicious WebP presumably shared over iMessage and other mediums",
                detected: blastpass_detected,
            },
            Results {
                name: "TRIANGULATION",
                cve_ids: "CVE-2023-41990",
                description: "Maliciously crafted TrueType font embedded in PDFs shared over iMessage",
                detected: triangulation_detected,
            },
            Results {
                name: "CVE-2025-43300",
                cve_ids: "CVE-2025-43300",
                description: "Malicious DNG with JPEG Lossless compression exploiting RawCamera.bundle",
                detected: cve_2025_43300_detected,
            },
        ];

        let table = Table::new(results).with(Style::rounded()).to_string();
        println!("{}", table);

        // Show detailed infected files table if any threats found
        if !all_scan_results.iter().any(|r| r.forcedentry || r.blastpass || r.triangulation || r.cve_2025_43300) {
            // No threats found
        } else {
            // Build detailed infected files list
            #[derive(Tabled)]
            struct InfectedFile {
                path: String,
                threat_name: String,
                cve_ids: String,
            }
            
            let mut infected_details = Vec::new();
            
            for result in &all_scan_results {
                let path_str = result.file_path.display().to_string();
                
                if result.forcedentry {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        threat_name: "FORCEDENTRY".to_string(),
                        cve_ids: "CVE-2021-30860".to_string(),
                    });
                }
                
                if result.blastpass {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        threat_name: "BLASTPASS".to_string(),
                        cve_ids: "CVE-2023-4863, CVE-2023-41064".to_string(),
                    });
                }
                
                if result.triangulation {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        threat_name: "TRIANGULATION".to_string(),
                        cve_ids: "CVE-2023-41990".to_string(),
                    });
                }
                
                if result.cve_2025_43300 {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        threat_name: "CVE-2025-43300".to_string(),
                        cve_ids: "CVE-2025-43300".to_string(),
                    });
                }
            }
            
            if !infected_details.is_empty() {
                println!();
                println!("{} Infected Files Details:", "[!]".red());
                let infected_table = Table::new(infected_details).with(Style::rounded()).to_string();
                println!("{}", infected_table);
            }
        }
    }

    Ok(())
}
