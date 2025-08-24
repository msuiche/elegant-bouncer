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
mod tui;
mod messaging;

use std::path::{Path, PathBuf};
use colored::*;
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Instant;

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

    /// Use Terminal User Interface for scanning
    #[clap(long)]
    tui: bool,

    /// Scan messaging app databases for attachments (iOS backup format)
    #[clap(short = 'm', long)]
    messaging: bool,

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
pub struct ScanResult {
    pub file_path: PathBuf,
    pub forcedentry: bool,
    pub blastpass: bool,
    pub triangulation: bool,
    pub cve_2025_43300: bool,
}

fn get_file_type(path: &Path) -> Option<String> {
    // Get extension and convert to lowercase
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase())
}

fn should_scan_for_threat(file_type: &str, threat_type: &str) -> bool {
    match threat_type {
        "forcedentry" => {
            // FORCEDENTRY is in PDFs with JBIG2
            matches!(file_type, "pdf" | "gif")
        }
        "blastpass" => {
            // BLASTPASS is in WebP files
            matches!(file_type, "webp" )
        }
        "triangulation" => {
            // TRIANGULATION is in TrueType fonts
            // PDFs can embed fonts but we don't parse fonts from PDFs atm.
            matches!(file_type, "ttf" | "otf" )
        }
        "cve_2025_43300" => {
            // CVE-2025-43300 is in DNG files
            matches!(file_type, "dng" | "tif" | "tiff")
        }
        _ => true
    }
}

pub fn scan_single_file(path: &Path) -> ScanResult {
    let mut result = ScanResult {
        file_path: path.to_path_buf(),
        forcedentry: false,
        blastpass: false,
        triangulation: false,
        cve_2025_43300: false,
    };

    // Determine file type once
    let file_type = get_file_type(path).unwrap_or_else(|| "unknown".to_string());

    // Only run relevant scanners based on file type
    
    // FORCEDENTRY scan - only for PDFs and GIFs
    if should_scan_for_threat(&file_type, "forcedentry") {
        match FORCEDENTRY::scan_pdf_jbig2_file(path) {
            Ok(status) => {
                if status == ScanResultStatus::StatusMalicious {
                    result.forcedentry = true;
                }
            },
            Err(_) => {}
        }
    }

    // BLASTPASS scan - only for image files
    if should_scan_for_threat(&file_type, "blastpass") {
        match BLASTPASS::scan_webp_vp8l_file(path) {
            Ok(status) => {
                if status == ScanResultStatus::StatusMalicious {
                    result.blastpass = true;
                }
            },
            Err(_) => {}
        }
    }

    // TRIANGULATION scan - only for font files and PDFs
    if should_scan_for_threat(&file_type, "triangulation") {
        match TRIANGULATION::scan_ttf_file(path) {
            Ok(status) => {
                if status == ScanResultStatus::StatusMalicious {
                    result.triangulation = true;
                }
            },
            Err(_) => {}
        }
    }

    // CVE-2025-43300 scan - only for DNG/TIFF files
    if should_scan_for_threat(&file_type, "cve_2025_43300") {
        let dng_status = dng::scan_dng_file(path);
        if dng_status == ScanResultStatus::StatusMalicious {
            result.cve_2025_43300 = true;
        }
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
    let args = Args::parse();
    
    // Print clean header only if not in TUI mode
    if !args.tui {
        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("                    {} v{}", "ELEGANTBOUNCER".green().bold(), CRATE_VERSION.cyan().bold());
        println!("          Detection Tool for File-Based Mobile Exploits");
        println!();
        println!("  {}: {} • {} • {} • {}", 
            "Threats".yellow().bold(),
            "FORCEDENTRY".bright_red(),
            "BLASTPASS".bright_red(),
            "TRIANGULATION".bright_red(),
            "CVE-2025-43300".bright_red()
        );
        println!();
        println!("  {} Matt Suiche (@msuiche)", "Author:".bright_blue());
        println!("  {} https://github.com/msuiche/elegant-bouncer", "GitHub:".bright_blue());
        println!("  {} https://www.msuiche.com", "Website:".bright_blue());
        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
    }

    // Don't initialize logger if in TUI mode to prevent output corruption
    if !args.tui {
        let level = if args.verbose {
            LevelFilter::max()
        } else {
            LevelFilter::Info
        };

        env_logger::Builder::new().filter_level(level).init();
    }

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

        // Check for messaging app scan mode
        if args.messaging {
            println!();
            println!("{} iOS Messaging App Attachment Scan", "►".cyan().bold());
            println!();
            println!("This mode scans iOS backup directories for messaging app databases");
            println!("and analyzes all attachments for known mobile exploits.");
            println!();
            
            let messaging_results = messaging::scan_messaging_apps(path);
            
            if !messaging_results.is_empty() {
                println!();
                println!("{} Found {} infected attachments in messaging apps", 
                    "⚠".red().bold(), 
                    messaging_results.len());
                
                // Convert messaging results to scan results
                for msg_result in messaging_results {
                    // Display infected file with origin first
                    println!("  {} {} ({})", 
                        "✗".red().bold(),
                        msg_result.file_path.display(),
                        msg_result.origin.yellow()
                    );
                    
                    all_scan_results.push(ScanResult {
                        file_path: msg_result.file_path,
                        forcedentry: msg_result.forcedentry,
                        blastpass: msg_result.blastpass,
                        triangulation: msg_result.triangulation,
                        cve_2025_43300: msg_result.cve_2025_43300,
                    });
                }
            } else {
                println!("{} No infected attachments found in messaging apps", "✓".green().bold());
                return Ok(());
            }
        // Use TUI mode if requested
        } else if args.tui {
            // Collect files to scan
            let mut files_to_scan = Vec::new();
            
            if path.is_file() {
                files_to_scan.push(path.to_path_buf());
            } else if path.is_dir() {
                let walker = if args.recursive {
                    WalkDir::new(path)
                } else {
                    WalkDir::new(path).max_depth(1)
                };

                files_to_scan = walker
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .filter(|e| should_scan_file(e.path(), &extensions))
                    .map(|e| e.path().to_path_buf())
                    .collect();
            }

            if files_to_scan.is_empty() {
                println!("No files found to scan.");
                return Ok(());
            }

            // Run TUI scan
            match tui::run_tui_scan(files_to_scan) {
                Ok(results) => {
                    all_scan_results = results;
                    // Exit after TUI completes - the TUI already shows results
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("TUI error: {}", e);
                    return Ok(());
                }
            }
        } else if path.is_file() {
            // Single file scan
            println!("[+] Scanning file: {}", path.display());
            let result = scan_single_file(path);
            all_scan_results.push(result);
            
            // Display file info
            println!();
            let _ = print_hashes(&args.path);
        } else if path.is_dir() {
            // Directory scan with progress bar
            println!("{} Scanning directory: {}", "►".cyan().bold(), path.display().to_string().bright_white());
            if args.recursive {
                println!("{} Recursive mode: {}", "►".cyan().bold(), "ENABLED".green());
            }
            println!("{} Extensions: {}", "►".cyan().bold(), extensions.join(", ").yellow());
            println!();

            // First, collect all files to scan
            let walker = if args.recursive {
                WalkDir::new(path)
            } else {
                WalkDir::new(path).max_depth(1)
            };

            let files_to_scan: Vec<_> = walker
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter(|e| should_scan_file(e.path(), &extensions))
                .collect();

            if files_to_scan.is_empty() {
                println!("{} No files found with specified extensions.", "⚠".yellow());
                return Ok(());
            }

            // Create progress bar
            let pb = Arc::new(ProgressBar::new(files_to_scan.len() as u64));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░ ")
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            );

            // Use number of CPU cores for parallel scanning
            let num_threads = num_cpus::get().min(8); // Cap at 8 threads
            println!("{} Using {} parallel threads", "►".cyan().bold(), num_threads.to_string().green());
            
            // Start timing
            let start_time = Instant::now();

            // Convert files to paths for parallel processing
            let file_paths: Vec<PathBuf> = files_to_scan.iter()
                .map(|e| e.path().to_path_buf())
                .collect();

            // Thread-safe counters
            let threat_count = Arc::new(Mutex::new(0));
            let scan_results = Arc::new(Mutex::new(Vec::new()));

            // Parallel scanning with rayon
            file_paths.par_iter().enumerate().for_each(|(idx, file_path)| {
                let file_name = file_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                
                pb.set_message(format!("Scanning: {}", file_name));
                pb.set_position((idx + 1) as u64);
                
                let result = scan_single_file(file_path);
                
                // Report if any threats found
                if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
                    let mut count = threat_count.lock().unwrap();
                    *count += 1;
                    
                    pb.suspend(|| {
                        print!("  {} {} - ", "✗".red().bold(), file_path.display().to_string().bright_white());
                        let mut threats = Vec::new();
                        if result.forcedentry { threats.push("FORCEDENTRY"); }
                        if result.blastpass { threats.push("BLASTPASS"); }
                        if result.triangulation { threats.push("TRIANGULATION"); }
                        if result.cve_2025_43300 { threats.push("CVE-2025-43300"); }
                        println!("{}", threats.join(", ").red().bold());
                    });
                }
                
                let mut results = scan_results.lock().unwrap();
                results.push(result);
            });
            
            // Get final results
            all_scan_results = Arc::try_unwrap(scan_results)
                .map(|mutex| mutex.into_inner().unwrap())
                .unwrap_or_else(|arc| {
                    let guard = arc.lock().unwrap();
                    guard.clone()
                });
            
            let final_threat_count = *threat_count.lock().unwrap();
            
            // Calculate performance metrics
            let elapsed = start_time.elapsed();
            let files_per_sec = if elapsed.as_secs() > 0 {
                file_paths.len() as f64 / elapsed.as_secs_f64()
            } else {
                file_paths.len() as f64
            };
            
            pb.finish_with_message(format!("Completed - {} threats found", final_threat_count));
            println!();
            println!("{} Scanned {} files in {:.2}s ({:.1} files/sec)", 
                "✓".green().bold(), 
                file_paths.len(),
                elapsed.as_secs_f64(),
                files_per_sec);
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

        // Display summary results with improved formatting
        println!();
        println!("╔══════════════════════════════════════════════════════════════════════════╗");
        println!("║                           {} SUMMARY RESULTS {}                           ║", "▓".cyan(), "▓".cyan());
        println!("╚══════════════════════════════════════════════════════════════════════════╝");
        println!();
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
                println!("╔══════════════════════════════════════════════════════════════════════════╗");
                println!("║                        {} INFECTED FILES DETECTED {}                       ║", "⚠".red().bold(), "⚠".red().bold());
                println!("╚══════════════════════════════════════════════════════════════════════════╝");
                println!();
                let infected_table = Table::new(infected_details).with(Style::rounded()).to_string();
                println!("{}", infected_table);
            }
        }
    }

    Ok(())
}
