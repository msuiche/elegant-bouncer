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

use clap::Parser;
use colored::*;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use log::LevelFilter;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::env;
use std::fs;
use lopdf::Document;
use rusqlite::{Connection, Result as RusqliteResult};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Instant;


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

fn scan_imessage_db(db_path: &Path, dump_root: &Path) -> Vec<ScanResult> {
    log::info!("[+] Scanning iMessage database: {}", db_path.display());
    let mut results = Vec::new();
    let home_domain_path = dump_root.join("HomeDomain");

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to open iMessage database {}: {}", db_path.display(), e);
            return results;
        }
    };

    let mut stmt = match conn.prepare("
        SELECT
            a.filename,
            h.id AS sender,
            datetime(m.date / 1000000000 + 978307200, 'unixepoch', 'localtime') AS message_date
        FROM attachment a
        JOIN message_attachment_join maj ON a.ROWID = maj.attachment_id
        JOIN message m ON maj.message_id = m.ROWID
        LEFT JOIN handle h ON m.handle_id = h.ROWID
    ") {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to prepare statement for {}: {}", db_path.display(), e);
            return results;
        }
    };

    let attachment_iter = match stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, String>(2)?))
    }) {
        Ok(iter) => iter,
        Err(e) => {
            log::error!("Failed to query attachments from {}: {}", db_path.display(), e);
            return results;
        }
    };

    for row in attachment_iter {
        if let Ok((relative_path_str, sender, message_date)) = row {
            if let Some(stripped_path) = relative_path_str.strip_prefix("~/Library/") {
                let potential_path = home_domain_path.join("Library").join(stripped_path);
                if potential_path.exists() {
                    let origin = format!("iMessage from {} on {}", sender.unwrap_or_else(|| "Unknown".to_string()), message_date);
                    log::info!("--> Scanning iMessage attachment: {} (Origin: {})", potential_path.display(), origin);
                    let result = scan_single_file_with_origin(&potential_path, Some(origin));
                    if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
                        results.push(result);
                    }
                } else {
                    log::warn!("Could not find iMessage attachment: {}", potential_path.display());
                }
            }
        }
    }
    results
}

fn scan_whatsapp_db(db_path: &Path, _dump_root: &Path) -> Vec<ScanResult> {
    log::info!("[+] Scanning WhatsApp database: {}", db_path.display());
    let mut results = Vec::new();
    
    let app_domain_path = match db_path.ancestors().find(|a| a.to_string_lossy().contains("AppDomainGroup")) {
        Some(p) => p.to_path_buf(),
        None => {
            log::error!("Could not determine AppDomainGroup path for WhatsApp DB: {}", db_path.display());
            return results;
        }
    };

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to open WhatsApp database {}: {}", db_path.display(), e);
            return results;
        }
    };

    let mut stmt = match conn.prepare("
        SELECT
            mi.ZMEDIALOCALPATH,
            cs.ZPARTNERNAME
        FROM ZWAMEDIAITEM mi
        JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
        LEFT JOIN ZWACHATSESSION cs ON m.ZCHATSESSION = cs.Z_PK
        WHERE mi.ZMEDIALOCALPATH IS NOT NULL
    ") {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to prepare statement for {}: {}", db_path.display(), e);
            return results;
        }
    };

    let media_items = match stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok(items) => items,
        Err(e) => {
            log::error!("Failed to query media items from {}: {}", db_path.display(), e);
            return results;
        }
    };

    for item_result in media_items {
        if let Ok((relative_path_str, chat_name)) = item_result {
            let attachment_path = app_domain_path.join(&relative_path_str);
            if attachment_path.exists() {
                let origin = format!("WhatsApp in chat '{}'", chat_name.unwrap_or_else(|| "Unknown".to_string()));
                log::info!("--> Scanning WhatsApp attachment: {} (Origin: {})", attachment_path.display(), origin);
                let result = scan_single_file_with_origin(&attachment_path, Some(origin));
                if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
                    results.push(result);
                }
            } else {
                log::warn!("Could not find WhatsApp attachment: {}", attachment_path.display());
            }
        }
    }
    results
}

fn scan_messaging_apps(path: &Path) -> Vec<ScanResult> {
    let mut app_scan_results = Vec::new();
    log::info!("[+] Starting database and app scan phase...");

    let walker = WalkDir::new(path).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        let entry_path = entry.path();
        if let Some(file_name) = entry_path.file_name().and_then(|n| n.to_str()) {
            if file_name == "sms.db" {
                app_scan_results.extend(scan_imessage_db(entry_path, path));
            } else if file_name == "ChatStorage.sqlite" {
                app_scan_results.extend(scan_whatsapp_db(entry_path, path));
            } else if file_name.ends_with("Viber.sqlite") {
                app_scan_results.extend(scan_viber_db(entry_path, path));
            } else if file_name == "db.sqlite" && entry_path.to_string_lossy().contains("Signal") {
                log::warn!("Found Signal database at {}. The database is encrypted and cannot be parsed directly. Performing a best-effort scan of the adjacent 'Attachments' directory.", entry_path.display());
                if let Some(parent_dir) = entry_path.parent() {
                    app_scan_results.extend(scan_signal_attachments(parent_dir.join("Attachments"), path));
                }
            }
        }
    }
    
    app_scan_results.extend(scan_telegram_cache(path));
    log::info!("[+] Database and app scan phase complete.");
    app_scan_results
}

fn scan_telegram_cache(path: &Path) -> Vec<ScanResult> {
    log::info!("[+] Searching for Telegram cache directories...");
    let mut telegram_results = Vec::new();
    let telegram_dirs = ["Telegram", "Telegram Documents", "Telegram Images", "Telegram Video", "Telegram Audio"];
    let walker = WalkDir::new(path).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_dir() {
            if let Some(dir_name) = entry.path().file_name().and_then(|n| n.to_str()) {
                if telegram_dirs.contains(&dir_name) {
                    log::info!("[+] Found Telegram directory: {}. Scanning all contents.", entry.path().display());
                    for telegram_entry in WalkDir::new(entry.path()).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
                        let result = scan_single_file_with_origin(telegram_entry.path(), Some("Telegram Cache File".to_string()));
                        if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
                            telegram_results.push(result);
                        }
                    }
                }
            }
        }
    }
    telegram_results
}


fn scan_viber_db(db_path: &Path, _dump_root: &Path) -> Vec<ScanResult> {
    log::info!("[+] Scanning Viber database: {}", db_path.display());
    let mut results = Vec::new();

    let app_domain_path = match db_path.ancestors().find(|a| a.to_string_lossy().contains("AppDomain")) {
        Some(p) => p.to_path_buf(),
        None => {
            log::error!("Could not determine AppDomain path for Viber DB: {}", db_path.display());
            return results;
        }
    };

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to open Viber database {}: {}", db_path.display(), e);
            return results;
        }
    };

    let mut stmt = match conn.prepare("
        SELECT
            m.ZPAYLOADPATH,
            c.ZPARTNERNAME
        FROM ZVCMESSAGE m
        LEFT JOIN ZVCCONVERSATION c ON m.ZCONVERSATION = c.Z_PK
        WHERE m.ZPAYLOADPATH IS NOT NULL
    ") {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to prepare statement for {}: {}", db_path.display(), e);
            return results;
        }
    };

    let attachment_iter = match stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok(iter) => iter,
        Err(e) => {
            log::error!("Failed to query attachments from {}: {}", db_path.display(), e);
            return results;
        }
    };

    for row in attachment_iter {
        if let Ok((relative_path_str, partner_name)) = row {
            // Viber paths are often relative to the 'Documents' folder within their AppDomain
            let attachment_path = app_domain_path.join("Documents").join(&relative_path_str);
            if attachment_path.exists() {
                let origin = format!("Viber from/to {}", partner_name.unwrap_or_else(|| "Unknown".to_string()));
                log::info!("--> Scanning Viber attachment: {} (Origin: {})", attachment_path.display(), origin);
                let result = scan_single_file_with_origin(&attachment_path, Some(origin));
                if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
                    results.push(result);
                }
            } else {
                log::warn!("Could not find Viber attachment: {}", attachment_path.display());
            }
        }
    }
    results
}

fn scan_signal_attachments(attachments_path: PathBuf, _dump_root: &Path) -> Vec<ScanResult> {
    let mut results = Vec::new();
    if !attachments_path.exists() {
        log::warn!("Signal 'Attachments' directory not found at {}", attachments_path.display());
        return results;
    }

    log::info!("[+] Scanning Signal attachments directory: {}", attachments_path.display());
    let walker = WalkDir::new(attachments_path).into_iter();
    for entry in walker.filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
        let path = entry.path();
        let origin = Some("Signal Attachment".to_string());
        log::debug!("Scanning Signal attachment: {}", path.display());
        let result = scan_single_file_with_origin(path, origin);
        if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
            results.push(result);
        }
    }
    results
}



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

    /// Only scan messaging apps (iMessage, WhatsApp, etc.) and skip the general file scan.
    #[clap(short, long)]
    messaging_only: bool,

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
    origin: Option<String>,
    timed_out: bool,
    forcedentry: bool,
    blastpass: bool,
    triangulation: bool,
    cve_2025_43300: bool,
}

fn scan_single_file(path: &Path) -> ScanResult {
    scan_single_file_with_origin(path, None)
}

fn do_actual_scan(path: &Path, origin: Option<String>) -> ScanResult {
    let mut result = ScanResult {
        file_path: path.to_path_buf(),
        origin,
        timed_out: false,
        forcedentry: false,
        blastpass: false,
        triangulation: false,
        cve_2025_43300: false,
    };

    // FORCEDENTRY scan
    if let Ok(status) = FORCEDENTRY::scan_pdf_jbig2_file(path) {
        if status == ScanResultStatus::StatusMalicious {
            result.forcedentry = true;
        }
    }

    // BLASTPASS scan
    if let Ok(status) = BLASTPASS::scan_webp_vp8l_file(path) {
        if status == ScanResultStatus::StatusMalicious {
            result.blastpass = true;
        }
    }

    // TRIANGULATION scan
    if let Ok(status) = TRIANGULATION::scan_ttf_file(path) {
        if status == ScanResultStatus::StatusMalicious {
            result.triangulation = true;
        }
    }

    // CVE-2025-43300 scan
    if dng::scan_dng_file(path) == ScanResultStatus::StatusMalicious {
        result.cve_2025_43300 = true;
    }

    // If the file is a PDF, extract and scan its streams
    if path.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("pdf")) {
        let temp_dir = env::temp_dir().join(format!(
            "elegant-bouncer-scan-{}",
            path.file_name().unwrap().to_string_lossy()
        ));

        if fs::create_dir_all(&temp_dir).is_ok() {
            if let Ok(doc) = Document::load(path) {
                for (_, object) in &doc.objects {
                    if let Ok(stream) = object.as_stream() {
                        let content = &stream.content;
                        let temp_file_path = temp_dir.join("stream.bin");
                        
                        if fs::write(&temp_file_path, content).is_ok() {
                            if !result.blastpass {
                                if let Ok(status) = BLASTPASS::scan_webp_vp8l_file(&temp_file_path) {
                                    if status == ScanResultStatus::StatusMalicious {
                                        result.blastpass = true;
                                    }
                                }
                            }
                            if !result.triangulation {
                                if let Ok(status) = TRIANGULATION::scan_ttf_file(&temp_file_path) {
                                    if status == ScanResultStatus::StatusMalicious {
                                        result.triangulation = true;
                                    }
                                }
                            }
                            if !result.cve_2025_43300 {
                                if dng::scan_dng_file(&temp_file_path) == ScanResultStatus::StatusMalicious {
                                    result.cve_2025_43300 = true;
                                }
                            }
                        }
                    }
                }
            }
            // Clean up the temporary directory
            let _ = fs::remove_dir_all(&temp_dir);
        }
    }

    result
}

fn scan_single_file_with_origin(path: &Path, origin: Option<String>) -> ScanResult {
    let (tx, rx) = mpsc::channel();
    let path_buf = path.to_path_buf();
    let origin_clone = origin.clone();

    thread::spawn(move || {
        let result = do_actual_scan(&path_buf, origin_clone);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(result) => result,
        Err(_) => {
            log::warn!("Scanning timed out for file: {}", path.display());
            ScanResult {
                file_path: path.to_path_buf(),
                origin,
                timed_out: true,
                forcedentry: false,
                blastpass: false,
                triangulation: false,
                cve_2025_43300: false,
            }
        }
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

fn setup_logging(level: LevelFilter) -> Result<()> {
    let log_filename = format!("elegant-bouncer-{}.log", chrono::Local::now().format("%Y-%m-%d-%H-%M-%S"));
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(level)
        .chain(std::io::stdout())
        .chain(fern::log_file(log_filename)?)
        .apply()?;
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

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    setup_logging(level)?;

    if !args.scan && !args.create_forcedentry {
        log::info!("You need to supply an action. Run with {} for more information.", "--help".green());
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

        // Use TUI mode if requested
        if args.tui {
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
            log::info!("[+] Scanning file: {}", path.display());
            let result = scan_single_file(path);
            all_scan_results.push(result);
            
            // Display file info
            println!();
            let _ = print_hashes(&args.path);
        } else if path.is_dir() {
            let files_found;
            if args.messaging_only {
                log::info!("[+] --messaging-only flag set. Skipping general file scan.");
                all_scan_results = scan_messaging_apps(path);
                files_found = !all_scan_results.is_empty();
            } else {
                // --- Full File Scan ---
                log::info!("[+] Starting general file scan...");
                let walker = if args.recursive {
                    WalkDir::new(path)
                } else {
                    WalkDir::new(path).max_depth(1)
                };

                let files_to_scan: Vec<_> = walker
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .map(|e| (e.into_path(), None))
                    .filter(|(path, _)| should_scan_file(path, &extensions))
                    .collect();
                
                files_found = !files_to_scan.is_empty();

                let pb = ProgressBar::new(files_to_scan.len() as u64);
                pb.set_style(ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                    .unwrap()
                    .progress_chars("#>-"));

                all_scan_results = files_to_scan
                    .par_iter()
                    .progress_with(pb.clone())
                    .map(|(file_path, origin)| {
                        pb.set_message(file_path.display().to_string());
                        scan_single_file_with_origin(file_path, origin.clone())
                    })
                    .collect();
                
                pb.finish_with_message("General file scan complete");
                // --- End Full File Scan ---

                // --- App Scan Phase ---
                all_scan_results.extend(scan_messaging_apps(path));
            }

            if !files_found && all_scan_results.is_empty() {
                log::info!("No files found with specified extensions or in messaging apps.");
                return Ok(());
            }

            println!();
            log::info!("[+] Detected Threats:");
        } else {
            log::error!("Error: Path '{}' does not exist or is not accessible", path.display());
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
                origin: String,
                threat_name: String,
                cve_ids: String,
            }
            
            let mut infected_details = Vec::new();
            
            for result in &all_scan_results {
                if result.timed_out { continue; } // Skip timed out files for this table
                let path_str = result.file_path.display().to_string();
                let origin_str = result.origin.as_deref().unwrap_or("N/A").to_string();
                
                if result.forcedentry {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        origin: origin_str.clone(),
                        threat_name: "FORCEDENTRY".to_string(),
                        cve_ids: "CVE-2021-30860".to_string(),
                    });
                }
                
                if result.blastpass {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        origin: origin_str.clone(),
                        threat_name: "BLASTPASS".to_string(),
                        cve_ids: "CVE-2023-4863, CVE-2023-41064".to_string(),
                    });
                }
                
                if result.triangulation {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        origin: origin_str.clone(),
                        threat_name: "TRIANGULATION".to_string(),
                        cve_ids: "CVE-2023-41990".to_string(),
                    });
                }
                
                if result.cve_2025_43300 {
                    infected_details.push(InfectedFile {
                        path: path_str.clone(),
                        origin: origin_str.clone(),
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

        // Show timed out files
        let timed_out_files: Vec<_> = all_scan_results.iter().filter(|r| r.timed_out).collect();
        if !timed_out_files.is_empty() {
            println!();
            println!("{} Timed Out Files (scan took >60s):", "[!]".yellow());
            for result in timed_out_files {
                println!("  - {}", result.file_path.display());
            }
        }
    }

    Ok(())
}
