//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  messaging.rs
//
// Abstract:
//  Messaging app database scanning for attachment threat detection
//
// Author:
//  Matt Suiche (msuiche) 24-Aug-2025
//

use crate::errors::*;
use crate::jbig2 as FORCEDENTRY;
use crate::webp as BLASTPASS;
use crate::ttf as TRIANGULATION;
use crate::dng;

use colored::*;
use lopdf::Document;
use rusqlite::{Connection, Result as RusqliteResult};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Clone, Debug)]
pub struct MessagingResult {
    pub file_path: PathBuf,
    pub origin: String,
    pub forcedentry: bool,
    pub blastpass: bool,
    pub triangulation: bool,
    pub cve_2025_43300: bool,
}

pub fn scan_messaging_apps(path: &Path) -> Vec<MessagingResult> {
    let mut results = Vec::new();
    println!("{} Starting messaging app scan...", "[+]".green());

    let walker = WalkDir::new(path).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        let entry_path = entry.path();
        if let Some(file_name) = entry_path.file_name().and_then(|n| n.to_str()) {
            match file_name {
                "sms.db" => {
                    println!("  {} Found iMessage database", "►".cyan());
                    results.extend(scan_imessage_db(entry_path, path));
                }
                "ChatStorage.sqlite" => {
                    println!("  {} Found WhatsApp database", "►".cyan());
                    results.extend(scan_whatsapp_db(entry_path));
                }
                _ if file_name.ends_with("Viber.sqlite") => {
                    println!("  {} Found Viber database", "►".cyan());
                    results.extend(scan_viber_db(entry_path));
                }
                "db.sqlite" if entry_path.to_string_lossy().contains("Signal") => {
                    println!("  {} Found Signal database (encrypted)", "►".cyan());
                    if let Some(parent_dir) = entry_path.parent() {
                        results.extend(scan_signal_attachments(&parent_dir.join("Attachments")));
                    }
                }
                _ => {}
            }
        }
    }

    // Scan Telegram cache directories
    results.extend(scan_telegram_cache(path));

    if results.is_empty() {
        println!("{} No messaging app attachments found", "[!]".yellow());
    } else {
        println!("{} Found {} messaging app attachments to scan", "[+]".green(), results.len());
    }

    results
}

fn scan_imessage_db(db_path: &Path, dump_root: &Path) -> Vec<MessagingResult> {
    let mut results = Vec::new();
    let home_domain_path = dump_root.join("HomeDomain");

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("    {} Failed to open iMessage database: {}", "✗".red(), e);
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
            eprintln!("    {} Failed to query iMessage database: {}", "✗".red(), e);
            return results;
        }
    };

    let attachment_iter = match stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?
        ))
    }) {
        Ok(iter) => iter,
        Err(e) => {
            eprintln!("    {} Failed to iterate iMessage attachments: {}", "✗".red(), e);
            return results;
        }
    };

    for row in attachment_iter {
        if let Ok((relative_path_str, sender, message_date)) = row {
            if let Some(stripped_path) = relative_path_str.strip_prefix("~/Library/") {
                let potential_path = home_domain_path.join("Library").join(stripped_path);
                if potential_path.exists() {
                    let origin = format!(
                        "iMessage from {} on {}",
                        sender.unwrap_or_else(|| "Unknown".to_string()),
                        message_date
                    );
                    
                    if let Some(scan_result) = scan_attachment(&potential_path, origin) {
                        results.push(scan_result);
                    }
                }
            }
        }
    }

    results
}

fn scan_whatsapp_db(db_path: &Path) -> Vec<MessagingResult> {
    let mut results = Vec::new();
    
    let app_domain_path = match db_path.ancestors().find(|a| a.to_string_lossy().contains("AppDomainGroup")) {
        Some(p) => p.to_path_buf(),
        None => {
            eprintln!("    {} Could not determine AppDomainGroup path for WhatsApp", "✗".red());
            return results;
        }
    };

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("    {} Failed to open WhatsApp database: {}", "✗".red(), e);
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
            eprintln!("    {} Failed to query WhatsApp database: {}", "✗".red(), e);
            return results;
        }
    };

    let media_items = match stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok(items) => items,
        Err(e) => {
            eprintln!("    {} Failed to iterate WhatsApp media: {}", "✗".red(), e);
            return results;
        }
    };

    for item_result in media_items {
        if let Ok((relative_path_str, chat_name)) = item_result {
            let attachment_path = app_domain_path.join(&relative_path_str);
            if attachment_path.exists() {
                let origin = format!(
                    "WhatsApp in chat '{}'",
                    chat_name.unwrap_or_else(|| "Unknown".to_string())
                );
                
                if let Some(scan_result) = scan_attachment(&attachment_path, origin) {
                    results.push(scan_result);
                }
            }
        }
    }

    results
}

fn scan_viber_db(db_path: &Path) -> Vec<MessagingResult> {
    let mut results = Vec::new();

    let app_domain_path = match db_path.ancestors().find(|a| a.to_string_lossy().contains("AppDomain")) {
        Some(p) => p.to_path_buf(),
        None => {
            eprintln!("    {} Could not determine AppDomain path for Viber", "✗".red());
            return results;
        }
    };

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("    {} Failed to open Viber database: {}", "✗".red(), e);
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
            eprintln!("    {} Failed to query Viber database: {}", "✗".red(), e);
            return results;
        }
    };

    let attachment_iter = match stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok(iter) => iter,
        Err(e) => {
            eprintln!("    {} Failed to iterate Viber attachments: {}", "✗".red(), e);
            return results;
        }
    };

    for row in attachment_iter {
        if let Ok((relative_path_str, partner_name)) = row {
            let attachment_path = app_domain_path.join("Documents").join(&relative_path_str);
            if attachment_path.exists() {
                let origin = format!(
                    "Viber from/to {}",
                    partner_name.unwrap_or_else(|| "Unknown".to_string())
                );
                
                if let Some(scan_result) = scan_attachment(&attachment_path, origin) {
                    results.push(scan_result);
                }
            }
        }
    }

    results
}

fn scan_signal_attachments(attachments_path: &Path) -> Vec<MessagingResult> {
    let mut results = Vec::new();
    
    if !attachments_path.exists() {
        eprintln!("    {} Signal Attachments directory not found", "⚠".yellow());
        return results;
    }

    println!("    {} Scanning Signal attachments directory", "►".cyan());
    let walker = WalkDir::new(attachments_path).into_iter();
    for entry in walker.filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
        let path = entry.path();
        let origin = "Signal Attachment".to_string();
        
        if let Some(scan_result) = scan_attachment(path, origin) {
            results.push(scan_result);
        }
    }

    results
}

fn scan_telegram_cache(path: &Path) -> Vec<MessagingResult> {
    println!("  {} Searching for Telegram cache directories...", "►".cyan());
    let mut results = Vec::new();
    let telegram_dirs = ["Telegram", "Telegram Documents", "Telegram Images", "Telegram Video", "Telegram Audio"];
    
    let walker = WalkDir::new(path).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_dir() {
            if let Some(dir_name) = entry.path().file_name().and_then(|n| n.to_str()) {
                if telegram_dirs.contains(&dir_name) {
                    println!("    {} Found Telegram directory: {}", "►".cyan(), dir_name);
                    for telegram_entry in WalkDir::new(entry.path())
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_type().is_file()) 
                    {
                        let origin = format!("Telegram Cache - {}", dir_name);
                        
                        if let Some(scan_result) = scan_attachment(telegram_entry.path(), origin) {
                            results.push(scan_result);
                        }
                    }
                }
            }
        }
    }
    
    results
}

fn scan_attachment(path: &Path, origin: String) -> Option<MessagingResult> {
    // Only scan relevant file types
    let ext = path.extension()?.to_str()?;
    let relevant_extensions = ["pdf", "gif", "webp", "jpg", "jpeg", "png", "tif", "tiff", "dng", "ttf", "otf"];
    
    if !relevant_extensions.iter().any(|&e| e.eq_ignore_ascii_case(ext)) {
        return None;
    }

    let mut result = MessagingResult {
        file_path: path.to_path_buf(),
        origin: origin.clone(),
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
                            // Check embedded WebP
                            if !result.blastpass {
                                if let Ok(status) = BLASTPASS::scan_webp_vp8l_file(&temp_file_path) {
                                    if status == ScanResultStatus::StatusMalicious {
                                        result.blastpass = true;
                                    }
                                }
                            }
                            // Check embedded TTF
                            if !result.triangulation {
                                if let Ok(status) = TRIANGULATION::scan_ttf_file(&temp_file_path) {
                                    if status == ScanResultStatus::StatusMalicious {
                                        result.triangulation = true;
                                    }
                                }
                            }
                            // Check embedded DNG
                            if !result.cve_2025_43300 {
                                if dng::scan_dng_file(&temp_file_path) == ScanResultStatus::StatusMalicious {
                                    result.cve_2025_43300 = true;
                                }
                            }
                        }
                    }
                }
            }
            // Clean up
            let _ = fs::remove_dir_all(&temp_dir);
        }
    }

    // Only return if a threat was found
    if result.forcedentry || result.blastpass || result.triangulation || result.cve_2025_43300 {
        println!("      {} THREAT in {}: {}", 
            "✗".red().bold(),
            origin,
            path.file_name()?.to_str()?
        );
        Some(result)
    } else {
        None
    }
}