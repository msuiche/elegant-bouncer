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

use colored::*;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use log::{info, debug, error};

#[derive(Clone, Debug)]
pub struct MessagingAttachment {
    pub file_path: PathBuf,
    pub origin: String,
}

pub fn find_messaging_attachments(path: &Path) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    info!("{} Starting messaging app scan...", "[+]".green());

    let walker = WalkDir::new(path).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        let entry_path = entry.path();
        if let Some(file_name) = entry_path.file_name().and_then(|n| n.to_str()) {
            match file_name {
                "sms.db" => {
                    info!("  {} Found iMessage database", "►".cyan());
                    results.extend(scan_imessage_db(entry_path, path));
                }
                "ChatStorage.sqlite" => {
                    info!("  {} Found WhatsApp database", "►".cyan());
                    results.extend(scan_whatsapp_db(entry_path, path));
                }
                _ if file_name.ends_with("Viber.sqlite") => {
                    info!("  {} Found Viber database", "►".cyan());
                    results.extend(scan_viber_db(entry_path, path));
                }
                "db.sqlite" if entry_path.to_string_lossy().contains("Signal") => {
                    info!("  {} Found Signal database (encrypted)", "►".cyan());
                    if let Some(parent_dir) = entry_path.parent() {
                        results.extend(scan_signal_attachments(parent_dir.join("Attachments"), path));
                    }
                }
                _ => {}
            }
        }
    }

    // Scan Telegram cache directories
    results.extend(scan_telegram_cache(path));

    if results.is_empty() {
        info!("{} No messaging app attachments found", "[!]".yellow());
    } else {
        info!("{} Found {} messaging app attachments to scan", "[+]".green(), results.len());
    }

    results
}

fn scan_imessage_db(db_path: &Path, dump_root: &Path) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    let home_domain_path = dump_root.join("HomeDomain");
    let media_domain_path = dump_root.join("MediaDomain");

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            error!("    {} Failed to open iMessage database: {}", "✗".red(), e);
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
            error!("    {} Failed to query iMessage database: {}", "✗".red(), e);
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
            error!("    {} Failed to iterate iMessage attachments: {}", "✗".red(), e);
            return results;
        }
    };

    let mut attachment_count = 0;
    for row in attachment_iter {
        if let Ok((relative_path_str, sender, message_date)) = row {
            attachment_count += 1;
            debug!("      Found attachment entry #{}: {}", attachment_count, relative_path_str);
            if let Some(stripped_path) = relative_path_str.strip_prefix("~/Library/") {
                // SMS attachments are in MediaDomain, not HomeDomain
                let potential_path = if stripped_path.starts_with("SMS/Attachments") {
                    media_domain_path.join("Library").join(stripped_path)
                } else {
                    home_domain_path.join("Library").join(stripped_path)
                };
                debug!("        Looking for: {}", potential_path.display());
                if potential_path.exists() {
                    debug!("        ✓ File exists!");
                    let origin = format!(
                        "iMessage from {} on {}",
                        sender.unwrap_or_else(|| "Unknown".to_string()),
                        message_date
                    );
                    
                    results.push(MessagingAttachment {
                        file_path: potential_path,
                        origin,
                    });
                } else {
                    debug!("        ✗ File not found");
                }
            } else {
                debug!("        Path doesn't start with ~/Library/: {}", relative_path_str);
            }
        }
    }
    
    debug!("      Total attachment entries in database: {}", attachment_count);

    results
}

fn scan_whatsapp_db(db_path: &Path, _dump_root: &Path) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    
    // Find the AppDomainGroup directory, not the database file itself
    let app_domain_path = match db_path.parent().and_then(|p| {
        if p.to_string_lossy().contains("AppDomainGroup") {
            Some(p.to_path_buf())
        } else {
            p.ancestors().find(|a| a.to_string_lossy().contains("AppDomainGroup")).map(|a| a.to_path_buf())
        }
    }) {
        Some(p) => p,
        None => {
            error!("    {} Could not determine AppDomainGroup path for WhatsApp", "✗".red());
            return results;
        }
    };

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            error!("    {} Failed to open WhatsApp database: {}", "✗".red(), e);
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
            error!("    {} Failed to query WhatsApp database: {}", "✗".red(), e);
            return results;
        }
    };

    let media_items = match stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok(items) => items,
        Err(e) => {
            error!("    {} Failed to iterate WhatsApp media: {}", "✗".red(), e);
            return results;
        }
    };

    for item_result in media_items {
        if let Ok((relative_path_str, chat_name)) = item_result {
            // WhatsApp stores paths like "Media/..." but they're actually in "Message/Media/..."
            let attachment_path = if relative_path_str.starts_with("Media/") {
                app_domain_path.join("Message").join(&relative_path_str)
            } else {
                app_domain_path.join(&relative_path_str)
            };
            debug!("      WhatsApp attachment path: {} -> {}", relative_path_str, attachment_path.display());
            if attachment_path.exists() {
                debug!("        ✓ WhatsApp file exists!");
                let origin = format!(
                    "WhatsApp in chat '{}'",
                    chat_name.unwrap_or_else(|| "Unknown".to_string())
                );
                
                results.push(MessagingAttachment {
                    file_path: attachment_path,
                    origin,
                });
            } else {
                debug!("        ✗ WhatsApp file not found");
            }
        }
    }

    results
}

fn scan_viber_db(db_path: &Path, _dump_root: &Path) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();

    // Find the AppDomain directory, not including subdirectories
    let app_domain_path = match db_path.parent().and_then(|p| {
        if p.to_string_lossy().contains("AppDomain") && !p.to_string_lossy().contains("/Documents") {
            Some(p.to_path_buf())
        } else {
            p.ancestors().find(|a| a.to_string_lossy().contains("AppDomain") && !a.to_string_lossy().contains("/Documents")).map(|a| a.to_path_buf())
        }
    }) {
        Some(p) => p,
        None => {
            error!("    {} Could not determine AppDomain path for Viber", "✗".red());
            return results;
        }
    };

    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            error!("    {} Failed to open Viber database: {}", "✗".red(), e);
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
            error!("    {} Failed to query Viber database: {}", "✗".red(), e);
            return results;
        }
    };

    let attachment_iter = match stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok(iter) => iter,
        Err(e) => {
            error!("    {} Failed to iterate Viber attachments: {}", "✗".red(), e);
            return results;
        }
    };

    for row in attachment_iter {
        if let Ok((relative_path_str, partner_name)) = row {
            let attachment_path = app_domain_path.join("Documents").join(&relative_path_str);
            info!("      Viber attachment path: {} -> {}", relative_path_str, attachment_path.display());
            if attachment_path.exists() {
                debug!("        ✓ Viber file exists!");
                let origin = format!(
                    "Viber from/to {}",
                    partner_name.unwrap_or_else(|| "Unknown".to_string())
                );
                
                results.push(MessagingAttachment {
                    file_path: attachment_path,
                    origin,
                });
            } else {
                debug!("        ✗ Viber file not found");
            }
        }
    }

    results
}

fn scan_signal_attachments(attachments_path: PathBuf, _dump_root: &Path) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    
    if !attachments_path.exists() {
        error!("    {} Signal Attachments directory not found", "⚠".yellow());
        return results;
    }

    info!("    {} Scanning Signal attachments directory", "►".cyan());
    let walker = WalkDir::new(&attachments_path).into_iter();
    for entry in walker.filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
        let path = entry.path();
        let origin = "Signal Attachment".to_string();
        
        results.push(MessagingAttachment {
            file_path: path.to_path_buf(),
            origin,
        });
    }

    results
}

fn scan_telegram_cache(path: &Path) -> Vec<MessagingAttachment> {
    info!("  {} Searching for Telegram cache directories...", "►".cyan());
    let mut results = Vec::new();
    let telegram_dirs = ["Telegram", "Telegram Documents", "Telegram Images", "Telegram Video", "Telegram Audio"];
    
    let walker = WalkDir::new(path).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_dir() {
            if let Some(dir_name) = entry.path().file_name().and_then(|n| n.to_str()) {
                if telegram_dirs.contains(&dir_name) {
                    debug!("    {} Found Telegram directory: {}", "►".cyan(), dir_name);
                    for telegram_entry in WalkDir::new(entry.path())
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_type().is_file()) 
                    {
                        let origin = format!("Telegram Cache - {}", dir_name);
                        
                        results.push(MessagingAttachment {
                            file_path: telegram_entry.path().to_path_buf(),
                            origin,
                        });
                    }
                }
            }
        }
    }
    
    results
}

