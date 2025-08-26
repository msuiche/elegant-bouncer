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
use std::collections::HashMap;
use std::sync::Arc;

use log::{info, debug, error};

#[derive(Clone, Debug)]
pub struct MessagingAttachment {
    pub file_path: PathBuf,      // Actual file path in the backup (could be hash)
    pub origin: String,           // Description like "WhatsApp in chat 'Patricia'"
    pub original_name: String,    // Original filename from iOS (e.g., "IMG_1234.jpg")
}

// Cache for iOS backup file mappings
struct IOSBackupCache {
    // Map from relative path to actual file path in backup
    file_map: HashMap<String, PathBuf>,
    // Map from filename to list of (relative_path, file_path) for fallback searches
    filename_map: HashMap<String, Vec<(String, PathBuf)>>,
}

impl IOSBackupCache {
    fn new(backup_path: &Path) -> Option<Self> {
        let manifest_db = backup_path.join("Manifest.db");
        
        if !manifest_db.exists() {
            return None;
        }
        
        let conn = Connection::open(&manifest_db).ok()?;
        
        let mut file_map = HashMap::new();
        let mut filename_map: HashMap<String, Vec<(String, PathBuf)>> = HashMap::new();
        
        // Load all file mappings into memory
        info!("Loading iOS backup file mappings into cache...");
        
        let query = "SELECT fileID, domain, relativePath FROM Files WHERE relativePath IS NOT NULL";
        if let Ok(mut stmt) = conn.prepare(query) {
            if let Ok(results) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?
                ))
            }) {
                let mut count = 0;
                for result in results {
                    if let Ok((file_id, domain, relative_path)) = result {
                        if file_id.len() >= 2 {
                            let subdir = &file_id[0..2];
                            let actual_path = backup_path.join(subdir).join(&file_id);
                            
                            // Store with domain prefix
                            let full_path = format!("{}-{}", domain, relative_path);
                            file_map.insert(full_path.clone(), actual_path.clone());
                            
                            // Store without domain prefix
                            file_map.insert(relative_path.clone(), actual_path.clone());
                            
                            // Store in filename map for fallback searches
                            if let Some(filename) = Path::new(&relative_path).file_name().and_then(|n| n.to_str()) {
                                filename_map.entry(filename.to_string())
                                    .or_insert_with(Vec::new)
                                    .push((relative_path, actual_path));
                            }
                            
                            count += 1;
                        }
                    }
                }
                info!("  Cached {} file mappings", count);
            }
        }
        
        Some(IOSBackupCache {
            file_map,
            filename_map,
        })
    }
    
    fn resolve_path(&self, ios_relative_path: &str) -> Option<PathBuf> {
        // Clean up the path
        let clean_path = ios_relative_path
            .strip_prefix("~/").unwrap_or(ios_relative_path)
            .strip_prefix("/").unwrap_or(ios_relative_path);
        
        debug!("    Resolving iOS path: {}", clean_path);
        
        // Try direct lookup first
        if let Some(path) = self.file_map.get(clean_path) {
            if path.exists() {
                debug!("      ✓ Found via direct lookup: {:?}", path);
                return Some(path.clone());
            }
        }
        
        // Try with different domain prefixes
        let search_paths = if clean_path.contains("SMS/Attachments") || clean_path.contains("Messages/Attachments") {
            vec![
                format!("MediaDomain-{}", clean_path),
                format!("HomeDomain-{}", clean_path),
            ]
        } else if clean_path.contains("Message/Media") || clean_path.contains("Media/") {
            vec![
                format!("AppDomainGroup-group.net.whatsapp.WhatsApp.shared-{}", clean_path),
                format!("AppDomainGroup-group.net.whatsapp.WhatsApp.shared-Message/{}", 
                    clean_path.strip_prefix("Message/").unwrap_or(clean_path)),
            ]
        } else {
            vec![
                format!("MediaDomain-{}", clean_path),
                format!("HomeDomain-{}", clean_path),
            ]
        };
        
        for search_path in &search_paths {
            if let Some(path) = self.file_map.get(search_path) {
                if path.exists() {
                    debug!("      ✓ Found via domain prefix: {:?}", path);
                    return Some(path.clone());
                }
            }
        }
        
        // Fallback: search by filename
        if let Some(filename) = Path::new(clean_path).file_name().and_then(|n| n.to_str()) {
            if let Some(entries) = self.filename_map.get(filename) {
                // Return the first matching file that exists
                for (rel_path, path) in entries {
                    if path.exists() {
                        debug!("      ✓ Found by filename '{}': {:?} (from: {})", filename, path, rel_path);
                        return Some(path.clone());
                    }
                }
            }
        }
        
        debug!("      ✗ Could not resolve path: {}", clean_path);
        None
    }
}

fn find_ios_backup_databases(backup_path: &Path) -> HashMap<String, PathBuf> {
    let mut databases = HashMap::new();
    let manifest_db = backup_path.join("Manifest.db");
    
    if !manifest_db.exists() {
        return databases;
    }
    
    match Connection::open(&manifest_db) {
        Ok(conn) => {
            info!("Searching for messaging databases in iOS backup...");
            
            // Define the exact database paths we're looking for
            // These match what find_messaging_attachments expects
            let db_queries = vec![
                // iMessage/SMS database
                ("sms.db", vec![
                    "HomeDomain-Library/SMS/sms.db",
                    "Library/SMS/sms.db",
                ]),
                // WhatsApp main database
                ("ChatStorage.sqlite", vec![
                    "ChatStorage.sqlite",
                ]),
                // Viber database
                ("Viber.sqlite", vec![
                    "Viber.sqlite",
                ]),
            ];
            
            for (db_name, possible_paths) in db_queries {
                for relative_path in possible_paths {
                    let query = "SELECT fileID FROM Files WHERE relativePath = ? OR domain || '-' || relativePath = ?";
                    
                    if let Ok(mut stmt) = conn.prepare(query) {
                        if let Ok(mut results) = stmt.query_map([&relative_path, &relative_path], |row| {
                            row.get::<_, String>(0)
                        }) {
                            if let Some(Ok(file_id)) = results.next() {
                                // Construct the actual file path in the backup
                                if file_id.len() >= 2 {
                                    let subdir = &file_id[0..2];
                                    let db_file = backup_path.join(subdir).join(&file_id);
                                    if db_file.exists() {
                                        info!("  ✓ Found {} at {:?} (from {})", db_name, db_file, relative_path);
                                        databases.insert(db_name.to_string(), db_file);
                                        break; // Found this database, move to next one
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to open Manifest.db: {}", e);
            error!("This iOS backup may be encrypted or require Full Disk Access permission.");
            error!("To grant access: System Preferences > Security & Privacy > Privacy > Full Disk Access");
            error!("Add Terminal.app or iTerm.app (or your terminal) to the list.");
        }
    }
    
    databases
}

pub fn find_messaging_attachments(path: &Path) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    info!("{} Starting messaging app and document scan...", "[+]".green());

    // Check if this is an iOS backup first
    let is_ios_backup = path.join("Manifest.db").exists();
    
    if is_ios_backup {
        // Handle iOS backup - find databases using Manifest.db
        info!("  {} Detected iOS backup structure, looking up database files...", "►".cyan());
        
        // Create the cache once for all database scans
        let cache = IOSBackupCache::new(path).map(Arc::new);
        
        if cache.is_none() {
            error!("Failed to create iOS backup cache");
            return results;
        }
        
        let databases = find_ios_backup_databases(path);
        
        for (db_name, db_path) in databases {
            match db_name.as_str() {
                "sms.db" => {
                    info!("  {} Found iMessage database", "►".cyan());
                    // Use cached version for iOS backups
                    results.extend(scan_imessage_db_with_cache(&db_path, path, cache.as_ref()));
                }
                "ChatStorage.sqlite" => {
                    info!("  {} Found WhatsApp database", "►".cyan());
                    // Use cached version for iOS backups
                    results.extend(scan_whatsapp_db_with_cache(&db_path, path, cache.as_ref()));
                }
                name if name.contains("Viber") => {
                    info!("  {} Found Viber database", "►".cyan());
                    results.extend(scan_viber_db(&db_path, path));
                }
                _ => {}
            }
        }
        
        // Scan iCloud Drive documents
        results.extend(scan_icloud_drive(path, cache.as_ref()));
    } else {
        // Handle regular directory structure (extracted backup or direct scan)
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
        
        // Scan iCloud Drive documents (for reconstructed backups)
        results.extend(scan_icloud_drive(path, None));
    }

    if results.is_empty() {
        info!("{} No messaging app attachments or documents found", "[!]".yellow());
    } else {
        info!("{} Found {} files to scan", "[+]".green(), results.len());
    }

    results
}

fn resolve_ios_backup_file(backup_path: &Path, ios_relative_path: &str) -> Option<PathBuf> {
    let manifest_db = backup_path.join("Manifest.db");
    
    if !manifest_db.exists() {
        return None;
    }
    
    if let Ok(conn) = Connection::open(&manifest_db) {
        // iMessage attachments are stored with paths like "Library/SMS/Attachments/..."
        // WhatsApp attachments are like "Message/Media/..."
        // We need to try different domain combinations
        
        let mut search_paths = Vec::new();
        
        // Clean up the path
        let clean_path = ios_relative_path
            .strip_prefix("~/").unwrap_or(ios_relative_path)
            .strip_prefix("/").unwrap_or(ios_relative_path);
        
        // For SMS/iMessage attachments
        if clean_path.contains("SMS/Attachments") || clean_path.contains("Messages/Attachments") {
            search_paths.push(format!("MediaDomain-{}", clean_path));
            search_paths.push(format!("HomeDomain-{}", clean_path));
            search_paths.push(clean_path.to_string());
        }
        // For WhatsApp attachments  
        else if clean_path.contains("Message/Media") || clean_path.contains("Media/") {
            // WhatsApp paths in backup
            search_paths.push(format!("AppDomainGroup-group.net.whatsapp.WhatsApp.shared-{}", clean_path));
            search_paths.push(format!("AppDomainGroup-group.net.whatsapp.WhatsApp.shared-Message/{}", 
                clean_path.strip_prefix("Message/").unwrap_or(clean_path)));
            search_paths.push(clean_path.to_string());
        }
        // Generic paths
        else {
            search_paths.push(format!("MediaDomain-{}", clean_path));
            search_paths.push(format!("HomeDomain-{}", clean_path));
            search_paths.push(clean_path.to_string());
        }
        
        // Try each search path
        for search_path in &search_paths {
            let query = "SELECT fileID, domain FROM Files WHERE relativePath = ? OR domain || '-' || relativePath = ?";
            
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(mut results) = stmt.query_map([&search_path, &search_path], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                }) {
                    if let Some(Ok((file_id, domain))) = results.next() {
                        // Construct the actual file path in the backup
                        if file_id.len() >= 2 {
                            let subdir = &file_id[0..2];
                            let file_path = backup_path.join(subdir).join(&file_id);
                            if file_path.exists() {
                                debug!("Resolved {} -> {:?} (domain: {})", ios_relative_path, file_path, domain);
                                return Some(file_path);
                            }
                        }
                    }
                }
            }
        }
        
        // If not found, try a more broad search by filename
        if let Some(filename) = Path::new(clean_path).file_name().and_then(|n| n.to_str()) {
            let query = "SELECT fileID, relativePath FROM Files WHERE relativePath LIKE ?";
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(results) = stmt.query_map([&format!("%{}", filename)], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                }) {
                    for result in results {
                        if let Ok((file_id, rel_path)) = result {
                            if file_id.len() >= 2 {
                                let subdir = &file_id[0..2];
                                let file_path = backup_path.join(subdir).join(&file_id);
                                if file_path.exists() {
                                    debug!("Found by filename {} -> {:?} (path: {})", filename, file_path, rel_path);
                                    return Some(file_path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
}

// Version with cache for iOS backups
fn scan_imessage_db_with_cache(db_path: &Path, dump_root: &Path, cache: Option<&Arc<IOSBackupCache>>) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();

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
    let mut found_count = 0;
    for row in attachment_iter {
        if let Ok((relative_path_str, sender, message_date)) = row {
            attachment_count += 1;
            
            // Use cache for fast lookups
            let attachment_path = if let Some(cache) = cache {
                let path_to_resolve = if let Some(stripped) = relative_path_str.strip_prefix("~/") {
                    stripped
                } else {
                    &relative_path_str
                };
                cache.resolve_path(path_to_resolve)
            } else {
                // Fallback to old method for non-iOS backups
                resolve_ios_backup_file(dump_root, &relative_path_str)
            };
            
            if let Some(file_path) = attachment_path {
                found_count += 1;
                let origin = format!(
                    "iMessage from {} on {}",
                    sender.unwrap_or_else(|| "Unknown".to_string()),
                    message_date
                );
                
                // Extract the original filename from the relative path
                let original_name = Path::new(&relative_path_str)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                debug!("    Adding iMessage attachment #{}: {:?} (original: {})", found_count, file_path, original_name);
                
                results.push(MessagingAttachment {
                    file_path,
                    origin,
                    original_name,
                });
            }
        }
    }
    
    info!("    Found {}/{} iMessage attachments", found_count, attachment_count);
    results
}

fn scan_imessage_db(db_path: &Path, dump_root: &Path) -> Vec<MessagingAttachment> {
    // Check if this is an iOS backup or reconstructed folder
    let is_ios_backup = dump_root.join("Manifest.db").exists();
    
    if is_ios_backup {
        // For iOS backups, we should use the cached version (but this is called from non-cached context)
        scan_imessage_db_with_cache(db_path, dump_root, None)
    } else {
        // For reconstructed folders, use the traditional path resolution
        scan_imessage_db_reconstructed(db_path, dump_root)
    }
}

// Version for reconstructed/extracted backups with traditional folder structure
fn scan_imessage_db_reconstructed(db_path: &Path, dump_root: &Path) -> Vec<MessagingAttachment> {
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
            
            // For reconstructed backups, use the traditional path resolution
            let attachment_path = if let Some(stripped_path) = relative_path_str.strip_prefix("~/Library/") {
                // SMS attachments are in MediaDomain, not HomeDomain
                let potential_path = if stripped_path.starts_with("SMS/Attachments") {
                    media_domain_path.join("Library").join(stripped_path)
                } else {
                    home_domain_path.join("Library").join(stripped_path)
                };
                if potential_path.exists() {
                    Some(potential_path)
                } else {
                    None
                }
            } else {
                None
            };
            
            if let Some(file_path) = attachment_path {
                debug!("        ✓ File found!");
                let origin = format!(
                    "iMessage from {} on {}",
                    sender.unwrap_or_else(|| "Unknown".to_string()),
                    message_date
                );
                
                // Extract the original filename
                let original_name = Path::new(&relative_path_str)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                results.push(MessagingAttachment {
                    file_path,
                    origin,
                    original_name,
                });
            } else {
                debug!("        ✗ File not found");
            }
        }
    }
    
    debug!("      Total attachment entries in database: {}", attachment_count);

    results
}

fn scan_whatsapp_db_with_cache(db_path: &Path, dump_root: &Path, cache: Option<&Arc<IOSBackupCache>>) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    
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

    let mut attachment_count = 0;
    let mut found_count = 0;
    
    for item_result in media_items {
        if let Ok((relative_path_str, chat_name)) = item_result {
            attachment_count += 1;
            
            // Use cache for fast lookups
            let attachment_path = if let Some(cache) = cache {
                // WhatsApp paths need special handling
                let search_path = if relative_path_str.starts_with("Media/") {
                    format!("Message/{}", relative_path_str)
                } else {
                    relative_path_str.clone()
                };
                cache.resolve_path(&search_path)
            } else {
                // Fallback for non-cached lookups
                resolve_ios_backup_file(dump_root, &relative_path_str)
            };
            
            if let Some(path) = attachment_path {
                found_count += 1;
                let origin = format!(
                    "WhatsApp in chat '{}'",
                    chat_name.unwrap_or_else(|| "Unknown".to_string())
                );
                
                // Extract the original filename from the WhatsApp path
                let original_name = Path::new(&relative_path_str)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                debug!("    Adding WhatsApp attachment #{}: {:?} (original: {})", found_count, path, original_name);
                
                results.push(MessagingAttachment {
                    file_path: path,
                    origin,
                    original_name,
                });
            }
        }
    }

    info!("    Found {}/{} WhatsApp attachments", found_count, attachment_count);
    results
}

fn scan_whatsapp_db(db_path: &Path, dump_root: &Path) -> Vec<MessagingAttachment> {
    // Check if this is an iOS backup or reconstructed folder
    let is_ios_backup = dump_root.join("Manifest.db").exists();
    
    if is_ios_backup {
        // For iOS backups, use the cached version
        scan_whatsapp_db_with_cache(db_path, dump_root, None)
    } else {
        // For reconstructed folders, use the traditional path resolution
        scan_whatsapp_db_reconstructed(db_path, dump_root)
    }
}

fn scan_whatsapp_db_reconstructed(db_path: &Path, dump_root: &Path) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    
    // For reconstructed backups, find the AppDomainGroup directory
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
            // For reconstructed backups, use the traditional path resolution
            let attachment_path = if relative_path_str.starts_with("Media/") {
                app_domain_path.join("Message").join(&relative_path_str)
            } else {
                app_domain_path.join(&relative_path_str)
            };
            
            debug!("      WhatsApp attachment path: {} -> {:?}", relative_path_str, attachment_path);
            if attachment_path.exists() {
                debug!("        ✓ WhatsApp file exists!");
                let origin = format!(
                    "WhatsApp in chat '{}'",
                    chat_name.unwrap_or_else(|| "Unknown".to_string())
                );
                
                // Extract the original filename
                let original_name = Path::new(&relative_path_str)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                results.push(MessagingAttachment {
                    file_path: attachment_path,
                    origin,
                    original_name,
                });
            } else {
                debug!("        ✗ WhatsApp file not found: {:?}", attachment_path);
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
                
                // Extract the original filename
                let original_name = Path::new(&relative_path_str)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                results.push(MessagingAttachment {
                    file_path: attachment_path,
                    origin,
                    original_name,
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
        
        let original_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        results.push(MessagingAttachment {
            file_path: path.to_path_buf(),
            origin,
            original_name,
        });
    }

    results
}

fn scan_icloud_drive(path: &Path, cache: Option<&Arc<IOSBackupCache>>) -> Vec<MessagingAttachment> {
    let mut results = Vec::new();
    info!("  {} Scanning iCloud Drive documents...", "►".cyan());
    
    let is_ios_backup = path.join("Manifest.db").exists();
    
    if is_ios_backup {
        // For iOS backup, use cache to find iCloud Drive files
        if let Some(cache) = cache {
            let mut found_count = 0;
            let mut total_count = 0;
            
            // Look for files in the iCloud Drive path pattern
            for (relative_path, actual_path) in &cache.file_map {
                // Check if this is an iCloud Drive file
                if relative_path.contains("com~apple~CloudDocs") || 
                   relative_path.contains("Mobile Documents/com~apple~CloudDocs") {
                    total_count += 1;
                    
                    // Check if file has a scannable extension
                    if let Some(filename) = Path::new(relative_path).file_name().and_then(|n| n.to_str()) {
                        // Get extension
                        let should_scan = Path::new(filename).extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| {
                                let ext_lower = ext.to_lowercase();
                                // Check for common document/image types
                                matches!(ext_lower.as_str(), 
                                    "pdf" | "doc" | "docx" | "xls" | "xlsx" | 
                                    "jpg" | "jpeg" | "png" | "gif" | "webp" | 
                                    "tif" | "tiff" | "dng" | "heic" | "heif" |
                                    "ttf" | "otf" | "zip" | "rar" | "7z")
                            })
                            .unwrap_or(false);
                        
                        if should_scan && actual_path.exists() {
                            found_count += 1;
                            let origin = format!("iCloud Drive: {}", relative_path);
                            let original_name = filename.to_string();
                            
                            debug!("    Adding iCloud file #{}: {:?} ({})", found_count, actual_path, filename);
                            
                            results.push(MessagingAttachment {
                                file_path: actual_path.clone(),
                                origin,
                                original_name,
                            });
                        }
                    }
                }
            }
            
            if found_count > 0 {
                info!("    Found {}/{} iCloud Drive files", found_count, total_count);
            }
        }
    } else {
        // For reconstructed backup, look for the iCloud Drive folder
        let icloud_paths = vec![
            path.join("HomeDomain/Library/Mobile Documents/com~apple~CloudDocs"),
            path.join("Library/Mobile Documents/com~apple~CloudDocs"),
            path.join("Mobile Documents/com~apple~CloudDocs"),
            path.join("com~apple~CloudDocs"),
        ];
        
        debug!("    Looking for iCloud Drive in reconstructed backup...");
        for icloud_path in &icloud_paths {
            debug!("    Checking path: {:?} (exists: {})", icloud_path, icloud_path.exists());
            if icloud_path.exists() && icloud_path.is_dir() {
                info!("    Found iCloud Drive at: {:?}", icloud_path);
                
                // Recursively scan the iCloud Drive folder with no depth limit
                let walker = WalkDir::new(&icloud_path)
                    .follow_links(false)  // Don't follow symlinks to avoid loops
                    .min_depth(0)         // Include the root directory
                    .max_open(50);        // Limit open file descriptors
                
                let mut found_count = 0;
                let mut total_files = 0;
                let mut skipped_files = 0;
                
                for entry in walker.into_iter() {
                    match entry {
                        Ok(entry) => {
                            if entry.file_type().is_file() {
                                total_files += 1;
                                let file_path = entry.path();
                                
                                // Debug log every 100th file to show progress
                                if total_files % 100 == 0 {
                                    debug!("      Processed {} files so far...", total_files);
                                }
                                
                                // Check if file has a scannable extension
                                let should_scan = file_path.extension()
                                    .and_then(|ext| ext.to_str())
                                    .map(|ext| {
                                        let ext_lower = ext.to_lowercase();
                                        matches!(ext_lower.as_str(),
                                            "pdf" | "doc" | "docx" | "xls" | "xlsx" |
                                            "jpg" | "jpeg" | "png" | "gif" | "webp" |
                                            "tif" | "tiff" | "dng" | "heic" | "heif" |
                                            "ttf" | "otf" | "zip" | "rar" | "7z")
                                    })
                                    .unwrap_or(false);
                                
                                if should_scan {
                                    found_count += 1;
                                    let relative_path = file_path.strip_prefix(&icloud_path)
                                        .unwrap_or(file_path)
                                        .to_string_lossy();
                                    
                                    let origin = format!("iCloud Drive: {}", relative_path);
                                    let original_name = file_path.file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    
                                    debug!("      Adding file #{}: {}", found_count, original_name);
                                    
                                    results.push(MessagingAttachment {
                                        file_path: file_path.to_path_buf(),
                                        origin,
                                        original_name,
                                    });
                                } else {
                                    skipped_files += 1;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("      Error accessing entry: {}", e);
                        }
                    }
                }
                
                info!("    Scanned {} total files, found {} scannable files (skipped {} non-matching extensions)", 
                    total_files, found_count, skipped_files);
                
                if found_count > 0 {
                    info!("    Found {} iCloud Drive files", found_count);
                } else if total_files > 0 {
                    info!("    Found {} files in iCloud Drive but none with scannable extensions", total_files);
                }
                break; // Found the iCloud folder, no need to check other paths
            }
        }
        
        if !icloud_paths.iter().any(|p| p.exists()) {
            debug!("    No iCloud Drive folder found in reconstructed backup");
        }
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
                        
                        let original_name = telegram_entry.path().file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        
                        results.push(MessagingAttachment {
                            file_path: telegram_entry.path().to_path_buf(),
                            origin,
                            original_name,
                        });
                    }
                }
            }
        }
    }
    
    results
}

