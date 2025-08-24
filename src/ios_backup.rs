//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  ios_backup.rs
//
// Abstract:
//  iOS backup reconstruction functionality
//
// Author:
//  Matt Suiche (msuiche) 24-Aug-2025
//
// Based on ios-backup-reconstruct.py by Hamid@darkcell.se
//

use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, Result as RusqliteResult};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use log::{info, warn, error};

pub struct BackupRecord {
    file_id: String,
    domain: String,
    relative_path: String,
}

pub fn reconstruct_ios_backup(source_dir: &Path, output_dir: &Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Check if source directory exists
    if !source_dir.exists() || !source_dir.is_dir() {
        return Err(format!("Source directory does not exist: {}", source_dir.display()).into());
    }

    // Check for Manifest.db
    let manifest_db = source_dir.join("Manifest.db");
    if !manifest_db.exists() {
        return Err("Manifest.db not found in source directory. Please ensure this is a decrypted iOS backup.".into());
    }

    // Check output directory
    if output_dir.exists() && output_dir.read_dir()?.next().is_some() && !force {
        return Err(format!(
            "Output directory '{}' is not empty. Use --force to overwrite.",
            output_dir.display()
        ).into());
    }

    // Create output directory
    fs::create_dir_all(output_dir)?;

    println!("{} iOS Backup Reconstruction", "►".cyan().bold());
    println!("  {} {}", "Source:".bright_blue(), source_dir.display());
    println!("  {} {}", "Output:".bright_blue(), output_dir.display());
    println!();

    // Query the database
    println!("{} Reading Manifest.db...", "[+]".green());
    let records = read_manifest_db(&manifest_db)?;
    
    if records.is_empty() {
        println!("{} No file records found in database", "[!]".yellow());
        return Ok(());
    }

    println!("{} Found {} file records to process", "[+]".green(), records.len());
    println!();

    // Create progress bar
    let pb = ProgressBar::new(records.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
            .unwrap()
            .progress_chars("█▓▒░ ")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
    );

    let mut copied_count = 0;
    let mut failed_count = 0;

    // Process each file record
    for (idx, record) in records.iter().enumerate() {
        pb.set_position((idx + 1) as u64);
        pb.set_message(format!("Processing: {}", record.relative_path));

        // Source file path: hash is split as XX/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        let source_file = if record.file_id.len() >= 2 {
            source_dir.join(&record.file_id[..2]).join(&record.file_id)
        } else {
            source_dir.join(&record.file_id)
        };

        // Destination file path
        let dest_file = output_dir.join(&record.domain).join(&record.relative_path);

        if !source_file.exists() {
            warn!("Source file not found: {}", source_file.display());
            failed_count += 1;
            continue;
        }

        // Create destination directory if needed
        if let Some(parent) = dest_file.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                error!("Failed to create directory {}: {}", parent.display(), e);
                failed_count += 1;
                continue;
            }
        }

        // Copy the file
        match fs::copy(&source_file, &dest_file) {
            Ok(_) => {
                info!("Copied: {} -> {}", source_file.display(), dest_file.display());
                copied_count += 1;
            }
            Err(e) => {
                error!("Failed to copy {} to {}: {}", source_file.display(), dest_file.display(), e);
                failed_count += 1;
            }
        }
    }

    pb.finish_with_message("Reconstruction complete");
    println!();

    // Display summary
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                      {} RECONSTRUCTION SUMMARY {}                         ║", "▓".cyan(), "▓".cyan());
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  {} {}", "Total Files Processed:".bright_blue(), records.len());
    println!("  {} {}", "Files Copied Successfully:".green(), copied_count);
    println!("  {} {}", "Files Failed/Skipped:".red(), failed_count);
    println!("  {} {}", "Output Location:".bright_blue(), output_dir.display());
    println!();

    if failed_count > 0 {
        println!("{} {} files could not be copied (this is normal for iOS backups)", 
            "[!]".yellow(), 
            failed_count);
    }

    Ok(())
}

fn read_manifest_db(db_path: &Path) -> Result<Vec<BackupRecord>, Box<dyn std::error::Error>> {
    let conn = Connection::open(db_path)?;
    
    let mut stmt = conn.prepare(
        "SELECT fileID, domain, relativePath FROM Files WHERE relativePath IS NOT NULL"
    )?;

    let records = stmt.query_map([], |row| {
        Ok(BackupRecord {
            file_id: row.get(0)?,
            domain: row.get(1)?,
            relative_path: row.get(2)?,
        })
    })?;

    let mut result = Vec::new();
    for record in records {
        result.push(record?);
    }

    Ok(result)
}

pub fn extract_ios_backup(source_dir: &Path, output_dir: Option<&Path>, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Determine output directory
    let output_path = if let Some(dir) = output_dir {
        dir.to_path_buf()
    } else {
        // Default: create reconstructed_backup folder next to source
        source_dir.parent()
            .unwrap_or(Path::new("."))
            .join(format!("{}_reconstructed", source_dir.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("backup")))
    };

    reconstruct_ios_backup(source_dir, &output_path, force)
}