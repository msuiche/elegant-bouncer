#!/usr/bin/env python3
"""
iOS Backup Reconstructor
Version: 0.1

iOS encrypted backups by default are not meant to be human-readable. The folder structure needs to be reconstructed, before it is consumable by most other tools.
This script provides a way to reconstruct the folder structure of an iOS backup, making it easier to analyze and work with.
Actual file names are extracted from the backup's manifest.db database.
Note that it is expected for the script to produce a lot of "source file not found" errors.

Hamid@darkcell.se

"""

import argparse
import sqlite3
import os
import shutil
import logging
from datetime import datetime
from pathlib import Path
from telnetlib import ENCRYPT

# Try to import rich, but fall back to standard printing if it's not installed.
try:
    from rich.console import Console
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn
    from rich.logging import RichHandler
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# --- Global Configuration ---
APP_NAME = "iOS Backup Reconstructor"
APP_VERSION = "1.0.0"
DEFAULT_OUTPUT_DIR = "reconstructed_backup"
MANIFEST_DB_NAME = "Manifest.db"

# --- Console and Logging Setup ---
# If rich is available, use it for a better experience.
if RICH_AVAILABLE:
    console = Console()
else:
    # Create a dummy console object if rich is not available.
    class DummyConsole:
        def print(self, text, *args, **kwargs):
            print(text)
    console = DummyConsole()

# Set up logging to be handled by rich or a standard handler.
log = logging.getLogger(__name__)

def setup_logging(log_dir: Path, timestamp: str):
    """Configures logging to both a file and the console."""
    log_filename = log_dir / f"reconstruction_log_{timestamp}.log"
    log.setLevel(logging.INFO)

    # File handler - always detailed.
    fh = logging.FileHandler(log_filename)
    fh.setLevel(logging.INFO)
    fh_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(fh_formatter)
    log.addHandler(fh)

    # Console handler - uses rich if available.
    if RICH_AVAILABLE:
        ch = RichHandler(console=console, show_time=False, show_path=False, markup=True)
        ch.setLevel(logging.WARNING) # Only show warnings and errors on console by default
    else:
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
    log.addHandler(ch)

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION} - Reconstructs a decrypted iOS backup into its original file structure.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python3 reconstruct_backup.py ./decrypted -o ./my_reconstructed_case"
    )
    parser.add_argument(
        "source_dir",
        type=Path,
        help="Path to the decrypted backup directory (containing Manifest.db)."
    )
    parser.add_argument(
        "-o", "--output_dir",
        type=Path,
        default=None,
        help=f"Path to the output directory for the reconstructed backup.\n(default: creates a '{DEFAULT_OUTPUT_DIR}' folder next to the source)"
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force overwrite of the output directory if it is not empty."
    )
    return parser.parse_args()

def get_file_records_from_db(db_path: Path):
    """Queries the Manifest.db to get the list of files."""
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found at: {db_path}")

    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # The Files table contains the mapping we need.
            cursor.execute("SELECT fileID, domain, relativePath FROM Files")
            records = cursor.fetchall()
            return records
    except sqlite3.Error as e:
        log.error(f"Database error while reading {db_path}: {e}")
        raise

def reconstruct_backup(source_dir: Path, output_dir: Path):
    """Main logic for the backup reconstruction process."""
    manifest_db_path = source_dir / MANIFEST_DB_NAME
    
    console.print(f"[bold cyan]Querying database:[/bold cyan] {manifest_db_path}")
    try:
        file_records = get_file_records_from_db(manifest_db_path)
    except (FileNotFoundError, sqlite3.Error) as e:
        console.print(f"[bold red]Error:[/bold red] Could not read file records. Aborting. Details in log.")
        log.critical(f"Fatal error during database query: {e}")
        return False, 0, 0

    if not file_records:
        console.print("[bold yellow]Warning:[/bold yellow] No file records found in the database.")
        return True, 0, 0

    console.print(f"[bold green]Success![/] Found {len(file_records)} file records to process.")
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    copied_count = 0
    failed_count = 0

    # --- Rich Progress Bar (if available) ---
    if RICH_AVAILABLE:
        progress_columns = [
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed} of {task.total})"),
            TimeRemainingColumn(),
            TransferSpeedColumn(),
        ]
        with Progress(*progress_columns, console=console) as progress:
            task = progress.add_task("[green]Reconstructing files...", total=len(file_records))
            for record in file_records:
                # This inner loop is duplicated below for the non-rich version.
                # A refactor could merge them, but this is clearer for now.
                file_id = record["fileID"]
                domain = record["domain"]
                relative_path_str = record["relativePath"]
                source_file = source_dir / file_id[:2] / file_id
                dest_file = output_dir / domain / relative_path_str
                
                progress.update(task, advance=1)

                if not source_file.exists():
                    log.warning(f"Source file not found, skipping: {source_file}")
                    failed_count += 1
                    continue
                try:
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_file, dest_file)
                    log.info(f"Copied: {source_file} -> {dest_file}")
                    copied_count += 1
                except (OSError, IOError) as e:
                    log.error(f"Failed to copy {source_file} to {dest_file}: {e}")
                    failed_count += 1
    
    # --- Standard Library Fallback ---
    else:
        total_files = len(file_records)
        for i, record in enumerate(file_records):
            # Print a simple progress indicator every 100 files.
            if i % 100 == 0:
                print(f"Processing file {i} of {total_files}...")

            file_id = record["fileID"]
            domain = record["domain"]
            relative_path_str = record["relativePath"]
            source_file = source_dir / file_id[:2] / file_id
            dest_file = output_dir / domain / relative_path_str

            if not source_file.exists():
                log.warning(f"Source file not found, skipping: {source_file}")
                failed_count += 1
                continue
            try:
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_file, dest_file)
                log.info(f"Copied: {source_file} -> {dest_file}")
                copied_count += 1
            except (OSError, IOError) as e:
                log.error(f"Failed to copy {source_file} to {dest_file}: {e}")
                failed_count += 1
        print(f"Processing complete.")

    return True, copied_count, failed_count

def main():
    """Main entry point for the script."""
    args = parse_arguments()
    source_dir = args.source_dir.resolve()
    
    if args.output_dir:
        output_dir = args.output_dir.resolve()
    else:
        # Default to a folder next to the source directory
        output_dir = source_dir.parent / f"{source_dir.name}_{DEFAULT_OUTPUT_DIR}"

    # --- Initial Checks ---
    if not source_dir.is_dir():
        console.print(f"[bold red]Error:[/bold red] Source directory not found at: {source_dir}")
        return 1
    
    if not (source_dir / MANIFEST_DB_NAME).exists():
        console.print(f"[bold red]Error:[/bold red] '{MANIFEST_DB_NAME}' not found in source directory.")
        console.print("Please ensure you provide the correct path to a decrypted iOS backup.")
        return 1

    if output_dir.exists() and any(output_dir.iterdir()) and not args.force:
        console.print(f"[bold yellow]Warning:[/bold yellow] Output directory '{output_dir}' is not empty.")
        if RICH_AVAILABLE:
            from rich.prompt import Confirm
            if not Confirm.ask("Do you want to continue and potentially overwrite files?"):
                console.print("[cyan]Operation cancelled.[/cyan]")
                return 0
        else:
            response = input("Do you want to continue and potentially overwrite files? (y/N): ")
            if response.lower() != 'y':
                print("Operation cancelled.")
                return 0

    # --- Setup ---
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Create the output directory *before* setting up logging
    output_dir.mkdir(parents=True, exist_ok=True)
    
    setup_logging(output_dir, timestamp)
    
    if RICH_AVAILABLE:
        console.print(Panel(f"[bold green]{APP_NAME} v{APP_VERSION}[/bold green]", title="Starting Process", border_style="blue"))
    else:
        print(f"--- {APP_NAME} v{APP_VERSION} ---")

    start_time = datetime.now()
    
    log.info(f"Starting reconstruction process at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    log.info(f"Source directory: {source_dir}")
    log.info(f"Output directory: {output_dir}")

    # --- Run Reconstruction ---
    success, copied, failed = reconstruct_backup(source_dir, output_dir)
    
    # --- Final Summary ---
    end_time = datetime.now()
    duration = end_time - start_time
    
    if success:
        summary_title = "[bold green]Reconstruction Complete[/bold green]"
        summary_status = "Success"
    else:
        summary_title = "[bold red]Reconstruction Failed[/bold red]"
        summary_status = "Failed"

    if RICH_AVAILABLE:
        table = Table(title=summary_title, show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="dim")
        table.add_column("Value")
        table.add_row("Status", summary_status)
        table.add_row("Total Files Processed", str(copied + failed))
        table.add_row("Files Copied Successfully", f"[green]{copied}[/green]")
        table.add_row("Files Failed/Skipped", f"[red]{failed}[/red]")
        table.add_row("Duration", str(duration).split('.')[0])
        table.add_row("Output Location", str(output_dir))
        table.add_row("Log File", f"reconstruction_log_{timestamp}.log")
        console.print(table)
    else:
        print("\n--- Reconstruction Summary ---")
        print(f"Status: {summary_status}")
        print(f"Total Files Processed: {copied + failed}")
        print(f"Files Copied Successfully: {copied}")
        print(f"Files Failed/Skipped: {failed}")
        print(f"Duration: {str(duration).split('.')[0]}")
        print(f"Output Location: {output_dir}")
        print(f"Log File: reconstruction_log_{timestamp}.log")

    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
