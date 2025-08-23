# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

ELEGANTBOUNCER is a defensive security tool for detecting file-based mobile exploits. It identifies threats like FORCEDENTRY (CVE-2021-30860), BLASTPASS (CVE-2023-4863, CVE-2023-41064), and TRIANGULATION (CVE-2023-41990) without requiring in-the-wild samples.

## Development Commands

### Build
```bash
cargo build
cargo build --release  # Production build with debug symbols
```

### Run Tests
```bash
cargo test                    # Run all tests
cargo test test_blastpass    # Run specific test
```

### Run the Tool
```bash
cargo run -- --scan <filepath>                    # Scan a file for vulnerabilities
cargo run -- --create-forcedentry <filepath>      # Create test FORCEDENTRY PDF
cargo run -- -v --scan <filepath>                 # Verbose scanning
```

### Format and Lint
```bash
cargo fmt         # Format code
cargo clippy      # Run linter
```

## Architecture

The codebase is organized as a Rust library with a CLI binary:

- **Main Entry**: `src/main.rs` - CLI interface using clap, handles arguments and orchestrates scanning
- **Core Modules** (each implements specific exploit detection):
  - `src/jbig2.rs` - FORCEDENTRY detection for malicious JBIG2 PDFs
  - `src/webp.rs` - BLASTPASS detection for malicious WebP VP8L files  
  - `src/ttf.rs` - TRIANGULATION detection for malicious TrueType fonts
  - `src/huffman.rs` - Huffman coding utilities used by detection algorithms
  - `src/errors.rs` - Error types and `ScanResultStatus` enum

The detection approach uses structural analysis rather than IOC matching. Each module exports a `scan_*_file()` function that returns `ScanResultStatus::StatusMalicious` or `StatusOk`.

## Testing

Tests are in `tests/tests.rs` and use sample files from `tests/samples/`. The samples include known malicious files for validation - these should only be used for testing detection capabilities.

## Important Notes

- This is a defensive security tool for threat detection only
- The `--create-forcedentry` flag generates test PDFs for research purposes
- Sample files in `tests/samples/` contain exploit demonstrations for testing