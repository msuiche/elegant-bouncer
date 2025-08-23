# `elegant-bouncer` Improvements

This document details the recent performance, user experience, and forensic analysis enhancements made to the `elegant-bouncer` tool.

## 1. Performance and UX Enhancements

### High-Speed Parallel Scanning
The tool's file scanning engine was re-engineered to be fully multi-threaded using the `rayon` library. This allows it to take full advantage of multi-core CPUs, resulting in significantly faster scans, especially on large directories.

### Robust Scan Timeout
A 60-second timeout has been implemented for each individual file scan. This prevents a single complex or corrupt file from hanging the scanner and halting the entire analysis. Files that time out are now listed in a separate section of the final report.

### Interactive Progress Bar
To provide better feedback during scans, an interactive progress bar from the `indicatif` library has been integrated. It displays:
- Elapsed time
- A visual bar showing the percentage of completion
- The number of files scanned out of the total
- The name of the file currently being processed

The console output was also refactored to ensure that verbose logging does not interfere with the progress bar, which now remains cleanly at the bottom of the screen during the scan.

### Comprehensive Logging
The logging system was upgraded from `env_logger` to `fern`. This provides two key benefits:
1.  **Clean Console Output:** Only high-level information is printed to the console, avoiding clutter.
2.  **Detailed Log Files:** A timestamped log file (e.g., `elegant-bouncer-2025-08-23-23-30-00.log`) is generated for every run, containing verbose output from all scanners. This is invaluable for detailed analysis and debugging.

## 2. Advanced Forensic Analysis Capabilities

### Targeted Scan Mode
A new `--messaging-only` (or `-m`) flag has been added. When used, the tool will skip the general recursive file scan and focus exclusively on high-value targets like iMessage, WhatsApp, and other messaging app data. This allows for much faster, targeted investigations.

### Deep PDF Stream Scanning
The tool's PDF analysis capabilities have been significantly enhanced. It now automatically:
1.  Parses all objects within a PDF file.
2.  Extracts any embedded data streams (such as fonts, images, or other data).
3.  Saves these streams to temporary files.
4.  Recursively runs all relevant vulnerability scans (`BLASTPASS`, `TRIANGULATION`, `CVE-2025-43300`) on the extracted files.

This allows the tool to find malicious files that are hidden or embedded inside a PDF.

### Messaging App Attachment Scanning
A major new feature is the ability to scan for attachments within popular messaging app databases. This is crucial for mobile forensics, as many malicious files are transmitted through these apps.

#### Supported Apps:
- **iMessage (`sms.db`):** Automatically parses the database, extracts attachment paths, and scans the corresponding files.
- **WhatsApp (`ChatStorage.sqlite`):** Finds and scans all media items referenced in the chat database.
- **Viber (`Viber.sqlite`):** Scans all attachments found in the Viber database.
- **Signal (`db.sqlite`):** Since the Signal database is encrypted, the tool performs a best-effort scan. It finds the database, warns the user that it cannot be decrypted, and then proceeds to scan all files in the adjacent `Attachments` directory.
- **Telegram (Cache Files):** The tool automatically identifies and scans all files within common Telegram cache directories (`Telegram`, `Telegram Documents`, etc.), which is the most reliable way to find Telegram attachments in a forensic dump.

### Forensic Context in Reporting
The final report has been enhanced to provide crucial forensic context. When a threat is found within a messaging app, the new **"Origin"** column will provide details such as:
- The sender's phone number/ID and the date of the message (for iMessage).
- The name of the WhatsApp or Viber chat session.
- A clear label indicating that the file came from a Signal or Telegram cache.

This transforms the tool's output from a simple list of malicious files into a more actionable forensic report.