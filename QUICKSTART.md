# SecureCodeX CLI - Quick Start Guide

## Installation

```bash
cd c:\Code\SecureCodeX
pip install -e .
```

## Basic Usage

```bash
# Scan current directory
securecodex scan

# Scan specific path
securecodex scan --path /path/to/code

# Scan with custom output
securecodex scan --path ./project --output ./reports

# Verbose mode
securecodex scan --path ./project --verbose

# Generate both PDF and JSON
securecodex scan --path ./project --format both
```

## Features

- ✅ Scans **all files** without size limits
- ✅ Generates PDF reports with:
  - Total lines of code
  - Severity breakdown (Critical, High, Medium, Low, Info)
  - Detailed findings with file paths and line numbers
- ✅ Real-time progress bars
- ✅ Supports absolute and relative paths
- ✅ JSON export option

## Report Contents

Each PDF report includes:
1. **Project Information**: Name, date, path, files, **LOC**, languages, duration
2. **Vulnerability Summary**: Count by severity + **total count**
3. **Detailed Findings**: Grouped by severity with code snippets

## Example Output

```
Scanning files: 100%|##########| 10/10 [00:00<00:00, 11.06file/s]

============================================================
 SCAN SUMMARY
============================================================
Files Scanned: 10
Total Lines of Code: 3,388
Duration: 1.89s

FINDINGS BY SEVERITY:
  CRITICAL: 37
  HIGH:     385
  MEDIUM:   71
  LOW:      6
  INFO:     2
  TOTAL:    501
============================================================

[OK] PDF report saved to: SecureCodeX_Report_project_20251217_130905.pdf
```

## Git Installation (Future)

```bash
pip install git+https://github.com/username/SecureCodeX.git
```

## Help

```bash
securecodex --help
securecodex scan --help
```
