# SecureCodeX CLI - Security Source Code Analysis Tool

A powerful command-line tool for scanning source code to detect security vulnerabilities, sensitive information, and code quality issues.

## Features

- 🔍 **Engine V3 (Structural Analysis)**: Moves beyond regex with Semgrep-style AST and Taint analysis
- 🌳 **Tree-sitter Powered**: Multi-language support with high-precision structural matching
- 🎯 **Advanced Taint Tracking**: Detects complex source-to-sink vulnerabilities
- 📊 **Rich Security Reports**: Includes confidence scores, secure code examples, and auto-fix suggestions
- 🚀 **Fast & Rule-Driven**: Extensible YAML-based rule DSL for rapid custom rule development
- 📈 **Standard Mapping**: Rules mapped to OWASP, CWE, ASVS, MITRE, and NIST

## Installation

### Install from Git Repository

```bash
# Install directly from Git
pip install git+https://github.com/yourusername/SecureCodeX.git

# Or clone and install locally
git clone https://github.com/yourusername/SecureCodeX.git
cd SecureCodeX
pip install -e .
```

### Install from Local Directory

```bash
cd /path/to/SecureCodeX
pip install -e .
```

## Usage

### Basic Scan

Scan the current directory:

```bash
securecodex scan
```

### Scan Specific Directory

```bash
securecodex scan --path /path/to/source/code
```

### Scan with Custom Output

```bash
securecodex scan --path ./myproject --output ./reports --project-name "MyApp"
```

### Generate Both PDF and JSON Reports

```bash
securecodex scan --path ./myproject --format both
```

### Verbose Output

```bash
securecodex scan --path ./myproject --verbose
```

## Command-Line Options

```
securecodex scan [OPTIONS]

Options:
  --path PATH           Path to scan (directory or file). Default: current directory
  --output PATH         Output directory for reports. Default: current directory
  --project-name NAME   Project name for the report. Default: directory name
  --format FORMAT       Output format: pdf, json, or both. Default: pdf
  --verbose            Enable verbose output
  --keep-db            Keep the SQLite database after scan (for debugging)
  --help               Show help message
```

## Report Contents

The generated PDF report includes:

- **Project Information**
  - Project name
  - Scan date and time
  - Total files scanned
  - **Total lines of code**
  - Languages detected
  - Scan duration

- **Vulnerability Summary**
  - **Critical findings count**
  - **High findings count**
  - **Medium findings count**
  - **Low findings count**
  - **Info findings count**
  - **Total findings count**

- **Detailed Findings**
  - Severity level
  - Finding name and description
  - File path and line number
  - Code snippet
  - CWE ID (when available)
  - Remediation advice

## Examples

### Example 1: Scan Current Directory

```bash
cd /path/to/your/project
securecodex scan
```

Output:
```
==============================================================
  SecureCodeX - Security Source Code Analysis Tool
==============================================================
Project: your-project
Scan Path: /path/to/your/project
Output Directory: /path/to/your/project
==============================================================

📁 Found 150 files to scan
Scanning files: 100%|████████████████| 150/150 [00:15<00:00, 10.2file/s]

💾 Saving 45 findings to database...

==============================================================
📊 SCAN SUMMARY
==============================================================
Project: your-project
Path: /path/to/your/project
Files Scanned: 150
Total Lines of Code: 12,543
Languages: .py, .js, .html
Duration: 15.32s

------------------------------------------------------------
FINDINGS BY SEVERITY:
------------------------------------------------------------
  🔴 Critical: 2
  🟠 High:     8
  🟡 Medium:   15
  🟢 Low:      12
  ℹ️  Info:     8

  📋 Total:    45
==============================================================

📄 Generating PDF report...
✅ PDF report saved to: SecureCodeX_Report_your-project_20251217_130045.pdf

✅ Scan completed successfully!
```

### Example 2: Scan Specific Directory with Custom Output

```bash
securecodex scan --path /sample/data/file --output ~/security-reports --project-name "MyApp"
```

### Example 3: Scan Single File

```bash
securecodex scan --path /path/to/file.py --verbose
```

## Engine V3 Rule DSL

SecureCodeX now supports a powerful YAML-based rule DSL inspired by Semgrep. This allows for structural pattern matching and taint analysis.

### Example: Dangerous API Pattern
```yaml
rules:
  - id: dangerous-os-system
    severity: HIGH
    languages: [python]
    pattern: os.system(...)
    message: "Using os.system() is dangerous."
```

### Example: Source-to-Sink Taint Rule
```yaml
rules:
  - id: python-sqli-taint
    mode: taint
    source: $REQ.params.get(...)
    sink: db.execute(...)
    message: "User input reaches SQL sink."
```

## Supported Vulnerability Types

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Hardcoded Credentials
- Insecure Cryptography
- Authentication Issues
- Authorization Flaws
- And many more...

## Requirements

- Python 3.8 or higher
- Operating System: Windows, Linux, macOS

## License

MIT License

## Support

For issues and questions, please open an issue on GitHub.
