# SecureCodeX CLI - Security Source Code Analysis Tool

A powerful command-line tool for scanning source code to detect security vulnerabilities, sensitive information, and code quality issues.

## Features

- 🔍 **Engine V3 (Structural Analysis)**: Moves beyond regex with Semgrep-style AST and Taint analysis
- 🌳 **Tree-sitter Powered**: Multi-language support with high-precision structural matching
- 🎯 **Advanced Taint Tracking**: Detects complex source-to-sink vulnerabilities
- 📊 **Rich Security Reports**: Includes confidence scores, secure code examples, and auto-fix suggestions
- 🚀 **Fast & Rule-Driven**: Extensible YAML-based rule DSL for rapid custom rule development
- 📈 **Standard Mapping**: Rules mapped to OWASP, CWE, ASVS, MITRE, and NIST
- 📖 **Full Documentation**: Comprehensive guides available in the [`docs/`](file:///c:/Code/SecureCodeX-CLI/docs/INDEX.md) directory

## 📄 Documentation

For in-depth information about SecureCodeX-CLI, please refer to the following guides:

- **[Main Documentation Index](file:///c:/Code/SecureCodeX-CLI/docs/INDEX.md)**
- **[CLI Reference Guide](file:///c:/Code/SecureCodeX-CLI/docs/CLI_REFERENCE.md)**
- **[Engine V3 Deep Dive](file:///c:/Code/SecureCodeX-CLI/docs/ENGINE_V3.md)**
- **[Custom Rules Guide](file:///c:/Code/SecureCodeX-CLI/docs/RULES_GUIDE.md)**
- **[Architecture Overview](file:///c:/Code/SecureCodeX-CLI/docs/ARCHITECTURE.md)**

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


## 🚀 Quick Start

```bash
# Security scan (code vulnerabilities)
python -m securecodex.cli scan --path . --languages python

# SBOM generation (dependencies)
python -m securecodex.cli sbom --path .

# Create custom rules
python -m securecodex.add_rule --language python --type taint
```

**[📖 Full Quick Start Guide](docs/QUICK_START.md)**

---

## Usage

### Security Scan
Scan your code for security vulnerabilities:
```bash
# Basic scan
python -m securecodex.cli scan --path .

# Scan specific languages (80% faster)
python -m securecodex.cli scan --path . --languages python,javascript

# Generate JSON report for CI/CD
python -m securecodex.cli scan --path . --format json --output ./reports
```

**[📖 Complete Scan Documentation](docs/SCAN_DOCUMENTATION.md)**

### SBOM Generation
Generate Software Bill of Materials for supply chain security:
```bash
# Generate SBOM
python -m securecodex.cli sbom --path .

# Specify output directory
python -m securecodex.cli sbom --path . --output ./sbom-reports
```

**[📖 Complete SBOM Documentation](docs/SBOM_DOCUMENTATION.md)**

### Create Custom Rules
Generate custom security rule templates:
```bash
# List supported languages
python -m securecodex.add_rule --list-languages

# Generate rule template
python -m securecodex.add_rule --language python --type taint --output my_rule.yaml

# Show examples
python -m securecodex.add_rule --show-example python-sqli
```

### Synchronize Rules
Update local security rules from external repositories:
```bash
python -m securecodex.cli sync --rules-dir rules
```

---

## Command Reference

### `scan` - Security Code Analysis
```
python -m securecodex.cli scan [OPTIONS]

Options:
  --path PATH              Path to scan (required)
  --languages LANGS        Comma-separated languages (e.g., python,javascript)
  --output PATH            Output directory. Default: current directory
  --project-name NAME      Project name for report. Default: directory name
  --format FORMAT          Report format: pdf, json, or both. Default: pdf
  --verbose               Enable verbose output
  --keep-db               Keep SQLite database after scan
```

### `sbom` - SBOM Generation
```
python -m securecodex.cli sbom [OPTIONS]

Options:
  --path PATH              Path to project (required)
  --output PATH            Output directory. Default: current directory
  --format FORMAT          SBOM format: json, cyclonedx, spdx. Default: json
  --verbose               Enable verbose output
```

### `add-rule` - Custom Rule Generator
```
python -m securecodex.add_rule [OPTIONS]

Options:
  --list-languages         List all supported languages
  --language LANG          Target language (e.g., python, javascript)
  --type TYPE              Rule type: taint, pattern, ast. Default: taint
  --output FILE            Output file path. Default: custom_rule.yaml
  --show-example EXAMPLE   Show example rule (python-sqli, javascript-xss, etc.)
```

### `sync` - Rule Synchronization
```
python -m securecodex.cli sync [OPTIONS]

Options:
  --rules-dir PATH         Local directory to store rules. Default: rules
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
