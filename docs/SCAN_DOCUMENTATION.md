# SecureCodeX Scan Command Documentation

## Overview
The `scan` command performs comprehensive security analysis of your source code, detecting vulnerabilities such as SQL injection, XSS, command injection, and more across multiple programming languages.

---

## Basic Usage

```bash
python -m securecodex.cli scan --path <PATH> [OPTIONS]
```

---

## Command Options

### Required Arguments

| Option | Description | Example |
|--------|-------------|---------|
| `--path` | Path to file or directory to scan | `--path /project` |

### Optional Arguments

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--languages` | string | all | Comma-separated list of languages to scan | 
| `--output` | string | `.` | Output directory for reports |
| `--project-name` | string | directory name | Custom project name for reports |
| `--format` | choice | `pdf` | Report format: `pdf`, `json`, or `both` |
| `--verbose` | flag | false | Enable detailed output |
| `--keep-db` | flag | false | Keep SQLite database after scan |

---

## Usage Examples

### Example 1: Basic Scan
Scan current directory with default settings:
```bash
python -m securecodex.cli scan --path .
```

### Example 2: Scan Specific Languages
Scan only Python and JavaScript files:
```bash
python -m securecodex.cli scan --path /project --languages python,javascript
```

**Benefits:**
- 80% faster rule loading
- 60% less memory usage
- Focused results

### Example 3: Generate JSON Report
Scan and generate JSON output for CI/CD integration:
```bash
python -m securecodex.cli scan --path . --format json --output ./reports
```

### Example 4: Verbose Scan
Get detailed progress information:
```bash
python -m securecodex.cli scan --path . --verbose --languages python
```

### Example 5: Custom Project Name
Specify a custom project name for the report:
```bash
python -m securecodex.cli scan --path . --project-name "MyApp v2.0"
```

---

## Supported Languages

SecureCodeX supports security analysis for the following languages:

| Language | File Extensions | Frameworks Supported |
|----------|----------------|---------------------|
| **Python** | `.py` | Flask, Django, FastAPI |
| **JavaScript** | `.js` | Node.js, Express, React |
| **TypeScript** | `.ts` | Node.js, Express, Angular |
| **Java** | `.java` | Spring, Android |
| **Kotlin** | `.kt` | Spring, Android |
| **PHP** | `.php` | Laravel, Symfony |
| **Go** | `.go` | Gin, Echo |
| **C#** | `.cs` | ASP.NET |
| **Ruby** | `.rb` | Rails, Sinatra |
| **C/C++** | `.c`, `.cpp`, `.h` | Standard libraries |
| **Rust** | `.rs` | Standard libraries |
| **Swift** | `.swift` | iOS frameworks |
| **Bash** | `.sh` | Shell scripts |

---

## Vulnerability Detection

### Categories Detected

1. **Injection Vulnerabilities**
   - SQL Injection (SQLi)
   - NoSQL Injection
   - Command Injection
   - Code Injection
   - LDAP Injection
   - XPath Injection
   - Server-Side Template Injection (SSTI)

2. **Cross-Site Vulnerabilities**
   - Cross-Site Scripting (XSS) - Reflected, Stored, DOM
   - Cross-Site Request Forgery (CSRF)

3. **Server-Side Request Forgery (SSRF)**

4. **Path Traversal & File Vulnerabilities**
   - Directory Traversal
   - Local File Inclusion (LFI)
   - Remote File Inclusion (RFI)
   - Unrestricted File Upload

5. **Deserialization Vulnerabilities**
   - Insecure Deserialization
   - Pickle/YAML deserialization

6. **Authentication & Authorization**
   - Hardcoded Credentials
   - Weak Password Logic
   - Broken Access Control

7. **Cryptographic Issues**
   - Weak Encryption
   - Insecure Random Number Generation
   - Hardcoded Secrets

8. **Other Security Issues**
   - Open Redirect
   - Prototype Pollution (JavaScript)
   - Regular Expression Denial of Service (ReDoS)

---

## Output Formats

### PDF Report
Default format with comprehensive findings, charts, and recommendations.

**Features:**
- Executive summary
- Findings by severity
- Code snippets with line numbers
- Remediation guidance
- Severity distribution charts

**Example:**
```bash
python -m securecodex.cli scan --path . --format pdf
```

**Output:** `SecureCodeX_Report_<project>_<timestamp>.pdf`

### JSON Report
Machine-readable format for CI/CD integration and automation.

**Structure:**
```json
{
  "scan": {
    "id": 1,
    "project_name": "MyProject",
    "scan_path": "/path/to/project",
    "status": "COMPLETED",
    "start_time": "2026-02-03T10:00:00Z",
    "end_time": "2026-02-03T10:05:00Z"
  },
  "summary": {
    "total_findings": 68,
    "critical": 16,
    "high": 45,
    "medium": 7,
    "low": 0
  },
  "findings": [
    {
      "id": 1,
      "rule_id": "python-sqli-flask",
      "severity": "CRITICAL",
      "file_path": "app.py",
      "line_number": 42,
      "code_snippet": "cursor.execute(query)",
      "message": "SQL injection vulnerability",
      "confidence": 0.95
    }
  ]
}
```

**Example:**
```bash
python -m securecodex.cli scan --path . --format json --output ./reports
```

**Output:** `SecureCodeX_Report_<project>_<timestamp>.json`

---

## Scan Output

### Console Output
```
============================================================
  SecureCodeX - Security Source Code Analysis Tool
============================================================
Project: MyProject
Scan Path: /path/to/project
Output Directory: ./reports
============================================================

[INFO] Scanning languages: python, javascript

[INFO] Loaded 800 rules (filtered out 1606 rules for other languages)
[INFO] EngineV3 initialized with 800 rules.

Scanning: 100%|██████████| 150/150 [00:45<00:00]

============================================================
 SCAN SUMMARY
============================================================
Project: MyProject
Path: /path/to/project
Files Scanned: 150
Total Lines of Code: 12,450
Languages: .py, .js
Duration: 45.23s

------------------------------------------------------------
FINDINGS BY SEVERITY:
------------------------------------------------------------
  CRITICAL: 5
  HIGH:     12
  MEDIUM:   8
  LOW:      2
  INFO:     1

  TOTAL:    28
============================================================

[REPORT] Generating PDF report...
[OK] PDF report saved to: ./reports/SecureCodeX_Report_MyProject_20260203.pdf

[OK] Scan completed successfully!
```

---

## Performance Optimization

### Using --languages Flag
Significantly improve scan performance by specifying only the languages you need:

```bash
# Scan only Python (loads 480 rules instead of 2,406)
python -m securecodex.cli scan --path . --languages python
```

**Performance Gains:**
- **80% reduction** in loaded rules
- **60% reduction** in memory usage
- **40-50% faster** startup time

### Recommended Practices

1. **Single Language Projects:**
   ```bash
   python -m securecodex.cli scan --path . --languages python
   ```

2. **Web Applications (Frontend + Backend):**
   ```bash
   python -m securecodex.cli scan --path . --languages python,javascript,typescript
   ```

3. **Microservices:**
   ```bash
   # Scan each service separately
   python -m securecodex.cli scan --path ./auth-service --languages go
   python -m securecodex.cli scan --path ./api-service --languages python
   ```

---

## CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install SecureCodeX
        run: pip install -e .
      
      - name: Run Security Scan
        run: |
          python -m securecodex.cli scan \
            --path . \
            --languages python,javascript \
            --format json \
            --output ./reports
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: ./reports/*.json
```

### GitLab CI
```yaml
security-scan:
  stage: test
  script:
    - pip install -e .
    - python -m securecodex.cli scan --path . --languages python --format json
  artifacts:
    paths:
      - SecureCodeX_Report_*.json
    expire_in: 1 week
```

### Jenkins
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install -e .'
                sh 'python -m securecodex.cli scan --path . --languages python,java --format both'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'SecureCodeX_Report_*.pdf', allowEmptyArchive: true
            archiveArtifacts artifacts: 'SecureCodeX_Report_*.json', allowEmptyArchive: true
        }
    }
}
```

---

## Troubleshooting

### Issue: Scan is slow
**Solution:** Use the `--languages` flag to scan only relevant languages:
```bash
python -m securecodex.cli scan --path . --languages python
```

### Issue: Out of memory
**Solution:** 
1. Use `--languages` to reduce memory footprint
2. Scan subdirectories separately
3. Increase system memory allocation

### Issue: No findings detected
**Solution:**
1. Verify file extensions are supported
2. Check if files contain actual code (not just comments)
3. Use `--verbose` to see which files are being scanned

### Issue: False positives
**Solution:**
1. Review findings in the report
2. Create custom rules to exclude known safe patterns
3. Use code comments to suppress specific findings (feature coming soon)

---

## Best Practices

1. **Run scans regularly** - Integrate into CI/CD pipeline
2. **Use language filtering** - Faster scans with `--languages`
3. **Review all CRITICAL findings** - Address immediately
4. **Track trends** - Compare reports over time
5. **Customize rules** - Use `add-rule` command for project-specific patterns
6. **Keep database** - Use `--keep-db` for debugging and analysis

---

## Related Commands

- [`sbom`](SBOM_DOCUMENTATION.md) - Generate Software Bill of Materials
- [`add-rule`](ADD_RULE_DOCUMENTATION.md) - Create custom security rules
- [`sync`](SYNC_DOCUMENTATION.md) - Synchronize rule sets

---

## Support

For issues, questions, or contributions:
- GitHub: https://github.com/nishanthan008/SecureCodeX
- Issues: https://github.com/nishanthan008/SecureCodeX/issues
