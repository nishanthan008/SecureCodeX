# SecureCodeX SBOM Command Documentation

## Overview
The `sbom` command generates a Software Bill of Materials (SBOM) by scanning your project for dependencies and identifying vulnerable packages across multiple language ecosystems.

---

## Basic Usage

```bash
python -m securecodex.cli sbom --path <PATH> [OPTIONS]
```

---

## Command Options

### Required Arguments

| Option | Description | Example |
|--------|-------------|---------|
| `--path` | Path to project directory to scan | `--path /project` |

### Optional Arguments

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output` | string | `.` | Output directory for SBOM report |
| `--format` | choice | `json` | SBOM format: `json`, `cyclonedx`, or `spdx` |
| `--verbose` | flag | false | Enable detailed output |

---

## Usage Examples

### Example 1: Basic SBOM Generation
Generate SBOM for current directory:
```bash
python -m securecodex.cli sbom --path .
```

**Output:** `sbom_<project>.json`

### Example 2: Specify Output Directory
Save SBOM to specific location:
```bash
python -m securecodex.cli sbom --path /project --output ./sbom-reports
```

### Example 3: Verbose Output
See detailed dependency scanning progress:
```bash
python -m securecodex.cli sbom --path . --verbose
```

### Example 4: Different Formats
Generate SBOM in different formats (CycloneDX, SPDX - coming soon):
```bash
# JSON format (default)
python -m securecodex.cli sbom --path . --format json

# CycloneDX format (planned)
python -m securecodex.cli sbom --path . --format cyclonedx

# SPDX format (planned)
python -m securecodex.cli sbom --path . --format spdx
```

---

## Supported Dependency Files

SecureCodeX automatically detects and scans the following dependency manifest files:

### JavaScript/TypeScript
| File | Description |
|------|-------------|
| `package.json` | NPM package manifest |
| `package-lock.json` | NPM lock file |
| `yarn.lock` | Yarn lock file |
| `pnpm-lock.yaml` | PNPM lock file |

### Python
| File | Description |
|------|-------------|
| `requirements.txt` | Pip requirements |
| `Pipfile` | Pipenv manifest |
| `Pipfile.lock` | Pipenv lock file |
| `poetry.lock` | Poetry lock file |
| `setup.py` | Setup script |
| `pyproject.toml` | PEP 518 build config |

### Java
| File | Description |
|------|-------------|
| `pom.xml` | Maven project file |
| `build.gradle` | Gradle build script |
| `build.gradle.kts` | Gradle Kotlin DSL |
| `gradle.lockfile` | Gradle lock file |

### Ruby
| File | Description |
|------|-------------|
| `Gemfile` | Bundler manifest |
| `Gemfile.lock` | Bundler lock file |

### Go
| File | Description |
|------|-------------|
| `go.mod` | Go modules file |
| `go.sum` | Go checksum file |

### PHP
| File | Description |
|------|-------------|
| `composer.json` | Composer manifest |
| `composer.lock` | Composer lock file |

### Rust
| File | Description |
|------|-------------|
| `Cargo.toml` | Cargo manifest |
| `Cargo.lock` | Cargo lock file |

### C#/.NET
| File | Description |
|------|-------------|
| `packages.config` | NuGet packages |
| `*.csproj` | C# project file |
| `project.json` | .NET Core project |

### Swift
| File | Description |
|------|-------------|
| `Package.swift` | Swift package manifest |
| `Podfile` | CocoaPods manifest |
| `Podfile.lock` | CocoaPods lock file |

---

## SBOM Output Format

### JSON Structure
```json
{
  "sbom_version": "1.0",
  "tool": "SecureCodeX",
  "tool_version": "3.0.0",
  "project": "my-project",
  "scan_date": "2026-02-03T16:00:00Z",
  "scan_path": "/path/to/project",
  "summary": {
    "total_dependencies": 45,
    "vulnerable_dependencies": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "languages": ["python", "javascript"]
  },
  "dependencies_by_language": {
    "python": [
      {
        "file": "requirements.txt",
        "language": "python",
        "finding": {
          "package": "flask",
          "version": "2.0.0",
          "severity": "HIGH",
          "vulnerability": "CVE-2023-XXXX",
          "description": "Security vulnerability in Flask",
          "remediation": "Update to Flask 2.3.0 or later"
        }
      }
    ],
    "javascript": [
      {
        "file": "package.json",
        "language": "javascript",
        "finding": {
          "package": "lodash",
          "version": "4.17.15",
          "severity": "CRITICAL",
          "vulnerability": "CVE-2021-23337",
          "description": "Prototype pollution vulnerability",
          "remediation": "Update to lodash 4.17.21 or later"
        }
      }
    ]
  },
  "vulnerable_dependencies": [
    {
      "file": "requirements.txt",
      "language": "python",
      "finding": {
        "package": "flask",
        "version": "2.0.0",
        "severity": "HIGH",
        "vulnerability": "CVE-2023-XXXX"
      }
    }
  ]
}
```

---

## Console Output

```
============================================================
  SecureCodeX - SBOM Generator
============================================================
Scan Path: /path/to/project
Output Directory: ./sbom-reports
Output Format: json
============================================================

[INFO] Found 5 dependency manifest files

Scanning dependencies: 100%|██████████| 5/5 [00:03<00:00]

============================================================
 SBOM SUMMARY
============================================================
Total Dependencies:       45
Vulnerable Dependencies:  3
  CRITICAL:               1
  HIGH:                   2
  MEDIUM:                 0
  LOW:                    0
Languages:                python, javascript
============================================================

[OK] SBOM saved to: ./sbom-reports/sbom_my-project.json
```

---

## Use Cases

### 1. Supply Chain Security
Identify vulnerable dependencies before deployment:
```bash
python -m securecodex.cli sbom --path . --format json
```

### 2. Compliance & Auditing
Generate SBOM for compliance requirements (NTIA, Executive Order 14028):
```bash
python -m securecodex.cli sbom --path /production-app --output ./compliance
```

### 3. License Management
Track all dependencies and their licenses (future feature):
```bash
python -m securecodex.cli sbom --path . --include-licenses
```

### 4. Vulnerability Tracking
Monitor dependencies over time:
```bash
# Generate SBOM weekly
python -m securecodex.cli sbom --path . --output ./sbom-archive/$(date +%Y%m%d)
```

---

## CI/CD Integration

### GitHub Actions
```yaml
name: SBOM Generation

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install SecureCodeX
        run: pip install -e .
      
      - name: Generate SBOM
        run: |
          python -m securecodex.cli sbom \
            --path . \
            --format json \
            --output ./sbom
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v2
        with:
          name: sbom-report
          path: ./sbom/*.json
      
      - name: Check for Vulnerabilities
        run: |
          VULN_COUNT=$(jq '.summary.vulnerable_dependencies' ./sbom/*.json)
          if [ "$VULN_COUNT" -gt 0 ]; then
            echo "::warning::Found $VULN_COUNT vulnerable dependencies"
          fi
```

### GitLab CI
```yaml
sbom-scan:
  stage: security
  script:
    - pip install -e .
    - python -m securecodex.cli sbom --path . --format json --output ./sbom
  artifacts:
    paths:
      - sbom/*.json
    reports:
      dependency_scanning: sbom/*.json
  only:
    - schedules
    - main
```

### Jenkins
```groovy
pipeline {
    agent any
    triggers {
        cron('H 0 * * 0')  // Weekly
    }
    stages {
        stage('Generate SBOM') {
            steps {
                sh 'pip install -e .'
                sh 'python -m securecodex.cli sbom --path . --format json --output ./sbom'
            }
        }
        stage('Check Vulnerabilities') {
            steps {
                script {
                    def sbom = readJSON file: 'sbom/sbom_*.json'
                    def vulnCount = sbom.summary.vulnerable_dependencies
                    if (vulnCount > 0) {
                        unstable("Found ${vulnCount} vulnerable dependencies")
                    }
                }
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'sbom/*.json', allowEmptyArchive: true
        }
    }
}
```

---

## Comparison: scan vs sbom

| Feature | `scan` Command | `sbom` Command |
|---------|---------------|----------------|
| **Purpose** | Code security analysis | Dependency analysis |
| **Scans** | Source code vulnerabilities | Dependency vulnerabilities |
| **Output** | Security findings | SBOM + vulnerable deps |
| **Speed** | Medium (code analysis) | Fast (manifest parsing) |
| **Use Case** | Code review, SAST | Supply chain security |
| **CI/CD** | Every commit/PR | Weekly/monthly |

### When to Use Each

**Use `scan` when:**
- Reviewing code changes
- Looking for code-level vulnerabilities
- Performing SAST analysis
- Auditing custom code

**Use `sbom` when:**
- Tracking dependencies
- Compliance requirements
- Supply chain security
- License management
- Vulnerability monitoring

### Combined Workflow
```bash
# 1. Code security scan (every commit)
python -m securecodex.cli scan --path . --languages python --format json

# 2. SBOM generation (weekly)
python -m securecodex.cli sbom --path . --format json
```

---

## Troubleshooting

### Issue: No dependencies found
**Solution:**
1. Verify dependency files exist in the project
2. Check file names match supported patterns
3. Use `--verbose` to see which files are scanned

### Issue: Missing vulnerabilities
**Solution:**
1. Ensure dependency detector is up to date
2. Check if vulnerability database is current
3. Verify package versions in manifest files

### Issue: SBOM generation is slow
**Solution:**
1. Large projects may take longer
2. Network issues can slow vulnerability lookups
3. Use `--verbose` to identify bottlenecks

---

## Best Practices

1. **Generate SBOMs regularly** - Weekly or monthly
2. **Version control SBOMs** - Track changes over time
3. **Automate in CI/CD** - Integrate into pipelines
4. **Review vulnerable dependencies** - Address CRITICAL/HIGH first
5. **Keep dependencies updated** - Regular maintenance
6. **Archive SBOMs** - For compliance and auditing

---

## Future Features

- **CycloneDX format support** - Industry-standard SBOM format
- **SPDX format support** - Linux Foundation standard
- **License scanning** - Identify license compliance issues
- **Dependency graph visualization** - Visual dependency trees
- **SBOM diff** - Compare SBOMs across versions
- **Custom vulnerability sources** - Integrate private databases

---

## Related Commands

- [`scan`](SCAN_DOCUMENTATION.md) - Security code analysis
- [`add-rule`](ADD_RULE_DOCUMENTATION.md) - Create custom rules
- [`sync`](SYNC_DOCUMENTATION.md) - Synchronize rule sets

---

## Support

For issues, questions, or contributions:
- GitHub: https://github.com/nishanthan008/SecureCodeX
- Issues: https://github.com/nishanthan008/SecureCodeX/issues
