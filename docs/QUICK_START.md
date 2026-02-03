# SecureCodeX CLI - Quick Start Guide

## Installation

```bash
git clone https://github.com/nishanthan008/SecureCodeX.git
cd SecureCodeX
pip install -e .
```

---

## Quick Commands

### 1. Security Scan
Scan your code for vulnerabilities:
```bash
# Scan current directory
python -m securecodex.cli scan --path .

# Scan specific languages (faster)
python -m securecodex.cli scan --path . --languages python,javascript

# Generate JSON report
python -m securecodex.cli scan --path . --format json
```

### 2. SBOM Generation
Generate Software Bill of Materials:
```bash
# Generate SBOM
python -m securecodex.cli sbom --path .

# Save to specific directory
python -m securecodex.cli sbom --path . --output ./sbom-reports
```

### 3. Create Custom Rules
Generate rule templates:
```bash
# List supported languages
python -m securecodex.add_rule --list-languages

# Generate rule template
python -m securecodex.add_rule --language python --type taint --output my_rule.yaml

# Show examples
python -m securecodex.add_rule --show-example python-sqli
```

---

## Common Workflows

### For Developers
```bash
# Quick security check before commit
python -m securecodex.cli scan --path . --languages python --format json
```

### For Security Teams
```bash
# Comprehensive scan
python -m securecodex.cli scan --path /project --format both

# Generate SBOM for compliance
python -m securecodex.cli sbom --path /project --output ./compliance
```

### For CI/CD
```bash
# Fast language-specific scan
python -m securecodex.cli scan --path . --languages python,javascript --format json

# Weekly SBOM generation
python -m securecodex.cli sbom --path . --format json
```

---

## Documentation

- **[Scan Command](docs/SCAN_DOCUMENTATION.md)** - Complete scan command reference
- **[SBOM Command](docs/SBOM_DOCUMENTATION.md)** - SBOM generation guide
- **[CLI Reference](docs/CLI_REFERENCE.md)** - All CLI commands
- **[Custom Rules](docs/RULES_GUIDE.md)** - Creating custom security rules

---

## Key Features

✅ **80% faster** with `--languages` flag  
✅ **60% less memory** for single-language scans  
✅ **88+ vulnerability patterns** across 7 languages  
✅ **SBOM generation** for supply chain security  
✅ **Custom rule templates** for project-specific needs  

---

## Support

- GitHub: https://github.com/nishanthan008/SecureCodeX
- Issues: https://github.com/nishanthan008/SecureCodeX/issues
