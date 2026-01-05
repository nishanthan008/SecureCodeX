# CLI Reference Guide

The `securecodex` command-line tool provides two main subcommands: `scan` for analyzing source code and `sync` for updating security rules.

## 🔍 `scan` Command

The `scan` command is the core functionality of SecureCodeX. It performs a comprehensive static analysis of the provided path.

### Usage
```bash
securecodex scan [OPTIONS]
```

### Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--path` | `PATH` | `.` | The path to the directory or file you want to scan. |
| `--output` | `PATH` | `.` | The directory where reports will be saved. |
| `--project-name` | `STRING` | *Directory Name* | A custom name for the project in the report. |
| `--format` | `pdf \| json \| both` | `pdf` | The output format for the security report. |
| `--verbose` | `Flag` | `False` | Enables detailed logging during the scan process. |
| `--keep-db` | `Flag` | `False` | Retains the internal SQLite database after the scan for debugging. |

### Examples

**Standard Scan:**
```bash
securecodex scan --path ./src
```

**JSON-only Report:**
```bash
securecodex scan --path ./project --format json --output ./findings
```

---

## 🔄 `sync` Command

The `sync` command allows you to synchronize your local rule set with external repositories, ensuring you have the latest vulnerability detection patterns.

### Usage
```bash
securecodex sync [OPTIONS]
```

### Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--rules-dir` | `PATH` | `rules` | The local directory where security rules are stored and synchronized. |

### Examples

**Update Rules:**
```bash
securecodex sync --rules-dir ./my-custom-rules
```

---

## ℹ️ Global Options

| Option | Description |
| :--- | :--- |
| `--version` | Displays the current version of SecureCodeX CLI. |
| `--help` | Displays help information for the command or subcommand. |
