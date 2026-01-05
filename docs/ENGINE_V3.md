# Engine V3: The Analysis Pipeline

Engine V3 is the core scanning engine of SecureCodeX, representing a significant evolution from simple regex-based detection to advanced structural and data-flow analysis.

## 🏗 Modular Architecture

The engine is built on a modular architecture that orchestrates several specialized components:

- **Parser Manager**: Utilizes **Tree-sitter** to generate high-precision Abstract Syntax Trees (AST) for multiple languages (Python, JavaScript, Go, etc.).
- **Matcher**: Performs structural pattern matching against the AST, allowing for complex queries that ignore whitespace, comments, and varying variable names.
- **Taint Engine**: Implements source-to-sink data flow analysis to track user-controlled input through the application.
- **Reachability Analyzer**: Filters out findings located in dead or unreachable code blocks (e.g., code after a return statement).
- **Sanitizer Library**: Evaluates the effectiveness of security controls and sanitizers found along a data flow path.

## 🔄 Multi-Phase Analysis

When a file is scanned, it goes through several distinct phases:

### 1. Pre-Filtering (L0)
To maximize performance, the engine first performs a rapid keyword-based pre-filter. If a file doesn't contain the literal keywords required by a rule, that rule is skipped before expensive AST parsing begins.

### 2. AST Parsing
The file content is parsed into an Abstract Syntax Tree using the appropriate Tree-sitter grammar for the detected language.

### 3. Structural Analysis
The `Matcher` evaluates "Pattern" rules. Unlike regex, structural matching understands the underlying code structure. For example, `os.system(...)` will match any call to `os.system` regardless of the arguments or formatting.

### 4. Taint Analysis
For rules defined in `mode: taint`, the engine:
1. Identifies **Sources** (e.g., `request.args`).
2. Identifies **Sinks** (e.g., `db.execute`).
3. Builds a **Data Flow Graph (DFG)**.
4. Searches for reachable paths from sources to sinks.
5. Checks for **Sanitizers** that might neutralize the threat.

### 5. Reachability Verification
Findings are passed to the `ReachabilityAnalyzer` to ensure they are actually executable. This significantly reduces false positives from template code or abandoned blocks.

### 6. Confidence Scoring
Finally, the `ConfidenceCalculator` assigns a score based on the detection method, source/sink reliability, and sanitization status.

## 📊 Performance Optimization

Engine V3 includes several optimizations for enterprise-scale scanning:
- **Hashing**: Files are hashed, and results are cached to skip re-scanning unchanged files.
- **Parallel Processing**: Scanning is distributed across available CPU cores.
- **Incremental DB**: The persistent SQLite database allows for fast incremental scans.
