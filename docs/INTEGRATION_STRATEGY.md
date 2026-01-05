# SecureCodeX v2: Integration & Rule Strategy

This document outlines the strategy for integrating and reusing detection logic from existing SAST tools (Semgrep, CodeQL, and Horusec) into the SecureCodeX v2 engine.

## 1. Rule Adaptation & Reuse

### 1.1 Semgrep Rule Bridge
*   **Mechanism:** SecureCodeX v2 will natively support the Semgrep YAML format for Phase 1 (Syntactic) and Phase 3 (Taint) analysis.
*   **Transpilation:** A rule converter will translate Semgrep `pattern-sources` and `pattern-sinks` into SecureCodeX's internal DFG (Data Flow Graph) nodes.
*   **Optimization:** Rules will be tagged with a "Pre-filter" keyword to enable L0 fast-skipping.

### 1.2 CodeQL Logic Mapping
*   **Challenge:** QL is a logic language, while SecureCodeX uses a graph-based analysis engine.
*   **Strategy:** We will implement "Semantic Templates" that mirror the behavior of CodeQL standard libraries (e.g., `Escaping::Range`, `DataFlow::PathGraph`).
*   **Data Models:** Standardizing on a relational model internally that allows running "Constraint Checks" equivalent to CodeQL predicates.

### 1.3 Horusec Analyzer Profiles
*   **Strategy:** Maintain a set of `AnalyzerProfiles` that define how to execute, parse, and normalize output from third-party tools.
*   **Profiles:**
    - `python-bandit`: High-volume, low-confidence patterns.
    - `go-gosec`: Language-specific security checks.
    - `node-npmaudit`: Dependency-based vulnerability matching.

## 2. Rule Execution Phasing

Rules are executed in waves to optimize for performance:

1.  **Fast Track:** Rules that only require `L1` parsing. Results are reported immediately to the UI.
2.  **Deep Track:** Taint rules that require `L3` cross-procedural analysis. These run in the background.
3.  **Audit Track:** High-noise rules that require manual review (marked as `CONFIDENCE: LOW`).

## 3. Findings Correlation & Deduplication

### 3.1 The Correlation ID
Every finding is assigned a `CorrelationID` based on:
`Language + FilePath + LineNumber + SinkPattern + VulnerabilityCategory`

### 3.2 Finding Merging
*   **Promotion:** If a Phase 1 finding (potential vulns) matches a Phase 3 verified path, the confidence is promoted to `CRITICAL`.
*   **Deduplication:** Multiple tools reporting the same line (e.g., Semgrep and Bandit both finding hardcoded keys) are collapsed into a single entry with "Multiple Scanners Verified" badge.

## 4. Normalization Layer

SecureCodeX v2 uses a strict JSON schema for all findings:

```json
{
  "id": "SCX-2026-001",
  "category": "Injection/SQL",
  "confidence": "HIGH",
  "severity": "CRITICAL",
  "origin": "NativeTaintEngine",
  "correlates": ["semgrep-rule-sqli", "bandit-B608"],
  "location": {
    "file": "app/db.py",
    "line": 15,
    "column": 10
  },
  "trace": [
    {"pos": "source", "file": "app/api.py", "line": 5, "snippet": "user_id = request.args.get('id')"},
    {"pos": "propagate", "file": "app/logic.py", "line": 12, "snippet": "return self.db.query(user_id)"},
    {"pos": "sink", "file": "app/db.py", "line": 15, "snippet": "f\"SELECT * FROM users WHERE id = {uid}\""}
  ]
}
```
