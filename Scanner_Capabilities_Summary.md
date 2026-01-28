# SecureCodeX-CLI: Scanner Capabilities Summary

This document provides a comprehensive overview of the scanning engines, rule sets, and multi-language support provided by the SecureCodeX security analysis tool.

---

## 🚀 1. Core Analysis Engines
SecureCodeX utilizes a 5-layer analysis architecture to balance speed and depth:

1.  **Engine V3 (Orchestrator)**: The primary next-gen engine that coordinates the 5-phase analysis pipeline (L0 Filter, AST Parsing, Structural Match, Taint Analysis, and Post-Processing).
2.  **Pattern Detector**: A high-speed regex-based engine for baseline security issues and secrets detection.
3.  **Advanced Pattern Detector**: A feature-rich engine covering 17+ vulnerability categories with complex multi-line patterns.
4.  **Multi-Language AST Detector**: Performs structural analysis of code using Abstract Syntax Trees (AST) for Python, Java, and JavaScript.
5.  **Dependency Detector**: Scans package manifests (requirements.txt, package.json, etc.) against a database of known vulnerabilities.

---

## 📜 2. Rule Set Breakdown
The scanner's detection logic is powered by hundreds of unique rules categorized into three tiers:

| Tier | Type | Scope |
| :--- | :--- | :--- |
| **Built-in Detectors** | Hardcoded (Python) | 4 Core detectors with 500+ optimized patterns. |
| **Internal YAML Rules** | Dynamic Rules | 8 Dedicated rule files for high-fidelity detection. |
| **External Rule Sets** | Community/Synchronized | 31 Folders of Semgrep-compatible rules (e.g., AI, Cloud, K8s). |

### Core Internal Rule Files:
*   `bash_scripts.yaml`
*   `c_memory_safety.yaml`
*   `csharp_security.yaml`
*   `docker_best_practices.yaml`
*   `python_high_fidelity.yaml`
*   `python_rules.yaml`
*   `salesforce_apex.yaml`
*   `shadow_ai.yaml`

---

## 🌐 3. Language & Format Support
SecureCodeX-CLI supports a wide range of programming languages and infrastructure-as-code (IaC) formats:

*   **Primary Languages**: Python, JavaScript, TypeScript, Java, Go, PHP, C, C++, C#, Ruby, Apex, Rust.
*   **Scripts & Shell**: Bash, Shell, Powershell.
*   **Infrastructure & Formats**: Dockerfile, YAML, JSON, Terraform, Kubernetes, HTML.
*   **Legacy/Niche**: Clojure, Elixir, Kotlin, OCaml, Perl, Scala, Solidity, Swift.

---

## 🛠️ 4. Vulnerability Categories
The engines are designed to detect issues across the complete security spectrum:
*   **Injection**: SQLi, NoSQLi, Command Injection, LDAP, XXE.
*   **Broken Access Control**: Unvalidated redirects, insecure auth logic.
*   **Insecure Crypto**: Weak hashes (MD5/SHA1), hardcoded keys, ECB mode.
*   **Data Exposure**: Hardcoded secrets, PII leaks, insecure logging.
*   **Platform Specific**: Docker best practices, Salesforce Apex governors, Cloud misconfigurations.

---
> **Note**: This summary is generated based on the current architecture of SecureCodeX-CLI. For more details, refer to the `docs/ARCHITECTURE.md` file in the source repository.
