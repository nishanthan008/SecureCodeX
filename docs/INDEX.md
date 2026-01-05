# SecureCodeX-CLI Documentation

Welcome to the official documentation for **SecureCodeX-CLI**, an enterprise-grade Static Application Security Testing (SAST) tool. SecureCodeX-CLI is designed to help security engineers and developers identify vulnerabilities, sensitive information leaks, and insecure coding patterns with high precision.

## 🚀 Quick Navigation

- **[CLI Reference](file:///c:/Code/SecureCodeX-CLI/docs/CLI_REFERENCE.md)**: Detailed guide for `scan` and `sync` commands.
- **[Engine V3 (AST & Taint)](file:///c:/Code/SecureCodeX-CLI/docs/ENGINE_V3.md)**: Deep dive into the structural analysis and data flow engine.
- **[Rules Guide](file:///c:/Code/SecureCodeX-CLI/docs/RULES_GUIDE.md)**: How to write and customize security rules using our YAML DSL.
- **[Architecture Overview](file:///c:/Code/SecureCodeX-CLI/docs/ARCHITECTURE.md)**: Technical breakdown of the tool's internal workings.

## 🛠 Key Features

- **Structural Pattern Matching**: Powered by Tree-sitter for multi-language AST analysis.
- **Advanced Taint Analysis**: Track user-controlled data from sources to dangerous sinks.
- **Reachability Analysis**: Intelligently discard findings in unreachable code blocks.
- **Rule Synchronization**: Stay up-to-date with community-driven security rules.
- **Rich Reporting**: Comprehensive PDF and JSON reports with remediation guidance.

## 📋 Get Started

To get started with SecureCodeX-CLI, check out the [README](file:///c:/Code/SecureCodeX-CLI/README.md) for installation instructions and a basic usage guide. Once installed, you can run your first scan:

```bash
securecodex scan --path ./your-source-code
```
