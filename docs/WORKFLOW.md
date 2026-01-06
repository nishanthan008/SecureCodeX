# SecureCodeX-CLI Professional Workflow & Architecture

![SecureCodeX Professional Architecture Diagram](file:///C:/Users/Hp/.gemini/antigravity/brain/428078b7-a8ec-4950-8461-20dc5a1cfd82/securecodex_architecture_diagram_1767699674874.png)

This document provides a technical deep-dive into the SecureCodeX-CLI architecture, scanning pipeline, and data flow mechanisms.

## 1. High-Level System Architecture

The following diagram illustrates the interaction between the CLI user interface, the orchestration engine, and the core analysis components.

```mermaid
graph TD
    User["CLI User / CI Pipeline"] -- "Command/Config" --> CLI["CLI Orchestrator (scans.py/main.py)"]
    
    subgraph Core ["Scanning Core (Engine V3)"]
        CLI -- "Scan Request" --> Orchestrator["Engine V3 Orchestrator"]
        Orchestrator -- "Rules" --> DSL["DSL Parser (YAML)"]
        Orchestrator -- "Pre-filter" --> L0["L0: Grep-based Filter"]
        Orchestrator -- "Parsing" --> AST["AST Parser (Tree-Sitter)"]
        Orchestrator -- "Pattern Match" --> L1["L1: Structural Matcher"]
        Orchestrator -- "Data Flow" --> L2["L2: Taint Analysis Engine"]
    end
    
    subgraph Enhancement ["Logic Enhancement Layer"]
        L2 -- "Raw Findings" --> Processor["Findings Processor (SCB Logic)"]
        Processor -- "Context" --> Sanitizer["Sanitizer Library"]
        Processor -- "Scoring" --> Confidence["Confidence Calculator"]
    end
    
    subgraph Data ["Persistence & Output"]
        Confidence -- "Filtered Findings" --> DB["SQLite (findings.db)"]
        DB -- "Export" --> Report["PDF/JSON Generator"]
    end
    
    Report --> User
```

## 2. Engine V3: 5-Phase Analysis Pipeline

SecureCodeX employs a high-accuracy, multi-stage detection pipeline to balance performance and precision.

```mermaid
flowchart LR
    Start([Source File]) --> L0[Phase 1: L0 Filter]
    L0 -- "Heuristic Match" --> L1[Phase 2: AST Parsing]
    L1 -- "Token Tree" --> L2[Phase 3: Structural Match]
    L2 -- "Vulnerable Pattern" --> L3[Phase 4: Taint Analysis]
    L3 -- "Reachability Check" --> L4[Phase 5: Post-Processing]
    L4 -- "Enriched Result" --> End([Final Finding])
    
    L0 -- "No Skip" --> Skip([Skip File])
    L1 -- "Parse Error" --> Regex[Regex Fallback]
    Regex --> L4
```

### Phase Details:
- **Phase 1 (L0 Filter)**: Rapid grep-based pre-filtering to skip irrelevant rules.
- **Phase 2 (AST Parsing)**: Conversion of source code into an Abstract Syntax Tree using `tree-sitter`.
- **Phase 3 (L1 Structural Match)**: Advanced pattern matching (metavariables, ellipses) to find dangerous code structures.
- **Phase 4 (L2 Taint Analysis)**: Deep data-flow tracking from source (user input) to sink (dangerous function).
- **Phase 5 (Post-Processing)**: Severity normalization, metadata injection (CWE/OWASP), and false-positive reduction via context analysis.

## 3. Taint Analysis Lifecycle

The following sequence diagram shows how data flow is verified across the system.

```mermaid
sequenceDiagram
    participant E as EngineV3
    participant T as TaintEngine
    participant S as SanitizerLib
    participant C as ConfidenceCalc

    E->>T: Detect Source-to-Sink Path
    T->>T: Build CFG/Data-Flow Graph
    T->>S: Check Path for Sanitizers
    S-->>T: Sanitization Rating (Strong/Weak/Missing)
    T->>E: Return Finding + Trace
    E->>C: Calculate Final Confidence
    C->>C: Apply Reachability Boost (+15)
    C->>C: Apply Multi-Engine Synergy (+10)
    C-->>E: Confidence Score (0-100)
```

## 4. Key Component Responsibilities

| Component | Responsibility |
| :--- | :--- |
| **DSLParser** | Ingests YAML rules and converts them into internal `Rule` objects. |
| **EngineV3** | Orchestrates the entire scanning lifecycle for each file. |
| **FindingsProcessor** | Normalizes severities and injects rich metadata (CWE/OWASP IDs). |
| **SanitizerLibrary** | Cross-language database of safety functions and their effectiveness. |
| **ConfidenceCalculator** | Implementation of the 0-100 weighted scoring model for findings. |
| **PDFReportGenerator** | Professional report rendering with vulnerability descriptions and remediations. |
