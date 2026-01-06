# SecureCodeX-CLI Professional Workflow & Architecture

![SecureCodeX Professional Architecture Diagram](/C:/Users/Hp/.gemini/antigravity/brain/428078b7-a8ec-4950-8461-20dc5a1cfd82/securecodex_proper_architecture_diagram_1767700192026.png)

This document provides a technical deep-dive into the SecureCodeX-CLI architecture, scanning pipeline, and data flow mechanisms.

## 1. High-Level System Architecture

The following diagram illustrates the interaction between the CLI user interface, the orchestration engine, and the core analysis components.

```mermaid
graph TD
    User["CLI User / CI Pipeline"] -- "securecodex scan" --> CLI["CLI Orchestrator"]
    
    subgraph Core ["Engine V3: Hybrid Multi-Phase Core"]
        CLI --> Orchestrator["Engine V3 Orchestrator"]
        Orchestrator --> L0["L0: Keyword-Based Filter"]
        Orchestrator --> AST["AST Parser (C/Python/JS/Go)"]
        Orchestrator --> L1["L1: Structural Pattern Matcher"]
        Orchestrator --> L2["L2: Inter-Procedural Taint Engine"]
    end
    
    subgraph PostProcessing ["Enhanced Post-Processing Layer"]
        L1 & L2 --> Findings["Raw Findings"]
        Findings --> Processor["Findings Processor (SCB Logic)"]
        Processor --> Sanitizer["Sanitizer Context Check"]
        Processor --> Confidence["Scoring Model (0-100)"]
    end
    
    subgraph Storage ["Persistence & Reporting"]
        Confidence --> DB[("SQLite Storage")]
        DB --> Report["PDF/JSON Generator"]
    end
    
    Report --> User
    
    style Core fill:#f0f8ff,stroke:#2563eb,stroke-width:2px
    style PostProcessing fill:#fef9c3,stroke:#eab308,stroke-width:2px
    style Storage fill:#f1f5f9,stroke:#475569,stroke-width:2px
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
