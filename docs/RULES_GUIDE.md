# Rules Guide: Writing Custom Patterns

SecureCodeX uses a powerful YAML-based Rule DSL inspired by Semgrep. This allows you to define complex security patterns and data flow rules without writing any Python code.

## 📄 Rule Structure

A rule file consists of a top-level `rules` list. Each rule has several mandatory and optional fields:

```yaml
rules:
  - id: my-custom-rule
    name: "Short Description"
    description: "Longer explanation of the issue."
    severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
    languages: [python, javascript, go, etc.]
    mode: pattern | taint  (default: pattern)
    # Match patterns go here...
    message: "Information to display when matched."
    metadata:
      cwe: CWE-XYZ
      confidence: 0.8
```

## 🎯 Pattern Matching (`mode: pattern`)

Structural pattern matching understands the syntax of the language.

### Simple Match
Matches any call to `eval()`:
```yaml
pattern: eval(...)
```

### Metavariables
Use `$VAR` to capture parts of a match and reuse them in the message.
```yaml
pattern: $OBJ.danger_method($ARG)
message: "Detected $OBJ using the dangerous method with $ARG."
```

## 🌊 Taint Analysis (`mode: taint`)

Taint analysis tracks data flow from a "Source" (user input) to a "Sink" (dangerous function).

### Taint Rule Example
```yaml
id: python-sqli
mode: taint
pattern-sources:
  - pattern: flask.request.args.get(...)
pattern-sinks:
  - pattern: db.execute($SQL)
pattern-sanitizers:
  - pattern: int(...)
message: "Untrusted input reaches SQL sink!"
```

### Taint Components:
- **`pattern-sources`**: Where the untrusted data enters the application.
- **`pattern-sinks`**: Where the untrusted data is used in a dangerous way.
- **`pattern-sanitizers`**: Functions or patterns that "clean" the data, breaking the taint path.

## 🔍 Pre-Filtering Optimization

SecureCodeX automatically extracts literal keywords from your patterns for high-speed pre-filtering. For example, if your pattern is `os.system(...)`, the engine will only parse files that contain the word `system`.

## 🧪 Testing Rules

You can test your custom rules by placing them in the `rules/` directory and running a scan:
```bash
securecodex scan --path ./test-code --verbose
```
