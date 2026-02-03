"""
Rule Template Generator for SecureCodeX
Helps users create custom security rules with proper structure
"""

import os
import sys
import argparse

# Supported languages
SUPPORTED_LANGUAGES = [
    'python', 'javascript', 'typescript', 'java', 'kotlin', 
    'php', 'go', 'csharp', 'ruby', 'c', 'cpp', 'rust',
    'swift', 'bash', 'html', 'yaml', 'json'
]

# Rule templates
TAINT_RULE_TEMPLATE = """rules:
  - id: custom-{language}-taint-rule
    name: "Custom {language_title} Taint Rule"
    description: "Describe what vulnerability this rule detects"
    severity: CRITICAL  # Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
    languages: [{language}]
    mode: taint
    
    # Define where untrusted data comes from (sources)
    pattern-sources:
      - pattern: request.get(...)  # Example: HTTP request parameter
      - pattern: user_input(...)    # Example: User input function
    
    # Define dangerous operations (sinks)
    pattern-sinks:
      - pattern: eval(...)          # Example: Code execution
      - pattern: execute_query(...) # Example: Database query
    
    # Define sanitization functions (optional)
    pattern-sanitizers:
      - pattern: sanitize(...)      # Example: Input sanitizer
      - pattern: escape(...)        # Example: Output escaper
    
    message: "Describe the security issue and remediation"
    metadata:
      cwe: CWE-XXX  # Common Weakness Enumeration ID
      owasp: A0X:2021-Category  # OWASP Top 10 category
      confidence: 0.9  # Confidence score (0.0 to 1.0)
"""

PATTERN_RULE_TEMPLATE = """rules:
  - id: custom-{language}-pattern-rule
    name: "Custom {language_title} Pattern Rule"
    description: "Describe what this pattern detects"
    severity: HIGH  # Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
    languages: [{language}]
    mode: pattern
    
    # Define the dangerous pattern to match
    pattern: dangerous_function(...)
    
    # Optional: Additional patterns (any match triggers the rule)
    # patterns:
    #   - pattern: risky_operation(...)
    #   - pattern: unsafe_call(...)
    
    message: "Describe why this pattern is dangerous and how to fix it"
    metadata:
      cwe: CWE-XXX
      owasp: A0X:2021-Category
      confidence: 0.85
"""

AST_RULE_TEMPLATE = """rules:
  - id: custom-{language}-ast-rule
    name: "Custom {language_title} AST Rule"
    description: "Describe what AST structure this detects"
    severity: MEDIUM  # Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
    languages: [{language}]
    mode: ast
    
    # Define AST node type to match
    ast-type: function_definition  # Example: function definition node
    
    # Optional: Additional constraints
    # ast-constraints:
    #   - name: starts_with_unsafe
    #   - parameter_count: "> 5"
    
    message: "Describe the issue detected by this AST rule"
    metadata:
      cwe: CWE-XXX
      confidence: 0.75
"""

EXAMPLES = {
    'python-sqli': """# Example: Python SQL Injection Detection
rules:
  - id: python-custom-sqli
    name: "Custom Python SQL Injection"
    description: "Detects SQL injection in custom database wrapper"
    severity: CRITICAL
    languages: [python]
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: db.execute(...)
      - pattern: cursor.execute(...)
    pattern-sanitizers:
      - pattern: int(...)
      - pattern: escape_sql(...)
    message: "SQL injection: use parameterized queries"
    metadata:
      cwe: CWE-89
      owasp: A03:2021-Injection
      confidence: 0.95
""",
    'javascript-xss': """# Example: JavaScript XSS Detection
rules:
  - id: javascript-custom-xss
    name: "Custom JavaScript XSS"
    description: "Detects XSS in custom rendering function"
    severity: HIGH
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: req.query.$PARAM
      - pattern: req.body.$PARAM
    pattern-sinks:
      - pattern: customRender(...)
      - pattern: element.innerHTML = ...
    pattern-sanitizers:
      - pattern: sanitizeHtml(...)
      - pattern: DOMPurify.sanitize(...)
    message: "XSS: sanitize user input before rendering"
    metadata:
      cwe: CWE-79
      owasp: A03:2021-Injection
      confidence: 0.9
""",
    'java-command-injection': """# Example: Java Command Injection
rules:
  - id: java-custom-command-injection
    name: "Custom Java Command Injection"
    description: "Detects command injection in custom executor"
    severity: CRITICAL
    languages: [java, kotlin]
    mode: taint
    pattern-sources:
      - pattern: request.getParameter(...)
      - pattern: "@RequestParam $PARAM"
    pattern-sinks:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern: customExecutor.run(...)
    message: "Command injection: validate input before execution"
    metadata:
      cwe: CWE-78
      owasp: A03:2021-Injection
      confidence: 0.98
"""
}

def list_languages():
    """List all supported languages"""
    print("\n[SUPPORTED LANGUAGES]")
    print("=" * 60)
    for i, lang in enumerate(SUPPORTED_LANGUAGES, 1):
        print(f"  {i:2d}. {lang}")
    print("=" * 60)
    print(f"\nTotal: {len(SUPPORTED_LANGUAGES)} languages supported\n")

def show_example(example_type: str):
    """Show example rule"""
    if example_type in EXAMPLES:
        print("\n" + "=" * 60)
        print(f"  EXAMPLE: {example_type.upper()}")
        print("=" * 60)
        print(EXAMPLES[example_type])
    else:
        print(f"\n[ERROR] Unknown example type: {example_type}")
        print(f"Available examples: {', '.join(EXAMPLES.keys())}\n")

def generate_template(language: str, rule_type: str, output_file: str):
    """Generate a rule template"""
    if language not in SUPPORTED_LANGUAGES:
        print(f"\n[ERROR] Unsupported language: {language}")
        print(f"Use --list-languages to see supported languages\n")
        return
    
    # Select template
    templates = {
        'taint': TAINT_RULE_TEMPLATE,
        'pattern': PATTERN_RULE_TEMPLATE,
        'ast': AST_RULE_TEMPLATE
    }
    
    if rule_type not in templates:
        print(f"\n[ERROR] Unknown rule type: {rule_type}")
        print(f"Available types: {', '.join(templates.keys())}\n")
        return
    
    # Generate template content
    template = templates[rule_type]
    content = template.format(
        language=language,
        language_title=language.title()
    )
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("\n" + "=" * 60)
    print("  RULE TEMPLATE GENERATED")
    print("=" * 60)
    print(f"Language:  {language}")
    print(f"Rule Type: {rule_type}")
    print(f"Output:    {output_file}")
    print("=" * 60)
    print("\n[NEXT STEPS]")
    print("1. Edit the generated file to customize the rule")
    print("2. Update patterns, severity, and metadata")
    print("3. Place the file in the 'rules/' directory")
    print("4. Run a scan to test your custom rule\n")

def main():
    parser = argparse.ArgumentParser(
        description='SecureCodeX Rule Template Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List supported languages
  python -m securecodex.add_rule --list-languages
  
  # Generate a taint rule template for Python
  python -m securecodex.add_rule --language python --type taint --output my_rule.yaml
  
  # Show example rules
  python -m securecodex.add_rule --show-example python-sqli
  python -m securecodex.add_rule --show-example javascript-xss
        """
    )
    
    parser.add_argument(
        '--list-languages',
        action='store_true',
        help='List all supported languages'
    )
    
    parser.add_argument(
        '--language',
        type=str,
        help='Target language for the rule (e.g., python, javascript, java)'
    )
    
    parser.add_argument(
        '--type',
        type=str,
        choices=['taint', 'pattern', 'ast'],
        default='taint',
        help='Type of rule to generate (default: taint)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='custom_rule.yaml',
        help='Output file path (default: custom_rule.yaml)'
    )
    
    parser.add_argument(
        '--show-example',
        type=str,
        help='Show example rule (python-sqli, javascript-xss, java-command-injection)'
    )
    
    args = parser.parse_args()
    
    # Handle commands
    if args.list_languages:
        list_languages()
    elif args.show_example:
        show_example(args.show_example)
    elif args.language:
        generate_template(args.language, args.type, args.output)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
