import re
from typing import List, Dict
from ..models import Severity

class PatternDetector:
    def __init__(self):
        self.rules = []
        # Initialize default rules
        self._init_default_rules()
        self._add_extended_rules()

    def _init_default_rules(self):
        self.rules = [
            {
                "id": "HARDCODED_AWS_KEY",
                "name": "Hardcoded AWS Access Key",
                "pattern": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
                "description": "Possible hardcoded AWS Access Key detected.",
                "severity": Severity.CRITICAL,
                "remediation": "Use environment variables or a secrets manager."
            },
            {
                "id": "HARDCODED_AWS_SECRET",
                "name": "Hardcoded AWS Secret Key",
                "pattern": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
                "description": "Possible hardcoded AWS Secret Key detected.",
                "severity": Severity.CRITICAL,
                "remediation": "Use environment variables or a secrets manager."
            },
            {
                "id": "GENERIC_PASSWORD",
                "name": "Hardcoded Password",
                "pattern": r"(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
                "description": "Possible hardcoded password or secret detected.",
                "severity": Severity.HIGH,
                "remediation": "Do not hardcode secrets. Use environment variables."
            },
            {
                "id": "SQL_INJECTION_SIMPLE",
                "name": "Potential SQL Injection",
                "pattern": r"(?i)(select|insert|update|delete).+where.+\+\s*[a-zA-Z0-9_]+",
                "description": "Potential SQL injection via string concatenation.",
                "severity": Severity.HIGH,
                "remediation": "Use parameterized queries or ORM methods."
            },
            {
                "id": "EVAL_USAGE",
                "name": "Dangerous eval() Usage",
                "pattern": r"eval\s*\(",
                "description": "Usage of eval() is dangerous and can lead to RCE.",
                "severity": Severity.CRITICAL,
                "remediation": "Avoid eval(). Use safer alternatives like ast.literal_eval()."
            },
             {
                "id": "TODO_COMMENT",
                "name": "TODO Comment",
                "pattern": r"(?i)//\s*TODO|#\s*TODO",
                "description": "Leftover TODO comment.",
                "severity": Severity.INFO,
                "remediation": "Review and address the TODO item."
            }
        ]
        self.rules.extend([
            {
                "id": "GOOGLE_API_KEY",
                "name": "Google API Key",
                "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
                "description": "Possible Google API Key detected.",
                "severity": Severity.HIGH,
                "remediation": "Restrict API key usage and use secrets management."
            },
            {
                "id": "PRIVATE_KEY",
                "name": "Private Key Block",
                "pattern": r"-----BEGIN\s+(?:RSA|DSA|EC|PGP|OPENSSH|PRIVATE)\s+KEY-----",
                "description": "Private key block detected in source code.",
                "severity": Severity.CRITICAL,
                "remediation": "Remove private keys from source control immediately."
            },
            {
                "id": "FLASK_DEBUG",
                "name": "Flask Debug Mode",
                "pattern": r"app\.run\(.*debug\s*=\s*True.*\)",
                "description": "Flask application running in debug mode.",
                "severity": Severity.HIGH,
                "remediation": "Ensure debug mode is disabled in production."
            },
            {
                "id": "HARDCODED_IP",
                "name": "Hardcoded IP Address",
                "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                "description": "Potential hardcoded IP address.",
                "severity": Severity.LOW,
                "remediation": "Use DNS names or configuration files."
            },
            {
                "id": "REACT_DANGEROUS_HTML",
                "name": "React Dangerous HTML",
                "pattern": r"dangerouslySetInnerHTML",
                "description": "Usage of dangerouslySetInnerHTML exposes to XSS.",
                "severity": Severity.MEDIUM,
                "remediation": "Sanitize input or avoid using raw HTML."
            }
        ])

    def scan_content(self, content: str, file_path: str) -> List[Dict]:
        findings = []
        lines = content.split('\n')
        
        # Skip if line count is too massive (e.g. minified large files) to save time, 
        # but requested "no threshold" so primarily skip very long lines
        
        for rule in self.rules:
            try:
                regex = re.compile(rule['pattern'])
                for i, line in enumerate(lines):
                    # Skip very long lines (likely minified code or data)
                    if len(line) > 1000:
                        continue
                        
                    if regex.search(line):
                        # False positive check
                        if self._is_false_positive(line, rule, file_path):
                            continue
                            
                        findings.append({
                            "rule_id": rule['id'],
                            "name": rule['name'],
                            "description": rule['description'],
                            "severity": rule['severity'],
                            "file_path": file_path,
                            "line_number": i + 1,
                            "code_snippet": line.strip()[:200],
                            "remediation": rule['remediation']
                        })
            except re.error:
                print(f"Invalid regex for rule {rule['id']}")
                
        return findings

    def _is_false_positive(self, line: str, rule: dict, file_path: str) -> bool:
        """Check for common false positives"""
        stripped = line.strip()
        
        # Ignore comments
        if stripped.startswith(('#', '//', '*', '--')):
            return True
            
        # For IP addresses, ignore version numbers or semantic versioning
        if rule['id'] == 'HARDCODED_IP':
            # Ignore 0.0.0.0 or 127.0.0.1 often used in config/tests
            if '0.0.0.0' in line or '127.0.0.1' in line:
                return True
            # Ignore version-like strings (e.g. v1.2.3.4)
            if re.search(r'v\d+\.\d+\.\d+', line, re.IGNORECASE):
                return True
                
        # For generic password, ignore common test/placeholder vars if "test" or "example" in line
        if rule['id'] == 'GENERIC_PASSWORD':
            if any(x in line.lower() for x in ['test', 'example', 'mock', 'fake', 'dummy']):
                return True

        return False

    def _add_extended_rules(self):
        """Add rules for extended languages"""
        self.rules.extend([
            # PHP
            {
                "id": "PHP_DANGEROUS_FUNC",
                "name": "Dangerous PHP Function",
                "pattern": r"(?i)(exec|passthru|shell_exec|system|proc_open|popen)\s*\(",
                "description": "Use of dangerous PHP execution function.",
                "severity": Severity.CRITICAL,
                "remediation": "Avoid system execution functions. Use safer alternatives."
            },
            # C/C++
            {
                "id": "CPP_NON_SECURE_FUNC",
                "name": "Insecure C/C++ Function",
                "pattern": r"\b(strcpy|strcat|sprintf|gets)\b\s*\(",
                "description": "Use of insecure string function leading to buffer overflows.",
                "severity": Severity.HIGH,
                "remediation": "Use safe alternatives like strncpy, strncat, snprintf."
            },
            # Go
            {
                "id": "GO_SQL_INJECTION",
                "name": "Potential Go SQL Injection",
                "pattern": r"fmt\.Sprintf\s*\(\s*\"(.*SELECT|.*INSERT|.*UPDATE|.*DELETE).*%s",
                "description": "Constructing SQL queries with fmt.Sprintf can lead to injection.",
                "severity": Severity.HIGH,
                "remediation": "Use parameterized queries ($1, $2, etc)."
            },
            # Ruby
            {
                "id": "RUBY_CMD_INJECTION",
                "name": "Ruby Command Injection",
                "pattern": r"(?<!\w)(eval|system|exec|`)\b",
                "description": "Dynamic code execution in Ruby.",
                "severity": Severity.HIGH,
                "remediation": "Validate input and avoid dynamic execution."
            }
        ])
