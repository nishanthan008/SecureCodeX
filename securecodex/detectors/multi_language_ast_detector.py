import ast
import sys
from typing import List, Dict, Optional
from ..models import Severity

class MultiLanguageASTDetector:
    """
    AST-based vulnerability detection for multiple programming languages.
    Currently supports Python with extensible architecture for other languages.
    """
    
    def __init__(self):
        self.supported_languages = ['python']
        # Try to import optional language parsers
        self._init_optional_parsers()
    
    def _init_optional_parsers(self):
        """Initialize optional language parsers if available"""
        try:
            import esprima
            self.esprima = esprima
            self.supported_languages.append('javascript')
        except ImportError:
            self.esprima = None
        
        try:
            import javalang
            self.javalang = javalang
            self.supported_languages.append('java')
        except ImportError:
            self.javalang = None
    
    def scan_content(self, content: str, file_path: str, language: str = None) -> List[Dict]:
        """
        Scan content using AST analysis.
        
        Args:
            content: File content to scan
            file_path: Path to the file
            language: Programming language
        
        Returns:
            List of findings
        """
        if not language:
            language = self._detect_language(file_path)
        
        if language == 'python':
            return self._scan_python(content, file_path)
        elif language == 'javascript' and self.esprima:
            return self._scan_javascript(content, file_path)
        elif language == 'java' and self.javalang:
            return self._scan_java(content, file_path)
        
        return []
    
    def _detect_language(self, file_path: str) -> Optional[str]:
        """Detect language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'javascript',
            '.java': 'java'
        }
        
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        
        return None
    
    def _scan_python(self, content: str, file_path: str) -> List[Dict]:
        """Scan Python code using AST"""
        findings = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Detect dangerous function calls
                if isinstance(node, ast.Call):
                    findings.extend(self._check_python_call(node, file_path))
                
                # Detect dangerous imports
                elif isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                    findings.extend(self._check_python_import(node, file_path))
                
                # Detect hardcoded strings (potential secrets)
                elif isinstance(node, ast.Assign):
                    findings.extend(self._check_python_assignment(node, file_path))
                
                # Detect assert statements (should not be used for security)
                elif isinstance(node, ast.Assert):
                    findings.append({
                        "rule_id": "AST_ASSERT_SECURITY",
                        "name": "Assert Used for Security Check",
                        "description": "Assert statements are removed in optimized Python (-O flag).",
                        "severity": Severity.MEDIUM,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": "assert ...",
                        "remediation": "Use proper exception handling instead of assert for security checks."
                    })
        
        except SyntaxError:
            # Not valid Python code, skip
            pass
        except Exception as e:
            print(f"Python AST scan error in {file_path}: {e}")
        
        return findings
    
    def _check_python_call(self, node: ast.Call, file_path: str) -> List[Dict]:
        """Check Python function calls for vulnerabilities"""
        findings = []
        
        # eval() detection
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            findings.append({
                "rule_id": "AST_EVAL",
                "name": "Dangerous eval() Usage",
                "description": "eval() allows execution of arbitrary code.",
                "severity": Severity.CRITICAL,
                "file_path": file_path,
                "line_number": node.lineno,
                "code_snippet": "eval(...)",
                "remediation": "Avoid eval(). Use ast.literal_eval() for parsing literals."
            })
        
        # exec() detection
        if isinstance(node.func, ast.Name) and node.func.id == 'exec':
            findings.append({
                "rule_id": "AST_EXEC",
                "name": "Dangerous exec() Usage",
                "description": "exec() allows execution of arbitrary code.",
                "severity": Severity.CRITICAL,
                "file_path": file_path,
                "line_number": node.lineno,
                "code_snippet": "exec(...)",
                "remediation": "Avoid exec(). Refactor code to avoid dynamic execution."
            })
        
        # compile() with 'exec' mode
        if isinstance(node.func, ast.Name) and node.func.id == 'compile':
            if len(node.args) >= 3:
                if isinstance(node.args[2], ast.Constant) and node.args[2].value == 'exec':
                    findings.append({
                        "rule_id": "AST_COMPILE_EXEC",
                        "name": "Compile with Exec Mode",
                        "description": "compile() in exec mode can execute arbitrary code.",
                        "severity": Severity.HIGH,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": "compile(..., 'exec')",
                        "remediation": "Avoid dynamic code compilation."
                    })
        
        # subprocess with shell=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['call', 'Popen', 'run', 'check_output']:
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            findings.append({
                                "rule_id": "AST_SUBPROCESS_SHELL",
                                "name": "Subprocess with shell=True",
                                "description": "Using shell=True can lead to command injection.",
                                "severity": Severity.HIGH,
                                "file_path": file_path,
                                "line_number": node.lineno,
                                "code_snippet": "subprocess.call(..., shell=True)",
                                "remediation": "Set shell=False and pass arguments as a list."
                            })
            
            # pickle.load() / pickle.loads()
            if node.func.attr in ['load', 'loads']:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle':
                    findings.append({
                        "rule_id": "AST_PICKLE_LOAD",
                        "name": "Insecure Deserialization (Pickle)",
                        "description": "pickle.load() is unsafe and allows arbitrary code execution.",
                        "severity": Severity.CRITICAL,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": "pickle.load(...)",
                        "remediation": "Use safer formats like JSON or verify the source."
                    })
            
            # yaml.load() (unsafe)
            if node.func.attr == 'load':
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'yaml':
                    findings.append({
                        "rule_id": "AST_YAML_UNSAFE_LOAD",
                        "name": "Unsafe YAML Load",
                        "description": "yaml.load() allows arbitrary code execution.",
                        "severity": Severity.CRITICAL,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": "yaml.load(...)",
                        "remediation": "Use yaml.safe_load() instead."
                    })
            
            # os.system()
            if node.func.attr == 'system':
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                    findings.append({
                        "rule_id": "AST_OS_SYSTEM",
                        "name": "Dangerous os.system() Usage",
                        "description": "os.system() can lead to command injection.",
                        "severity": Severity.HIGH,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": "os.system(...)",
                        "remediation": "Use subprocess with argument lists instead."
                    })
            
            # SQL execution methods
            if node.func.attr in ['execute', 'executemany', 'raw']:
                # Check if using string formatting
                if node.args and isinstance(node.args[0], ast.JoinedStr):  # f-string
                    findings.append({
                        "rule_id": "AST_SQL_FSTRING",
                        "name": "SQL Query with f-string",
                        "description": "SQL query using f-string (SQL injection risk).",
                        "severity": Severity.CRITICAL,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": "execute(f'...')",
                        "remediation": "Use parameterized queries."
                    })
                elif node.args and isinstance(node.args[0], ast.BinOp):  # String concatenation
                    findings.append({
                        "rule_id": "AST_SQL_CONCAT",
                        "name": "SQL Query with String Concatenation",
                        "description": "SQL query using string concatenation (SQL injection risk).",
                        "severity": Severity.CRITICAL,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": "execute('...' + ...)",
                        "remediation": "Use parameterized queries."
                    })
        
        return findings
    
    def _check_python_import(self, node, file_path: str) -> List[Dict]:
        """Check Python imports for security issues"""
        findings = []
        
        # Check for dangerous imports
        dangerous_modules = {
            'pickle': ('CRITICAL', 'Pickle module allows arbitrary code execution during deserialization.'),
            'shelve': ('HIGH', 'Shelve uses pickle internally, which is unsafe.'),
            'dill': ('HIGH', 'Dill is similar to pickle and has the same security risks.'),
        }
        
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in dangerous_modules:
                    severity_str, desc = dangerous_modules[alias.name]
                    severity = getattr(Severity, severity_str)
                    findings.append({
                        "rule_id": f"AST_IMPORT_{alias.name.upper()}",
                        "name": f"Dangerous Import: {alias.name}",
                        "description": desc,
                        "severity": severity,
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "code_snippet": f"import {alias.name}",
                        "remediation": "Consider safer alternatives for serialization."
                    })
        
        return findings
    
    def _check_python_assignment(self, node: ast.Assign, file_path: str) -> List[Dict]:
        """Check Python assignments for hardcoded secrets"""
        findings = []
        
        # Check for potential hardcoded secrets
        secret_keywords = ['password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'token', 'private_key']
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # Check if variable name suggests a secret
                if any(keyword in var_name for keyword in secret_keywords):
                    # Check if assigned a string literal
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 3:  # Ignore very short strings
                            findings.append({
                                "rule_id": "AST_HARDCODED_SECRET",
                                "name": "Hardcoded Secret in Assignment",
                                "description": f"Variable '{target.id}' assigned a hardcoded string value.",
                                "severity": Severity.HIGH,
                                "file_path": file_path,
                                "line_number": node.lineno,
                                "code_snippet": f"{target.id} = '...'",
                                "remediation": "Use environment variables or secrets management."
                            })
        
        return findings
    
    def _scan_javascript(self, content: str, file_path: str) -> List[Dict]:
        """Scan JavaScript code using esprima"""
        findings = []
        
        if not self.esprima:
            return findings
        
        try:
            tree = self.esprima.parseScript(content, {'loc': True})
            findings.extend(self._walk_js_ast(tree, file_path))
        except Exception as e:
            print(f"JavaScript AST scan error in {file_path}: {e}")
        
        return findings
    
    def _walk_js_ast(self, node, file_path: str) -> List[Dict]:
        """Walk JavaScript AST and detect vulnerabilities"""
        findings = []
        
        if hasattr(node, 'type'):
            # Detect eval()
            if node.type == 'CallExpression':
                if hasattr(node.callee, 'name') and node.callee.name == 'eval':
                    findings.append({
                        "rule_id": "AST_JS_EVAL",
                        "name": "JavaScript eval() Usage",
                        "description": "eval() allows execution of arbitrary code.",
                        "severity": Severity.CRITICAL,
                        "file_path": file_path,
                        "line_number": node.loc.start.line if hasattr(node, 'loc') else 0,
                        "code_snippet": "eval(...)",
                        "remediation": "Avoid eval(). Use JSON.parse() for parsing JSON."
                    })
                
                # Detect innerHTML usage
                if hasattr(node.callee, 'property') and hasattr(node.callee.property, 'name'):
                    if node.callee.property.name == 'innerHTML':
                        findings.append({
                            "rule_id": "AST_JS_INNERHTML",
                            "name": "Unsafe innerHTML Usage",
                            "description": "Setting innerHTML with user input can lead to XSS.",
                            "severity": Severity.HIGH,
                            "file_path": file_path,
                            "line_number": node.loc.start.line if hasattr(node, 'loc') else 0,
                            "code_snippet": "element.innerHTML = ...",
                            "remediation": "Use textContent or sanitize input."
                        })
        
        # Recursively walk child nodes
        for key in dir(node):
            if not key.startswith('_'):
                child = getattr(node, key)
                if isinstance(child, list):
                    for item in child:
                        findings.extend(self._walk_js_ast(item, file_path))
                elif hasattr(child, 'type'):
                    findings.extend(self._walk_js_ast(child, file_path))
        
        return findings
    
    def _scan_java(self, content: str, file_path: str) -> List[Dict]:
        """Scan Java code using javalang"""
        findings = []
        
        if not self.javalang:
            return findings
        
        try:
            tree = self.javalang.parse.parse(content)
            
            for path, node in tree:
                # Detect Runtime.exec()
                if isinstance(node, self.javalang.tree.MethodInvocation):
                    if node.member == 'exec':
                        findings.append({
                            "rule_id": "AST_JAVA_RUNTIME_EXEC",
                            "name": "Runtime.exec() Usage",
                            "description": "Runtime.exec() can lead to command injection.",
                            "severity": Severity.HIGH,
                            "file_path": file_path,
                            "line_number": node.position.line if hasattr(node, 'position') and node.position else 0,
                            "code_snippet": "Runtime.exec(...)",
                            "remediation": "Validate input and use ProcessBuilder."
                        })
        
        except Exception as e:
            print(f"Java AST scan error in {file_path}: {e}")
        
        return findings
