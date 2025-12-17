import ast
from typing import List, Dict
from ..models import Severity

class ASTDetector:
    def scan_content(self, content: str, file_path: str) -> List[Dict]:
        findings = []
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Detect eval()
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                        findings.append({
                            "rule_id": "AST_EVAL",
                            "name": "Dangerous eval() usage",
                            "description": "Usage of eval() allows execution of arbitrary code.",
                            "severity": Severity.CRITICAL,
                            "file_path": file_path,
                            "line_number": node.lineno,
                            "code_snippet": "eval(...)",
                            "remediation": "Avoid eval(). Use ast.literal_eval() if parsing literals."
                        })
                        
                    # Detect subprocess.call/Popen with shell=True
                    if isinstance(node.func, ast.Attribute) and node.func.attr in ['call', 'Popen', 'run']:
                        # Check for shell=True keyword argument
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                findings.append({
                                    "rule_id": "AST_SUBPROCESS_SHELL",
                                    "name": "Subprocess with shell=True",
                                    "description": "Using shell=True in subprocess can lead to command injection.",
                                    "severity": Severity.HIGH,
                                    "file_path": file_path,
                                    "line_number": node.lineno,
                                    "code_snippet": "subprocess.call(..., shell=True)",
                                    "remediation": "Set shell=False and pass arguments as a list."
                                })

                    # Detect pickle.load()
                    if isinstance(node.func, ast.Attribute) and node.func.attr == 'load':
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

        except SyntaxError:
            # Not valid Python code, skip
            pass
        except Exception as e:
            print(f"AST scan error in {file_path}: {e}")
            
        return findings
