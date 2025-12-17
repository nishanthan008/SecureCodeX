import re
from typing import List, Dict
from ..models import Severity

class AdvancedPatternDetector:
    """
    Comprehensive pattern-based vulnerability detector covering all major security categories.
    Supports multiple programming languages and vulnerability types.
    """
    
    def __init__(self):
        self.rules = []
        self._initialize_input_data_handling_rules()
        self._initialize_auth_authz_rules()
        self._initialize_crypto_rules()
        self._initialize_memory_resource_rules()
        self._initialize_api_logic_rules()
        self._initialize_data_exposure_rules()
        self._initialize_code_quality_rules()
        self._initialize_web_repo_rules()
        self._initialize_ssrf_rules()
        self._initialize_xxe_rules()
        self._initialize_file_inclusion_rules()
        self._initialize_mobile_security_rules()
        self._initialize_cloud_security_rules()
        self._initialize_supply_chain_rules()
        self._initialize_additional_injection_rules()

    
    def _initialize_input_data_handling_rules(self):
        """Input & Data Handling vulnerabilities"""
        self.rules.extend([
            # SQL Injection - Multiple variants
            {
                "id": "SQL_INJECTION_CONCAT",
                "name": "SQL Injection via String Concatenation",
                "pattern": r"(?i)(execute|query|exec)\s*\(\s*['\"]?\s*(select|insert|update|delete|drop).+\+.+\)",
                "description": "SQL query constructed using string concatenation with user input.",
                "severity": Severity.CRITICAL,
                "remediation": "Use parameterized queries or prepared statements.",
                "languages": ["python", "java", "javascript", "php", "csharp", "go"]
            },
            {
                "id": "SQL_INJECTION_FORMAT",
                "name": "SQL Injection via String Formatting",
                "pattern": r"(?i)(execute|query|exec)\s*\(\s*['\"]?\s*(select|insert|update|delete|drop).+(%s|%d|\{|\$)",
                "description": "SQL query using string formatting with potential user input.",
                "severity": Severity.CRITICAL,
                "remediation": "Use parameterized queries instead of string formatting.",
                "languages": ["python", "java", "javascript", "php", "csharp"]
            },
            {
                "id": "SQL_INJECTION_FSTRING",
                "name": "SQL Injection via f-string",
                "pattern": r"(?i)f['\"].*?(select|insert|update|delete|drop).*?\{.*?\}",
                "description": "SQL query using f-strings with variables (potential injection).",
                "severity": Severity.HIGH,
                "remediation": "Use parameterized queries, not f-strings for SQL.",
                "languages": ["python"]
            },
            
            # NoSQL Injection
            {
                "id": "NOSQL_INJECTION_MONGO",
                "name": "MongoDB NoSQL Injection",
                "pattern": r"(?i)(find|findOne|update|remove|aggregate)\s*\(\s*\{.*?\$where.*?\}",
                "description": "MongoDB query using $where operator with potential user input.",
                "severity": Severity.HIGH,
                "remediation": "Avoid $where operator, use query operators instead.",
                "languages": ["javascript", "typescript", "python"]
            },
            {
                "id": "NOSQL_INJECTION_EVAL",
                "name": "NoSQL Injection via eval",
                "pattern": r"(?i)\$where.*?eval\s*\(",
                "description": "NoSQL query using eval in $where clause.",
                "severity": Severity.CRITICAL,
                "remediation": "Never use eval in database queries.",
                "languages": ["javascript", "typescript"]
            },
            
            # Command Injection
            {
                "id": "COMMAND_INJECTION_SYSTEM",
                "name": "Command Injection via system()",
                "pattern": r"(?i)(system|exec|shell_exec|passthru|popen)\s*\(.+\+.+\)",
                "description": "System command execution with concatenated user input.",
                "severity": Severity.CRITICAL,
                "remediation": "Use subprocess with argument lists, not shell=True.",
                "languages": ["python", "php", "ruby", "perl"]
            },
            {
                "id": "COMMAND_INJECTION_BACKTICKS",
                "name": "Command Injection via Backticks",
                "pattern": r"`[^`]*\$[^`]*`",
                "description": "Shell command execution using backticks with variables.",
                "severity": Severity.CRITICAL,
                "remediation": "Use safe subprocess methods with argument arrays.",
                "languages": ["php", "ruby", "perl", "shell"]
            },
            {
                "id": "COMMAND_INJECTION_CHILD_PROCESS",
                "name": "Command Injection via child_process",
                "pattern": r"(?i)(exec|spawn|execSync)\s*\(\s*['\"].*?\$\{.*?\}",
                "description": "Node.js child_process with template literals containing variables.",
                "severity": Severity.CRITICAL,
                "remediation": "Use execFile or spawn with argument arrays.",
                "languages": ["javascript", "typescript"]
            },
            
            # LDAP Injection
            {
                "id": "LDAP_INJECTION",
                "name": "LDAP Injection",
                "pattern": r"(?i)(search|add|modify|delete).*?\(\s*['\"].*?[\+\&].*?['\"]",
                "description": "LDAP query constructed with string concatenation.",
                "severity": Severity.HIGH,
                "remediation": "Use parameterized LDAP queries and input validation.",
                "languages": ["java", "python", "csharp", "php"]
            },
            
            # Path Traversal
            {
                "id": "PATH_TRAVERSAL_DOTDOT",
                "name": "Path Traversal Attack",
                "pattern": r"(open|read|readFile|file_get_contents|include|require)\s*\([^)]*\.\.[/\\]",
                "description": "File operation with path traversal sequence (..).",
                "severity": Severity.HIGH,
                "remediation": "Validate and sanitize file paths, use allowlists.",
                "languages": ["python", "javascript", "php", "ruby", "java"]
            },
            {
                "id": "PATH_TRAVERSAL_ABSOLUTE",
                "name": "Unsafe Absolute Path Usage",
                "pattern": r"(open|read|readFile|file_get_contents)\s*\([^)]*[\+\&].*?['\"]",
                "description": "File operation with concatenated path (potential traversal).",
                "severity": Severity.MEDIUM,
                "remediation": "Use path.join() or os.path.join() with validation.",
                "languages": ["python", "javascript", "php", "ruby"]
            },
            
            # Unvalidated Redirects
            {
                "id": "OPEN_REDIRECT",
                "name": "Unvalidated Redirect",
                "pattern": r"(?i)(redirect|location|href)\s*[=:]\s*.*?(request\.|params\.|query\.|GET\[|POST\[)",
                "description": "Redirect using unvalidated user input.",
                "severity": Severity.MEDIUM,
                "remediation": "Validate redirect URLs against allowlist.",
                "languages": ["python", "javascript", "php", "ruby", "java"]
            },
            
            # XSS Vulnerabilities
            {
                "id": "XSS_REFLECTED",
                "name": "Reflected XSS",
                "pattern": r"(?i)(innerHTML|outerHTML|document\.write|eval)\s*[=\(].*?(request\.|params\.|query\.|\$_GET|\$_POST)",
                "description": "Direct output of user input to DOM without sanitization.",
                "severity": Severity.HIGH,
                "remediation": "Sanitize user input, use textContent instead of innerHTML.",
                "languages": ["javascript", "typescript", "php"]
            },
            {
                "id": "XSS_DOM_BASED",
                "name": "DOM-based XSS",
                "pattern": r"(?i)(location\.hash|location\.search|document\.referrer|window\.name).*?(innerHTML|outerHTML|eval|document\.write)",
                "description": "DOM-based XSS using untrusted sources.",
                "severity": Severity.HIGH,
                "remediation": "Validate and encode data from DOM sources.",
                "languages": ["javascript", "typescript"]
            },
            {
                "id": "XSS_TEMPLATE_INJECTION",
                "name": "Template Injection XSS",
                "pattern": r"(?i)(render_template_string|Template\(|eval\(.*?template)",
                "description": "Server-side template injection vulnerability.",
                "severity": Severity.CRITICAL,
                "remediation": "Never use user input in template rendering.",
                "languages": ["python", "javascript", "ruby", "java"]
            },
            
            # Deserialization Flaws
            {
                "id": "UNSAFE_DESERIALIZATION_PICKLE",
                "name": "Unsafe Pickle Deserialization",
                "pattern": r"pickle\.(load|loads)\s*\(",
                "description": "Unsafe deserialization using pickle (allows code execution).",
                "severity": Severity.CRITICAL,
                "remediation": "Use JSON or validate pickle sources. Consider safer alternatives.",
                "languages": ["python"]
            },
            {
                "id": "UNSAFE_DESERIALIZATION_YAML",
                "name": "Unsafe YAML Deserialization",
                "pattern": r"yaml\.(load|unsafe_load)\s*\(",
                "description": "Unsafe YAML deserialization (allows code execution).",
                "severity": Severity.CRITICAL,
                "remediation": "Use yaml.safe_load() instead of yaml.load().",
                "languages": ["python", "ruby"]
            },
            {
                "id": "UNSAFE_DESERIALIZATION_PHP",
                "name": "Unsafe PHP Unserialize",
                "pattern": r"unserialize\s*\(",
                "description": "PHP unserialize on untrusted data (object injection).",
                "severity": Severity.CRITICAL,
                "remediation": "Use JSON instead of serialize/unserialize.",
                "languages": ["php"]
            },
            {
                "id": "UNSAFE_DESERIALIZATION_JAVA",
                "name": "Unsafe Java Deserialization",
                "pattern": r"ObjectInputStream.*?readObject\s*\(",
                "description": "Java deserialization vulnerability.",
                "severity": Severity.CRITICAL,
                "remediation": "Validate serialized data, use allowlists for classes.",
                "languages": ["java"]
            },
            
            # Buffer Overflow
            {
                "id": "BUFFER_OVERFLOW_STRCPY",
                "name": "Buffer Overflow - strcpy",
                "pattern": r"\bstrcpy\s*\(",
                "description": "Use of unsafe strcpy function (buffer overflow risk).",
                "severity": Severity.HIGH,
                "remediation": "Use strncpy or safer alternatives like strlcpy.",
                "languages": ["c", "cpp"]
            },
            {
                "id": "BUFFER_OVERFLOW_SPRINTF",
                "name": "Buffer Overflow - sprintf",
                "pattern": r"\bsprintf\s*\(",
                "description": "Use of unsafe sprintf function (buffer overflow risk).",
                "severity": Severity.HIGH,
                "remediation": "Use snprintf with buffer size limits.",
                "languages": ["c", "cpp"]
            },
            {
                "id": "BUFFER_OVERFLOW_GETS",
                "name": "Buffer Overflow - gets",
                "pattern": r"\bgets\s*\(",
                "description": "Use of extremely unsafe gets function.",
                "severity": Severity.CRITICAL,
                "remediation": "Use fgets with buffer size limits.",
                "languages": ["c", "cpp"]
            },
            
            # Integer Overflow
            {
                "id": "INTEGER_OVERFLOW",
                "name": "Potential Integer Overflow",
                "pattern": r"(?i)(malloc|calloc|realloc|new\s+\w+\[)\s*\([^)]*[\+\*][^)]*\)",
                "description": "Memory allocation with arithmetic (integer overflow risk).",
                "severity": Severity.MEDIUM,
                "remediation": "Check for integer overflow before allocation.",
                "languages": ["c", "cpp", "java"]
            },
            
            # Unvalidated Input
            {
                "id": "UNVALIDATED_INPUT_DIRECT",
                "name": "Unvalidated User Input",
                "pattern": r"(?i)(request\.|params\.|query\.|GET\[|POST\[|argv\[).*?(execute|query|system|eval|exec)",
                "description": "Direct use of user input in dangerous functions.",
                "severity": Severity.HIGH,
                "remediation": "Always validate and sanitize user input.",
                "languages": ["python", "javascript", "php", "ruby", "java"]
            }
        ])
    
    def _initialize_auth_authz_rules(self):
        """Authentication & Authorization vulnerabilities"""
        self.rules.extend([
            # Hardcoded Credentials (Enhanced)
            {
                "id": "HARDCODED_PASSWORD",
                "name": "Hardcoded Password",
                "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]",
                "description": "Hardcoded password in source code.",
                "severity": Severity.CRITICAL,
                "remediation": "Use environment variables or secrets management.",
                "languages": ["all"]
            },
            {
                "id": "HARDCODED_API_KEY",
                "name": "Hardcoded API Key",
                "pattern": r"(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                "description": "Hardcoded API key in source code.",
                "severity": Severity.CRITICAL,
                "remediation": "Use environment variables or secrets vault.",
                "languages": ["all"]
            },
            {
                "id": "HARDCODED_TOKEN",
                "name": "Hardcoded Authentication Token",
                "pattern": r"(?i)(auth[_-]?token|bearer|jwt)\s*[:=]\s*['\"][^'\"]{20,}['\"]",
                "description": "Hardcoded authentication token.",
                "severity": Severity.CRITICAL,
                "remediation": "Generate tokens dynamically, never hardcode.",
                "languages": ["all"]
            },
            {
                "id": "HARDCODED_SECRET",
                "name": "Hardcoded Secret Key",
                "pattern": r"(?i)(secret[_-]?key|private[_-]?key|encryption[_-]?key)\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                "description": "Hardcoded secret or encryption key.",
                "severity": Severity.CRITICAL,
                "remediation": "Use secure key management systems.",
                "languages": ["all"]
            },
            
            # Weak Password Enforcement
            {
                "id": "WEAK_PASSWORD_POLICY",
                "name": "Weak Password Policy",
                "pattern": r"(?i)(password|passwd).*?(length|len|size)\s*[<>=]+\s*[1-5]",
                "description": "Weak password length requirement (less than 6 characters).",
                "severity": Severity.MEDIUM,
                "remediation": "Enforce minimum 8-12 character passwords with complexity.",
                "languages": ["all"]
            },
            {
                "id": "NO_PASSWORD_COMPLEXITY",
                "name": "Missing Password Complexity Check",
                "pattern": r"(?i)def\s+validate_password.*?:\s*return\s+len\(",
                "description": "Password validation only checks length, not complexity.",
                "severity": Severity.LOW,
                "remediation": "Check for uppercase, lowercase, numbers, and special chars.",
                "languages": ["python", "javascript", "ruby"]
            },
            
            # Session Handling
            {
                "id": "SESSION_FIXATION",
                "name": "Session Fixation Vulnerability",
                "pattern": r"(?i)session\s*\[\s*['\"]id['\"]\s*\]\s*=\s*.*?(request\.|params\.|GET\[)",
                "description": "Session ID set from user input (session fixation).",
                "severity": Severity.HIGH,
                "remediation": "Regenerate session ID after authentication.",
                "languages": ["python", "php", "ruby", "java"]
            },
            {
                "id": "NO_SESSION_TIMEOUT",
                "name": "Missing Session Timeout",
                "pattern": r"(?i)(session|cookie).*?(permanent|expires\s*=\s*None|max[_-]?age\s*=\s*0)",
                "description": "Session without expiration timeout.",
                "severity": Severity.MEDIUM,
                "remediation": "Set appropriate session timeout values.",
                "languages": ["python", "javascript", "php", "java"]
            },
            
            # Access Control
            {
                "id": "MISSING_AUTH_CHECK",
                "name": "Missing Authentication Check",
                "pattern": r"(?i)@(app\.route|router\.|get|post|put|delete)\s*\([^)]*\)(?!\s*@(login_required|authenticate|auth|requires_auth))",
                "description": "Route/endpoint without authentication decorator.",
                "severity": Severity.HIGH,
                "remediation": "Add authentication checks to protected endpoints.",
                "languages": ["python", "javascript", "ruby"]
            },
            {
                "id": "BROKEN_ACCESS_CONTROL",
                "name": "Broken Access Control",
                "pattern": r"(?i)(is_admin|is_superuser|role)\s*==\s*['\"]?true['\"]?(?!.*?and)",
                "description": "Simple boolean check for admin access (easily bypassed).",
                "severity": Severity.HIGH,
                "remediation": "Implement proper role-based access control.",
                "languages": ["all"]
            },
            
            # Privilege Escalation
            {
                "id": "PRIVILEGE_ESCALATION_SUDO",
                "name": "Unsafe Sudo Usage",
                "pattern": r"(?i)(sudo|su\s+-|runas).*?-c.*?\$",
                "description": "Sudo command with variable substitution (privilege escalation).",
                "severity": Severity.CRITICAL,
                "remediation": "Avoid dynamic sudo commands, use sudoers configuration.",
                "languages": ["shell", "python", "ruby"]
            },
            
            # Authentication Bypass
            {
                "id": "AUTH_BYPASS_COMMENTED",
                "name": "Commented Authentication Check",
                "pattern": r"(?i)#.*?(authenticate|login_required|check_auth|verify_token)",
                "description": "Authentication check commented out.",
                "severity": Severity.CRITICAL,
                "remediation": "Remove commented code or re-enable authentication.",
                "languages": ["python", "ruby", "shell"]
            },
            {
                "id": "AUTH_BYPASS_ALWAYS_TRUE",
                "name": "Authentication Always Returns True",
                "pattern": r"(?i)def\s+(authenticate|check_auth|verify).*?:\s*return\s+True",
                "description": "Authentication function always returns True.",
                "severity": Severity.CRITICAL,
                "remediation": "Implement proper authentication logic.",
                "languages": ["python", "javascript", "ruby"]
            }
        ])
    
    def _initialize_crypto_rules(self):
        """Cryptographic Issues"""
        self.rules.extend([
            # Weak Algorithms
            {
                "id": "WEAK_HASH_MD5",
                "name": "Weak Cryptographic Hash - MD5",
                "pattern": r"(?i)(md5|hashlib\.md5|Md5|MD5)\s*\(",
                "description": "Use of cryptographically broken MD5 hash.",
                "severity": Severity.HIGH,
                "remediation": "Use SHA-256 or stronger hash functions.",
                "languages": ["all"]
            },
            {
                "id": "WEAK_HASH_SHA1",
                "name": "Weak Cryptographic Hash - SHA1",
                "pattern": r"(?i)(sha1|hashlib\.sha1|Sha1|SHA1)\s*\(",
                "description": "Use of deprecated SHA1 hash (collision attacks exist).",
                "severity": Severity.MEDIUM,
                "remediation": "Use SHA-256 or SHA-3 instead.",
                "languages": ["all"]
            },
            {
                "id": "WEAK_CIPHER_DES",
                "name": "Weak Encryption - DES",
                "pattern": r"(?i)(DES|des)(?!c|ign|cri|eri)",
                "description": "Use of weak DES encryption algorithm.",
                "severity": Severity.HIGH,
                "remediation": "Use AES-256 or ChaCha20.",
                "languages": ["all"]
            },
            {
                "id": "WEAK_CIPHER_RC4",
                "name": "Weak Encryption - RC4",
                "pattern": r"(?i)\bRC4\b",
                "description": "Use of broken RC4 stream cipher.",
                "severity": Severity.HIGH,
                "remediation": "Use AES-GCM or ChaCha20-Poly1305.",
                "languages": ["all"]
            },
            {
                "id": "WEAK_CIPHER_ECB",
                "name": "Weak Cipher Mode - ECB",
                "pattern": r"(?i)(AES|DES).*?ECB",
                "description": "Use of ECB mode (not semantically secure).",
                "severity": Severity.MEDIUM,
                "remediation": "Use GCM, CBC, or CTR modes with proper IV.",
                "languages": ["all"]
            },
            
            # Hardcoded Keys
            {
                "id": "HARDCODED_ENCRYPTION_KEY",
                "name": "Hardcoded Encryption Key",
                "pattern": r"(?i)(aes|des|key).*?=\s*['\"][0-9a-fA-F]{16,}['\"]",
                "description": "Hardcoded encryption key in source code.",
                "severity": Severity.CRITICAL,
                "remediation": "Use key derivation functions and secure storage.",
                "languages": ["all"]
            },
            {
                "id": "HARDCODED_IV",
                "name": "Hardcoded Initialization Vector",
                "pattern": r"(?i)(iv|init.*?vector).*?=\s*['\"][0-9a-fA-F]{16,}['\"]",
                "description": "Hardcoded IV (should be random for each encryption).",
                "severity": Severity.HIGH,
                "remediation": "Generate random IV for each encryption operation.",
                "languages": ["all"]
            },
            
            # Weak Random
            {
                "id": "WEAK_RANDOM_MATH",
                "name": "Weak Random Number Generator",
                "pattern": r"Math\.random\s*\(",
                "description": "Use of Math.random() for security purposes (predictable).",
                "severity": Severity.MEDIUM,
                "remediation": "Use crypto.randomBytes() or crypto.getRandomValues().",
                "languages": ["javascript", "typescript"]
            },
            {
                "id": "WEAK_RANDOM_PYTHON",
                "name": "Weak Random - Python random module",
                "pattern": r"(?i)import\s+random(?!.*?secrets)|from\s+random\s+import",
                "description": "Use of random module for security (not cryptographically secure).",
                "severity": Severity.MEDIUM,
                "remediation": "Use secrets module for cryptographic randomness.",
                "languages": ["python"]
            },
            
            # Certificate Validation
            {
                "id": "DISABLED_SSL_VERIFICATION",
                "name": "Disabled SSL Certificate Verification",
                "pattern": r"(?i)(verify\s*=\s*False|SSL_VERIFY_NONE|InsecureRequestWarning|check_hostname\s*=\s*False)",
                "description": "SSL/TLS certificate verification disabled.",
                "severity": Severity.HIGH,
                "remediation": "Enable certificate verification for all HTTPS requests.",
                "languages": ["python", "java", "javascript", "csharp"]
            },
            {
                "id": "ACCEPT_ALL_CERTIFICATES",
                "name": "Accept All SSL Certificates",
                "pattern": r"(?i)(TrustAllCertificates|AcceptAllCertificates|trust.*?all|verify.*?none)",
                "description": "Configuration to accept all SSL certificates.",
                "severity": Severity.HIGH,
                "remediation": "Properly validate SSL certificates.",
                "languages": ["java", "csharp", "go"]
            }
        ])
    
    def _initialize_memory_resource_rules(self):
        """Memory & Resource Management (C/C++/Rust focused)"""
        self.rules.extend([
            # Use-after-free
            {
                "id": "USE_AFTER_FREE",
                "name": "Potential Use-After-Free",
                "pattern": r"(free|delete)\s*\([^)]+\).*?\n.*?\1",
                "description": "Pointer used after being freed (use-after-free).",
                "severity": Severity.CRITICAL,
                "remediation": "Set pointer to NULL after freeing, avoid use after free.",
                "languages": ["c", "cpp"]
            },
            
            # Double Free
            {
                "id": "DOUBLE_FREE",
                "name": "Potential Double Free",
                "pattern": r"(free|delete)\s*\(([^)]+)\).*?free\s*\(\2\)",
                "description": "Same pointer freed multiple times (double free).",
                "severity": Severity.CRITICAL,
                "remediation": "Set pointer to NULL after freeing.",
                "languages": ["c", "cpp"]
            },
            
            # Memory Leaks
            {
                "id": "MEMORY_LEAK_MALLOC",
                "name": "Potential Memory Leak",
                "pattern": r"(malloc|calloc|realloc|new)\s*\([^)]+\)(?!.*?(free|delete))",
                "description": "Memory allocated but no corresponding free/delete found.",
                "severity": Severity.MEDIUM,
                "remediation": "Ensure all allocated memory is freed.",
                "languages": ["c", "cpp"]
            },
            
            # Race Conditions
            {
                "id": "RACE_CONDITION_SHARED_STATE",
                "name": "Race Condition - Unprotected Shared State",
                "pattern": r"(?i)(global|static).*?(?!.*?(mutex|lock|synchronized|atomic))",
                "description": "Shared state without synchronization (race condition).",
                "severity": Severity.HIGH,
                "remediation": "Use mutexes, locks, or atomic operations.",
                "languages": ["c", "cpp", "java", "go", "rust"]
            },
            
            # Deadlocks
            {
                "id": "DEADLOCK_NESTED_LOCKS",
                "name": "Potential Deadlock - Nested Locks",
                "pattern": r"(lock|acquire).*?\n.*?(lock|acquire)",
                "description": "Nested lock acquisition (potential deadlock).",
                "severity": Severity.MEDIUM,
                "remediation": "Acquire locks in consistent order, use lock hierarchies.",
                "languages": ["c", "cpp", "java", "python", "go"]
            },
            
            # Resource Cleanup
            {
                "id": "MISSING_RESOURCE_CLEANUP",
                "name": "Missing Resource Cleanup",
                "pattern": r"(fopen|open|socket|connect)\s*\([^)]+\)(?!.*?(fclose|close))",
                "description": "Resource opened but not closed (resource leak).",
                "severity": Severity.MEDIUM,
                "remediation": "Use RAII or ensure resources are closed in finally blocks.",
                "languages": ["c", "cpp", "python", "java"]
            },
            {
                "id": "NO_FINALLY_BLOCK",
                "name": "Missing Finally Block for Cleanup",
                "pattern": r"try\s*\{[^}]*?(open|acquire|lock)[^}]*?\}(?!\s*finally)",
                "description": "Resource acquired in try block without finally cleanup.",
                "severity": Severity.LOW,
                "remediation": "Use finally block or context managers for cleanup.",
                "languages": ["python", "java", "javascript"]
            }
        ])
    
    def _initialize_api_logic_rules(self):
        """API & Logic Issues"""
        self.rules.extend([
            # Insecure Defaults
            {
                "id": "INSECURE_DEFAULT_DEBUG",
                "name": "Debug Mode Enabled",
                "pattern": r"(?i)(debug|DEBUG)\s*[:=]\s*True",
                "description": "Debug mode enabled (exposes sensitive information).",
                "severity": Severity.HIGH,
                "remediation": "Disable debug mode in production.",
                "languages": ["python", "javascript", "ruby"]
            },
            {
                "id": "INSECURE_DEFAULT_CORS",
                "name": "Insecure CORS Configuration",
                "pattern": r"(?i)(Access-Control-Allow-Origin|cors).*?[\'\"]?\*[\'\"]?",
                "description": "CORS allows all origins (*).",
                "severity": Severity.MEDIUM,
                "remediation": "Restrict CORS to specific trusted origins.",
                "languages": ["python", "javascript", "java", "csharp"]
            },
            
            # Error Handling
            {
                "id": "EMPTY_EXCEPTION_HANDLER",
                "name": "Empty Exception Handler",
                "pattern": r"(except|catch)\s*[^:]*:\s*(pass|;|\{\s*\})",
                "description": "Empty exception handler (silent failure).",
                "severity": Severity.MEDIUM,
                "remediation": "Log exceptions or handle them appropriately.",
                "languages": ["python", "javascript", "java", "csharp"]
            },
            {
                "id": "GENERIC_EXCEPTION_CATCH",
                "name": "Generic Exception Catching",
                "pattern": r"(?i)(except\s*:|catch\s*\(Exception|catch\s*\(Throwable)",
                "description": "Catching generic exceptions (masks specific errors).",
                "severity": Severity.LOW,
                "remediation": "Catch specific exception types.",
                "languages": ["python", "java", "csharp"]
            },
            {
                "id": "STACK_TRACE_EXPOSURE",
                "name": "Stack Trace Exposure",
                "pattern": r"(?i)(print|echo|console\.log|response\.write).*?(traceback|stack|exception|error)",
                "description": "Stack trace or error details exposed to user.",
                "severity": Severity.MEDIUM,
                "remediation": "Log errors server-side, show generic messages to users.",
                "languages": ["all"]
            },
            
            # Rate Limiting
            {
                "id": "MISSING_RATE_LIMIT",
                "name": "Missing Rate Limiting",
                "pattern": r"(?i)@(app\.route|post|get).*?(login|auth|api)(?!.*?(rate_limit|throttle|limiter))",
                "description": "API endpoint without rate limiting.",
                "severity": Severity.MEDIUM,
                "remediation": "Implement rate limiting on API endpoints.",
                "languages": ["python", "javascript", "ruby"]
            }
        ])
    
    def _initialize_data_exposure_rules(self):
        """Access & Data Exposure"""
        self.rules.extend([
            # Sensitive Data in Logs
            {
                "id": "PASSWORD_IN_LOGS",
                "name": "Password Logged",
                "pattern": r"(?i)(log|print|console|echo).*?(password|passwd|pwd)",
                "description": "Password or credential logged.",
                "severity": Severity.HIGH,
                "remediation": "Never log passwords or sensitive credentials.",
                "languages": ["all"]
            },
            {
                "id": "TOKEN_IN_LOGS",
                "name": "Token Logged",
                "pattern": r"(?i)(log|print|console|echo).*?(token|api[_-]?key|secret)",
                "description": "Authentication token or API key logged.",
                "severity": Severity.HIGH,
                "remediation": "Redact sensitive data from logs.",
                "languages": ["all"]
            },
            {
                "id": "SSN_IN_LOGS",
                "name": "SSN or PII Logged",
                "pattern": r"(?i)(log|print|console|echo).*?(ssn|social.*?security|credit.*?card)",
                "description": "Personally identifiable information (PII) logged.",
                "severity": Severity.HIGH,
                "remediation": "Never log PII, implement data masking.",
                "languages": ["all"]
            },
            
            # Secrets in Comments
            {
                "id": "SECRET_IN_COMMENT",
                "name": "Secret in Comment",
                "pattern": r"(?i)(#|//|/\*).*?(password|api[_-]?key|secret|token)\s*[:=]\s*['\"]?[a-zA-Z0-9]{8,}",
                "description": "Potential secret or credential in code comment.",
                "severity": Severity.MEDIUM,
                "remediation": "Remove secrets from comments and code.",
                "languages": ["all"]
            },
            
            # Environment Variables
            {
                "id": "ENV_VAR_EXPOSURE",
                "name": "Environment Variable Exposure",
                "pattern": r"(?i)(print|echo|console\.log|response).*?(process\.env|os\.environ|\$_ENV)",
                "description": "Environment variables exposed in output.",
                "severity": Severity.MEDIUM,
                "remediation": "Never expose environment variables to users.",
                "languages": ["all"]
            },
            
            # Internal APIs
            {
                "id": "INTERNAL_API_EXPOSED",
                "name": "Internal API Exposed",
                "pattern": r"(?i)@(app\.route|router).*?(/internal|/admin|/debug)(?!.*?@(login_required|auth))",
                "description": "Internal API endpoint without authentication.",
                "severity": Severity.HIGH,
                "remediation": "Protect internal endpoints with authentication.",
                "languages": ["python", "javascript", "ruby"]
            }
        ])
    
    def _initialize_code_quality_rules(self):
        """Code Quality / Maintainability Risks"""
        self.rules.extend([
            # Null Checks
            {
                "id": "MISSING_NULL_CHECK",
                "name": "Missing Null Check",
                "pattern": r"(\w+)\s*=.*?(?:get|find|query).*?\n.*?\1\.",
                "description": "Object used without null/undefined check.",
                "severity": Severity.LOW,
                "remediation": "Add null/undefined checks before using objects.",
                "languages": ["javascript", "java", "csharp"]
            },
            
            # Magic Numbers
            {
                "id": "MAGIC_NUMBER",
                "name": "Magic Number",
                "pattern": r"(?<![a-zA-Z0-9_])(if|while|for).*?[<>=!]+\s*[0-9]{2,}(?![a-zA-Z0-9_])",
                "description": "Magic number in conditional (should be named constant).",
                "severity": Severity.INFO,
                "remediation": "Replace magic numbers with named constants.",
                "languages": ["all"]
            },
            
            # Dead Code
            {
                "id": "UNREACHABLE_CODE",
                "name": "Unreachable Code",
                "pattern": r"(return|throw|break|continue)\s*;?\s*\n\s*(?![\}])",
                "description": "Code after return/throw statement (unreachable).",
                "severity": Severity.INFO,
                "remediation": "Remove unreachable code.",
                "languages": ["all"]
            },
            
            # TODO/FIXME
            {
                "id": "TODO_SECURITY",
                "name": "Security TODO",
                "pattern": r"(?i)(TODO|FIXME|XXX|HACK).*?(security|auth|crypto|password|token)",
                "description": "Security-related TODO comment.",
                "severity": Severity.LOW,
                "remediation": "Address security TODOs before production.",
                "languages": ["all"]
            }
        ])
    
    def _initialize_web_repo_rules(self):
        """Web & Repository-Specific Risks"""
        self.rules.extend([
            # CSRF
            {
                "id": "CSRF_MISSING_TOKEN",
                "name": "Missing CSRF Protection",
                "pattern": r"(?i)@(app\.route|post|put|delete)(?!.*?(csrf|token))",
                "description": "State-changing endpoint without CSRF protection.",
                "severity": Severity.HIGH,
                "remediation": "Implement CSRF tokens for state-changing operations.",
                "languages": ["python", "javascript", "ruby", "php"]
            },
            
            # Clickjacking
            {
                "id": "CLICKJACKING_NO_FRAME_OPTIONS",
                "name": "Missing X-Frame-Options",
                "pattern": r"(?i)response(?!.*?(X-Frame-Options|frame-options))",
                "description": "Response without X-Frame-Options header (clickjacking risk).",
                "severity": Severity.MEDIUM,
                "remediation": "Set X-Frame-Options: DENY or SAMEORIGIN.",
                "languages": ["python", "javascript", "java", "php"]
            },
            
            # Git Command Injection
            {
                "id": "GIT_COMMAND_INJECTION",
                "name": "Git Command Injection",
                "pattern": r"(?i)(git|svn|hg)\s+.*?\$\{.*?\}",
                "description": "Git command with variable substitution (injection risk).",
                "severity": Severity.HIGH,
                "remediation": "Validate input, use git libraries instead of shell commands.",
                "languages": ["shell", "javascript", "python"]
            },
            
            # File Upload DoS
            {
                "id": "LARGE_FILE_UPLOAD_DOS",
                "name": "Large File Upload DoS",
                "pattern": r"(?i)(upload|multipart)(?!.*?(max.*?size|limit|validate))",
                "description": "File upload without size limits (DoS risk).",
                "severity": Severity.MEDIUM,
                "remediation": "Implement file size limits and validation.",
                "languages": ["python", "javascript", "java", "php"]
            },
            
            # Workflow Race Conditions
            {
                "id": "WORKFLOW_RACE_CONDITION",
                "name": "Workflow Race Condition",
                "pattern": r"(?i)(check|verify).*?\n.*?(update|modify|delete)(?!.*?(lock|transaction))",
                "description": "Check-then-act pattern without synchronization (TOCTOU).",
                "severity": Severity.MEDIUM,
                "remediation": "Use transactions or locks for atomic operations.",
                "languages": ["all"]
            }
        ])
    
    def scan_content(self, content: str, file_path: str, language: str = None) -> List[Dict]:
        """
        Scan content for vulnerabilities using pattern matching.
        
        Args:
            content: File content to scan
            file_path: Path to the file being scanned
            language: Programming language (optional, for filtering rules)
        
        Returns:
            List of findings
        """
        findings = []
        lines = content.split('\n')
        
        for rule in self.rules:
            # Skip rules not applicable to this language
            if language and 'languages' in rule:
                rule_langs = rule['languages']
                if 'all' not in rule_langs and language not in rule_langs:
                    continue
            
            try:
                regex = re.compile(rule['pattern'], re.MULTILINE | re.DOTALL)
                
                # Search line by line for better line number accuracy
                for i, line in enumerate(lines):
                    if regex.search(line):
                        findings.append({
                            "rule_id": rule['id'],
                            "name": rule['name'],
                            "description": rule['description'],
                            "severity": rule['severity'],
                            "file_path": file_path,
                            "line_number": i + 1,
                            "code_snippet": line.strip()[:200],  # Limit snippet length
                            "remediation": rule['remediation']
                        })
                
            except re.error as e:
                print(f"Invalid regex for rule {rule['id']}: {e}")
        
        return findings
    
    def get_rule_count(self) -> int:
        """Get total number of detection rules"""
        return len(self.rules)
    
    def get_rules_by_category(self) -> Dict[str, int]:
        """Get rule count by category"""
        categories = {
            "Input & Data Handling": 0,
            "Authentication & Authorization": 0,
            "Cryptographic Issues": 0,
            "Memory & Resource Management": 0,
            "API & Logic Issues": 0,
            "Access & Data Exposure": 0,
            "Code Quality": 0,
            "Web & Repo-Specific": 0
        }
        
        for rule in self.rules:
            rule_id = rule['id']
            if any(x in rule_id for x in ['SQL', 'NOSQL', 'COMMAND', 'LDAP', 'PATH', 'REDIRECT', 'XSS', 'DESERIALIZATION', 'BUFFER', 'INTEGER', 'INPUT']):
                categories["Input & Data Handling"] += 1
            elif any(x in rule_id for x in ['PASSWORD', 'AUTH', 'SESSION', 'ACCESS', 'PRIVILEGE', 'TOKEN', 'API_KEY', 'SECRET']):
                categories["Authentication & Authorization"] += 1
            elif any(x in rule_id for x in ['HASH', 'CIPHER', 'CRYPTO', 'ENCRYPTION', 'RANDOM', 'SSL', 'CERTIFICATE']):
                categories["Cryptographic Issues"] += 1
            elif any(x in rule_id for x in ['MEMORY', 'FREE', 'LEAK', 'RACE', 'DEADLOCK', 'RESOURCE']):
                categories["Memory & Resource Management"] += 1
            elif any(x in rule_id for x in ['DEBUG', 'CORS', 'EXCEPTION', 'STACK', 'RATE_LIMIT']):
                categories["API & Logic Issues"] += 1
            elif any(x in rule_id for x in ['LOGS', 'COMMENT', 'ENV', 'INTERNAL', 'EXPOSURE']):
                categories["Access & Data Exposure"] += 1
            elif any(x in rule_id for x in ['NULL', 'MAGIC', 'UNREACHABLE', 'TODO']):
                categories["Code Quality"] += 1
            elif any(x in rule_id for x in ['CSRF', 'CLICKJACKING', 'GIT', 'UPLOAD', 'WORKFLOW']):
                categories["Web & Repo-Specific"] += 1
        
        return categories

    def _initialize_ssrf_rules(self):
        """Server-Side Request Forgery vulnerabilities"""
        self.rules.extend([
            # SSRF - HTTP Requests
            {
                "id": "SSRF_USER_CONTROLLED_URL",
                "name": "SSRF via User-Controlled URL",
                "pattern": r"(?i)(requests\.(get|post|put|delete)|urllib\.request|fetch|axios|http\.get|HttpClient).*?(request\.|params\.|query\.|GET\[|POST\[|\$_GET|\$_POST)",
                "description": "HTTP request with user-controlled URL (SSRF risk).",
                "severity": Severity.HIGH,
                "remediation": "Validate URLs against allowlist, block internal IPs.",
                "languages": ["python", "javascript", "php", "java", "csharp"]
            },
            {
                "id": "SSRF_CLOUD_METADATA",
                "name": "Cloud Metadata API Access",
                "pattern": r"(?i)(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2)",
                "description": "Access to cloud metadata API (potential SSRF).",
                "severity": Severity.CRITICAL,
                "remediation": "Block access to metadata endpoints, validate all URLs.",
                "languages": ["all"]
            },
            {
                "id": "SSRF_INTERNAL_IP",
                "name": "Internal IP Address Access",
                "pattern": r"(?i)(http|https)://(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+)",
                "description": "HTTP request to internal/private IP address.",
                "severity": Severity.MEDIUM,
                "remediation": "Implement URL validation and IP allowlisting.",
                "languages": ["all"]
            },
            {
                "id": "SSRF_URL_REDIRECT",
                "name": "SSRF via URL Redirect",
                "pattern": r"(?i)(follow.*?redirect|allow.*?redirect).*?=.*?True",
                "description": "HTTP client configured to follow redirects (SSRF amplification).",
                "severity": Severity.MEDIUM,
                "remediation": "Disable automatic redirects or validate redirect targets.",
                "languages": ["python", "java", "csharp"]
            }
        ])
    
    def _initialize_xxe_rules(self):
        """XML External Entity vulnerabilities"""
        self.rules.extend([
            # XXE Detection
            {
                "id": "XXE_PARSER_UNSAFE",
                "name": "Unsafe XML Parser Configuration",
                "pattern": r"(?i)(XMLParser|DocumentBuilder|SAXParser|etree\.XML)(?!.*?(resolve_entities.*?False|setFeature.*?disallow))",
                "description": "XML parser without XXE protection.",
                "severity": Severity.HIGH,
                "remediation": "Disable external entity resolution in XML parser.",
                "languages": ["python", "java", "csharp", "php"]
            },
            {
                "id": "XXE_DOCTYPE_ENTITY",
                "name": "XML DOCTYPE with ENTITY",
                "pattern": r"(?i)\u003c!DOCTYPE.*?\u003c!ENTITY",
                "description": "XML with DOCTYPE and ENTITY declarations (XXE risk).",
                "severity": Severity.HIGH,
                "remediation": "Reject XML with DOCTYPE declarations.",
                "languages": ["all"]
            },
            {
                "id": "XXE_EXTERNAL_ENTITY",
                "name": "XML External Entity Reference",
                "pattern": r"(?i)\u003c!ENTITY.*?SYSTEM",
                "description": "XML with external entity reference.",
                "severity": Severity.CRITICAL,
                "remediation": "Disable external entity processing.",
                "languages": ["all"]
            },
            {
                "id": "XXE_PYTHON_ETREE",
                "name": "Python lxml Unsafe Usage",
                "pattern": r"(?i)etree\.(XML|parse)(?!.*?resolve_entities\s*=\s*False)",
                "description": "lxml XML parsing without disabling entity resolution.",
                "severity": Severity.HIGH,
                "remediation": "Use etree.XMLParser(resolve_entities=False).",
                "languages": ["python"]
            }
        ])
    
    def _initialize_file_inclusion_rules(self):
        """File Inclusion vulnerabilities (LFI/RFI)"""
        self.rules.extend([
            # Local File Inclusion
            {
                "id": "LFI_INCLUDE_USER_INPUT",
                "name": "Local File Inclusion",
                "pattern": r"(?i)(include|require|include_once|require_once|readfile|file_get_contents)\s*\(.*?(\$_GET|\$_POST|\$_REQUEST|request\.|params\.)",
                "description": "File inclusion with user input (LFI vulnerability).",
                "severity": Severity.CRITICAL,
                "remediation": "Use allowlist for file paths, avoid user input in includes.",
                "languages": ["php", "python", "ruby"]
            },
            {
                "id": "RFI_REMOTE_INCLUDE",
                "name": "Remote File Inclusion",
                "pattern": r"(?i)(include|require).*?(http://|https://|ftp://)",
                "description": "Remote file inclusion detected.",
                "severity": Severity.CRITICAL,
                "remediation": "Disable allow_url_include, validate all file paths.",
                "languages": ["php"]
            },
            {
                "id": "FILE_UPLOAD_UNRESTRICTED",
                "name": "Unrestricted File Upload",
                "pattern": r"(?i)(upload|multipart|file)(?!.*?(extension|mime|type|validate|whitelist))",
                "description": "File upload without extension/type validation.",
                "severity": Severity.HIGH,
                "remediation": "Validate file extensions, MIME types, and content.",
                "languages": ["all"]
            },
            {
                "id": "FILE_UPLOAD_EXEC",
                "name": "File Upload to Executable Directory",
                "pattern": r"(?i)move_uploaded_file.*?(www|public|htdocs|webroot)",
                "description": "File uploaded to web-accessible directory.",
                "severity": Severity.HIGH,
                "remediation": "Store uploads outside webroot, serve via controller.",
                "languages": ["php", "python", "ruby"]
            }
        ])
    
    def _initialize_mobile_security_rules(self):
        """Mobile Security (iOS/Android) vulnerabilities"""
        self.rules.extend([
            # Android Security
            {
                "id": "ANDROID_INSECURE_STORAGE",
                "name": "Android Insecure Data Storage",
                "pattern": r"(?i)(MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|SharedPreferences.*?MODE_PRIVATE)",
                "description": "Insecure data storage mode on Android.",
                "severity": Severity.HIGH,
                "remediation": "Use MODE_PRIVATE for sensitive data storage.",
                "languages": ["java", "kotlin"]
            },
            {
                "id": "ANDROID_WEBVIEW_JAVASCRIPT",
                "name": "Android WebView JavaScript Enabled",
                "pattern": r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)",
                "description": "WebView with JavaScript enabled (XSS risk).",
                "severity": Severity.MEDIUM,
                "remediation": "Disable JavaScript if not needed, validate all content.",
                "languages": ["java", "kotlin"]
            },
            {
                "id": "ANDROID_SSL_VALIDATION_DISABLED",
                "name": "Android SSL Validation Disabled",
                "pattern": r"(?i)(TrustAllCertificates|X509TrustManager.*?checkServerTrusted.*?\{\s*\})",
                "description": "SSL certificate validation disabled on Android.",
                "severity": Severity.CRITICAL,
                "remediation": "Enable proper SSL certificate validation.",
                "languages": ["java", "kotlin"]
            },
            {
                "id": "ANDROID_EXPORTED_COMPONENT",
                "name": "Android Exported Component",
                "pattern": r"(?i)android:exported\s*=\s*['\"]true['\"]",
                "description": "Android component exported without protection.",
                "severity": Severity.MEDIUM,
                "remediation": "Add permission checks to exported components.",
                "languages": ["xml"]
            },
            
            # iOS Security
            {
                "id": "IOS_INSECURE_STORAGE",
                "name": "iOS Insecure Data Storage",
                "pattern": r"(?i)NSUserDefaults.*?(password|token|secret|key)",
                "description": "Sensitive data stored in NSUserDefaults (not encrypted).",
                "severity": Severity.HIGH,
                "remediation": "Use Keychain for sensitive data storage.",
                "languages": ["swift", "objectivec"]
            },
            {
                "id": "IOS_NO_CERTIFICATE_PINNING",
                "name": "iOS Missing Certificate Pinning",
                "pattern": r"(?i)URLSession(?!.*?(pinning|TrustEvaluator|ServerTrustPolicy))",
                "description": "URLSession without certificate pinning.",
                "severity": Severity.MEDIUM,
                "remediation": "Implement certificate pinning for API calls.",
                "languages": ["swift"]
            },
            {
                "id": "IOS_JAILBREAK_DETECTION_MISSING",
                "name": "iOS Missing Jailbreak Detection",
                "pattern": r"(?i)UIApplication(?!.*?(jailbreak|canOpenURL.*?cydia))",
                "description": "No jailbreak detection implemented.",
                "severity": Severity.LOW,
                "remediation": "Add jailbreak detection for sensitive apps.",
                "languages": ["swift", "objectivec"]
            }
        ])
    
    def _initialize_cloud_security_rules(self):
        """Cloud Security (AWS/GCP/Azure) vulnerabilities"""
        self.rules.extend([
            # AWS Security
            {
                "id": "AWS_ACCESS_KEY_EXPOSED",
                "name": "AWS Access Key Exposed",
                "pattern": r"(?i)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                "description": "AWS Access Key ID detected in code.",
                "severity": Severity.CRITICAL,
                "remediation": "Remove credentials, use IAM roles or environment variables.",
                "languages": ["all"]
            },
            {
                "id": "AWS_SECRET_KEY_PATTERN",
                "name": "AWS Secret Key Pattern",
                "pattern": r"(?i)aws[_-]?secret[_-]?access[_-]?key.*?[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
                "description": "AWS Secret Access Key pattern detected.",
                "severity": Severity.CRITICAL,
                "remediation": "Rotate credentials immediately, use secrets manager.",
                "languages": ["all"]
            },
            {
                "id": "AWS_S3_PUBLIC_ACL",
                "name": "AWS S3 Public ACL",
                "pattern": r"(?i)(public-read|public-read-write|authenticated-read)",
                "description": "S3 bucket with public ACL.",
                "severity": Severity.HIGH,
                "remediation": "Use private ACLs, implement bucket policies.",
                "languages": ["all"]
            },
            
            # GCP Security
            {
                "id": "GCP_API_KEY_EXPOSED",
                "name": "GCP API Key Exposed",
                "pattern": r"(?i)AIza[0-9A-Za-z\\-_]{35}",
                "description": "Google Cloud API Key detected.",
                "severity": Severity.HIGH,
                "remediation": "Restrict API key, use service accounts.",
                "languages": ["all"]
            },
            {
                "id": "GCP_SERVICE_ACCOUNT_KEY",
                "name": "GCP Service Account Key",
                "pattern": r"(?i)\"type\":\s*\"service_account\"",
                "description": "GCP service account key file detected.",
                "severity": Severity.CRITICAL,
                "remediation": "Remove service account keys from code.",
                "languages": ["all"]
            },
            
            # Azure Security
            {
                "id": "AZURE_CONNECTION_STRING",
                "name": "Azure Connection String",
                "pattern": r"(?i)(DefaultEndpointsProtocol|AccountKey|AccountName).*?=",
                "description": "Azure storage connection string detected.",
                "severity": Severity.HIGH,
                "remediation": "Use managed identities or Key Vault.",
                "languages": ["all"]
            },
            {
                "id": "AZURE_SUBSCRIPTION_KEY",
                "name": "Azure Subscription Key",
                "pattern": r"(?i)Ocp-Apim-Subscription-Key.*?[:=]\s*['\"][a-f0-9]{32}['\"]",
                "description": "Azure API Management subscription key.",
                "severity": Severity.HIGH,
                "remediation": "Use Azure Key Vault for secrets.",
                "languages": ["all"]
            }
        ])
    
    def _initialize_supply_chain_rules(self):
        """Supply Chain Security vulnerabilities"""
        self.rules.extend([
            # Dependency Security
            {
                "id": "NPM_INSTALL_UNSAFE",
                "name": "npm install without lock file",
                "pattern": r"(?i)npm\s+install(?!.*?--frozen-lockfile)",
                "description": "npm install without using lock file (supply chain risk).",
                "severity": Severity.MEDIUM,
                "remediation": "Use npm ci or --frozen-lockfile in CI/CD.",
                "languages": ["shell", "javascript"]
            },
            {
                "id": "PIP_INSTALL_INSECURE",
                "name": "pip install from untrusted source",
                "pattern": r"(?i)pip\s+install.*?(--index-url|--extra-index-url).*?http://",
                "description": "pip install from insecure HTTP source.",
                "severity": Severity.HIGH,
                "remediation": "Use HTTPS for package indexes.",
                "languages": ["shell", "python"]
            },
            {
                "id": "DEPENDENCY_CONFUSION",
                "name": "Potential Dependency Confusion",
                "pattern": r"(?i)(npm|pip|gem|nuget)\s+(install|add).*?@.*?/",
                "description": "Scoped package installation (check for typosquatting).",
                "severity": Severity.LOW,
                "remediation": "Verify package names and sources.",
                "languages": ["all"]
            },
            {
                "id": "UNSIGNED_PACKAGE",
                "name": "Unsigned Package Installation",
                "pattern": r"(?i)(apt-get|yum|dnf)\s+install.*?--allow-unauthenticated",
                "description": "Installing unsigned/unauthenticated packages.",
                "severity": Severity.HIGH,
                "remediation": "Only install signed packages from trusted sources.",
                "languages": ["shell"]
            },
            {
                "id": "CURL_PIPE_BASH",
                "name": "Curl Pipe to Bash",
                "pattern": r"(?i)curl.*?\|\s*(bash|sh)",
                "description": "Downloading and executing script (supply chain risk).",
                "severity": Severity.HIGH,
                "remediation": "Download, review, and execute scripts separately.",
                "languages": ["shell"]
            }
        ])
    
    def _initialize_additional_injection_rules(self):
        """Additional Injection Attack Types"""
        self.rules.extend([
            # CRLF Injection
            {
                "id": "CRLF_INJECTION_HEADER",
                "name": "CRLF Injection in Headers",
                "pattern": r"(?i)(header|set-cookie|location).*?(\r\n|\\r\\n|%0d%0a)",
                "description": "CRLF injection in HTTP headers.",
                "severity": Severity.HIGH,
                "remediation": "Sanitize input, remove CR/LF characters.",
                "languages": ["all"]
            },
            {
                "id": "CRLF_INJECTION_RESPONSE",
                "name": "CRLF in HTTP Response",
                "pattern": r"(?i)response\.(write|send|setHeader).*?\\n",
                "description": "Newline in HTTP response (header injection risk).",
                "severity": Severity.MEDIUM,
                "remediation": "Validate and encode all header values.",
                "languages": ["javascript", "python", "java"]
            },
            
            # Log Injection
            {
                "id": "LOG_INJECTION",
                "name": "Log Injection",
                "pattern": r"(?i)(log|logger)\.(info|debug|warn|error).*?(\+|%s|f['\"]|\\{).*?(request\.|params\.|query\.)",
                "description": "User input in log statements (log injection/forging).",
                "severity": Severity.MEDIUM,
                "remediation": "Sanitize user input before logging, use structured logging.",
                "languages": ["all"]
            },
            {
                "id": "LOG_FORGING",
                "name": "Log Forging via Newlines",
                "pattern": r"(?i)(log|logger).*?(\\n|\\r|%0a|%0d)",
                "description": "Newline characters in log messages (log forging).",
                "severity": Severity.MEDIUM,
                "remediation": "Remove or encode newline characters in log data.",
                "languages": ["all"]
            },
            
            # Expression Language Injection
            {
                "id": "EL_INJECTION_JAVA",
                "name": "Java EL Injection",
                "pattern": r"(?i)(\\$\\{|#\\{).*?(param|request|session)",
                "description": "Expression Language injection in Java.",
                "severity": Severity.HIGH,
                "remediation": "Avoid EL in user-controlled data, use parameterized expressions.",
                "languages": ["java", "jsp"]
            },
            {
                "id": "SSTI_TEMPLATE_INJECTION",
                "name": "Server-Side Template Injection",
                "pattern": r"(?i)(render_template_string|Template\(|Jinja2|Twig|Freemarker).*?(\+|%s|f['\"])",
                "description": "Template rendering with user input (SSTI).",
                "severity": Severity.CRITICAL,
                "remediation": "Never pass user input to template engines.",
                "languages": ["python", "javascript", "java", "php"]
            },
            
            # XPath Injection
            {
                "id": "XPATH_INJECTION",
                "name": "XPath Injection",
                "pattern": r"(?i)(xpath|selectNodes|evaluate).*?(\+|%s|f['\"]|\\{).*?(request\.|params\.)",
                "description": "XPath query with user input (injection risk).",
                "severity": Severity.HIGH,
                "remediation": "Use parameterized XPath queries.",
                "languages": ["all"]
            },
            
            # GraphQL Injection
            {
                "id": "GRAPHQL_INJECTION",
                "name": "GraphQL Injection",
                "pattern": r"(?i)graphql.*?(query|mutation).*?(\+|%s|f['\"]|\\{).*?(request\.|params\.)",
                "description": "GraphQL query with unsanitized user input.",
                "severity": Severity.HIGH,
                "remediation": "Use parameterized queries, validate input.",
                "languages": ["javascript", "python", "java"]
            },
            
            # HTML Injection
            {
                "id": "HTML_INJECTION",
                "name": "HTML Injection",
                "pattern": r"(?i)(innerHTML|outerHTML|document\.write).*?=.*?(request\.|params\.|query\.)",
                "description": "HTML injection via DOM manipulation.",
                "severity": Severity.HIGH,
                "remediation": "Use textContent, sanitize HTML input.",
                "languages": ["javascript", "typescript"]
            }
        ])

    def scan_content(self, content: str, file_path: str) -> List[Dict]:
        """Scan content using loaded rules"""
        findings = []
        lines = content.split('\n')
        
        for rule in self.rules:
            # Check if rule applies to this file's language
            if 'languages' in rule and rule['languages'] != ["all"]:
                # Simple extension check
                ext = file_path.split('.')[-1].lower()
                lang_map = {
                    'py': 'python', 'js': 'javascript', 'ts': 'typescript',
                    'java': 'java', 'c': 'c', 'cpp': 'cpp', 'cc': 'cpp',
                    'h': 'cpp', 'hpp': 'cpp', 'cs': 'csharp', 'php': 'php',
                    'rb': 'ruby', 'go': 'go', 'rs': 'rust', 'sh': 'shell'
                }
                file_lang = lang_map.get(ext)
                if file_lang and file_lang not in rule['languages']:
                    continue

            try:
                regex = re.compile(rule['pattern'])
                for i, line in enumerate(lines):
                    # Skip very long lines
                    if len(line) > 1000:
                        continue
                        
                    if regex.search(line):
                        # False positive check
                        if self._is_false_positive(line, rule):
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
                # print(f"Invalid regex for rule {rule['id']}")
                pass
                
        return findings

    def _is_false_positive(self, line: str, rule: dict) -> bool:
        """Check for common false positives"""
        stripped = line.strip()
        
        # Ignore comments
        if stripped.startswith(('#', '//', '*', '--', '<!--')):
            return True
            
        # Ignore test files logic could be here, but usually controlled by scanner
        
        return False

