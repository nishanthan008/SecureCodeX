"""
Sanitizer Library for SecureCodeX.
Framework-aware sanitizer knowledge base for reducing false positives.
"""

from typing import Dict, List, Set, Optional
from enum import Enum


class SanitizerEffectiveness(str, Enum):
    """Sanitizer effectiveness ratings."""
    STRONG = "STRONG"      # Properly prevents the vulnerability
    MEDIUM = "MEDIUM"      # Provides some protection but may have edge cases
    WEAK = "WEAK"          # Minimal protection, easily bypassed


class SanitizerLibrary:
    """
    Knowledge base of sanitizers and safe APIs across different frameworks.
    """
    
    def __init__(self):
        self.sanitizers = self._build_sanitizer_database()
    
    def _build_sanitizer_database(self) -> Dict[str, Dict[str, List[Dict]]]:
        """Build comprehensive sanitizer database."""
        return {
            'python': {
                'sql': [
                    {
                        'pattern': 'cursor.execute',
                        'safe_when': 'parameterized',  # execute(query, params)
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Parameterized queries prevent SQL injection'
                    },
                    {
                        'pattern': 'db.execute',
                        'safe_when': 'parameterized',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'SQLAlchemy parameterized execution'
                    },
                    {
                        'pattern': '.filter(',
                        'safe_when': 'orm',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Django/SQLAlchemy ORM methods are safe by default'
                    },
                    {
                        'pattern': '.filter_by(',
                        'safe_when': 'orm',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'ORM filter_by uses parameterization'
                    },
                    {
                        'pattern': '.get(',
                        'safe_when': 'orm',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'ORM get method is safe'
                    },
                ],
                'xss': [
                    {
                        'pattern': 'markupsafe.escape(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'MarkupSafe HTML escaping'
                    },
                    {
                        'pattern': 'html.escape(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Python HTML escaping'
                    },
                    {
                        'pattern': 'bleach.clean(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Bleach HTML sanitizer'
                    },
                    {
                        'pattern': 'render_template(',
                        'safe_when': 'jinja_autoescape',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Jinja2 auto-escapes by default'
                    },
                ],
                'command': [
                    {
                        'pattern': 'shlex.quote(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Shell argument quoting'
                    },
                    {
                        'pattern': 'subprocess.run(',
                        'safe_when': 'list_args',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'subprocess with list arguments (shell=False)'
                    },
                    {
                        'pattern': 'subprocess.Popen(',
                        'safe_when': 'list_args',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Popen with list arguments (shell=False)'
                    },
                ],
                'path': [
                    {
                        'pattern': 'os.path.basename(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Extracts filename, removes path traversal'
                    },
                    {
                        'pattern': 'werkzeug.utils.secure_filename(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Werkzeug secure filename sanitizer'
                    },
                    {
                        'pattern': 'os.path.abspath(',
                        'safe_when': 'with_validation',
                        'effectiveness': SanitizerEffectiveness.MEDIUM,
                        'description': 'Normalizes path but needs additional validation'
                    },
                ],
                'type_conversion': [
                    {
                        'pattern': 'int(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Type conversion to integer'
                    },
                    {
                        'pattern': 'float(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Type conversion to float'
                    },
                    {
                        'pattern': 'str.isdigit(',
                        'safe_when': 'with_validation',
                        'effectiveness': SanitizerEffectiveness.MEDIUM,
                        'description': 'Validation check for numeric strings'
                    },
                ],
            },
            'javascript': {
                'sql': [
                    {
                        'pattern': '.query(',
                        'safe_when': 'parameterized',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Parameterized queries'
                    },
                    {
                        'pattern': '.execute(',
                        'safe_when': 'parameterized',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Prepared statements'
                    },
                    {
                        'pattern': 'knex(',
                        'safe_when': 'orm',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Knex query builder'
                    },
                    {
                        'pattern': 'sequelize.',
                        'safe_when': 'orm',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Sequelize ORM methods'
                    },
                ],
                'xss': [
                    {
                        'pattern': 'DOMPurify.sanitize(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'DOMPurify HTML sanitizer'
                    },
                    {
                        'pattern': 'escape(',
                        'safe_when': 'library',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'HTML escape function'
                    },
                    {
                        'pattern': 'textContent',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'textContent is safe (no HTML parsing)'
                    },
                    {
                        'pattern': 'innerText',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'innerText is safe (no HTML parsing)'
                    },
                ],
                'command': [
                    {
                        'pattern': 'child_process.execFile(',
                        'safe_when': 'array_args',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'execFile with array arguments'
                    },
                    {
                        'pattern': 'child_process.spawn(',
                        'safe_when': 'array_args',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'spawn with array arguments'
                    },
                ],
                'path': [
                    {
                        'pattern': 'path.basename(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Extracts filename'
                    },
                    {
                        'pattern': 'path.normalize(',
                        'safe_when': 'with_validation',
                        'effectiveness': SanitizerEffectiveness.MEDIUM,
                        'description': 'Normalizes path but needs validation'
                    },
                ],
            },
            'java': {
                'sql': [
                    {
                        'pattern': 'PreparedStatement',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'JDBC PreparedStatement'
                    },
                    {
                        'pattern': '.setString(',
                        'safe_when': 'prepared_statement',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'PreparedStatement parameter binding'
                    },
                ],
                'xss': [
                    {
                        'pattern': 'StringEscapeUtils.escapeHtml(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'Apache Commons HTML escaping'
                    },
                    {
                        'pattern': 'ESAPI.encoder().encodeForHTML(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'OWASP ESAPI HTML encoding'
                    },
                ],
            },
            'php': {
                'sql': [
                    {
                        'pattern': '->prepare(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'PDO prepared statements'
                    },
                    {
                        'pattern': '->bindParam(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'PDO parameter binding'
                    },
                    {
                        'pattern': 'mysqli_prepare(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'MySQLi prepared statements'
                    },
                ],
                'xss': [
                    {
                        'pattern': 'htmlspecialchars(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'PHP HTML special characters encoding'
                    },
                    {
                        'pattern': 'htmlentities(',
                        'safe_when': 'always',
                        'effectiveness': SanitizerEffectiveness.STRONG,
                        'description': 'PHP HTML entities encoding'
                    },
                ],
            },
        }
    
    def get_sanitizers_for_language(self, language: str, vulnerability_type: str) -> List[Dict]:
        """
        Get sanitizers for a specific language and vulnerability type.
        
        Args:
            language: Programming language (python, javascript, java, etc.)
            vulnerability_type: Type of vulnerability (sql, xss, command, path, etc.)
        
        Returns:
            List of sanitizer definitions
        """
        return self.sanitizers.get(language, {}).get(vulnerability_type, [])
    
    def is_sanitizer(self, code_snippet: str, language: str, vulnerability_type: str) -> Optional[Dict]:
        """
        Check if a code snippet contains a sanitizer.
        
        Args:
            code_snippet: Code to check
            language: Programming language
            vulnerability_type: Type of vulnerability
        
        Returns:
            Sanitizer definition if found, None otherwise
        """
        sanitizers = self.get_sanitizers_for_language(language, vulnerability_type)
        
        for sanitizer in sanitizers:
            if sanitizer['pattern'] in code_snippet:
                return sanitizer
        
        return None
    
    def get_effectiveness(self, sanitizer_pattern: str, language: str, vulnerability_type: str) -> Optional[SanitizerEffectiveness]:
        """
        Get effectiveness rating for a sanitizer.
        
        Args:
            sanitizer_pattern: The sanitizer pattern
            language: Programming language
            vulnerability_type: Type of vulnerability
        
        Returns:
            Effectiveness rating or None if not found
        """
        sanitizers = self.get_sanitizers_for_language(language, vulnerability_type)
        
        for sanitizer in sanitizers:
            if sanitizer['pattern'] == sanitizer_pattern:
                return sanitizer['effectiveness']
        
        return None
    
    def get_all_sanitizer_patterns(self, language: str) -> Set[str]:
        """
        Get all sanitizer patterns for a language.
        
        Args:
            language: Programming language
        
        Returns:
            Set of sanitizer patterns
        """
        patterns = set()
        lang_sanitizers = self.sanitizers.get(language, {})
        
        for vuln_type, sanitizers in lang_sanitizers.items():
            for sanitizer in sanitizers:
                patterns.add(sanitizer['pattern'])
        
        return patterns
    
    def analyze_sanitization(
        self, 
        source: str, 
        sink: str, 
        path: List[str], 
        language: str, 
        vulnerability_type: str
    ) -> Dict[str, any]:
        """
        Analyze sanitization along a data flow path.
        
        Args:
            source: Source code snippet
            sink: Sink code snippet
            path: List of code snippets in the data flow path
            language: Programming language
            vulnerability_type: Type of vulnerability
        
        Returns:
            Analysis result with status and details
        """
        sanitizers = self.get_sanitizers_for_language(language, vulnerability_type)
        found_sanitizers = []
        
        # Check each step in the path for sanitizers
        for step in path:
            for sanitizer in sanitizers:
                if sanitizer['pattern'] in step:
                    found_sanitizers.append({
                        'pattern': sanitizer['pattern'],
                        'effectiveness': sanitizer['effectiveness'],
                        'description': sanitizer['description'],
                        'location': step
                    })
        
        # Determine sanitization status
        if not found_sanitizers:
            status = 'MISSING'
            explanation = 'No sanitization detected in the data flow path'
        else:
            # Check effectiveness of sanitizers
            strong_sanitizers = [s for s in found_sanitizers if s['effectiveness'] == SanitizerEffectiveness.STRONG]
            
            if strong_sanitizers:
                status = 'EFFECTIVE'
                explanation = f"Strong sanitization found: {strong_sanitizers[0]['description']}"
            else:
                weak_sanitizers = [s for s in found_sanitizers if s['effectiveness'] == SanitizerEffectiveness.WEAK]
                if weak_sanitizers:
                    status = 'WEAK'
                    explanation = f"Weak sanitization found: {weak_sanitizers[0]['description']}"
                else:
                    status = 'MEDIUM'
                    explanation = f"Medium-strength sanitization found: {found_sanitizers[0]['description']}"
        
        return {
            'status': status,
            'explanation': explanation,
            'sanitizers_found': found_sanitizers,
            'recommendation': self._get_recommendation(vulnerability_type, language, found_sanitizers)
        }
    
    def _get_recommendation(
        self, 
        vulnerability_type: str, 
        language: str, 
        found_sanitizers: List[Dict]
    ) -> str:
        """Get sanitization recommendation."""
        if not found_sanitizers:
            # Recommend strong sanitizers
            sanitizers = self.get_sanitizers_for_language(language, vulnerability_type)
            strong = [s for s in sanitizers if s['effectiveness'] == SanitizerEffectiveness.STRONG]
            
            if strong:
                return f"Use {strong[0]['pattern']} - {strong[0]['description']}"
            else:
                return f"Apply proper sanitization for {vulnerability_type} vulnerabilities"
        else:
            # Check if upgrade is needed
            if all(s['effectiveness'] != SanitizerEffectiveness.STRONG for s in found_sanitizers):
                sanitizers = self.get_sanitizers_for_language(language, vulnerability_type)
                strong = [s for s in sanitizers if s['effectiveness'] == SanitizerEffectiveness.STRONG]
                
                if strong:
                    return f"Upgrade to stronger sanitization: {strong[0]['pattern']}"
            
            return "Current sanitization appears adequate"
