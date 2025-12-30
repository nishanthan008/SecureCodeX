"""
Framework Detector for SecureCodeX.
Detects frameworks and libraries in use to provide context-aware analysis.
"""

from typing import Dict, List, Set, Optional
import re


class FrameworkDetector:
    """
    Detects frameworks and provides context for vulnerability analysis.
    """
    
    def __init__(self):
        self.framework_cache: Dict[str, Dict] = {}
        self.framework_signatures = self._build_framework_signatures()
    
    def _build_framework_signatures(self) -> Dict[str, Dict]:
        """Build framework detection signatures."""
        return {
            'python': {
                'django': {
                    'imports': ['django', 'django.db', 'django.http', 'django.views'],
                    'patterns': [r'from\s+django', r'import\s+django', r'models\.Model', r'@login_required'],
                    'features': {
                        'orm': True,
                        'auto_escape': True,
                        'csrf_protection': True,
                        'sql_safe_by_default': True,
                    }
                },
                'flask': {
                    'imports': ['flask', 'flask.request', 'flask.render_template'],
                    'patterns': [r'from\s+flask\s+import', r'@app\.route', r'Flask\(__name__\)'],
                    'features': {
                        'orm': False,
                        'auto_escape': True,  # Jinja2
                        'csrf_protection': False,  # Requires extension
                        'sql_safe_by_default': False,
                    }
                },
                'fastapi': {
                    'imports': ['fastapi', 'fastapi.FastAPI'],
                    'patterns': [r'from\s+fastapi\s+import', r'@app\.get', r'@app\.post', r'FastAPI\('],
                    'features': {
                        'orm': False,
                        'auto_escape': False,
                        'csrf_protection': False,
                        'sql_safe_by_default': False,
                    }
                },
                'sqlalchemy': {
                    'imports': ['sqlalchemy', 'sqlalchemy.orm'],
                    'patterns': [r'from\s+sqlalchemy', r'import\s+sqlalchemy', r'declarative_base'],
                    'features': {
                        'orm': True,
                        'sql_safe_by_default': True,
                    }
                },
            },
            'javascript': {
                'express': {
                    'imports': ['express', 'require(\'express\')'],
                    'patterns': [r'require\([\'"]express[\'"]\)', r'app\.get\(', r'app\.post\(', r'express\(\)'],
                    'features': {
                        'orm': False,
                        'auto_escape': False,
                        'csrf_protection': False,
                        'sql_safe_by_default': False,
                    }
                },
                'react': {
                    'imports': ['react', 'react-dom'],
                    'patterns': [r'import\s+React', r'from\s+[\'"]react[\'"]', r'useState', r'useEffect'],
                    'features': {
                        'auto_escape': True,  # JSX escapes by default
                        'xss_safe_by_default': True,
                    }
                },
                'vue': {
                    'imports': ['vue'],
                    'patterns': [r'import\s+Vue', r'from\s+[\'"]vue[\'"]', r'new\s+Vue\('],
                    'features': {
                        'auto_escape': True,
                        'xss_safe_by_default': True,
                    }
                },
                'sequelize': {
                    'imports': ['sequelize'],
                    'patterns': [r'require\([\'"]sequelize[\'"]\)', r'Sequelize\(', r'sequelize\.define'],
                    'features': {
                        'orm': True,
                        'sql_safe_by_default': True,
                    }
                },
            },
            'java': {
                'spring': {
                    'imports': ['org.springframework', 'springframework'],
                    'patterns': [r'@RestController', r'@Controller', r'@Autowired', r'@RequestMapping'],
                    'features': {
                        'csrf_protection': True,
                        'xss_protection': True,
                        'sql_safe_by_default': False,
                    }
                },
                'hibernate': {
                    'imports': ['org.hibernate', 'hibernate'],
                    'patterns': [r'@Entity', r'@Table', r'SessionFactory', r'createQuery'],
                    'features': {
                        'orm': True,
                        'sql_safe_by_default': True,
                    }
                },
            },
            'php': {
                'laravel': {
                    'imports': ['Illuminate\\', 'Laravel\\'],
                    'patterns': [r'use\s+Illuminate', r'Route::', r'Eloquent', r'->where\('],
                    'features': {
                        'orm': True,
                        'csrf_protection': True,
                        'sql_safe_by_default': True,
                        'auto_escape': True,
                    }
                },
                'symfony': {
                    'imports': ['Symfony\\'],
                    'patterns': [r'use\s+Symfony', r'@Route', r'->render\('],
                    'features': {
                        'orm': True,
                        'csrf_protection': True,
                        'sql_safe_by_default': True,
                        'auto_escape': True,
                    }
                },
            },
        }
    
    def detect_frameworks(self, content: str, language: str, file_path: str) -> Dict[str, any]:
        """
        Detect frameworks used in the code.
        
        Args:
            content: Source code content
            language: Programming language
            file_path: Path to the file
        
        Returns:
            Dictionary with detected frameworks and their features
        """
        # Check cache
        if file_path in self.framework_cache:
            return self.framework_cache[file_path]
        
        detected = {
            'frameworks': [],
            'features': {},
            'language': language
        }
        
        lang_frameworks = self.framework_signatures.get(language, {})
        
        for framework_name, framework_info in lang_frameworks.items():
            if self._is_framework_present(content, framework_info):
                detected['frameworks'].append(framework_name)
                # Merge features
                detected['features'].update(framework_info['features'])
        
        # Cache the result
        self.framework_cache[file_path] = detected
        
        return detected
    
    def _is_framework_present(self, content: str, framework_info: Dict) -> bool:
        """Check if a framework is present in the code."""
        # Check import statements
        for import_pattern in framework_info['imports']:
            if import_pattern in content:
                return True
        
        # Check code patterns
        for pattern in framework_info['patterns']:
            if re.search(pattern, content, re.MULTILINE):
                return True
        
        return False
    
    def has_feature(self, framework_context: Dict, feature: str) -> bool:
        """
        Check if detected frameworks have a specific feature.
        
        Args:
            framework_context: Framework detection result
            feature: Feature name (e.g., 'auto_escape', 'csrf_protection')
        
        Returns:
            True if feature is present
        """
        return framework_context.get('features', {}).get(feature, False)
    
    def get_framework_protection(
        self, 
        framework_context: Dict, 
        vulnerability_type: str
    ) -> Optional[str]:
        """
        Get framework protection information for a vulnerability type.
        
        Args:
            framework_context: Framework detection result
            vulnerability_type: Type of vulnerability (sql, xss, csrf, etc.)
        
        Returns:
            Protection description or None
        """
        features = framework_context.get('features', {})
        frameworks = framework_context.get('frameworks', [])
        
        if not frameworks:
            return None
        
        # Map vulnerability types to features
        protection_map = {
            'sql': 'sql_safe_by_default',
            'xss': 'auto_escape',
            'csrf': 'csrf_protection',
        }
        
        feature_key = protection_map.get(vulnerability_type)
        if feature_key and features.get(feature_key):
            return f"{', '.join(frameworks)} provides built-in protection against {vulnerability_type}"
        
        return None
    
    def should_reduce_confidence(
        self, 
        framework_context: Dict, 
        vulnerability_type: str
    ) -> bool:
        """
        Determine if confidence should be reduced due to framework protections.
        
        Args:
            framework_context: Framework detection result
            vulnerability_type: Type of vulnerability
        
        Returns:
            True if confidence should be reduced
        """
        protection = self.get_framework_protection(framework_context, vulnerability_type)
        return protection is not None
    
    def get_context_explanation(self, framework_context: Dict) -> str:
        """
        Get human-readable explanation of framework context.
        
        Args:
            framework_context: Framework detection result
        
        Returns:
            Explanation string
        """
        frameworks = framework_context.get('frameworks', [])
        
        if not frameworks:
            return "No framework detected"
        
        features = framework_context.get('features', {})
        active_features = [k for k, v in features.items() if v]
        
        explanation = f"Detected frameworks: {', '.join(frameworks)}"
        if active_features:
            explanation += f"\nActive protections: {', '.join(active_features)}"
        
        return explanation
    
    def clear_cache(self):
        """Clear the framework detection cache."""
        self.framework_cache.clear()
