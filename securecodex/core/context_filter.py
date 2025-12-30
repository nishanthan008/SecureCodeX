"""
Context Filter for SecureCodeX.
Filters findings based on code context to reduce false positives.
"""

from typing import Dict, List, Optional, Set
import re
import os


class ContextFilter:
    """
    Filters findings based on code context (test code, comments, strings, etc.)
    """
    
    def __init__(self):
        self.test_patterns = self._build_test_patterns()
        self.test_frameworks = self._build_test_frameworks()
    
    def _build_test_patterns(self) -> List[str]:
        """Build patterns for detecting test code."""
        return [
            r'test_',
            r'_test\.py$',
            r'_test\.js$',
            r'\.test\.js$',
            r'\.spec\.js$',
            r'\.test\.ts$',
            r'\.spec\.ts$',
            r'Test\.java$',
            r'test/',
            r'tests/',
            r'__tests__/',
            r'spec/',
            r'specs/',
        ]
    
    def _build_test_frameworks(self) -> Dict[str, List[str]]:
        """Build test framework detection patterns."""
        return {
            'python': [
                'import unittest',
                'import pytest',
                'from unittest',
                'from pytest',
                'import nose',
                '@pytest.',
                'TestCase',
                'def test_',
            ],
            'javascript': [
                'describe(',
                'it(',
                'test(',
                'expect(',
                'jest.',
                'mocha',
                'chai',
                'jasmine',
                'require(\'jest\')',
                'from \'jest\'',
            ],
            'java': [
                '@Test',
                'import org.junit',
                'import org.testng',
                'JUnit',
                'TestNG',
            ],
            'php': [
                'PHPUnit',
                'use PHPUnit',
                'extends TestCase',
            ],
        }
    
    def is_test_code(self, file_path: str, content: str, language: str) -> bool:
        """
        Determine if code is test code.
        
        Args:
            file_path: Path to the file
            content: File content
            language: Programming language
        
        Returns:
            True if this is test code
        """
        # Check file path patterns
        for pattern in self.test_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        
        # Check for test framework imports
        framework_patterns = self.test_frameworks.get(language, [])
        for pattern in framework_patterns:
            if pattern in content:
                return True
        
        return False
    
    def is_in_comment(self, line_number: int, content: str, language: str) -> bool:
        """
        Check if a line is inside a comment.
        
        Args:
            line_number: Line number (1-indexed)
            content: File content
            language: Programming language
        
        Returns:
            True if line is in a comment
        """
        lines = content.split('\n')
        if line_number < 1 or line_number > len(lines):
            return False
        
        target_line = lines[line_number - 1].strip()
        
        # Single-line comment patterns
        comment_patterns = {
            'python': r'^\s*#',
            'javascript': r'^\s*//',
            'java': r'^\s*//',
            'php': r'^\s*//',
            'c': r'^\s*//',
            'cpp': r'^\s*//',
            'csharp': r'^\s*//',
            'bash': r'^\s*#',
        }
        
        pattern = comment_patterns.get(language)
        if pattern and re.match(pattern, target_line):
            return True
        
        # Multi-line comment detection (simplified)
        # This is a basic implementation; full AST-based detection is better
        if language in ['javascript', 'java', 'php', 'c', 'cpp', 'csharp']:
            # Check if we're inside /* ... */
            before_line = '\n'.join(lines[:line_number])
            
            # Count opening and closing comment markers
            open_count = before_line.count('/*')
            close_count = before_line.count('*/')
            
            if open_count > close_count:
                return True
        
        if language == 'python':
            # Check for docstrings
            if '"""' in target_line or "'''" in target_line:
                return True
        
        return False
    
    def is_in_string_literal(self, node: any, language: str) -> bool:
        """
        Check if a node is inside a string literal.
        
        Args:
            node: AST node
            language: Programming language
        
        Returns:
            True if inside a string literal
        """
        if not hasattr(node, 'type'):
            return False
        
        # String literal node types by language
        string_types = {
            'python': ['string', 'string_content', 'interpolation'],
            'javascript': ['string', 'template_string', 'string_fragment'],
            'java': ['string_literal'],
            'php': ['string'],
        }
        
        node_types = string_types.get(language, [])
        
        # Check if node itself is a string
        if node.type in node_types:
            return True
        
        # Check if any parent is a string
        current = node.parent
        while current:
            if current.type in node_types:
                return True
            current = current.parent
        
        return False
    
    def is_development_code(self, content: str, file_path: str) -> bool:
        """
        Check if code is development/debug code.
        
        Args:
            content: File content
            file_path: Path to the file
        
        Returns:
            True if this is development code
        """
        dev_patterns = [
            r'DEBUG\s*=\s*True',
            r'DEVELOPMENT\s*=\s*True',
            r'console\.log\(',
            r'print\(["\']DEBUG',
            r'logger\.debug\(',
            r'example\.py$',
            r'demo\.py$',
            r'sample\.py$',
            r'/examples/',
            r'/demos/',
        ]
        
        for pattern in dev_patterns:
            if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, file_path, re.IGNORECASE):
                return True
        
        return False
    
    def should_filter_finding(
        self, 
        finding: Dict, 
        content: str, 
        language: str,
        allow_test_findings: bool = False
    ) -> tuple[bool, Optional[str]]:
        """
        Determine if a finding should be filtered out.
        
        Args:
            finding: The vulnerability finding
            content: File content
            language: Programming language
            allow_test_findings: Whether to allow findings in test code
        
        Returns:
            Tuple of (should_filter, reason)
        """
        file_path = finding.get('file_path', '')
        line_number = finding.get('line', 0)
        rule_id = finding.get('rule_id', '')
        
        # Don't filter secret detection in comments (secrets can be in comments)
        is_secret_rule = 'secret' in rule_id.lower() or 'credential' in rule_id.lower() or 'password' in rule_id.lower()
        
        # Check if in comment (unless it's a secret rule)
        if not is_secret_rule and self.is_in_comment(line_number, content, language):
            return True, "Finding is in a comment"
        
        # Check if test code (unless allowed)
        if not allow_test_findings and self.is_test_code(file_path, content, language):
            return True, "Finding is in test code"
        
        # Check if development code
        if self.is_development_code(content, file_path):
            return True, "Finding is in development/debug code"
        
        # Check if in string literal (for non-secret rules)
        if not is_secret_rule and 'node' in finding:
            node = finding['node']
            if self.is_in_string_literal(node, language):
                return True, "Finding is in a string literal"
        
        return False, None
    
    def enrich_finding_context(
        self, 
        finding: Dict, 
        content: str, 
        language: str
    ) -> Dict:
        """
        Add context information to a finding.
        
        Args:
            finding: The vulnerability finding
            content: File content
            language: Programming language
        
        Returns:
            Finding with added context fields
        """
        file_path = finding.get('file_path', '')
        line_number = finding.get('line', 0)
        
        finding['context'] = {
            'is_test_code': self.is_test_code(file_path, content, language),
            'in_comment': self.is_in_comment(line_number, content, language),
            'is_development': self.is_development_code(content, file_path),
        }
        
        if 'node' in finding:
            finding['context']['in_string_literal'] = self.is_in_string_literal(finding['node'], language)
        
        return finding
    
    def get_filter_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        """
        Get statistics on filtered findings.
        
        Args:
            findings: List of findings with context
        
        Returns:
            Dictionary with filter statistics
        """
        stats = {
            'total': len(findings),
            'test_code': 0,
            'comments': 0,
            'development': 0,
            'string_literals': 0,
        }
        
        for finding in findings:
            context = finding.get('context', {})
            if context.get('is_test_code'):
                stats['test_code'] += 1
            if context.get('in_comment'):
                stats['comments'] += 1
            if context.get('is_development'):
                stats['development'] += 1
            if context.get('in_string_literal'):
                stats['string_literals'] += 1
        
        return stats
