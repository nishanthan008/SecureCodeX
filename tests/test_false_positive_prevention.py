"""
Unit tests for false positive prevention.
Tests context filtering, test code detection, and comment filtering.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securecodex.core.context_filter import ContextFilter


class TestFalsePositivePrevention(unittest.TestCase):
    def setUp(self):
        self.filter = ContextFilter()
    
    def test_detect_test_file_by_path(self):
        """Test detection of test files by path."""
        self.assertTrue(self.filter.is_test_code('tests/test_auth.py', '', 'python'))
        self.assertTrue(self.filter.is_test_code('src/auth.test.js', '', 'javascript'))
        self.assertTrue(self.filter.is_test_code('spec/user_spec.rb', '', 'ruby'))
        self.assertFalse(self.filter.is_test_code('src/auth.py', '', 'python'))
    
    def test_detect_test_by_imports(self):
        """Test detection of test code by imports."""
        python_test = """
import unittest
from myapp import auth

class TestAuth(unittest.TestCase):
    def test_login(self):
        pass
"""
        self.assertTrue(self.filter.is_test_code('auth.py', python_test, 'python'))
        
        js_test = """
const { describe, it, expect } = require('jest');

describe('Auth', () => {
    it('should login', () => {
        expect(true).toBe(true);
    });
});
"""
        self.assertTrue(self.filter.is_test_code('auth.js', js_test, 'javascript'))
    
    def test_detect_comment_python(self):
        """Test detection of comments in Python."""
        content = """
# This is a comment with password=123
x = 1
y = 2  # Another comment
"""
        self.assertTrue(self.filter.is_in_comment(2, content, 'python'))  # Line 2 is the comment
        self.assertFalse(self.filter.is_in_comment(3, content, 'python'))  # Line 3 is code
    
    def test_detect_comment_javascript(self):
        """Test detection of comments in JavaScript."""
        content = """
// This is a comment
var x = 1;
/* Multi-line
   comment here */
var y = 2;
"""
        self.assertTrue(self.filter.is_in_comment(2, content, 'javascript'))  # Line 2 is comment
        self.assertFalse(self.filter.is_in_comment(3, content, 'javascript'))  # Line 3 is code
        self.assertTrue(self.filter.is_in_comment(4, content, 'javascript'))  # Line 4 is in multi-line comment
    
    def test_detect_development_code(self):
        """Test detection of development/debug code."""
        dev_code = """
DEBUG = True
console.log("Debug info")
"""
        self.assertTrue(self.filter.is_development_code(dev_code, 'config.py'))
        
        prod_code = """
PRODUCTION = True
logger.info("Application started")
"""
        self.assertFalse(self.filter.is_development_code(prod_code, 'config.py'))
    
    def test_should_filter_finding_in_comment(self):
        """Test filtering of findings in comments."""
        finding = {
            'file_path': 'src/auth.py',
            'line': 5,
            'rule_id': 'sql-injection'
        }
        
        content = """
import db

def login(username):
    # Example: cursor.execute("SELECT * FROM users WHERE name='" + username + "'")
    cursor.execute("SELECT * FROM users WHERE name=?", (username,))
"""
        
        should_filter, reason = self.filter.should_filter_finding(finding, content, 'python')
        self.assertTrue(should_filter)
        self.assertIn('comment', reason.lower())
    
    def test_should_not_filter_secret_in_comment(self):
        """Test that secrets in comments are NOT filtered."""
        finding = {
            'file_path': 'src/config.py',
            'line': 2,
            'rule_id': 'hardcoded-secret-password'
        }
        
        content = """
# TODO: Remove this before commit
# password = "SuperSecret123!"
"""
        
        should_filter, reason = self.filter.should_filter_finding(finding, content, 'python')
        # Secret rules should NOT be filtered even in comments
        self.assertFalse(should_filter)
    
    def test_should_filter_test_code(self):
        """Test filtering of findings in test code."""
        finding = {
            'file_path': 'tests/test_auth.py',
            'line': 10,
            'rule_id': 'sql-injection'
        }
        
        content = """
import unittest

class TestAuth(unittest.TestCase):
    def test_sql_injection(self):
        # This is a test for SQL injection
        pass
"""
        
        should_filter, reason = self.filter.should_filter_finding(finding, content, 'python')
        self.assertTrue(should_filter)
        self.assertIn('test', reason.lower())
    
    def test_enrich_finding_context(self):
        """Test context enrichment."""
        finding = {
            'file_path': 'tests/test_auth.py',
            'line': 5
        }
        
        content = """
import unittest
# Test comment
def test_function():
    pass
"""
        
        enriched = self.filter.enrich_finding_context(finding, content, 'python')
        
        self.assertIn('context', enriched)
        self.assertTrue(enriched['context']['is_test_code'])
    
    def test_filter_statistics(self):
        """Test filter statistics calculation."""
        findings = [
            {'context': {'is_test_code': True, 'in_comment': False}},
            {'context': {'is_test_code': False, 'in_comment': True}},
            {'context': {'is_test_code': False, 'in_comment': False}},
        ]
        
        stats = self.filter.get_filter_statistics(findings)
        
        self.assertEqual(stats['total'], 3)
        self.assertEqual(stats['test_code'], 1)
        self.assertEqual(stats['comments'], 1)


if __name__ == '__main__':
    unittest.main()
