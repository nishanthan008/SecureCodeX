"""
Unit tests for ConfidenceCalculator.
Tests the 0-100 confidence scoring system.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securecodex.core.confidence_calculator import ConfidenceCalculator


class TestConfidenceCalculator(unittest.TestCase):
    def setUp(self):
        self.calc = ConfidenceCalculator()
    
    def test_high_confidence_taint_finding(self):
        """Test high confidence score for complete taint finding."""
        finding = {
            'source': type('obj', (object,), {'text': b'request.args.get("id")'}),
            'sink': type('obj', (object,), {'text': b'cursor.execute(query)'}),
            'sanitization_status': 'MISSING',
            'evidence': [
                {'step': 'Source', 'line': 10},
                {'step': 'Propagation', 'line': 11},
                {'step': 'Sink', 'line': 12}
            ]
        }
        
        rule = {
            'id': 'python-sqli-taint',
            'mode': 'taint',
            'metadata': {'confidence': 0.95}  # Old scale
        }
        
        context = {}
        
        score = self.calc.calculate_confidence(finding, rule, context)
        
        # Should get: 30 (source) + 30 (sink) + 25 (unsanitized) + 5 (evidence) = 90
        self.assertGreaterEqual(score, 85)
        self.assertEqual(self.calc.get_confidence_level(score), 'HIGH')
    
    def test_medium_confidence_with_weak_sanitizer(self):
        """Test medium confidence when weak sanitizer is present."""
        finding = {
            'source': type('obj', (object,), {'text': b'request.args.get("id")'}),
            'sink': type('obj', (object,), {'text': b'cursor.execute(query)'}),
            'sanitization_status': 'WEAK',
            'evidence': [{'step': 'Source', 'line': 10}]
        }
        
        rule = {
            'id': 'python-sqli-taint',
            'mode': 'taint',
            'metadata': {'confidence': 80}
        }
        
        context = {}
        
        score = self.calc.calculate_confidence(finding, rule, context)
        
        # Should get base 80 + adjustments
        self.assertGreaterEqual(score, 70)
        self.assertLessEqual(score, 95)
        # Confidence level may be HIGH or MEDIUM depending on exact score
        self.assertIn(self.calc.get_confidence_level(score), ['MEDIUM', 'HIGH'])
    
    def test_low_confidence_test_code(self):
        """Test confidence reduction for test code."""
        finding = {
            'source': type('obj', (object,), {'text': b'request.args.get("id")'}),
            'sink': type('obj', (object,), {'text': b'cursor.execute(query)'}),
            'sanitization_status': 'MISSING',
        }
        
        rule = {
            'id': 'python-sqli-taint',
            'mode': 'taint',
            'metadata': {'confidence': 90}
        }
        
        context = {'is_test_code': True}
        
        score = self.calc.calculate_confidence(finding, rule, context)
        
        # Test code should reduce confidence significantly
        self.assertLess(score, 60)
        # May be MEDIUM or LOW depending on base score
        self.assertIn(self.calc.get_confidence_level(score), ['LOW', 'MEDIUM'])
    
    def test_pattern_based_secret_detection(self):
        """Test high confidence for secret detection."""
        finding = {
            'snippet': 'password = "hardcoded123"'
        }
        
        rule = {
            'id': 'hardcoded-secret-password',
            'mode': 'pattern',
            'metadata': {'confidence': 70}
        }
        
        context = {}
        
        score = self.calc.calculate_confidence(finding, rule, context)
        
        # Secret rules should get boosted to at least 85
        self.assertGreaterEqual(score, 85)
        self.assertEqual(self.calc.get_confidence_level(score), 'HIGH')
    
    def test_should_report_filtering(self):
        """Test confidence-based reporting filter."""
        # High confidence should always be reported
        self.assertTrue(self.calc.should_report(85, 'LOW'))
        self.assertTrue(self.calc.should_report(85, 'MEDIUM'))
        self.assertTrue(self.calc.should_report(85, 'HIGH'))
        
        # Medium confidence
        self.assertTrue(self.calc.should_report(65, 'LOW'))
        self.assertTrue(self.calc.should_report(65, 'MEDIUM'))
        self.assertFalse(self.calc.should_report(65, 'HIGH'))
        
        # Low confidence
        self.assertTrue(self.calc.should_report(45, 'LOW'))
        self.assertFalse(self.calc.should_report(45, 'MEDIUM'))
        self.assertFalse(self.calc.should_report(45, 'HIGH'))
    
    def test_unreachable_code_penalty(self):
        """Test confidence reduction for unreachable code."""
        finding = {}
        rule = {'id': 'test-rule', 'metadata': {'confidence': 80}}
        context = {'is_reachable': False}
        
        score = self.calc.calculate_confidence(finding, rule, context)
        
        # Unreachable code should reduce confidence significantly (70% reduction)
        self.assertLess(score, 35)
    
    def test_framework_protection_bonus(self):
        """Test confidence increase when framework protection is absent."""
        finding = {}
        rule = {'id': 'test-rule', 'metadata': {'confidence': 70}}
        context = {'framework_protection': False}
        
        score = self.calc.calculate_confidence(finding, rule, context)
        
        # Should get +10 bonus
        self.assertGreaterEqual(score, 80)


if __name__ == '__main__':
    unittest.main()
