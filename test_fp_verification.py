import unittest
from securecodex.detectors.advanced_pattern_detector import AdvancedPatternDetector

class TestFalsePositives(unittest.TestCase):
    def setUp(self):
        self.detector = AdvancedPatternDetector()

    def test_ignore_comments_python(self):
        content = """
        # This is a comment with a password=12345
        x = 1
        y = "not a secret" # key='1234567890'
        """
        # We expect 0 findings because the "vulnerabilities" are in comments and are NOT TODO/SECRET rules
        findings = self.detector.scan_content(content, "test.py", language="python")
        self.assertEqual(len(findings), 0, f"Found unexpected findings: {findings}")

    def test_ignore_comments_js(self):
        content = """
        // var password = "secretpassword123";
        """
        findings = self.detector.scan_content(content, "test.js", language="javascript")
        # specific "Secret in Comment" rule should still fire
        self.assertTrue(any(f['rule_id'] == 'SECRET_IN_COMMENT' for f in findings), "Should find SECRET_IN_COMMENT")
        # But should NOT find HARDCODED_PASSWORD (if that rule existed/matched)
        self.assertFalse(any(f['rule_id'] == 'HARDCODED_PASSWORD' for f in findings), "Should NOT find HARDCODED_PASSWORD as it is commented")

    def test_ignore_sql_injection_in_comment(self):
        content = """
        # db.execute("select * from users where id=" + input)
        """
        findings = self.detector.scan_content(content, "test.py", language="python")
        # Should be 0 because SQL injection should be filtered out
        self.assertEqual(len(findings), 0, f"False positive SQL Injection found: {findings}")

    def test_true_positive(self):
        content = """
        password = "hardcoded_password_123"
        """
        findings = self.detector.scan_content(content, "test.py", language="python")
        self.assertTrue(len(findings) > 0, "Should have found the hardcoded password")

if __name__ == '__main__':
    unittest.main()
