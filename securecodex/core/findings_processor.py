"""
Findings Processor for SecureCodeX.
Handles severity normalization, metadata enrichment (CWE/OWASP), 
and rule-based overrides inspired by secureCodeBox hooks.
"""

import re
from typing import List, Dict, Any, Optional
from ..models import Severity

class FindingsProcessor:
    """
    Processes raw findings to normalize metadata and apply custom logic.
    """
    
    def __init__(self):
        # Mapping from common rule prefixes or tags to CWE IDs
        self.cwe_mapping = {
            'sql': 'CWE-89',
            'sqli': 'CWE-89',
            'xss': 'CWE-79',
            'cross-site': 'CWE-79',
            'command': 'CWE-78',
            'os-injection': 'CWE-78',
            'path': 'CWE-22',
            'traversal': 'CWE-22',
            'deserial': 'CWE-502',
            'hardcoded': 'CWE-798',
            'secret': 'CWE-798',
            'crypt': 'CWE-327',
            'hash': 'CWE-328',
            'insecure': 'CWE-327'
        }
        
        # Mapping from vulnerability type to OWASP Top 10 (2021)
        self.owasp_mapping = {
            'sql': 'A03:2021-Injection',
            'command': 'A03:2021-Injection',
            'xss': 'A03:2021-Injection',
            'path': 'A01:2021-Broken Access Control',
            'deserial': 'A08:2021-Software and Data Integrity Failures',
            'secret': 'A07:2021-Identification and Authentication Failures',
            'auth': 'A07:2021-Identification and Authentication Failures',
            'crypt': 'A02:2021-Cryptographic Failures'
        }

    def process_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for processing a finding.
        """
        # 1. Normalize Severity (Ensure it matches our enum)
        finding['severity'] = self.normalize_severity(finding.get('severity', 'MEDIUM'))
        
        # 2. Enrich with Metadata (CWE/OWASP)
        finding = self.enrich_metadata(finding)
        
        # 3. Apply Path-based Overrides
        finding = self.apply_overrides(finding)
        
        return finding

    def normalize_severity(self, raw_severity: str) -> str:
        """Normalizes external severity levels to internal ones."""
        if not isinstance(raw_severity, str):
            return Severity.MEDIUM.value
            
        s = raw_severity.upper()
        if s in [sev.value for sev in Severity]:
            return s
            
        # Common external mappings
        mapping = {
            'ERROR': 'HIGH',
            'WARNING': 'MEDIUM',
            'INFO': 'INFO',
            'NOTE': 'INFO',
            'CRITICAL': 'CRITICAL',
            'FATAL': 'CRITICAL',
            'MAJOR': 'HIGH',
            'MINOR': 'LOW',
            'BLOCKER': 'CRITICAL'
        }
        return mapping.get(s, Severity.MEDIUM.value)

    def enrich_metadata(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Adds CWE and OWASP IDs based on rule ID and vulnerability type."""
        rule_id = finding.get('rule_id', '').lower()
        vuln_type = finding.get('vulnerability_type', '').lower()
        
        # Determine CWE if not present
        if not finding.get('cwe_id'):
            for key, cwe in self.cwe_mapping.items():
                if key in rule_id or key in vuln_type:
                    finding['cwe_id'] = cwe
                    break
        
        # Determine OWASP if not present
        if not finding.get('owasp_id'):
            for key, owasp in self.owasp_mapping.items():
                if key in rule_id or key in vuln_type:
                    finding['owasp_id'] = owasp
                    break
                    
        return finding

    def apply_overrides(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Applies logic-based overrides (e.g., lower severity for test files).
        Similar to SCB Post-Processing Hook.
        """
        file_path = finding.get('file_path', '').lower()
        
        # Rule 1: Downgrade everything in 'test' or 'mock' folders to INFO or LOW
        if 'test' in file_path or 'mock' in file_path or 'example' in file_path:
            old_sev = finding['severity']
            if old_sev in ['CRITICAL', 'HIGH', 'MEDIUM']:
                finding['severity'] = 'LOW'
                finding['message'] = f"[TEST-CODE] {finding.get('message', '')} (Severity downgraded from {old_sev})"
                finding['is_test_code'] = True
        
        # Rule 2: High Confidence secrets should be CRITICAL
        if 'secret' in finding.get('rule_id', '').lower() and finding.get('confidence_level') == 'HIGH':
            finding['severity'] = 'CRITICAL'
            
        return finding

    def normalize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Processes a list of findings."""
        return [self.process_finding(f) for f in findings]
