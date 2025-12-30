"""
Confidence Calculator for SecureCodeX.
Implements the mandatory detection model scoring system (0-100 scale).
"""

from typing import Dict, Any, Optional


class ConfidenceCalculator:
    """
    Calculates confidence scores for vulnerability findings.
    
    Scoring Model:
    - User-controlled source detected: +30
    - Dangerous sink confirmed: +30
    - Unsanitized data flow: +25
    - Known vulnerable API: +10
    - Weak heuristic evidence: +5
    
    Thresholds:
    - ≥80: High confidence (report as vulnerability)
    - 60-79: Medium confidence (warning)
    - <60: Low confidence (informational)
    """
    
    def __init__(self):
        # Known dangerous sinks by category
        self.dangerous_sinks = {
            'sql': ['execute', 'executemany', 'raw', 'query', 'filter_by'],
            'command': ['system', 'popen', 'exec', 'eval', 'spawn', 'run'],
            'file': ['open', 'read', 'write', 'unlink', 'remove'],
            'network': ['request', 'urlopen', 'fetch', 'get', 'post'],
            'deserialization': ['pickle.loads', 'yaml.load', 'eval', 'unserialize'],
            'template': ['render_template_string', 'Template', 'compile'],
        }
        
        # Known user-controlled sources
        self.user_sources = {
            'request': ['request.args', 'request.form', 'request.json', 'request.data', 
                       'request.params', 'request.query', 'request.body', 'req.params',
                       'req.query', 'req.body', '$_GET', '$_POST', '$_REQUEST'],
            'file_upload': ['request.files', 'req.files', '$_FILES'],
            'environment': ['os.environ', 'process.env', 'getenv'],
            'url': ['request.url', 'request.path', 'window.location'],
        }
    
    def calculate_confidence(
        self, 
        finding: Dict[str, Any], 
        rule: Dict[str, Any], 
        context: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Calculate confidence score for a finding.
        
        Args:
            finding: The vulnerability finding
            rule: The rule that generated the finding
            context: Additional context (framework, reachability, etc.)
        
        Returns:
            Confidence score (0-100)
        """
        score = 0
        context = context or {}
        
        # Base score from rule metadata
        rule_confidence = rule.get('metadata', {}).get('confidence', 0)
        if isinstance(rule_confidence, float) and rule_confidence <= 1.0:
            # Convert old 0-1.0 scale to 0-100
            score = int(rule_confidence * 100)
        elif isinstance(rule_confidence, (int, float)):
            score = int(rule_confidence)
        
        # For taint-mode rules, apply the mandatory detection model
        if rule.get('mode') == 'taint':
            score = self._calculate_taint_confidence(finding, rule, context)
        else:
            # For pattern-based rules, adjust based on context
            score = self._calculate_pattern_confidence(finding, rule, context, score)
        
        # Apply context adjustments
        score = self._apply_context_adjustments(score, finding, context)
        
        # Ensure score is within bounds
        return max(0, min(100, score))
    
    def _calculate_taint_confidence(
        self, 
        finding: Dict[str, Any], 
        rule: Dict[str, Any],
        context: Dict[str, Any]
    ) -> int:
        """Calculate confidence for taint-analysis findings."""
        score = 0
        
        # 1. User-controlled source detected (+30)
        if self._has_user_controlled_source(finding, rule):
            score += 30
        
        # 2. Dangerous sink confirmed (+30)
        if self._has_dangerous_sink(finding, rule):
            score += 30
        
        # 3. Unsanitized data flow (+25)
        sanitization_status = finding.get('sanitization_status', 'UNKNOWN')
        if sanitization_status == 'MISSING':
            score += 25
        elif sanitization_status == 'WEAK':
            score += 15
        elif sanitization_status == 'BYPASSED':
            score += 20
        
        # 4. Known vulnerable API (+10)
        if self._uses_vulnerable_api(finding, rule):
            score += 10
        
        # 5. Evidence quality (+5)
        if finding.get('evidence') and len(finding.get('evidence', [])) >= 3:
            score += 5
        
        return score
    
    def _calculate_pattern_confidence(
        self,
        finding: Dict[str, Any],
        rule: Dict[str, Any],
        context: Dict[str, Any],
        base_score: int
    ) -> int:
        """Calculate confidence for pattern-based findings."""
        score = base_score
        
        # Hardcoded secrets and credentials are high confidence
        if 'secret' in rule.get('id', '').lower() or 'credential' in rule.get('id', '').lower():
            score = max(score, 85)
        
        # Deprecated/insecure APIs are medium-high confidence
        if 'deprecated' in rule.get('id', '').lower() or 'insecure' in rule.get('id', '').lower():
            score = max(score, 75)
        
        # Configuration issues are medium confidence
        if 'config' in rule.get('id', '').lower():
            score = max(score, 65)
        
        return score
    
    def _apply_context_adjustments(
        self,
        score: int,
        finding: Dict[str, Any],
        context: Dict[str, Any]
    ) -> int:
        """Apply context-based adjustments to confidence score."""
        
        # Reduce confidence for test code
        if context.get('is_test_code', False):
            score = int(score * 0.5)  # 50% reduction
        
        # Reduce confidence for unreachable code
        if context.get('is_reachable', True) is False:
            score = int(score * 0.3)  # 70% reduction
        
        # Reduce confidence for commented code
        if context.get('in_comment', False):
            score = int(score * 0.2)  # 80% reduction
        
        # Increase confidence if framework protections are absent
        if context.get('framework_protection', False) is False:
            score = min(100, score + 10)
        
        # Increase confidence for known CVE patterns
        if finding.get('cve_id'):
            score = min(100, score + 15)
        
        return score
    
    def _has_user_controlled_source(self, finding: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if the finding has a user-controlled source."""
        source_node = finding.get('source')
        if not source_node:
            return False
        
        source_text = source_node.text.decode('utf8') if hasattr(source_node, 'text') else str(source_node)
        
        # Check against known user sources
        for category, patterns in self.user_sources.items():
            for pattern in patterns:
                if pattern in source_text:
                    return True
        
        return False
    
    def _has_dangerous_sink(self, finding: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if the finding has a dangerous sink."""
        sink_node = finding.get('sink')
        if not sink_node:
            return False
        
        sink_text = sink_node.text.decode('utf8') if hasattr(sink_node, 'text') else str(sink_node)
        
        # Check against known dangerous sinks
        for category, patterns in self.dangerous_sinks.items():
            for pattern in patterns:
                if pattern in sink_text:
                    return True
        
        return False
    
    def _uses_vulnerable_api(self, finding: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if the finding uses a known vulnerable API."""
        # Check if rule has CVE or known vulnerability metadata
        metadata = rule.get('metadata', {})
        if metadata.get('cve') or metadata.get('vulnerability'):
            return True
        
        # Check for known vulnerable patterns in rule ID
        vulnerable_keywords = ['md5', 'sha1', 'des', 'rc4', 'eval', 'pickle', 'yaml.load']
        rule_id = rule.get('id', '').lower()
        
        return any(keyword in rule_id for keyword in vulnerable_keywords)
    
    def get_confidence_level(self, score: int) -> str:
        """
        Convert numeric confidence score to level.
        
        Args:
            score: Confidence score (0-100)
        
        Returns:
            Confidence level: 'HIGH', 'MEDIUM', or 'LOW'
        """
        if score >= 80:
            return 'HIGH'
        elif score >= 60:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def should_report(self, score: int, min_confidence: str = 'MEDIUM') -> bool:
        """
        Determine if a finding should be reported based on confidence.
        
        Args:
            score: Confidence score (0-100)
            min_confidence: Minimum confidence level to report ('HIGH', 'MEDIUM', 'LOW')
        
        Returns:
            True if finding should be reported
        """
        level = self.get_confidence_level(score)
        
        levels_order = ['LOW', 'MEDIUM', 'HIGH']
        min_index = levels_order.index(min_confidence)
        current_index = levels_order.index(level)
        
        return current_index >= min_index
