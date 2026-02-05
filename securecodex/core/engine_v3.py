import os
import time
import re
from typing import List, Dict, Any, Optional
from .parser_manager import ParserManager
from .matcher import Matcher
from .dsl_parser import DSLParser
from .taint_engine import TaintEngine
from .utils import calculate_file_hash
from ..models import Severity

from .db import ScanDB
from .confidence_calculator import ConfidenceCalculator
from .framework_detector import FrameworkDetector
from .context_filter import ContextFilter
from .reachability_analyzer import ReachabilityAnalyzer
from .findings_processor import FindingsProcessor

class EngineV3:
    """
    Engine V3 Coordinator.
    Orchestrates the multi-phase analysis process.
    """
    
    def __init__(self, rules_dir: str, db_path: str = ".securecodex.db", min_confidence: str = 'MEDIUM', selected_languages: List[str] = None):
        self.parser_manager = ParserManager()
        self.matcher = Matcher(self.parser_manager)
        self.dsl_parser = DSLParser(rules_dir)
        self.taint_engine = TaintEngine(self.parser_manager)
        self.selected_languages = selected_languages
        
        # Initialize new analysis modules
        self.confidence_calc = ConfidenceCalculator()
        self.framework_detector = FrameworkDetector()
        self.context_filter = ContextFilter()
        self.reachability_analyzer = ReachabilityAnalyzer()
        self.findings_processor = FindingsProcessor()
        
        self.min_confidence = min_confidence  # Minimum confidence level to report
        self.rules = self.dsl_parser.load_rules(selected_languages=selected_languages)
        self.db = ScanDB(db_path)
        print(f"[INFO] EngineV3 initialized with {len(self.rules)} rules.")
        print(f"[INFO] Minimum confidence level: {min_confidence}")

    def scan_project(self, project_path: str) -> List[Dict[str, Any]]:
        """
        Scan a complete project directory.
        """
        all_findings = []
        files_to_scan = self._get_all_files(project_path)
        
        for file_path in files_to_scan:
            findings = self.scan_file(file_path)
            all_findings.extend(findings)
            
        return self._deduplicate(all_findings)


    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a single file through all execution phases.
        Implements incremental scanning via hashing.
        """
        findings = []
        
        # Incremental Scanning: Check if file has changed
        current_hash = calculate_file_hash(file_path)
        stored_hash = self.db.get_hash(file_path)
        if stored_hash == current_hash:
            return [] # Skip unchanged file
        
        self.db.update_hash(file_path, current_hash)
        content = self._read_file(file_path)
        if not content:
            return []
            
        language = self._detect_language(file_path)
        applicable_rules = self._get_applicable_rules(language)
        # print(f"DEBUG: Found {len(applicable_rules)} applicable rules for language '{language}'")
        
        # Phase 1: Filter (L0) - Fast regex pre-filter
        filtered_rules = self._pre_filter(content, applicable_rules)
        # print(f"DEBUG: {len(filtered_rules)} rules remain after L0 filter")
        if not filtered_rules:
            return []


        # Phase 2: AST Parsing
        tree = self.parser_manager.parse(content, language)
        if not tree:
            # Fallback for generic or unknown languages: simplified regex scan
            return self._fallback_regex_scan(content, filtered_rules, file_path)

        # Detect frameworks for context-aware analysis
        framework_context = self.framework_detector.detect_frameworks(content, language, file_path)

        # Phase 3: Pattern (L1) - Structural Matching
        for rule in filtered_rules:
            if rule.get('mode') == 'taint':
                continue
                
            rule_findings = self.matcher.evaluate_rule(rule, tree, content)
            for rf in rule_findings:
                # Enrich with context
                rf = self.context_filter.enrich_finding_context(rf, content, language)
                rf = self.reachability_analyzer.enrich_finding_with_reachability(rf, tree)
                
                # Check if should be filtered
                should_filter, filter_reason = self.context_filter.should_filter_finding(rf, content, language)
                if should_filter:
                    continue
                
                # Calculate confidence score
                context_data = {
                    'is_test_code': rf.get('context', {}).get('is_test_code', False),
                    'is_reachable': rf.get('is_reachable', True),
                    'in_comment': rf.get('context', {}).get('in_comment', False),
                    'framework_protection': self.framework_detector.should_reduce_confidence(
                        framework_context, self._get_vulnerability_type(rule)
                    ),
                }
                
                confidence_score = self.confidence_calc.calculate_confidence(rf, rule, context_data)
                
                # Filter by minimum confidence
                if not self.confidence_calc.should_report(confidence_score, self.min_confidence):
                    continue
                
                rf.update({
                    "rule_id": rule['id'],
                    "severity": rule['severity'],
                    "file_path": file_path,
                    "message": rule.get('message', ''),
                    "phase": "structural",
                    "confidence_score": confidence_score,
                    "confidence_level": self.confidence_calc.get_confidence_level(confidence_score),
                    "framework_context": framework_context.get('frameworks', []),
                })
                findings.append(rf)

        # Phase 4: Deep (L2) - Taint Analysis (Enhanced)
        taint_rules = [r for r in filtered_rules if r.get('mode') == 'taint']
        for rule in taint_rules:
            # Mandatory validation: taint rules MUST have sources and sinks
            if not rule.get('pattern-sources') or not rule.get('pattern-sinks'):
                continue
            
            # 1. Identify all components
            sources = []
            for src_block in rule.get('pattern-sources', []):
                sources.extend(self.matcher.find_nodes(src_block, tree.root_node, content))
            
            sinks = []
            for sink_block in rule.get('pattern-sinks', []):
                sinks.extend(self.matcher.find_nodes(sink_block, tree.root_node, content))
                
            sanitizers = []
            for san_block in rule.get('pattern-sanitizers', []):
                sanitizers.extend(self.matcher.find_nodes(san_block, tree.root_node, content))
            
            # Mandatory detection model: must have both source and sink
            if not sources or not sinks:
                continue
            propagators = rule.get('pattern-propagators', [])
            vulnerability_type = self._get_vulnerability_type(rule)
            
            taint_findings = self.taint_engine.analyze_flow(
                tree, sources, sinks, sanitizers, 
                propagators=propagators, 
                matcher=self.matcher, 
                content=content,
                language=language,
                vulnerability_type=vulnerability_type
            )
            
            # 3. Process findings with confidence scoring
            for tf in taint_findings:
                # Enrich with context
                tf = self.context_filter.enrich_finding_context(tf, content, language)
                tf = self.reachability_analyzer.enrich_finding_with_reachability(tf, tree)
                
                # Check if should be filtered
                should_filter, filter_reason = self.context_filter.should_filter_finding(tf, content, language)
                if should_filter:
                    continue
                
                # Calculate confidence score for taint findings
                context_data = {
                    'is_test_code': tf.get('context', {}).get('is_test_code', False),
                    'is_reachable': tf.get('is_reachable', True),
                    'in_comment': tf.get('context', {}).get('in_comment', False),
                    'framework_protection': self.framework_detector.should_reduce_confidence(
                        framework_context, vulnerability_type
                    ),
                }
                
                confidence_score = self.confidence_calc.calculate_confidence(tf, rule, context_data)
                
                # Filter by minimum confidence
                if not self.confidence_calc.should_report(confidence_score, self.min_confidence):
                    continue
                
                tf.update({
                    "rule_id": rule['id'],
                    "severity": rule['severity'],
                    "file_path": file_path,
                    "message": rule.get('message', ''),
                    "phase": "taint",
                    "confidence_score": confidence_score,
                    "confidence_level": self.confidence_calc.get_confidence_level(confidence_score),
                    "framework_context": framework_context.get('frameworks', []),
                    "vulnerability_type": vulnerability_type,
                })
                # Add line info if missing (TaintEngine should provide it)
                if 'line' not in tf:
                    tf['line'] = tf['sink'].start_point[0] + 1
                    tf['column'] = tf['sink'].start_point[1]
                    tf['snippet'] = tf['sink'].text.decode('utf8')
                findings.append(tf)

        # Phase 5: Post-Processing & Enrichment
        return self.findings_processor.normalize_findings(findings)

    def _fallback_regex_scan(self, content: str, rules: List[Dict], file_path: str) -> List[Dict]:
        """Simple regex-based scan for files where AST parsing failed or language is generic."""
        findings = []
        for rule in rules:
            patterns = self._extract_all_patterns(rule)
            for p in patterns:
                try:
                    # Robust literal/regex mixed match
                    # 1. Normalize whitespace in pattern
                    p_norm = re.sub(r'\s+', ' ', p.strip())
                    # 2. Escape for regex but then handle our special tokens
                    pattern_regex = re.escape(p_norm)
                    # 3. Replace escaped metavariables \$VAR with .*
                    pattern_regex = re.sub(r'\\\$\w+', '.*', pattern_regex)
                    # 4. Replace escaped ellipsis \.\.\. with .*
                    pattern_regex = pattern_regex.replace(r'\\\.\\\.\\\.', '.*')
                    # 5. Replace literal spaces with \s+ to be whitespace-agnostic
                    pattern_regex = pattern_regex.replace(r'\ ', r'\s+')
                    
                    match = re.search(pattern_regex, content, re.I | re.S)
                    if match:
                        line = content.count('\n', 0, match.start()) + 1
                        findings.append({
                            "rule_id": rule['id'],
                            "severity": rule['severity'],
                            "file_path": file_path,
                            "line": line,
                            "column": match.start() - content.rfind('\n', 0, match.start()),
                            "message": rule.get('message', ''),
                            "snippet": match.group(0),
                            "phase": "fallback-regex"
                        })
                except Exception as e: # Catch specific exception for better debugging
                    # print(f"DEBUG: Error in fallback regex scan for rule {rule.get('id', 'N/A')} with pattern '{p}': {e}")
                    pass
                    continue
        return findings

    def _extract_all_patterns(self, block: Dict) -> List[str]:
        """Recursively extract all literal patterns/regexes from a rule block."""
        if not isinstance(block, dict):
            return []
            
        patterns = []
        if 'pattern' in block and block['pattern']: patterns.append(block['pattern'])
        if 'pattern-regex' in block and block['pattern-regex']: patterns.append(block['pattern-regex'])
        
        # Helper to process lists of patterns
        def process_list(key):
            items = block.get(key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        patterns.append(item)
                    elif isinstance(item, dict):
                        patterns.extend(self._extract_all_patterns(item))

        process_list('pattern-either')
        process_list('patterns')
        process_list('pattern-sources')
        process_list('pattern-sinks')
        process_list('pattern-sanitizers')
        
        if 'pattern-inside' in block and block['pattern-inside']:
            patterns.append(block['pattern-inside'])

        # Filter out anything that isn't a string (e.g. None from empty keys)
        return list(set(p for p in patterns if isinstance(p, str)))

    def _get_all_files(self, path: str) -> List[str]:
        files = []
        for root, _, filenames in os.walk(path):
            for f in filenames:
                files.append(os.path.join(root, f))
        return files

    def _read_file(self, path: str) -> Optional[str]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except:
            return None

    def _detect_language(self, path: str) -> str:
        ext = path.split('.')[-1].lower()
        mapping = {
            'py': 'python', 'js': 'javascript', 'ts': 'typescript',
            'java': 'java', 'go': 'go', 'php': 'php', 'cpp': 'cpp',
            'cs': 'csharp', 'cls': 'apex', 'sh': 'bash', 'bash': 'bash',
            'c': 'c'
        }
        # Handle Dockerfile (no extension or capitalized)
        if ext == 'dockerfile' or os.path.basename(path).lower() == 'dockerfile':
            return 'dockerfile'
            
        return mapping.get(ext, 'unknown')

    def _get_applicable_rules(self, language: str) -> List[Dict]:
        return [r for r in self.rules if 'all' in r['languages'] or language in r['languages']]

    def _pre_filter(self, content: str, rules: List[Dict]) -> List[Dict]:
        """Skip rules whose literal keywords are not found in the content."""
        if not rules:
            return []
            
        filtered = []
        for rule in rules:
            keywords = rule.get('keywords', [])
            if not keywords:
                # If no keywords were extracted, we can't safely skip it
                filtered.append(rule)
                continue
            
            # Check if ANY keyword matches
            if any(kw in content for kw in keywords):
                filtered.append(rule)
                
        return filtered

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Remove redundant findings based on rule ID, file, and line."""
        seen = set()
        deduped = []
        for f in findings:
            key = (f['rule_id'], f['file_path'], f.get('line', 0), f.get('snippet', ''))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
    
    def _get_vulnerability_type(self, rule: Dict) -> str:
        """Extract vulnerability type from rule."""
        rule_id = rule.get('id', '').lower()
        
        # Map common patterns to vulnerability types
        if 'sql' in rule_id or 'sqli' in rule_id:
            return 'sql'
        elif 'xss' in rule_id or 'cross-site' in rule_id:
            return 'xss'
        elif 'command' in rule_id or 'cmd' in rule_id or 'os-injection' in rule_id:
            return 'command'
        elif 'path' in rule_id or 'traversal' in rule_id:
            return 'path'
        elif 'csrf' in rule_id:
            return 'csrf'
        elif 'deserial' in rule_id:
            return 'deserialization'
        else:
            # Check metadata
            return rule.get('metadata', {}).get('vulnerability_type', 'unknown')
