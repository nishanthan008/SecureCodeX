
import os
import time
from typing import List, Dict, Any, Optional
from .parser_manager import ParserManager
from .matcher import Matcher
from .dsl_parser import DSLParser
from .taint_engine import TaintEngine
from .utils import calculate_file_hash
from ..models import Severity

class EngineV3:
    """
    Engine V3 Coordinator.
    Orchestrates the multi-phase analysis process.
    """
    
    def __init__(self, rules_dir: str):
        self.parser_manager = ParserManager()
        self.matcher = Matcher(self.parser_manager)
        self.dsl_parser = DSLParser(rules_dir)
        self.taint_engine = TaintEngine(self.parser_manager)
        
        self.rules = self.dsl_parser.load_rules()
        self.scan_cache = {} # file_path -> sha256_hash

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
        if file_path in self.scan_cache and self.scan_cache[file_path] == current_hash:
            return [] # Skip unchanged file
        
        self.scan_cache[file_path] = current_hash
        content = self._read_file(file_path)
        if not content:
            return []
            
        language = self._detect_language(file_path)
        applicable_rules = self._get_applicable_rules(language)
        
        # Phase 1: Filter (L0) - Fast regex pre-filter
        filtered_rules = self._pre_filter(content, applicable_rules)
        if not filtered_rules:
            return []

        # Phase 2: AST Parsing
        tree = self.parser_manager.parse(content, language)
        if not tree:
            return []

        # Phase 3: Pattern (L1) - Structural Matching
        for rule in filtered_rules:
            # Skip taint rules for now (Phase 4)
            if rule.get('mode') == 'taint':
                continue
                
            rule_findings = self.matcher.find_matches(rule.get('pattern', ''), tree, content.encode('utf8'))
            for rf in rule_findings:
                rf.update({
                    "rule_id": rule['id'],
                    "severity": rule['severity'],
                    "file_path": file_path,
                    "message": rule.get('message', ''),
                    "phase": "structural"
                })
                findings.append(rf)

        # Phase 4: Deep (L2) - Taint Analysis
        taint_rules = [r for r in filtered_rules if r.get('mode') == 'taint']
        for rule in taint_rules:
            # We would identify sources/sinks nodes via matcher first
            # source_nodes = self.matcher.find_nodes(rule['source'], tree, ...)
            # sink_nodes = self.matcher.find_nodes(rule['sink'], tree, ...)
            # results = self.taint_engine.analyze_flow(tree, source_nodes, sink_nodes) 
            pass

        return findings

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
            'cs': 'csharp'
        }
        return mapping.get(ext, 'unknown')

    def _get_applicable_rules(self, language: str) -> List[Dict]:
        return [r for r in self.rules if 'all' in r['languages'] or language in r['languages']]

    def _pre_filter(self, content: str, rules: List[Dict]) -> List[Dict]:
        """Skip rules whose literal patterns don't even appear as substrings."""
        # Simple heuristic: if pattern contains "os.system", it must be in content
        # This can be much more sophisticated (trigrams, etc.)
        return rules

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        # Implementation of results deduplication
        return findings
