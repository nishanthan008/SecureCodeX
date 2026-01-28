import yaml
import os
import re
from typing import List, Dict, Any

class DSLParser:
    """
    Parses YAML-based rule definitions (Semgrep-style).
    Handles metadata, pattern extraction, and taint configurations.
    """
    
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir

    def load_rules(self) -> List[Dict[str, Any]]:
        """Load all .yaml rules from the specified directory."""
        all_rules = []
        if not os.path.exists(self.rules_dir):
            return []
            
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(('.yaml', '.yml')):
                    rules = self._parse_file(os.path.join(root, file))
                    all_rules.extend(rules)
        return all_rules

    def _parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Support multi-document YAML files
                docs = list(yaml.safe_load_all(f))
                all_file_rules = []
                for data in docs:
                    if not data or 'rules' not in data:
                        continue
                    
                    # Normalize rules
                    for i, rule in enumerate(data['rules']):
                        rule['file_source'] = file_path
                        if 'id' not in rule:
                            # Fallback ID: filename + index
                            base = os.path.basename(file_path).split('.')[0]
                            rule['id'] = f"auto-{base}-{i}"
                        
                        rule.setdefault('severity', 'INFO')
                        rule.setdefault('languages', ['all'])
                        # Pre-calculate keywords for L0 filtering
                        rule['keywords'] = self._extract_keywords(rule)
                        all_file_rules.append(rule)
                        
                return all_file_rules
        except Exception as e:
            # print(f"Error parsing rule file {file_path}: {e}")
            return []

    def _extract_keywords(self, rule: Dict[str, Any]) -> List[str]:
        """Extract literal keywords from patterns for fast pre-filtering."""
        keywords = set()
        
        def process_block(block):
            if isinstance(block, str):
                # Extract words/method calls that aren't metavariables or wildcards
                # Use a regex that finds contiguous alphanumeric strings (plus dots/underscores)
                # Filter out anything that starts with $ or is too short
                literals = re.findall(r'[a-zA-Z0-9_\.]{4,}', block)
                for lit in literals:
                    if not lit.startswith('$') and lit not in ['true', 'false', 'None', 'self', 'pattern', 'regex']:
                        keywords.add(lit)
                
                # Also extract potential keywords from pattern-regex if they are long enough
                if 'pattern-regex' in block:
                    regex_literals = re.findall(r'[a-zA-Z]{5,}', str(block))
                    for rlit in regex_literals:
                        if len(rlit) >= 6: # Only high-entropy literals
                            keywords.add(rlit)
            elif isinstance(block, dict):
                for k, v in block.items():
                    if k in ['pattern', 'pattern-inside', 'pattern-not-inside', 'pattern-regex', 'pattern-either', 'patterns', 'pattern-not']:
                        process_block(v)
            elif isinstance(block, list):
                for item in block:
                    process_block(item)

        process_block(rule)
        return list(keywords)
