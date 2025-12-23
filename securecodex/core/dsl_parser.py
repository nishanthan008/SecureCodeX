
import yaml
import os
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
                data = yaml.safe_load(f)
                if not data or 'rules' not in data:
                    return []
                
                # Normalize rules
                for rule in data['rules']:
                    rule['file_source'] = file_path
                    # Add default values for missing keys
                    rule.setdefault('severity', 'INFO')
                    rule.setdefault('languages', ['all'])
                    
                return data['rules']
        except Exception as e:
            print(f"Error parsing rule file {file_path}: {e}")
            return []
