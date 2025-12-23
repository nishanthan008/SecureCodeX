
import json
import os
from datetime import datetime
from typing import List, Dict, Any

class SARIFReporter:
    """
    Generates SARIF v2.1.0 reports for static analysis results.
    Natively supported by GitHub Advanced Security, GitLab, and Azure DevOps.
    """
    
    def __init__(self, project_path: str):
        self.project_path = os.path.abspath(project_path)

    def generate(self, findings: List[Dict[str, Any]], output_path: str):
        sarif_log = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureCodeX",
                            "version": "3.0.0",
                            "informationUri": "https://github.com/nishanthan008/SecureCodeX",
                            "rules": self._extract_rules(findings)
                        }
                    },
                    "results": self._convert_findings(findings)
                }
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_log, f, indent=2)

    def _extract_rules(self, findings: List[Dict]) -> List[Dict]:
        rules = {}
        for f in findings:
            rule_id = f['rule_id']
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.get('message', 'Security finding')},
                    "defaultConfiguration": {"level": self._map_severity(f['severity'])}
                }
        return list(rules.values())

    def _convert_findings(self, findings: List[Dict]) -> List[Dict]:
        results = []
        for f in findings:
            rel_path = os.path.relpath(f['file_path'], self.project_path)
            results.append({
                "ruleId": f['rule_id'],
                "message": {"text": f['message']},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": rel_path},
                            "region": {
                                "startLine": f['line'],
                                "startColumn": f['column'],
                                "snippet": {"text": f.get('snippet', '')}
                            }
                        }
                    }
                ],
                "level": self._map_severity(f['severity']),
                "properties": {
                    "confidence": f.get('confidence', 'MEDIUM'),
                    "phase": f.get('phase', 'unknown')
                }
            })
        return results

    def _map_severity(self, severity: str) -> str:
        mapping = {
            'ERROR': 'error',
            'WARNING': 'warning',
            'INFO': 'note'
        }
        return mapping.get(severity, 'note')
