
from typing import List, Dict, Any

class EvidenceGenerator:
    """
    Generates structured evidence for security findings.
    Transforms raw AST paths into a human-readable proof sequence.
    """
    
    @staticmethod
    def generate_proof(path: List[Any], context_metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a proof object from a sequence of AST nodes.
        """
        proof = {
            "summary": "Source-to-Sink Data Flow",
            "steps": [],
            "verifiable": True
        }
        
        for i, node in enumerate(path):
            role = "SOURCE" if i == 0 else "SINK" if i == len(path)-1 else "DATA_FLOW"
            
            # Extract line and snippet (mock for PoC)
            step = {
                "order": i + 1,
                "role": role,
                "line": node.start_point[0] + 1 if hasattr(node, 'start_point') else 0,
                "node_type": node.type if hasattr(node, 'type') else "Unknown",
                "evidence": f"Node matched at line {node.start_point[0] + 1}" if hasattr(node, 'start_point') else ""
            }
            proof["steps"].append(step)
            
        return proof

    @staticmethod
    def format_as_text(proof: Dict[str, Any]) -> str:
        """Format the proof as a readable string for CLI output."""
        lines = [f"Proof: {proof['summary']}"]
        for step in proof['steps']:
            lines.append(f"  [{step['order']}] {step['role']}: Line {step['line']} ({step['node_type']})")
        return "\n".join(lines)
