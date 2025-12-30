
from typing import List, Dict, Any, Set, Optional
from .sanitizer_library import SanitizerLibrary, SanitizerEffectiveness

class TaintEngine:
    """
    Implements source-to-sink taint analysis.
    Tracks data flow through the AST to verify if user input reaches a dangerous sink.
    Enhanced with sanitizer effectiveness analysis.
    """
    
    def __init__(self, parser_manager):
        self.parser_manager = parser_manager
        self.sanitizer_lib = SanitizerLibrary()

    def analyze_flow(self, tree: Any, sources_nodes: List[Any], sinks_nodes: List[Any], sanitizers_nodes: List[Any] = None, propagators: List[Dict] = None, matcher: Any = None, content: str = "", language: str = "unknown", vulnerability_type: str = "unknown") -> List[Dict[str, Any]]:
        """
        Main entry point for taint analysis on a given tree.
        Enhanced with sanitizer effectiveness analysis.
        """
        findings = []
        dfg, node_map = self._build_dfg(tree, propagators, matcher, content)
        sanitizer_ids = {id(n) for n in (sanitizers_nodes or [])}
        
        for source in sources_nodes:
            # Find all paths from source to sinks
            tainted_paths = self._find_paths_to_sinks(source, sinks_nodes, sanitizer_ids, dfg, node_map)
            
            for path in tainted_paths:
                # Analyze sanitization along the path
                sanitization_analysis = self._analyze_path_sanitization(
                    path, sanitizers_nodes or [], language, vulnerability_type
                )
                
                findings.append({
                    "source": path[0],
                    "sink": path[-1],
                    "path": path,
                    "evidence": self._generate_evidence_sequence(path),
                    "sanitization_status": sanitization_analysis['status'],
                    "sanitization_explanation": sanitization_analysis['explanation'],
                    "sanitizers_found": sanitization_analysis.get('sanitizers_found', []),
                })
        
        return findings

    def _build_dfg(self, tree: Any, propagators: List[Dict] = None, matcher: Any = None, content: str = "") -> (Dict[int, Set[int]], Dict[int, Any]):
        """
        Build a Data Flow Graph.
        Returns a mapping of node IDs to reachable node IDs and a node_id -> node_obj map.
        """
        dfg = {}
        node_map = {}
        
        def add_edge(u, v):
            uid, vid = id(u), id(v)
            node_map[uid], node_map[vid] = u, v
            if uid not in dfg: dfg[uid] = set()
            dfg[uid].add(vid)

        # 1. Generic AST-based flow
        def walk(node):
            node_map[id(node)] = node
            
            # Python Assignment: lhs = rhs
            if node.type in ['assignment', 'assign']:
                lhs = node.child_by_field_name('left') or node.child_by_field_name('targets')
                rhs = node.child_by_field_name('right') or node.child_by_field_name('value')
                if lhs and rhs:
                    add_edge(rhs, lhs)
            
            # F-Strings / JoinedStr (Python)
            if node.type in ['joinedstr', 'f_string']:
                for i in range(node.child_count):
                    add_edge(node.child(i), node)

            # Subscripts (x[0])
            if node.type == 'subscript':
                value = node.child_by_field_name('value')
                if value:
                    add_edge(value, node)

            # Identifier usage in calls/ops
            if node.type in ['identifier', 'name']:
                p = node.parent
                if p:
                    # Flow from var name to the expression using it
                    add_edge(node, p)

            for i in range(node.child_count):
                walk(node.child(i))

        walk(tree.root_node)
        
        # 2. Pattern Propagators (Advanced flow like list.append or string builders)
        if propagators and matcher:
            for prop in propagators:
                pattern = prop.get('pattern')
                from_var = prop.get('from')
                to_var = prop.get('to')
                
                if pattern and from_var and to_var:
                    # Find instances of the propagator pattern
                    matches = matcher.evaluate_rule({'id': 'temp-prop', 'pattern': pattern}, tree, content)
                    for m in matches:
                        bindings = m.get('bindings', {})
                        u_node = bindings.get(from_var)
                        v_node = bindings.get(to_var)
                        if u_node and v_node:
                            # Taint flows from 'from' node to 'to' node
                            # If they are nodes, add edge. 
                            # If they are strings (captured meta), we might need to find the node index.
                            if hasattr(u_node, 'id') and hasattr(v_node, 'id'):
                                add_edge(u_node, v_node)

        return dfg, node_map

    def _find_paths_to_sinks(self, source: Any, sinks: List[Any], sanitizer_ids: Set[int], dfg: Dict, node_map: Dict) -> List[List[Any]]:
        """
        Breadth-first search on the DFG to find reachable sinks while avoiding sanitizers.
        """
        paths = []
        sink_ids = {id(s) for s in sinks}
        queue = [[source]]
        visited = {id(source)}
        
        while queue:
            path = queue.pop(0)
            node = path[-1]
            
            if id(node) in sink_ids:
                paths.append(path)
                continue
            
            if id(node) in sanitizer_ids:
                continue 
                
            for next_node_id in dfg.get(id(node), []):
                if next_node_id not in visited:
                    visited.add(next_node_id)
                    next_node = node_map.get(next_node_id)
                    if next_node:
                        new_path = list(path)
                        new_path.append(next_node)
                        queue.append(new_path)
        return paths

    def _analyze_path_sanitization(
        self, 
        path: List[Any], 
        sanitizers: List[Any],
        language: str,
        vulnerability_type: str
    ) -> Dict[str, Any]:
        """
        Analyze sanitization effectiveness along a data flow path.
        
        Args:
            path: List of AST nodes in the data flow path
            sanitizers: List of sanitizer nodes
            language: Programming language
            vulnerability_type: Type of vulnerability
        
        Returns:
            Dictionary with sanitization analysis
        """
        # Extract code snippets from path
        path_snippets = []
        for node in path:
            if hasattr(node, 'text'):
                path_snippets.append(node.text.decode('utf8'))
            else:
                path_snippets.append(str(node))
        
        # Use sanitizer library to analyze
        source_snippet = path_snippets[0] if path_snippets else ""
        sink_snippet = path_snippets[-1] if path_snippets else ""
        
        analysis = self.sanitizer_lib.analyze_sanitization(
            source_snippet,
            sink_snippet,
            path_snippets,
            language,
            vulnerability_type
        )
        
        return analysis

    def _generate_evidence_sequence(self, path: List[Any]) -> List[Dict]:
        """Convert a list of AST nodes into a human-readable evidence sequence."""
        sequence = []
        for i, node in enumerate(path):
            step = "Source" if i == 0 else "Sink" if i == len(path)-1 else "Propagation"
            sequence.append({
                "step": step,
                "line": node.start_point[0] + 1,
                "type": node.type,
                "snippet": node.text.decode('utf8')
            })
        return sequence
