
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
                
                # False Positive Reduction: Constant Propagation check
                # Many rules should only trigger if the input is variable (tainted) 
                # and not a hardcoded constant.
                is_constant = self._is_constant_value(path[0])
                if is_constant:
                    # If the source is a literal string/number, it's often a false positive
                    # for injection-style vulnerabilities.
                    continue

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

    def _is_constant_value(self, node: Any) -> bool:
        """Check if a node represents a constant literal value."""
        constant_types = [
            'string', 'string_literal', 'number', 'integer', 'float', 
            'boolean', 'true', 'false', 'none', 'null', 'constant'
        ]
        # Check node type
        if node.type in constant_types:
            return True
        
        # Check if it's an assignment of a constant
        if node.type in ['assignment', 'assign']:
            rhs = node.child_by_field_name('right') or node.child_by_field_name('value')
            if rhs and rhs.type in constant_types:
                return True
                
        return False

    def _build_dfg(self, tree: Any, propagators: List[Dict] = None, matcher: Any = None, content: str = "") -> (Dict[int, Set[int]], Dict[int, Any]):
        """
        Build a Data Flow Graph.
        Returns a mapping of node IDs to reachable node IDs and a node_id -> node_obj map.
        """
        dfg = {}
        node_map = {}
        
        def add_edge(u, v):
            uid, vid = u.id if hasattr(u, 'id') else id(u), v.id if hasattr(v, 'id') else id(v)
            node_map[uid], node_map[vid] = u, v
            if uid not in dfg: dfg[uid] = set()
            dfg[uid].add(vid)

        # 1. Generic AST-based flow
        variable_map = {} # Track last assigned node for each variable name
        
        def walk(node):
            node_map[id(node)] = node
            
            # Python Assignment: lhs = rhs
            if node.type in ['assignment', 'assign']:
                lhs = node.child_by_field_name('left') or node.child_by_field_name('targets')
                rhs = node.child_by_field_name('right') or node.child_by_field_name('value')
                if lhs and rhs:
                    add_edge(rhs, lhs)
                    
                    # Handle multiple targets (e.g. x, y = ...)
                    targets = [lhs]
                    if hasattr(lhs, 'child_count') and lhs.child_count > 0:
                        targets = [lhs.child(i) for i in range(lhs.child_count)]
                    
                    for target in targets:
                        var_name = target.text.decode('utf8').strip()
                        if var_name:
                            variable_map[var_name] = target
                            # Also flow from LHS wrapper to specific target if needed
                            if target != lhs:
                                add_edge(lhs, target)
            
            # 2. Function Calls (result = func(arg1, arg2))
            if node.type in ['call', 'call_expression']:
                args = node.child_by_field_name('arguments') or node.child_by_field_name('args')
                if args:
                    # In many languages, arguments is a node containing children
                    # In Python AST bridge, it might be a list or a single node
                    for i in range(args.child_count if hasattr(args, 'child_count') else 0):
                        add_edge(args.child(i), node)
                
                # Check for explicit 'args' in Python AST bridge
                if hasattr(node.node, 'args'):
                    for arg in node.node.args:
                        # Find the corresponding bridge node or just dummy if needed
                        # Simplification: TaintEngine walk already visits children, 
                        # we just need to ensure edges are added.
                        pass

            # 3. Binary Operations (a + b)
            if node.type in ['binary_operator', 'binary_expression', 'binop']:
                left = node.child_by_field_name('left')
                right = node.child_by_field_name('right')
                if left: add_edge(left, node)
                if right: add_edge(right, node)

            # 4. F-Strings / JoinedStr (Python)
            if node.type in ['joinedstr', 'f_string', 'template_string']:
                for i in range(node.child_count):
                    add_edge(node.child(i), node)

            # 5. Member/Attribute Access (obj.prop)
            if node.type in ['attribute', 'member_expression']:
                value = node.child_by_field_name('value') or node.child_by_field_name('object')
                if value:
                    add_edge(value, node)

            # 6. Subscripts (x[0])
            if node.type in ['subscript', 'subscript_expression']:
                value = node.child_by_field_name('value') or node.child_by_field_name('object')
                if value:
                    add_edge(value, node)

            # 7. Identifier usage in calls/ops
            if node.type in ['identifier', 'name']:
                # If we've seen an assignment to this name, flow from that assignment to this usage
                var_name = node.text.decode('utf8').strip()
                if var_name in variable_map:
                    add_edge(variable_map[var_name], node)
                
                p = node.parent
                if p:
                    # Flow from var name to the expression using it
                    add_edge(node, p)

            # 8. Generic flow to parent for expressions
            expression_types = [
                'binary_operator', 'binary_expression', 'binop',
                'call', 'call_expression', 'attribute', 'subscript',
                'joinedstr', 'f_string', 'template_string'
            ]
            if node.type in expression_types:
                p = node.parent
                if p and p.type not in ['module', 'function_definition', 'class_definition']:
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
        sink_ids = {s.id if hasattr(s, 'id') else id(s) for s in sinks}
        start_id = source.id if hasattr(source, 'id') else id(source)
        
        queue = [[source]]
        visited = {start_id}
        
        while queue:
            path = queue.pop(0)
            node = path[-1]
            node_id = node.id if hasattr(node, 'id') else id(node)
            
            if node_id in sink_ids:
                paths.append(path)
                continue
            
            if node_id in sanitizer_ids:
                continue 
                
            for next_node_id in dfg.get(node_id, []):
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
