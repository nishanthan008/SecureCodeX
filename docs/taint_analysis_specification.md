# SecureCodeX v2 - Taint Analysis Engine Specification

## Overview

This document provides the complete technical specification for SecureCodeX v2's production-ready taint analysis engine, including interprocedural tracking, control-flow awareness, and framework-specific source/sink detection.

## Taint Analysis Fundamentals

### Core Concept

**Taint analysis** validates that untrusted input (source) can reach a dangerous operation (sink) through a data flow path without proper sanitization. This is the gold standard for detecting exploitable vulnerabilities.

**Formula**: `Vulnerability = Source ∩ Dataflow ∩ Sink ∩ ¬Sanitization`

---

## Framework-Aware Sources and Sinks

### Python Web Frameworks

#### Flask/Werkzeug Sources
```python
FLASK_SOURCES = {
    # GET parameters
    'request.args.get': {'type': 'http_param', 'risk': 'HIGH'},
    'request.args': {'type': 'http_param', 'risk': 'HIGH'},
    
    # POST data
    'request.form.get': {'type': 'http_body', 'risk': 'HIGH'},
    'request.form': {'type': 'http_body', 'risk': 'HIGH'},
    'request.json': {'type': 'http_json', 'risk': 'HIGH'},
    'request.data': {'type': 'http_raw', 'risk': 'HIGH'},
    
    # Headers
    'request.headers.get': {'type': 'http_header', 'risk': 'MEDIUM'},
    'request.cookies.get': {'type': 'http_cookie', 'risk': 'MEDIUM'},
    
    # Files
    'request.files': {'type': 'file_upload', 'risk': 'CRITICAL'},
    
    # URL components
    'request.path': {'type': 'http_path', 'risk': 'LOW'},
    'request.url': {'type': 'http_url', 'risk': 'LOW'},
}

#### Django Sources
DJANGO_SOURCES = {
    'request.GET.get': {'type': 'http_param', 'risk': 'HIGH'},
    'request.POST.get': {'type': 'http_body', 'risk': 'HIGH'},
    'request.body': {'type': 'http_raw', 'risk': 'HIGH'},
    'request.FILES': {'type': 'file_upload', 'risk': 'CRITICAL'},
    'request.META': {'type': 'http_meta', 'risk': 'MEDIUM'},
}

#### FastAPI Sources
FASTAPI_SOURCES = {
    'Query(...)': {'type': 'http_param', 'risk': 'HIGH'},
    'Path(...)': {'type': 'http_path_param', 'risk': 'HIGH'},
    'Body(...)': {'type': 'http_body', 'risk': 'HIGH'},
    'Header(...)': {'type': 'http_header', 'risk': 'MEDIUM'},
    'Cookie(...)': {'type': 'http_cookie', 'risk': 'MEDIUM'},
    'File(...)': {'type': 'file_upload', 'risk': 'CRITICAL'},
}
```

### JavaScript/Node.js Frameworks

#### Express.js Sources
```javascript
EXPRESS_SOURCES = {
    'req.query': {'type': 'http_param', 'risk': 'HIGH'},
    'req.params': {'type': 'http_path_param', 'risk': 'HIGH'},
    'req.body': {'type': 'http_body', 'risk': 'HIGH'},
    'req.headers': {'type': 'http_header', 'risk': 'MEDIUM'},
    'req.cookies': {'type': 'http_cookie', 'risk': 'MEDIUM'},
    'req.files': {'type': 'file_upload', 'risk': 'CRITICAL'},
}
```

### Dangerous Sinks by Category

#### SQL Injection Sinks
```python
SQL_SINKS = {
    # Python
    'cursor.execute': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    'cursor.executemany': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    'connection.execute': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    'db.execute': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    'session.execute': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    
    # JavaScript
    'db.query': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    'connection.query': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    'sequelize.query': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    
    # Java
    'Statement.execute': {'vuln': 'sqli', 'severity': 'CRITICAL'},
    'Statement.executeQuery': {'vuln': 'sqli', 'severity': 'CRITICAL'},
}

#### Command Injection Sinks
COMMAND_SINKS = {
    # Python
    'os.system': {'vuln': 'command_injection', 'severity': 'CRITICAL'},
    'subprocess.Popen': {'vuln': 'command_injection', 'severity': 'CRITICAL'},
    'subprocess.run': {'vuln': 'command_injection', 'severity': 'CRITICAL'},
    'subprocess.call': {'vuln': 'command_injection', 'severity': 'CRITICAL'},
    'eval': {'vuln': 'code_injection', 'severity': 'CRITICAL'},
    'exec': {'vuln': 'code_injection', 'severity': 'CRITICAL'},
    
    # JavaScript
    'child_process.exec': {'vuln': 'command_injection', 'severity': 'CRITICAL'},
    'child_process.spawn': {'vuln': 'command_injection', 'severity': 'CRITICAL'},
    'eval': {'vuln': 'code_injection', 'severity': 'CRITICAL'},
}

#### Path Traversal Sinks
PATH_SINKS = {
    'open': {'vuln': 'path_traversal', 'severity': 'HIGH'},
    'os.open': {'vuln': 'path_traversal', 'severity': 'HIGH'},
    'pathlib.Path': {'vuln': 'path_traversal', 'severity': 'HIGH'},
    'fs.readFile': {'vuln': 'path_traversal', 'severity': 'HIGH'},
    'fs.writeFile': {'vuln': 'path_traversal', 'severity': 'HIGH'},
}

#### XSS Sinks
XSS_SINKS = {
    # Python
    'render_template_string': {'vuln': 'xss', 'severity': 'HIGH'},
    'Markup': {'vuln': 'xss', 'severity': 'HIGH'},
    'response.write': {'vuln': 'xss', 'severity': 'HIGH'},
    
    # JavaScript
    'innerHTML': {'vuln': 'xss', 'severity': 'HIGH'},
    'document.write': {'vuln': 'xss', 'severity': 'HIGH'},
    'eval': {'vuln': 'xss', 'severity': 'CRITICAL'},
}
```

### Sanitizers by Vulnerability Type

#### SQL Sanitizers
```python
SQL_SANITIZERS = {
    # Strong sanitizers (eliminate vulnerability)
    'int': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'float': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'str.isdigit': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'cursor.execute with params': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    
    # Medium sanitizers (reduce risk)
    'str.replace': {'effectiveness': 'MEDIUM', 'confidence_reduction': 30},
    're.escape': {'effectiveness': 'MEDIUM', 'confidence_reduction': 30},
    
    # Weak sanitizers (easily bypassed)
    'str.strip': {'effectiveness': 'WEAK', 'confidence_reduction': 10},
}

#### Command Injection Sanitizers
COMMAND_SANITIZERS = {
    'shlex.quote': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'subprocess with list args': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'pipes.quote': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
}

#### Path Traversal Sanitizers
PATH_SANITIZERS = {
    'os.path.basename': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'werkzeug.utils.secure_filename': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'os.path.abspath': {'effectiveness': 'MEDIUM', 'confidence_reduction': 30},
    'os.path.normpath': {'effectiveness': 'WEAK', 'confidence_reduction': 10},
}

#### XSS Sanitizers
XSS_SANITIZERS = {
    'html.escape': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'markupsafe.escape': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'bleach.clean': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'DOMPurify.sanitize': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
    'textContent': {'effectiveness': 'STRONG', 'confidence_reduction': 0},
}
```

---

## Taint Propagation Algorithm

### Data Flow Graph Construction

```python
class DataFlowGraph:
    """
    Represents data flow relationships between AST nodes.
    Nodes = variables/expressions, Edges = data flow.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_metadata = {}
    
    def build_from_ast(self, ast: AST) -> None:
        """Build DFG from AST by analyzing data flow patterns."""
        
        def visit_node(node):
            # Pattern 1: Assignment (x = y)
            if node.type in ['assignment', 'assign']:
                lhs = node.child_by_field_name('left')
                rhs = node.child_by_field_name('right')
                if lhs and rhs:
                    self.add_flow(rhs, lhs, 'assignment')
            
            # Pattern 2: Function call (result = func(arg))
            elif node.type == 'call':
                func_name = self._get_function_name(node)
                args = node.child_by_field_name('arguments')
                
                # Taint flows from arguments to return value
                if args:
                    for arg in args.children:
                        self.add_flow(arg, node, 'call_return')
                
                # Check for propagator functions
                if func_name in TAINT_PROPAGATORS:
                    self._apply_propagator_rules(node, func_name)
            
            # Pattern 3: String formatting (f"...{var}...")
            elif node.type in ['f_string', 'template_string', 'joinedstr']:
                for child in node.children:
                    if child.type in ['interpolation', 'formatted_value']:
                        self.add_flow(child, node, 'string_format')
            
            # Pattern 4: Binary operations (a + b)
            elif node.type in ['binary_operator', 'binary_expression']:
                left = node.child_by_field_name('left')
                right = node.child_by_field_name('right')
                if left:
                    self.add_flow(left, node, 'binary_op')
                if right:
                    self.add_flow(right, node, 'binary_op')
            
            # Pattern 5: Array/Object access (arr[0], obj.prop)
            elif node.type in ['subscript', 'member_expression']:
                value = node.child_by_field_name('object') or node.child_by_field_name('value')
                if value:
                    self.add_flow(value, node, 'member_access')
            
            # Pattern 6: Return statement
            elif node.type in ['return_statement', 'return']:
                value = node.child_by_field_name('value')
                if value:
                    # Mark this as function return
                    self.node_metadata[node.id] = {'is_return': True}
                    self.add_flow(value, node, 'return')
            
            # Recursively visit children
            for child in node.children:
                visit_node(child)
        
        visit_node(ast.root_node)
    
    def add_flow(self, from_node, to_node, flow_type: str):
        """Add a data flow edge."""
        self.graph.add_edge(
            from_node.id,
            to_node.id,
            type=flow_type,
            from_node=from_node,
            to_node=to_node
        )
    
    def _apply_propagator_rules(self, node, func_name: str):
        """
        Apply special propagation rules for known functions.
        Example: list.append(x) taints the list
        """
        rules = TAINT_PROPAGATORS.get(func_name, {})
        
        if 'from_arg_to_object' in rules:
            # Example: list.append(x) -> list is tainted
            obj = node.child_by_field_name('object')
            args = node.child_by_field_name('arguments')
            if obj and args:
                for arg in args.children:
                    self.add_flow(arg, obj, 'propagator')
        
        elif 'from_object_to_return' in rules:
            # Example: list.pop() -> return value is tainted
            obj = node.child_by_field_name('object')
            if obj:
                self.add_flow(obj, node, 'propagator')
```

### Interprocedural Taint Tracking

```python
class InterproceduralTaintAnalyzer:
    """
    Tracks taint across function boundaries.
    """
    
    def __init__(self):
        self.function_summaries = {}  # func_name -> TaintSummary
        self.call_graph = nx.DiGraph()
    
    def analyze_function(self, func_node: Node, dfg: DataFlowGraph) -> TaintSummary:
        """
        Analyze a single function to create taint summary.
        Summary describes which parameters taint which return values.
        """
        summary = TaintSummary(func_name=self._get_function_name(func_node))
        
        # Find all parameters
        params = self._get_function_parameters(func_node)
        
        # Find all return statements
        returns = self._find_return_statements(func_node)
        
        # For each return, check which parameters it depends on
        for ret in returns:
            ret_value = ret.child_by_field_name('value')
            if ret_value:
                # Trace backwards from return to parameters
                tainted_params = self._trace_to_params(ret_value, params, dfg)
                summary.add_flow(tainted_params, 'return')
        
        return summary
    
    def _trace_to_params(self, node: Node, params: List[Node], dfg: DataFlowGraph) -> List[int]:
        """
        Trace backwards from node to find which parameters it depends on.
        Returns list of parameter indices.
        """
        tainted_param_indices = []
        visited = set()
        queue = [node]
        
        while queue:
            current = queue.pop(0)
            if current.id in visited:
                continue
            visited.add(current.id)
            
            # Check if this is a parameter
            for idx, param in enumerate(params):
                if current.id == param.id:
                    tainted_param_indices.append(idx)
                    continue
            
            # Trace backwards through data flow
            for predecessor in dfg.graph.predecessors(current.id):
                pred_node = dfg.graph.nodes[predecessor]['node']
                queue.append(pred_node)
        
        return tainted_param_indices
    
    def apply_summary_at_call_site(self, call_node: Node, summary: TaintSummary, dfg: DataFlowGraph):
        """
        Apply function summary at a call site.
        If parameter X taints return value, and argument Y is passed to X,
        then Y taints the call result.
        """
        args = call_node.child_by_field_name('arguments')
        if not args:
            return
        
        # For each tainted parameter in summary
        for param_idx in summary.tainted_params:
            if param_idx < len(args.children):
                arg = args.children[param_idx]
                # Add flow from argument to call result
                dfg.add_flow(arg, call_node, 'interprocedural')
```

### Control Flow Aware Taint Analysis

```python
class ControlFlowAwareTaintAnalyzer:
    """
    Taint analysis that considers control flow branches.
    """
    
    def analyze_with_branches(self, ast: AST, sources: List[Node], 
                               sinks: List[Node], sanitizers: List[Node]) -> List[TaintPath]:
        """
        Analyze taint considering control flow.
        Reports vulnerability only if taint reaches sink on at least one path.
        """
        # Build control flow graph
        cfg = self._build_cfg(ast)
        
        # Build data flow graph
        dfg = DataFlowGraph()
        dfg.build_from_ast(ast)
        
        paths = []
        
        # For each source-sink pair
        for source in sources:
            for sink in sinks:
                # Find all CFG paths from source to sink
                cfg_paths = self._find_cfg_paths(source, sink, cfg)
                
                for cfg_path in cfg_paths:
                    # Check if taint flows on this specific path
                    if self._taint_flows_on_path(source, sink, cfg_path, dfg, sanitizers):
                        paths.append(TaintPath(
                            source=source,
                            sink=sink,
                            cfg_path=cfg_path,
                            dfg_path=self._extract_dfg_path(source, sink, dfg)
                        ))
        
        return paths
    
    def _taint_flows_on_path(self, source: Node, sink: Node, cfg_path: List[Node],
                              dfg: DataFlowGraph, sanitizers: List[Node]) -> bool:
        """
        Check if taint flows from source to sink along this specific CFG path.
        """
        # Get all nodes on this CFG path
        path_nodes = {node.id for node in cfg_path}
        
        # Find DFG path from source to sink
        try:
            dfg_path = nx.shortest_path(dfg.graph, source.id, sink.id)
        except nx.NetworkXNoPath:
            return False
        
        # Check if DFG path is consistent with CFG path
        # (all DFG nodes must be on the CFG path)
        for node_id in dfg_path:
            if node_id not in path_nodes:
                return False
        
        # Check for sanitizers on this path
        sanitizer_ids = {s.id for s in sanitizers}
        for node_id in dfg_path:
            if node_id in sanitizer_ids:
                return False  # Sanitized on this path
        
        return True
```

---

## Confidence Calculation

```python
class TaintConfidenceCalculator:
    """
    Calculate confidence score (0-100) for taint paths.
    """
    
    def calculate(self, path: TaintPath, context: Dict) -> int:
        """
        Calculate confidence based on multiple factors.
        """
        score = 0
        
        # Factor 1: Source Validation (0-30 points)
        source_score = self._score_source(path.source)
        score += source_score
        
        # Factor 2: Sink Validation (0-30 points)
        sink_score = self._score_sink(path.sink)
        score += sink_score
        
        # Factor 3: Path Quality (0-25 points)
        path_score = self._score_path(path)
        score += path_score
        
        # Factor 4: Sanitization Analysis (0-10 points)
        sanitization_score = self._score_sanitization(path)
        score += sanitization_score
        
        # Factor 5: Context (0-5 points)
        context_score = self._score_context(context)
        score += context_score
        
        # Apply penalties
        score = self._apply_penalties(score, path, context)
        
        return max(0, min(100, score))
    
    def _score_source(self, source: Node) -> int:
        """Score source based on how user-controlled it is."""
        source_text = source.text.decode('utf8')
        
        # User-controlled HTTP input
        if any(pattern in source_text for pattern in [
            'request.args', 'request.form', 'request.json',
            'req.query', 'req.body', 'req.params'
        ]):
            return 30
        
        # Environment variables
        if 'os.environ' in source_text or 'process.env' in source_text:
            return 20
        
        # File input
        if 'open(' in source_text or 'readFile' in source_text:
            return 15
        
        # Database input (less risky)
        if 'cursor.fetch' in source_text or 'db.query' in source_text:
            return 10
        
        return 0
    
    def _score_sink(self, sink: Node) -> int:
        """Score sink based on how dangerous it is."""
        sink_text = sink.text.decode('utf8')
        
        # Critical sinks
        if any(pattern in sink_text for pattern in [
            'eval(', 'exec(', 'os.system(', 'subprocess.Popen('
        ]):
            return 30
        
        # High-risk sinks
        if any(pattern in sink_text for pattern in [
            'cursor.execute', 'db.execute', 'connection.query'
        ]):
            return 25
        
        # Medium-risk sinks
        if any(pattern in sink_text for pattern in [
            'open(', 'fs.readFile', 'innerHTML'
        ]):
            return 20
        
        return 0
    
    def _score_path(self, path: TaintPath) -> int:
        """Score based on path characteristics."""
        score = 0
        
        # Complete data flow path
        if len(path.dfg_path) > 0:
            score += 15
        
        # Short path (more confident)
        if len(path.dfg_path) < 5:
            score += 10
        elif len(path.dfg_path) > 10:
            score -= 5  # Long path, less confident
        
        return max(0, score)
    
    def _score_sanitization(self, path: TaintPath) -> int:
        """Score based on sanitization status."""
        if path.sanitization_status == 'none':
            return 10
        elif path.sanitization_status == 'weak':
            return 5
        elif path.sanitization_status == 'bypassed':
            return 8
        else:  # strong sanitization
            return 0
    
    def _score_context(self, context: Dict) -> int:
        """Score based on code context."""
        score = 0
        
        if not context.get('in_test_code', False):
            score += 3
        
        if not context.get('in_comment', False):
            score += 2
        
        return score
    
    def _apply_penalties(self, score: int, path: TaintPath, context: Dict) -> int:
        """Apply penalties for various factors."""
        
        # Test code
        if context.get('in_test_code', False):
            score = int(score * 0.5)  # 50% reduction
        
        # Unreachable code
        if not context.get('is_reachable', True):
            score = int(score * 0.3)  # 70% reduction
        
        # Framework protection
        if context.get('framework_protected', False):
            score -= 20
        
        # Dead code
        if context.get('in_dead_code', False):
            score -= 30
        
        return score
```

---

## Human-Readable Exploit Traces

```python
class ExploitTraceFormatter:
    """
    Format taint paths into human-readable exploit traces.
    """
    
    def format(self, path: TaintPath, confidence: int) -> str:
        """Generate human-readable trace."""
        
        trace = []
        trace.append(f"[{self._severity_emoji(path.sink)}] {path.vulnerability_type.upper()}")
        trace.append(f"File: {path.file}:{path.source.start_point[0] + 1}")
        trace.append("")
        trace.append("Exploit Chain:")
        
        # Format each step
        for i, step in enumerate(path.steps, 1):
            step_type = self._get_step_type(step, i, len(path.steps))
            trace.append(f"  {i}. {step_type} (Line {step.start_point[0] + 1}): {step.text.decode('utf8')}")
            
            if i < len(path.steps):
                trace.append(f"     └─ {self._get_flow_description(step, path.steps[i])}")
        
        trace.append("")
        trace.append("Sanitization Analysis:")
        if path.sanitization_status == 'none':
            trace.append("  ❌ No sanitization detected in data flow path")
        elif path.sanitization_status == 'weak':
            trace.append("  ⚠️  Weak sanitization detected (easily bypassed)")
        
        trace.append(f"  ✓ Expected: {self._get_expected_sanitizers(path.vulnerability_type)}")
        
        trace.append("")
        trace.append(f"Confidence: {confidence}/100 ({self._confidence_level(confidence)})")
        trace.append(f"CWE: {path.cwe}")
        trace.append(f"OWASP: {path.owasp}")
        
        trace.append("")
        trace.append("Remediation:")
        trace.append(f"  {self._get_remediation(path)}")
        
        return "\n".join(trace)
```

---

This specification provides the complete technical foundation for SecureCodeX v2's taint analysis engine, ready for implementation.
