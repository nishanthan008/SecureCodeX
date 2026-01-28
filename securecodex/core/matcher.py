
import re
from typing import Dict, List, Any, Optional, Union
import tree_sitter

class Matcher:
    """
    Advanced Structural Matcher for SAST.
    Supports logical operators (either, not, inside) and metavariables.
    """
    
    def __init__(self, parser_manager):
        self.parser_manager = parser_manager

    def evaluate_rule(self, rule: Dict[str, Any], tree: tree_sitter.Tree, content: str) -> List[Dict[str, Any]]:
        """
        Evaluate a complex rule (with patterns, pattern-either, etc.) against a file's AST.
        """
        content_bytes = content.encode('utf8')
        findings = []
        
        # Start matching from the root
        matches = self._match_patterns_block(rule, tree.root_node, content_bytes)
        
        for match in matches:
            bindings = match.get('bindings', {})
            node = match.get('node')
            
            # Additional filters
            if not self._check_metavariable_regex(rule, bindings, content_bytes):
                continue
            if not self._check_metavariable_comparison(rule, bindings, content_bytes):
                continue
                
            findings.append({
                "node": node,
                "bindings": bindings,
                "line": node.start_point[0] + 1,
                "column": node.start_point[1] + 1,
                "snippet": node.text.decode('utf8')
            })
            
        return findings


    def _match_patterns_block(self, block: Dict[str, Any], root: Any, content_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Evaluate a block of patterns against a root node.
        Returns a list of matching nodes with their bindings.
        """
        # If this is a leaf-level pattern or regex, find all matches in the subtree
        if 'pattern' in block:
            return self.find_matches(block['pattern'], root, content_bytes)
        if 'pattern-regex' in block:
            return self._find_regex_matches(block['pattern-regex'], root, content_bytes)

        # Handle complex logical blocks by finding candidates and filtering
        candidates = []
        if 'patterns' in block:
            # For 'patterns' (AND), we need a seed pattern to find candidates
            # We'll pick the first available 'pattern' or 'pattern-either'
            seed_found = False
            for sub_p in block['patterns']:
                if 'pattern' in sub_p or 'pattern-regex' in sub_p or 'pattern-either' in sub_p:
                    candidates = self._match_patterns_block(sub_p, root, content_bytes)
                    seed_found = True
                    break
            
            if not seed_found:
                # Fallback: walk the tree if no obvious seed exists (expensive)
                candidates = [{"node": n, "bindings": {}} for n in self._walk_tree(root)]
            
            # Now filter the candidates through all other patterns in the block
            for sub_p in block['patterns']:
                candidates = [c for c in candidates if self._matches_filter(c, sub_p, root, content_bytes)]
                
        elif 'pattern-either' in block:
            # For 'pattern-either' (OR), return matches for any sub-pattern
            for sub_p in block['pattern-either']:
                candidates.extend(self._match_patterns_block(sub_p, root, content_bytes))
        
        return candidates

    def _matches_filter(self, candidate: Dict, sub_block: Dict, root: Any, content_bytes: bytes) -> bool:
        """Check if a specific candidate node matches a pattern filter."""
        node = candidate['node']
        bindings = candidate['bindings']

        if 'pattern' in sub_block:
            # Candidate node itself must match the pattern
            # (or at least one of its subnodes, but usually it's the node itself)
            temp_bindings = bindings.copy()
            if self._simple_text_match(sub_block['pattern'], node, temp_bindings):
                candidate['bindings'] = temp_bindings # Update bindings
                return True
            return False

        if 'pattern-not' in sub_block:
            not_matches = self.find_matches(sub_block['pattern-not'], root, content_bytes)
            return not any(m['node'].id == node.id for m in not_matches)

        if 'pattern-inside' in sub_block:
            # Candidate must be inside a node matching pattern-inside
            inside_matches = self.find_matches(sub_block['pattern-inside'], root, content_bytes)
            return any(self._is_descendant(node, m['node']) for m in inside_matches)

        if 'pattern-either' in sub_block:
            return any(self._matches_filter(candidate, p, root, content_bytes) for p in sub_block['pattern-either'])

        # Recursive patterns block
        if 'patterns' in sub_block:
            return all(self._matches_filter(candidate, p, root, content_bytes) for p in sub_block['patterns'])

        return True

    def find_matches(self, pattern_str: str, root: Any, content_bytes: bytes) -> List[Dict[str, Any]]:
        """Basic structural search for a pattern string."""
        matches = []
        # Parse pattern (simplified: using generic or same-language parser)
        # For now, let's assume we can walk the target tree and call match_node
        for node in self._walk_tree(root):
            bindings = {}
            if self._simple_text_match(pattern_str, node, bindings):
                matches.append({"node": node, "bindings": bindings})
        return matches

    def _simple_text_match(self, pattern_str: str, node: Any, bindings: Dict) -> bool:
        """
        Improved structural matching with metavariable consistency and robust ellipsis.
        """
        # Normalize whitespace
        pattern_norm = re.sub(r'\s+', ' ', pattern_str.strip())
        node_text = node.text.decode('utf8')
        node_norm = re.sub(r'\s+', ' ', node_text.strip())
        
        # 1. Handle ellipsis (...) with context-aware regex
        # We use non-greedy matching but try to respect obvious boundaries like commas or semicolons
        # if the ellipsis is within a list or block.
        regex_pattern = re.escape(pattern_norm)
        
        # Replace escaped ellipsis with a more robust pattern
        # [\s\S]*? is non-greedy "everything" including newlines
        regex_pattern = regex_pattern.replace(r'\.\.\.', r'[\s\S]*?')
        
        # 2. Identify $VAR metavariables
        vars_found = re.findall(r'\$[A-Z_0-9]+', pattern_norm)
        vars_to_replace = sorted(list(set(vars_found)), key=len, reverse=True)
        
        # 3. Build regex with named groups for metavariables
        for v in vars_to_replace:
            # Check if this variable is already bound in a parent block
            if v in bindings:
                # If bound, we must match the EXACT same content (escaped for regex)
                val = bindings[v]
                text_val = val.text.decode('utf8') if hasattr(val, 'text') else str(val)
                regex_pattern = regex_pattern.replace(re.escape(v), re.escape(text_val))
            else:
                # If not bound, create a named capture group
                # We use a unique suffix to avoid name collisions if the same var appears multiple times
                # (though for consistency, they should match the same thing, we'll verify this post-match)
                group_name = f"var_{v[1:]}"
                # If there are multiple occurrences of the same $VAR in the pattern, 
                # we need to capture them and then check they are equal.
                # Here we handle the first occurrences.
                regex_pattern = regex_pattern.replace(re.escape(v), f'(?P<{group_name}>.*?)', 1)
                # Subsequent occurrences should match the first one using backreferences
                regex_pattern = regex_pattern.replace(re.escape(v), f'(?P={group_name})')

        # 4. Perform the match
        # We try normalized first, then original for complex multi-line matches
        match = re.fullmatch(regex_pattern, node_norm, re.IGNORECASE | re.DOTALL)
        if not match:
            # Try original text
            match = re.fullmatch(regex_pattern, node_text, re.IGNORECASE | re.DOTALL)

        if match:
            # Update bindings with new captured variables
            for v in vars_to_replace:
                if v not in bindings:
                    try:
                        bindings[v] = match.group(f"var_{v[1:]}")
                    except (IndexError, KeyError):
                        pass
            return True
            
        return False

    def _find_regex_matches(self, regex: str, root: Any, content_bytes: bytes) -> List[Dict[str, Any]]:
        matches = []
        for node in self._walk_tree(root):
            if re.search(regex, node.text.decode('utf8'), re.MULTILINE):
                matches.append({"node": node, "bindings": {}})
        return matches

    def _check_metavariable_regex(self, rule: Dict, bindings: Dict, content_bytes: bytes) -> bool:
        if 'metavariable-regex' not in rule:
            return True
        
        mv_config = rule['metavariable-regex']
        var = mv_config.get('metavariable')
        regex = mv_config.get('regex')
        
        if var and regex and var in bindings:
            val = bindings[var]
            # Bindings might be nodes or strings depending on match depth
            text = val.text.decode('utf8') if hasattr(val, 'text') else str(val)
            if not re.search(regex, text):
                return False
        return True

    def _check_metavariable_comparison(self, rule: Dict, bindings: Dict, content_bytes: bytes) -> bool:
        if 'metavariable-comparison' not in rule:
            return True
            
        config = rule['metavariable-comparison']
        metavar = config.get('metavariable')
        comparison = config.get('comparison')
        
        if metavar and comparison and metavar in bindings:
            val = bindings[metavar]
            text = val.text.decode('utf8') if hasattr(val, 'text') else str(val)
            
            # Simple numeric comparison for now
            # e.g. "$TIME > 5" -> replace $TIME with actual value and eval
            try:
                # Basic safety: only allow alphanumeric, dots and comparison operators
                if not re.match(r'^[\w\.\s><=!&|]+$', comparison):
                    return False
                    
                eval_str = comparison.replace(metavar, text)
                # Note: eval is dangerous, in a production SAST we'd use a safe expression parser
                return eval(eval_str, {"__builtins__": {}}, {})
            except:
                return False
        return True

    def find_nodes(self, rule_block: Dict[str, Any], root: Any, content: str) -> List[Any]:
        """Find all AST nodes that match a specific rule sub-block (e.g. pattern-sources)."""
        content_bytes = content.encode('utf8')
        matches = self._match_patterns_block(rule_block, root, content_bytes)
        return [m['node'] for m in matches]

    def _walk_tree(self, node: Any):
        """Recursively walk the tree using native child access."""
        yield node
        for i in range(node.child_count):
            yield from self._walk_tree(node.child(i))

    def _is_descendant(self, node: Any, potential_ancestor: Any) -> bool:
        curr = node.parent
        while curr:
            if curr.id == potential_ancestor.id:
                return True
            curr = curr.parent
        return False
