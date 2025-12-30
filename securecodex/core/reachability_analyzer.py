"""
Reachability Analyzer for SecureCodeX.
Analyzes code reachability to reduce false positives from unreachable code.
"""

from typing import Dict, List, Set, Optional, Any


class ReachabilityAnalyzer:
    """
    Analyzes code reachability using simple control flow analysis.
    """
    
    def __init__(self):
        self.unreachable_cache: Dict[str, Set[int]] = {}
    
    def is_reachable(self, node: Any, tree: Any) -> bool:
        """
        Determine if a code node is reachable.
        
        Args:
            node: AST node to check
            tree: Full AST tree
        
        Returns:
            True if the code is reachable
        """
        if not hasattr(node, 'start_point'):
            return True  # Assume reachable if we can't determine
        
        line_number = node.start_point[0] + 1
        
        # Check if this line is in unreachable code
        return not self._is_line_unreachable(node, tree)
    
    def _is_line_unreachable(self, node: Any, tree: Any) -> bool:
        """Check if a line is unreachable."""
        # Walk up the tree to find control flow statements
        current = node
        
        while current:
            # Check if we're after a return statement in the same block
            if self._is_after_return(current):
                return True
            
            # Check if we're after a throw/raise statement
            if self._is_after_throw(current):
                return True
            
            # Check if we're in an always-false condition
            if self._is_in_false_condition(current):
                return True
            
            current = current.parent
        
        return False
    
    def _is_after_return(self, node: Any) -> bool:
        """Check if node is after a return statement in the same block."""
        if not hasattr(node, 'parent'):
            return False
        
        parent = node.parent
        
        # Find the block containing this node
        while parent and parent.type not in ['block', 'function_definition', 'method_definition', 'arrow_function']:
            parent = parent.parent
        
        if not parent:
            return False
        
        # Check if there's a return before this node in the same block
        found_return = False
        node_found = False
        
        for child in self._get_children(parent):
            if child.type in ['return_statement', 'return']:
                found_return = True
            
            if child.id == node.id:
                node_found = True
                break
        
        return found_return and node_found
    
    def _is_after_throw(self, node: Any) -> bool:
        """Check if node is after a throw/raise statement."""
        if not hasattr(node, 'parent'):
            return False
        
        parent = node.parent
        
        # Find the block
        while parent and parent.type not in ['block', 'function_definition', 'method_definition']:
            parent = parent.parent
        
        if not parent:
            return False
        
        # Check for throw/raise before this node
        found_throw = False
        node_found = False
        
        for child in self._get_children(parent):
            if child.type in ['throw_statement', 'raise_statement', 'throw', 'raise']:
                found_throw = True
            
            if child.id == node.id:
                node_found = True
                break
        
        return found_throw and node_found
    
    def _is_in_false_condition(self, node: Any) -> bool:
        """Check if node is in an always-false condition."""
        if not hasattr(node, 'parent'):
            return False
        
        current = node.parent
        
        while current:
            # Check for if (false) or if (0)
            if current.type in ['if_statement', 'if']:
                condition = current.child_by_field_name('condition')
                if condition:
                    condition_text = condition.text.decode('utf8') if hasattr(condition, 'text') else ''
                    
                    # Simple constant false detection
                    if condition_text.strip() in ['false', 'False', '0', 'null', 'None', 'nil']:
                        return True
            
            current = current.parent
        
        return False
    
    def _get_children(self, node: Any) -> List[Any]:
        """Get all children of a node."""
        children = []
        if hasattr(node, 'child_count'):
            for i in range(node.child_count):
                children.append(node.child(i))
        return children
    
    def analyze_function_reachability(self, tree: Any) -> Dict[str, Set[int]]:
        """
        Analyze reachability for all functions in the tree.
        
        Args:
            tree: AST tree
        
        Returns:
            Dictionary mapping function names to sets of unreachable line numbers
        """
        unreachable_lines = {}
        
        # Walk the tree to find functions
        for node in self._walk_tree(tree.root_node):
            if node.type in ['function_definition', 'method_definition', 'function_declaration']:
                func_name = self._get_function_name(node)
                unreachable = self._find_unreachable_in_function(node)
                
                if unreachable:
                    unreachable_lines[func_name] = unreachable
        
        return unreachable_lines
    
    def _walk_tree(self, node: Any):
        """Recursively walk the tree."""
        yield node
        if hasattr(node, 'child_count'):
            for i in range(node.child_count):
                yield from self._walk_tree(node.child(i))
    
    def _get_function_name(self, node: Any) -> str:
        """Get function name from function definition node."""
        name_node = node.child_by_field_name('name')
        if name_node and hasattr(name_node, 'text'):
            return name_node.text.decode('utf8')
        return 'anonymous'
    
    def _find_unreachable_in_function(self, func_node: Any) -> Set[int]:
        """Find unreachable lines within a function."""
        unreachable = set()
        
        body = func_node.child_by_field_name('body')
        if not body:
            return unreachable
        
        # Track if we've seen a return/throw
        seen_return = False
        
        for child in self._get_children(body):
            if seen_return:
                # Everything after return is unreachable
                if hasattr(child, 'start_point'):
                    unreachable.add(child.start_point[0] + 1)
            
            if child.type in ['return_statement', 'return', 'throw_statement', 'raise_statement']:
                seen_return = True
        
        return unreachable
    
    def enrich_finding_with_reachability(
        self, 
        finding: Dict, 
        tree: Any
    ) -> Dict:
        """
        Add reachability information to a finding.
        
        Args:
            finding: The vulnerability finding
            tree: AST tree
        
        Returns:
            Finding with reachability information
        """
        if 'node' in finding:
            finding['is_reachable'] = self.is_reachable(finding['node'], tree)
        else:
            # Assume reachable if we don't have node information
            finding['is_reachable'] = True
        
        return finding
    
    def clear_cache(self):
        """Clear the reachability cache."""
        self.unreachable_cache.clear()
