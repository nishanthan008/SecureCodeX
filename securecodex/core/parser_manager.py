
import os
import tree_sitter
import ast
from typing import Dict, Optional, Any, List

class ParserManager:
    """
    Manages Tree-sitter parsers and language grammars.
    Provides a unified interface for AST generation across multiple languages.
    """
    
    def __init__(self, grammar_cache_dir: str = None):
        if grammar_cache_dir is None:
            # Default to a .grammars folder in the package root
            self.grammar_cache_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), ".grammars"
            )
        else:
            self.grammar_cache_dir = grammar_cache_dir
            
        if not os.path.exists(self.grammar_cache_dir):
            os.makedirs(self.grammar_cache_dir)
            
        self.languages: Dict[str, tree_sitter.Language] = {}
        self.parsers: Dict[str, tree_sitter.Parser] = {}
        
        # Mapping from file extensions/language names to tree-sitter identifiers
        self.lang_map = {
            'python': 'python',
            'javascript': 'javascript',
            'typescript': 'typescript',
            'java': 'java',
            'go': 'go',
            'cpp': 'cpp',
            'c': 'c',
            'php': 'php',
            'rust': 'rust',
            'ruby': 'ruby',
            'csharp': 'c_sharp'
        }

    def get_parser(self, language_id: str) -> Optional[tree_sitter.Parser]:
        """Get or initialize a parser for the specified language."""
        lang_name = self.lang_map.get(language_id, language_id)
        
        if lang_name in self.parsers:
            return self.parsers[lang_name]
            
        lang = self._get_language(lang_name)
        if lang:
            parser = tree_sitter.Parser()
            parser.set_language(lang)
            self.parsers[lang_name] = parser
            return parser
            
        return None

    def _get_language(self, lang_name: str) -> Optional[tree_sitter.Language]:
        """Load or build the Tree-sitter language object."""
        if lang_name in self.languages:
            return self.languages[lang_name]
            
        lib_path = os.path.join(self.grammar_cache_dir, f"{lang_name}.so")
        # In Windows, it might be .dll or .so depending on how it was built
        if os.name == 'nt':
            lib_path = os.path.join(self.grammar_cache_dir, f"{lang_name}.dll")

        if os.path.exists(lib_path):
            try:
                lang = tree_sitter.Language(lib_path, lang_name)
                self.languages[lang_name] = lang
                return lang
            except Exception as e:
                print(f"Error loading grammar for {lang_name}: {e}")
                
        return None

    def parse(self, content: str, language_id: str) -> Optional[Any]:
        """Parse source code content into a Tree-sitter Tree or a native fallback."""
        parser = self.get_parser(language_id)
        if parser:
            return parser.parse(bytes(content, "utf8"))
        
        # Fallback for Python using native ast module
        if language_id == 'python':
            try:
                native_tree = ast.parse(content)
                return PythonASTBridge(native_tree, content)
            except:
                return None
        return None

class PythonASTBridge:
    def __init__(self, tree, content):
        self.root_node = PythonNodeBridge(tree, content)

class PythonNodeBridge:
    def __init__(self, node, content, parent=None):
        self.node = node
        self.content = content
        self.parent = parent
        self.type = node.__class__.__name__.lower()
        self.start_point = (getattr(node, 'lineno', 1) - 1, getattr(node, 'col_offset', 0))
        self.end_point = (getattr(node, 'end_lineno', 1) - 1, getattr(node, 'end_col_offset', 0))
        self.text = self._get_text()
        self._children = []
        self._set_children()

    def _get_text(self):
        try:
            lines = self.content.splitlines()
            start_row, start_col = self.start_point
            end_row, end_col = self.end_point
            if start_row == end_row:
                return lines[start_row][start_col:end_col].encode('utf8')
            res = [lines[start_row][start_col:]]
            for r in range(start_row + 1, end_row):
                res.append(lines[r])
            res.append(lines[end_row][:end_col])
            return "\n".join(res).encode('utf8')
        except:
            return b""

    def _set_children(self):
        for child in ast.iter_child_nodes(self.node):
            self._children.append(PythonNodeBridge(child, self.content, self))

    @property
    def child_count(self):
        return len(self._children)

    def child(self, i):
        return self._children[i]
    
    def child_by_field_name(self, name):
        # Map fields like 'left', 'right' for assignments/binary ops
        if hasattr(self.node, name):
            val = getattr(self.node, name)
            if isinstance(val, ast.AST):
                return PythonNodeBridge(val, self.content, self)
            elif isinstance(val, list):
                # Return a virtual node that represents the list
                return PythonListBridge(val, self.content, self, name)
        return None

    @property
    def id(self):
        return id(self.node)

class PythonListBridge:
    """A virtual node to bridge Python AST lists (like call args) to Tree-sitter style children."""
    def __init__(self, nodes, content, parent, type_name):
        self._children = [PythonNodeBridge(n, content, parent) for n in nodes if isinstance(n, ast.AST)]
        self.type = type_name
        self.parent = parent
        self.text = b"" 
        self.start_point = (0, 0)
        self.end_point = (0, 0)
        if self._children:
            self.start_point = self._children[0].start_point
            self.end_point = self._children[-1].end_point

    @property
    def child_count(self):
        return len(self._children)

    def child(self, i):
        return self._children[i]
    
    @property
    def id(self):
        return id(self)
