
import os
import tree_sitter
from typing import Dict, Optional, Any

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
                
        # If not found, we might need to build it (if source is available)
        # For now, we return None and expect the user to have provided the libs
        # Or we could provide a helper to download and build (out of scope for now)
        return None

    def parse(self, content: str, language_id: str) -> Optional[tree_sitter.Tree]:
        """Parse source code content into a Tree-sitter Tree."""
        parser = self.get_parser(language_id)
        if parser:
            return parser.parse(bytes(content, "utf8"))
        return None

    def get_node_text(self, node: Any, content_bytes: bytes) -> str:
        """Extract text from a node using the original content bytes."""
        return content_bytes[node.start_byte:node.end_byte].decode("utf8")
