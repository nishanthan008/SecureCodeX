import os
import importlib
import inspect
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

class DetectorPlugin(ABC):
    """
    Base class for detector plugins.
    All custom detector plugins must inherit from this class.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    @abstractmethod
    def supported_languages(self) -> List[str]:
        """List of supported programming languages"""
        pass
    
    @abstractmethod
    def scan_content(self, content: str, file_path: str, language: str = None) -> List[Dict]:
        """
        Scan content for vulnerabilities.
        
        Args:
            content: File content to scan
            file_path: Path to the file being scanned
            language: Programming language (optional)
        
        Returns:
            List of findings in the format:
            [
                {
                    'rule_id': str,
                    'name': str,
                    'description': str,
                    'severity': Severity,
                    'file_path': str,
                    'line_number': int,
                    'code_snippet': str,
                    'remediation': str
                }
            ]
        """
        pass


class PluginManager:
    """
    Plugin manager for loading and managing detector plugins.
    Provides extensibility for adding new language support and detection rules.
    """
    
    def __init__(self, plugin_dir: str = None):
        """
        Initialize plugin manager.
        
        Args:
            plugin_dir: Directory containing plugin modules (default: ./plugins)
        """
        self.plugin_dir = plugin_dir or os.path.join(os.path.dirname(__file__), '..', 'plugins')
        self.plugins: Dict[str, DetectorPlugin] = {}
        self.load_plugins()
    
    def load_plugins(self):
        """Discover and load all plugins from the plugin directory"""
        if not os.path.exists(self.plugin_dir):
            print(f"Plugin directory not found: {self.plugin_dir}")
            return
        
        # Add plugin directory to Python path
        import sys
        if self.plugin_dir not in sys.path:
            sys.path.insert(0, self.plugin_dir)
        
        # Discover plugin modules
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                module_name = filename[:-3]
                try:
                    self._load_plugin_module(module_name)
                except Exception as e:
                    print(f"Error loading plugin {module_name}: {e}")
    
    def _load_plugin_module(self, module_name: str):
        """Load a single plugin module"""
        try:
            module = importlib.import_module(module_name)
            
            # Find all classes that inherit from DetectorPlugin
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, DetectorPlugin) and obj is not DetectorPlugin:
                    plugin_instance = obj()
                    self.register_plugin(plugin_instance)
                    print(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
        
        except Exception as e:
            print(f"Error loading plugin module {module_name}: {e}")
    
    def register_plugin(self, plugin: DetectorPlugin):
        """Register a plugin instance"""
        self.plugins[plugin.name] = plugin
    
    def unregister_plugin(self, plugin_name: str):
        """Unregister a plugin"""
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
    
    def get_plugin(self, plugin_name: str) -> Optional[DetectorPlugin]:
        """Get a specific plugin by name"""
        return self.plugins.get(plugin_name)
    
    def get_all_plugins(self) -> List[DetectorPlugin]:
        """Get all registered plugins"""
        return list(self.plugins.values())
    
    def get_plugins_for_language(self, language: str) -> List[DetectorPlugin]:
        """Get all plugins that support a specific language"""
        return [
            plugin for plugin in self.plugins.values()
            if language in plugin.supported_languages or 'all' in plugin.supported_languages
        ]
    
    def scan_with_plugins(self, content: str, file_path: str, language: str = None) -> List[Dict]:
        """
        Run all applicable plugins on the content.
        
        Args:
            content: File content to scan
            file_path: Path to the file
            language: Programming language (optional)
        
        Returns:
            Combined findings from all plugins
        """
        findings = []
        
        if language:
            plugins = self.get_plugins_for_language(language)
        else:
            plugins = self.get_all_plugins()
        
        for plugin in plugins:
            try:
                plugin_findings = plugin.scan_content(content, file_path, language)
                findings.extend(plugin_findings)
            except Exception as e:
                print(f"Error running plugin {plugin.name}: {e}")
        
        return findings
    
    def get_plugin_info(self) -> List[Dict[str, Any]]:
        """Get information about all loaded plugins"""
        return [
            {
                'name': plugin.name,
                'version': plugin.version,
                'supported_languages': plugin.supported_languages
            }
            for plugin in self.plugins.values()
        ]


# Example plugin implementation
class ExampleCustomDetector(DetectorPlugin):
    """
    Example custom detector plugin.
    This demonstrates how to create a custom detector.
    """
    
    @property
    def name(self) -> str:
        return "example_custom_detector"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def supported_languages(self) -> List[str]:
        return ["python", "javascript"]
    
    def scan_content(self, content: str, file_path: str, language: str = None) -> List[Dict]:
        """Example scan implementation"""
        findings = []
        
        # Example: Detect print statements (for demonstration)
        if language == "python":
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'print(' in line:
                    from ..models import Severity
                    findings.append({
                        'rule_id': 'EXAMPLE_PRINT_STATEMENT',
                        'name': 'Print Statement Detected',
                        'description': 'Print statement found (example rule).',
                        'severity': Severity.INFO,
                        'file_path': file_path,
                        'line_number': i + 1,
                        'code_snippet': line.strip()[:200],
                        'remediation': 'Use logging instead of print statements.'
                    })
        
        return findings
