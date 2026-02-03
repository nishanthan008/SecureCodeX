"""
Enhanced Dependency Extractor for SBOM Generation
Extracts ALL dependencies from manifest files (not just vulnerable ones)
"""
import os
import json
import re
from typing import List, Dict

class DependencyExtractor:
    """Extract all dependencies from various package manager files for SBOM generation"""
    
    def __init__(self, vulnerable_packages: Dict = None):
        self.vulnerable_packages = vulnerable_packages or {}
    
    def extract_all(self, file_path: str) -> List[Dict]:
        """Extract ALL dependencies from a file for SBOM generation"""
        dependencies = []
        filename = os.path.basename(file_path).lower()

        # Python
        if filename == "requirements.txt":
            dependencies.extend(self._extract_python_requirements(file_path))
        elif filename == "pipfile":
            dependencies.extend(self._extract_pipfile(file_path))
        elif filename == "pyproject.toml":
            dependencies.extend(self._extract_pyproject(file_path))
        
        # JavaScript/Node
        elif filename == "package.json":
            dependencies.extend(self._extract_node_package(file_path))
        elif filename == "package-lock.json":
            dependencies.extend(self._extract_node_lock(file_path))
        
        # Java
        elif filename == "pom.xml":
            dependencies.extend(self._extract_maven(file_path))
        elif filename in ["build.gradle", "build.gradle.kts"]:
            dependencies.extend(self._extract_gradle(file_path))
        
        # Go
        elif filename == "go.mod":
            dependencies.extend(self._extract_go_mod(file_path))
        
        # Ruby
        elif filename == "gemfile":
            dependencies.extend(self._extract_gemfile(file_path))
        
        # Rust
        elif filename == "cargo.toml":
            dependencies.extend(self._extract_cargo(file_path))
        
        # PHP
        elif filename == "composer.json":
            dependencies.extend(self._extract_composer(file_path))
            
        return dependencies

    def _extract_python_requirements(self, file_path: str) -> List[Dict]:
        """Extract all Python dependencies from requirements.txt"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse: package==version or package>=version
                    match = re.match(r'([a-zA-Z0-9_-]+)\s*([=<>!]+)\s*([0-9.]+)', line)
                    if match:
                        pkg_name = match.group(1)
                        pkg_version = match.group(3)
                        is_vulnerable = pkg_name.lower() in self.vulnerable_packages.get("python", {})
                        
                        dependencies.append({
                            "name": pkg_name,
                            "version": pkg_version,
                            "ecosystem": "python",
                            "purl": f"pkg:pypi/{pkg_name}@{pkg_version}",
                            "vulnerable": is_vulnerable
                        })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_pipfile(self, file_path: str) -> List[Dict]:
        """Extract all Python dependencies from Pipfile"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Simple parsing for [packages] section
                in_packages = False
                for line in content.split('\n'):
                    if '[packages]' in line:
                        in_packages = True
                        continue
                    if in_packages and line.startswith('['):
                        break
                    if in_packages and '=' in line:
                        match = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*["\']([^"\']+)["\']', line)
                        if match:
                            pkg_name = match.group(1)
                            pkg_version = match.group(2).replace('==', '').replace('^', '').replace('~', '')
                            is_vulnerable = pkg_name.lower() in self.vulnerable_packages.get("python", {})
                            
                            dependencies.append({
                                "name": pkg_name,
                                "version": pkg_version,
                                "ecosystem": "python",
                                "purl": f"pkg:pypi/{pkg_name}@{pkg_version}",
                                "vulnerable": is_vulnerable
                            })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_pyproject(self, file_path: str) -> List[Dict]:
        """Extract all Python dependencies from pyproject.toml"""
        dependencies = []
        try:
            import toml
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
                deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
                
                for pkg_name, pkg_version in deps.items():
                    if pkg_name == 'python':  # Skip Python version
                        continue
                    version_str = str(pkg_version).replace('^', '').replace('~', '').replace('>=', '').replace('==', '')
                    is_vulnerable = pkg_name.lower() in self.vulnerable_packages.get("python", {})
                    
                    dependencies.append({
                        "name": pkg_name,
                        "version": version_str,
                        "ecosystem": "python",
                        "purl": f"pkg:pypi/{pkg_name}@{version_str}",
                        "vulnerable": is_vulnerable
                    })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_node_package(self, file_path: str) -> List[Dict]:
        """Extract all Node.js dependencies from package.json"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                all_deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                
                for pkg_name, pkg_version in all_deps.items():
                    clean_version = re.sub(r'^[\^~>=<]+', '', pkg_version)
                    is_vulnerable = pkg_name in self.vulnerable_packages.get("javascript", {})
                    
                    dependencies.append({
                        "name": pkg_name,
                        "version": clean_version,
                        "ecosystem": "npm",
                        "purl": f"pkg:npm/{pkg_name}@{clean_version}",
                        "vulnerable": is_vulnerable
                    })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_node_lock(self, file_path: str) -> List[Dict]:
        """Extract dependencies from package-lock.json"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                packages = data.get('packages', {})
                
                for pkg_path, pkg_info in packages.items():
                    if not pkg_path or pkg_path == '':  # Skip root
                        continue
                    pkg_name = pkg_path.replace('node_modules/', '')
                    pkg_version = pkg_info.get('version', 'unknown')
                    is_vulnerable = pkg_name in self.vulnerable_packages.get("javascript", {})
                    
                    dependencies.append({
                        "name": pkg_name,
                        "version": pkg_version,
                        "ecosystem": "npm",
                        "purl": f"pkg:npm/{pkg_name}@{pkg_version}",
                        "vulnerable": is_vulnerable
                    })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_maven(self, file_path: str) -> List[Dict]:
        """Extract all Java dependencies from pom.xml"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                matches = re.findall(r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>', content, re.DOTALL)
                
                for group, artifact, version in matches:
                    group = group.strip()
                    artifact = artifact.strip()
                    version = version.strip()
                    is_vulnerable = artifact in self.vulnerable_packages.get("java", {})
                    
                    dependencies.append({
                        "name": artifact,
                        "group": group,
                        "version": version,
                        "ecosystem": "maven",
                        "purl": f"pkg:maven/{group}/{artifact}@{version}",
                        "vulnerable": is_vulnerable
                    })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_gradle(self, file_path: str) -> List[Dict]:
        """Extract all Java dependencies from build.gradle"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Match: implementation 'group:artifact:version'
                matches = re.findall(r'(?:implementation|compile|api|testImplementation)\s+["\']([^:]+):([^:]+):([^"\']+)["\']', content)
                
                for group, artifact, version in matches:
                    is_vulnerable = artifact in self.vulnerable_packages.get("java", {})
                    
                    dependencies.append({
                        "name": artifact,
                        "group": group,
                        "version": version,
                        "ecosystem": "maven",
                        "purl": f"pkg:maven/{group}/{artifact}@{version}",
                        "vulnerable": is_vulnerable
                    })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_go_mod(self, file_path: str) -> List[Dict]:
        """Extract all Go dependencies from go.mod"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    # Match: require github.com/package v1.2.3
                    match = re.match(r'\s*([a-zA-Z0-9./\-_]+)\s+v([0-9.]+)', line)
                    if match:
                        pkg_name = match.group(1)
                        pkg_version = match.group(2)
                        is_vulnerable = pkg_name in self.vulnerable_packages.get("go", {})
                        
                        dependencies.append({
                            "name": pkg_name,
                            "version": pkg_version,
                            "ecosystem": "go",
                            "purl": f"pkg:golang/{pkg_name}@{pkg_version}",
                            "vulnerable": is_vulnerable
                        })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_gemfile(self, file_path: str) -> List[Dict]:
        """Extract all Ruby dependencies from Gemfile"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    # Match: gem 'rails', '~> 5.2.0'
                    match = re.match(r'\s*gem\s+["\']([^"\']+)["\'](?:,\s*["\']([^"\']+)["\'])?', line)
                    if match:
                        pkg_name = match.group(1)
                        pkg_version = match.group(2) if match.group(2) else 'latest'
                        pkg_version = pkg_version.replace('~>', '').replace('>=', '').strip()
                        is_vulnerable = pkg_name in self.vulnerable_packages.get("ruby", {})
                        
                        dependencies.append({
                            "name": pkg_name,
                            "version": pkg_version,
                            "ecosystem": "rubygems",
                            "purl": f"pkg:gem/{pkg_name}@{pkg_version}",
                            "vulnerable": is_vulnerable
                        })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_cargo(self, file_path: str) -> List[Dict]:
        """Extract all Rust dependencies from Cargo.toml"""
        dependencies = []
        try:
            import toml
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
                deps = data.get('dependencies', {})
                
                for pkg_name, pkg_version in deps.items():
                    version_str = str(pkg_version) if isinstance(pkg_version, str) else pkg_version.get('version', 'latest')
                    is_vulnerable = pkg_name in self.vulnerable_packages.get("rust", {})
                    
                    dependencies.append({
                        "name": pkg_name,
                        "version": version_str,
                        "ecosystem": "cargo",
                        "purl": f"pkg:cargo/{pkg_name}@{version_str}",
                        "vulnerable": is_vulnerable
                    })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies

    def _extract_composer(self, file_path: str) -> List[Dict]:
        """Extract all PHP dependencies from composer.json"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                all_deps = {**data.get('require', {}), **data.get('require-dev', {})}
                
                for pkg_name, pkg_version in all_deps.items():
                    if pkg_name == 'php':  # Skip PHP version
                        continue
                    clean_version = re.sub(r'^[\^~>=<]+', '', pkg_version)
                    is_vulnerable = pkg_name in self.vulnerable_packages.get("php", {})
                    
                    dependencies.append({
                        "name": pkg_name,
                        "version": clean_version,
                        "ecosystem": "composer",
                        "purl": f"pkg:composer/{pkg_name}@{clean_version}",
                        "vulnerable": is_vulnerable
                    })
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
        
        return dependencies
