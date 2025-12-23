import os
import json
import re
from typing import List, Dict
from ..models import Severity

try:
    from packaging import version
    PACKAGING_AVAILABLE = True
except ImportError:
    PACKAGING_AVAILABLE = False

class DependencyDetector:
    """
    Enhanced dependency detector supporting multiple package managers and ecosystems.
    """
    
    def __init__(self):
        # Expanded database of vulnerable packages
        # In production, this would query OSV, NVD, or similar databases
        self.vulnerable_packages = {
            "python": {
                "flask": {"version": "0.12", "id": "CVE-2018-1000656", "severity": Severity.HIGH},
                "django": {"version": "1.11", "id": "CVE-2019-3498", "severity": Severity.HIGH},
                "requests": {"version": "2.19", "id": "CVE-2018-18074", "severity": Severity.MEDIUM},
                "pillow": {"version": "6.2.1", "id": "CVE-2020-5313", "severity": Severity.HIGH},
                "pyyaml": {"version": "5.3", "id": "CVE-2020-14343", "severity": Severity.HIGH},
                "urllib3": {"version": "1.24.1", "id": "CVE-2019-11324", "severity": Severity.MEDIUM},
            },
            "javascript": {
                "lodash": {"version": "4.17.15", "id": "CVE-2020-8203", "severity": Severity.HIGH},
                "axios": {"version": "0.18.0", "id": "CVE-2019-10742", "severity": Severity.MEDIUM},
                "react": {"version": "16.8.0", "id": "CVE-2019-11300", "severity": Severity.LOW},
                "express": {"version": "4.16.0", "id": "CVE-2019-5413", "severity": Severity.MEDIUM},
                "minimist": {"version": "1.2.5", "id": "CVE-2021-44906", "severity": Severity.HIGH},
                "node-fetch": {"version": "2.6.0", "id": "CVE-2020-15168", "severity": Severity.MEDIUM},
            },
            "java": {
                "log4j-core": {"version": "2.14.1", "id": "CVE-2021-44228", "severity": Severity.CRITICAL},
                "spring-core": {"version": "5.2.0", "id": "CVE-2020-5398", "severity": Severity.HIGH},
                "jackson-databind": {"version": "2.9.8", "id": "CVE-2019-12384", "severity": Severity.HIGH},
            },
            "ruby": {
                "rails": {"version": "5.2.0", "id": "CVE-2019-5418", "severity": Severity.HIGH},
                "nokogiri": {"version": "1.10.3", "id": "CVE-2019-5477", "severity": Severity.HIGH},
            },
            "go": {
                "github.com/gin-gonic/gin": {"version": "1.6.0", "id": "CVE-2020-28483", "severity": Severity.MEDIUM},
            },
            "rust": {
                "actix-web": {"version": "2.0.0", "id": "RUSTSEC-2020-0036", "severity": Severity.MEDIUM},
            },
            "php": {
                "symfony/symfony": {"version": "4.4.0", "id": "CVE-2020-5255", "severity": Severity.HIGH},
                "laravel/framework": {"version": "7.0.0", "id": "CVE-2021-3129", "severity": Severity.CRITICAL},
            }
        }

    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan dependency file for vulnerable packages"""
        findings = []
        filename = os.path.basename(file_path).lower()

        # Python
        if filename == "requirements.txt":
            findings.extend(self._scan_python_requirements(file_path))
        elif filename == "pipfile":
            findings.extend(self._scan_pipfile(file_path))
        elif filename == "pyproject.toml":
            findings.extend(self._scan_pyproject(file_path))
        
        # JavaScript/Node
        elif filename == "package.json":
            findings.extend(self._scan_node_package(file_path))
        elif filename == "package-lock.json":
            findings.extend(self._scan_node_lock(file_path))
        
        # Java
        elif filename == "pom.xml":
            findings.extend(self._scan_maven(file_path))
        elif filename in ["build.gradle", "build.gradle.kts"]:
            findings.extend(self._scan_gradle(file_path))
        
        # Go
        elif filename == "go.mod":
            findings.extend(self._scan_go_mod(file_path))
        
        # Ruby
        elif filename == "gemfile":
            findings.extend(self._scan_gemfile(file_path))
        
        # Rust
        elif filename == "cargo.toml":
            findings.extend(self._scan_cargo(file_path))
        
        # PHP
        elif filename == "composer.json":
            findings.extend(self._scan_composer(file_path))
            
        return findings

    def _compare_versions(self, installed: str, vulnerable: str) -> bool:
        """Compare versions (returns True if installed version is vulnerable)"""
        if not PACKAGING_AVAILABLE:
            # Fallback to string comparison
            return installed == vulnerable
        
        try:
            return version.parse(installed) <= version.parse(vulnerable)
        except:
            return installed == vulnerable

    def _scan_python_requirements(self, file_path: str) -> List[Dict]:
        """Scan Python requirements.txt"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse: package==version or package>=version
                    match = re.match(r'([a-zA-Z0-9_-]+)\s*([=<>!]+)\s*([0-9.]+)', line)
                    if match:
                        pkg_name = match.group(1).lower()
                        operator = match.group(2)
                        pkg_version = match.group(3)
                        
                        if pkg_name in self.vulnerable_packages["python"]:
                            vuln = self.vulnerable_packages["python"][pkg_name]
                            if operator == '==' and self._compare_versions(pkg_version, vuln["version"]):
                                findings.append({
                                    "rule_id": "VULN_DEPENDENCY_PY",
                                    "name": f"Vulnerable Python Package: {pkg_name}",
                                    "description": f"Package {pkg_name} version {pkg_version} is vulnerable to {vuln['id']}.",
                                    "severity": vuln["severity"],
                                    "file_path": file_path,
                                    "line_number": i + 1,
                                    "code_snippet": line,
                                    "remediation": f"Upgrade {pkg_name} to a safe version."
                                })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_pipfile(self, file_path: str) -> List[Dict]:
        """Scan Python Pipfile"""
        # Similar to requirements.txt but TOML format
        return self._scan_python_requirements(file_path)

    def _scan_pyproject(self, file_path: str) -> List[Dict]:
        """Scan Python pyproject.toml"""
        findings = []
        try:
            import toml
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
                dependencies = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
                
                for pkg_name, pkg_version in dependencies.items():
                    pkg_name = pkg_name.lower()
                    if pkg_name in self.vulnerable_packages["python"]:
                        vuln = self.vulnerable_packages["python"][pkg_name]
                        findings.append({
                            "rule_id": "VULN_DEPENDENCY_PY",
                            "name": f"Vulnerable Python Package: {pkg_name}",
                            "description": f"Package {pkg_name} may be vulnerable to {vuln['id']}.",
                            "severity": vuln["severity"],
                            "file_path": file_path,
                            "line_number": 0,
                            "code_snippet": f"{pkg_name} = {pkg_version}",
                            "remediation": f"Upgrade {pkg_name} to a safe version."
                        })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_node_package(self, file_path: str) -> List[Dict]:
        """Scan Node.js package.json"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                
                for pkg_name, pkg_version in dependencies.items():
                    if pkg_name in self.vulnerable_packages["javascript"]:
                        vuln = self.vulnerable_packages["javascript"][pkg_name]
                        # Remove version prefixes like ^, ~, >=
                        clean_version = re.sub(r'^[\^~>=<]+', '', pkg_version)
                        
                        if self._compare_versions(clean_version, vuln["version"]):
                            findings.append({
                                "rule_id": "VULN_DEPENDENCY_JS",
                                "name": f"Vulnerable JS Package: {pkg_name}",
                                "description": f"Package {pkg_name} version {pkg_version} is vulnerable to {vuln['id']}.",
                                "severity": vuln["severity"],
                                "file_path": file_path,
                                "line_number": 0,
                                "code_snippet": f'"{pkg_name}": "{pkg_version}"',
                                "remediation": f"Upgrade {pkg_name} to a safe version."
                            })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_node_lock(self, file_path: str) -> List[Dict]:
        """Scan package-lock.json"""
        # Similar to package.json but with resolved versions
        return self._scan_node_package(file_path)

    def _scan_maven(self, file_path: str) -> List[Dict]:
        """Scan Maven pom.xml"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Simple XML parsing for dependencies
                for pkg_name, vuln in self.vulnerable_packages["java"].items():
                    if pkg_name in content and vuln["version"] in content:
                        findings.append({
                            "rule_id": "VULN_DEPENDENCY_JAVA",
                            "name": f"Vulnerable Java Package: {pkg_name}",
                            "description": f"Package {pkg_name} version {vuln['version']} is vulnerable to {vuln['id']}.",
                            "severity": vuln["severity"],
                            "file_path": file_path,
                            "line_number": 0,
                            "code_snippet": f"{pkg_name}:{vuln['version']}",
                            "remediation": f"Upgrade {pkg_name} to a safe version."
                        })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_gradle(self, file_path: str) -> List[Dict]:
        """Scan Gradle build files"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for pkg_name, vuln in self.vulnerable_packages["java"].items():
                    if pkg_name in content:
                        findings.append({
                            "rule_id": "VULN_DEPENDENCY_JAVA",
                            "name": f"Vulnerable Java Package: {pkg_name}",
                            "description": f"Package {pkg_name} may be vulnerable to {vuln['id']}.",
                            "severity": vuln["severity"],
                            "file_path": file_path,
                            "line_number": 0,
                            "code_snippet": pkg_name,
                            "remediation": f"Upgrade {pkg_name} to a safe version."
                        })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_go_mod(self, file_path: str) -> List[Dict]:
        """Scan Go go.mod"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    for pkg_name, vuln in self.vulnerable_packages["go"].items():
                        if pkg_name in line and vuln["version"] in line:
                            findings.append({
                                "rule_id": "VULN_DEPENDENCY_GO",
                                "name": f"Vulnerable Go Package: {pkg_name}",
                                "description": f"Package {pkg_name} version {vuln['version']} is vulnerable to {vuln['id']}.",
                                "severity": vuln["severity"],
                                "file_path": file_path,
                                "line_number": i + 1,
                                "code_snippet": line.strip(),
                                "remediation": f"Upgrade {pkg_name} to a safe version."
                            })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_gemfile(self, file_path: str) -> List[Dict]:
        """Scan Ruby Gemfile"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    for pkg_name, vuln in self.vulnerable_packages["ruby"].items():
                        if pkg_name in line:
                            findings.append({
                                "rule_id": "VULN_DEPENDENCY_RUBY",
                                "name": f"Vulnerable Ruby Gem: {pkg_name}",
                                "description": f"Gem {pkg_name} may be vulnerable to {vuln['id']}.",
                                "severity": vuln["severity"],
                                "file_path": file_path,
                                "line_number": i + 1,
                                "code_snippet": line.strip(),
                                "remediation": f"Upgrade {pkg_name} to a safe version."
                            })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_cargo(self, file_path: str) -> List[Dict]:
        """Scan Rust Cargo.toml"""
        findings = []
        try:
            import toml
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
                dependencies = data.get('dependencies', {})
                
                for pkg_name, pkg_version in dependencies.items():
                    if pkg_name in self.vulnerable_packages["rust"]:
                        vuln = self.vulnerable_packages["rust"][pkg_name]
                        findings.append({
                            "rule_id": "VULN_DEPENDENCY_RUST",
                            "name": f"Vulnerable Rust Crate: {pkg_name}",
                            "description": f"Crate {pkg_name} may be vulnerable to {vuln['id']}.",
                            "severity": vuln["severity"],
                            "file_path": file_path,
                            "line_number": 0,
                            "code_snippet": f"{pkg_name} = {pkg_version}",
                            "remediation": f"Upgrade {pkg_name} to a safe version."
                        })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def _scan_composer(self, file_path: str) -> List[Dict]:
        """Scan PHP composer.json"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                dependencies = {**data.get('require', {}), **data.get('require-dev', {})}
                
                for pkg_name, pkg_version in dependencies.items():
                    if pkg_name in self.vulnerable_packages["php"]:
                        vuln = self.vulnerable_packages["php"][pkg_name]
                        findings.append({
                            "rule_id": "VULN_DEPENDENCY_PHP",
                            "name": f"Vulnerable PHP Package: {pkg_name}",
                            "description": f"Package {pkg_name} may be vulnerable to {vuln['id']}.",
                            "severity": vuln["severity"],
                            "file_path": file_path,
                            "line_number": 0,
                            "code_snippet": f'"{pkg_name}": "{pkg_version}"',
                            "remediation": f"Upgrade {pkg_name} to a safe version."
                        })
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        
        return findings

    def generate_sbom(self, file_paths: List[str]) -> Dict:
        """
        Generates a Software Bill of Materials (SBOM) in CycloneDX-like JSON format.
        
        Args:
            file_paths: List of dependency file paths to scan.
            
        Returns:
            Dictionary representing the SBOM.
        """
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": []
        }
        
        for file_path in file_paths:
            filename = os.path.basename(file_path).lower()
            components = []
            
            if filename.endswith("requirements.txt"):
                components = self._parse_requirements_txt(file_path)
            elif filename == "package.json":
                components = self._parse_package_json(file_path)
            elif filename == "pom.xml":
                components = self._parse_pom_xml(file_path)
            elif filename == "composer.json":
                components = self._parse_composer_json(file_path)
            # Add other parsers as needed
            
            sbom["components"].extend(components)
            
        return sbom

    def _parse_requirements_txt(self, file_path: str) -> List[Dict]:
        """Parse requirements.txt for SBOM"""
        components = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    match = re.match(r'([a-zA-Z0-9_-]+)\s*([=<>!]+)\s*([0-9.]+)', line)
                    if match:
                        components.append({
                            "type": "library",
                            "name": match.group(1),
                            "version": match.group(3),
                            "purl": f"pkg:pypi/{match.group(1)}@{match.group(3)}"
                        })
        except Exception:
            pass
        return components

    def _parse_package_json(self, file_path: str) -> List[Dict]:
        """Parse package.json for SBOM"""
        components = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                for name, version in dependencies.items():
                    clean_version = re.sub(r'^[\^~>=<]+', '', version)
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": clean_version,
                        "purl": f"pkg:npm/{name}@{clean_version}"
                    })
        except Exception:
            pass
        return components

    def _parse_pom_xml(self, file_path: str) -> List[Dict]:
        """Parse pom.xml for SBOM (Simplified)"""
        components = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Basic regex for demo purposes (proper XML parsing recommended for prod)
                matches = re.findall(r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>', content, re.DOTALL)
                for group, artifact, version in matches:
                    components.append({
                        "type": "library",
                        "group": group.strip(),
                        "name": artifact.strip(),
                        "version": version.strip(),
                        "purl": f"pkg:maven/{group.strip()}/{artifact.strip()}@{version.strip()}"
                    })
        except Exception:
            pass
        return components

    def _parse_composer_json(self, file_path: str) -> List[Dict]:
        """Parse composer.json for SBOM"""
        components = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                dependencies = {**data.get('require', {}), **data.get('require-dev', {})}
                for name, version in dependencies.items():
                    clean_version = re.sub(r'^[\^~>=<]+', '', version)
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": clean_version,
                        "purl": f"pkg:composer/{name}@{clean_version}"
                    })
        except Exception:
            pass
        return components
