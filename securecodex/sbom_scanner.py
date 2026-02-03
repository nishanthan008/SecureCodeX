"""
SBOM Scanner - Dedicated dependency and SBOM analysis
"""
import os
import json
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from tqdm import tqdm
from . import models
from .detectors.dependency import DependencyDetector
from .detectors.dependency_extractor import DependencyExtractor

class SBOMScanner:
    """Dedicated SBOM and dependency scanner"""
    
    def __init__(self, db: Session, scan_id: int, scan_path: str, verbose=False):
        self.db = db
        self.scan_id = scan_id
        self.scan_path = scan_path
        self.verbose = verbose
        self.dependency_detector = DependencyDetector()
        # Initialize extractor with vulnerable packages database
        self.dependency_extractor = DependencyExtractor(self.dependency_detector.vulnerable_packages)
        
        # Dependency manifest file patterns
        self.dependency_patterns = {
            'javascript': ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
            'python': ['requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'setup.py', 'pyproject.toml'],
            'java': ['pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile'],
            'ruby': ['Gemfile', 'Gemfile.lock'],
            'go': ['go.mod', 'go.sum'],
            'php': ['composer.json', 'composer.lock'],
            'rust': ['Cargo.toml', 'Cargo.lock'],
            'csharp': ['packages.config', '*.csproj', 'project.json'],
            'swift': ['Package.swift', 'Podfile', 'Podfile.lock']
        }
    
    def run(self) -> Dict[str, Any]:
        """Run SBOM scan and return SBOM data"""
        scan = self.db.query(models.Scan).filter(models.Scan.id == self.scan_id).first()
        if not scan:
            return {}
        
        scan.status = models.ScanStatus.RUNNING.value
        self.db.commit()
        
        try:
            # Find all dependency files
            dependency_files = self._find_dependency_files()
            
            if self.verbose:
                print(f"\n[INFO] Found {len(dependency_files)} dependency manifest files")
            
            # Scan each dependency file
            all_dependencies = []
            vulnerable_deps = []
            
            with tqdm(total=len(dependency_files), desc="Scanning dependencies", unit="file") as pbar:
                for dep_file in dependency_files:
                    if self.verbose:
                        print(f"\n[SCAN] {dep_file}")
                    
                    # Extract ALL dependencies from this file
                    extracted_deps = self.dependency_extractor.extract_all(dep_file)
                    
                    # Add to all_dependencies list
                    for dep in extracted_deps:
                        dep_info = {
                            'file': dep_file,
                            'language': dep.get('ecosystem', self._detect_language(dep_file)),
                            'package': dep
                        }
                        all_dependencies.append(dep_info)
                        
                        # Track vulnerable dependencies
                        if dep.get('vulnerable', False):
                            vulnerable_deps.append(dep_info)
                    
                    pbar.update(1)
            
            # Generate SBOM structure
            sbom = self._generate_sbom(all_dependencies, vulnerable_deps)
            
            # Update scan status
            scan.status = models.ScanStatus.COMPLETED.value
            scan.end_time = datetime.now(timezone.utc)
            self.db.commit()
            
            return sbom
            
        except Exception as e:
            scan.status = models.ScanStatus.FAILED.value
            self.db.commit()
            raise e
    
    def _find_dependency_files(self) -> List[str]:
        """Find all dependency manifest files in the project"""
        dependency_files = []
        
        # Flatten all patterns
        all_patterns = []
        for patterns in self.dependency_patterns.values():
            all_patterns.extend(patterns)
        
        # Walk directory tree
        for root, dirs, files in os.walk(self.scan_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build']]
            
            for file in files:
                # Check if file matches any pattern
                for pattern in all_patterns:
                    if pattern.startswith('*'):
                        # Wildcard pattern
                        if file.endswith(pattern[1:]):
                            dependency_files.append(os.path.join(root, file))
                            break
                    else:
                        # Exact match
                        if file == pattern:
                            dependency_files.append(os.path.join(root, file))
                            break
        
        return dependency_files
    
    def _detect_language(self, file_path: str) -> str:
        """Detect language from dependency file"""
        filename = os.path.basename(file_path)
        
        for lang, patterns in self.dependency_patterns.items():
            for pattern in patterns:
                if pattern.startswith('*'):
                    if filename.endswith(pattern[1:]):
                        return lang
                else:
                    if filename == pattern:
                        return lang
        
        return 'unknown'
    
    def _generate_sbom(self, all_dependencies: List[Dict], vulnerable_deps: List[Dict]) -> Dict[str, Any]:
        """Generate SBOM structure"""
        # Count vulnerable dependencies by severity (estimate based on known vulnerabilities)
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for dep in vulnerable_deps:
            # Estimate severity - in production, query vulnerability database
            severity_counts['HIGH'] += 1  # Default to HIGH for vulnerable packages
        
        # Group by language/ecosystem
        by_language = {}
        for dep in all_dependencies:
            lang = dep['language']
            if lang not in by_language:
                by_language[lang] = []
            by_language[lang].append(dep)
        
        # Create detailed package list
        packages = []
        for dep in all_dependencies:
            pkg = dep['package']
            packages.append({
                'name': pkg.get('name'),
                'version': pkg.get('version'),
                'ecosystem': pkg.get('ecosystem'),
                'purl': pkg.get('purl'),
                'vulnerable': pkg.get('vulnerable', False),
                'source_file': dep['file']
            })
        
        sbom = {
            'sbom_version': '1.0',
            'tool': 'SecureCodeX',
            'tool_version': '3.0.0',
            'project': os.path.basename(self.scan_path),
            'scan_date': datetime.now(timezone.utc).isoformat(),
            'scan_path': self.scan_path,
            'summary': {
                'total_dependencies': len(all_dependencies),
                'vulnerable_dependencies': len(vulnerable_deps),
                'critical': severity_counts['CRITICAL'],
                'high': severity_counts['HIGH'],
                'medium': severity_counts['MEDIUM'],
                'low': severity_counts['LOW'],
                'ecosystems': list(by_language.keys())
            },
            'packages': packages,
            'dependencies_by_ecosystem': by_language,
            'vulnerable_dependencies': vulnerable_deps
        }
        
        return sbom
