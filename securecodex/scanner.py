import os
from typing import List
from sqlalchemy.orm import Session
from datetime import datetime
from tqdm import tqdm
from . import models
from .detectors.pattern import PatternDetector
from .detectors.dependency import DependencyDetector
from .detectors.advanced_pattern_detector import AdvancedPatternDetector
from .detectors.multi_language_ast_detector import MultiLanguageASTDetector
from .scanner_config import ScannerConfig

class CLIScanner:
    """Standalone scanner for CLI usage"""
    
    def __init__(self, db: Session, scan_id: int, scan_path: str, verbose=False):
        self.db = db
        self.scan_id = scan_id
        self.scan_path = scan_path
        self.verbose = verbose
        
        # Initialize detectors
        self.pattern_detector = PatternDetector()
        self.dependency_detector = DependencyDetector()
        
        # Initialize advanced detectors
        self.advanced_detector = AdvancedPatternDetector()
        self.ast_detector = MultiLanguageASTDetector()
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'files_skipped': 0,
            'large_files': 0,
            'errors': 0,
            'total_loc': 0
        }
    
    def run(self):
        """Run the scan"""
        scan = self.db.query(models.Scan).filter(models.Scan.id == self.scan_id).first()
        if not scan:
            return
        
        scan.status = models.ScanStatus.RUNNING.value
        self.db.commit()
        
        findings_batch = []
        languages_set = set()
        
        try:
            # Collect all files to scan
            files_to_scan = self._collect_files(self.scan_path)
            total_file_count = len(files_to_scan)
            
            if self.verbose:
                print(f"\n[FILES] Found {total_file_count} files to scan")
            
            # Update scan with file count
            scan.total_files = total_file_count
            self.db.commit()
            
            # Process files with progress bar
            with tqdm(total=total_file_count, desc="Scanning files", unit="file") as pbar:
                for file_path in files_to_scan:
                    findings = self._scan_single_file(file_path)
                    findings_batch.extend(findings)
                    
                    # Track languages
                    ext = os.path.splitext(file_path)[1]
                    if ext:
                        languages_set.add(ext)
                    
                    pbar.update(1)
                    pbar.set_postfix({
                        'findings': len(findings_batch),
                        'errors': self.stats['errors']
                    })
            
            # Batch insert findings
            if self.verbose:
                print(f"\n[SAVE] Saving {len(findings_batch)} findings to database...")
            self._batch_insert_findings(findings_batch)
            
            # Update scan status
            scan.status = models.ScanStatus.COMPLETED.value
            scan.total_files = self.stats['files_scanned']
            scan.total_loc = self.stats['total_loc']
            scan.languages = ', '.join(sorted(languages_set))
            scan.end_time = datetime.utcnow()
            self.db.commit()
            
            # Print summary
            self._print_summary(scan, findings_batch)
            
        except Exception as e:
            print(f"\n[ERROR] Scan failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            scan.status = models.ScanStatus.FAILED.value
            scan.end_time = datetime.utcnow()
            self.db.commit()
    
    def _collect_files(self, scan_path: str) -> List[str]:
        """Collect all files to scan from the given path"""
        files = []
        
        if os.path.isfile(scan_path):
            # Single file
            files.append(scan_path)
        else:
            # Directory - walk recursively
            for root, dirs, filenames in os.walk(scan_path):
                # Filter out directories to skip
                dirs[:] = [d for d in dirs if not self._should_skip_directory(d)]
                
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    
                    # Skip hidden files but don't skip based on size (no threshold)
                    if not self._should_skip_file_basic(file_path):
                        files.append(file_path)
        
        return files
    
    def _should_skip_directory(self, dirname: str) -> bool:
        """Check if directory should be skipped"""
        skip_dirs = {
            'node_modules', '__pycache__', '.git', '.svn', '.hg',
            'venv', 'env', '.env', 'dist', 'build', '.next',
            'target', 'bin', 'obj', '.idea', '.vscode'
        }
        return dirname in skip_dirs or dirname.startswith('.')
    
    def _should_skip_file_basic(self, file_path: str) -> bool:
        """Basic file skip check (no size threshold as requested)"""
        # Skip hidden files
        if os.path.basename(file_path).startswith('.'):
            return True
        
        # Skip binary files
        binary_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.db', '.sqlite', '.mdb'
        }
        ext = os.path.splitext(file_path)[1].lower()
        if ext in binary_extensions:
            return True
        
        return False
    
    def _scan_single_file(self, file_path: str) -> List[dict]:
        """Scan a single file"""
        findings = []
        
        try:
            # Count lines
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                self.stats['total_loc'] += len(lines)
                content = ''.join(lines)
            
            # Run pattern detector
            findings.extend(self.pattern_detector.scan_content(content, file_path))
            
            # Run advanced pattern detector
            findings.extend(self.advanced_detector.scan_content(content, file_path))
            
            # Run AST detector
            findings.extend(self.ast_detector.scan_content(content, file_path))
            
            # Run dependency detector
            findings.extend(self.dependency_detector.scan_file(file_path))
            
            self.stats['files_scanned'] += 1
            
        except Exception as e:
            if self.verbose:
                print(f"\n[WARNING]  Error scanning file {file_path}: {e}")
            self.stats['errors'] += 1
        
        return findings
    
    def _batch_insert_findings(self, findings: List[dict]):
        """Insert findings in batches for better performance"""
        batch_size = 100
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            
            for f_data in batch:
                finding = models.Finding(
                    scan_id=self.scan_id,
                    rule_id=f_data.get('rule_id', 'UNKNOWN'),
                    name=f_data.get('name', 'Unknown'),
                    description=f_data.get('description', ''),
                    severity=f_data.get('severity', models.Severity.INFO.value),
                    file_path=f_data.get('file_path', ''),
                    line_number=f_data.get('line_number', 0),
                    code_snippet=f_data.get('code_snippet', ''),
                    cwe_id=f_data.get('cwe_id', None),
                    remediation=f_data.get('remediation', '')
                )
                self.db.add(finding)
            
            # Commit batch
            try:
                self.db.commit()
            except Exception as e:
                print(f"Error committing findings batch: {e}")
                self.db.rollback()
    
    def _print_summary(self, scan, findings):
        """Print scan summary"""
        # Count by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        print("\n" + "="*60)
        print(" SCAN SUMMARY")
        print("="*60)
        print(f"Project: {scan.project_name}")
        print(f"Path: {scan.scan_path}")
        print(f"Files Scanned: {self.stats['files_scanned']}")
        print(f"Total Lines of Code: {self.stats['total_loc']:,}")
        print(f"Languages: {scan.languages}")
        print(f"Duration: {(scan.end_time - scan.start_time).total_seconds():.2f}s")
        print("\n" + "-"*60)
        print("FINDINGS BY SEVERITY:")
        print("-"*60)
        print(f"  CRITICAL: Critical: {severity_counts['CRITICAL']}")
        print(f"  HIGH:     High:     {severity_counts['HIGH']}")
        print(f"  MEDIUM:   Medium:   {severity_counts['MEDIUM']}")
        print(f"  LOW:      Low:      {severity_counts['LOW']}")
        print(f"  INFO:      Info:     {severity_counts['INFO']}")
        print(f"\n  TOTAL:    Total:    {len(findings)}")
        print("="*60 + "\n")

