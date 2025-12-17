#!/usr/bin/env python3
"""
SecureCodeX CLI - Security Source Code Analysis Tool
Command-line interface for scanning source code for vulnerabilities
"""

import argparse
import os
import sys
from datetime import datetime
from .database import DatabaseManager
from .scanner import CLIScanner
from .report import PDFReportGenerator
from . import models

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='SecureCodeX - Security Source Code Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory
  securecodex scan
  
  # Scan specific directory
  securecodex scan --path /path/to/source
  
  # Scan with custom output location
  securecodex scan --path ./myproject --output ./reports
  
  # Scan with verbose output
  securecodex scan --path ./myproject --verbose
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan source code for vulnerabilities')
    scan_parser.add_argument(
        '--path',
        type=str,
        default='.',
        help='Path to scan (directory or file). Default: current directory'
    )
    scan_parser.add_argument(
        '--output',
        type=str,
        default='.',
        help='Output directory for reports. Default: current directory'
    )
    scan_parser.add_argument(
        '--project-name',
        type=str,
        default=None,
        help='Project name for the report. Default: directory name'
    )
    scan_parser.add_argument(
        '--format',
        type=str,
        choices=['pdf', 'json', 'both'],
        default='pdf',
        help='Output format. Default: pdf'
    )
    scan_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    scan_parser.add_argument(
        '--keep-db',
        action='store_true',
        help='Keep the SQLite database after scan (for debugging)'
    )
    
    # Version command
    parser.add_argument('--version', action='version', version='SecureCodeX CLI 1.0.0')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        run_scan(args)

def run_scan(args):
    """Run a security scan"""
    # Validate and normalize path
    scan_path = os.path.abspath(args.path)
    
    if not os.path.exists(scan_path):
        print(f"[ERROR] Error: Path does not exist: {scan_path}")
        sys.exit(1)
    
    # Determine project name
    if args.project_name:
        project_name = args.project_name
    else:
        if os.path.isfile(scan_path):
            project_name = os.path.basename(os.path.dirname(scan_path))
        else:
            project_name = os.path.basename(scan_path)
    
    # Create output directory if needed
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)
    
    # Print banner
    print("\n" + "="*60)
    print("  SecureCodeX - Security Source Code Analysis Tool")
    print("="*60)
    print(f"Project: {project_name}")
    print(f"Scan Path: {scan_path}")
    print(f"Output Directory: {output_dir}")
    print("="*60 + "\n")
    
    # Initialize database
    db_manager = DatabaseManager()
    db = db_manager.get_session()
    
    try:
        # Create scan record
        scan = models.Scan(
            project_name=project_name,
            scan_path=scan_path,
            status=models.ScanStatus.PENDING.value,
            start_time=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        if args.verbose:
            print(f"[NOTE] Created scan record with ID: {scan.id}\n")
        
        # Run scanner
        scanner = CLIScanner(db, scan.id, scan_path, verbose=args.verbose)
        scanner.run()
        
        # Generate reports
        if scan.status == models.ScanStatus.COMPLETED.value:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Generate PDF report
            if args.format in ['pdf', 'both']:
                pdf_filename = f"SecureCodeX_Report_{project_name}_{timestamp}.pdf"
                pdf_path = os.path.join(output_dir, pdf_filename)
                
                print(f"\n[REPORT] Generating PDF report...")
                report_gen = PDFReportGenerator(db, scan.id)
                report_gen.generate(pdf_path)
                print(f"[OK] PDF report saved to: {pdf_path}")
            
            # Generate JSON report
            if args.format in ['json', 'both']:
                json_filename = f"SecureCodeX_Report_{project_name}_{timestamp}.json"
                json_path = os.path.join(output_dir, json_filename)
                
                print(f"\n[REPORT] Generating JSON report...")
                generate_json_report(db, scan.id, json_path)
                print(f"[OK] JSON report saved to: {json_path}")
            
            print("\n[OK] Scan completed successfully!\n")
        else:
            print("\n[ERROR] Scan failed or was stopped.\n")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\n[WARNING]  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()
        # Cleanup database unless --keep-db is specified
        if not args.keep_db:
            db_manager.cleanup(keep_db=False)
        else:
            print(f"\n[SAVE] Database kept at: {db_manager.db_path}")

def generate_json_report(db, scan_id, output_path):
    """Generate JSON report"""
    import json
    
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    
    # Count by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    report_data = {
        "scan": {
            "id": scan.id,
            "project_name": scan.project_name,
            "scan_path": scan.scan_path,
            "status": scan.status,
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "total_files": scan.total_files,
            "total_loc": scan.total_loc,
            "languages": scan.languages
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts
        },
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "name": f.name,
                "description": f.description,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "cwe_id": f.cwe_id,
                "remediation": f.remediation
            }
            for f in findings
        ]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)

if __name__ == '__main__':
    main()

