from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.units import inch
from io import BytesIO
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
from . import models
import os
import html

class PDFReportGenerator:
    """Generate PDF reports for CLI scans"""
    
    def __init__(self, db: Session, scan_id: int):
        self.db = db
        self.scan_id = scan_id
    
    def generate(self, output_path: str):
        """
        Generate PDF report
        
        Args:
            output_path: Path where PDF should be saved
        """
        scan = self.db.query(models.Scan).filter(models.Scan.id == self.scan_id).first()
        if not scan:
            raise ValueError(f"Scan {self.scan_id} not found")
        
        findings = self.db.query(models.Finding).filter(models.Finding.scan_id == self.scan_id).all()
        
        # Count vulnerabilities by severity
        severity_counts = self.db.query(
            models.Finding.severity,
            func.count(models.Finding.id)
        ).filter(models.Finding.scan_id == self.scan_id).group_by(models.Finding.severity).all()
        
        severity_dict = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
        for severity, count in severity_counts:
            severity_dict[severity] = count
        
        # Create PDF
        doc = SimpleDocTemplate(
            output_path, 
            pagesize=letter,
            topMargin=0.5*inch, 
            bottomMargin=0.5*inch,
            leftMargin=0.5*inch,
            rightMargin=0.5*inch
        )
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2563eb'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph("SecureCodeX Security Scan Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Project Information
        story.append(Paragraph("Project Information", heading_style))
        
        duration = "N/A"
        if scan.start_time and scan.end_time:
            duration = f"{(scan.end_time - scan.start_time).total_seconds():.2f}s"
        
        project_data = [
            ["Project Name:", Paragraph(html.escape(scan.project_name), styles['Normal'])],
            ["Scan Date:", scan.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan.start_time else "N/A"],
            ["Scan Path:", Paragraph(html.escape(scan.scan_path), styles['Normal'])],
            ["Status:", scan.status],
            ["Total Files:", str(scan.total_files)],
            ["Lines of Code:", f"{scan.total_loc:,}"],
            ["Languages:", Paragraph(html.escape(scan.languages or "N/A"), styles['Normal'])],
            ["Scan Duration:", duration],
        ]
        
        project_table = Table(project_data, colWidths=[2.0*inch, 5.5*inch])
        project_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(project_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Vulnerability Summary
        story.append(Paragraph("Vulnerability Summary", heading_style))
        vuln_data = [
            ["Severity", "Count"],
            ["Critical", str(severity_dict["CRITICAL"])],
            ["High", str(severity_dict["HIGH"])],
            ["Medium", str(severity_dict["MEDIUM"])],
            ["Low", str(severity_dict["LOW"])],
            ["Info", str(severity_dict["INFO"])],
            ["Total", str(len(findings))],
        ]
        
        vuln_table = Table(vuln_data, colWidths=[3.75*inch, 3.75*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#f3f4f6')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", heading_style))
        if findings:
            # Group findings by severity
            findings_by_severity = {
                'CRITICAL': [],
                'HIGH': [],
                'MEDIUM': [],
                'LOW': [],
                'INFO': []
            }
            
            for finding in findings:
                severity = finding.severity
                if severity in findings_by_severity:
                    findings_by_severity[severity].append(finding)
            
            # Add findings for each severity level
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                sev_findings = findings_by_severity[severity]
                if sev_findings:
                    story.append(Paragraph(f"{severity} Severity ({len(sev_findings)} findings)", styles['Heading3']))
                    
                    # New Columns: Finding, File Path, Line, Remediation, Standards
                    findings_data = [["Finding Details", "Location / Method", "Code & Security Examples", "Standards"]]
                    for finding in sev_findings[:50]:  # Limit to 50 per severity
                        file_display = finding.file_path
                        if scan.scan_path and finding.file_path.startswith(scan.scan_path):
                            file_display = os.path.relpath(finding.file_path, scan.scan_path)
                        
                        # Confidence string
                        conf_label = f" (Confidence: {finding.confidence_score:.0f}%)" if finding.confidence_score else ""
                        
                        # Formatted Standards
                        standards = []
                        if finding.owasp_id: standards.append(f"OWASP: {finding.owasp_id}")
                        if finding.cwe_id: standards.append(f"{finding.cwe_id}")
                        # Filter to most relevant standards for space
                        standards_text = "\n".join(standards[:3]) if standards else "N/A"

                        # Examples
                        v_ex = finding.vulnerable_example if finding.vulnerable_example and finding.vulnerable_example != 'N/A' else None
                        s_ex = finding.secure_example if finding.secure_example and finding.secure_example != 'N/A' else None
                        
                        snippet = html.escape(finding.code_snippet[:150]) if finding.code_snippet else "N/A"
                        
                        # Col 1: Name, Conf, Remediation, Fix
                        col1_html = f"<b>{html.escape(finding.name)}</b><font color='grey'>{conf_label}</font><br/><br/>"
                        col1_html += f"<i>Remediation:</i> {html.escape(finding.remediation or 'N/A')}<br/><br/>"
                        if finding.auto_fix and finding.auto_fix != 'N/A':
                            col1_html += f"<b>Auto-fix:</b> {html.escape(finding.auto_fix)}"
                        
                        # Col 2: Location, Method
                        col2_html = f"{html.escape(file_display)}<br/>Line: {finding.line_number}<br/><br/>"
                        col2_html += f"<i>Method: {finding.detection_method or 'Pattern'}</i>"
                        
                        # Col 3: Snippet compare
                        col3_html = f"<b>Matched Code:</b><br/><font face='Courier' size='7'>{snippet}</font><br/><br/>"
                        if s_ex:
                            col3_html += f"<b>Secure Example:</b><br/><font face='Courier' size='7' color='green'>{html.escape(s_ex[:150])}</font>"

                        findings_data.append([
                            Paragraph(col1_html, styles['Normal']),
                            Paragraph(col2_html, styles['Normal']),
                            Paragraph(col3_html, styles['Normal']),
                            Paragraph(standards_text, styles['Normal'])
                        ])
                    
                    # Column Widths Adjusted for V2 metadata
                    findings_table = Table(findings_data, colWidths=[2.8*inch, 1.5*inch, 2.2*inch, 1.0*inch])
                    findings_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(findings_table)
                    story.append(Spacer(1, 0.2*inch))
                    
                    if len(sev_findings) > 50:
                        story.append(Paragraph(f"... and {len(sev_findings) - 50} more {severity} findings", styles['Italic']))
                        story.append(Spacer(1, 0.2*inch))
        else:
            story.append(Paragraph("No vulnerabilities found. ✓", styles['Normal']))
            
        story.append(PageBreak())
        
        # SBOM Section
        story.append(Paragraph("Software Bill of Materials (SBOM)", heading_style))
        story.append(Paragraph("The following third-party components were identified:", styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # We need to re-scan for dependencies to generate SBOM (or store it in DB).
        # For this implementation, we will perform a quick re-scan or assume it's passed.
        # Ideally, SBOM should be stored in the DB.
        # Since I didn't update the DB model for SBOM storage yet, I will use a placeholder or
        # trigger the dependency scanner if I can access the path. 
        # But report generator typically just reads from DB.
        
        # Check if we can scan on the fly for the report (if scan_path exists)
        if scan.scan_path and os.path.exists(scan.scan_path):
            from .detectors.dependency import DependencyDetector
            dep_detector = DependencyDetector()
            
            # Find dependency files
            dep_files = []
            for root, _, files in os.walk(scan.scan_path):
                for file in files:
                    if file.lower() in ["requirements.txt", "package.json", "pom.xml", "composer.json"]:
                        dep_files.append(os.path.join(root, file))
            
            sbom = dep_detector.generate_sbom(dep_files)
            
            sbom_data = [["Component", "Version", "Type", "PURL"]]
            for component in sbom.get("components", []):
                sbom_data.append([
                    component.get("name", "N/A"),
                    component.get("version", "N/A"),
                    component.get("type", "library"),
                    Paragraph(component.get("purl", "N/A"), styles['Normal'])
                ])
            
            if len(sbom_data) > 1:
                sbom_table = Table(sbom_data, colWidths=[2.0*inch, 1.0*inch, 1.0*inch, 3.5*inch])
                sbom_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#059669')), # Green for SBOM
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                story.append(sbom_table)
            else:
                story.append(Paragraph("No dependencies found.", styles['Normal']))
        else:
             story.append(Paragraph("Scan path not available for SBOM generation.", styles['Normal']))

        # Build PDF
        doc.build(story)
        
        return output_path
