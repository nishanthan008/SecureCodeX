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
        doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
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
            ["Project Name:", scan.project_name],
            ["Scan Date:", scan.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan.start_time else "N/A"],
            ["Scan Path:", scan.scan_path],
            ["Status:", scan.status],
            ["Total Files:", str(scan.total_files)],
            ["Lines of Code:", f"{scan.total_loc:,}"],
            ["Languages:", scan.languages or "N/A"],
            ["Scan Duration:", duration],
        ]
        
        project_table = Table(project_data, colWidths=[2*inch, 4*inch])
        project_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
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
        
        vuln_table = Table(vuln_data, colWidths=[3*inch, 3*inch])
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
                    
                    findings_data = [["Finding", "File Path", "Line", "Code Snippet"]]
                    for finding in sev_findings[:50]:  # Limit to 50 per severity to avoid huge PDFs
                        # Make file path relative if possible
                        file_display = finding.file_path
                        if scan.scan_path and finding.file_path.startswith(scan.scan_path):
                            file_display = os.path.relpath(finding.file_path, scan.scan_path)
                        
                        snippet = finding.code_snippet[:60] + "..." if finding.code_snippet and len(finding.code_snippet) > 60 else (finding.code_snippet or "N/A")
                        # Escape HTML to prevent PDF parsing errors
                        snippet = html.escape(snippet)
                        file_display = html.escape(file_display)
                        finding_name = html.escape(finding.name)
                        
                        findings_data.append([
                            Paragraph(finding_name, styles['Normal']),
                            Paragraph(file_display, styles['Normal']),
                            str(finding.line_number),
                            Paragraph(snippet, styles['Normal'])
                        ])
                    
                    findings_table = Table(findings_data, colWidths=[1.8*inch, 2.2*inch, 0.5*inch, 2*inch])
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
        
        # Build PDF
        doc.build(story)
        
        return output_path
