from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, index=True)
    scan_path = Column(String)
    status = Column(String, default=ScanStatus.PENDING.value)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    total_files = Column(Integer, default=0)
    total_loc = Column(Integer, default=0)
    languages = Column(String, default="")
    current_file = Column(String, nullable=True)
    scanned_loc = Column(Integer, default=0)
    
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    rule_id = Column(String, index=True)
    name = Column(String)
    description = Column(Text)
    severity = Column(String)
    file_path = Column(String)
    line_number = Column(Integer)
    code_snippet = Column(Text)
    cwe_id = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    
    scan = relationship("Scan", back_populates="findings")
    
    # Standard Controls
    owasp_id = Column(String, nullable=True)  # OWASP Top 10 (e.g., A01:2021)
    asvs_id = Column(String, nullable=True)   # OWASP ASVS (e.g., V5.1.1)
    mitre_id = Column(String, nullable=True)  # MITRE ATT&CK (e.g., T1190)
    nist_id = Column(String, nullable=True)   # NIST SSDF (e.g., PW.1.1)
    cve_id = Column(String, nullable=True)    # CVE ID (e.g., CVE-2021-44228)

    # Enhanced V2 fields - Confidence & Evidence
    confidence_score = Column(Integer, default=50)  # 0-100 scale (changed from Float)
    confidence_level = Column(String, default="MEDIUM")  # HIGH, MEDIUM, LOW
    detection_method = Column(String, default="Pattern")  # Pattern, AST, Taint
    secure_example = Column(Text, nullable=True)
    vulnerable_example = Column(Text, nullable=True)
    auto_fix = Column(Text, nullable=True)
    
    # High-Accuracy Detection fields
    evidence_trace = Column(Text, nullable=True)  # JSON string of source-sink-sanitizer trace
    sanitization_status = Column(String, nullable=True)  # MISSING, WEAK, BYPASSED, EFFECTIVE
    sanitization_explanation = Column(Text, nullable=True)
    framework_context = Column(String, nullable=True)  # Detected frameworks (comma-separated)
    vulnerability_type = Column(String, nullable=True)  # sql, xss, command, path, etc.
    is_reachable = Column(Integer, default=1)  # Boolean as integer (1=True, 0=False)
    is_test_code = Column(Integer, default=0)  # Boolean as integer
