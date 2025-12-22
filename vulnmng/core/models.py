from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    UNKNOWN = "Unknown"
    NEGLIGIBLE = "Negligible"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class VulnerabilityStatus(str, Enum):
    NEW = "new"
    FALSE_POSITIVE = "false-positive"
    FIXED = "fixed"
    IGNORED = "ignored"
    TRIAGED = "triaged"

class Vulnerability(BaseModel):
    cve_id: str
    package_name: str
    version: str
    severity: Severity = Severity.UNKNOWN
    fix_version: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    location_id: Optional[str] = None # Identifying where it was found (e.g. path in image)
    target: str # The scan target (e.g. image name or repo path)
    
class ScanResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    tool_name: str
    vulnerabilities: List[Vulnerability] = []
    metadata: Dict[str, Any] = {}

class ScanMetadata(BaseModel):
    target: str
    last_scan: datetime
    tool: str
    vulnerability_count: int
    status: str # "clean", "vulnerable", "failed"

class Issue(BaseModel):
    id: Optional[str] = None # ID in the issue tracking system
    cve_id: str
    title: str
    status: VulnerabilityStatus = VulnerabilityStatus.NEW
    labels: List[str] = []
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    details: Dict[str, Any] = {}
    vulnerability: Vulnerability
