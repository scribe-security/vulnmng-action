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
    NEW = "status:new"
    FALSE_POSITIVE = "status:false-positive"
    NOT_EXPLOITABLE = "status:not-exploitable"
    FIXED = "status:fixed"
    IGNORED = "status:ignored"
    TRIAGED = "status:triaged"

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
    target_name: Optional[str] = None # Human readable identifier
    aliases: List[str] = Field(default_factory=list) # Related vulnerability IDs (e.g., GHSA, CGA when CVE is primary, or vice versa)
    ecosystem: Optional[str] = None # Package ecosystem (e.g., npm, pypi, go, maven)
    
class ScanResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    tool_name: str
    vulnerabilities: List[Vulnerability] = []
    target_name: Optional[str] = None
    metadata: Dict[str, Any] = {}

class ScanMetadata(BaseModel):
    target: str
    target_name: Optional[str] = None
    last_scan: datetime
    tool: str
    vulnerability_count: int
    status: str # "clean", "vulnerable", "failed"

class Issue(BaseModel):
    id: Optional[str] = None # ID in the issue tracking system
    cve_id: str
    title: str
    labels: List[str] = Field(default_factory=list)  # Includes status:* labels
    user_comment: Optional[str] = None  # User's explanation for status/triage
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    details: Dict[str, Any] = {}  # Enrichment data
    additional_info: Optional[str] = None  # Formatted markdown summary from enrichments
    vulnerability: Vulnerability
    aliases: List[str] = Field(default_factory=list) # Related vulnerability IDs (mirrors vulnerability.aliases for convenience)
