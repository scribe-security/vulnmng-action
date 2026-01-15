from abc import ABC, abstractmethod
from typing import List, Optional
from .models import ScanResult, Issue, Vulnerability

class ScannerBase(ABC):
    @abstractmethod
    def scan(self, target: str) -> ScanResult:
        """Run the scanner against a target (path or image name)."""
        pass

class IssueManagerBase(ABC):
    @abstractmethod
    def get_issue(self, cve_id: str) -> Optional[Issue]:
        """Retrieve an issue by CVE ID."""
        pass
        
    @abstractmethod
    def create_issue(self, vulnerability: Vulnerability) -> Issue:
        """Create a new issue from a vulnerability."""
        pass
        
    @abstractmethod
    def update_issue_status(self, issue_id: str, status: str) -> Issue:
        """Update the status of an issue."""
        pass
    
    @abstractmethod
    def get_all_issues(self) -> List[Issue]:
        """Retrieve all issues."""
        pass

    def save(self):
        """Persist changes to storage."""
        pass

class EnhancerBase(ABC):
    @abstractmethod
    def enhance(self, vulnerability: Vulnerability) -> dict:
        """Enhance a vulnerability with external data and return enrichment data."""
        pass
    
    @abstractmethod
    def format_summary(self, enrichment_data: dict) -> str:
        """Format enrichment data into a markdown summary for display.
        
        Args:
            enrichment_data: The raw enrichment data returned by enhance()
            
        Returns:
            A markdown-formatted string suitable for display in reports
        """
        pass
