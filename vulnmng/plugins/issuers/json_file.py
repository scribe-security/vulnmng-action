import json
import os
import logging
from typing import List, Optional, Dict
from datetime import datetime
from vulnmng.core.interfaces import IssueManagerBase
from vulnmng.core.models import Issue, Vulnerability, VulnerabilityStatus, ScanMetadata

logger = logging.getLogger(__name__)

class JsonFileIssueManager(IssueManagerBase):
    def __init__(self, file_path: str = "issues.json"):
        self.file_path = file_path
        self._issues: Dict[str, Issue] = {}
        self._scans: Dict[str, ScanMetadata] = {}
        self._load()

    def _generate_id(self, cve_id: str, target: str) -> str:
        # Simple unique ID generation
        return f"{cve_id}::{target}"

    def _load(self):
        self._issues = {}
        self._scans = {}
        if not os.path.exists(self.file_path):
            return
        
        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)
                
                # Handle migration from list (old schema) to dict (new schema)
                if isinstance(data, list):
                    issues_list = data
                    scans_list = []
                else:
                    issues_list = data.get("issues", [])
                    # Scans can be list or dict in storage? generic dict easier
                    # Let's say storage is list for readability, but in-memory is dict
                    scans_list = data.get("scans", [])

                for item in issues_list:
                    issue = Issue(**item)
                    key = issue.id if issue.id else self._generate_id(issue.vulnerability.cve_id, issue.vulnerability.target)
                    self._issues[key] = issue
                    
                for item in scans_list:
                    scan = ScanMetadata(**item)
                    self._scans[scan.target] = scan

        except Exception as e:
            logger.error(f"Failed to load issues from {self.file_path}: {e}")
            self._issues = {}
            self._scans = {}

    def save(self):
        try:
            data = {
                "scans": [s.model_dump(mode='json') for s in self._scans.values()],
                "issues": [i.model_dump(mode='json') for i in self._issues.values()]
            }
            with open(self.file_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved issues to {self.file_path}")
        except Exception as e:
            logger.error(f"Failed to save issues to {self.file_path}: {e}")

    def get_issue(self, cve_id: str) -> Optional[Issue]:
        return self._issues.get(cve_id)

    def create_issue(self, vulnerability: Vulnerability, details: Dict = {}) -> Issue:
        unique_id = self._generate_id(vulnerability.cve_id, vulnerability.target)
        
        if unique_id in self._issues:
             issue = self._issues[unique_id]
             # Update logic for existing issue
             # 1. Sync labels: ensure status is present
             if issue.status.value not in issue.labels:
                 issue.labels.append(issue.status.value)
             
             # 2. Merge details (Overwrite to remove stale/duplicate data from previous schema)
             if details:
                 issue.details = details
             
             return issue
        
        # Ensure status is in labels
        initial_status = VulnerabilityStatus.NEW
        labels = [initial_status.value]
             
        issue = Issue(
            id=unique_id,
            cve_id=vulnerability.cve_id,
            title=f"{vulnerability.cve_id} - {vulnerability.package_name}",
            vulnerability=vulnerability,
            status=initial_status,
            labels=labels,
            details=details
        )
        self._issues[unique_id] = issue
        # self.save() # Optimization: Save only once at end
        return issue
        
    def record_scan(self, target: str, tool: str, vulnerability_count: int):
        status = "clean" if vulnerability_count == 0 else "vulnerable"
        self._scans[target] = ScanMetadata(
            target=target,
            last_scan=datetime.now(),
            tool=tool,
            vulnerability_count=vulnerability_count,
            status=status
        )

    def update_issue_status(self, issue_id: str, status: str) -> Issue:
        # Here issue_id is treated as cve_id for this simple manager
        if issue_id in self._issues:
            try:
                issue = self._issues[issue_id]
                old_status = issue.status
                new_status = VulnerabilityStatus(status)
                
                # Update Status
                issue.status = new_status
                issue.updated_at = datetime.now()
                
                # Update Labels: Remove old status label, add new one
                if old_status.value in issue.labels:
                    issue.labels.remove(old_status.value)
                if new_status.value not in issue.labels:
                    issue.labels.append(new_status.value)

                self._save()
                return issue
            except ValueError:
                logger.error(f"Invalid status: {status}")
                raise ValueError(f"Invalid status: {status}")
        raise ValueError(f"Issue {issue_id} not found")
        
    def get_all_issues(self) -> List[Issue]:
        return list(self._issues.values())

    def get_scans(self) -> List[ScanMetadata]:
        return list(self._scans.values())
