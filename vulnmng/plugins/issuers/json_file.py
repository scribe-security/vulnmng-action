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
    
    def _get_status_from_labels(self, labels: List[str]) -> Optional[str]:
        """Extract status from labels. Returns the status:* label or None."""
        status_labels = [l for l in labels if l.startswith("status:")]
        if len(status_labels) > 1:
            logger.error(f"Multiple status labels found: {status_labels}. Issue has invalid state.")
            raise ValueError(f"Multiple status labels found: {status_labels}")
        return status_labels[0] if status_labels else None
    
    def _ensure_single_status_label(self, labels: List[str], new_status: str) -> List[str]:
        """Remove any existing status:* labels and add the new one."""
        # Remove all status:* labels
        labels = [l for l in labels if not l.startswith("status:")]
        # Add new status
        labels.append(new_status)
        return labels

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
                    # Migration: if old schema has 'status' field, convert to label
                    if "status" in item:
                        old_status = item["status"]
                        # Remove status field
                        del item["status"]
                        # Ensure status is in labels with new format
                        if "labels" not in item:
                            item["labels"] = []
                        if not any(l.startswith("status:") for l in item["labels"]):
                            # Convert old status to new label format
                            if old_status in ["new", "false-positive", "fixed", "ignored", "triaged", "not-exploitable"]:
                                item["labels"].append(f"status:{old_status}")
                            else:
                                item["labels"].append(VulnerabilityStatus.NEW.value)
                    
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
             # 1. Ensure status label exists
             if not self._get_status_from_labels(issue.labels):
                 issue.labels.append(VulnerabilityStatus.NEW.value)
             
             # 2. Overwrite details to remove stale/duplicate data
             if details:
                 issue.details = details
             
             return issue
        
        # Create new issue with status:new label
        initial_labels = [VulnerabilityStatus.NEW.value]
             
        issue = Issue(
            id=unique_id,
            cve_id=vulnerability.cve_id,
            title=f"{vulnerability.cve_id} - {vulnerability.package_name}",
            vulnerability=vulnerability,
            labels=initial_labels,
            details=details
        )
        self._issues[unique_id] = issue
        return issue
        
    def record_scan(self, target: str, tool: str, vulnerability_count: int, target_name: Optional[str] = None):
        status = "clean" if vulnerability_count == 0 else "vulnerable"
        self._scans[target] = ScanMetadata(
            target=target,
            target_name=target_name,
            last_scan=datetime.now(),
            tool=tool,
            vulnerability_count=vulnerability_count,
            status=status
        )

    def update_issue_status(self, issue_id: str, new_status: str, comment: Optional[str] = None) -> Issue:
        """Update issue status via labels. new_status should be in format 'status:*'."""
        if issue_id not in self._issues:
            raise ValueError(f"Issue {issue_id} not found")
        
        issue = self._issues[issue_id]
        
        # Validate new_status format
        if not new_status.startswith("status:"):
            raise ValueError(f"Status must be in format 'status:*', got: {new_status}")
        
        # Validate it's a known status
        valid_statuses = [s.value for s in VulnerabilityStatus]
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}. Valid: {valid_statuses}")
        
        # Update labels
        issue.labels = self._ensure_single_status_label(issue.labels, new_status)
        issue.updated_at = datetime.now()
        
        # Update comment if provided
        if comment:
            issue.user_comment = comment
        
        return issue
        
    def get_all_issues(self) -> List[Issue]:
        return list(self._issues.values())

    def get_scans(self) -> List[ScanMetadata]:
        return list(self._scans.values())
