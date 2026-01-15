import json
import os
import logging
from typing import List, Optional, Dict
from datetime import datetime, timezone
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
    
    def _find_issue_by_alias(self, vuln_id: str, target: str) -> Optional[Issue]:
        """
        Find an issue where the given vuln_id appears in the aliases list.
        This is used to detect when a CVE is assigned to an existing non-CVE issue.
        """
        for issue in self._issues.values():
            # Check if this issue is for the same target and has vuln_id in aliases
            if issue.vulnerability.target == target and vuln_id in issue.aliases:
                return issue
        return None
    
    def _find_issue_for_renaming(self, vulnerability: Vulnerability) -> Optional[Issue]:
        """
        Find an existing issue that should be renamed based on the new vulnerability.
        This happens when:
        1. The new vuln's primary ID is in an existing issue's aliases (reverse lookup)
        2. An existing issue's primary ID is in the new vuln's aliases (forward lookup)
        
        Only rename if the new ID is a CVE and the old one is not (CVE prioritization).
        """
        target = vulnerability.target
        new_id = vulnerability.cve_id
        new_is_cve = new_id.startswith("CVE-")
        
        # Check all existing issues for the same target
        for issue in self._issues.values():
            if issue.vulnerability.target != target:
                continue
            
            old_id = issue.cve_id
            old_is_cve = old_id.startswith("CVE-")
            
            # Only rename if we're upgrading from non-CVE to CVE
            if not new_is_cve or old_is_cve:
                continue
            
            # Scenario 1: Existing issue's primary ID is in new vulnerability's aliases
            if old_id in vulnerability.aliases:
                return issue
            
            # Scenario 2: New vulnerability's ID is in existing issue's aliases
            if new_id in issue.aliases:
                return issue
        
        return None

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
                    
                    # Migration: ensure aliases field exists
                    if "aliases" not in item:
                        item["aliases"] = []
                    if "vulnerability" in item and "aliases" not in item["vulnerability"]:
                        item["vulnerability"]["aliases"] = []
                    
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
            # Ensure directory exists
            dir_path = os.path.dirname(self.file_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
                
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
        
        # Check if this issue already exists by the current ID
        if unique_id in self._issues:
            issue = self._issues[unique_id]
            # Update logic for existing issue
            # 1. Ensure status label exists
            if not self._get_status_from_labels(issue.labels):
                issue.labels.append(VulnerabilityStatus.NEW.value)
            
            # 2. Overwrite details to remove stale/duplicate data
            if details:
                issue.details = details
            
            # 3. Update aliases if they changed
            issue.aliases = vulnerability.aliases.copy()
            issue.vulnerability.aliases = vulnerability.aliases.copy()
            
            return issue
        
        # Check if we need to rename an existing issue (CVE assignment case)
        # Two scenarios:
        # 1. An existing issue's primary ID is in the new vulnerability's aliases
        # 2. The new vulnerability's ID is in an existing issue's aliases
        existing_issue = self._find_issue_for_renaming(vulnerability)
        if existing_issue:
            # This is a CVE being assigned to an existing non-CVE issue
            # Rename: move old primary ID to aliases, use new CVE as primary
            old_id = existing_issue.cve_id
            logger.info(f"CVE {vulnerability.cve_id} assigned to existing issue {old_id}. Renaming issue.")
            
            # Remove old issue entry
            old_unique_id = existing_issue.id
            del self._issues[old_unique_id]
            
            # Update the issue with new primary ID
            existing_issue.cve_id = vulnerability.cve_id
            existing_issue.id = unique_id
            existing_issue.title = f"{vulnerability.cve_id} - {vulnerability.package_name}"
            
            # Update aliases: add old ID if not already there, and include new aliases
            new_aliases = vulnerability.aliases.copy()
            if old_id not in new_aliases:
                new_aliases.insert(0, old_id)  # Put old primary ID first
            existing_issue.aliases = new_aliases
            existing_issue.vulnerability = vulnerability
            existing_issue.vulnerability.aliases = new_aliases
            existing_issue.updated_at = datetime.now()
            
            # Store with new ID
            self._issues[unique_id] = existing_issue
            return existing_issue
        
        # Create new issue with status:new label
        initial_labels = [VulnerabilityStatus.NEW.value]
        
        issue = Issue(
            id=unique_id,
            cve_id=vulnerability.cve_id,
            title=f"{vulnerability.cve_id} - {vulnerability.package_name}",
            vulnerability=vulnerability,
            labels=initial_labels,
            details=details,
            aliases=vulnerability.aliases.copy()
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

    def mark_missing_vulnerabilities_as_fixed(self, target: str, scanned_cve_ids: List[str]) -> int:
        """
        Mark vulnerabilities as fixed if they don't appear in the current scan.
        
        Args:
            target: The scan target to check
            scanned_cve_ids: List of CVE IDs found in the current scan
            
        Returns:
            Number of issues marked as fixed
        """
        fixed_count = 0
        current_time = datetime.now(timezone.utc)
        date_str = current_time.strftime("%Y-%m-%d")
        
        for issue in self._issues.values():
            # Only process issues for the same target
            if issue.vulnerability.target != target:
                continue
            
            # Skip if this vulnerability was found in the current scan
            if issue.cve_id in scanned_cve_ids:
                continue
            
            # Get current status
            current_status = self._get_status_from_labels(issue.labels)
            
            # Skip if already marked as fixed or other excluded statuses
            excluded_statuses = {
                VulnerabilityStatus.FIXED.value,
                VulnerabilityStatus.IGNORED.value
            }
            if current_status in excluded_statuses:
                continue
            
            # Special handling for false-positive status
            if current_status == VulnerabilityStatus.FALSE_POSITIVE.value:
                # Prepend the message to existing user_comment
                prefix = f"CVE did not appear in scan since {date_str}. "
                if issue.user_comment:
                    issue.user_comment = prefix + issue.user_comment
                else:
                    issue.user_comment = prefix[:-2]  # Remove trailing '. '
            
            # Mark as fixed
            issue.labels = self._ensure_single_status_label(issue.labels, VulnerabilityStatus.FIXED.value)
            issue.updated_at = current_time
            fixed_count += 1
            logger.info(f"Marked {issue.cve_id} as fixed (not found in current scan)")
        
        return fixed_count

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
