import csv
import sys
import logging
from typing import List
from datetime import datetime
from vulnmng.core.models import Issue, VulnerabilityStatus, ScanMetadata

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, issues: List[Issue], scans: List[ScanMetadata] = []):
        self.issues = issues
        self.scans = scans
        self._validate_issues()
    
    def _get_status_from_labels(self, labels: List[str]) -> str:
        """Extract status from labels. Validates single status exists."""
        status_labels = [l for l in labels if l.startswith("status:")]
        if len(status_labels) == 0:
            return "status:unknown"
        if len(status_labels) > 1:
            logger.error(f"Multiple status labels found: {status_labels}")
            sys.exit(1)
        return status_labels[0]
    
    def _validate_issues(self):
        """Validate all issues have exactly one status label."""
        for issue in self.issues:
            self._get_status_from_labels(issue.labels)

    def generate_markdown(self, output_path: str = "report.md"):
        # Ensure directory exists
        dir_path = os.path.dirname(output_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
            
        with open(output_path, 'w') as f:
            f.write(f"# Vulnerability Scan Report\n")
            f.write(f"Generated at: {datetime.now().isoformat()}\n\n")
            
            # Summary
            total = len(self.issues)
            by_status = {}
            for i in self.issues:
                status = self._get_status_from_labels(i.labels)
                by_status[status] = by_status.get(status, 0) + 1
            
            f.write("## Summary\n")
            f.write(f"- Total Issues: {total}\n")
            for status, count in sorted(by_status.items()):
                f.write(f"- {status}: {count}\n")
            f.write("\n")
            
            # Scans Table
            if self.scans:
                f.write("## Scans\n")
                f.write("| Target | Target Name | Last Scan | Tool | Issues Found | Status |\n")
                f.write("|---|---|---|---|---|---|\n")
                for scan in self.scans:
                    f.write(f"| {scan.target} | {scan.target_name or 'N/A'} | {scan.last_scan.isoformat()} | {scan.tool} | {scan.vulnerability_count} | {scan.status} |\n")
                f.write("\n")
            
            # Table
            f.write("## Vulnerabilities\n")
            f.write("| Target | Target Name | CVE ID | Package | Version | Severity | Status | Fix Version | User Comment | Description |\n")
            f.write("|---|---|---|---|---|---|---|---|---|---|\n")
            
            # Sort by status (new first), then Severity
            sorted_issues = sorted(self.issues, key=lambda x: (
                self._get_status_from_labels(x.labels) != VulnerabilityStatus.NEW.value,
                x.vulnerability.severity.value
            ))
            
            for issue in sorted_issues:
                v = issue.vulnerability
                status = self._get_status_from_labels(issue.labels)
                desc = (v.description[:80] + '...') if v.description and len(v.description) > 80 else (v.description or "")
                comment = (issue.user_comment[:50] + '...') if issue.user_comment and len(issue.user_comment) > 50 else (issue.user_comment or "")
                f.write(f"| {v.target} | {v.target_name or 'N/A'} | {v.cve_id} | {v.package_name} | {v.version} | {v.severity.value} | {status} | {v.fix_version or 'N/A'} | {comment} | {desc} |\n")

    def generate_csv(self, output_path: str = "report.csv"):
        # Ensure directory exists
        dir_path = os.path.dirname(output_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
            
        fieldnames = ['target', 'target_name', 'cve_id', 'package_name', 'version', 'severity', 'status', 'fix_version', 'cvss_score', 'user_comment', 'description']
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for issue in self.issues:
                v = issue.vulnerability
                status = self._get_status_from_labels(issue.labels)
                writer.writerow({
                    'target': v.target,
                    'target_name': v.target_name or '',
                    'cve_id': v.cve_id,
                    'package_name': v.package_name,
                    'version': v.version,
                    'severity': v.severity.value,
                    'status': status,
                    'fix_version': v.fix_version,
                    'cvss_score': v.cvss_score,
                    'user_comment': issue.user_comment or '',
                    'description': v.description
                })
