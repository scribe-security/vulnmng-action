import csv
import os
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
            f.write("| Target | Target Name | ID | Package | Version | Severity | Status | Fix Version | User Comment | Description | Additional Info |\n")
            f.write("|---|---|---|---|---|---|---|---|---|---|---|\n")
            
            # Sort by status (new first), then Severity
            sorted_issues = sorted(self.issues, key=lambda x: (
                self._get_status_from_labels(x.labels) != VulnerabilityStatus.NEW.value,
                x.vulnerability.severity.value
            ))
            
            for issue in sorted_issues:
                v = issue.vulnerability
                status = self._get_status_from_labels(issue.labels)
                desc = v.description or ""
                comment = issue.user_comment or ""
                
                # Create link for CVE/GHSA
                cve_id_display = self._format_id_with_link(v.cve_id)
                
                # Create link for package with deps.dev
                package_display = self._format_package_with_link(v.package_name, v.version, v.ecosystem)
                
                # Format additional info for table
                additional_info = ""
                if issue.additional_info:
                    # Escape pipes in additional info to avoid breaking table
                    additional_info = issue.additional_info.replace('|', '\\|').replace('\n', ' ')
                
                f.write(f"| {v.target} | {v.target_name or 'N/A'} | {cve_id_display} | {package_display} | {v.version} | {v.severity.value} | {status} | {v.fix_version or 'N/A'} | {comment} | {desc} | {additional_info} |\n")
    
    def _format_id_with_link(self, cve_id: str) -> str:
        """Format CVE/GHSA ID with appropriate link."""
        if cve_id.startswith("CVE-"):
            # Link to NVD
            return f"[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})"
        elif cve_id.startswith("GHSA-"):
            # Link to GitHub Advisory
            return f"[{cve_id}](https://github.com/advisories/{cve_id})"
        else:
            # No link for other types
            return cve_id
    
    def _format_package_with_link(self, package_name: str, version: str, ecosystem: str = None) -> str:
        """Format package name with link to deps.dev if ecosystem is known."""
        if not ecosystem:
            return package_name
        
        # Map grype ecosystem names to deps.dev format
        ecosystem_map = {
            'npm': 'npm',
            'python': 'pypi',
            'gem': 'gem',
            'java-archive': 'maven',
            'go-module': 'go',
            'apk': 'alpine',
            'deb': 'debian',
            'rpm': 'rpm',
        }
        
        deps_ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem.lower())
        
        # deps.dev URL format: https://deps.dev/{ecosystem}/{package}/{version}
        # For some ecosystems, we need special handling
        if deps_ecosystem in ['npm', 'pypi', 'gem', 'maven', 'go']:
            # URL encode package name for special characters
            import urllib.parse
            encoded_package = urllib.parse.quote(package_name, safe='')
            deps_url = f"https://deps.dev/{deps_ecosystem}/{encoded_package}/{version}"
            return f"[{package_name}]({deps_url})"
        
        # For other ecosystems, just return the package name without link
        return package_name

    def generate_csv(self, output_path: str = "report.csv"):
        # Ensure directory exists
        dir_path = os.path.dirname(output_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
            
        fieldnames = ['target', 'target_name', 'cve_id', 'link', 'package_name', 'package_link', 'version', 'severity', 'status', 'fix_version', 'cvss_score', 'user_comment', 'description', 'additional_info']
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for issue in self.issues:
                v = issue.vulnerability
                status = self._get_status_from_labels(issue.labels)
                
                # Generate link for CVE/GHSA
                link = self._get_id_link(v.cve_id)
                
                # Generate link for package
                package_link = self._get_package_link(v.package_name, v.version, v.ecosystem)
                
                writer.writerow({
                    'target': v.target,
                    'target_name': v.target_name or '',
                    'cve_id': v.cve_id,
                    'link': link,
                    'package_name': v.package_name,
                    'package_link': package_link,
                    'version': v.version,
                    'severity': v.severity.value,
                    'status': status,
                    'fix_version': v.fix_version,
                    'cvss_score': v.cvss_score,
                    'user_comment': issue.user_comment or '',
                    'description': v.description,
                    'additional_info': issue.additional_info or ''
                })
    
    def _get_id_link(self, cve_id: str) -> str:
        """Get the full URL for CVE/GHSA ID."""
        if cve_id.startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        elif cve_id.startswith("GHSA-"):
            return f"https://github.com/advisories/{cve_id}"
        else:
            return ""
    
    def _get_package_link(self, package_name: str, version: str, ecosystem: str = None) -> str:
        """Get the full URL for package on deps.dev."""
        if not ecosystem:
            return ""
        
        # Map grype ecosystem names to deps.dev format
        ecosystem_map = {
            'npm': 'npm',
            'python': 'pypi',
            'gem': 'gem',
            'java-archive': 'maven',
            'go-module': 'go',
            'apk': 'alpine',
            'deb': 'debian',
            'rpm': 'rpm',
        }
        
        deps_ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem.lower())
        
        # deps.dev URL format: https://deps.dev/{ecosystem}/{package}/{version}
        if deps_ecosystem in ['npm', 'pypi', 'gem', 'maven', 'go']:
            import urllib.parse
            encoded_package = urllib.parse.quote(package_name, safe='')
            return f"https://deps.dev/{deps_ecosystem}/{encoded_package}/{version}"
        
        return ""
