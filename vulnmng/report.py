import csv
import os
import sys
import logging
from typing import List
from datetime import datetime
from vulnmng.core.models import Issue, VulnerabilityStatus, ScanMetadata, Severity

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
            relevant_statuses = {"status:new", "status:triage", "status:triaged"}
            relevant_total = 0
            by_status = {}
            high_critical_total = 0
            high_critical_relevant = 0
            
            # Per-target statistics
            by_target = {}  # target -> {total: int, relevant: int, hc_relevant: int, hc_total: int}
            
            for i in self.issues:
                status = self._get_status_from_labels(i.labels)
                by_status[status] = by_status.get(status, 0) + 1
                is_relevant = status in relevant_statuses
                if is_relevant:
                    relevant_total += 1
                
                # Count High and Critical severity issues
                if i.vulnerability.severity in [Severity.HIGH, Severity.CRITICAL]:
                    high_critical_total += 1
                    # Count relevant (new, triage) H+C issues
                    if is_relevant:
                        high_critical_relevant += 1
                
                # Per-target statistics
                target = i.vulnerability.target
                if target not in by_target:
                    by_target[target] = {'total': 0, 'relevant': 0, 'hc_relevant': 0, 'hc_total': 0}
                
                by_target[target]['total'] += 1
                if is_relevant:
                    by_target[target]['relevant'] += 1
                if i.vulnerability.severity in [Severity.HIGH, Severity.CRITICAL]:
                    by_target[target]['hc_total'] += 1
                    if is_relevant:
                        by_target[target]['hc_relevant'] += 1
            
            f.write("## Summary\n")
            f.write(f"- Total Vulnerabilities (relevant/total): {relevant_total}/{total}\n")
            f.write(f"- High+Critical (relevant/total): {high_critical_relevant}/{high_critical_total}\n")
            f.write("\n")
            
            # Per-target summary table
            if by_target:
                f.write("**Per Target:**\n\n")
                f.write("| Target | H+C Relevant/Total | Vulnerabilities Relevant/Total |\n")
                f.write("|---|---|---|\n")
                for target, stats in sorted(by_target.items()):
                    f.write(f"| {target} | {stats['hc_relevant']}/{stats['hc_total']} | {stats['relevant']}/{stats['total']} |\n")
                f.write("\n")
            
            f.write("**By Status:**\n")
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
            f.write("| Target | Target Name | ID | Package | Version | Severity | CVSS | EPSS | Status | Fix Version | User Comment | Description | Additional Info |\n")
            f.write("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
            
            # Sort by status (new first), then Severity
            sorted_issues = sorted(self.issues, key=lambda x: (
                self._get_status_from_labels(x.labels) != VulnerabilityStatus.NEW.value,
                x.vulnerability.severity.value
            ))
            
            for issue in sorted_issues:
                v = issue.vulnerability
                status = self._get_status_from_labels(issue.labels)
                
                # Sanitize description and comment to prevent table breaks
                desc = (v.description or "").replace('\n', ' ').replace('\r', ' ')
                comment = (issue.user_comment or "").replace('\n', ' ').replace('\r', ' ')
                
                # Create link for CVE/GHSA
                cve_id_display = self._format_id_with_link(v.cve_id)
                
                # Create link for package with deps.dev
                package_display = self._format_package_with_link(v.package_name, v.version, v.ecosystem)
                
                # Format additional info for table
                additional_info = ""
                if issue.additional_info:
                    # Escape pipes and newlines in additional info to avoid breaking table
                    additional_info = issue.additional_info.replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
                
                # Format CVSS - show vector in code block if available, otherwise score
                cvss_display = "N/A"
                if v.cvss_vector:
                    cvss_display = f"`{v.cvss_vector}`"
                elif v.cvss_score:
                    cvss_display = str(v.cvss_score)
                
                # Format EPSS score
                epss_display = f"{v.epss_score:.2%}" if v.epss_score else "N/A"
                
                f.write(f"| {v.target} | {v.target_name or 'N/A'} | {cve_id_display} | {package_display} | {v.version} | {v.severity.value} | {cvss_display} | {epss_display} | {status} | {v.fix_version or 'N/A'} | {comment} | {desc} | {additional_info} |\n")
    
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
            
        fieldnames = ['target', 'target_name', 'cve_id', 'link', 'package_name', 'package_link', 'version', 'severity', 'cvss_score', 'cvss_vector', 'epss_score', 'status', 'fix_version', 'user_comment', 'description', 'additional_info']
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
                
                # Sanitize text fields to prevent issues
                description = (v.description or "").replace('\n', ' ').replace('\r', ' ')
                user_comment = (issue.user_comment or "").replace('\n', ' ').replace('\r', ' ')
                additional_info = (issue.additional_info or "").replace('\n', ' ').replace('\r', ' ')
                
                writer.writerow({
                    'target': v.target,
                    'target_name': v.target_name or '',
                    'cve_id': v.cve_id,
                    'link': link,
                    'package_name': v.package_name,
                    'package_link': package_link,
                    'version': v.version,
                    'severity': v.severity.value,
                    'cvss_score': v.cvss_score,
                    'cvss_vector': v.cvss_vector or '',
                    'epss_score': v.epss_score,
                    'status': status,
                    'fix_version': v.fix_version,
                    'user_comment': user_comment,
                    'description': description,
                    'additional_info': additional_info
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
