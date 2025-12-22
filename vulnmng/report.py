import csv
from typing import List
from datetime import datetime
from vulnmng.core.models import Issue, VulnerabilityStatus, ScanMetadata

class ReportGenerator:
    def __init__(self, issues: List[Issue], scans: List[ScanMetadata] = []):
        self.issues = issues
        self.scans = scans

    def generate_markdown(self, output_path: str = "report.md"):
        with open(output_path, 'w') as f:
            f.write(f"# Vulnerability Scan Report\n")
            f.write(f"Generated at: {datetime.now().isoformat()}\n\n")
            
            # Summary
            total = len(self.issues)
            by_status = {}
            for i in self.issues:
                by_status[i.status] = by_status.get(i.status, 0) + 1
            
            f.write("## Summary\n")
            f.write(f"- Total Issues: {total}\n")
            for status, count in by_status.items():
                f.write(f"- {status.value}: {count}\n")
            f.write("\n")
            
            # Scans Table
            if self.scans:
                f.write("## Scans\n")
                f.write("| Target | Last Scan | Tool | Issues Found | Status |\n")
                f.write("|---|---|---|---|---|\n")
                for scan in self.scans:
                    f.write(f"| {scan.target} | {scan.last_scan.isoformat()} | {scan.tool} | {scan.vulnerability_count} | {scan.status} |\n")
                f.write("\n")
            
            # Table
            f.write("## Vulnerabilities\n")
            f.write("| Target | CVE ID | Package | Version | Severity | Status | Fix Version | Description |\n")
            f.write("|---|---|---|---|---|---|---|---|\n")
            
            # Sort by Open (New), then Severity (Critical -> Low)
            # Custom sort: New first, then by Severity enum logic needs care as it is string
            # Simplified sort for now
            sorted_issues = sorted(self.issues, key=lambda x: (x.status != VulnerabilityStatus.NEW, x.vulnerability.severity), reverse=False)
            
            for issue in sorted_issues:
                v = issue.vulnerability
                desc = (v.description[:100] + '...') if v.description and len(v.description) > 100 else v.description
                f.write(f"| {v.target} | {v.cve_id} | {v.package_name} | {v.version} | {v.severity.value} | {issue.status.value} | {v.fix_version or 'N/A'} | {desc} |\n")

    def generate_csv(self, output_path: str = "report.csv"):
        fieldnames = ['target', 'cve_id', 'package_name', 'version', 'severity', 'status', 'fix_version', 'cvss_score', 'description']
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for issue in self.issues:
                v = issue.vulnerability
                writer.writerow({
                    'target': v.target,
                    'cve_id': v.cve_id,
                    'package_name': v.package_name,
                    'version': v.version,
                    'severity': v.severity.value,
                    'status': issue.status.value,
                    'fix_version': v.fix_version,
                    'cvss_score': v.cvss_score,
                    'description': v.description
                })
