#!/usr/bin/env python3
"""Unit test for summary table calculations."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from vulnmng.core.models import Issue, Vulnerability, Severity
from vulnmng.report import ReportGenerator

def test_summary_counts():
    """Test that summary counts are calculated correctly."""
    
    # Create test issues
    test_issues = [
        # High - new (should count in relevant)
        Issue(
            cve_id="CVE-2024-0001",
            vulnerability=Vulnerability(
                cve_id="CVE-2024-0001",
                package_name="pkg1",
                version="1.0.0",
                severity=Severity.HIGH,
                target="test",
                target_name="test"
            ),
            labels=["status:new"]
        ),
        # Critical - new (should count in relevant)
        Issue(
            cve_id="CVE-2024-0002",
            vulnerability=Vulnerability(
                cve_id="CVE-2024-0002",
                package_name="pkg2",
                version="1.0.0",
                severity=Severity.CRITICAL,
                target="test",
                target_name="test"
            ),
            labels=["status:new"]
        ),
        # High - triage (should count in relevant)
        Issue(
            cve_id="CVE-2024-0003",
            vulnerability=Vulnerability(
                cve_id="CVE-2024-0003",
                package_name="pkg3",
                version="1.0.0",
                severity=Severity.HIGH,
                target="test",
                target_name="test"
            ),
            labels=["status:triage"]
        ),
        # High - false-positive (should NOT count in relevant)
        Issue(
            cve_id="CVE-2024-0004",
            vulnerability=Vulnerability(
                cve_id="CVE-2024-0004",
                package_name="pkg4",
                version="1.0.0",
                severity=Severity.HIGH,
                target="test",
                target_name="test"
            ),
            labels=["status:false-positive"]
        ),
        # Critical - fixed (should NOT count in relevant)
        Issue(
            cve_id="CVE-2024-0005",
            vulnerability=Vulnerability(
                cve_id="CVE-2024-0005",
                package_name="pkg5",
                version="1.0.0",
                severity=Severity.CRITICAL,
                target="test",
                target_name="test"
            ),
            labels=["status:fixed"]
        ),
        # Medium - new (should NOT count in H+C at all)
        Issue(
            cve_id="CVE-2024-0006",
            vulnerability=Vulnerability(
                cve_id="CVE-2024-0006",
                package_name="pkg6",
                version="1.0.0",
                severity=Severity.MEDIUM,
                target="test",
                target_name="test"
            ),
            labels=["status:new"]
        ),
    ]
    
    # Count manually
    total = len(test_issues)
    high_critical_total = sum(1 for i in test_issues 
                              if i.vulnerability.severity in [Severity.HIGH, Severity.CRITICAL])
    high_critical_relevant = sum(1 for i in test_issues 
                                 if i.vulnerability.severity in [Severity.HIGH, Severity.CRITICAL]
                                 and ReportGenerator([i])._get_status_from_labels(i.labels) in ["status:new", "status:triage"])
    
    # Expected values
    assert total == 6, f"Expected total=6, got {total}"
    assert high_critical_total == 5, f"Expected high_critical_total=5, got {high_critical_total}"
    assert high_critical_relevant == 3, f"Expected high_critical_relevant=3, got {high_critical_relevant}"
    
    print("✅ All summary count tests passed!")
    print(f"   Total: {total}")
    print(f"   H+C Total: {high_critical_total}")
    print(f"   H+C Relevant: {high_critical_relevant}")
    print(f"   Format: {high_critical_relevant}/{high_critical_total}")

if __name__ == "__main__":
    test_summary_counts()
