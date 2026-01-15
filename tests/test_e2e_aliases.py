#!/usr/bin/env python3
"""
End-to-end test for alias handling functionality.
This script simulates a complete workflow with non-CVE and CVE IDs.
"""

import os
import sys
import json
import tempfile
import shutil
from datetime import datetime

# Add the vulnmng module to the path - relative to this test file
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from vulnmng.core.models import Vulnerability, Severity
from vulnmng.plugins.issuers.json_file import JsonFileIssueManager
from vulnmng.plugins.scanners.grype import GrypeScanner

def test_e2e_alias_handling():
    print("=" * 80)
    print("E2E Test: Alias Handling and CVE Assignment")
    print("=" * 80)
    
    # Create a temporary directory for testing
    temp_dir = tempfile.mkdtemp()
    json_path = os.path.join(temp_dir, "test_issues.json")
    
    try:
        # Step 1: Create initial non-CVE vulnerability
        print("\n[Step 1] Creating initial vulnerability with GHSA ID...")
        issue_manager = JsonFileIssueManager(file_path=json_path)
        
        ghsa_vuln = Vulnerability(
            cve_id="GHSA-1234-5678-9012",
            package_name="test-package",
            version="1.0.0",
            severity=Severity.HIGH,
            target="test-image:latest",
            description="Test vulnerability with GHSA ID",
            aliases=["CGA-9999-8888-7777"]
        )
        
        issue1 = issue_manager.create_issue(ghsa_vuln)
        issue_manager.save()
        
        print(f"  ✓ Created issue with ID: {issue1.cve_id}")
        print(f"  ✓ Aliases: {issue1.aliases}")
        
        # Verify the saved data
        with open(json_path, 'r') as f:
            data = json.load(f)
        print(f"  ✓ Issues saved: {len(data['issues'])}")
        
        # Step 2: Simulate CVE assignment (new scan with CVE)
        print("\n[Step 2] Simulating CVE assignment to existing GHSA issue...")
        
        # Reload issue manager to simulate fresh start
        issue_manager2 = JsonFileIssueManager(file_path=json_path)
        
        cve_vuln = Vulnerability(
            cve_id="CVE-2024-9999",
            package_name="test-package",
            version="1.0.0",
            severity=Severity.HIGH,
            target="test-image:latest",
            description="Test vulnerability now has CVE",
            aliases=["GHSA-1234-5678-9012", "CGA-9999-8888-7777", "CGA-1111-2222-3333"]
        )
        
        issue2 = issue_manager2.create_issue(cve_vuln)
        issue_manager2.save()
        
        print(f"  ✓ Issue renamed to: {issue2.cve_id}")
        print(f"  ✓ Aliases now include old ID: {issue2.aliases}")
        
        # Verify GHSA ID is in aliases
        assert "GHSA-1234-5678-9012" in issue2.aliases, "Old GHSA ID should be in aliases!"
        
        # Verify only one issue exists
        all_issues = issue_manager2.get_all_issues()
        print(f"  ✓ Total issues: {len(all_issues)} (should be 1)")
        assert len(all_issues) == 1, "Should only have one issue!"
        
        # Step 3: Test scanner with related vulnerabilities
        print("\n[Step 3] Testing Grype scanner with related vulnerabilities...")
        
        scanner = GrypeScanner()
        mock_grype_data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "GHSA-abcd-efgh-ijkl",
                        "severity": "Medium",
                        "description": "Scanner found GHSA first",
                        "relatedVulnerabilities": [
                            {"id": "CVE-2024-5555"},
                            {"id": "CGA-6666-7777-8888"}
                        ]
                    },
                    "artifact": {
                        "name": "another-package",
                        "version": "2.0.0",
                        "locations": [{"path": "/app/lib"}]
                    }
                }
            ]
        }
        
        vulns = scanner._parse_grype_output(mock_grype_data, "test-image:v2")
        
        print(f"  ✓ Parsed {len(vulns)} vulnerabilities")
        print(f"  ✓ Primary ID: {vulns[0].cve_id} (should be CVE)")
        print(f"  ✓ Aliases: {vulns[0].aliases}")
        
        assert vulns[0].cve_id == "CVE-2024-5555", "CVE should be primary!"
        assert "GHSA-abcd-efgh-ijkl" in vulns[0].aliases, "GHSA should be in aliases!"
        assert "CGA-6666-7777-8888" in vulns[0].aliases, "CGA should be in aliases!"
        
        # Step 4: Test non-CVE only case
        print("\n[Step 4] Testing scanner with non-CVE IDs only...")
        
        non_cve_data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "GHSA-zzzz-yyyy-xxxx",
                        "severity": "Low",
                        "description": "Only GHSA available",
                        "relatedVulnerabilities": [
                            {"id": "CGA-1111-2222-3333"}
                        ]
                    },
                    "artifact": {
                        "name": "third-package",
                        "version": "3.0.0",
                        "locations": []
                    }
                }
            ]
        }
        
        vulns2 = scanner._parse_grype_output(non_cve_data, "test-image:v3")
        
        print(f"  ✓ Primary ID: {vulns2[0].cve_id} (should be GHSA)")
        print(f"  ✓ Aliases: {vulns2[0].aliases}")
        
        assert vulns2[0].cve_id == "GHSA-zzzz-yyyy-xxxx", "GHSA should be primary when no CVE!"
        assert "CGA-1111-2222-3333" in vulns2[0].aliases, "CGA should be in aliases!"
        
        print("\n" + "=" * 80)
        print("✓ All E2E tests passed!")
        print("=" * 80)
        
    finally:
        # Cleanup
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        print("\n✓ Cleanup completed")

if __name__ == "__main__":
    test_e2e_alias_handling()
