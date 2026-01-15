import unittest
import os
import tempfile
import json
from vulnmng.core.models import Vulnerability, Severity
from vulnmng.plugins.issuers.json_file import JsonFileIssueManager

class TestAliasHandling(unittest.TestCase):
    def setUp(self):
        # Create a temporary file for testing
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.temp_file.close()
        self.issue_manager = JsonFileIssueManager(file_path=self.temp_file.name)
    
    def tearDown(self):
        # Clean up the temporary file
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_create_issue_with_cve_and_aliases(self):
        """Test creating an issue with CVE and aliases"""
        vuln = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target",
            aliases=["GHSA-xxxx-yyyy-zzzz", "CGA-1111-2222-3333"]
        )
        
        issue = self.issue_manager.create_issue(vuln)
        
        self.assertEqual(issue.cve_id, "CVE-2024-1111")
        self.assertEqual(len(issue.aliases), 2)
        self.assertIn("GHSA-xxxx-yyyy-zzzz", issue.aliases)
        self.assertIn("CGA-1111-2222-3333", issue.aliases)
    
    def test_create_issue_with_non_cve_id(self):
        """Test creating an issue with non-CVE primary ID"""
        vuln = Vulnerability(
            cve_id="GHSA-abcd-efgh-ijkl",
            package_name="test-pkg",
            version="2.0.0",
            target="test-target",
            aliases=["CGA-9999-8888-7777"]
        )
        
        issue = self.issue_manager.create_issue(vuln)
        
        self.assertEqual(issue.cve_id, "GHSA-abcd-efgh-ijkl")
        self.assertEqual(len(issue.aliases), 1)
        self.assertIn("CGA-9999-8888-7777", issue.aliases)
    
    def test_cve_assignment_to_existing_non_cve_issue(self):
        """Test that when a CVE is assigned to an existing non-CVE issue, the issue is renamed"""
        # First, create an issue with non-CVE ID
        non_cve_vuln = Vulnerability(
            cve_id="GHSA-1234-5678-9012",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target",
            aliases=[]
        )
        
        first_issue = self.issue_manager.create_issue(non_cve_vuln)
        first_id = first_issue.id
        
        self.assertEqual(first_issue.cve_id, "GHSA-1234-5678-9012")
        self.assertEqual(len(first_issue.aliases), 0)
        
        # Save to persist
        self.issue_manager.save()
        
        # Now, create a vulnerability with CVE that has the GHSA in aliases
        cve_vuln = Vulnerability(
            cve_id="CVE-2024-9999",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target",
            aliases=["GHSA-1234-5678-9012", "CGA-4444-5555-6666"]
        )
        
        renamed_issue = self.issue_manager.create_issue(cve_vuln)
        
        # The issue should be renamed with CVE as primary ID
        self.assertEqual(renamed_issue.cve_id, "CVE-2024-9999")
        
        # The old GHSA ID should now be in aliases
        self.assertIn("GHSA-1234-5678-9012", renamed_issue.aliases)
        self.assertIn("CGA-4444-5555-6666", renamed_issue.aliases)
        
        # The old ID should no longer exist in the issues dict
        self.assertNotIn(first_id, self.issue_manager._issues)
        
        # The new ID should exist
        new_id = self.issue_manager._generate_id("CVE-2024-9999", "test-target")
        self.assertIn(new_id, self.issue_manager._issues)
    
    def test_migration_adds_aliases_field(self):
        """Test that loading old issues.json without aliases field adds empty aliases"""
        # Create an old-format issue (no aliases)
        old_data = {
            "scans": [],
            "issues": [
                {
                    "id": "CVE-2023-1111::test-target",
                    "cve_id": "CVE-2023-1111",
                    "title": "CVE-2023-1111 - old-pkg",
                    "labels": ["status:new"],
                    "user_comment": None,
                    "created_at": "2024-01-01T00:00:00",
                    "updated_at": "2024-01-01T00:00:00",
                    "details": {},
                    "vulnerability": {
                        "cve_id": "CVE-2023-1111",
                        "package_name": "old-pkg",
                        "version": "1.0.0",
                        "severity": "Medium",
                        "target": "test-target"
                    }
                }
            ]
        }
        
        # Write old format to file
        with open(self.temp_file.name, 'w') as f:
            json.dump(old_data, f)
        
        # Load with new issue manager
        manager = JsonFileIssueManager(file_path=self.temp_file.name)
        
        # Check that aliases field was added
        issues = manager.get_all_issues()
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.aliases, [])
        self.assertEqual(issue.vulnerability.aliases, [])
    
    def test_multiple_cves_in_aliases(self):
        """Test handling when there are multiple CVEs (first one becomes primary)"""
        vuln = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target",
            aliases=["CVE-2024-2222", "GHSA-xxxx-yyyy-zzzz"]
        )
        
        issue = self.issue_manager.create_issue(vuln)
        
        self.assertEqual(issue.cve_id, "CVE-2024-1111")
        self.assertIn("CVE-2024-2222", issue.aliases)
        self.assertIn("GHSA-xxxx-yyyy-zzzz", issue.aliases)

if __name__ == '__main__':
    unittest.main()
