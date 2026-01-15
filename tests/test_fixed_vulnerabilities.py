import unittest
import os
import tempfile
import json
from datetime import datetime
from vulnmng.core.models import Vulnerability, Severity, VulnerabilityStatus
from vulnmng.plugins.issuers.json_file import JsonFileIssueManager


class TestFixedVulnerabilities(unittest.TestCase):
    def setUp(self):
        # Create a temporary file for testing
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.temp_file.close()
        self.issue_manager = JsonFileIssueManager(file_path=self.temp_file.name)
    
    def tearDown(self):
        # Clean up the temporary file
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_mark_missing_vulnerability_as_fixed(self):
        """Test that a vulnerability not in current scan is marked as fixed"""
        # Create initial vulnerability
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target",
            severity=Severity.HIGH
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        self.assertEqual(self._get_status(issue1), VulnerabilityStatus.NEW.value)
        
        # Scan again with a different vulnerability (CVE-2024-1111 is missing)
        scanned_cve_ids = ["CVE-2024-2222"]
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        self.assertEqual(fixed_count, 1)
        
        # Check that the issue is now marked as fixed
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertEqual(self._get_status(issue1_updated), VulnerabilityStatus.FIXED.value)
    
    def test_vulnerability_in_current_scan_not_marked_fixed(self):
        """Test that vulnerabilities found in current scan are not marked as fixed"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        
        # Scan again with the same vulnerability
        scanned_cve_ids = ["CVE-2024-1111"]
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        self.assertEqual(fixed_count, 0)
        
        # Status should still be NEW
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertEqual(self._get_status(issue1_updated), VulnerabilityStatus.NEW.value)
    
    def test_false_positive_gets_comment_prefix(self):
        """Test that false-positive status gets comment prefix when marked as fixed"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        
        # Mark it as false-positive with a comment
        issue1.labels = self.issue_manager._ensure_single_status_label(
            issue1.labels, 
            VulnerabilityStatus.FALSE_POSITIVE.value
        )
        issue1.user_comment = "This is not exploitable in our context"
        
        # Scan again without this vulnerability
        scanned_cve_ids = []
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        self.assertEqual(fixed_count, 1)
        
        # Check that the status is now fixed
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertEqual(self._get_status(issue1_updated), VulnerabilityStatus.FIXED.value)
        
        # Check that the comment has the prefix
        self.assertIsNotNone(issue1_updated.user_comment)
        self.assertIn("CVE did not appear in scan since", issue1_updated.user_comment)
        self.assertIn("This is not exploitable in our context", issue1_updated.user_comment)
    
    def test_false_positive_without_comment_gets_prefix(self):
        """Test that false-positive without existing comment gets prefix"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        
        # Mark it as false-positive without a comment
        issue1.labels = self.issue_manager._ensure_single_status_label(
            issue1.labels, 
            VulnerabilityStatus.FALSE_POSITIVE.value
        )
        
        # Scan again without this vulnerability
        scanned_cve_ids = []
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        self.assertEqual(fixed_count, 1)
        
        # Check that the comment has the prefix
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertIsNotNone(issue1_updated.user_comment)
        self.assertIn("CVE did not appear in scan since", issue1_updated.user_comment)
    
    def test_already_fixed_not_processed_again(self):
        """Test that already fixed vulnerabilities are not processed again"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        
        # Mark it as fixed
        issue1.labels = self.issue_manager._ensure_single_status_label(
            issue1.labels, 
            VulnerabilityStatus.FIXED.value
        )
        
        # Scan again without this vulnerability
        scanned_cve_ids = []
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        # Should not count as newly fixed
        self.assertEqual(fixed_count, 0)
    
    def test_ignored_status_not_changed_to_fixed(self):
        """Test that ignored vulnerabilities are not marked as fixed"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        
        # Mark it as ignored
        issue1.labels = self.issue_manager._ensure_single_status_label(
            issue1.labels, 
            VulnerabilityStatus.IGNORED.value
        )
        
        # Scan again without this vulnerability
        scanned_cve_ids = []
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        # Should not be marked as fixed
        self.assertEqual(fixed_count, 0)
        
        # Status should still be ignored
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertEqual(self._get_status(issue1_updated), VulnerabilityStatus.IGNORED.value)
    
    def test_different_targets_not_affected(self):
        """Test that only vulnerabilities for the specific target are marked as fixed"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="target-A"
        )
        
        vuln2 = Vulnerability(
            cve_id="CVE-2024-2222",
            package_name="test-pkg",
            version="1.0.0",
            target="target-B"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        issue2 = self.issue_manager.create_issue(vuln2)
        
        # Scan target-A without any vulnerabilities
        scanned_cve_ids = []
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("target-A", scanned_cve_ids)
        
        # Only one issue should be marked as fixed
        self.assertEqual(fixed_count, 1)
        
        # Check target-A issue is fixed
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertEqual(self._get_status(issue1_updated), VulnerabilityStatus.FIXED.value)
        
        # Check target-B issue is still new
        issue2_updated = self.issue_manager.get_issue(issue2.id)
        self.assertEqual(self._get_status(issue2_updated), VulnerabilityStatus.NEW.value)
    
    def test_multiple_vulnerabilities_marked_fixed(self):
        """Test that multiple missing vulnerabilities are all marked as fixed"""
        vulns = [
            Vulnerability(
                cve_id=f"CVE-2024-{i:04d}",
                package_name="test-pkg",
                version="1.0.0",
                target="test-target"
            )
            for i in range(1, 6)  # Create 5 vulnerabilities
        ]
        
        # Create all issues
        for vuln in vulns:
            self.issue_manager.create_issue(vuln)
        
        # Scan with only 2 vulnerabilities (3 are missing)
        scanned_cve_ids = ["CVE-2024-0001", "CVE-2024-0002"]
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        # 3 vulnerabilities should be marked as fixed
        self.assertEqual(fixed_count, 3)
    
    def test_triaged_status_marked_as_fixed(self):
        """Test that triaged vulnerabilities are marked as fixed when missing"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        
        # Mark it as triaged
        issue1.labels = self.issue_manager._ensure_single_status_label(
            issue1.labels, 
            VulnerabilityStatus.TRIAGED.value
        )
        
        # Scan again without this vulnerability
        scanned_cve_ids = []
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        self.assertEqual(fixed_count, 1)
        
        # Check that the status is now fixed
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertEqual(self._get_status(issue1_updated), VulnerabilityStatus.FIXED.value)
    
    def test_not_exploitable_status_marked_as_fixed(self):
        """Test that not-exploitable vulnerabilities are marked as fixed when missing"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1111",
            package_name="test-pkg",
            version="1.0.0",
            target="test-target"
        )
        
        issue1 = self.issue_manager.create_issue(vuln1)
        
        # Mark it as not-exploitable
        issue1.labels = self.issue_manager._ensure_single_status_label(
            issue1.labels, 
            VulnerabilityStatus.NOT_EXPLOITABLE.value
        )
        
        # Scan again without this vulnerability
        scanned_cve_ids = []
        
        fixed_count = self.issue_manager.mark_missing_vulnerabilities_as_fixed("test-target", scanned_cve_ids)
        
        self.assertEqual(fixed_count, 1)
        
        # Check that the status is now fixed
        issue1_updated = self.issue_manager.get_issue(issue1.id)
        self.assertEqual(self._get_status(issue1_updated), VulnerabilityStatus.FIXED.value)
    
    def _get_status(self, issue):
        """Helper method to get status from labels"""
        return self.issue_manager._get_status_from_labels(issue.labels)


if __name__ == '__main__':
    unittest.main()
