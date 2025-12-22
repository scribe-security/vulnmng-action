import unittest
import tempfile
import shutil
import os
import subprocess
import json
from pathlib import Path
from vulnmng.plugins.issuers.json_file import JsonFileIssueManager
from vulnmng.core.models import Vulnerability, Severity, ScanMetadata
from vulnmng.utils.git_integration import GitIntegration

class TestGitIntegration(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for the test repo
        self.test_dir = tempfile.mkdtemp()
        self.repo_path = os.path.join(self.test_dir, "test_repo")
        os.makedirs(self.repo_path)
        
        # Initialize a git repository
        subprocess.run(["git", "init"], cwd=self.repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.repo_path, check=True, capture_output=True)
        
        # Create an initial commit on main branch
        readme_path = os.path.join(self.repo_path, "README.md")
        with open(readme_path, 'w') as f:
            f.write("# Test Repository\n")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.repo_path, check=True, capture_output=True)

    def tearDown(self):
        # Clean up the temporary directory
        shutil.rmtree(self.test_dir)

    def test_store_and_retrieve_issues_from_branch(self):
        """Test storing issues.json in vulnmanage-data branch and retrieving it"""
        
        # 1. Create GitIntegration instance for vulnmanage-data branch
        git_integration = GitIntegration(repo_path=self.repo_path, branch="vulnmanage-data")
        
        # Verify it's a git repo
        self.assertTrue(git_integration.is_repo())
        
        # 2. Checkout/create the vulnmanage-data branch
        git_integration.checkout_branch()
        
        # Verify we're on the correct branch
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result.stdout.strip(), "vulnmanage-data")
        
        # 3. Create some test issues
        issues_path = os.path.join(self.repo_path, "issues.json")
        issue_manager = JsonFileIssueManager(file_path=issues_path)
        
        # Create test vulnerabilities
        vuln1 = Vulnerability(
            cve_id="CVE-2024-1234",
            package_name="test-package",
            version="1.0.0",
            severity=Severity.HIGH,
            target="test-target"
        )
        
        vuln2 = Vulnerability(
            cve_id="CVE-2024-5678",
            package_name="another-package",
            version="2.0.0",
            severity=Severity.MEDIUM,
            target="test-target"
        )
        
        # Create issues with enrichment details
        issue1 = issue_manager.create_issue(vuln1, details={"cisagov/vulnrichment": {"test": "data1"}})
        issue2 = issue_manager.create_issue(vuln2, details={"cisagov/vulnrichment": {"test": "data2"}})
        
        # Record scan metadata
        issue_manager.record_scan("test-target", "grype", 2)
        
        # Save issues
        issue_manager.save()
        
        # 4. Commit and verify the file exists
        git_integration.add(issues_path)
        git_integration.commit("Add vulnerability scan results")
        
        # Verify the file was committed
        result = subprocess.run(
            ["git", "log", "--oneline", "-1"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.assertIn("Add vulnerability scan results", result.stdout)
        
        # 5. Verify the content structure
        with open(issues_path, 'r') as f:
            data = json.load(f)
        
        self.assertIn("scans", data)
        self.assertIn("issues", data)
        self.assertEqual(len(data["scans"]), 1)
        self.assertEqual(len(data["issues"]), 2)
        
        # Verify scan metadata
        scan = data["scans"][0]
        self.assertEqual(scan["target"], "test-target")
        self.assertEqual(scan["tool"], "grype")
        self.assertEqual(scan["vulnerability_count"], 2)
        
        # Verify issue structure
        for issue in data["issues"]:
            self.assertIn("labels", issue)
            self.assertIn("new", issue["labels"])
            self.assertIn("details", issue)
            self.assertIn("cisagov/vulnrichment", issue["details"])
        
        # 6. Simulate retrieving from the branch (fresh clone scenario)
        # Delete the issues.json and reload from git
        os.remove(issues_path)
        self.assertFalse(os.path.exists(issues_path))
        
        # Checkout the file from git
        subprocess.run(
            ["git", "checkout", "vulnmanage-data", "--", "issues.json"],
            cwd=self.repo_path,
            check=True,
            capture_output=True
        )
        
        # 7. Load and verify the retrieved data
        issue_manager_retrieved = JsonFileIssueManager(file_path=issues_path)
        retrieved_issues = issue_manager_retrieved.get_all_issues()
        retrieved_scans = issue_manager_retrieved.get_scans()
        
        self.assertEqual(len(retrieved_issues), 2)
        self.assertEqual(len(retrieved_scans), 1)
        
        # Verify the issues have correct structure
        for issue in retrieved_issues:
            self.assertIn("new", issue.labels)
            self.assertIn("cisagov/vulnrichment", issue.details)
        
        # Verify scan metadata
        self.assertEqual(retrieved_scans[0].target, "test-target")
        self.assertEqual(retrieved_scans[0].vulnerability_count, 2)

    def test_branch_creation_and_switching(self):
        """Test that GitIntegration correctly creates and switches to vulnmanage-data branch"""
        
        git_integration = GitIntegration(repo_path=self.repo_path, branch="vulnmanage-data")
        
        # Initially on main branch
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result.stdout.strip(), "main")
        
        # Checkout the branch (should create it)
        git_integration.checkout_branch()
        
        # Verify we switched to vulnmanage-data
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result.stdout.strip(), "vulnmanage-data")
        
        # Verify the branch exists in branch list
        result = subprocess.run(
            ["git", "branch"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.assertIn("vulnmanage-data", result.stdout)

if __name__ == '__main__':
    unittest.main()
