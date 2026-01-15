import unittest
import json
from unittest.mock import MagicMock, patch
from vulnmng.core.models import Severity, Vulnerability
from vulnmng.plugins.scanners.grype import GrypeScanner

class TestGrypeScanner(unittest.TestCase):
    def test_parse_grype_output(self):
        scanner = GrypeScanner()
        mock_data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-1234",
                        "severity": "Medium",
                        "description": "Test vuln",
                        "fix": {
                            "state": "fixed",
                            "versions": ["1.2.3"]
                        },
                        "cvss": [
                            {
                                "version": "3.1",
                                "metrics": {"baseScore": 5.5}
                            }
                        ]
                    },
                    "artifact": {
                        "name": "package-a",
                        "version": "1.0.0",
                        "locations": [{"path": "/usr/lib/package-a"}]
                    }
                }
            ]
        }
        
        vulns = scanner._parse_grype_output(mock_data, target="dummy_target")
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v.cve_id, "CVE-2023-1234")
        self.assertEqual(v.severity, Severity.MEDIUM)
        self.assertEqual(v.package_name, "package-a")
        self.assertEqual(v.version, "1.0.0")
        self.assertEqual(v.fix_version, "1.2.3")
        self.assertEqual(v.cvss_score, 5.5)
        self.assertEqual(v.location_id, "/usr/lib/package-a")
        self.assertEqual(v.target, "dummy_target") # Default target passed
        self.assertEqual(v.aliases, [])  # No aliases in this test

    def test_parse_grype_output_with_aliases(self):
        """Test that related vulnerabilities are extracted as aliases when CVE is present"""
        scanner = GrypeScanner()
        mock_data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-5678",
                        "severity": "High",
                        "description": "Test vuln with aliases",
                        "fix": {
                            "state": "fixed",
                            "versions": ["2.0.0"]
                        }
                    },
                    "relatedVulnerabilities": [
                        {"id": "GHSA-xxxx-yyyy-zzzz"},
                        {"id": "CGA-1234-5678-9012"}
                    ],
                    "artifact": {
                        "name": "package-b",
                        "version": "1.5.0",
                        "locations": [{"path": "/app/lib"}]
                    }
                }
            ]
        }
        
        vulns = scanner._parse_grype_output(mock_data, target="test_target")
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v.cve_id, "CVE-2023-5678")
        self.assertIn("GHSA-xxxx-yyyy-zzzz", v.aliases)
        self.assertIn("CGA-1234-5678-9012", v.aliases)
        self.assertEqual(len(v.aliases), 2)

    def test_parse_grype_output_non_cve_primary(self):
        """Test that non-CVE ID is used as primary when no CVE is present"""
        scanner = GrypeScanner()
        mock_data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "GHSA-abcd-efgh-ijkl",
                        "severity": "Low",
                        "description": "Non-CVE vuln"
                    },
                    "relatedVulnerabilities": [
                        {"id": "CGA-9999-8888-7777"}
                    ],
                    "artifact": {
                        "name": "package-c",
                        "version": "3.0.0",
                        "locations": [{"path": "/opt/app"}]
                    }
                }
            ]
        }
        
        vulns = scanner._parse_grype_output(mock_data, target="test_target")
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v.cve_id, "GHSA-abcd-efgh-ijkl")
        self.assertIn("CGA-9999-8888-7777", v.aliases)

    def test_parse_grype_output_cve_in_related(self):
        """Test that CVE in relatedVulnerabilities becomes primary ID"""
        scanner = GrypeScanner()
        mock_data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "GHSA-1111-2222-3333",
                        "severity": "Critical",
                        "description": "GHSA with CVE in related"
                    },
                    "relatedVulnerabilities": [
                        {"id": "CVE-2024-9999"},
                        {"id": "CGA-4444-5555-6666"}
                    ],
                    "artifact": {
                        "name": "package-d",
                        "version": "0.5.0",
                        "locations": []
                    }
                }
            ]
        }
        
        vulns = scanner._parse_grype_output(mock_data, target="test_target")
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v.cve_id, "CVE-2024-9999")  # CVE takes priority
        self.assertIn("GHSA-1111-2222-3333", v.aliases)
        self.assertIn("CGA-4444-5555-6666", v.aliases)

    @patch("subprocess.run")
    def test_scan_success(self, mock_run):
        scanner = GrypeScanner()
        mock_stdout = json.dumps({"matches": []})
        mock_run.return_value = MagicMock(stdout=mock_stdout, returncode=0)
        
        result = scanner.scan("dummy_target")
        self.assertEqual(len(result.vulnerabilities), 0)
        self.assertEqual(result.tool_name, "grype")

if __name__ == '__main__':
    unittest.main()
