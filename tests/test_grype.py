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
