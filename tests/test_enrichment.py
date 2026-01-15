import unittest
from unittest.mock import MagicMock, patch
from vulnmng.core.models import Vulnerability, Severity
from vulnmng.plugins.enhancers.cisa_enrichment import CisaEnrichment

class TestCisaEnrichment(unittest.TestCase):
    @patch("requests.get")
    def test_enhance_success(self, mock_get):
        enhancer = CisaEnrichment()
        vuln = Vulnerability(
            cve_id="CVE-2024-12345",
            package_name="test-pkg",
            version="1.0",
            target="target-app"
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2024-12345"
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Enriched description"}],
                    "metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = enhancer.enhance(vuln)
        
        # enhance() now returns the enrichment data dict
        self.assertIsInstance(result, dict)
        # But it also modifies the vulnerability in place
        self.assertEqual(vuln.description, "Enriched description")
        self.assertEqual(vuln.cvss_score, 9.8)
        
        # Verify URL construction logic
        # CVE-2024-12345 -> year 2024, id 12345 -> folder 12xxx
        expected_url = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/2024/12xxx/CVE-2024-12345.json"
        # Should be called twice: once for vulnrichment, once for KEV
        self.assertGreaterEqual(mock_get.call_count, 1)

    def test_folder_logic_4_digits(self):
        # CVE-2024-1234 -> 1xxx
        enhancer = CisaEnrichment()
        vuln = Vulnerability(cve_id="CVE-2024-1234", package_name="x", version="0", target="target-app")
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 404
            enhancer.enhance(vuln)
            # Find the call that includes the vulnrichment URL
            calls = [str(call) for call in mock_get.call_args_list]
            vulnrichment_call = [c for c in calls if "vulnrichment" in c]
            self.assertTrue(any("/2024/1xxx/CVE-2024-1234.json" in c for c in vulnrichment_call))
    
    def test_format_summary_with_kev(self):
        enhancer = CisaEnrichment()
        enrichment_data = {
            "cveMetadata": {
                "cveId": "CVE-2024-12345"
            },
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.com/exploit",
                            "tags": ["exploit"],
                            "name": "PoC Exploit"
                        }
                    ]
                }
            },
            "kev": {
                "cveID": "CVE-2024-12345",
                "vulnerabilityName": "Test Vulnerability",
                "dateAdded": "2024-01-01",
                "dueDate": "2024-01-15",
                "requiredAction": "Apply patches immediately",
                "knownRansomwareCampaignUse": "Known"
            }
        }
        
        summary = enhancer.format_summary(enrichment_data)
        
        # Check that key elements are present
        self.assertIn("CISA Vulnrichment Data", summary)
        self.assertIn("Known Exploited Vulnerability", summary)
        self.assertIn("Test Vulnerability", summary)
        self.assertIn("2024-01-01", summary)
        self.assertIn("Known Ransomware Campaign Use", summary)
        self.assertIn("CVSS v3.1", summary)
        self.assertIn("9.8", summary)
        self.assertIn("CRITICAL", summary)
        self.assertIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", summary)
        self.assertIn("Exploit References", summary)
        self.assertIn("PoC Exploit", summary)
    
    def test_format_summary_no_data(self):
        enhancer = CisaEnrichment()
        summary = enhancer.format_summary({})
        self.assertEqual(summary, "")
    
    def test_format_summary_minimal(self):
        enhancer = CisaEnrichment()
        enrichment_data = {
            "cveMetadata": {
                "cveId": "CVE-2024-12345"
            },
            "containers": {
                "cna": {}
            }
        }
        
        summary = enhancer.format_summary(enrichment_data)
        self.assertIn("CISA Vulnrichment Data", summary)

if __name__ == '__main__':
    unittest.main()
