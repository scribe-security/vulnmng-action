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
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Enriched description"}],
                    "metrics": [{"cvssV3_1": {"baseScore": 9.8}}]
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = enhancer.enhance(vuln)
        
        # Should populate description and score
        self.assertEqual(result.description, "Enriched description")
        self.assertEqual(result.cvss_score, 9.8)
        
        # Verify URL construction logic
        # CVE-2024-12345 -> year 2024, id 12345 -> folder 12xxx
        expected_url = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/2024/12xxx/CVE-2024-12345.json"
        mock_get.assert_called_with(expected_url, timeout=5)

    def test_folder_logic_4_digits(self):
        # CVE-2024-1234 -> 1xxx
        enhancer = CisaEnrichment()
        vuln = Vulnerability(cve_id="CVE-2024-1234", package_name="x", version="0", target="target-app")
        with patch("requests.get") as mock_get:
            enhancer.enhance(vuln)
            args, _ = mock_get.call_args
            self.assertIn("/2024/1xxx/CVE-2024-1234.json", args[0])

if __name__ == '__main__':
    unittest.main()
