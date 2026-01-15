import requests
import logging
from typing import Optional, Dict, Any
from vulnmng.core.interfaces import EnhancerBase
from vulnmng.core.models import Vulnerability

logger = logging.getLogger(__name__)

class CisaEnrichment(EnhancerBase):
    BASE_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self):
        self._kev_cache = None

    def _get_kev_data(self) -> Dict[str, Any]:
        """Fetch and cache CISA KEV catalog."""
        if self._kev_cache is not None:
            return self._kev_cache
        
        try:
            logger.debug(f"Fetching CISA KEV catalog from {self.KEV_URL}")
            response = requests.get(self.KEV_URL, timeout=10)
            if response.status_code == 200:
                self._kev_cache = response.json()
                return self._kev_cache
            else:
                logger.warning(f"Failed to fetch KEV catalog: {response.status_code}")
        except Exception as e:
            logger.error(f"Error fetching KEV catalog: {e}")
        
        return {}

    def enhance(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """Enhance a vulnerability and return the raw enrichment data."""
        cve_id = vulnerability.cve_id
        # Parse CVE ID: CVE-YYYY-NNNNN
        parts = cve_id.split("-")
        if len(parts) != 3:
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return {}
            
        year = parts[1]
        id_num = parts[2]
        
        # Determine folder: 
        # 4 digit: 1xxx for 1234
        # 5 digit: 12xxx for 12345
        if len(id_num) == 4:
            folder = f"{id_num[0]}xxx"
        elif len(id_num) >= 5:
            folder = f"{id_num[:-3]}xxx"
        else:
            folder = "xxxx" # Fallback, unlikely for valid CVEs
             
        url = f"{self.BASE_URL}/{year}/{folder}/{cve_id}.json"
        
        enrichment_data = {}
        try:
            logger.debug(f"Fetching enrichment for {cve_id} from {url}")
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                self._enrich_vulnerability(vulnerability, data)
                enrichment_data = data
            elif response.status_code == 404:
                logger.debug(f"No CISA enrichment found for {cve_id}")
            else:
                logger.warning(f"Failed to fetch CISA data: {response.status_code}")
        except Exception as e:
            logger.error(f"Error fetching CISA data: {e}")
        
        # Check KEV catalog
        kev_data = self._get_kev_data()
        kev_vulnerabilities = kev_data.get("vulnerabilities", [])
        kev_entry = next((v for v in kev_vulnerabilities if v.get("cveID") == cve_id), None)
        
        if kev_entry:
            enrichment_data["kev"] = kev_entry
            
        return enrichment_data

    def _enrich_vulnerability(self, vuln: Vulnerability, data: dict):
        cve_metadata = data.get("cveMetadata", {})
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        
        # Update description if missing or we want to append
        descriptions = cna.get("descriptions", [])
        if descriptions:
            # Look for english description
            desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
            if desc_text:
                if not vuln.description:
                    vuln.description = desc_text
                else:
                    # Maybe append if different? For now keeping original if present usually better from scanner
                    pass
        
        # Update metrics (CVSS/EPSS) if available and missing in vuln
        metrics = cna.get("metrics", [])
        if not vuln.cvss_score:
            for m in metrics:
                cvss_v3_1 = m.get("cvssV3_1", {})
                if cvss_v3_1:
                    vuln.cvss_score = cvss_v3_1.get("baseScore")
                    break
                     
        # SSVC / EPSS might be in other containers or 'adp'
        # Currently CISA vulnrichment mainly provides SSVC and other decision points in 'adp'
        adp = containers.get("adp", [])
        for entry in adp:
            # Check for EPSS or other metrics
            pass
            
        # TODO: Add more specific enrichment fields if needed (e.g. kev, ssvc)
    
    def format_summary(self, enrichment_data: dict) -> str:
        """Format CISA enrichment data into markdown summary."""
        if not enrichment_data:
            return ""
        
        summary_parts = []
        
        # Add title with link to CISA vulnrichment
        cve_id = enrichment_data.get("cveMetadata", {}).get("cveId")
        if cve_id:
            summary_parts.append(f"### [CISA Vulnrichment Data](https://github.com/cisagov/vulnrichment)")
        else:
            summary_parts.append("### CISA Vulnrichment Data")
        
        # KEV Information
        kev_entry = enrichment_data.get("kev")
        if kev_entry:
            summary_parts.append("\n**🚨 Known Exploited Vulnerability (KEV)**")
            summary_parts.append(f"- **Vulnerability Name:** {kev_entry.get('vulnerabilityName', 'N/A')}")
            summary_parts.append(f"- **Date Added to KEV:** {kev_entry.get('dateAdded', 'N/A')}")
            summary_parts.append(f"- **Due Date:** {kev_entry.get('dueDate', 'N/A')}")
            summary_parts.append(f"- **Required Action:** {kev_entry.get('requiredAction', 'N/A')}")
            if kev_entry.get('knownRansomwareCampaignUse') == 'Known':
                summary_parts.append("- **⚠️ Known Ransomware Campaign Use**")
        
        # CVSS Vectors and Exploitability
        containers = enrichment_data.get("containers", {})
        cna = containers.get("cna", {})
        metrics = cna.get("metrics", [])
        
        if metrics:
            summary_parts.append("\n**CVSS Information:**")
            for metric in metrics:
                cvss_v3_1 = metric.get("cvssV3_1", {})
                if cvss_v3_1:
                    vector_string = cvss_v3_1.get("vectorString", "N/A")
                    base_score = cvss_v3_1.get("baseScore", "N/A")
                    base_severity = cvss_v3_1.get("baseSeverity", "N/A")
                    summary_parts.append(f"- **CVSS v3.1:** {base_score} ({base_severity})")
                    summary_parts.append(f"  - Vector: `{vector_string}`")
                    
                    # Exploitability info from CVSS
                    exploit_code = cvss_v3_1.get("exploitCodeMaturity")
                    if exploit_code:
                        summary_parts.append(f"  - Exploit Code Maturity: {exploit_code}")
                
                cvss_v3_0 = metric.get("cvssV3_0", {})
                if cvss_v3_0:
                    vector_string = cvss_v3_0.get("vectorString", "N/A")
                    base_score = cvss_v3_0.get("baseScore", "N/A")
                    summary_parts.append(f"- **CVSS v3.0:** {base_score}")
                    summary_parts.append(f"  - Vector: `{vector_string}`")
                
                cvss_v2 = metric.get("cvssV2_0", {})
                if cvss_v2:
                    vector_string = cvss_v2.get("vectorString", "N/A")
                    base_score = cvss_v2.get("baseScore", "N/A")
                    summary_parts.append(f"- **CVSS v2.0:** {base_score}")
                    summary_parts.append(f"  - Vector: `{vector_string}`")
        
        # References and Exploits
        references = cna.get("references", [])
        exploit_refs = [ref for ref in references if any(tag in ref.get("tags", []) for tag in ["exploit", "Exploit"])]
        
        if exploit_refs:
            summary_parts.append("\n**Exploit References:**")
            for ref in exploit_refs:
                url = ref.get("url", "N/A")
                name = ref.get("name", url)
                summary_parts.append(f"- [{name}]({url})")
        
        # ADP information (additional analysis)
        adp_list = containers.get("adp", [])
        for adp in adp_list:
            provider_metadata = adp.get("providerMetadata", {})
            org_id = provider_metadata.get("orgId", "")
            
            # Check for SSVC decision points
            if "metrics" in adp:
                for adp_metric in adp.get("metrics", []):
                    ssvc = adp_metric.get("other", {})
                    if ssvc.get("type") == "ssvc":
                        summary_parts.append("\n**SSVC Decision Points:**")
                        content = ssvc.get("content", {})
                        for key, value in content.items():
                            if isinstance(value, dict):
                                for sub_key, sub_value in value.items():
                                    summary_parts.append(f"- {sub_key}: {sub_value}")
                            else:
                                summary_parts.append(f"- {key}: {value}")
        
        return "\n".join(summary_parts) if summary_parts else ""
