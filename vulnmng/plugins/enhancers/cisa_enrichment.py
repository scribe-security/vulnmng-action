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
        """Format CISA enrichment data into compact text summary."""
        if not enrichment_data:
            return ""
        
        parts = []
        
        # KEV Information
        kev_entry = enrichment_data.get("kev")
        if kev_entry:
            kev_info = f"KEV: {kev_entry.get('vulnerabilityName', 'N/A')}"
            if kev_entry.get('knownRansomwareCampaignUse') == 'Known':
                kev_info += " (Ransomware)"
            parts.append(kev_info)
        
        # CVSS Vectors and Exploitability
        containers = enrichment_data.get("containers", {})
        cna = containers.get("cna", {})
        metrics = cna.get("metrics", [])
        
        cvss_parts = []
        for metric in metrics:
            cvss_v3_1 = metric.get("cvssV3_1", {})
            if cvss_v3_1:
                vector_string = cvss_v3_1.get("vectorString", "N/A")
                base_score = cvss_v3_1.get("baseScore", "N/A")
                base_severity = cvss_v3_1.get("baseSeverity", "N/A")
                cvss_parts.append(f"CVSS v3.1: {base_score} ({base_severity}) {vector_string}")
            
            cvss_v3_0 = metric.get("cvssV3_0", {})
            if cvss_v3_0:
                vector_string = cvss_v3_0.get("vectorString", "N/A")
                base_score = cvss_v3_0.get("baseScore", "N/A")
                cvss_parts.append(f"CVSS v3.0: {base_score} {vector_string}")
            
            cvss_v2 = metric.get("cvssV2_0", {})
            if cvss_v2:
                vector_string = cvss_v2.get("vectorString", "N/A")
                base_score = cvss_v2.get("baseScore", "N/A")
                cvss_parts.append(f"CVSS v2.0: {base_score} {vector_string}")
        
        if cvss_parts:
            parts.extend(cvss_parts)
        
        # References and Exploits
        references = cna.get("references", [])
        exploit_refs = [ref for ref in references if any(tag in ref.get("tags", []) for tag in ["exploit", "Exploit"])]
        
        if exploit_refs:
            exploit_count = len(exploit_refs)
            parts.append(f"Exploits: {exploit_count} available")
        
        # SSVC Decision Points
        adp_list = containers.get("adp", [])
        ssvc_parts = []
        for adp in adp_list:
            if "metrics" in adp:
                for adp_metric in adp.get("metrics", []):
                    ssvc = adp_metric.get("other", {})
                    if ssvc.get("type") == "ssvc":
                        content = ssvc.get("content", {})
                        # Extract options if they exist
                        if "options" in content and isinstance(content["options"], list):
                            for option in content["options"]:
                                if isinstance(option, dict):
                                    for k, v in option.items():
                                        ssvc_parts.append(f"{k}: {v}")
                        else:
                            # Extract key SSVC values from other fields
                            for key, value in content.items():
                                if isinstance(value, dict):
                                    for sub_key, sub_value in value.items():
                                        if sub_key in ['Exploitation', 'Automatable', 'Technical Impact']:
                                            ssvc_parts.append(f"{sub_key}: {sub_value}")
                                elif key in ['id', 'role', 'version', 'timestamp']:
                                    continue  # Skip metadata
                                else:
                                    ssvc_parts.append(f"{key}: {value}")
        
        if ssvc_parts:
            parts.append("SSVC: " + ", ".join(ssvc_parts))
        
        return " | ".join(parts) if parts else ""
