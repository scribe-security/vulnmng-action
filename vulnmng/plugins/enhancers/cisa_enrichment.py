import requests
import logging
from typing import Optional, Dict, Any
from vulnmng.core.interfaces import EnhancerBase
from vulnmng.core.models import Vulnerability

logger = logging.getLogger(__name__)

class CisaEnrichment(EnhancerBase):
    BASE_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"

    def enhance(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """Enhance a vulnerability and return the raw enrichment data."""
        cve_id = vulnerability.cve_id
        # Parse CVE ID: CVE-YYYY-NNNNN
        parts = cve_id.split("-")
        if len(parts) != 3:
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return vulnerability
            
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
