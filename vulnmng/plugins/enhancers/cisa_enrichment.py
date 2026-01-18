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
        """Enhance a vulnerability and return structured enrichment data.
        
        Returns dict with:
        - exploitability: SSVC exploitation status from containers.adp
        - kev: KEV catalog entry if listed
        - cwe: CWE ID and description from containers.cna
        - raw_data: Full CISA record for reference
        """
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
        cisa_data = None
        
        try:
            logger.debug(f"Fetching enrichment for {cve_id} from {url}")
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                cisa_data = response.json()
                enrichment_data["raw_data"] = cisa_data
            elif response.status_code == 404:
                logger.debug(f"No CISA enrichment found for {cve_id}")
            else:
                logger.warning(f"Failed to fetch CISA data: {response.status_code}")
        except Exception as e:
            logger.error(f"Error fetching CISA data: {e}")
        
        # Extract structured data from CISA record
        if cisa_data:
            containers = cisa_data.get("containers", {})
            
            # 1. Extract exploitability from containers.adp (SSVC)
            adp = containers.get("adp", [])
            for entry in adp:
                if entry.get("title") == "CISA ADP Vulnrichment":
                    metrics = entry.get("metrics", [])
                    for metric in metrics:
                        ssvc = metric.get("other", {})
                        if ssvc.get("type") == "ssvc":
                            content = ssvc.get("content", {})
                            options = content.get("options", [])
                            for option in options:
                                if "Exploitation" in option:
                                    enrichment_data["exploitability"] = option["Exploitation"]
                                    break
                    if "exploitability" in enrichment_data:
                        break
            
            # 2. Extract CWE from containers.cna
            cna = containers.get("cna", {})
            problem_types = cna.get("problemTypes", [])
            for problem_type in problem_types:
                descriptions = problem_type.get("descriptions", [])
                for desc in descriptions:
                    if desc.get("type") == "CWE" and "cweId" in desc:
                        enrichment_data["cwe"] = {
                            "id": desc.get("cweId"),
                            "description": desc.get("description", "")
                        }
                        break
                if "cwe" in enrichment_data:
                    break
            
            # Store containers for format_summary to access references
            enrichment_data["containers"] = containers
        
        # 3. Check KEV catalog
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
    
    def format_summary(self, enrichment_data: dict, cve_id: str = None) -> str:
        """Format CISA enrichment data into markdown text for additional info column.
        
        Creates a formatted markdown block with:
        - Exploitability status (from SSVC)
        - KEV status and ransomware usage
        - CWE information
        - Available exploits with references
        - Link to CISA vulnrichment data
        
        Note: CVSS data is now sourced from Grype and displayed in separate columns.
        """
        if not enrichment_data:
            return ""
        
        markdown_parts = []
        
        # 1. Exploitability Status (SSVC from ADP)
        exploitability = enrichment_data.get("exploitability")
        if exploitability:
            exploit_emoji = {
                "none": "🟢",
                "poc": "🟡", 
                "active": "🔴"
            }.get(exploitability.lower(), "⚪")
            markdown_parts.append(f"{exploit_emoji} **Exploitability**: {exploitability.upper()}")
        
        # 2. KEV Information (critical security info)
        kev_entry = enrichment_data.get("kev")
        if kev_entry:
            vuln_name = kev_entry.get('vulnerabilityName', 'N/A')
            ransomware = ""
            if kev_entry.get('knownRansomwareCampaignUse') == 'Known':
                ransomware = " ⚠️ **Used in Ransomware**"
            markdown_parts.append(f"**KEV Listed**: {vuln_name}{ransomware}")
        
        # 3. CWE Information
        cwe = enrichment_data.get("cwe")
        if cwe:
            cwe_id = cwe.get("id", "")
            cwe_desc = cwe.get("description", "")
            markdown_parts.append(f"**{cwe_id}**: {cwe_desc}")
        
        # 4. References and Exploits (threat intelligence)
        containers = enrichment_data.get("containers", {})
        if containers:
            cna = containers.get("cna", {})
            references = cna.get("references", [])
            exploit_refs = [ref for ref in references if any(tag in ref.get("tags", []) for tag in ["exploit", "Exploit"])]
            
            if exploit_refs:
                exploit_count = len(exploit_refs)
                exploit_links = []
                for ref in exploit_refs[:3]:  # Show up to 3 exploit links
                    url = ref.get("url", "")
                    if url:
                        # Extract domain for display
                        domain = url.split("//")[-1].split("/")[0]
                        exploit_links.append(f"[{domain}]({url})")
                
                exploit_text = f"**🔴 {exploit_count} Exploit(s) Available**"
                if exploit_links:
                    exploit_text += f": {', '.join(exploit_links)}"
                if exploit_count > 3:
                    exploit_text += f" (+{exploit_count - 3} more)"
                markdown_parts.append(exploit_text)
        
        # 5. Add link to specific CISA vulnrichment JSON file
        if cve_id and cve_id.startswith("CVE-"):
            cve_parts = cve_id.split("-")
            if len(cve_parts) == 3:
                year = cve_parts[1]
                id_num = cve_parts[2]
                
                # Determine folder structure
                if len(id_num) == 4:
                    folder = f"{id_num[0]}xxx"
                elif len(id_num) >= 5:
                    folder = f"{id_num[:-3]}xxx"
                else:
                    folder = "xxxx"
                
                cisa_url = f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{folder}/{cve_id}.json"
                markdown_parts.append(f"[View CISA Data]({cisa_url})")
        
        return " | ".join(markdown_parts) if markdown_parts else ""
