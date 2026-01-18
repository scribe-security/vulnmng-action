import subprocess
import json
import logging
from typing import List
from vulnmng.core.interfaces import ScannerBase
from vulnmng.core.models import ScanResult, Vulnerability, Severity

logger = logging.getLogger(__name__)

class GrypeScanner(ScannerBase):
    def scan(self, target: str) -> ScanResult:
        logger.info(f"Scanning target {target} with Grype...")
        try:
            # -o json to get JSON output
            # --by-cve to prefer CVE IDs
            result = subprocess.run(
                ["grype", target, "-o", "json", "--by-cve"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            data = json.loads(result.stdout)
            vulnerabilities = self._parse_grype_output(data, target)
            return ScanResult(tool_name="grype", vulnerabilities=vulnerabilities, metadata={"target": target})
        except subprocess.CalledProcessError as e:
            logger.error(f"Grype failed: {e.stderr}")
            raise RuntimeError(f"Grype scan failed: {e.stderr}")
        except json.JSONDecodeError:
            logger.error(f"Failed to decode Grype output")
            raise RuntimeError("Failed to decode Grype output")

    def _parse_grype_output(self, data: dict, target: str) -> List[Vulnerability]:
        vulns = []
        matches = data.get("matches", [])
        for match in matches:
            vuln_data = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            locations = artifact.get("locations", [])
            location_id = locations[0].get("path") if locations else None
            
            # Map severity
            severity_str = vuln_data.get("severity", "Unknown")
            try:
                # Capitalize first letter to match Enum
                severity = Severity(severity_str.capitalize())
            except ValueError:
                severity = Severity.UNKNOWN
            
            # Extract primary ID and aliases (pass entire match, not just vuln_data)
            primary_id, aliases = self._extract_ids(match)
            
            # Extract ecosystem/language
            ecosystem = artifact.get("type") or artifact.get("language")
                
            # Extract CVSS vector and score
            cvss_score, cvss_vector = self._get_cvss_data(vuln_data)
            
            # Extract EPSS score
            epss_score = self._get_epss(vuln_data)
            
            vuln = Vulnerability(
                cve_id=primary_id,
                package_name=artifact.get("name"),
                version=artifact.get("version"),
                severity=severity,
                fix_version=self._get_fix_version(vuln_data),
                description=vuln_data.get("description"),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                epss_score=epss_score,
                location_id=location_id,
                target=target,
                aliases=aliases,
                ecosystem=ecosystem
            )
            vulns.append(vuln)
        return vulns

    def _get_fix_version(self, vuln_data: dict) -> str:
        fix_state = vuln_data.get("fix", {}).get("state")
        if fix_state == "fixed":
            return vuln_data.get("fix", {}).get("versions", [None])[0]
        return None

    def _get_cvss_data(self, vuln_data: dict) -> tuple[float, str]:
        """Extract CVSS score and vector string from vulnerability data.
        
        Returns:
            tuple: (cvss_score, cvss_vector) or (None, None) if not available
        """
        metrics = vuln_data.get("cvss", [])
        if metrics:
            # Prioritize v3 over v2
            for m in metrics:
                if m.get("version", "").startswith("3"):
                    score = m.get("metrics", {}).get("baseScore")
                    vector = m.get("vector")
                    return (float(score) if score else None, vector)
            # Fallback to first metric
            first = metrics[0]
            score = first.get("metrics", {}).get("baseScore")
            vector = first.get("vector")
            return (float(score) if score else None, vector)
        return None, None
    
    def _get_epss(self, vuln_data: dict) -> float:
        """Extract EPSS (Exploit Prediction Scoring System) score.
        
        Grype returns EPSS as an array of dicts with format:
        [{'cve': 'CVE-2025-13836', 'epss': 0.00087, 'percentile': 0.25444, 'date': '2026-01-17'}]
        
        Returns:
            float: EPSS score or None if not available
        """
        epss_data = vuln_data.get("epss")
        if epss_data:
            # EPSS is an array, take first entry
            if isinstance(epss_data, list) and len(epss_data) > 0:
                first_entry = epss_data[0]
                if isinstance(first_entry, dict):
                    score = first_entry.get("epss")
                    return float(score) if score is not None else None
            # Fallback for dict format (in case format changes)
            elif isinstance(epss_data, dict):
                score = epss_data.get("score") or epss_data.get("epss")
                return float(score) if score is not None else None
        return None
    
    def _extract_ids(self, match: dict) -> tuple[str, list[str]]:
        """
        Extract primary vulnerability ID and aliases from a grype match.
        Prioritizes CVE-ID over other identifiers (GHSA, CGA, etc.).
        
        Args:
            match: The full match object from grype output
            
        Returns:
            tuple: (primary_id, aliases_list)
        """
        vuln_data = match.get("vulnerability", {})
        primary_id = vuln_data.get("id", "")
        related = match.get("relatedVulnerabilities", [])  # This is at match level, not vuln level!
        
        all_ids = [primary_id]
        if related:
            for rel in related:
                rel_id = rel.get("id")
                if rel_id and rel_id not in all_ids:
                    all_ids.append(rel_id)
        
        # Separate CVE IDs from non-CVE IDs
        cve_ids = [vid for vid in all_ids if vid.startswith("CVE-")]
        non_cve_ids = [vid for vid in all_ids if not vid.startswith("CVE-")]
        
        # Priority: Use CVE-ID if available, otherwise use the primary ID from scanner
        if cve_ids:
            # Use first CVE as primary, rest go to aliases
            final_primary = cve_ids[0]
            aliases = cve_ids[1:] + non_cve_ids
        else:
            # No CVE found, use primary ID from scanner
            final_primary = primary_id
            aliases = [vid for vid in non_cve_ids if vid != primary_id]
        
        return final_primary, aliases
