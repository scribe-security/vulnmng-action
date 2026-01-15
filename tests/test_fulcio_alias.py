#!/usr/bin/env python3
"""
Demonstration test showing that GHSA aliases are now properly extracted.

This test uses the actual grype output from tmp.json to verify that
the fix correctly extracts aliases from relatedVulnerabilities.
"""

import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnmng.plugins.scanners.grype import GrypeScanner

def test_fulcio_alias_extraction():
    """Test that GHSA-f83f-xpx7-ffpw is extracted as an alias for CVE-2025-66506"""
    
    # Read the actual grype output
    with open('tmp.json', 'r') as f:
        grype_output = json.load(f)
    
    # Parse with the scanner
    scanner = GrypeScanner()
    target = grype_output['source']['target']['userInput']
    vulnerabilities = scanner._parse_grype_output(grype_output, target)
    
    # Find the fulcio vulnerability
    fulcio_vulns = [v for v in vulnerabilities 
                    if v.cve_id == 'CVE-2025-66506' or 
                       'fulcio' in v.package_name.lower()]
    
    assert len(fulcio_vulns) > 0, "Should find fulcio vulnerability"
    
    # Find the specific one with CVE-2025-66506
    cve_vuln = next((v for v in fulcio_vulns if v.cve_id == 'CVE-2025-66506'), None)
    
    assert cve_vuln is not None, "Should find CVE-2025-66506"
    assert 'GHSA-f83f-xpx7-ffpw' in cve_vuln.aliases, \
        f"GHSA-f83f-xpx7-ffpw should be in aliases, but got: {cve_vuln.aliases}"
    
    print("✅ Test passed!")
    print(f"   CVE ID: {cve_vuln.cve_id}")
    print(f"   Aliases: {cve_vuln.aliases}")
    print(f"   Package: {cve_vuln.package_name} {cve_vuln.version}")

if __name__ == '__main__':
    test_fulcio_alias_extraction()
