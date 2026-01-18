import argparse
import logging
import sys
import os
from vulnmng.plugins.scanners.grype import GrypeScanner
from vulnmng.plugins.issuers.json_file import JsonFileIssueManager
from vulnmng.plugins.enhancers.cisa_enrichment import CisaEnrichment
from vulnmng.plugins.enhancers.registry import EnhancerRegistry
from vulnmng.report import ReportGenerator
from vulnmng.utils.git_integration import GitIntegration
from vulnmng.core.models import Severity, VulnerabilityStatus

logger = logging.getLogger("vulnmng")

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Management System CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan Command
    scan_parser = subparsers.add_parser("scan", help="Scan a target")
    scan_parser.add_argument("target", help="Target to scan (path or image)")
    scan_parser.add_argument("--format", choices=["json", "github"], default="json", help="Issue Manager Backend")
    scan_parser.add_argument("--json-path", default="issues.json", help="Path to JSON file")
    scan_parser.add_argument("--git-root", help="Path to Git repository root. If set, enables Git integration.")
    scan_parser.add_argument("--git-branch", help="Git branch to use. Default: current branch.")
    scan_parser.add_argument("--git-token", help="GitHub token for authentication. Can also use GITHUB_TOKEN env var.")
    scan_parser.add_argument("--target-name", help="Human-readable name for the scan target.")
    scan_parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="WARNING", help="Logging level (default: WARNING)")
    scan_parser.add_argument("--fail-on", choices=["None", "Low", "Medium", "High", "Critical"], default="None", help="Fail if any vulnerability with this severity or higher is found (default: None - never fail).")
    scan_parser.add_argument("--enrichment", default="none", help="Comma-separated list of enrichment sources to apply (e.g., 'cisa' or 'cisa,other'). Use 'none' to disable enrichment (default: none).")


    # Report Command
    report_parser = subparsers.add_parser("report", help="Generate a report")
    report_parser.add_argument("--json-path", default="issues.json", help="Path to JSON file")
    report_parser.add_argument("--target", help="Filter report by target")
    report_parser.add_argument("--format-md", help="Path to generate Markdown report")
    report_parser.add_argument("--format-csv", help="Path to generate CSV report")
    report_parser.add_argument("--git-root", help="Path to Git repository root. If set, enables Git integration.")
    report_parser.add_argument("--git-branch", help="Git branch to use. Default: current branch.")
    report_parser.add_argument("--git-token", help="GitHub token for authentication. Can also use GITHUB_TOKEN env var.")
    report_parser.add_argument("--target-name", help="Filter report by target name")
    report_parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="WARNING", help="Logging level (default: WARNING)")
    report_parser.add_argument("--enrichment", default="none", help="Comma-separated list of enrichment sources to apply (e.g., 'cisa' or 'cisa,other'). Use 'none' to disable enrichment (default: none).")

    args = parser.parse_args()

    # Configure logging based on log-level argument
    if hasattr(args, 'log_level'):
        numeric_level = getattr(logging, args.log_level)
        logging.basicConfig(level=numeric_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        # Default if no command specified
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if args.command == "scan":
        logger.info(f"Starting scan for {args.target}")

        # 0. Git Setup
        git_integration = None
        if args.git_root:
            logger.info("Git integration enabled.")
            token = args.git_token or os.environ.get("GITHUB_TOKEN")
            git_integration = GitIntegration(repo_path=args.git_root, branch=args.git_branch, token=token)
            git_integration.ensure_safe_directory()
            git_integration.ensure_identity()
            if not git_integration.is_repo():
                 logger.error(f"{args.git_root} is not a valid git repository.")
                 sys.exit(1)
            
            git_integration.checkout_branch()
            git_integration.pull()

        # 1. Scan
        scanner = GrypeScanner()
        scan_result = scanner.scan(args.target)
        
        # 1.1 Handle Target Name defaulting
        target_name = args.target_name
        if not target_name:
            if ":" in args.target and not os.path.exists(args.target):
                # Looks like a docker image (registry:image:tag)
                target_name = args.target
            else:
                # Looks like a path
                abs_target = os.path.abspath(args.target)
                target_name = os.path.basename(abs_target)
                
                # Check if it's a git repo to get a better name
                try:
                    import subprocess
                    # Try to get remote origin URL
                    result = subprocess.run(
                        ["git", "remote", "get-url", "origin"],
                        cwd=abs_target,
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        repo_url = result.stdout.strip()
                        # Extract repo name from URL (e.g., https://github.com/user/repo_name.git)
                        target_name = repo_url.split("/")[-1].replace(".git", "")
                except Exception:
                    pass # Fallback to basename is fine
        
        logger.info(f"Using target name: {target_name}")
        # Update vulnerabilities and scan result with target_name
        scan_result.target_name = target_name
        for v in scan_result.vulnerabilities:
            v.target_name = target_name

        logger.info(f"Found {len(scan_result.vulnerabilities)} vulnerabilities")

        # 2. Enrich
        # Parse enrichment list from argument
        enrichment_names = [e.strip() for e in args.enrichment.split(',') if e.strip() and e.strip().lower() != 'none']
        
        enhancers = []
        if enrichment_names:
            try:
                enhancers = EnhancerRegistry.get_enhancers(enrichment_names)
                logger.info(f"Applying enrichments: {', '.join(enrichment_names)}")
            except ValueError as e:
                logger.error(str(e))
                sys.exit(1)
        else:
            logger.info("No enrichments requested (--enrichment none or not specified)")
        
        enrichment_map = {} # map vuln index/id to data
        
        for enhancer in enhancers:
             for i, vuln in enumerate(scan_result.vulnerabilities):
                 extra_data = enhancer.enhance(vuln)
                 if extra_data: # Only add if we got data
                    if i not in enrichment_map:
                        enrichment_map[i] = {}
                    # Get enhancer name from class
                    enhancer_name = enhancer.__class__.__name__.lower().replace('enrichment', '')
                    enrichment_map[i][enhancer_name] = extra_data

        # 3. Manage Issues
        if args.format == "json":
            # If git root is set, we need to ensure json path is absolute or relative to where we want it?
            # User provides --json-path. If it's relative, it's relative to CWD.
            # If running in a git repo context, user probably wants the json IN the repo.
            # But let's respect the path provided.
            issue_manager = JsonFileIssueManager(file_path=args.json_path)
        else:
            # TODO: Implement GitHub Issue Manager
            logger.warning("GitHub Issue Manager not implemented yet, falling back to JSON")
            issue_manager = JsonFileIssueManager(file_path=args.json_path)

        issues = []
        for i, vuln in enumerate(scan_result.vulnerabilities):
            details = enrichment_map.get(i, {})
            issue = issue_manager.create_issue(vuln, details=details)
            
            # Generate additional_info from enrichment data
            if details and enhancers:
                additional_info_parts = []
                for enhancer in enhancers:
                    enhancer_name = enhancer.__class__.__name__.lower().replace('enrichment', '')
                    enrichment_data = details.get(enhancer_name, {})
                    if enrichment_data:
                        # Pass CVE ID to formatter if available
                        if hasattr(enhancer, 'format_summary'):
                            summary = enhancer.format_summary(enrichment_data, cve_id=vuln.cve_id)
                        else:
                            summary = enhancer.format_summary(enrichment_data)
                        if summary:
                            additional_info_parts.append(summary)
                
                if additional_info_parts:
                    issue.additional_info = " | ".join(additional_info_parts)
            
            issues.append(issue)
        
        # Extract CVE IDs from scanned vulnerabilities for comparison
        scanned_cve_ids = [vuln.cve_id for vuln in scan_result.vulnerabilities]
        
        # Mark vulnerabilities that didn't appear in this scan as fixed
        fixed_count = issue_manager.mark_missing_vulnerabilities_as_fixed(args.target, scanned_cve_ids)
        if fixed_count > 0:
            logger.info(f"Marked {fixed_count} missing vulnerabilities as fixed")
        
        # Record Scan Metadata
        issue_manager.record_scan(args.target, "grype", len(issues), target_name=target_name)
        
        # Explicit save
        issue_manager.save()
        logger.info("Issues updated.")
        
        # 5. Git Commit & Push (Scan Command logic ends here for reporting)
        if git_integration:
            # Add the JSON file. 
            # We need to resolve JSON path relative to Git Root?
            # 'git add' expects path relative to CWD (if run inside repo) or absolute?
            # Our GitIntegration runs commands with cwd=repo_path. 
            # So we need to provide path relative to repo_path or absolute.
            # Let's try absolute path for safety if git allows it, or calculate relative.
            
            abs_json_path = os.path.abspath(args.json_path)
            # Just use absolute path for git add, usually works if file is inside repo
            git_integration.add(abs_json_path)
            
            git_integration.commit(f"Update vulnerabilities scan results [skip ci]")
            git_integration.push()
            logger.info("Git push completed.")

        # 6. Failure Logic
        if args.fail_on and args.fail_on != "None":
            severity_order = {
                "Low": 1,
                "Medium": 2,
                "High": 3,
                "Critical": 4
            }
            threshold = severity_order.get(args.fail_on, 0)
            
            # Map model Severity to our internal order
            model_severity_map = {
                Severity.LOW: 1,
                Severity.MEDIUM: 2,
                Severity.HIGH: 3,
                Severity.CRITICAL: 4,
                Severity.NEGLIGIBLE: 0,
                Severity.UNKNOWN: 0
            }
            
            # Statuses that should NOT cause a failure
            excluded_statuses = {
                VulnerabilityStatus.FIXED.value,
                VulnerabilityStatus.FALSE_POSITIVE.value,
                VulnerabilityStatus.NOT_EXPLOITABLE.value,
                VulnerabilityStatus.IGNORED.value
            }
            
            # Check issues that meet severity threshold AND are not in excluded status
            failed_issues = [
                issue for issue in issues
                if model_severity_map.get(issue.vulnerability.severity, 0) >= threshold
                and not any(label in excluded_statuses for label in issue.labels)
            ]
            
            if failed_issues:
                logger.error(f"Found {len(failed_issues)} unresolved vulnerabilities with severity {args.fail_on} or higher.")
                for issue in failed_issues:
                    status = next((l for l in issue.labels if l.startswith("status:")), "status:unknown")
                    logger.error(f"  - {issue.cve_id} ({issue.vulnerability.severity.value}) [{status}]")
                sys.exit(1)
            else:
                logger.info(f"No unresolved vulnerabilities with severity {args.fail_on} or higher found.")

    elif args.command == "report":
        # 0. Git Setup
        git_integration = None
        if args.git_root:
            logger.info("Git integration enabled for report.")
            token = args.git_token or os.environ.get("GITHUB_TOKEN")
            git_integration = GitIntegration(repo_path=args.git_root, branch=args.git_branch, token=token)
            git_integration.ensure_safe_directory()
            git_integration.ensure_identity()
            if not git_integration.is_repo():
                 logger.error(f"{args.git_root} is not a valid git repository.")
                 sys.exit(1)
            
            git_integration.checkout_branch()
            git_integration.pull()

        issue_manager = JsonFileIssueManager(file_path=args.json_path)
        all_issues = issue_manager.get_all_issues()
        scans = issue_manager.get_scans()
        
        # Filter by target PATH if requested
        if args.target:
            all_issues = [i for i in all_issues if i.vulnerability.target == args.target]
            scans = [s for s in scans if s.target == args.target]
        
        # Filter by target NAME if requested
        if args.target_name:
            all_issues = [i for i in all_issues if i.vulnerability.target_name == args.target_name]
            scans = [s for s in scans if s.target_name == args.target_name]
        
        # Apply enrichments if requested
        enrichment_names = [e.strip() for e in args.enrichment.split(',') if e.strip() and e.strip().lower() != 'none']
        
        if enrichment_names:
            try:
                enhancers = EnhancerRegistry.get_enhancers(enrichment_names)
                logger.info(f"Applying enrichments to report: {', '.join(enrichment_names)}")
                
                # Enrich issues that don't already have additional_info
                for issue in all_issues:
                    if not issue.additional_info:
                        enrichment_data = {}
                        for enhancer in enhancers:
                            extra_data = enhancer.enhance(issue.vulnerability)
                            if extra_data:
                                enhancer_name = enhancer.__class__.__name__.lower().replace('enrichment', '')
                                enrichment_data[enhancer_name] = extra_data
                        
                        if enrichment_data:
                            additional_info_parts = []
                            for enhancer in enhancers:
                                enhancer_name = enhancer.__class__.__name__.lower().replace('enrichment', '')
                                data = enrichment_data.get(enhancer_name, {})
                                if data:
                                    # Pass CVE ID to formatter if available
                                    if hasattr(enhancer, 'format_summary'):
                                        summary = enhancer.format_summary(data, cve_id=issue.cve_id)
                                    else:
                                        summary = enhancer.format_summary(data)
                                    if summary:
                                        additional_info_parts.append(summary)
                            
                            if additional_info_parts:
                                issue.additional_info = " | ".join(additional_info_parts)
                                # Also update details for persistence
                                issue.details.update(enrichment_data)
                
                # Save updated issues with enrichment data
                issue_manager.save()
                
            except ValueError as e:
                logger.error(str(e))
                sys.exit(1)
            
        reporter = ReportGenerator(all_issues, scans)
        
        if args.format_md:
            reporter.generate_markdown(args.format_md)
            logger.info(f"Markdown report ready: {args.format_md}")
            
        if args.format_csv:
            reporter.generate_csv(args.format_csv)
            logger.info(f"CSV report ready: {args.format_csv}")

        # 5. Git Commit & Push
        if git_integration:
            # Add the reports and the JSON file
            files_to_add = [os.path.abspath(args.json_path)]
            if args.format_md:
                files_to_add.append(os.path.abspath(args.format_md))
            if args.format_csv:
                files_to_add.append(os.path.abspath(args.format_csv))
            
            for f in files_to_add:
                git_integration.add(f)
            
            git_integration.commit(f"Update vulnerability reports [skip ci]")
            git_integration.push()
            logger.info("Git push completed.")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
