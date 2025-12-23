import argparse
import logging
import sys
import os
from vulnmng.plugins.scanners.grype import GrypeScanner
from vulnmng.plugins.issuers.json_file import JsonFileIssueManager
from vulnmng.plugins.enhancers.cisa_enrichment import CisaEnrichment
from vulnmng.report import ReportGenerator
from vulnmng.utils.git_integration import GitIntegration

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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

    # Report Command
    report_parser = subparsers.add_parser("report", help="Generate a report")
    report_parser.add_argument("--json-path", default="issues.json", help="Path to JSON file")
    report_parser.add_argument("--target", help="Filter report by target")
    report_parser.add_argument("--format-md", help="Path to generate Markdown report")
    report_parser.add_argument("--format-csv", help="Path to generate CSV report")
    report_parser.add_argument("--git-root", help="Path to Git repository root. If set, enables Git integration.")
    report_parser.add_argument("--git-branch", help="Git branch to use. Default: current branch.")
    report_parser.add_argument("--git-token", help="GitHub token for authentication. Can also use GITHUB_TOKEN env var.")

    args = parser.parse_args()

    if args.command == "scan":
        logger.info(f"Starting scan for {args.target}")

        # 0. Git Setup
        git_integration = None
        if args.git_root:
            logger.info("Git integration enabled.")
            token = args.git_token or os.environ.get("GITHUB_TOKEN")
            git_integration = GitIntegration(repo_path=args.git_root, branch=args.git_branch, token=token)
            if not git_integration.is_repo():
                 logger.error(f"{args.git_root} is not a valid git repository.")
                 sys.exit(1)
            
            git_integration.checkout_branch()
            git_integration.pull()

        # 1. Scan
        scanner = GrypeScanner()
        scan_result = scanner.scan(args.target)
        logger.info(f"Found {len(scan_result.vulnerabilities)} vulnerabilities")

        # 2. Enrich
        enhancers = [CisaEnrichment()] 
        logger.info("Enriching vulnerabilities...")
        
        enrichment_map = {} # map vuln index/id to data
        
        for enhancer in enhancers:
             for i, vuln in enumerate(scan_result.vulnerabilities):
                 extra_data = enhancer.enhance(vuln)
                 if extra_data: # Only add if we got data
                    if i not in enrichment_map:
                        enrichment_map[i] = {}
                    # Namespace the enrichment data
                    # Assuming we know the enhancer source name, for now hardcoding or we can add `source_name` to enhancer interface
                    # Using hardcoded "cisagov/vulnrichment" for this specific enhancer instance
                    enrichment_map[i]["cisagov/vulnrichment"] = extra_data

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
            issues.append(issue)
        
        # Record Scan Metadata
        issue_manager.record_scan(args.target, "grype", len(issues))
        
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

    elif args.command == "report":
        # 0. Git Setup
        git_integration = None
        if args.git_root:
            logger.info("Git integration enabled for report.")
            token = args.git_token or os.environ.get("GITHUB_TOKEN")
            git_integration = GitIntegration(repo_path=args.git_root, branch=args.git_branch, token=token)
            if not git_integration.is_repo():
                 logger.error(f"{args.git_root} is not a valid git repository.")
                 sys.exit(1)
            
            git_integration.checkout_branch()
            git_integration.pull()

        issue_manager = JsonFileIssueManager(file_path=args.json_path)
        all_issues = issue_manager.get_all_issues()
        scans = issue_manager.get_scans()
        
        # Filter by target if requested
        if args.target:
            all_issues = [i for i in all_issues if i.vulnerability.target == args.target]
            scans = [s for s in scans if s.target == args.target]
            
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
