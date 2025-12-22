# Vulnmng: Vulnerability Management System

A CLI tool to scan for vulnerabilities, manage them as issues, and enrich them with external intelligence.

## Features
- **Scan**: Wraps `grype` to scan source code or container images.
- **Enrich**: Fetches CISA Vulnrichment data (CVSS, descriptions, etc.).
- **Manage**: Tracks issues in `vulnerabilities.json` (or GitHub - future).
- **Report**: Markdown and CSV support.

## Installation
Build the Docker image:
```bash
make build
```

## Usage

### Scanning a Directory
```bash
make scan
```
Or manually:
```bash
docker run --rm -v $(pwd):/target vulnmng:latest python -m vulnmng.cli scan /target
```

### Scanning a Docker Image
To scan a remote image (e.g., `postgres:alpine`):
```bash
docker run --rm vulnmng:latest python -m vulnmng.cli scan "registry:postgres:alpine"
```
*Note: This requires network access from the container.*

### Issue Management & JSON
The system stores issues in `issues.json` in the current directory (mapped volume).
Each issue has a unique ID composed of `CVE::Target`.

**Status Management via Labels**:
Issues use labels to track their status. The status is stored as a label in the format `status:<value>`.

Valid status labels:
- `status:new` (default for new findings)
- `status:false-positive`
- `status:not-exploitable`
- `status:fixed`
- `status:ignored`
- `status:triaged`

**Manual Triage**:
You can manually edit `issues.json` to update the status and add comments:

1. **Update Status**: Find the issue and modify the `labels` array:
   ```json
   "labels": ["status:false-positive"]
   ```
   **Important**: Each issue must have exactly ONE `status:*` label. Multiple status labels will cause an error during reporting.

2. **Add User Comment**: Add or update the `user_comment` field to explain your triage decision:
   ```json
   "user_comment": "This vulnerability does not affect our usage of the library"
   ```

Example issue after triage:
```json
{
  "id": "CVE-2024-1234::my-app",
  "cve_id": "CVE-2024-1234",
  "title": "CVE-2024-1234 - vulnerable-package",
  "labels": ["status:false-positive"],
  "user_comment": "Not exploitable in our configuration",
  "vulnerability": { ... }
}
```

Re-running the scan will preserve your status labels and comments.

## Development
- **Tests**: `make test`
- **E2E**: `make e2e`
