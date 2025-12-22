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
The system stores issues in `vulnerabilities.json` in the current directory (mapped volume).
Each issue has a unique ID composed of `CVE::Target`.

**Triage / Manual Updates**:
You can manually edit `vulnerabilities.json` to update the status of an issue.
Allowed statuses:
- `new` (default)
- `false-positive`
- `fixed`
- `ignored`
- `triaged`

Example: To mark an issue as a false positive, find the entry in `vulnerabilities.json` and change:
```json
"status": "false-positive"
```
Re-running the scan will preserve this status.

## Development
- **Tests**: `make test`
- **E2E**: `make e2e`
