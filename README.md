# Vulnmng: Vulnerability Management System

`vulnmng` is a comprehensive Vulnerability Management System (VMS) CLI tool. It automates the lifecycle of vulnerability detection and management by:
1. **Scanning**: Detecting vulnerabilities in source code or container images using `Grype`.
2. **Enriching**: Fetching contextual intelligence (like CISA Vulnrichment) to prioritize findings.
3. **Managing**: Storing and tracking vulnerabilities as "issues" with state persistence.
4. **Automating**: Integrating directly with Git branches for persistent storage and CI/CD reporting.

---

## Usage with Docker

All examples below use the public Docker image: `ghcr.io/scribe-security/vulnmng:latest`.

### 1. Basic Scan (Local File Storage)
Use this if you want to store and manage `issues.json` in your local directory.

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  python -m vulnmng.cli scan "registry:postgres:alpine" \
  --json-path /workspace/issues.json
```

### 2. Git-Integrated Scan
Use this to automatically pull, commit, and push scan results to a specific Git branch (e.g., `json-issues`). This requires a `GITHUB_TOKEN` for authenticated pushes.

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  ghcr.io/scribe-security/vulnmng:latest \
  sh -c "git config --global --add safe.directory /workspace && \
         python -m vulnmng.cli scan 'registry:postgres:alpine' \
         --git-root /workspace \
         --git-branch json-issues"
```

### 3. Generating Reports
Generate Markdown and CSV reports from the stored issues.

**Local storage example:**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  python -m vulnmng.cli report \
  --json-path /workspace/issues.json \
  --format-md /workspace/report.md \
  --format-csv /workspace/report.csv
```

**Git-integrated example (commits reports back to branch):**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  ghcr.io/scribe-security/vulnmng:latest \
  sh -c "git config --global --add safe.directory /workspace && \
         python -m vulnmng.cli report \
         --git-root /workspace \
         --git-branch json-issues \
         --format-md /workspace/report.md \
         --format-csv /workspace/report.csv"
```

---

## CLI Reference

### `scan` Command
| Flag | Description |
|------|-------------|
| `target` | (Positional) Path to scan or image (e.g., `registry:name:tag`) |
| `--json-path` | Path to save/read the issues database (default: `issues.json`) |
| `--git-root` | Path to the Git repository root (enables Git integration) |
| `--git-branch` | Target branch for storing findings (e.g., `json-issues`) |
| `--git-token` | GitHub token for pushes (can also use `GITHUB_TOKEN` env) |

### `report` Command
| Flag | Description |
|------|-------------|
| `--json-path` | Path to the issues database |
| `--target` | Optional filter to report only on a specific scan target |
| `--format-md` | Path to generate a Markdown report |
| `--format-csv` | Path to generate a CSV report |
| `--git-root` | Path to Git root (commits/pushes reports if set) |
| `--git-branch` | Branch to commit reports to |

---

## Triage & Status Management

Issues are tracked in `issues.json`. You can manually triage findings by updating the `labels` and `user_comment` fields.

### Status Labels
The system strictly enforces a "one status per issue" rule via labels prefixed with `status:`.

- `status:new`: Default for newly discovered vulnerabilities.
- `status:false-positive`: Manually identified as not a bug.
- `status:not-exploitable`: Vulnerability exists but cannot be reached.
- `status:fixed`: Finding has been patched.
- `status:ignored`: No action required.
- `status:triaged`: Acknowledged but awaiting further action.

### Example Triage
```json
{
  "id": "CVE-2024-1234::my-app",
  "labels": ["status:false-positive"],
  "user_comment": "This component is not used in production."
}
```
*Subsequent scans will preserve these overrides.*

---

## Development
- **Build**: `make build`
- **Unit Tests**: `make test`
- **E2E Tests**: `make e2e`
