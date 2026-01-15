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
  scan "registry:postgres:alpine" \
  --json-path /workspace/issues.json
```

### 2. Git-Integrated Scan
Use this to automatically pull, commit, and push scan results to a specific Git branch (e.g., `json-issues`).

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  ghcr.io/scribe-security/vulnmng:latest \
  scan "registry:postgres:alpine" \
  --git-root /workspace \
  --git-branch json-issues
```

### 3. Repository Scanning with Custom Name
When scanning a local repository, the tool automatically detects the repository name. You can also override it with `--target-name`.

**Scan current directory (automatically named):**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  scan /workspace
```

**Scan with custom target name:**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  scan /workspace --target-name "MyCoolRepo"
```

### 4. Generating Reports
Generate reports from all issues, or filter by a specific target name.

**Generate all reports:**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  report \
  --json-path /workspace/issues.json \
  --format-md /workspace/report.md
```

**Generate report for a specific target name:**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  report \
  --json-path /workspace/issues.json \
  --target-name "MyCoolRepo" \
  --format-md /workspace/target-report.md
```

---

## CLI Reference

### `scan` Command
| Flag | Description |
|------|-------------|
| `target` | (Positional) Path to scan or image (e.g., `registry:name:tag`) |
| `--target-name` | Human-readable identifier for the scan (e.g. `frontend-app`). Defaults to repo name or image name. |
| `--json-path` | Path to save/read the issues database (default: `issues.json`) |
| `--git-root` | Path to the Git repository root (enables Git integration) |
| `--git-branch` | Target branch for storing findings (e.g., `json-issues`) |
| `--git-token` | GitHub token for pushes (can also use `GITHUB_TOKEN` env) |
| `--enrichment` | Comma-separated list of enrichment sources (e.g., `cisa`). Use `none` to disable (default: `none`) |
| `--fail-on` | Fail if any vulnerability with this severity or higher is found (default: `None`) |

### `report` Command
| Flag | Description |
|------|-------------|
| `--json-path` | Path to the issues database |
| `--target` | Filter report by exact target path/image string |
| `--target-name` | Filter report by the human-readable target name |
| `--format-md` | Path to generate a Markdown report |
| `--format-csv` | Path to generate a CSV report |
| `--git-root` | Path to Git root (commits/pushes reports if set) |
| `--git-branch` | Branch to commit reports to |
| `--enrichment` | Comma-separated list of enrichment sources to apply during report generation (default: `none`) |

---

## Vulnerability Enrichment

Enrich vulnerability reports with additional intelligence data from external sources to improve prioritization and understanding.

### Available Enrichments

#### CISA Vulnrichment

Fetches data from [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) and the [Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):

**Enriched data includes:**
- **KEV Status**: Whether the vulnerability is in CISA's Known Exploited Vulnerabilities catalog
- **Exploitability**: Links to public exploits and exploit code maturity
- **CVSS Vectors**: Full CVSS v2, v3.0, and v3.1 vector strings
- **SSVC Decision Points**: Stakeholder-specific Vulnerability Categorization data
- **Ransomware Usage**: Indicators of known ransomware campaign usage

### Usage Examples

**Scan with enrichment:**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  scan /workspace \
  --enrichment cisa \
  --json-path /workspace/issues.json
```

**Generate enriched report:**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/scribe-security/vulnmng:latest \
  report \
  --enrichment cisa \
  --format-md /workspace/report.md \
  --format-csv /workspace/report.csv
```

**Multiple enrichments (future):**
```bash
# Comma-separated list for sequential enrichment
--enrichment cisa,other
```

### Enrichment Output

Enriched data appears in three places:

1. **Markdown Reports**: `Additional Info` column with formatted summaries including links
2. **CSV Reports**: `additional_info` column with full markdown text, plus separate `link` column
3. **JSON Database**: `additional_info` field stores formatted summary, `details` field stores raw data

**Example enrichment summary:**
```markdown
### CISA Vulnrichment Data

🚨 Known Exploited Vulnerability (KEV)
- Vulnerability Name: Apache Log4j2 Remote Code Execution
- Date Added to KEV: 2021-12-10
- Due Date: 2021-12-24
- Required Action: Apply updates per vendor instructions
- ⚠️ Known Ransomware Campaign Use

CVSS Information:
- CVSS v3.1: 10.0 (CRITICAL)
  - Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

Exploit References:
- [Proof of Concept](https://github.com/example/poc)
```

---

## Triage & Status Management

Issues are tracked in `issues.json`. You can manually triage findings by updating the `labels` and `user_comment` fields.

### Status Labels
The system strictly enforces a "one status per issue" rule via labels prefixed with `status:`.

- `status:new`: Default for newly discovered vulnerabilities.
- `status:false-positive`: Manually identified as not a bug.
- `status:not-exploitable`: Vulnerability exists but cannot be reached.
- `status:fixed`: Finding has been patched or no longer appears in scans.
- `status:ignored`: No action required.
- `status:triaged`: Acknowledged but awaiting further action.

### Automatic Status Updates

**Auto-fixing Resolved Vulnerabilities:**
When you scan a target, VulnMng automatically marks vulnerabilities as `status:fixed` if they:
- Previously appeared in a scan
- Are no longer detected in the current scan
- Are not already marked as `fixed` or `ignored`

**Special Handling for False Positives:**
If a `status:false-positive` vulnerability disappears from scans, it will be marked as `fixed` and the system will prepend "CVE did not appear in scan since YYYY-MM-DD" to the existing `user_comment` to maintain the audit trail.

**Example:**
```bash
# First scan finds CVE-2024-1234
docker run --rm -v $(pwd):/workspace vulnmng scan /workspace

# Manually triage as false-positive in issues.json
# ... edit issues.json to add user_comment ...

# After dependency update, second scan no longer finds CVE-2024-1234
docker run --rm -v $(pwd):/workspace vulnmng scan /workspace

# Result: CVE-2024-1234 is automatically marked as status:fixed
# Comment becomes: "CVE did not appear in scan since 2024-01-15. [original comment]"
```

---

## Vulnerability ID Handling & Aliases

VulnMng intelligently handles multiple vulnerability identifier types (CVE, GHSA, CGA, etc.) and manages their relationships.

### ID Prioritization

When a vulnerability is detected with multiple identifiers, VulnMng applies the following priority:

1. **CVE-ID First**: If a CVE identifier exists (e.g., `CVE-2024-1234`), it becomes the primary ID
2. **Other IDs as Aliases**: Related identifiers (GHSA, CGA, etc.) are stored in the `aliases` field
3. **Non-CVE Primary**: If no CVE exists, the scanner's primary identifier is used (e.g., `GHSA-xxxx-yyyy-zzzz`)

### CVE Assignment Flow

When a CVE is later assigned to an existing vulnerability:

1. **Automatic Renaming**: The issue is automatically renamed to use the CVE as primary ID
2. **Alias Preservation**: The previous identifier moves to the `aliases` list
3. **History Maintained**: All status labels and triage comments are preserved

**Example:**
```json
// Initial scan finds GHSA-1234-5678-9012
{
  "cve_id": "GHSA-1234-5678-9012",
  "aliases": ["CGA-9999-8888-7777"]
}

// Later scan finds CVE was assigned
{
  "cve_id": "CVE-2024-9999",
  "aliases": ["GHSA-1234-5678-9012", "CGA-9999-8888-7777"]
}
```

### Benefits

- **Unified Tracking**: One issue per vulnerability, regardless of identifier changes
- **CVE Priority**: Users prioritize CVEs, so they automatically become primary when available
- **Full Traceability**: All related identifiers are tracked in aliases for cross-referencing

---

## Development
- **Build**: `make build`
- **Unit Tests**: `make test`
- **E2E Tests**: `make e2e`

---

## Contributing & Versioning

This project uses **automatic versioning** based on [Conventional Commits](https://www.conventionalcommits.org/).

### Commit Message Format

When contributing, use conventional commit messages to trigger automatic version bumps:

**Version Bump Types:**
- **Major (1.0.0 → 2.0.0)**: Breaking changes
  ```
  feat!: change --fail-on default behavior
  fix!: remove deprecated --legacy-mode flag
  
  BREAKING CHANGE: Users must now explicitly set --fail-on
  ```

- **Minor (1.0.0 → 1.1.0)**: New features (backwards compatible)
  ```
  feat: add --fail-on None option to never fail
  feat: add support for SARIF output format
  ```

- **Patch (1.0.0 → 1.0.1)**: Bug fixes
  ```
  fix: resolve issue with status label handling
  fix: correct EPSS score parsing
  ```

- **No version bump**: Other changes
  ```
  chore: update dependencies
  docs: improve README examples
  style: format code with black
  refactor: simplify git integration logic
  test: add unit tests for status management
  ```

### Automatic Release Flow

1. Push commits to `main` using conventional commit format
2. Auto-version workflow analyzes commits and creates version tag (e.g., `v1.1.0`)
3. CI builds and pushes Docker images with version tags
4. Sync workflow updates the public GitHub Action repository
5. GitHub Action users can reference the new version

**Docker Image Tags:**
- `latest` - Latest stable release from main branch
- `dev-latest` - Latest development build
- `1.0.0`, `1.1.0`, `2.0.0` - Specific semantic versions
- `sha-abc123` - Commit-specific builds
