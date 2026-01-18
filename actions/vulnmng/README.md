# vulnmng-action

![Version](https://img.shields.io/github/v/release/scribe-security/vulnmng-action?include_prereleases)
![License](https://img.shields.io/github/license/scribe-security/vulnmng-action)

**vulnmng-action** is a powerful GitHub Action that wraps the `vulnmng` CLI to provide seamless vulnerability management, security scanning, and reporting directly in your CI/CD pipelines.

## Features

- 🔍 **Vulnerability Scanning**: Uses `grype` under the hood to detect vulnerabilities in your code and container images.
- 📊 **Automated Reporting**: Generates detailed Markdown and CSV reports.
- 💾 **Persistent State**: Stores vulnerabilities in a machine-readable JSON format, allowing for history tracking and triage.
- 🐙 **Git Integration**: Automatically commits and pushes scan results and reports to your repository (e.g., to a dedicated branch).
- 🛡️ **Build Gating**: Fail workflows based on severity thresholds (Low, Medium, High, Critical).

---

## Quickstart

### Basic Scan
Scan the current directory and fail if any **High** or **Critical** vulnerabilities are found.

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Run Scan
    uses: scribe-security/vulnmng-action@latest
    with:
      target: '.'
      fail-on: 'High'
```

---

## Configuration

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `command` | Action to perform: `scan` or `report`. | `scan` |
| `target` | Path to scan or container image name. | |
| `target-name` | Human-readable name for the target (internal label). | |
| `json-path` | Path to store/read the vulnerability data JSON. | `issues.json` |
| `format-md` | Path to save the Markdown report. | |
| `format-csv` | Path to save the CSV report. | |
| `git-root` | Path to the Git root if using Git integration. | |
| `git-branch` | Target branch for Git commits. | |
| `git-token` | GitHub Token for authenticated operations. | `${{ github.token }}` |
| `fail-on` | Severity threshold to fail the build (`Low`, `Medium`, `High`, `Critical`). | `None` |
| `enrichment` | Comma-separated list of enrichment sources (e.g., `cisa`). Use `none` to disable. | `none` |
| `log-level` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Use `DEBUG` for troubleshooting. | `WARNING` |
| `git-force-push` | Force push to remote (use with caution). Set to `true` to enable. | `false` |
| `extra-args` | Additional raw arguments for the `vulnmng` CLI. | |

### Outputs

| Output | Description |
|--------|-------------|
| `json-path` | Path where the issue data was saved. |
| `report-md` | Path where the Markdown report was saved. |
| `report-csv` | Path where the CSV report was saved. |

---

## Advanced Usage

### Enrichment

Enrich vulnerability reports with additional intelligence data from external sources. Currently supported enrichments:

- **CISA**: Fetches data from [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) including:
  - Known Exploited Vulnerabilities (KEV) catalog data
  - CVSS vectors and scores
  - Exploit references
  - SSVC decision points

**Example: Scan with CISA enrichment**

```yaml
- name: Scan with Enrichment
  uses: scribe-security/vulnmng-action@latest
  with:
    target: '.'
    enrichment: 'cisa'
    format-md: 'security-report.md'
```

The enriched data appears in:
- **Markdown reports**: `Additional Info` column with formatted summaries
- **CSV reports**: `additional_info` column with full data
- **JSON database**: `additional_info` field for each issue

### Recording Findings to a Dedicated Branch

Maintain a clean history of security findings without bloating your main branch history.

```yaml
- name: Scan and Archive
  uses: scribe-security/vulnmng-action@latest
  with:
    target: '.'
    git-root: '.'
    git-branch: 'security-archives'
    git-token: ${{ secrets.GITHUB_TOKEN }}
```

### Full Reporting Workflow

```yaml
- name: Generate Reports
  uses: scribe-security/vulnmng-action@latest
  with:
    command: 'report'
    format-md: 'reports/security.md'
    format-csv: 'reports/security.csv'

- name: Upload Artifacts
  uses: actions/upload-artifact@v4
  with:
    name: security-reports
    path: reports/
```

---

## Permissions

When using Git integration (committing results back to the repo), you must grant `contents: write` permissions.

```yaml
permissions:
  contents: write
```

---

## Troubleshooting

- **Authentication Error**: Ensure `git-token` is provided and has write permissions if using `git-root`.
- **Target Not Found**: Verify the `target` path exists relative to the runner's workspace or that the container image is public/accessible.
- **Hyphenated Variable Errors**: This action uses a robust entrypoint that handles both `INPUT_VAR_NAME` and `INPUT_VAR-NAME` variants passed by different GitHub Action versions.

---

## Release and Versioning

### Syncing from Monorepo
Internal developers can sync changes using the `scripts/sync-action.sh` script:
```bash
./scripts/sync-action.sh <public-repo-url> [prod|dev]
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
