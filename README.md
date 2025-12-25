# vulnmng-action

GitHub Action to scan targets for vulnerabilities and generate reports using the `vulnmng` CLI.

## Quickstart

```yaml
steps:
  - name: Checkout code
    uses: actions/checkout@v4

  - name: Run Vulnerability Scan
    uses: scribe-security/vulnmng-action@v1
    with:
      command: 'scan'
      target: '.'
      fail-on: 'High'
      git-token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `command` | Command to run (`scan` or `report`) | `scan` |
| `target` | Target to scan (path or image name) | |
| `target-name` | Human-readable name for the scan target | |
| `json-path` | Path to the issues JSON file | `issues.json` |
| `format-md` | Path to generate Markdown report | |
| `format-csv` | Path to generate CSV report | |
| `git-root` | Path to Git repository root for integration | |
| `git-branch` | Git branch to use | |
| `git-token` | GitHub token for authentication | `${{ secrets.GITHUB_TOKEN }}` |
| `fail-on` | Fail if any vulnerability with this severity or higher is found (`Low`, `Medium`, `High`, `Critical`) | |
| `extra-args` | Additional raw CLI arguments | |

## Outputs

| Output | Description |
|--------|-------------|
| `json-path` | Path to the generated or updated issues JSON file |
| `report-md` | Path to the generated Markdown report |
| `report-csv` | Path to the generated CSV report |

## Example Usage Patterns

### CI Gating (Fail on High/Critical)

```yaml
- name: Scan and Fail on High
  uses: scribe-security/vulnmng-action@v1
  with:
    target: 'my-app-image:latest'
    fail-on: 'High'
```

### Generate and Upload Reports

```yaml
- name: Generate Reports
  uses: scribe-security/vulnmng-action@v1
  with:
    command: 'report'
    format-md: 'vuln-report.md'
    format-csv: 'vuln-report.csv'

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: vulnerability-reports
    path: |
      vuln-report.md
      vuln-report.csv
```

### Git Integration (Automatic Commits)

```yaml
- name: Scan and Commit Results
  uses: scribe-security/vulnmng-action@v1
  with:
    target: '.'
    git-root: '.'
    git-branch: 'main'
    git-token: ${{ secrets.PAT_WITH_WORKFLOW_SCOPE }}
```

## Permissions

The action requires `contents: write` permission if using git integration with `GITHUB_TOKEN`.

```yaml
permissions:
  contents: write
```

## Troubleshooting

### Authentication
If using git integration, ensure the `git-token` has sufficient permissions (e.g., `contents: write`). The default `GITHUB_TOKEN` might need explicit permissions in the workflow.

### Rate Limits
Underlying tools like `grype` might hit rate limits for vulnerability database updates. Ensure your environment has internet access or pre-cached databases if running in a restricted environment.

### Common Failure Modes
- **Target not found**: Ensure the `target` path exists or the image is accessible.
- **Git root invalid**: Ensure `git-root` points to a valid git repository if enabled.

## Release and Versioning

### Syncing to Public Repo
To sync changes from the monorepo to the public action repository, use the provided sync script:
```bash
./scripts/sync-action.sh <public-repo-url>
```

### Tagging Guidance
When releasing new versions, follow semantic versioning:
1. **Major versions** (`v1`, `v2`): Tag the specific commit and also update the moving major version tag.
   ```bash
   git tag -a v1.0.1 -m "Release v1.0.1"
   git tag -fa v1 -m "Update v1 to v1.0.1"
   git push origin v1.0.1 v1 --force
   ```
2. **Users should pin** to major versions (e.g., `uses: scribe-security/vulnmng-action@v1`) for automatic updates within that version, or pin to a specific version (e.g., `@v1.0.1`) or commit SHA for maximum security and reproducibility.
