# Git Branch Workflows Demo

This repository includes two manually-triggered workflows that demonstrate storing vulnerability scan results in a dedicated Git branch (`json-issues`).

## Workflows

### 1. JSON Branch Scan (`json-branch-scan.yml`)
**Purpose**: Scan a target and store results in the `json-issues` branch.

**How to run**:
1. Go to **Actions** → **JSON Branch Scan**
2. Click **Run workflow**
3. Enter the target to scan (e.g., `registry:postgres:alpine` or `/scan_target`)
4. Click **Run workflow**

**What it does**:
- Pulls the published Docker image from GHCR
- Runs a vulnerability scan on the specified target
- Uses Git integration to store/update `issues.json` in the `json-issues` branch
- Automatically commits and pushes changes

### 2. JSON Branch Report (`json-branch-report.yml`)
**Purpose**: Generate reports from the stored issues in the `json-issues` branch.

**How to run**:
1. Go to **Actions** → **JSON Branch Report**
2. Click **Run workflow**
3. Optionally filter by target (leave empty for all issues)
4. Click **Run workflow**

**What it does**:
- Checks out the `json-issues` branch
- Reads `issues.json` from that branch
- Generates Markdown and CSV reports
- Uploads reports as downloadable artifacts

## Benefits of This Approach

1. **Separation of Concerns**: Scan data is isolated in a dedicated branch
2. **History Tracking**: Git history shows how vulnerabilities change over time
3. **No Main Branch Pollution**: Keeps scan results separate from source code
4. **Easy Collaboration**: Team members can review and triage issues via the branch
5. **Manual Triage**: Edit `issues.json` in the `json-issues` branch to update status labels and add comments

## Example Usage

```bash
# Scan postgres:alpine image
# Trigger: json-branch-scan workflow with target "registry:postgres:alpine"

# Generate report for all issues
# Trigger: json-branch-report workflow (leave target empty)

# Generate report filtered by target
# Trigger: json-branch-report workflow with target "registry:postgres:alpine"
```

## Manual Triage in json-issues Branch

You can manually edit `issues.json` in the `json-issues` branch to triage vulnerabilities:

1. Switch to the `json-issues` branch
2. Edit `issues.json`
3. Update labels: `["status:false-positive"]`, `["status:fixed"]`, etc.
4. Add user comments: `"user_comment": "Not exploitable in our configuration"`
5. Commit and push

The next scan will preserve your manual changes!
