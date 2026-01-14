# GitHub Copilot Instructions for VulnMng

## Project Architecture

This is a **monorepo** containing:
- **Core VulnMng CLI** (root directory)
- **GitHub Action** (`actions/vulnmng/`) - synced to public `scribe-security/vulnmng-action` repo

### Docker Image Flow
1. Root `Dockerfile` builds the base image (`ghcr.io/scribe-security/vulnmng:latest`)
2. CI workflow builds and pushes versioned images on tag creation
3. Action's `Dockerfile` uses the base image: `FROM ghcr.io/scribe-security/vulnmng:latest`
4. Public repo users pull the action, which pulls the Docker image

## Project Guidelines

### CLI and GitHub Action Synchronization
**CRITICAL**: Any changes to the CLI (`vulnmng/cli.py`) MUST be reflected in the GitHub Action:
- Update `actions/vulnmng/action.yml` with new/modified input parameters
- Update `actions/vulnmng/entrypoint.sh` to handle new CLI flags
- Ensure parameter descriptions match between CLI help text and action.yml
- Keep default values consistent across both interfaces
- Update action examples in `actions/vulnmng/examples/` if behavior changes

### Key Synchronization Points
1. **New CLI Arguments**: Add corresponding input in `action.yml` and handle in `entrypoint.sh`
2. **Default Values**: Must match between CLI argparse defaults and action.yml defaults
3. **Help Text**: CLI help descriptions should align with action.yml descriptions
4. **Choices/Enums**: Valid choices in CLI must match action documentation
5. **Output Files**: Any new output files should be added to action outputs

### Development Workflow
- When modifying CLI arguments, create a checklist:
  - [ ] Update CLI argparse definition
  - [ ] Update action.yml inputs section
  - [ ] Update entrypoint.sh flag handling
  - [ ] Update action examples if needed
  - [ ] Update README documentation

### Code Organization
- Core models in `vulnmng/core/models.py` define the data structures
- Plugin architecture: scanners, issuers, enhancers in `vulnmng/plugins/`
- Git integration lives in `vulnmng/utils/git_integration.py`
- Issue status is managed via labels (format: `status:*`)

### Testing Requirements
- Changes affecting the scan or report commands should include E2E test updates
- Git integration changes should update `tests/test_git_integration.py`
- Plugin changes should have corresponding unit tests

### Status Management
- Issue statuses are labels in format `status:*` (e.g., `status:new`, `status:fixed`)
- Only one status label per issue is allowed
- Excluded statuses (fixed, false-positive, not-exploitable, ignored) don't cause `--fail-on` failures

### Versioning and Release Management

**Automatic Versioning**: Pushes to `main` trigger automatic version tagging based on commit messages.

**Conventional Commits** (REQUIRED for automatic versioning):
- `fix:` - Patch version bump (1.0.0 → 1.0.1)
- `feat:` - Minor version bump (1.0.0 → 1.1.0)
- `BREAKING CHANGE:` or `feat!:` or `fix!:` - Major version bump (1.0.0 → 2.0.0)
- Other types: `chore:`, `docs:`, `style:`, `refactor:`, `test:` - No version bump

**Commit Message Examples**:
```
feat: add new --output-format flag to report command
fix: resolve issue with status label migration
feat!: change --fail-on default to None (breaking change)
chore: update dependencies
```

**Version Tag Flow**:
1. Commits merged to `main` → Auto-tag workflow analyzes commits
2. Creates version tag (e.g., `v1.0.0`) based on conventional commits
3. CI builds and pushes Docker image with version tag
4. Sync workflow pushes to public `vulnmng-action` repo
5. Manual tagging in public repo for GitHub Action releases (`v1`, `v1.0.0`)

**Docker Image Tags**:
- `latest` - Latest main branch build
- `dev-latest` - Latest dev branch build
- `1.0.0`, `1.1.0` - Semantic version tags
- `sha-abc123` - Commit SHA tags
