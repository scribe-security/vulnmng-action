# GitHub Copilot Instructions for VulnMng

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
