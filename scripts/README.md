# Scripts

## set-version.sh

Updates the Dockerfile to use a specific version of the `vulnmng` Docker image.

### Usage

```bash
./scripts/set-version.sh <version>
```

### Examples

```bash
# Set to a specific version (for production releases)
./scripts/set-version.sh 0.1.3

# Set to dev-latest (for development)
./scripts/set-version.sh dev-latest

# Set to latest (for main branch)
./scripts/set-version.sh latest
```

### Integration with Monorepo Sync Script

This script should be called by the monorepo's `sync-action.sh` script during the sync process:

```bash
# In the monorepo sync script, after creating the subtree split:

# For dev mode:
cd /path/to/temp/branch
./scripts/set-version.sh dev-latest
git add Dockerfile
git commit -m "chore: update to dev-latest"

# For prod mode with version tag (e.g., v0.1.3):
cd /path/to/temp/branch
VERSION_NO_V=${VERSION_TAG#v}  # Remove 'v' prefix: v0.1.3 -> 0.1.3
./scripts/set-version.sh ${VERSION_NO_V}
git add Dockerfile
git commit -m "chore: update to version ${VERSION_NO_V}"
```

### How It Works

The script uses `sed` to update the `ARG VULNMNG_VERSION` line in the Dockerfile:

```dockerfile
# Before:
ARG VULNMNG_VERSION=latest

# After running: ./scripts/set-version.sh 0.1.3
ARG VULNMNG_VERSION=0.1.3
```

This ensures that when the action is used with a specific version tag (e.g., `@v0.1.3`), it will use the corresponding `vulnmng` Docker image version (`vulnmng:0.1.3`).
