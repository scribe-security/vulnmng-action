# Monorepo Sync Script Update Guide

## Issue
The Dockerfile in the public `vulnmng-action` repository was hardcoded to use `ghcr.io/scribe-security/vulnmng:latest`. This meant that even when using a specific version tag of the action (e.g., `@v0.1.3`), it would always pull the `:latest` version of the vulnmng Docker image instead of the corresponding versioned image (e.g., `:0.1.3`).

## Solution
The Dockerfile has been updated to use a build argument (`ARG`) that allows the vulnmng image version to be configured:

```dockerfile
ARG VULNMNG_VERSION=latest
FROM ghcr.io/scribe-security/vulnmng:${VULNMNG_VERSION}
```

This allows the version to be set either:
1. At build time using `--build-arg VULNMNG_VERSION=0.1.3`
2. By updating the default value in the Dockerfile before committing

## Required Changes to Monorepo Sync Script

The monorepo's `scripts/sync-action.sh` needs to be updated to set the correct vulnmng version when syncing to the public repository.

### Current Behavior (v0.1.3 sync script)

```bash
# 2. Patch Dockerfile if in dev mode
if [ "$SYNC_MODE" = "dev" ]; then
  echo "Patching Dockerfile for dev-latest..."
  git checkout "${TEMP_BRANCH}"
  # Replace latest with dev-latest in FROM line
  sed -i "s/vulnmng:latest/vulnmng:${VULNMNG_TAG}/g" Dockerfile
  
  # ... additional patching ...
  git add Dockerfile
  git commit -m "chore: patch Dockerfile and test.yml for dev mode"
  git checkout -
fi
```

### Proposed Updates

#### Option 1: Use the set-version.sh Script (Recommended)

The public repository now includes a `scripts/set-version.sh` script that handles version updates correctly:

```bash
# After creating the subtree split
git checkout "${TEMP_BRANCH}"

if [ "$SYNC_MODE" = "dev" ]; then
  echo "Patching for dev mode..."
  
  # Update vulnmng version to dev-latest
  ./scripts/set-version.sh dev-latest
  
  # Update test workflow to use @dev
  TEST_WF=".github/workflows/test.yml"
  if [ -f "$TEST_WF" ]; then
    echo "Patching $TEST_WF for @dev..."
    sed -i "s/@main/@dev/g" "$TEST_WF"
    git add "$TEST_WF"
  fi
  
  git add Dockerfile
  git commit -m "chore: patch for dev mode"
  
elif [ -n "$VERSION_TAG" ]; then
  echo "Patching for version ${VERSION_TAG}..."
  
  # Remove 'v' prefix from version tag (v0.1.3 -> 0.1.3)
  VERSION_NO_V=${VERSION_TAG#v}
  
  # Update vulnmng version to match the release
  ./scripts/set-version.sh "${VERSION_NO_V}"
  
  git add Dockerfile
  git commit -m "chore: update to version ${VERSION_NO_V}"
fi

git checkout -
```

#### Option 2: Direct sed Replacement

If you prefer not to use the script, you can update the sed pattern:

```bash
# For dev mode:
sed -i "s/^ARG VULNMNG_VERSION=.*/ARG VULNMNG_VERSION=dev-latest/" Dockerfile

# For prod mode with version tag:
VERSION_NO_V=${VERSION_TAG#v}  # Remove 'v' prefix
sed -i "s/^ARG VULNMNG_VERSION=.*/ARG VULNMNG_VERSION=${VERSION_NO_V}/" Dockerfile
```

### Important Notes

1. **Version Format**: The vulnmng Docker images are tagged without the 'v' prefix (e.g., `0.1.3`, not `v0.1.3`), so make sure to remove the 'v' when converting the action version tag.

2. **Prod Mode**: The original sync script only patched the Dockerfile in dev mode. It should ALSO patch in prod mode when a version tag is provided to ensure version alignment.

3. **Commit**: After patching the Dockerfile, it should be committed on the temp branch BEFORE pushing to the public repo.

### Verification

After updating the sync script, verify that:

1. Dev syncs result in `ARG VULNMNG_VERSION=dev-latest`
2. Prod syncs with version v0.1.3 result in `ARG VULNMNG_VERSION=0.1.3`
3. The sync creates tags correctly in the public repo
4. The version tag commits match between monorepo and public repo (no dangling commits)

## Testing

You can test the updated sync script by:

1. Running a dev sync: `./scripts/sync-action.sh <public-repo-url> dev`
2. Running a prod sync with version: `./scripts/sync-action.sh <public-repo-url> prod v0.1.3`
3. Checking the resulting Dockerfile in the public repo

## Benefits

- ✅ Action version tags now use corresponding vulnmng image versions
- ✅ No more hardcoded `:latest` causing version mismatches
- ✅ Backward compatible: defaults to `:latest` when no version is specified
- ✅ Build-time override possible: `docker build --build-arg VULNMNG_VERSION=0.1.2`
- ✅ Clear separation between dev and prod versions
