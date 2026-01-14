# Docker Image Tagging Fix - Summary

## Issues Addressed

### 1. Hardcoded `:latest` Tag
**Problem**: The Dockerfile was hardcoded to use `ghcr.io/scribe-security/vulnmng:latest`, meaning all versions of the action used the latest vulnmng image regardless of the action version.

**Solution**: Updated Dockerfile to use a build argument:
```dockerfile
ARG VULNMNG_VERSION=latest
FROM ghcr.io/scribe-security/vulnmng:${VULNMNG_VERSION}
```

### 2. Version Mismatch
**Problem**: When users referenced a specific action version (e.g., `@v0.1.3`), it should use the corresponding vulnmng image version (`:0.1.3`), but it always used `:latest`.

**Solution**: Created `scripts/set-version.sh` to update the Dockerfile version during the sync process from the monorepo.

### 3. Dangling Commits
**Problem**: The monorepo sync script wasn't properly versioning the Dockerfile when pushing version tags, causing version tags to point to commits that didn't have the correct version set.

**Solution**: The sync script should now call `scripts/set-version.sh` to update and commit the version before creating tags. See `MONOREPO_SYNC_UPDATE.md` for implementation details.

## Changes Made

### Files Modified
1. **Dockerfile**
   - Added `ARG VULNMNG_VERSION=latest` for version configuration
   - Changed FROM line to use `${VULNMNG_VERSION}` variable

### Files Created
1. **scripts/set-version.sh**
   - Utility script to update Dockerfile version
   - Can be called by monorepo sync script
   - Example: `./scripts/set-version.sh 0.1.3`

2. **scripts/README.md**
   - Documentation for the set-version.sh script
   - Usage examples and integration guide

3. **MONOREPO_SYNC_UPDATE.md**
   - Detailed guide for updating the monorepo sync script
   - Code examples for both script-based and direct sed approaches
   - Testing and verification instructions

## Next Steps for Monorepo

The monorepo's `scripts/sync-action.sh` needs to be updated to:

1. **For dev syncs**: Call `./scripts/set-version.sh dev-latest`
2. **For prod syncs with version**: Call `./scripts/set-version.sh <version-without-v-prefix>`
3. **Commit changes**: Commit the updated Dockerfile before creating tags

See `MONOREPO_SYNC_UPDATE.md` for detailed implementation instructions.

## Testing

### Verify Docker Build with Different Versions

```bash
# Build with default (latest)
docker build -t test:latest .

# Build with specific version
docker build --build-arg VULNMNG_VERSION=0.1.3 -t test:0.1.3 .

# Update Dockerfile default and build
./scripts/set-version.sh 0.1.3
docker build -t test:0.1.3 .
```

### Verify Version Alignment

When a new version is released:
1. Monorepo creates tag v0.1.4
2. Sync script runs with VERSION_TAG=v0.1.4
3. Dockerfile is updated to ARG VULNMNG_VERSION=0.1.4
4. Changes are committed
5. Tag v0.1.4 is pushed to public repo
6. Users using @v0.1.4 get vulnmng:0.1.4 image ✅

## Backward Compatibility

- Default behavior unchanged: uses `:latest` if no version specified
- Existing workflows continue to work
- Build-time override available via `--build-arg`

## Benefits

✅ Version alignment between action and vulnmng image  
✅ No more hardcoded `:latest` tag  
✅ Clear version management through ARG  
✅ Easy version updates via script  
✅ Documented process for monorepo integration  
✅ Eliminates dangling commit issues  
