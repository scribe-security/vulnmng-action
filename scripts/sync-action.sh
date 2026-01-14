#!/bin/bash
# Script to sync the vulnmng action from the monorepo to a public repository

set -e

ACTION_PATH="actions/vulnmng"
TEMP_BRANCH="sync-action-$(date +%s)"
PUBLIC_REPO_URL=$1
SYNC_MODE=${2:-prod} # prod or dev
VERSION_TAG=$3 # Optional version tag (e.g., v1.0.0)

if [ -z "$PUBLIC_REPO_URL" ]; then
  echo "Usage: $0 <public-repo-url> [prod|dev] [version-tag]"
  exit 1
fi

TARGET_BRANCH="main"
VULNMNG_TAG="latest"

if [ "$SYNC_MODE" = "dev" ]; then
  TARGET_BRANCH="dev"
  VULNMNG_TAG="dev-latest"
fi

echo "Syncing ${ACTION_PATH} to ${PUBLIC_REPO_URL} (Mode: ${SYNC_MODE}, Target: ${TARGET_BRANCH})..."

# 1. Create a subtree split
echo "Creating subtree split..."
git subtree split --prefix="${ACTION_PATH}" -b "${TEMP_BRANCH}"

# 2. Patch Dockerfile if in dev mode
if [ "$SYNC_MODE" = "dev" ]; then
  echo "Patching Dockerfile for dev-latest..."
  git checkout "${TEMP_BRANCH}"
  # Replace latest with dev-latest in FROM line
  sed -i "s/vulnmng:latest/vulnmng:${VULNMNG_TAG}/g" Dockerfile
  
  # Replace @main with @dev in test.yml
  TEST_WF=".github/workflows/test.yml"
  if [ -f "$TEST_WF" ]; then
    echo "Patching $TEST_WF for @dev..."
    sed -i "s/@main/@dev/g" "$TEST_WF"
    git add "$TEST_WF"
  fi
  
  git add Dockerfile
  git commit -m "chore: patch Dockerfile and test.yml for dev mode"
  git checkout - # Go back to original branch
fi

# 3. Push to public repo
echo "Pushing to public repository branch ${TARGET_BRANCH}..."

# If the URL contains x-access-token, try to extract and use it as a header instead 
# to see if it improves the 403 situation.
if [[ "$PUBLIC_REPO_URL" == *"x-access-token:"* ]]; then
  TOKEN=$(echo "$PUBLIC_REPO_URL" | sed -e 's/.*x-access-token:\(.*\)@.*/\1/')
  CLEAN_URL=$(echo "$PUBLIC_REPO_URL" | sed -e 's/x-access-token:.*@//')
  
  echo "Using Authorization header for push..."
  AUTH_HEADER=$(echo -n "x-access-token:$TOKEN" | base64 | tr -d '\n')
  git -c "http.extraHeader=AUTHORIZATION: basic $AUTH_HEADER" push "${CLEAN_URL}" "${TEMP_BRANCH}":"${TARGET_BRANCH}" --force
else
  git push "${PUBLIC_REPO_URL}" "${TEMP_BRANCH}":"${TARGET_BRANCH}" --force
fi

# 4. Sync version tags if provided
if [ -n "$VERSION_TAG" ]; then
  echo "Syncing version tag ${VERSION_TAG} to public repo..."
  
  # Tag the temp branch with the version
  git tag "${VERSION_TAG}" "${TEMP_BRANCH}" 2>/dev/null || true
  
  # Push the tag
  if [[ "$PUBLIC_REPO_URL" == *"x-access-token:"* ]]; then
    TOKEN=$(echo "$PUBLIC_REPO_URL" | sed -e 's/.*x-access-token:\(.*\)@.*/\1/')
    CLEAN_URL=$(echo "$PUBLIC_REPO_URL" | sed -e 's/x-access-token:.*@//')
    AUTH_HEADER=$(echo -n "x-access-token:$TOKEN" | base64 | tr -d '\n')
    git -c "http.extraHeader=AUTHORIZATION: basic $AUTH_HEADER" push "${CLEAN_URL}" "${VERSION_TAG}" --force
  else
    git push "${PUBLIC_REPO_URL}" "${VERSION_TAG}" --force
  fi
  
  # Create/update major version tag (e.g., v1 for v1.2.3)
  MAJOR_VERSION=$(echo "${VERSION_TAG}" | sed -E 's/^v([0-9]+)\..*/v\1/')
  if [ "$MAJOR_VERSION" != "$VERSION_TAG" ]; then
    echo "Creating/updating major version tag ${MAJOR_VERSION}..."
    git tag -f "${MAJOR_VERSION}" "${TEMP_BRANCH}"
    
    if [[ "$PUBLIC_REPO_URL" == *"x-access-token:"* ]]; then
      git -c "http.extraHeader=AUTHORIZATION: basic $AUTH_HEADER" push "${CLEAN_URL}" "${MAJOR_VERSION}" --force
    else
      git push "${PUBLIC_REPO_URL}" "${MAJOR_VERSION}" --force
    fi
  fi
  
  echo "Version tags synced successfully!"
fi

# 5. Cleanup
echo "Cleaning up..."
git branch -D "${TEMP_BRANCH}"

echo "Sync complete!"
