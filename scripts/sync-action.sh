#!/bin/bash
# Script to sync the vulnmng action from the monorepo to a public repository

set -e

ACTION_PATH="actions/vulnmng"
TEMP_BRANCH="sync-action-$(date +%s)"
PUBLIC_REPO_URL=$1
SYNC_MODE=${2:-prod} # prod or dev

if [ -z "$PUBLIC_REPO_URL" ]; then
  echo "Usage: $0 <public-repo-url> [prod|dev]"
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
  git add Dockerfile
  git commit -m "chore: patch Dockerfile for dev-latest"
  git checkout - # Go back to original branch
fi

# 3. Push to public repo
echo "Pushing to public repository branch ${TARGET_BRANCH}..."
git push "${PUBLIC_REPO_URL}" "${TEMP_BRANCH}":"${TARGET_BRANCH}" --force

# 4. Cleanup
echo "Cleaning up..."
git branch -D "${TEMP_BRANCH}"

echo "Sync complete!"

echo "Sync complete!"
