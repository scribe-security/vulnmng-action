#!/bin/bash
# Script to sync the vulnmng action from the monorepo to a public repository

set -e

ACTION_PATH="actions/vulnmng"
TEMP_BRANCH="sync-action-$(date +%s)"
PUBLIC_REPO_URL=$1

if [ -z "$PUBLIC_REPO_URL" ]; then
  echo "Usage: $0 <public-repo-url>"
  exit 1
fi

echo "Syncing ${ACTION_PATH} to ${PUBLIC_REPO_URL}..."

# 1. Create a subtree split
echo "Creating subtree split..."
git subtree split --prefix="${ACTION_PATH}" -b "${TEMP_BRANCH}"

# 2. Push to public repo
echo "Pushing to public repository..."
git push "${PUBLIC_REPO_URL}" "${TEMP_BRANCH}":main --force

# 3. Cleanup
echo "Cleaning up..."
git branch -D "${TEMP_BRANCH}"

echo "Sync complete!"
