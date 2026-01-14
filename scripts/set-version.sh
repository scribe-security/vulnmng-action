#!/bin/bash
# Script to update the Dockerfile with a specific vulnmng version
# This script should be called by the monorepo sync script during versioning

set -e

VERSION=${1:-latest}

if [ "$VERSION" = "-h" ] || [ "$VERSION" = "--help" ]; then
  echo "Usage: $0 <version>"
  echo "  version: The vulnmng image version to use (e.g., '0.1.3', 'dev-latest', or 'latest')"
  echo ""
  echo "Example:"
  echo "  $0 0.1.3    # Sets Dockerfile to use vulnmng:0.1.3"
  echo "  $0 latest   # Sets Dockerfile to use vulnmng:latest"
  exit 0
fi

# Validate version format (alphanumeric, dots, and hyphens only)
if ! [[ "$VERSION" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "❌ Error: Invalid version format: ${VERSION}"
  echo "   Version must contain only letters, numbers, dots, hyphens, and underscores"
  exit 1
fi

# Get the script directory and find Dockerfile
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE="${REPO_ROOT}/Dockerfile"

# Check if Dockerfile exists
if [ ! -f "$DOCKERFILE" ]; then
  echo "❌ Error: Dockerfile not found at ${DOCKERFILE}"
  exit 1
fi

echo "Updating Dockerfile to use vulnmng version: ${VERSION}"

# Update the ARG default value in the Dockerfile
# Use | as delimiter to avoid issues with / in version strings
sed -i "s|^ARG VULNMNG_VERSION=.*|ARG VULNMNG_VERSION=${VERSION}|" "$DOCKERFILE"

# Verify the change
if grep -q "^ARG VULNMNG_VERSION=${VERSION}" "$DOCKERFILE"; then
  echo "✅ Dockerfile updated successfully"
  echo "   FROM ghcr.io/scribe-security/vulnmng:${VERSION}"
else
  echo "❌ Failed to update Dockerfile"
  exit 1
fi
