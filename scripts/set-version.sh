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

echo "Updating Dockerfile to use vulnmng version: ${VERSION}"

# Update the ARG default value in the Dockerfile
sed -i "s/^ARG VULNMNG_VERSION=.*/ARG VULNMNG_VERSION=${VERSION}/" Dockerfile

# Verify the change
if grep -q "^ARG VULNMNG_VERSION=${VERSION}" Dockerfile; then
  echo "✅ Dockerfile updated successfully"
  echo "   FROM ghcr.io/scribe-security/vulnmng:${VERSION}"
else
  echo "❌ Failed to update Dockerfile"
  exit 1
fi
