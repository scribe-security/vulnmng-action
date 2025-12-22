#!/bin/bash
set -e

# Define image name
IMAGE_NAME="vulnmng:latest"
TARGET="." # Scan self

echo "Running E2E Test..."

# 1. Run Scan using the Docker image
# Mount current dir to /app/code to scan it
docker run --rm \
    -v $(pwd):/scan_target \
    -v $(pwd):/app/output \
    $IMAGE_NAME python -m vulnmng.cli scan /scan_target --json-path /app/output/issues.json

# 1.1 Run Scan against a public docker image (needs docker socket if grype uses docker daemon, or grype can pull if it has net access)
# Note: For this to work in dind, we need to handle docker socket. 
# Simplification: Grype can inspect a tarball or remote Registry if network is available.
# We will assume network access for "postgres:alpine"
docker run --rm \
    -v $(pwd):/app/output \
    $IMAGE_NAME python -m vulnmng.cli scan "registry:postgres:alpine" --json-path /app/output/issues.json

# 1.2 Generate Report
docker run --rm \
    -v $(pwd):/app/output \
    $IMAGE_NAME python -m vulnmng.cli report --json-path /app/output/issues.json --format-md /app/output/report.md --format-csv /app/output/report.csv


# 2. Verify Outputs
if [ -f "report.md" ]; then
    echo "SUCCESS: report.md generated"
else
    echo "FAILURE: report.md not found"
    exit 1
fi

if [ -f "issues.json" ]; then
    echo "SUCCESS: issues.json generated"
else
    echo "FAILURE: issues.json not found"
    exit 1
fi

echo "E2E Test Passed!"
