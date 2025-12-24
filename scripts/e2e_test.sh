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
    $IMAGE_NAME scan /scan_target --json-path /app/output/issues.json

# 1.1 Run Scan against a public docker image
docker run --rm \
    -v $(pwd):/app/output \
    $IMAGE_NAME scan "registry:postgres:alpine" --json-path /app/output/issues.json

# 1.2 Generate Report
docker run --rm \
    -v $(pwd):/app/output \
    $IMAGE_NAME report --json-path /app/output/issues.json --format-md /app/output/report.md --format-csv /app/output/report.csv


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
