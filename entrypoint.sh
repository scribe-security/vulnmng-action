#!/bin/bash
set -e

# Function to append flags
add_flag() {
  local flag_name=$1
  local input_val=$2
  if [ -n "$input_val" ]; then
    CLI_ARGS="${CLI_ARGS} ${flag_name} ${input_val}"
  fi
}

COMMAND="${INPUT_COMMAND:-scan}"
CLI_ARGS=""

# Common flags
add_flag "--json-path" "${INPUT_JSON_PATH}"
add_flag "--git-root" "${INPUT_GIT_ROOT}"
add_flag "--git-branch" "${INPUT_GIT_BRANCH}"
add_flag "--git-token" "${INPUT_GIT_TOKEN}"
add_flag "--target-name" "${INPUT_TARGET_NAME}"

# Fallback for GITHUB_TOKEN environment variable
if [ -n "$INPUT_GIT_TOKEN" ]; then
  export GITHUB_TOKEN="$INPUT_GIT_TOKEN"
fi

if [ "$COMMAND" = "scan" ]; then
  # Scan specific flags
  if [ -n "${INPUT_TARGET}" ]; then
    CLI_ARGS="${CLI_ARGS} ${INPUT_TARGET}"
  fi
  add_flag "--fail-on" "${INPUT_FAIL_ON}"
  
elif [ "$COMMAND" = "report" ]; then
  # Report specific flags
  add_flag "--target" "${INPUT_TARGET}"
  add_flag "--format-md" "${INPUT_FORMAT_MD}"
  add_flag "--format-csv" "${INPUT_FORMAT_CSV}"
fi

# Extra arguments
if [ -n "${INPUT_EXTRA_ARGS}" ]; then
  CLI_ARGS="${CLI_ARGS} ${INPUT_EXTRA_ARGS}"
fi

echo "Running: vulnmng ${COMMAND} ${CLI_ARGS}"

# Execute vulnmng
# Assuming vulnmng is available in the path as 'python -m vulnmng.cli' or similar
# Based on the root Dockerfile, it's 'python -m vulnmng.cli'
python -m vulnmng.cli ${COMMAND} ${CLI_ARGS}

# Set outputs for GitHub Actions
if [ -n "${INPUT_JSON_PATH}" ]; then
  echo "json-path=${INPUT_JSON_PATH}" >> "$GITHUB_OUTPUT"
fi
if [ -n "${INPUT_FORMAT_MD}" ]; then
  echo "report-md=${INPUT_FORMAT_MD}" >> "$GITHUB_OUTPUT"
fi
if [ -n "${INPUT_FORMAT_CSV}" ]; then
  echo "report-csv=${INPUT_FORMAT_CSV}" >> "$GITHUB_OUTPUT"
fi
