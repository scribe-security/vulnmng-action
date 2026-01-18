#!/bin/bash
set -e

# Debug: show what's happening
if [ "${VULNMNG_DEBUG}" = "true" ]; then
  set -x
  echo "--- Environment Variables ---"
  env | grep "^INPUT_" | sort
fi

# Function to get input value robustly
get_input() {
  local name=$1
  # Try Underscore version (standard)
  local var_name="INPUT_${name^^}"
  var_name="${var_name//-/_}"
  local val=$(printenv "$var_name")
  if [ -n "$val" ]; then
    echo "$val"
    return
  fi
  # Try Hyphenated version (fallback)
  local var_name_hyphen="INPUT_${name^^}"
  local val_hyphen=$(printenv "$var_name_hyphen")
  if [ -n "$val_hyphen" ]; then
    echo "$val_hyphen"
    return
  fi
}

# Function to append flags
add_flag() {
  local flag_name=$1
  local input_name=$2
  local input_val=$(get_input "$input_name")
  
  if [ -n "$input_val" ]; then
    CLI_ARGS="${CLI_ARGS} ${flag_name} ${input_val}"
  fi
}

COMMAND=$(get_input "command")
COMMAND="${COMMAND:-scan}"
CLI_ARGS=""

# Common flags
add_flag "--json-path" "json-path"
add_flag "--git-root" "git-root"
add_flag "--git-branch" "git-branch"
add_flag "--git-token" "git-token"
add_flag "--target-name" "target-name"

# Fallback for GITHUB_TOKEN environment variable
GIT_TOKEN=$(get_input "git-token")
if [ -n "$GIT_TOKEN" ]; then
  export GITHUB_TOKEN="$GIT_TOKEN"
fi

if [ "$COMMAND" = "scan" ]; then
  # Scan specific flags
  add_flag "--fail-on" "fail-on"
  add_flag "--enrichment" "enrichment"
  
  # Target positional argument must come LAST
  TARGET=$(get_input "target")
  if [ -n "$TARGET" ]; then
    CLI_ARGS="${CLI_ARGS} ${TARGET}"
  fi
  
elif [ "$COMMAND" = "report" ]; then
  # Report specific flags
  add_flag "--target" "target"
  add_flag "--format-md" "format-md"
  add_flag "--format-csv" "format-csv"
  add_flag "--enrichment" "enrichment"
fi

# Extra arguments
EXTRA_ARGS=$(get_input "extra-args")
if [ -n "${EXTRA_ARGS}" ]; then
  CLI_ARGS="${CLI_ARGS} ${EXTRA_ARGS}"
fi

echo "Running: vulnmng ${COMMAND}${CLI_ARGS}"

# Execute vulnmng
python -m vulnmng.cli ${COMMAND} ${CLI_ARGS}

# Set outputs for GitHub Actions
JSON_PATH=$(get_input "json-path")
if [ -n "${JSON_PATH}" ]; then
  echo "json-path=${JSON_PATH}" >> "$GITHUB_OUTPUT"
fi
FORMAT_MD=$(get_input "format-md")
if [ -n "${FORMAT_MD}" ]; then
  echo "report-md=${FORMAT_MD}" >> "$GITHUB_OUTPUT"
fi
FORMAT_CSV=$(get_input "format-csv")
if [ -n "${FORMAT_CSV}" ]; then
  echo "report-csv=${FORMAT_CSV}" >> "$GITHUB_OUTPUT"
fi
