# Build argument for vulnmng version - can be overridden during build
# This will be updated by the sync script for versioned releases
ARG VULNMNG_VERSION=latest
FROM ghcr.io/scribe-security/vulnmng:${VULNMNG_VERSION}

# The base image already contains the vulnmng CLI and its dependencies.
# We only need to add the action-specific entrypoint script.

COPY entrypoint.sh /entrypoint.sh

# Ensure the entrypoint is executable
RUN chmod +x /entrypoint.sh

# The base image might have its own ENTRYPOINT, we override it for the action
ENTRYPOINT ["/entrypoint.sh"]
