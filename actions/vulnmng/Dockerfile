FROM ghcr.io/scribe-security/vulnmng:latest

# The base image already contains the vulnmng CLI and its dependencies.
# We only need to add the action-specific entrypoint script.

COPY entrypoint.sh /entrypoint.sh

# Ensure the entrypoint is executable
RUN chmod +x /entrypoint.sh

# The base image might have its own ENTRYPOINT, we override it for the action
ENTRYPOINT ["/entrypoint.sh"]
