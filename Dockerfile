FROM python:3.13-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache curl bash git

# Install Tools (Grype)
COPY scripts/install_tools.sh /tmp/install_tools.sh
RUN sh /tmp/install_tools.sh

# Install Dependencies
# In a real project we would use requirements.txt or pyproject.toml
# For this MVP we install minimal deps directly
RUN pip install pydantic requests

# Copy Source
COPY vulnmng /app/vulnmng

# Set PYTHONPATH
ENV PYTHONPATH=/app

# Entrypoint
ENTRYPOINT ["python", "-m", "vulnmng.cli"]
