FROM python:3.12-slim

# Base utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy action code
COPY entrypoint.sh /app/entrypoint.sh
COPY rg /app/rg

# Ensure entrypoint is executable
RUN chmod +x /app/entrypoint.sh

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/entrypoint.sh"]
