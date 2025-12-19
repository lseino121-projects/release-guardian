FROM python:3.12-slim

# Base utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    git \
  && rm -rf /var/lib/apt/lists/*

# Install Trivy (pinned) via GitHub Release .deb
# Works even when Debian codename (e.g., trixie) isn't supported by the Trivy APT repo.
ARG TRIVY_VERSION=0.57.1

RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64)  deb_arch="64bit" ;; \
    arm64)  deb_arch="ARM64" ;; \
    *) echo "Unsupported arch: $arch"; exit 1 ;; \
  esac; \
  curl -fsSL -o /tmp/trivy.deb \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${deb_arch}.deb"; \
  apt-get update; \
  apt-get install -y --no-install-recommends /tmp/trivy.deb; \
  rm -f /tmp/trivy.deb; \
  rm -rf /var/lib/apt/lists/*

# Fail fast if install didn't work
RUN trivy --version

WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
COPY rg /app/rg

RUN chmod +x /app/entrypoint.sh

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

ENTRYPOINT ["/app/entrypoint.sh"]
