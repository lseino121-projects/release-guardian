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
ARG SYFT_VERSION=1.6.0
ARG GRYPE_VERSION=0.79.2
ARG SEMGREP_VERSION=1.146.0

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

RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64)  bin_arch="amd64" ;; \
    arm64)  bin_arch="arm64" ;; \
    *) echo "Unsupported arch: $arch"; exit 1 ;; \
  esac; \
  curl -fsSL -o /tmp/syft.tgz \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${bin_arch}.tar.gz"; \
  tar -xzf /tmp/syft.tgz -C /tmp syft; \
  mv /tmp/syft /usr/local/bin/syft; \
  chmod +x /usr/local/bin/syft; \
  rm -f /tmp/syft.tgz

RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64)  bin_arch="amd64" ;; \
    arm64)  bin_arch="arm64" ;; \
    *) echo "Unsupported arch: $arch"; exit 1 ;; \
  esac; \
  curl -fsSL -o /tmp/grype.tgz \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${bin_arch}.tar.gz"; \
  tar -xzf /tmp/grype.tgz -C /tmp grype; \
  mv /tmp/grype /usr/local/bin/grype; \
  chmod +x /usr/local/bin/grype; \
  rm -f /tmp/grype.tgz

RUN python -m pip install --no-cache-dir --upgrade pip \
  && python -m pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
  && semgrep --version

COPY action/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
COPY rg /app/rg

RUN chmod +x /app/entrypoint.sh

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

ENTRYPOINT ["/app/entrypoint.sh"]
