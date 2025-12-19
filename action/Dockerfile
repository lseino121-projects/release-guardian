FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    git \
  && rm -rf /var/lib/apt/lists/*

# Install Trivy via APT repo (deterministic)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg lsb-release \
  && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
     > /etc/apt/sources.list.d/trivy.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends trivy \
  && rm -rf /var/lib/apt/lists/*

RUN trivy --version
WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
COPY rg /app/rg

RUN chmod +x /app/entrypoint.sh

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

ENTRYPOINT ["/app/entrypoint.sh"]
