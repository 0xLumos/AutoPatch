# AutoPatch — SBOM-Guided Automated Remediation
#
# Reproducible runtime image. Pinned dependency versions match what the
# paper experiments and integration tests rely on. Build:
#     docker build -t autopatch:dev .
#
# The image runs as a non-root user. To use the container against the
# host docker daemon, mount the docker socket:
#     docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
#         -v "$PWD":/workspace autopatch:dev \
#         python -m src.main --dockerfile /workspace/Dockerfile ...
FROM python:3.12-slim-bookworm

ARG TRIVY_VERSION=0.72.0
ARG COSIGN_VERSION=2.4.1
ARG GRYPE_VERSION=0.117.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System dependencies (curl for installer scripts, docker CLI for sibling
# container ops, git for --create-pr workflows, tcpdump for the optional
# network-monitor module). We do NOT install the docker daemon; the
# operator mounts the host socket.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
        tcpdump \
        docker.io \
    && rm -rf /var/lib/apt/lists/*

# Pinned scanner binaries.
RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        | tar -xz -C /usr/local/bin trivy \
    && curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
        | tar -xz -C /usr/local/bin grype \
    && curl -fsSL -o /usr/local/bin/cosign "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
    && chmod +x /usr/local/bin/cosign

WORKDIR /opt/autopatch

# Install Python dependencies first for layer caching.
COPY pyproject.toml /opt/autopatch/
COPY requirements.txt /opt/autopatch/
RUN pip install --upgrade pip setuptools wheel \
    && pip install --requirement /opt/autopatch/requirements.txt

# Application source.
COPY src/ /opt/autopatch/src/
COPY README.md LICENSE /opt/autopatch/

# Non-root runtime user.
RUN useradd --create-home --shell /usr/sbin/nologin autopatch \
    && chown -R autopatch:autopatch /opt/autopatch
USER autopatch
WORKDIR /workspace

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]
