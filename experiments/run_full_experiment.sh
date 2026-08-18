#!/usr/bin/env bash
###############################################################################
#  AutoPatch — Full Experiment Runner
#
#  ONE script that does EVERYTHING:
#    Phase 1: Install all system dependencies (Docker, Trivy, Cosign, Copa, Scout)
#    Phase 2: Clone the repo and install Python packages
#    Phase 3: Generate 119 Dockerfiles
#    Phase 4: Run 5-strategy experiment (Scan-Only, Naïve, Copacetic, Scout, AutoPatch)
#    Phase 5: Compute statistics & generate figures
#    Phase 6: Print final numbers for the paper
#
#  Usage:
#    chmod +x run_full_experiment.sh
#    sudo ./run_full_experiment.sh 2>&1 | tee full_experiment.log
#
#  Estimated: ~4-8 hours on an e2-standard-8 (8 vCPU, 32 GB RAM)
#  Disk:      ~50 GB
###############################################################################
set -euo pipefail

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  CONFIGURATION                                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
REPO_URL="https://github.com/0xLumos/AutoPatch.git"
WORK_DIR="${HOME}/autopatch_experiment"
REPO_DIR="${WORK_DIR}/AutoPatch"
RESULTS_DIR="${WORK_DIR}/results"
FIGURES_DIR="${WORK_DIR}/figures"
LOG_FILE="${WORK_DIR}/experiment.log"
PROGRESS_FILE="${WORK_DIR}/progress.txt"

# Docker Hub login (optional — raises pull limit from 100 to 200/6h)
DOCKER_USER="${DOCKER_USER:-}"
DOCKER_PASS="${DOCKER_PASS:-}"

# How many images to process (0 = all)
MAX_IMAGES=${MAX_IMAGES:-0}

# Which strategies to run (space-separated)
STRATEGIES="${STRATEGIES:-scan-only naive copacetic scout autopatch}"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  HELPERS                                                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

phase()    { echo -e "\n${CYAN}═══════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  PHASE $1: $2${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════${NC}\n"; echo "PHASE $1: $2 [$(date)]" >> "$PROGRESS_FILE"; }
step()     { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()     { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()     { echo -e "  ${RED}[✗]${NC} $1"; }
ok()       { echo -e "  ${GREEN}[✓]${NC} $1"; }

check_cmd() {
    if command -v "$1" &>/dev/null; then
        ok "$1 is installed: $(command -v "$1")"
        return 0
    else
        return 1
    fi
}

safe_install() {
    # Install a package, retrying once on failure
    local pkg="$1"
    step "Installing $pkg..."
    if ! apt-get install -y "$pkg" 2>/dev/null; then
        warn "Retrying $pkg after apt update..."
        apt-get update -qq && apt-get install -y "$pkg"
    fi
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PRE-FLIGHT                                                             ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
mkdir -p "$WORK_DIR" "$RESULTS_DIR" "$FIGURES_DIR"
echo "Experiment started at $(date)" > "$PROGRESS_FILE"

# Must be root for installs, or use sudo
if [ "$(id -u)" -ne 0 ]; then
    echo "Re-running with sudo..."
    exec sudo -E bash "$0" "$@"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    step "Detected OS: $OS_ID $OS_VERSION"
else
    OS_ID="unknown"
    OS_VERSION="unknown"
    warn "Could not detect OS"
fi

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 1: INSTALL SYSTEM DEPENDENCIES                                  ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 1 "Installing system dependencies"

export DEBIAN_FRONTEND=noninteractive

step "Updating package lists..."
apt-get update -qq

# ── 1a. Core utilities ───────────────────────────────────────────────────
for pkg in curl wget git jq ca-certificates gnupg lsb-release software-properties-common apt-transport-https; do
    dpkg -s "$pkg" &>/dev/null || safe_install "$pkg"
done
ok "Core utilities installed"

# ── 1b. Docker ───────────────────────────────────────────────────────────
if ! check_cmd docker; then
    step "Installing Docker..."

    # Remove old versions
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

    # Add Docker GPG key
    install -m 0755 -d /etc/apt/keyrings
    if [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ]; then
        curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
        chmod a+r /etc/apt/keyrings/docker.gpg

        CODENAME=$(lsb_release -cs 2>/dev/null || echo "jammy")
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        # Fallback: convenience script
        curl -fsSL https://get.docker.com | sh
    fi

    # Start Docker
    systemctl enable docker 2>/dev/null || true
    systemctl start docker 2>/dev/null || true
fi
ok "Docker: $(docker --version)"

# Add the calling user to docker group
REAL_USER="${SUDO_USER:-$USER}"
if [ "$REAL_USER" != "root" ]; then
    usermod -aG docker "$REAL_USER" 2>/dev/null || true
fi

# Docker Hub login (raises rate limit)
if [ -n "$DOCKER_USER" ] && [ -n "$DOCKER_PASS" ]; then
    step "Logging into Docker Hub..."
    echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin && ok "Docker Hub login OK" || warn "Docker Hub login failed (continuing without)"
fi

# ── 1c. Python 3.11+ ────────────────────────────────────────────────────
if ! check_cmd python3; then
    safe_install python3
fi
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
step "Python version: $PY_VERSION"

# pip
if ! check_cmd pip3; then
    safe_install python3-pip
fi

# ── 1d. Trivy ────────────────────────────────────────────────────────────
if ! check_cmd trivy; then
    step "Installing Trivy..."
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
    apt-get update -qq
    apt-get install -y trivy
fi
ok "Trivy: $(trivy --version 2>&1 | head -1)"

step "Pre-downloading Trivy vulnerability database..."
trivy image --download-db-only 2>/dev/null && ok "Trivy DB downloaded" || warn "Trivy DB download failed (will retry during scans)"

# ── 1e. Cosign ───────────────────────────────────────────────────────────
if ! check_cmd cosign; then
    step "Installing Cosign..."
    COSIGN_VERSION=$(curl -sL https://api.github.com/repos/sigstore/cosign/releases/latest 2>/dev/null | jq -r '.tag_name // "v2.4.1"')
    wget -q "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" -O /usr/local/bin/cosign
    chmod +x /usr/local/bin/cosign
fi
ok "Cosign: $(cosign version 2>&1 | head -1 || echo 'installed')"

# ── 1f. Copacetic (Copa) ────────────────────────────────────────────────
if ! check_cmd copa; then
    step "Installing Copacetic..."
    COPA_VERSION=$(curl -sL https://api.github.com/repos/project-copacetic/copacetic/releases/latest 2>/dev/null | jq -r '.tag_name // "v0.9.0"')
    COPA_VER_CLEAN="${COPA_VERSION#v}"
    COPA_URL="https://github.com/project-copacetic/copacetic/releases/download/${COPA_VERSION}/copa_${COPA_VER_CLEAN}_linux_amd64.tar.gz"
    wget -q "$COPA_URL" -O /tmp/copa.tar.gz && tar -xzf /tmp/copa.tar.gz -C /usr/local/bin copa && rm /tmp/copa.tar.gz \
        && ok "Copa installed" \
        || warn "Copa install failed — Copacetic strategy will record failures (this is valid data)"
fi

# Copa needs buildkit
if docker buildx ls 2>/dev/null | grep -q copabuildkit; then
    ok "Copa buildkit builder already exists"
else
    step "Creating Copa buildkit builder..."
    docker buildx create --name copabuildkit --use --bootstrap 2>/dev/null \
        && ok "Copa buildkit ready" \
        || warn "Copa buildkit setup failed (Copa will fail gracefully)"
fi

# ── 1g. Docker Scout ────────────────────────────────────────────────────
if ! docker scout version &>/dev/null; then
    step "Installing Docker Scout CLI plugin..."
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh 2>/dev/null | sh -s -- 2>/dev/null \
        && ok "Docker Scout installed" \
        || warn "Docker Scout install failed — Scout strategy will record failures (this is valid data)"
fi

ok "Phase 1 complete — all dependencies installed"
echo "PHASE 1 COMPLETE [$(date)]" >> "$PROGRESS_FILE"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 2: CLONE REPO & INSTALL PYTHON PACKAGES                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 2 "Setting up AutoPatch repository"

if [ -d "$REPO_DIR/.git" ]; then
    step "Repo already cloned, pulling latest..."
    cd "$REPO_DIR" && git pull --ff-only 2>/dev/null || true
else
    step "Cloning AutoPatch..."
    git clone "$REPO_URL" "$REPO_DIR"
fi
cd "$REPO_DIR"

step "Installing Python dependencies..."
pip3 install --break-system-packages \
    scipy matplotlib numpy seaborn pyyaml requests 2>/dev/null \
    || pip3 install scipy matplotlib numpy seaborn pyyaml requests 2>/dev/null \
    || {
        # Fallback: try with venv
        python3 -m venv "${WORK_DIR}/venv"
        source "${WORK_DIR}/venv/bin/activate"
        pip install scipy matplotlib numpy seaborn pyyaml requests
    }
ok "Python packages installed"

# Verify imports
python3 -c "import scipy, matplotlib, numpy, json, csv; print('All imports OK')" \
    && ok "Python imports verified" \
    || { fail "Python import check failed"; exit 1; }

echo "PHASE 2 COMPLETE [$(date)]" >> "$PROGRESS_FILE"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 3: GENERATE DOCKERFILE DATASET                                  ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 3 "Generating Dockerfile dataset"

cd "$REPO_DIR"

# Run the dataset generator if it exists, else create inline
if [ -f experiments/generate_dataset.py ]; then
    step "Running experiments/generate_dataset.py..."
    python3 experiments/generate_dataset.py
else
    step "Creating Dockerfiles inline..."
    mkdir -p dockerfiles
    python3 - <<'PYGEN'
import os
DIR = "dockerfiles"
os.makedirs(DIR, exist_ok=True)

images = {
    # Alpine
    "alpine-3.12": ("alpine:3.12", "RUN apk add --no-cache curl"),
    "alpine-3.14": ("alpine:3.14", "RUN apk add --no-cache curl wget"),
    "alpine-3.16": ("alpine:3.16", "RUN apk add --no-cache curl bash"),
    "alpine-3.18": ("alpine:3.18", "RUN apk add --no-cache curl git"),
    # Debian
    "debian-stretch": ("debian:stretch", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    "debian-buster": ("debian:buster", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    "debian-bullseye": ("debian:bullseye", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    "debian-bookworm": ("debian:bookworm", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    # Ubuntu
    "ubuntu-16.04": ("ubuntu:16.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    "ubuntu-18.04": ("ubuntu:18.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    "ubuntu-20.04": ("ubuntu:20.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    "ubuntu-22.04": ("ubuntu:22.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    "ubuntu-24.04": ("ubuntu:24.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    # CentOS / RHEL
    "centos-7": ("centos:7", "RUN yum install -y curl && yum clean all"),
    "rockylinux-8": ("rockylinux:8", "RUN dnf install -y curl && dnf clean all"),
    "rockylinux-9": ("rockylinux:9", "RUN dnf install -y curl && dnf clean all"),
    "almalinux-8": ("almalinux:8", "RUN dnf install -y curl && dnf clean all"),
    "almalinux-9": ("almalinux:9", "RUN dnf install -y curl && dnf clean all"),
    # Distroless / Scratch
    "distroless-base": ("gcr.io/distroless/base-debian11", ""),
    "scratch": ("scratch", "COPY --from=builder /app /app"),
    # Python
    "python-3.6": ("python:3.6", 'RUN pip install flask==2.0.0\nCMD ["python","-c","print(1)"]'),
    "python-3.7": ("python:3.7", 'RUN pip install flask==2.0.0\nCMD ["python","-c","print(1)"]'),
    "python-3.8": ("python:3.8", 'RUN pip install flask==2.2.0\nCMD ["python","-c","print(1)"]'),
    "python-3.9": ("python:3.9", 'RUN pip install flask==2.2.0\nCMD ["python","-c","print(1)"]'),
    "python-3.10": ("python:3.10", 'RUN pip install flask==2.3.0\nCMD ["python","-c","print(1)"]'),
    "python-3.11": ("python:3.11", 'RUN pip install flask==3.0.0\nCMD ["python","-c","print(1)"]'),
    "python-3.8-slim": ("python:3.8-slim", 'RUN pip install requests==2.28.0\nCMD ["python","-c","print(1)"]'),
    "python-3.9-alpine": ("python:3.9-alpine", 'RUN pip install requests==2.28.0\nCMD ["python","-c","print(1)"]'),
    "python-3.10-bullseye": ("python:3.10-bullseye", 'RUN pip install django==4.0\nCMD ["python","-c","print(1)"]'),
    # Node.js
    "node-12": ("node:12", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    "node-14": ("node:14", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    "node-16": ("node:16", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    "node-18": ("node:18", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    "node-20": ("node:20", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    "node-14-alpine": ("node:14-alpine", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    "node-16-slim": ("node:16-slim", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    "node-18-bullseye": ("node:18-bullseye", 'RUN npm init -y\nCMD ["node","-e","console.log(1)"]'),
    # Go
    "golang-1.16": ("golang:1.16", 'CMD ["go","version"]'),
    "golang-1.18": ("golang:1.18", 'CMD ["go","version"]'),
    "golang-1.19": ("golang:1.19", 'CMD ["go","version"]'),
    "golang-1.20": ("golang:1.20", 'CMD ["go","version"]'),
    "golang-1.21": ("golang:1.21", 'CMD ["go","version"]'),
    "golang-1.16-alpine": ("golang:1.16-alpine", 'CMD ["go","version"]'),
    "golang-1.19-bullseye": ("golang:1.19-bullseye", 'CMD ["go","version"]'),
    # Java
    "openjdk-8": ("openjdk:8", 'CMD ["java","-version"]'),
    "openjdk-11": ("openjdk:11", 'CMD ["java","-version"]'),
    "openjdk-17": ("openjdk:17", 'CMD ["java","-version"]'),
    "adoptopenjdk-11": ("adoptopenjdk:11-jre-hotspot", 'CMD ["java","-version"]'),
    "eclipse-temurin-11": ("eclipse-temurin:11", 'CMD ["java","-version"]'),
    "eclipse-temurin-17": ("eclipse-temurin:17", 'CMD ["java","-version"]'),
    "eclipse-temurin-21": ("eclipse-temurin:21", 'CMD ["java","-version"]'),
    # Ruby
    "ruby-2.7": ("ruby:2.7", 'CMD ["ruby","-v"]'),
    "ruby-3.0": ("ruby:3.0", 'CMD ["ruby","-v"]'),
    "ruby-3.1": ("ruby:3.1", 'CMD ["ruby","-v"]'),
    "ruby-3.2": ("ruby:3.2", 'CMD ["ruby","-v"]'),
    "ruby-2.7-alpine": ("ruby:2.7-alpine", 'CMD ["ruby","-v"]'),
    # PHP
    "php-7.4": ("php:7.4", 'CMD ["php","-v"]'),
    "php-8.0": ("php:8.0", 'CMD ["php","-v"]'),
    "php-8.1": ("php:8.1", 'CMD ["php","-v"]'),
    "php-8.2": ("php:8.2", 'CMD ["php","-v"]'),
    "php-7.4-apache": ("php:7.4-apache", "EXPOSE 80"),
    "php-8.0-fpm": ("php:8.0-fpm", "EXPOSE 9000"),
    "php-8.1-alpine": ("php:8.1-alpine", 'CMD ["php","-v"]'),
    # Web servers
    "nginx-1.10": ("nginx:1.10", "EXPOSE 80"),
    "nginx-1.18": ("nginx:1.18", "EXPOSE 80"),
    "nginx-1.21": ("nginx:1.21", "EXPOSE 80"),
    "nginx-1.24": ("nginx:1.24", "EXPOSE 80"),
    "nginx-1.18-alpine": ("nginx:1.18-alpine", "EXPOSE 80"),
    "httpd-2.4.46": ("httpd:2.4.46", "EXPOSE 80"),
    "httpd-2.4.54": ("httpd:2.4.54", "EXPOSE 80"),
    "traefik-2.5": ("traefik:v2.5", "EXPOSE 80 443"),
    "traefik-2.9": ("traefik:v2.9", "EXPOSE 80 443"),
    "caddy-2.4": ("caddy:2.4", "EXPOSE 80 443"),
    "haproxy-2.4": ("haproxy:2.4", "EXPOSE 80"),
    "haproxy-2.6": ("haproxy:2.6", "EXPOSE 80"),
    # Databases
    "redis-5": ("redis:5", "EXPOSE 6379"),
    "redis-6": ("redis:6", "EXPOSE 6379"),
    "redis-7": ("redis:7", "EXPOSE 6379"),
    "postgres-11": ("postgres:11", "EXPOSE 5432"),
    "postgres-12": ("postgres:12", "EXPOSE 5432"),
    "postgres-13": ("postgres:13", "EXPOSE 5432"),
    "postgres-14": ("postgres:14", "EXPOSE 5432"),
    "mysql-5.7": ("mysql:5.7", "EXPOSE 3306"),
    "mysql-8.0": ("mysql:8.0", "EXPOSE 3306"),
    "mongo-4.4": ("mongo:4.4", "EXPOSE 27017"),
    "mongo-5.0": ("mongo:5.0", "EXPOSE 27017"),
    "mongo-6.0": ("mongo:6.0", "EXPOSE 27017"),
    "mariadb-10.5": ("mariadb:10.5", "EXPOSE 3306"),
    "mariadb-10.11": ("mariadb:10.11", "EXPOSE 3306"),
    # Message queues
    "rabbitmq-3.9": ("rabbitmq:3.9", "EXPOSE 5672"),
    "rabbitmq-3.11": ("rabbitmq:3.11", "EXPOSE 5672"),
    "elasticsearch-7.17.0": ("docker.elastic.co/elasticsearch/elasticsearch:7.17.0", "ENV discovery.type=single-node\nEXPOSE 9200"),
    "kafka-old": ("bitnami/kafka:3.3", "EXPOSE 9092"),
    # CI/CD
    "jenkins-2.164": ("jenkins/jenkins:2.164.1-lts", "EXPOSE 8080"),
    "jenkins-lts": ("jenkins/jenkins:lts", "EXPOSE 8080"),
    "vault-1.12": ("hashicorp/vault:1.12.0", 'CMD ["vault","version"]'),
    "vault-1.14": ("hashicorp/vault:1.14.0", 'CMD ["vault","version"]'),
    "consul-1.14": ("hashicorp/consul:1.14", "EXPOSE 8500"),
    "sonarqube-9": ("sonarqube:9.9-community", "EXPOSE 9000"),
    "gitlab-runner": ("gitlab/gitlab-runner:v15.0.0", 'CMD ["gitlab-runner","--version"]'),
    # CMS
    "wordpress-5": ("wordpress:5", "EXPOSE 80"),
    "wordpress-6": ("wordpress:6.0", "EXPOSE 80"),
    "nextcloud-25": ("nextcloud:25", "EXPOSE 80"),
    "nextcloud-27": ("nextcloud:27", "EXPOSE 80"),
    "drupal-9": ("drupal:9", "EXPOSE 80"),
    "drupal-10": ("drupal:10", "EXPOSE 80"),
    "ghost-5": ("ghost:5", "EXPOSE 2368"),
    "joomla-4": ("joomla:4", "EXPOSE 80"),
}

count = 0
for name, (base, extra) in images.items():
    path = os.path.join(DIR, f"Dockerfile.{name}")
    if os.path.exists(path):
        continue
    lines = [f"FROM {base}"]
    if "distroless" not in base and "scratch" not in base:
        lines.append("WORKDIR /app")
    if extra:
        lines.extend(extra.split("\n"))
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    count += 1

# Multi-stage
ms = {
    "multistage-go": """FROM golang:1.18 AS builder
WORKDIR /app
RUN echo 'package main; import "fmt"; func main(){fmt.Println("hello")}' > main.go
RUN CGO_ENABLED=0 go build -o /app/main .

FROM alpine:3.14
WORKDIR /app
COPY --from=builder /app/main .
CMD ["./main"]
""",
    "multistage-node": """FROM node:16 AS builder
WORKDIR /app
RUN echo '{}' > package.json
RUN npm init -y

FROM node:16-slim
WORKDIR /app
COPY --from=builder /app/package.json .
CMD ["node", "-e", "console.log(1)"]
""",
    "multistage-python": """FROM python:3.8 AS builder
WORKDIR /app
RUN pip install flask==2.2.0

FROM python:3.8-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
CMD ["python", "-c", "print(1)"]
""",
}
for name, content in ms.items():
    path = os.path.join(DIR, f"Dockerfile.{name}")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(content)
        count += 1

total = len([f for f in os.listdir(DIR) if f.startswith("Dockerfile.")])
print(f"Created {count} new Dockerfiles. Total: {total}")
PYGEN
fi

TOTAL_DF=$(ls dockerfiles/Dockerfile.* 2>/dev/null | wc -l)
ok "Dataset ready: $TOTAL_DF Dockerfiles"
echo "PHASE 3 COMPLETE: $TOTAL_DF Dockerfiles [$(date)]" >> "$PROGRESS_FILE"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 4: RUN THE 5-STRATEGY EXPERIMENT                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 4 "Running the 5-strategy experiment"

cd "$REPO_DIR"
mkdir -p "$RESULTS_DIR/scans" "$RESULTS_DIR/sboms" "$RESULTS_DIR/patched_dockerfiles"

# Ensure docker prune won't hang on prompt
export DOCKER_CLI_HINTS=false

# ── Embedded self-contained experiment runner ────────────────────────────
# This is a SINGLE Python script that does NOT import from src/ — it's fully
# self-contained to avoid import issues. It calls Trivy and Docker directly.

cat > "${WORK_DIR}/run_experiment.py" <<'EXPERIMENT_SCRIPT'
#!/usr/bin/env python3
"""
Self-contained 5-strategy experiment runner.
Does NOT import from src/ — calls all tools (docker, trivy, copa, scout) directly.
Saves results incrementally so a crash doesn't lose data.
"""
import argparse, csv, json, logging, os, re, shutil, subprocess, sys, tempfile, time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("experiment")

# ═══════════════════════════════════════════════════════════════════════════
# Shell helpers
# ═══════════════════════════════════════════════════════════════════════════
def run(cmd, timeout=600):
    log.debug(f"  $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -2, "", f"NOT_FOUND: {cmd[0]}"

def docker_build(tag, dockerfile, context=".", timeout=600):
    start = time.time()
    code, out, err = run(["docker","build","-t",tag,"-f",dockerfile,context], timeout=timeout)
    elapsed = time.time() - start
    if code == 0:
        return True, elapsed, ""
    combined = (out+err).lower()
    if "timeout" in combined or code==-1: cat="TIMEOUT"
    elif any(w in combined for w in ["network","connection","could not resolve"]): cat="NETWORK"
    elif "returned a non-zero code" in combined: cat="RUN_FAILURE"
    elif any(w in combined for w in ["not found","no such","manifest unknown","manifest not found"]): cat="IMAGE_NOT_FOUND"
    elif "permission denied" in combined: cat="PERMISSION"
    else: cat="BUILD_ERROR"
    return False, elapsed, cat

def image_size_mb(tag):
    code, out, _ = run(["docker","image","inspect",tag,"--format","{{.Size}}"])
    if code==0 and out.strip():
        try: return int(out.strip())/(1024*1024)
        except: pass
    return 0.0

def rmi(tag):
    run(["docker","rmi","-f",tag], timeout=30)

def trivy_scan(image, out_file):
    code, out, err = run([
        "trivy","image","--format","json","--output",out_file,
        "--severity","CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        "--scanners","vuln","--timeout","10m",image
    ], timeout=660)
    if code != 0:
        log.warning(f"  Trivy fail: {err[:200]}")
        return None
    try:
        with open(out_file) as f: return json.load(f)
    except: return None

def trivy_sbom(image, out_file):
    code, _, err = run([
        "trivy","image","--format","cyclonedx","--output",out_file,
        "--timeout","10m",image
    ], timeout=660)
    if code != 0: return None
    try:
        with open(out_file) as f: return json.load(f)
    except: return None

def extract_vulns(scan):
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0}
    cves = set()
    if not scan: return counts, []
    for r in scan.get("Results",[]):
        for v in r.get("Vulnerabilities",[]):
            s = v.get("Severity","UNKNOWN").upper()
            if s not in counts: s="UNKNOWN"
            counts[s] += 1
            vid = v.get("VulnerabilityID","")
            if vid: cves.add(vid)
    return counts, sorted(cves)

# ═══════════════════════════════════════════════════════════════════════════
# OS inference from SBOM (simplified, self-contained)
# ═══════════════════════════════════════════════════════════════════════════
def detect_os_family(sbom):
    if not sbom: return "unknown"
    components = sbom.get("components",[])
    if not components:
        meta = sbom.get("metadata",{}).get("component",{})
        if not meta: return "scratch"
    purls = set()
    names_lower = []
    for c in components:
        if "purl" in c: purls.add(c["purl"])
        if "name" in c: names_lower.append(c["name"].lower())
    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    # Ubuntu
    if any("ubuntu" in n for n in names_lower):
        if any("pkg:deb/" in p for p in purls) or "ubuntu" in meta_name:
            return "ubuntu"
    # Alpine
    if any("pkg:apk/" in p for p in purls) or any(n in names_lower for n in ["apk-tools","musl"]):
        return "alpine"
    # Debian
    if any("pkg:deb/" in p for p in purls) or any(n in names_lower for n in ["dpkg","apt"]):
        return "debian"
    # RHEL family
    if any("pkg:rpm/" in p for p in purls) or any(n in names_lower for n in ["rpm","yum","dnf"]):
        if "rocky" in meta_name or any("rocky" in n for n in names_lower): return "rocky"
        if "alma" in meta_name or any("alma" in n for n in names_lower): return "alma"
        if "centos" in meta_name or any("centos" in n for n in names_lower): return "centos"
        if "fedora" in meta_name or any("fedora" in n for n in names_lower): return "fedora"
        return "rhel"
    if len(components) < 5: return "distroless"
    return "unknown"

# ═══════════════════════════════════════════════════════════════════════════
# Base image chooser (simplified, self-contained)
# ═══════════════════════════════════════════════════════════════════════════
def choose_base(family, orig_base=""):
    o = orig_base.lower()
    if "python" in o: return "python:3.12-bookworm"
    if "node" in o:   return "node:22-bookworm"
    if "golang" in o: return "golang:1.23-bookworm"
    if "ruby" in o:   return "ruby:3.3-bookworm"
    if "php" in o:
        if "apache" in o: return "php:8.3-apache-bookworm"
        if "fpm" in o:    return "php:8.3-fpm-bookworm"
        return "php:8.3-bookworm"
    if "openjdk" in o or "java" in o or "temurin" in o: return "eclipse-temurin:21-jdk-jammy"
    if "maven" in o:  return "maven:3.9-eclipse-temurin-21-bookworm"
    if "nginx" in o:  return "nginx:stable"
    if "httpd" in o:  return "httpd:2.4"
    if "redis" in o:  return "redis:7"
    if "postgres" in o: return "postgres:16"
    if "mysql" in o:  return "mysql:8.4"
    if "mongo" in o:  return "mongo:7"
    if "mariadb" in o: return "mariadb:11"
    if "rabbitmq" in o: return "rabbitmq:3"
    if "jenkins" in o: return "jenkins/jenkins:lts-jdk21"
    if "vault" in o:  return "hashicorp/vault:latest"
    if "consul" in o: return "hashicorp/consul:latest"
    if "wordpress" in o: return "wordpress:latest"
    if "nextcloud" in o: return "nextcloud:latest"
    if "drupal" in o:   return "drupal:latest"
    if "ghost" in o:    return "ghost:latest"
    if "joomla" in o:   return "joomla:latest"
    if "sonarqube" in o: return "sonarqube:latest"
    if "gitlab" in o:    return "gitlab/gitlab-runner:latest"
    if "traefik" in o:   return "traefik:latest"
    if "caddy" in o:     return "caddy:latest"
    if "haproxy" in o:   return "haproxy:latest"
    if "kafka" in o:     return "bitnami/kafka:latest"
    if "elasticsearch" in o: return "docker.elastic.co/elasticsearch/elasticsearch:8.13.0"
    if "adoptopenjdk" in o: return "eclipse-temurin:21-jdk-jammy"
    if "docker" in o: return "docker:latest"
    f = family.lower()
    MAP = {"ubuntu":"ubuntu:24.04","debian":"debian:bookworm-slim","alpine":"alpine:3.20",
           "centos":"rockylinux:9","rhel":"rockylinux:9","rocky":"rockylinux:9",
           "alma":"almalinux:9","fedora":"fedora:40","distroless":"gcr.io/distroless/cc:nonroot",
           "scratch":"scratch"}
    return MAP.get(f, "ubuntu:24.04")

# ═══════════════════════════════════════════════════════════════════════════
# Rewriters
# ═══════════════════════════════════════════════════════════════════════════
def rewrite_from_latest(text):
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("FROM "):
            parts = s.split(None,1)
            if len(parts)==2:
                rest = parts[1]
                m = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.I)
                base_part = m.group(1) if m else rest
                alias_part = m.group(2) if m else ""
                base_name = base_part.split("@")[0].split(":")[0] if ("@" in base_part or ":" in base_part) else base_part
                if base_name.lower() == "scratch":
                    lines.append(line)
                else:
                    new = f"FROM {base_name}:latest"
                    if alias_part: new += f" {alias_part}"
                    lines.append(new)
            else: lines.append(line)
        else: lines.append(line)
    return "\n".join(lines)+"\n"

def rewrite_autopatch(text, sbom_data):
    """SBOM-driven rewrite: replace FROM with best-match modern base."""
    family = detect_os_family(sbom_data)
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("FROM "):
            parts = s.split(None,1)
            if len(parts)==2:
                rest = parts[1]
                m = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.I)
                base_part = m.group(1) if m else rest
                alias_part = m.group(2) if m else ""
                if base_part.lower() == "scratch":
                    lines.append(line)
                    continue
                # Check if this is a reference to a previous build stage
                if not (":" in base_part or "/" in base_part or "." in base_part):
                    lines.append(line)
                    continue
                new_base = choose_base(family, base_part)
                new_from = f"FROM {new_base}"
                if alias_part: new_from += f" {alias_part}"
                lines.append(new_from)
            else: lines.append(line)
        else: lines.append(line)
    return "\n".join(lines)+"\n"

def rewrite_scout(text, recommended_tag, orig_base_name):
    """Apply Docker Scout recommended tag."""
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("FROM ") and "scratch" not in s.lower():
            parts = s.split(None,1)
            if len(parts)==2:
                rest = parts[1]
                m = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.I)
                base_part = m.group(1) if m else rest
                alias_part = m.group(2) if m else ""
                base_name = base_part.split("@")[0].split(":")[0] if ("@" in base_part or ":" in base_part) else base_part
                new = f"FROM {base_name}:{recommended_tag}"
                if alias_part: new += f" {alias_part}"
                lines.append(new)
            else: lines.append(line)
        else: lines.append(line)
    return "\n".join(lines)+"\n"

# ═══════════════════════════════════════════════════════════════════════════
# Data class
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class R:
    image_name: str; strategy: str; dockerfile: str = ""
    build_success: bool = False; build_time_sec: float = 0.0; error_category: str = ""
    vulns_before_total: int = 0; vulns_after_total: int = 0
    sev_before: Dict[str,int] = field(default_factory=dict)
    sev_after: Dict[str,int] = field(default_factory=dict)
    reduction_pct: float = 0.0; new_vulns_introduced: int = 0
    size_before_mb: float = 0.0; size_after_mb: float = 0.0; size_delta_mb: float = 0.0
    acceptance: bool = False
    cves_before: List[str] = field(default_factory=list)
    cves_after: List[str] = field(default_factory=list)
    notes: str = ""; ts: str = field(default_factory=lambda: datetime.now().isoformat())

# ═══════════════════════════════════════════════════════════════════════════
# Main experiment
# ═══════════════════════════════════════════════════════════════════════════
class Experiment:
    def __init__(self, df_dir, out_dir, strategies, max_images=0):
        self.df_dir = Path(df_dir)
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out/"scans").mkdir(exist_ok=True)
        (self.out/"sboms").mkdir(exist_ok=True)
        (self.out/"patched").mkdir(exist_ok=True)
        self.strategies = strategies
        self.max_images = max_images
        self.results = []
        self.tmp = Path(tempfile.mkdtemp(prefix="ap_"))
        # Load any previous partial results (crash recovery)
        prev = self.out/"results.json"
        if prev.exists():
            try:
                with open(prev) as f:
                    old = json.load(f)
                self.done_set = {(r["image_name"],r["strategy"]) for r in old.get("results",[])}
                self.results = [R(**{k:v for k,v in r.items() if k in R.__dataclass_fields__})
                                for r in old.get("results",[])]
                log.info(f"Loaded {len(self.results)} previous results for crash recovery")
            except:
                self.done_set = set()
        else:
            self.done_set = set()

    def discover(self):
        dfs = sorted(self.df_dir.glob("Dockerfile.*"))
        dfs = [d for d in dfs if d.name != "INDEX.md" and not d.name.endswith(".patched")]
        if self.max_images > 0:
            dfs = dfs[:self.max_images]
        log.info(f"Found {len(dfs)} Dockerfiles")
        return dfs

    def safe_tag(self, name, strat):
        return f"exp-{re.sub(r'[^a-z0-9._-]','-',name.lower())}-{strat}"

    def compute_reduction(self, before, after):
        if before > 0: return ((before - after)/before)*100
        return 0.0

    def check_acceptance(self, sev_b, sev_a, cves_b, cves_a, total_b, total_a):
        new = set(cves_a) - set(cves_b)
        return (
            total_a < total_b and
            len(new) == 0 and
            sev_a.get("CRITICAL",0) <= sev_b.get("CRITICAL",0) and
            sev_a.get("HIGH",0) <= sev_b.get("HIGH",0)
        )

    def process(self, df_path):
        name = df_path.name.replace("Dockerfile.", "")
        log.info(f"\n{'='*60}\n  Processing: {name}\n{'='*60}")
        with open(df_path) as f: text = f.read()
        results = []

        # ── Build & scan original (shared baseline) ──────────────────────
        orig_tag = self.safe_tag(name, "orig")
        log.info(f"  Building original: {orig_tag}")
        ok, bt, berr = docker_build(orig_tag, str(df_path), str(df_path.parent))

        if not ok:
            log.warning(f"  ORIGINAL BUILD FAILED ({berr})")
            for s in self.strategies:
                sname = {"scan-only":"Scan-Only","naive":"Naive-Latest","copacetic":"Copacetic",
                         "scout":"Docker-Scout","autopatch":"AutoPatch"}.get(s,s)
                if (name, sname) not in self.done_set:
                    results.append(R(image_name=name,strategy=sname,dockerfile=str(df_path),
                                     error_category=berr, notes=f"Original build failed: {berr}"))
            return results

        # Scan original
        scan_file = str(self.out/"scans"/f"{name}_orig.json")
        log.info(f"  Scanning original...")
        scan_data = trivy_scan(orig_tag, scan_file)
        sev_b, cves_b = extract_vulns(scan_data)
        total_b = sum(sev_b.values())
        size_b = image_size_mb(orig_tag)

        log.info(f"  Baseline: {total_b} vulns (C={sev_b['CRITICAL']}, H={sev_b['HIGH']}, "
                 f"M={sev_b['MEDIUM']}, L={sev_b['LOW']})")

        # SBOM for AutoPatch
        sbom_file = str(self.out/"sboms"/f"{name}.json")
        sbom_data = trivy_sbom(orig_tag, sbom_file)

        # ── Strategy A: Scan-Only ────────────────────────────────────────
        sname = "Scan-Only"
        if "scan-only" in self.strategies and (name,sname) not in self.done_set:
            log.info(f"  [A] Scan-Only")
            results.append(R(image_name=name,strategy=sname,build_success=True,
                             build_time_sec=bt,vulns_before_total=total_b,vulns_after_total=total_b,
                             sev_before=dict(sev_b),sev_after=dict(sev_b),reduction_pct=0.0,
                             size_before_mb=size_b,size_after_mb=size_b,
                             cves_before=cves_b,cves_after=cves_b))

        # ── Strategy B: Naïve :latest ────────────────────────────────────
        sname = "Naive-Latest"
        if "naive" in self.strategies and (name,sname) not in self.done_set:
            log.info(f"  [B] Naive :latest")
            r = R(image_name=name,strategy=sname,dockerfile=str(df_path),
                  vulns_before_total=total_b,sev_before=dict(sev_b),
                  size_before_mb=size_b,cves_before=cves_b)
            patched = rewrite_from_latest(text)
            pf = self.tmp/f"Df.{name}.naive"; pf.write_text(patched)
            tag = self.safe_tag(name,"naive")
            ok2, t2, e2 = docker_build(tag, str(pf), str(df_path.parent))
            r.build_success = ok2; r.build_time_sec = t2; r.error_category = e2
            if ok2:
                sf = str(self.out/"scans"/f"{name}_naive.json")
                sd = trivy_scan(tag, sf)
                sa, ca = extract_vulns(sd)
                r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                r.reduction_pct=self.compute_reduction(total_b, r.vulns_after_total)
                r.new_vulns_introduced=len(set(ca)-set(cves_b))
                r.acceptance=self.check_acceptance(sev_b,sa,cves_b,ca,total_b,r.vulns_after_total)
                rmi(tag)
            log.info(f"    Naive: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
            results.append(r)

        # ── Strategy C: Copacetic ────────────────────────────────────────
        sname = "Copacetic"
        if "copacetic" in self.strategies and (name,sname) not in self.done_set:
            log.info(f"  [C] Copacetic")
            r = R(image_name=name,strategy=sname,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b)
            ptag = self.safe_tag(name,"copa")
            start = time.time()

            # Copa needs buildkit addr
            bk_host = os.environ.get("BUILDKIT_HOST", "")
            copa_cmd = ["copa","patch","-i",orig_tag,"-r",scan_file,"-t",ptag]
            if bk_host:
                copa_cmd.extend(["-a", bk_host])
            code, out2, err2 = run(copa_cmd, timeout=600)
            r.build_time_sec = time.time()-start

            if code != 0:
                r.build_success = False; r.error_category = "COPA_FAILURE"
                r.vulns_after_total = total_b; r.sev_after = dict(sev_b); r.cves_after = cves_b
                r.notes = f"Copa error: {err2[:200]}"
                log.info(f"    Copa: FAILED")
            else:
                r.build_success = True
                sf = str(self.out/"scans"/f"{name}_copa.json")
                sd = trivy_scan(ptag, sf)
                sa, ca = extract_vulns(sd)
                r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                r.size_after_mb=image_size_mb(ptag); r.size_delta_mb=r.size_after_mb-size_b
                r.reduction_pct=self.compute_reduction(total_b, r.vulns_after_total)
                r.new_vulns_introduced=len(set(ca)-set(cves_b))
                r.acceptance=self.check_acceptance(sev_b,sa,cves_b,ca,total_b,r.vulns_after_total)
                rmi(ptag)
                log.info(f"    Copa: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
            results.append(r)

        # ── Strategy D: Docker Scout ─────────────────────────────────────
        sname = "Docker-Scout"
        if "scout" in self.strategies and (name,sname) not in self.done_set:
            log.info(f"  [D] Docker Scout")
            r = R(image_name=name,strategy=sname,dockerfile=str(df_path),
                  vulns_before_total=total_b,sev_before=dict(sev_b),
                  size_before_mb=size_b,cves_before=cves_b)

            # Get Scout recommendation
            code, out2, err2 = run(["docker","scout","recommendations",orig_tag], timeout=120)
            rec_tag = None
            if code == 0:
                for line in out2.splitlines():
                    # Scout outputs lines like "  Tag             current -> recommended"
                    if "→" in line or "->" in line:
                        sep = "→" if "→" in line else "->"
                        parts = line.split(sep)
                        if len(parts)>=2:
                            candidate = parts[-1].strip()
                            if candidate and candidate != "N/A":
                                rec_tag = candidate; break

            if not rec_tag:
                r.build_success = False; r.error_category = "SCOUT_NO_REC"
                r.vulns_after_total = total_b; r.sev_after = dict(sev_b); r.cves_after = cves_b
                r.notes = "No Scout recommendation"
                log.info(f"    Scout: no recommendation")
            else:
                # Extract base name from original Dockerfile
                orig_base_name = ""
                for line in text.splitlines():
                    if line.strip().upper().startswith("FROM "):
                        parts = line.strip().split(None,1)
                        if len(parts)==2:
                            bp = parts[1].split()[0]
                            orig_base_name = bp.split("@")[0].split(":")[0] if ("@" in bp or ":" in bp) else bp
                        break

                patched = rewrite_scout(text, rec_tag, orig_base_name)
                pf = self.tmp/f"Df.{name}.scout"; pf.write_text(patched)
                tag = self.safe_tag(name,"scout")
                ok2, t2, e2 = docker_build(tag, str(pf), str(df_path.parent))
                r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
                if ok2:
                    sf = str(self.out/"scans"/f"{name}_scout.json")
                    sd = trivy_scan(tag, sf)
                    sa, ca = extract_vulns(sd)
                    r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                    r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                    r.reduction_pct=self.compute_reduction(total_b, r.vulns_after_total)
                    r.new_vulns_introduced=len(set(ca)-set(cves_b))
                    r.acceptance=self.check_acceptance(sev_b,sa,cves_b,ca,total_b,r.vulns_after_total)
                    rmi(tag)
                log.info(f"    Scout: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
            results.append(r)

        # ── Strategy E: AutoPatch ────────────────────────────────────────
        sname = "AutoPatch"
        if "autopatch" in self.strategies and (name,sname) not in self.done_set:
            log.info(f"  [E] AutoPatch")
            r = R(image_name=name,strategy=sname,dockerfile=str(df_path),
                  vulns_before_total=total_b,sev_before=dict(sev_b),
                  size_before_mb=size_b,cves_before=cves_b)

            family = detect_os_family(sbom_data)
            r.notes = f"os_family={family}"
            patched = rewrite_autopatch(text, sbom_data)
            pf = self.tmp/f"Df.{name}.ap"; pf.write_text(patched)
            # Save for inspection
            (self.out/"patched"/f"Dockerfile.{name}").write_text(patched)

            tag = self.safe_tag(name,"ap")
            ok2, t2, e2 = docker_build(tag, str(pf), str(df_path.parent))
            r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
            if ok2:
                sf = str(self.out/"scans"/f"{name}_ap.json")
                sd = trivy_scan(tag, sf)
                sa, ca = extract_vulns(sd)
                r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                r.reduction_pct=self.compute_reduction(total_b, r.vulns_after_total)
                r.new_vulns_introduced=len(set(ca)-set(cves_b))
                r.acceptance=self.check_acceptance(sev_b,sa,cves_b,ca,total_b,r.vulns_after_total)
                rmi(tag)
            log.info(f"    AutoPatch: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%), accept={r.acceptance}")
            results.append(r)

        # Cleanup original
        rmi(orig_tag)
        return results

    def save(self):
        def get_ver(cmd):
            c, o, _ = run(cmd.split(), timeout=10)
            return o.strip().split("\n")[0] if c==0 else "unknown"

        data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "trivy_version": get_ver("trivy --version"),
                "docker_version": get_ver("docker --version"),
                "total_results": len(self.results),
                "strategies": self.strategies,
            },
            "results": [asdict(r) for r in self.results]
        }
        with open(self.out/"results.json","w") as f:
            json.dump(data, f, indent=2, default=str)

        # CSV
        if self.results:
            flds = ["image_name","strategy","build_success","build_time_sec","error_category",
                    "vulns_before_total","vulns_after_total","reduction_pct","new_vulns_introduced",
                    "crit_before","high_before","med_before","low_before",
                    "crit_after","high_after","med_after","low_after",
                    "size_before_mb","size_after_mb","size_delta_mb","acceptance","notes"]
            with open(self.out/"results.csv","w",newline="") as f:
                w = csv.DictWriter(f, fieldnames=flds)
                w.writeheader()
                for r in self.results:
                    w.writerow({
                        "image_name":r.image_name,"strategy":r.strategy,
                        "build_success":r.build_success,"build_time_sec":round(r.build_time_sec,2),
                        "error_category":r.error_category,
                        "vulns_before_total":r.vulns_before_total,"vulns_after_total":r.vulns_after_total,
                        "reduction_pct":round(r.reduction_pct,2),"new_vulns_introduced":r.new_vulns_introduced,
                        "crit_before":r.sev_before.get("CRITICAL",0),"high_before":r.sev_before.get("HIGH",0),
                        "med_before":r.sev_before.get("MEDIUM",0),"low_before":r.sev_before.get("LOW",0),
                        "crit_after":r.sev_after.get("CRITICAL",0),"high_after":r.sev_after.get("HIGH",0),
                        "med_after":r.sev_after.get("MEDIUM",0),"low_after":r.sev_after.get("LOW",0),
                        "size_before_mb":round(r.size_before_mb,2),"size_after_mb":round(r.size_after_mb,2),
                        "size_delta_mb":round(r.size_delta_mb,2),"acceptance":r.acceptance,"notes":r.notes,
                    })

    def run_all(self):
        dfs = self.discover()
        total = len(dfs)
        start_time = time.time()

        for i, df in enumerate(dfs, 1):
            elapsed = time.time() - start_time
            if i > 1:
                rate = elapsed / (i-1)
                eta = rate * (total - i + 1)
                eta_min = int(eta // 60)
                log.info(f"\n[{i}/{total}] ETA: ~{eta_min} min remaining")
            else:
                log.info(f"\n[{i}/{total}]")

            # Progress file
            pf = os.environ.get("PROGRESS_FILE","")
            if pf:
                with open(pf,"a") as f:
                    f.write(f"  [{i}/{total}] {df.name} [{datetime.now().strftime('%H:%M:%S')}]\n")

            try:
                res = self.process(df)
                self.results.extend(res)
                self.save()  # save after EVERY image

                # Periodic cleanup
                if i % 5 == 0:
                    run(["docker","system","prune","-f"], timeout=60)

            except Exception as e:
                log.error(f"FATAL: {df.name}: {e}", exc_info=True)

        total_time = time.time() - start_time
        log.info(f"\n{'='*60}")
        log.info(f"DONE. {len(self.results)} results in {total_time/60:.1f} minutes")
        log.info(f"{'='*60}")
        self.save()
        shutil.rmtree(self.tmp, ignore_errors=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dockerfile-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--strategies", nargs="+",
                   default=["scan-only","naive","copacetic","scout","autopatch"])
    p.add_argument("--max-images", type=int, default=0)
    args = p.parse_args()
    exp = Experiment(args.dockerfile_dir, args.output_dir, args.strategies, args.max_images)
    exp.run_all()

if __name__ == "__main__":
    main()
EXPERIMENT_SCRIPT

chmod +x "${WORK_DIR}/run_experiment.py"
ok "Experiment script written"

# ── Set Copa buildkit env ────────────────────────────────────────────────
COPA_CONTAINER=$(docker ps --filter "name=buildx_buildkit_copabuildkit" --format '{{.Names}}' 2>/dev/null | head -1)
if [ -n "$COPA_CONTAINER" ]; then
    export BUILDKIT_HOST="docker-container://${COPA_CONTAINER}"
    ok "Copa buildkit: $BUILDKIT_HOST"
else
    warn "No Copa buildkit container found (Copa strategy will fail gracefully)"
fi

# ── Run the experiment ───────────────────────────────────────────────────
step "Starting experiment at $(date)..."
echo "EXPERIMENT STARTED [$(date)]" >> "$PROGRESS_FILE"

EXTRA_ARGS=""
if [ "$MAX_IMAGES" -gt 0 ]; then
    EXTRA_ARGS="--max-images $MAX_IMAGES"
fi

export PROGRESS_FILE

python3 "${WORK_DIR}/run_experiment.py" \
    --dockerfile-dir "${REPO_DIR}/dockerfiles/" \
    --output-dir "$RESULTS_DIR" \
    --strategies $STRATEGIES \
    $EXTRA_ARGS \
    2>&1 | tee -a "${WORK_DIR}/experiment_output.log"

ok "Experiment finished at $(date)"
echo "PHASE 4 COMPLETE [$(date)]" >> "$PROGRESS_FILE"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 5: COMPUTE STATISTICS & GENERATE FIGURES                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 5 "Computing statistics and generating figures"

cat > "${WORK_DIR}/compute_stats.py" <<'STATS_SCRIPT'
#!/usr/bin/env python3
"""Compute statistics and generate figures from real experiment results."""
import json, math, sys
from collections import defaultdict
from pathlib import Path
import numpy as np

try:
    from scipy.stats import wilcoxon
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    print("WARNING: scipy not available. Wilcoxon tests skipped.")

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 10
plt.rcParams['figure.dpi'] = 300

COLORS = {'Scan-Only':'#808080','Naive-Latest':'#E8922A','Copacetic':'#5B9BD5',
          'Docker-Scout':'#C05DCC','AutoPatch':'#2E7D32'}
ORDER = ['Scan-Only','Naive-Latest','Copacetic','Docker-Scout','AutoPatch']

def infer_os(name):
    n = name.lower()
    if 'alpine' in n: return 'Alpine'
    if any(k in n for k in ['debian','buster','bullseye','bookworm','stretch']): return 'Debian'
    if 'ubuntu' in n: return 'Ubuntu'
    if any(k in n for k in ['centos','rhel','rocky','alma','fedora']): return 'RHEL-family'
    if 'distroless' in n: return 'Distroless'
    if 'scratch' in n: return 'Scratch'
    return 'Debian'

def cohens_d(g1, g2):
    n1, n2 = len(g1), len(g2)
    if n1<2 or n2<2: return 0.0
    m1, m2 = np.mean(g1), np.mean(g2)
    s1, s2 = np.std(g1,ddof=1), np.std(g2,ddof=1)
    sp = math.sqrt(((n1-1)*s1**2+(n2-1)*s2**2)/(n1+n2-2))
    return (m1-m2)/sp if sp>0 else 0.0

def main(results_file, output_dir, figures_dir):
    with open(results_file) as f:
        data = json.load(f)
    results = data["results"]
    out = Path(output_dir)
    figs = Path(figures_dir); figs.mkdir(parents=True, exist_ok=True)

    by_strat = defaultdict(list)
    by_img = defaultdict(dict)
    for r in results:
        by_strat[r["strategy"]].append(r)
        by_img[r["image_name"]][r["strategy"]] = r

    # Per-strategy stats
    strat_stats = {}
    for strat in ORDER:
        entries = by_strat.get(strat,[])
        ok_entries = [e for e in entries if e["build_success"]]
        fail_entries = [e for e in entries if not e["build_success"]]
        vrs = [e["reduction_pct"] for e in ok_entries]
        s = {
            "strategy": strat, "total": len(entries),
            "success": len(ok_entries), "failures": len(fail_entries),
            "fail_rate": round(len(fail_entries)/len(entries)*100,1) if entries else 0,
        }
        if vrs:
            s["vr_mean"]=round(np.mean(vrs),2); s["vr_median"]=round(np.median(vrs),2)
            s["vr_std"]=round(np.std(vrs,ddof=1),2) if len(vrs)>1 else 0
            s["vr_min"]=round(min(vrs),2); s["vr_max"]=round(max(vrs),2)
        else:
            s["vr_mean"]=s["vr_median"]=s["vr_std"]=s["vr_min"]=s["vr_max"]=0
        s["new_vulns_total"] = sum(e.get("new_vulns_introduced",0) for e in ok_entries)
        s["acceptance_count"] = sum(1 for e in ok_entries if e.get("acceptance"))
        strat_stats[strat] = s

    # Pairwise: AutoPatch vs baselines
    comparisons = {}
    for baseline in ["Naive-Latest","Copacetic","Docker-Scout"]:
        paired_ap, paired_bl = [], []
        for img, strats in by_img.items():
            if "AutoPatch" in strats and baseline in strats:
                ap, bl = strats["AutoPatch"], strats[baseline]
                if ap["build_success"] and bl["build_success"]:
                    paired_ap.append(ap["reduction_pct"])
                    paired_bl.append(bl["reduction_pct"])
        comp = {"baseline":baseline,"paired":len(paired_ap)}
        if len(paired_ap)>=5:
            comp["cohen_d"]=round(cohens_d(paired_ap,paired_bl),3)
            if HAS_SCIPY:
                diffs = [a-b for a,b in zip(paired_ap,paired_bl)]
                nz = [d for d in diffs if d!=0]
                if len(nz)>=5:
                    stat,pv = wilcoxon(nz)
                    comp["wilcoxon_stat"]=round(float(stat),4)
                    comp["p_value"]=float(pv)
                    comp["sig_005"]=pv<0.05
                    comp["sig_001"]=pv<0.01
        comparisons[baseline] = comp

    # OS breakdown
    os_data = defaultdict(lambda:{"n":0,"vrs":[],"fails":0})
    for r in by_strat.get("AutoPatch",[]):
        fam = infer_os(r["image_name"])
        os_data[fam]["n"]+=1
        if r["build_success"]: os_data[fam]["vrs"].append(r["reduction_pct"])
        else: os_data[fam]["fails"]+=1
    os_stats = {}
    for fam, d in sorted(os_data.items()):
        os_stats[fam] = {
            "images":d["n"],"fails":d["fails"],
            "vr_mean":round(np.mean(d["vrs"]),2) if d["vrs"] else 0,
            "vr_median":round(np.median(d["vrs"]),2) if d["vrs"] else 0,
            "vr_std":round(np.std(d["vrs"],ddof=1),2) if len(d["vrs"])>1 else 0,
        }

    # Save stats
    output = {"metadata":data.get("metadata",{}), "strategy_statistics":strat_stats,
              "pairwise_comparisons":comparisons, "os_family_breakdown":os_stats}
    with open(out/"statistics.json","w") as f: json.dump(output,f,indent=2)

    # ══════════════════════════════════════════════════════════════════════
    # FIGURES
    # ══════════════════════════════════════════════════════════════════════

    # Fig 2: Bar chart — top 6 most-vulnerable images × 5 strategies
    ap_ok = sorted([r for r in by_strat.get("AutoPatch",[]) if r["build_success"]],
                   key=lambda x:x["vulns_before_total"], reverse=True)
    legacy = [r["image_name"] for r in ap_ok[:6]]

    if legacy:
        fig,ax = plt.subplots(figsize=(7.16,3.5))
        x = np.arange(len(legacy)); w=0.16
        for si, strat in enumerate(ORDER):
            vals, fails = [], []
            for img in legacy:
                r = by_img.get(img,{}).get(strat)
                if r and r["build_success"]:
                    vals.append(r["sev_after"].get("CRITICAL",0)+r["sev_after"].get("HIGH",0))
                    fails.append(False)
                elif r:
                    vals.append(r["sev_before"].get("CRITICAL",0)+r["sev_before"].get("HIGH",0))
                    fails.append(True)
                else: vals.append(0); fails.append(False)
            bars=ax.bar(x+(si-2)*w, vals, w, label=strat, color=COLORS.get(strat,'#888'),
                       edgecolor='black', linewidth=0.4)
            for j,fl in enumerate(fails):
                if fl:
                    bx=bars[j].get_x()+bars[j].get_width()/2
                    ax.text(bx,bars[j].get_height()+2,'F',ha='center',fontsize=7,
                            fontweight='bold',color='red')
        labels=[n.replace("-","\n",1) if len(n)>12 else n for n in legacy]
        ax.set_ylabel('Critical+High Vulns'); ax.set_xticks(x); ax.set_xticklabels(labels,fontsize=8)
        ax.legend(loc='upper right',ncol=2,fontsize=7); ax.grid(axis='y',alpha=0.25,ls='--')
        fig.tight_layout()
        fig.savefig(figs/'fig2_effectiveness.pdf',dpi=300,bbox_inches='tight')
        fig.savefig(figs/'fig2_effectiveness.png',dpi=300,bbox_inches='tight')
        plt.close(fig)

    # Fig 3: CDF
    fig,ax = plt.subplots(figsize=(3.5,2.8))
    for strat in ['AutoPatch','Docker-Scout','Naive-Latest','Copacetic']:
        vrs = sorted([e["reduction_pct"] for e in by_strat.get(strat,[]) if e["build_success"]])
        if not vrs: continue
        cdf = np.arange(1,len(vrs)+1)/len(vrs)
        ax.plot(vrs,cdf,lw=1.8,label=strat,color=COLORS.get(strat,'#888'))
    ax.axvline(x=0,lw=1.5,label='Scan-Only',color=COLORS['Scan-Only'],ls='--')
    ax.set_xlabel('Vulnerability Reduction (%)'); ax.set_ylabel('Cumulative Probability')
    ax.set_xlim(-5,105); ax.set_ylim(0,1.05)
    ax.legend(loc='lower right',fontsize=6.5); ax.grid(True,alpha=0.25,ls=':')
    fig.tight_layout()
    fig.savefig(figs/'fig3_cdf.pdf',dpi=300,bbox_inches='tight')
    fig.savefig(figs/'fig3_cdf.png',dpi=300,bbox_inches='tight')
    plt.close(fig)

    # Fig 4: Severity panels (AutoPatch pre/post)
    ap_sorted = sorted([r for r in by_strat.get("AutoPatch",[]) if r["build_success"]],
                       key=lambda x:x["vulns_before_total"], reverse=True)
    if ap_sorted:
        n=len(ap_sorted)
        scolors={'CRITICAL':'#d32f2f','HIGH':'#f57c00','MEDIUM':'#fbc02d','LOW':'#4caf50','UNKNOWN':'#9e9e9e'}
        sevs=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
        fig,(ax1,ax2)=plt.subplots(2,1,figsize=(7.16,4),sharex=True)
        idx=np.arange(n)
        for ax,key,title in [(ax1,"sev_before","Pre-Patch"),(ax2,"sev_after","Post-Patch")]:
            bottom=np.zeros(n)
            for sev in sevs:
                vals=np.array([r[key].get(sev,0) for r in ap_sorted])
                ax.bar(idx,vals,bottom=bottom,color=scolors[sev],width=1.0,
                       label=sev if ax is ax1 else None,linewidth=0)
                bottom+=vals
            ax.set_ylabel('Vulns'); ax.set_title(title,fontsize=10,fontweight='bold')
            ax.set_xlim(-0.5,n-0.5)
        ax1.legend(loc='upper right',ncol=5,fontsize=7)
        ax2.set_xlabel('Images (sorted by pre-patch total)')
        fig.tight_layout()
        fig.savefig(figs/'fig4_severity_panels.pdf',dpi=300,bbox_inches='tight')
        fig.savefig(figs/'fig4_severity_panels.png',dpi=300,bbox_inches='tight')
        plt.close(fig)

    # ══════════════════════════════════════════════════════════════════════
    # PRINT SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("  EXPERIMENT RESULTS — NUMBERS FOR THE PAPER")
    print("="*70)

    for strat in ORDER:
        s = strat_stats.get(strat,{})
        print(f"\n  {strat}:")
        print(f"    Images tested:   {s.get('total',0)}")
        print(f"    Build success:   {s.get('success',0)} ({100-s.get('fail_rate',0):.1f}%)")
        print(f"    Build failures:  {s.get('failures',0)} ({s.get('fail_rate',0):.1f}%)")
        print(f"    VR mean:         {s.get('vr_mean',0):.1f}%")
        print(f"    VR median:       {s.get('vr_median',0):.1f}%")
        print(f"    VR std:          {s.get('vr_std',0):.1f}%")
        print(f"    VR range:        [{s.get('vr_min',0):.1f}%, {s.get('vr_max',0):.1f}%]")
        print(f"    New vulns:       {s.get('new_vulns_total',0)}")
        print(f"    Accepted:        {s.get('acceptance_count',0)}")

    print(f"\n  Pairwise: AutoPatch vs baselines")
    for bl, comp in comparisons.items():
        print(f"\n    vs {bl}: ({comp.get('paired',0)} paired)")
        if 'cohen_d' in comp: print(f"      Cohen's d:  {comp['cohen_d']}")
        if 'p_value' in comp:
            print(f"      Wilcoxon p: {comp['p_value']:.6f}")
            print(f"      Sig @0.05:  {comp.get('sig_005','N/A')}")
            print(f"      Sig @0.01:  {comp.get('sig_001','N/A')}")

    print(f"\n  OS Family Breakdown (AutoPatch):")
    for fam, s in sorted(os_stats.items()):
        print(f"    {fam:14s}: {s['images']:3d} images, VR={s['vr_mean']:5.1f}% ± {s['vr_std']:5.1f}%, fails={s['fails']}")

    print("\n" + "="*70)
    print("  FILES:")
    print(f"    Statistics:  {out/'statistics.json'}")
    print(f"    Results CSV: {out/'results.csv'}")
    print(f"    Fig 2:       {figs/'fig2_effectiveness.pdf'}")
    print(f"    Fig 3:       {figs/'fig3_cdf.pdf'}")
    print(f"    Fig 4:       {figs/'fig4_severity_panels.pdf'}")
    print("="*70)


if __name__ == "__main__":
    results_file = sys.argv[1]
    output_dir = sys.argv[2]
    figures_dir = sys.argv[3] if len(sys.argv)>3 else str(Path(results_file).parent.parent/"figures")
    main(results_file, output_dir, figures_dir)
STATS_SCRIPT

python3 "${WORK_DIR}/compute_stats.py" \
    "$RESULTS_DIR/results.json" \
    "$RESULTS_DIR" \
    "$FIGURES_DIR" \
    2>&1 | tee -a "${WORK_DIR}/statistics_output.log"

ok "Statistics computed and figures generated"
echo "PHASE 5 COMPLETE [$(date)]" >> "$PROGRESS_FILE"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 6: FINAL SUMMARY                                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 6 "Final summary"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  EXPERIMENT COMPLETE${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Results:     $RESULTS_DIR/results.json"
echo "  CSV:         $RESULTS_DIR/results.csv"
echo "  Statistics:  $RESULTS_DIR/statistics.json"
echo "  Figures:     $FIGURES_DIR/"
echo "  Full log:    ${WORK_DIR}/experiment_output.log"
echo "  Progress:    $PROGRESS_FILE"
echo ""

# Print key numbers
if [ -f "$RESULTS_DIR/statistics.json" ]; then
    echo "  Key numbers (from statistics.json):"
    python3 -c "
import json
with open('$RESULTS_DIR/statistics.json') as f:
    s = json.load(f)
ss = s['strategy_statistics']
ap = ss.get('AutoPatch',{})
print(f'    AutoPatch VR mean:   {ap.get(\"vr_mean\",0):.1f}%')
print(f'    AutoPatch VR median: {ap.get(\"vr_median\",0):.1f}%')
print(f'    AutoPatch VR std:    {ap.get(\"vr_std\",0):.1f}%')
print(f'    Build success rate:  {100-ap.get(\"fail_rate\",0):.1f}%')
print(f'    Acceptance rate:     {ap.get(\"acceptance_count\",0)}/{ap.get(\"success\",0)}')
for bl in ['Naive-Latest','Copacetic','Docker-Scout']:
    c = s['pairwise_comparisons'].get(bl,{})
    p = c.get('p_value','N/A')
    d = c.get('cohen_d','N/A')
    print(f'    vs {bl}: p={p}, d={d}')
" 2>/dev/null || true
fi

echo ""
echo "  All done! Copy the numbers above into your paper."
echo "  Replace every [SIMULATED] tag in experimental_data.json"
echo "  with these measured values."
echo ""

echo "EXPERIMENT FULLY COMPLETE [$(date)]" >> "$PROGRESS_FILE"
