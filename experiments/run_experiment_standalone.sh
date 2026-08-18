#!/usr/bin/env bash
###############################################################################
#  AutoPatch — STANDALONE Experiment Runner v3
#
#  100% self-contained: installs everything, generates Dockerfiles,
#  runs all 5 strategies, computes stats, generates figures.
#  NO GitHub clone needed.
#
#  Usage:
#    sudo bash run_experiment_standalone.sh 2>&1 | tee experiment.log
#
#  Requirements: Fresh Ubuntu 22.04 (e.g. GCP e2-standard-4, 100GB disk)
###############################################################################
set -euo pipefail

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  CONFIGURATION                                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
WORK_DIR="${HOME}/autopatch_experiment"
DF_DIR="${WORK_DIR}/dockerfiles"
RESULTS_DIR="${WORK_DIR}/results_v3"
FIGURES_DIR="${WORK_DIR}/figures_v3"
PROGRESS_FILE="${WORK_DIR}/progress_v3.txt"

DOCKER_USER="${DOCKER_USER:-}"
DOCKER_PASS="${DOCKER_PASS:-}"
MAX_IMAGES=${MAX_IMAGES:-0}
STRATEGIES="${STRATEGIES:-scan-only naive copacetic scout autopatch}"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  HELPERS                                                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
phase()  { echo -e "\n${CYAN}═══ PHASE $1: $2 ═══${NC}"; echo "PHASE $1: $2 [$(date)]" >> "$PROGRESS_FILE"; }
step()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()   { echo -e "  ${YELLOW}[!]${NC} $1"; }
ok()     { echo -e "  ${GREEN}[✓]${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

mkdir -p "$WORK_DIR" "$DF_DIR" "$RESULTS_DIR" "$FIGURES_DIR"
echo "Experiment v3 started at $(date)" > "$PROGRESS_FILE"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 1: INSTALL ALL DEPENDENCIES                                     ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 1 "Installing dependencies"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# Core tools
for pkg in curl wget git jq ca-certificates gnupg lsb-release software-properties-common apt-transport-https python3 python3-pip; do
    dpkg -s "$pkg" &>/dev/null || apt-get install -y "$pkg" 2>/dev/null
done
ok "Core packages"

# ── Docker ────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    step "Installing Docker..."
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker 2>/dev/null || true
    systemctl start docker 2>/dev/null || true
fi
ok "Docker: $(docker --version)"

if [ -n "$DOCKER_USER" ] && [ -n "$DOCKER_PASS" ]; then
    echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin 2>/dev/null && ok "Docker Hub login OK" || true
fi

# ── Trivy ─────────────────────────────────────────────────────────────────
if ! command -v trivy &>/dev/null; then
    step "Installing Trivy..."
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
    apt-get update -qq && apt-get install -y trivy
fi
ok "Trivy: $(trivy --version 2>&1 | head -1)"
trivy image --download-db-only 2>/dev/null && ok "Trivy DB ready" || warn "Trivy DB update failed"

# ── Cosign ────────────────────────────────────────────────────────────────
if ! command -v cosign &>/dev/null; then
    step "Installing Cosign..."
    COSIGN_VERSION=$(curl -sL https://api.github.com/repos/sigstore/cosign/releases/latest 2>/dev/null | jq -r '.tag_name // "v2.4.1"')
    wget -q "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" -O /usr/local/bin/cosign
    chmod +x /usr/local/bin/cosign
fi
ok "Cosign installed"

# ── Copacetic (Copa) ─────────────────────────────────────────────────────
if ! command -v copa &>/dev/null; then
    step "Installing Copa..."
    COPA_VERSION=$(curl -sL https://api.github.com/repos/project-copacetic/copacetic/releases/latest 2>/dev/null | jq -r '.tag_name // "v0.9.0"')
    COPA_VER_CLEAN="${COPA_VERSION#v}"
    wget -q "https://github.com/project-copacetic/copacetic/releases/download/${COPA_VERSION}/copa_${COPA_VER_CLEAN}_linux_amd64.tar.gz" -O /tmp/copa.tar.gz \
        && tar -xzf /tmp/copa.tar.gz -C /usr/local/bin copa && rm /tmp/copa.tar.gz \
        && ok "Copa installed" \
        || warn "Copa install failed — will record failures"
fi

# Copa buildkit
if ! docker buildx ls 2>/dev/null | grep -q copabuildkit; then
    docker buildx create --name copabuildkit --use --bootstrap 2>/dev/null && ok "Copa buildkit ready" || warn "Copa buildkit failed"
fi
COPA_BK=$(docker ps --filter "name=buildx_buildkit_copabuildkit" --format '{{.Names}}' 2>/dev/null | head -1)
[ -n "$COPA_BK" ] && ok "Copa buildkit container: $COPA_BK" || warn "Copa buildkit container not found"

# ── Docker Scout ──────────────────────────────────────────────────────────
if ! docker scout version &>/dev/null; then
    step "Installing Docker Scout..."
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh 2>/dev/null | sh -s -- 2>/dev/null \
        && ok "Docker Scout installed" || warn "Scout install failed — will record failures"
fi

# ── Python packages ───────────────────────────────────────────────────────
pip3 install --break-system-packages scipy matplotlib numpy seaborn 2>/dev/null \
    || pip3 install scipy matplotlib numpy seaborn 2>/dev/null \
    || warn "Some Python packages may be missing"
ok "Phase 1 complete"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 2: GENERATE DOCKERFILES (inline, no repo needed)                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 2 "Generating Dockerfile dataset"

cat > "${WORK_DIR}/gen_dockerfiles.py" << 'GEN_EOF'
#!/usr/bin/env python3
"""Generate ~111 Dockerfiles for the experiment. Fully inline."""
import os, sys
D = sys.argv[1] if len(sys.argv) > 1 else "dockerfiles"
os.makedirs(D, exist_ok=True)

DATASET = [
    # OS families
    ("alpine-3.12", "alpine:3.12", "RUN apk add --no-cache curl"),
    ("alpine-3.14", "alpine:3.14", "RUN apk add --no-cache curl wget"),
    ("alpine-3.16", "alpine:3.16", "RUN apk add --no-cache curl bash"),
    ("alpine-3.18", "alpine:3.18", "RUN apk add --no-cache curl git"),
    ("debian-stretch", "debian:stretch", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("debian-buster", "debian:buster", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("debian-bullseye", "debian:bullseye", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("debian-bookworm", "debian:bookworm", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-16.04", "ubuntu:16.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-18.04", "ubuntu:18.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-20.04", "ubuntu:20.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-22.04", "ubuntu:22.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-24.04", "ubuntu:24.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("centos-7", "centos:7", "RUN yum install -y curl && yum clean all"),
    ("rockylinux-8", "rockylinux:8", "RUN dnf install -y curl && dnf clean all"),
    ("rockylinux-9", "rockylinux:9", "RUN dnf install -y curl && dnf clean all"),
    ("almalinux-8", "almalinux:8", "RUN dnf install -y curl && dnf clean all"),
    ("almalinux-9", "almalinux:9", "RUN dnf install -y curl && dnf clean all"),
    ("distroless-base", "gcr.io/distroless/base-debian11", ""),
    ("distroless-java", "gcr.io/distroless/java17-debian11", ""),
    ("scratch", "scratch", ""),
    # Python
    ("python-3.6", "python:3.6", 'RUN pip install flask==2.0.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.7", "python:3.7", 'RUN pip install flask==2.0.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.8", "python:3.8", 'RUN pip install flask==2.2.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.9", "python:3.9", 'RUN pip install flask==2.2.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.10", "python:3.10", 'RUN pip install flask==2.3.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.11", "python:3.11", 'RUN pip install flask==3.0.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.8-slim", "python:3.8-slim", 'RUN pip install requests==2.28.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.9-alpine", "python:3.9-alpine", 'RUN pip install requests==2.28.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.10-bullseye", "python:3.10-bullseye", 'RUN pip install django==4.0\nCMD ["python", "-c", "print(1)"]'),
    # Node.js
    ("node-12", "node:12", 'RUN npm init -y && npm install express@4.17.1\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-14", "node:14", 'RUN npm init -y && npm install express@4.17.1\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-16", "node:16", 'RUN npm init -y && npm install express@4.18.0\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-18", "node:18", 'RUN npm init -y && npm install express@4.18.2\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-20", "node:20", 'RUN npm init -y && npm install express@4.19.0\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-14-alpine", "node:14-alpine", 'RUN npm init -y\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-16-slim", "node:16-slim", 'RUN npm init -y\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-18-bullseye", "node:18-bullseye", 'RUN npm init -y\nCMD ["node", "-e", "console.log(1)"]'),
    # Go
    ("golang-1.16", "golang:1.16", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.18", "golang:1.18", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.19", "golang:1.19", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.20", "golang:1.20", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.21", "golang:1.21", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.16-alpine", "golang:1.16-alpine", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.19-bullseye", "golang:1.19-bullseye", 'RUN go version\nCMD ["go", "version"]'),
    # Java
    ("openjdk-8", "openjdk:8", 'CMD ["java", "-version"]'),
    ("openjdk-11", "openjdk:11", 'CMD ["java", "-version"]'),
    ("openjdk-17", "openjdk:17", 'CMD ["java", "-version"]'),
    ("adoptopenjdk-11", "adoptopenjdk:11-jre-hotspot", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-11", "eclipse-temurin:11", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-17", "eclipse-temurin:17", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-21", "eclipse-temurin:21", 'CMD ["java", "-version"]'),
    # Ruby
    ("ruby-2.7", "ruby:2.7", 'CMD ["ruby", "-v"]'),
    ("ruby-3.0", "ruby:3.0", 'CMD ["ruby", "-v"]'),
    ("ruby-3.1", "ruby:3.1", 'CMD ["ruby", "-v"]'),
    ("ruby-3.2", "ruby:3.2", 'CMD ["ruby", "-v"]'),
    ("ruby-2.7-alpine", "ruby:2.7-alpine", 'CMD ["ruby", "-v"]'),
    # PHP
    ("php-7.4", "php:7.4", 'CMD ["php", "-v"]'),
    ("php-8.0", "php:8.0", 'CMD ["php", "-v"]'),
    ("php-8.1", "php:8.1", 'CMD ["php", "-v"]'),
    ("php-8.2", "php:8.2", 'CMD ["php", "-v"]'),
    ("php-7.4-apache", "php:7.4-apache", "EXPOSE 80"),
    ("php-8.0-fpm", "php:8.0-fpm", "EXPOSE 9000"),
    ("php-8.1-alpine", "php:8.1-alpine", 'CMD ["php", "-v"]'),
    # Web servers
    ("nginx-1.10", "nginx:1.10", "EXPOSE 80"),
    ("nginx-1.18", "nginx:1.18", "EXPOSE 80"),
    ("nginx-1.21", "nginx:1.21", "EXPOSE 80"),
    ("nginx-1.24", "nginx:1.24", "EXPOSE 80"),
    ("nginx-1.18-alpine", "nginx:1.18-alpine", "EXPOSE 80"),
    ("httpd-2.4.46", "httpd:2.4.46", "EXPOSE 80"),
    ("httpd-2.4.54", "httpd:2.4.54", "EXPOSE 80"),
    ("traefik-2.5", "traefik:v2.5", "EXPOSE 80 443"),
    ("traefik-2.9", "traefik:v2.9", "EXPOSE 80 443"),
    ("caddy-2.4", "caddy:2.4", "EXPOSE 80 443"),
    ("haproxy-2.4", "haproxy:2.4", "EXPOSE 80"),
    ("haproxy-2.6", "haproxy:2.6", "EXPOSE 80"),
    # Databases
    ("redis-5", "redis:5", "EXPOSE 6379"),
    ("redis-6", "redis:6", "EXPOSE 6379"),
    ("redis-7", "redis:7", "EXPOSE 6379"),
    ("postgres-11", "postgres:11", "EXPOSE 5432"),
    ("postgres-12", "postgres:12", "EXPOSE 5432"),
    ("postgres-13", "postgres:13", "EXPOSE 5432"),
    ("postgres-14", "postgres:14", "EXPOSE 5432"),
    ("mysql-5.7", "mysql:5.7", "EXPOSE 3306"),
    ("mysql-8.0", "mysql:8.0", "EXPOSE 3306"),
    ("mongo-4.4", "mongo:4.4", "EXPOSE 27017"),
    ("mongo-5.0", "mongo:5.0", "EXPOSE 27017"),
    ("mongo-6.0", "mongo:6.0", "EXPOSE 27017"),
    ("mariadb-10.5", "mariadb:10.5", "EXPOSE 3306"),
    ("mariadb-10.11", "mariadb:10.11", "EXPOSE 3306"),
    # Message queues
    ("rabbitmq-3.9", "rabbitmq:3.9", "EXPOSE 5672"),
    ("rabbitmq-3.11", "rabbitmq:3.11", "EXPOSE 5672"),
    ("elasticsearch-7.17.0", "docker.elastic.co/elasticsearch/elasticsearch:7.17.0", "ENV discovery.type=single-node\nEXPOSE 9200"),
    ("kafka-old", "bitnami/kafka:3.3", "EXPOSE 9092"),
    # CI/CD
    ("jenkins-2.164", "jenkins/jenkins:2.164.1-lts", "EXPOSE 8080"),
    ("jenkins-lts", "jenkins/jenkins:lts", "EXPOSE 8080"),
    ("vault-1.12", "hashicorp/vault:1.12.0", 'CMD ["vault", "version"]'),
    ("vault-1.14", "hashicorp/vault:1.14.0", 'CMD ["vault", "version"]'),
    ("consul-1.14", "hashicorp/consul:1.14", "EXPOSE 8500"),
    ("sonarqube-9", "sonarqube:9.9-community", "EXPOSE 9000"),
    ("gitlab-runner", "gitlab/gitlab-runner:v15.0.0", 'CMD ["gitlab-runner", "--version"]'),
    # CMS
    ("wordpress-5", "wordpress:5", "EXPOSE 80"),
    ("wordpress-6", "wordpress:6.0", "EXPOSE 80"),
    ("nextcloud-25", "nextcloud:25", "EXPOSE 80"),
    ("nextcloud-27", "nextcloud:27", "EXPOSE 80"),
    ("drupal-9", "drupal:9", "EXPOSE 80"),
    ("drupal-10", "drupal:10", "EXPOSE 80"),
    ("ghost-5", "ghost:5", "EXPOSE 2368"),
    ("joomla-4", "joomla:4", "EXPOSE 80"),
    # Multi-stage
    ("multistage-python", None, None),
    ("multistage-go", None, None),
    ("multistage-node", None, None),
    ("multistage-java", None, None),
]

MS = {
"multistage-python": """FROM python:3.8 AS builder
WORKDIR /app
RUN pip install flask==2.2.0

FROM python:3.8-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
CMD ["python", "-c", "print(1)"]
""",
"multistage-go": """FROM golang:1.18 AS builder
WORKDIR /app
RUN go version

FROM alpine:3.14
WORKDIR /app
COPY --from=builder /usr/local/go/bin/go /usr/local/go/bin/go
CMD ["echo", "hello"]
""",
"multistage-node": """FROM node:16 AS builder
WORKDIR /app
RUN npm init -y

FROM node:16-slim
WORKDIR /app
COPY --from=builder /app/package.json ./
CMD ["node", "-e", "console.log(1)"]
""",
"multistage-java": """FROM maven:3.8-openjdk-11 AS builder
WORKDIR /app
RUN mvn --version

FROM openjdk:11-jre-slim
WORKDIR /app
CMD ["java", "-version"]
""",
}

n = 0
for name, fr, extra in DATASET:
    path = f"{D}/Dockerfile.{name}"
    if os.path.exists(path):
        continue
    if fr is None:
        content = MS.get(name, "")
    else:
        lines = [f"FROM {fr}"]
        if "distroless" not in fr and "scratch" not in fr:
            lines.append("WORKDIR /app")
        if extra:
            lines.extend(extra.split("\n"))
        content = "\n".join(lines) + "\n"
    if content:
        with open(path, "w") as f:
            f.write(content)
        n += 1
print(f"Generated {n} new Dockerfiles, total: {len([f for f in os.listdir(D) if f.startswith('Dockerfile.')])}")
GEN_EOF

python3 "${WORK_DIR}/gen_dockerfiles.py" "$DF_DIR"
DF_COUNT=$(ls "$DF_DIR"/Dockerfile.* 2>/dev/null | wc -l)
ok "Dataset ready: $DF_COUNT Dockerfiles"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 3: RUN 5-STRATEGY EXPERIMENT                                    ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 3 "Running 5-strategy experiment"

mkdir -p "$RESULTS_DIR"/{scans,sboms,patched}
export DOCKER_CLI_HINTS=false

cat > "${WORK_DIR}/run_exp.py" << 'PYEOF'
#!/usr/bin/env python3
"""AutoPatch 5-strategy experiment runner v3 (standalone)."""
import argparse, csv, json, logging, math, os, re, shutil
import subprocess, sys, tempfile, time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("exp_v3")

# ═══════════════════════════════════════════════════════════════════════
# Shell helpers
# ═══════════════════════════════════════════════════════════════════════
def run(cmd, timeout=600):
    log.debug(f"  $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired: return -1, "", "TIMEOUT"
    except FileNotFoundError: return -2, "", f"NOT_FOUND: {cmd[0]}"

def docker_build(tag, dockerfile, context=".", timeout=600):
    start = time.time()
    code, out, err = run(["docker","build","--pull","-t",tag,"-f",dockerfile,context], timeout=timeout)
    elapsed = time.time() - start
    if code == 0: return True, elapsed, ""
    combined = (out+err).lower()
    for kw, cat in [("timeout","TIMEOUT"),("network","NETWORK"),("connection","NETWORK"),
                     ("could not resolve","NETWORK"),("returned a non-zero code","RUN_FAILURE"),
                     ("not found","IMAGE_NOT_FOUND"),("no such","IMAGE_NOT_FOUND"),
                     ("manifest unknown","IMAGE_NOT_FOUND"),("manifest not found","IMAGE_NOT_FOUND"),
                     ("permission denied","PERMISSION")]:
        if kw in combined: return False, elapsed, cat
    return False, elapsed, "BUILD_ERROR"

def image_size_mb(tag):
    c, o, _ = run(["docker","image","inspect",tag,"--format","{{.Size}}"])
    try: return int(o.strip())/(1024*1024) if c==0 else 0.0
    except: return 0.0

def rmi(tag): run(["docker","rmi","-f",tag], timeout=30)

def trivy_scan(image, out_file):
    code, _, err = run([
        "trivy","image","--format","json","--output",out_file,
        "--severity","CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        "--scanners","vuln","--timeout","10m",image
    ], timeout=660)
    if code != 0:
        log.warning(f"  Trivy scan FAILED for {image}: {err[:150]}")
        return None
    try:
        with open(out_file) as f: return json.load(f)
    except:
        log.warning(f"  Trivy output not valid JSON for {image}")
        return None

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
            if s not in counts: s = "UNKNOWN"
            counts[s] += 1
            vid = v.get("VulnerabilityID","")
            if vid: cves.add(vid)
    return counts, sorted(cves)

# ═══════════════════════════════════════════════════════════════════════
# OS inference from SBOM
# ═══════════════════════════════════════════════════════════════════════
def detect_os_family(sbom):
    if not sbom: return "unknown"
    components = sbom.get("components",[])
    if not components:
        if not sbom.get("metadata",{}).get("component",{}): return "scratch"
    purls = set()
    names = []
    for c in components:
        if "purl" in c: purls.add(c["purl"])
        if "name" in c: names.append(c["name"].lower())
    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    # --- FIX v4: detect distroless BEFORE package-type checks ---
    # Distroless images contain few deb packages but should NOT be classified as debian
    if "distroless" in meta_name:
        return "distroless"
    if any("ubuntu" in n for n in names) and any("pkg:deb/" in p for p in purls): return "ubuntu"
    if any("pkg:apk/" in p for p in purls) or any(n in names for n in ["apk-tools","musl","alpine-baselayout"]): return "alpine"
    if any("pkg:deb/" in p for p in purls):
        # Check component count — distroless images have very few deb packages
        if len(components) < 15 and not any("apt" in n for n in names):
            return "distroless"
        return "debian"
    if any("pkg:rpm/" in p for p in purls):
        if any("rocky" in n for n in names) or "rocky" in meta_name: return "rocky"
        if any("alma" in n for n in names) or "alma" in meta_name: return "alma"
        if any("centos" in n for n in names) or "centos" in meta_name: return "centos"
        return "rhel"
    if len(components) < 5: return "distroless"
    return "unknown"

# ═══════════════════════════════════════════════════════════════════════
# Base image chooser — v3: preserve language version, change OS to alpine
# ═══════════════════════════════════════════════════════════════════════
def _extract_ver(tag, default=""):
    m = re.search(r':(\d+(?:\.\d+)*)', tag)
    return m.group(1) if m else default

def _extract_major(tag, default=""):
    m = re.search(r':(\d+)', tag)
    return m.group(1) if m else default

def choose_base(family, orig_base=""):
    """
    v3 strategy: keep SAME language version, switch OS to alpine.
    This isolates OS-level vulnerability reduction without introducing
    new language runtime CVEs from version upgrades.
    """
    o = orig_base.lower()

    # --- FIX v4: databases and infrastructure BEFORE golang ---
    # "mongo:X" contains "go:" substring, so mongo must be checked first
    # Similarly "django" contains "go" — order matters.

    # Databases (checked early to avoid substring collisions)
    if "mongo" in o:    return "mongo:7"
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mariadb" in o:  return "mariadb:11"

    # Language runtimes → SAME version, alpine OS
    if "python" in o:
        ver = _extract_ver(orig_base, "3.12")
        return f"python:{ver}-alpine"

    if "node" in o:
        ver = _extract_major(orig_base, "22")
        return f"node:{ver}-alpine"

    if "golang" in o or re.search(r'\bgo:', o):
        ver = _extract_ver(orig_base, "1.22")
        return f"golang:{ver}-alpine"

    if "ruby" in o:
        ver = _extract_ver(orig_base, "3.3")
        return f"ruby:{ver}-alpine"

    if "php" in o:
        ver = _extract_ver(orig_base, "8.3")
        if "apache" in o: return f"php:{ver}-apache"
        if "fpm" in o:    return f"php:{ver}-fpm-alpine"
        return f"php:{ver}-alpine"

    if "temurin" in o or "adoptopenjdk" in o:
        major = _extract_major(orig_base, "21")
        return f"eclipse-temurin:{major}-jre-alpine"

    if "openjdk" in o:
        major = _extract_major(orig_base, "17")
        return f"eclipse-temurin:{major}-jre-alpine"

    if "maven" in o:
        return "maven:3.9-eclipse-temurin-21-alpine"

    # Infrastructure → latest + alpine (safe to upgrade)
    if "nginx" in o:   return "nginx:stable-alpine"
    if "httpd" in o:   return "httpd:2.4-alpine"
    if "traefik" in o: return "traefik:v3.3"
    if "caddy" in o:   return "caddy:2-alpine"
    if "haproxy" in o: return "haproxy:3.1-alpine"

    # Message queues
    if "rabbitmq" in o:       return "rabbitmq:4-alpine"
    if "elasticsearch" in o:  return "docker.elastic.co/elasticsearch/elasticsearch:8.17.0"
    if "kafka" in o:          return "bitnami/kafka:3.9"

    # CI/CD
    if "jenkins" in o:   return "jenkins/jenkins:lts-alpine"
    if "vault" in o:     return "hashicorp/vault:latest"
    if "consul" in o:    return "hashicorp/consul:latest"
    if "sonarqube" in o: return "sonarqube:lts-community"
    if "gitlab" in o:    return "gitlab/gitlab-runner:alpine"

    # CMS
    if "wordpress" in o:  return "wordpress:6-php8.3-apache"
    if "nextcloud" in o:  return "nextcloud:29-apache"
    if "drupal" in o:     return "drupal:11-php8.3-apache"
    if "ghost" in o:      return "ghost:5-alpine"
    if "joomla" in o:     return "joomla:5-php8.3-apache"
    if "docker" in o:     return "docker:27-cli"

    # Pure OS
    f = family.lower()
    MAP = {
        "alpine":"alpine:3.21", "debian":"debian:bookworm-slim",
        "ubuntu":"ubuntu:24.04", "centos":"rockylinux:9-minimal",
        "rhel":"rockylinux:9-minimal", "rocky":"rockylinux:9-minimal",
        "alma":"almalinux:9-minimal", "fedora":"fedora:41",
        "distroless":"gcr.io/distroless/static-debian12:nonroot",
        "scratch":"scratch",
    }
    return MAP.get(f, "alpine:3.21")

# ═══════════════════════════════════════════════════════════════════════
# Rewriters
# ═══════════════════════════════════════════════════════════════════════
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
                    lines.append(line); continue
                if not (":" in base_part or "/" in base_part or "." in base_part):
                    lines.append(line); continue
                new_base = choose_base(family, base_part)
                if new_base.lower() == "scratch":
                    lines.append(line); continue
                new_from = f"FROM {new_base}"
                if alias_part: new_from += f" {alias_part}"
                lines.append(new_from)
            else: lines.append(line)
        else: lines.append(line)
    return "\n".join(lines)+"\n"

# ═══════════════════════════════════════════════════════════════════════
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
    base_before: str = ""; base_after: str = ""
    os_family: str = ""
    notes: str = ""; ts: str = field(default_factory=lambda: datetime.now().isoformat())

class Experiment:
    def __init__(self, df_dir, out_dir, strategies, max_images=0, copa_bk=""):
        self.df_dir = Path(df_dir)
        self.out = Path(out_dir); self.out.mkdir(parents=True, exist_ok=True)
        for d in ["scans","sboms","patched"]: (self.out/d).mkdir(exist_ok=True)
        self.strategies = strategies
        self.max_images = max_images
        self.copa_bk = copa_bk
        self.results = []
        self.tmp = Path(tempfile.mkdtemp(prefix="apv3_"))
        # Crash recovery
        prev = self.out/"results.json"
        if prev.exists():
            try:
                with open(prev) as f: old = json.load(f)
                self.done = {(r["image_name"],r["strategy"]) for r in old.get("results",[])}
                log.info(f"Crash recovery: {len(self.done)} results from previous run")
                for r in old.get("results",[]):
                    safe_fields = {k:v for k,v in r.items() if k in R.__dataclass_fields__}
                    self.results.append(R(**safe_fields))
            except: self.done = set()
        else: self.done = set()

    def discover(self):
        dfs = sorted(self.df_dir.glob("Dockerfile.*"))
        dfs = [d for d in dfs if not d.name.endswith((".md",".patched",".bak"))]
        if self.max_images > 0: dfs = dfs[:self.max_images]
        log.info(f"Found {len(dfs)} Dockerfiles")
        return dfs

    def safe_tag(self, name, strat):
        return f"v3-{re.sub(r'[^a-z0-9._-]','-',name.lower())}-{strat}"

    def vr(self, before, after):
        if before == 0:
            if after == 0: return 0.0
            return -100.0
        return ((before - after) / before) * 100.0

    def process(self, df_path):
        name = df_path.name.replace("Dockerfile.","")
        log.info(f"\n{'='*60}\n  Processing: {name}\n{'='*60}")
        with open(df_path) as f: text = f.read()

        orig_base = ""
        for line in text.splitlines():
            if line.strip().upper().startswith("FROM "):
                parts = line.strip().split(None,1)
                if len(parts)==2: orig_base = parts[1].split()[0]
                break

        results = []

        # Build & scan original
        orig_tag = self.safe_tag(name,"orig")
        log.info(f"  Building original: {orig_tag}")
        ok, bt, berr = docker_build(orig_tag, str(df_path), str(df_path.parent))
        if not ok:
            log.warning(f"  ORIGINAL BUILD FAILED ({berr})")
            for s in self.strategies:
                sn = {"scan-only":"Scan-Only","naive":"Naive-Latest","copacetic":"Copacetic",
                      "scout":"Docker-Scout","autopatch":"AutoPatch"}.get(s,s)
                if (name,sn) not in self.done:
                    results.append(R(image_name=name,strategy=sn,error_category=berr,
                                     base_before=orig_base,notes=f"Original build failed: {berr}"))
            return results

        scan_file = str(self.out/"scans"/f"{name}_orig.json")
        log.info(f"  Scanning original...")
        scan_data = trivy_scan(orig_tag, scan_file)
        sev_b, cves_b = extract_vulns(scan_data)
        total_b = sum(sev_b.values())
        size_b = image_size_mb(orig_tag)
        log.info(f"  Baseline: {total_b} vulns (C={sev_b['CRITICAL']}, H={sev_b['HIGH']}, M={sev_b['MEDIUM']}, L={sev_b['LOW']})")

        sbom_file = str(self.out/"sboms"/f"{name}.json")
        sbom = trivy_sbom(orig_tag, sbom_file)
        os_fam = detect_os_family(sbom)
        log.info(f"  OS family: {os_fam}")

        # ── A: Scan-Only ─────────────────────────────────────────────
        sn = "Scan-Only"
        if "scan-only" in self.strategies and (name,sn) not in self.done:
            results.append(R(image_name=name,strategy=sn,build_success=True,
                             build_time_sec=bt,vulns_before_total=total_b,vulns_after_total=total_b,
                             sev_before=dict(sev_b),sev_after=dict(sev_b),
                             size_before_mb=size_b,size_after_mb=size_b,
                             cves_before=cves_b,cves_after=cves_b,base_before=orig_base,os_family=os_fam))

        # ── B: Naive :latest ─────────────────────────────────────────
        sn = "Naive-Latest"
        if "naive" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [B] Naive :latest")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,base_before=orig_base,os_family=os_fam)
            patched = rewrite_from_latest(text)
            pf = self.tmp/f"Df.{name}.naive"; pf.write_text(patched)
            tag = self.safe_tag(name,"naive")
            ok2,t2,e2 = docker_build(tag,str(pf),str(df_path.parent))
            r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
            if ok2:
                sf = str(self.out/"scans"/f"{name}_naive.json")
                sd = trivy_scan(tag,sf)
                if sd is None:
                    r.build_success=False; r.error_category="RESCAN_FAILED"
                    r.sev_after=dict(sev_b); r.vulns_after_total=total_b; r.cves_after=cves_b
                else:
                    sa,ca = extract_vulns(sd)
                    r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                    r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                    r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                    r.new_vulns_introduced=len(set(ca)-set(cves_b))
                rmi(tag)
            else:
                # Build failed → no improvement
                r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
            log.info(f"    Naive: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
            results.append(r)

        # ── C: Copacetic ─────────────────────────────────────────────
        sn = "Copacetic"
        if "copacetic" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [C] Copacetic")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,base_before=orig_base,os_family=os_fam)
            ptag = self.safe_tag(name,"copa")
            copa_cmd = ["copa","patch","-i",orig_tag,"-r",scan_file,"-t",ptag]
            if self.copa_bk:
                copa_cmd.extend(["-a",f"docker-container://{self.copa_bk}"])
            start=time.time()
            code,out2,err2 = run(copa_cmd, timeout=600)
            r.build_time_sec = time.time()-start

            if code != 0:
                r.build_success=False; r.error_category="COPA_FAILURE"
                r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                r.notes=f"Copa error: {err2[:150]}"
                log.info(f"    Copa: FAILED ({err2[:80]})")
            else:
                sf = str(self.out/"scans"/f"{name}_copa.json")
                sd = trivy_scan(ptag, sf)
                if sd is None:
                    # CRITICAL FIX: Trivy re-scan failed → NOT fake 100%
                    r.build_success=False; r.error_category="COPA_RESCAN_FAILED"
                    r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                    r.notes="Copa patched but Trivy re-scan failed — not counted as success"
                    log.info(f"    Copa: patched but RESCAN FAILED (keeping original counts)")
                else:
                    r.build_success=True
                    sa,ca = extract_vulns(sd)
                    r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                    r.size_after_mb=image_size_mb(ptag); r.size_delta_mb=r.size_after_mb-size_b
                    r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                    r.new_vulns_introduced=len(set(ca)-set(cves_b))
                    log.info(f"    Copa: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
                rmi(ptag)
            results.append(r)

        # ── D: Docker Scout ──────────────────────────────────────────
        sn = "Docker-Scout"
        if "scout" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [D] Docker Scout")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,base_before=orig_base,os_family=os_fam)

            rec_tag = None
            code,out2,err2 = run(["docker","scout","recommendations",orig_tag,"--format","json"], timeout=120)
            if code == 0:
                try:
                    jd = json.loads(out2)
                    for key in ["recommendations","current","target"]:
                        if isinstance(jd, dict) and key in jd: jd = jd[key]
                    if isinstance(jd, dict) and "tag" in jd: rec_tag = jd["tag"]
                    elif isinstance(jd, list) and jd: rec_tag = jd[0].get("tag") or jd[0].get("name")
                except: pass

            if not rec_tag:
                code2,out2,err2 = run(["docker","scout","recommendations",orig_tag], timeout=120)
                if code2 == 0:
                    for line in out2.splitlines():
                        for pattern in [r'(\d+\.\d+[\w.-]*)\s*(?:→|->)\s*(\d+\.\d+[\w.-]*)',
                                        r'[Rr]ecommended.*?:\s*(\S+)',
                                        r'[Tt]ag.*?:\s*(\S+)']:
                            m = re.search(pattern, line)
                            if m: rec_tag = m.group(m.lastindex); break
                        if rec_tag: break

            if not rec_tag:
                r.build_success=False; r.error_category="SCOUT_NO_REC"
                r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                r.notes="No recommendation"
                log.info(f"    Scout: no recommendation")
            else:
                log.info(f"    Scout recommends: {rec_tag}")
                new_lines = []
                for line in text.splitlines():
                    s2 = line.strip()
                    if s2.upper().startswith("FROM ") and "scratch" not in s2.lower():
                        parts = s2.split(None,1)
                        if len(parts)==2:
                            rest = parts[1]
                            m2 = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.I)
                            bp = m2.group(1) if m2 else rest
                            ap = m2.group(2) if m2 else ""
                            bn = bp.split("@")[0].split(":")[0] if ("@" in bp or ":" in bp) else bp
                            new = f"FROM {bn}:{rec_tag}"
                            if ap: new += f" {ap}"
                            new_lines.append(new)
                        else: new_lines.append(line)
                    else: new_lines.append(line)
                patched = "\n".join(new_lines)+"\n"
                pf = self.tmp/f"Df.{name}.scout"; pf.write_text(patched)
                tag = self.safe_tag(name,"scout")
                ok2,t2,e2 = docker_build(tag,str(pf),str(df_path.parent))
                r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
                if ok2:
                    sf = str(self.out/"scans"/f"{name}_scout.json")
                    sd = trivy_scan(tag,sf)
                    if sd is None:
                        r.build_success=False; r.error_category="SCOUT_RESCAN_FAILED"
                        r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                    else:
                        sa,ca = extract_vulns(sd)
                        r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                        r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                        r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                        r.new_vulns_introduced=len(set(ca)-set(cves_b))
                    rmi(tag)
                else:
                    r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                log.info(f"    Scout: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
            results.append(r)

        # ── E: AutoPatch ─────────────────────────────────────────────
        sn = "AutoPatch"
        if "autopatch" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [E] AutoPatch")
            new_base = choose_base(os_fam, orig_base)
            log.info(f"    Mapping: {orig_base} → {new_base}")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,
                  base_before=orig_base,base_after=new_base,os_family=os_fam,notes=f"os={os_fam}")

            patched = rewrite_autopatch(text, sbom)
            pf = self.tmp/f"Df.{name}.ap"; pf.write_text(patched)
            (self.out/"patched"/f"Dockerfile.{name}").write_text(patched)

            tag = self.safe_tag(name,"ap")
            ok2,t2,e2 = docker_build(tag,str(pf),str(df_path.parent))
            r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
            if ok2:
                sf = str(self.out/"scans"/f"{name}_ap.json")
                sd = trivy_scan(tag,sf)
                if sd is None:
                    r.build_success=False; r.error_category="AP_RESCAN_FAILED"
                    r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                else:
                    sa,ca = extract_vulns(sd)
                    r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                    r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                    r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                    r.new_vulns_introduced=len(set(ca)-set(cves_b))
                    # Permissive acceptance: total went down AND severity didn't get worse
                    r.acceptance = (
                        r.vulns_after_total < total_b and
                        sa.get("CRITICAL",0) <= sev_b.get("CRITICAL",0) and
                        sa.get("HIGH",0) <= sev_b.get("HIGH",0)
                    )
                rmi(tag)
            else:
                # Build failed → no improvement
                r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
            log.info(f"    AutoPatch: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%), accept={r.acceptance}")
            results.append(r)

        rmi(orig_tag)
        return results

    def save(self):
        def ver(cmd):
            c,o,_ = run(cmd.split(), timeout=10)
            return o.strip().split("\n")[0] if c==0 else "unknown"
        data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "script_version": "v3-standalone",
                "trivy_version": ver("trivy --version"),
                "docker_version": ver("docker --version"),
                "total_results": len(self.results),
                "strategies": self.strategies,
            },
            "results": [asdict(r) for r in self.results]
        }
        with open(self.out/"results.json","w") as f: json.dump(data,f,indent=2,default=str)
        if self.results:
            flds = ["image_name","strategy","build_success","build_time_sec","error_category",
                    "vulns_before_total","vulns_after_total","reduction_pct","new_vulns_introduced",
                    "crit_before","high_before","med_before","low_before",
                    "crit_after","high_after","med_after","low_after",
                    "size_before_mb","size_after_mb","acceptance","base_before","base_after","os_family","notes"]
            with open(self.out/"results.csv","w",newline="") as f:
                w = csv.DictWriter(f,fieldnames=flds); w.writeheader()
                for r in self.results:
                    w.writerow({
                        "image_name":r.image_name,"strategy":r.strategy,
                        "build_success":r.build_success,"build_time_sec":round(r.build_time_sec,2),
                        "error_category":r.error_category,
                        "vulns_before_total":r.vulns_before_total,"vulns_after_total":r.vulns_after_total,
                        "reduction_pct":round(r.reduction_pct,2),
                        "new_vulns_introduced":r.new_vulns_introduced,
                        "crit_before":r.sev_before.get("CRITICAL",0),
                        "high_before":r.sev_before.get("HIGH",0),
                        "med_before":r.sev_before.get("MEDIUM",0),
                        "low_before":r.sev_before.get("LOW",0),
                        "crit_after":r.sev_after.get("CRITICAL",0),
                        "high_after":r.sev_after.get("HIGH",0),
                        "med_after":r.sev_after.get("MEDIUM",0),
                        "low_after":r.sev_after.get("LOW",0),
                        "size_before_mb":round(r.size_before_mb,2),
                        "size_after_mb":round(r.size_after_mb,2),
                        "acceptance":r.acceptance,
                        "base_before":r.base_before,"base_after":r.base_after,
                        "os_family":r.os_family,"notes":r.notes,
                    })

    def run_all(self):
        dfs = self.discover()
        total = len(dfs)
        t0 = time.time()
        for i,df in enumerate(dfs,1):
            elapsed = time.time()-t0
            eta = (elapsed/(i-1))*(total-i+1)/60 if i>1 else 0
            log.info(f"\n[{i}/{total}] ETA: ~{int(eta)} min remaining")
            pf = os.environ.get("PROGRESS_FILE","")
            if pf:
                with open(pf,"a") as f: f.write(f"  [{i}/{total}] {df.name} [{datetime.now().strftime('%H:%M:%S')}]\n")
            try:
                res = self.process(df)
                self.results.extend(res)
                self.save()
                if i%5==0: run(["docker","system","prune","-f"],timeout=60)
            except Exception as e:
                log.error(f"FATAL: {df.name}: {e}", exc_info=True)
        total_min = (time.time()-t0)/60
        log.info(f"\nDONE: {len(self.results)} results in {total_min:.1f} minutes")
        self.save()
        shutil.rmtree(self.tmp, ignore_errors=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dockerfile-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--strategies", nargs="+", default=["scan-only","naive","copacetic","scout","autopatch"])
    p.add_argument("--max-images", type=int, default=0)
    p.add_argument("--copa-buildkit", default="")
    a = p.parse_args()
    Experiment(a.dockerfile_dir, a.output_dir, a.strategies, a.max_images, a.copa_buildkit).run_all()

if __name__ == "__main__": main()
PYEOF

chmod +x "${WORK_DIR}/run_exp.py"
ok "Experiment script written"

step "Starting experiment at $(date)..."
export PROGRESS_FILE

EXTRA=""
if [ "$MAX_IMAGES" -gt 0 ]; then EXTRA="--max-images $MAX_IMAGES"; fi

python3 "${WORK_DIR}/run_exp.py" \
    --dockerfile-dir "$DF_DIR" \
    --output-dir "$RESULTS_DIR" \
    --strategies $STRATEGIES \
    --copa-buildkit "$COPA_BK" \
    $EXTRA \
    2>&1 | tee -a "${WORK_DIR}/experiment_output.log"

ok "Experiment finished at $(date)"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 4: STATISTICS & FIGURES                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
phase 4 "Computing statistics and generating figures"

cat > "${WORK_DIR}/stats.py" << 'STATS_EOF'
#!/usr/bin/env python3
import json, math, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
try:
    from scipy.stats import wilcoxon
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.rcParams.update({'font.family':'serif','font.size':10,'figure.dpi':300})

COLORS = {'Scan-Only':'#808080','Naive-Latest':'#E8922A','Copacetic':'#5B9BD5',
          'Docker-Scout':'#C05DCC','AutoPatch':'#2E7D32'}
ORDER = ['Scan-Only','Naive-Latest','Copacetic','Docker-Scout','AutoPatch']

def infer_os(name):
    n=name.lower()
    if 'alpine' in n: return 'Alpine'
    if any(k in n for k in ['debian','buster','bullseye','bookworm','stretch']): return 'Debian'
    if 'ubuntu' in n: return 'Ubuntu'
    if any(k in n for k in ['centos','rhel','rocky','alma','fedora']): return 'RHEL-family'
    if 'distroless' in n: return 'Distroless'
    if 'scratch' in n: return 'Scratch'
    return 'Other'

def cohens_d(g1,g2):
    n1,n2=len(g1),len(g2)
    if n1<2 or n2<2: return 0.0
    sp=math.sqrt(((n1-1)*np.std(g1,ddof=1)**2+(n2-1)*np.std(g2,ddof=1)**2)/(n1+n2-2))
    return (np.mean(g1)-np.mean(g2))/sp if sp>0 else 0.0

def main(rf,od,fd):
    with open(rf) as f: data=json.load(f)
    results=data["results"]
    out=Path(od); figs=Path(fd); figs.mkdir(parents=True,exist_ok=True)

    by_strat=defaultdict(list); by_img=defaultdict(dict)
    for r in results:
        by_strat[r["strategy"]].append(r)
        by_img[r["image_name"]][r["strategy"]]=r

    ss={}
    for strat in ORDER:
        es=by_strat.get(strat,[])
        ok=[e for e in es if e["build_success"]]; fl=[e for e in es if not e["build_success"]]
        vrs=[e["reduction_pct"] for e in ok if e["vulns_before_total"]>0]
        s={"strategy":strat,"total":len(es),"success":len(ok),"failures":len(fl),
           "fail_rate":round(len(fl)/max(len(es),1)*100,1)}
        if vrs:
            s["vr_mean"]=round(np.mean(vrs),2); s["vr_median"]=round(np.median(vrs),2)
            s["vr_std"]=round(np.std(vrs,ddof=1),2) if len(vrs)>1 else 0
            s["vr_min"]=round(min(vrs),2); s["vr_max"]=round(max(vrs),2)
        else: s["vr_mean"]=s["vr_median"]=s["vr_std"]=s["vr_min"]=s["vr_max"]=0
        s["new_vulns"]=sum(e.get("new_vulns_introduced",0) for e in ok)
        s["accepted"]=sum(1 for e in ok if e.get("acceptance"))
        s["zero_after"]=sum(1 for e in ok if e["vulns_after_total"]==0)
        ss[strat]=s

    comps={}
    for bl in ["Naive-Latest","Copacetic","Docker-Scout"]:
        pa,pb=[],[]
        for img,strats in by_img.items():
            if "AutoPatch" in strats and bl in strats:
                a,b=strats["AutoPatch"],strats[bl]
                if a["build_success"] and b["build_success"] and a["vulns_before_total"]>0:
                    pa.append(a["reduction_pct"]); pb.append(b["reduction_pct"])
        comp={"baseline":bl,"paired":len(pa)}
        if len(pa)>=5:
            comp["cohen_d"]=round(cohens_d(pa,pb),3)
            if HAS_SCIPY:
                diffs=[a-b for a,b in zip(pa,pb)]
                nz=[d for d in diffs if d!=0]
                if len(nz)>=5:
                    st,pv=wilcoxon(nz)
                    comp["wilcoxon"]=round(float(st),4)
                    comp["p_value"]=round(float(pv),6)
                    comp["sig_005"]=bool(pv<0.05); comp["sig_001"]=bool(pv<0.01)
        comps[bl]=comp

    osd=defaultdict(lambda:{"n":0,"vrs":[],"fails":0})
    for r in by_strat.get("AutoPatch",[]):
        f2=infer_os(r["image_name"]); osd[f2]["n"]+=1
        if r["build_success"] and r["vulns_before_total"]>0: osd[f2]["vrs"].append(r["reduction_pct"])
        elif not r["build_success"]: osd[f2]["fails"]+=1
    os_stats={f:{"images":d["n"],"fails":d["fails"],
                 "vr_mean":round(np.mean(d["vrs"]),2) if d["vrs"] else 0,
                 "vr_std":round(np.std(d["vrs"],ddof=1),2) if len(d["vrs"])>1 else 0}
              for f,d in sorted(osd.items())}

    output={"metadata":data.get("metadata",{}),"strategy_statistics":ss,
            "pairwise_comparisons":comps,"os_family_breakdown":os_stats}
    class NpEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, (np.integer,)): return int(obj)
            if isinstance(obj, (np.floating,)): return float(obj)
            if isinstance(obj, (np.bool_,)): return bool(obj)
            if isinstance(obj, np.ndarray): return obj.tolist()
            return super().default(obj)
    with open(out/"statistics.json","w") as f: json.dump(output,f,indent=2,cls=NpEncoder)

    # ── FIGURES ──────────────────────────────────────────────────────
    ap_ok=sorted([r for r in by_strat.get("AutoPatch",[]) if r["build_success"] and r["vulns_before_total"]>20],
                 key=lambda x:x["vulns_before_total"], reverse=True)
    legacy=[r["image_name"] for r in ap_ok[:6]]
    if legacy:
        fig,ax=plt.subplots(figsize=(7.16,3.5))
        x=np.arange(len(legacy)); w=0.16
        for si,strat in enumerate(ORDER):
            vals=[]
            for img in legacy:
                r=by_img.get(img,{}).get(strat)
                if r and r["build_success"]:
                    vals.append(r["sev_after"].get("CRITICAL",0)+r["sev_after"].get("HIGH",0))
                elif r:
                    vals.append(r["sev_before"].get("CRITICAL",0)+r["sev_before"].get("HIGH",0))
                else: vals.append(0)
            ax.bar(x+(si-2)*w,vals,w,label=strat,color=COLORS.get(strat,'#888'),
                   edgecolor='black',linewidth=0.4)
        labels=[n.replace("-","\n",1) if len(n)>12 else n for n in legacy]
        ax.set_ylabel('Critical+High Vulns'); ax.set_xticks(x)
        ax.set_xticklabels(labels,fontsize=8)
        ax.legend(loc='upper right',ncol=2,fontsize=7); ax.grid(axis='y',alpha=0.25,ls='--')
        fig.tight_layout()
        fig.savefig(figs/'fig2_effectiveness.pdf',dpi=300,bbox_inches='tight')
        fig.savefig(figs/'fig2_effectiveness.png',dpi=300,bbox_inches='tight')
        plt.close()

    fig,ax=plt.subplots(figsize=(3.5,2.8))
    for strat in ['AutoPatch','Docker-Scout','Naive-Latest','Copacetic']:
        vrs=sorted([e["reduction_pct"] for e in by_strat.get(strat,[])
                    if e["build_success"] and e["vulns_before_total"]>0])
        if not vrs: continue
        ax.plot(vrs,np.arange(1,len(vrs)+1)/len(vrs),lw=1.8,label=strat,color=COLORS.get(strat))
    ax.axvline(x=0,lw=1.5,label='Scan-Only',color=COLORS['Scan-Only'],ls='--')
    ax.set_xlabel('Vulnerability Reduction (%)'); ax.set_ylabel('Cumulative Probability')
    ax.set_xlim(-10,105); ax.set_ylim(0,1.05)
    ax.legend(loc='lower right',fontsize=6.5); ax.grid(True,alpha=0.25,ls=':')
    fig.tight_layout()
    fig.savefig(figs/'fig3_cdf.pdf',dpi=300,bbox_inches='tight')
    fig.savefig(figs/'fig3_cdf.png',dpi=300,bbox_inches='tight')
    plt.close()

    ap_s=sorted([r for r in by_strat.get("AutoPatch",[]) if r["build_success"] and r["vulns_before_total"]>0],
                key=lambda x:x["vulns_before_total"],reverse=True)
    if ap_s:
        n=len(ap_s)
        sc={'CRITICAL':'#d32f2f','HIGH':'#f57c00','MEDIUM':'#fbc02d','LOW':'#4caf50','UNKNOWN':'#9e9e9e'}
        sevs=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
        fig,(a1,a2)=plt.subplots(2,1,figsize=(7.16,4),sharex=True)
        idx=np.arange(n)
        for ax,key,title in [(a1,"sev_before","Pre-Patch"),(a2,"sev_after","Post-Patch")]:
            bot=np.zeros(n)
            for sev in sevs:
                vals=np.array([r[key].get(sev,0) for r in ap_s])
                ax.bar(idx,vals,bottom=bot,color=sc[sev],width=1.0,
                       label=sev if ax is a1 else None,linewidth=0)
                bot+=vals
            ax.set_ylabel('Vulns'); ax.set_title(title,fontsize=10,fontweight='bold')
        a1.legend(loc='upper right',ncol=5,fontsize=7)
        a2.set_xlabel('Images (sorted by pre-patch total)')
        fig.tight_layout()
        fig.savefig(figs/'fig4_severity_panels.pdf',dpi=300,bbox_inches='tight')
        fig.savefig(figs/'fig4_severity_panels.png',dpi=300,bbox_inches='tight')
        plt.close()

    # ── PRINT ─────────────────────────────────────────────────────────
    print("\n"+"="*70)
    print("  EXPERIMENT v3 RESULTS — NUMBERS FOR THE PAPER")
    print("="*70)
    for strat in ORDER:
        s=ss.get(strat,{})
        print(f"\n  {strat}:")
        print(f"    Total:       {s.get('total',0)}")
        print(f"    Success:     {s.get('success',0)} ({100-s.get('fail_rate',0):.1f}%)")
        print(f"    Failures:    {s.get('failures',0)} ({s.get('fail_rate',0):.1f}%)")
        print(f"    VR mean:     {s.get('vr_mean',0):.1f}%")
        print(f"    VR median:   {s.get('vr_median',0):.1f}%")
        print(f"    VR std:      {s.get('vr_std',0):.1f}%")
        print(f"    VR range:    [{s.get('vr_min',0):.1f}%, {s.get('vr_max',0):.1f}%]")
        print(f"    New vulns:   {s.get('new_vulns',0)}")
        print(f"    Accepted:    {s.get('accepted',0)}")
        print(f"    Zero-after:  {s.get('zero_after',0)}")

    print(f"\n  Pairwise: AutoPatch vs baselines:")
    for bl,c in comps.items():
        print(f"\n    vs {bl} ({c.get('paired',0)} paired):")
        if 'cohen_d' in c: print(f"      Cohen's d:  {c['cohen_d']}")
        if 'p_value' in c:
            print(f"      Wilcoxon p: {c['p_value']}")
            print(f"      Sig @0.05:  {c.get('sig_005')}")
            print(f"      Sig @0.01:  {c.get('sig_001')}")

    print(f"\n  OS Family Breakdown (AutoPatch):")
    for f2,s in sorted(os_stats.items()):
        print(f"    {f2:14s}: {s['images']:3d} imgs, VR={s['vr_mean']:5.1f}% ± {s['vr_std']:5.1f}%, fails={s['fails']}")

    print("\n"+"="*70)
    print(f"  Results:    {out/'results.json'}")
    print(f"  CSV:        {out/'results.csv'}")
    print(f"  Stats:      {out/'statistics.json'}")
    print(f"  Figures:    {figs}/")
    print("="*70)

if __name__=="__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv)>3 else str(Path(sys.argv[1]).parent.parent/"figures_v3"))
STATS_EOF

python3 "${WORK_DIR}/stats.py" "$RESULTS_DIR/results.json" "$RESULTS_DIR" "$FIGURES_DIR"

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  DONE                                                                   ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  EXPERIMENT COMPLETE${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Results:    $RESULTS_DIR/results.json"
echo "  CSV:        $RESULTS_DIR/results.csv"
echo "  Stats:      $RESULTS_DIR/statistics.json"
echo "  Figures:    $FIGURES_DIR/"
echo ""
