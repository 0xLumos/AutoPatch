#!/usr/bin/env python3
"""
Generate a comprehensive Dockerfile dataset for AutoPatch experiments.

Creates ~120 Dockerfiles across these categories:
  - OS families: Alpine, Debian, Ubuntu, CentOS, Rocky, Alma, Distroless, Scratch
  - Language runtimes: Python, Node.js, Go, Java/OpenJDK, Ruby, PHP
  - Infrastructure: Nginx, Apache, Redis, PostgreSQL, MySQL, MongoDB, MariaDB
  - CI/CD & DevTools: Jenkins, Vault, Consul
  - CMS & Applications: WordPress, Nextcloud, Drupal, Ghost

Each Dockerfile is intentionally outdated to have known vulnerabilities.
"""

import os
from pathlib import Path

# Target directory
DOCKERFILE_DIR = Path(__file__).parent.parent / "dockerfiles"
DOCKERFILE_DIR.mkdir(exist_ok=True)

# ─── Dockerfile templates ────────────────────────────────────────────────
# Each entry: (filename_suffix, FROM line, optional extra lines)

DATASET = [
    # ═══════════════════════════════════════════════════════════════════════
    # OS FAMILIES (base images, deliberately old versions)
    # ═══════════════════════════════════════════════════════════════════════

    # Alpine
    ("alpine-3.12", "alpine:3.12", "RUN apk add --no-cache curl"),
    ("alpine-3.14", "alpine:3.14", "RUN apk add --no-cache curl wget"),
    ("alpine-3.16", "alpine:3.16", "RUN apk add --no-cache curl bash"),
    ("alpine-3.18", "alpine:3.18", "RUN apk add --no-cache curl git"),

    # Debian
    ("debian-stretch", "debian:stretch", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("debian-buster", "debian:buster", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("debian-bullseye", "debian:bullseye", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("debian-bookworm", "debian:bookworm", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),

    # Ubuntu
    ("ubuntu-16.04", "ubuntu:16.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-18.04", "ubuntu:18.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-20.04", "ubuntu:20.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-22.04", "ubuntu:22.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-24.04", "ubuntu:24.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),

    # CentOS
    ("centos-7", "centos:7", "RUN yum install -y curl && yum clean all"),

    # Rocky Linux
    ("rockylinux-8", "rockylinux:8", "RUN dnf install -y curl && dnf clean all"),
    ("rockylinux-9", "rockylinux:9", "RUN dnf install -y curl && dnf clean all"),

    # AlmaLinux
    ("almalinux-8", "almalinux:8", "RUN dnf install -y curl && dnf clean all"),
    ("almalinux-9", "almalinux:9", "RUN dnf install -y curl && dnf clean all"),

    # Distroless
    ("distroless-base", "gcr.io/distroless/base-debian11", ""),
    ("distroless-java", "gcr.io/distroless/java17-debian11", "COPY --from=builder /app/app.jar /app.jar"),

    # Scratch
    ("scratch", "scratch", "COPY --from=builder /app /app"),

    # ═══════════════════════════════════════════════════════════════════════
    # PYTHON RUNTIMES
    # ═══════════════════════════════════════════════════════════════════════
    ("python-3.6", "python:3.6", 'RUN pip install flask==2.0.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.7", "python:3.7", 'RUN pip install flask==2.0.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.8", "python:3.8", 'RUN pip install flask==2.2.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.9", "python:3.9", 'RUN pip install flask==2.2.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.10", "python:3.10", 'RUN pip install flask==2.3.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.11", "python:3.11", 'RUN pip install flask==3.0.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.8-slim", "python:3.8-slim", 'RUN pip install requests==2.28.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.9-alpine", "python:3.9-alpine", 'RUN pip install requests==2.28.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.10-bullseye", "python:3.10-bullseye", 'RUN pip install django==4.0\nCMD ["python", "-c", "print(1)"]'),

    # ═══════════════════════════════════════════════════════════════════════
    # NODE.JS RUNTIMES
    # ═══════════════════════════════════════════════════════════════════════
    ("node-12", "node:12", 'RUN npm init -y && npm install express@4.17.1\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-14", "node:14", 'RUN npm init -y && npm install express@4.17.1\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-16", "node:16", 'RUN npm init -y && npm install express@4.18.0\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-18", "node:18", 'RUN npm init -y && npm install express@4.18.2\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-20", "node:20", 'RUN npm init -y && npm install express@4.19.0\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-14-alpine", "node:14-alpine", 'RUN npm init -y\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-16-slim", "node:16-slim", 'RUN npm init -y\nCMD ["node", "-e", "console.log(1)"]'),
    ("node-18-bullseye", "node:18-bullseye", 'RUN npm init -y\nCMD ["node", "-e", "console.log(1)"]'),

    # ═══════════════════════════════════════════════════════════════════════
    # GO RUNTIMES
    # ═══════════════════════════════════════════════════════════════════════
    ("golang-1.16", "golang:1.16", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.18", "golang:1.18", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.19", "golang:1.19", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.20", "golang:1.20", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.21", "golang:1.21", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.16-alpine", "golang:1.16-alpine", 'RUN go version\nCMD ["go", "version"]'),
    ("golang-1.19-bullseye", "golang:1.19-bullseye", 'RUN go version\nCMD ["go", "version"]'),

    # ═══════════════════════════════════════════════════════════════════════
    # JAVA / OPENJDK
    # ═══════════════════════════════════════════════════════════════════════
    ("openjdk-8", "openjdk:8", 'CMD ["java", "-version"]'),
    ("openjdk-11", "openjdk:11", 'CMD ["java", "-version"]'),
    ("openjdk-17", "openjdk:17", 'CMD ["java", "-version"]'),
    ("adoptopenjdk-11", "adoptopenjdk:11-jre-hotspot", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-11", "eclipse-temurin:11", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-17", "eclipse-temurin:17", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-21", "eclipse-temurin:21", 'CMD ["java", "-version"]'),

    # ═══════════════════════════════════════════════════════════════════════
    # RUBY
    # ═══════════════════════════════════════════════════════════════════════
    ("ruby-2.7", "ruby:2.7", 'CMD ["ruby", "-v"]'),
    ("ruby-3.0", "ruby:3.0", 'CMD ["ruby", "-v"]'),
    ("ruby-3.1", "ruby:3.1", 'CMD ["ruby", "-v"]'),
    ("ruby-3.2", "ruby:3.2", 'CMD ["ruby", "-v"]'),
    ("ruby-2.7-alpine", "ruby:2.7-alpine", 'CMD ["ruby", "-v"]'),

    # ═══════════════════════════════════════════════════════════════════════
    # PHP
    # ═══════════════════════════════════════════════════════════════════════
    ("php-7.4", "php:7.4", 'CMD ["php", "-v"]'),
    ("php-8.0", "php:8.0", 'CMD ["php", "-v"]'),
    ("php-8.1", "php:8.1", 'CMD ["php", "-v"]'),
    ("php-8.2", "php:8.2", 'CMD ["php", "-v"]'),
    ("php-7.4-apache", "php:7.4-apache", "EXPOSE 80"),
    ("php-8.0-fpm", "php:8.0-fpm", "EXPOSE 9000"),
    ("php-8.1-alpine", "php:8.1-alpine", 'CMD ["php", "-v"]'),

    # ═══════════════════════════════════════════════════════════════════════
    # WEB SERVERS / PROXIES
    # ═══════════════════════════════════════════════════════════════════════
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

    # ═══════════════════════════════════════════════════════════════════════
    # DATABASES
    # ═══════════════════════════════════════════════════════════════════════
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

    # ═══════════════════════════════════════════════════════════════════════
    # MESSAGE QUEUES / SEARCH
    # ═══════════════════════════════════════════════════════════════════════
    ("rabbitmq-3.9", "rabbitmq:3.9", "EXPOSE 5672"),
    ("rabbitmq-3.11", "rabbitmq:3.11", "EXPOSE 5672"),
    ("elasticsearch-7.17.0", "docker.elastic.co/elasticsearch/elasticsearch:7.17.0",
     'ENV discovery.type=single-node\nEXPOSE 9200'),
    ("kafka-old", "bitnami/kafka:3.3", "EXPOSE 9092"),

    # ═══════════════════════════════════════════════════════════════════════
    # CI/CD & DEVTOOLS
    # ═══════════════════════════════════════════════════════════════════════
    ("jenkins-2.164", "jenkins/jenkins:2.164.1-lts", "EXPOSE 8080"),
    ("jenkins-lts", "jenkins/jenkins:lts", "EXPOSE 8080"),
    ("vault-1.12", "hashicorp/vault:1.12.0", 'CMD ["vault", "version"]'),
    ("vault-1.14", "hashicorp/vault:1.14.0", 'CMD ["vault", "version"]'),
    ("consul-1.14", "hashicorp/consul:1.14", "EXPOSE 8500"),
    ("sonarqube-9", "sonarqube:9.9-community", "EXPOSE 9000"),
    ("gitlab-runner", "gitlab/gitlab-runner:v15.0.0", 'CMD ["gitlab-runner", "--version"]'),

    # ═══════════════════════════════════════════════════════════════════════
    # CMS & APPLICATIONS
    # ═══════════════════════════════════════════════════════════════════════
    ("wordpress-5", "wordpress:5", "EXPOSE 80"),
    ("wordpress-6", "wordpress:6.0", "EXPOSE 80"),
    ("nextcloud-25", "nextcloud:25", "EXPOSE 80"),
    ("nextcloud-27", "nextcloud:27", "EXPOSE 80"),
    ("drupal-9", "drupal:9", "EXPOSE 80"),
    ("drupal-10", "drupal:10", "EXPOSE 80"),
    ("ghost-5", "ghost:5", "EXPOSE 2368"),
    ("joomla-4", "joomla:4", "EXPOSE 80"),

    # ═══════════════════════════════════════════════════════════════════════
    # MULTI-STAGE BUILDS (test Dockerfile rewrite correctness)
    # ═══════════════════════════════════════════════════════════════════════
    ("multistage-python", None, None),  # special handling below
    ("multistage-go", None, None),
    ("multistage-node", None, None),
    ("multistage-java", None, None),
]

# Multi-stage Dockerfile templates
MULTISTAGE_TEMPLATES = {
    "multistage-python": """FROM python:3.8 AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.8-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY . .
CMD ["python", "app.py"]
""",
    "multistage-go": """FROM golang:1.18 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/main .

FROM alpine:3.14
WORKDIR /app
COPY --from=builder /app/main .
CMD ["./main"]
""",
    "multistage-node": """FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:16-slim
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
CMD ["node", "dist/index.js"]
""",
    "multistage-java": """FROM maven:3.8-openjdk-11 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn package -DskipTests

FROM openjdk:11-jre-slim
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
CMD ["java", "-jar", "app.jar"]
""",
}


def generate_simple_dockerfile(from_line: str, extra_lines: str) -> str:
    """Generate a simple single-stage Dockerfile."""
    lines = [f"FROM {from_line}"]

    # Distroless and scratch don't support RUN
    if "distroless" not in from_line and "scratch" not in from_line:
        lines.append("WORKDIR /app")

    if extra_lines:
        for line in extra_lines.split("\n"):
            lines.append(line)

    return "\n".join(lines) + "\n"


def main():
    count = 0
    skipped = 0

    for entry in DATASET:
        name = entry[0]
        from_line = entry[1]
        extra = entry[2]

        filepath = DOCKERFILE_DIR / f"Dockerfile.{name}"

        # Skip if file already exists (don't overwrite user customizations)
        if filepath.exists():
            print(f"  [skip] {filepath.name} (already exists)")
            skipped += 1
            continue

        if from_line is None:
            # Multi-stage template
            if name in MULTISTAGE_TEMPLATES:
                content = MULTISTAGE_TEMPLATES[name]
            else:
                print(f"  [warn] No template for multi-stage {name}")
                continue
        else:
            content = generate_simple_dockerfile(from_line, extra)

        filepath.write_text(content)
        count += 1
        print(f"  [+] Created {filepath.name}")

    total = count + skipped
    print(f"\nDone: {count} created, {skipped} skipped (already existed), {total} total")
    print(f"Total Dockerfiles in {DOCKERFILE_DIR}: {len(list(DOCKERFILE_DIR.glob('Dockerfile.*')))}")


if __name__ == "__main__":
    main()
