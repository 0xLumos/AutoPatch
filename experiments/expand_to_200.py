#!/usr/bin/env python3
"""
Expand the Dockerfile dataset to 200 entries with real, buildable base images.

Adds images across OS families, language runtimes, and infrastructure that are
NOT already present. Each Dockerfile is a minimal, single-stage build that
Trivy can scan and (for OS-package images) that Copacetic can patch in-place.

Existing files are never overwritten. Run again idempotently.
"""

from pathlib import Path

DOCKERFILE_DIR = Path(__file__).parent.parent / "dockerfiles"
DOCKERFILE_DIR.mkdir(exist_ok=True)

# (suffix, FROM, extra_lines)  -- extra tuned to the base's package manager
NEW = [
    # ── OS families (deliberately old, real CVEs, in-place patchable) ──
    ("alpine-3.14", "alpine:3.14", "RUN apk add --no-cache curl"),
    ("alpine-3.18", "alpine:3.18", "RUN apk add --no-cache curl git"),
    ("alpine-3.9",  "alpine:3.9",  "RUN apk add --no-cache curl"),
    ("debian-jessie", "debian:jessie", "RUN echo debian jessie"),
    ("ubuntu-24.04", "ubuntu:24.04", "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu-14.04", "ubuntu:14.04", "RUN echo ubuntu trusty"),
    ("oraclelinux-8", "oraclelinux:8", "RUN dnf install -y curl && dnf clean all"),
    ("oraclelinux-9", "oraclelinux:9", "RUN dnf install -y curl && dnf clean all"),
    ("amazonlinux-2", "amazonlinux:2", "RUN yum install -y curl && yum clean all"),
    ("amazonlinux-2023", "amazonlinux:2023", "RUN dnf install -y curl-minimal && dnf clean all"),
    ("fedora-38", "fedora:38", "RUN dnf install -y curl && dnf clean all"),
    ("fedora-39", "fedora:39", "RUN dnf install -y curl && dnf clean all"),
    ("opensuse-leap-15", "opensuse/leap:15.4", "RUN zypper --non-interactive install curl"),
    ("photon-4", "photon:4.0", "RUN tdnf install -y curl && tdnf clean all"),
    ("busybox-1.35", "busybox:1.35", 'CMD ["true"]'),
    ("rockylinux-8-minimal", "rockylinux:8-minimal", "RUN microdnf install -y curl"),

    # ── Python ──
    ("python-3.5", "python:3.5", 'CMD ["python", "-c", "print(1)"]'),
    ("python-3.12", "python:3.12", 'RUN pip install requests==2.31.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.11-slim", "python:3.11-slim", 'RUN pip install flask==3.0.0\nCMD ["python", "-c", "print(1)"]'),
    ("python-3.9-slim", "python:3.9-slim", 'RUN pip install requests==2.28.0\nCMD ["python", "-c", "print(1)"]'),

    # ── Node.js ──
    ("node-10", "node:10", 'CMD ["node", "-e", "console.log(1)"]'),
    ("node-20-alpine", "node:20-alpine", 'CMD ["node", "-e", "console.log(1)"]'),
    ("node-22", "node:22", 'CMD ["node", "-e", "console.log(1)"]'),

    # ── Go ──
    ("golang-1.17", "golang:1.17", 'CMD ["go", "version"]'),
    ("golang-1.22", "golang:1.22", 'CMD ["go", "version"]'),

    # ── Java ──
    ("openjdk-21", "openjdk:21", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-11", "eclipse-temurin:11", 'CMD ["java", "-version"]'),
    ("eclipse-temurin-21", "eclipse-temurin:21", 'CMD ["java", "-version"]'),
    ("amazoncorretto-17", "amazoncorretto:17", 'CMD ["java", "-version"]'),

    # ── Ruby ──
    ("ruby-3.3", "ruby:3.3", 'CMD ["ruby", "-v"]'),
    ("ruby-3.0-slim", "ruby:3.0-slim", 'CMD ["ruby", "-v"]'),

    # ── PHP ──
    ("php-8.3", "php:8.3", 'CMD ["php", "-v"]'),
    ("php-8.2-apache", "php:8.2-apache", "EXPOSE 80"),
    ("php-8.1-fpm", "php:8.1-fpm", "EXPOSE 9000"),

    # ── Rust / Perl / .NET / BEAM ──
    ("rust-1.70", "rust:1.70", 'CMD ["rustc", "--version"]'),
    ("rust-1.75", "rust:1.75", 'CMD ["rustc", "--version"]'),
    ("perl-5.36", "perl:5.36", 'CMD ["perl", "-v"]'),
    ("dotnet-sdk-8.0", "mcr.microsoft.com/dotnet/sdk:8.0", 'CMD ["dotnet", "--version"]'),
    ("dotnet-aspnet-8.0", "mcr.microsoft.com/dotnet/aspnet:8.0", "EXPOSE 8080"),
    ("elixir-1.14", "elixir:1.14", 'CMD ["elixir", "--version"]'),
    ("erlang-25", "erlang:25", 'CMD ["erl", "-version"]'),

    # ── Web servers / proxies ──
    ("nginx-1.20", "nginx:1.20", "EXPOSE 80"),
    ("nginx-1.22", "nginx:1.22", "EXPOSE 80"),
    ("httpd-2.4.57", "httpd:2.4.57", "EXPOSE 80"),
    ("caddy-2.7", "caddy:2.7", "EXPOSE 80 443"),
    ("traefik-3.0", "traefik:v3.0", "EXPOSE 80 443"),
    ("kong-3.4", "kong:3.4", "EXPOSE 8000"),

    # ── Databases / caches ──
    ("redis-7", "redis:7", "EXPOSE 6379"),
    ("redis-7.2", "redis:7.2", "EXPOSE 6379"),
    ("postgres-10", "postgres:10", "EXPOSE 5432"),
    ("postgres-15", "postgres:15", "EXPOSE 5432"),
    ("postgres-16", "postgres:16", "EXPOSE 5432"),
    ("mariadb-11.0", "mariadb:11.0", "EXPOSE 3306"),
    ("mongo-7.0", "mongo:7.0", "EXPOSE 27017"),
    ("memcached-1.6.21", "memcached:1.6.21", "EXPOSE 11211"),

    # ── Queues / search ──
    ("rabbitmq-3.12", "rabbitmq:3.12", "EXPOSE 5672"),
    ("elasticsearch-8.5", "docker.elastic.co/elasticsearch/elasticsearch:8.5.0",
     'ENV discovery.type=single-node\nEXPOSE 9200'),

    # ── CI/CD / infra / apps ──
    ("vault-1.15", "hashicorp/vault:1.15", 'CMD ["vault", "version"]'),
    ("consul-1.15", "hashicorp/consul:1.15", "EXPOSE 8500"),
    ("wordpress-6.2", "wordpress:6.2", "EXPOSE 80"),
    ("drupal-8", "drupal:8", "EXPOSE 80"),
    ("sonarqube-10", "sonarqube:10.0-community", "EXPOSE 9000"),
]


def render(from_line: str, extra: str) -> str:
    lines = [f"FROM {from_line}"]
    low = from_line.lower()
    if "distroless" not in low and low != "scratch":
        lines.append("WORKDIR /app")
    if extra:
        lines.extend(extra.split("\n"))
    return "\n".join(lines) + "\n"


def main():
    target = 200
    existing = len(list(DOCKERFILE_DIR.glob("Dockerfile.*")))
    created = 0
    for suffix, from_line, extra in NEW:
        if len(list(DOCKERFILE_DIR.glob("Dockerfile.*"))) >= target:
            break
        fp = DOCKERFILE_DIR / f"Dockerfile.{suffix}"
        if fp.exists():
            continue
        fp.write_text(render(from_line, extra))
        created += 1
        print(f"  [+] {fp.name}  (FROM {from_line})")
    total = len(list(DOCKERFILE_DIR.glob("Dockerfile.*")))
    print(f"\nStarted at {existing}, created {created}, total now {total}")
    if total < target:
        print(f"  ! Still {target - total} short of {target}; add more entries to NEW[].")


if __name__ == "__main__":
    main()
