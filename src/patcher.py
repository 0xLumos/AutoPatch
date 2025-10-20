import re
from typing import Optional

BASE_RE = re.compile(r"^\s*FROM\s+([^\s:]+)(?::([^\s@]+))?", re.IGNORECASE)


def find_base_image(text: str):
    for line in text.splitlines():
        m = BASE_RE.match(line)
        if m:
            return m.group(1), m.group(2)
    return None, None


def replace_base_image(text: str, new_image: str):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("FROM "):
            lines[i] = f"FROM {new_image}"
            break
    return "\n".join(lines)


def add_apt_upgrade(text: str):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "apt-get install" in line and "apt-get update" not in line:
            lines.insert(i, "RUN apt-get update -y && apt-get upgrade -y || true")
            break
    return "\n".join(lines)


def propose_upgrade(base_name: str):
    mapping = {
        "python": "python:3.11-slim",
        "node": "node:20-slim",
        "ubuntu": "ubuntu:24.04",
        "debian": "debian:12-slim",
        "alpine": "alpine:3.19"
    }
    for k, v in mapping.items():
        if base_name.lower().startswith(k):
            return v
    return None
