from __future__ import annotations
import re
from typing import Optional
try:
    import requests
except Exception:
    requests = None

BASE_RE = re.compile(r"^\s*FROM\s+([^\s:@]+)(?::([^\s@]+))?", re.IGNORECASE)

FALLBACK_BASES = {
    "vulnerables/web-dvwa": "ubuntu:latest",
    "vulnerables": "ubuntu:latest",
    "scratch": "alpine:latest",
    "unknown": "ubuntu:latest"
}


def find_base_image(text: str) -> tuple[Optional[str], Optional[str]]:
    for line in text.splitlines():
        m = BASE_RE.match(line)
        if m:
            return m.group(1), m.group(2)
    return None, None


def replace_base_image(text: str, new_image: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().upper().startswith("FROM "):
            lines[i] = f"FROM {new_image}"
            break
    return "\n".join(lines)


def add_apt_upgrade(text: str) -> str:
    lines = text.splitlines()
    insert_line = (
        "RUN (apt-get update -y && apt-get dist-upgrade -y) "
        "|| (apk update && apk upgrade) "
        "|| (yum update -y) || true"
    )

    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if not inserted and line.strip().upper().startswith("FROM "):
            new_lines.append(insert_line)
            inserted = True

    if not inserted:
        new_lines.append(insert_line)

    return "\n".join(new_lines)


def get_latest_tag(repo: str) -> Optional[str]:
    if requests is None:
        return "latest"
    repo = repo.lower().strip()
    url = f"https://hub.docker.com/v2/repositories/library/{repo}/tags?page_size=50"
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        data = res.json()
        tags = [t["name"] for t in data.get("results", []) if "name" in t]
        slim = [t for t in tags if "slim" in t]
        lts = [t for t in tags if "lts" in t]
        for pref in (slim, lts, tags):
            if pref:
                return pref[0]
    except Exception:
        pass
    return "latest"


def propose_upgrade(base_name: str, unknown_ratio: float = 0.0) -> Optional[str]:
    
    if not base_name:
        return None

    base = base_name.lower().strip()

    for key, new_base in FALLBACK_BASES.items():
        if key in base:
            return new_base

    if unknown_ratio > 0.5:
        if "alpine" not in base:
            return "alpine:latest"
        return "ubuntu:latest"

    common = ["ubuntu", "debian", "python", "node", "alpine"]
    for c in common:
        if c in base:
            tag = get_latest_tag(c)
            return f"{c}:{tag}"

    return "latest"
