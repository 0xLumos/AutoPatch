"""
AutoPatch base-image utilities — safer version.

Key behaviours:
- Protect Python base images (do not replace or rewrite them).
- Preserve multi-stage "AS" aliases when replacing FROM lines.
- Use DockerHub to suggest latest tags (optional; requires `requests`).
- Provide a safe fallback when network/requests is unavailable.
"""
from __future__ import annotations
import re
import logging
from typing import Optional

try:
    import requests
except Exception:
    requests = None  # network unavailable in some CI runners

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Match FROM <image>[:<tag>] [AS <name>], case-insensitive
BASE_RE = re.compile(r"^\s*FROM\s+([^\s:@]+(?:/[^\s:@]+)*)(?::([^\s@]+))?", re.IGNORECASE)

# Specific fallback replacements for known problematic images
FALLBACK_BASES = {
    "vulnerables/web-dvwa": "ubuntu:latest",
    "vulnerables": "ubuntu:latest",
    "scratch": "alpine:latest",
    "unknown": "ubuntu:latest"
}


def find_base_image(text: str) -> tuple[Optional[str], Optional[str]]:
    """
    Return (base_name, tag) from the first FROM line in the Dockerfile-like text.
    Example results: ("python", "3.11-slim"), ("ubuntu", "20.04"), (None, None)
    """
    for line in text.splitlines():
        matched = BASE_RE.match(line)
        if matched:
            base = matched.group(1)
            tag = matched.group(2) or "latest"
            logger.debug("Found base image: %s:%s", base, tag)
            return base, tag
    logger.debug("No FROM line found")
    return None, None


def replace_base_image(text: str, new_image: str) -> str:
    """
    Replace the first FROM line's image with new_image while preserving any 'AS <name>' alias.
    Only replaces the first FROM line (the most common need). Returns the modified text.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().upper().startswith("FROM "):
            # preserve trailing "AS <alias>" if present (case-insensitive)
            parts = line.split()
            # find 'AS' index case-insensitive
            alias_suffix = ""
            lower = line.lower()
            as_idx = lower.find(" as ")
            if as_idx != -1:
                alias_suffix = line[as_idx:]  # includes leading space
            # replace line
            lines[i] = f"FROM {new_image}{alias_suffix}"
            logger.info("Replaced FROM line: '%s' -> '%s'", line.strip(), lines[i].strip())
            break
    return "\n".join(lines)


def add_apt_upgrade(text: str) -> str:
    """
    Insert a safe OS-update line immediately after the first FROM line.
    The command uses apt, apk, or yum in a way that won't break builds on different bases.
    """
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
        if not inserted and line.lstrip().upper().startswith("FROM "):
            new_lines.append(insert_line)
            inserted = True

    if not inserted:
        new_lines.append(insert_line)

    logger.debug("Inserted OS upgrade command after first FROM")
    return "\n".join(new_lines)


def get_latest_tag(repo: str) -> str:
    """
    Query Docker Hub for tags for a repo (simple heuristic).
    - If requests is not available or an error occurs, returns "latest".
    - repo may be like "ubuntu" or "library/ubuntu" or "python".
    """
    if requests is None:
        logger.debug("requests not available, returning 'latest'")
        return "latest"

    # normalize repo name: if no namespace given, use `library/<repo>` (docker hub)
    repo = repo.strip().lower()
    if "/" not in repo:
        hub_repo = f"library/{repo}"
    else:
        hub_repo = repo

    url = f"https://hub.docker.com/v2/repositories/{hub_repo}/tags?page_size=50"
    try:
        res = requests.get(url, timeout=8)
        res.raise_for_status()
        data = res.json()
        tags = [t["name"] for t in data.get("results", []) if "name" in t]
        # prefer slim, then lts, then numeric tags, then first available
        for predicate in (lambda s: "slim" in s, lambda s: "lts" in s, lambda s: re.match(r"^\d+(\.|$)", s)):
            filtered = [t for t in tags if predicate(t)]
            if filtered:
                logger.debug("get_latest_tag(%s) -> %s", repo, filtered[0])
                return filtered[0]
        if tags:
            logger.debug("get_latest_tag(%s) -> %s", repo, tags[0])
            return tags[0]
    except Exception as e:
        logger.debug("Failed to fetch tags for %s: %s", repo, e)
    return "latest"


def propose_upgrade(base_name: str, unknown_ratio: float = 0.0) -> Optional[str]:
    """
    Decide what base image to propose given the original base_name.
    - If base_name indicates a Python image, keep it unchanged.
    - For known problematic images (FALLBACK_BASES) return mapped replacement.
    - If unknown_ratio is high, prefer ubuntu:latest as a safe fallback (not alpine by default).
    - For common bases, attempt to suggest an image with a recent tag.
    """
    if not base_name:
        logger.debug("propose_upgrade: no base provided")
        return None

    base = base_name.lower().strip()
    logger.debug("propose_upgrade: evaluating base '%s' (unknown_ratio=%s)", base, unknown_ratio)

    # 1) Protect Python images: keep original exact image (do not rewrite)
    # This prevents accidental replacement with Alpine or other incompatible bases.
    if base.startswith("python") or "python" in base:
        logger.info("propose_upgrade: preserving python base '%s'", base_name)
        return base_name

    # 1b) protect chainguard/other secure python images (exact match), also preserve
    if base.startswith("cgr.dev/chainguard/python"):
        logger.info("propose_upgrade: preserving chainguard python base '%s'", base_name)
        return base_name

    # 2) Check explicit fallbacks for known images
    for key, new_base in FALLBACK_BASES.items():
        if key in base:
            logger.info("propose_upgrade: mapping '%s' -> '%s'", base, new_base)
            return new_base

    # 3) If unknown_ratio is high, use ubuntu as a safe general fallback (avoid alpine unless explicitly requested)
    if unknown_ratio > 0.5:
        if "ubuntu" not in base:
            logger.info("propose_upgrade: unknown_ratio high, using 'ubuntu:latest'")
            return "ubuntu:latest"
        logger.info("propose_upgrade: unknown_ratio high but base already ubuntu, keeping '%s'", base_name)
        return base_name

    # 4) Suggest latest tags for common families (do not touch Python)
    common = ["ubuntu", "debian", "node", "alpine"]
    for c in common:
        if c in base:
            tag = get_latest_tag(c)
            suggested = f"{c}:{tag}"
            logger.info("propose_upgrade: suggesting '%s' for base '%s'", suggested, base_name)
            return suggested

    # 5) As a final fallback, return the original base unchanged
    logger.info("propose_upgrade: no change recommended for '%s'", base_name)
    return base_name
