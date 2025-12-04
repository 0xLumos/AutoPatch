import json
import re
from typing import Tuple
from .utils import log_info


FIRST_FROM_RE = re.compile(
    r"^\s*FROM\s+([^\s:@]+(?:/[^\s:@]+)*)(?::([^\s@]+))?",
    re.IGNORECASE
)


# ------------------------------------------------------------
# Extract base
# ------------------------------------------------------------
def extract_first_base(text: str) -> Tuple[str, str]:
    for line in text.splitlines():
        m = FIRST_FROM_RE.match(line)
        if m:
            return m.group(1), (m.group(2) or "latest")
    return None, None


# ------------------------------------------------------------
# SBOM → distro family
# ------------------------------------------------------------
def detect_family(sbom: dict) -> str:
    meta = json.dumps(sbom).lower()

    if any(x in meta for x in ["centos", "red hat", "rhel"]):
        return "redhat"
    if "apk-tools" in meta or "musl" in meta:
        return "alpine"
    if "dpkg" in meta:
        return "debian"

    return "unknown"


# ------------------------------------------------------------
# Based on family, propose new base
# ------------------------------------------------------------
def choose_base(family: str) -> str:
    if family == "redhat":
        return "rockylinux:9"
    if family == "alpine":
        return "alpine:3.20"
    if family == "debian":
        return "debian:bookworm"
    return "ubuntu:latest"


# ------------------------------------------------------------
# Replace only the FROM line — preserve everything else
# ------------------------------------------------------------
def replace_from_only(text: str, new_base: str) -> str:
    lines = text.splitlines()
    output = []

    replaced = False
    for line in lines:
        if not replaced and FIRST_FROM_RE.match(line):
            idx = line.lower().find(" as ")
            alias = line[idx:] if idx != -1 else ""
            output.append(f"FROM {new_base}{alias}")
            replaced = True
        else:
            output.append(line)

    return "\n".join(output)


# ------------------------------------------------------------
# Insert appropriate OS upgrade block based on distro
# ------------------------------------------------------------
def insert_upgrade_block(text: str, new_base: str) -> str:
    lines = text.splitlines()
    new_lines = []
    inserted = False

    # Detect what update commands to use
    ubuntu_debian_upgrade = (
        "RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list || true && "
        "sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list || true && "
        "sed -i 's|deb.debian.org|archive.debian.org|g' /etc/apt/sources.list || true && "
        "apt-get update -y || true && apt-get dist-upgrade -y || true"
    )

    alpine_upgrade = "RUN apk update && apk upgrade || true"
    rhel_upgrade = "RUN yum update -y || true"

    # Choose correct upgrade block
    if "ubuntu" in new_base or "debian" in new_base:
        upgrade_block = ubuntu_debian_upgrade
    elif "alpine" in new_base:
        upgrade_block = alpine_upgrade
    elif "rockylinux" in new_base or "centos" in new_base:
        upgrade_block = rhel_upgrade
    else:
        upgrade_block = "RUN true"

    for line in lines:
        new_lines.append(line)

        if not inserted and line.strip().upper().startswith("FROM "):
            new_lines.append(upgrade_block)
            inserted = True

    return "\n".join(new_lines)


# ------------------------------------------------------------
# PROFESSIONAL PATCHER — preserves everything, only upgrades FROM
# ------------------------------------------------------------
def patch_dockerfile(text: str, sbom_path: str):
    # Load SBOM
    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    # Extract original base
    base, tag = extract_first_base(text)
    log_info(f"Found base image: {base}:{tag}")

    # Detect distro family
    family = detect_family(sbom)
    log_info(f"SBOM family detected: {family}")

    # Select new base according to your research logic
    new_base = choose_base(family)
    log_info(f"New base proposed: {new_base}")

    # STEP 1 — Only replace FROM (preserve rest of Dockerfile)
    patched = replace_from_only(text, new_base)

    # STEP 2 — Insert upgrade block *after* new FROM (for EOL, security)
    patched = insert_upgrade_block(patched, new_base)

    # All RUN, COPY, ENV, EXPOSE, WORKDIR … lines remain intact
    return patched, base, new_base
