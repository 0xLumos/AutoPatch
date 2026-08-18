"""
AutoPatch In-Place Patching Mode (J1)

Provides an OS-level in-place patching strategy as an alternative to
full base-image replacement. This is useful when:
  - The image cannot be rebuilt (no Dockerfile available, or build is complex)
  - The operator wants minimal changes (OS patches only, no base change)
  - Speed is critical (in-place patching is faster than rebuild)

Uses the image's native package manager to upgrade vulnerable OS packages
without changing the base image. This is similar to what Copacetic (copa)
does, but integrated into the AutoPatch pipeline.

Scope note: an application-package tier (pip/npm/gem upgrades) previously
lived here and in ``app_patcher.py``. It was removed. AutoPatch's claim,
and its evaluation, concern the OS package layer reached through the base
image; upgrading a project's own Python or npm dependencies is a
different problem with different correctness conditions (lockfile and
transitive-constraint solving, semantic-version compatibility, the
project's own test suite as the only real oracle) that this pipeline was
never able to verify. Shipping it unevaluated meant claiming remediation
we could not substantiate.

Design notes:
  - In-place patching creates a new layer on top of the existing image.
    This means the original vulnerable files still exist in lower layers.
    For full supply chain integrity, base image replacement (the default
    AutoPatch mode) is preferred.
  - This module generates a "patch Dockerfile" that uses the original image
    as its base and adds RUN commands for package upgrades.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set

logger = logging.getLogger("docker_patch_tool")


# ════════════════════════════════════════════════════════════════════
# Data structures
# ════════════════════════════════════════════════════════════════════

@dataclass
class InPlacePatchResult:
    """Result of in-place patching analysis and generation."""
    original_image: str = ""
    patch_dockerfile: str = ""  # Generated Dockerfile content
    os_upgrade_commands: List[str] = field(default_factory=list)
    os_packages_to_upgrade: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    skipped_packages: List[Dict[str, str]] = field(default_factory=list)


# Package manager detection from OS family
_OS_PKG_MANAGERS = {
    "alpine": {
        "update": "apk update",
        "upgrade_cmd": "apk add --no-cache",
        "upgrade_all": "apk upgrade --no-cache",
    },
    "debian": {
        "update": "apt-get update",
        "upgrade_cmd": "apt-get install -y --no-install-recommends",
        "upgrade_all": "apt-get upgrade -y",
        "cleanup": "rm -rf /var/lib/apt/lists/*",
    },
    "ubuntu": {
        "update": "apt-get update",
        "upgrade_cmd": "apt-get install -y --no-install-recommends",
        "upgrade_all": "apt-get upgrade -y",
        "cleanup": "rm -rf /var/lib/apt/lists/*",
    },
    "centos": {
        "update": "yum makecache",
        "upgrade_cmd": "yum update -y",
        "upgrade_all": "yum update -y",
        "cleanup": "yum clean all",
    },
    "rhel": {
        "update": "dnf makecache",
        "upgrade_cmd": "dnf update -y",
        "upgrade_all": "dnf update -y",
        "cleanup": "dnf clean all",
    },
    "rocky": {
        "update": "dnf makecache",
        "upgrade_cmd": "dnf update -y",
        "upgrade_all": "dnf update -y",
        "cleanup": "dnf clean all",
    },
    "alma": {
        "update": "dnf makecache",
        "upgrade_cmd": "dnf update -y",
        "upgrade_all": "dnf update -y",
        "cleanup": "dnf clean all",
    },
    "fedora": {
        "update": "dnf makecache",
        "upgrade_cmd": "dnf update -y",
        "upgrade_all": "dnf update -y",
        "cleanup": "dnf clean all",
    },
    "amazon": {
        "update": "yum makecache",
        "upgrade_cmd": "yum update -y",
        "upgrade_all": "yum update -y",
        "cleanup": "yum clean all",
    },
}


# ════════════════════════════════════════════════════════════════════
# Tier 1: OS-Level In-Place Patching
# ════════════════════════════════════════════════════════════════════

def extract_os_vulnerable_packages(
    scan_result: Dict[str, Any],
    os_family: str,
) -> List[Dict[str, str]]:
    """
    Extract OS-level vulnerable packages from Trivy scan results.

    Args:
        scan_result: Trivy JSON scan results
        os_family: Detected OS family (alpine, debian, ubuntu, etc.)

    Returns:
        List of dicts with name, installed_version, fix_version, severity, cve_id
    """
    os_types = {
        "alpine", "debian", "ubuntu", "centos", "redhat", "rocky",
        "amazon", "oracle", "suse", "photon", "cbl-mariner", "wolfi",
    }

    packages: List[Dict[str, str]] = []
    seen: Set[str] = set()

    for result_entry in scan_result.get("Results", []):
        result_type = result_entry.get("Type", "").lower()
        if result_type not in os_types:
            continue

        for vuln in result_entry.get("Vulnerabilities", []):
            pkg_name = vuln.get("PkgName", "")
            fix_ver = vuln.get("FixedVersion", "")
            if not pkg_name or not fix_ver:
                continue

            key = f"{pkg_name}:{fix_ver}"
            if key in seen:
                continue
            seen.add(key)

            packages.append({
                "name": pkg_name,
                "installed_version": vuln.get("InstalledVersion", ""),
                "fix_version": fix_ver,
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cve_id": vuln.get("VulnerabilityID", ""),
            })

    logger.info(
        f"Found {len(packages)} OS-level vulnerable packages with available fixes"
    )
    return packages


def generate_os_patch_commands(
    packages: List[Dict[str, str]],
    os_family: str,
    targeted: bool = True,
) -> Tuple[List[str], List[str]]:
    """
    Generate OS package manager commands to patch vulnerable packages.

    Args:
        packages: List of vulnerable package dicts from extract_os_vulnerable_packages
        os_family: Detected OS family
        targeted: If True, upgrade specific packages. If False, upgrade all.

    Returns:
        Tuple of (commands, warnings)
    """
    pkg_info = _OS_PKG_MANAGERS.get(os_family)
    if not pkg_info:
        return [], [f"No package manager configuration for OS family '{os_family}'"]

    commands: List[str] = []
    warnings: List[str] = []

    # Always start with updating the package index
    commands.append(pkg_info["update"])

    if targeted and packages:
        # Targeted upgrade: only the specific vulnerable packages
        pkg_names = sorted(set(p["name"] for p in packages))
        upgrade_cmd = pkg_info["upgrade_cmd"]

        # Batch packages into groups to avoid excessively long command lines
        batch_size = 20
        for i in range(0, len(pkg_names), batch_size):
            batch = pkg_names[i:i + batch_size]
            commands.append(f"{upgrade_cmd} {' '.join(batch)}")
    else:
        # Full upgrade: upgrade everything
        commands.append(pkg_info["upgrade_all"])
        warnings.append(
            "Using full OS upgrade instead of targeted patches. "
            "This may change more packages than necessary."
        )

    # Cleanup to reduce layer size
    cleanup = pkg_info.get("cleanup")
    if cleanup:
        commands.append(cleanup)

    return commands, warnings


# ════════════════════════════════════════════════════════════════════
# Combined: Generate In-Place Patch Dockerfile
# ════════════════════════════════════════════════════════════════════

def generate_inplace_patch(
    original_image: str,
    scan_result: Dict[str, Any],
    os_family: str,
    sbom_data: Optional[Dict[str, Any]] = None,
    targeted_os: bool = True,
) -> InPlacePatchResult:
    """
    Generate a complete in-place patch Dockerfile.

    The generated Dockerfile uses the ORIGINAL image as its base and adds
    RUN commands to upgrade vulnerable packages.

    Args:
        original_image: Original image reference (used as FROM base)
        scan_result: Trivy JSON scan results
        os_family: Detected OS family
        sbom_data: CycloneDX SBOM data. Retained because callers pass it
            and future OS-level heuristics may use it; it no longer feeds
            an application-package tier.
        targeted_os: If True, upgrade specific packages. If False, upgrade all OS packages.

    Returns:
        InPlacePatchResult with generated Dockerfile and metadata
    """
    result = InPlacePatchResult(original_image=original_image)

    os_packages = extract_os_vulnerable_packages(scan_result, os_family)
    result.os_packages_to_upgrade = os_packages

    if os_packages:
        os_commands, os_warnings = generate_os_patch_commands(
            os_packages, os_family, targeted=targeted_os
        )
        result.os_upgrade_commands = os_commands
        result.warnings.extend(os_warnings)
    else:
        result.warnings.append("No OS-level vulnerable packages with fixes found")

    # Generate the patch Dockerfile
    lines = [
        f"# AutoPatch In-Place Patch Dockerfile",
        f"# Generated for: {original_image}",
        f"# Strategy: in-place OS package upgrade",
        f"# WARNING: Vulnerable files remain in lower image layers.",
        f"# For full remediation, use base image replacement mode.",
        f"",
        f"FROM {original_image}",
        f"",
    ]

    if result.os_upgrade_commands:
        lines.append("# OS-level security patches")
        combined_os = " && \\\n    ".join(result.os_upgrade_commands)
        lines.append(f"RUN {combined_os}")
        lines.append("")

    result.patch_dockerfile = "\n".join(lines)

    logger.info(
        "In-place patch generated: %d OS packages",
        len(result.os_packages_to_upgrade),
    )

    return result


def save_inplace_patch(
    result: InPlacePatchResult,
    output_dir: str,
    filename: str = "Dockerfile.patch",
) -> Optional[str]:
    """
    Save the generated patch Dockerfile to disk.

    Args:
        result: InPlacePatchResult from generate_inplace_patch
        output_dir: Directory to write the file
        filename: Output filename (default: Dockerfile.patch)

    Returns:
        Full path to the saved file, or None on failure
    """
    if not result.patch_dockerfile:
        logger.warning("No patch Dockerfile content to save")
        return None

    try:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(result.patch_dockerfile)
        logger.info(f"Saved in-place patch Dockerfile to {path}")
        return path
    except OSError as e:
        logger.error(f"Failed to save patch Dockerfile: {e}")
        return None
