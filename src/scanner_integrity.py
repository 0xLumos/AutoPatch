"""
Scanner Binary Integrity Verification Module

Verifies the integrity and authenticity of scanner binaries (Trivy, Grype)
before they are used in the pipeline. This defends against supply chain
attacks where a compromised scanner binary could hide vulnerabilities
or inject false results.

Defense layers:
1. Cosign verify-blob: Verify binary signature against Sigstore transparency log
2. SHA256 checksum: Compare binary hash against known-good checksums
3. Version pinning: Ensure the installed version matches expected version

References:
- CVE-2026-33634 / GHSA-69fq-xp46-6x23: Trivy March 2026 supply chain compromise
- SLSA Framework: https://slsa.dev/
"""

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")


class IntegrityError(Exception):
    """Raised when scanner binary integrity verification fails."""
    pass


class BinaryNotFoundError(IntegrityError):
    """Raised when a scanner binary is not found on PATH."""
    pass


class SignatureVerificationError(IntegrityError):
    """Raised when Cosign signature verification fails."""
    pass


class ChecksumMismatchError(IntegrityError):
    """Raised when binary checksum does not match expected value."""
    pass


class VersionMismatchError(IntegrityError):
    """Raised when binary version does not match pinned version."""
    pass


@dataclass
class IntegrityReport:
    """Result of a binary integrity verification."""
    binary_name: str
    binary_path: str
    version_detected: Optional[str] = None
    version_expected: Optional[str] = None
    sha256_hash: Optional[str] = None
    sha256_expected: Optional[str] = None
    cosign_verified: bool = False
    all_checks_passed: bool = False
    checks_performed: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# Known Trivy release checksums (SHA256) for verified versions.
# Update these when pinning to a new Trivy release.
# Source: https://github.com/aquasecurity/trivy/releases
KNOWN_CHECKSUMS: Dict[str, Dict[str, str]] = {
    "trivy": {
        # Format: "version": "sha256_of_binary"
        # These must be populated from official release artifacts.
        # Left empty here because checksums are architecture-specific;
        # operators should populate via --scanner-checksums config file.
    },
    "grype": {
        # Source: https://github.com/anchore/grype/releases
    },
}

# Minimum acceptable versions (anything below is considered compromised
# or too old to trust). Update when new critical fixes ship.
MINIMUM_VERSIONS: Dict[str, str] = {
    "trivy": "0.58.0",    # Post-supply-chain-fix release
    "grype": "0.86.0",    # Minimum tested version
}

# Cosign verification identities for official scanner releases.
# These are the Sigstore OIDC identities used by the release workflows.
COSIGN_IDENTITIES: Dict[str, Dict[str, str]] = {
    "trivy": {
        "identity_regexp": r"https://github\.com/aquasecurity/trivy/.*",
        "issuer_regexp": r"https://token\.actions\.githubusercontent\.com",
    },
    "grype": {
        "identity_regexp": r"https://github\.com/anchore/grype/.*",
        "issuer_regexp": r"https://token\.actions\.githubusercontent\.com",
    },
}


def find_binary(name: str) -> Optional[str]:
    """
    Locate a binary on the system PATH.

    Args:
        name: Binary name (e.g., "trivy", "grype")

    Returns:
        Absolute path to the binary, or None if not found.
    """
    code, output = run_cmd(["which", name])
    if code == 0 and output.strip():
        return output.strip()
    return None


def get_binary_version(name: str) -> Optional[str]:
    """
    Extract the version string from a scanner binary.

    Args:
        name: Binary name ("trivy" or "grype")

    Returns:
        Version string (e.g., "0.58.1") or None if extraction fails.
    """
    code, output = run_cmd([name, "version"])
    if code != 0:
        # Try --version as fallback
        code, output = run_cmd([name, "--version"])
        if code != 0:
            return None

    # Trivy output: "Version: 0.58.1"
    # Grype output: "grype 0.86.1"
    version_match = re.search(r'(\d+\.\d+\.\d+)', output)
    if version_match:
        return version_match.group(1)
    return None


def compute_sha256(filepath: str) -> str:
    """
    Compute SHA256 hash of a file.

    Args:
        filepath: Path to the file

    Returns:
        Hex-encoded SHA256 hash string

    Raises:
        FileNotFoundError: If file does not exist
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(8192), b""):
            sha256.update(block)
    return sha256.hexdigest()


def _version_gte(version: str, minimum: str) -> bool:
    """
    Compare two semver version strings: version >= minimum.

    Args:
        version: Version to check
        minimum: Minimum acceptable version

    Returns:
        True if version >= minimum
    """
    def parse(v: str) -> Tuple[int, ...]:
        return tuple(int(x) for x in v.split("."))

    try:
        return parse(version) >= parse(minimum)
    except (ValueError, IndexError):
        logger.warning(f"Could not parse version '{version}' or '{minimum}'")
        return False


def verify_cosign_blob(
    binary_path: str, scanner_name: str
) -> bool:
    """
    Verify a scanner binary using Cosign verify-blob against Sigstore.

    This checks that the binary was signed by the expected GitHub Actions
    workflow identity, providing supply chain provenance.

    Args:
        binary_path: Path to the binary to verify
        scanner_name: "trivy" or "grype"

    Returns:
        True if verification succeeds

    Note:
        This requires the binary to have been released with keyless
        Sigstore signing (which both Trivy and Grype do). If the release
        did not include a .sig file in the transparency log, this check
        will fail gracefully with a warning rather than blocking the pipeline.
    """
    identity_info = COSIGN_IDENTITIES.get(scanner_name)
    if not identity_info:
        logger.warning(f"No Cosign identity configured for {scanner_name}")
        return False

    # Check if cosign is available
    cosign_path = find_binary("cosign")
    if not cosign_path:
        logger.warning(
            "Cosign not found on PATH; skipping binary signature verification. "
            "Install cosign to enable supply chain verification."
        )
        return False

    cmd = [
        "cosign", "verify-blob",
        "--certificate-identity-regexp", identity_info["identity_regexp"],
        "--certificate-oidc-issuer-regexp", identity_info["issuer_regexp"],
        binary_path,
    ]

    code, output = run_cmd(cmd)
    if code != 0:
        # Cosign verify-blob failure is a warning, not a hard block,
        # because not all binary distributions include Sigstore signatures.
        logger.warning(
            f"Cosign verify-blob failed for {scanner_name} at {binary_path}. "
            f"This may indicate a tampered binary or a release without "
            f"Sigstore signatures. Output: {output[:500]}"
        )
        return False

    logger.info(f"Cosign verify-blob passed for {scanner_name}")
    return True


def verify_scanner_integrity(
    scanner_name: str,
    expected_version: Optional[str] = None,
    expected_checksum: Optional[str] = None,
    checksums_file: Optional[str] = None,
    strict: bool = False,
) -> IntegrityReport:
    """
    Perform comprehensive integrity verification of a scanner binary.

    Checks performed (in order):
    1. Binary existence on PATH
    2. Version detection and minimum version check
    3. Optional: exact version pin match
    4. Optional: SHA256 checksum verification
    5. Optional: Cosign verify-blob signature verification

    Args:
        scanner_name: "trivy" or "grype"
        expected_version: If set, require this exact version
        expected_checksum: If set, verify SHA256 matches
        checksums_file: Path to JSON file with version->checksum mappings
        strict: If True, any failed check raises IntegrityError

    Returns:
        IntegrityReport with all check results

    Raises:
        BinaryNotFoundError: If binary not found (always raised, even non-strict)
        IntegrityError: If strict=True and any check fails
    """
    start_time = time.time()
    report = IntegrityReport(binary_name=scanner_name, binary_path="")

    # Load custom checksums from file if provided
    custom_checksums: Dict[str, str] = {}
    if checksums_file and os.path.exists(checksums_file):
        try:
            import json
            with open(checksums_file, "r") as f:
                data = json.load(f)
                custom_checksums = data.get(scanner_name, {})
                logger.debug(
                    f"Loaded {len(custom_checksums)} checksums for "
                    f"{scanner_name} from {checksums_file}"
                )
        except Exception as e:
            report.warnings.append(f"Failed to load checksums file: {e}")

    # ── Check 1: Binary existence ────────────────────────────────────
    binary_path = find_binary(scanner_name)
    if not binary_path:
        report.errors.append(f"{scanner_name} binary not found on PATH")
        report.duration_seconds = time.time() - start_time
        raise BinaryNotFoundError(
            f"{scanner_name} is not installed or not on PATH. "
            f"Install it from the official source before running AutoPatch."
        )
    report.binary_path = binary_path
    report.checks_performed.append("binary_exists")

    # ── Check 2: Version detection ───────────────────────────────────
    detected_version = get_binary_version(scanner_name)
    report.version_detected = detected_version

    if detected_version:
        report.checks_performed.append("version_detected")

        # Check minimum version
        min_ver = MINIMUM_VERSIONS.get(scanner_name)
        if min_ver and not _version_gte(detected_version, min_ver):
            msg = (
                f"{scanner_name} version {detected_version} is below minimum "
                f"acceptable version {min_ver}. This version may contain known "
                f"vulnerabilities or supply chain issues. Please upgrade."
            )
            report.errors.append(msg)
            if strict:
                report.duration_seconds = time.time() - start_time
                raise VersionMismatchError(msg)
        else:
            report.checks_performed.append("minimum_version_ok")

        # Check exact version pin if specified
        if expected_version:
            report.version_expected = expected_version
            if detected_version != expected_version:
                msg = (
                    f"{scanner_name} version mismatch: "
                    f"expected {expected_version}, got {detected_version}"
                )
                report.warnings.append(msg)
                if strict:
                    report.duration_seconds = time.time() - start_time
                    raise VersionMismatchError(msg)
            else:
                report.checks_performed.append("version_pin_match")
    else:
        report.warnings.append(
            f"Could not detect {scanner_name} version; "
            f"skipping version checks"
        )

    # ── Check 3: SHA256 checksum ─────────────────────────────────────
    actual_checksum = compute_sha256(binary_path)
    report.sha256_hash = actual_checksum

    # Resolve expected checksum from: explicit param > custom file > built-in
    effective_checksum = expected_checksum
    if not effective_checksum and detected_version:
        effective_checksum = custom_checksums.get(detected_version)
    if not effective_checksum and detected_version:
        effective_checksum = KNOWN_CHECKSUMS.get(scanner_name, {}).get(
            detected_version
        )

    if effective_checksum:
        report.sha256_expected = effective_checksum
        if actual_checksum != effective_checksum:
            msg = (
                f"{scanner_name} checksum mismatch at {binary_path}: "
                f"expected {effective_checksum[:16]}..., "
                f"got {actual_checksum[:16]}..."
            )
            report.errors.append(msg)
            if strict:
                report.duration_seconds = time.time() - start_time
                raise ChecksumMismatchError(msg)
        else:
            report.checks_performed.append("checksum_match")
            logger.info(f"{scanner_name} SHA256 checksum verified")
    else:
        report.warnings.append(
            f"No expected checksum available for {scanner_name} "
            f"v{detected_version}; skipping checksum verification. "
            f"Provide --scanner-checksums for full supply chain verification."
        )

    # ── Check 4: Cosign verify-blob ──────────────────────────────────
    cosign_ok = verify_cosign_blob(binary_path, scanner_name)
    report.cosign_verified = cosign_ok
    if cosign_ok:
        report.checks_performed.append("cosign_verify_blob")
    else:
        report.warnings.append(
            f"Cosign verify-blob did not pass for {scanner_name}. "
            f"This is informational unless --strict-integrity is set."
        )
        if strict:
            report.duration_seconds = time.time() - start_time
            raise SignatureVerificationError(
                f"Cosign verify-blob failed for {scanner_name} at {binary_path}"
            )

    # ── Final assessment ─────────────────────────────────────────────
    report.all_checks_passed = len(report.errors) == 0
    report.duration_seconds = time.time() - start_time

    if report.all_checks_passed:
        logger.info(
            f"Scanner integrity OK: {scanner_name} v{detected_version} "
            f"at {binary_path} "
            f"(checks: {', '.join(report.checks_performed)})"
        )
    else:
        logger.warning(
            f"Scanner integrity issues for {scanner_name}: "
            f"{'; '.join(report.errors)}"
        )

    return report


def verify_all_scanners(
    scanners: Optional[List[str]] = None,
    strict: bool = False,
    checksums_file: Optional[str] = None,
) -> Dict[str, IntegrityReport]:
    """
    Verify integrity of all configured scanner binaries.

    Args:
        scanners: List of scanner names to verify. Defaults to ["trivy"].
        strict: If True, raise on any failure.
        checksums_file: Path to checksums config file.

    Returns:
        Dict mapping scanner name to its IntegrityReport.

    Raises:
        IntegrityError: If strict and any scanner fails verification.
    """
    if scanners is None:
        scanners = ["trivy"]

    reports: Dict[str, IntegrityReport] = {}
    for name in scanners:
        try:
            report = verify_scanner_integrity(
                name,
                checksums_file=checksums_file,
                strict=strict,
            )
            reports[name] = report
        except BinaryNotFoundError:
            if name == "trivy":
                # Trivy is mandatory
                raise
            else:
                # Secondary scanners are optional
                logger.info(
                    f"Optional scanner '{name}' not found; skipping"
                )

    return reports
