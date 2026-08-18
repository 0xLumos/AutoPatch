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

import enum
import hashlib
import shutil
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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
    # "verified" | "unavailable" | "failed". cosign_verified alone could
    # not distinguish "signature is bad" from "no signature to check".
    cosign_status: str = "unavailable"
    all_checks_passed: bool = False
    checks_performed: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# Known scanner binary checksums (SHA256) for verified releases.
# Loaded lazily from ``scanner_checksums.yaml`` shipped alongside this
# module. Operators can extend or override via --scanner-checksums
# pointing at a JSON/YAML file with the same shape.
#
# The bundled set covers the versions installed by the project Dockerfile
# (linux/amd64). When pinning to a new release, regenerate by running
# ``shasum -a 256 trivy`` on the official release tarball and add a row.
KNOWN_CHECKSUMS: Dict[str, Dict[str, str]] = {}


def _load_known_checksums() -> Dict[str, Dict[str, str]]:
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    yaml_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "scanner_checksums.yaml"
    )
    if not os.path.isfile(yaml_path):
        return {}
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning(
            "Failed to load %s (%s: %s); KNOWN_CHECKSUMS will be empty.",
            yaml_path, type(e).__name__, e,
        )
        return {}
    out: Dict[str, Dict[str, str]] = {}
    if isinstance(data, dict):
        for binary, entries in data.items():
            if isinstance(entries, dict):
                out[str(binary)] = {str(k): str(v) for k, v in entries.items()}
    return out


KNOWN_CHECKSUMS = _load_known_checksums()

# Minimum acceptable versions (anything below is considered compromised
# or too old to trust). Update when new critical fixes ship.
#
# INVARIANT: every entry here must be <= the version the project
# Dockerfile pins and <= the newest version in scanner_checksums.yaml.
# Grype previously sat at "0.86.0" while the Dockerfile pinned
# GRYPE_VERSION=0.85.0 and the only checksum on file was for 0.85.0, so
# the reference image failed AutoPatch's own integrity gate: every run
# in the shipped container reported grype as below minimum, and with
# --strict-integrity it aborted outright. tests/test_scanner_integrity.py
# asserts this invariant so the two cannot drift again.
MINIMUM_VERSIONS: Dict[str, str] = {
    "trivy": "0.58.0",    # Post-supply-chain-fix release
    "grype": "0.85.0",    # Pinned + checksummed in scanner_checksums.yaml
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

    Uses :func:`shutil.which` (pure Python, cross-platform, no
    subprocess) rather than shelling out to ``which`` for every
    integrity probe.

    Args:
        name: Binary name (e.g., "trivy", "grype")

    Returns:
        Absolute path to the binary, or None if not found.
    """
    return shutil.which(name)


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


# Hard ceiling on what compute_sha256 will read off disk. Real Trivy
# binaries are ~150 MB; Grype is comparable. Anything past this is
# either a misconfiguration or an attacker pointing us at an arbitrary
# large file. Override only if you know exactly what you are hashing.
from .constants import MAX_HASH_BYTES as _MAX_HASH_BYTES
# Sourced from constants.py so the documented AUTOPATCH_* env
# override is real. It was a duplicated literal, which made
# every override in the README silently inert.


def compute_sha256(filepath: str, max_bytes: int = _MAX_HASH_BYTES) -> str:
    """
    Compute SHA256 hash of a file with an enforced size cap.

    Args:
        filepath: Path to the file
        max_bytes: Maximum number of bytes to read before refusing.
            Defaults to 256 MB. Pass a larger value only when you have
            independently validated the file size.

    Returns:
        Hex-encoded SHA256 hash string.

    Raises:
        FileNotFoundError: file does not exist.
        ValueError: file exceeds ``max_bytes``.
    """
    try:
        size = os.path.getsize(filepath)
    except OSError:
        raise
    if size > max_bytes:
        raise ValueError(
            f"Refusing to hash {filepath}: size {size} bytes exceeds cap "
            f"{max_bytes} bytes. Increase max_bytes only after validating "
            f"this is not a malicious large input."
        )

    sha256 = hashlib.sha256()
    read_total = 0
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(8192), b""):
            read_total += len(block)
            if read_total > max_bytes:
                raise ValueError(
                    f"compute_sha256({filepath}) read past size cap "
                    f"({max_bytes} bytes) during hashing; possible race "
                    f"with a growing file."
                )
            sha256.update(block)
    return sha256.hexdigest()


def _parse_version(v: str) -> Tuple[Tuple[int, ...], Tuple[Any, ...]]:
    """Parse a semver-ish string into ``(release, prerelease)`` keys.

    Handles the three shapes the old ``tuple(int(x) for x in v.split("."))``
    got wrong:

    * **Pre-release** ``0.86.0-rc1``: ``int("0-rc1")`` raised ValueError,
      the caller logged a warning and returned False, so every release
      candidate was reported as "below minimum version" and blocked.
    * **Unequal length** ``"0.86"`` vs ``"0.86.0"``: ``(0, 86) >= (0, 86, 0)``
      is False in Python, so a two-component version was rejected against
      an equal three-component minimum.
    * **Build metadata** ``0.86.0+build.5``: same ValueError path.

    Ordering follows semver: a pre-release sorts BEFORE its release
    (``1.0.0-rc1 < 1.0.0``), which matters because an rc must not
    satisfy a minimum-version gate for the final release.
    """
    s = (v or "").strip().lstrip("vV")
    s = s.split("+", 1)[0]                      # drop build metadata
    core, _, pre = s.partition("-")
    release = tuple(int(p) for p in core.split(".") if p != "")
    if not release:
        raise ValueError(f"no numeric components in version {v!r}")
    # (1,) marks "no pre-release", which sorts above any pre-release (0, ...)
    if not pre:
        return release, (1,)
    ids: List[Any] = [0]
    for part in pre.split("."):
        # numeric identifiers compare numerically and rank below
        # alphanumeric ones, per semver §11.4
        ids.append((0, int(part)) if part.isdigit() else (1, part))
    return release, tuple(ids)


def _version_gte(version: str, minimum: str) -> bool:
    """Return True when ``version >= minimum`` under semver ordering.

    Unparseable input returns False (fail closed): an unknown scanner
    version must not satisfy a minimum-version security gate.
    """
    try:
        a_rel, a_pre = _parse_version(version)
        b_rel, b_pre = _parse_version(minimum)
    except (ValueError, TypeError):
        logger.warning(
            "Could not parse version %r or %r; treating as BELOW minimum.",
            version, minimum,
        )
        return False
    # Zero-pad so 0.86 and 0.86.0 compare equal rather than less-than.
    width = max(len(a_rel), len(b_rel))
    a_rel += (0,) * (width - len(a_rel))
    b_rel += (0,) * (width - len(b_rel))
    if a_rel != b_rel:
        return a_rel > b_rel
    return a_pre >= b_pre


class CosignBlobStatus(str, enum.Enum):
    """Outcome of a ``cosign verify-blob`` attempt.

    Two-valued (bool) reporting conflated "the signature is bad" with
    "there is no signature material to check", and the strict path
    raised on both. Since AutoPatch ships no ``.sig``/``.pem`` next to
    the scanner binaries, ``--strict-integrity`` could never succeed on
    any host. These are different security facts and are now reported
    as such.
    """
    VERIFIED = "verified"      # cosign checked a signature and it is valid
    UNAVAILABLE = "unavailable"  # no cosign, or no signature material present
    FAILED = "failed"          # signature material present and it did NOT verify


def _discover_signature_material(binary_path: str) -> Dict[str, str]:
    """Find cosign verification material sitting next to ``binary_path``.

    Looks for the conventional names produced by the Trivy and Grype
    release workflows. A bundle is self-contained and preferred; the
    detached pair must be complete to be usable.
    """
    found: Dict[str, str] = {}
    for suffix in (".cosign.bundle", ".bundle"):
        if os.path.exists(binary_path + suffix):
            found["bundle"] = binary_path + suffix
            return found
    sig = next((binary_path + s for s in (".sig", ".signature")
                if os.path.exists(binary_path + s)), None)
    cert = next((binary_path + s for s in (".pem", ".crt", ".cert")
                 if os.path.exists(binary_path + s)), None)
    if sig and cert:
        found["signature"] = sig
        found["certificate"] = cert
    return found


def verify_cosign_blob(
    binary_path: str,
    scanner_name: str,
    signature_path: Optional[str] = None,
    certificate_path: Optional[str] = None,
    bundle_path: Optional[str] = None,
) -> CosignBlobStatus:
    """
    Verify a scanner binary using ``cosign verify-blob``.

    The previous implementation invoked::

        cosign verify-blob --certificate-identity-regexp ... <binary>

    with no ``--signature``, ``--certificate`` or ``--bundle``. Cosign
    cannot verify a blob without the signature material, so the command
    exited non-zero on every invocation and this function returned False
    unconditionally. Under ``strict=True`` that raised
    ``SignatureVerificationError``, meaning ``--strict-integrity`` was
    unusable, and under the default it emitted a permanent warning that
    trained operators to ignore signature warnings. A check that always
    fails is worse than no check.

    Args:
        binary_path: Path to the binary to verify.
        scanner_name: "trivy" or "grype".
        signature_path: Detached signature. Auto-discovered if omitted.
        certificate_path: Fulcio certificate. Auto-discovered if omitted.
        bundle_path: Sigstore bundle (supersedes the detached pair).

    Returns:
        A :class:`CosignBlobStatus`. Only ``FAILED`` indicates tampering;
        ``UNAVAILABLE`` means the check could not be run at all.
    """
    identity_info = COSIGN_IDENTITIES.get(scanner_name)
    if not identity_info:
        logger.warning("No Cosign identity configured for %s", scanner_name)
        return CosignBlobStatus.UNAVAILABLE

    if not find_binary("cosign"):
        logger.warning(
            "Cosign not found on PATH; skipping binary signature verification. "
            "Install cosign to enable supply chain verification."
        )
        return CosignBlobStatus.UNAVAILABLE

    material: Dict[str, str] = {}
    if bundle_path:
        material["bundle"] = bundle_path
    elif signature_path and certificate_path:
        material["signature"] = signature_path
        material["certificate"] = certificate_path
    else:
        material = _discover_signature_material(binary_path)

    if not material:
        logger.info(
            "No cosign signature material found for %s next to %s "
            "(looked for .cosign.bundle, .sig + .pem). Signature "
            "verification not attempted; download the release "
            "signature and pass --scanner-signature to enable it.",
            scanner_name, binary_path,
        )
        return CosignBlobStatus.UNAVAILABLE

    cmd = [
        "cosign", "verify-blob",
        "--certificate-identity-regexp", identity_info["identity_regexp"],
        "--certificate-oidc-issuer-regexp", identity_info["issuer_regexp"],
    ]
    for flag, path in material.items():
        cmd.extend([f"--{flag}", path])
    cmd.append(binary_path)

    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(
            "Cosign verify-blob FAILED for %s at %s using %s. The "
            "signature material is present but does not verify, which "
            "is consistent with a tampered binary. Output: %s",
            scanner_name, binary_path, sorted(material), output[:500],
        )
        return CosignBlobStatus.FAILED

    logger.info("Cosign verify-blob passed for %s", scanner_name)
    return CosignBlobStatus.VERIFIED


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
    # Tri-state. UNAVAILABLE (no cosign, or no .sig/.bundle beside the
    # binary) is a coverage gap and must not be reported as a failed
    # signature, or strict mode blocks every host on which signature
    # material was simply never downloaded.
    cosign_status = verify_cosign_blob(binary_path, scanner_name)
    report.cosign_verified = (cosign_status is CosignBlobStatus.VERIFIED)
    report.cosign_status = cosign_status.value
    if cosign_status is CosignBlobStatus.VERIFIED:
        report.checks_performed.append("cosign_verify_blob")
    elif cosign_status is CosignBlobStatus.UNAVAILABLE:
        report.warnings.append(
            f"Cosign verify-blob not attempted for {scanner_name}: cosign "
            f"or the release signature material is absent. Supply chain "
            f"provenance for this binary is UNVERIFIED, not disproven."
        )
    else:  # FAILED
        msg = (
            f"Cosign verify-blob FAILED for {scanner_name} at {binary_path}: "
            f"signature material is present and does not verify. Treat this "
            f"binary as tampered."
        )
        report.errors.append(msg)
        if strict:
            report.duration_seconds = time.time() - start_time
            raise SignatureVerificationError(msg)

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
