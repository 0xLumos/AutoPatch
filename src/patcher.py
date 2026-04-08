"""
AutoPatch Patcher Module — Optimized SBOM-Driven Base Image Selection

This module implements the core patching logic for AutoPatch. It replaces
vulnerable base images with secure alternatives using a multi-signal
inference pipeline:

1. OS family detection via SBOM package URL (purl) analysis
2. Language/runtime version extraction from SBOM components (not tag regex)
3. glibc compatibility checking before Alpine selection
4. Confidence scoring with graceful fallback on uncertainty
5. Optional lightweight smoke test to catch runtime failures

The key design principle: read what is ACTUALLY INSTALLED (from the SBOM),
not what the tag STRING claims. Tags lie; SBOMs don't.
"""

import logging
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Set
from .parser import (
    parse_dockerfile_stages, analyze_run_commands, RunCommand,
    detect_package_manager_from_dockerfile,
    _extract_packages_apt, _extract_packages_apk,
    _extract_packages_yum
)

try:
    from .resolver import ImageResolver
except ImportError:
    # If PyYAML not installed, we'll gracefully fall back to legacy logic
    ImageResolver = None

try:
    from .version_resolver import resolve_eol_upgrade, validate_dockerhub_tag
except ImportError:
    resolve_eol_upgrade = None
    validate_dockerhub_tag = None

logger = logging.getLogger("docker_patch_tool")


# ════════════════════════════════════════════════════════════════════
# Data structures
# ════════════════════════════════════════════════════════════════════

@dataclass
class InferenceResult:
    """Result of SBOM-based inference with confidence scoring."""
    os_family: str = "unknown"
    os_version: Optional[str] = None       # e.g., "22.04", "9", "3.18"
    language: Optional[str] = None
    language_version: Optional[str] = None
    variant: Optional[str] = None          # e.g., "fpm", "apache", "slim"
    needs_glibc: bool = False
    libc_type: str = "unknown"             # "glibc", "musl", "bionic", "unknown"
    is_immutable: bool = False             # True for Bottlerocket, Flatcar, etc.
    confidence: float = 0.0                # 0.0 = no idea, 1.0 = certain
    signals: List[str] = field(default_factory=list)  # audit trail of what was detected
    warnings: List[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════

# Packages that indicate glibc dependency — Alpine uses musl and will
# cause silent runtime failures if these are present
GLIBC_INDICATOR_PACKAGES: Set[str] = {
    "glibc", "libc6", "libc-bin", "libc6-dev",
    "libstdc++6", "libgcc-s1",
}

# Python packages with common C extensions that may break on musl/Alpine
GLIBC_PYTHON_PACKAGES: Set[str] = {
    "numpy", "pandas", "scipy", "grpcio", "pillow",
    "cryptography", "lxml", "psycopg2", "mysqlclient",
    "tensorflow", "torch", "opencv-python", "matplotlib",
    "scikit-learn", "h5py", "pyarrow",
}

# purl prefix -> OS family mapping (Layer 1 of universal detection)
# The purl ecosystem is the single most reliable signal for OS family.
# New distros using apk/deb/rpm are automatically covered; only truly
# novel package managers (e.g., Nix, Guix) would need a new entry.
PURL_OS_MAP = {
    "pkg:apk/": "alpine",      # Refined to wolfi/chainguard if glibc present
    "pkg:deb/": "debian",      # Refined to ubuntu/distroless by metadata
    "pkg:rpm/": "rhel",        # Refined to centos/rocky/alma/fedora/amazon/oracle/suse by metadata
    "pkg:alpm/": "archlinux",  # Arch Linux uses ALPM
    "pkg:nix/": "nixos",       # NixOS uses Nix package manager
}

# Immutable / hardened OS families that should NOT be patched via
# base image replacement. These use atomic updates or are intentionally
# minimal. AutoPatch should warn and skip, not force-patch.
IMMUTABLE_OS_FAMILIES = {
    "bottlerocket",    # AWS Bottlerocket - purpose-built container host
    "flatcar",         # Flatcar Container Linux - immutable infrastructure
    "talos",           # Talos Linux - immutable Kubernetes OS
    "cos",             # Google Container-Optimized OS
    "fedora-coreos",   # Fedora CoreOS - immutable, auto-updating
}

# RPM sub-family detection keywords.
# When we see pkg:rpm/, these component name patterns disambiguate.
# Adding a new RPM-based distro requires only a new entry here.
RPM_SUBFAMILY_INDICATORS = {
    "rocky": "rocky",
    "alma": "alma",
    "centos": "centos",
    "fedora": "fedora",
    "amzn": "amazon",
    "amazon": "amazon",
    "amazonlinux": "amazon",
    "oraclelinux": "oracle",
    "oracle": "oracle",
    "sles": "sles",
    "suse": "opensuse",
    "opensuse": "opensuse",
    "photon": "photon",
    "mariner": "mariner",
    "azurelinux": "mariner",  # CBL-Mariner rebranded to Azure Linux
}

# DEB sub-family detection keywords.
DEB_SUBFAMILY_INDICATORS = {
    "ubuntu": "ubuntu",
    "pop-os": "ubuntu",       # Pop!_OS is Ubuntu-based
    "linuxmint": "ubuntu",    # Mint is Ubuntu-based
}

# SBOM component name → language detection
# We look for the runtime itself as an installed component
LANGUAGE_COMPONENT_PATTERNS = {
    "python": re.compile(r'^python(\d[\d.]*)?(|-minimal)$', re.IGNORECASE),
    "node": re.compile(r'^(node(js)?|nodejs-doc)$', re.IGNORECASE),
    "golang": re.compile(r'^go(lang)?$', re.IGNORECASE),
    "ruby": re.compile(r'^ruby[\d.]*$', re.IGNORECASE),
    "php": re.compile(r'^php[\d.]*(-cli|-fpm|-common)?$', re.IGNORECASE),
    "openjdk": re.compile(r'^(openjdk|java|temurin|adoptopenjdk)', re.IGNORECASE),
    "rust": re.compile(r'^rust(c)?$', re.IGNORECASE),
    "perl": re.compile(r'^perl[\d.]*$', re.IGNORECASE),
    "erlang": re.compile(r'^(erlang|otp)', re.IGNORECASE),
    "elixir": re.compile(r'^elixir[\d.]*$', re.IGNORECASE),
    "dotnet": re.compile(r'^(dotnet|aspnet)', re.IGNORECASE),
}

# purl type -> language mapping (secondary signal from installed packages)
# D2: Extended with additional language ecosystems
PURL_LANGUAGE_MAP = {
    "pkg:pypi/": "python",
    "pkg:npm/": "node",
    "pkg:gem/": "ruby",
    "pkg:composer/": "php",
    "pkg:maven/": "openjdk",
    "pkg:golang/": "golang",
    "pkg:cargo/": "rust",
    "pkg:nuget/": "dotnet",
    "pkg:hex/": "elixir",
    "pkg:cpan/": "perl",
    "pkg:pub/": "dart",
    "pkg:swift/": "swift",
    "pkg:cocoapods/": "swift",
    "pkg:hackage/": "haskell",
    "pkg:cran/": "r",
}


# ════════════════════════════════════════════════════════════════════
# Module-level ImageResolver (lazy-loaded)
# ════════════════════════════════════════════════════════════════════

_resolver: Optional['ImageResolver'] = None


def _get_resolver() -> Optional['ImageResolver']:
    """Get or create the module-level ImageResolver instance."""
    global _resolver
    if ImageResolver is None:
        # PyYAML not installed, resolver unavailable
        return None
    if _resolver is None:
        try:
            _resolver = ImageResolver()
        except Exception as e:
            logger.warning(f"Failed to initialize ImageResolver: {e}. Falling back to legacy logic.")
            return None
    return _resolver


# ════════════════════════════════════════════════════════════════════
# SBOM Analysis — the core inference engine
# ════════════════════════════════════════════════════════════════════

def analyze_sbom(
    sbom_data: Optional[Dict[str, Any]],
    language_override: Optional[str] = None,
    language_version_override: Optional[str] = None,
) -> InferenceResult:
    """
    Perform full SBOM analysis: OS family, language, version, glibc needs.

    This is the single entry point for all SBOM-based inference. It reads
    the CycloneDX SBOM and extracts structured signals rather than guessing
    from image tag strings.

    Args:
        sbom_data: CycloneDX SBOM as a dictionary (from Trivy)
        language_override: D3 - If set, forces this language instead of SBOM detection
        language_version_override: D3 - If set, forces this version

    Returns:
        InferenceResult with all detected properties and confidence score
    """
    result = InferenceResult()

    if not sbom_data:
        result.warnings.append("No SBOM data provided")
        return result

    components = sbom_data.get("components", [])
    metadata = sbom_data.get("metadata", {})
    meta_component = metadata.get("component", {})
    meta_name = meta_component.get("name", "").lower()

    # Collect all purls and component names
    purls: List[str] = []
    comp_names: List[str] = []
    comp_map: Dict[str, str] = {}  # name → version

    for comp in components:
        purl = comp.get("purl", "")
        name = comp.get("name", "")
        version = comp.get("version", "")
        if purl:
            purls.append(purl)
        if name:
            comp_names.append(name.lower())
            comp_map[name.lower()] = version

    # ── Step 1: Detect OS family from purl prefixes ──────────────

    result.os_family = _detect_os_family(purls, comp_names, meta_name, len(components))
    if result.os_family != "unknown":
        result.confidence += 0.4
        result.signals.append(f"OS={result.os_family} (from purl/metadata)")

    # ── Step 2: Detect language and version from SBOM components ──

    # D3: Apply language override if provided (highest priority)
    if language_override:
        result.language = language_override
        result.language_version = language_version_override
        result.confidence += 0.5  # Override gives highest confidence
        result.signals.append(
            f"lang={language_override}:{language_version_override} "
            f"(from --language override)"
        )
    else:
        lang, lang_ver = _detect_language_from_sbom(purls, comp_map, meta_name)
        if lang:
            result.language = lang
            result.language_version = lang_ver
            result.confidence += 0.3
            result.signals.append(f"lang={lang}:{lang_ver} (from SBOM components)")

    # ── Step 3: Detect libc type ────────────────────────────────────

    result.libc_type = _detect_libc_type(comp_names, purls, result.os_family)
    if result.libc_type != "unknown":
        result.signals.append(f"libc={result.libc_type}")

    # ── Step 4: Check glibc dependency ────────────────────────────

    result.needs_glibc = _check_glibc_dependency(comp_names, purls)
    # Also infer glibc need from libc_type
    if result.libc_type == "glibc":
        result.needs_glibc = True
    if result.needs_glibc:
        result.signals.append("glibc dependency detected - Alpine unsafe")

    # ── Step 5: Detect variant hints ──────────────────────────────

    result.variant = _detect_variant(comp_names, meta_name)
    if result.variant:
        result.signals.append(f"variant={result.variant}")

    # ── Step 6: Detect immutable OS ──────────────────────────────

    if result.os_family in IMMUTABLE_OS_FAMILIES:
        result.is_immutable = True
        result.warnings.append(
            f"Immutable OS detected ({result.os_family}). "
            f"Base image replacement is not appropriate for this OS family. "
            f"Consider using the OS vendor's update mechanism instead."
        )

    # ── Step 7: Scratch detection ────────────────────────────────

    if not components and not meta_component:
        result.os_family = "scratch"
        result.confidence = 1.0
        result.signals.append("zero components -> scratch image")

    # ── Step 8: Extract OS version from metadata ─────────────────

    os_props = metadata.get("properties", [])
    for prop in os_props if isinstance(os_props, list) else []:
        if isinstance(prop, dict):
            name = prop.get("name", "")
            if name in ("aquasecurity:trivy:os:name", "os:name"):
                result.os_version = prop.get("value")
                result.signals.append(f"os_version={result.os_version}")

    return result


def _detect_os_family(
    purls: List[str], comp_names: List[str], meta_name: str, comp_count: int
) -> str:
    """
    Universal 3-layer OS family detection.

    Layer 1 (Primary): purl ecosystem prefix (pkg:apk/, pkg:deb/, pkg:rpm/)
        This is the highest-confidence signal because it comes from what
        is actually installed. New distros using existing package managers
        are automatically covered without code changes.

    Layer 2 (Secondary): SBOM metadata and component name patterns
        Disambiguates within a package ecosystem. For example, both
        Ubuntu and Debian use pkg:deb/, but component names like
        "ubuntu-keyring" differentiate them.

    Layer 3 (Tertiary): Immutability and special-case classification
        Detects hardened/immutable OS families (Bottlerocket, Flatcar),
        distroless images, scratch images, and Windows containers.

    To add support for a new distro:
    - If it uses apk/deb/rpm: add a keyword to the appropriate
      *_SUBFAMILY_INDICATORS dict. No code changes needed.
    - If it uses a new package manager: add a PURL_OS_MAP entry.
    """

    # ---- Layer 3 first: special cases that override everything ----

    # Check distroless FIRST: distroless images contain pkg:deb/ but
    # must NOT be classified as debian
    if "distroless" in meta_name:
        return "distroless"

    # Immutable OS detection
    for immutable_os in IMMUTABLE_OS_FAMILIES:
        if immutable_os in meta_name:
            return immutable_os
        if any(immutable_os in n for n in comp_names):
            return immutable_os

    # Windows detection: pkg:nuget/ or Windows-specific components
    has_nuget = any("pkg:nuget/" in p for p in purls)
    if has_nuget or any(n in comp_names for n in ["windows", "nanoserver", "servercore"]):
        return "windows"

    # ---- Layer 1: purl ecosystem prefix ----

    has_apk = any("pkg:apk/" in p for p in purls)
    has_deb = any("pkg:deb/" in p for p in purls)
    has_rpm = any("pkg:rpm/" in p for p in purls)

    # APK ecosystem: Alpine or Wolfi/Chainguard
    if has_apk:
        # Wolfi/Chainguard: uses apk but ships glibc instead of musl
        if any(n in comp_names for n in ["glibc", "wolfi-baselayout", "chainguard-baselayout"]):
            return "wolfi"
        if any(n in comp_names for n in ["apk-tools", "musl", "alpine-baselayout"]):
            return "alpine"
        return "alpine"  # Default for apk ecosystem

    # DEB ecosystem: Debian, Ubuntu, or distroless
    if has_deb:
        # Layer 2: disambiguate within DEB family
        for keyword, family in DEB_SUBFAMILY_INDICATORS.items():
            if any(keyword in n for n in comp_names) or keyword in meta_name:
                return family

        # Distroless heuristic: few deb packages, no apt
        if comp_count < 15 and not any("apt" in n for n in comp_names):
            return "distroless"

        return "debian"  # Default for deb ecosystem

    # RPM ecosystem: RHEL, CentOS, Rocky, Alma, Amazon, Oracle, SUSE, etc.
    if has_rpm:
        # Layer 2: disambiguate within RPM family using component names and metadata
        # Check metadata name first (higher confidence)
        for keyword, family in RPM_SUBFAMILY_INDICATORS.items():
            if keyword in meta_name:
                return family

        # Then check component names
        for keyword, family in RPM_SUBFAMILY_INDICATORS.items():
            if any(keyword in n for n in comp_names):
                return family

        # Check for release files as components (e.g., "centos-release")
        for comp_name in comp_names:
            if comp_name.endswith("-release") or comp_name.endswith("-release-server"):
                prefix = comp_name.replace("-release-server", "").replace("-release", "")
                for keyword, family in RPM_SUBFAMILY_INDICATORS.items():
                    if keyword in prefix:
                        return family

        return "rhel"  # Default for rpm ecosystem

    # ---- Fallback heuristics ----

    # Very small component sets with no package manager -> likely distroless
    if 0 < comp_count < 5:
        return "distroless"

    # Check for any other purl ecosystems we might have added
    for purl in purls:
        for prefix, os_family in PURL_OS_MAP.items():
            if prefix in purl:
                return os_family

    return "unknown"


def _detect_language_from_sbom(
    purls: List[str], comp_map: Dict[str, str], meta_name: str = ""
) -> Tuple[Optional[str], Optional[str]]:
    """
    Detect language runtime and version from SBOM components.

    Four-pass approach:
    1. Check SBOM metadata component name for strong language hints
       (e.g., meta_name="node-orig" → node is the primary runtime)
    2. Find ALL runtime binaries installed as SBOM components
    3. Count application-level packages (pkg:npm/, pkg:pypi/, etc.)
       to determine which runtime is PRIMARY vs build-dependency
    4. If purl counts tie, use a priority heuristic that deprioritizes
       languages commonly installed as build dependencies (Python, Java)

    This fixes the node:18 → python:3.11 misclassification: Node.js Debian
    images include python3 as a build dep, but pkg:npm/ packages reveal
    Node.js as the actual application runtime.

    Returns:
        (language, version) tuple, either or both may be None
    """
    # Pass 0: Check SBOM metadata name for strong language hints.
    # Trivy sets metadata.component.name to the scanned image name (e.g.,
    # "node-orig", "python-3.11-slim"). This is a high-confidence signal
    # that should boost the corresponding language if found in components.
    _META_LANG_HINTS = {
        "node": "node", "python": "python", "golang": "golang",
        "ruby": "ruby", "php": "php", "openjdk": "openjdk",
        "temurin": "openjdk",
    }
    meta_lang_hint: Optional[str] = None
    for keyword, lang in _META_LANG_HINTS.items():
        if keyword in meta_name:
            meta_lang_hint = lang
            break

    # Pass 1: Find ALL installed runtime components (not just the first)
    all_matches: Dict[str, str] = {}  # lang → version
    for lang, pattern in LANGUAGE_COMPONENT_PATTERNS.items():
        for name, version in comp_map.items():
            if pattern.match(name) and version:
                clean_ver = _normalize_version(version, lang)
                all_matches[lang] = clean_ver
                break  # one match per language is enough

    # Count application-level purl packages for disambiguation
    purl_lang_counts: Dict[str, int] = {}
    for purl in purls:
        for prefix, lang in PURL_LANGUAGE_MAP.items():
            if prefix in purl:
                purl_lang_counts[lang] = purl_lang_counts.get(lang, 0) + 1

    # Single match — unambiguous
    if len(all_matches) == 1:
        lang = next(iter(all_matches))
        return lang, all_matches[lang]

    # Multiple runtimes installed — disambiguate
    if len(all_matches) > 1:
        # Priority 1: If metadata name hints at a specific language, use that
        if meta_lang_hint and meta_lang_hint in all_matches:
            logger.info(
                f"Multiple runtimes found {list(all_matches.keys())} — "
                f"selected '{meta_lang_hint}' (matches SBOM metadata name)"
            )
            return meta_lang_hint, all_matches[meta_lang_hint]

        # Priority 2: Use purl counts (application-level packages)
        best_lang = None
        best_count = -1
        for lang in all_matches:
            count = purl_lang_counts.get(lang, 0)
            if count > best_count:
                best_count = count
                best_lang = lang

        if best_lang and best_count > 0:
            return best_lang, all_matches[best_lang]

        # Priority 3: Fall back to priority heuristic.
        # Python and Java are commonly installed as *system build dependencies*
        # in images whose primary runtime is something else (e.g., node:18
        # ships python3 for node-gyp). Deprioritize them when ambiguous.
        _PRIORITY = {
            "node": 1, "golang": 2, "ruby": 3,
            "php": 4, "openjdk": 5, "python": 6,
        }
        best_lang = min(all_matches, key=lambda l: _PRIORITY.get(l, 99))
        logger.info(
            f"Multiple runtimes found {list(all_matches.keys())} — "
            f"selected '{best_lang}' as primary (deprioritized system deps)"
        )
        return best_lang, all_matches[best_lang]

    # No component matches — fall back to purl-type inference only
    if purl_lang_counts:
        dominant_lang = max(purl_lang_counts, key=purl_lang_counts.get)
        return dominant_lang, None  # version unknown from this signal

    return None, None


def _normalize_version(version: str, language: str) -> str:
    """
    Normalize a version string to major.minor for tag construction.

    Examples:
        "3.8.12" -> "3.8" (python)
        "18.19.0" -> "18" (node - uses major only)
        "1.22.5" -> "1.22" (golang)
        "17.0.9" -> "17" (openjdk - uses major only, invalid tag otherwise)
    """
    parts = version.split(".")

    # Node.js uses major-only tags (node:18, node:20)
    if language == "node" and parts:
        return parts[0]

    # OpenJDK uses major-only tags (openjdk:17, openjdk:21)
    # "17.0.9" truncated to "17.0" is NOT a valid Docker Hub tag
    if language == "openjdk" and parts:
        return parts[0]

    # Most languages use major.minor (python:3.8, golang:1.22)
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"

    return version


def _check_glibc_dependency(comp_names: List[str], purls: List[str]) -> bool:
    """
    Check if the image has components that require glibc.

    If True, switching to Alpine (musl libc) is unsafe and we should
    prefer -slim variants instead.
    """
    # Check for glibc system packages
    for name in comp_names:
        if name in GLIBC_INDICATOR_PACKAGES:
            return True

    # Check for Python packages known to have C extensions
    for purl in purls:
        if "pkg:pypi/" in purl:
            # Extract package name from purl
            # e.g., "pkg:pypi/numpy@1.24.0" → "numpy"
            match = re.search(r'pkg:pypi/([^@/]+)', purl)
            if match and match.group(1).lower() in GLIBC_PYTHON_PACKAGES:
                return True

    return False


def _detect_libc_type(
    comp_names: List[str], purls: List[str], os_family: str
) -> str:
    """
    Detect the libc implementation used by the image.

    This is critical for safe base image selection:
    - glibc: Debian, Ubuntu, RHEL, CentOS, Fedora, Wolfi, Amazon, Oracle, SLES
    - musl: Alpine
    - bionic: Android (rare in containers)
    - uclibc: embedded systems (rare)

    Knowing the libc type prevents silent runtime failures when switching
    base images (e.g., a glibc binary will segfault on musl Alpine).

    Args:
        comp_names: Lowercase component names from SBOM
        purls: Package URLs from SBOM
        os_family: Already-detected OS family

    Returns:
        One of: "glibc", "musl", "bionic", "uclibc", "unknown"
    """
    # Direct component detection (highest confidence)
    musl_indicators = {"musl", "musl-utils", "musl-dev"}
    glibc_indicators = {"glibc", "libc6", "libc-bin", "libc6-dev", "glibc-common", "glibc-minimal-langpack"}

    if any(n in musl_indicators for n in comp_names):
        return "musl"
    if any(n in glibc_indicators for n in comp_names):
        return "glibc"

    # Infer from OS family (secondary signal)
    musl_families = {"alpine"}
    glibc_families = {
        "debian", "ubuntu", "rhel", "centos", "rocky", "alma",
        "fedora", "amazon", "oracle", "opensuse", "sles",
        "photon", "mariner", "wolfi",
    }

    if os_family in musl_families:
        return "musl"
    if os_family in glibc_families:
        return "glibc"

    # Check purl ecosystem as last resort
    if any("pkg:apk/" in p for p in purls):
        return "musl"  # apk ecosystem defaults to musl
    if any("pkg:deb/" in p for p in purls) or any("pkg:rpm/" in p for p in purls):
        return "glibc"

    return "unknown"


def _detect_variant(comp_names: List[str], meta_name: str) -> Optional[str]:
    """Detect image variant (e.g., apache, fpm) from component names."""
    if any("apache" in n for n in comp_names) or "apache" in meta_name:
        return "apache"
    if any("nginx" in n for n in comp_names) or "nginx" in meta_name:
        return "nginx"
    return None


# ════════════════════════════════════════════════════════════════════
# Base Image Selection — uses inference result, not tag parsing
# ════════════════════════════════════════════════════════════════════

def choose_base_image(
    inference: InferenceResult,
    original_base: Optional[str] = None,
) -> Tuple[str, float]:
    """
    Choose an updated base image using SBOM inference results.

    Selection priority (NEW WITH RESOLVER):
    1. Try ImageResolver first (data-driven registry-based resolution)
    2. If resolver unavailable or low confidence, fall back to legacy paths:
       a. If language+version known from SBOM → use that with appropriate OS
       b. If only language known (no version) → fall back to tag regex extraction
       c. If neither → use original_base substring matching (legacy path)
       d. If nothing matches → select based on OS family alone

    The OS target depends on glibc compatibility:
    - No glibc needed → Alpine (smallest attack surface)
    - glibc needed → slim Debian variant (glibc-compatible, minimal)

    Args:
        inference: InferenceResult from analyze_sbom()
        original_base: Original FROM value for fallback extraction

    Returns:
        Tuple of (new_base_image, confidence) where confidence is 0.0–1.0
    """
    original_base = original_base or ""
    o = original_base.lower()

    # Handle Windows images: we cannot patch Windows containers
    if inference.os_family == "windows":
        inference.warnings.append(
            "Windows-based image detected; cannot patch Windows containers. "
            "Returning original base unchanged."
        )
        return original_base, 0.0

    # Handle immutable OS families: warn and return original
    if inference.is_immutable:
        inference.warnings.append(
            f"Immutable OS ({inference.os_family}) detected. "
            f"AutoPatch cannot replace base images for immutable OS families. "
            f"Use the vendor's native update mechanism instead."
        )
        return original_base, 0.0

    # Handle Wolfi/Chainguard images: treat like glibc-requiring distro
    if inference.os_family == "wolfi":
        inference.needs_glibc = True

    # ── Try ImageResolver first (new primary path) ──────────────────
    resolver = _get_resolver()
    if resolver:
        new_image, confidence, metadata = resolver.resolve(original_base, inference)
        if confidence > 0.3:
            logger.info(
                f"ImageResolver selected '{new_image}' (confidence {confidence:.2f}, "
                f"strategy={metadata.get('strategy_used')})"
            )
            return new_image, confidence
        else:
            logger.debug(
                f"ImageResolver returned low confidence ({confidence:.2f}), "
                f"falling back to legacy logic"
            )

    # Determine OS suffix based on glibc needs
    alpine_safe = not inference.needs_glibc
    os_suffix = "alpine" if alpine_safe else "slim-bookworm"

    # ── Pre-check: Infrastructure / application images ──────────────
    # These images are NOT language runtimes — they are databases, web
    # servers, message queues, CI tools, and CMS applications. Their SBOMs
    # contain Go, Python, or Java as system/build dependencies, NOT as the
    # application runtime. If we let SBOM language detection proceed, we
    # get catastrophic results like consul → golang:1.14-alpine.
    #
    # Strategy: for infrastructure images, skip SBOM language inference
    # entirely and go straight to _match_by_image_name() which has
    # curated mappings for these specific images.
    _INFRASTRUCTURE_KEYWORDS = {
        # Databases
        "mongo", "mysql", "mariadb", "postgres", "redis", "elasticsearch",
        "cassandra", "couchdb", "influxdb", "neo4j", "memcached", "zookeeper",
        # Web servers / proxies
        "nginx", "httpd", "apache", "traefik", "caddy", "haproxy",
        "envoy", "kong",
        # Message queues
        "rabbitmq", "kafka", "nats",
        # Monitoring / observability
        "grafana", "prometheus", "alertmanager", "fluentd", "logstash", "kibana",
        # CI/CD & DevOps tools
        "jenkins", "gitlab", "vault", "consul", "sonarqube",
        "gitea", "drone", "nexus",
        # CMS & Applications
        "wordpress", "nextcloud", "drupal", "ghost", "joomla",
        "redmine", "mediawiki", "phpmyadmin", "adminer", "matomo",
        # App servers (contain JDK but want specific app server images)
        "tomcat", "jetty", "wildfly",
        # Build tools (contain JDK but want specific build tool images)
        "maven", "gradle",
        # Container/cloud infrastructure
        "docker", "registry", "minio", "portainer",
        # Data processing & search
        "solr", "flink",
    }
    image_name_part = o.split(":")[0].split("/")[-1]
    is_infrastructure = any(kw in image_name_part for kw in _INFRASTRUCTURE_KEYWORDS)

    if is_infrastructure:
        logger.info(
            f"Infrastructure image detected ('{image_name_part}') — "
            f"bypassing SBOM language inference, using curated mapping"
        )
        image = _match_by_image_name(o, os_suffix)
        if image:
            return image, 0.8  # high confidence for curated mappings
        # If no match found, fall through to OS-family selection

    # ── Safety check: cross-validate SBOM language against image name ──
    # Prevents misclassification when a build dependency (e.g. python3 in
    # a node:18 image) is mistakenly detected as the primary runtime.
    effective_language = inference.language
    effective_version = inference.language_version
    _IMAGE_NAME_LANGS = {
        "python": "python", "node": "node", "golang": "golang",
        "ruby": "ruby", "php": "php", "openjdk": "openjdk",
        "temurin": "openjdk", "adoptopenjdk": "openjdk",
    }
    image_name_lang = None
    for keyword, lang in _IMAGE_NAME_LANGS.items():
        if keyword in image_name_part:
            image_name_lang = lang
            break

    if image_name_lang and effective_language and image_name_lang != effective_language:
        logger.warning(
            f"SBOM detected '{effective_language}' but image name suggests "
            f"'{image_name_lang}' — overriding to match image name"
        )
        effective_language = image_name_lang
        # Extract version from tag since SBOM version is for wrong language
        effective_version = _extract_version_from_tag(o, image_name_lang)

    # ── Path 1: SBOM gave us language + version (highest confidence) ──
    if effective_language and effective_version:
        image = _build_image_tag(
            effective_language, effective_version,
            os_suffix, inference.variant, o
        )
        if image:
            return image, min(inference.confidence + 0.2, 1.0)

    # ── Path 2: SBOM gave us language but no version → extract from tag ──
    if effective_language and not effective_version:
        ver = _extract_version_from_tag(o, effective_language)
        if ver:
            image = _build_image_tag(
                effective_language, ver, os_suffix, inference.variant, o
            )
            if image:
                return image, min(inference.confidence + 0.1, 0.8)

    # ── Path 3: No language from SBOM → substring match on original tag ──
    # This is the legacy fallback path — lower confidence
    image = _match_by_image_name(o, os_suffix)
    if image:
        return image, 0.5

    # ── Path 4: OS family only — pure OS images ──
    image = _select_by_os_family(inference.os_family, alpine_safe)
    return image, 0.3


def _build_image_tag(
    language: str, version: str, os_suffix: str,
    variant: Optional[str], original_lower: str
) -> Optional[str]:
    """
    Construct a Docker image tag for a known language + version.

    IMPORTANT: Each Docker Hub image uses its own tag convention for slim
    variants. Using a single os_suffix for all images WILL produce invalid
    tags (e.g., node:18-slim-bookworm does not exist — it's node:18-slim
    or node:18-bookworm-slim). This function handles each language's actual
    Docker Hub tag format.

    Args:
        language: Detected language (python, node, golang, etc.)
        version: Detected version (3.8, 18, 1.22, etc.)
        os_suffix: OS suffix hint ("alpine" or "slim-bookworm")
        variant: Optional variant (apache, fpm, etc.)
        original_lower: Lowercased original base for context hints
    """
    is_alpine = (os_suffix == "alpine")

    # ── EOL version upgrade: if the detected version is end-of-life,
    # upgrade to the latest supported version to actually reduce vulns ──
    version = _upgrade_eol_version(language, version)

    if language == "python":
        # python:3.12-alpine  OR  python:3.12-slim (tracks current Debian)
        return f"python:{version}-alpine" if is_alpine else f"python:{version}-slim"

    if language == "node":
        # node:22-alpine  OR  node:22-slim (NOT node:22-slim-bookworm!)
        return f"node:{version}-alpine" if is_alpine else f"node:{version}-slim"

    if language == "golang":
        # golang:1.23-alpine  OR  golang:1.23-bookworm (Go has no -slim)
        return f"golang:{version}-alpine" if is_alpine else f"golang:{version}-bookworm"

    if language == "ruby":
        # ruby:3.3-alpine  OR  ruby:3.3-slim (tracks current Debian)
        return f"ruby:{version}-alpine" if is_alpine else f"ruby:{version}-slim"

    if language == "php":
        if variant == "apache":
            return f"php:{version}-apache"
        if "fpm" in original_lower:
            return f"php:{version}-fpm-alpine" if is_alpine else f"php:{version}-fpm"
        return f"php:{version}-cli-alpine" if is_alpine else f"php:{version}-cli"

    if language == "openjdk":
        # eclipse-temurin:21-jre-alpine  OR  eclipse-temurin:21-jre-jammy
        return f"eclipse-temurin:{version}-jre-alpine" if is_alpine else f"eclipse-temurin:{version}-jre-jammy"

    if language == "rust":
        return f"rust:{version}-slim" if not is_alpine else f"rust:{version}-alpine"

    if language == "perl":
        return f"perl:{version}-slim"

    if language == "erlang":
        return f"erlang:{version}-slim"

    if language == "elixir":
        return f"elixir:{version}-slim"

    if language == "dotnet":
        return f"mcr.microsoft.com/dotnet/aspnet:{version}-alpine"

    return None


def _upgrade_eol_version(language: str, version: str) -> str:
    """
    Upgrade EOL language versions to the latest supported version.

    Uses the dynamic version resolver (endoflife.date API) when available,
    with automatic fallback to hardcoded mappings for offline/air-gapped
    environments.

    Args:
        language: Detected language runtime
        version: Detected version string (e.g., "7.4", "12", "1.16")

    Returns:
        Upgraded version if EOL, otherwise the original version unchanged
    """
    if resolve_eol_upgrade is not None:
        new_version, source = resolve_eol_upgrade(language, version)
        if source in ("live", "fallback"):
            logger.info(
                f"Upgrading EOL {language} version {version} -> {new_version} "
                f"(source: {source})"
            )
        return new_version

    # resolve_eol_upgrade not importable -- minimal inline fallback
    logger.warning(
        "version_resolver module not available; EOL checking disabled. "
        "Install the module for dynamic version resolution."
    )
    return version


def _resolve_arg_in_from(from_value: str, dockerfile_text: str) -> Optional[str]:
    """
    G3: 3-tier ARG resolution for FROM directives using build arguments.

    Resolution order:
    1. Look for ARG directive with default value in the Dockerfile
    2. Look for environment variable override (build-time args)
    3. Return None if unresolvable

    Handles patterns like:
    - FROM $BASE_IMAGE
    - FROM ${BASE_IMAGE}
    - FROM ${BASE_IMAGE:-default}
    - FROM ${BASE_IMAGE:+override}

    Args:
        from_value: The FROM value containing $ or {} references
        dockerfile_text: Full Dockerfile text for ARG extraction

    Returns:
        Resolved image reference, or None if unresolvable
    """
    import os as _os

    # Extract variable name from FROM value
    # Pattern: $VAR, ${VAR}, ${VAR:-default}, ${VAR:+value}
    var_match = re.match(
        r'\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::[-+]([^}]*))?\}?',
        from_value
    )
    if not var_match:
        return None

    var_name = var_match.group(1)
    default_value = var_match.group(2)

    # Tier 1: Look for ARG with default in Dockerfile
    # Matches: ARG BASE_IMAGE=python:3.12-slim
    arg_pattern = re.compile(
        rf'^\s*ARG\s+{re.escape(var_name)}\s*=\s*(.+?)\s*$',
        re.MULTILINE
    )
    arg_match = arg_pattern.search(dockerfile_text)
    if arg_match:
        resolved = arg_match.group(1).strip().strip('"').strip("'")
        logger.debug(f"Resolved ${var_name} from Dockerfile ARG: {resolved}")
        return resolved

    # Tier 2: Check environment variable (build-time override)
    env_value = _os.environ.get(var_name)
    if env_value:
        logger.debug(f"Resolved ${var_name} from environment: {env_value}")
        return env_value

    # Tier 3: Use default from ${VAR:-default} syntax
    if default_value:
        logger.debug(f"Resolved ${var_name} from default syntax: {default_value}")
        return default_value

    return None


def _extract_version_from_tag(tag_lower: str, language: str) -> Optional[str]:
    """
    Fallback: extract version from the Docker tag string.

    Only used when SBOM detection found the language but not the version.
    """
    if language == "node":
        m = re.search(r':(\d+)', tag_lower)
        return m.group(1) if m else None
    else:
        m = re.search(r':(\d+(?:\.\d+)*)', tag_lower)
        if m:
            return _normalize_version(m.group(1), language)
    return None


def _match_by_image_name(o: str, os_suffix: str) -> Optional[str]:
    """
    Legacy fallback: match image by substring in the original tag.

    This handles databases, infrastructure, and other non-language images
    where the SBOM won't contain a language runtime.
    """
    # ── Databases (check mongo BEFORE go to avoid substring collision) ──
    if "mongo-express" in o:
        return "mongo-express:latest"
    if "mongo" in o:
        return "mongo:7"
    if "redis" in o:
        return "redis:7-alpine"
    if "postgres" in o:
        return "postgres:17-alpine"
    if "mysql" in o:
        return "mysql:8.4"
    if "mariadb" in o:
        return "mariadb:11"
    if "cassandra" in o:
        return "cassandra:5.0"
    if "couchdb" in o:
        return "couchdb:3.4"
    if "influxdb" in o:
        return "influxdb:2.7-alpine"
    if "neo4j" in o:
        return "neo4j:5-community"
    if "memcached" in o:
        return "memcached:1.6-alpine"
    if "zookeeper" in o:
        return "zookeeper:3.9"

    # ── App servers (check BEFORE language images to avoid JDK substring collisions) ──
    if "tomcat" in o:
        return "tomcat:10.1-jre21"
    if "jetty" in o:
        return "jetty:12-jre21"
    if "wildfly" in o:
        return "wildfly:34-jre21"
    # ── Build tools (check BEFORE openjdk — maven:3.8-openjdk-11 contains "openjdk") ──
    if "maven" in o:
        return "maven:3.9-eclipse-temurin-21-alpine"
    if "gradle" in o:
        return "gradle:8-jdk21-alpine"
    # ── CMS apps containing "php" (check BEFORE generic php match) ──
    if "phpmyadmin" in o:
        return "phpmyadmin:latest"

    # ── Language images (fallback when SBOM didn't detect language) ──
    # Use _build_image_tag to ensure correct Docker Hub tag conventions.
    # IMPORTANT: apply _upgrade_eol_version() to every extracted version
    # so that EOL runtimes are upgraded even when SBOM didn't detect the language.
    is_alpine = (os_suffix == "alpine")
    if "rust" in o:
        ver = _extract_version_from_tag(o, "rust") or "1.85"
        ver = _upgrade_eol_version("rust", ver)
        return f"rust:{ver}-alpine" if is_alpine else f"rust:{ver}-slim"
    if "perl" in o:
        ver = _extract_version_from_tag(o, "perl") or "5.40"
        ver = _upgrade_eol_version("perl", ver)
        return f"perl:{ver}-slim"
    if "erlang" in o:
        ver = _extract_version_from_tag(o, "erlang") or "27"
        ver = _upgrade_eol_version("erlang", ver)
        return f"erlang:{ver}-slim"
    if "elixir" in o:
        ver = _extract_version_from_tag(o, "elixir") or "1.18"
        ver = _upgrade_eol_version("elixir", ver)
        return f"elixir:{ver}-slim"
    if "aspnet" in o or ("dotnet" in o and "aspnet" in o):
        ver = _extract_version_from_tag(o, "dotnet") or "8.0"
        ver = _upgrade_eol_version("dotnet", ver)
        return f"mcr.microsoft.com/dotnet/aspnet:{ver}-alpine"
    if "dotnet" in o and "sdk" in o:
        ver = _extract_version_from_tag(o, "dotnet") or "8.0"
        ver = _upgrade_eol_version("dotnet", ver)
        return f"mcr.microsoft.com/dotnet/sdk:{ver}-alpine"
    if "python" in o:
        ver = _extract_version_from_tag(o, "python") or "3.12"
        ver = _upgrade_eol_version("python", ver)
        return f"python:{ver}-alpine" if is_alpine else f"python:{ver}-slim"
    if "node" in o:
        ver = _extract_version_from_tag(o, "node") or "22"
        ver = _upgrade_eol_version("node", ver)
        return f"node:{ver}-alpine" if is_alpine else f"node:{ver}-slim"
    if "golang" in o or re.search(r'\bgo:', o):
        ver = _extract_version_from_tag(o, "golang") or "1.22"
        ver = _upgrade_eol_version("golang", ver)
        return f"golang:{ver}-alpine" if is_alpine else f"golang:{ver}-bookworm"
    if "ruby" in o:
        ver = _extract_version_from_tag(o, "ruby") or "3.3"
        ver = _upgrade_eol_version("ruby", ver)
        return f"ruby:{ver}-alpine" if is_alpine else f"ruby:{ver}-slim"
    if "php" in o:
        ver = _extract_version_from_tag(o, "php") or "8.3"
        ver = _upgrade_eol_version("php", ver)
        if "apache" in o:
            return f"php:{ver}-apache"
        if "fpm" in o:
            return f"php:{ver}-fpm-alpine" if is_alpine else f"php:{ver}-fpm"
        return f"php:{ver}-cli-alpine" if is_alpine else f"php:{ver}-cli"
    if "temurin" in o or "adoptopenjdk" in o or "openjdk" in o:
        m = re.search(r':(\d+)', o)
        major = m.group(1) if m else "21"
        major = _upgrade_eol_version("openjdk", major)
        return f"eclipse-temurin:{major}-jre-alpine" if is_alpine else f"eclipse-temurin:{major}-jre-jammy"

    # ── Web servers / infrastructure ──
    if "nginx" in o:
        return "nginx:stable-alpine"
    if "httpd" in o:
        return "httpd:2.4-alpine"
    if "traefik" in o:
        return "traefik:v3.3"
    if "caddy" in o:
        return "caddy:2-alpine"
    if "haproxy" in o:
        return "haproxy:3.1-alpine"
    if "envoy" in o:
        return "envoyproxy/envoy:v1.32-latest"
    if "kong" in o:
        return "kong:3.9"

    # ── Message queues ──
    if "rabbitmq" in o:
        return "rabbitmq:4-alpine"
    if "elasticsearch" in o:
        return "docker.elastic.co/elasticsearch/elasticsearch:8.17.0"
    if "kafka" in o:
        return "bitnami/kafka:3.9"
    if "nats" in o:
        return "nats:2.10-alpine"

    # ── Monitoring & observability ──
    if "grafana" in o:
        return "grafana/grafana:11.5.2"
    if "prometheus" in o:
        return "prom/prometheus:v2.53.4"
    if "alertmanager" in o:
        return "prom/alertmanager:v0.28.1"
    if "fluentd" in o:
        return "fluentd:v1.17-debian-1"
    if "kibana" in o:
        return "docker.elastic.co/kibana/kibana:8.17.0"
    if "logstash" in o:
        return "docker.elastic.co/logstash/logstash:8.17.0"

    # ── CI/CD tools ──
    if "jenkins" in o:
        return "jenkins/jenkins:lts-alpine"
    if "vault" in o:
        return "hashicorp/vault:latest"
    if "consul" in o:
        return "hashicorp/consul:latest"
    if "sonarqube" in o:
        return "sonarqube:lts-community"
    if "gitlab" in o:
        return "gitlab/gitlab-runner:alpine"
    if "gitea" in o:
        return "gitea/gitea:latest"
    if "drone" in o:
        return "drone/drone:latest"
    if "nexus" in o:
        return "sonatype/nexus3:latest"

    # ── Cloud native infrastructure ──
    if o.startswith("registry") or "registry:" in o:
        return "registry:2"
    if "minio" in o:
        return "minio/minio:latest"
    if "portainer" in o:
        return "portainer/portainer-ce:2.24.1"

    # ── CMS / Applications ──
    if "wordpress" in o:
        return "wordpress:6-php8.3-apache"
    if "nextcloud" in o:
        return "nextcloud:29-apache"
    if "drupal" in o:
        # Preserve the major Drupal version to avoid introducing new vulns
        # from a larger base image (e.g., drupal:11 >> drupal:10 in size)
        m = re.search(r'drupal:(\d+)', o)
        drupal_major = m.group(1) if m else "11"
        return f"drupal:{drupal_major}-php8.3-apache"
    if "ghost" in o:
        return "ghost:5-alpine"
    if "joomla" in o:
        return "joomla:5-php8.3-apache"
    if "redmine" in o:
        return "redmine:5-alpine"
    if "mediawiki" in o:
        return "mediawiki:lts-fpm"
    if "adminer" in o:
        return "adminer:latest"
    if "matomo" in o:
        return "matomo:5-apache"
    if "docker" in o:
        # docker:27-cli has significantly more Trivy-visible vulns than
        # older docker images. Use docker:27-dind which is more minimal.
        # Also preserve major version if possible.
        return "docker:27-cli"  # TODO: investigate docker:27-dind or skip

    # ── Data processing & search ──
    if "solr" in o:
        return "solr:9"
    if "flink" in o:
        return "flink:1.20"

    return None


def _select_by_os_family(family: str, alpine_safe: bool) -> str:
    """
    Select a base image based purely on OS family.

    Covers all major Linux distributions including:
    - Alpine, Debian, Ubuntu (DEB family)
    - RHEL, CentOS, Rocky, Alma, Fedora (RPM family)
    - Amazon Linux, Oracle Linux (RPM family, cloud-native)
    - openSUSE, SLES (RPM family, enterprise)
    - Photon OS, CBL-Mariner/Azure Linux (RPM family, cloud-native)
    - Wolfi/Chainguard (apk but glibc)
    - Distroless, scratch (minimal)
    - Immutable OS families (returned as-is with warning)
    """
    family_lower = family.lower()

    # Windows images cannot be patched
    if family_lower == "windows":
        return "windows"

    # Immutable OS families should not be patched via base image swap
    if family_lower in IMMUTABLE_OS_FAMILIES:
        logger.warning(
            f"Immutable OS '{family_lower}' detected. "
            f"Returning original - use vendor update mechanism instead."
        )
        return family_lower

    # Wolfi is glibc-compatible, use Chainguard static
    if family_lower == "wolfi":
        return "cgr.dev/chainguard/static:latest"

    # Comprehensive OS family -> latest secure base image mapping.
    # For glibc-requiring images, stay within the same ecosystem when
    # possible to minimize package manager migration issues.
    os_map_glibc = {
        "alpine": "alpine:3.21",
        "debian": "debian:bookworm-slim",
        "ubuntu": "ubuntu:24.04",
        "centos": "rockylinux:9-minimal",
        "rhel": "rockylinux:9-minimal",
        "rocky": "rockylinux:9-minimal",
        "alma": "almalinux:9-minimal",
        "fedora": "fedora:41",
        "amazon": "amazonlinux:2023",
        "oracle": "oraclelinux:9-slim",
        "opensuse": "opensuse/leap:15.6",
        "sles": "registry.suse.com/bci/bci-base:15.6",
        "photon": "photon:5.0",
        "mariner": "mcr.microsoft.com/cbl-mariner/base/core:2.0",
        "distroless": "gcr.io/distroless/static-debian12:nonroot",
        "scratch": "scratch",
        "archlinux": "archlinux:base",
        "nixos": "nixos/nix:latest",
    }

    # For alpine-safe images, prefer Alpine for smallest attack surface
    os_map_alpine = {
        "alpine": "alpine:3.21",
        "debian": "debian:bookworm-slim",
        "ubuntu": "ubuntu:24.04",
        "centos": "rockylinux:9-minimal",
        "rhel": "rockylinux:9-minimal",
        "rocky": "rockylinux:9-minimal",
        "alma": "almalinux:9-minimal",
        "fedora": "fedora:41",
        "amazon": "amazonlinux:2023",
        "oracle": "oraclelinux:9-slim",
        "opensuse": "opensuse/leap:15.6",
        "sles": "registry.suse.com/bci/bci-base:15.6",
        "photon": "photon:5.0",
        "mariner": "mcr.microsoft.com/cbl-mariner/base/core:2.0",
        "distroless": "gcr.io/distroless/static-debian12:nonroot",
        "scratch": "scratch",
        "archlinux": "archlinux:base",
        "nixos": "nixos/nix:latest",
    }

    if not alpine_safe:
        return os_map_glibc.get(family_lower, "debian:bookworm-slim")

    return os_map_alpine.get(family_lower, "alpine:3.21")


# ════════════════════════════════════════════════════════════════════
# Package Manager Migration — handle OS family transitions
# ════════════════════════════════════════════════════════════════════

def _infer_os_from_image(image_ref: str) -> Optional[str]:
    """
    Infer OS family from an image reference string.

    Examines the image name and tag for OS indicators (alpine, debian, ubuntu, rocky, etc.).

    Args:
        image_ref: Image reference (e.g., "python:3.11-slim", "alpine:3.21")

    Returns:
        OS family string or None if not determinable
    """
    lower = image_ref.lower()
    if "alpine" in lower:
        return "alpine"
    if "slim" in lower or "bookworm" in lower or "bullseye" in lower or "buster" in lower:
        return "debian"
    if "ubuntu" in lower or "jammy" in lower or "focal" in lower or "bionic" in lower:
        return "ubuntu"
    if "rocky" in lower:
        return "rocky"
    if "alma" in lower:
        return "alma"
    if "centos" in lower:
        return "centos"
    if "fedora" in lower:
        return "fedora"
    return None


def migrate_package_commands(
    dockerfile_text: str,
    from_os: str,
    to_os: str,
) -> Tuple[str, List[str], List[str]]:
    """
    Migrate package manager commands in a Dockerfile when switching OS families.

    When the base image changes from e.g., Debian to Alpine, all apt-get commands
    need to become apk commands. This function detects and translates them.

    Implementation strategy:
    - Parse RUN commands to identify package manager usage
    - Determine source and target package managers based on OS families
    - Get package name translations from the ImageResolver registry
    - Replace commands while preserving non-package-manager instructions
    - Track which packages could not be translated

    Args:
        dockerfile_text: The Dockerfile content (already patched with new FROM)
        from_os: Source OS family (e.g., "debian", "ubuntu")
        to_os: Target OS family (e.g., "alpine")

    Returns:
        Tuple of (migrated_text, changes_made, warnings) where:
        - migrated_text: Updated Dockerfile with migrated commands
        - changes_made: List of human-readable changes made
        - warnings: List of warnings about untranslatable packages
    """
    if from_os == to_os:
        # No migration needed
        return dockerfile_text, [], []

    # Determine source and target package managers
    pm_map = {
        "debian": "apt",
        "ubuntu": "apt",
        "alpine": "apk",
        "centos": "yum",
        "rhel": "yum",
        "rocky": "yum",
        "alma": "yum",
        "fedora": "dnf",
    }

    source_pm = pm_map.get(from_os.lower())
    target_pm = pm_map.get(to_os.lower())

    if not source_pm or not target_pm:
        # Cannot migrate if we don't know the package managers
        logger.warning(
            f"Cannot migrate package commands: unknown package manager for "
            f"from_os={from_os} or to_os={to_os}"
        )
        return dockerfile_text, [], [
            f"Unknown package manager for OS transition {from_os} to {to_os}"
        ]

    if source_pm == target_pm:
        # Same package manager, no migration needed
        return dockerfile_text, [], []

    # Get package name mapping from resolver if available
    resolver = _get_resolver()
    pkg_migration = None
    if resolver:
        pkg_migration = resolver.get_package_migration(from_os, to_os)

    # Analyze RUN commands
    run_commands = analyze_run_commands(dockerfile_text)
    if not run_commands:
        return dockerfile_text, [], []

    # Filter to commands that use the source package manager
    relevant_commands = [
        cmd for cmd in run_commands
        if cmd.package_manager and cmd.package_manager.lower() in [source_pm.lower(), "apt", "yum", "dnf", "apk"]
    ]

    if not relevant_commands:
        return dockerfile_text, [], []

    lines = dockerfile_text.splitlines(keepends=True)
    changes_made = []
    warnings_list = []

    # Process each RUN command that needs migration
    for run_cmd in relevant_commands:
        if not (run_cmd.is_install or run_cmd.is_update or run_cmd.is_cleanup):
            continue

        # Get the range of lines for this RUN command
        start_idx = run_cmd.line_start
        end_idx = run_cmd.line_end

        # Reconstruct and migrate the command
        migrated_text = _migrate_run_command(
            run_cmd, source_pm, target_pm, pkg_migration, warnings_list
        )

        if migrated_text != run_cmd.raw_text:
            changes_made.append(
                f"Migrated RUN command at line {start_idx + 1}: "
                f"{source_pm} {run_cmd.package_manager} to {target_pm}"
            )

            # Replace the lines
            if start_idx == end_idx:
                # Single line RUN command
                indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
                lines[start_idx] = " " * indent + f"RUN {migrated_text}\n"
            else:
                # Multi-line RUN command (with continuations)
                # Reconstruct as single line to avoid continuation complexities
                indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
                lines[start_idx] = " " * indent + f"RUN {migrated_text}\n"
                # Remove continuation lines
                for i in range(start_idx + 1, end_idx + 1):
                    lines[i] = ""

    migrated_text = "".join(line for line in lines if line)
    return migrated_text, changes_made, warnings_list


def _migrate_run_command(
    run_cmd: RunCommand,
    source_pm: str,
    target_pm: str,
    pkg_migration: Optional[Dict[str, str]],
    warnings: List[str],
) -> str:
    """
    Migrate a single RUN command from one package manager to another.

    Args:
        run_cmd: Parsed RunCommand
        source_pm: Source package manager (apt, yum, apk, etc.)
        target_pm: Target package manager (apt, yum, apk, etc.)
        pkg_migration: Optional dict mapping source packages to target packages
        warnings: List to accumulate warnings about untranslatable packages

    Returns:
        Migrated command text
    """
    sub_commands = run_cmd.combined_commands
    migrated_subs = []

    for sub_cmd in sub_commands:
        cmd_lower = sub_cmd.lower()

        # Detect if this is a package manager command
        is_apt_cmd = "apt-get" in cmd_lower or ("apt " in cmd_lower and "install" in cmd_lower)
        is_yum_cmd = ("yum" in cmd_lower or "dnf" in cmd_lower) and ("install" in cmd_lower or "update" in cmd_lower)
        is_apk_cmd = "apk" in cmd_lower and ("add" in cmd_lower or "update" in cmd_lower or "del" in cmd_lower)

        # If this command doesn't match the source PM, keep it unchanged
        if source_pm == "apt" and not is_apt_cmd:
            migrated_subs.append(sub_cmd)
            continue
        if source_pm in ("yum", "dnf") and not is_yum_cmd:
            migrated_subs.append(sub_cmd)
            continue
        if source_pm == "apk" and not is_apk_cmd:
            migrated_subs.append(sub_cmd)
            continue

        # Migrate the command
        migrated = _translate_package_command(
            sub_cmd, source_pm, target_pm, pkg_migration, warnings
        )
        migrated_subs.append(migrated)

    return " && ".join(migrated_subs)


def _translate_package_command(
    command: str,
    source_pm: str,
    target_pm: str,
    pkg_migration: Optional[Dict[str, str]],
    warnings: List[str],
) -> str:
    """
    Translate a package manager command from one format to another.

    Examples:
    - apt-get update -> apk update
    - apt-get install -y pkg1 pkg2 -> apk add --no-cache pkg1_migrated pkg2_migrated
    - yum install -y pkg1 && yum clean all -> apk add --no-cache pkg1_migrated

    Args:
        command: The RUN subcommand to translate
        source_pm: Source package manager
        target_pm: Target package manager
        pkg_migration: Package name mapping dict
        warnings: List to accumulate warnings

    Returns:
        Translated command
    """
    cmd_lower = command.lower()

    # Apt to Alpine
    if source_pm == "apt" and target_pm == "apk":
        if "update" in cmd_lower:
            return "apk update"
        if "install" in cmd_lower:
            # Extract packages
            packages = _extract_packages_apt(command)
            if packages:
                migrated_pkgs = [
                    pkg_migration.get(pkg, pkg) if pkg_migration else pkg
                    for pkg in packages
                ]
                # Check for untranslatable packages
                if pkg_migration:
                    for pkg in packages:
                        if pkg not in pkg_migration:
                            warnings.append(
                                f"Package '{pkg}' has no translation from {source_pm} to {target_pm}, using original name"
                            )
                return f"apk add --no-cache {' '.join(migrated_pkgs)}"
            return "apk add --no-cache"
        if "clean" in cmd_lower or "purge" in cmd_lower:
            # APK with --no-cache doesn't need cleanup
            return ""

    # Yum/DNF to Alpine
    elif source_pm in ("yum", "dnf") and target_pm == "apk":
        if "update" in cmd_lower or "check-update" in cmd_lower:
            return "apk update"
        if "install" in cmd_lower:
            packages = _extract_packages_yum(command)
            if packages:
                migrated_pkgs = [
                    pkg_migration.get(pkg, pkg) if pkg_migration else pkg
                    for pkg in packages
                ]
                if pkg_migration:
                    for pkg in packages:
                        if pkg not in pkg_migration:
                            warnings.append(
                                f"Package '{pkg}' has no translation from {source_pm} to {target_pm}, using original name"
                            )
                return f"apk add --no-cache {' '.join(migrated_pkgs)}"
            return "apk add --no-cache"
        if "clean" in cmd_lower:
            return ""

    # Fallback: return command unchanged if we can't translate
    return command


# ════════════════════════════════════════════════════════════════════
# Smoke Test — lightweight runtime validation
# ════════════════════════════════════════════════════════════════════

def smoke_test_image(image_name: str, timeout_seconds: int = 10) -> Tuple[bool, str]:
    """
    Run a lightweight smoke test on a built image.

    Starts the container with its default entrypoint and checks whether
    the process stays alive for a few seconds. This catches:
    - Missing shared libraries (musl vs glibc)
    - Segfaults from incompatible native binaries
    - Immediate crash on startup

    This is NOT a full integration test — just a "does it start?" check.

    Args:
        image_name: Docker image to test
        timeout_seconds: How long to wait for the process (default 10)

    Returns:
        Tuple of (passed, message)
    """
    from .utils import run_cmd
    import re

    # Sanitize container name to prevent injection
    # Docker container names can only contain [a-zA-Z0-9_.-]
    sanitized_name = image_name.replace('/', '-').replace(':', '-')
    sanitized_name = re.sub(r'[^a-zA-Z0-9_.-]', '', sanitized_name)
    container_name = f"autopatch-smoke-{sanitized_name}"

    # Start container detached using list format to prevent shell injection
    start_cmd = ["docker", "run", "-d", "--name", container_name, image_name]
    code, output = run_cmd(start_cmd, timeout=30)

    if code != 0:
        return False, f"Container failed to start: {output}"

    container_id = output.strip()

    try:
        # Wait a few seconds then check if container is still running
        import time
        time.sleep(min(timeout_seconds, 5))

        code, state = run_cmd(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
            timeout=10
        )

        if code != 0:
            return False, f"Failed to inspect container: {state}"

        # Check exit code if stopped
        if "false" in state.lower():
            _, exit_output = run_cmd(
                ["docker", "inspect", "--format", "{{.State.ExitCode}}", container_id],
                timeout=10
            )
            exit_code = exit_output.strip()

            # Exit code 0 is fine -- some containers (like CLI tools) exit immediately
            if exit_code == "0":
                return True, "Container exited cleanly (exit code 0)"
            else:
                # Get last few log lines for diagnosis
                _, logs = run_cmd(
                    ["docker", "logs", "--tail", "20", container_id],
                    timeout=10
                )
                return False, f"Container crashed with exit code {exit_code}. Logs: {logs[:500]}"

        return True, "Container running successfully"

    finally:
        # Cleanup
        run_cmd(["docker", "rm", "-f", container_id], timeout=10)


# ════════════════════════════════════════════════════════════════════
# Legacy compatibility wrappers
# ════════════════════════════════════════════════════════════════════

def detect_os_family(sbom_data: Optional[Dict[str, Any]]) -> str:
    """
    Legacy wrapper — detect OS family from SBOM.

    Prefer analyze_sbom() for full inference. This exists for backward
    compatibility with code that only needs the OS family string.
    """
    result = analyze_sbom(sbom_data)
    return result.os_family


# ════════════════════════════════════════════════════════════════════
# Main entry point: patch_dockerfile
# ════════════════════════════════════════════════════════════════════

# Minimum confidence to auto-patch. Below this, we emit a warning
# and suggest the user provide a --base-mapping override.
MIN_AUTO_PATCH_CONFIDENCE = 0.4


def patch_dockerfile(
    dockerfile_text: str,
    sbom_before: Optional[Dict[str, Any]] = None,
    base_mapping: Optional[Dict[str, str]] = None,
    patch_final_only: bool = False,
    dry_run: bool = False,
    enable_smoke_test: bool = False,
) -> Tuple[str, List[Tuple[str, str]], List[str], str]:
    """
    Patch the Dockerfile by replacing base images with updated, minimal variants.

    Uses a multi-signal inference pipeline:
    1. Analyze SBOM → get OS, language, version, glibc needs, confidence
    2. For each FROM stage, select the best replacement image
    3. If confidence is below threshold, warn instead of silently patching
    4. Only FROM lines are rewritten; all other instructions preserved verbatim

    Handles multi-stage builds correctly:
    - FROM stage_alias (internal references) are NOT rewritten
    - FROM scratch is NOT rewritten
    - FROM $ARG_VAR is skipped with a warning
    - COPY --from= references trigger a warning about potential breakage

    Args:
        dockerfile_text: The original Dockerfile content
        sbom_before: SBOM data (CycloneDX dict) of the original image
        base_mapping: Dict mapping original bases to user-specified overrides
        patch_final_only: If True, only patch the final stage
        dry_run: If True, compute changes but don't apply (returns original text)
        enable_smoke_test: If True, run smoke test after each stage patch

    Returns:
        Tuple of (patched_text, base_changes, warnings, diff_text) where:
        - patched_text: The modified Dockerfile
        - base_changes: List of (original_base, new_base) tuples
        - warnings: List of warning messages
        - diff_text: Human-readable diff of changes
    """
    stages = parse_dockerfile_stages(dockerfile_text)
    if not stages:
        logger.error("No FROM instructions found in Dockerfile.")
        return dockerfile_text, [], ["No FROM instructions found"], ""

    # Run full SBOM inference once
    inference = analyze_sbom(sbom_before)
    logger.info(
        f"SBOM inference: OS={inference.os_family}, "
        f"lang={inference.language}:{inference.language_version}, "
        f"glibc={inference.needs_glibc}, confidence={inference.confidence:.2f}"
    )
    for signal in inference.signals:
        logger.debug(f"  signal: {signal}")

    patched_lines = []
    base_changes = []
    warnings = list(inference.warnings)  # Start with any inference warnings

    for idx, stage in enumerate(stages):
        is_final = (idx == len(stages) - 1)

        # Skip intermediate stages if patch_final_only
        if patch_final_only and not is_final:
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Handle internal stage references — do NOT rewrite
        if stage['is_stage_alias']:
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        orig_base = stage['base_image']
        alias = stage['alias']
        comment = stage['comment'] or ""

        # G2: Skip FROM scratch with informational warning
        if stage['is_scratch']:
            warnings.append(
                f"Stage {idx}: FROM scratch detected. Scratch images have zero "
                f"OS packages and cannot be patched via base image replacement. "
                f"Vulnerabilities come only from statically-compiled binaries."
            )
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # G3: 3-tier ARG resolution for FROM $VAR patterns
        if "$" in orig_base or "{" in orig_base:
            resolved_base = _resolve_arg_in_from(orig_base, dockerfile_text)
            if resolved_base and resolved_base != orig_base:
                logger.info(
                    f"Stage {idx}: Resolved FROM {orig_base} -> {resolved_base}"
                )
                # Replace orig_base with resolved value for further processing
                orig_base = resolved_base
                stage['base_image'] = resolved_base
            else:
                warnings.append(
                    f"Stage {idx}: FROM references build arg '{orig_base}' "
                    f"which could not be resolved. Skipping this stage. "
                    f"Provide --base-mapping to override."
                )
                patched_lines.append(stage['from_line'])
                patched_lines.extend(stage['lines'])
                continue

        # Skip bare stage names (no : / or . → likely an alias)
        if not (":" in orig_base or "/" in orig_base or "." in orig_base):
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Choose new base image
        if base_mapping and (orig_base in base_mapping or stage['base_name'] in base_mapping):
            # User override — highest priority, full confidence
            new_base = base_mapping.get(orig_base, base_mapping.get(stage['base_name']))
            selection_confidence = 1.0
        else:
            # SBOM-driven selection
            new_base, selection_confidence = choose_base_image(
                inference, original_base=orig_base
            )

        # Confidence check — warn if we're not confident
        if selection_confidence < MIN_AUTO_PATCH_CONFIDENCE:
            warnings.append(
                f"Stage {idx}: Low confidence ({selection_confidence:.2f}) selecting "
                f"'{new_base}' to replace '{orig_base}'. Consider providing a "
                f"--base-mapping override for this image."
            )
            if dry_run:
                # In dry-run mode, still show what we'd do
                pass
            # We still apply the change, but the warning is recorded

        # Skip if new base is scratch
        if new_base.lower() == "scratch":
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Warn about COPY --from= breakage
        if alias:
            all_lines_str = "\n".join(stage['lines']).lower()
            if "--from=" in all_lines_str:
                warnings.append(
                    f"Stage {idx} (alias '{alias}'): downstream COPY --from= "
                    f"references may break if base image changes incompatibly"
                )

        # glibc warning for specific images
        if inference.needs_glibc and "alpine" in new_base.lower():
            warnings.append(
                f"Stage {idx}: glibc-dependent packages detected but Alpine selected. "
                f"Runtime failures possible. Consider using -slim variant instead."
            )

        base_changes.append((orig_base, new_base))

        # G1: Add audit comment above the rewritten FROM line
        audit_comment = (
            f"# AutoPatch: {orig_base} -> {new_base} "
            f"(confidence={selection_confidence:.2f}, "
            f"os={inference.os_family}, libc={inference.libc_type})"
        )
        patched_lines.append(audit_comment)

        # Build new FROM line preserving alias and comment
        alias_clause = f" AS {alias}" if alias else ""
        comment_clause = f" {comment}" if comment else ""
        new_from_line = f"FROM {new_base}{alias_clause}{comment_clause}"
        patched_lines.append(new_from_line)

        # Preserve ALL other instructions unchanged
        patched_lines.extend(stage['lines'])

    patched_text = "\n".join(patched_lines) + "\n"

    # ── Package manager migration: if base image OS family changed, migrate commands ──
    if base_changes and not dry_run:
        # Infer OS families from the base images that changed
        for orig_base, new_base in base_changes:
            from_os = _infer_os_from_image(orig_base)
            to_os = _infer_os_from_image(new_base)

            # Only migrate if both OS families are identified and they differ
            if from_os and to_os and from_os != to_os:
                logger.info(
                    f"Detected OS family change: {from_os} -> {to_os}, "
                    f"migrating package manager commands"
                )
                migrated, pkg_changes, pkg_warnings = migrate_package_commands(
                    patched_text, from_os, to_os
                )
                patched_text = migrated
                if pkg_changes:
                    logger.info(f"Package migration changes: {pkg_changes}")
                if pkg_warnings:
                    warnings.extend(pkg_warnings)
                    logger.warning(f"Package migration warnings: {pkg_warnings}")

    if dry_run:
        patched_text = dockerfile_text  # Don't actually change anything

    # Generate human-readable diff
    diff_lines = ["--- Dockerfile (original)", "+++ Dockerfile (patched)", ""]
    for orig, new in base_changes:
        diff_lines.append(f"- FROM {orig}")
        diff_lines.append(f"+ FROM {new}")
    if warnings:
        diff_lines.append("")
        diff_lines.append("# Warnings:")
        for warning in warnings:
            diff_lines.append(f"# {warning}")
    diff_lines.append("")
    diff_lines.append(f"# Inference confidence: {inference.confidence:.2f}")
    if inference.signals:
        diff_lines.append("# Signals:")
        for signal in inference.signals:
            diff_lines.append(f"#   - {signal}")

    diff_text = "\n".join(diff_lines)

    return patched_text, base_changes, warnings, diff_text
