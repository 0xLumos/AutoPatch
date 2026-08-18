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
import uuid
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Set
from .parser import (
    parse_dockerfile_stages, analyze_run_commands, RunCommand,
    detect_package_manager_from_dockerfile, extract_preamble,
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
    # Highest GLIBC_x.y symbol version any binary in the ORIGINAL image
    # requires, e.g. "2.36". Populated by main.py from
    # glibc_detector.detect_min_glibc_from_image before patching; None
    # when the scan found nothing (static binaries, scratch, or no
    # docker). The patcher rejects candidate bases below this floor.
    #
    # `needs_glibc` is a boolean "is this a glibc workload at all";
    # this is the precise version floor, which is what actually decides
    # whether debian:12 (2.36) can host a binary built on ubuntu:24.04
    # (2.39). The two are not interchangeable.
    min_glibc: Optional[str] = None
    is_immutable: bool = False             # True for Bottlerocket, Flatcar, etc.
    confidence: float = 0.0                # 0.0 = no idea, 1.0 = certain
    signals: List[str] = field(default_factory=list)  # audit trail of what was detected
    warnings: List[str] = field(default_factory=list)

    # P5: Optional Bayesian augmentation. These fields are populated
    # only when enhance_with_provenance() is called (typically by the
    # pipeline orchestrator with the image_ref in hand). Existing
    # callers that consume analyze_sbom() directly are unaffected.
    bayesian_distro: Optional[str] = None
    bayesian_distro_probability: float = 0.0
    bayesian_tamper_probability: float = 0.0
    bayesian_evidence_loglik: float = 0.0   # log P(obs) under the BN model
    provenance_fingerprint_hash: Optional[str] = None
    provenance_tiers_observed: tuple = ()
    provenance_consensus_distro: Optional[str] = None
    provenance_consensus_libc: Optional[str] = None
    inter_tier_agreement: float = 0.0


def enhance_with_provenance(
    inference: "InferenceResult",
    *,
    image_ref: Optional[str] = None,
    provenance_fingerprint: Any = None,
) -> "InferenceResult":
    """Augment an InferenceResult with provenance fingerprint and
    Bayesian posterior. Opt-in by callers; existing behaviour is
    unchanged when this function is not invoked.

    Args:
        inference: The InferenceResult produced by analyze_sbom().
        image_ref: Image reference for live fingerprinting via Docker.
        provenance_fingerprint: Pre-computed fingerprint (test path).

    Returns:
        The same InferenceResult (mutated in place) with the new
        Bayesian fields populated. The mutation is intentional so
        downstream consumers see the augmented data without rewiring.
    """
    fp = provenance_fingerprint
    if fp is None and image_ref:
        try:
            from .provenance_fingerprint import fingerprint_image
            fp = fingerprint_image(image_ref)
        except Exception as e:
            logger.debug("provenance fingerprint failed: %s", e)
            return inference

    if fp is None:
        return inference

    try:
        from .bayesian_inference import (
            infer as bayesian_infer,
            observations_from_fingerprint,
        )
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("bayesian inference unavailable: %s", e)
        return inference

    # Map the SBOM-derived answer into exactly ONE low-trust slot.
    #
    # `analyze_sbom` produces a single conclusion. Feeding that one
    # conclusion into both `sbom_purl_distro` and `sbom_compname_distro`
    # presents it to the network as two independent witnesses, which is
    # wrong twice over. It double-counts the evidence, and because
    # `compname` is a distro-level signal while `purl` is family-level,
    # it also reintroduces the exact Ubuntu-classified-as-Debian failure
    # the family-level scoring exists to prevent: measured on an Ubuntu
    # image, ubuntu 0.871 becomes debian 0.533 purely from the
    # duplication. The same duplication inflates the tamper posterior
    # roughly threefold on any honest SBOM/filesystem disagreement.
    #
    # The purl namespace is what `analyze_sbom` actually reads, so the
    # purl slot is the honest home for its answer.
    sbom_answer = (
        inference.os_family if inference.os_family != "unknown" else None
    )
    obs = observations_from_fingerprint(
        fp,
        sbom_purl_distro=sbom_answer,
        sbom_compname_distro=None,
        trivy_result_distro=getattr(inference, "trivy_result_type", None),
    )
    posterior = bayesian_infer(obs)

    inference.bayesian_distro = posterior.distro
    inference.bayesian_distro_probability = posterior.distro_probability
    inference.bayesian_tamper_probability = posterior.tamper_probability
    inference.bayesian_evidence_loglik = posterior.evidence_loglik
    inference.provenance_fingerprint_hash = fp.fingerprint_hash
    inference.provenance_tiers_observed = fp.tiers_observed
    inference.provenance_consensus_distro = fp.consensus_distro
    inference.provenance_consensus_libc = fp.consensus_libc
    inference.inter_tier_agreement = fp.inter_tier_agreement

    if posterior.likely_tampered:
        # When tampering is likely, fall back to the filesystem-derived
        # consensus (high-trust signals) rather than the BN posterior.
        # The BN's distro_probability is correctly lower under
        # tampering because the conflicting evidence creates honest
        # uncertainty; we should still trust the filesystem signals
        # because they are by construction the ones an attacker
        # cannot lie about without breaking the image.
        fallback_distro = fp.consensus_distro or posterior.distro
        fallback_libc = fp.consensus_libc or posterior.libc
        inference.warnings.append(
            "Bayesian inference indicates likely tampering "
            f"(P(T=1)={posterior.tamper_probability:.2f}); SBOM "
            f"signals disagree with filesystem evidence. Falling back "
            f"to filesystem-derived identity: {fallback_distro}"
        )
        if fallback_distro and fallback_distro != "unknown" \
                and fallback_distro != inference.os_family:
            inference.signals.append(
                f"os_family corrected by filesystem consensus: "
                f"{inference.os_family} -> {fallback_distro}"
            )
            inference.os_family = fallback_distro
            if fallback_libc == "musl":
                inference.libc_type = "musl"
                inference.needs_glibc = False
            elif fallback_libc == "glibc":
                inference.libc_type = "glibc"
                inference.needs_glibc = True

    return inference


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


def invalidate_resolver_cache() -> None:
    """Drop the module-level :class:`ImageResolver` and any caches it
    owns.

    Long-running drivers (the experiment runner, a daemon, a notebook)
    should call this between independent runs so a 1-hour-stale Hub
    tag response from a prior invocation does not silently feed the
    next one. The next call to :func:`_get_resolver` will re-load the
    YAML registry from disk and re-warm its own caches.
    """
    global _resolver
    if _resolver is not None:
        try:
            cache = getattr(_resolver, "_cache", None)
            if isinstance(cache, dict):
                cache.clear()
            hub_cache = getattr(_resolver, "_hub_token", None)
            if hub_cache is not None:
                setattr(_resolver, "_hub_token", None)
            hub_expiry = getattr(_resolver, "_hub_token_expiry", None)
            if hub_expiry is not None:
                setattr(_resolver, "_hub_token_expiry", 0)
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("invalidate_resolver_cache: %s", e)
    _resolver = None


# ════════════════════════════════════════════════════════════════════
# SBOM Analysis — the core inference engine
# ════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════
# Inference confidence calibration
# ════════════════════════════════════════════════════════════════════
# Per-signal weights live in inference_calibration.json so they can be
# retuned (or swapped with logistic-regression coefficients fit on a
# labeled dataset) without touching code. Backstop weights are kept
# inline in case the JSON file is missing entirely.

_INFERENCE_CALIBRATION_BACKSTOP: Dict[str, Any] = {
    "weights": {
        "os_family_purl": 1.10,
        "os_family_metadata": 0.55,
        "os_family_contradiction": -0.80,
        "language_from_sbom": 0.70,
        "language_override": 2.20,
        "libc_explicit": 0.40,
        "variant_detected": 0.20,
    },
    "default_intercept": -0.50,
    "min_confidence_threshold": 0.50,
}


def _load_inference_calibration() -> Dict[str, Any]:
    try:
        import json as _json
        from pathlib import Path as _Path
        p = _Path(__file__).parent / "inference_calibration.json"
        if not p.is_file():
            return dict(_INFERENCE_CALIBRATION_BACKSTOP)
        with open(p, "r", encoding="utf-8") as f:
            data = _json.load(f)
        if not isinstance(data, dict) or "weights" not in data:
            return dict(_INFERENCE_CALIBRATION_BACKSTOP)
        return data
    except Exception:
        return dict(_INFERENCE_CALIBRATION_BACKSTOP)


_CALIBRATION: Dict[str, Any] = _load_inference_calibration()


def _sigmoid(x: float) -> float:
    """Numerically-stable sigmoid; avoids overflow on extreme inputs."""
    import math as _math
    if x >= 0:
        z = _math.exp(-x)
        return 1.0 / (1.0 + z)
    z = _math.exp(x)
    return z / (1.0 + z)


def _calibrated_confidence(log_likelihood: float) -> float:
    """Map a log-likelihood sum to a probability in [0, 1]."""
    return _sigmoid(log_likelihood + _CALIBRATION.get("default_intercept", 0.0))



def _extract_trivy_os_type(scan_or_sbom: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Pull Trivy's own OS-family classification from a scan or SBOM.

    Trivy emits ``Type`` at the Result level for OS-package results
    (e.g. ``"alpine"``, ``"debian"``, ``"amazon"``, ``"centos"``,
    ``"redhat"``). When present this is a strong, independent signal
    that corroborates (or contradicts) our purl-based detection.

    Looks first under ``Results[*].Type`` (scan JSON), then under the
    CycloneDX SBOM metadata properties (``aquasecurity:trivy:Type``).
    Returns a normalised lowercase family name or None.
    """
    if not isinstance(scan_or_sbom, dict):
        return None
    # Try scan-JSON shape first.
    for result in scan_or_sbom.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        cls = (result.get("Class") or "").lower()
        if cls != "os-pkgs":
            continue
        t = (result.get("Type") or "").lower().strip()
        if t:
            # Trivy uses "redhat" where we use "rhel"; normalise.
            return "rhel" if t == "redhat" else t
    # Try SBOM-metadata shape.
    meta = scan_or_sbom.get("metadata", {}) or {}
    props = meta.get("properties", []) or []
    if isinstance(props, list):
        for prop in props:
            if isinstance(prop, dict):
                name = (prop.get("name") or "").lower()
                if name in ("aquasecurity:trivy:type", "aquasecurity:trivy:os:type"):
                    v = (prop.get("value") or "").lower().strip()
                    if v:
                        return "rhel" if v == "redhat" else v
    return None


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

    # Calibrated confidence accumulation. Each signal contributes a
    # log-likelihood; the final confidence is sigmoid(sum), giving a
    # real probability in [0, 1] rather than an arbitrary score.
    # Weights live in inference_calibration.json.
    weights = _CALIBRATION["weights"]
    log_likelihood = 0.0

    result.os_family = _detect_os_family(purls, comp_names, meta_name, len(components))

    # Independent corroborating signal from Trivy itself. If Trivy
    # classified the OS-pkgs result as a specific family, compare to
    # our derived family; agreement is reassurance, disagreement is
    # contradiction.
    trivy_type = _extract_trivy_os_type(sbom_data)
    if trivy_type:
        result.signals.append(f"trivy_type={trivy_type}")
        if result.os_family == "unknown":
            # Trust Trivy when our derived family came up empty.
            result.os_family = trivy_type
            result.signals.append(
                f"OS={trivy_type} (recovered from Trivy Result.Type)"
            )

    if result.os_family != "unknown":
        has_strong_purl = any(p.startswith(("pkg:apk/", "pkg:deb/", "pkg:rpm/"))
                              for p in purls)
        if has_strong_purl:
            log_likelihood += weights["os_family_purl"]
            result.signals.append(f"OS={result.os_family} (from purl, strong)")
        else:
            log_likelihood += weights["os_family_metadata"]
            result.signals.append(f"OS={result.os_family} (from metadata, moderate)")

        # Contradiction detection: purls and component-name signals
        # disagree about which family this is.
        if has_strong_purl:
            purl_families = set()
            for p in purls:
                if p.startswith("pkg:apk/"): purl_families.add("alpine")
                elif p.startswith("pkg:deb/"): purl_families.add("debian-ish")
                elif p.startswith("pkg:rpm/"): purl_families.add("rhel-ish")
            comp_says_apk = any("apk-tools" in n or "musl" in n for n in comp_names)
            comp_says_deb = any("dpkg" in n or "apt-utils" in n for n in comp_names)
            comp_says_rpm = any("rpm-libs" in n or "yum" in n for n in comp_names)
            contradictions = 0
            if "alpine" in purl_families and (comp_says_deb or comp_says_rpm):
                contradictions += 1
            if "debian-ish" in purl_families and (comp_says_apk or comp_says_rpm):
                contradictions += 1
            if "rhel-ish" in purl_families and (comp_says_apk or comp_says_deb):
                contradictions += 1
            if trivy_type and trivy_type != result.os_family and trivy_type != "unknown":
                # Trivy disagrees with our derived family too.
                contradictions += 1
            if contradictions:
                log_likelihood += weights["os_family_contradiction"] * contradictions
                result.signals.append(
                    f"contradiction: purls/components/Trivy disagree on "
                    f"OS family (penalty x{contradictions})"
                )

    # ── Step 2: Detect language and version from SBOM components ──

    if language_override:
        result.language = language_override
        result.language_version = language_version_override
        log_likelihood += weights["language_override"]
        result.signals.append(
            f"lang={language_override}:{language_version_override} "
            f"(from --language override)"
        )
    else:
        lang, lang_ver = _detect_language_from_sbom(purls, comp_map, meta_name)
        if lang:
            result.language = lang
            result.language_version = lang_ver
            log_likelihood += weights["language_from_sbom"]
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
    # We treat an SBOM as evidence of a real scratch image when ANY of:
    #   - components is EXPLICITLY an empty list (the generator ran and
    #     found zero components), OR
    #   - the document carries CycloneDX wrapper fields (bomFormat /
    #     specVersion / serialNumber / dependencies), meaning the
    #     generator ran successfully.
    # If none of these hold we are looking at a failed SBOM and must
    # NOT silently classify it as scratch — that turns a scanner outage
    # into a no-op patch run with full confidence.
    components_key_present = "components" in sbom_data
    sbom_looks_well_formed = components_key_present or bool(
        sbom_data.get("bomFormat")
        or sbom_data.get("specVersion")
        or sbom_data.get("serialNumber")
        or sbom_data.get("dependencies")
    )

    if not components and not meta_component:
        if sbom_looks_well_formed:
            result.os_family = "scratch"
            result.confidence = 1.0
            result.signals.append("zero components -> scratch image")
        else:
            result.confidence = max(result.confidence, 0.0)
            result.warnings.append(
                "SBOM generation appears to have failed (no components key "
                "and no CycloneDX wrapper fields). Treating image as "
                "low-confidence rather than scratch. Re-run with a working "
                "scanner or pass --language to override."
            )
            result.signals.append("empty SBOM (likely failed) -> low confidence")

    # ── Step 8: Extract OS version from metadata ─────────────────

    os_props = metadata.get("properties", [])
    for prop in os_props if isinstance(os_props, list) else []:
        if isinstance(prop, dict):
            name = prop.get("name", "")
            if name in ("aquasecurity:trivy:os:name", "os:name"):
                result.os_version = prop.get("value")
                result.signals.append(f"os_version={result.os_version}")

    # Final confidence: sigmoid of the accumulated log-likelihood.
    # Scratch detection sets confidence=1.0 explicitly; preserve that.
    if result.os_family != "scratch":
        if result.libc_type and result.libc_type != "unknown":
            log_likelihood += weights["libc_explicit"]
        if result.variant:
            log_likelihood += weights["variant_detected"]
        result.confidence = _calibrated_confidence(log_likelihood)
        result.signals.append(
            f"calibrated_log_likelihood={log_likelihood:.2f} -> "
            f"confidence={result.confidence:.3f}"
        )

    return result


def _os_token_in(token: str, text: str) -> bool:
    """True if ``token`` appears in ``text`` as a whole word.

    "Whole word" means not flanked by another letter or digit, so
    ``cos`` matches ``cos`` and ``cos-release`` but NOT the ``cos`` buried
    in ``microcosm``. Delimiters common in image and package names
    (``-``, ``_``, ``/``, ``.``, ``:``, whitespace) count as boundaries.
    This is the difference between recognising Container-Optimized OS
    and misreading an HTML-sanitiser dependency as one.
    """
    if not token or not text:
        return False
    return re.search(
        rf"(?<![a-z0-9]){re.escape(token.lower())}(?![a-z0-9])",
        text.lower(),
    ) is not None


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

    # Ecosystem detection is needed up front, because the immutable-OS
    # gate below depends on it.
    has_apk = any("pkg:apk/" in p for p in purls)
    has_deb = any("pkg:deb/" in p for p in purls)
    has_rpm = any("pkg:rpm/" in p for p in purls)
    has_mutable_pkgdb = has_apk or has_deb or has_rpm

    # ---- Layer 3 first: special cases that override everything ----

    # Check distroless FIRST: distroless images contain pkg:deb/ but
    # must NOT be classified as debian
    if "distroless" in meta_name:
        return "distroless"

    # Immutable OS detection.
    #
    # Two guards, because the family tokens are short (e.g. "cos" for
    # Google Container-Optimized OS) and were previously substring-
    # matched against EVERY SBOM component name:
    #
    #   1. Gate on the ABSENCE of a mutable package database. Real
    #      immutable hosts (Bottlerocket, Flatcar, Talos, COS, Fedora
    #      CoreOS) ship no apk/deb/rpm DB, so an image that HAS one
    #      cannot be any of them, whatever its component names contain.
    #   2. Word-boundary the match. "cos" must be a standalone token,
    #      not a fragment of another word.
    #
    # Without these, gitea's HTML-sanitiser dependency
    # github.com/microCOSm-cc/bluemonday made every gitea image (a
    # normal Alpine build) classify as Container-Optimized OS, which
    # refuses base replacement entirely and silently declined the
    # remediation. Any Go/npm/pypi app vendoring a module whose name
    # merely contained "cos", "talos", etc. was affected.
    if not has_mutable_pkgdb:
        for immutable_os in IMMUTABLE_OS_FAMILIES:
            if _os_token_in(immutable_os, meta_name):
                return immutable_os
            if any(_os_token_in(immutable_os, n) for n in comp_names):
                return immutable_os

    # Windows detection: pkg:nuget/ or Windows-specific components
    has_nuget = any("pkg:nuget/" in p for p in purls)
    if has_nuget or any(n in comp_names for n in ["windows", "nanoserver", "servercore"]):
        return "windows"

    # ---- Layer 1: purl ecosystem prefix ----

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

    Recognised values:
      - ``glibc``    Debian, Ubuntu, RHEL family, Fedora, Wolfi, etc.
      - ``musl``     Alpine, distroless-static-musl, BusyBox-static-musl.
      - ``distroless-glibc`` gcr.io/distroless/* glibc variants.
      - ``distroless-static`` gcr.io/distroless/static-debian* (no libc;
        any binary must be fully static).
      - ``bionic``   Android (rare in containers).
      - ``uclibc``   Embedded (rare).
      - ``unknown``  No reliable signal.

    Distroless splits matter because moving a glibc-linked binary onto
    a distroless-static base or an Alpine base will segfault at first
    run; the resolver consults this value to refuse unsafe transitions.

    Args:
        comp_names: Lowercase component names from SBOM
        purls: Package URLs from SBOM
        os_family: Already-detected OS family

    Returns:
        One of the literal strings listed above.
    """
    musl_indicators = {"musl", "musl-utils", "musl-dev"}
    glibc_indicators = {"glibc", "libc6", "libc-bin", "libc6-dev",
                         "glibc-common", "glibc-minimal-langpack"}

    if any(n in musl_indicators for n in comp_names):
        return "musl"
    if any(n in glibc_indicators for n in comp_names):
        return "glibc"

    # Distroless detection: the gcr.io/distroless images carry distinctive
    # component-name markers (cacerts, base-files, tzdata) but no libc
    # package on the static variant.
    distroless_markers = {"cacerts-distroless", "base-files-distroless"}
    if any(n in distroless_markers for n in comp_names) or os_family == "distroless":
        # If we also see glibc/libc6 the distroless is the glibc variant.
        if any(n in glibc_indicators for n in comp_names):
            return "distroless-glibc"
        # Otherwise assume the static variant (no libc).
        return "distroless-static"

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
        return "musl"
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

def _repo_of(ref: str) -> str:
    """Repository portion of an image reference, without tag or digest."""
    ref = (ref or "").strip()
    if "@" in ref:
        ref = ref.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref = ref[: len(ref) - len(last) + last.index(":")]
    return ref


def apply_allowlist_gate(
    original_base: str,
    candidate: str,
    inference: Optional[InferenceResult] = None,
) -> Tuple[str, Optional[str]]:
    """Adjudicate a proposed base-image substitution against the
    mechanically verified allow-list.

    Rationale for the policy, which is deliberately narrow:

    * **Same repository, new tag** is never gated. ``python:3.9-slim``
      to ``python:3.12-slim`` keeps the same publisher, namespace and
      signing identity; there is no new party to trust, so requiring an
      allow-list entry would only block routine upgrades.
    * **Different repository** IS gated. Rewriting ``FROM centos:7`` to
      ``FROM someone-elses/centos`` hands build-time code execution to a
      new publisher. That is the substitution an attacker wants, and it
      is exactly what the allow-list exists to constrain.
    * **Unknown source repository** (the allow-list has no entry for it)
      cannot be adjudicated either way. Rejecting would disable
      remediation for every repository not yet enumerated; the migration
      is permitted and the gap is logged, so the report shows which
      substitutions were unverified rather than implying all were checked.

    Returns:
        ``(effective_base, note)``. ``note`` is None when nothing needed
        saying, otherwise a human-readable warning for the report.
    """
    if not candidate or not original_base or candidate == original_base:
        return candidate, None

    src_repo = _repo_of(original_base)
    dst_repo = _repo_of(candidate)
    if src_repo == dst_repo:
        return candidate, None

    try:
        from .allowlist_loader import load_allowlist
        allow = load_allowlist()
    except Exception as e:                     # pragma: no cover
        logger.warning("Allow-list unavailable (%s); migration ungated", e)
        return candidate, (
            f"allow-list could not be loaded ({e}); the migration "
            f"{src_repo} -> {dst_repo} was NOT verified"
        )

    approved = allow.alternates_for(
        src_repo,
        family=getattr(inference, "os_family", None) if inference else None,
        libc=("glibc" if getattr(inference, "needs_glibc", False) else None)
        if inference else None,
    )
    if not approved:
        logger.info(
            "Allow-list has no entry for source repository %r; migration "
            "to %r is unverified.", src_repo, dst_repo,
        )
        return candidate, (
            f"no allow-list entry for '{src_repo}', so the migration to "
            f"'{dst_repo}' is unverified"
        )

    if any(t.target_repo == dst_repo for t in approved):
        logger.debug("Allow-list approves %s -> %s", src_repo, dst_repo)
        return candidate, None

    # The source repository IS enumerated and this target is not among
    # its approved alternates. Substitute the highest-priority approved
    # alternate (alternates_for already sorts deterministically) rather
    # than abandoning the upgrade entirely.
    best = approved[0]
    logger.warning(
        "Allow-list rejects %s -> %s (not an approved alternate); "
        "substituting %s instead.", src_repo, dst_repo, best.target_ref,
    )
    return best.target_ref, (
        f"'{dst_repo}' is not an approved alternate for '{src_repo}'; "
        f"used the allow-listed '{best.target_ref}' instead"
    )


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

    # ── Distro runtime stages stay within their distribution ────────
    #
    # This guard runs BEFORE the resolver and the language paths on
    # purpose. A final stage whose base is a plain OS distribution
    # (FROM alpine, FROM debian:11) must be upgraded to a newer release
    # of THAT distribution, never redirected to a language image.
    #
    # gitea and act copy a compiled binary onto a bare alpine runtime.
    # The SBOM of that runtime then shows Go/Python, and BOTH the
    # resolver (which returns first) and the legacy language paths below
    # would build golang:X-alpine / python:X-alpine from it. Observed
    # damage: gitea -> golang:3.11-alpine, a tag that does not exist, so
    # the registry guard rejects it and 191 CVEs go unpatched; act ->
    # python:3.12-alpine, which exists but is the WRONG runtime, turning
    # a clean 0-CVE image into a broken 0->5-CVE one (correctly rejected
    # by the gate, but a missed upgrade either way). A distribution base
    # carries no language toolchain at runtime, so the SBOM-detected
    # language is a property of the copied application, not of the base
    # that should host it. Preserve the family.
    if original_base and (_is_distribution_repo(original_base)
                          or _is_distroless(original_base)):
        if _is_distroless(original_base):
            # Distroless runtime bases carry a copied application binary,
            # so their SBOM shows a language just as a bare distro's does.
            # The Debian release is encoded in the repo leaf, not the tag.
            # Left unfixed, headscale@legacy went
            # gcr.io/distroless/base-debian11 -> golang:1.23-bookworm,
            # 238 -> 5667 CVEs (declined by the gate, but a catastrophic
            # mis-pick). Keep it in-family: base-debian11 -> base-debian12.
            _bump = _distroless_same_family_bump(original_base)
        else:
            _repo_leaf = _repo_of(original_base).rsplit("/", 1)[-1].lower()
            _tag = _tag_of_ref(original_base)
            _bump = _distro_same_family_bump(_repo_leaf, _tag) if _tag else None
        if _bump:
            logger.info(
                "Minimal/distribution runtime base %s: in-family upgrade "
                "to %s (language image suppressed)", original_base, _bump[0],
            )
            return _bump
        # Already on a current/unrecognised release of its own family.
        # Return the original unchanged so the acceptance gate sees no
        # change and declines, rather than crossing to a language image
        # or forcing a downgrade to a hardcoded "current" release (which
        # would turn alpine:3.24 into alpine:3.21).
        logger.info(
            "Runtime base %s is already current or has no in-family "
            "upgrade; leaving unchanged rather than crossing to a "
            "language image.", original_base,
        )
        return original_base, 0.0

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
        # Preserve the PHP variant. apache/fpm carry apache2/php-fpm binaries
        # and RUN steps (a2enmod, apache2-foreground) that do not exist in the
        # cli image, so dropping the variant breaks the build. Detect from the
        # original tag, not just the `variant` param.
        if variant == "apache" or "apache" in original_lower:
            return f"php:{version}-apache"
        if "fpm" in original_lower:
            return f"php:{version}-fpm-alpine" if is_alpine else f"php:{version}-fpm"
        return f"php:{version}-cli-alpine" if is_alpine else f"php:{version}-cli"

    if language == "openjdk":
        # Preserve JDK vs JRE: a JDK image compiles (javac/maven/gradle), a JRE
        # only runs. Rewriting a build image (jdk) to a jre removes javac and
        # breaks `mvn package`/`gradle build`. Default to jdk unless the tag is
        # explicitly a jre.
        kind = "jre" if ("jre" in original_lower and "jdk" not in original_lower) else "jdk"
        return (f"eclipse-temurin:{version}-{kind}-alpine" if is_alpine
                else f"eclipse-temurin:{version}-{kind}-jammy")

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


# Module-level toggle. When False (the default), _upgrade_eol_version
# returns the caller-supplied version unchanged so a user-pinned tag
# like ``python:3.9`` is preserved verbatim. main.py flips this to
# True when invoked with ``--eol-upgrade`` so the experiment runner
# can still benefit from EOL detection.
_EOL_UPGRADE_ACTIVE = False


def _upgrade_eol_version(language: str, version: str) -> str:
    """
    Upgrade EOL language versions to the latest supported version.

    Gated by the module-level ``_EOL_UPGRADE_ACTIVE`` toggle. When that
    is False (the default), this function returns ``version`` unchanged
    so a user-pinned tag like ``python:3.9`` is preserved verbatim and
    the variant-only rewrite (e.g. ``python:3.9 -> python:3.9-alpine``)
    is what the caller sees. When True, the function defers to
    ``version_resolver.resolve_eol_upgrade`` which consults
    endoflife.date (or the hardcoded fallback table) for the currently
    supported successor of an EOL release.

    Args:
        language: Detected language runtime
        version: Detected version string (e.g., "7.4", "12", "1.16")

    Returns:
        Upgraded version if EOL and upgrades are active, otherwise the
        original version unchanged.
    """
    if not _EOL_UPGRADE_ACTIVE:
        return version
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


# Base-image repo -> primary language. When the base IS a language image its
# tag is AUTHORITATIVE for the runtime: official golang/node/rust images install
# the toolchain as a binary tarball, not a distro package, so Trivy's SBOM never
# lists it. SBOM-only inference then misfires onto incidental system deps
# (golang/node Debian bases ship python3+perl), rewriting e.g. golang -> python.
_LANGUAGE_IMAGE_REPOS: Dict[str, str] = {
    "golang": "golang", "go": "golang",
    "node": "node", "nodejs": "node",
    "python": "python", "ruby": "ruby", "php": "php", "rust": "rust",
    "perl": "perl",
    "openjdk": "openjdk", "eclipse-temurin": "openjdk", "temurin": "openjdk",
    "adoptopenjdk": "openjdk", "amazoncorretto": "openjdk",
    "elixir": "elixir", "erlang": "erlang",
}


def _language_from_base_image(base_ref: str) -> Tuple[Optional[str], Optional[str]]:
    """If ``base_ref`` is a known language image, return (language, version)
    derived from its tag; otherwise (None, None) so SBOM inference decides.

    OS/app bases (debian, alpine, nginx, postgres, ...) and stage aliases
    (``builder``, ``gorun``) return (None, None) on purpose: for those the SBOM
    is the right signal (e.g. debian + ``pip install`` really is python).
    """
    if not base_ref:
        return None, None
    repo = base_ref.split("@")[0].split(":")[0].lower()
    last = repo.rsplit("/", 1)[-1]
    lang = _LANGUAGE_IMAGE_REPOS.get(last)
    if lang is None and "dotnet" in repo:
        lang = "dotnet"
    if lang is None:
        return None, None
    return lang, _extract_version_from_tag(base_ref.lower(), lang)


# ════════════════════════════════════════════════════════════════════
# Data tables for _match_by_image_name (substring-based legacy fallback)
# ════════════════════════════════════════════════════════════════════
#
# Order is significant: more specific patterns precede less specific
# ones (e.g. "mongo-express" before "mongo", "phpmyadmin" before "php",
# "aspnet" before "dotnet"). Keep the comments in place when editing
# so the next maintainer doesn't reshuffle and reintroduce the
# collisions the audit caught.

_STATIC_MATCHERS: List[Tuple[str, str]] = [
    # Databases (mongo-express first; substring of "mongo").
    ("mongo-express",    "mongo-express:latest"),
    ("mongo",            "mongo:7"),
    ("redis",            "redis:7-alpine"),
    ("postgres",         "postgres:17-alpine"),
    ("mysql",            "mysql:8.4"),
    ("mariadb",          "mariadb:11"),
    ("cassandra",        "cassandra:5.0"),
    ("couchdb",          "couchdb:3.4"),
    ("influxdb",         "influxdb:2.7-alpine"),
    ("neo4j",            "neo4j:5-community"),
    ("memcached",        "memcached:1.6-alpine"),
    ("zookeeper",        "zookeeper:3.9"),

    # App servers (must precede JDK/openjdk matches because Tomcat
    # tags often embed "openjdk" — e.g. tomcat:10.1.18-jdk21-openjdk-bullseye).
    ("tomcat",           "tomcat:10.1-jre21"),
    ("jetty",            "jetty:12-jre21"),
    ("wildfly",          "wildfly:34-jre21"),

    # Build tools (precede openjdk; maven:3.8-openjdk-11 etc.).
    ("maven",            "maven:3.9-eclipse-temurin-21-alpine"),
    ("gradle",           "gradle:8-jdk21-alpine"),

    # CMS app that contains "php" as substring.
    ("phpmyadmin",       "phpmyadmin:latest"),

    # Web servers / infrastructure.
    ("nginx",            "nginx:stable-alpine"),
    ("httpd",            "httpd:2.4-alpine"),
    ("traefik",          "traefik:v3.3"),
    ("caddy",            "caddy:2-alpine"),
    ("haproxy",          "haproxy:3.1-alpine"),
    ("envoy",            "envoyproxy/envoy:v1.32-latest"),
    ("kong",             "kong:3.9"),

    # Message queues / data plane.
    ("rabbitmq",         "rabbitmq:4-alpine"),
    ("elasticsearch",    "docker.elastic.co/elasticsearch/elasticsearch:8.17.0"),
    ("kafka",            "bitnami/kafka:3.9"),
    ("nats",             "nats:2.10-alpine"),

    # Monitoring & observability.
    ("grafana",          "grafana/grafana:11.5.2"),
    ("prometheus",       "prom/prometheus:v2.53.4"),
    ("alertmanager",     "prom/alertmanager:v0.28.1"),
    ("fluentd",          "fluentd:v1.17-debian-1"),
    ("kibana",           "docker.elastic.co/kibana/kibana:8.17.0"),
    ("logstash",         "docker.elastic.co/logstash/logstash:8.17.0"),

    # CI/CD tools.
    ("jenkins",          "jenkins/jenkins:lts-alpine"),
    ("vault",            "hashicorp/vault:latest"),
    ("consul",           "hashicorp/consul:latest"),
    ("sonarqube",        "sonarqube:lts-community"),
    ("gitlab",           "gitlab/gitlab-runner:alpine"),
    ("gitea",            "gitea/gitea:latest"),
    ("drone",            "drone/drone:latest"),
    ("nexus",            "sonatype/nexus3:latest"),

    # Cloud native infrastructure.
    ("minio",            "minio/minio:latest"),
    ("portainer",        "portainer/portainer-ce:2.24.1"),

    # CMS / applications (drupal handled separately for version preservation).
    ("wordpress",        "wordpress:6-php8.3-apache"),
    ("nextcloud",        "nextcloud:29-apache"),
    ("ghost",            "ghost:5-alpine"),
    ("joomla",           "joomla:5-php8.3-apache"),
    ("redmine",          "redmine:5-alpine"),
    ("mediawiki",        "mediawiki:lts-fpm"),
    ("adminer",          "adminer:latest"),
    ("matomo",           "matomo:5-apache"),

    # Docker tooling (use the more minimal :27-cli variant).
    ("docker",           "docker:27-cli"),  # TODO: re-evaluate docker:27-dind

    # Data processing & search.
    ("solr",             "solr:9"),
    ("flink",            "flink:1.20"),
]


# Language matchers in priority order. "aspnet" and "dotnet+sdk" are
# handled before generic dotnet so the MS Docker org's tag layout wins;
# the order here mirrors the original if/elif chain to preserve
# behaviour for callers that rely on it.
_LANGUAGE_MATCHERS: List[Dict[str, str]] = [
    {
        "pattern": "rust", "language": "rust", "fallback": "1.85",
        "alpine": "rust:{ver}-alpine", "default": "rust:{ver}-slim",
    },
    {
        "pattern": "perl", "language": "perl", "fallback": "5.40",
        "alpine": "perl:{ver}-slim", "default": "perl:{ver}-slim",
    },
    {
        "pattern": "erlang", "language": "erlang", "fallback": "27",
        "alpine": "erlang:{ver}-slim", "default": "erlang:{ver}-slim",
    },
    {
        "pattern": "elixir", "language": "elixir", "fallback": "1.18",
        "alpine": "elixir:{ver}-slim", "default": "elixir:{ver}-slim",
    },
    # ASP.NET / .NET SDK (substring "aspnet" or "dotnet sdk") come
    # before plain dotnet matches.
    {
        "pattern": "aspnet", "language": "dotnet", "fallback": "8.0",
        "alpine": "mcr.microsoft.com/dotnet/aspnet:{ver}-alpine",
        "default": "mcr.microsoft.com/dotnet/aspnet:{ver}-alpine",
    },
    # Note: dotnet+sdk requires both substrings present; we handle it
    # with a custom check inline in the function rather than fitting
    # it into this table.
    {
        "pattern": "python", "language": "python", "fallback": "3.12",
        "alpine": "python:{ver}-alpine", "default": "python:{ver}-slim",
    },
    {
        "pattern": "node", "language": "node", "fallback": "22",
        "alpine": "node:{ver}-alpine", "default": "node:{ver}-slim",
    },
    {
        "pattern": "ruby", "language": "ruby", "fallback": "3.3",
        "alpine": "ruby:{ver}-alpine", "default": "ruby:{ver}-slim",
    },
]


def _match_by_image_name(o: str, os_suffix: str) -> Optional[str]:
    """LEGACY substring fallback. When this returns non-None it means
    the YAML registry (`ImageResolver`) failed to match an image that
    the substring table CAN match -- that's a YAML coverage gap that
    should be filled. Each such fallback logs at WARNING so gaps are
    visible during the deprecation window before this function is
    removed.

    The original docstring follows."""
    _result = _match_by_image_name_impl(o, os_suffix)
    if _result is not None:
        logger.warning(
            "Legacy substring fallback matched %r -> %r. The YAML "
            "image registry (image_registry.yaml) should be extended "
            "to cover this image; the substring table is deprecated "
            "and will be removed in 0.4.0.",
            o, _result,
        )
    return _result


def _match_by_image_name_impl(o: str, os_suffix: str) -> Optional[str]:
    """
    Legacy fallback: match image by substring in the original tag.

    The function works through three ordered tables:

    1. ``_STATIC_MATCHERS``  - substring -> literal target. Used for
       databases, message queues, monitoring, CI tools, CMS apps, etc.
       Order matters: ``mongo-express`` must precede ``mongo`` so the
       more specific pattern wins.

    2. ``_LANGUAGE_MATCHERS`` - substring -> (language, fallback_version,
       alpine_tpl, slim_tpl). The version is extracted from the original
       tag via ``_extract_version_from_tag`` and optionally upgraded via
       ``_upgrade_eol_version`` (which is itself gated on the
       ``_EOL_UPGRADE_ACTIVE`` toggle).

    3. ``_PHP_MATCHER`` - PHP gets a richer variant table because the
       Docker Hub tag schema includes ``-apache``, ``-fpm``, and ``-cli``
       sub-variants.

    The previous implementation hand-rolled all of the above as 200
    lines of ``if "x" in o`` chains; consolidating them eliminates
    accidental ordering bugs (a recurring source of the
    ``mongo`` / ``mongo-express`` style collisions noted in the audit).
    """
    is_alpine = (os_suffix == "alpine")

    # C1 fix: match against the repository basename only, never the
    # registry host or namespace. "docker.io/library/python:3.6" reduces
    # to name_part "python:3.6" and repo "python". Without this, the
    # registry host "docker.io" matched the "docker" static pattern and a
    # Python image was rewritten to the Docker CLI image; likewise
    # "registry.example.com/myapp" hit the registry:2 rule. Version
    # extraction still runs against the full original ref ``o`` because the
    # tag may carry the version we need to preserve.
    name_part = o.split("/")[-1].lower()
    repo = name_part.split(":")[0].split("@")[0]

    def _name_matches(pattern: str) -> bool:
        """Anchored match on the repo basename. Exact, or pattern followed
        by a digit or a separator (covers ``nexus3``, ``gitlab-runner``,
        ``node-red``). Never a bare substring over the full reference."""
        if repo == pattern:
            return True
        if repo.startswith(pattern):
            rest = repo[len(pattern):]
            return bool(rest) and (rest[0].isdigit() or rest[0] in "-._/")
        return False

    # Pass 1: static matchers (literal returns, no version templating).
    for pattern, target in _STATIC_MATCHERS:
        if _name_matches(pattern):
            return target

    # Pass 1.5: openjdk-family special case (Temurin / AdoptOpenJDK /
    # OpenJDK all consolidate onto eclipse-temurin).
    if any(_name_matches(s) for s in ("temurin", "adoptopenjdk", "openjdk", "eclipse-temurin")):
        m = re.search(r":(\d+)", o)
        major = m.group(1) if m else "21"
        major = _upgrade_eol_version("openjdk", major)
        return (
            f"eclipse-temurin:{major}-jre-alpine"
            if is_alpine
            else f"eclipse-temurin:{major}-jre-jammy"
        )

    # Pass 1.6: golang short-form match (``go`` repo not covered by the
    # plain table; matched on the repo basename, never the tag).
    if repo == "golang" or repo == "go":
        ver = _extract_version_from_tag(o, "golang") or "1.22"
        ver = _upgrade_eol_version("golang", ver)
        return (
            f"golang:{ver}-alpine"
            if is_alpine
            else f"golang:{ver}-bookworm"
        )

    # Pass 2: language matchers (version-templated returns).
    for matcher in _LANGUAGE_MATCHERS:
        if not _name_matches(matcher["pattern"]):
            continue
        ver = (
            _extract_version_from_tag(o, matcher["language"])
            or matcher["fallback"]
        )
        ver = _upgrade_eol_version(matcher["language"], ver)
        template = matcher["alpine"] if is_alpine else matcher["default"]
        return template.format(ver=ver)

    # Pass 3: PHP variants (apache / fpm / cli sub-selection). The variant
    # lives in the tag, so it is read from name_part once the repo matches.
    if repo == "php":
        ver = _extract_version_from_tag(o, "php") or "8.3"
        ver = _upgrade_eol_version("php", ver)
        if "apache" in name_part:
            return f"php:{ver}-apache"
        if "fpm" in name_part:
            return f"php:{ver}-fpm-alpine" if is_alpine else f"php:{ver}-fpm"
        return f"php:{ver}-cli-alpine" if is_alpine else f"php:{ver}-cli"

    # Pass 4: drupal preserves its own major version.
    if repo == "drupal":
        m = re.search(r"drupal:(\d+)", o)
        drupal_major = m.group(1) if m else "11"
        return f"drupal:{drupal_major}-php8.3-apache"

    # Registry images: anchored on the repo basename so private registry
    # hostnames beginning with "registry" no longer false-match.
    if repo == "registry":
        return "registry:2"

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
        "centos": "rockylinux:9",
        "rhel": "rockylinux:9",
        "rocky": "rockylinux:9",
        "alma": "almalinux:9",
        "fedora": "fedora:41",
        "amazon": "amazonlinux:2023",
        "oracle": "oraclelinux:9",
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
        "centos": "rockylinux:9",
        "rhel": "rockylinux:9",
        "rocky": "rockylinux:9",
        "alma": "almalinux:9",
        "fedora": "fedora:41",
        "amazon": "amazonlinux:2023",
        "oracle": "oraclelinux:9",
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

    # Repository name first. A reference whose repository IS the
    # distribution is the least ambiguous signal available, and
    # matching only on codenames previously missed the most common
    # form of all: plain "debian:11" and "debian:12" returned None,
    # which silently disabled both package-manager migration and the
    # cross-family compatibility guards for those images.
    repo = lower.split("@", 1)[0].rsplit(":", 1)[0]
    repo_leaf = repo.rsplit("/", 1)[-1]
    _REPO_FAMILY = {
        "alpine": "alpine",
        "debian": "debian",
        "ubuntu": "ubuntu",
        "rockylinux": "rocky", "rocky": "rocky",
        "almalinux": "alma", "alma": "alma",
        "centos": "centos",
        "fedora": "fedora",
        "wolfi-base": "wolfi", "wolfi": "wolfi",
    }
    if repo_leaf in _REPO_FAMILY:
        return _REPO_FAMILY[repo_leaf]

    # Then distribution codenames and variant suffixes carried in the
    # tag of a language-runtime image (python:3.12-slim-bookworm).
    if "alpine" in lower:
        return "alpine"
    if ("slim" in lower or "bookworm" in lower or "bullseye" in lower
            or "buster" in lower or "trixie" in lower):
        return "debian"
    if ("ubuntu" in lower or "jammy" in lower or "focal" in lower
            or "bionic" in lower or "noble" in lower):
        return "ubuntu"
    if "rocky" in lower:
        return "rocky"
    if "alma" in lower:
        return "alma"
    if "centos" in lower:
        return "centos"
    if "fedora" in lower:
        return "fedora"
    if "ubi9" in lower or "ubi8" in lower or "/ubi" in lower:
        return "rhel"

    # Last: the DEFAULT variant of an official language/runtime image.
    #
    # Docker Official language images ship a Debian rootfs unless the
    # tag says otherwise, so `golang:1.19`, `node:18`, `python:3.12`
    # and friends are glibc Debian images. Returning None for them
    # disabled every family-keyed check on the stages where those
    # images overwhelmingly appear: BUILDER stages. That is precisely
    # where the glibc-to-musl COPY --from boundary bug lives, so the
    # single most important guard was inert for the single most common
    # builder base. Consulted only after the explicit suffix and
    # codename checks above, so `golang:1.22-alpine` still resolves to
    # alpine and an explicit signal always wins over this default.
    _DEFAULT_DEBIAN_REPOS = {
        "golang", "node", "python", "ruby", "rust", "php", "perl",
        "openjdk", "maven", "gradle", "eclipse-temurin", "amazoncorretto",
        "nginx", "httpd", "haproxy", "postgres", "mysql", "mariadb",
        "redis", "mongo", "rabbitmq", "elixir", "erlang", "haskell",
        "gcc", "buildpack-deps", "tomcat", "jetty", "composer",
    }
    if repo_leaf in _DEFAULT_DEBIAN_REPOS:
        logger.debug(
            "%s carries no distribution suffix; official %s images default "
            "to Debian, assuming glibc/debian.", image_ref, repo_leaf,
        )
        return "debian"
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

            # Replace the lines, preserving the originals as inline
            # comments so the diff is auditable (the previous behaviour
            # silently dropped continuation lines and any human comments
            # interleaved between them).
            indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
            indent_str = " " * indent

            original_block_lines = lines[start_idx:end_idx + 1]
            commented_original = "".join(
                indent_str + "# [autopatch migrated] " + ln
                if ln.strip() else ""
                for ln in original_block_lines
            )

            if start_idx == end_idx:
                lines[start_idx] = (
                    commented_original
                    + indent_str + f"RUN {migrated_text}\n"
                )
            else:
                lines[start_idx] = (
                    commented_original
                    + indent_str + f"RUN {migrated_text}\n"
                )
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

    # C2 fix: _translate_package_command returns "" for steps that have no
    # target equivalent (e.g. "apt-get clean" has no apk counterpart).
    # Joining those empties with " && " produced broken shell such as
    # "apk update &&  && apk add curl", which fails every migration of a
    # Dockerfile that contains a cleanup step. Drop empty subcommands first.
    migrated_subs = [s for s in migrated_subs if s and s.strip()]
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
    container_name = f"autopatch-smoke-{sanitized_name}-{uuid.uuid4().hex[:8]}"

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
from .constants import MIN_AUTO_PATCH_CONFIDENCE
# Sourced from constants.py so the documented AUTOPATCH_* env
# override is real. It was a duplicated literal, which made
# every override in the README silently inert.


# Repos that carry a language toolchain and a clean numeric version in the
# tag, for which a same-repo version bump is safe and meaningful. The value
# is the language key understood by _upgrade_eol_version / _extract_version_from_tag.
_CONSERVATIVE_BUMP_REPOS: Dict[str, str] = {
    "golang": "golang",
    "python": "python",
    "node": "node",
    "ruby": "ruby",
    "php": "php",
    "rust": "rust",
    "perl": "perl",
    "erlang": "erlang",
    "elixir": "elixir",
    "openjdk": "openjdk",
    "eclipse-temurin": "openjdk",
    "maven": "openjdk",
    "gradle": "openjdk",
}


# Current supported release per OS distribution repository, keyed by the
# tag forms that repository actually publishes. Used ONLY to move a tag
# forward within the same repository, so the publisher, package manager
# and libc are unchanged by construction.
#
# MAINTENANCE: these are release facts with a shelf life. Two things
# keep a stale entry from becoming a wrong answer rather than merely an
# incomplete one:
#   1. The table only ever maps OLD -> NEWER inside one repository, so
#      the worst case of a missing row is "no bump offered".
#   2. When the resolver is reachable the candidate tag is verified
#      against the registry before it is emitted, and a tag that does
#      not exist upstream is dropped. See _distro_same_family_bump.
# Reviewed: 2026-08. tests/test_multistage_graph.py pins the shape and
# the direction of these mappings, not the specific release numbers, so
# a refresh does not require rewriting tests.
_DISTRO_CURRENT: Dict[str, Dict[str, str]] = {
    # Debian 13 "trixie" is the current stable. 12 "bookworm" is oldstable
    # and still supported, so it stays a valid target rather than being
    # rewritten again; only releases at or past EOL are moved. The legacy
    # stratum surfaces images as old as wheezy/jessie, so the coverage
    # goes back that far: a missing old row silently declines to upgrade
    # exactly the EOL image the tool exists to fix.
    "debian":     {"6": "12", "7": "12", "8": "12", "9": "12",
                   "10": "12", "11": "12",
                   "squeeze": "bookworm", "wheezy": "bookworm",
                   "jessie": "bookworm", "stretch": "bookworm",
                   "buster": "bookworm", "bullseye": "bookworm"},
    "ubuntu":     {"12.04": "24.04", "14.04": "24.04", "16.04": "24.04",
                   "18.04": "24.04", "20.04": "24.04", "22.04": "24.04",
                   "precise": "noble", "trusty": "noble", "xenial": "noble",
                   "bionic": "noble", "focal": "noble", "jammy": "noble"},
    # Alpine supports the two most recent minors; everything older is
    # unsupported and receives no security updates at all. Coverage goes
    # back to 3.2 (2015) so a decade-old legacy image still resolves;
    # gitea@legacy on alpine:3.11 was returning "no newer tag" purely
    # because the table started at 3.14.
    "alpine":     {f"3.{n}": "3.21" for n in range(2, 21)},
    "rockylinux": {"8": "9"},
    "rocky":      {"8": "9"},
    "almalinux":  {"8": "9"},
    "alma":       {"8": "9"},
    "centos":     {"6": "9", "7": "9", "8": "9"},
    "oraclelinux": {"6": "9", "7": "9", "8": "9"},
    "amazonlinux": {"1": "2023", "2": "2023"},
    "fedora":     {str(n): "41" for n in range(28, 41)},
}


# Repositories that publish an OS DISTRIBUTION, as opposed to a language
# runtime (python, golang, node, ...). A final stage on one of these is
# upgraded WITHIN its distribution and must never be redirected to a
# language image. Derived from the bump table plus a few distros that
# have no older-release rows to migrate.
_DISTRO_REPOS = set(_DISTRO_CURRENT) | {
    "busybox", "ubi", "ubi8", "ubi9", "ubi-minimal", "ubi8-minimal",
    "ubi9-minimal", "opensuse", "leap", "tumbleweed", "archlinux",
    "arch", "clearlinux", "photon", "slackware", "gentoo",
}


def _is_distribution_repo(ref: str) -> bool:
    """True if ``ref`` names an OS distribution image, not a language
    runtime. `FROM alpine` and `FROM debian:11` are distributions;
    `FROM python:3.9` and `FROM golang:1.21` are language runtimes."""
    if not ref:
        return False
    repo_leaf = _repo_of(ref).rsplit("/", 1)[-1].lower()
    return repo_leaf in _DISTRO_REPOS


def _tag_of_ref(ref: str) -> str:
    """Tag portion of an image reference, or "" for none/digest refs."""
    last = (ref or "").rsplit("/", 1)[-1]
    if "@" in last:                 # digest-pinned: no tag bump applies
        return ""
    return last.split(":", 1)[1] if ":" in last else ""


def _distro_same_family_bump(
    repo: str, tag: str
) -> Optional[Tuple[str, float]]:
    """Move an OS distribution image to a newer release of the SAME repo.

    Same repository means same publisher, same package manager and same
    libc, so this is safe in exactly the situations where a cross-family
    migration is not: a builder stage whose toolchain we cannot see, or
    a runtime stage whose cross-family candidate a guard rejected.

    Returns None when the tag is already current or unrecognised, which
    the caller treats as "no safe move available".
    """
    table = _DISTRO_CURRENT.get(repo)
    if not table:
        return None

    base_tag = tag.strip().lower()
    # Preserve a variant suffix such as debian:11-slim -> debian:12-slim.
    suffix = ""
    for sep in ("-",):
        if sep in base_tag:
            head, _, rest = base_tag.partition(sep)
            if head in table:
                base_tag, suffix = head, sep + rest
                break

    target = table.get(base_tag)
    if not target or target == base_tag:
        return None

    candidate = f"{repo}:{target}{suffix}"

    # Prefer registry truth over the table when we can reach it, but
    # distinguish the two ways a check can come back negative:
    #
    #   * The registry ANSWERED and the tag is absent: skip the bump,
    #     correctly (a debian:12-slim that upstream never published
    #     must not be emitted).
    #   * The registry DID NOT ANSWER (Docker Hub 429 rate limiting,
    #     outage, offline): trust the curated table. verify_tag fails
    #     closed on unreachability, which is right for verification
    #     but fatal here: under sustained rate limiting every distro
    #     bump silently became "no upgrade available" and the exact
    #     images the experiment exists to remediate declined with all
    #     their CVEs in place. The table's entries are curated
    #     known-good tags; if one is genuinely wrong the build fails
    #     LOUDLY, which is an honest recorded failure rather than a
    #     silent decline.
    #
    # get_available_tags makes the distinction observable: an empty
    # list means the registry did not produce a listing, a non-empty
    # list is an authoritative answer we can test membership against.
    try:
        resolver = _get_resolver()
        if resolver:
            tags = resolver.get_available_tags(repo)
            if tags:
                if f"{target}{suffix}" in tags:
                    pass                              # verified present
                elif suffix and target in tags:
                    logger.debug(
                        "%s does not exist upstream; using %s:%s",
                        candidate, repo, target,
                    )
                    return f"{repo}:{target}", 0.75
                else:
                    logger.debug(
                        "distro bump %s not present upstream; skipping",
                        candidate,
                    )
                    return None
            else:
                logger.warning(
                    "Registry produced no tag listing for %r (rate limit "
                    "or outage); trusting the curated release table for "
                    "%s. A wrong entry will fail the build loudly.",
                    repo, candidate,
                )
    except Exception as e:
        logger.warning(
            "Could not verify %s against the registry (%s: %s); falling "
            "back to the pinned release table, which may be stale.",
            candidate, type(e).__name__, e,
        )

    return candidate, 0.80


# Official language-runtime image repositories. A final-stage candidate
# may only cross INTO this set when the original base is already in it:
# an SBOM-detected language is a property of the application copied onto
# a base, never a reason to replace a utility/distro base with a
# toolchain image. Observed damage before this guard: alpine/git:2.49.1
# (drone's clone stage, which bundles perl as a git dependency) was
# rewritten to perl:5.40-alpine, a tag that does not even exist.
_LANGUAGE_TOOLCHAIN_REPOS = {
    "python", "pypy", "golang", "node", "ruby", "php", "perl",
    "openjdk", "eclipse-temurin", "amazoncorretto", "ibm-semeru-runtimes",
    "rust", "erlang", "elixir", "julia", "haskell", "mono", "dart",
    "swift", "clojure", "groovy",
}


def _is_language_image_repo(ref: str) -> bool:
    """True if ``ref``'s repository is an official language-runtime
    image (python, golang, node, ...)."""
    if not ref:
        return False
    return _repo_of(ref).rsplit("/", 1)[-1].lower() in _LANGUAGE_TOOLCHAIN_REPOS


def _is_distroless(ref: str) -> bool:
    """True if ``ref`` names a distroless runtime base, e.g.
    ``gcr.io/distroless/base-debian12`` or ``.../static-debian11``.

    Distroless images are minimal runtime bases that host a copied
    application binary, so their SBOM shows the application's language
    exactly the way a bare distro's does. Like a distribution, they must
    be upgraded WITHIN their own family, never redirected to a language
    toolchain image."""
    return "distroless" in _repo_of(ref).lower()


# The current Debian release the distroless images track. A base below
# this is bumped up to it; at or above it there is nothing to do.
_DISTROLESS_CURRENT_DEBIAN = 12


def _distroless_same_family_bump(ref: str) -> Optional[Tuple[str, float]]:
    """Upgrade a distroless base within its own family, moving only the
    Debian release encoded in the repository leaf:
    ``gcr.io/distroless/base-debian11`` -> ``.../base-debian12``.

    The variant prefix (``base``, ``static``, ``cc``, ``python3``,
    ``nodejs20``, ``java17``, ...) and any explicit ``:tag`` are kept. A
    ``@sha256`` digest is dropped, because a digest names one specific
    older image and cannot carry across a release change. Returns None
    when the base is already current or carries no ``debianNN`` token, so
    the caller leaves it unchanged rather than crossing families.

    The registry is not consulted here: the target is always one of the
    handful of official ``gcr.io/distroless`` images for the current
    Debian release, which are known to exist, and the resolver's tag
    verification is Docker-Hub oriented and would false-negative on gcr.io.
    """
    repo = _repo_of(ref)
    namespace, _, leaf = repo.rpartition("/")
    m = re.search(r"(?i)debian(\d+)", leaf)
    if not m:
        return None
    if int(m.group(1)) >= _DISTROLESS_CURRENT_DEBIAN:
        return None
    new_leaf = (leaf[: m.start()] + f"debian{_DISTROLESS_CURRENT_DEBIAN}"
                + leaf[m.end():])
    new_repo = f"{namespace}/{new_leaf}" if namespace else new_leaf

    # Preserve an explicit tag (":nonroot", ":debug") but never a digest.
    ref_leaf = (ref or "").rsplit("/", 1)[-1]
    tag = ""
    if ":" in ref_leaf and "@" not in ref_leaf:
        tag = ":" + ref_leaf.split(":", 1)[1]
    return new_repo + tag, 0.80


def _conservative_same_image_bump(orig_base: str) -> Optional[Tuple[str, float]]:
    """C3 helper: produce a same-repo, same-variant tag bump for a non-final
    (builder) stage, or None if no safe bump applies.

    Non-final stages must never be patched from the final image's SBOM, and
    must never change OS family. This keeps the repository and any variant
    suffix (for example ``-alpine``, ``-bookworm``) identical and only moves
    an end-of-life language version forward to a supported one. When the
    version is already current, or the repo is not a recognised language
    image, it returns None and the caller leaves the stage untouched.

    Returns (new_base, confidence) on a real change, else None.
    """
    ref = orig_base.strip()
    # Only handle plain repo:tag forms. Digest-pinned refs are already
    # reproducible and namespaced/registry refs are left to the caller.
    if "@" in ref or "$" in ref or "{" in ref:
        return None
    if ":" not in ref:
        return None

    name_part = ref.split("/")[-1]
    repo = name_part.split(":")[0].lower()
    tag = name_part.split(":", 1)[1]

    language = _CONSERVATIVE_BUMP_REPOS.get(repo)
    if language is None:
        # Not a language image. It may still be an OS distribution
        # image, where the same-family upgrade is the only move a
        # builder stage (or a runtime stage whose cross-family
        # candidate was rejected by a guard) is allowed to make.
        # Without this, `debian:11` had no fallback at all and any
        # guard rejection turned into a zero-change run.
        return _distro_same_family_bump(repo, tag)

    current = _extract_version_from_tag(ref.lower(), language)
    if not current:
        return None

    upgraded = _upgrade_eol_version(language, current)
    if not upgraded or upgraded == current:
        return None

    # Preserve the rest of the tag (variant suffix) by replacing only the
    # first occurrence of the version substring.
    new_tag = tag.replace(current, upgraded, 1)
    if new_tag == tag:
        new_tag = upgraded
    new_base = f"{repo}:{new_tag}"
    if new_base == f"{repo}:{tag}":
        return None
    return new_base, 0.85


def resolve_stage_graph(
    stages: List[Dict[str, Any]],
    target: Optional[str] = None,
) -> Tuple[Set[int], Set[int], Dict[int, Optional[str]]]:
    """Resolve which stages ship, which are built at all, and their families.

    A multi-stage Dockerfile is a DAG, not a list, and three facts about
    it were previously approximated by ``idx == len(stages) - 1``:

    **Which stage ships.** ``docker build --target runtime`` stops at
    the named stage. A trailing ``FROM runtime AS debug`` stage, a very
    common layout, therefore made the real runtime stage "non-final",
    so it received only the conservative same-image tag bump reserved
    for builder stages. On a golang-builder + debian-runtime + debug
    file that produced ZERO changes: AutoPatch reported success and
    patched nothing.

    **Which stages are built.** BuildKit builds only the target stage
    and its transitive dependencies. A stage nobody references and that
    is not the target never runs, so rewriting it cannot reduce a single
    shipped CVE, while it can trip a compatibility guard and spend a
    build attempt.

    **What distribution each stage ends up on.** ``FROM builder`` has
    no image reference to infer from, so ``_infer_os_from_image``
    returned None and every family-keyed guard silently passed on that
    stage. The family is inherited along the alias chain instead.

    Args:
        stages: Stage records from :func:`parser.parse_dockerfile_stages`.
        target: Optional ``--target`` stage name or numeric index.

    Returns:
        ``(final_indices, live_indices, families)``.
        ``live_indices`` always contains ``final_indices``.
    """
    alias_to_idx: Dict[str, int] = {}
    for i, s in enumerate(stages):
        alias = (s.get("alias") or "").lower()
        if alias:
            alias_to_idx[alias] = i
        alias_to_idx.setdefault(str(i), i)   # numeric COPY --from=0

    # ── Which stage(s) ship ─────────────────────────────────────────
    final: Set[int] = set()
    if target:
        t = target.strip().lower()
        if t in alias_to_idx:
            final.add(alias_to_idx[t])
        else:
            logger.warning(
                "Build target %r matches no stage alias or index; falling "
                "back to the last stage. Stage aliases present: %s",
                target, sorted(a for a in alias_to_idx if not a.isdigit()),
            )
    if not final and stages:
        final.add(len(stages) - 1)

    # ── Dependency edges: FROM <alias> and COPY --from=<alias> ──────
    deps: Dict[int, Set[int]] = {}
    for i, s in enumerate(stages):
        d: Set[int] = set()
        if s.get("is_stage_alias"):
            parent = alias_to_idx.get(str(s.get("base_image", "")).lower())
            if parent is not None and parent != i:
                d.add(parent)
        for ref in s.get("copy_from_refs") or set():
            # A ref that is not a known alias is an EXTERNAL image
            # (COPY --from=nginx:1.25), not a stage. It creates no
            # intra-file edge; the libc guard handles it separately.
            parent = alias_to_idx.get(str(ref).lower())
            if parent is not None and parent != i:
                d.add(parent)
        deps[i] = d

    # ── Reachability from the shipping stage(s) ─────────────────────
    live: Set[int] = set()
    frontier = list(final)
    while frontier:
        cur = frontier.pop()
        if cur in live:
            continue
        live.add(cur)
        frontier.extend(deps.get(cur, ()))

    # ── Family per stage, inherited along alias chains ──────────────
    families: Dict[int, Optional[str]] = {}

    def _family(i: int, seen: Optional[Set[int]] = None) -> Optional[str]:
        if i in families:
            return families[i]
        seen = seen or set()
        if i in seen:              # cyclic FROM: malformed, do not hang
            return None
        seen.add(i)
        s = stages[i]
        if s.get("is_scratch"):
            fam = "scratch"
        elif s.get("is_stage_alias"):
            parent = alias_to_idx.get(str(s.get("base_image", "")).lower())
            fam = _family(parent, seen) if parent is not None else None
        else:
            fam = _infer_os_from_image(s.get("base_name", "") or "")
        families[i] = fam
        return fam

    for i in range(len(stages)):
        _family(i)

    return final, live, families


def patch_dockerfile(
    dockerfile_text: str,
    sbom_before: Optional[Dict[str, Any]] = None,
    base_mapping: Optional[Dict[str, str]] = None,
    patch_final_only: bool = False,
    dry_run: bool = False,
    enable_smoke_test: bool = False,
    target: Optional[str] = None,
    ai_candidate: Optional[Tuple[str, float]] = None,
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

    # The FINAL stage's base tag is authoritative for the primary runtime when
    # it is a language image (golang/node/rust/...), because the toolchain is
    # binary-installed and absent from the SBOM. Deriving an override here stops
    # the SBOM misclassifying such images as an incidental system dep (python).
    # For OS/app bases and stage aliases this returns None, so SBOM inference is
    # left in charge (e.g. debian + pip install really is python).
    # Resolve the build DAG before anything reads "the final stage".
    _final_idxs, _live_idxs, _families_after = resolve_stage_graph(
        stages, target=target
    )
    # The shipping stage, not the last line in the file. With
    # `--target runtime` followed by a debug stage, stages[-1] is the
    # debug stage and its base tag would drive language inference for
    # an image that never ships.
    _ship_idx = min(_final_idxs) if _final_idxs else len(stages) - 1
    _final_base = stages[_ship_idx].get('base_image', '') if stages else ''
    _lang_ovr, _lang_ver_ovr = _language_from_base_image(_final_base)
    if _lang_ovr:
        logger.info(
            f"Primary runtime from base tag: {_lang_ovr}:{_lang_ver_ovr} "
            f"(base={_final_base}); overriding SBOM language inference"
        )

    # Run full SBOM inference once
    inference = analyze_sbom(
        sbom_before,
        language_override=_lang_ovr,
        language_version_override=_lang_ver_ovr,
    )
    # Preserve the build-relevant variant from the base tag, which is
    # authoritative. _detect_variant misses it when the scanned image name
    # dropped the suffix (e.g. "php-orig-<hash>" loses "-apache"). php apache/
    # fpm images carry apache2 / php-fpm binaries and RUN steps (a2enmod,
    # apache2-foreground) absent from the cli image, so losing the variant
    # breaks the build.
    _fb_low = _final_base.lower()
    if "-apache" in _fb_low:
        inference.variant = "apache"
    elif "-fpm" in _fb_low:
        inference.variant = "fpm"
    elif "jdk" in _fb_low and "jre" not in _fb_low:
        # Explicit JDK base (e.g. adoptopenjdk:11-jdk, openjdk:17-jdk): keep a
        # JDK so javac/maven/gradle build steps survive the rewrite.
        inference.variant = "jdk"

    # RHEL-family / non-Debian OS bases ship python/perl as SYSTEM packages,
    # which the SBOM language detector mistakes for the app runtime and then
    # rewrites the image onto a Debian python base with no dnf/yum/zypper —
    # breaking "RUN dnf install". For a pure OS base, the OS family (not an
    # incidental system interpreter) must drive the rewrite, so clear the
    # spurious language and let the os_family path pick a same-family image.
    _base_repo = _final_base.split("@")[0].split(":")[0].lower().rsplit("/", 1)[-1]
    _OS_FAMILY_IMAGES = {
        "almalinux", "rockylinux", "centos", "rhel", "redhat", "fedora",
        "amazonlinux", "oraclelinux", "opensuse", "photon",
    }
    if _base_repo in _OS_FAMILY_IMAGES and not _lang_ovr:
        inference.language = None
        inference.language_version = None

    logger.info(
        f"SBOM inference: OS={inference.os_family}, "
        f"lang={inference.language}:{inference.language_version}, "
        f"glibc={inference.needs_glibc}, confidence={inference.confidence:.2f}"
    )
    for signal in inference.signals:
        logger.debug(f"  signal: {signal}")

    # Everything above the first FROM (syntax directives, global ARG
    # declarations, licence headers) is global state the rewriter must
    # carry through. Reconstructing the file from stages alone drops
    # it, which in particular deletes the very ARG that a
    # "FROM ${BASE_IMAGE}" line resolves against.
    patched_lines = list(extract_preamble(dockerfile_text))
    base_changes = []
    warnings = list(inference.warnings)  # Start with any inference warnings

    # Distribution family per stage, as the rewritten file will be
    # built. Seeded from the original bases and updated as each stage
    # is decided, so a cross-stage guard evaluates the graph that will
    # actually exist rather than a mix of old and new.
    # _final_idxs / _live_idxs / _families_after were resolved from the
    # build DAG above. See resolve_stage_graph for why a positional
    # `idx == len(stages) - 1` was wrong on all three counts.
    if len(stages) > 1:
        logger.info(
            "Stage graph: %d stages, shipping=%s, built=%s, families=%s",
            len(stages),
            sorted(_final_idxs), sorted(_live_idxs),
            {i: f for i, f in sorted(_families_after.items())},
        )
        _dead = sorted(set(range(len(stages))) - _live_idxs)
        if _dead:
            warnings.append(
                "Stages " + ", ".join(
                    f"{i} ('{stages[i].get('alias') or i}')" for i in _dead
                ) + " are not reachable from the stage that ships and are "
                "never built by BuildKit; they were left unchanged. "
                "Patching them cannot remove a shipped CVE."
            )

    for idx, stage in enumerate(stages):
        is_final = idx in _final_idxs

        # Skip intermediate stages if patch_final_only
        if patch_final_only and not is_final:
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Skip stages BuildKit will never build. Rewriting them cannot
        # reduce a shipped vulnerability, and a needless rewrite can
        # trip a compatibility guard or burn a build attempt.
        if idx not in _live_idxs:
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
        # True when the candidate came from --base-mapping. An explicit
        # operator choice is never silently replaced with one of ours.
        _operator_chose = False

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
            # User override — highest priority, full confidence. Applies to
            # any stage because it is an explicit operator decision.
            new_base = base_mapping.get(orig_base, base_mapping.get(stage['base_name']))
            selection_confidence = 1.0
            _operator_chose = True
        elif not is_final:
            # C3 fix: non-final (builder) stages are patched conservatively
            # with a same-image tag bump only. The single SBOM inference was
            # computed from the FINAL image and does not describe a builder
            # stage's toolchain, so using it to choose a cross-family base
            # here patches the wrong stage with the wrong evidence. We never
            # change the repo or OS family of a non-final external stage; we
            # only move it to a newer tag of the same image. If no safe bump
            # exists, the stage is left untouched.
            bump = _conservative_same_image_bump(orig_base)
            if bump is None:
                warnings.append(
                    f"Stage {idx}: non-final stage '{orig_base}' left "
                    f"unchanged (conservative policy: builder stages get "
                    f"same-image tag bumps only; no newer same-family tag "
                    f"was identified). Use --base-mapping to override."
                )
                patched_lines.append(stage['from_line'])
                patched_lines.extend(stage['lines'])
                continue
            new_base, selection_confidence = bump
        else:
            # Final stage: candidate selection.
            #
            # Two selectors can fill this slot. The deterministic
            # registry-driven selector is the default; an AI-proposed
            # candidate (arm B of the selection experiment) replaces
            # ONLY this line when supplied. Everything after this
            # point, the allow-list gate, the compatibility guards, the
            # glibc floor, the same-family fallback, the build, the
            # scan and the acceptance criterion, is byte-for-byte
            # identical for both, and _operator_chose stays False so an
            # AI proposal enjoys no operator trust. That is the entire
            # experimental design: vary the proposer, hold the
            # verification constant.
            if ai_candidate is not None:
                new_base, selection_confidence = ai_candidate
                warnings.append(
                    f"Stage {idx}: candidate '{new_base}' proposed by the "
                    f"AI selector (confidence {selection_confidence:.2f}); "
                    f"subject to the same verification as any inferred "
                    f"candidate"
                )
            else:
                new_base, selection_confidence = choose_base_image(
                    inference, original_base=orig_base
                )
            # Language-image guard: never redirect a base that is not
            # itself a language image onto a language toolchain image.
            # Applies to the deterministic selector AND arm B proposals
            # (operator --base-mapping is exempt: explicit choice).
            if (new_base and new_base != orig_base
                    and _is_language_image_repo(new_base)
                    and not _is_language_image_repo(orig_base)):
                _lang_fallback = _conservative_same_image_bump(orig_base)
                if _lang_fallback:
                    warnings.append(
                        f"Stage {idx}: candidate '{new_base}' is a language "
                        f"toolchain image but '{orig_base}' is not; using "
                        f"same-image bump '{_lang_fallback[0]}' instead"
                    )
                    new_base, selection_confidence = _lang_fallback
                else:
                    warnings.append(
                        f"Stage {idx}: candidate '{new_base}' is a language "
                        f"toolchain image but '{orig_base}' is not; no safe "
                        f"same-image bump found, leaving base unchanged"
                    )
                    new_base, selection_confidence = orig_base, 0.0

            # Gate cross-repository migrations on the mechanically
            # verified allow-list. Until now the loader was written,
            # tested, and never called, so an unlisted repository could
            # be substituted into a Dockerfile with nothing checking it.
            new_base, _al_note = apply_allowlist_gate(
                orig_base, new_base, inference
            )
            if _al_note:
                warnings.append(f"Stage {idx}: {_al_note}")

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

        # ── Pre-flight compatibility guards ─────────────────────────
        # A candidate that trips a blocking guard would fail the build
        # (or, worse, build and then break at exec). Detecting that
        # here costs milliseconds; detecting it by attempting the
        # build costs the full build timeout and consumes one of the
        # two candidate attempts.
        _from_family = _infer_os_from_image(orig_base)
        _to_family = _infer_os_from_image(new_base)
        if _from_family and _to_family and _from_family != _to_family:
            try:
                from .compat_guards import (
                    evaluate_candidate as _guard_eval,
                    normalize_family as _norm_family,
                )
                # Guards see only THIS stage's commands. Passing the
                # whole file made an `apt-key` in a builder stage block
                # the rewrite of an unrelated runtime stage, which
                # suppresses exactly the substitutions the pipeline
                # exists to make.
                _stage_text = "\n".join(
                    [stage['from_line']] + list(stage.get('lines') or [])
                )
                # Reflect decisions already taken this pass rather than
                # the original families, so the libc guard reasons over
                # the graph as it will actually be built. `_families_after`
                # is seeded before the loop and updated as each stage is
                # decided.
                _fam_view = dict(_families_after)
                _fam_view[idx] = _to_family
                _guard = _guard_eval(
                    _stage_text, _from_family, _to_family,
                    stages=stages,
                    stage_family_after=_fam_view,
                )
                warnings.extend(_guard.warnings)
                if _guard.blocked:
                    for reason in _guard.blocking_reasons:
                        warnings.append(f"Stage {idx}: {reason}")

                    # Before abandoning the stage, retry WITHIN the
                    # original distribution family.
                    #
                    # Almost every guard that fires is a CROSS-family
                    # objection: musl cannot run the builder's glibc
                    # binaries, apt-key does not exist on the target,
                    # a version pin will not resolve. None of those
                    # objects to a newer release of the SAME family,
                    # and that upgrade still removes real CVEs. Giving
                    # up outright turned "this particular candidate is
                    # unsafe" into "this Dockerfile gets no patch at
                    # all", which on a golang-builder plus
                    # debian-runtime file meant a zero-change run.
                    # ...but never in place of an explicit operator
                    # choice. If --base-mapping named alpine:3.19 and a
                    # guard rejects it, substituting debian:12 would
                    # ship an image the operator never asked for and
                    # did not review. Report the rejection and stop.
                    _fallback = (None if _operator_chose
                                 else _conservative_same_image_bump(orig_base))
                    _fb_ok = False
                    if _fallback:
                        _fb_base, _fb_conf = _fallback
                        _fb_family = _infer_os_from_image(_fb_base)
                        _fb_view = dict(_families_after)
                        _fb_view[idx] = _fb_family
                        _fb_report = _guard_eval(
                            _stage_text, _from_family, _fb_family or _from_family,
                            stages=stages, stage_family_after=_fb_view,
                        )
                        if not _fb_report.blocked:
                            warnings.append(
                                f"Stage {idx}: candidate '{new_base}' failed "
                                f"pre-flight guards; fell back to the "
                                f"same-family upgrade '{_fb_base}'"
                            )
                            new_base = _fb_base
                            selection_confidence = _fb_conf
                            _to_family = _fb_family
                            _families_after[idx] = _fb_family
                            warnings.extend(_fb_report.warnings)
                            _fb_ok = True

                    if not _fb_ok:
                        # Keep the original base rather than emitting a
                        # Dockerfile we already know cannot work.
                        warnings.append(
                            f"Stage {idx}: keeping '{orig_base}' because the "
                            f"operator-specified '{new_base}' fails pre-flight "
                            f"compatibility guards"
                            if _operator_chose else
                            f"Stage {idx}: keeping '{orig_base}' because the "
                            f"candidate '{new_base}' fails pre-flight "
                            f"compatibility guards and no same-family "
                            f"upgrade was available"
                        )
                        # The stage keeps its original family; leave
                        # _families_after[idx] as seeded.
                        patched_lines.append(stage['from_line'])
                        patched_lines.extend(stage['lines'])
                        continue
                # Guard cleared: this stage will be built on the new
                # family, so later stages must see that.
                _families_after[idx] = _to_family
            except ImportError as e:
                # The guards module is part of the package; if it cannot
                # be imported something is wrong with the install, and
                # proceeding means rewriting Dockerfiles with no
                # compatibility checking at all.
                warnings.append(
                    f"Stage {idx}: compatibility guards unavailable ({e}); "
                    f"the substitution to '{new_base}' was NOT checked for "
                    f"distro-locked commands, libc boundaries or shell "
                    f"dialect"
                )
                logger.warning("compat guards unavailable: %s", e)
            except Exception as e:
                # A crash in a guard is not a passing guard. It was
                # logged at DEBUG and the rewrite proceeded, so a defect
                # in the guard silently converted a checked pipeline
                # into an unchecked one, invisibly at default verbosity.
                warnings.append(
                    f"Stage {idx}: compatibility guards FAILED to evaluate "
                    f"({type(e).__name__}: {e}); '{new_base}' is unchecked"
                )
                logger.warning(
                    "compat guards crashed for stage %d (%s: %s); the "
                    "candidate is unchecked", idx, type(e).__name__, e,
                )

        # Precise glibc-floor check against the candidate base.
        #
        # This guard was unreachable. It read
        # `getattr(inference, "min_glibc", None)`, and the comment
        # claimed main.py set that field "when --check-glibc was
        # supplied" -- but no --check-glibc flag ever existed and
        # nothing anywhere assigned min_glibc, so the condition was
        # always falsy and `detect_min_glibc_from_image` had no
        # callers. main.py now populates `inference.min_glibc` from
        # the original image before patching (see the GLIBC FLOOR block
        # there), which makes this fire.
        #
        # The old handler was also `except Exception: pass`, so a raise
        # inside base_satisfies_requirement dropped the warning
        # entirely: the opposite of the fail-closed behaviour the
        # docstring promises. It now reports the failure.
        _min_glibc = getattr(inference, "min_glibc", None)
        if _min_glibc:
            try:
                from .glibc_detector import (
                    GlibcRequirement,
                    base_satisfies_requirement,
                )
                _req = GlibcRequirement(
                    versions=(_min_glibc,),
                    minimum_required=_min_glibc,
                )
                _satisfies = base_satisfies_requirement(new_base, _req)
            except Exception as e:
                # Fail closed: an unevaluated floor is not a satisfied
                # floor. Say so rather than swallowing it.
                logger.warning(
                    "glibc floor check failed for %s (%s: %s); treating the "
                    "floor as UNSATISFIED", new_base, type(e).__name__, e,
                )
                _satisfies = False
            if not _satisfies:
                warnings.append(
                    f"Stage {idx}: workload requires glibc>={_min_glibc} "
                    f"but candidate base '{new_base}' does not satisfy "
                    f"that floor (or is unknown). Build will likely fail "
                    f"with 'version GLIBC_{_min_glibc} not found' at "
                    f"runtime."
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
