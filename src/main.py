"""
LimenSec / AutoPatch CLI orchestrator.

INTENDED MODULE SPLIT (Phase 2 tech-debt follow-up)
====================================================
This file currently houses three responsibilities that should live in
their own modules:

  * ``cli.py``           -- argparse definition and dispatch
                            (build_argparser, main, run_pipeline).
  * ``pipeline.py``      -- the phase orchestrator (build, scan, infer,
                            patch, rebuild, gate, sign).
  * ``reports/``         -- _generate_json_report, _generate_markdown_report,
                            _generate_html_report and any shared report
                            data classes.

The split is structural cleanup, not functional change. Each report
generator already takes a flat dict of fields and emits a string, so
extracting them is a copy-paste plus an import. The orchestrator
similarly has clean phase boundaries marked by ``step.set_phase("...")``
calls; each phase could become a function in pipeline.py.

Why this hasn't happened yet: a single-shot split of a 2k-line file
is high-risk for a project with the file-corruption history this
repo has. The split should be done over multiple PRs:
  1. Extract reports/ first (no orchestration state involved).
  2. Extract the build/scan/sign phases as plain functions.
  3. Reduce main.py to thin argparse + dispatch.

Until then, treat this file as authoritative for orchestration logic.
"""

import argparse
import html
import logging
import json
import os
import re
import sys
import tempfile
import time
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Tuple, List

# Configure the logger (console output format)
logger = logging.getLogger("docker_patch_tool")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Import functions from other modules
from .utils import (
    run_cmd, load_base_mapping, load_json, save_json, save_csv,
    generate_diff, compute_reduction_percentage, format_reduction_percentage
)
from .parser import parse_dockerfile_stages
from .builder import (
    build_image, tag_image, push_image, get_image_digest,
    measure_image_size, remove_image,
)
from .scanner import (
    scan_image, scan_image_detailed, generate_sbom, summarize_vulnerabilities,
    ScanError, NetworkError, DBUpdateError, ScanExecutionError
)
from .patcher import patch_dockerfile, analyze_sbom, smoke_test_image, migrate_package_commands
from .signer import (
    sign_image, verify_image, generate_attestation, attach_sbom, get_signing_log,
    SigningError, KeyGenerationError, VerificationError
)
from .comparer import (
    diff_vulnerabilities, diff_sbom, compute_metrics, check_acceptance_criteria
)

# Optional imports for new modules (graceful degradation if not available)
try:
    from .dep_graph import (
        build_dependency_graph, get_vulnerability_reachability,
        extract_embedded_vulnerabilities, merge_embedded_with_scan,
        summarize_graph,
    )
except ImportError:
    build_dependency_graph = None

try:
    from .inplace_patcher import generate_inplace_patch, save_inplace_patch
except ImportError:
    generate_inplace_patch = None

try:
    from .vex_generator import apply_vex_suppression
except ImportError:
    apply_vex_suppression = None

try:
    from .supply_chain_scanner import scan_supply_chain, SupplyChainResult
except ImportError:
    scan_supply_chain = None
    SupplyChainResult = None

try:
    from .network_monitor import analyze_network_behavior, NetworkAnalysisResult
except ImportError:
    analyze_network_behavior = None
    NetworkAnalysisResult = None

try:
    from .threat_intel import update_feeds as update_threat_feeds
except ImportError:
    update_threat_feeds = None


@dataclass
class PatchStrategy:
    """A patching strategy to attempt."""
    name: str
    description: str
    patch_kwargs: dict  # kwargs to pass to patch_dockerfile


def _evidence_snapshot(epss_path: Optional[str], kev_path: Optional[str]) -> Dict[str, Optional[str]]:
    """Capture file mtimes / version metadata so the attestation
    records WHICH EPSS data and KEV catalog the gate ran against.
    Same gate inputs + same scan = same decision; this lets a future
    auditor reproduce the call."""
    snap: Dict[str, Optional[str]] = {
        "epss_path": None, "epss_mtime": None,
        "kev_path": None, "kev_mtime": None, "kev_catalog_version": None,
        "trivy_db_version": None,
    }
    from datetime import datetime, timezone
    def _mtime(p: Optional[str]) -> Optional[str]:
        if not p:
            return None
        try:
            ts = os.path.getmtime(p)
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except OSError:
            return None
    snap["epss_path"] = epss_path
    snap["epss_mtime"] = _mtime(epss_path)
    snap["kev_path"] = kev_path
    snap["kev_mtime"] = _mtime(kev_path)
    # KEV JSON catalogs carry a catalogVersion field; sniff it.
    if kev_path and os.path.isfile(kev_path):
        try:
            with open(kev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                snap["kev_catalog_version"] = str(
                    data.get("catalogVersion") or data.get("version") or ""
                ) or None
        except Exception as e:
            # The evidence snapshot exists so a reader can tell which KEV
            # catalog a verdict was made against. Recording the version as
            # absent is indistinguishable from a catalog that has no
            # version field, so a corrupt or truncated file looked the
            # same as a fine one.
            snap["kev_catalog_version"] = None
            snap["kev_catalog_error"] = f"{type(e).__name__}: {e}"
            logger.warning(
                "Could not read the KEV catalog version from %s (%s: %s); "
                "the evidence snapshot cannot pin which catalog this run "
                "used.", kev_path, type(e).__name__, e,
            )
    return snap


def _load_epss_file(path: Optional[str]) -> Optional[Dict[str, float]]:
    """Load a JSON file mapping CVE IDs to EPSS scores. Returns None if
    no path is given. Skips entries that aren't valid (CVE_ID -> float)."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Could not load EPSS file {path}: {type(e).__name__}: {e}")
        return None

    # Accept either {cve_id: score} or [{cve: id, epss: score}, ...]
    out: Dict[str, float] = {}
    if isinstance(data, dict):
        for cve, score in data.items():
            try:
                out[cve] = float(score)
            except (TypeError, ValueError):
                continue
    elif isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            cve = entry.get("cve") or entry.get("cve_id") or entry.get("CVE")
            score = entry.get("epss") or entry.get("epss_score")
            if cve is None or score is None:
                continue
            try:
                out[cve] = float(score)
            except (TypeError, ValueError):
                continue
    logger.info(f"Loaded {len(out)} EPSS entries from {path}")
    return out


def _load_kev_file(path: Optional[str]) -> Optional[set]:
    """Load a CISA KEV catalog file into a set of CVE IDs. Accepts
    either a plain JSON array of CVE IDs or the official
    {'vulnerabilities':[{cveID:...}]} schema."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Could not load KEV file {path}: {type(e).__name__}: {e}")
        return None

    kev: set = set()
    if isinstance(data, list):
        kev = {str(x) for x in data if x}
    elif isinstance(data, dict):
        for entry in data.get("vulnerabilities", []):
            cid = (entry.get("cveID") if isinstance(entry, dict) else None) or \
                  (entry.get("cve_id") if isinstance(entry, dict) else None)
            if cid:
                kev.add(str(cid))
    logger.info(f"Loaded {len(kev)} KEV CVE IDs from {path}")
    return kev


def _verify_across_platforms(
    *,
    platforms_spec: str,
    patched_dockerfile_path: str,
    build_context_path: Optional[str],
    output_dir: str,
    image_prefix: str,
    target: Optional[str],
    before_scan: Dict[str, Any],
    accept_kwargs: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Build, scan and gate the patched Dockerfile on every platform.

    Why this is not optional cosmetics: AutoPatch verifies a base
    substitution by building and scanning ONE image, on whatever
    architecture the runner happens to be. That result does not
    transfer. ``rockylinux:9`` publishes arm64; several of the images
    in the corpus do not. Package sets and their CVE exposure differ
    per architecture, and a tag that exists for amd64 can 404 for
    arm64, which turns a verified remediation into a broken build for
    half the fleet.

    ``multiarch.py`` implemented the parsing, aggregation and manifest
    plumbing for this and was never called from anywhere, so the
    multi-architecture capability existed only as a tested module.

    Returns the summary dict, or None when the platform set could not
    be honoured (buildx absent), so the caller can distinguish "not
    checked" from "checked and passed".
    """
    from .multiarch import (
        PlatformResult, aggregate_results, ensure_buildx_available,
        parse_platforms, summarise,
    )

    platforms = parse_platforms(platforms_spec)   # raises on malformed input
    if not ensure_buildx_available():
        logger.error(
            "--platforms %s requested but 'docker buildx' is unavailable. "
            "Refusing to claim multi-architecture verification that did "
            "not happen.", platforms_spec,
        )
        return None

    results = []
    for plat in platforms:
        tag = f"{image_prefix}-{plat.replace('/', '-')}"
        pr = PlatformResult(platform=plat)
        try:
            ok, err_cat, _ = build_image(
                tag, patched_dockerfile_path,
                build_context_path=build_context_path,
                target=target,
                platform=plat,
            )
            if not ok:
                pr.error = f"build failed ({err_cat})"
                results.append(pr)
                logger.warning("[%s] %s", plat, pr.error)
                continue

            plat_scan = scan_image(
                tag,
                os.path.join(output_dir,
                             f"trivy-after-{plat.replace('/', '-')}.json"),
                skip_db_update=True,
            )
            # The SAME acceptance criterion as the primary platform.
            # A weaker gate here would let a regression ship on arm64
            # under cover of an amd64 pass.
            accepted, reasons = check_acceptance_criteria(
                before_scan, plat_scan, **accept_kwargs)
            pr.accepted = accepted
            pr.reasons = list(reasons)
            pr.image_digest = get_image_digest(tag) or ""
            logger.info(
                "[%s] %s%s", plat, "ACCEPTED" if accepted else "REJECTED",
                "" if accepted else f": {'; '.join(reasons[:2])}",
            )
        except Exception as e:
            pr.error = f"{type(e).__name__}: {e}"
            logger.warning("[%s] verification error: %s", plat, pr.error)
        finally:
            remove_image(tag, force=True)
        results.append(pr)

    outcome = aggregate_results(results)
    summary = summarise(outcome)
    save_json(summary, os.path.join(output_dir, "multiarch.json"))
    if not outcome.all_accepted:
        failed = outcome.first_failure
        logger.warning(
            "Multi-architecture verification FAILED on %s (%s). The "
            "substitution is not safe to publish as a manifest list.",
            failed.platform, failed.error or "; ".join(failed.reasons[:2]),
        )
    return summary


def _scan_possibly_fused(
    image: str,
    trivy_output_path: str,
    *,
    output_dir: str,
    phase: str,
    dual: bool,
    skip_db_update: bool = False,
) -> Dict[str, Any]:
    """Scan ``image`` with Trivy, and with Grype as well when ``dual``.

    Returns a Trivy-shaped scan dict either way, so every downstream
    consumer (comparer, acceptance gate, VEX, reports) is unchanged.

    Why this exists: ``--dual-scanner`` previously did nothing but add
    "grype" to the list of binaries whose checksum was verified. Grype
    was never invoked, ``scanner_fusion`` was never called, and the run
    reported single-scanner results while the flag claimed otherwise.

    Fusion is a UNION of the two finding sets, classified CONFIRMED
    (both scanners agree) or CONTESTED (one scanner only). A union is
    the right default for a remediation gate: a CVE that only Grype
    sees is still a CVE the gate should refuse to ignore, and the
    classification is preserved on each row so a reviewer can weigh
    single-scanner findings differently.

    Failure policy: if Grype fails on ONE side of a before/after pair we
    must not fall back to Trivy-only for that side, because the delta
    would then be taken between two differently-constructed finding
    sets. The exception propagates and the caller aborts.
    """
    trivy_scan = scan_image(image, trivy_output_path, skip_db_update=skip_db_update)
    if not dual:
        return trivy_scan

    from .grype_scanner import scan_image as grype_scan_image
    from .scanner_fusion import fuse_scan_results, fusion_to_trivy_format

    grype_path = os.path.join(output_dir, f"grype-{phase}.json")
    grype_scan = grype_scan_image(image, grype_path, skip_db_update=skip_db_update)

    # EPSS/KEV are deliberately not passed here. They only reorder
    # findings by composite priority; they do not change membership of
    # the set. Risk scoring stays in the acceptance gate, which already
    # loads them, so the scan stage has exactly one responsibility.
    fusion = fuse_scan_results(trivy_scan, grype_scan)
    logger.info(
        "Fused %s scan of %s: %d unique CVEs (%d confirmed by both "
        "scanners, %d contested by one)",
        phase, image, fusion.total_unique_cves,
        fusion.confirmed_count, fusion.contested_count,
    )
    fused = fusion_to_trivy_format(fusion)
    save_json(fused, os.path.join(output_dir, f"fused-{phase}.json"))
    return fused


def _generate_fallback_strategies(
    original_dockerfile: str,
    sbom_before: dict,
    base_mapping: Optional[dict],
    patch_final_only: bool,
) -> list:
    """
    Generate a ranked list of patching strategies to try.

    If the primary strategy fails (e.g., Alpine build fails due to glibc),
    we try progressively safer alternatives.

    Strategy order:
    1. Primary: Full SBOM-driven patch (default behavior)
    2. Slim fallback: Force -slim variants instead of Alpine
    3. Same-OS upgrade: Stay on same OS family, just upgrade version
    """
    strategies = []

    # Strategy 1: Primary (default SBOM-driven)
    strategies.append(PatchStrategy(
        name="primary",
        description="SBOM-driven base image replacement",
        patch_kwargs={
            "sbom_before": sbom_before,
            "base_mapping": base_mapping,
            "patch_final_only": patch_final_only,
        }
    ))

    # Strategy 2: Force slim (no Alpine) via a base_mapping override
    # If the primary chose Alpine and it failed, try slim-bookworm variants
    slim_mapping = base_mapping.copy() if base_mapping else {}
    # We'll populate this dynamically after the first failure
    strategies.append(PatchStrategy(
        name="slim_fallback",
        description="Force slim Debian variants (avoid Alpine/musl)",
        patch_kwargs={
            "sbom_before": sbom_before,
            "base_mapping": slim_mapping,
            "patch_final_only": patch_final_only,
        }
    ))

    return strategies


class StepCounter:
    """Simple step counter for descriptive phase names."""
    def __init__(self):
        self.phase = None

    def set_phase(self, phase_name: str):
        self.phase = phase_name

    def log(self, message: str):
        if self.phase:
            return f"[{self.phase}] {message}"
        return message


@dataclass
class CascadeOutcome:
    """Result of a cascade attempt: which strategy won (or none), what
    the post-patch state looks like, and any feedback collected along
    the way. Returned by :func:`_run_cascade` so the caller can decide
    whether to publish/sign the patched image."""
    accepted: bool = False
    strategy: Optional[str] = None
    dockerfile_path: Optional[str] = None
    image_tag: Optional[str] = None
    after_scan: Optional[Dict[str, Any]] = None
    sbom_after: Optional[Dict[str, Any]] = None
    feedback: List[str] = field(default_factory=list)
    # Best-of selection metadata: the winner's selection key
    # (applicable, fixable-os, raw), its applicable total, and its
    # measured build time, so the caller can compare against an
    # incumbent and report honest metrics.
    applicable_after: Optional[int] = None
    selection_key: Optional[Tuple[int, int, int]] = None
    build_time: Optional[float] = None


def _slim_variant_of(ref: str) -> Optional[str]:
    """'-slim' variant of an image ref, when the repository publishes
    one and the tag is not already a slim/alpine variant. Digest-pinned
    refs are not eligible: appending '-slim' to a '@sha256:...' tag
    would fabricate a nonexistent reference."""
    if "@" in (ref or ""):
        return None
    repo, _, tag = (ref or "").partition(":")
    leaf = repo.rsplit("/", 1)[-1].lower()
    if leaf not in {"python", "node", "debian", "ruby", "perl", "openjdk"}:
        return None
    if not tag or "slim" in tag or "alpine" in tag:
        return None
    return f"{repo}:{tag}-slim"


# Wolfi/Chainguard equivalents by runtime. glibc-based, daily-rebuilt
# minimal images; candidates only, and only through the cascade, where
# each one must independently pass build + scan + the acceptance gate.
_WOLFI_EQUIVALENT = {
    "python": "cgr.dev/chainguard/python:latest",
    "node": "cgr.dev/chainguard/node:latest",
    "ruby": "cgr.dev/chainguard/ruby:latest",
    "golang": "cgr.dev/chainguard/go:latest",
    "php": "cgr.dev/chainguard/php:latest",
    "openjdk": "cgr.dev/chainguard/jdk:latest",
    "eclipse-temurin": "cgr.dev/chainguard/jdk:latest",
    "debian": "cgr.dev/chainguard/wolfi-base:latest",
    "ubuntu": "cgr.dev/chainguard/wolfi-base:latest",
    "alpine": "cgr.dev/chainguard/wolfi-base:latest",
}


def _wolfi_equivalent_of(ref: str) -> Optional[str]:
    leaf = (ref or "").partition(":")[0].rsplit("/", 1)[-1].lower()
    return _WOLFI_EQUIVALENT.get(leaf)


def _latest_equivalent_of(ref: str) -> Optional[str]:
    """Same-repository ':latest' candidate, pinned by manifest digest.

    A conservative in-family bump can land on an intermediate release
    whose newer sibling has already fixed hundreds of findings (the
    golang:onbuild -> golang:1.23-bookworm case). This candidate brings
    the newest-tag move into the ranked pool without either failure
    mode of naive ':latest' replacement: the reference is digest-pinned
    at selection time, and the result must still pass the acceptance
    gate. Returns None when the digest cannot be resolved; an unpinned
    ':latest' is never emitted.
    """
    if not ref or "@" in ref:
        return None
    repo, _, tag = ref.partition(":")
    if not repo or tag in ("", "latest"):
        return None
    if repo.startswith("cgr.dev/") or "distroless" in repo:
        return None
    if repo.rsplit("/", 1)[-1].lower() == "scratch":
        return None
    try:
        from .builder import _remote_manifest_digest
        digest = _remote_manifest_digest(f"{repo}:latest")
    except Exception:
        return None
    if not digest:
        return None
    return f"{repo}:latest@{digest}"


def _fixable_os_total(scan: Optional[Dict[str, Any]]) -> Optional[int]:
    """OS-layer findings with a released fix, kernel-space included.
    Second-level selection key: at equal applicable totals, the
    candidate leaving fewer fixable OS findings is strictly better
    even when the gate (which excludes kernel-space) cannot see it."""
    if scan is None:
        return None
    try:
        n = 0
        for res in (scan.get("Results") or []):
            if (res.get("Class") or "") != "os-pkgs":
                continue
            for v in (res.get("Vulnerabilities") or []):
                if (v.get("FixedVersion") or "").strip():
                    n += 1
        return n
    except Exception:
        return None


def _selection_key(scan: Optional[Dict[str, Any]], policy,
                   kev_set=None) -> Optional[Tuple[int, int, int]]:
    """Ranking key for gate-passing candidates: (applicable total,
    remaining fixable OS findings, raw total), lexicographic, lower is
    better. The first component preserves gate semantics; the second
    and third only break ties, so a candidate can never displace one
    that is better on the applicable set."""
    if scan is None:
        return None
    app = _applicable_total(scan, policy, kev_set=kev_set)
    if app is None:
        return None
    fix = _fixable_os_total(scan)
    try:
        from . import vulnerability_index as _vix
        raw = len(_vix.extract_records(scan))
    except Exception:
        raw = 0
    return (app, fix if fix is not None else 0, raw)


def _applicable_total(scan: Optional[Dict[str, Any]], policy,
                      kev_set=None) -> Optional[int]:
    """Size of the applicable finding set the gate reasons about, or
    None when it cannot be computed. Used to compare gate-passing
    candidates: acceptance is boolean, so ranking passers needs the
    same applicability partition the gate itself uses. An empty scan
    is a real result (zero findings); only a missing scan is None."""
    if scan is None:
        return None
    try:
        from . import vulnerability_index as _vix
        from .applicability import ApplicabilityPolicy, partition_applicable
        recs = _vix.extract_records(scan)
        app, _ = partition_applicable(
            recs, policy or ApplicabilityPolicy(),
            kev_set=set(kev_set or set()))
        return len(app)
    except Exception:
        return None


def _run_cascade(
    *,
    args,
    output_dir: str,
    step: "StepCounter",
    base_image_name: str,
    run_id: str,
    local_orig: str,
    before_scan: Dict[str, Any],
    sbom_before: Dict[str, Any],
    inference,
    patched_text_base_swap: Optional[str],
    after_scan_base_swap: Optional[Dict[str, Any]],
    epss_data: Optional[Dict[str, float]],
    kev_set: Optional[set],
    patched_build_timeout: int,
    applicability_policy: Optional[Any] = None,
    alternate_bases: Optional[List[Tuple[str, str, str]]] = None,
    incumbent_key: Optional[Tuple[int, int, int]] = None,
) -> CascadeOutcome:
    """Evaluate the ranked alternate strategies and select the BEST
    gate-passing candidate, not the first.

    Candidates are ranked by :func:`_selection_key` (applicable total,
    remaining fixable OS findings, raw total; lexicographic). Two entry
    modes share this function. When the primary candidate failed the
    gate (``incumbent_key`` is None), any gate-passer is eligible and
    the best-keyed one is selected. When the primary candidate passed
    (improver mode), ``incumbent_key`` carries its key and a candidate
    is selected only when it passes the gate AND strictly improves the
    key, so an improver pass can never make the outcome worse.

    Each strategy is a triple (name, dockerfile_generator, on_image)
    where ``dockerfile_generator`` produces a Dockerfile text and
    ``on_image`` is the image the strategy is layered on top of
    (the original image, or the base-swap result if one exists).
    The cascade builds, scans, and gates every candidate; passers are
    ranked by the size of their applicable finding set and only the
    leader's image is kept alive between iterations.

    The cascade does NOT publish or sign -- it only chooses which
    candidate the surrounding pipeline should treat as the
    accepted result. The caller is responsible for the publish/sign
    phases.
    """
    out = CascadeOutcome()
    if generate_inplace_patch is None:
        out.feedback.append("inplace_patcher module unavailable; cascade skipped")
        return out

    strategies: List[Tuple[str, Callable[[], Optional[str]], str]] = []

    # Alternate-base candidates first (the ranked candidate loop): the
    # primary candidate already failed the gate before we got here, so
    # with N alternates the run tries at least 1+N ranked candidates
    # before declining. Slim variants are ranked ahead of Wolfi
    # equivalents (prefer-slim policy); each alternate is the primary
    # patched Dockerfile with only the FROM ref substituted, so build,
    # scan, and gate see an otherwise identical transformation.
    def _make_alt_generator(replace_ref: str, alt_ref: str):
        def _gen() -> Optional[str]:
            if not patched_text_base_swap:
                return None
            if f"FROM {replace_ref}" not in patched_text_base_swap:
                return None
            return patched_text_base_swap.replace(
                f"FROM {replace_ref}", f"FROM {alt_ref}")
        return _gen

    for _label, _replace_ref, _alt_ref in (alternate_bases or []):
        strategies.append(
            (_label, _make_alt_generator(_replace_ref, _alt_ref), local_orig))

    # "inplace_os": ignore the base swap and apply OS package upgrades
    #    on the original image. This recovers the "already on the latest
    #    base" case, where a base swap produces 0% vulnerability
    #    reduction because there is nothing newer to move to.
    def _strategy_inplace_os() -> Optional[str]:
        inplace = generate_inplace_patch(
            original_image=local_orig,
            scan_result=before_scan,
            os_family=inference.os_family,
            sbom_data=sbom_before,
        )
        if not inplace.os_upgrade_commands:
            return None
        return inplace.patch_dockerfile

    strategies.append(("inplace_os", _strategy_inplace_os, local_orig))


    for strategy_name, generator, _origin in strategies:
        logger.info(step.log(f"Cascade attempt: {strategy_name}"))
        try:
            dockerfile_text = generator()
        except Exception as e:
            out.feedback.append(f"{strategy_name}: generator raised {type(e).__name__}: {e}")
            continue
        if not dockerfile_text:
            out.feedback.append(f"{strategy_name}: nothing to do")
            continue

        cascade_tag = f"{base_image_name}-cascade-{strategy_name.replace('+', '-')}-{run_id}"
        cascade_df_path = os.path.join(output_dir, f"Dockerfile.cascade-{strategy_name}")
        try:
            with open(cascade_df_path, "w", encoding="utf-8") as f:
                f.write(dockerfile_text)
        except OSError as e:
            out.feedback.append(f"{strategy_name}: cannot write Dockerfile ({e})")
            continue

        # Build the candidate.
        success, error_cat, _build_time = build_image(
            cascade_tag, cascade_df_path,
            timeout=patched_build_timeout,
            cache_from=getattr(args, "cache_from", []) or [],
            cache_to=getattr(args, "cache_to", None),
            buildkit=not getattr(args, "no_buildkit", False),
            # Build against the ORIGINAL context so COPY of app source/configs
            # resolves (the cascade Dockerfile lives in output_dir).
            build_context_path=(os.path.dirname(os.path.abspath(args.dockerfile))
                                if getattr(args, "dockerfile", None) else None),
        )
        if not success:
            out.feedback.append(
                f"{strategy_name}: build failed ({error_cat})"
            )
            run_cmd(["docker", "rmi", "-f", cascade_tag])
            continue

        # Scan and gate.
        try:
            cascade_scan = scan_image(
                cascade_tag,
                os.path.join(output_dir, f"trivy-cascade-{strategy_name}.json"),
            )
        except ScanError as e:
            out.feedback.append(f"{strategy_name}: scan failed ({e})")
            run_cmd(["docker", "rmi", "-f", cascade_tag])
            continue

        try:
            cascade_sbom = generate_sbom(
                cascade_tag,
                os.path.join(output_dir, f"sbom-cascade-{strategy_name}.json"),
            )
        except ScanError:
            cascade_sbom = {}

        accepted, feedback = check_acceptance_criteria(
            before_scan, cascade_scan,
            threshold=args.accept_threshold,
            epss_data=epss_data,
            kev_set=kev_set,
            epss_safe_threshold=getattr(args, "epss_safe_threshold", 0.01),
            min_risk_reduction=getattr(args, "min_risk_reduction", 0.0),
            # A cascade candidate must pass the SAME gate as the primary
            # candidate, including the applicability policy; otherwise a
            # strategy could win merely by being judged on a different
            # finding set.
            applicability_policy=applicability_policy,
        )

        if accepted:
            # Best-of selection: a passer must strictly improve the
            # selection key relative to the current leader (or the
            # incumbent primary candidate in improver mode).
            _key = _selection_key(
                cascade_scan, applicability_policy, kev_set)
            _bar = out.selection_key if out.accepted else incumbent_key
            if _bar is not None and (_key is None or _key >= _bar):
                out.feedback.append(
                    f"{strategy_name}: passed the gate but does not "
                    f"improve the selection key "
                    f"({_key} vs {_bar}); not selected")
                run_cmd(["docker", "rmi", "-f", cascade_tag])
                continue
            logger.info(step.log(
                f"Cascade candidate {strategy_name} leads "
                f"(key applicable/fixable-os/raw: {_key})"))
            if out.image_tag:
                # A previous passer led; the new candidate is strictly
                # better, so release the old leader's image.
                run_cmd(["docker", "rmi", "-f", out.image_tag])
            out.accepted = True
            out.strategy = strategy_name
            out.dockerfile_path = cascade_df_path
            out.image_tag = cascade_tag
            out.after_scan = cascade_scan
            out.sbom_after = cascade_sbom
            out.applicable_after = _key[0] if _key else None
            out.selection_key = _key
            out.build_time = _build_time
            out.feedback.append(
                f"{strategy_name}: accepted (key: {_key})")
            continue

        # Gate rejected this candidate -- record reasons, clean up,
        # and try the next strategy.
        _hard = [r for r in feedback if not r.startswith("[WARNING]")]
        out.feedback.append(
            f"{strategy_name}: rejected ({'; '.join(_hard) or 'no reasons'})"
        )
        run_cmd(["docker", "rmi", "-f", cascade_tag])

    if out.accepted:
        logger.info(step.log(f"Cascade WINNER: {out.strategy}"))
    return out


def _sanitize_image_name(name: str) -> str:
    """
    Sanitize image name to only allow [a-zA-Z0-9._-].

    Args:
        name: Raw image name from Dockerfile

    Returns:
        Sanitized name safe for Docker commands
    """
    # Allow alphanumeric, dots, hyphens, and forward slashes (for registry paths).
    # Collapse multiple slashes and strip leading/trailing slashes to avoid
    # malformed image references like "//foo/" or "foo//bar".
    sanitized = re.sub(r'[^a-zA-Z0-9._/-]', '', name)
    sanitized = re.sub(r'/+', '/', sanitized).strip('/')
    if not sanitized:
        sanitized = "image"
    return sanitized[:128]  # Limit length


def _infer_os_from_base(image_ref: str) -> Optional[str]:
    """Infer OS family from a base image reference for migration detection."""
    lower = image_ref.lower()
    if "alpine" in lower:
        return "alpine"
    if any(x in lower for x in ["slim", "bookworm", "bullseye", "buster", "stretch"]):
        return "debian"
    if any(x in lower for x in ["ubuntu", "jammy", "focal", "noble"]):
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


# Hosts allowed for --git-url. Adding to this set should be a deliberate
# decision: each entry can clone code that AutoPatch will then build,
# scan, and (when --create-pr is set) push back to.
_ALLOWED_GIT_HOSTS = frozenset({
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
})


def _validate_github_url(url: str) -> bool:
    """
    Validate a remote repository URL.

    Returns True only when the URL is HTTPS, the host is in
    ``_ALLOWED_GIT_HOSTS``, and the path looks like ``owner/repo[/...]``.
    The earlier regex accepted ``https://github.com.evil.example/...``
    via substring match; this version anchors on the URL parser so the
    host check cannot be tricked by appended subdomains.
    """
    if not url or not url.startswith("https://"):
        return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_GIT_HOSTS:
        logger.warning(
            "Rejecting git URL %r: host %r not in allowlist %s. Set "
            "AUTOPATCH_EXTRA_GIT_HOSTS to extend.",
            url, host, sorted(_ALLOWED_GIT_HOSTS),
        )
        return False
    # Path must look like /owner/repo[/...] -- at least two segments.
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return False
    if not all(re.match(r"^[A-Za-z0-9._-]+$", p.replace(".git", "")) for p in parts[:2]):
        return False
    return True


def _clone_github_repo(repo_url: str) -> str:
    """
    Clone a GitHub repository to a temporary directory.

    Args:
        repo_url: GitHub URL (e.g., https://github.com/user/repo)

    Returns:
        Path to the cloned directory

    Raises:
        Exception on clone failure
    """
    temp_dir = tempfile.mkdtemp(prefix="autopatch-github-")
    logger.info(f"Cloning repository {repo_url} to {temp_dir}...")

    code, output = run_cmd(["git", "clone", repo_url, temp_dir])
    if code != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {output}")

    return temp_dir


def _find_dockerfile(repo_path: str) -> str:
    """
    Find Dockerfile in a directory (searches recursively).

    Args:
        repo_path: Directory path to search

    Returns:
        Path to Dockerfile

    Raises:
        FileNotFoundError if no Dockerfile found
    """
    # First check root
    root_dockerfile = os.path.join(repo_path, "Dockerfile")
    if os.path.exists(root_dockerfile):
        return root_dockerfile

    # Search recursively
    for root, dirs, files in os.walk(repo_path):
        if "Dockerfile" in files:
            return os.path.join(root, "Dockerfile")

    raise FileNotFoundError(f"No Dockerfile found in {repo_path}")


def _generate_json_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    signing_logs: list,
    supply_chain_result=None,
    network_result=None,
    provenance_summary=None,
) -> str:
    """Generate JSON format report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "base_image_changes": [{"original": o, "new": n} for o, n in base_changes],
        "vulnerabilities_before": before_summary,
        "vulnerabilities_after": after_summary,
        "resolved_vulnerabilities": vulns_diff["resolved"],
        "remaining_vulnerabilities": vulns_diff["remaining"],
        "new_vulnerabilities": vulns_diff["new"],
        "sbom_diff": sbom_diff,
        "metrics": metrics,
        "signing_operations": signing_logs,
        # Present when the multi-tier fingerprint ran. Its absence is
        # itself information: it means the base decision rested on the
        # SBOM alone, with no corroborating filesystem evidence.
        "provenance": provenance_summary,
    }

    if supply_chain_result is not None:
        report["supply_chain_scan"] = {
            "overall_risk": supply_chain_result.overall_risk,
            "findings_count": len(supply_chain_result.findings),
            "findings": [
                {
                    "check": f.check_name,
                    "severity": f.severity,
                    "package": f.package_name,
                    "ecosystem": f.ecosystem,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.recommendation,
                }
                for f in supply_chain_result.findings
            ],
        }

    if network_result is not None:
        report["network_analysis"] = {
            "risk_score": network_result.risk_score,
            "overall_risk": network_result.overall_risk,
            "findings_count": len(network_result.findings),
            "findings": [
                {
                    "detector": f.detector,
                    "severity": f.severity,
                    "indicator": f.target,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in network_result.findings
            ],
            "dns_queries": len(network_result.network_profile.dns_queries) if network_result.network_profile else 0,
            "tcp_connections": len(network_result.network_profile.tcp_connections) if network_result.network_profile else 0,
        }

    return json.dumps(report, indent=2)


def _generate_markdown_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    acceptance_status: bool,
    acceptance_reasons: list,
    patched_dockerfile_path: Optional[str] = None,
    diff_text: Optional[str] = None,
    supply_chain_result=None,
    network_result=None
) -> str:
    """Generate Markdown format report."""
    lines = ["# AutoPatch Report\n"]

    lines.append(f"**Generated:** {datetime.now().isoformat()}\n")

    lines.append("## Summary\n")
    lines.append(f"- **Acceptance Status:** {'ACCEPTED' if acceptance_status else 'REJECTED'}\n")
    if acceptance_reasons:
        rejections = [r for r in acceptance_reasons if not r.startswith("[WARNING]")]
        warnings_list = [r.replace("[WARNING] ", "") for r in acceptance_reasons if r.startswith("[WARNING]")]
        if rejections:
            lines.append("- **Rejection Reasons:**\n")
            for reason in rejections:
                escaped_reason = html.escape(reason)
                lines.append(f"  - {escaped_reason}\n")
        if warnings_list:
            lines.append("- **Warnings:**\n")
            for warning in warnings_list:
                escaped_warning = html.escape(warning)
                lines.append(f"  - {escaped_warning}\n")

    lines.append("## Base Image Changes\n")
    if base_changes:
        for orig, new in base_changes:
            escaped_orig = html.escape(orig)
            escaped_new = html.escape(new)
            lines.append(f"- `{escaped_orig}` -> `{escaped_new}`\n")
    else:
        lines.append("- None\n")

    lines.append("## Vulnerabilities\n")
    lines.append(f"### Before: {before_summary.get('total', 0)} total\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in before_summary:
            lines.append(f"- {sev}: {before_summary[sev]}\n")

    lines.append(f"### After: {after_summary.get('total', 0)} total\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in after_summary:
            lines.append(f"- {sev}: {after_summary[sev]}\n")

    reduction = before_summary.get('total', 0) - after_summary.get('total', 0)
    # format_reduction_percentage prints "n/a" rather than fabricating
    # "0.0%" when the baseline is zero and the ratio is undefined.
    reduction_pct = format_reduction_percentage(
        before_summary.get('total', 0), after_summary.get('total', 0)
    )
    lines.append(f"### Reduction: {reduction} CVEs ({reduction_pct})\n")

    lines.append("## CVE Details\n")
    lines.append(f"### Resolved ({len(vulns_diff['resolved'])})\n")
    for v in vulns_diff["resolved"][:10]:
        escaped_id = html.escape(v['id'])
        escaped_pkg = html.escape(v['package'])
        lines.append(f"- {escaped_id} in {escaped_pkg}\n")
    if len(vulns_diff["resolved"]) > 10:
        lines.append(f"- ... and {len(vulns_diff['resolved']) - 10} more\n")

    lines.append(f"### Remaining ({len(vulns_diff['remaining'])})\n")
    for v in vulns_diff["remaining"][:5]:
        escaped_id = html.escape(v['id'])
        escaped_pkg = html.escape(v['package'])
        lines.append(f"- {escaped_id} in {escaped_pkg} ({v['severity']})\n")
    if len(vulns_diff["remaining"]) > 5:
        lines.append(f"- ... and {len(vulns_diff['remaining']) - 5} more\n")

    if vulns_diff["new"]:
        lines.append(f"### New ({len(vulns_diff['new'])})\n")
        for v in vulns_diff["new"][:5]:
            escaped_id = html.escape(v['id'])
            escaped_pkg = html.escape(v['package'])
            lines.append(f"- {escaped_id} in {escaped_pkg} ({v['severity']})\n")
        if len(vulns_diff["new"]) > 5:
            lines.append(f"- ... and {len(vulns_diff['new']) - 5} more\n")

    lines.append("## SBOM Changes\n")
    lines.append(f"- Added: {len(sbom_diff['added'])} components\n")
    lines.append(f"- Removed: {len(sbom_diff['removed'])} components\n")
    lines.append(f"- Updated: {len(sbom_diff['updated'])} components\n")

    if metrics:
        lines.append("## Metrics\n")
        lines.append(f"- Vulnerability Reduction: {metrics.get('vulnerability_reduction_pct', 0):.1f}%\n")
        lines.append(f"- CVE Resolution Rate: {metrics.get('cve_resolution_rate', 0):.1f}%\n")
        if 'build_time_seconds' in metrics:
            lines.append(f"- Build Time: {metrics['build_time_seconds']:.2f}s\n")
        if 'image_size_delta_mb' in metrics:
            lines.append(f"- Image Size Delta: {metrics['image_size_delta_mb']:+.2f}MB\n")

    if supply_chain_result is not None:
        lines.append("## Supply Chain Scan\n")
        lines.append(f"- **Overall Risk:** {supply_chain_result.overall_risk}\n")
        lines.append(f"- **Findings:** {len(supply_chain_result.findings)}\n")
        if supply_chain_result.findings:
            lines.append("\n| Severity | Check | Package | Description |\n")
            lines.append("|----------|-------|---------|-------------|\n")
            for f in supply_chain_result.findings:
                lines.append(
                    f"| {f.severity} | {html.escape(f.check_name)} | "
                    f"{html.escape(f.package_name or 'N/A')} | {html.escape(f.description)} |\n"
                )

    if network_result is not None:
        lines.append("## Network Behavior Analysis\n")
        lines.append(f"- **Risk Score:** {network_result.risk_score}/100\n")
        lines.append(f"- **Overall Risk:** {network_result.overall_risk}\n")
        lines.append(f"- **Findings:** {len(network_result.findings)}\n")
        if network_result.findings:
            lines.append("\n| Severity | Detector | Indicator | Description |\n")
            lines.append("|----------|----------|-----------|-------------|\n")
            for f in network_result.findings:
                lines.append(
                    f"| {f.severity} | {html.escape(f.detector)} | "
                    f"{html.escape(f.target)} | {html.escape(f.description)} |\n"
                )

    if diff_text:
        lines.append("## Dockerfile Changes\n")
        lines.append("```diff\n")
        lines.append(diff_text)
        lines.append("\n```\n")

    return "".join(lines)


def _generate_html_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    acceptance_status: bool,
    acceptance_reasons: list,
    supply_chain_result=None,
    network_result=None
) -> str:
    """Generate HTML format report with HTML escaping for all interpolated values."""
    html_lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<title>AutoPatch Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        "h1 { color: #333; }",
        "h2 { color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; }",
        ".summary { background: #f9f9f9; padding: 10px; border-left: 4px solid #007bff; }",
        ".accepted { color: green; font-weight: bold; }",
        ".rejected { color: red; font-weight: bold; }",
        ".metric { display: inline-block; margin: 10px 20px 10px 0; }",
        "table { border-collapse: collapse; width: 100%; margin: 10px 0; }",
        "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
        "th { background: #f0f0f0; }",
        ".critical { color: red; }",
        ".high { color: orange; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>AutoPatch Report</h1>",
        f"<p><strong>Generated:</strong> {html.escape(datetime.now().isoformat())}</p>",
    ]

    # Summary
    html_lines.append('<div class="summary">')
    status_class = "accepted" if acceptance_status else "rejected"
    status_text = "ACCEPTED" if acceptance_status else "REJECTED"
    html_lines.append(f'<p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>')
    if acceptance_reasons:
        rejections = [r for r in acceptance_reasons if not r.startswith("[WARNING]")]
        warnings_list = [r.replace("[WARNING] ", "") for r in acceptance_reasons if r.startswith("[WARNING]")]
        if rejections:
            html_lines.append("<p><strong>Rejection Reasons:</strong></p><ul>")
            for reason in rejections:
                escaped_reason = html.escape(reason)
                html_lines.append(f"<li>{escaped_reason}</li>")
            html_lines.append("</ul>")
        if warnings_list:
            html_lines.append('<p><strong>Warnings:</strong></p><ul style="color: #856404;">')
            for warning in warnings_list:
                escaped_warning = html.escape(warning)
                html_lines.append(f"<li>{escaped_warning}</li>")
            html_lines.append("</ul>")
    html_lines.append("</div>")

    # Base Changes
    html_lines.append("<h2>Base Image Changes</h2>")
    if base_changes:
        html_lines.append("<ul>")
        for orig, new in base_changes:
            escaped_orig = html.escape(orig)
            escaped_new = html.escape(new)
            html_lines.append(f"<li><code>{escaped_orig}</code> -> <code>{escaped_new}</code></li>")
        html_lines.append("</ul>")
    else:
        html_lines.append("<p>None</p>")

    # Vulnerabilities
    html_lines.append("<h2>Vulnerabilities</h2>")
    html_lines.append("<table>")
    html_lines.append("<tr><th>Severity</th><th>Before</th><th>After</th></tr>")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        before = before_summary.get(sev, 0)
        after = after_summary.get(sev, 0)
        sev_class = "critical" if sev == "CRITICAL" else "high" if sev == "HIGH" else ""
        html_lines.append(
            f'<tr><td class="{sev_class}"><strong>{sev}</strong></td>'
            f'<td>{before}</td><td>{after}</td></tr>'
        )
    html_lines.append("</table>")

    # CVE Summary
    total_before = before_summary.get('total', 0)
    total_after = after_summary.get('total', 0)
    reduction = total_before - total_after
    reduction_pct = format_reduction_percentage(total_before, total_after)
    html_lines.append(
        f"<p><strong>Total Reduction:</strong> {reduction} CVEs ({reduction_pct})</p>"
    )

    # CVE Details
    html_lines.append("<h2>CVE Details</h2>")
    html_lines.append(f"<p><strong>Resolved:</strong> {len(vulns_diff['resolved'])}</p>")
    html_lines.append(f"<p><strong>Remaining:</strong> {len(vulns_diff['remaining'])}</p>")
    html_lines.append(f"<p><strong>New:</strong> {len(vulns_diff['new'])}</p>")

    # SBOM Changes
    html_lines.append("<h2>SBOM Changes</h2>")
    html_lines.append("<ul>")
    html_lines.append(f"<li>Added: {len(sbom_diff['added'])} components</li>")
    html_lines.append(f"<li>Removed: {len(sbom_diff['removed'])} components</li>")
    html_lines.append(f"<li>Updated: {len(sbom_diff['updated'])} components</li>")
    html_lines.append("</ul>")

    # Metrics
    if metrics:
        html_lines.append("<h2>Metrics</h2>")
        html_lines.append(f'<div class="metric">Vulnerability Reduction: <strong>{metrics.get("vulnerability_reduction_pct", 0):.1f}%</strong></div>')
        html_lines.append(f'<div class="metric">CVE Resolution Rate: <strong>{metrics.get("cve_resolution_rate", 0):.1f}%</strong></div>')
        if 'build_time_seconds' in metrics:
            html_lines.append(f'<div class="metric">Build Time: <strong>{metrics["build_time_seconds"]:.2f}s</strong></div>')
        if 'image_size_delta_mb' in metrics:
            sign = "+" if metrics['image_size_delta_mb'] >= 0 else ""
            html_lines.append(f'<div class="metric">Image Size Delta: <strong>{sign}{metrics["image_size_delta_mb"]:.2f}MB</strong></div>')

    if supply_chain_result is not None:
        html_lines.append("<h2>Supply Chain Scan</h2>")
        risk_color = "red" if supply_chain_result.overall_risk == "CRITICAL" else "orange" if supply_chain_result.overall_risk == "HIGH" else "#333"
        html_lines.append(f'<p><strong>Overall Risk:</strong> <span style="color:{risk_color};font-weight:bold;">{html.escape(supply_chain_result.overall_risk)}</span></p>')
        html_lines.append(f"<p><strong>Findings:</strong> {len(supply_chain_result.findings)}</p>")
        if supply_chain_result.findings:
            html_lines.append("<table><tr><th>Severity</th><th>Check</th><th>Package</th><th>Description</th><th>Remediation</th></tr>")
            for f in supply_chain_result.findings:
                sev_class = "critical" if f.severity == "CRITICAL" else "high" if f.severity == "HIGH" else ""
                html_lines.append(
                    f'<tr><td class="{sev_class}">{html.escape(f.severity)}</td>'
                    f"<td>{html.escape(f.check_name)}</td>"
                    f"<td>{html.escape(f.package_name or 'N/A')}</td>"
                    f"<td>{html.escape(f.description)}</td>"
                    f"<td>{html.escape(f.recommendation or '')}</td></tr>"
                )
            html_lines.append("</table>")

    if network_result is not None:
        html_lines.append("<h2>Network Behavior Analysis</h2>")
        net_color = "red" if network_result.risk_score >= 70 else "orange" if network_result.risk_score >= 40 else "green"
        html_lines.append(f'<p><strong>Risk Score:</strong> <span style="color:{net_color};font-weight:bold;">{network_result.risk_score}/100</span></p>')
        html_lines.append(f'<p><strong>Overall Risk:</strong> {html.escape(network_result.overall_risk)}</p>')
        html_lines.append(f"<p><strong>Findings:</strong> {len(network_result.findings)}</p>")
        if network_result.findings:
            html_lines.append("<table><tr><th>Severity</th><th>Detector</th><th>Indicator</th><th>Description</th></tr>")
            for f in network_result.findings:
                sev_class = "critical" if f.severity == "CRITICAL" else "high" if f.severity == "HIGH" else ""
                html_lines.append(
                    f'<tr><td class="{sev_class}">{html.escape(f.severity)}</td>'
                    f"<td>{html.escape(f.detector)}</td>"
                    f"<td>{html.escape(f.target)}</td>"
                    f"<td>{html.escape(f.description)}</td></tr>"
                )
            html_lines.append("</table>")

    html_lines.extend(["</body>", "</html>"])
    return "\n".join(html_lines)


def run_pipeline(argv: Optional[List[str]] = None) -> int:
    """
    Library entry point for the AutoPatch pipeline.

    Equivalent to invoking the CLI: parses ``argv`` (or ``sys.argv``
    when omitted) and runs the full base-swap + acceptance + sign
    pipeline. Returns the process-style exit code (0 on success).

    The experiment runner, integration tests, and any embedding
    application should call this rather than re-implementing the
    orchestration in :func:`patch_dockerfile` + :func:`build_image`
    + :func:`scan_image`. That guarantees experiment numbers and
    production-CLI numbers come from one code path.
    """
    return main(argv)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Docker Image Auto-Patching Tool")

    # Required flags (one of these two)
    parser.add_argument("--dockerfile", help="Path to the Dockerfile to patch")
    parser.add_argument("--context",
                        help="Build-context directory for docker build "
                             "(typically the repo root). Defaults to the "
                             "Dockerfile's own directory, which breaks COPY "
                             "of repo-root files when the Dockerfile lives in "
                             "a subdirectory (docker/, scripts/, ...).")
    parser.add_argument("--github-url", help="GitHub repository URL (auto-clones and finds Dockerfile)")

    # Registry and signing
    parser.add_argument("--registry", default="localhost:5000", help="Target registry (default: localhost:5000)")
    parser.add_argument(
        "--signing-mode", "--signing",
        choices=["keyless", "key-based", "key", "disabled", "none"],
        default="key",
        help="Signing mode: keyless, key-based/key (default), disabled/none"
    )
    parser.add_argument("--insecure-image-registry",
                        "--insecure-registry",  # backward-compatible alias
                        action="store_true",
                        dest="insecure_registry",
                        default=False,
                       help="Allow insecure (HTTP) registry connections")

    # Patching options
    parser.add_argument("--base-mapping", help="JSON/YAML file with base image overrides")
    parser.add_argument("--patch-final-only", action="store_true", help="Only patch final stage")
    parser.add_argument("--eol-upgrade", action="store_true",
                       help="When the SBOM-detected language version is EOL "
                            "(per endoflife.date), upgrade to the current "
                            "supported successor instead of preserving the "
                            "user-pinned tag. Off by default so that `python:3.9` "
                            "stays at 3.9 and only the OS variant is "
                            "rewritten. Pass this flag in experiment runs "
                            "where aggressive EOL chasing is desired.")
    parser.add_argument("--accept-threshold",
                       choices=["strict", "count-strict", "moderate",
                                "permissive", "risk", "reachability"],
                       default="count-strict",
                       help="Acceptance criteria threshold (default: "
                            "count-strict). 'count-strict' is the operational "
                            "gate: over the applicable finding set, CRITICAL "
                            "and HIGH counts must not rise, the total must "
                            "strictly decrease, and any newly-introduced KEV "
                            "(known-exploited) CVE blocks unconditionally. "
                            "This matches production admission-controller "
                            "practice, which gates on severity counts with an "
                            "available fix rather than CVE identity. 'strict' "
                            "is the paper's Eq. (1) identity gate (no new "
                            "Critical/High identity at all): the no-regression "
                            "bound, stricter than any fielded system. 'risk' "
                            "uses NIST CSWP 41 LEV + EPSS + KEV composite "
                            "scoring and requires --epss-file and/or --kev-file. "
                            "'reachability' filters records to packages reachable "
                            "from declared entrypoints (requires --dep-graph) and "
                            "applies strict-mode logic to the reachable subset.")
    parser.add_argument("--epss-file",
                       help="Optional JSON file mapping CVE IDs to EPSS scores "
                            "in [0,1]. Enables EPSS-aware demotion of new "
                            "low-exploitability HIGH/CRITICAL CVEs in strict "
                            "mode, and is required for --accept-threshold=risk.")
    parser.add_argument("--kev-file",
                       help="Optional JSON file listing CVE IDs in the CISA "
                            "Known Exploited Vulnerabilities catalog "
                            "(accepts either a JSON array or the official "
                            "{'vulnerabilities':[{cveID:...}]} schema).")
    parser.add_argument("--require-vex-for-new-critical", action="store_true",
                       help="Reject unless every newly-introduced CRITICAL CVE has a VEX not_affected statement in --vex-suppress files. Stricter posture for regulated environments where new criticals must be explicitly dismissed.")
    parser.add_argument("--min-posture-score", type=float, default=None,
                       help="Optional posture-score floor (0-100). Layers on top of any --accept-threshold and rejects images whose composite posture (KEV/EPSS/severity/reachability) falls below the floor. By default the posture score is report-only.")
    parser.add_argument("--no-runtime-validation", action="store_true",
                       help="Skip runtime validation of the patched image. "
                            "By default an accepted image must start, survive "
                            "entrypoint introspection, and pass any declared "
                            "application probe, because a rebuilt image can "
                            "compile and scan clean yet fail at startup.")
    parser.add_argument("--runtime-validation-advisory", action="store_true",
                       help="Report runtime-validation failures as warnings "
                            "instead of rejecting the patch. Useful when "
                            "characterizing a corpus; not recommended for "
                            "pipelines that publish the result.")
    parser.add_argument("--smoke-manifest", default=None,
                       help="Path to a YAML manifest of per-image "
                            "application probes (see dataset/smoke/"
                            "manifest.yaml). Enables the application "
                            "validation tier; without it only the startup "
                            "and introspection tiers run.")
    parser.add_argument("--no-differential-validation",
                       dest="differential_validation",
                       action="store_false", default=True,
                       help="Skip the before/after behavioural comparison "
                            "(entrypoint, ports, user, workdir, env, CA "
                            "trust, DNS, file modes, shared libs). The "
                            "comparison is advisory: divergences are "
                            "reported, never a reason to reject a "
                            "security patch.")
    parser.add_argument("--multistage-attribution", action="store_true",
                       help="For multi-stage Dockerfiles, build and scan "
                            "each builder stage so CVEs can be split into "
                            "those that ship and those discarded at the "
                            "final COPY. Costs one build and one scan per "
                            "stage, which is why it is opt-in; without it "
                            "no attribution is reported rather than a "
                            "fabricated one that assumes builder stages "
                            "are clean.")
    parser.add_argument("--target", default=None,
                       help="Name of the stage that ships (docker build "
                            "--target). Determines which stage is treated "
                            "as final for multi-stage attribution. "
                            "Defaults to the last stage in the file.")
    parser.add_argument("--demote-adjacent-av", action="store_true",
                       help="In strict and reachability modes, treat new "
                            "AV:Adjacent CRITICAL/HIGH as non-exploitable. "
                            "OFF by default because Adjacent maps to "
                            "neighbor-pod attacks in multi-tenant K8s; "
                            "only enable on single-tenant clusters.")
    parser.add_argument("--no-demote-local-av", action="store_true",
                       help="Disable the default behaviour of demoting "
                            "AV:Local and AV:Physical CRITICAL/HIGH. "
                            "Use this when the container DOES run "
                            "interactive shells or carries physical-attack "
                            "code paths (kernel modules, hardware drivers).")
    parser.add_argument("--epss-safe-threshold", type=float, default=0.01,
                       help="EPSS below this is treated as non-exploitable for "
                            "strict-mode demotion (default 0.01 = 1%%).")
    parser.add_argument("--cascade", action="store_true",
                       help="On acceptance-gate rejection, try a sequence "
                            "of alternate strategies (base-swap+app-layer-inplace, "
                            "inplace OS+app, inplace app-only) before declaring "
                            "failure. Off by default. The first strategy whose "
                            "rebuilt image passes the gate wins.")
    parser.add_argument("--min-risk-reduction", type=float, default=0.0,
                       help="Required fractional reduction in composite risk "
                            "for --accept-threshold=risk (default 0.0 = any "
                            "strict reduction is accepted).")
    parser.add_argument("--cache-from", action="append", default=[],
                       help="Image ref to pull BuildKit layer cache from. May be repeated. Enables BuildKit even if --no-buildkit is set.")
    parser.add_argument("--cache-to",
                       help="BuildKit --cache-to spec (e.g. type=registry,ref=registry.example/cache:autopatch). Requires BuildKit.")
    parser.add_argument("--no-buildkit", action="store_true",
                       help="Disable DOCKER_BUILDKIT=1 for docker build. Not recommended: BuildKit dramatically improves retry-after-partial-failure behavior.")

    # Logging and output
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--dry-run", action="store_true", help="Generate patched Dockerfile but don't build/push/sign")
    parser.add_argument("--no-push", action="store_true",
                        help="Skip the registry publish step (tag+push) after "
                             "acceptance. For evaluation environments with no "
                             "registry: the build, scans, acceptance verdict "
                             "and all artifacts are unaffected; only the "
                             "publish of the accepted image is skipped.")
    parser.add_argument("--output-dir", default="./autopatch-output", help="Output directory for reports (default: ./autopatch-output)")
    parser.add_argument("--report-format",
                       choices=["json", "markdown", "html"],
                       default="json",
                       help="Report format (default: json)")
    parser.add_argument("--test-cmd", help="Command to test inside patched image")
    parser.add_argument("--smoke-test", action="store_true",
                       help="Run a lightweight smoke test after build to catch runtime crashes (musl/glibc, missing libs)")
    parser.add_argument("--ci-mode", action="store_true", help="Output GitHub Actions annotations and appropriate exit codes")

    # Scanner integrity and dual-scanner options
    parser.add_argument("--dual-scanner", action="store_true",
                       help="Enable dual-scanner mode (Trivy + Grype) for higher confidence")
    parser.add_argument("--scanner-checksums",
                       help="JSON file with scanner binary SHA256 checksums for supply chain verification")
    parser.add_argument("--strict-integrity", action="store_true",
                       help="Fail pipeline if scanner binary integrity verification fails")

    # Language override (D3)
    parser.add_argument("--language",
                       help="Override SBOM-detected language (e.g., python, node, golang)")
    parser.add_argument("--language-version",
                       help="Override SBOM-detected language version (e.g., 3.12, 22, 1.23)")

    # VEX and attestation
    parser.add_argument("--generate-vex", action="store_true",
                       help="Generate VEX documents (OpenVEX + CycloneDX) for resolved vulnerabilities")
    parser.add_argument("--generate-attestation", action="store_true",
                       help="Generate SLSA remediation attestation")

    # PR creation
    parser.add_argument("--create-pr", action="store_true",
                       help="Create a GitHub PR with the remediation changes (requires gh CLI)")
    parser.add_argument("--pr-base-branch", default="main",
                       help="Base branch for PR creation (default: main)")
    parser.add_argument("--pr-draft", action="store_true",
                       help="Create PR as draft")

    # In-place patching mode (J1)
    parser.add_argument("--inplace", action="store_true",
                       help="Use in-place patching instead of base image replacement")
    # --inplace-tier is gone: in-place patching is OS-package only.
    # The application-package tier was removed because AutoPatch could
    # not verify a dependency upgrade was correct (no lockfile solving,
    # no project test suite), so the tier claimed remediation the
    # pipeline never validated.

    parser.add_argument("--applicability",
                       choices=["default", "kernel-only", "literal", "nofix",
                                "reachability", "epss"],
                       default="default",
                       help="Which exploitability-class filter the acceptance "
                            "gate applies before evaluating the criterion. "
                            "'default' excludes kernel-space and no-fix "
                            "findings: a container shares the host kernel, "
                            "and a no-fix CVE has no version to move to, "
                            "which is why production admission controllers "
                            "gate on vulnerabilities WITH an available fix. "
                            "'kernel-only' keeps no-fix findings in the gate "
                            "(the previous default). 'nofix' is a synonym for "
                            "'default', kept for compatibility. 'literal' "
                            "disables all filtering, recovering the raw-scanner "
                            "reading of Eq. (1). 'reachability' and 'epss' add "
                            "the corresponding sensitivity rule when the "
                            "evidence is supplied. KEV always overrides "
                            "exclusion: an actively-exploited CVE is never "
                            "filtered by any rule.")
    parser.add_argument("--no-glibc-floor", action="store_true",
                       help="Skip scanning the original image for its glibc "
                            "symbol-version floor. Without the floor a "
                            "candidate base with an older glibc passes the "
                            "build and fails at runtime with "
                            "'version GLIBC_x.y not found'.")

    # Multi-architecture builds (P4-27)
    parser.add_argument("--platforms", default=None,
                       help="Comma-separated platforms to build and verify, "
                            "e.g. 'linux/amd64,linux/arm64'. Requires "
                            "docker buildx. A base substitution valid on "
                            "amd64 is not automatically valid on arm64: tag "
                            "coverage differs per architecture, so each "
                            "platform is built and scanned separately.")

    # Provenance fingerprinting (P5)
    # A/B candidate selection experiment
    parser.add_argument("--ai-propose", action="store_true",
                       help="Arm B of the selection experiment: ask Claude "
                            "(pinned model, temperature 0, response cached "
                            "on disk) to propose the replacement base for "
                            "the shipping stage. The proposal passes through "
                            "the identical allow-list, guards, build, scan "
                            "and acceptance gates as deterministic "
                            "selection, and falls back to it on any "
                            "failure. Requires ANTHROPIC_API_KEY.")
    parser.add_argument("--ai-cache-only", action="store_true",
                       help="With --ai-propose, refuse network calls and "
                            "serve proposals only from the on-disk cache. "
                            "Makes a replay run provably offline and "
                            "byte-reproducible.")
    parser.add_argument("--no-provenance", action="store_true",
                       help="Skip multi-tier provenance fingerprinting and "
                            "the Bayesian distribution/libc/tamper posterior. "
                            "Inference then rests on the SBOM alone, which is "
                            "a single attacker-writable witness.")
    parser.add_argument("--tamper-threshold", type=float, default=0.5,
                       help="P(tamper) at or above which the run emits a "
                            "provenance anomaly warning (default: 0.5). The "
                            "posterior rises when high-trust filesystem "
                            "evidence contradicts low-trust package metadata.")

    # Dependency graph analysis (B1-B2)
    parser.add_argument("--dep-graph", action="store_true",
                       help="Run dependency graph reachability analysis on SBOM")

    # VEX suppression (I3)
    parser.add_argument("--vex-suppress", nargs="*", metavar="VEX_FILE",
                       help="VEX file(s) to apply as suppression on rescan "
                            "results. Informational by default; pass "
                            "--vex-affects-gate to let VEX influence acceptance.")
    parser.add_argument("--vex-affects-gate", action="store_true",
                       help="Allow --vex-suppress entries to filter the input "
                            "to the acceptance gate (default: VEX is reported "
                            "but does not change accept/reject).")

    # Layer 2: Supply chain integrity scanning
    parser.add_argument("--supply-chain-scan", action="store_true",
                       help="Enable Layer 2 supply chain integrity scanning (phantom deps, .pth files, install scripts)")
    parser.add_argument("--min-package-age-days", type=int, default=7,
                       help="Minimum package age in days for npm age check (default: 7)")

    # Layer 5: Network behavior monitoring
    parser.add_argument("--network-monitor", action="store_true",
                       help="Enable Layer 5 network behavior analysis (C2 detection, DGA, beaconing)")
    parser.add_argument("--network-duration", type=int, default=60,
                       help="Network capture duration in seconds (default: 60)")
    parser.add_argument("--network-test-cmd",
                       help="Command to run inside container during network capture")
    parser.add_argument("--network-risk-threshold", type=int, default=50,
                       help="Network risk score threshold for rejection (0-100, default: 50)")
    parser.add_argument("--threat-intel-dir", default="~/.autopatch/threat_intel",
                       help="Directory for cached threat intelligence feeds")
    parser.add_argument("--allowed-ports",
                       help="Comma-separated list of allowed outbound ports")
    parser.add_argument("--update-threat-feeds", action="store_true",
                       help="Force-refresh threat intelligence feeds before analysis")

    # Backward compat aliases
    parser.add_argument("--output-file", help="[DEPRECATED] Use --output-dir instead")

    args = parser.parse_args(argv)

    # Item 13: validate flag interdependencies immediately, before any build
    # or scan work. Previously --accept-threshold=risk without --epss-file/
    # --kev-file was only rejected after both builds and both scans, wasting
    # minutes of work on an unsatisfiable run. Fail fast here instead.
    _early_errors = []
    if args.accept_threshold == "risk" and not getattr(args, "epss_file", None) \
            and not getattr(args, "kev_file", None):
        _early_errors.append(
            "--accept-threshold=risk requires --epss-file and/or --kev-file"
        )
    if args.accept_threshold == "reachability" and not getattr(args, "dep_graph", None):
        _early_errors.append(
            "--accept-threshold=reachability requires --dep-graph"
        )
    for _f_attr, _f_flag in (("epss_file", "--epss-file"), ("kev_file", "--kev-file")):
        _p = getattr(args, _f_attr, None)
        if _p and not os.path.exists(_p):
            _early_errors.append(f"{_f_flag} path does not exist: {_p}")
    if _early_errors:
        parser.error("; ".join(_early_errors))

    # Wire --eol-upgrade through to the patcher module-level toggle.
    from . import patcher as _patcher_mod
    _patcher_mod._EOL_UPGRADE_ACTIVE = bool(args.eol_upgrade)

    # Adjust logging level based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.INFO if args.report_format in ("markdown", "html") else logging.WARNING)

    # Normalize signing mode (handle aliases)
    signing_mode = args.signing_mode
    if signing_mode in ("key-based",):
        signing_mode = "key"
    elif signing_mode in ("disabled",):
        signing_mode = "none"

    # Handle backward compat flags
    report_format = args.report_format or "json"
    output_file = args.output_file

    # Resolve Dockerfile path
    dockerfile_path: Optional[str] = None
    temp_repo_dir: Optional[str] = None

    try:
        if args.github_url:
            if not _validate_github_url(args.github_url):
                logger.error("Invalid GitHub URL format. Must be a valid HTTPS URL (e.g., https://github.com/user/repo)")
                if args.ci_mode:
                    print("::error::Invalid GitHub URL format")
                return 1

            logger.info(f"Cloning GitHub repository: {args.github_url}")
            temp_repo_dir = _clone_github_repo(args.github_url)
            dockerfile_path = _find_dockerfile(temp_repo_dir)
            logger.info(f"Found Dockerfile at: {dockerfile_path}")
        elif args.dockerfile:
            dockerfile_path = args.dockerfile
        else:
            logger.error("Either --dockerfile or --github-url must be provided")
            if args.ci_mode:
                print("::error::Either --dockerfile or --github-url must be provided")
            return 1

        # Read original Dockerfile
        try:
            with open(dockerfile_path, "r", encoding="utf-8") as f:
                original_dockerfile = f.read()
        except Exception as e:
            logger.error(f"Could not read Dockerfile: {e}")
            if args.ci_mode:
                print(f"::error::Could not read Dockerfile: {e}")
            return 1

        # Create output directory
        output_dir = os.path.abspath(args.output_dir)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Output directory: {output_dir}")

        # Parse stages
        stages = parse_dockerfile_stages(original_dockerfile)
        if not stages:
            logger.error("No valid FROM line found in Dockerfile")
            if args.ci_mode:
                print("::error::No valid FROM line found in Dockerfile")
            return 1

        base_image_raw = stages[0]['base_name'].split("/")[-1].lower() or "image"
        base_image_name = _sanitize_image_name(base_image_raw)
        # Per-run UUID suffix to avoid colliding with concurrent pipelines
        # patching the same Dockerfile (e.g. parallel CI matrix jobs).
        run_id = uuid.uuid4().hex[:8]
        local_orig = f"{base_image_name}-orig-{run_id}"
        local_patched = f"{base_image_name}-patched-{run_id}"
        registry = args.registry.rstrip("/")
        registry_patched = f"{registry}/{base_image_name}-patched:latest"

        logger.info(f"Base image: {stages[0]['base_image']}")

        step = StepCounter()

        # ============================================================================
        # PHASE 1: INPUT
        # ============================================================================
        logger.info(step.log("Input validation complete"))

        # ============================================================================
        # PHASE 1.5: SCANNER INTEGRITY VERIFICATION
        # ============================================================================
        # Resolve dual-scanner mode ONCE, here, before any scan runs.
        # --dual-scanner previously only widened the integrity check; no
        # Grype scan was ever executed and scanner_fusion was never
        # called, so the flag advertised a capability the run did not
        # have. Resolving it once also guarantees the before-scan and
        # the after-scan use the same scanner set (see the symmetry note
        # at the after-scan call site).
        dual_scanner_active = bool(getattr(args, 'dual_scanner', False))
        if dual_scanner_active:
            try:
                from .grype_scanner import is_grype_available, get_grype_version
                if not is_grype_available():
                    logger.error(step.log(
                        "--dual-scanner requested but grype is not on PATH. "
                        "Refusing to silently downgrade to Trivy-only, which "
                        "would report single-scanner results as fused."
                    ))
                    if args.ci_mode:
                        print("::error::--dual-scanner requested but grype not found")
                    return 1
                logger.info(step.log(
                    f"Dual-scanner mode: Trivy + Grype v{get_grype_version()}"
                ))
            except ImportError as e:
                logger.error(step.log(f"Grype scanner module unavailable: {e}"))
                return 1

        try:
            from .scanner_integrity import verify_all_scanners
            scanners_to_verify = ["trivy"]
            if dual_scanner_active:
                scanners_to_verify.append("grype")
            integrity_reports = verify_all_scanners(
                scanners=scanners_to_verify,
                strict=getattr(args, 'strict_integrity', False),
                checksums_file=getattr(args, 'scanner_checksums', None),
            )
            for name, report in integrity_reports.items():
                logger.info(
                    step.log(
                        f"Scanner integrity [{name}]: v{report.version_detected}, "
                        f"checks={report.checks_performed}, "
                        f"passed={'YES' if report.all_checks_passed else 'NO'}"
                    )
                )
                for w in report.warnings:
                    logger.warning(step.log(f"Scanner integrity warning: {w}"))
        except ImportError:
            logger.debug("Scanner integrity module not available, skipping")
        except Exception as e:
            logger.warning(step.log(f"Scanner integrity check failed: {e}"))
            if getattr(args, 'strict_integrity', False):
                return 1

        # ============================================================================
        # PHASE 2: SCAN ORIGINAL
        # ============================================================================

        # Build original image and capture build time
        step.set_phase("SCAN")
        logger.info(step.log("Building original image"))
        success, error_cat, build_time_orig = build_image(
            local_orig, dockerfile_path,
            # Same --target the patcher treated as final. Building the
            # whole file when the deployment builds only `--target
            # runtime` scans an image that never ships, so both the
            # baseline CVE count and the delta describe the wrong image.
            target=getattr(args, "target", None),
            cache_from=args.cache_from,
            cache_to=args.cache_to,
            buildkit=not args.no_buildkit,
            # Build against the explicit repo-root context when given, so
            # COPY of repo-root files resolves for sub-directory
            # Dockerfiles; else fall back to the Dockerfile's directory.
            build_context_path=(getattr(args, "context", None)
                                or os.path.dirname(os.path.abspath(dockerfile_path))),
        )

        if not success:
            logger.error(step.log(f"Failed to build original image ({error_cat})"))
            if args.ci_mode:
                print(f"::error::Failed to build original image: {error_cat}")
            return 1

        logger.info(step.log("Scanning original image for vulnerabilities"))
        try:
            before_scan = _scan_possibly_fused(
                local_orig,
                os.path.join(output_dir, "trivy-before.json"),
                output_dir=output_dir,
                phase="before",
                dual=dual_scanner_active,
            )
        except ScanError as e:
            logger.error(step.log(f"Scan failed: {e}"))
            if args.ci_mode:
                print(f"::error::Scan failed: {e}")
            return 1

        before_summary = summarize_vulnerabilities(before_scan)
        logger.info(step.log(f"Vulnerabilities BEFORE: {before_summary}"))

        logger.info(step.log("Generating SBOM for original image"))
        try:
            sbom_before = generate_sbom(local_orig, os.path.join(output_dir, "sbom-before.json"))
        except ScanError as e:
            logger.warning(step.log(f"SBOM generation failed (non-critical): {e}"))
            sbom_before = {}

        # ============================================================================
        # PHASE 3: INFER & PATCH
        # ============================================================================
        step.set_phase("PATCH")
        logger.info(step.log("Analyzing SBOM for OS, language, and compatibility"))
        inference = analyze_sbom(
            sbom_before,
            language_override=getattr(args, 'language', None),
            language_version_override=getattr(args, 'language_version', None),
        )

        # ── Multi-tier provenance fingerprint + Bayesian posterior ──
        #
        # analyze_sbom reads ONE witness: the SBOM. An SBOM is produced
        # by a scanner reading package metadata, and package metadata is
        # attacker-writable, absent from distroless images, and simply
        # wrong on any image whose rootfs was rebased. Deciding a base
        # substitution on that single signal is the weakest link in the
        # whole pipeline.
        #
        # This step collects independent evidence from the image itself
        # (T0 layer ancestry, T1 image config, T2 package database, T3
        # filesystem topology, T4 /etc/os-release, T5 dynamic loader)
        # and combines it with the SBOM answer under a Bayesian network
        # over (distribution, libc, tampering). Disagreement between
        # high-trust filesystem evidence and low-trust SBOM evidence is
        # what raises the tamper posterior.
        #
        # It ran nowhere until now: enhance_with_provenance had zero
        # callers, so every one of those tiers was dead code and the
        # pipeline shipped decisions made on the SBOM alone.
        provenance_summary: Optional[Dict[str, Any]] = None
        if not getattr(args, "no_provenance", False):
            try:
                from .patcher import enhance_with_provenance
                _t0 = time.time()
                inference = enhance_with_provenance(
                    inference, image_ref=local_orig
                )
                if inference.provenance_tiers_observed:
                    provenance_summary = {
                        "fingerprint_sha256": inference.provenance_fingerprint_hash,
                        "tiers_observed": list(inference.provenance_tiers_observed),
                        "consensus_distro": inference.provenance_consensus_distro,
                        "consensus_libc": inference.provenance_consensus_libc,
                        "inter_tier_agreement": inference.inter_tier_agreement,
                        "bayesian_distro": inference.bayesian_distro,
                        "bayesian_distro_probability":
                            inference.bayesian_distro_probability,
                        "bayesian_tamper_probability":
                            inference.bayesian_tamper_probability,
                        "bayesian_evidence_loglik":
                            inference.bayesian_evidence_loglik,
                        "sbom_only_distro": inference.os_family,
                        "duration_seconds": round(time.time() - _t0, 2),
                    }
                    save_json(provenance_summary,
                              os.path.join(output_dir, "provenance.json"))
                    logger.info(step.log(
                        f"Provenance: {len(inference.provenance_tiers_observed)} "
                        f"tiers -> {inference.bayesian_distro} "
                        f"p={inference.bayesian_distro_probability:.3f}, "
                        f"libc={inference.provenance_consensus_libc}, "
                        f"agreement={inference.inter_tier_agreement:.2f}, "
                        f"P(tamper)={inference.bayesian_tamper_probability:.3f}"
                    ))
                    # A high tamper posterior means the image's own
                    # filesystem contradicts its declared metadata. That
                    # is exactly the state in which a base substitution
                    # chosen from that metadata is untrustworthy, so it
                    # is surfaced loudly rather than buried in JSON.
                    _tamper_threshold = float(
                        getattr(args, "tamper_threshold", 0.5) or 0.5)
                    if inference.bayesian_tamper_probability >= _tamper_threshold:
                        logger.warning(step.log(
                            f"PROVENANCE ANOMALY: P(tamper)="
                            f"{inference.bayesian_tamper_probability:.3f} "
                            f">= {_tamper_threshold}. The image's filesystem "
                            f"evidence contradicts its declared metadata; the "
                            f"SBOM says '{inference.os_family}' while the "
                            f"image looks like "
                            f"'{inference.provenance_consensus_distro}'. "
                            f"Treat the inferred base with suspicion."
                        ))
                        if args.ci_mode:
                            print(f"::warning::Provenance anomaly: P(tamper)="
                                  f"{inference.bayesian_tamper_probability:.3f}")
                else:
                    logger.info(step.log(
                        "Provenance: no tiers could be observed (image not "
                        "inspectable); inference rests on the SBOM alone"
                    ))
            except Exception as e:
                # Advisory: the fingerprint refines the SBOM answer, it
                # does not replace it. A probe failure must not stop a
                # security patch, but it IS recorded so a run that
                # decided on the SBOM alone is distinguishable in the
                # report from one that had corroborating evidence.
                logger.warning(step.log(
                    f"Provenance fingerprinting unavailable ({e}); "
                    f"proceeding on SBOM inference alone"
                ))
                provenance_summary = {"error": f"{type(e).__name__}: {e}"}

        # ── glibc floor ─────────────────────────────────────────────
        #
        # `needs_glibc` only says "this is a glibc workload". It does
        # not say WHICH glibc, and that is what decides whether a
        # candidate base can actually host the binaries: something
        # linked on ubuntu:24.04 (glibc 2.39) will not run on
        # debian:12 (2.36), and the failure is the runtime error
        # "version GLIBC_2.39 not found", after a build that succeeded.
        #
        # The patcher has always had a floor check for this, keyed on
        # `inference.min_glibc`, and nothing ever set that field, so
        # the check was dead and detect_min_glibc_from_image had no
        # callers. Scan the original image here and populate it.
        if not getattr(args, "no_glibc_floor", False) and not args.dry_run:
            try:
                from .glibc_detector import detect_min_glibc_from_image
                _req = detect_min_glibc_from_image(local_orig)
                if _req and _req.minimum_required:
                    inference.min_glibc = _req.minimum_required
                    logger.info(step.log(
                        f"glibc floor: workload requires >= "
                        f"{_req.minimum_required} "
                        f"(observed {len(_req.versions)} distinct GLIBC_* "
                        f"symbol versions); candidate bases below this "
                        f"floor will be rejected"
                    ))
                else:
                    logger.debug(
                        "No glibc floor observed for %s (static binaries, "
                        "scratch, or docker unavailable)", local_orig,
                    )
            except Exception as e:
                logger.warning(step.log(
                    f"glibc floor detection failed ({e}); candidate bases "
                    f"will not be checked against a version floor"
                ))

        # J1: In-place patching mode (alternative to base image replacement)
        if getattr(args, 'inplace', False):
            if generate_inplace_patch is None:
                logger.error(step.log("In-place patching module not available"))
                return 1

            logger.info(step.log(
                "Using IN-PLACE patching mode (OS packages)"
            ))
            inplace_result = generate_inplace_patch(
                original_image=local_orig,
                scan_result=before_scan,
                os_family=inference.os_family,
                sbom_data=sbom_before,
            )
            patch_path = save_inplace_patch(inplace_result, output_dir)
            if patch_path:
                logger.info(step.log(f"In-place patch Dockerfile saved to {patch_path}"))
            for w in inplace_result.warnings:
                logger.warning(step.log(f"In-place: {w}"))

            if args.dry_run:
                logger.info(step.log("Dry run mode: not building in-place patch"))
                return 0

            # Use the generated patch Dockerfile for the build phase
            patched_text = inplace_result.patch_dockerfile
            patched_dockerfile_path = os.path.join(output_dir, "Dockerfile.patched")
            try:
                with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                    f.write(patched_text)
            except Exception as e:
                logger.error(step.log(f"Failed to write in-place Dockerfile: {e}"))
                return 1

            base_changes = []
            patch_warnings = inplace_result.warnings
            diff_text = ""
            _primary_candidate_ref = None
            # In-place mode: skip the normal patching flow below

        else:
            # Normal mode: SBOM-driven base image replacement
            logger.info(
                step.log(
                    f"Inference result: OS={inference.os_family}, "
                    f"lang={inference.language}:{inference.language_version}, "
                    f"glibc_needed={inference.needs_glibc}, "
                    f"confidence={inference.confidence:.2f}"
                )
            )
            if inference.needs_glibc:
                logger.info(step.log("glibc dependency detected - will prefer -slim variants over Alpine"))

            # ── Candidate proposer selection (A/B experiment) ────────
            # Arm A (default): deterministic registry-driven selection.
            # Arm B (--ai-propose): Claude proposes the candidate; every
            # gate downstream is identical, so the arms differ ONLY in
            # who proposed. The decision is logged either way so the
            # experiment can attribute each outcome to its proposer.
            _ai_candidate = None
            if getattr(args, "ai_propose", False):
                try:
                    from .ai_candidate import propose_base
                    from .patcher import resolve_stage_graph
                    # The proposal is for the stage that SHIPS, which
                    # honours --target; the last FROM line is not
                    # necessarily it.
                    _stages = parse_dockerfile_stages(original_dockerfile)
                    _finals, _, _ = resolve_stage_graph(
                        _stages, target=getattr(args, "target", None))
                    _ship_base = (
                        _stages[min(_finals)].get("base_image", "")
                        if _stages and _finals else ""
                    )
                    _ai_candidate = propose_base(
                        _ship_base,
                        inference,
                        original_dockerfile,
                        cache_only=bool(getattr(args, "ai_cache_only", False)),
                    )
                    if _ai_candidate:
                        logger.info(step.log(
                            f"AI selector proposed "
                            f"'{_ai_candidate[0]}' "
                            f"(confidence {_ai_candidate[1]:.2f}) to replace "
                            f"'{_ship_base}'"
                        ))
                    else:
                        logger.warning(step.log(
                            "AI selector produced no usable proposal; this "
                            "run proceeds with deterministic selection and "
                            "is recorded as a fallback in the decision log"
                        ))
                except Exception as e:
                    logger.warning(step.log(
                        f"AI selector unavailable ({e}); deterministic "
                        f"selection used"
                    ))
                    _ai_candidate = None
                save_json(
                    {
                        "arm": "ai" if _ai_candidate else "ai-fallback",
                        "proposal": (
                            {"candidate": _ai_candidate[0],
                             "confidence": _ai_candidate[1]}
                            if _ai_candidate else None
                        ),
                    },
                    os.path.join(output_dir, "selector-decision.json"),
                )

            logger.info(step.log("Patching Dockerfile using SBOM inference"))
            base_map = load_base_mapping(args.base_mapping) if args.base_mapping else None
            patched_text, base_changes, patch_warnings, diff_text = patch_dockerfile(
                original_dockerfile,
                sbom_before,
                base_mapping=base_map,
                patch_final_only=args.patch_final_only,
                # Without this the patcher assumes the LAST stage ships.
                # A trailing debug/test stage then demotes the real
                # runtime stage to "builder", which only gets a
                # conservative tag bump, and the run patches nothing.
                target=getattr(args, "target", None),
                ai_candidate=_ai_candidate,
            )

            for warning in patch_warnings:
                logger.warning(step.log(f"Patch warning: {warning}"))

            # Snapshot the PRIMARY candidate ref before the build-retry
            # loop can rebind base_changes to a fallback rung's rewrite.
            # Cascade alternates must derive from this ref: deriving
            # slim/wolfi variants from a fallback's digest-pinned or
            # rewritten base fabricates unreachable candidates (the
            # memos regression).
            _primary_candidate_ref = (
                base_changes[-1][1] if base_changes else None)

            patched_dockerfile_path = os.path.join(output_dir, "Dockerfile.patched")
            try:
                with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                    f.write(patched_text)
                logger.info(step.log(f"Patched Dockerfile saved to {patched_dockerfile_path}"))
            except Exception as e:
                logger.error(step.log(f"Failed to write patched Dockerfile: {e}"))
                if args.ci_mode:
                    print(f"::error::Failed to write patched Dockerfile: {e}")
                return 1

        diff_path = os.path.join(output_dir, "dockerfile.diff")
        try:
            with open(diff_path, "w", encoding="utf-8") as f:
                f.write(diff_text)
        except Exception as e:
            logger.warning(step.log(f"Failed to save diff: {e}"))

        if base_changes:
            logger.info(step.log("Base image changes:"))
            for orig, new in base_changes:
                logger.info(step.log(f"  {orig} -> {new}"))

        # Dry-run check
        if args.dry_run:
            logger.info(step.log("DRY-RUN mode - skipping build, push, sign, and scan"))
            logger.info(step.log(f"Patched Dockerfile available at: {patched_dockerfile_path}"))

            report_text = _generate_markdown_report(
                {},
                base_changes,
                before_summary,
                {},
                {"resolved": [], "remaining": [], "new": []},
                {"added": [], "removed": [], "updated": []},
                True,
                [],
                patched_dockerfile_path,
                diff_text
            )
            report_file = os.path.join(output_dir, "report.md")
            with open(report_file, "w") as f:
                f.write(report_text)
            logger.info(step.log(f"Report saved to {report_file}"))
            return 0

        # ============================================================================
        # PHASE 4: BUILD PATCHED (with feedback loop)
        # ============================================================================
        step.set_phase("BUILD")

        # Under --cascade the ranked candidate loop applies to BUILD
        # failures too: a candidate that cannot build is as declined as
        # one the gate rejects, so it must not exhaust the run before
        # the alternates are tried. Without --cascade the historical
        # 2-attempt behavior is preserved so base-swap-only results
        # stay directly comparable.
        # 5 under cascade: primary + alpine-to-slim + latest-equivalent
        # + slim-variant + wolfi-equivalent, one queue rung per attempt.
        max_build_attempts = 5 if getattr(args, "cascade", False) else 2
        build_success = False
        current_patched_text = patched_text
        current_base_changes = base_changes
        fallback_queue: List[Tuple[str, Dict[str, str]]] = []
        fallback_built = False
        fallback_idx = 0
        # Transient failures (rate limit, registry 5xx, daemon hiccup)
        # are retried against the SAME target and must not consume the
        # candidate-switching budget. Counted separately so that a
        # single Docker Hub 429 cannot deprive the run of its slim
        # fallback, which was previously the common case: attempt 1
        # hits a rate limit, attempt 2 is spent re-trying the identical
        # target, and the fallback never runs.
        max_transient_retries = 3
        transient_retries = 0

        # Adaptive timeout: large multi-stage builds (Java, native exts,
        # apt-get update over slow mirrors) can take well over 5 minutes.
        # The patched build closely mirrors the original; size it as
        # twice the measured original build time, floored at the default.
        from .builder import DEFAULT_BUILD_TIMEOUT as _DBT
        patched_build_timeout = max(_DBT, int(2 * (build_time_orig or 0)))

        # Candidate attempts and transient retries are tracked
        # independently. A `for attempt in range(...)` loop cannot
        # express that, because `continue` advances the counter, so the
        # attempt index is managed explicitly here.
        attempt = 0
        while attempt < max_build_attempts:
            attempt += 1
            logger.info(step.log(
                f"Building patched image (attempt {attempt}/{max_build_attempts}, "
                f"timeout {patched_build_timeout}s)"
            ))
            success, error_cat, build_time_patched = build_image(
                local_patched, patched_dockerfile_path,
                timeout=patched_build_timeout,
                target=getattr(args, "target", None),
                cache_from=args.cache_from,
                cache_to=args.cache_to,
                buildkit=not args.no_buildkit,
                # Original context so COPY of app source/configs resolves
                # (the patched Dockerfile lives in output_dir). Prefer the
                # explicit repo-root context for sub-directory Dockerfiles.
                build_context_path=(getattr(args, "context", None)
                                    or (os.path.dirname(os.path.abspath(dockerfile_path))
                                        if dockerfile_path else None)),
            )

            if success:
                # Smoke test if enabled
                if args.smoke_test:
                    logger.info(step.log("Running smoke test on patched image"))
                    smoke_passed, smoke_msg = smoke_test_image(local_patched)
                    if not smoke_passed:
                        logger.warning(step.log(f"Smoke test FAILED: {smoke_msg}"))
                        success = False
                        error_cat = "SMOKE_TEST_FAILED"
                    else:
                        logger.info(step.log(f"Smoke test passed: {smoke_msg}"))

                # Test command if provided
                if success and args.test_cmd:
                    logger.info(step.log(f"Running test command: {args.test_cmd}"))
                    code, output = run_cmd(["docker", "run", "--rm", "--entrypoint", "", local_patched, "sh", "-c", args.test_cmd])
                    if code != 0:
                        logger.warning(step.log(f"Test command failed: {output}"))
                        success = False
                        error_cat = "TEST_CMD_FAILED"
                    else:
                        logger.info(step.log("Test command passed"))

            if success:
                build_success = True
                break

            # Build or test failed.
            #
            # If the failure looks transient (rate limit, registry 5xx,
            # docker daemon hiccup, timeout, generic network error),
            # back off and retry the SAME target — switching candidates
            # would not help and would waste the next attempt slot.
            # Otherwise treat it as a real failure of this candidate
            # and fall back to slim variants.
            from .builder import TRANSIENT_BUILD_ERRORS
            if (error_cat in TRANSIENT_BUILD_ERRORS
                    and transient_retries < max_transient_retries):
                import random as _r, time as _t
                transient_retries += 1
                # Exponential backoff with jitter. A rate limit window
                # is measured in minutes, so a flat 5s retry usually
                # burns the attempt for nothing.
                wait = min(60.0, 5.0 * (2 ** (transient_retries - 1)))
                wait *= (1.0 + _r.uniform(-0.25, 0.25))
                logger.warning(step.log(
                    f"Build attempt {attempt} failed transiently ({error_cat}); "
                    f"retrying same target in {wait:.1f}s "
                    f"(transient retry {transient_retries}/{max_transient_retries})"
                ))
                run_cmd(["docker", "rmi", "-f", local_patched])
                _t.sleep(wait)
                # Give the attempt back: the target is unchanged, so a
                # transient failure must not consume the budget that
                # exists for switching candidates.
                attempt -= 1
                continue

            if attempt < max_build_attempts:
                # Clean up failed image
                run_cmd(["docker", "rmi", "-f", local_patched])

                # Ranked fallback candidates, built once from the PRIMARY
                # candidate set. Order: the historical alpine-to-slim
                # rewrite first (unchanged), then, under --cascade, the
                # slim variant of the primary candidate and its Wolfi
                # equivalent. Each attempt consumes one queue slot.
                if not fallback_built:
                    fallback_built = True
                    _alp = {}
                    for orig, new in current_base_changes:
                        if "alpine" in new.lower():
                            slim_new = new.replace("-alpine", "-slim").replace(":alpine", ":slim-bookworm")
                            if slim_new == new:
                                # Handle cases like "alpine:3.21" -> "debian:bookworm-slim"
                                slim_new = "debian:bookworm-slim"
                            _alp[orig] = slim_new
                    if _alp:
                        fallback_queue.append(("alpine-to-slim", _alp))
                    if getattr(args, "cascade", False):
                        _sl = {orig: _slim_variant_of(new)
                               for orig, new in current_base_changes
                               if _slim_variant_of(new)}
                        if _sl:
                            fallback_queue.append(("slim-variant", _sl))
                        _wf = {orig: _wolfi_equivalent_of(new)
                               for orig, new in current_base_changes
                               if _wolfi_equivalent_of(new)}
                        if _wf:
                            fallback_queue.append(("wolfi-equivalent", _wf))
                        # Same-repo pinned-latest LAST: the loop stops at
                        # the first successful build, and a latest image
                        # that builds but remediates nothing would shadow
                        # the historically effective rungs above (the
                        # memos regression). Last preserves the prior
                        # queue's reachability exactly; this rung fires
                        # only when every older rung fails to build.
                        _lt = {}
                        for orig, new in current_base_changes:
                            _l = _latest_equivalent_of(new)
                            if _l and _l != new:
                                _lt[orig] = _l
                        if _lt:
                            fallback_queue.append(("latest-equivalent", _lt))

                slim_overrides = {}
                _fb_label = ""
                if fallback_idx < len(fallback_queue):
                    _fb_label, slim_overrides = fallback_queue[fallback_idx]
                    fallback_idx += 1
                    logger.warning(step.log(
                        f"Build attempt {attempt} failed ({error_cat}). "
                        f"Trying ranked fallback candidate: {_fb_label}"
                    ))
                    for _o, _n in slim_overrides.items():
                        logger.info(step.log(f"  Fallback: {_o} -> {_n}"))

                if slim_overrides:
                    merged_mapping = base_map.copy() if base_map else {}
                    merged_mapping.update(slim_overrides)

                    current_patched_text, current_base_changes, retry_warnings, diff_text = patch_dockerfile(
                        original_dockerfile,
                        sbom_before,
                        base_mapping=merged_mapping,
                        patch_final_only=args.patch_final_only,
                        target=getattr(args, "target", None),
                    )

                    # Also attempt package manager migration if OS changed
                    for orig, new in current_base_changes:
                        from_os = _infer_os_from_base(orig)
                        to_os = _infer_os_from_base(new)
                        if from_os and to_os and from_os != to_os:
                            try:
                                current_patched_text, migration_changes, migration_warnings = migrate_package_commands(
                                    current_patched_text, from_os, to_os
                                )
                                for w in migration_warnings:
                                    logger.warning(step.log(f"Migration: {w}"))
                            except Exception as e:
                                logger.warning(step.log(f"Package migration skipped: {e}"))

                    for w in retry_warnings:
                        logger.warning(step.log(f"Retry patch warning: {w}"))
                    patch_warnings.extend(retry_warnings)
                    base_changes = current_base_changes
                    # Rebind the canonical Dockerfile text as well, not
                    # just base_changes. Downstream consumers read
                    # patched_text: _run_cascade uses it as the
                    # base-swap starting point and create_remediation_pr
                    # puts it in the pull request. Leaving it bound to
                    # the discarded first attempt produces a PR whose
                    # body describes the fallback bases while its diff
                    # contains a Dockerfile that was never built or
                    # scanned.
                    patched_text = current_patched_text

                    try:
                        with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                            f.write(current_patched_text)
                    except Exception as e:
                        logger.error(step.log(f"Failed to write fallback Dockerfile: {e}"))
                        break
                else:
                    logger.error(step.log(
                        "No further ranked fallback candidates for this "
                        "base set. Cannot retry."))
                    break

        if not build_success:
            logger.error(step.log(f"All {max_build_attempts} build attempts failed"))
            if args.ci_mode:
                print(f"::error::All build attempts failed. Last error: {error_cat}")
            return 1

        # ============================================================================
        # PHASE 4b: SUPPLY CHAIN SCAN (optional, Layer 2)
        # ============================================================================
        supply_chain_result = None
        if getattr(args, 'supply_chain_scan', False):
            if scan_supply_chain is None:
                logger.warning("Supply chain scanner module not available, skipping")
            else:
                step.set_phase("SUPPLY-CHAIN")
                logger.info(step.log("Running supply chain integrity scan"))

                supply_chain_result = scan_supply_chain(
                    image_name=local_patched,
                    dockerfile_path=dockerfile_path,
                    output_dir=output_dir,
                    previous_lockfiles=None,
                    min_package_age_days=getattr(args, 'min_package_age_days', 7),
                )

                logger.info(step.log(
                    f"Supply chain scan: {len(supply_chain_result.findings)} findings, "
                    f"risk={supply_chain_result.overall_risk}"
                ))
                for finding in supply_chain_result.findings:
                    log_fn = logger.error if finding.severity == "CRITICAL" else logger.warning
                    log_fn(step.log(
                        f"  [{finding.severity}] {finding.check_name}: "
                        f"{finding.package_name} - {finding.description}"
                    ))

                # Reject immediately on CRITICAL supply chain findings
                if supply_chain_result.overall_risk == "CRITICAL":
                    logger.error(step.log(
                        "SUPPLY CHAIN CHECK FAILED: CRITICAL findings detected. "
                        "Image rejected before vulnerability evaluation."
                    ))
                    if args.ci_mode:
                        print("::error::Supply chain integrity check failed with CRITICAL findings")
                    run_cmd(["docker", "rmi", "-f", local_orig])
                    run_cmd(["docker", "rmi", "-f", local_patched])
                    return 1

        # ============================================================================
        # PHASE 4c: NETWORK BEHAVIOR ANALYSIS (optional, Layer 5)
        # ============================================================================
        network_result = None
        if getattr(args, 'network_monitor', False):
            if analyze_network_behavior is None:
                logger.warning("Network monitor module not available, skipping")
            else:
                step.set_phase("NETWORK")

                # Update threat feeds if requested
                if getattr(args, 'update_threat_feeds', False) and update_threat_feeds is not None:
                    logger.info(step.log("Updating threat intelligence feeds"))
                    update_threat_feeds(
                        getattr(args, 'threat_intel_dir', '~/.autopatch/threat_intel'),
                        force=True,
                    )

                # Parse allowed ports
                allowed_ports_list = None
                if getattr(args, 'allowed_ports', None):
                    try:
                        allowed_ports_list = [int(p.strip()) for p in args.allowed_ports.split(",")]
                    except ValueError:
                        logger.warning("Invalid --allowed-ports format, using defaults")

                logger.info(step.log(
                    f"Running network behavior analysis "
                    f"(duration={getattr(args, 'network_duration', 60)}s)"
                ))

                network_result = analyze_network_behavior(
                    image_name=local_patched,
                    dockerfile_path=dockerfile_path,
                    output_dir=output_dir,
                    duration_seconds=getattr(args, 'network_duration', 60),
                    test_cmd=getattr(args, 'network_test_cmd', None),
                    threat_intel_dir=getattr(args, 'threat_intel_dir', '~/.autopatch/threat_intel'),
                    allowed_ports=allowed_ports_list,
                )

                logger.info(step.log(
                    f"Network analysis: risk_score={network_result.risk_score}, "
                    f"overall={network_result.overall_risk}, "
                    f"{len(network_result.findings)} findings"
                ))
                for finding in network_result.findings:
                    log_fn = logger.error if finding.severity == "CRITICAL" else logger.warning
                    log_fn(step.log(
                        f"  [{finding.severity}] {finding.detector}: "
                        f"{finding.target} - {finding.description}"
                    ))

                # Reject if risk exceeds threshold
                threshold = getattr(args, 'network_risk_threshold', 50)
                if network_result.risk_score > threshold:
                    logger.error(step.log(
                        f"NETWORK CHECK FAILED: risk_score={network_result.risk_score} "
                        f"exceeds threshold={threshold}. Image rejected."
                    ))
                    if args.ci_mode:
                        print(
                            f"::error::Network behavior analysis detected C2 indicators "
                            f"(risk_score={network_result.risk_score})"
                        )
                    run_cmd(["docker", "rmi", "-f", local_orig])
                    run_cmd(["docker", "rmi", "-f", local_patched])
                    return 1

        # ============================================================================
        # PHASE 5: EVALUATE (scan locally, check acceptance, NO push yet)
        # ============================================================================
        step.set_phase("EVAL")
        logger.info(step.log("Scanning patched image locally for vulnerabilities"))
        try:
            # Item 8: pin the DB snapshot. The before-scan (above) refreshed
            # the Trivy DB once; the after-scan reuses that identical snapshot
            # via --skip-db-update so the before/after delta cannot be polluted
            # by a newly published advisory landing mid-run.
            after_scan = _scan_possibly_fused(
                local_patched,
                os.path.join(output_dir, "trivy-after.json"),
                output_dir=output_dir,
                phase="after",
                # Symmetry invariant: dual_scanner_active is resolved ONCE
                # before the before-scan and reused verbatim here. Scanning
                # "before" with two scanners and "after" with one would
                # subtract a Trivy-only finding set from a Trivy-union-Grype
                # set and manufacture a reduction out of nothing.
                dual=dual_scanner_active,
                skip_db_update=True,
            )
        except ScanError as e:
            logger.error(step.log(f"Scan failed: {e}"))
            if args.ci_mode:
                print(f"::error::Scan of patched image failed: {e}")
            return 1

        after_summary = summarize_vulnerabilities(after_scan)
        logger.info(step.log(f"Vulnerabilities AFTER: {after_summary}"))

        # Build a set of VEX-not-affected CVEs from the supplied VEX
        # docs (when present). This set is used by
        # --require-vex-for-new-critical and is reported alongside
        # acceptance feedback.
        vex_suppressed_set: set = set()
        if getattr(args, 'vex_suppress', None) and apply_vex_suppression is not None:
            try:
                from .vex_generator import extract_suppressed_cves, load_vex_document
                for _p in args.vex_suppress:
                    _d = load_vex_document(_p)
                    if _d:
                        vex_suppressed_set.update(extract_suppressed_cves(_d))
            except Exception as _vex_err:
                # Item 13: never silently disable an explicitly requested
                # security control. If the operator asked for VEX-gated
                # acceptance, a malformed VEX document must fail the run
                # rather than quietly turning enforcement off.
                if getattr(args, "require_vex_for_new_critical", False):
                    logger.error(step.log(
                        f"VEX load failed while --require-vex-for-new-critical "
                        f"is set; refusing to proceed with enforcement silently "
                        f"disabled: {type(_vex_err).__name__}: {_vex_err}"
                    ))
                    if args.ci_mode:
                        print(f"::error::VEX load failed: {_vex_err}")
                    return 1
                logger.warning(step.log(
                    f"VEX suppression document(s) could not be loaded; "
                    f"continuing without suppression: "
                    f"{type(_vex_err).__name__}: {_vex_err}"
                ))

        # I3: VEX suppression.
        #
        # VEX is informational by default: we compute a VEX-filtered view
        # of the after-scan for reporting, but the acceptance gate runs on
        # the *raw* after-scan so a not_affected document cannot silently
        # game the gate. Operators that explicitly trust their VEX
        # statements can opt in to feeding the filtered scan to the gate
        # by passing --vex-affects-gate.
        after_scan_vex = after_scan
        after_summary_vex = after_summary
        if getattr(args, 'vex_suppress', None) and apply_vex_suppression is not None:
            logger.info(step.log(f"Applying VEX suppression from {len(args.vex_suppress)} file(s) (informational)"))
            after_scan_vex = apply_vex_suppression(after_scan, vex_paths=args.vex_suppress)
            after_summary_vex = summarize_vulnerabilities(after_scan_vex)
            logger.info(step.log(f"Vulnerabilities AFTER (VEX-filtered): {after_summary_vex}"))
            if getattr(args, 'vex_affects_gate', False):
                logger.warning(step.log(
                    "--vex-affects-gate enabled: acceptance gate will use "
                    "VEX-filtered counts. The unfiltered counts remain in the report."
                ))
                after_scan = after_scan_vex
                after_summary = after_summary_vex

        logger.info(step.log("Generating SBOM for patched image"))
        try:
            sbom_after = generate_sbom(local_patched, os.path.join(output_dir, "sbom-after.json"))
        except ScanError as e:
            logger.warning(step.log(f"SBOM generation failed (non-critical): {e}"))
            sbom_after = {}

        # B1-B2: Dependency graph analysis (optional)
        dep_graph_summary = None
        if getattr(args, 'dep_graph', False) and build_dependency_graph is not None:
            logger.info(step.log("Building dependency graph from post-patch SBOM"))
            graph = build_dependency_graph(sbom_after)
            dep_graph_summary = summarize_graph(graph)
            save_json(dep_graph_summary, os.path.join(output_dir, "dep-graph-summary.json"))
            logger.info(step.log(
                f"Dependency graph: {graph.reachable_count} reachable, "
                f"{graph.unreachable_count} unreachable, max depth {graph.max_depth}"
            ))

            # Also extract and merge embedded SBOM vulnerabilities
            embedded_vulns = extract_embedded_vulnerabilities(sbom_after)
            if embedded_vulns:
                logger.info(step.log(f"Found {len(embedded_vulns)} embedded SBOM vulnerabilities"))

        logger.info(step.log("Checking acceptance criteria"))
        # Load optional EPSS / KEV side-channels for risk-aware gating.
        epss_data = _load_epss_file(getattr(args, "epss_file", None))
        kev_set = _load_kev_file(getattr(args, "kev_file", None))
        evidence_snapshot = _evidence_snapshot(
            getattr(args, "epss_file", None),
            getattr(args, "kev_file", None),
        )
        if args.accept_threshold == "risk" and not epss_data and not kev_set:
            logger.error(step.log(
                "--accept-threshold=risk requires --epss-file and/or --kev-file"
            ))
            return 1
        # Reachability: when --dep-graph was set, compute the reachable
        # package set from the post-patch SBOM dependency graph and
        # pass it to the gate. Without --dep-graph the gate treats
        # reachable_packages=None and falls back to whole-image counts.
        reachable_packages: Optional[set] = None
        if getattr(args, "dep_graph", False) and dep_graph_summary is not None:
            reach = dep_graph_summary.get("reachable_components") if isinstance(dep_graph_summary, dict) else None
            if reach:
                reachable_packages = {p for p in reach if isinstance(p, str)}

        if args.accept_threshold == "reachability" and reachable_packages is None:
            logger.error(step.log(
                "--accept-threshold=reachability requires --dep-graph to "
                "produce the set of reachable components"
            ))
            return 1

        # ── Runtime validation ──────────────────────────────────────
        # A rebuilt image that compiles and scans clean can still fail
        # at startup, lose a shared library, or break a service
        # endpoint. Build success is necessary but not sufficient, so
        # the image is started and exercised before the CVE arithmetic
        # is allowed to decide anything.
        runtime_result = None
        runtime_error: Optional[str] = None
        runtime_requested = not getattr(args, "no_runtime_validation", False)
        if runtime_requested:
            try:
                from .runtime_validator import validate_image as _rt_validate
                from .smoke_manifest import load_manifest as _load_smoke

                spec = None
                manifest_path = getattr(args, "smoke_manifest", None)
                if manifest_path and os.path.isfile(manifest_path):
                    try:
                        spec = _load_smoke(manifest_path).spec_for(
                            base_changes[0][1] if base_changes else local_patched
                        )
                    except Exception as e:
                        logger.warning(step.log(
                            f"Smoke manifest unusable ({e}); falling back to "
                            f"startup and introspection tiers only"
                        ))

                logger.info(step.log("Running runtime validation on patched image"))
                runtime_result = _rt_validate(local_patched, spec)
                tier_summary = ", ".join(
                    f"{t.tier.value}={t.outcome.value}"
                    for t in runtime_result.tiers
                )
                logger.info(step.log(
                    f"Runtime validation: "
                    f"{'PASS' if runtime_result.passed else 'FAIL'} "
                    f"({tier_summary}) in {runtime_result.total_duration_s:.1f}s"
                ))
                save_json(runtime_result.to_dict(),
                          os.path.join(output_dir, "runtime-validation.json"))
            except Exception as e:
                # A crash in the validator is NOT a pass.
                #
                # The gate reads runtime_result=None as "not evaluated"
                # and lets the run through on CVE arithmetic alone. That
                # is correct when the operator disabled validation with
                # --no-runtime-validation, and wrong when validation was
                # requested and then failed: the runtime gate silently
                # stopped enforcing while the operator still believed it
                # was on. Any bug in runtime_validator, a missing docker
                # socket, or an OOM would quietly convert an enforcing
                # pipeline into a non-enforcing one. The distinguishing
                # state is recorded and adjudicated below.
                runtime_error = f"{type(e).__name__}: {e}"
                logger.warning(step.log(
                    f"Runtime validation could not run ({runtime_error})"
                ))
                runtime_result = None

        # Fail closed on an errored validator unless the operator asked
        # for advisory mode. --runtime-validation-advisory and
        # --no-runtime-validation remain the two explicit, auditable
        # ways to proceed without runtime evidence.
        _runtime_enforced = not getattr(args, "runtime_validation_advisory", False)
        if runtime_error and _runtime_enforced:
            logger.error(step.log(
                f"Runtime validation was requested but did not complete "
                f"({runtime_error}). Refusing to accept the patched image on "
                f"build success alone. Re-run with "
                f"--runtime-validation-advisory to downgrade this to a "
                f"warning, or --no-runtime-validation to opt out explicitly."
            ))
            if args.ci_mode:
                print(f"::error::Runtime validation failed to run: {runtime_error}")
            return 1
        if runtime_error:
            logger.warning(step.log(
                "Runtime validation errored and advisory mode is on; "
                "acceptance proceeds WITHOUT runtime evidence."
            ))

        # ── Differential validation ─────────────────────────────────
        # Runtime validation answers "does the patched image still
        # start and serve?". It cannot answer "does it behave the same
        # as the image it replaced?" A patch that drops a CA bundle,
        # changes the default USER from appuser to root, or loses an
        # EXPOSEd port passes every startup probe and still breaks
        # production. This module compares the two images across those
        # dimensions; it was implemented and tested but never invoked,
        # so the behavioural-equivalence claim had no code behind it.
        differential_result = None
        if getattr(args, "differential_validation", True) and not args.dry_run:
            try:
                from .differential_validator import compare_images as _diff_images
                differential_result = _diff_images(local_orig, local_patched)
                _diff_summary = ", ".join(
                    f"{d.dimension.value}={d.verdict.value}"
                    for d in differential_result.dimensions
                )
                logger.info(step.log(
                    f"Differential validation: "
                    f"{'EQUIVALENT' if differential_result.equivalent else 'DIVERGENT'} "
                    f"({_diff_summary})"
                ))
                save_json(differential_result.to_dict(),
                          os.path.join(output_dir, "differential-validation.json"))
                if not differential_result.equivalent:
                    for _d in differential_result.dimensions:
                        if _d.verdict.value in ("regression", "divergent"):
                            logger.warning(step.log(
                                f"Behavioural change [{_d.dimension.value}]: "
                                f"{_d.detail}"
                            ))
            except Exception as e:
                # Advisory by design: a divergence is information for
                # the operator, not grounds to block a security patch.
                logger.warning(step.log(
                    f"Differential validation unavailable ({e})"
                ))
                differential_result = None

        # ── Multi-stage CVE attribution ─────────────────────────────
        # In a multi-stage build, CVEs in a builder stage never ship:
        # the compilers, headers and package caches that carry most of
        # them are discarded at the final COPY. Counting them in the
        # headline totals overstates both the baseline and the
        # reduction. This attributes each CVE to the stage it came from
        # so the report can separate what ships from what does not.
        #
        # Doing this HONESTLY costs one build and one scan per builder
        # stage, because a builder stage is not an image until it is
        # built with `--target`. Attributing without those scans would
        # report every builder stage as having zero CVEs, which is not
        # an approximation but a fabrication, so the feature is opt-in
        # via --multistage-attribution rather than silently degraded.
        multistage_summary = None
        if getattr(args, "multistage_attribution", False) and not args.dry_run:
            try:
                from .multistage import (
                    StageScan, classify_cves_by_stage,
                    derive_final_stage_aliases, summarise,
                )
                _parsed_stages = parse_dockerfile_stages(patched_text)
                if len(_parsed_stages) > 1:
                    _final = set(derive_final_stage_aliases(
                        _parsed_stages, getattr(args, "target", None)))
                    _stage_scans: List[Any] = []
                    for _i, _s in enumerate(_parsed_stages):
                        _alias = _s.get("alias") or str(_i)
                        _is_final = _alias in _final
                        if _is_final:
                            # Already built and scanned as the shipping image.
                            _stage_scans.append(
                                StageScan(stage=_alias, is_final=True,
                                          scan=after_scan))
                            continue
                        _stage_img = f"{local_patched}-stage-{_i}"
                        _ok, _cat, _ = build_image(
                            _stage_img, patched_dockerfile_path,
                            target=_s.get("alias") or None,
                            buildkit=not args.no_buildkit,
                            build_context_path=(
                                os.path.dirname(os.path.abspath(dockerfile_path))
                                if dockerfile_path else None),
                        )
                        if not _ok:
                            logger.warning(step.log(
                                f"Stage '{_alias}' could not be built for "
                                f"attribution ({_cat}); it is omitted, so "
                                f"build-only counts are a LOWER bound"
                            ))
                            continue
                        try:
                            _stage_scans.append(StageScan(
                                stage=_alias, is_final=False,
                                scan=scan_image(
                                    _stage_img,
                                    os.path.join(output_dir,
                                                 f"trivy-stage-{_i}.json"),
                                    skip_db_update=True),
                            ))
                        finally:
                            remove_image(_stage_img, force=True)

                    multistage_summary = summarise(
                        classify_cves_by_stage(_stage_scans))
                    multistage_summary["stages_scanned"] = len(_stage_scans)
                    multistage_summary["stages_total"] = len(_parsed_stages)
                    logger.info(step.log(
                        f"Multi-stage attribution over "
                        f"{len(_stage_scans)}/{len(_parsed_stages)} stages: "
                        f"{multistage_summary['runtime_cve_count']} shipping, "
                        f"{multistage_summary['build_only_cve_count']} build-only"
                    ))
                    save_json(multistage_summary,
                              os.path.join(output_dir,
                                           "multistage-attribution.json"))
            except Exception as e:
                logger.warning(step.log(
                    f"Multi-stage attribution failed ({e}); headline counts "
                    f"remain whole-image and are unaffected"
                ))
                multistage_summary = None

        # Build the applicability policy the gate reasons under. Default
        # scopes out kernel-space and no-fix findings (the container
        # cannot be exploited through a host-kernel CVE, and a no-fix
        # CVE has no version to move to; fielded admission controllers
        # gate on findings with an available fix for the same reason).
        # --applicability kernel-only keeps no-fix findings in the gate;
        # --applicability literal recovers the raw-scanner gate of the
        # paper's literal Eq. (1). KEV overrides every exclusion.
        from .applicability import ApplicabilityPolicy
        _appl_mode = getattr(args, "applicability", "default")
        if _appl_mode == "literal":
            _applicability_policy = ApplicabilityPolicy.literal()
        else:
            # kernel-space is always on outside literal mode. The other
            # rules layer on per requested mode; each needs its evidence.
            _applicability_policy = ApplicabilityPolicy(
                exclude_kernel_space=True,
                exclude_no_fix=(_appl_mode in ("default", "nofix")),
                exclude_unreachable=(reachable_packages is not None
                                     and _appl_mode == "reachability"),
                reachable_packages=reachable_packages,
                exclude_low_exploitability=(epss_data is not None
                                            and _appl_mode == "epss"),
                epss_data=epss_data,
                epss_threshold=getattr(args, "epss_safe_threshold", 0.01),
            )
        logger.info(step.log(
            f"Applicability policy: {_applicability_policy.describe()}"
        ))

        accepted, acceptance_reasons = check_acceptance_criteria(
            before_scan, after_scan,
            threshold=args.accept_threshold,
            epss_data=epss_data,
            kev_set=kev_set,
            epss_safe_threshold=getattr(args, "epss_safe_threshold", 0.01),
            min_risk_reduction=getattr(args, "min_risk_reduction", 0.0),
            reachable_packages=reachable_packages,
            demote_local_av=not getattr(args, "no_demote_local_av", False),
            demote_adjacent_av=getattr(args, "demote_adjacent_av", False),
            min_posture_score=getattr(args, "min_posture_score", None),
            require_vex_not_affected=getattr(args, "require_vex_for_new_critical", False),
            vex_not_affected_cves=vex_suppressed_set,
            runtime_result=runtime_result,
            require_runtime_ok=_runtime_enforced,
            applicability_policy=_applicability_policy,
        )
        # ── Multi-architecture verification ─────────────────────────
        # The gate above judged ONE image, built on whatever
        # architecture this runner happens to be. That verdict does not
        # transfer to other platforms, so when the operator names them
        # each is built, scanned and gated under the identical
        # criterion.
        multiarch_summary = None
        if getattr(args, "platforms", None) and not args.dry_run:
            step.set_phase("MULTIARCH")
            logger.info(step.log(
                f"Verifying the substitution on {args.platforms}"
            ))
            try:
                multiarch_summary = _verify_across_platforms(
                    platforms_spec=args.platforms,
                    patched_dockerfile_path=patched_dockerfile_path,
                    build_context_path=(
                        os.path.dirname(os.path.abspath(dockerfile_path))
                        if dockerfile_path else None),
                    output_dir=output_dir,
                    image_prefix=local_patched,
                    target=getattr(args, "target", None),
                    before_scan=before_scan,
                    accept_kwargs=dict(
                        threshold=args.accept_threshold,
                        epss_data=epss_data,
                        kev_set=kev_set,
                        epss_safe_threshold=getattr(
                            args, "epss_safe_threshold", 0.01),
                        min_risk_reduction=getattr(
                            args, "min_risk_reduction", 0.0),
                        reachable_packages=reachable_packages,
                        demote_local_av=not getattr(
                            args, "no_demote_local_av", False),
                        demote_adjacent_av=getattr(
                            args, "demote_adjacent_av", False),
                        min_posture_score=getattr(
                            args, "min_posture_score", None),
                        # Same applicability policy as the primary gate:
                        # a platform must not be judged on a finding set
                        # the primary verdict was not judged on.
                        applicability_policy=_applicability_policy,
                    ),
                )
            except ValueError as e:
                logger.error(step.log(f"--platforms rejected: {e}"))
                return 1

            # A platform that fails is a platform on which this
            # substitution is not safe, so it revokes the acceptance
            # rather than being filed as a note.
            if multiarch_summary is None:
                accepted = False
                acceptance_reasons.append(
                    "multi-architecture verification was requested but could "
                    "not run (docker buildx unavailable)"
                )
            elif not multiarch_summary.get("all_accepted"):
                accepted = False
                _bad = [p["platform"] for p in multiarch_summary["platforms"]
                        if not p["accepted"]]
                acceptance_reasons.append(
                    f"rejected on {', '.join(_bad)}; the substitution is "
                    f"verified only on the platforms that passed"
                )

        # Split feedback into hard rejections and informational warnings.
        _hard = [r for r in acceptance_reasons if not r.startswith("[WARNING]")]
        _warns = [r.replace("[WARNING] ", "", 1)
                  for r in acceptance_reasons if r.startswith("[WARNING]")]

        # Warnings always surface, regardless of accept/reject outcome.
        for w in _warns:
            logger.warning(step.log(f"acceptance note: {w}"))
            if args.ci_mode:
                print(f"::warning::{w}")

        # Ranked alternate bases: candidate refs derive from the
        # PRIMARY candidate snapshot (deriving them from a fallback
        # rung's digest-pinned rewrite fabricates unreachable refs),
        # while the replace target is the CURRENT text's base so the
        # FROM substitution actually matches. Pinned-latest first
        # (largest remediation headroom), then slim, then Wolfi; under
        # best-of the order only affects logging, every alternate is
        # evaluated.
        def _cascade_alternates() -> List[Tuple[str, str, str]]:
            alts: List[Tuple[str, str, str]] = []
            if base_changes:
                _replace_ref = base_changes[-1][1]
                _source_ref = _primary_candidate_ref or _replace_ref
                _latest = _latest_equivalent_of(_source_ref)
                if _latest and _latest != _replace_ref:
                    alts.append(
                        ("alt_base_latest", _replace_ref, _latest))
                _slim = _slim_variant_of(_source_ref)
                if _slim and _slim != _replace_ref:
                    alts.append(
                        ("alt_base_slim", _replace_ref, _slim))
                _wolfi = _wolfi_equivalent_of(_source_ref)
                if _wolfi and _wolfi != _replace_ref:
                    alts.append(
                        ("alt_base_wolfi", _replace_ref, _wolfi))
            return alts

        def _cascade_run(
                incumbent: Optional[Tuple[int, int, int]]
        ) -> CascadeOutcome:
            return _run_cascade(
                args=args,
                output_dir=output_dir,
                step=step,
                base_image_name=base_image_name,
                run_id=run_id,
                local_orig=local_orig,
                before_scan=before_scan,
                sbom_before=sbom_before or {},
                inference=inference,
                patched_text_base_swap=patched_text,
                after_scan_base_swap=after_scan,
                epss_data=epss_data,
                kev_set=kev_set,
                patched_build_timeout=patched_build_timeout,
                applicability_policy=_applicability_policy,
                alternate_bases=_cascade_alternates(),
                incumbent_key=incumbent,
            )

        _cascade_winner: Optional[CascadeOutcome] = None
        if accepted:
            logger.info(step.log("ACCEPTANCE CHECK PASSED"))

            # ---- CASCADE IMPROVER (best-of-k) ----
            # The accepted primary candidate is the incumbent. When it
            # leaves applicable findings on the table, the ranked
            # alternates get a turn; one is adopted only when it passes
            # the same gate AND strictly improves the selection key
            # (applicable, fixable-os, raw), so this pass can never
            # make an accepted outcome worse.
            if getattr(args, "cascade", False):
                _inc = _selection_key(
                    after_scan, _applicability_policy, kev_set)
                if _inc is not None and (_inc[0] > 0 or _inc[1] > 0):
                    logger.info(step.log(
                        f"Cascade improver: accepted candidate leaves "
                        f"applicable/fixable-os/raw {_inc}; evaluating "
                        f"ranked alternates"))
                    cascade = _cascade_run(_inc)
                    for note in cascade.feedback:
                        logger.info(step.log(f"cascade: {note}"))
                    if cascade.accepted:
                        _cascade_winner = cascade
        else:
            logger.error(step.log("ACCEPTANCE CHECK FAILED"))
            for reason in _hard:
                logger.error(step.log(f"  - {reason}"))
            if args.ci_mode:
                for reason in _hard:
                    print(f"::error::{reason}")

            # ---- CASCADE PATH (rejection recovery) ----
            # Alternate bases plus the in-place OS upgrade strategy get
            # a turn before failing the run; the best gate-passer wins.
            if getattr(args, "cascade", False):
                logger.info(step.log(
                    "Acceptance rejected; cascade enabled, trying alternate strategies"
                ))
                cascade = _cascade_run(None)
                for note in cascade.feedback:
                    logger.info(step.log(f"cascade: {note}"))

                if cascade.accepted:
                    _cascade_winner = cascade
                    accepted = True
                else:
                    logger.error(step.log("Cascade exhausted; no strategy passed acceptance"))
                    if args.ci_mode:
                        print("::error::Cascade exhausted; no strategy passed acceptance")

            if not accepted:
                # Rejected: cleanup and exit without pushing
                logger.info(step.log("Cleanup (rejected)"))
                run_cmd(["docker", "rmi", "-f", local_orig])
                run_cmd(["docker", "rmi", "-f", local_patched])
                logger.info(step.log("Pipeline failed acceptance check. Not pushing or signing."))
                return 1

        if _cascade_winner is not None:
            cascade = _cascade_winner
            # Promote the cascade winner to act as the patched image
            # for the publish/sign phases below.
            logger.info(step.log(
                f"Cascade strategy {cascade.strategy!r} selected; "
                f"continuing with publish/sign on {cascade.image_tag}"
            ))
            # Release the superseded candidate's image; the cascade
            # produced a different tag we now treat as canonical.
            run_cmd(["docker", "rmi", "-f", local_patched])
            local_patched = cascade.image_tag
            patched_dockerfile_path = cascade.dockerfile_path or patched_dockerfile_path
            after_scan = cascade.after_scan or after_scan
            if cascade.sbom_after:
                sbom_after = cascade.sbom_after
            if cascade.build_time is not None:
                build_time_patched = cascade.build_time

            # Persist the winner's artifacts under the canonical names.
            # Post-hoc analysis reads trivy-after.json / sbom-after.json
            # / the patched Dockerfile text for THE accepted image;
            # leaving the superseded candidate's files in place silently
            # corrupts every downstream reduction computation.
            try:
                with open(os.path.join(output_dir, "trivy-after.json"),
                          "w", encoding="utf-8") as f:
                    json.dump(after_scan, f, indent=2)
                if cascade.sbom_after:
                    with open(os.path.join(output_dir, "sbom-after.json"),
                              "w", encoding="utf-8") as f:
                        json.dump(sbom_after, f, indent=2)
            except OSError as e:
                logger.warning(step.log(
                    f"Could not persist cascade winner artifacts: {e}"))
            if cascade.dockerfile_path:
                try:
                    with open(cascade.dockerfile_path, "r",
                              encoding="utf-8") as f:
                        patched_text = f.read()
                except OSError:
                    pass
            after_summary = summarize_vulnerabilities(after_scan)
            logger.info(step.log(
                f"Vulnerabilities AFTER (cascade winner): {after_summary}"))
            accepted = True

        logger.info(step.log("Computing metrics"))
        vulns_diff = diff_vulnerabilities(before_scan, after_scan)
        sbom_diff = diff_sbom(sbom_before or {}, sbom_after or {})

        before_size = measure_image_size(local_orig)
        after_size = measure_image_size(local_patched)

        metrics = compute_metrics(
            before_scan, after_scan,
            sbom_before or {}, sbom_after or {},
            before_size=before_size,
            after_size=after_size,
            build_time=build_time_patched
        )

        # Enrich metrics with supply chain and network results
        if supply_chain_result is not None:
            metrics["supply_chain_findings_count"] = len(supply_chain_result.findings)
            metrics["supply_chain_critical_count"] = sum(
                1 for f in supply_chain_result.findings if f.severity == "CRITICAL"
            )
            metrics["supply_chain_risk"] = supply_chain_result.overall_risk
        if network_result is not None:
            metrics["network_risk_score"] = network_result.risk_score
            metrics["network_findings_count"] = len(network_result.findings)
            metrics["network_overall_risk"] = network_result.overall_risk

        # ============================================================================
        # PHASE 6: PUBLISH (only if accepted)
        # ============================================================================
        step.set_phase("PUSH")
        if getattr(args, "no_push", False):
            # Evaluation environments have no registry. The accepted image
            # exists locally with full artifacts; publishing it is not part
            # of the measurement, so its absence must not fail the run.
            logger.info(step.log(
                "Skipping registry publish (--no-push); accepted image "
                f"remains available locally as {local_patched}"
            ))
        else:
            logger.info(step.log("Tagging and pushing patched image to registry"))
            if not tag_image(local_patched, registry_patched):
                logger.error(step.log("Failed to tag image"))
                if args.ci_mode:
                    print("::error::Failed to tag image")
                return 1

            push_result = push_image(registry_patched, insecure_registry=args.insecure_registry)
            if not push_result.success:
                logger.error(step.log(f"Failed to push image: {push_result.error}"))
                if args.ci_mode:
                    print(f"::error::Failed to push image: {push_result.error}")
                return 1
            if push_result.digest:
                logger.info(step.log(
                    f"Registry-issued manifest digest: {push_result.digest}"
                ))

        logger.info(step.log("Retrieving image digest from local image"))
        digest_ref = get_image_digest(local_patched)
        if not digest_ref:
            logger.error(step.log("Could not retrieve image digest"))
            if args.ci_mode:
                print("::error::Could not retrieve image digest")
            return 1
        logger.info(step.log(f"Image digest: {digest_ref}"))

        # Sign and verify
        step.set_phase("SIGN")
        if signing_mode != "none":
            logger.info(step.log(f"Signing image ({signing_mode})"))
            try:
                sign_image(digest_ref, signing_mode, insecure_registry=args.insecure_registry)
                verify_image(digest_ref, signing_mode, insecure_registry=args.insecure_registry)
                logger.info(step.log("Image signed and verified"))
            except (SigningError, VerificationError) as e:
                logger.error(step.log(f"Signing/verification failed: {e}"))
                if args.ci_mode:
                    print(f"::error::Signing failed: {e}")
                return 1

        # Attach SBOM
        if sbom_after and signing_mode != "none":
            logger.info(step.log("Attaching SBOM to image"))
            try:
                attach_sbom(digest_ref, os.path.join(output_dir, "sbom-after.json"), signing_mode, insecure_registry=args.insecure_registry)
                logger.info(step.log("SBOM attached"))
            except Exception as e:
                logger.warning(step.log(f"SBOM attachment failed (non-critical): {e}"))

        # ============================================================================
        # PHASE 7: REPORT
        # ============================================================================
        step.set_phase("REPORT")
        logger.info(step.log("Generating report"))
        if report_format == "json":
            report_text = _generate_json_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, get_signing_log(),
                supply_chain_result=supply_chain_result,
                network_result=network_result,
                provenance_summary=provenance_summary,
            )
        elif report_format == "markdown":
            report_text = _generate_markdown_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, accepted, acceptance_reasons,
                patched_dockerfile_path, diff_text,
                supply_chain_result=supply_chain_result,
                network_result=network_result
            )
        else:  # html
            report_text = _generate_html_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, accepted, acceptance_reasons,
                supply_chain_result=supply_chain_result,
                network_result=network_result
            )

        logger.info(step.log("Exporting reports"))
        report_ext = {"json": "json", "markdown": "md", "html": "html"}[report_format]
        report_file = os.path.join(output_dir, f"report.{report_ext}")
        try:
            with open(report_file, "w") as f:
                f.write(report_text)
            logger.info(step.log(f"Report saved to {report_file}"))
        except Exception as e:
            logger.error(step.log(f"Failed to save report: {e}"))

        # Print report to stdout
        print(report_text)

        logger.info(step.log("Exporting metrics"))
        metrics_json = os.path.join(output_dir, "metrics.json")
        metrics_csv = os.path.join(output_dir, "metrics.csv")

        try:
            save_json(metrics, metrics_json)
            save_csv([metrics], metrics_csv)
            logger.info(step.log(f"Metrics saved to {metrics_json} and {metrics_csv}"))
        except Exception as e:
            logger.warning(step.log(f"Failed to save metrics: {e}"))

        # Output GitHub Actions annotations if in CI mode
        if args.ci_mode:
            logger.info(step.log("Outputting GitHub Actions annotations"))
            print(f"::notice::Patched image accepted. Vulnerabilities reduced by {metrics.get('vulnerability_reduction_pct', 0):.1f}%")

        # ============================================================================
        # PHASE 8: VEX GENERATION (optional)
        # ============================================================================
        if getattr(args, 'generate_vex', False):
            step.set_phase("VEX")
            logger.info(step.log("Generating VEX documents"))
            try:
                from .vex_generator import (
                    build_vex_statements_from_diff, generate_openvex,
                    generate_cyclonedx_vex
                )
                base_change_desc = " -> ".join([f"{o} -> {n}" for o, n in base_changes]) if base_changes else ""
                vex_statements = build_vex_statements_from_diff(
                    vulns_diff, base_image_change=base_change_desc
                )
                # OpenVEX
                openvex_path = os.path.join(output_dir, "autopatch.openvex.json")
                generate_openvex(
                    product_id=local_patched,
                    product_name=local_patched,
                    statements=vex_statements,
                    output_path=openvex_path,
                )
                logger.info(step.log(f"OpenVEX document saved to {openvex_path}"))

                # CycloneDX VEX
                cdx_vex_path = os.path.join(output_dir, "sbom-after-vex.json")
                sbom_after_path = os.path.join(output_dir, "sbom-after.json")
                if os.path.exists(sbom_after_path):
                    from .utils import load_json as _load_json
                    sbom_after = _load_json(sbom_after_path)
                    generate_cyclonedx_vex(sbom_after, vex_statements, output_path=cdx_vex_path)
                    logger.info(step.log(f"CycloneDX VEX saved to {cdx_vex_path}"))
            except Exception as e:
                logger.warning(step.log(f"VEX generation failed (non-critical): {e}"))

        # ============================================================================
        # PHASE 9: ATTESTATION
        # ============================================================================
        # Two attestations are produced here:
        #  (a) The optional SLSA-shaped remediation attestation (legacy
        #      path, gated by --generate-attestation).
        #  (b) The lineage attestation (P4-26), which is ALWAYS written
        #      to disk so every run leaves a verifiable chain link
        #      behind, even with --signing-mode none or --dry-run.
        if getattr(args, 'generate_attestation', False):
            step.set_phase("ATTEST")
            logger.info(step.log("Generating remediation attestation"))
            try:
                from .vex_generator import generate_remediation_attestation
                orig_base_str = base_changes[0][0] if base_changes else ""
                new_base_str = base_changes[0][1] if base_changes else ""
                attestation_path = os.path.join(output_dir, "remediation-attestation.json")
                # Pass the digest reference when we have one. Handing a
                # bare tag here produced an in-toto subject with an
                # empty sha256, which binds the attestation to no image.
                generate_remediation_attestation(
                    image_ref=locals().get("digest_ref") or local_patched,
                    original_base=orig_base_str,
                    patched_base=new_base_str,
                    vuln_diff=vulns_diff,
                    metrics=metrics,
                    output_path=attestation_path,
                )
                logger.info(step.log(f"Attestation saved to {attestation_path}"))
            except Exception as e:
                logger.warning(step.log(f"Attestation generation failed (non-critical): {e}"))

        # Lineage attestation (P4-26): ALWAYS emit.
        step.set_phase("ATTEST")
        try:
            from .lineage import emit_lineage_attestation
            from .comparer import compute_posture_score
            # Recompute posture before/after deterministically so the
            # attestation captures the exact same components the gate
            # evaluated. We use the same EPSS/KEV and reachability
            # inputs that fed check_acceptance_criteria above so the
            # attestation never contradicts the gate's decision.
            try:
                _post_before = compute_posture_score(
                    before_scan,
                    epss_data=epss_data,
                    kev_set=kev_set,
                    reachable_packages=None,
                    snapshot=evidence_snapshot,
                )
                _post_after = compute_posture_score(
                    after_scan,
                    epss_data=epss_data,
                    kev_set=kev_set,
                    reachable_packages=reachable_packages,
                    snapshot=evidence_snapshot,
                )
                posture_before = {
                    "total": _post_before.total,
                    "kev": _post_before.kev_component,
                    "epss": _post_before.epss_component,
                    "severity": _post_before.severity_component,
                    "reachability": _post_before.reachability_component,
                    "time": _post_before.time_component,
                    "components_evaluated": _post_before.components_evaluated,
                }
                posture_after = {
                    "total": _post_after.total,
                    "kev": _post_after.kev_component,
                    "epss": _post_after.epss_component,
                    "severity": _post_after.severity_component,
                    "reachability": _post_after.reachability_component,
                    "time": _post_after.time_component,
                    "components_evaluated": _post_after.components_evaluated,
                }
            except Exception as _post_err:
                logger.debug(f"Posture recompute for attestation failed: {_post_err}")
                posture_before = {}
                posture_after = {}

            # Predecessor reference: prefer the originally pulled
            # image (which we may have resolved to a digest) and fall
            # back to the FROM line we patched against.
            predecessor_ref = locals().get("local_orig") or (
                base_changes[0][0] if base_changes else ""
            )
            # Subject reference: prefer the registry-issued digest if
            # we pushed, else the local sha256-bearing tag.
            subject_ref = (
                locals().get("digest_ref")
                or locals().get("local_patched")
                or ""
            )

            lineage = emit_lineage_attestation(
                output_dir=output_dir,
                subject_ref=subject_ref,
                predecessor_ref=predecessor_ref,
                cve_diff=vulns_diff,
                posture_before=posture_before,
                posture_after=posture_after,
                evidence_snapshot=evidence_snapshot,
                scanner_versions={
                    "trivy": locals().get("_trivy_version", ""),
                    "grype": locals().get("_grype_version", ""),
                    "cosign": locals().get("_cosign_version", ""),
                },
                pipeline_config={
                    "accept_threshold": getattr(args, "accept_threshold", None),
                    "cascade": bool(getattr(args, "cascade", False)),
                    "dep_graph": bool(getattr(args, "dep_graph", False)),
                    "min_posture_score": getattr(args, "min_posture_score", None),
                },
                # The fingerprint and posterior are the evidence behind
                # the base-image decision this attestation is about, so
                # they belong in the attested predicate. A verifier can
                # then see WHY this base was chosen, not just that it was.
                provenance=provenance_summary,
                sign=(signing_mode != "none"),
                insecure_registry=getattr(args, "insecure_registry", False),
                # Without this the lineage attestation was always signed
                # keyless, even when the run was configured with --signing-mode key.
                signing_mode=signing_mode,
            )
            logger.info(step.log(
                f"Lineage attestation written to {lineage['path']} "
                f"(chain_id={lineage['chain_id'][:12]}..., signed={lineage['signed']})"
            ))
        except Exception as e:
            logger.warning(step.log(
                f"Lineage attestation emission failed (non-critical): {e}"
            ))

        # ── Rollback manifest ───────────────────────────────────────
        # The pipeline is non-destructive by construction: the original
        # Dockerfile is never edited in place, the original image is
        # never modified, and the patched image is a NEW tag. Rollback
        # is therefore always structurally possible, but until now
        # nothing recorded what "back" is, so reverting meant a human
        # reconstructing digests from logs at the worst possible
        # moment. This manifest is written on EVERY run that produced a
        # patched image, accepted or not, and tools/rollback.py
        # consumes it.
        try:
            import hashlib as _hl
            import shutil as _sh
            _orig_df_sha = ""
            if dockerfile_path and os.path.isfile(dockerfile_path):
                with open(dockerfile_path, "rb") as _f:
                    _orig_df_sha = _hl.sha256(_f.read()).hexdigest()
                # Byte-identical copy of the INPUT Dockerfile, so the
                # restore tool has verifiable original bytes even if
                # the working-tree copy is later overwritten with the
                # patched text. Without this, rollback of the
                # Dockerfile depends on git being present and clean.
                _sh.copyfile(
                    dockerfile_path,
                    os.path.join(output_dir, "Dockerfile.original"),
                )
            save_json({
                "schema": "autopatch/rollback/v1",
                "created": datetime.now().isoformat(),
                "original": {
                    "dockerfile_path": os.path.abspath(dockerfile_path)
                                       if dockerfile_path else None,
                    "dockerfile_sha256": _orig_df_sha,
                    "image_tag": locals().get("local_orig"),
                    "image_digest": get_image_digest(
                        locals().get("local_orig") or "") or None,
                    "base_image": base_changes[0][0] if base_changes else None,
                },
                "patched": {
                    "dockerfile_path": os.path.abspath(
                        patched_dockerfile_path)
                        if locals().get("patched_dockerfile_path") else None,
                    "image_tag": locals().get("local_patched"),
                    "image_digest": locals().get("digest_ref"),
                    "base_image": base_changes[0][1] if base_changes else None,
                },
                "accepted": bool(accepted),
                "restore": {
                    "note": (
                        "The original Dockerfile was never modified; the "
                        "patched image is a separate tag. To roll back a "
                        "deployment, redeploy original.image_digest. To "
                        "roll back a merged PR, revert the commit that "
                        "changed the FROM line."
                    ),
                    "command": "python tools/rollback.py <this-file>",
                },
            }, os.path.join(output_dir, "rollback.json"))
            logger.info(step.log("Rollback manifest written to rollback.json"))
        except Exception as e:
            logger.warning(step.log(
                f"Rollback manifest emission failed (non-critical): {e}"
            ))

        # ============================================================================
        # PHASE 10: PR CREATION (optional)
        # ============================================================================
        if getattr(args, 'create_pr', False):
            step.set_phase("PR")
            logger.info(step.log("Creating remediation pull request"))
            try:
                from .pr_creator import create_remediation_pr
                pr_url = create_remediation_pr(
                    dockerfile_path=dockerfile_path,
                    original_base=base_changes[0][0] if base_changes else "",
                    patched_base=base_changes[0][1] if base_changes else "",
                    metrics=metrics,
                    vuln_diff=vulns_diff,
                    original_dockerfile=original_dockerfile,
                    patched_dockerfile=patched_text,
                    acceptance_result=(accepted, acceptance_reasons),
                    base_branch=getattr(args, 'pr_base_branch', 'main'),
                    draft=getattr(args, 'pr_draft', False),
                )
                if pr_url:
                    logger.info(step.log(f"Pull request created: {pr_url}"))
                else:
                    logger.warning(step.log("PR creation skipped or failed"))
            except Exception as e:
                logger.warning(step.log(f"PR creation failed (non-critical): {e}"))

        logger.info(step.log("Cleanup"))
        run_cmd(["docker", "rmi", "-f", local_orig])
        run_cmd(["docker", "rmi", "-f", local_patched])

        logger.info(step.log("Pipeline complete"))
        logger.info(step.log(f"All artifacts saved to: {output_dir}"))
        return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        if args.ci_mode:
            print(f"::error::Unexpected error: {e}")
        return 1

    finally:
        # Cleanup temp repo if cloned
        if temp_repo_dir and os.path.exists(temp_repo_dir):
            logger.debug(f"Cleaning up temporary directory: {temp_repo_dir}")
            shutil.rmtree(temp_repo_dir, ignore_errors=True)


if __name__ == "__main__":
    exit(main())
