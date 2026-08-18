#!/usr/bin/env python3
"""
Run the full 5-strategy AutoPatch experiment with REAL Trivy scans.

Strategies:
  A. Scan-Only        — build original, scan, record baseline (VR = 0%)
  B. Naïve :latest    — rewrite all FROM to :latest, rebuild, rescan
  C. Copacetic        — run copa patch on the built image, rescan
  D. Docker Scout     — get Scout recommendations, apply, rescan
  E. AutoPatch        — full SBOM-driven pipeline: infer OS, rewrite, rebuild, rescan

For each strategy × image, records:
  - build_success, build_time_seconds, error_category
  - vulns_before (total + per-severity), vulns_after (total + per-severity)
  - reduction_percentage, new_vulns_introduced
  - image_size_before_mb, image_size_after_mb
  - acceptance_passed (AutoPatch criterion)
  - cve_ids_before, cve_ids_after (for set-containment check)

Outputs:
  results.json   — structured results for all images × strategies
  results.csv    — flat CSV for analysis
  summary.json   — aggregate statistics per strategy
"""

import argparse
import json
import csv
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("experiment")

# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def run(cmd: List[str], timeout: int = 600, capture: bool = True,
        env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr).

    env: extra environment variables merged over os.environ (used to pass
    BUILDKIT_HOST to copa without disturbing the parent process env).
    """
    log.debug(f"  $ {' '.join(cmd)}")
    proc_env = None
    if env:
        proc_env = dict(os.environ)
        proc_env.update(env)
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True,
                           timeout=timeout, env=proc_env)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"


def docker_build(tag: str, dockerfile: str, context: str = ".", timeout: int = 600) -> Tuple[bool, float, str]:
    """Build a Docker image. Returns (success, build_time_sec, error_category)."""
    start = time.time()
    code, out, err = run(
        ["docker", "build", "-t", tag, "-f", dockerfile, context],
        timeout=timeout
    )
    elapsed = time.time() - start

    if code == 0:
        return True, elapsed, ""

    # Categorize error
    combined = (out + err).lower()
    if "timeout" in combined or code == -1:
        cat = "TIMEOUT"
    elif "network" in combined or "connection" in combined or "could not resolve" in combined:
        cat = "NETWORK"
    elif "returned a non-zero code" in combined:
        cat = "RUN_FAILURE"
    elif "not found" in combined or "no such" in combined:
        cat = "IMAGE_NOT_FOUND"
    elif "permission denied" in combined:
        cat = "PERMISSION"
    elif "manifest unknown" in combined or "manifest not found" in combined:
        cat = "IMAGE_NOT_FOUND"
    else:
        cat = "UNKNOWN"

    log.warning(f"    Build failed ({cat}): {err[:200]}")
    return False, elapsed, cat


def docker_image_size_mb(tag: str) -> Optional[float]:
    """Get image size in MB."""
    code, out, _ = run(["docker", "image", "inspect", tag, "--format", "{{.Size}}"])
    if code == 0 and out.strip():
        try:
            return int(out.strip()) / (1024 * 1024)
        except ValueError:
            pass
    return None


def docker_rmi(tag: str):
    """Remove a Docker image (ignore errors)."""
    run(["docker", "rmi", "-f", tag], timeout=30)


def trivy_scan(image: str, output_file: str) -> Optional[Dict]:
    """Run Trivy vulnerability scan, return parsed JSON."""
    code, out, err = run([
        "trivy", "image",
        "--format", "json",
        "--output", output_file,
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        "--scanners", "vuln",
        "--timeout", "10m",
        image
    ], timeout=660)

    if code != 0:
        log.warning(f"    Trivy scan failed: {err[:200]}")
        return None

    try:
        with open(output_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning(f"    Failed to parse Trivy output: {e}")
        return None


def trivy_sbom(image: str, output_file: str) -> Optional[Dict]:
    """Generate CycloneDX SBOM via Trivy."""
    code, out, err = run([
        "trivy", "image",
        "--format", "cyclonedx",
        "--output", output_file,
        "--timeout", "10m",
        image
    ], timeout=660)

    if code != 0:
        log.warning(f"    SBOM generation failed: {err[:200]}")
        return None

    try:
        with open(output_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return None


def extract_vulns(scan_data: Optional[Dict]) -> Tuple[Dict[str, int], List[str]]:
    """
    Extract per-severity counts and CVE IDs from Trivy JSON output.
    Returns (severity_counts, cve_id_list).
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    cve_ids = set()

    if not scan_data:
        return counts, []

    results = scan_data.get("Results", [])
    for result in results:
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev not in counts:
                sev = "UNKNOWN"
            counts[sev] += 1
            vid = vuln.get("VulnerabilityID", "")
            if vid:
                cve_ids.add(vid)

    return counts, sorted(cve_ids)


def _resolve_buildkit_env() -> Dict[str, str]:
    """
    Copa needs BuildKit's mergeop/diffop, which are ONLY available from the
    BuildKit worker that is backed by Docker's containerd image store. That
    worker is the Docker "default" builder (the moby driver) once the daemon
    is started with features.containerd-snapshotter=true.

    A separate `docker buildx create` container builder has its OWN image
    store and therefore (a) cannot see locally-built images and (b) errors on
    mergeop. So we must NOT point copa at a buildx container. We let copa use
    its own default address (the local Docker daemon) unless the operator has
    deliberately exported BUILDKIT_HOST to something else.
    """
    host = os.environ.get("BUILDKIT_HOST")
    if host:
        return {"BUILDKIT_HOST": host}
    return {}


def copa_patch(image: str, scan_file: str, patched_tag: str) -> Tuple[bool, float, str]:
    """
    Run Copacetic (copa) to patch an image in-place.

    Strategy (strongest, fairest Copa configuration):
      1. Report-less "update all OS packages" mode (`copa patch -i img -t tag`).
         Supported on copa >= 0.6 and succeeds on the widest set of images
         because it does not depend on a specific CVE being flagged fixable.
      2. If that errors, fall back to report-driven mode (`-r <trivy.json>`),
         which fixes only the CVEs Trivy reported as having a fixed version.

    Returns (success, time_seconds, mode_or_error).
    mode_or_error is "patch-all" / "report" on success, or a short reason on
    a genuine skip (e.g. distroless / no OS package manager) — never faked.
    """
    bk_env = _resolve_buildkit_env()
    start = time.time()

    def _canonicalize_output() -> bool:
        """
        Copa succeeds by producing an image. With --platform it may write the
        result as either `<patched_tag>` or `<patched_tag>-amd64`. Trust the
        ARTIFACT, not copa's exit code (copa can return non-zero on a benign
        registry-probe warning while still emitting a valid patched image).

        If the arch-suffixed image exists, retag it to the canonical tag so the
        caller can scan `patched_tag`. Returns True iff a patched image exists.
        """
        code_c, _, _ = run(["docker", "image", "inspect", patched_tag], timeout=30)
        if code_c == 0:
            return True
        suffixed = f"{patched_tag}-amd64"
        code_s, _, _ = run(["docker", "image", "inspect", suffixed], timeout=30)
        if code_s == 0:
            run(["docker", "tag", suffixed, patched_tag], timeout=30)
            run(["docker", "rmi", "-f", suffixed], timeout=30)
            return True
        return False

    # Ordered attempts. Report-less patch-all is the strongest, broadest mode;
    # report-driven is the fallback that fixes only Trivy-flagged fixable CVEs.
    attempts: List[Tuple[str, List[str]]] = [
        ("patch-all", ["copa", "patch", "-i", image, "-t", patched_tag,
                       "--platform", "linux/amd64"]),
    ]
    if scan_file and os.path.exists(scan_file):
        attempts.append(("report", ["copa", "patch", "-i", image,
                                     "-r", scan_file, "-t", patched_tag]))

    combined = ""
    all_err = ""
    last_code = 0
    for mode, cmd in attempts:
        code, out, err = run(cmd, timeout=600, env=bk_env)
        last_code = code
        # Verify by artifact: did copa actually produce the patched image?
        if _canonicalize_output():
            return True, time.time() - start, mode
        combined = (out + err).lower()
        all_err = err[:300]

    elapsed = time.time() - start

    # No patched image was produced — classify the genuine reason, honestly.
    if "unsupported" in combined or "no package manager" in combined or \
       "distroless" in combined or "unsupported ostype" in combined or \
       "unsupported os" in combined:
        reason = "UNSUPPORTED_IMAGE"
    elif "no patchable" in combined or "no updates" in combined or \
         "no upgradable" in combined or "already up to date" in combined or \
         "no package updates found" in combined or "no package updates" in combined:
        reason = "NO_PATCHABLE_PACKAGES"
    elif "buildkit" in combined or "connection refused" in combined or \
         "failed to dial" in combined or "no such host" in combined:
        reason = "BUILDKIT_UNAVAILABLE"
    elif "timeout" in combined or last_code == -1:
        reason = "TIMEOUT"
    else:
        reason = "COPA_ERROR"

    log.warning(f"    Copa produced no patched image [{reason}]: {all_err}")
    return False, elapsed, reason


def docker_scout_recommendations(image: str) -> Optional[str]:
    """
    Get Docker Scout's recommended base image tag.
    Returns the recommended FROM line or None.
    """
    code, out, err = run([
        "docker", "scout", "recommendations", image,
        "--format", "json"
    ], timeout=120)

    if code != 0:
        # Try non-json format and parse
        code2, out2, err2 = run([
            "docker", "scout", "recommendations", image
        ], timeout=120)
        if code2 != 0:
            log.warning(f"    Scout failed: {err2[:200]}")
            return None
        # Try to extract recommended tag from text output
        for line in out2.splitlines():
            if "Tag" in line and "→" in line:
                parts = line.split("→")
                if len(parts) >= 2:
                    return parts[-1].strip()
        return None

    try:
        data = json.loads(out)
        # Extract recommended base image from Scout JSON
        recs = data.get("recommendations", [])
        if recs:
            return recs[0].get("tag", None)
    except json.JSONDecodeError:
        pass

    return None


def rewrite_from_latest(dockerfile_text: str) -> str:
    """Naïve strategy: replace all FROM tags with :latest."""
    lines = []
    for line in dockerfile_text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                rest = parts[1]
                # Handle AS alias
                as_match = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.IGNORECASE)
                if as_match:
                    base_part = as_match.group(1)
                    alias_part = as_match.group(2)
                else:
                    base_part = rest
                    alias_part = ""

                # Strip existing tag/digest
                if "@" in base_part:
                    base_name = base_part.split("@")[0]
                elif ":" in base_part:
                    base_name = base_part.split(":")[0]
                else:
                    base_name = base_part

                if base_name.lower() == "scratch":
                    lines.append(line)
                else:
                    new_from = f"FROM {base_name}:latest"
                    if alias_part:
                        new_from += f" {alias_part}"
                    lines.append(new_from)
            else:
                lines.append(line)
        else:
            lines.append(line)
    return "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════════════
# Result data class
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ImageResult:
    image_name: str
    dockerfile: str
    strategy: str
    build_success: bool = False
    build_time_sec: float = 0.0
    error_category: str = ""
    vulns_before_total: int = 0
    vulns_after_total: int = 0
    severity_before: Dict[str, int] = field(default_factory=dict)
    severity_after: Dict[str, int] = field(default_factory=dict)
    reduction_pct: float = 0.0
    new_vulns_introduced: int = 0
    image_size_before_mb: float = 0.0
    image_size_after_mb: float = 0.0
    size_delta_mb: float = 0.0
    acceptance_passed: bool = False
    cve_ids_before: List[str] = field(default_factory=list)
    cve_ids_after: List[str] = field(default_factory=list)
    notes: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ═══════════════════════════════════════════════════════════════════════════
# Main experiment logic
# ═══════════════════════════════════════════════════════════════════════════

class Experiment:
    def __init__(self, dockerfile_dir: Optional[str], output_dir: str,
                 strategies: List[str], manifest: Optional[str] = None):
        self.df_dir = Path(dockerfile_dir) if dockerfile_dir else None
        self.manifest = manifest
        self.out_dir = Path(output_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir = self.out_dir / "scans"
        self.scans_dir.mkdir(exist_ok=True)
        self.sboms_dir = self.out_dir / "sboms"
        self.sboms_dir.mkdir(exist_ok=True)
        self.strategies = strategies
        self.results: List[ImageResult] = []
        self.tmp = Path(tempfile.mkdtemp(prefix="autopatch_exp_"))
        # Build context for the image currently being processed. In stub mode
        # this is the Dockerfile's own directory; in manifest (real-repo) mode
        # it is the cloned repo's build-context directory.
        self.ctx: Optional[Path] = None

        # Add AutoPatch src to path
        src_dir = Path(__file__).parent.parent / "src"
        if str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir.parent))

    def discover(self) -> List[Tuple[str, Path, Path]]:
        """
        Return a list of (name, dockerfile_path, build_context_dir).

        Two modes:
          • manifest mode (real repos): read a JSON list of
            {"name", "dockerfile", "context"} entries produced by the repo
            collector. Each build context is that repo's own directory.
          • stub mode: glob Dockerfile.* in one dir; context is that dir.
        """
        if self.manifest:
            entries = json.load(open(self.manifest))
            out: List[Tuple[str, Path, Path]] = []
            for e in entries:
                dfp = Path(e["dockerfile"])
                ctx = Path(e.get("context") or dfp.parent)
                if dfp.is_file() and ctx.is_dir():
                    out.append((e["name"], dfp, ctx))
                else:
                    log.warning(f"  manifest entry skipped (missing df/ctx): {e.get('name')}")
            log.info(f"Loaded {len(out)} real Dockerfiles from manifest {self.manifest}")
            return out

        dfs = sorted(self.df_dir.glob("Dockerfile.*"))
        dfs = [d for d in dfs if d.name != "INDEX.md"]
        log.info(f"Found {len(dfs)} Dockerfiles")
        return [(d.name.replace("Dockerfile.", ""), d, d.parent) for d in dfs]

    def safe_tag(self, name: str, strategy: str) -> str:
        """Create a safe, EXPLICITLY-TAGGED Docker image reference.

        The explicit ':v1' tag is essential: Copa resolves a bare repo name as
        ':latest' and then fails local resolution ("object required") because it
        falls through to a registry pull. An explicit tag keeps resolution local.
        """
        safe = re.sub(r'[^a-z0-9._-]', '-', name.lower())
        return f"exp-{safe}-{strategy}:v1"

    @staticmethod
    def image_exists(tag: str) -> bool:
        code, _, _ = run(["docker", "image", "inspect", tag], timeout=30)
        return code == 0

    def scan_after_or_fail(self, r: "ImageResult", tag: str, scan_file: str,
                           total_before: int, sev_before: Dict[str, int],
                           cves_before: List[str]) -> Optional[Tuple[Dict[str, int], List[str]]]:
        """
        Scan a patched image. Returns (sev_after, cves_after) on success.

        On ANY failure — patched image missing, or Trivy returning no parseable
        result — mutates `r` to record the failure HONESTLY (no reduction, not
        accepted) and returns None. This closes the fabrication path where a
        failed scan was silently counted as 0 vulns = 100% reduction.
        """
        if not self.image_exists(tag):
            r.error_category = "PATCHED_IMAGE_MISSING"
            r.reduction_pct = 0.0
            r.vulns_after_total = total_before
            r.severity_after = dict(sev_before)
            r.cve_ids_after = list(cves_before)
            r.acceptance_passed = False
            r.notes = (r.notes + "; patched image not produced — not counted").lstrip("; ")
            return None

        scan_data = trivy_scan(tag, scan_file)
        if scan_data is None:
            r.error_category = "POST_SCAN_FAILED"
            r.reduction_pct = 0.0
            r.vulns_after_total = total_before
            r.severity_after = dict(sev_before)
            r.cve_ids_after = list(cves_before)
            r.acceptance_passed = False
            r.notes = (r.notes + "; post-patch Trivy scan failed — not counted").lstrip("; ")
            return None

        return extract_vulns(scan_data)

    def process_one(self, name: str, df_path: Path, context: Path) -> List[ImageResult]:
        """Process one Dockerfile through all enabled strategies.

        `context` is the docker build context (repo dir for real Dockerfiles).
        """
        self.ctx = context
        log.info(f"\n{'='*60}")
        log.info(f"Processing: {name}  (context={context})")
        log.info(f"{'='*60}")

        results = []

        with open(df_path, encoding="utf-8", errors="replace") as f:
            original_text = f.read()

        # ── Step 1: Build original image (shared across strategies) ──────
        orig_tag = self.safe_tag(name, "orig")
        log.info(f"  Building original: {orig_tag}")
        build_ok, build_time, build_err = docker_build(
            orig_tag, str(df_path), str(context)
        )

        if not build_ok:
            log.warning(f"  Original build FAILED ({build_err}). Skipping all strategies.")
            for strat in self.strategies:
                r = ImageResult(
                    image_name=name, dockerfile=str(df_path), strategy=strat,
                    build_success=False, error_category=build_err,
                    notes=f"Original build failed: {build_err}"
                )
                results.append(r)
            return results

        # ── Step 2: Scan original (shared baseline) ──────────────────────
        scan_orig_file = str(self.scans_dir / f"{name}_original.json")
        log.info(f"  Scanning original...")
        scan_orig = trivy_scan(orig_tag, scan_orig_file)
        sev_before, cves_before = extract_vulns(scan_orig)
        total_before = sum(sev_before.values())
        size_before = docker_image_size_mb(orig_tag) or 0.0

        log.info(f"  Baseline: {total_before} vulns (C={sev_before['CRITICAL']}, "
                 f"H={sev_before['HIGH']}, M={sev_before['MEDIUM']}, "
                 f"L={sev_before['LOW']}, U={sev_before['UNKNOWN']})")

        # ── Step 3: Generate SBOM (needed for AutoPatch) ─────────────────
        sbom_file = str(self.sboms_dir / f"{name}_sbom.json")
        sbom_data = trivy_sbom(orig_tag, sbom_file)

        # ── Strategy A: Scan-Only ────────────────────────────────────────
        if "scan-only" in self.strategies:
            log.info(f"  [A] Scan-Only")
            r = ImageResult(
                image_name=name, dockerfile=str(df_path), strategy="Scan-Only",
                build_success=True, build_time_sec=build_time,
                vulns_before_total=total_before, vulns_after_total=total_before,
                severity_before=dict(sev_before), severity_after=dict(sev_before),
                reduction_pct=0.0, new_vulns_introduced=0,
                image_size_before_mb=size_before, image_size_after_mb=size_before,
                cve_ids_before=cves_before, cve_ids_after=cves_before,
                acceptance_passed=False
            )
            results.append(r)

        # ── Strategy B: Naïve :latest ────────────────────────────────────
        if "naive" in self.strategies:
            log.info(f"  [B] Naïve :latest")
            r = self._run_naive(name, df_path, original_text,
                                sev_before, cves_before, total_before, size_before,
                                scan_orig_file)
            results.append(r)

        # ── Strategy C: Copacetic ────────────────────────────────────────
        if "copacetic" in self.strategies:
            log.info(f"  [C] Copacetic")
            r = self._run_copacetic(name, orig_tag, scan_orig_file,
                                     sev_before, cves_before, total_before, size_before)
            results.append(r)

        # ── Strategy D: Docker Scout ─────────────────────────────────────
        if "scout" in self.strategies:
            log.info(f"  [D] Docker Scout")
            r = self._run_scout(name, df_path, orig_tag, original_text,
                                sev_before, cves_before, total_before, size_before)
            results.append(r)

        # ── Strategy E: AutoPatch ────────────────────────────────────────
        if "autopatch" in self.strategies:
            log.info(f"  [E] AutoPatch")
            r = self._run_autopatch(name, df_path, original_text, sbom_data,
                                     sev_before, cves_before, total_before, size_before,
                                     scan_orig_file)
            results.append(r)

        # ── Cleanup original image ───────────────────────────────────────
        docker_rmi(orig_tag)

        return results

    def _run_naive(self, name, df_path, original_text,
                   sev_before, cves_before, total_before, size_before,
                   scan_before_file) -> ImageResult:
        """Strategy B: rewrite all FROM to :latest."""
        r = ImageResult(
            image_name=name, dockerfile=str(df_path), strategy="Naive-Latest",
            vulns_before_total=total_before, severity_before=dict(sev_before),
            image_size_before_mb=size_before, cve_ids_before=cves_before
        )

        patched_text = rewrite_from_latest(original_text)
        patched_file = self.tmp / f"Dockerfile.{name}.naive"
        patched_file.write_text(patched_text)

        tag = self.safe_tag(name, "naive")
        ok, t, err = docker_build(tag, str(patched_file), str(self.ctx))
        r.build_success = ok
        r.build_time_sec = t
        r.error_category = err

        if ok:
            scan_file = str(self.scans_dir / f"{name}_naive.json")
            scanned = self.scan_after_or_fail(r, tag, scan_file,
                                              total_before, sev_before, cves_before)
            if scanned is None:
                docker_rmi(tag)
                log.info(f"    Naive: post-scan/image failed ({r.error_category})")
                return r
            sev_after, cves_after = scanned
            r.severity_after = sev_after
            r.vulns_after_total = sum(sev_after.values())
            r.cve_ids_after = cves_after
            r.image_size_after_mb = docker_image_size_mb(tag) or 0.0
            r.size_delta_mb = r.image_size_after_mb - size_before

            if total_before > 0:
                r.reduction_pct = ((total_before - r.vulns_after_total) / total_before) * 100

            new_cves = set(cves_after) - set(cves_before)
            r.new_vulns_introduced = len(new_cves)
            r.acceptance_passed = (
                r.vulns_after_total < total_before and
                r.new_vulns_introduced == 0 and
                sev_after.get("CRITICAL", 0) <= sev_before.get("CRITICAL", 0) and
                sev_after.get("HIGH", 0) <= sev_before.get("HIGH", 0)
            )

            docker_rmi(tag)

        log.info(f"    Naive: {total_before} → {r.vulns_after_total} "
                 f"({r.reduction_pct:.1f}%), build={'OK' if r.build_success else 'FAIL'}")
        return r

    def _run_copacetic(self, name, orig_tag, scan_file,
                        sev_before, cves_before, total_before, size_before) -> ImageResult:
        """Strategy C: Copacetic in-place patching."""
        r = ImageResult(
            image_name=name, dockerfile="", strategy="Copacetic",
            vulns_before_total=total_before, severity_before=dict(sev_before),
            image_size_before_mb=size_before, cve_ids_before=cves_before
        )

        patched_tag = self.safe_tag(name, "copa")
        ok, t, mode = copa_patch(orig_tag, scan_file, patched_tag)
        r.build_time_sec = t

        if not ok:
            r.build_success = False
            r.error_category = mode  # UNSUPPORTED_IMAGE / NO_PATCHABLE_PACKAGES / BUILDKIT_UNAVAILABLE / ...
            r.vulns_after_total = total_before
            r.severity_after = dict(sev_before)
            r.cve_ids_after = cves_before
            r.notes = f"copa skip: {mode}"
            log.info(f"    Copa: skipped ({mode})")
            return r

        r.notes = f"copa mode: {mode}"

        r.build_success = True
        scan_after_file = str(self.scans_dir / f"{name}_copa.json")
        scanned = self.scan_after_or_fail(r, patched_tag, scan_after_file,
                                          total_before, sev_before, cves_before)
        if scanned is None:
            docker_rmi(patched_tag)
            log.info(f"    Copa: patched but post-scan/image failed ({r.error_category})")
            return r
        sev_after, cves_after = scanned
        r.severity_after = sev_after
        r.vulns_after_total = sum(sev_after.values())
        r.cve_ids_after = cves_after
        r.image_size_after_mb = docker_image_size_mb(patched_tag) or 0.0
        r.size_delta_mb = r.image_size_after_mb - size_before

        if total_before > 0:
            r.reduction_pct = ((total_before - r.vulns_after_total) / total_before) * 100

        new_cves = set(cves_after) - set(cves_before)
        r.new_vulns_introduced = len(new_cves)
        r.acceptance_passed = (
            r.vulns_after_total < total_before and
            r.new_vulns_introduced == 0
        )

        docker_rmi(patched_tag)
        log.info(f"    Copa: {total_before} → {r.vulns_after_total} ({r.reduction_pct:.1f}%)")
        return r

    def _run_scout(self, name, df_path, orig_tag, original_text,
                   sev_before, cves_before, total_before, size_before) -> ImageResult:
        """Strategy D: Apply Docker Scout recommended base image."""
        r = ImageResult(
            image_name=name, dockerfile=str(df_path), strategy="Docker-Scout",
            vulns_before_total=total_before, severity_before=dict(sev_before),
            image_size_before_mb=size_before, cve_ids_before=cves_before
        )

        rec_tag = docker_scout_recommendations(orig_tag)
        if not rec_tag:
            r.build_success = False
            r.error_category = "SCOUT_NO_RECOMMENDATION"
            r.vulns_after_total = total_before
            r.severity_after = dict(sev_before)
            r.cve_ids_after = cves_before
            r.notes = "Scout provided no recommendation"
            log.info(f"    Scout: no recommendation available")
            return r

        # Rewrite Dockerfile with Scout's recommended tag
        lines = []
        for line in original_text.splitlines():
            stripped = line.strip()
            if stripped.upper().startswith("FROM ") and "scratch" not in stripped.lower():
                parts = stripped.split(None, 1)
                if len(parts) == 2:
                    rest = parts[1]
                    as_match = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.IGNORECASE)
                    if as_match:
                        base_part = as_match.group(1)
                        alias_part = as_match.group(2)
                    else:
                        base_part = rest
                        alias_part = ""

                    # Get base name without tag
                    if "@" in base_part:
                        base_name = base_part.split("@")[0]
                    elif ":" in base_part:
                        base_name = base_part.split(":")[0]
                    else:
                        base_name = base_part

                    new_line = f"FROM {base_name}:{rec_tag}"
                    if alias_part:
                        new_line += f" {alias_part}"
                    lines.append(new_line)
                else:
                    lines.append(line)
            else:
                lines.append(line)
        patched_text = "\n".join(lines) + "\n"

        patched_file = self.tmp / f"Dockerfile.{name}.scout"
        patched_file.write_text(patched_text)

        tag = self.safe_tag(name, "scout")
        ok, t, err = docker_build(tag, str(patched_file), str(self.ctx))
        r.build_success = ok
        r.build_time_sec = t
        r.error_category = err

        if ok:
            scan_file = str(self.scans_dir / f"{name}_scout.json")
            scanned = self.scan_after_or_fail(r, tag, scan_file,
                                              total_before, sev_before, cves_before)
            if scanned is None:
                docker_rmi(tag)
                log.info(f"    Scout: post-scan/image failed ({r.error_category})")
                return r
            sev_after, cves_after = scanned
            r.severity_after = sev_after
            r.vulns_after_total = sum(sev_after.values())
            r.cve_ids_after = cves_after
            r.image_size_after_mb = docker_image_size_mb(tag) or 0.0
            r.size_delta_mb = r.image_size_after_mb - size_before

            if total_before > 0:
                r.reduction_pct = ((total_before - r.vulns_after_total) / total_before) * 100

            new_cves = set(cves_after) - set(cves_before)
            r.new_vulns_introduced = len(new_cves)
            r.acceptance_passed = (
                r.vulns_after_total < total_before and
                r.new_vulns_introduced == 0
            )
            docker_rmi(tag)

        log.info(f"    Scout: {total_before} → {r.vulns_after_total} "
                 f"({r.reduction_pct:.1f}%), rec={rec_tag}")
        return r

    def _run_autopatch(self, name, df_path, original_text, sbom_data,
                        sev_before, cves_before, total_before, size_before,
                        scan_before_file) -> ImageResult:
        """Strategy E: Full AutoPatch pipeline."""
        r = ImageResult(
            image_name=name, dockerfile=str(df_path), strategy="AutoPatch",
            vulns_before_total=total_before, severity_before=dict(sev_before),
            image_size_before_mb=size_before, cve_ids_before=cves_before
        )

        try:
            from src.patcher import patch_dockerfile, detect_os_family
        except ImportError:
            # Try relative import
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from src.patcher import patch_dockerfile, detect_os_family

        # Detect OS family
        os_family = detect_os_family(sbom_data)
        r.notes = f"os_family={os_family}"
        log.info(f"    OS family detected: {os_family}")

        # Patch Dockerfile
        try:
            result = patch_dockerfile(original_text, sbom_before=sbom_data)
            if isinstance(result, tuple) and len(result) >= 2:
                patched_text = result[0]
            else:
                patched_text = result
        except Exception as e:
            r.build_success = False
            r.error_category = "PATCH_FAILURE"
            r.vulns_after_total = total_before
            r.severity_after = dict(sev_before)
            r.cve_ids_after = cves_before
            r.notes += f"; patch error: {e}"
            log.warning(f"    AutoPatch: patch_dockerfile failed: {e}")
            return r

        patched_file = self.tmp / f"Dockerfile.{name}.autopatch"
        patched_file.write_text(patched_text if isinstance(patched_text, str) else str(patched_text))

        # Also save patched Dockerfile for inspection
        saved = self.out_dir / "patched_dockerfiles"
        saved.mkdir(exist_ok=True)
        (saved / f"Dockerfile.{name}").write_text(
            patched_text if isinstance(patched_text, str) else str(patched_text)
        )

        tag = self.safe_tag(name, "autopatch")
        ok, t, err = docker_build(tag, str(patched_file), str(self.ctx))
        r.build_success = ok
        r.build_time_sec = t
        r.error_category = err

        if ok:
            scan_file = str(self.scans_dir / f"{name}_autopatch.json")
            scanned = self.scan_after_or_fail(r, tag, scan_file,
                                              total_before, sev_before, cves_before)
            if scanned is None:
                docker_rmi(tag)
                log.info(f"    AutoPatch: post-scan/image failed ({r.error_category})")
                return r
            sev_after, cves_after = scanned
            r.severity_after = sev_after
            r.vulns_after_total = sum(sev_after.values())
            r.cve_ids_after = cves_after
            r.image_size_after_mb = docker_image_size_mb(tag) or 0.0
            r.size_delta_mb = r.image_size_after_mb - size_before

            if total_before > 0:
                r.reduction_pct = ((total_before - r.vulns_after_total) / total_before) * 100

            new_cves = set(cves_after) - set(cves_before)
            r.new_vulns_introduced = len(new_cves)

            # Formal acceptance criterion
            r.acceptance_passed = (
                r.vulns_after_total < total_before and
                len(new_cves) == 0 and
                sev_after.get("CRITICAL", 0) <= sev_before.get("CRITICAL", 0) and
                sev_after.get("HIGH", 0) <= sev_before.get("HIGH", 0)
            )

            docker_rmi(tag)

        log.info(f"    AutoPatch: {total_before} → {r.vulns_after_total} "
                 f"({r.reduction_pct:.1f}%), accepted={r.acceptance_passed}")
        return r

    def run_all(self):
        """Run the full experiment."""
        dockerfiles = self.discover()
        total = len(dockerfiles)

        for i, (name, df_path, ctx) in enumerate(dockerfiles, 1):
            log.info(f"\n[{i}/{total}] {name}")
            try:
                results = self.process_one(name, df_path, ctx)
                self.results.extend(results)

                # Save intermediate results after each image (crash recovery)
                self._save_results()

                # Aggressive cleanup: real multi-stage builds accumulate large
                # BuildKit caches (several GB each). Prune the builder cache and
                # dangling images after EVERY image so the disk does not fill.
                run(["docker", "builder", "prune", "-f"], timeout=120)
                run(["docker", "image", "prune", "-f"], timeout=60)
                if i % 5 == 0:
                    run(["docker", "system", "prune", "-f"], timeout=120)

            except Exception as e:
                log.error(f"FATAL error on {df.name}: {e}", exc_info=True)

        # Final save
        self._save_results()
        log.info(f"\nExperiment complete. {len(self.results)} results saved to {self.out_dir}")

    def _save_results(self):
        """Save all results to JSON and CSV."""
        # JSON
        data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "trivy_version": self._get_tool_version("trivy --version"),
                "docker_version": self._get_tool_version("docker --version"),
                "total_results": len(self.results),
                "strategies": self.strategies,
            },
            "results": [asdict(r) for r in self.results]
        }
        json_path = self.out_dir / "results.json"
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        # CSV
        csv_path = self.out_dir / "results.csv"
        if self.results:
            fieldnames = [
                "image_name", "strategy", "build_success", "build_time_sec",
                "error_category", "vulns_before_total", "vulns_after_total",
                "reduction_pct", "new_vulns_introduced",
                "crit_before", "high_before", "med_before", "low_before",
                "crit_after", "high_after", "med_after", "low_after",
                "image_size_before_mb", "image_size_after_mb", "size_delta_mb",
                "acceptance_passed", "notes"
            ]
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in self.results:
                    row = {
                        "image_name": r.image_name,
                        "strategy": r.strategy,
                        "build_success": r.build_success,
                        "build_time_sec": round(r.build_time_sec, 2),
                        "error_category": r.error_category,
                        "vulns_before_total": r.vulns_before_total,
                        "vulns_after_total": r.vulns_after_total,
                        "reduction_pct": round(r.reduction_pct, 2),
                        "new_vulns_introduced": r.new_vulns_introduced,
                        "crit_before": r.severity_before.get("CRITICAL", 0),
                        "high_before": r.severity_before.get("HIGH", 0),
                        "med_before": r.severity_before.get("MEDIUM", 0),
                        "low_before": r.severity_before.get("LOW", 0),
                        "crit_after": r.severity_after.get("CRITICAL", 0),
                        "high_after": r.severity_after.get("HIGH", 0),
                        "med_after": r.severity_after.get("MEDIUM", 0),
                        "low_after": r.severity_after.get("LOW", 0),
                        "image_size_before_mb": round(r.image_size_before_mb, 2),
                        "image_size_after_mb": round(r.image_size_after_mb, 2),
                        "size_delta_mb": round(r.size_delta_mb, 2),
                        "acceptance_passed": r.acceptance_passed,
                        "notes": r.notes,
                    }
                    writer.writerow(row)

    def _get_tool_version(self, cmd: str) -> str:
        code, out, err = run(cmd.split(), timeout=10)
        return out.strip().split("\n")[0] if code == 0 else "unknown"

    def cleanup(self):
        if self.tmp.exists():
            shutil.rmtree(self.tmp, ignore_errors=True)


def main():
    p = argparse.ArgumentParser(description="Run 5-strategy AutoPatch experiment")
    p.add_argument("--dockerfile-dir", help="Dir with stub Dockerfile.* files")
    p.add_argument("--manifest", help="JSON manifest of real repos "
                   "[{name, dockerfile, context}] (overrides --dockerfile-dir)")
    p.add_argument("--output-dir", required=True, help="Output directory")
    p.add_argument("--strategies", nargs="+",
                   default=["scan-only", "naive", "copacetic", "scout", "autopatch"],
                   choices=["scan-only", "naive", "copacetic", "scout", "autopatch"],
                   help="Strategies to run")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    if not args.manifest and not args.dockerfile_dir:
        p.error("provide either --manifest (real repos) or --dockerfile-dir (stubs)")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    exp = Experiment(args.dockerfile_dir, args.output_dir, args.strategies,
                     manifest=args.manifest)
    try:
        exp.run_all()
    finally:
        exp.cleanup()


if __name__ == "__main__":
    main()
