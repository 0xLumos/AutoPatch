#!/usr/bin/env python3
"""
Comprehensive experiment runner for AutoPatch.

Runs three patching strategies on a directory of Dockerfiles and collects metrics:
- Strategy A: Scan-Only (baseline vulnerability count)
- Strategy B: Naive (replace all base images with :latest tag)
- Strategy C: AutoPatch (full pipeline with intelligent patching)

For each strategy, records:
- Build success/failure
- Pre/post vulnerability counts by severity
- Vulnerability reduction percentage
- Build time (seconds)
- Image size delta (MB)
- New vulnerabilities introduced

Saves results as JSON and CSV. Supports parallel execution and graceful failure handling.
"""

import os
import sys
import json
import csv
import logging
import argparse
import time
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import statistics

from .scanner import scan_image, scan_image_detailed, generate_sbom
from .patcher import patch_dockerfile, detect_os_family
from .builder import build_image, remove_image, measure_image_size
from .comparer import compute_metrics, check_acceptance_criteria
from .utils import run_cmd, save_json, save_csv, load_base_mapping

logger = logging.getLogger("docker_patch_tool")


@dataclass
class StrategyResult:
    """Results for a single strategy run on a single image."""
    strategy: str
    dockerfile_path: str
    image_name: str
    build_success: bool
    build_time_seconds: Optional[float] = None
    error_category: Optional[str] = None
    vulnerabilities_before: int = 0
    vulnerabilities_after: int = 0
    severity_before: Dict[str, int] = field(default_factory=dict)
    severity_after: Dict[str, int] = field(default_factory=dict)
    reduction_percentage: float = 0.0
    new_vulnerabilities_count: int = 0
    image_size_before_mb: Optional[float] = None
    image_size_after_mb: Optional[float] = None
    image_size_delta_mb: Optional[float] = None
    acceptance_passed: bool = False
    notes: str = ""


@dataclass
class ExperimentSummary:
    """Summary statistics across all experiments."""
    total_images: int = 0
    total_runs: int = 0
    successful_builds: int = 0
    failed_builds: int = 0
    mean_reduction_pct: float = 0.0
    median_reduction_pct: float = 0.0
    std_dev_reduction_pct: float = 0.0
    total_acceptance_passed: int = 0
    total_acceptance_failed: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ExperimentRunner:
    """Orchestrates running AutoPatch strategies and collecting metrics."""

    def __init__(
        self,
        image_dir: str,
        output_dir: str,
        parallel: int = 1,
        ci_mode: bool = False,
        base_mapping_file: Optional[str] = None
    ):
        """
        Initialize experiment runner.

        Args:
            image_dir: Directory containing Dockerfiles to test
            output_dir: Directory where results will be saved
            parallel: Number of parallel workers (default: 1, sequential)
            ci_mode: If True, fail CI if acceptance criteria not met
            base_mapping_file: Optional JSON/YAML file with base image overrides
        """
        self.image_dir = Path(image_dir)
        self.output_dir = Path(output_dir)
        self.parallel = parallel
        self.ci_mode = ci_mode
        self.base_mapping = load_base_mapping(base_mapping_file) if base_mapping_file else {}
        self.results: List[StrategyResult] = []
        self.temp_dir = tempfile.mkdtemp(prefix="autopatch_")

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Experiment runner initialized: output_dir={self.output_dir}, parallel={parallel}")

    def discover_dockerfiles(self) -> List[Path]:
        """
        Discover all Dockerfiles in the image directory.

        Returns:
            Sorted list of Dockerfile paths
        """
        dockerfiles = []

        # Look for files named "Dockerfile" or "Dockerfile.*"
        for pattern in ["Dockerfile", "Dockerfile.*"]:
            dockerfiles.extend(self.image_dir.glob(pattern))

        # Also recurse subdirectories
        for dockerfile in self.image_dir.rglob("Dockerfile*"):
            if dockerfile not in dockerfiles:
                dockerfiles.append(dockerfile)

        dockerfiles = sorted(set(dockerfiles))
        logger.info(f"Discovered {len(dockerfiles)} Dockerfile(s)")
        return dockerfiles

    def run_strategy_scan_only(
        self, dockerfile_path: Path, image_name: str
    ) -> StrategyResult:
        """
        Strategy A: Scan-Only (no patching, just vulnerability baseline).

        Args:
            dockerfile_path: Path to Dockerfile
            image_name: Name to tag the built image

        Returns:
            StrategyResult with scan data
        """
        logger.info(f"[Strategy A: Scan-Only] Processing {dockerfile_path.name}")
        result = StrategyResult(
            strategy="Scan-Only",
            dockerfile_path=str(dockerfile_path),
            image_name=image_name
        )

        start_time = time.time()

        # Build original image
        build_success, error_cat, _build_time = build_image(image_name, str(dockerfile_path))
        result.build_success = build_success
        result.build_time_seconds = time.time() - start_time
        result.error_category = error_cat

        if not build_success:
            logger.warning(f"[Strategy A] Build failed: {error_cat}")
            return result

        # Measure image size
        result.image_size_before_mb = measure_image_size(image_name)

        # Scan for vulnerabilities
        try:
            scan_path = self.output_dir / f"scan_a_{image_name.replace('/', '_')}.json"
            scan_result = scan_image(image_name, str(scan_path))
            from .comparer import _count_vulnerabilities_by_severity
            counts = _count_vulnerabilities_by_severity(scan_result)
            result.severity_before = counts
            result.vulnerabilities_before = sum(counts.values())
            result.vulnerabilities_after = result.vulnerabilities_before
            result.reduction_percentage = 0.0
            result.acceptance_passed = False
            logger.info(f"[Strategy A] Scan complete: {result.vulnerabilities_before} vulns found")
        except Exception as e:
            logger.error(f"[Strategy A] Scan failed: {e}")
            result.notes = f"Scan error: {str(e)}"

        # Clean up image
        remove_image(image_name, force=True)

        return result

    def run_strategy_naive(
        self, dockerfile_path: Path, image_name: str
    ) -> StrategyResult:
        """
        Strategy B: Naive :latest tag replacement (replace all base images with :latest).

        Args:
            dockerfile_path: Path to Dockerfile
            image_name: Name to tag the patched image

        Returns:
            StrategyResult with patching and scan data
        """
        logger.info(f"[Strategy B: Naive] Processing {dockerfile_path.name}")
        result = StrategyResult(
            strategy="Naive",
            dockerfile_path=str(dockerfile_path),
            image_name=image_name
        )

        # Read original Dockerfile
        with open(dockerfile_path) as f:
            original_text = f.read()

        start_time = time.time()

        # Build original image first
        original_image_name = f"{image_name}-original"
        build_success, error_cat, _build_time = build_image(original_image_name, str(dockerfile_path))

        if not build_success:
            result.build_success = False
            result.error_category = error_cat
            logger.warning(f"[Strategy B] Original build failed: {error_cat}")
            return result

        # Scan original
        try:
            scan_before_path = self.output_dir / f"scan_b_before_{image_name.replace('/', '_')}.json"
            scan_before = scan_image(original_image_name, str(scan_before_path))
            from .comparer import _count_vulnerabilities_by_severity
            counts_before = _count_vulnerabilities_by_severity(scan_before)
            result.severity_before = counts_before
            result.vulnerabilities_before = sum(counts_before.values())
        except Exception as e:
            logger.error(f"[Strategy B] Original scan failed: {e}")
            remove_image(original_image_name, force=True)
            return result

        # Apply naive patching: replace all base images with :latest
        patched_lines = []
        for line in original_text.splitlines():
            stripped = line.strip().upper()
            if stripped.startswith("FROM "):
                # Extract base image and replace tag with :latest
                parts = line.split(None, 1)
                if len(parts) == 2:
                    from_keyword = parts[0]
                    base_part = parts[1]
                    # Remove existing tag/digest
                    if "@" in base_part:
                        base_name = base_part.split("@")[0]
                    elif ":" in base_part:
                        base_name = base_part.split(":")[0]
                    else:
                        base_name = base_part
                    # Add :latest
                    if base_name.lower() != "scratch":
                        patched_lines.append(f"{from_keyword} {base_name}:latest")
                    else:
                        patched_lines.append(line)
                else:
                    patched_lines.append(line)
            else:
                patched_lines.append(line)

        patched_text = "\n".join(patched_lines) + "\n"

        # Write patched Dockerfile to temp
        patched_dockerfile = Path(self.temp_dir) / f"Dockerfile_naive_{image_name.replace('/', '_')}"
        with open(patched_dockerfile, "w") as f:
            f.write(patched_text)

        # Build patched image
        patched_image_name = f"{image_name}-naive"
        build_success, error_cat, _build_time = build_image(patched_image_name, str(patched_dockerfile))
        result.build_success = build_success
        result.build_time_seconds = time.time() - start_time
        result.error_category = error_cat

        if not build_success:
            logger.warning(f"[Strategy B] Patched build failed: {error_cat}")
            remove_image(original_image_name, force=True)
            return result

        # Measure patched image size
        result.image_size_after_mb = measure_image_size(patched_image_name)
        if result.image_size_before_mb and result.image_size_after_mb:
            result.image_size_delta_mb = result.image_size_after_mb - result.image_size_before_mb

        # Scan patched image
        try:
            scan_after_path = self.output_dir / f"scan_b_after_{image_name.replace('/', '_')}.json"
            scan_after = scan_image(patched_image_name, str(scan_after_path))
            counts_after = _count_vulnerabilities_by_severity(scan_after)
            result.severity_after = counts_after
            result.vulnerabilities_after = sum(counts_after.values())

            # Calculate reduction
            if result.vulnerabilities_before > 0:
                result.reduction_percentage = (
                    (result.vulnerabilities_before - result.vulnerabilities_after)
                    / result.vulnerabilities_before
                ) * 100

            # Check for new vulnerabilities
            from .comparer import diff_vulnerabilities
            vuln_diff = diff_vulnerabilities(scan_before, scan_after)
            result.new_vulnerabilities_count = len(vuln_diff.get("new", []))

            # Check acceptance criteria
            accepted, reasons = check_acceptance_criteria(scan_before, scan_after)
            result.acceptance_passed = accepted
            if not accepted:
                result.notes = "; ".join(reasons)

            logger.info(f"[Strategy B] Complete: {result.vulnerabilities_before} -> {result.vulnerabilities_after} vulns, {result.reduction_percentage:.1f}% reduction")
        except Exception as e:
            logger.error(f"[Strategy B] Patched scan failed: {e}")

        # Clean up images
        remove_image(original_image_name, force=True)
        remove_image(patched_image_name, force=True)

        return result

    def run_strategy_autopatch(
        self, dockerfile_path: Path, image_name: str
    ) -> StrategyResult:
        """
        Strategy C: Full AutoPatch pipeline (intelligent patching).

        Args:
            dockerfile_path: Path to Dockerfile
            image_name: Name to tag the patched image

        Returns:
            StrategyResult with full patching and metrics
        """
        logger.info(f"[Strategy C: AutoPatch] Processing {dockerfile_path.name}")
        result = StrategyResult(
            strategy="AutoPatch",
            dockerfile_path=str(dockerfile_path),
            image_name=image_name
        )

        # Read original Dockerfile
        with open(dockerfile_path) as f:
            original_text = f.read()

        start_time = time.time()

        # Build original image
        original_image_name = f"{image_name}-original"
        build_success, error_cat, _build_time = build_image(original_image_name, str(dockerfile_path))

        if not build_success:
            result.build_success = False
            result.error_category = error_cat
            logger.warning(f"[Strategy C] Original build failed: {error_cat}")
            return result

        # Measure original image size
        result.image_size_before_mb = measure_image_size(original_image_name)

        # Scan original
        try:
            scan_before_path = self.output_dir / f"scan_c_before_{image_name.replace('/', '_')}.json"
            scan_before = scan_image(original_image_name, str(scan_before_path))
            from .comparer import _count_vulnerabilities_by_severity
            counts_before = _count_vulnerabilities_by_severity(scan_before)
            result.severity_before = counts_before
            result.vulnerabilities_before = sum(counts_before.values())

            # Generate SBOM for OS detection
            sbom_path = self.output_dir / f"sbom_c_before_{image_name.replace('/', '_')}.json"
            sbom_before = generate_sbom(original_image_name, str(sbom_path))
        except Exception as e:
            logger.error(f"[Strategy C] Original scan/SBOM failed: {e}")
            remove_image(original_image_name, force=True)
            return result

        # Apply AutoPatch patching
        try:
            patched_text, base_changes, warnings, diff_text = patch_dockerfile(
                original_text,
                sbom_before=sbom_before,
                base_mapping=self.base_mapping,
                patch_final_only=False
            )
            logger.debug(f"[Strategy C] Patched {len(base_changes)} base image(s)")
        except Exception as e:
            logger.error(f"[Strategy C] Patching failed: {e}")
            result.notes = f"Patching error: {str(e)}"
            remove_image(original_image_name, force=True)
            return result

        # Write patched Dockerfile
        patched_dockerfile = Path(self.temp_dir) / f"Dockerfile_autopatch_{image_name.replace('/', '_')}"
        with open(patched_dockerfile, "w") as f:
            f.write(patched_text)

        # Save patched Dockerfile
        patched_output = self.output_dir / f"patched_{image_name.replace('/', '_')}_Dockerfile"
        with open(patched_output, "w") as f:
            f.write(patched_text)

        # Build patched image
        patched_image_name = f"{image_name}-autopatch"
        build_success, error_cat, _build_time = build_image(patched_image_name, str(patched_dockerfile))
        result.build_success = build_success
        result.build_time_seconds = time.time() - start_time
        result.error_category = error_cat

        if not build_success:
            logger.warning(f"[Strategy C] Patched build failed: {error_cat}")
            remove_image(original_image_name, force=True)
            return result

        # Measure patched image size
        result.image_size_after_mb = measure_image_size(patched_image_name)
        if result.image_size_before_mb and result.image_size_after_mb:
            result.image_size_delta_mb = result.image_size_after_mb - result.image_size_before_mb

        # Scan patched image
        try:
            scan_after_path = self.output_dir / f"scan_c_after_{image_name.replace('/', '_')}.json"
            scan_after = scan_image(patched_image_name, str(scan_after_path))
            counts_after = _count_vulnerabilities_by_severity(scan_after)
            result.severity_after = counts_after
            result.vulnerabilities_after = sum(counts_after.values())

            # Calculate reduction
            if result.vulnerabilities_before > 0:
                result.reduction_percentage = (
                    (result.vulnerabilities_before - result.vulnerabilities_after)
                    / result.vulnerabilities_before
                ) * 100

            # Check for new vulnerabilities
            from .comparer import diff_vulnerabilities
            vuln_diff = diff_vulnerabilities(scan_before, scan_after)
            result.new_vulnerabilities_count = len(vuln_diff.get("new", []))

            # Check acceptance criteria
            accepted, reasons = check_acceptance_criteria(scan_before, scan_after)
            result.acceptance_passed = accepted
            if not accepted:
                result.notes = "; ".join(reasons)

            logger.info(f"[Strategy C] Complete: {result.vulnerabilities_before} -> {result.vulnerabilities_after} vulns, {result.reduction_percentage:.1f}% reduction, accepted={accepted}")
        except Exception as e:
            logger.error(f"[Strategy C] Patched scan failed: {e}")

        # Clean up images
        remove_image(original_image_name, force=True)
        remove_image(patched_image_name, force=True)

        return result

    def run_strategy_copacetic(
        self, dockerfile_path: Path, image_name: str
    ) -> StrategyResult:
        """
        Strategy D: Copacetic (copa) in-place OS-level patching.

        Copacetic patches vulnerabilities in-place without rebuilding the image.
        It uses Trivy scan results to identify fixable OS-level vulns and applies
        package manager updates directly to the image layers.

        Requires 'copa' CLI to be installed. If not available, records a skip.

        Args:
            dockerfile_path: Path to Dockerfile
            image_name: Name to tag the image

        Returns:
            StrategyResult with patching and scan data
        """
        logger.info(f"[Strategy D: Copacetic] Processing {dockerfile_path.name}")
        result = StrategyResult(
            strategy="Copacetic",
            dockerfile_path=str(dockerfile_path),
            image_name=image_name
        )

        # Check if copa is available
        check_code, check_output = run_cmd(["copa", "--version"])
        if check_code != 0:
            result.build_success = False
            result.notes = "copa CLI not installed; skipping Copacetic strategy"
            logger.warning(f"[Strategy D] copa not installed, skipping")
            return result

        start_time = time.time()

        # Build original image
        original_image_name = f"{image_name}-original"
        build_success, error_cat, _bt = build_image(original_image_name, str(dockerfile_path))

        if not build_success:
            result.build_success = False
            result.error_category = error_cat
            logger.warning(f"[Strategy D] Original build failed: {error_cat}")
            return result

        result.image_size_before_mb = measure_image_size(original_image_name)

        # Scan original
        try:
            scan_before_path = self.output_dir / f"scan_d_before_{image_name.replace('/', '_')}.json"
            scan_before = scan_image(original_image_name, str(scan_before_path))
            from .comparer import _count_vulnerabilities_by_severity
            counts_before = _count_vulnerabilities_by_severity(scan_before)
            result.severity_before = counts_before
            result.vulnerabilities_before = sum(counts_before.values())
        except Exception as e:
            logger.error(f"[Strategy D] Original scan failed: {e}")
            remove_image(original_image_name, force=True)
            return result

        # Run copa patch using the Trivy scan report
        patched_image_name = f"{image_name}-copa"
        try:
            copa_cmd = [
                "copa", "patch",
                "-i", original_image_name,
                "-r", str(scan_before_path),
                "-t", patched_image_name,
            ]
            copa_code, copa_output = run_cmd(copa_cmd, timeout=600)
            if copa_code != 0:
                result.build_success = False
                result.error_category = "COPA_PATCH_FAILED"
                result.notes = f"copa patch failed: {copa_output[:500]}"
                logger.warning(f"[Strategy D] copa patch failed: {copa_output[:200]}")
                remove_image(original_image_name, force=True)
                return result

            result.build_success = True
            result.build_time_seconds = time.time() - start_time
        except Exception as e:
            result.build_success = False
            result.notes = f"copa error: {str(e)}"
            remove_image(original_image_name, force=True)
            return result

        result.image_size_after_mb = measure_image_size(patched_image_name)
        if result.image_size_before_mb and result.image_size_after_mb:
            result.image_size_delta_mb = result.image_size_after_mb - result.image_size_before_mb

        # Scan patched image
        try:
            scan_after_path = self.output_dir / f"scan_d_after_{image_name.replace('/', '_')}.json"
            scan_after = scan_image(patched_image_name, str(scan_after_path))
            counts_after = _count_vulnerabilities_by_severity(scan_after)
            result.severity_after = counts_after
            result.vulnerabilities_after = sum(counts_after.values())

            if result.vulnerabilities_before > 0:
                result.reduction_percentage = (
                    (result.vulnerabilities_before - result.vulnerabilities_after)
                    / result.vulnerabilities_before
                ) * 100

            from .comparer import diff_vulnerabilities
            vuln_diff = diff_vulnerabilities(scan_before, scan_after)
            result.new_vulnerabilities_count = len(vuln_diff.get("new", []))

            accepted, reasons = check_acceptance_criteria(scan_before, scan_after)
            result.acceptance_passed = accepted
            if not accepted:
                result.notes = "; ".join(reasons)

            logger.info(
                f"[Strategy D] Complete: {result.vulnerabilities_before} -> "
                f"{result.vulnerabilities_after} vulns, "
                f"{result.reduction_percentage:.1f}% reduction"
            )
        except Exception as e:
            logger.error(f"[Strategy D] Patched scan failed: {e}")

        remove_image(original_image_name, force=True)
        remove_image(patched_image_name, force=True)

        return result

    def run_strategy_docker_scout(
        self, dockerfile_path: Path, image_name: str
    ) -> StrategyResult:
        """
        Strategy E: Docker Scout recommendations.

        Uses 'docker scout recommendations' to get suggested base image updates,
        applies the first recommendation, rebuilds, and rescans.

        Requires Docker Scout CLI plugin. If not available, records a skip.

        Args:
            dockerfile_path: Path to Dockerfile
            image_name: Name to tag the image

        Returns:
            StrategyResult with patching and scan data
        """
        logger.info(f"[Strategy E: Docker Scout] Processing {dockerfile_path.name}")
        result = StrategyResult(
            strategy="Docker Scout",
            dockerfile_path=str(dockerfile_path),
            image_name=image_name
        )

        # Check if docker scout is available
        check_code, check_output = run_cmd(["docker", "scout", "version"])
        if check_code != 0:
            result.build_success = False
            result.notes = "docker scout CLI not installed; skipping Docker Scout strategy"
            logger.warning(f"[Strategy E] docker scout not installed, skipping")
            return result

        start_time = time.time()

        # Read original Dockerfile
        with open(dockerfile_path) as f:
            original_text = f.read()

        # Build original image
        original_image_name = f"{image_name}-original"
        build_success, error_cat, _bt = build_image(original_image_name, str(dockerfile_path))

        if not build_success:
            result.build_success = False
            result.error_category = error_cat
            logger.warning(f"[Strategy E] Original build failed: {error_cat}")
            return result

        result.image_size_before_mb = measure_image_size(original_image_name)

        # Scan original with Trivy (our standard scanner)
        try:
            scan_before_path = self.output_dir / f"scan_e_before_{image_name.replace('/', '_')}.json"
            scan_before = scan_image(original_image_name, str(scan_before_path))
            from .comparer import _count_vulnerabilities_by_severity
            counts_before = _count_vulnerabilities_by_severity(scan_before)
            result.severity_before = counts_before
            result.vulnerabilities_before = sum(counts_before.values())
        except Exception as e:
            logger.error(f"[Strategy E] Original scan failed: {e}")
            remove_image(original_image_name, force=True)
            return result

        # Get Docker Scout recommendations (JSON format)
        try:
            scout_cmd = [
                "docker", "scout", "recommendations",
                "--format", "json",
                original_image_name
            ]
            scout_code, scout_output = run_cmd(scout_cmd, timeout=120)

            if scout_code != 0:
                result.build_success = False
                result.notes = f"docker scout recommendations failed: {scout_output[:300]}"
                logger.warning(f"[Strategy E] Scout recommendations failed")
                remove_image(original_image_name, force=True)
                return result

            # Parse Scout recommendations and extract the recommended base image
            import json as json_mod
            try:
                scout_data = json_mod.loads(scout_output)
            except json_mod.JSONDecodeError:
                # Scout may output non-JSON; try to extract base image from text
                scout_data = None

            recommended_base = None
            if scout_data and isinstance(scout_data, dict):
                # Navigate Scout JSON structure for recommended tag
                recs = scout_data.get("recommendations", [])
                if recs and isinstance(recs, list):
                    first_rec = recs[0]
                    if isinstance(first_rec, dict):
                        recommended_base = first_rec.get("tag") or first_rec.get("image")

            if not recommended_base:
                result.build_success = False
                result.notes = "Docker Scout returned no actionable recommendation"
                logger.warning(f"[Strategy E] No recommendation extracted")
                remove_image(original_image_name, force=True)
                return result

            # Apply the Scout recommendation: replace first FROM with recommended base
            patched_lines = []
            replaced = False
            for line in original_text.splitlines():
                stripped = line.strip()
                if not replaced and stripped.upper().startswith("FROM "):
                    parts = stripped.split()
                    alias_part = ""
                    # Preserve AS alias if present
                    for i, p in enumerate(parts):
                        if p.upper() == "AS" and i + 1 < len(parts):
                            alias_part = f" AS {parts[i + 1]}"
                            break
                    patched_lines.append(f"FROM {recommended_base}{alias_part}")
                    replaced = True
                else:
                    patched_lines.append(line)

            patched_text = "\n".join(patched_lines) + "\n"

        except Exception as e:
            result.build_success = False
            result.notes = f"Scout processing error: {str(e)}"
            remove_image(original_image_name, force=True)
            return result

        # Write patched Dockerfile and build
        patched_dockerfile = Path(self.temp_dir) / f"Dockerfile_scout_{image_name.replace('/', '_')}"
        with open(patched_dockerfile, "w") as f:
            f.write(patched_text)

        patched_image_name = f"{image_name}-scout"
        build_success, error_cat, _bt = build_image(patched_image_name, str(patched_dockerfile))
        result.build_success = build_success
        result.build_time_seconds = time.time() - start_time
        result.error_category = error_cat

        if not build_success:
            logger.warning(f"[Strategy E] Patched build failed: {error_cat}")
            remove_image(original_image_name, force=True)
            return result

        result.image_size_after_mb = measure_image_size(patched_image_name)
        if result.image_size_before_mb and result.image_size_after_mb:
            result.image_size_delta_mb = result.image_size_after_mb - result.image_size_before_mb

        # Scan patched image
        try:
            scan_after_path = self.output_dir / f"scan_e_after_{image_name.replace('/', '_')}.json"
            scan_after = scan_image(patched_image_name, str(scan_after_path))
            counts_after = _count_vulnerabilities_by_severity(scan_after)
            result.severity_after = counts_after
            result.vulnerabilities_after = sum(counts_after.values())

            if result.vulnerabilities_before > 0:
                result.reduction_percentage = (
                    (result.vulnerabilities_before - result.vulnerabilities_after)
                    / result.vulnerabilities_before
                ) * 100

            from .comparer import diff_vulnerabilities
            vuln_diff = diff_vulnerabilities(scan_before, scan_after)
            result.new_vulnerabilities_count = len(vuln_diff.get("new", []))

            accepted, reasons = check_acceptance_criteria(scan_before, scan_after)
            result.acceptance_passed = accepted
            if not accepted:
                result.notes = "; ".join(reasons)

            logger.info(
                f"[Strategy E] Complete: {result.vulnerabilities_before} -> "
                f"{result.vulnerabilities_after} vulns, "
                f"{result.reduction_percentage:.1f}% reduction"
            )
        except Exception as e:
            logger.error(f"[Strategy E] Patched scan failed: {e}")

        remove_image(original_image_name, force=True)
        remove_image(patched_image_name, force=True)

        return result

    def process_image(self, dockerfile_path: Path) -> List[StrategyResult]:
        """
        Process a single Dockerfile through all five strategies.

        Args:
            dockerfile_path: Path to Dockerfile

        Returns:
            List of StrategyResult objects (one per strategy)
        """
        image_name = f"autopatch-test-{dockerfile_path.stem}-{int(time.time())}"
        results = []

        try:
            # Strategy A: Scan-Only
            result_a = self.run_strategy_scan_only(dockerfile_path, f"{image_name}-a")
            results.append(result_a)
        except Exception as e:
            logger.error(f"Strategy A failed for {dockerfile_path}: {e}")

        try:
            # Strategy B: Naive
            result_b = self.run_strategy_naive(dockerfile_path, f"{image_name}-b")
            results.append(result_b)
        except Exception as e:
            logger.error(f"Strategy B failed for {dockerfile_path}: {e}")

        try:
            # Strategy C: AutoPatch
            result_c = self.run_strategy_autopatch(dockerfile_path, f"{image_name}-c")
            results.append(result_c)
        except Exception as e:
            logger.error(f"Strategy C failed for {dockerfile_path}: {e}")

        try:
            # Strategy D: Copacetic
            result_d = self.run_strategy_copacetic(dockerfile_path, f"{image_name}-d")
            results.append(result_d)
        except Exception as e:
            logger.error(f"Strategy D failed for {dockerfile_path}: {e}")

        try:
            # Strategy E: Docker Scout
            result_e = self.run_strategy_docker_scout(dockerfile_path, f"{image_name}-e")
            results.append(result_e)
        except Exception as e:
            logger.error(f"Strategy E failed for {dockerfile_path}: {e}")

        return results

    def run(self) -> Tuple[List[StrategyResult], ExperimentSummary]:
        """
        Run all strategies on all discovered Dockerfiles.

        Returns:
            Tuple of (all_results, summary)
        """
        dockerfiles = self.discover_dockerfiles()

        if not dockerfiles:
            logger.error("No Dockerfiles found!")
            return [], ExperimentSummary()

        logger.info(f"Processing {len(dockerfiles)} Dockerfile(s)")

        # Process images
        if self.parallel > 1:
            results = self._run_parallel(dockerfiles)
        else:
            results = self._run_sequential(dockerfiles)

        self.results = results

        # Generate summary
        summary = self._compute_summary(results)

        # Save results
        self._save_results(results, summary)

        return results, summary

    def _run_sequential(self, dockerfiles: List[Path]) -> List[StrategyResult]:
        """Run strategies sequentially."""
        all_results = []
        for i, dockerfile in enumerate(dockerfiles, 1):
            logger.info(f"Processing image {i}/{len(dockerfiles)}: {dockerfile.name}")
            results = self.process_image(dockerfile)
            all_results.extend(results)
        return all_results

    def _run_parallel(self, dockerfiles: List[Path]) -> List[StrategyResult]:
        """Run strategies in parallel using ThreadPoolExecutor."""
        all_results = []
        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            futures = {
                executor.submit(self.process_image, df): df for df in dockerfiles
            }
            for i, future in enumerate(as_completed(futures), 1):
                dockerfile = futures[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    logger.info(f"Completed {i}/{len(dockerfiles)}: {dockerfile.name}")
                except Exception as e:
                    logger.error(f"Failed to process {dockerfile.name}: {e}")
        return all_results

    def _compute_summary(self, results: List[StrategyResult]) -> ExperimentSummary:
        """Compute summary statistics from results."""
        summary = ExperimentSummary()
        summary.total_runs = len(results)

        # Count unique dockerfiles
        unique_dockerfiles = set(r.dockerfile_path for r in results)
        summary.total_images = len(unique_dockerfiles)

        # Count successes/failures
        summary.successful_builds = sum(1 for r in results if r.build_success)
        summary.failed_builds = sum(1 for r in results if not r.build_success)

        # Count acceptance
        summary.total_acceptance_passed = sum(1 for r in results if r.acceptance_passed)
        summary.total_acceptance_failed = sum(1 for r in results if not r.acceptance_passed)

        # Compute reduction statistics (only for successful builds)
        reductions = [r.reduction_percentage for r in results if r.build_success and r.reduction_percentage >= 0]
        if reductions:
            summary.mean_reduction_pct = statistics.mean(reductions)
            summary.median_reduction_pct = statistics.median(reductions)
            if len(reductions) > 1:
                summary.std_dev_reduction_pct = statistics.stdev(reductions)

        return summary

    def _save_results(self, results: List[StrategyResult], summary: ExperimentSummary) -> None:
        """Save results to JSON and CSV files."""
        # Convert to dictionaries
        results_dicts = [asdict(r) for r in results]
        summary_dict = asdict(summary)

        # Save as JSON
        json_path = self.output_dir / "results.json"
        save_json({"results": results_dicts, "summary": summary_dict}, str(json_path))
        logger.info(f"Results saved to {json_path}")

        # Save as CSV
        csv_path = self.output_dir / "results.csv"
        save_csv(results_dicts, str(csv_path))
        logger.info(f"Results saved to {csv_path}")

        # Save summary
        summary_path = self.output_dir / "summary.json"
        save_json(summary_dict, str(summary_path))
        logger.info(f"Summary saved to {summary_path}")

        # Print summary to console
        self._print_summary(summary)

    def _print_summary(self, summary: ExperimentSummary) -> None:
        """Print summary statistics to console."""
        print("\n" + "=" * 70)
        print("EXPERIMENT SUMMARY")
        print("=" * 70)
        print(f"Total images processed: {summary.total_images}")
        print(f"Total runs: {summary.total_runs}")
        print(f"Successful builds: {summary.successful_builds}")
        print(f"Failed builds: {summary.failed_builds}")
        print(f"Acceptance passed: {summary.total_acceptance_passed}")
        print(f"Acceptance failed: {summary.total_acceptance_failed}")
        print(f"\nVulnerability Reduction (successful builds only):")
        print(f"  Mean: {summary.mean_reduction_pct:.2f}%")
        print(f"  Median: {summary.median_reduction_pct:.2f}%")
        print(f"  Std Dev: {summary.std_dev_reduction_pct:.2f}%")
        print(f"\nResults saved to: {self.output_dir}")
        print("=" * 70 + "\n")

        # In CI mode, fail if acceptance criteria not met
        if self.ci_mode:
            if summary.total_acceptance_failed > 0:
                logger.error("CI mode: Some acceptance criteria were not met!")
                sys.exit(1)
            else:
                logger.info("CI mode: All acceptance criteria passed!")

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            logger.debug(f"Cleaned up temp directory: {self.temp_dir}")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Run AutoPatch strategies and collect metrics"
    )
    parser.add_argument(
        "--image-dir",
        required=True,
        help="Directory containing Dockerfiles to test"
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where results will be saved"
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of parallel workers (default: 1)"
    )
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="Fail CI if acceptance criteria not met"
    )
    parser.add_argument(
        "--base-mapping",
        help="Optional JSON/YAML file with base image overrides"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Run experiment
    runner = ExperimentRunner(
        image_dir=args.image_dir,
        output_dir=args.output_dir,
        parallel=args.parallel,
        ci_mode=args.ci_mode,
        base_mapping_file=args.base_mapping
    )

    try:
        results, summary = runner.run()
        logger.info("Experiment completed successfully")
    except Exception as e:
        logger.error(f"Experiment failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        runner.cleanup()


if __name__ == "__main__":
    main()
