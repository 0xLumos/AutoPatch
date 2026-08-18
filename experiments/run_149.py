#!/usr/bin/env python3
"""
Run AutoPatch 3-strategy experiment on all 149 images.
Strategies: Scan-Only, Naive-Latest, AutoPatch.
Scans base images directly (no Dockerfile build) to avoid COPY failures.
Cleans up aggressively to stay within disk limits.
Saves results incrementally for crash recovery.
"""

import json
import csv
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("experiment.log")
    ]
)
log = logging.getLogger("exp149")

# Add src to path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR.parent) not in sys.path:
    sys.path.insert(0, str(SRC_DIR.parent))


def run(cmd, timeout=600):
    log.debug(f"  $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -2, "", f"Not found: {cmd[0]}"


def docker_pull(image, timeout=300):
    start = time.time()
    code, out, err = run(["docker", "pull", image], timeout=timeout)
    elapsed = time.time() - start
    if code == 0:
        return True, elapsed
    log.warning(f"  Pull failed for {image}: {err[:200]}")
    return False, elapsed


def docker_rmi(image):
    run(["docker", "rmi", "-f", image], timeout=30)


def docker_size_mb(image):
    code, out, _ = run(["docker", "image", "inspect", image, "--format", "{{.Size}}"])
    if code == 0 and out.strip():
        try:
            return round(int(out.strip()) / (1024 * 1024), 2)
        except ValueError:
            pass
    return 0.0


def trivy_scan(image, output_file):
    code, out, err = run([
        "trivy", "image", "--format", "json", "--output", output_file,
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        "--scanners", "vuln", "--timeout", "10m", image
    ], timeout=660)
    if code != 0:
        log.warning(f"  Trivy failed for {image}: {err[:200]}")
        return None
    try:
        with open(output_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning(f"  Parse error: {e}")
        return None


def trivy_sbom(image, output_file):
    code, out, err = run([
        "trivy", "image", "--format", "cyclonedx", "--output", output_file,
        "--timeout", "10m", image
    ], timeout=660)
    if code != 0:
        return None
    try:
        with open(output_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return None


def extract_vulns(scan_data):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    cve_ids = set()
    if not scan_data:
        return counts, []
    for result in scan_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev not in counts:
                sev = "UNKNOWN"
            counts[sev] += 1
            vid = vuln.get("VulnerabilityID", "")
            if vid:
                cve_ids.add(vid)
    return counts, sorted(cve_ids)


def extract_from_image(dockerfile_path):
    """Extract the first FROM image from a Dockerfile."""
    with open(dockerfile_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.upper().startswith("FROM "):
                parts = stripped.split()
                if len(parts) >= 2:
                    img = parts[1]
                    # Remove AS alias
                    return img
    return None


def rewrite_to_latest(image):
    """Naive: strip tag, add :latest."""
    if "@" in image:
        base = image.split("@")[0]
    elif ":" in image:
        base = image.split(":")[0]
    else:
        base = image
    if base.lower() == "scratch":
        return None
    return f"{base}:latest"


def autopatch_image(dockerfile_text, sbom_data):
    """Use AutoPatch patcher to determine replacement."""
    try:
        from src.patcher import patch_dockerfile
        result = patch_dockerfile(dockerfile_text, sbom_before=sbom_data)
        if isinstance(result, tuple) and len(result) >= 1:
            patched_text = result[0]
        else:
            patched_text = result

        # Extract FROM from patched text
        if isinstance(patched_text, str):
            for line in patched_text.splitlines():
                stripped = line.strip()
                if stripped.upper().startswith("FROM "):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception as e:
        log.warning(f"  AutoPatch patcher error: {e}")
    return None


class Experiment:
    def __init__(self, dockerfile_dir, output_dir):
        self.df_dir = Path(dockerfile_dir)
        self.out_dir = Path(output_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir = self.out_dir / "scans"
        self.scans_dir.mkdir(exist_ok=True)
        self.results = []
        self.start_time = time.time()

        # Load any existing results for crash recovery
        self.results_file = self.out_dir / "results.json"
        self.completed = set()
        if self.results_file.exists():
            try:
                with open(self.results_file) as f:
                    data = json.load(f)
                self.results = data.get("results", [])
                for r in self.results:
                    self.completed.add(r["image_name"])
                log.info(f"Recovered {len(self.completed)} completed images from previous run")
            except Exception:
                pass

    def discover(self):
        dfs = sorted(self.df_dir.glob("Dockerfile.*"))
        dfs = [d for d in dfs if d.name != "INDEX.md"]
        log.info(f"Found {len(dfs)} Dockerfiles")
        return dfs

    def process_one(self, df_path):
        name = df_path.name.replace("Dockerfile.", "")

        if name in self.completed:
            log.info(f"  Skipping {name} (already completed)")
            return

        log.info(f"\n{'='*60}")
        log.info(f"Processing: {name}")
        log.info(f"{'='*60}")

        # Read Dockerfile
        with open(df_path) as f:
            df_text = f.read()

        # Extract base image
        base_image = extract_from_image(df_path)
        if not base_image or base_image.lower() == "scratch":
            log.info(f"  Skipping scratch image: {name}")
            self._add_skip_result(name, "scratch image")
            return

        # ── Pull & scan original ──────────────────────────────
        log.info(f"  Pulling original: {base_image}")
        pull_ok, pull_time = docker_pull(base_image)
        if not pull_ok:
            log.warning(f"  Cannot pull {base_image}")
            self._add_skip_result(name, f"pull failed: {base_image}")
            return

        size_before = docker_size_mb(base_image)
        scan_file = str(self.scans_dir / f"{name}_original.json")
        log.info(f"  Scanning original...")
        scan_data = trivy_scan(base_image, scan_file)
        sev_before, cves_before = extract_vulns(scan_data)
        total_before = sum(sev_before.values())
        log.info(f"  Baseline: {total_before} vulns (C={sev_before['CRITICAL']}, H={sev_before['HIGH']}, M={sev_before['MEDIUM']}, L={sev_before['LOW']})")

        # Generate SBOM for AutoPatch
        sbom_file = str(self.scans_dir / f"{name}_sbom.json")
        sbom_data = trivy_sbom(base_image, sbom_file)

        # Clean up original scan files to save disk
        for f in [scan_file, sbom_file]:
            if os.path.exists(f):
                os.remove(f)

        # ── Strategy A: Scan-Only ─────────────────────────────
        self.results.append({
            "image_name": name,
            "base_image": base_image,
            "strategy": "Scan-Only",
            "target_image": base_image,
            "pull_success": True,
            "vulns_before_total": total_before,
            "vulns_after_total": total_before,
            "severity_before": dict(sev_before),
            "severity_after": dict(sev_before),
            "reduction_pct": 0.0,
            "new_vulns_introduced": 0,
            "image_size_before_mb": size_before,
            "image_size_after_mb": size_before,
            "acceptance_passed": False,
            "notes": "",
        })

        # ── Strategy B: Naive :latest ─────────────────────────
        latest_image = rewrite_to_latest(base_image)
        if latest_image and latest_image != base_image:
            self._run_strategy(
                name, base_image, latest_image, "Naive-Latest",
                sev_before, cves_before, total_before, size_before
            )
        else:
            self.results.append({
                "image_name": name, "base_image": base_image,
                "strategy": "Naive-Latest", "target_image": latest_image or base_image,
                "pull_success": False, "vulns_before_total": total_before,
                "vulns_after_total": total_before,
                "severity_before": dict(sev_before), "severity_after": dict(sev_before),
                "reduction_pct": 0.0, "new_vulns_introduced": 0,
                "image_size_before_mb": size_before, "image_size_after_mb": size_before,
                "acceptance_passed": False, "notes": "same as original",
            })

        # ── Strategy E: AutoPatch ─────────────────────────────
        autopatch_target = autopatch_image(df_text, sbom_data)
        if autopatch_target and autopatch_target != base_image:
            self._run_strategy(
                name, base_image, autopatch_target, "AutoPatch",
                sev_before, cves_before, total_before, size_before
            )
        else:
            reason = "no change" if autopatch_target == base_image else "patcher returned None"
            self.results.append({
                "image_name": name, "base_image": base_image,
                "strategy": "AutoPatch", "target_image": autopatch_target or base_image,
                "pull_success": False, "vulns_before_total": total_before,
                "vulns_after_total": total_before,
                "severity_before": dict(sev_before), "severity_after": dict(sev_before),
                "reduction_pct": 0.0, "new_vulns_introduced": 0,
                "image_size_before_mb": size_before, "image_size_after_mb": size_before,
                "acceptance_passed": False, "notes": reason,
            })

        # Clean up original image
        docker_rmi(base_image)
        self.completed.add(name)
        self._save()

    def _run_strategy(self, name, base_image, target_image, strategy,
                      sev_before, cves_before, total_before, size_before):
        """Pull target, scan, compare, cleanup."""
        log.info(f"  [{strategy}] Target: {target_image}")

        result = {
            "image_name": name, "base_image": base_image,
            "strategy": strategy, "target_image": target_image,
            "vulns_before_total": total_before,
            "severity_before": dict(sev_before),
            "image_size_before_mb": size_before,
        }

        pull_ok, _ = docker_pull(target_image)
        if not pull_ok:
            result.update({
                "pull_success": False,
                "vulns_after_total": total_before,
                "severity_after": dict(sev_before),
                "reduction_pct": 0.0,
                "new_vulns_introduced": 0,
                "image_size_after_mb": 0.0,
                "acceptance_passed": False,
                "notes": f"pull failed: {target_image}",
            })
            self.results.append(result)
            return

        size_after = docker_size_mb(target_image)
        scan_file = str(self.scans_dir / f"{name}_{strategy.lower().replace('-','_')}.json")
        scan_data = trivy_scan(target_image, scan_file)
        sev_after, cves_after = extract_vulns(scan_data)
        total_after = sum(sev_after.values())

        # Clean scan file to save disk
        if os.path.exists(scan_file):
            os.remove(scan_file)

        reduction = ((total_before - total_after) / total_before * 100) if total_before > 0 else 0.0
        new_cves = len(set(cves_after) - set(cves_before))

        accepted = (
            total_after < total_before and
            new_cves == 0 and
            sev_after.get("CRITICAL", 0) <= sev_before.get("CRITICAL", 0) and
            sev_after.get("HIGH", 0) <= sev_before.get("HIGH", 0)
        )

        result.update({
            "pull_success": True,
            "vulns_after_total": total_after,
            "severity_after": sev_after,
            "reduction_pct": round(reduction, 2),
            "new_vulns_introduced": new_cves,
            "image_size_after_mb": size_after,
            "acceptance_passed": accepted,
            "notes": "",
        })

        log.info(f"  [{strategy}] {total_before} -> {total_after} ({reduction:.1f}%), accepted={accepted}")

        # Cleanup target if different from original
        if target_image != base_image:
            docker_rmi(target_image)

        self.results.append(result)

    def _add_skip_result(self, name, reason):
        for strat in ["Scan-Only", "Naive-Latest", "AutoPatch"]:
            self.results.append({
                "image_name": name, "base_image": "", "strategy": strat,
                "target_image": "", "pull_success": False,
                "vulns_before_total": 0, "vulns_after_total": 0,
                "severity_before": {}, "severity_after": {},
                "reduction_pct": 0.0, "new_vulns_introduced": 0,
                "image_size_before_mb": 0.0, "image_size_after_mb": 0.0,
                "acceptance_passed": False, "notes": reason,
            })
        self.completed.add(name)

    def _save(self):
        """Save results incrementally."""
        data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_results": len(self.results),
                "total_images_completed": len(self.completed),
                "elapsed_seconds": round(time.time() - self.start_time, 1),
            },
            "results": self.results
        }
        with open(self.results_file, "w") as f:
            json.dump(data, f, indent=2, default=str)

        # Also save CSV
        csv_path = self.out_dir / "results.csv"
        fieldnames = [
            "image_name", "base_image", "strategy", "target_image", "pull_success",
            "vulns_before_total", "vulns_after_total", "reduction_pct",
            "new_vulns_introduced", "crit_before", "high_before", "med_before", "low_before",
            "crit_after", "high_after", "med_after", "low_after",
            "image_size_before_mb", "image_size_after_mb", "acceptance_passed", "notes",
        ]
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in self.results:
                sb = r.get("severity_before", {})
                sa = r.get("severity_after", {})
                w.writerow({
                    "image_name": r["image_name"],
                    "base_image": r.get("base_image", ""),
                    "strategy": r["strategy"],
                    "target_image": r.get("target_image", ""),
                    "pull_success": r.get("pull_success", False),
                    "vulns_before_total": r["vulns_before_total"],
                    "vulns_after_total": r["vulns_after_total"],
                    "reduction_pct": r["reduction_pct"],
                    "new_vulns_introduced": r["new_vulns_introduced"],
                    "crit_before": sb.get("CRITICAL", 0),
                    "high_before": sb.get("HIGH", 0),
                    "med_before": sb.get("MEDIUM", 0),
                    "low_before": sb.get("LOW", 0),
                    "crit_after": sa.get("CRITICAL", 0),
                    "high_after": sa.get("HIGH", 0),
                    "med_after": sa.get("MEDIUM", 0),
                    "low_after": sa.get("LOW", 0),
                    "image_size_before_mb": r.get("image_size_before_mb", 0),
                    "image_size_after_mb": r.get("image_size_after_mb", 0),
                    "acceptance_passed": r.get("acceptance_passed", False),
                    "notes": r.get("notes", ""),
                })

    def run_all(self):
        dockerfiles = self.discover()
        total = len(dockerfiles)
        for i, df in enumerate(dockerfiles, 1):
            log.info(f"\n[{i}/{total}] {df.name} (completed: {len(self.completed)}/{total})")
            try:
                self.process_one(df)
            except Exception as e:
                log.error(f"FATAL on {df.name}: {e}", exc_info=True)
                self._add_skip_result(df.name.replace("Dockerfile.", ""), f"exception: {e}")
                self._save()

            # Aggressive cleanup every 5 images
            if i % 5 == 0:
                run(["docker", "system", "prune", "-f"], timeout=60)
                log.info(f"  [cleanup] Docker prune done")

        self._save()
        elapsed = time.time() - self.start_time
        log.info(f"\nDone! {len(self.completed)} images, {len(self.results)} results, {elapsed:.0f}s elapsed")
        self._print_summary()

    def _print_summary(self):
        """Print aggregate summary."""
        for strat in ["Scan-Only", "Naive-Latest", "AutoPatch"]:
            strat_results = [r for r in self.results if r["strategy"] == strat and r.get("pull_success")]
            if not strat_results:
                continue
            reductions = [r["reduction_pct"] for r in strat_results if r["vulns_before_total"] > 0]
            accepted = sum(1 for r in strat_results if r.get("acceptance_passed"))
            if reductions:
                avg = sum(reductions) / len(reductions)
                log.info(f"\n[{strat}] {len(strat_results)} images, avg reduction={avg:.1f}%, accepted={accepted}")
            else:
                log.info(f"\n[{strat}] {len(strat_results)} images, no reductions computed")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--dockerfile-dir", default=str(Path(__file__).parent.parent / "dockerfiles"))
    p.add_argument("--output-dir", default=str(Path(__file__).parent.parent / "experiment_output"))
    args = p.parse_args()

    exp = Experiment(args.dockerfile_dir, args.output_dir)
    exp.run_all()
