#!/usr/bin/env python3
"""
Re-run the 78-image dataset through the new gate modes.

Produces a CSV with one row per (image, threshold) combination so the
paper's Table I can be regenerated with the post-Phase-1 acceptance
rates and posture-score distributions.

Modes evaluated:
    1. strict   (the current paper's baseline)
    2. risk     (requires EPSS + KEV data files; auto-skipped if missing)
    3. reachability (requires --dep-graph; auto-enabled here)
    4. strict + cascade
    5. risk + cascade

Usage (on the GCP experiment box with Docker + Trivy + Cosign on PATH):

    cd /path/to/AutoPatch
    python experiments/rerun_with_new_gate.py \\
        --dockerfiles-dir dockerfiles/ \\
        --output experiments/rerun_results.csv \\
        --epss-file data/epss.json \\
        --kev-file  data/kev.json

EPSS and KEV files are optional; modes that require them are skipped
when missing. The script invokes :func:`src.main.run_pipeline` per
image so the production CLI and experiment runner share one code
path (Phase 1 P1-3).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _run_one(
    dockerfile_path: str,
    threshold: str,
    output_dir: str,
    *,
    epss_file: Optional[str] = None,
    kev_file: Optional[str] = None,
    cascade: bool = False,
    dep_graph: bool = False,
    extra_flags: Optional[List[str]] = None,
) -> Dict[str, object]:
    """Invoke run_pipeline for one image; return a result dict."""
    from src.main import run_pipeline

    argv = [
        "--dockerfile", dockerfile_path,
        "--accept-threshold", threshold,
        "--output-dir", output_dir,
        "--signing-mode", "none",
        "--report-format", "json",
        "--dry-run",  # rewrite + scan only; no push/sign
    ]
    if epss_file:
        argv.extend(["--epss-file", epss_file])
    if kev_file:
        argv.extend(["--kev-file", kev_file])
    if cascade:
        argv.append("--cascade")
    if dep_graph:
        argv.append("--dep-graph")
    if extra_flags:
        argv.extend(extra_flags)

    start = time.time()
    try:
        exit_code = run_pipeline(argv)
    except SystemExit as e:
        exit_code = e.code
    except Exception as e:  # pragma: no cover - defensive
        exit_code = 99
        print(f"  EXCEPTION: {type(e).__name__}: {e}", file=sys.stderr)
    elapsed = time.time() - start

    # Parse the JSON report (if present) for metrics.
    report_path = Path(output_dir) / "report.json"
    report: Dict[str, object] = {}
    if report_path.is_file():
        try:
            with open(report_path) as f:
                report = json.load(f)
        except Exception:
            pass

    accepted = exit_code == 0
    metrics = report.get("metrics") if isinstance(report, dict) else None
    if not isinstance(metrics, dict):
        metrics = {}
    return {
        "exit_code": exit_code,
        "accepted": accepted,
        "elapsed_seconds": round(elapsed, 2),
        "threshold": threshold,
        "cascade": cascade,
        "vulnerability_reduction_pct": metrics.get("vulnerability_reduction_pct"),
        "total_before": metrics.get("total_before"),
        "total_after": metrics.get("total_after"),
        "unique_cves_before": metrics.get("unique_cves_before"),
        "unique_cves_after": metrics.get("unique_cves_after"),
        "posture_score": (report.get("posture_score", {}) or {}).get("total")
                         if isinstance(report.get("posture_score"), dict) else None,
    }


def _iter_dockerfiles(root: Path) -> List[Path]:
    """Find every Dockerfile under ``root`` (recursive)."""
    out: List[Path] = []
    for p in root.rglob("Dockerfile*"):
        if p.is_file():
            out.append(p)
    return sorted(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-run the dataset with the new gate modes",
    )
    parser.add_argument("--dockerfiles-dir", required=True,
                        help="Directory containing the dataset Dockerfiles")
    parser.add_argument("--output", default="experiments/rerun_results.csv",
                        help="Output CSV path")
    parser.add_argument("--epss-file", default=None,
                        help="EPSS data JSON (optional; enables risk mode)")
    parser.add_argument("--kev-file", default=None,
                        help="KEV catalog JSON (optional; enables risk mode)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Process at most N images (smoke testing)")
    parser.add_argument("--modes", nargs="+",
                        default=["count-strict", "strict", "risk",
                                 "reachability"],
                        help="Which threshold modes to evaluate. "
                             "count-strict is the operational default "
                             "gate; strict is the identity-level "
                             "Eq. (1) bound.")
    parser.add_argument("--cascade", action="store_true", default=False,
                        help="Also evaluate each mode with --cascade enabled")
    args = parser.parse_args()

    root = Path(args.dockerfiles_dir)
    dockerfiles = _iter_dockerfiles(root)
    if args.limit:
        dockerfiles = dockerfiles[: args.limit]
    if not dockerfiles:
        print(f"No Dockerfiles found under {root}", file=sys.stderr)
        return 1

    print(f"Found {len(dockerfiles)} Dockerfiles in {root}")

    have_epss = args.epss_file and os.path.isfile(args.epss_file)
    have_kev = args.kev_file and os.path.isfile(args.kev_file)
    if "risk" in args.modes and not (have_epss or have_kev):
        print("Skipping 'risk' mode: no EPSS or KEV file provided")
        args.modes = [m for m in args.modes if m != "risk"]

    rows: List[Dict[str, object]] = []
    for i, df in enumerate(dockerfiles, 1):
        print(f"\n[{i}/{len(dockerfiles)}] {df.relative_to(root)}")
        for mode in args.modes:
            for use_cascade in ([False, True] if args.cascade else [False]):
                with tempfile.TemporaryDirectory() as td:
                    res = _run_one(
                        str(df),
                        threshold=mode,
                        output_dir=td,
                        epss_file=args.epss_file if have_epss else None,
                        kev_file=args.kev_file if have_kev else None,
                        cascade=use_cascade,
                        dep_graph=(mode == "reachability"),
                    )
                    res["image"] = str(df.relative_to(root))
                    rows.append(res)
                    tag = f"{mode}{'+cascade' if use_cascade else ''}"
                    print(
                        f"  {tag:25s} "
                        f"exit={res['exit_code']} "
                        f"VR={res.get('vulnerability_reduction_pct')} "
                        f"posture={res.get('posture_score')}"
                    )

    # Write CSV
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"\nWrote {len(rows)} rows to {out_path}")

    # Quick aggregate
    by_mode: Dict[str, Dict[str, int]] = {}
    for r in rows:
        key = f"{r['threshold']}{'+cascade' if r['cascade'] else ''}"
        by_mode.setdefault(key, {"total": 0, "accepted": 0})
        by_mode[key]["total"] += 1
        if r["accepted"]:
            by_mode[key]["accepted"] += 1
    print("\nAcceptance summary:")
    for mode, c in by_mode.items():
        rate = 100.0 * c["accepted"] / c["total"] if c["total"] else 0.0
        print(f"  {mode:25s} {c['accepted']:3d}/{c['total']:3d}  ({rate:.1f}%)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
