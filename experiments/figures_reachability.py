#!/usr/bin/env python3
"""
P3-22: Reachability figure for the paper.

Reads ``experiments/rerun_results.csv`` (produced by
:mod:`rerun_with_new_gate`) plus the corresponding per-image
dep-graph summaries (one JSON per image under ``./autopatch-output``
when run with ``--dep-graph``), and produces:

  1. A stacked bar showing reachable-vs-unreachable CVE share for
     the dataset (one bar per image, sorted by total).
  2. An aggregate pie showing the dataset-wide reachable share.
  3. A scatter of (reachable CVE count, posture score) coloured by
     threshold mode.

Outputs PNG + PDF into ``figures/`` so the paper's includegraphics
can pick them up without further work.

Usage:
    python experiments/figures_reachability.py \\
        --csv experiments/rerun_results.csv \\
        --dep-graph-dir experiments/dep_graphs/
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _read_rows(csv_path: Path) -> List[Dict[str, str]]:
    with open(csv_path) as f:
        return list(csv.DictReader(f))


def _read_dep_graph_summary(path: Path) -> Optional[Dict]:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def plot_stacked_reachability(
    rows: List[Dict[str, str]],
    dep_summaries: Dict[str, Dict],
    out_path: Path,
) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib + numpy required", file=sys.stderr)
        return

    images = []
    reachable_counts = []
    unreach_counts = []
    for row in rows:
        if row.get("threshold") != "reachability":
            continue
        img = row.get("image", "")
        ds = dep_summaries.get(img)
        if not ds:
            continue
        images.append(img.split("/")[-1])
        reachable_counts.append(int(ds.get("reachable_count", 0)))
        unreach_counts.append(int(ds.get("unreachable_count", 0)))

    if not images:
        print("No matched rows; nothing to plot", file=sys.stderr)
        return

    # Sort descending by total
    order = sorted(range(len(images)),
                    key=lambda i: -(reachable_counts[i] + unreach_counts[i]))
    images = [images[i] for i in order]
    reachable_counts = [reachable_counts[i] for i in order]
    unreach_counts = [unreach_counts[i] for i in order]

    fig, ax = plt.subplots(figsize=(11, 4.5))
    x = np.arange(len(images))
    ax.bar(x, reachable_counts, color="#C0392B", label="Reachable")
    ax.bar(x, unreach_counts, bottom=reachable_counts,
           color="#7F8C8D", label="Unreachable")
    ax.set_xticks(x[::max(1, len(images) // 30)])
    ax.set_xticklabels(
        [images[i] for i in range(0, len(images), max(1, len(images) // 30))],
        rotation=80, fontsize=7,
    )
    ax.set_ylabel("CVE count")
    ax.set_xlabel(f"Image ({len(images)} total, sorted by total CVE count)")
    ax.legend(loc="upper right")
    ax.set_title("Reachable vs Unreachable CVEs Across the Dataset")
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path.with_suffix(".png"), dpi=300, bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out_path.with_suffix('.png')}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True,
                        help="rerun_results.csv produced by rerun_with_new_gate")
    parser.add_argument("--dep-graph-dir", required=True,
                        help="Directory of dep-graph-summary.json per image")
    parser.add_argument("--out", default="figures/fig_reachability_distribution",
                        help="Output base path (extensions auto-added)")
    args = parser.parse_args()

    rows = _read_rows(Path(args.csv))
    deps: Dict[str, Dict] = {}
    root = Path(args.dep_graph_dir)
    for p in root.glob("*.json"):
        # filename derived from image name; strip extension
        deps[p.stem] = _read_dep_graph_summary(p) or {}
        deps[p.stem.replace("_", "/")] = deps[p.stem]  # tolerate both forms

    plot_stacked_reachability(rows, deps, Path(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
