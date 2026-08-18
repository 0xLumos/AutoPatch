#!/usr/bin/env python3
"""
P3-23: Posture-score distribution figure for the paper.

Reads ``experiments/rerun_results.csv`` (produced by
:mod:`rerun_with_new_gate`) and renders a box-plot of the
``posture_score`` distribution per threshold mode, with
strict / risk / reachability laid out left to right and the
cascade variants drawn alongside their non-cascade peer.

The plot is meant to support the paper claim that the new
gate modes shift the dataset's posture distribution upward
without inflating false acceptances. Per-image points are
overlaid as a strip so reviewers can see the dispersion.

Outputs PNG + PDF into ``figures/`` so the paper's
``includegraphics`` can pick them up without further work.

Usage:
    python experiments/figures_posture_distribution.py \\
        --csv experiments/rerun_results.csv \\
        --out figures/fig_posture_distribution
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _read_rows(csv_path: Path) -> List[Dict[str, str]]:
    with open(csv_path) as f:
        return list(csv.DictReader(f))


def _coerce_float(value: Optional[str]) -> Optional[float]:
    if value is None or value == "" or value == "None":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bucket_label(row: Dict[str, str]) -> str:
    threshold = row.get("threshold", "?")
    cascade = str(row.get("cascade", "")).lower() in {"true", "1", "yes"}
    return f"{threshold}{'+cascade' if cascade else ''}"


def _collect_buckets(rows: List[Dict[str, str]]) -> Dict[str, List[float]]:
    buckets: Dict[str, List[float]] = defaultdict(list)
    for r in rows:
        score = _coerce_float(r.get("posture_score"))
        if score is None:
            continue
        buckets[_bucket_label(r)].append(score)
    return buckets


# Canonical ordering so paper figures are reproducible across runs.
_CANONICAL_ORDER = [
    "strict",
    "strict+cascade",
    "risk",
    "risk+cascade",
    "reachability",
    "reachability+cascade",
]


def _ordered_keys(buckets: Dict[str, List[float]]) -> List[str]:
    present = [k for k in _CANONICAL_ORDER if k in buckets]
    # Append anything unexpected (e.g. future modes) at the end, sorted
    extras = sorted(k for k in buckets.keys() if k not in present)
    return present + extras


def plot_posture_distribution(
    buckets: Dict[str, List[float]],
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

    keys = _ordered_keys(buckets)
    if not keys:
        print("No posture scores found in CSV; nothing to plot",
              file=sys.stderr)
        return

    data = [buckets[k] for k in keys]
    counts = [len(d) for d in data]

    fig, ax = plt.subplots(figsize=(9, 4.5))
    positions = list(range(1, len(keys) + 1))

    # Colour cascade variants slightly differently so the figure is
    # readable in greyscale print.
    box_colours = []
    for k in keys:
        if "+cascade" in k:
            box_colours.append("#5B8FB9")
        else:
            box_colours.append("#2C3E50")

    bp = ax.boxplot(
        data,
        positions=positions,
        widths=0.55,
        patch_artist=True,
        showfliers=False,
        medianprops=dict(color="#E67E22", linewidth=2),
    )
    for patch, colour in zip(bp["boxes"], box_colours):
        patch.set_facecolor(colour)
        patch.set_alpha(0.55)
        patch.set_edgecolor("black")

    # Overlay individual points (jittered) so the reader can see
    # within-bucket dispersion and the size of each bucket.
    rng = np.random.default_rng(seed=0)
    for pos, values in zip(positions, data):
        if not values:
            continue
        jitter = rng.uniform(-0.12, 0.12, size=len(values))
        ax.scatter(
            [pos + j for j in jitter],
            values,
            s=12,
            alpha=0.45,
            color="#34495E",
            edgecolors="none",
        )

    ax.set_xticks(positions)
    ax.set_xticklabels(
        [f"{k}\n(n={n})" for k, n in zip(keys, counts)],
        fontsize=9,
    )
    ax.set_ylabel("Posture score (0 = worst, 1 = best)")
    ax.set_title("Posture Score Distribution Across Acceptance Modes")
    ax.set_ylim(0.0, 1.0)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)

    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path.with_suffix(".png"), dpi=300, bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out_path.with_suffix('.png')}")
    print(f"wrote {out_path.with_suffix('.pdf')}")


def _summarise(buckets: Dict[str, List[float]]) -> None:
    """Print a quick stats summary so the script doubles as a sanity
    check when run from the command line."""
    try:
        import numpy as np
    except ImportError:
        return
    print("\nPer-mode posture summary:")
    for k in _ordered_keys(buckets):
        v = np.asarray(buckets[k], dtype=float)
        if v.size == 0:
            continue
        print(
            f"  {k:25s} n={v.size:3d} "
            f"median={np.median(v):.3f} "
            f"mean={v.mean():.3f} "
            f"p25={np.percentile(v, 25):.3f} "
            f"p75={np.percentile(v, 75):.3f}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True,
                        help="rerun_results.csv produced by rerun_with_new_gate")
    parser.add_argument("--out", default="figures/fig_posture_distribution",
                        help="Output base path (extensions auto-added)")
    args = parser.parse_args()

    rows = _read_rows(Path(args.csv))
    buckets = _collect_buckets(rows)
    _summarise(buckets)
    plot_posture_distribution(buckets, Path(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
