#!/usr/bin/env python3
"""
Compute statistics from real experiment results and generate publication-grade figures.

Reads: results.json (from run_real_experiment.py)
Outputs:
  - statistics.json          — per-strategy stats (mean, median, σ, Wilcoxon, Cohen's d)
  - os_family_breakdown.json — VR by OS family
  - figures/fig2_effectiveness.pdf   — grouped bar chart (6 legacy images × 5 strategies)
  - figures/fig3_cdf.pdf             — CDF curves (5 strategies)
  - figures/fig4_severity_panels.pdf — pre/post severity stacked bars
"""

import argparse
import json
import math
import statistics as stats
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any

import numpy as np

# ─── Optional: scipy for Wilcoxon test ────────────────────────────────────
try:
    from scipy.stats import wilcoxon
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    print("WARNING: scipy not installed. Wilcoxon tests will be skipped.")
    print("  Install with: pip3 install scipy")

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif']
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['legend.fontsize'] = 8
plt.rcParams['figure.dpi'] = 300

STRATEGY_COLORS = {
    'Scan-Only':      '#808080',
    'Naive-Latest':   '#E8922A',
    'Copacetic':      '#5B9BD5',
    'Docker-Scout':   '#C05DCC',
    'AutoPatch':      '#2E7D32',
}

STRATEGY_ORDER = ['Scan-Only', 'Naive-Latest', 'Copacetic', 'Docker-Scout', 'AutoPatch']

# ─── OS family detection from image name ──────────────────────────────────
def infer_os_family(image_name: str) -> str:
    """Infer OS family from Dockerfile name for breakdown analysis."""
    name = image_name.lower()
    if any(k in name for k in ['alpine']):
        return 'Alpine'
    if any(k in name for k in ['debian', 'buster', 'bullseye', 'bookworm', 'stretch']):
        return 'Debian'
    if any(k in name for k in ['ubuntu']):
        return 'Ubuntu'
    if any(k in name for k in ['centos', 'rhel', 'rocky', 'alma', 'fedora']):
        return 'RHEL-family'
    if any(k in name for k in ['distroless']):
        return 'Distroless'
    if any(k in name for k in ['scratch']):
        return 'Scratch'
    # Language runtimes — check underlying OS from tag
    if any(k in name for k in ['slim', 'bullseye', 'buster']):
        return 'Debian'
    # Default: most Docker Hub official images are Debian-based
    return 'Debian'


def cohens_d(group1: List[float], group2: List[float]) -> float:
    """Compute Cohen's d effect size."""
    n1, n2 = len(group1), len(group2)
    if n1 < 2 or n2 < 2:
        return 0.0
    m1, m2 = np.mean(group1), np.mean(group2)
    s1, s2 = np.std(group1, ddof=1), np.std(group2, ddof=1)
    pooled_std = math.sqrt(((n1 - 1) * s1**2 + (n2 - 1) * s2**2) / (n1 + n2 - 2))
    if pooled_std == 0:
        return 0.0
    return (m1 - m2) / pooled_std


def compute_stats(results_file: str, output_dir: str, figures_dir: str):
    """Main statistics computation."""
    with open(results_file) as f:
        data = json.load(f)

    results = data["results"]
    out = Path(output_dir)
    figs = Path(figures_dir)
    figs.mkdir(parents=True, exist_ok=True)

    # ── Group by strategy ────────────────────────────────────────────────
    by_strategy: Dict[str, List[Dict]] = defaultdict(list)
    by_image: Dict[str, Dict[str, Dict]] = defaultdict(dict)

    for r in results:
        by_strategy[r["strategy"]].append(r)
        by_image[r["image_name"]][r["strategy"]] = r

    # ── Per-strategy statistics ──────────────────────────────────────────
    strategy_stats = {}

    for strat in STRATEGY_ORDER:
        entries = by_strategy.get(strat, [])
        successful = [e for e in entries if e["build_success"]]
        failed = [e for e in entries if not e["build_success"]]

        vr_values = [e["reduction_pct"] for e in successful]
        new_vuln_counts = [e["new_vulns_introduced"] for e in successful]

        s = {
            "strategy": strat,
            "total_images": len(entries),
            "build_success": len(successful),
            "build_failure": len(failed),
            "failure_rate_pct": (len(failed) / len(entries) * 100) if entries else 0,
        }

        if vr_values:
            s["vr_mean"] = round(np.mean(vr_values), 2)
            s["vr_median"] = round(np.median(vr_values), 2)
            s["vr_std"] = round(np.std(vr_values, ddof=1), 2) if len(vr_values) > 1 else 0
            s["vr_min"] = round(min(vr_values), 2)
            s["vr_max"] = round(max(vr_values), 2)
        else:
            s["vr_mean"] = s["vr_median"] = s["vr_std"] = s["vr_min"] = s["vr_max"] = 0

        s["new_vulns_total"] = sum(new_vuln_counts)
        s["acceptance_passed"] = sum(1 for e in successful if e.get("acceptance_passed"))

        strategy_stats[strat] = s

    # ── Pairwise comparisons: AutoPatch vs each baseline ────────────────
    autopatch_vrs = [e["reduction_pct"] for e in by_strategy.get("AutoPatch", []) if e["build_success"]]
    comparisons = {}

    # Item 11: report TWO analyses for every baseline.
    #   per_pair  - paired only over images where BOTH strategies built
    #               successfully. This is the optimistic view and suffers
    #               survivorship bias: a baseline that fails on the hard
    #               images is judged only on its easy ones.
    #   itt       - intention-to-treat: paired over every image where both
    #               strategies were attempted, scoring a failed build as 0%
    #               reduction. This charges each strategy for its failures.
    def _run_wilcoxon(ap_vals, bl_vals):
        """Return a dict with cohen_d and (if scipy + enough non-zero diffs)
        the Wilcoxon statistic and raw p-value. p is left uncorrected here;
        Holm correction is applied across baselines afterwards."""
        out = {"paired_count": len(ap_vals)}
        if len(ap_vals) < 5:
            out["note"] = f"Only {len(ap_vals)} paired observations, insufficient for test"
            return out
        out["cohen_d"] = round(cohens_d(ap_vals, bl_vals), 3)
        if not HAS_SCIPY:
            out["wilcoxon_note"] = "scipy not installed"
            return out
        diffs = [a - b for a, b in zip(ap_vals, bl_vals)]
        nonzero_diffs = [d for d in diffs if d != 0]
        if len(nonzero_diffs) < 5:
            out["wilcoxon_note"] = f"Only {len(nonzero_diffs)} non-zero diffs, test skipped"
            return out
        stat, p_val = wilcoxon(nonzero_diffs)
        out["wilcoxon_statistic"] = round(float(stat), 4)
        out["wilcoxon_p_value_raw"] = float(p_val)
        out["nonzero_diffs"] = len(nonzero_diffs)
        return out

    for baseline in ["Naive-Latest", "Copacetic", "Docker-Scout"]:
        per_pair_ap, per_pair_bl = [], []
        itt_ap, itt_bl = [], []
        for img_name, strats in by_image.items():
            if "AutoPatch" in strats and baseline in strats:
                ap = strats["AutoPatch"]
                bl = strats[baseline]
                # ITT: failed build counts as 0% reduction.
                itt_ap.append(ap["reduction_pct"] if ap["build_success"] else 0.0)
                itt_bl.append(bl["reduction_pct"] if bl["build_success"] else 0.0)
                if ap["build_success"] and bl["build_success"]:
                    per_pair_ap.append(ap["reduction_pct"])
                    per_pair_bl.append(bl["reduction_pct"])

        comparisons[baseline] = {
            "baseline": baseline,
            "per_pair_mutual_success": _run_wilcoxon(per_pair_ap, per_pair_bl),
            "intention_to_treat": _run_wilcoxon(itt_ap, itt_bl),
        }

    # ── Holm-Bonferroni correction across the three baseline comparisons ──
    # Applied separately within each analysis family so the family-wise error
    # rate across the three baselines is controlled at alpha=0.05.
    def _holm(comparisons_dict, analysis_key):
        pvals = []
        for name, comp in comparisons_dict.items():
            a = comp.get(analysis_key, {})
            if "wilcoxon_p_value_raw" in a:
                pvals.append((name, a["wilcoxon_p_value_raw"]))
        m = len(pvals)
        # Sort ascending; Holm step-down: compare p_(k) to alpha/(m-k).
        for rank, (name, p) in enumerate(sorted(pvals, key=lambda x: x[1])):
            adj = min(1.0, p * (m - rank))
            a = comparisons_dict[name][analysis_key]
            a["wilcoxon_p_value_holm"] = round(adj, 6)
            a["significant_at_005_holm"] = adj < 0.05
            a["significant_at_001_holm"] = adj < 0.01

    _holm(comparisons, "per_pair_mutual_success")
    _holm(comparisons, "intention_to_treat")

    # ── OS family breakdown ──────────────────────────────────────────────
    os_breakdown = defaultdict(lambda: {"images": 0, "vr_values": [], "build_failures": 0})
    for r in by_strategy.get("AutoPatch", []):
        family = infer_os_family(r["image_name"])
        os_breakdown[family]["images"] += 1
        if r["build_success"]:
            os_breakdown[family]["vr_values"].append(r["reduction_pct"])
        else:
            os_breakdown[family]["build_failures"] += 1

    os_stats = {}
    for family, d in sorted(os_breakdown.items()):
        os_stats[family] = {
            "images": d["images"],
            "build_failures": d["build_failures"],
            "vr_mean": round(np.mean(d["vr_values"]), 2) if d["vr_values"] else 0,
            "vr_median": round(np.median(d["vr_values"]), 2) if d["vr_values"] else 0,
            "vr_std": round(np.std(d["vr_values"], ddof=1), 2) if len(d["vr_values"]) > 1 else 0,
        }

    # ── Save statistics ──────────────────────────────────────────────────
    output = {
        "metadata": data.get("metadata", {}),
        "strategy_statistics": strategy_stats,
        "pairwise_comparisons": comparisons,
        "os_family_breakdown": os_stats,
    }

    stats_file = out / "statistics.json"
    with open(stats_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Statistics saved to {stats_file}")

    # ══════════════════════════════════════════════════════════════════════
    # FIGURE GENERATION (from real data)
    # ══════════════════════════════════════════════════════════════════════

    # ── Fig 2: Bar chart (select 6 representative "legacy" images) ───────
    # Pick the 6 images with the highest pre-patch vulnerability count
    autopatch_results = [r for r in by_strategy.get("AutoPatch", []) if r["build_success"]]
    autopatch_results.sort(key=lambda x: x["vulns_before_total"], reverse=True)
    legacy_images = [r["image_name"] for r in autopatch_results[:6]]

    if legacy_images:
        print("Generating Fig 2: bar chart...")
        fig, ax = plt.subplots(figsize=(7.16, 3.5))
        x = np.arange(len(legacy_images))
        w = 0.16

        for si, strat in enumerate(STRATEGY_ORDER):
            vals = []
            fail_flags = []
            for img in legacy_images:
                r = by_image.get(img, {}).get(strat, None)
                if r and r["build_success"]:
                    # Critical + High
                    ch = r["severity_after"].get("CRITICAL", 0) + r["severity_after"].get("HIGH", 0)
                    vals.append(ch)
                    fail_flags.append(False)
                elif r and not r["build_success"]:
                    # Use before counts for failed builds
                    ch = r["severity_before"].get("CRITICAL", 0) + r["severity_before"].get("HIGH", 0)
                    vals.append(ch)
                    fail_flags.append(True)
                else:
                    vals.append(0)
                    fail_flags.append(False)

            color = STRATEGY_COLORS.get(strat, '#888888')
            bars = ax.bar(x + (si - 2) * w, vals, w, label=strat,
                          color=color, edgecolor='black', linewidth=0.4)

            # Mark failures with F
            for j, fail in enumerate(fail_flags):
                if fail:
                    bx = bars[j].get_x() + bars[j].get_width() / 2
                    by = bars[j].get_height()
                    ax.text(bx, by + 3, 'F', ha='center', va='bottom',
                            fontsize=7, fontweight='bold', color='red')

        # Wrap long names
        labels = [n.replace("-", "\n", 1) if len(n) > 12 else n for n in legacy_images]
        ax.set_ylabel('Critical+High Vulnerabilities')
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=8)
        ax.legend(loc='upper right', ncol=2, frameon=True, fontsize=7)
        ax.grid(axis='y', alpha=0.25, linestyle='--')
        ax.set_axisbelow(True)
        fig.tight_layout()
        fig.savefig(figs / 'fig2_effectiveness.pdf', format='pdf', dpi=300, bbox_inches='tight')
        fig.savefig(figs / 'fig2_effectiveness.png', format='png', dpi=300, bbox_inches='tight')
        plt.close(fig)
        print("  Saved fig2_effectiveness")

    # ── Fig 3: CDF curves ────────────────────────────────────────────────
    print("Generating Fig 3: CDF...")
    fig, ax = plt.subplots(figsize=(3.5, 2.8))

    for strat in ['AutoPatch', 'Docker-Scout', 'Naive-Latest', 'Copacetic']:
        entries = by_strategy.get(strat, [])
        vrs = sorted([e["reduction_pct"] for e in entries if e["build_success"]])
        if not vrs:
            continue
        cdf = np.arange(1, len(vrs) + 1) / len(vrs)
        color = STRATEGY_COLORS.get(strat, '#888888')
        ax.plot(vrs, cdf, linewidth=1.8, label=strat, color=color)

    ax.axvline(x=0, linewidth=1.5, label='Scan-Only', color=STRATEGY_COLORS['Scan-Only'], linestyle='--')
    ax.set_xlabel('Vulnerability Reduction (%)')
    ax.set_ylabel('Cumulative Probability')
    ax.set_xlim(-5, 105)
    ax.set_ylim(0, 1.05)
    ax.legend(loc='lower right', fontsize=6.5, frameon=True)
    ax.grid(True, alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(figs / 'fig3_cdf.pdf', format='pdf', dpi=300, bbox_inches='tight')
    fig.savefig(figs / 'fig3_cdf.png', format='png', dpi=300, bbox_inches='tight')
    plt.close(fig)
    print("  Saved fig3_cdf")

    # ── Fig 4: Severity panels (pre/post for AutoPatch) ──────────────────
    print("Generating Fig 4: severity panels...")
    ap_results = sorted(
        [r for r in by_strategy.get("AutoPatch", []) if r["build_success"]],
        key=lambda x: x["vulns_before_total"],
        reverse=True
    )

    if ap_results:
        n_img = len(ap_results)
        sev_colors = {
            'CRITICAL': '#d32f2f', 'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d', 'LOW': '#4caf50', 'UNKNOWN': '#9e9e9e'
        }
        sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.16, 4), sharex=True)
        idx = np.arange(n_img)

        for ax, key, title in [
            (ax1, "severity_before", "Pre-Patch"),
            (ax2, "severity_after", "Post-Patch"),
        ]:
            bottom = np.zeros(n_img)
            for sev in sevs:
                vals = np.array([r[key].get(sev, 0) for r in ap_results])
                ax.bar(idx, vals, bottom=bottom, color=sev_colors[sev],
                       width=1.0, label=sev if ax is ax1 else None, linewidth=0)
                bottom += vals
            ax.set_ylabel('Vulnerabilities')
            ax.set_title(title, fontsize=10, fontweight='bold')
            ax.set_xlim(-0.5, n_img - 0.5)

        ax1.legend(loc='upper right', ncol=5, fontsize=7, frameon=True)
        ax2.set_xlabel('Images (sorted by pre-patch total)')
        fig.tight_layout()
        fig.savefig(figs / 'fig4_severity_panels.pdf', format='pdf', dpi=300, bbox_inches='tight')
        fig.savefig(figs / 'fig4_severity_panels.png', format='png', dpi=300, bbox_inches='tight')
        plt.close(fig)
        print("  Saved fig4_severity_panels")

    # ── Print summary to console ─────────────────────────────────────────
    print("\n" + "=" * 70)
    print("STATISTICS SUMMARY")
    print("=" * 70)
    for strat in STRATEGY_ORDER:
        s = strategy_stats.get(strat, {})
        print(f"\n{strat}:")
        print(f"  Images: {s.get('total_images', 0)}, "
              f"Success: {s.get('build_success', 0)}, "
              f"Failures: {s.get('build_failure', 0)} "
              f"({s.get('failure_rate_pct', 0):.1f}%)")
        print(f"  VR: mean={s.get('vr_mean', 0):.1f}%, "
              f"median={s.get('vr_median', 0):.1f}%, "
              f"σ={s.get('vr_std', 0):.1f}%")
        print(f"  New vulns introduced: {s.get('new_vulns_total', 0)}")

    print("\nPairwise comparisons (AutoPatch vs baseline):")
    for baseline, comp in comparisons.items():
        print(f"\n  vs {baseline}:")
        print(f"    Paired observations: {comp.get('paired_count', 0)}")
        if 'cohen_d' in comp:
            print(f"    Cohen's d: {comp['cohen_d']}")
        if 'wilcoxon_p_value' in comp:
            print(f"    Wilcoxon p-value: {comp['wilcoxon_p_value']:.6f}")
            print(f"    Significant at 0.05: {comp.get('significant_at_005')}")
            print(f"    Significant at 0.01: {comp.get('significant_at_001')}")
        elif 'wilcoxon_note' in comp:
            print(f"    Note: {comp['wilcoxon_note']}")

    print("\nOS family breakdown (AutoPatch):")
    for family, s in sorted(os_stats.items()):
        print(f"  {family}: {s['images']} images, "
              f"VR mean={s['vr_mean']:.1f}%, "
              f"failures={s['build_failures']}")

    print("=" * 70)


def main():
    p = argparse.ArgumentParser(description="Compute statistics from experiment results")
    p.add_argument("--results", required=True, help="Path to results.json")
    p.add_argument("--output-dir", required=True, help="Output directory for statistics")
    p.add_argument("--figures-dir", default=None, help="Output directory for figures (default: ../figures)")
    args = p.parse_args()

    if args.figures_dir is None:
        args.figures_dir = str(Path(args.results).parent.parent / "figures")

    compute_stats(args.results, args.output_dir, args.figures_dir)


if __name__ == "__main__":
    main()
