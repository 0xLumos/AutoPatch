#!/usr/bin/env python3
"""Post-hoc admit-rate and reduction sweep across criteria x policies.

Every run persists trivy-before.json / trivy-after.json per image, so
the admission decision under ANY acceptance criterion and ANY
applicability policy is recoverable from disk with zero re-execution.
This is the Section V table: it shows how much of the "0 admitted"
result is the strict identity criterion versus real residual exposure,
and how the applicability filter moves the line.

It reuses the ACTUAL gate (comparer.check_acceptance_criteria) for
every cell, so the numbers cannot drift from the pipeline's own logic.

Criteria swept:
  identity-strict : no new Critical/High IDENTITY, total identities drop
                    (the paper's literal Eq. (1); the no-regression bound)
  count-strict    : Critical/High COUNTS do not rise, total drops
                    (the practical criterion; permits identity churn)
  moderate        : count-strict plus Medium non-increasing

Applicability policies swept (from src/applicability.py):
  literal     : raw scanner set
  kernel-only : exclude host-kernel CVEs (the previous pipeline default)
  default     : kernel-only plus exclude no-fix findings (the shipped
                pipeline default; fielded admission gates require an
                available fix). KEV overrides exclusion in all columns.

Usage:
  python experiments/policy_sweep.py results/ab_full_<stamp> [--arm A]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.comparer import check_acceptance_criteria      # noqa: E402
from src.applicability import ApplicabilityPolicy        # noqa: E402
from src import vulnerability_index as _vi               # noqa: E402

_CRITERIA = ["identity-strict", "count-strict", "moderate"]
_THRESHOLD = {"identity-strict": "strict", "count-strict": "count-strict",
              "moderate": "moderate"}
_POLICIES = {
    "literal": ApplicabilityPolicy.literal(),
    "kernel-only": ApplicabilityPolicy.kernel_only(),
    "default": ApplicabilityPolicy.with_no_fix(),
}


def _find_pairs(root: Path, arm: str):
    """Yield (image, stratum, before_scan, after_scan) for every run
    that produced both scans."""
    for before in root.rglob("trivy-before.json"):
        run_dir = before.parent
        if not run_dir.name.lower().endswith(arm.lower()):
            continue
        after = run_dir / "trivy-after.json"
        if not after.is_file():
            continue
        image = run_dir.parent.name
        stratum = "legacy" if "@legacy" in image else "current"
        try:
            b = json.loads(before.read_text(encoding="utf-8"))
            a = json.loads(after.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        yield image, stratum, b, a


def _reduction(before_scan, after_scan):
    nb = len(_vi.extract_records(before_scan))
    na = len(_vi.extract_records(after_scan))
    if nb == 0:
        return None
    return round((nb - na) / nb * 100.0, 2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results_dir")
    ap.add_argument("--arm", default="A")
    args = ap.parse_args(argv)
    root = Path(args.results_dir)
    if not root.is_dir():
        print(f"error: {root} not found", file=sys.stderr)
        return 1

    pairs = list(_find_pairs(root, args.arm))
    if not pairs:
        print("no before/after scan pairs found", file=sys.stderr)
        return 1

    # cells[(criterion, policy, stratum)] = [n_images, n_admitted]
    cells: dict = {}
    reductions: dict = {"ALL": [], "current": [], "legacy": []}
    for image, stratum, b, a in pairs:
        red = _reduction(b, a)
        if red is not None:
            reductions["ALL"].append(red)
            reductions[stratum].append(red)
        for crit in _CRITERIA:
            for pol_name, pol in _POLICIES.items():
                accepted, _ = check_acceptance_criteria(
                    b, a, threshold=_THRESHOLD[crit],
                    demote_local_av=False, applicability_policy=pol)
                for strat in ("ALL", stratum):
                    key = (crit, pol_name, strat)
                    cell = cells.setdefault(key, [0, 0])
                    cell[0] += 1
                    if accepted:
                        cell[1] += 1

    def _rate(crit, pol, strat):
        n, adm = cells.get((crit, pol, strat), [0, 0])
        return f"{adm}/{n}" + (f" ({100*adm/n:.0f}%)" if n else "")

    out = {"images_analyzed": len(pairs), "arm": args.arm,
           "admit_rate": {}, "reduction_pct": {}}
    for strat in ("ALL", "current", "legacy"):
        out["admit_rate"][strat] = {
            crit: {pol: _rate(crit, pol, strat) for pol in _POLICIES}
            for crit in _CRITERIA}
        xs = reductions[strat]
        if xs:
            xs_sorted = sorted(xs)
            out["reduction_pct"][strat] = {
                "n": len(xs),
                "mean": round(sum(xs) / len(xs), 2),
                "median": xs_sorted[len(xs) // 2],
                "max": max(xs),
            }

    (root / "policy_sweep.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8")

    # Human table.
    print(f"\nImages with before/after scans (arm {args.arm}): {len(pairs)}\n")
    for strat in ("ALL", "current", "legacy"):
        print(f"=== {strat} ===  admit-rate  [criterion x applicability]")
        header = "  {:16}".format("") + "".join(
            f"{p:>14}" for p in _POLICIES)
        print(header)
        for crit in _CRITERIA:
            row = "  {:16}".format(crit) + "".join(
                f"{_rate(crit, p, strat):>14}" for p in _POLICIES)
            print(row)
        r = out["reduction_pct"].get(strat)
        if r:
            print(f"  reduction: mean {r['mean']}%  median {r['median']}%  "
                  f"max {r['max']}%  (n={r['n']})")
        print()
    print(f"Full matrix: {root/'policy_sweep.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
