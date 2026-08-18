#!/usr/bin/env python3
"""Mechanism-ceiling analysis: how much of what base-image substitution
CAN reach does AutoPatch actually remove, and what is the residual made
of. Trivy tags every finding with Class: os-pkgs (OS layer, reachable
by base substitution) or lang-pkgs (application layer, unreachable).
"""
import glob
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.expanduser("~/AutoPatch"))
from src import vulnerability_index as vi

R = os.path.expanduser("~/AutoPatch/results")
CAS = f"{R}/ab2yr_cascade_20260812_001147"


def load(p):
    try:
        return json.load(open(p))
    except Exception:
        return None


def classify(scan):
    """Counts by (class, fixable)."""
    out = Counter()
    for res in (scan.get("Results") or []):
        cls = res.get("Class") or "unknown"
        for v in (res.get("Vulnerabilities") or []):
            fixable = bool((v.get("FixedVersion") or "").strip())
            out[(cls, fixable)] += 1
            out[("TOTAL", None)] += 1
    return out


def resolve_after(img):
    d = f"{CAS}/{img}/armA"
    rep = load(f"{d}/report.json")
    want = (rep or {}).get("metrics", {}).get("total_after")
    cands = [f"{d}/trivy-after.json"] + sorted(
        glob.glob(f"{d}/trivy-cascade-*.json"))
    fb = None
    for p in cands:
        s = load(p)
        if not s:
            continue
        if fb is None:
            fb = s
        if want is not None and len(vi.extract_records(s)) == want:
            return s
    return fb


rows = [json.loads(l) for l in open(f"{CAS}/results.jsonl") if l.strip()]
agg_b = Counter()
agg_a = Counter()
n_adm = 0
per_img = []
for r in rows:
    if r["exit_code"] != 0:
        continue
    img = r["image"]
    b = load(f"{CAS}/{img}/armA/trivy-before.json")
    a = resolve_after(img)
    if not b or not a:
        continue
    n_adm += 1
    cb, ca = classify(b), classify(a)
    agg_b.update(cb)
    agg_a.update(ca)
    os_fix_b = cb[("os-pkgs", True)]
    os_fix_a = ca[("os-pkgs", True)]
    cap = (100.0 * (1 - os_fix_a / os_fix_b)) if os_fix_b else None
    per_img.append((img, os_fix_b, os_fix_a, cap,
                    ca[("lang-pkgs", True)] + ca[("lang-pkgs", False)]))

print(f"admits analyzed: {n_adm}")
print("\n===== AGGREGATE, before -> after (admits) =====")
for cls in ("os-pkgs", "lang-pkgs"):
    for fx in (True, False):
        bb, aa = agg_b[(cls, fx)], agg_a[(cls, fx)]
        tag = "fixable" if fx else "no-fix "
        pct = f"{100.0 * (1 - aa / bb):5.1f}%" if bb else "  n/a"
        print(f"{cls:9s} {tag}: {bb:6d} -> {aa:6d}  removed {pct}")
print(f"TOTAL            : {agg_b[('TOTAL', None)]:6d} -> "
      f"{agg_a[('TOTAL', None)]:6d}")

osb = agg_b[("os-pkgs", True)]
osa = agg_a[("os-pkgs", True)]
print(f"\nCEILING CAPTURE (fixable OS-layer removed): "
      f"{100.0 * (1 - osa / osb):.1f}%  ({osb} -> {osa})")

resid = agg_a[("TOTAL", None)]
r_lang = agg_a[("lang-pkgs", True)] + agg_a[("lang-pkgs", False)]
r_osnf = agg_a[("os-pkgs", False)]
r_osfx = agg_a[("os-pkgs", True)]
print(f"\nRESIDUAL DECOMPOSITION ({resid} findings after):")
print(f"  app-layer (lang-pkgs, unreachable by base swap): {r_lang}"
      f"  ({100.0 * r_lang / resid:.0f}%)")
print(f"  OS-layer no-fix (no fixed version exists):       {r_osnf}"
      f"  ({100.0 * r_osnf / resid:.0f}%)")
print(f"  OS-layer fixable (left on table):                {r_osfx}"
      f"  ({100.0 * r_osfx / resid:.0f}%)")

print("\n===== per-image fixable-OS capture =====")
print(f"{'image':28s} {'osfix_b':>7s} {'osfix_a':>7s} {'capture':>8s} "
      f"{'app_resid':>9s}")
for img, b0, a0, cap, lang in sorted(
        per_img, key=lambda x: -(x[3] if x[3] is not None else -1)):
    caps = f"{cap:.1f}%" if cap is not None else "n/a"
    print(f"{img:28s} {b0:>7d} {a0:>7d} {caps:>8s} {lang:>9d}")
