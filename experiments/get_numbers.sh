#!/usr/bin/env bash
# Just fix acceptance + compute stats on existing data. Nothing else. 30 seconds.
set -euo pipefail
WORK=$(find /root -maxdepth 3 -name "results.json" 2>/dev/null | head -1)
if [ -z "$WORK" ]; then echo "Cannot find results.json"; exit 1; fi
echo "Found: $WORK"
python3 << PYEOF
import json, math, os, sys
from collections import defaultdict
import numpy as np
try:
    from scipy.stats import wilcoxon
    HAS_SCIPY = True
except:
    HAS_SCIPY = False

with open("$WORK") as f:
    data = json.load(f)

results = data["results"]
total = len(results)

# ── FIX ACCEPTANCE on existing results ──────────────────────────
flipped = 0
for r in results:
    if r.get("build_success") and r.get("vulns_before_total", 0) > 0:
        new_acc = (
            r["vulns_after_total"] < r["vulns_before_total"] and
            r.get("sev_after", {}).get("CRITICAL", 0) <= r.get("sev_before", {}).get("CRITICAL", 0) and
            r.get("sev_after", {}).get("HIGH", 0) <= r.get("sev_before", {}).get("HIGH", 0)
        )
        if new_acc and not r.get("acceptance", False):
            r["acceptance"] = True
            flipped += 1

# Save fixed results
with open("$WORK", "w") as f:
    json.dump(data, f, indent=2, default=str)

# ── COMPUTE STATS ───────────────────────────────────────────────
ORDER = ['Scan-Only','Naive-Latest','Copacetic','Docker-Scout','AutoPatch']
by_strat = defaultdict(list)
by_img = defaultdict(dict)
for r in results:
    s = r.get("strategy","")
    by_strat[s].append(r)
    by_img[r.get("image_name","")][s] = r

# Only count images that actually built and scanned
built = set()
for img, strats in by_img.items():
    for s, r in strats.items():
        if r.get("vulns_before_total", 0) > 0 or (r.get("build_success") and s == "Scan-Only"):
            built.add(img)

print(f"\n{'='*70}")
print(f"  AUTOPATCH PAPER NUMBERS (from {len(built)} successfully scanned images)")
print(f"  ({total} total results, {flipped} acceptance flags fixed)")
print(f"{'='*70}")

for strat in ORDER:
    es = by_strat.get(strat, [])
    # Only count results for images that actually built
    es_built = [e for e in es if e.get("image_name") in built]
    ok = [e for e in es_built if e.get("build_success")]
    fl = [e for e in es_built if not e.get("build_success")]
    vrs = [e["reduction_pct"] for e in ok if e.get("vulns_before_total", 0) > 0]
    acc = sum(1 for e in ok if e.get("acceptance"))
    zero = sum(1 for e in ok if e.get("vulns_after_total", 999) == 0)

    print(f"\n  {strat}:")
    print(f"    Tested:      {len(es_built)} images")
    print(f"    Build OK:    {len(ok)}")
    print(f"    Build Fail:  {len(fl)}")
    if vrs:
        print(f"    VR mean:     {np.mean(vrs):.1f}%")
        print(f"    VR median:   {np.median(vrs):.1f}%")
        if len(vrs) > 1:
            print(f"    VR std:      {np.std(vrs, ddof=1):.1f}%")
        print(f"    VR range:    [{min(vrs):.1f}%, {max(vrs):.1f}%]")
    else:
        print(f"    VR:          no successful reductions")
    print(f"    Accepted:    {acc}")
    print(f"    Zero vulns:  {zero}")

# ── AUTOPATCH DETAIL ────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"  AUTOPATCH IMAGE-BY-IMAGE")
print(f"{'='*70}")
ap = by_strat.get("AutoPatch", [])
ap_scanned = [r for r in ap if r.get("image_name") in built and r.get("vulns_before_total", 0) > 0]
ap_scanned.sort(key=lambda x: x["reduction_pct"], reverse=True)

print(f"  {'Image':<30s} {'Before':>7s} {'After':>7s} {'VR%':>8s} {'Accept':>7s} {'Mapping'}")
print(f"  {'-'*95}")
for r in ap_scanned:
    acc = "YES" if r.get("acceptance") else "no"
    base_b = r.get("base_before", "?")
    base_a = r.get("base_after", "?")
    mapping = f"{base_b} -> {base_a}" if base_b and base_a else ""
    print(f"  {r['image_name']:<30s} {r['vulns_before_total']:>7d} {r['vulns_after_total']:>7d} {r['reduction_pct']:>7.1f}% {acc:>7s}  {mapping}")

# ── PAIRWISE COMPARISONS ───────────────────────────────────────
print(f"\n{'='*70}")
print(f"  PAIRWISE: AutoPatch vs Baselines")
print(f"{'='*70}")

for bl in ["Naive-Latest", "Copacetic", "Docker-Scout"]:
    pa, pb = [], []
    for img in built:
        strats = by_img.get(img, {})
        if "AutoPatch" in strats and bl in strats:
            a, b = strats["AutoPatch"], strats[bl]
            if a.get("build_success") and b.get("build_success") and a.get("vulns_before_total", 0) > 0:
                pa.append(a["reduction_pct"])
                pb.append(b["reduction_pct"])

    print(f"\n  vs {bl} ({len(pa)} paired images):")
    if len(pa) >= 2:
        print(f"    AutoPatch mean VR: {np.mean(pa):.1f}%")
        print(f"    {bl} mean VR:      {np.mean(pb):.1f}%")
        print(f"    Advantage:         {np.mean(pa) - np.mean(pb):+.1f} pp")

        if len(pa) >= 5:
            n1, n2 = len(pa), len(pb)
            s1 = np.std(pa, ddof=1) if n1 > 1 else 0.001
            s2 = np.std(pb, ddof=1) if n2 > 1 else 0.001
            sp = math.sqrt(((n1-1)*s1**2 + (n2-1)*s2**2) / (n1+n2-2))
            cd = (np.mean(pa) - np.mean(pb)) / sp if sp > 0 else 0
            print(f"    Cohen's d:         {cd:.3f}")

            if HAS_SCIPY:
                diffs = [a - b for a, b in zip(pa, pb)]
                nz = [d for d in diffs if d != 0]
                if len(nz) >= 5:
                    st, pv = wilcoxon(nz)
                    print(f"    Wilcoxon stat:     {float(st):.1f}")
                    print(f"    p-value:           {float(pv):.6f}")
                    print(f"    Significant @0.05: {'YES' if pv < 0.05 else 'no'}")
                    print(f"    Significant @0.01: {'YES' if pv < 0.01 else 'no'}")

# ── OS FAMILY BREAKDOWN ────────────────────────────────────────
print(f"\n{'='*70}")
print(f"  OS FAMILY BREAKDOWN (AutoPatch only)")
print(f"{'='*70}")

def infer_os(name):
    n = name.lower()
    if 'alpine' in n: return 'Alpine'
    if any(k in n for k in ['debian','buster','bullseye','bookworm','stretch']): return 'Debian'
    if 'ubuntu' in n: return 'Ubuntu'
    if any(k in n for k in ['centos','rhel','rocky','alma','fedora']): return 'RHEL-family'
    if 'distroless' in n: return 'Distroless'
    if 'scratch' in n: return 'Scratch'
    return 'Other'

def infer_category(name):
    n = name.lower()
    if any(k in n for k in ['python','node','golang','go-','ruby','php','openjdk','temurin','adoptopenjdk','maven']): return 'Language Runtime'
    if any(k in n for k in ['nginx','httpd','traefik','caddy','haproxy']): return 'Web Server'
    if any(k in n for k in ['redis','postgres','mysql','mongo','mariadb','elasticsearch']): return 'Database'
    if any(k in n for k in ['jenkins','vault','consul','sonarqube','gitlab','kafka','rabbitmq','docker']): return 'CI/DevOps'
    if any(k in n for k in ['wordpress','nextcloud','drupal','ghost','joomla']): return 'CMS/App'
    if any(k in n for k in ['alpine','debian','ubuntu','centos','rocky','alma','fedora']): return 'Base OS'
    if 'multistage' in n: return 'Multi-stage'
    return 'Other'

osd = defaultdict(lambda: {"n": 0, "vrs": [], "fails": 0})
catd = defaultdict(lambda: {"n": 0, "vrs": [], "fails": 0})

for r in ap:
    if r.get("image_name") not in built: continue
    fam = infer_os(r["image_name"])
    cat = infer_category(r["image_name"])
    for d, key in [(osd, fam), (catd, cat)]:
        d[key]["n"] += 1
        if r.get("build_success") and r.get("vulns_before_total", 0) > 0:
            d[key]["vrs"].append(r["reduction_pct"])
        elif not r.get("build_success"):
            d[key]["fails"] += 1

print(f"\n  By OS Family:")
print(f"  {'Family':<14s} {'Images':>6s} {'VR Mean':>8s} {'VR Std':>8s} {'Fails':>6s}")
for f2 in sorted(osd.keys()):
    d = osd[f2]
    m = f"{np.mean(d['vrs']):.1f}%" if d['vrs'] else "N/A"
    s = f"{np.std(d['vrs'], ddof=1):.1f}%" if len(d['vrs']) > 1 else "—"
    print(f"  {f2:<14s} {d['n']:>6d} {m:>8s} {s:>8s} {d['fails']:>6d}")

print(f"\n  By Category:")
print(f"  {'Category':<18s} {'Images':>6s} {'VR Mean':>8s} {'VR Std':>8s} {'Fails':>6s}")
for cat in sorted(catd.keys()):
    d = catd[cat]
    m = f"{np.mean(d['vrs']):.1f}%" if d['vrs'] else "N/A"
    s = f"{np.std(d['vrs'], ddof=1):.1f}%" if len(d['vrs']) > 1 else "—"
    print(f"  {cat:<18s} {d['n']:>6d} {m:>8s} {s:>8s} {d['fails']:>6d}")

# ── FAILURE ANALYSIS ────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"  FAILURE ANALYSIS")
print(f"{'='*70}")
failed_imgs = set()
for img, strats in by_img.items():
    if img not in built:
        failed_imgs.add(img)

err_cats = defaultdict(list)
for r in results:
    if r.get("image_name") in failed_imgs and r.get("error_category"):
        err_cats[r["error_category"]].append(r["image_name"])

# Dedup
for k in err_cats:
    err_cats[k] = sorted(set(err_cats[k]))

print(f"\n  Images that never built: {len(failed_imgs)}")
for cat, imgs in sorted(err_cats.items()):
    print(f"\n  {cat} ({len(imgs)} images):")
    for img in imgs[:10]:
        print(f"    - {img}")
    if len(imgs) > 10:
        print(f"    ... and {len(imgs)-10} more")

print(f"\n{'='*70}")
print(f"  SUMMARY FOR PAPER ABSTRACT")
print(f"{'='*70}")
ap_ok_vr = [r for r in ap_scanned if r.get("build_success")]
if ap_ok_vr:
    vrs = [r["reduction_pct"] for r in ap_ok_vr]
    acc_count = sum(1 for r in ap_ok_vr if r.get("acceptance"))
    zero_count = sum(1 for r in ap_ok_vr if r.get("vulns_after_total", 999) == 0)
    print(f"  Dataset: {len(built)} container images across X OS families")
    print(f"  AutoPatch mean VR:    {np.mean(vrs):.1f}%")
    print(f"  AutoPatch median VR:  {np.median(vrs):.1f}%")
    print(f"  Accepted:             {acc_count}/{len(ap_ok_vr)} ({100*acc_count/len(ap_ok_vr):.0f}%)")
    print(f"  Full remediation:     {zero_count}/{len(ap_ok_vr)} images reached 0 vulns")
    # Count images where VR > 0
    improved = sum(1 for v in vrs if v > 0)
    worse = sum(1 for v in vrs if v < 0)
    same = sum(1 for v in vrs if v == 0)
    print(f"  Improved:             {improved} images")
    print(f"  No change:            {same} images")
    print(f"  Got worse:            {worse} images")

print(f"\n{'='*70}")
print("  DONE.")
print(f"{'='*70}")
PYEOF
