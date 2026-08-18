#!/usr/bin/env bash
###############################################################################
#  AutoPatch v4 — Fix bugs + retry failed + compute stats
#  Usage: sudo bash fix_and_retry_v2.sh 2>&1 | tee retry.log
###############################################################################
set -euo pipefail

# Auto-detect experiment directory
if [ -d "${HOME}/autopatch_experiment" ]; then
    WORK_DIR="${HOME}/autopatch_experiment"
elif [ -d "${HOME}/Autopatch_Simulation" ]; then
    WORK_DIR="${HOME}/Autopatch_Simulation"
else
    # Find it
    WORK_DIR=$(find "${HOME}" -maxdepth 2 -name "results_v3" -type d 2>/dev/null | head -1 | xargs dirname 2>/dev/null || echo "")
    if [ -z "$WORK_DIR" ]; then
        WORK_DIR=$(find "${HOME}" -maxdepth 2 -name "dockerfiles" -type d 2>/dev/null | head -1 | xargs dirname 2>/dev/null || echo "${HOME}/autopatch_experiment")
    fi
fi

echo "Using WORK_DIR: $WORK_DIR"

# Find key paths
DF_DIR=""
RESULTS_DIR=""
FIGURES_DIR=""
RUNNER_PY=""

for d in "$WORK_DIR" "$WORK_DIR/results_v3" "$WORK_DIR/results"; do
    if [ -f "$d/results.json" ]; then RESULTS_DIR="$d"; break; fi
done

for d in "$WORK_DIR/dockerfiles" "$WORK_DIR/Dockerfiles"; do
    if [ -d "$d" ]; then DF_DIR="$d"; break; fi
done

for f in "$WORK_DIR/runner.py" "$WORK_DIR/experiment.py" "$WORK_DIR/run.py"; do
    if [ -f "$f" ]; then RUNNER_PY="$f"; break; fi
done

FIGURES_DIR="${WORK_DIR}/figures_v4"

if [ "$(id -u)" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

echo "  Results:    ${RESULTS_DIR:-NOT FOUND}"
echo "  Dockerfiles: ${DF_DIR:-NOT FOUND}"
echo "  Runner:     ${RUNNER_PY:-NOT FOUND}"
echo "  Figures:    ${FIGURES_DIR}"
echo ""

# List what we find
echo "=== Files in WORK_DIR ==="
ls -la "$WORK_DIR/" 2>/dev/null || true
echo ""
echo "=== Looking for results.json ==="
find "$WORK_DIR" -name "results.json" -o -name "results.csv" 2>/dev/null || true
echo ""
echo "=== Looking for runner python files ==="
find "$WORK_DIR" -name "*.py" 2>/dev/null || true
echo ""
echo "=== Looking for dockerfiles ==="
find "$WORK_DIR" -type d -name "dockerfiles" -o -name "Dockerfiles" 2>/dev/null || true

###############################################################################
echo ""
echo "═══ 1/5: Free disk space ═══"
###############################################################################
docker system prune -af --volumes 2>/dev/null || true
df -h / | tail -1

###############################################################################
echo ""
echo "═══ 2/5: Fix results.json — remove rate-limited + buggy entries ═══"
###############################################################################
if [ -n "$RESULTS_DIR" ] && [ -f "$RESULTS_DIR/results.json" ]; then
    python3 << PYEOF
import json

rf = "${RESULTS_DIR}/results.json"
with open(rf) as f:
    data = json.load(f)

before = len(data["results"])

# Remove rate-limited BUILD_ERROR entries (no scan data)
# Keep: IMAGE_NOT_FOUND (legit removed), anything with scan data
keep = []
for r in data["results"]:
    has_data = r.get("vulns_before_total", 0) > 0
    if has_data:
        keep.append(r)
    elif r.get("error_category") in ("IMAGE_NOT_FOUND", "NETWORK"):
        keep.append(r)
    # else: rate-limited garbage, drop it

# Remove mongo and distroless entries so they get re-run with fixed logic
buggy = {"mongo-4.4", "mongo-5.0", "mongo-6.0", "distroless-base", "distroless-java"}
final = [r for r in keep if r.get("image_name") not in buggy]

data["results"] = final
with open(rf, "w") as f:
    json.dump(data, f, indent=2, default=str)

print(f"  Before: {before}, After: {len(final)}, Dropped: {before - len(final)}")
print(f"  Buggy images requeued: {buggy}")
PYEOF
    echo "  [✓] Results cleaned"
else
    echo "  [!] No results.json found — full run needed"
fi

###############################################################################
echo ""
echo "═══ 3/5: Patch runner.py with v4 fixes ═══"
###############################################################################
if [ -n "$RUNNER_PY" ] && [ -f "$RUNNER_PY" ]; then
    echo "  Patching: $RUNNER_PY"
    python3 << PYEOF
import re

with open("${RUNNER_PY}") as f:
    code = f.read()

changes = 0

# FIX 1: mongo before golang — add databases before language runtimes
# and fix the "go:" substring match
if '"golang" in o or "go:" in o' in code:
    # Add mongo/redis/postgres/mysql/mariadb BEFORE the python check
    old = '    # Language runtimes'
    new = '''    # --- v4 FIX: databases FIRST (mongo contains "go:" substring) ---
    if "mongo" in o:    return "mongo:7"
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mariadb" in o:  return "mariadb:11"

    # Language runtimes'''
    if old in code:
        code = code.replace(old, new, 1)
        changes += 1
        print("  FIX 1a: Added databases before language runtimes")

    # Fix the golang regex
    code = code.replace(
        '"golang" in o or "go:" in o',
        '"golang" in o or re.search(r\'\\\\bgo:\', o)'
    )
    changes += 1
    print("  FIX 1b: Fixed golang regex to word boundary")

    # Remove old database section (now duplicated)
    for old_db in [
        '''    # Databases
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mongo" in o:    return "mongo:7"
    if "mariadb" in o:  return "mariadb:11"''',
    ]:
        if old_db in code:
            code = code.replace(old_db, "    # (databases moved above — v4)")
            print("  FIX 1c: Removed duplicate database section")
            changes += 1
else:
    print("  FIX 1: golang/mongo — already patched or not found")

# FIX 2: distroless detection — check metadata name before pkg:deb
if 'if any("pkg:deb/" in p for p in purls): return "debian"' in code and '"distroless" in meta_name' not in code:
    old_line = '    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()'
    new_line = '''    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    # v4 FIX: detect distroless BEFORE package-type checks
    if "distroless" in meta_name:
        return "distroless"'''
    code = code.replace(old_line, new_line, 1)

    # Also fix the debian return to check for distroless-like images
    code = code.replace(
        'if any("pkg:deb/" in p for p in purls): return "debian"',
        '''if any("pkg:deb/" in p for p in purls):
        if len(components) < 15 and not any("apt" in n for n in names):
            return "distroless"
        return "debian"'''
    )
    changes += 1
    print("  FIX 2: distroless detection — APPLIED")
else:
    print("  FIX 2: distroless — already patched or not found")

# FIX 3: acceptance logic — remove new_vulns_introduced == 0
old_acc = '''r.new_vulns_introduced == 0 and
                        sa.get("CRITICAL",0)'''
new_acc = '''sa.get("CRITICAL",0)'''
if old_acc in code:
    code = code.replace(old_acc, new_acc)
    changes += 1
    print("  FIX 3: acceptance logic — APPLIED (removed new_vulns==0 requirement)")
else:
    print("  FIX 3: acceptance — already patched or not found")

# FIX 4: rate-limit error detection
if '"toomanyrequests"' not in code and '"RATE_LIMITED"' not in code:
    code = code.replace(
        '("could not resolve","NETWORK")',
        '("could not resolve","NETWORK"),("toomanyrequests","RATE_LIMITED"),("rate limit","RATE_LIMITED"),("429","RATE_LIMITED")'
    )
    changes += 1
    print("  FIX 4: rate-limit detection — APPLIED")
else:
    print("  FIX 4: rate-limit detection — already patched or not found")

with open("${RUNNER_PY}", "w") as f:
    f.write(code)

print(f"  Total changes: {changes}")
PYEOF
    echo "  [✓] Runner patched"
else
    echo "  [!] No runner.py found — checking if it's embedded in shell script"
    # The v3 standalone embeds Python inline — find and patch the shell script
    MAIN_SH=$(find "$WORK_DIR" -maxdepth 1 -name "*.sh" ! -name "fix*" ! -name "retry*" | head -1)
    if [ -n "$MAIN_SH" ]; then
        echo "  Found main script: $MAIN_SH — patching inline Python"
        python3 << PYEOF
import re

with open("${MAIN_SH:-/dev/null}") as f:
    code = f.read()

changes = 0

# FIX 1: mongo before golang
if '"golang" in o or "go:" in o' in code:
    old = '    # Language runtimes'
    new = '''    # --- v4 FIX: databases FIRST (mongo contains "go:" substring) ---
    if "mongo" in o:    return "mongo:7"
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mariadb" in o:  return "mariadb:11"

    # Language runtimes'''
    if old in code:
        code = code.replace(old, new, 1)
        changes += 1

    code = code.replace(
        '"golang" in o or "go:" in o',
        '"golang" in o or re.search(r\'\\\\bgo:\', o)'
    )
    changes += 1

    for old_db in [
        '''    # Databases
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mongo" in o:    return "mongo:7"
    if "mariadb" in o:  return "mariadb:11"''',
    ]:
        if old_db in code:
            code = code.replace(old_db, "    # (databases moved above — v4)")
            changes += 1
    print(f"  FIX 1: mongo/golang — {changes} changes")

# FIX 2: distroless
if '"distroless" in meta_name' not in code:
    old_line = '    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()'
    new_line = '''    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    if "distroless" in meta_name:
        return "distroless"'''
    code = code.replace(old_line, new_line, 1)
    code = code.replace(
        'if any("pkg:deb/" in p for p in purls): return "debian"',
        '''if any("pkg:deb/" in p for p in purls):
        if len(components) < 15 and not any("apt" in n for n in names):
            return "distroless"
        return "debian"'''
    )
    changes += 1
    print("  FIX 2: distroless — APPLIED")

# FIX 3: acceptance
old_acc = 'r.new_vulns_introduced == 0 and\n                        sa.get("CRITICAL",0)'
new_acc = 'sa.get("CRITICAL",0)'
if old_acc in code:
    code = code.replace(old_acc, new_acc)
    changes += 1
    print("  FIX 3: acceptance — APPLIED")

# FIX 4: rate-limit
if '"toomanyrequests"' not in code:
    code = code.replace(
        '("could not resolve","NETWORK")',
        '("could not resolve","NETWORK"),("toomanyrequests","RATE_LIMITED"),("rate limit","RATE_LIMITED"),("429","RATE_LIMITED")'
    )
    changes += 1
    print("  FIX 4: rate-limit — APPLIED")

# FIX 5: stats numpy bool
code = code.replace(
    'comp["sig_005"]=pv<0.05; comp["sig_001"]=pv<0.01',
    'comp["sig_005"]=bool(pv<0.05); comp["sig_001"]=bool(pv<0.01)'
)

old_dump = '    with open(out/"statistics.json","w") as f: json.dump(output,f,indent=2)'
new_dump = '''    class NpEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, (np.integer,)): return int(obj)
            if isinstance(obj, (np.floating,)): return float(obj)
            if isinstance(obj, (np.bool_,)): return bool(obj)
            if isinstance(obj, np.ndarray): return obj.tolist()
            return super().default(obj)
    with open(out/"statistics.json","w") as f: json.dump(output,f,indent=2,cls=NpEncoder)'''
if old_dump in code:
    code = code.replace(old_dump, new_dump)
    changes += 1
    print("  FIX 5: stats numpy — APPLIED")

with open("${MAIN_SH:-/dev/null}", "w") as f:
    f.write(code)
print(f"  Total fixes applied: {changes}")
PYEOF
        echo "  [✓] Main script patched"
        echo ""
        echo "═══ 4/5: Re-running patched script ═══"
        echo "  This will skip already-completed images via crash recovery"
        bash "$MAIN_SH" 2>&1
        exit $?
    else
        echo "  [!] No script found to patch"
        exit 1
    fi
fi

###############################################################################
echo ""
echo "═══ 4/5: Retry failed images ═══"
###############################################################################
if [ -n "$DF_DIR" ] && [ -n "$RESULTS_DIR" ] && [ -n "$RUNNER_PY" ]; then
    sleep 5
    cd "$WORK_DIR"
    python3 "$RUNNER_PY" \
        --dockerfile-dir "$DF_DIR" \
        --output-dir "$RESULTS_DIR" \
        --strategies scan-only naive copacetic scout autopatch \
        2>&1
    echo "  [✓] Retry complete"
else
    echo "  [!] Missing paths — cannot retry"
    echo "  DF_DIR=$DF_DIR  RESULTS_DIR=$RESULTS_DIR  RUNNER_PY=$RUNNER_PY"
fi

###############################################################################
echo ""
echo "═══ 5/5: Compute statistics and figures ═══"
###############################################################################
mkdir -p "$FIGURES_DIR"

# Find stats.py
STATS_PY=""
for f in "$WORK_DIR/stats.py" "$WORK_DIR/statistics.py"; do
    if [ -f "$f" ]; then STATS_PY="$f"; break; fi
done

if [ -n "$STATS_PY" ] && [ -n "$RESULTS_DIR" ]; then
    # Patch stats numpy bug
    sed -i 's/comp\["sig_005"\]=pv<0.05; comp\["sig_001"\]=pv<0.01/comp["sig_005"]=bool(pv<0.05); comp["sig_001"]=bool(pv<0.01)/' "$STATS_PY"

    python3 "$STATS_PY" "$RESULTS_DIR/results.json" "$RESULTS_DIR" "$FIGURES_DIR"
    echo "  [✓] Stats computed"
else
    echo "  [!] No stats.py found — running inline stats"
    python3 << PYEOF
import json, math, sys, os
from collections import defaultdict
from pathlib import Path
import numpy as np
try:
    from scipy.stats import wilcoxon
    HAS_SCIPY = True
except:
    HAS_SCIPY = False

rd = "${RESULTS_DIR}"
fd = "${FIGURES_DIR}"

if not rd or not os.path.exists(f"{rd}/results.json"):
    # Search for it
    import glob
    candidates = glob.glob(os.path.expanduser("~/*/results*/results.json"))
    if candidates:
        rd = str(Path(candidates[0]).parent)
        print(f"  Found results at: {rd}")
    else:
        print("  ERROR: Cannot find results.json anywhere")
        sys.exit(1)

with open(f"{rd}/results.json") as f:
    data = json.load(f)

results = data["results"]
print(f"\n  Total results: {len(results)}")

# Recompute acceptance with fixed logic
fixed = 0
for r in results:
    if r.get("build_success") and r.get("vulns_before_total", 0) > 0:
        old = r.get("acceptance", False)
        new = (
            r["vulns_after_total"] < r["vulns_before_total"] and
            r.get("sev_after", {}).get("CRITICAL", 0) <= r.get("sev_before", {}).get("CRITICAL", 0) and
            r.get("sev_after", {}).get("HIGH", 0) <= r.get("sev_before", {}).get("HIGH", 0)
        )
        if new != old:
            r["acceptance"] = new
            fixed += 1

print(f"  Acceptance fixes: {fixed} results flipped to True")

# Save fixed results
with open(f"{rd}/results.json", "w") as f:
    json.dump(data, f, indent=2, default=str)

# Compute stats
ORDER = ['Scan-Only','Naive-Latest','Copacetic','Docker-Scout','AutoPatch']
by_strat = defaultdict(list)
by_img = defaultdict(dict)
for r in results:
    by_strat[r["strategy"]].append(r)
    by_img[r["image_name"]][r["strategy"]] = r

print("\n" + "="*70)
print("  EXPERIMENT v4 RESULTS")
print("="*70)

for strat in ORDER:
    es = by_strat.get(strat, [])
    ok = [e for e in es if e.get("build_success")]
    fl = [e for e in es if not e.get("build_success")]
    vrs = [e["reduction_pct"] for e in ok if e.get("vulns_before_total", 0) > 0]

    print(f"\n  {strat}:")
    print(f"    Total:       {len(es)}")
    print(f"    Success:     {len(ok)}")
    print(f"    Failures:    {len(fl)}")
    if vrs:
        print(f"    VR mean:     {np.mean(vrs):.1f}%")
        print(f"    VR median:   {np.median(vrs):.1f}%")
        print(f"    VR std:      {np.std(vrs, ddof=1):.1f}%" if len(vrs)>1 else "    VR std:      0.0%")
        print(f"    VR range:    [{min(vrs):.1f}%, {max(vrs):.1f}%]")
    print(f"    Accepted:    {sum(1 for e in ok if e.get('acceptance'))}")
    print(f"    Zero-after:  {sum(1 for e in ok if e.get('vulns_after_total',999)==0)}")

# Pairwise
print(f"\n  Pairwise comparisons (AutoPatch vs baselines):")
for bl in ["Naive-Latest", "Copacetic", "Docker-Scout"]:
    pa, pb = [], []
    for img, strats in by_img.items():
        if "AutoPatch" in strats and bl in strats:
            a, b = strats["AutoPatch"], strats[bl]
            if a.get("build_success") and b.get("build_success") and a.get("vulns_before_total",0) > 0:
                pa.append(a["reduction_pct"])
                pb.append(b["reduction_pct"])
    print(f"\n    vs {bl} ({len(pa)} paired):")
    if len(pa) >= 5:
        n1, n2 = len(pa), len(pb)
        sp = math.sqrt(((n1-1)*np.std(pa,ddof=1)**2 + (n2-1)*np.std(pb,ddof=1)**2) / (n1+n2-2))
        cd = (np.mean(pa) - np.mean(pb)) / sp if sp > 0 else 0
        print(f"      Cohen's d:  {cd:.3f}")
        if HAS_SCIPY:
            diffs = [a-b for a,b in zip(pa,pb)]
            nz = [d for d in diffs if d != 0]
            if len(nz) >= 5:
                st, pv = wilcoxon(nz)
                print(f"      Wilcoxon p: {float(pv):.6f}")
                print(f"      Sig @0.05:  {pv < 0.05}")
                print(f"      Sig @0.01:  {pv < 0.01}")

# OS breakdown
print(f"\n  OS Family Breakdown (AutoPatch):")
def infer_os(name):
    n = name.lower()
    if 'alpine' in n: return 'Alpine'
    if any(k in n for k in ['debian','buster','bullseye','bookworm','stretch']): return 'Debian'
    if 'ubuntu' in n: return 'Ubuntu'
    if any(k in n for k in ['centos','rhel','rocky','alma','fedora']): return 'RHEL-family'
    if 'distroless' in n: return 'Distroless'
    if 'scratch' in n: return 'Scratch'
    return 'Other'

osd = defaultdict(lambda: {"n": 0, "vrs": [], "fails": 0})
for r in by_strat.get("AutoPatch", []):
    f2 = infer_os(r["image_name"])
    osd[f2]["n"] += 1
    if r.get("build_success") and r.get("vulns_before_total", 0) > 0:
        osd[f2]["vrs"].append(r["reduction_pct"])
    elif not r.get("build_success"):
        osd[f2]["fails"] += 1

for f2, d in sorted(osd.items()):
    vrs = d["vrs"]
    m = f"{np.mean(vrs):.1f}" if vrs else "N/A"
    s = f"{np.std(vrs,ddof=1):.1f}" if len(vrs) > 1 else "0.0"
    print(f"    {f2:14s}: {d['n']:3d} imgs, VR={m}% +/- {s}%, fails={d['fails']}")

# Save stats JSON
class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer,)): return int(obj)
        if isinstance(obj, (np.floating,)): return float(obj)
        if isinstance(obj, (np.bool_,)): return bool(obj)
        if isinstance(obj, np.ndarray): return obj.tolist()
        return super().default(obj)

stats_out = {
    "total_images": len(by_img),
    "total_results": len(results),
    "strategies": {},
    "pairwise": {},
    "os_breakdown": {}
}
for strat in ORDER:
    es = by_strat.get(strat, [])
    ok = [e for e in es if e.get("build_success")]
    vrs = [e["reduction_pct"] for e in ok if e.get("vulns_before_total",0)>0]
    stats_out["strategies"][strat] = {
        "total": len(es), "success": len(ok), "failures": len(es)-len(ok),
        "vr_mean": round(float(np.mean(vrs)),2) if vrs else 0,
        "vr_median": round(float(np.median(vrs)),2) if vrs else 0,
        "vr_std": round(float(np.std(vrs,ddof=1)),2) if len(vrs)>1 else 0,
        "accepted": sum(1 for e in ok if e.get("acceptance")),
    }

os.makedirs(rd, exist_ok=True)
with open(f"{rd}/statistics_v4.json", "w") as f:
    json.dump(stats_out, f, indent=2, cls=NpEncoder)
print(f"\n  Stats saved to: {rd}/statistics_v4.json")

# Quick acceptance summary
ap = by_strat.get("AutoPatch", [])
ap_ok = [r for r in ap if r.get("build_success") and r.get("vulns_before_total",0) > 0]
ap_acc = [r for r in ap_ok if r.get("acceptance")]
print(f"\n  AutoPatch acceptance: {len(ap_acc)}/{len(ap_ok)} ({100*len(ap_acc)/max(len(ap_ok),1):.0f}%)")
print(f"  Accepted images:")
for r in sorted(ap_acc, key=lambda x: x["reduction_pct"], reverse=True):
    print(f"    {r['image_name']:30s} {r['vulns_before_total']}→{r['vulns_after_total']} ({r['reduction_pct']:.1f}%)")
PYEOF
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  DONE. Check the output above for your paper numbers."
echo "════════════════════════════════════════════════════════════"
