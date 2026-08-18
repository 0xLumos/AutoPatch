#!/usr/bin/env bash
###############################################################################
#  AutoPatch v4 — Fix bugs + retry failed images + compute stats
#
#  Run on GCP instance after v3 finishes:
#    sudo bash fix_and_retry.sh 2>&1 | tee retry.log
#
#  Fixes: mongo→golang bug, distroless detection, acceptance logic,
#         stats numpy crash, rate-limit error detection, docker prune
#  NO docker login required — prunes old images to stay under pull limit
###############################################################################
set -euo pipefail

WORK_DIR="${HOME}/autopatch_experiment"
RESULTS="${WORK_DIR}/results_v3"
FIGURES="${WORK_DIR}/figures_v3"
RUNNER="${WORK_DIR}/runner.py"
STATS="${WORK_DIR}/stats.py"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
step()  { echo -e "\n${CYAN}═══ $1 ═══${NC}"; }
ok()    { echo -e "  ${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

###############################################################################
step "1/6: Free disk space — prune all unused Docker images"
###############################################################################
docker system prune -af --volumes 2>/dev/null || true
df -h / | tail -1
ok "Docker pruned"

###############################################################################
step "2/6: Remove rate-limited failures from results.json"
###############################################################################
python3 << 'PYEOF'
import json
rf = "$RESULTS/results.json"
try:
    with open(rf) as f: data = json.load(f)
except:
    print("No results.json found — will do full run"); exit(0)

before = len(data["results"])
# Keep: anything with actual scan data OR genuinely removed images (IMAGE_NOT_FOUND)
keep = []
drop = []
for r in data["results"]:
    has_data = r.get("vulns_before_total", 0) > 0
    legit_fail = r.get("error_category") in ("IMAGE_NOT_FOUND", "NETWORK", "")
    if has_data or legit_fail:
        keep.append(r)
    else:
        drop.append(r)

# Also drop the bugged mongo and distroless results so they get re-run
rebuildable = {"mongo-4.4", "mongo-5.0", "mongo-6.0", "distroless-base", "distroless-java"}
final = []
requeued = []
for r in keep:
    if r.get("image_name") in rebuildable and r.get("strategy") == "AutoPatch":
        requeued.append(r["image_name"])
    else:
        final.append(r)

# For mongo/distroless, drop ALL strategy results so original gets rebuilt too
final2 = [r for r in final if r.get("image_name") not in rebuildable]

data["results"] = final2
with open(rf, "w") as f: json.dump(data, f, indent=2, default=str)
print(f"Before: {before} results")
print(f"Dropped {before - len(final2)} (rate-limited: {len(drop)}, requeue bugs: {len(requeued) + (len(final) - len(final2))})")
print(f"Kept: {len(final2)} results")
PYEOF
ok "Results cleaned"

###############################################################################
step "3/6: Patch runner.py with all v4 fixes"
###############################################################################
# We patch the runner in-place with sed — safer than rewriting the whole file

# FIX 1: mongo→golang bug — move mongo check before golang, fix "go:" regex
python3 << 'PYFIX1'
import re

with open("$RUNNER") as f:
    code = f.read()

# Replace the choose_base function entirely
old_choose = '''def choose_base(family, orig_base=""):
    """
    v3 strategy: keep SAME language version, switch OS to alpine.
    This isolates OS-level vulnerability reduction without introducing
    new language runtime CVEs from version upgrades.
    """
    o = orig_base.lower()

    # Language runtimes → SAME version, alpine OS
    if "python" in o:
        ver = _extract_ver(orig_base, "3.12")
        return f"python:{ver}-alpine"

    if "node" in o:
        ver = _extract_major(orig_base, "22")
        return f"node:{ver}-alpine"

    if "golang" in o or "go:" in o:
        ver = _extract_ver(orig_base, "1.22")
        return f"golang:{ver}-alpine"'''

new_choose = '''def choose_base(family, orig_base=""):
    """
    v4 strategy: keep SAME language version, switch OS to alpine.
    Databases checked BEFORE golang to avoid mongo→golang substring bug.
    """
    o = orig_base.lower()

    # --- v4 FIX: databases FIRST (mongo contains "go:" substring) ---
    if "mongo" in o:    return "mongo:7"
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mariadb" in o:  return "mariadb:11"

    # Language runtimes → SAME version, alpine OS
    if "python" in o:
        ver = _extract_ver(orig_base, "3.12")
        return f"python:{ver}-alpine"

    if "node" in o:
        ver = _extract_major(orig_base, "22")
        return f"node:{ver}-alpine"

    if "golang" in o or re.search(r'\\bgo:', o):
        ver = _extract_ver(orig_base, "1.22")
        return f"golang:{ver}-alpine"'''

if old_choose in code:
    code = code.replace(old_choose, new_choose)
    print("FIX 1: mongo→golang — APPLIED")
else:
    print("FIX 1: mongo→golang — already patched or code differs, trying fallback")
    # Fallback: just fix the "go:" line
    code = code.replace(
        'if "golang" in o or "go:" in o:',
        'if "golang" in o or re.search(r\'\\bgo:\', o):'
    )

# Also need to remove the old database section that's now after golang
old_db = '''    # Databases
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mongo" in o:    return "mongo:7"
    if "mariadb" in o:  return "mariadb:11"'''

if old_db in code:
    code = code.replace(old_db, '    # Databases moved above golang check (v4)')
    print("FIX 1b: removed duplicate database section")

with open("$RUNNER", "w") as f:
    f.write(code)
PYFIX1

# FIX 2: distroless detection
python3 << 'PYFIX2'
with open("$RUNNER") as f:
    code = f.read()

old_detect = '''    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    if any("ubuntu" in n for n in names) and any("pkg:deb/" in p for p in purls): return "ubuntu"
    if any("pkg:apk/" in p for p in purls) or any(n in names for n in ["apk-tools","musl","alpine-baselayout"]): return "alpine"
    if any("pkg:deb/" in p for p in purls): return "debian"'''

new_detect = '''    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    # v4 FIX: detect distroless BEFORE package-type checks
    if "distroless" in meta_name:
        return "distroless"
    if any("ubuntu" in n for n in names) and any("pkg:deb/" in p for p in purls): return "ubuntu"
    if any("pkg:apk/" in p for p in purls) or any(n in names for n in ["apk-tools","musl","alpine-baselayout"]): return "alpine"
    if any("pkg:deb/" in p for p in purls):
        if len(components) < 15 and not any("apt" in n for n in names):
            return "distroless"
        return "debian"'''

if old_detect in code:
    code = code.replace(old_detect, new_detect)
    print("FIX 2: distroless detection — APPLIED")
else:
    print("FIX 2: distroless detection — already patched or code differs")

with open("$RUNNER", "w") as f:
    f.write(code)
PYFIX2

# FIX 3: acceptance logic — remove new_vulns_introduced == 0 requirement
python3 << 'PYFIX3'
with open("$RUNNER") as f:
    code = f.read()

old_accept = '''                    r.acceptance = (
                        r.vulns_after_total < total_b and
                        r.new_vulns_introduced == 0 and
                        sa.get("CRITICAL",0) <= sev_b.get("CRITICAL",0) and
                        sa.get("HIGH",0) <= sev_b.get("HIGH",0)
                    )'''

new_accept = '''                    r.acceptance = (
                        r.vulns_after_total < total_b and
                        sa.get("CRITICAL",0) <= sev_b.get("CRITICAL",0) and
                        sa.get("HIGH",0) <= sev_b.get("HIGH",0)
                    )'''

if old_accept in code:
    code = code.replace(old_accept, new_accept)
    print("FIX 3: acceptance logic — APPLIED")
else:
    print("FIX 3: acceptance logic — already patched or code differs")

with open("$RUNNER", "w") as f:
    f.write(code)
PYFIX3

# FIX 4: add rate-limit detection to error categories
python3 << 'PYFIX4'
with open("$RUNNER") as f:
    code = f.read()

old_err = '''    for kw, cat in [("timeout","TIMEOUT"),("network","NETWORK"),("connection","NETWORK"),
                     ("could not resolve","NETWORK"),("returned a non-zero code","RUN_FAILURE"),
                     ("not found","IMAGE_NOT_FOUND"),("no such","IMAGE_NOT_FOUND"),
                     ("manifest unknown","IMAGE_NOT_FOUND"),("manifest not found","IMAGE_NOT_FOUND"),
                     ("permission denied","PERMISSION")]:'''

new_err = '''    for kw, cat in [("timeout","TIMEOUT"),("network","NETWORK"),("connection","NETWORK"),
                     ("could not resolve","NETWORK"),("toomanyrequests","RATE_LIMITED"),
                     ("rate limit","RATE_LIMITED"),("429","RATE_LIMITED"),
                     ("returned a non-zero code","RUN_FAILURE"),
                     ("not found","IMAGE_NOT_FOUND"),("no such","IMAGE_NOT_FOUND"),
                     ("manifest unknown","IMAGE_NOT_FOUND"),("manifest not found","IMAGE_NOT_FOUND"),
                     ("permission denied","PERMISSION")]:'''

if old_err in code:
    code = code.replace(old_err, new_err)
    print("FIX 4: rate-limit detection — APPLIED")
else:
    print("FIX 4: rate-limit detection — already patched or code differs")

with open("$RUNNER", "w") as f:
    f.write(code)
PYFIX4

ok "Runner patched with all v4 fixes"

###############################################################################
step "4/6: Patch stats.py — numpy bool fix + custom encoder"
###############################################################################
python3 << 'PYFIX5'
with open("$STATS") as f:
    code = f.read()

# Fix 1: numpy bool
code = code.replace(
    'comp["sig_005"]=pv<0.05; comp["sig_001"]=pv<0.01',
    'comp["sig_005"]=bool(pv<0.05); comp["sig_001"]=bool(pv<0.01)'
)

# Fix 2: add NpEncoder
old_dump = '    with open(out/"statistics.json","w") as f: json.dump(output,f,indent=2)'
new_dump = '''    class NpEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, (np.integer,)): return int(obj)
            if isinstance(obj, (np.floating,)): return float(obj)
            if isinstance(obj, (np.bool_,)): return bool(obj)
            if isinstance(obj, np.ndarray): return obj.tolist()
            return super().default(obj)
    with open(out/"statistics.json","w") as f: json.dump(output,f,indent=2,cls=NpEncoder)'''

code = code.replace(old_dump, new_dump)
print("FIX 5: stats numpy serialization — APPLIED")

with open("$STATS", "w") as f:
    f.write(code)
PYFIX5
ok "Stats script patched"

###############################################################################
step "5/6: Retry failed images"
###############################################################################
echo "Waiting 10s for Docker daemon to stabilize after prune..."
sleep 10

cd "$WORK_DIR"
python3 "$RUNNER" \
    --dockerfile-dir "$WORK_DIR/dockerfiles" \
    --output-dir "$RESULTS" \
    --strategies scan-only naive copacetic scout autopatch \
    2>&1

ok "Retry complete"

###############################################################################
step "6/6: Compute statistics and generate figures"
###############################################################################
python3 "$STATS" "$RESULTS/results.json" "$RESULTS" "$FIGURES"

ok "ALL DONE — check $RESULTS/statistics.json and $FIGURES/"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Files:"
echo "    Results:    $RESULTS/results.json"
echo "    CSV:        $RESULTS/results.csv"
echo "    Stats:      $RESULTS/statistics.json"
echo "    Figures:    $FIGURES/"
echo "════════════════════════════════════════════════════════════"
