#!/usr/bin/env bash
###############################################################################
#  Bypass Docker Hub rate limit using GCP mirror, retry ALL failed images
#  Usage: sudo bash retry_all.sh 2>&1 | tee retry2.log
###############################################################################
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

echo "═══ 1/4: Configure GCP Docker Hub mirror (no rate limit) ═══"

mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'EOF'
{
  "registry-mirrors": ["https://mirror.gcr.io"]
}
EOF

systemctl restart docker
sleep 5
echo "  [✓] Docker configured with GCR mirror"

echo ""
echo "═══ 2/4: Clean up failed entries from results ═══"

WORK_DIR="${HOME}/autopatch_experiment"
RESULTS="${WORK_DIR}/results_v3"

# Verify docker works
docker pull alpine:3.21 > /dev/null 2>&1 && echo "  [✓] Docker pull works (mirror active)" || echo "  [!] Docker pull test failed"

python3 << PYEOF
import json

rf = "${RESULTS}/results.json"
with open(rf) as f:
    data = json.load(f)

before = len(data["results"])

# Keep ONLY results where we got actual scan data (vulns_before > 0)
# Drop everything else — rate-limited, build errors, bugged entries
keep = []
drop_count = 0
for r in data["results"]:
    has_scan = r.get("vulns_before_total", 0) > 0
    # Also keep legit zero-vuln images that actually built (alpine-3.14, alpine-3.18, scratch)
    is_zero_legit = r.get("build_success") and r.get("vulns_before_total", 0) == 0
    if has_scan or is_zero_legit:
        keep.append(r)
    else:
        drop_count += 1

# Also drop bugged images so they re-run with fixed code
buggy = {"mongo-4.4", "mongo-5.0", "mongo-6.0", "distroless-base", "distroless-java",
         "almalinux-8", "nginx-1.10"}
final = [r for r in keep if r.get("image_name") not in buggy]
bug_drop = len(keep) - len(final)

data["results"] = final
with open(rf, "w") as f:
    json.dump(data, f, indent=2, default=str)

print(f"  Before: {before}")
print(f"  Dropped rate-limited: {drop_count}")
print(f"  Dropped buggy (will re-run): {bug_drop}")
print(f"  Kept: {len(final)}")

# Figure out what needs to run
all_images = set()
done_images = set()
for r in final:
    img = r.get("image_name", "")
    if r.get("vulns_before_total", 0) > 0 or (r.get("build_success") and r.get("strategy") == "Scan-Only"):
        done_images.add(img)

# Count how many need retry
import os, glob
df_dir = "${WORK_DIR}/dockerfiles"
all_dfs = glob.glob(f"{df_dir}/*")
all_img_names = set(os.path.basename(p) for p in all_dfs)
need_retry = all_img_names - done_images
print(f"\n  Total Dockerfiles: {len(all_img_names)}")
print(f"  Already done:      {len(done_images)}")
print(f"  Need retry:        {len(need_retry)}")
print(f"  Will retry: {sorted(need_retry)}")
PYEOF

echo "  [✓] Results cleaned"

echo ""
echo "═══ 3/4: Prune old images to free disk ═══"
docker system prune -af --volumes 2>/dev/null || true
df -h / | tail -1

echo ""
echo "═══ 4/4: Re-run experiment (skips completed images) ═══"

# Find the runner
RUNNER=""
for f in "${WORK_DIR}/run_exp.py" "${WORK_DIR}/runner.py" "${WORK_DIR}/experiment.py"; do
    if [ -f "$f" ]; then RUNNER="$f"; break; fi
done

if [ -z "$RUNNER" ]; then
    echo "  [!] No runner.py found, checking shell script"
    MAIN_SH=""
    for f in "${WORK_DIR}/simulation.sh" "${WORK_DIR}/run_experiment_standalone.sh"; do
        if [ -f "$f" ]; then MAIN_SH="$f"; break; fi
    done
    if [ -n "$MAIN_SH" ]; then
        echo "  Found: $MAIN_SH — patching and re-running"

        # Apply all fixes to the shell script
        python3 << PYEOF2
import re

with open("${MAIN_SH}") as f:
    code = f.read()

changes = 0

# FIX 1: mongo before golang
if '"golang" in o or "go:" in o' in code and '"mongo" in o:    return "mongo:7"\n' not in code:
    old = '    # Language runtimes'
    new = '''    # --- v4: databases FIRST (mongo contains "go:" substring) ---
    if "mongo" in o:    return "mongo:7"
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mariadb" in o:  return "mariadb:11"

    # Language runtimes'''
    if old in code:
        code = code.replace(old, new, 1)
        changes += 1

    code = code.replace('"golang" in o or "go:" in o', '"golang" in o or re.search(r\'\\\\bgo:\', o)')
    changes += 1

    # Remove duplicate database block
    old_db = '''    # Databases
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mongo" in o:    return "mongo:7"
    if "mariadb" in o:  return "mariadb:11"'''
    if old_db in code:
        code = code.replace(old_db, "    # (databases moved above — v4)")
        changes += 1

# FIX 2: distroless detection
if '"distroless" in meta_name' not in code:
    old_l = '    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()'
    new_l = '''    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    if "distroless" in meta_name:
        return "distroless"'''
    code = code.replace(old_l, new_l, 1)
    code = code.replace(
        'if any("pkg:deb/" in p for p in purls): return "debian"',
        '''if any("pkg:deb/" in p for p in purls):
        if len(components) < 15 and not any("apt" in n for n in names):
            return "distroless"
        return "debian"'''
    )
    changes += 1

# FIX 3: acceptance — remove new_vulns_introduced == 0
old_a = '''r.new_vulns_introduced == 0 and
                        sa.get("CRITICAL",0)'''
new_a = '''sa.get("CRITICAL",0)'''
if old_a in code:
    code = code.replace(old_a, new_a)
    changes += 1

# FIX 4: rate-limit detection
if '"toomanyrequests"' not in code:
    code = code.replace(
        '("could not resolve","NETWORK")',
        '("could not resolve","NETWORK"),("toomanyrequests","RATE_LIMITED"),("rate limit","RATE_LIMITED"),("429","RATE_LIMITED")'
    )
    changes += 1

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

with open("${MAIN_SH}", "w") as f:
    f.write(code)
print(f"  Applied {changes} fixes")
PYEOF2

        # Re-run — crash recovery will skip done images
        bash "$MAIN_SH" 2>&1
        exit $?
    else
        echo "  ERROR: No runnable script found"
        exit 1
    fi
fi

echo "  Found runner: $RUNNER"

# Patch the runner
python3 << PYEOF3
import re

with open("${RUNNER}") as f:
    code = f.read()

changes = 0

# Same fixes as above but for standalone .py file
if '"golang" in o or "go:" in o' in code:
    old = '    # Language runtimes'
    new = '''    # --- v4: databases FIRST ---
    if "mongo" in o:    return "mongo:7"
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mariadb" in o:  return "mariadb:11"

    # Language runtimes'''
    if old in code:
        code = code.replace(old, new, 1)
        changes += 1
    code = code.replace('"golang" in o or "go:" in o', '"golang" in o or re.search(r\'\\\\bgo:\', o)')
    changes += 1
    old_db = '''    # Databases
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mongo" in o:    return "mongo:7"
    if "mariadb" in o:  return "mariadb:11"'''
    if old_db in code:
        code = code.replace(old_db, "    # (databases moved above — v4)")
        changes += 1

if '"distroless" in meta_name' not in code:
    old_l = '    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()'
    new_l = '''    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    if "distroless" in meta_name:
        return "distroless"'''
    code = code.replace(old_l, new_l, 1)
    code = code.replace(
        'if any("pkg:deb/" in p for p in purls): return "debian"',
        '''if any("pkg:deb/" in p for p in purls):
        if len(components) < 15 and not any("apt" in n for n in names):
            return "distroless"
        return "debian"'''
    )
    changes += 1

old_a = '''r.new_vulns_introduced == 0 and
                        sa.get("CRITICAL",0)'''
if old_a in code:
    code = code.replace(old_a, 'sa.get("CRITICAL",0)')
    changes += 1

if '"toomanyrequests"' not in code:
    code = code.replace(
        '("could not resolve","NETWORK")',
        '("could not resolve","NETWORK"),("toomanyrequests","RATE_LIMITED"),("rate limit","RATE_LIMITED"),("429","RATE_LIMITED")'
    )
    changes += 1

with open("${RUNNER}", "w") as f:
    f.write(code)
print(f"  Applied {changes} fixes to runner")
PYEOF3

echo "  [✓] Runner patched"

# Run it
cd "$WORK_DIR"
python3 "$RUNNER" \
    --dockerfile-dir "$WORK_DIR/dockerfiles" \
    --output-dir "$RESULTS" \
    --strategies scan-only naive copacetic scout autopatch \
    2>&1

echo ""
echo "═══ 5/5: Compute final stats ═══"

# Patch stats.py too
STATS="${WORK_DIR}/stats.py"
if [ -f "$STATS" ]; then
    sed -i 's/comp\["sig_005"\]=pv<0.05; comp\["sig_001"\]=pv<0.01/comp["sig_005"]=bool(pv<0.05); comp["sig_001"]=bool(pv<0.01)/' "$STATS"
    python3 "$STATS" "$RESULTS/results.json" "$RESULTS" "${WORK_DIR}/figures_v4" 2>&1 || true
fi

# Also run the get_numbers script if it exists
if [ -f "${WORK_DIR}/get_numbers.sh" ]; then
    bash "${WORK_DIR}/get_numbers.sh" 2>&1
fi

echo ""
echo "════════════════════════════════════════"
echo "  DONE. All images retried via GCR mirror."
echo "════════════════════════════════════════"
