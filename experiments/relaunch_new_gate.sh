#!/usr/bin/env bash
# Relaunch the A/B experiment under the NEW default gate
# (count-strict over applicable+fixable findings, KEV hard block).
#
# Run ON the GCP VM from anywhere inside the repo:
#   bash experiments/relaunch_new_gate.sh
#
# What it does, in order, and why:
#   1. Stops any active runner. Two concurrent runners destroy each
#      other: the post-image cleanup prunes ALL Docker images and the
#      whole build cache, so a second runner would delete the first
#      one's images mid-build. Old results stay on disk; admission
#      under any criterion is recomputable from the persisted scans
#      with experiments/policy_sweep.py, so nothing is lost.
#   2. Verifies THIS checkout actually contains the new gate. The gate
#      change was made on the local machine; launching a stale VM
#      checkout would silently rerun the old experiment.
#   3. Runs the test suite. Repo rule: green before burning compute.
#      This is also the first execution of the gate change anywhere,
#      so a failure here is exactly what this step exists to catch.
#   4. Launches a FRESH detached run via the existing launcher
#      (setsid + nohup + PID file + per-run checkpointing). Never
#      resumes an old OUT: rows gated live under different criteria
#      must not share a results.jsonl.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail() { echo "RELAUNCH ABORTED: $*" >&2; exit 1; }

# ── 1. Stop any active runner ───────────────────────────────────────
for pidfile in results/ab_*/runner.pid; do
  [ -f "$pidfile" ] || continue
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  [ -n "$pid" ] || continue
  if kill -0 "$pid" 2>/dev/null; then
    echo "Stopping active runner pid=$pid ($pidfile)"
    kill "$pid" || true
    for _ in $(seq 1 60); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    kill -0 "$pid" 2>/dev/null && fail "runner $pid did not exit; investigate before relaunching"
    echo "Runner $pid stopped. Its results remain in $(dirname "$pidfile")."
  fi
done

# ── 2. Prove this checkout has the new gate ─────────────────────────
grep -q '"count-strict"' src/comparer.py \
  || fail "src/comparer.py has no count-strict mode: checkout is stale, sync the repo first"
grep -q 'default="count-strict"' src/main.py \
  || fail "src/main.py does not default to count-strict: checkout is stale, sync the repo first"
grep -q -- '"--accept-threshold", "count-strict"' experiments/run_ab_experiment.py \
  || fail "run_ab_experiment.py does not pin the new gate: checkout is stale, sync the repo first"
python3 - <<'EOF' || fail "ApplicabilityPolicy.kernel_only missing: src/applicability.py is stale"
from src.applicability import ApplicabilityPolicy
p = ApplicabilityPolicy.with_no_fix()
assert p.exclude_kernel_space and p.exclude_no_fix
ApplicabilityPolicy.kernel_only()
EOF
echo "Gate code present: count-strict default, fixable-only applicability, KEV block."

# ── 3. Tests: green before compute ──────────────────────────────────
python3 -m pytest tests/test_applicability.py tests/test_acceptance_identity.py -q \
  || fail "gate tests failed; fix before launching"
python3 -m pytest tests/ -q --ignore=tests/integration \
  || fail "test suite not green; repo rule says no compute until it is"

# ── 4. Fresh detached launch ────────────────────────────────────────
# ARMS defaults to A,B (the launcher refuses a degenerate A/B run when
# ANTHROPIC_API_KEY is missing; export it first, or set ARMS=A).
CORPUS="${CORPUS:-real_repos}" \
TIMEOUT="${TIMEOUT:-1800}" \
ARMS="${ARMS:-A,B}" \
LIMIT="${LIMIT:-0}" \
  bash experiments/launch_ab_gcp.sh

echo
echo "Launched under the new gate. Provenance now records"
echo "--accept-threshold count-strict and --applicability default"
echo "(kernel + no-fix excluded, KEV never excluded) in every per-run cmd."
