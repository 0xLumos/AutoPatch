#!/usr/bin/env bash
# Launch the paired A/B selection experiment on a GCP VM, DETACHED.
#
# The run must survive the SSH session and any assistant session that
# started it: setsid + nohup + disown, PID file, append-only logs, and
# the runner's own per-run checkpointing mean the experiment continues
# through disconnects and resumes through reboots.
#
# Run ON the VM from the repo root:
#   ANTHROPIC_API_KEY=... bash experiments/launch_ab_gcp.sh
#
# Monitor:
#   tail -f results/ab_$(date +%Y%m%d)*/runner.log
#   cat results/ab_*/summary.json
# Stop:
#   kill "$(cat results/ab_*/runner.pid)"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-results/ab_${STAMP}}"
CORPUS="${CORPUS:-dataset/corpus}"
LIMIT="${LIMIT:-0}"
TIMEOUT="${TIMEOUT:-1800}"
mkdir -p "$OUT"

# ── Pre-flight: fail loudly NOW, not three hours in ─────────────────
fail() { echo "PRE-FLIGHT FAILED: $*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker not on PATH"
docker info >/dev/null 2>&1 || fail "docker daemon unreachable"
command -v trivy  >/dev/null || fail "trivy not on PATH"
python3 -c "import src.main" 2>/dev/null || fail "src.main not importable from $REPO_ROOT"

if [ ! -d "$CORPUS" ] || [ -z "$(find "$CORPUS" -mindepth 2 -maxdepth 2 -name Dockerfile -print -quit 2>/dev/null)" ]; then
  fail "no corpus at $CORPUS. Build it first: python3 experiments/collect_real_dockerfiles.py --dest $CORPUS"
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "WARNING: ANTHROPIC_API_KEY is not set." >&2
  echo "Arm B will fall back to deterministic selection on every image," >&2
  echo "and the comparison degenerates to A vs A. Set the key, or run" >&2
  echo "with ARMS=A to do the deterministic arm only." >&2
  [ "${ARMS:-A,B}" = "A" ] || fail "refusing to burn compute on a degenerate A/B run"
fi

# Record the exact code and environment the numbers came from. A result
# that cannot name its inputs is not a result.
{
  echo "started:        $(date -u +%FT%TZ)"
  echo "host:           $(hostname)"
  echo "git commit:     $(git rev-parse HEAD 2>/dev/null || echo 'no git')"
  echo "git dirty:      $(git status --porcelain 2>/dev/null | wc -l) files"
  echo "trivy:          $(trivy --version 2>/dev/null | head -1)"
  echo "docker:         $(docker --version)"
  echo "python:         $(python3 --version)"
  echo "corpus:         $CORPUS ($(find "$CORPUS" -mindepth 2 -maxdepth 2 -name Dockerfile | wc -l) Dockerfiles)"
  echo "arms:           ${ARMS:-A,B}   limit: $LIMIT   timeout: ${TIMEOUT}s"
} | tee "$OUT/provenance.txt"

# Warm the Trivy DB once before the loop so the first image does not
# pay the download and every run starts from the same snapshot.
trivy image --download-db-only >/dev/null 2>&1 || true

# ── Detach ──────────────────────────────────────────────────────────
setsid nohup python3 experiments/run_ab_experiment.py \
    --corpus "$CORPUS" \
    --out "$OUT" \
    --arms "${ARMS:-A,B}" \
    --limit "$LIMIT" \
    --timeout "$TIMEOUT" \
    >> "$OUT/runner.log" 2>&1 < /dev/null &
PID=$!
disown "$PID" 2>/dev/null || true
echo "$PID" > "$OUT/runner.pid"

echo
echo "Detached. The run now survives this shell and any SSH disconnect."
echo "  pid:     $PID"
echo "  log:     $OUT/runner.log"
echo "  resume:  rerun this script with OUT=$OUT (completed pairs are skipped)"
echo "  summary: $OUT/summary.json (rewritten after every completed run)"
