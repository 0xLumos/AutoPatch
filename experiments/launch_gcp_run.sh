#!/usr/bin/env bash
# Durable launcher for the 200-image, 5-strategy AutoPatch experiment.
# Runs under setsid+nohup so it KEEPS RUNNING after you close the SSH session.
#
# Usage (on the GCP VM, inside the AutoPatch repo):
#   bash experiments/launch_gcp_run.sh
#   tail -f experiments/real_results/run.log     # watch progress
#
# Re-running is safe: results.json is rewritten after every image, so a crash
# or disconnect loses at most the in-flight image.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

OUT="experiments/real_results"
mkdir -p "$OUT"

# ── BuildKit endpoint for Copacetic ──────────────────────────────────────
# Copa needs a BuildKit instance. Bootstrap a buildx builder once and export
# its address; run_real_experiment.py's _resolve_buildkit_env() picks it up.
if ! docker buildx inspect copabuildkit >/dev/null 2>&1; then
  docker buildx create --name copabuildkit --use --bootstrap
fi
export BUILDKIT_HOST="docker-container://$(docker ps --filter name=buildx_buildkit_copabuildkit --format '{{.Names}}' | head -1)"
echo "BUILDKIT_HOST=$BUILDKIT_HOST"

# ── Pre-pull the Trivy DB so the first scan doesn't stall ─────────────────
trivy image --download-db-only || true

# ── Launch detached; survives SSH disconnect ─────────────────────────────
setsid nohup python3 experiments/run_real_experiment.py \
    --dockerfile-dir dockerfiles/ \
    --output-dir "$OUT" \
    --strategies scan-only naive copacetic scout autopatch \
    --verbose \
    > "$OUT/run.log" 2>&1 < /dev/null &

PID=$!
echo "$PID" > "$OUT/run.pid"
echo "Launched experiment PID $PID"
echo "  log:  $OUT/run.log"
echo "  pid:  $OUT/run.pid   (kill with: kill \$(cat $OUT/run.pid))"
echo "  results stream into: $OUT/results.json and $OUT/results.csv"
