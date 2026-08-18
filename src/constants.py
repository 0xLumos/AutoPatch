"""
Central place for tunables that were previously scattered as magic
numbers across the codebase. The goal is reproducible behaviour and
one diff to find when an operator wants to tune the pipeline.

Anything that survives in this file should be a value an operator
might reasonably want to override at run-time; values that are part
of a protocol contract (HTTP status code thresholds, severity bucket
names, etc.) stay where they are used.

Override at run-time via environment variables prefixed
``AUTOPATCH_`` — e.g. ``AUTOPATCH_BUILD_TIMEOUT_SECONDS=1200``.
"""
from __future__ import annotations

import os


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# Subprocess primitives -------------------------------------------------------

#: Default per-attempt timeout for ``utils.run_cmd``. Subprocess
#: calls heavier than this (Docker build, Trivy scan) override
#: explicitly at the call site.
DEFAULT_RUN_CMD_TIMEOUT_SECONDS: int = _int_env(
    "AUTOPATCH_RUN_CMD_TIMEOUT_SECONDS", 300
)

#: Default retry attempts for scanner network calls.
DEFAULT_SCANNER_RETRIES: int = _int_env("AUTOPATCH_SCANNER_RETRIES", 3)

#: Base for exponential backoff between retries; final wait per
#: attempt is ``BACKOFF_BASE ** (attempt - 1)`` with +/- 25% jitter.
RETRY_BACKOFF_BASE: float = _float_env("AUTOPATCH_RETRY_BACKOFF_BASE", 2.0)


# Docker / build --------------------------------------------------------------

#: Original-image build timeout. The patched-image timeout adapts
#: from the measured original build time (max of this and 2x).
DEFAULT_BUILD_TIMEOUT_SECONDS: int = _int_env(
    "AUTOPATCH_BUILD_TIMEOUT_SECONDS", 600
)

#: Cosign operations are usually fast; cap so a hung registry never
#: wedges the pipeline.
COSIGN_TIMEOUT_SECONDS: int = _int_env("AUTOPATCH_COSIGN_TIMEOUT_SECONDS", 90)

#: Default docker push retries / inter-attempt delay.
PUSH_MAX_RETRIES: int = _int_env("AUTOPATCH_PUSH_MAX_RETRIES", 3)
PUSH_RETRY_DELAY_SECONDS: int = _int_env("AUTOPATCH_PUSH_RETRY_DELAY", 5)


# Scanner / SBOM --------------------------------------------------------------

#: Cap on bytes hashed by ``scanner_integrity.compute_sha256``.
#: Real scanner binaries top out around 150 MB; anything past 256 MB
#: is either a misconfiguration or an attacker-supplied path.
MAX_HASH_BYTES: int = _int_env(
    "AUTOPATCH_MAX_HASH_BYTES", 256 * 1024 * 1024
)


# Confidence + acceptance -----------------------------------------------------

#: Below this composite confidence the patcher refuses to auto-rewrite
#: a Dockerfile; the operator must supply ``--base-mapping`` instead.
MIN_AUTO_PATCH_CONFIDENCE: float = _float_env(
    "AUTOPATCH_MIN_CONFIDENCE", 0.4
)

#: Default EPSS exploitation-probability threshold below which a new
#: HIGH/CRITICAL is considered non-exploitable and demoted to warning
#: in strict mode. 1% matches common EPSS triage practice.
DEFAULT_EPSS_SAFE_THRESHOLD: float = _float_env(
    "AUTOPATCH_EPSS_SAFE_THRESHOLD", 0.01
)


# Caches ----------------------------------------------------------------------

#: TTL on per-resolver caches (Hub tag lookups, EOL queries).
RESOLVER_CACHE_TTL_SECONDS: int = _int_env(
    "AUTOPATCH_RESOLVER_CACHE_TTL", 3600  # 1 hour
)

#: TTL on threat-intel feeds (URLhaus / ThreatFox).
THREAT_INTEL_CACHE_TTL_SECONDS: int = _int_env(
    "AUTOPATCH_THREAT_INTEL_CACHE_TTL", 86400  # 24 hours
)


# Network monitor (optional extension; values here for completeness) ----------

#: Composite DGA-entropy threshold; domains scoring above this are
#: flagged as likely C2 channels.
DGA_ENTROPY_THRESHOLD: float = _float_env(
    "AUTOPATCH_DGA_ENTROPY_THRESHOLD", 3.9
)
