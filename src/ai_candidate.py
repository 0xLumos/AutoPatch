"""Per-image base-candidate proposal via the Anthropic Messages API.

This module exists for exactly one experiment: comparing deterministic,
registry-driven base selection (arm A) against model-proposed selection
(arm B) under IDENTICAL mechanical verification. It is therefore built
around two non-negotiable properties:

**The model proposes; it never decides.** The returned candidate enters
``patch_dockerfile`` through the same code path as an inferred
candidate: it is gated by the allow-list, the pre-flight compatibility
guards, the glibc floor, the build, the scan, runtime validation, and
the acceptance criterion. It carries NO operator trust (the
``_operator_chose`` flag stays False), so a guard rejection falls back
to the same-family upgrade exactly as it would for the deterministic
path. If arm B outperforms arm A, it is because the proposals were
better, not because they were checked less.

**Reproducibility as far as an API allows.** Pinned model string,
temperature 0, a tool-schema-constrained response so parsing adds no
variance, and a mandatory on-disk response cache keyed by the SHA-256
of (model, prompt). Re-running the corpus replays cached responses
byte-for-byte, which makes the experiment repeatable and makes the
second run free. The cache file is an artifact of the experiment and
should be published with it.

Failure policy: every failure (no API key, no SDK, network error,
schema violation, implausible reference) returns ``None``, and the
caller falls back to the deterministic selector. Arm B therefore
degrades toward arm A, never below it; the experiment records how
often that happened via the ``source`` field in the decision log.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("docker_patch_tool")

# Pinned for the experiment. Record this string in the paper; a rerun
# on a different model is a different experiment.
DEFAULT_MODEL = "claude-sonnet-4-5"

_CACHE_DIR_ENV = "AUTOPATCH_AI_CACHE_DIR"
_DEFAULT_CACHE_DIR = Path(__file__).parent / "ai_cache"

# The same shape the rest of the pipeline validates against. A
# reference with a space or shell metacharacters is rejected before it
# goes anywhere near a Dockerfile.
_IMAGE_REF_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:[/][a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r":[\w][\w.-]{0,127}$"
)

_PROPOSAL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "candidate": {
            "type": "string",
            "description": (
                "Full replacement base image reference including tag, "
                "e.g. python:3.13-slim or rockylinux:9. Must be a "
                "currently supported, actively patched image suitable "
                "for the described workload."
            ),
        },
        "distro_family": {
            "type": "string",
            "description": "Distribution family of the candidate.",
        },
        "libc": {
            "type": "string",
            "enum": ["glibc", "musl", "none"],
        },
        "rationale": {
            "type": "string",
            "description": "One or two sentences on why this candidate.",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
    },
    "required": ["candidate", "libc", "confidence"],
}

_PROMPT_TEMPLATE = """You are selecting a replacement base image for a \
container as part of an automated vulnerability remediation pipeline. \
Your proposal will be mechanically verified (registry existence, libc \
compatibility, build, CVE scan, runtime probes) before use, so propose \
the best candidate rather than the safest one.

Workload facts, derived from the image's SBOM and filesystem evidence:
- Original base image: {original_base}
- Distribution family: {distro_family}
- libc requirement: {libc}
- Language runtime: {language} {language_version}
- Needs glibc: {needs_glibc}
- Minimum glibc symbol version observed in binaries: {min_glibc}
- Multi-stage build: {multistage}

Dockerfile (may be truncated):
```
{dockerfile_excerpt}
```

Constraints:
1. The candidate must be publicly pullable from a mainstream registry.
2. Prefer the SAME repository at a newer, supported tag when one \
exists; propose a cross-repository migration only when the original \
lineage is end-of-life or unmaintained.
3. Never propose a musl-based image for a workload that needs glibc.
4. Prefer minimal variants (slim, minimal) over full images.
5. The tag must be specific, never 'latest'.

Return exactly one candidate via the tool."""


def _cache_dir() -> Path:
    d = Path(os.environ.get(_CACHE_DIR_ENV, str(_DEFAULT_CACHE_DIR)))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_key(model: str, prompt: str) -> str:
    return hashlib.sha256(f"{model}\x00{prompt}".encode("utf-8")).hexdigest()


def _cache_read(key: str) -> Optional[Dict[str, Any]]:
    p = _cache_dir() / f"{key}.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning("AI cache entry %s unreadable (%s); ignoring", key, e)
        return None


def _cache_write(key: str, payload: Dict[str, Any]) -> None:
    p = _cache_dir() / f"{key}.json"
    try:
        p.write_text(json.dumps(payload, indent=2, sort_keys=True),
                     encoding="utf-8")
    except OSError as e:
        logger.warning("Could not persist AI cache entry (%s); the run "
                       "remains correct but is not replayable", e)


def _build_prompt(original_base: str, inference: Any,
                  dockerfile_text: str) -> str:
    excerpt = dockerfile_text.strip()
    if len(excerpt) > 3000:
        excerpt = excerpt[:3000] + "\n# [truncated]"
    stages = excerpt.count("\nFROM ") + (1 if excerpt.startswith("FROM") else 0)
    return _PROMPT_TEMPLATE.format(
        original_base=original_base,
        distro_family=getattr(inference, "os_family", "unknown") or "unknown",
        libc=getattr(inference, "libc_type", "unknown") or "unknown",
        language=getattr(inference, "language", None) or "none detected",
        language_version=getattr(inference, "language_version", None) or "",
        needs_glibc=bool(getattr(inference, "needs_glibc", False)),
        min_glibc=getattr(inference, "min_glibc", None) or "not observed",
        multistage=stages > 1,
        dockerfile_excerpt=excerpt,
    )


def _validate(payload: Dict[str, Any], original_base: str,
              inference: Any) -> Optional[Tuple[str, float]]:
    """Mechanical sanity checks BEFORE the proposal enters the pipeline.

    These do not replace the pipeline's gates; they reject responses
    that are malformed enough that logging them as 'candidate rejected
    by guards' would pollute the experiment's guard statistics with
    parser noise.
    """
    candidate = str(payload.get("candidate", "")).strip().lower()
    if not candidate or not _IMAGE_REF_RE.match(candidate):
        logger.warning("AI proposal rejected: %r is not a valid image "
                       "reference", candidate)
        return None
    if candidate.endswith(":latest"):
        logger.warning("AI proposal rejected: ':latest' violates the "
                       "pinning constraint")
        return None
    if candidate == original_base.strip().lower():
        logger.info("AI proposal is the original base; treating as "
                    "'no change proposed'")
        return None
    claimed_libc = str(payload.get("libc", "")).strip().lower()
    if getattr(inference, "needs_glibc", False) and claimed_libc == "musl":
        # The model contradicted the workload facts it was given. The
        # guards would catch this too, but it is a proposal defect, not
        # a compatibility discovery, so it is filtered here and counted
        # as such.
        logger.warning("AI proposal rejected: musl candidate for a "
                       "glibc workload")
        return None
    try:
        confidence = float(payload.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    # Clamp: the model's self-reported confidence is advisory and must
    # never exceed what an operator override would carry.
    confidence = max(0.0, min(confidence, 0.95))
    return candidate, confidence


def propose_base(
    original_base: str,
    inference: Any,
    dockerfile_text: str,
    *,
    model: str = DEFAULT_MODEL,
    timeout_s: float = 60.0,
    cache_only: bool = False,
) -> Optional[Tuple[str, float]]:
    """Ask Claude for one replacement base image. Returns
    ``(candidate_ref, confidence)`` or None on any failure.

    ``cache_only=True`` refuses to hit the network, so a replay run is
    provably offline: if the cache misses, the arm falls back to the
    deterministic selector and the miss is logged.
    """
    prompt = _build_prompt(original_base, inference, dockerfile_text)
    key = _cache_key(model, prompt)

    cached = _cache_read(key)
    if cached is not None:
        logger.info("AI proposal for %s served from cache (%s)",
                    original_base, key[:12])
        return _validate(cached.get("payload", {}), original_base, inference)
    if cache_only:
        logger.warning("AI cache miss for %s in cache-only mode; falling "
                       "back to deterministic selection", original_base)
        return None

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set; --ai-propose falls back "
                       "to deterministic selection")
        return None
    try:
        import anthropic
    except ImportError:
        logger.warning("anthropic SDK not installed; --ai-propose falls "
                       "back to deterministic selection")
        return None

    client = anthropic.Anthropic(api_key=api_key, timeout=timeout_s)
    t0 = time.time()
    try:
        resp = client.messages.create(
            model=model,
            max_tokens=1024,
            temperature=0,
            tools=[{
                "name": "propose_base_image",
                "description": "Return the single best replacement base image.",
                "input_schema": _PROPOSAL_SCHEMA,
            }],
            tool_choice={"type": "tool", "name": "propose_base_image"},
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        logger.warning("AI proposal call failed for %s (%s: %s); falling "
                       "back to deterministic selection",
                       original_base, type(e).__name__, e)
        return None

    payload: Dict[str, Any] = {}
    for block in getattr(resp, "content", []) or []:
        if getattr(block, "type", "") == "tool_use":
            payload = dict(getattr(block, "input", {}) or {})
            break

    # Cache the RAW payload plus provenance, before validation, so a
    # replay reproduces the validation decision as well as the answer.
    _cache_write(key, {
        "model": model,
        "prompt_sha256": key,
        "original_base": original_base,
        "payload": payload,
        "latency_seconds": round(time.time() - t0, 2),
        "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    return _validate(payload, original_base, inference)
