#!/usr/bin/env python3
"""
P4-27: Multi-architecture support.

Lets AutoPatch build, scan, gate, and publish a patched image for
*every* requested platform in one pipeline run. The contract is:

  * Build each platform separately with ``docker buildx build
    --platform <p>``. Each build produces a per-platform image
    digest.
  * Run the existing scan + acceptance gate against EACH platform's
    image. The combined run is only accepted when ALL platforms
    pass; one failure rejects the whole release. This is the only
    safe policy: a manifest list whose ``amd64`` entry is patched
    but whose ``arm64`` entry still ships the old base image is
    strictly worse than a single-platform release, because consumers
    on the bad arch will silently get the unpatched build.
  * If every platform passes, publish a manifest list (also called
    an "image index" in the OCI spec) pointing at the per-arch
    digests. ``docker buildx imagetools create`` is the right tool
    for this; ``docker manifest`` is deprecated.

This module deliberately contains only the *coordination logic*
(parsing, validation, aggregation) so it can be unit-tested without
Docker. The actual buildx invocations live behind small wrappers
that the integration tests can mock out.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# Set of OCI platforms we accept on the command line. Anything else is
# rejected up front so the user gets a clear error rather than a
# half-built release.
_KNOWN_PLATFORMS: frozenset = frozenset({
    "linux/amd64",
    "linux/arm64",
    "linux/arm/v7",
    "linux/arm/v6",
    "linux/386",
    "linux/ppc64le",
    "linux/s390x",
    "linux/riscv64",
})

# A loose syntactic check for platform spec strings: ``os/arch`` or
# ``os/arch/variant``. We allow only lowercase letters, digits, and a
# couple of separators so the string is always safe to embed in a
# shell argument without quoting tricks.
_PLATFORM_RE = re.compile(r"^[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?$")


@dataclass
class PlatformResult:
    """Per-platform outcome of build + scan + gate."""
    platform: str
    image_digest: str = ""
    accepted: bool = False
    reasons: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class MultiArchOutcome:
    """Aggregate result across every requested platform."""
    platforms: List[PlatformResult]
    manifest_ref: Optional[str] = None  # set when published

    @property
    def all_accepted(self) -> bool:
        return bool(self.platforms) and all(p.accepted for p in self.platforms)

    @property
    def first_failure(self) -> Optional[PlatformResult]:
        for p in self.platforms:
            if not p.accepted:
                return p
        return None


def parse_platforms(spec: str) -> List[str]:
    """Parse a ``--platforms`` argument string into a deduplicated,
    order-preserving list. ``spec`` may be ``linux/amd64`` or
    ``linux/amd64,linux/arm64``; whitespace is tolerated. Unknown or
    malformed platform strings raise ``ValueError`` so the caller
    fails fast rather than building something it cannot publish.
    """
    if not spec or not spec.strip():
        raise ValueError("empty --platforms spec")
    seen: List[str] = []
    seen_set = set()
    for raw in spec.split(","):
        p = raw.strip().lower()
        if not p:
            continue
        if not _PLATFORM_RE.match(p):
            raise ValueError(f"malformed platform: {raw!r}")
        if p not in _KNOWN_PLATFORMS:
            raise ValueError(
                f"unknown platform {p!r}; supported: "
                f"{', '.join(sorted(_KNOWN_PLATFORMS))}"
            )
        if p not in seen_set:
            seen.append(p)
            seen_set.add(p)
    if not seen:
        raise ValueError("no platforms parsed from spec")
    return seen


def ensure_buildx_available(
    runner: Optional[Callable[[Sequence[str]], Tuple[int, str]]] = None,
) -> bool:
    """Return True iff a working ``docker buildx`` is on PATH.

    A custom ``runner`` lets tests inject a deterministic stub. The
    real runner shells out via :mod:`subprocess`.
    """
    if not shutil.which("docker"):
        return False
    cmd: Sequence[str] = ["docker", "buildx", "version"]
    try:
        if runner is None:
            proc = subprocess.run(
                list(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            code = proc.returncode
            out = proc.stdout.decode("utf-8", "replace")
        else:
            code, out = runner(cmd)
        return code == 0 and "buildx" in out.lower()
    except (OSError, subprocess.TimeoutExpired):
        return False


def aggregate_results(per_platform: Iterable[PlatformResult]) -> MultiArchOutcome:
    """Combine per-platform outcomes into the aggregate result.

    Pure function — no I/O — so the orchestration can be tested in
    isolation. Ordering is preserved so the report shows platforms in
    the same order the user listed them.
    """
    return MultiArchOutcome(platforms=list(per_platform))


def build_manifest_list_command(
    target_tag: str,
    per_platform: Sequence[PlatformResult],
) -> List[str]:
    """Return the ``docker buildx imagetools create`` argv that would
    publish the manifest list for ``target_tag`` pointing at every
    per-platform digest.

    Returned as a list so the caller can run it with the same
    ``run_cmd`` helper the rest of the codebase uses (and so tests
    can assert on the exact argv without spawning a process).
    """
    if not target_tag:
        raise ValueError("target_tag is required")
    digests = [p.image_digest for p in per_platform if p.image_digest]
    if not digests:
        raise ValueError(
            "cannot publish manifest list: no per-platform digests"
        )
    return [
        "docker", "buildx", "imagetools", "create",
        "--tag", target_tag,
        *digests,
    ]


def summarise(outcome: MultiArchOutcome) -> Dict[str, object]:
    """Compact summary suitable for the JSON report and the lineage
    attestation. The structure is intentionally flat so a downstream
    consumer can diff two summaries without recursive walks."""
    return {
        "all_accepted": outcome.all_accepted,
        "platform_count": len(outcome.platforms),
        "manifest_ref": outcome.manifest_ref,
        "platforms": [
            {
                "platform": p.platform,
                "image_digest": p.image_digest,
                "accepted": p.accepted,
                "reasons": list(p.reasons),
                "error": p.error,
            }
            for p in outcome.platforms
        ],
    }
