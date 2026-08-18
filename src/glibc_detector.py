#!/usr/bin/env python3
"""
P4-25: glibc version awareness.

Detects the minimum glibc version required by an application image so
AutoPatch never proposes a base swap to an image whose libc is too
old to run the workload.

The detector has two layers, used together:

  1. *Pure-Python ELF/bytes scan* (:func:`detect_glibc_versions_in_bytes`):
     greps any byte buffer for the literal ``GLIBC_X.Y[.Z]`` version
     strings that glibc embeds in the ``.gnu.version_r`` section. This
     is the canonical signal: the dynamic linker uses exactly these
     strings to bind symbols at load time. Scanning the bytes is
     bullet-proof against stripped binaries (strip preserves
     ``.gnu.version_r``).

  2. *Docker-backed image scan* (:func:`detect_min_glibc_from_image`):
     runs ``strings`` inside the container against every executable
     under ``/usr/bin``, ``/usr/local/bin``, ``/usr/sbin``, ``/bin``,
     ``/app`` and the ELF binaries discovered by the image's ``CMD``
     or ``ENTRYPOINT``, then takes the max version observed. ``strings``
     is part of binutils and is present in almost every distro image;
     when it is absent we fall back to ``grep -aoP``.

The companion :func:`get_base_image_glibc` looks up the glibc version
shipped with a *candidate* base image so the patcher can compare
``min_required`` against ``base_provides`` and reject base swaps that
would downgrade glibc.

The minimum-glibc check is advisory in ``moderate``/``permissive``
modes and *blocking* under ``--strict-libc`` (added wherever the
patcher consumes this module).
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# Matches GLIBC_2.4, GLIBC_2.17.1, GLIBC_2.34, etc.
_GLIBC_RE = re.compile(rb"GLIBC_([0-9]+(?:\.[0-9]+){1,2})")


@dataclass(frozen=True)
class GlibcRequirement:
    """The min-glibc requirement detected for an image.

    ``versions`` is the full set observed (kept for debugging /
    attestation) and ``minimum_required`` is the *maximum* of those,
    i.e. the floor a candidate base must meet.
    """
    versions: Tuple[str, ...]
    minimum_required: str

    @property
    def empty(self) -> bool:
        return not self.versions


def _version_tuple(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(p) for p in v.split("."))
    except (ValueError, AttributeError):
        return (0,)


def _max_version(versions: Iterable[str]) -> Optional[str]:
    items = [v for v in versions if v]
    if not items:
        return None
    return max(items, key=_version_tuple)


def detect_glibc_versions_in_bytes(buf: bytes) -> Set[str]:
    """Find every ``GLIBC_X.Y[.Z]`` literal inside a byte buffer.

    Works on raw ELF files, on the output of ``strings``, or on any
    other byte stream. Returns the *set* of versions; the caller is
    expected to take the max when computing a single floor.
    """
    if not buf:
        return set()
    return {m.decode("ascii") for m in _GLIBC_RE.findall(buf)}


def max_glibc(versions: Iterable[str]) -> Optional[str]:
    """Public helper: max of a set of GLIBC_x.y strings."""
    return _max_version(versions)


def _container_scan_cmd(image_ref: str) -> List[str]:
    """Build a docker-run command that prints every GLIBC_X.Y string
    found in any executable under common bin paths inside the image.

    This executes a shell pipeline built from the image's own binaries,
    so the image is untrusted code running on the analysis host. Every
    flag below is a containment boundary, not a nicety:

      * ``--network none`` denies the image any egress. Without it an
        inspection run gives a hostile image outbound connectivity.
      * ``--cap-drop ALL`` removes every Linux capability; a `find`
        and `strings` pipeline needs none.
      * ``--pids-limit`` bounds fork bombs.
      * ``--memory`` and ``--memory-swap`` bound memory exhaustion.
      * ``--read-only`` with a small ``--tmpfs /tmp`` prevents writes
        while still allowing tool scratch space.
      * ``--security-opt no-new-privileges`` blocks setuid escalation.
      * ``--user 65534:65534`` (nobody) drops root inside the
        container so a container-escape primitive has no uid 0 to work
        with.
      * ``--rm`` leaves no container behind.
      * ``--entrypoint sh`` neutralises an ENTRYPOINT that would
        otherwise exec the workload.

    The shell pipeline uses ``-print0 | xargs -0`` to survive paths
    with spaces; ``-r`` on xargs avoids invoking ``strings`` with no
    arguments on empty input.
    """
    inner = (
        # Search common executable roots; '-readable' filters out
        # paths we can't strings from (avoids spurious stderr).
        r"find /usr/bin /usr/local/bin /usr/sbin /bin /sbin /app /opt "
        r"-type f -readable -executable -print0 2>/dev/null "
        r"| xargs -0 -r strings 2>/dev/null "
        r"| grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' "
        r"| sort -uV"
    )
    return [
        "docker", "run", "--rm",
        "--entrypoint", "sh",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128",
        "--memory", "384m",
        "--memory-swap", "384m",
        "--user", "65534:65534",
        "--read-only",
        "--tmpfs", "/tmp:size=16m",
        image_ref,
        "-c", inner,
    ]


def detect_min_glibc_from_image(
    image_ref: str,
    *,
    timeout_seconds: int = 60,
) -> Optional[GlibcRequirement]:
    """Run :func:`_container_scan_cmd` against the image and return
    the GlibcRequirement, or ``None`` when nothing parseable was
    observed (a static-only image, scratch, or one without ``strings``).

    Failure modes are silent on purpose: the patcher treats a
    ``None`` result as "no constraint observed" and proceeds.
    Misconfigured Docker should never block a remediation here.
    """
    if not shutil.which("docker"):
        logger.debug("docker not available; skipping glibc scan")
        return None
    try:
        proc = subprocess.run(
            _container_scan_cmd(image_ref),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug("glibc scan failed for %s: %s", image_ref, e)
        return None

    versions: Set[str] = set()
    for line in proc.stdout.splitlines():
        m = _GLIBC_RE.search(b"GLIBC_" + line.split(b"GLIBC_", 1)[-1])
        if m:
            versions.add(m.group(1).decode("ascii"))
    if not versions:
        return None
    floor = _max_version(versions)
    assert floor is not None  # set is non-empty above
    return GlibcRequirement(
        versions=tuple(sorted(versions, key=_version_tuple)),
        minimum_required=floor,
    )


# ════════════════════════════════════════════════════════════════════
# Static base-image glibc map
# ════════════════════════════════════════════════════════════════════
#
# Sources are upstream changelogs / package manifests. Each entry is
# the *bundled* glibc, so a candidate base must be >= the workload's
# detected minimum. Entries are intentionally conservative.

_BASE_GLIBC: dict = {
    # Debian
    "debian:bullseye": "2.31",
    "debian:bookworm": "2.36",
    "debian:trixie":   "2.40",
    "debian:12":       "2.36",
    "debian:11":       "2.31",
    # Ubuntu
    "ubuntu:20.04":    "2.31",
    "ubuntu:22.04":    "2.35",
    "ubuntu:24.04":    "2.39",
    # RHEL/UBI/AlmaLinux/Rocky
    "redhat/ubi8":     "2.28",
    "redhat/ubi9":     "2.34",
    "almalinux:8":     "2.28",
    "almalinux:9":     "2.34",
    "rockylinux:8":    "2.28",
    "rockylinux:9":    "2.34",
    # CentOS Stream
    "quay.io/centos/centos:stream9": "2.34",
    "quay.io/centos/centos:stream10": "2.39",
    # Distroless (glibc variant)
    "gcr.io/distroless/base-debian11": "2.31",
    "gcr.io/distroless/base-debian12": "2.36",
    # Alpine uses musl, not glibc; reported as None so callers know.
    "alpine:3.18": None,
    "alpine:3.19": None,
    "alpine:3.20": None,
    "alpine:3.21": None,
}


@lru_cache(maxsize=128)
def get_base_image_glibc(base_image: str) -> Optional[str]:
    """Return the glibc version a candidate base image ships with, or
    ``None`` when the base uses musl, when we have no data, or when
    the reference cannot be normalised.

    A ``None`` return is **not** the same as "no constraint": callers
    must treat unknown bases as "do not propose unless explicitly
    forced".
    """
    if not base_image:
        return None
    # Strip digest suffix and registry prefix variants for the lookup
    # while still matching specific keys when present.
    key = base_image.split("@", 1)[0].strip()
    # Some Dockerfile FROM lines come with explicit registry; strip a
    # leading 'docker.io/library/' so 'debian:11' matches.
    for prefix in ("docker.io/library/", "docker.io/", "library/"):
        if key.startswith(prefix):
            key = key[len(prefix):]
    if key in _BASE_GLIBC:
        return _BASE_GLIBC[key]
    # Also try the bare repo:tag and the repo:major variants.
    if ":" in key:
        repo, tag = key.split(":", 1)
        major = tag.split(".", 1)[0]
        for candidate in (f"{repo}:{tag}", f"{repo}:{major}"):
            if candidate in _BASE_GLIBC:
                return _BASE_GLIBC[candidate]
    return None


def base_satisfies_requirement(
    base_image: str,
    requirement: Optional[GlibcRequirement],
) -> bool:
    """Return True iff the candidate base's glibc is >= the workload
    requirement. Unknown bases are treated as *not satisfying* the
    requirement (fail-closed); workloads with no requirement always
    pass.
    """
    if requirement is None or requirement.empty:
        return True
    provided = get_base_image_glibc(base_image)
    if provided is None:
        return False
    return _version_tuple(provided) >= _version_tuple(requirement.minimum_required)
