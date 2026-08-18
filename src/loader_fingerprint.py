#!/usr/bin/env python3
"""
P5-2: Dynamic-loader fingerprinting.

Extracts a tampering-resistant identity signal from a container image
by reading the dynamic linker artifacts. None of the data sources used
here can be lied about without breaking the image's dynamically-linked
binaries, which makes this a strong corroborating witness for the
multi-tier provenance fingerprint in :mod:`src.provenance_fingerprint`.

Signals collected (each is None when the image does not expose it):

  * ``loader_path``   ELF ``PT_INTERP`` of a canonical binary
                       (``/bin/sh`` or ``/usr/bin/env``)
  * ``libc_family``   ``glibc`` / ``musl`` / ``uclibc`` / ``none``
  * ``libc_version``  As reported by ``ldd --version`` when available
  * ``ld_conf_set``   Inventory of ``/etc/ld.so.conf.d/*.conf`` entries
  * ``musl_conf``     Presence of ``/etc/ld-musl-<arch>.path``
  * ``ldconfig_path`` Location of the ``ldconfig`` binary
  * ``architecture``  Inferred from ELF header

The module does NOT execute any code from inside the image. It uses
``docker create`` + ``docker cp`` against an inert container, parses
files in process, then ``docker rm`` cleans up.
"""
from __future__ import annotations

import logging
import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Recognized loader paths and the libc family they imply.
# Keys are case-sensitive Linux paths; values are (libc_family,
# architecture) tuples used downstream by the inference engine.
_LOADER_FAMILIES: Dict[str, Tuple[str, str]] = {
    "/lib64/ld-linux-x86-64.so.2":         ("glibc",   "x86_64"),
    "/lib/ld-linux.so.2":                  ("glibc",   "i386"),
    "/lib/ld-linux-aarch64.so.1":          ("glibc",   "aarch64"),
    "/lib/ld-linux-armhf.so.3":            ("glibc",   "armv7"),
    "/lib64/ld-linux-riscv64-lp64d.so.1":  ("glibc",   "riscv64"),
    "/lib64/ld64.so.2":                    ("glibc",   "ppc64le"),
    "/lib/ld64.so.1":                      ("glibc",   "s390x"),
    "/lib/ld-musl-x86_64.so.1":            ("musl",    "x86_64"),
    "/lib/ld-musl-aarch64.so.1":           ("musl",    "aarch64"),
    "/lib/ld-musl-armhf.so.1":             ("musl",    "armv7"),
    "/lib/ld-uClibc.so.0":                 ("uclibc",  "x86_64"),
}

# Canonical binaries we try (in order) for PT_INTERP extraction.
_CANONICAL_BINARIES = (
    "/bin/sh", "/usr/bin/env", "/bin/busybox",
    "/usr/bin/coreutils", "/bin/bash", "/usr/bin/python3",
)

# Files we extract for non-binary signals.
_FS_PROBES = (
    "/etc/ld.so.conf",
    "/etc/ld.so.cache",
    "/etc/ld-musl-x86_64.path",
    "/etc/ld-musl-aarch64.path",
    "/sbin/ldconfig",
    "/usr/sbin/ldconfig",
)
_FS_DIRS = ("/etc/ld.so.conf.d",)


@dataclass(frozen=True)
class LoaderFingerprint:
    loader_path: Optional[str] = None
    libc_family: Optional[str] = None
    libc_version: Optional[str] = None
    architecture: Optional[str] = None
    ld_conf_present: bool = False
    ld_so_cache_present: bool = False
    musl_conf_present: bool = False
    ldconfig_location: Optional[str] = None
    ld_conf_d_entries: Tuple[str, ...] = ()
    distro_hint: Optional[str] = None
    evidence: Tuple[str, ...] = ()
    confidence: float = 0.0

    @property
    def empty(self) -> bool:
        return self.loader_path is None and not self.ld_conf_d_entries


# ════════════════════════════════════════════════════════════════════
# ELF parser (pure Python, no third-party deps)
# ════════════════════════════════════════════════════════════════════

# Minimal ELF subset needed to find PT_INTERP. Reads only the headers,
# never the section data, so a malformed-but-runnable ELF still yields
# the loader path. Tolerant to truncated tails.
def _read_pt_interp(elf_path: Path) -> Optional[str]:
    try:
        with open(elf_path, "rb") as f:
            ident = f.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF":
                return None
            ei_class = ident[4]  # 1 = 32-bit, 2 = 64-bit
            ei_data = ident[5]   # 1 = little-endian, 2 = big-endian
            endian = "<" if ei_data == 1 else ">"

            if ei_class == 1:  # 32-bit
                # Ehdr layout after e_ident: e_type, e_machine,
                # e_version, e_entry, e_phoff, e_shoff, e_flags,
                # e_ehsize, e_phentsize, e_phnum, e_shentsize,
                # e_shnum, e_shstrndx
                fmt_eh = endian + "HHIIIIIHHHHHH"
                eh_size = struct.calcsize(fmt_eh)
                eh = struct.unpack(fmt_eh, f.read(eh_size))
                e_phoff = eh[4]
                e_phentsize = eh[8]
                e_phnum = eh[9]
                fmt_ph = endian + "IIIIIIII"
            elif ei_class == 2:  # 64-bit
                # Ehdr64 layout: same field order, e_entry/e_phoff/
                # e_shoff widened to 64-bit.
                fmt_eh = endian + "HHIQQQIHHHHHH"
                eh_size = struct.calcsize(fmt_eh)
                eh = struct.unpack(fmt_eh, f.read(eh_size))
                e_phoff = eh[4]
                e_phentsize = eh[8]
                e_phnum = eh[9]
                fmt_ph = endian + "IIQQQQQQ"
            else:
                return None

            f.seek(e_phoff)
            for _ in range(min(e_phnum, 64)):  # cap for safety
                ph_bytes = f.read(e_phentsize)
                if len(ph_bytes) < struct.calcsize(fmt_ph):
                    return None
                ph = struct.unpack(fmt_ph, ph_bytes[:struct.calcsize(fmt_ph)])
                # PT_INTERP = 3
                if ei_class == 1:
                    p_type, p_offset, _, _, p_filesz, *_ = ph
                else:
                    p_type, _, p_offset, _, _, p_filesz, *_ = ph
                if p_type == 3 and 0 < p_filesz < 4096:
                    f.seek(p_offset)
                    raw = f.read(p_filesz)
                    return raw.rstrip(b"\x00").decode("ascii", "replace")
            return None
    except (OSError, struct.error, UnicodeDecodeError) as e:
        logger.debug("ELF parse failed for %s: %s", elf_path, e)
        return None


def _classify_loader(loader_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Map a PT_INTERP path to (libc_family, architecture)."""
    if not loader_path:
        return None, None
    if loader_path in _LOADER_FAMILIES:
        return _LOADER_FAMILIES[loader_path]
    if "ld-musl" in loader_path:
        return "musl", None
    if "ld-linux" in loader_path or "ld64.so" in loader_path:
        return "glibc", None
    if "uClibc" in loader_path:
        return "uclibc", None
    return None, None


# ════════════════════════════════════════════════════════════════════
# Distro fingerprint from ld.so.conf.d entries
# ════════════════════════════════════════════════════════════════════

# Per-distro fingerprint sets (subset of conf.d entries that strongly
# indicate the listed distribution family). Each fingerprint is a set
# of conf.d basenames; presence-or-absence is the signal.
_CONFD_FINGERPRINTS: Dict[str, frozenset] = {
    "debian": frozenset({"libc.conf", "x86_64-linux-gnu.conf"}),
    "ubuntu": frozenset({"libc.conf", "x86_64-linux-gnu.conf",
                         "fakeroot-x86_64-linux-gnu.conf"}),
    "rhel":   frozenset({"tls.conf", "usrmove.conf"}),
    "fedora": frozenset({"tls.conf", "usrmove.conf",
                         "libiscsi-x86_64.conf"}),
    "alma":   frozenset({"tls.conf", "usrmove.conf"}),
    "rocky":  frozenset({"tls.conf", "usrmove.conf"}),
    "centos": frozenset({"tls.conf", "usrmove.conf"}),
    "arch":   frozenset(),  # Arch ships ld.so.conf.d empty by default
}


def _confd_distro_hint(entries: Tuple[str, ...]) -> Optional[str]:
    """Match observed conf.d basenames against per-distro signatures."""
    obs = set(entries)
    if not obs:
        return None
    best, best_score = None, 0.0
    for distro, fp in _CONFD_FINGERPRINTS.items():
        if not fp:
            continue
        overlap = len(fp & obs)
        denom = max(len(fp | obs), 1)
        score = overlap / denom
        if score > best_score:
            best, best_score = distro, score
    return best if best_score >= 0.4 else None


# ════════════════════════════════════════════════════════════════════
# Image filesystem extraction (no code execution)
# ════════════════════════════════════════════════════════════════════

def _docker_create(image_ref: str, timeout_s: int) -> Optional[str]:
    """Create an inert container; return its id or None on failure."""
    try:
        r = subprocess.run(
            ["docker", "create", "--entrypoint", "/bin/true", image_ref],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s, check=False,
        )
        if r.returncode != 0:
            logger.debug("docker create failed: %s", r.stderr.decode("utf-8", "replace"))
            return None
        return r.stdout.decode("ascii", "replace").strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug("docker create error: %s", e)
        return None


def _docker_cp(container_id: str, src: str, dst: Path, timeout_s: int) -> bool:
    try:
        # -L: dereference the symlink INSIDE the container and copy the
        # target's bytes. Without it, a container symlink like
        # /bin/sh -> /bin/busybox is copied as an absolute-target symlink,
        # and reading it on the host follows the link into the HOST
        # filesystem (e.g. the host's glibc busybox), corrupting the
        # loader signal — a musl image can read back as glibc.
        r = subprocess.run(
            ["docker", "cp", "-L", f"{container_id}:{src}", str(dst)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s, check=False,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _docker_rm(container_id: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", container_id],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


# ════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════

def fingerprint_image(
    image_ref: str,
    *,
    timeout_s: int = 30,
) -> LoaderFingerprint:
    """Build a LoaderFingerprint for ``image_ref`` without executing
    any code from inside the image.

    Returns an empty LoaderFingerprint when Docker is not available
    or the image cannot be inspected. Callers must treat ``empty=True``
    as "no signal" rather than as "image is broken."
    """
    import shutil
    if not shutil.which("docker"):
        logger.debug("docker not on PATH; skipping loader fingerprint")
        return LoaderFingerprint()

    cid = _docker_create(image_ref, timeout_s)
    if not cid:
        return LoaderFingerprint()

    evidence: List[str] = []
    loader_path: Optional[str] = None
    libc_family: Optional[str] = None
    architecture: Optional[str] = None
    ld_conf_d_entries: Tuple[str, ...] = ()
    ld_conf_present = False
    ld_so_cache_present = False
    musl_conf_present = False
    ldconfig_location: Optional[str] = None

    try:
        with tempfile.TemporaryDirectory(prefix="autopatch_fp_") as td:
            tdp = Path(td)

            # Tier A: PT_INTERP from a canonical binary
            for candidate in _CANONICAL_BINARIES:
                local = tdp / Path(candidate).name
                if _docker_cp(cid, candidate, local, timeout_s):
                    interp = _read_pt_interp(local)
                    if interp:
                        loader_path = interp
                        libc_family, architecture = _classify_loader(interp)
                        evidence.append(
                            f"PT_INTERP from {candidate}: {interp}"
                        )
                        break

            # Tier B: ld.so.conf presence
            for probe in _FS_PROBES:
                local = tdp / Path(probe).name
                if _docker_cp(cid, probe, local, timeout_s):
                    if probe == "/etc/ld.so.conf":
                        ld_conf_present = True
                        evidence.append("/etc/ld.so.conf present")
                    elif probe == "/etc/ld.so.cache":
                        ld_so_cache_present = True
                        evidence.append("/etc/ld.so.cache present")
                    elif probe.startswith("/etc/ld-musl-"):
                        musl_conf_present = True
                        evidence.append(f"{probe} present")
                    elif probe.endswith("ldconfig"):
                        ldconfig_location = probe
                        evidence.append(f"ldconfig at {probe}")

            # Tier C: /etc/ld.so.conf.d/ contents
            for d in _FS_DIRS:
                local = tdp / "ld_conf_d"
                if _docker_cp(cid, d, local, timeout_s):
                    if local.is_dir():
                        entries = sorted(
                            p.name for p in local.iterdir()
                            if p.is_file() and p.name.endswith(".conf")
                        )
                        ld_conf_d_entries = tuple(entries)
                        if entries:
                            evidence.append(
                                f"{d}/ has {len(entries)} entries"
                            )
    finally:
        _docker_rm(cid)

    distro_hint = _confd_distro_hint(ld_conf_d_entries)
    if distro_hint:
        evidence.append(f"conf.d fingerprint matched {distro_hint}")

    # Confidence: sum of signal strengths, sigmoid-bounded
    score = 0.0
    if loader_path:
        score += 1.5
    if libc_family:
        score += 1.0
    if ld_conf_present or musl_conf_present:
        score += 0.6
    if ld_conf_d_entries:
        score += 0.4
    if distro_hint:
        score += 0.7
    if ldconfig_location:
        score += 0.3
    confidence = 1.0 / (1.0 + 2.71828 ** (-score + 1.0))

    return LoaderFingerprint(
        loader_path=loader_path,
        libc_family=libc_family,
        architecture=architecture,
        ld_conf_present=ld_conf_present,
        ld_so_cache_present=ld_so_cache_present,
        musl_conf_present=musl_conf_present,
        ldconfig_location=ldconfig_location,
        ld_conf_d_entries=ld_conf_d_entries,
        distro_hint=distro_hint,
        evidence=tuple(evidence),
        confidence=confidence,
    )


def fingerprint_from_paths(
    binary_path: Optional[Path] = None,
    ld_conf_d_dir: Optional[Path] = None,
    musl_conf_path: Optional[Path] = None,
) -> LoaderFingerprint:
    """Test-only entrypoint: build a fingerprint from already-extracted
    local paths. Avoids the Docker dependency so unit tests can run on
    any host.
    """
    evidence: List[str] = []
    loader_path: Optional[str] = None
    libc_family: Optional[str] = None
    architecture: Optional[str] = None
    entries: Tuple[str, ...] = ()
    musl_conf_present = bool(musl_conf_path and Path(musl_conf_path).exists())

    if binary_path and Path(binary_path).is_file():
        loader_path = _read_pt_interp(Path(binary_path))
        if loader_path:
            libc_family, architecture = _classify_loader(loader_path)
            evidence.append(f"PT_INTERP from {binary_path}: {loader_path}")

    if ld_conf_d_dir and Path(ld_conf_d_dir).is_dir():
        entries = tuple(sorted(
            p.name for p in Path(ld_conf_d_dir).iterdir()
            if p.is_file() and p.name.endswith(".conf")
        ))

    distro_hint = _confd_distro_hint(entries)
    if distro_hint:
        evidence.append(f"conf.d fingerprint matched {distro_hint}")

    score = (1.5 if loader_path else 0) + (1.0 if libc_family else 0) \
            + (0.4 if entries else 0) + (0.7 if distro_hint else 0) \
            + (0.6 if musl_conf_present else 0)
    confidence = 1.0 / (1.0 + 2.71828 ** (-score + 1.0))

    return LoaderFingerprint(
        loader_path=loader_path,
        libc_family=libc_family,
        architecture=architecture,
        ld_conf_d_entries=entries,
        musl_conf_present=musl_conf_present,
        distro_hint=distro_hint,
        evidence=tuple(evidence),
        confidence=confidence,
    )
