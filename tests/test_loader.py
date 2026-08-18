"""Tests for src.loader_fingerprint (P5-2)."""
from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest


def _make_elf64(loader_path: str) -> bytes:
    """Build a minimal ELF64 file with a PT_INTERP program header
    pointing to ``loader_path``. The file has just enough structure
    that _read_pt_interp can parse it."""
    interp_bytes = loader_path.encode("ascii") + b"\x00"
    interp_offset = 0x1000

    e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9  # 64-bit LE Linux
    # Ehdr (after e_ident): HHIQQQIHHHHHH
    e_type = 2          # ET_EXEC
    e_machine = 0x3e    # x86_64
    e_version = 1
    e_entry = 0
    e_phoff = 0x40
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 0
    e_shnum = 0
    e_shstrndx = 0

    ehdr = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
        e_flags, e_ehsize, e_phentsize, e_phnum,
        e_shentsize, e_shnum, e_shstrndx,
    )

    # Phdr: IIQQQQQQ  (p_type, p_flags, p_offset, p_vaddr, p_paddr,
    #                  p_filesz, p_memsz, p_align)
    p_type = 3  # PT_INTERP
    phdr = struct.pack(
        "<IIQQQQQQ",
        p_type, 0x4, interp_offset, 0, 0, len(interp_bytes),
        len(interp_bytes), 1,
    )

    blob = bytearray(0x2000)
    blob[0:16] = e_ident
    blob[16:16 + len(ehdr)] = ehdr
    blob[0x40:0x40 + len(phdr)] = phdr
    blob[interp_offset:interp_offset + len(interp_bytes)] = interp_bytes
    return bytes(blob)


class TestLoaderClassification:

    def test_classify_glibc_x86_64(self):
        from src.loader_fingerprint import _classify_loader
        assert _classify_loader("/lib64/ld-linux-x86-64.so.2") == (
            "glibc", "x86_64"
        )

    def test_classify_musl(self):
        from src.loader_fingerprint import _classify_loader
        assert _classify_loader("/lib/ld-musl-aarch64.so.1") == (
            "musl", "aarch64"
        )

    def test_classify_unknown(self):
        from src.loader_fingerprint import _classify_loader
        assert _classify_loader("") == (None, None)
        assert _classify_loader("/some/weird/path") == (None, None)

    def test_classify_pattern_fallback(self):
        """Unknown exact path but recognizable pattern."""
        from src.loader_fingerprint import _classify_loader
        family, arch = _classify_loader("/usr/lib/ld-musl-mips64.so.1")
        assert family == "musl"


class TestConfdFingerprint:

    def test_debian_signature(self):
        from src.loader_fingerprint import _confd_distro_hint
        assert _confd_distro_hint(
            ("libc.conf", "x86_64-linux-gnu.conf")
        ) == "debian"

    def test_rhel_family_signature(self):
        from src.loader_fingerprint import _confd_distro_hint
        result = _confd_distro_hint(("tls.conf", "usrmove.conf"))
        assert result in {"rhel", "alma", "rocky", "centos"}

    def test_empty(self):
        from src.loader_fingerprint import _confd_distro_hint
        assert _confd_distro_hint(()) is None


class TestElfReader:

    def test_reads_pt_interp_x86_64(self):
        from src.loader_fingerprint import _read_pt_interp
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(_make_elf64("/lib64/ld-linux-x86-64.so.2"))
            path = Path(f.name)
        try:
            assert _read_pt_interp(path) == "/lib64/ld-linux-x86-64.so.2"
        finally:
            path.unlink(missing_ok=True)

    def test_reads_musl_pt_interp(self):
        from src.loader_fingerprint import _read_pt_interp
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(_make_elf64("/lib/ld-musl-x86_64.so.1"))
            path = Path(f.name)
        try:
            assert _read_pt_interp(path) == "/lib/ld-musl-x86_64.so.1"
        finally:
            path.unlink(missing_ok=True)

    def test_non_elf_returns_none(self):
        from src.loader_fingerprint import _read_pt_interp
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"not an ELF file at all")
            path = Path(f.name)
        try:
            assert _read_pt_interp(path) is None
        finally:
            path.unlink(missing_ok=True)


class TestFingerprintFromPaths:

    def test_full_glibc_debian(self):
        """End-to-end: binary + conf.d gives debian + glibc."""
        from src.loader_fingerprint import fingerprint_from_paths
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # Fake binary with glibc loader
            bin_path = tdp / "sh"
            bin_path.write_bytes(_make_elf64("/lib64/ld-linux-x86-64.so.2"))
            # Debian-style conf.d
            confd = tdp / "ld.so.conf.d"
            confd.mkdir()
            (confd / "libc.conf").write_text("/usr/local/lib")
            (confd / "x86_64-linux-gnu.conf").write_text("/usr/lib/x86_64-linux-gnu")

            fp = fingerprint_from_paths(
                binary_path=bin_path, ld_conf_d_dir=confd,
            )
            assert fp.libc_family == "glibc"
            assert fp.architecture == "x86_64"
            assert fp.distro_hint == "debian"
            assert fp.confidence > 0.5

    def test_empty_input(self):
        from src.loader_fingerprint import fingerprint_from_paths
        fp = fingerprint_from_paths()
        assert fp.empty
        assert fp.confidence < 0.5
