"""Tests for src.glibc_detector (P4-25)."""
from __future__ import annotations

import pytest


class TestGlibcByteScan:
    """detect_glibc_versions_in_bytes / max_glibc are pure functions
    over byte buffers; they must extract every GLIBC_X.Y literal
    regardless of surrounding noise."""

    def test_extracts_versions_from_raw_bytes(self):
        from src.glibc_detector import detect_glibc_versions_in_bytes
        # Simulate the .gnu.version_r region of an ELF: GLIBC_X.Y
        # strings interleaved with NULs and unrelated symbols.
        blob = b"\x00\x00GLIBC_2.17\x00__libc_start_main\x00GLIBC_2.34\x00"
        vs = detect_glibc_versions_in_bytes(blob)
        assert vs == {"2.17", "2.34"}

    def test_returns_empty_on_no_match(self):
        from src.glibc_detector import detect_glibc_versions_in_bytes
        assert detect_glibc_versions_in_bytes(b"") == set()
        assert detect_glibc_versions_in_bytes(b"hello world") == set()

    def test_handles_three_component_versions(self):
        from src.glibc_detector import detect_glibc_versions_in_bytes
        assert detect_glibc_versions_in_bytes(b"GLIBC_2.17.1") == {"2.17.1"}

    def test_max_glibc_picks_highest(self):
        from src.glibc_detector import max_glibc
        # Lexicographic ordering would give "2.9" > "2.34"; we must
        # do tuple comparison so 2.34 wins.
        assert max_glibc({"2.9", "2.17", "2.34"}) == "2.34"
        assert max_glibc(set()) is None

    def test_max_glibc_ignores_garbage(self):
        from src.glibc_detector import max_glibc
        # Non-numeric entries fall back to (0,) so they cannot win.
        assert max_glibc({"2.17", "garbage", "2.34"}) == "2.34"


class TestBaseImageLookup:
    """get_base_image_glibc must look up the glibc bundled with the
    candidate base, tolerating registry prefixes and tag variants."""

    def test_known_debian(self):
        from src.glibc_detector import get_base_image_glibc
        assert get_base_image_glibc("debian:bookworm") == "2.36"
        assert get_base_image_glibc("debian:12") == "2.36"

    def test_strips_registry_prefix(self):
        from src.glibc_detector import get_base_image_glibc
        assert get_base_image_glibc("docker.io/library/debian:12") == "2.36"

    def test_alpine_is_musl_none(self):
        from src.glibc_detector import get_base_image_glibc
        # Alpine returns None to signal "musl, not glibc".
        assert get_base_image_glibc("alpine:3.19") is None

    def test_unknown_returns_none(self):
        from src.glibc_detector import get_base_image_glibc
        assert get_base_image_glibc("nonexistent/base:99.99") is None
        assert get_base_image_glibc("") is None

    def test_falls_back_to_major_tag(self):
        from src.glibc_detector import get_base_image_glibc
        # When `debian:11.5` isn't known, fall back to `debian:11`.
        assert get_base_image_glibc("debian:11.5") == "2.31"


class TestRequirementSatisfaction:
    """base_satisfies_requirement must fail closed: unknown bases
    against a real requirement are rejected; no-requirement always
    passes."""

    def test_passes_with_no_requirement(self):
        from src.glibc_detector import base_satisfies_requirement
        assert base_satisfies_requirement("debian:11", None) is True

    def test_passes_when_base_newer(self):
        from src.glibc_detector import (
            base_satisfies_requirement, GlibcRequirement,
        )
        req = GlibcRequirement(versions=("2.31",), minimum_required="2.31")
        # debian:12 ships 2.36 >= 2.31
        assert base_satisfies_requirement("debian:12", req) is True

    def test_fails_when_base_older(self):
        from src.glibc_detector import (
            base_satisfies_requirement, GlibcRequirement,
        )
        # Workload requires 2.36 but ubuntu:20.04 only ships 2.31
        req = GlibcRequirement(versions=("2.36",), minimum_required="2.36")
        assert base_satisfies_requirement("ubuntu:20.04", req) is False

    def test_fails_closed_on_unknown_base(self):
        from src.glibc_detector import (
            base_satisfies_requirement, GlibcRequirement,
        )
        req = GlibcRequirement(versions=("2.17",), minimum_required="2.17")
        # Unknown bases are rejected even though 2.17 is trivially old.
        assert base_satisfies_requirement("ghost/distro:1", req) is False

    def test_alpine_musl_fails_glibc_requirement(self):
        from src.glibc_detector import (
            base_satisfies_requirement, GlibcRequirement,
        )
        req = GlibcRequirement(versions=("2.17",), minimum_required="2.17")
        # Alpine ships musl, not glibc; can't satisfy a glibc floor.
        assert base_satisfies_requirement("alpine:3.19", req) is False
