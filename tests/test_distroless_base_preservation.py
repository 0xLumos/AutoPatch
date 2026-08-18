"""A distroless runtime stage must stay distroless.

The bug this pins (bug #2, part two): the fix that kept plain distros in
their family (test_distro_runtime_selection) only recognised
``_is_distribution_repo`` bases. Distroless images
(``gcr.io/distroless/base-debian11``) were not covered, so a distroless
runtime hosting a Go binary still fell through to the language path:

  * headscale@legacy: gcr.io/distroless/base-debian11 running Go
    -> golang:1.23-bookworm, exploding 238 CVEs into 5667 (the full Go
    toolchain image). The acceptance gate declined it, but it is a
    catastrophic mis-pick and wastes an ~800MB build on every distroless
    image in the corpus.

The fix: distroless is minimal-runtime, upgraded within its own family
(the Debian release encoded in the repo leaf: base-debian11 ->
base-debian12), never redirected to a language image; and if already
current, left unchanged.
"""
from __future__ import annotations

import pytest

from src.patcher import (
    InferenceResult,
    _is_distroless,
    _distroless_same_family_bump,
    choose_base_image,
)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr("src.patcher._get_resolver", lambda: None)


def _inf(os_family, language=None, version=None, needs_glibc=False):
    r = InferenceResult()
    r.os_family = os_family
    r.language = language
    r.language_version = version
    r.needs_glibc = needs_glibc
    r.confidence = 0.7
    return r


class TestIsDistroless:

    @pytest.mark.parametrize("ref,want", [
        ("gcr.io/distroless/base-debian11", True),
        ("gcr.io/distroless/static-debian12", True),
        ("gcr.io/distroless/cc-debian12:nonroot", True),
        ("gcr.io/distroless/python3-debian12", True),
        # not distroless
        ("debian:11-slim", False),
        ("alpine:3.19", False),
        ("golang:1.23-bookworm", False),
        ("gcr.io/myproj/app:1", False),
    ])
    def test_classification(self, ref, want):
        assert _is_distroless(ref) is want


class TestDistrolessFamilyBump:

    def test_base_debian11_bumps_to_debian12(self):
        got = _distroless_same_family_bump("gcr.io/distroless/base-debian11")
        assert got is not None
        assert got[0] == "gcr.io/distroless/base-debian12"

    def test_variant_prefix_is_preserved(self):
        got = _distroless_same_family_bump("gcr.io/distroless/static-debian11")
        assert got[0] == "gcr.io/distroless/static-debian12"

    def test_explicit_tag_is_preserved(self):
        got = _distroless_same_family_bump(
            "gcr.io/distroless/cc-debian11:nonroot")
        assert got[0] == "gcr.io/distroless/cc-debian12:nonroot"

    def test_digest_is_dropped_across_release_change(self):
        got = _distroless_same_family_bump(
            "gcr.io/distroless/base-debian11@sha256:" + "0" * 64)
        assert got[0] == "gcr.io/distroless/base-debian12"

    def test_already_current_is_noop(self):
        assert _distroless_same_family_bump(
            "gcr.io/distroless/base-debian12") is None

    def test_no_debian_token_is_noop(self):
        assert _distroless_same_family_bump(
            "gcr.io/distroless/static") is None


class TestDistrolessRuntimeStaysDistroless:

    def test_go_on_old_distroless_bumps_distroless_not_golang(self):
        """The headscale@legacy reproduction: a Go binary on
        gcr.io/distroless/base-debian11 must go to base-debian12, never
        golang:1.23-bookworm."""
        base, conf = choose_base_image(
            _inf("debian", language="golang", version="1.23", needs_glibc=True),
            original_base="gcr.io/distroless/base-debian11")
        assert base == "gcr.io/distroless/base-debian12"
        assert "golang" not in base
        assert conf >= 0.4

    def test_current_distroless_is_left_unchanged(self):
        """Already on base-debian12: leave it, do not cross to a language
        image."""
        base, _ = choose_base_image(
            _inf("debian", language="golang", version="1.23", needs_glibc=True),
            original_base="gcr.io/distroless/base-debian12")
        assert base == "gcr.io/distroless/base-debian12"
        assert "golang" not in base
