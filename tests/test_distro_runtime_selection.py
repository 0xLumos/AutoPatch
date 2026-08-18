"""A distribution runtime stage must stay in its distribution.

The bug this pins (bug #2, unmasked once the cos misclassification was
fixed): `choose_base_image` used the SBOM-detected language to build a
language image even when the ORIGINAL base was a plain OS distribution.
Multi-stage apps copy a compiled binary onto a bare `FROM alpine`
runtime; the runtime SBOM then shows Go or Python, and both the
resolver and the legacy language paths proposed a language image:

  * gitea (Go on alpine:3.11)  -> golang:3.11-alpine  (tag does not
    exist; registry-rejected; 191 CVEs left unpatched)
  * act (Python on alpine:3.21, 0 CVEs) -> python:3.12-alpine (exists,
    but wrong runtime; turned a clean image into a broken 0->5-CVE one)

The fix: a distribution base is upgraded within its distribution and is
never redirected to a language image. Language-image selection only
applies when the base is itself a language runtime.
"""
from __future__ import annotations

import pytest

from src.patcher import (
    InferenceResult,
    _is_distribution_repo,
    choose_base_image,
)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    # The distro-bump path registry-verifies its candidate; force the
    # offline branch so the table value is trusted and no network is hit.
    monkeypatch.setattr("src.patcher._get_resolver", lambda: None)


def _inf(os_family, language=None, version=None, needs_glibc=False):
    r = InferenceResult()
    r.os_family = os_family
    r.language = language
    r.language_version = version
    r.needs_glibc = needs_glibc
    r.confidence = 0.7
    return r


class TestIsDistributionRepo:

    @pytest.mark.parametrize("ref,want", [
        ("alpine:3.11", True),
        ("alpine", True),
        ("debian:11-slim", True),
        ("ubuntu:22.04", True),
        ("rockylinux:8", True),
        ("registry.access.redhat.com/ubi9:latest", True),
        ("busybox:1.36", True),
        # language runtimes are NOT distributions
        ("python:3.9", False),
        ("golang:1.21-alpine", False),
        ("node:18", False),
        ("eclipse-temurin:21", False),
        ("myorg/customapp:1", False),
    ])
    def test_classification(self, ref, want):
        assert _is_distribution_repo(ref) is want


class TestDistroRuntimeStaysInDistribution:

    def test_go_on_old_alpine_bumps_alpine_not_golang(self):
        """gitea@legacy: alpine:3.11 running Go must go to alpine:3.21,
        never golang:3.11-alpine."""
        base, conf = choose_base_image(
            _inf("alpine", language="golang", version="1.21"),
            original_base="alpine:3.11")
        assert base == "alpine:3.21"
        assert "golang" not in base
        assert conf >= 0.4

    def test_python_on_current_alpine_is_left_unchanged(self):
        """act: alpine:3.21 (already current) running Python must NOT be
        swapped to python:3.12-alpine, which broke the runtime."""
        base, conf = choose_base_image(
            _inf("alpine", language="python", version="3.12"),
            original_base="alpine:3.21")
        assert base == "alpine:3.21"       # unchanged
        assert "python" not in base

    def test_newer_alpine_is_not_downgraded(self):
        """alpine:3.24 must stay 3.24, not drop to the table's 3.21."""
        base, _ = choose_base_image(
            _inf("alpine", language="golang", version="1.22"),
            original_base="alpine:3.24")
        assert base == "alpine:3.24"

    def test_old_debian_running_python_bumps_debian(self):
        base, _ = choose_base_image(
            _inf("debian", language="python", version="3.11", needs_glibc=True),
            original_base="debian:10")
        assert base.startswith("debian:12")
        assert "python" not in base

    def test_old_ubuntu_running_node_bumps_ubuntu(self):
        base, _ = choose_base_image(
            _inf("ubuntu", language="node", version="20"),
            original_base="ubuntu:18.04")
        assert base.startswith("ubuntu:24.04")
        assert "node" not in base


class TestLanguageBasesStillUpgradeNormally:
    """The guard must not touch a stage whose base is a real language
    image; those still get a language-version bump."""

    def test_python_base_still_goes_to_python(self, monkeypatch):
        # No resolver, so this exercises the legacy language path.
        base, _ = choose_base_image(
            _inf("debian", language="python", version="3.9", needs_glibc=True),
            original_base="python:3.9-slim")
        assert base.startswith("python:")

    def test_golang_base_is_not_treated_as_distro(self):
        assert _is_distribution_repo("golang:1.21") is False
