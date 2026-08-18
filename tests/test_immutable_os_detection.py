"""Immutable-OS classification must not fire on application dependencies.

The bug this pins: `IMMUTABLE_OS_FAMILIES` contains short tokens (notably
"cos" for Google Container-Optimized OS), and `_detect_os_family`
substring-matched them against every SBOM component name, BEFORE the
package-ecosystem check. So gitea's HTML-sanitiser dependency
`github.com/microcosm-cc/bluemonday` ("cos" inside "microCOSm") made a
normal Alpine image classify as an immutable OS, which disables base
replacement entirely and silently declined the remediation (191 -> 191
CVEs, no change). Any Go/npm/pypi app vendoring a module whose name
merely contained "cos", "talos", etc. was affected, including in the
already-recorded 100-image run.

Two independent guards now prevent it, and both are tested: the
immutable check is gated on the ABSENCE of an apk/deb/rpm package
database, and the match is word-bounded.
"""
from __future__ import annotations

import pytest

from src.patcher import _detect_os_family, _os_token_in


class TestWordBoundaryMatch:

    @pytest.mark.parametrize("token,text,want", [
        ("cos", "cos", True),
        ("cos", "cos-release", True),
        ("cos", "google-cos", True),
        ("cos", "pkg:oci/cos", True),
        # the actual false positive
        ("cos", "github.com/microcosm-cc/bluemonday", False),
        ("cos", "microcosm", False),
        ("cos", "cosmos", False),
        ("cos", "cosign", False),
        ("talos", "talosctl-client", False),   # flanked by a letter
        ("talos", "talos", True),
        ("flatcar", "flatcar-release", True),
        ("", "anything", False),
        ("cos", "", False),
    ])
    def test_token_boundary(self, token, text, want):
        assert _os_token_in(token, text) is want


class TestGiteaIsNotImmutable:
    """The exact reproduction: an Alpine image whose SBOM vendors
    microcosm-cc/bluemonday must classify as alpine, not cos."""

    GITEA_PURLS = [
        "pkg:apk/alpine/musl@1.2.4",
        "pkg:apk/alpine/apk-tools@2.14.0",
        "pkg:golang/github.com/microcosm-cc/bluemonday@1.0.26",
        "pkg:golang/github.com/gitea/gitea@1.21.0",
    ]
    GITEA_NAMES = [
        "musl", "apk-tools", "alpine-baselayout",
        "github.com/microcosm-cc/bluemonday",
        "github.com/gitea/gitea",
    ]

    def test_gitea_classifies_as_alpine(self):
        fam = _detect_os_family(
            self.GITEA_PURLS, self.GITEA_NAMES,
            meta_name="gitea", comp_count=len(self.GITEA_NAMES))
        assert fam == "alpine", (
            "an apk image vendoring microcosm-cc/bluemonday was "
            "misread as an immutable OS"
        )

    def test_apk_db_alone_defeats_the_immutable_guard(self):
        """Even if a component name did contain a bare immutable token,
        the presence of an apk/deb/rpm database means the image is a
        mutable distro and cannot be immutable."""
        purls = ["pkg:apk/alpine/musl@1.2.4"]
        names = ["musl", "alpine-baselayout", "cos"]  # bare 'cos' component
        assert _detect_os_family(purls, names, "someimage", 3) == "alpine"

    def test_deb_app_vendoring_cos_module_is_debian(self):
        purls = ["pkg:deb/debian/libc6@2.36",
                 "pkg:npm/microcosm@12.0.0"]
        names = ["libc6", "microcosm", "apt"]
        assert _detect_os_family(purls, names, "myapp", 3) == "debian"


class TestRealImmutableStillDetected:
    """The fix must not blind the detector to genuine immutable OSes,
    which ship no mutable package database."""

    @pytest.mark.parametrize("meta,want", [
        ("bottlerocket", "bottlerocket"),
        ("flatcar", "flatcar"),
        ("cos", "cos"),
    ])
    def test_metadata_named_immutable_os(self, meta, want):
        # No apk/deb/rpm purls: a real immutable host.
        assert _detect_os_family([], [], meta, 0) == want

    def test_immutable_component_without_pkgdb(self):
        assert _detect_os_family(
            [], ["bottlerocket-release"], "", 1) == "bottlerocket"
