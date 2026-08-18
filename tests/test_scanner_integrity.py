"""Tests for scanner binary integrity verification.

Two classes of defect motivate these tests:

1. A check that can never pass. ``verify_cosign_blob`` invoked cosign
   without the signature material, so it returned failure on every host,
   which made ``--strict-integrity`` unusable and trained operators to
   ignore signature warnings.
2. A gate that rejects the project's own reference image, which was the
   effect of ``MINIMUM_VERSIONS["grype"]`` exceeding the pinned version.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from src.scanner_integrity import (
    COSIGN_IDENTITIES,
    CosignBlobStatus,
    MINIMUM_VERSIONS,
    _discover_signature_material,
    _parse_version,
    _version_gte,
    verify_cosign_blob,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestVersionComparison:

    @pytest.mark.parametrize("a,b,want", [
        # equal lengths
        ("0.86.1", "0.86.0", True),
        ("0.85.9", "0.86.0", False),
        ("1.0.0", "1.0.0", True),
        # unequal lengths: the old tuple compare said (0,86) < (0,86,0)
        ("0.86", "0.86.0", True),
        ("0.86.0", "0.86", True),
        ("1.2", "1.2.1", False),
        # pre-release: the old parser raised on int("0-rc1") and returned
        # False, so every rc was reported as below minimum
        ("1.0.0-rc1", "1.0.0", False),
        ("1.0.0", "1.0.0-rc1", True),
        ("1.0.1-rc1", "1.0.0", True),
        ("1.0.0-rc2", "1.0.0-rc1", True),
        ("1.0.0-rc1", "1.0.0-rc2", False),
        # build metadata is ignored for ordering (semver 11.4)
        ("1.0.0+build.5", "1.0.0", True),
        # a leading v is common in release tags
        ("v0.86.1", "0.86.0", True),
    ])
    def test_ordering(self, a, b, want):
        assert _version_gte(a, b) is want

    def test_unparseable_fails_closed(self):
        """An unknown version must not satisfy a security gate."""
        assert _version_gte("unknown", "0.86.0") is False
        assert _version_gte("", "0.86.0") is False
        assert _version_gte(None, "0.86.0") is False  # type: ignore[arg-type]

    def test_numeric_prerelease_sorts_below_alphanumeric(self):
        assert _parse_version("1.0.0-1")[1] < _parse_version("1.0.0-alpha")[1]


class TestMinimumVersionsAreSatisfiable:
    """MINIMUM_VERSIONS must never exceed what the project itself ships,
    or the reference image fails its own integrity gate."""

    @staticmethod
    def _dockerfile_pins():
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        return {
            m.group(1).lower(): m.group(2)
            for m in re.finditer(r"^ARG\s+(\w+)_VERSION=([\w.]+)", text, re.M)
        }

    @pytest.mark.parametrize("scanner", sorted(MINIMUM_VERSIONS))
    def test_pinned_version_satisfies_minimum(self, scanner):
        pins = self._dockerfile_pins()
        if scanner not in pins:
            pytest.skip(f"{scanner} is not pinned in the Dockerfile")
        assert _version_gte(pins[scanner], MINIMUM_VERSIONS[scanner]), (
            f"Dockerfile pins {scanner} {pins[scanner]} but MINIMUM_VERSIONS "
            f"demands >= {MINIMUM_VERSIONS[scanner]}; the reference image "
            f"cannot pass its own integrity check."
        )

    @pytest.mark.parametrize("scanner", sorted(MINIMUM_VERSIONS))
    def test_a_checksummed_release_satisfies_minimum(self, scanner):
        yaml = pytest.importorskip("yaml")
        path = REPO_ROOT / "src" / "scanner_checksums.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        versions = list((data.get(scanner) or {}).keys())
        if not versions:
            pytest.skip(f"no bundled checksums for {scanner}")
        assert any(_version_gte(str(v), MINIMUM_VERSIONS[scanner])
                   for v in versions), (
            f"No checksummed {scanner} release satisfies the minimum "
            f"{MINIMUM_VERSIONS[scanner]}; checksum verification and the "
            f"version gate can never both pass."
        )


class TestCosignBlobVerification:

    def test_missing_material_is_unavailable_not_failed(self, tmp_path, monkeypatch):
        """No .sig/.bundle beside the binary means the check could not be
        run. Reporting that as FAILED made strict mode block every host."""
        binary = tmp_path / "grype"
        binary.write_bytes(b"\x7fELF fake")
        monkeypatch.setattr(
            "src.scanner_integrity.find_binary", lambda n: "/usr/bin/cosign")
        called = []
        monkeypatch.setattr(
            "src.scanner_integrity.run_cmd",
            lambda *a, **k: called.append(a) or (1, "missing flags"))
        status = verify_cosign_blob(str(binary), "grype")
        assert status is CosignBlobStatus.UNAVAILABLE
        assert not called, "cosign was invoked with no signature material"

    def test_no_cosign_on_path_is_unavailable(self, tmp_path, monkeypatch):
        binary = tmp_path / "grype"
        binary.write_bytes(b"x")
        monkeypatch.setattr("src.scanner_integrity.find_binary", lambda n: None)
        assert verify_cosign_blob(str(binary), "grype") is CosignBlobStatus.UNAVAILABLE

    def test_detached_pair_is_passed_to_cosign(self, tmp_path, monkeypatch):
        binary = tmp_path / "grype"
        binary.write_bytes(b"x")
        (tmp_path / "grype.sig").write_text("sig")
        (tmp_path / "grype.pem").write_text("cert")
        monkeypatch.setattr(
            "src.scanner_integrity.find_binary", lambda n: "/usr/bin/cosign")
        seen = {}

        def fake_run(cmd, *a, **k):
            seen["cmd"] = cmd
            return 0, "Verified OK"

        monkeypatch.setattr("src.scanner_integrity.run_cmd", fake_run)
        assert verify_cosign_blob(str(binary), "grype") is CosignBlobStatus.VERIFIED
        assert "--signature" in seen["cmd"] and "--certificate" in seen["cmd"]

    def test_bundle_preferred_over_detached(self, tmp_path):
        binary = tmp_path / "trivy"
        binary.write_bytes(b"x")
        (tmp_path / "trivy.sig").write_text("s")
        (tmp_path / "trivy.pem").write_text("c")
        (tmp_path / "trivy.cosign.bundle").write_text("b")
        assert _discover_signature_material(str(binary)) == {
            "bundle": str(tmp_path / "trivy.cosign.bundle")}

    def test_half_a_detached_pair_is_not_usable(self, tmp_path):
        binary = tmp_path / "trivy"
        binary.write_bytes(b"x")
        (tmp_path / "trivy.sig").write_text("s")   # no certificate
        assert _discover_signature_material(str(binary)) == {}

    def test_present_but_invalid_signature_is_failed(self, tmp_path, monkeypatch):
        binary = tmp_path / "trivy"
        binary.write_bytes(b"x")
        (tmp_path / "trivy.cosign.bundle").write_text("b")
        monkeypatch.setattr(
            "src.scanner_integrity.find_binary", lambda n: "/usr/bin/cosign")
        monkeypatch.setattr(
            "src.scanner_integrity.run_cmd",
            lambda *a, **k: (1, "error: signature verification failed"))
        assert verify_cosign_blob(str(binary), "trivy") is CosignBlobStatus.FAILED

    def test_unknown_scanner_is_unavailable(self, tmp_path):
        assert verify_cosign_blob(
            str(tmp_path / "nope"), "notascanner") is CosignBlobStatus.UNAVAILABLE

    def test_issuer_identities_are_anchored_at_the_host(self):
        """A trailing .* on the identity is intended; the issuer must not
        be open-ended or any issuer whose URL contains the trusted one
        would match."""
        for name, info in COSIGN_IDENTITIES.items():
            assert info["issuer_regexp"].endswith("com"), name
