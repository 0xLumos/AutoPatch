"""Tests for src.provenance_fingerprint (P5-1)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


def _build_debian_extract(td):
    tdp = Path(td)
    (tdp / "etc/apt/sources.list.d").mkdir(parents=True)
    (tdp / "etc/ssl/certs").mkdir(parents=True)
    (tdp / "etc/ssl/certs/ca-certificates.crt").write_text("fake")
    (tdp / "var/lib/dpkg").mkdir(parents=True)
    (tdp / "var/lib/dpkg/status").write_text(
        "Package: bash\nVersion: 5.1\n\nPackage: openssl\nVersion: 3.0.11\n\n"
    )
    (tdp / "etc/os-release").write_text(
        'ID=debian\nVERSION_ID="12"\nID_LIKE=""\nNAME="Debian"\n'
    )
    return tdp


def _build_alpine_extract(td):
    tdp = Path(td)
    (tdp / "etc/apk").mkdir(parents=True)
    (tdp / "etc/apk/repositories").write_text(
        "https://dl-cdn.alpinelinux.org/alpine/v3.19/main\n"
    )
    (tdp / "etc/apk/world").write_text("musl=1.2.4\nbusybox=1.36\nbash=5.2\n")
    (tdp / "lib/apk/db").mkdir(parents=True)
    (tdp / "lib/apk/db/installed").write_text("C:Q1\n")
    (tdp / "etc/ssl").mkdir(parents=True)
    (tdp / "etc/ssl/cert.pem").write_text("fake")
    (tdp / "etc/os-release").write_text(
        'ID=alpine\nVERSION_ID="3.19"\nNAME="Alpine Linux"\n'
    )
    return tdp


class TestPkgdbDetection:

    def test_dpkg_status_detected(self):
        from src.provenance_fingerprint import _scan_pkgdb
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_debian_extract(td)
            sig = _scan_pkgdb(tdp)
            assert sig.family == "dpkg"
            assert sig.installed_count == 2
            assert "bash" in sig.sample_packages

    def test_apk_world_detected(self):
        from src.provenance_fingerprint import _scan_pkgdb
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_alpine_extract(td)
            sig = _scan_pkgdb(tdp)
            assert sig.family == "apk"
            assert sig.distro_hint == "alpine"

    def test_no_pkgdb(self):
        from src.provenance_fingerprint import _scan_pkgdb
        with tempfile.TemporaryDirectory() as td:
            sig = _scan_pkgdb(Path(td))
            assert sig.family is None


class TestTopology:

    def test_debian_topology(self):
        from src.provenance_fingerprint import _scan_topology
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_debian_extract(td)
            top = _scan_topology(tdp)
            assert top.repo_config_style == "apt"
            assert top.ca_bundle_style == "debian"
            assert top.distro_hint == "debian-family"

    def test_alpine_topology(self):
        from src.provenance_fingerprint import _scan_topology
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_alpine_extract(td)
            top = _scan_topology(tdp)
            assert top.repo_config_style == "apk"
            assert top.distro_hint == "alpine"


class TestOsRelease:

    def test_parses_debian(self):
        from src.provenance_fingerprint import _parse_os_release
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_debian_extract(td)
            r = _parse_os_release(tdp)
            assert r.id == "debian"
            assert r.version_id == "12"
            assert r.name == "Debian"

    def test_missing_returns_empty(self):
        from src.provenance_fingerprint import _parse_os_release
        with tempfile.TemporaryDirectory() as td:
            r = _parse_os_release(Path(td))
            assert r.id is None


class TestFingerprintAggregation:

    def test_clean_debian_consensus(self):
        from src.provenance_fingerprint import fingerprint_from_extracted
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_debian_extract(td)
            fp = fingerprint_from_extracted(tdp)
            assert fp.consensus_distro == "debian"
            assert fp.consensus_libc == "glibc"
            assert fp.inter_tier_agreement == 1.0
            assert "T2" in fp.tiers_observed
            assert "T3" in fp.tiers_observed
            assert "T4" in fp.tiers_observed

    def test_clean_alpine_consensus(self):
        from src.provenance_fingerprint import fingerprint_from_extracted
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_alpine_extract(td)
            fp = fingerprint_from_extracted(tdp)
            assert fp.consensus_distro == "alpine"
            assert fp.consensus_libc == "musl"

    def test_disagreement_lowers_agreement(self):
        """Filesystem says debian, os-release says alpine: agreement < 1."""
        from src.provenance_fingerprint import fingerprint_from_extracted
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_debian_extract(td)
            (tdp / "etc/os-release").write_text(
                'ID=alpine\nVERSION_ID="3.19"\n'
            )
            fp = fingerprint_from_extracted(tdp)
            # Consensus is still debian (majority of high-trust signals)
            assert fp.consensus_distro == "debian"
            # But agreement drops because os-release disagrees
            assert fp.inter_tier_agreement < 1.0

    def test_fingerprint_hash_is_stable(self):
        """Two fingerprints from identical input have identical hash."""
        from src.provenance_fingerprint import fingerprint_from_extracted
        with tempfile.TemporaryDirectory() as td1:
            tdp1 = _build_debian_extract(td1)
            fp1 = fingerprint_from_extracted(tdp1)
        with tempfile.TemporaryDirectory() as td2:
            tdp2 = _build_debian_extract(td2)
            fp2 = fingerprint_from_extracted(tdp2)
        assert fp1.fingerprint_hash == fp2.fingerprint_hash


class TestDistroNormalization:

    def test_normalize_centos_to_rhel(self):
        from src.provenance_fingerprint import _normalize_distro
        assert _normalize_distro("centos") == "rhel"
        assert _normalize_distro("rocky") == "rhel"
        assert _normalize_distro("alma") == "rhel"

    def test_normalize_preserves_debian(self):
        from src.provenance_fingerprint import _normalize_distro
        assert _normalize_distro("debian") == "debian"
        assert _normalize_distro("ubuntu") == "ubuntu"

    def test_normalize_none(self):
        from src.provenance_fingerprint import _normalize_distro
        assert _normalize_distro(None) is None
        assert _normalize_distro("") is None


class TestSerialization:

    def test_to_dict_is_jsonable(self):
        from src.provenance_fingerprint import fingerprint_from_extracted
        with tempfile.TemporaryDirectory() as td:
            tdp = _build_debian_extract(td)
            fp = fingerprint_from_extracted(tdp)
            d = fp.to_dict()
            # Must serialize cleanly
            blob = json.dumps(d)
            assert "debian" in blob
            assert "tiers_observed" in d
