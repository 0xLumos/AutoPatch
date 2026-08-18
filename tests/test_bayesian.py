"""Tests for src.bayesian_inference (P5-3)."""
from __future__ import annotations

import pytest


class TestCleanCases:

    def test_clean_debian_full_agreement(self):
        from src.bayesian_inference import Observations, infer
        obs = Observations(
            sbom_purl="debian", sbom_compname="debian",
            trivy_result_type="debian", layer_match="debian",
            config_path_style="debian", pkgdb_family="debian",
            topology_distro="debian", os_release_id="debian",
            loader_distro="debian", loader_libc="glibc",
        )
        p = infer(obs)
        assert p.distro == "debian"
        assert p.distro_probability > 0.9
        assert p.libc == "glibc"
        assert p.tamper_probability < 0.1
        assert p.high_confidence
        assert not p.likely_tampered

    def test_clean_alpine_full_agreement(self):
        from src.bayesian_inference import Observations, infer
        obs = Observations(
            sbom_purl="alpine", pkgdb_family="alpine",
            topology_distro="alpine", os_release_id="alpine",
            loader_distro="alpine", loader_libc="musl",
        )
        p = infer(obs)
        assert p.distro == "alpine"
        assert p.libc == "musl"
        assert not p.likely_tampered


class TestTamperDetection:

    def test_full_sbom_tamper(self):
        """SBOM lies completely; filesystem says debian."""
        from src.bayesian_inference import Observations, infer
        obs = Observations(
            sbom_purl="alpine", sbom_compname="alpine",
            trivy_result_type="alpine", os_release_id="alpine",
            layer_match="debian", pkgdb_family="debian",
            topology_distro="debian", loader_distro="debian",
        )
        p = infer(obs)
        assert p.distro == "debian", (
            f"high-trust evidence should win, got {p.distro}"
        )
        assert p.likely_tampered, (
            f"all SBOM signals disagreeing should trip tamper, "
            f"got P(T=1)={p.tamper_probability}"
        )

    def test_partial_disagreement_no_tamper(self):
        """One disagreeing low-trust signal should NOT trip tampering."""
        from src.bayesian_inference import Observations, infer
        obs = Observations(
            sbom_purl="debian", sbom_compname="alpine",  # 1 out of 4 disagree
            trivy_result_type="debian", os_release_id="debian",
            layer_match="debian", pkgdb_family="debian",
        )
        p = infer(obs)
        assert p.distro == "debian"
        assert not p.likely_tampered

    def test_no_evidence_no_false_tamper(self):
        """Sparse evidence should not falsely indicate tampering."""
        from src.bayesian_inference import Observations, infer
        obs = Observations(os_release_id="debian")
        p = infer(obs)
        assert not p.likely_tampered


class TestSparseEvidence:

    def test_only_loader(self):
        """Just the loader fingerprint should yield meaningful posterior."""
        from src.bayesian_inference import Observations, infer
        obs = Observations(loader_distro="alpine", loader_libc="musl")
        p = infer(obs)
        assert p.distro == "alpine"
        assert p.libc == "musl"

    def test_only_layer_match(self):
        from src.bayesian_inference import Observations, infer
        obs = Observations(layer_match="debian")
        p = infer(obs)
        assert p.distro == "debian"

    def test_no_observations(self):
        """With no evidence, posterior follows the prior."""
        from src.bayesian_inference import Observations, infer
        obs = Observations()
        p = infer(obs)
        # Debian has the highest prior so should be the MAP
        assert p.distro == "debian"
        # But probability should be modest (just the prior)
        assert p.distro_probability < 0.4


class TestLibcInference:

    def test_libc_from_loader_override(self):
        """Loader libc evidence should pin libc family."""
        from src.bayesian_inference import Observations, infer
        # Distro evidence is ambiguous but loader says musl
        obs = Observations(loader_libc="musl")
        p = infer(obs)
        assert p.libc == "musl"

    def test_libc_from_distro_cpt(self):
        """Without loader evidence, libc comes from per-distro prior."""
        from src.bayesian_inference import Observations, infer
        obs = Observations(
            layer_match="debian", pkgdb_family="debian",
            topology_distro="debian", os_release_id="debian",
        )
        p = infer(obs)
        assert p.libc == "glibc"


class TestObservationsAdapter:

    def test_from_fingerprint_with_no_fp(self):
        from src.bayesian_inference import observations_from_fingerprint
        obs = observations_from_fingerprint(None, sbom_purl_distro="debian")
        assert obs.sbom_purl == "debian"
        assert obs.layer_match is None

    def test_from_fingerprint_extracts_signals(self):
        import tempfile
        from pathlib import Path
        from src.bayesian_inference import observations_from_fingerprint
        from src.provenance_fingerprint import fingerprint_from_extracted

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "var/lib/dpkg").mkdir(parents=True)
            (tdp / "var/lib/dpkg/status").write_text("Package: bash\n\n")
            (tdp / "etc/apt").mkdir(parents=True)
            (tdp / "etc/apt/sources.list").write_text("deb foo\n")
            (tdp / "etc/ssl/certs").mkdir(parents=True)
            (tdp / "etc/ssl/certs/ca-certificates.crt").write_text("x")
            (tdp / "etc/os-release").write_text("ID=debian\n")
            fp = fingerprint_from_extracted(tdp)

        obs = observations_from_fingerprint(fp)
        assert obs.pkgdb_family == "debian"
        assert obs.topology_distro == "debian"
        assert obs.os_release_id == "debian"


class TestFamilyLevelSignals:
    """Regression coverage for the family-vs-point-distro fix.

    A package-db / purl / topology signal cannot resolve members of a
    distro family (dpkg is identical on Debian and Ubuntu). Earlier these
    were collapsed to a single distro and penalised every sibling with a
    symmetric false-match weight, which misclassified every Ubuntu image
    as Debian and could trip a false tamper alarm.
    """

    def test_clean_ubuntu_not_misclassified_as_debian(self):
        from src.bayesian_inference import Observations, infer
        # dpkg/apt are deb-family (cannot say "ubuntu"); the distro-level
        # signals do say ubuntu. The high-trust family signals must not
        # override them toward debian.
        obs = Observations(
            sbom_purl="ubuntu", sbom_compname="ubuntu",
            trivy_result_type="ubuntu",
            pkgdb_family="debian", topology_distro="debian",
            os_release_id="ubuntu", loader_distro="ubuntu",
            loader_libc="glibc",
        )
        p = infer(obs)
        assert p.distro == "ubuntu", f"got {p.distro}"
        assert p.distro_probability > 0.9
        assert not p.likely_tampered, (
            "deb-family pkgdb on a genuine Ubuntu image must not look "
            f"like tampering, got P(T=1)={p.tamper_probability}"
        )

    def test_family_signal_gives_all_members_real_mass(self):
        from src.bayesian_inference import Observations, infer
        # A lone deb-family signal should leave debian/ubuntu/distroless
        # ranked by prior, NOT crush the siblings to ~0.
        p = infer(Observations(pkgdb_family="debian"))
        d = p.distro_distribution
        assert d["ubuntu"] > 0.2, f"ubuntu unfairly penalised: {d['ubuntu']}"
        assert d["distroless"] > 0.05
        assert d["alpine"] < 0.05
        # Ratio between siblings should track the prior ratio (0.30/0.20),
        # not a hard penalty.
        assert 1.2 < d["debian"] / d["ubuntu"] < 1.9

    def test_wolfi_not_forced_to_alpine(self):
        from src.bayesian_inference import Observations, infer
        # apk pkgdb is the apk family (alpine + wolfi); glibc + os-release
        # disambiguate to wolfi.
        obs = Observations(
            pkgdb_family="alpine", topology_distro="alpine",
            os_release_id="wolfi", loader_distro="wolfi",
            loader_libc="glibc",
        )
        p = infer(obs)
        assert p.distro == "wolfi", f"got {p.distro}"
        assert p.libc == "glibc"


class TestEvidenceAndCalibration:

    def test_evidence_loglik_is_finite_and_nonpositive(self):
        from src.bayesian_inference import Observations, infer
        p = infer(Observations(layer_match="debian", pkgdb_family="debian"))
        assert p.evidence_loglik <= 0.0
        assert p.evidence_loglik > float("-inf")

    def test_agreement_fits_better_than_conflict(self):
        from src.bayesian_inference import Observations, infer
        # Same number of signals; agreeing evidence has a higher
        # per-signal average log-likelihood than conflicting evidence.
        agree = infer(Observations(layer_match="debian", pkgdb_family="debian"))
        conflict = infer(Observations(layer_match="debian", pkgdb_family="alpine"))
        assert agree.evidence_loglik / 2 > conflict.evidence_loglik / 2

    def test_calibration_fingerprint_matches_yaml(self):
        from src.bayesian_inference import (
            calibration_fingerprint, CALIBRATION_SHA256, _load_calibration,
            _canonical_hash,
        )
        fp = calibration_fingerprint()
        assert fp["sha256"] == CALIBRATION_SHA256
        # Recomputing the hash from the loaded calibration is stable.
        cal = _load_calibration()
        assert _canonical_hash({**cal, "sha256_self": None}) == CALIBRATION_SHA256

    def test_partial_yaml_override_merges_over_defaults(self, tmp_path,
                                                        monkeypatch):
        # A YAML that only sets tamper_prior must keep every other default.
        import importlib
        import src.bayesian_inference as bi
        yaml = pytest.importorskip("yaml")  # noqa: F841
        (tmp_path / "bayesian_calibration.yaml").write_text(
            "tamper_prior: 0.5\n"
        )
        monkeypatch.setattr(
            bi.os.path, "dirname",
            lambda _p: str(tmp_path),
        )
        cal = bi._load_calibration()
        assert cal["tamper_prior"] == 0.5
        assert "debian" in cal["distro_prior"]      # defaults preserved
        assert "layer_match" in cal["signals"]
