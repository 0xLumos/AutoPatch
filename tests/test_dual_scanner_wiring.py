"""Tests that --dual-scanner is actually wired, not just advertised.

Before this, ``--dual-scanner`` added "grype" to the list of binaries
whose checksum was verified and nothing else. ``grype_scanner.scan_image``
and every function in ``scanner_fusion`` were unreachable from the
pipeline, so a run with the flag set produced Trivy-only results while
the report and the paper claimed dual-scanner coverage.
"""
from __future__ import annotations

import json
import os

import pytest

from src import main as m
from src.scanner_fusion import fuse_scan_results, fusion_to_trivy_format


def _trivy(*pairs):
    return {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": c, "PkgName": p, "Severity": s,
         "InstalledVersion": "1.0", "FixedVersion": "1.1", "Description": ""}
        for c, p, s in pairs]}]}


def _ids(scan):
    return {(v["VulnerabilityID"], v["PkgName"])
            for r in scan.get("Results", []) for v in r.get("Vulnerabilities", [])}


class TestScanPossiblyFused:

    def test_single_scanner_mode_does_not_invoke_grype(self, tmp_path, monkeypatch):
        monkeypatch.setattr(m, "scan_image",
                            lambda img, path, **k: _trivy(("CVE-1", "a", "HIGH")))

        def boom(*a, **k):
            raise AssertionError("grype invoked without --dual-scanner")

        monkeypatch.setattr("src.grype_scanner.scan_image", boom)
        out = m._scan_possibly_fused(
            "img", str(tmp_path / "t.json"),
            output_dir=str(tmp_path), phase="before", dual=False)
        assert _ids(out) == {("CVE-1", "a")}

    def test_dual_mode_unions_both_scanners(self, tmp_path, monkeypatch):
        monkeypatch.setattr(m, "scan_image",
                            lambda img, path, **k: _trivy(("CVE-1", "a", "HIGH"),
                                                          ("CVE-2", "b", "LOW")))
        monkeypatch.setattr("src.grype_scanner.scan_image",
                            lambda img, path, **k: _trivy(("CVE-2", "b", "LOW"),
                                                          ("CVE-3", "c", "CRITICAL")))
        out = m._scan_possibly_fused(
            "img", str(tmp_path / "t.json"),
            output_dir=str(tmp_path), phase="before", dual=True)
        # A CVE only Grype sees is still a CVE the gate must not ignore.
        assert _ids(out) == {("CVE-1", "a"), ("CVE-2", "b"), ("CVE-3", "c")}

    def test_dual_mode_records_agreement_classification(self, tmp_path, monkeypatch):
        monkeypatch.setattr(m, "scan_image",
                            lambda img, path, **k: _trivy(("CVE-1", "a", "HIGH")))
        monkeypatch.setattr("src.grype_scanner.scan_image",
                            lambda img, path, **k: _trivy(("CVE-1", "a", "HIGH"),
                                                          ("CVE-9", "z", "LOW")))
        out = m._scan_possibly_fused(
            "img", str(tmp_path / "t.json"),
            output_dir=str(tmp_path), phase="after", dual=True)
        cls = {v["VulnerabilityID"]: v["_fusion_classification"]
               for r in out["Results"] for v in r["Vulnerabilities"]}
        assert cls["CVE-1"] == "CONFIRMED"
        # The classification names which scanner saw it, so a reviewer
        # can weigh single-scanner findings without re-running anything.
        assert cls["CVE-9"] == "EXCLUSIVE_GRYPE"

    def test_fused_output_is_persisted_for_audit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(m, "scan_image",
                            lambda img, path, **k: _trivy(("CVE-1", "a", "HIGH")))
        monkeypatch.setattr("src.grype_scanner.scan_image",
                            lambda img, path, **k: _trivy(("CVE-1", "a", "HIGH")))
        m._scan_possibly_fused("img", str(tmp_path / "t.json"),
                               output_dir=str(tmp_path), phase="before", dual=True)
        saved = tmp_path / "fused-before.json"
        assert saved.exists()
        assert json.loads(saved.read_text())["_fusion_metadata"]["confirmed_count"] == 1

    def test_grype_failure_propagates_rather_than_degrading(self, tmp_path, monkeypatch):
        """Silently falling back to Trivy-only on one side of a
        before/after pair would take the delta between two
        differently-constructed finding sets."""
        from src.grype_scanner import GrypeScanError
        monkeypatch.setattr(m, "scan_image",
                            lambda img, path, **k: _trivy(("CVE-1", "a", "HIGH")))

        def fail(*a, **k):
            raise GrypeScanError("db corrupt")

        monkeypatch.setattr("src.grype_scanner.scan_image", fail)
        with pytest.raises(GrypeScanError):
            m._scan_possibly_fused("img", str(tmp_path / "t.json"),
                                   output_dir=str(tmp_path), phase="after", dual=True)

    def test_db_pin_is_forwarded_to_both_scanners(self, tmp_path, monkeypatch):
        seen = {}

        def record(who):
            def _scan(img, path, **k):
                seen[who] = k.get("skip_db_update")
                return _trivy(("CVE-1", "a", "HIGH"))
            return _scan

        monkeypatch.setattr(m, "scan_image", record("trivy"))
        monkeypatch.setattr("src.grype_scanner.scan_image", record("grype"))
        m._scan_possibly_fused("img", str(tmp_path / "t.json"),
                               output_dir=str(tmp_path), phase="after",
                               dual=True, skip_db_update=True)
        assert seen == {"trivy": True, "grype": True}, (
            "an unpinned DB on either scanner lets an advisory published "
            "mid-run masquerade as a patch-introduced vulnerability"
        )


class TestGrypeDbPinning:

    def test_skip_db_update_sets_auto_update_false(self, tmp_path, monkeypatch):
        import src.grype_scanner as gs
        monkeypatch.setattr(gs, "is_grype_available", lambda: True)
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env_override")
            out = tmp_path / "g.json"
            out.write_text(json.dumps({"matches": [], "descriptor": {}}))
            return 0, ""

        monkeypatch.setattr(gs, "run_cmd", fake_run)
        gs.scan_image("img", str(tmp_path / "g.json"), skip_db_update=True)
        assert captured["env"] == {"GRYPE_DB_AUTO_UPDATE": "false"}

        gs.scan_image("img", str(tmp_path / "g.json"), skip_db_update=False)
        assert captured["env"] is None


class TestSymmetryInvariant:
    """The before-scan and the after-scan must use the same scanner set."""

    def test_union_minus_single_scanner_would_fabricate_reduction(self):
        before_trivy_only = _trivy(("CVE-1", "a", "HIGH"))
        after_trivy = _trivy(("CVE-1", "a", "HIGH"))
        after_grype = _trivy(("CVE-1", "a", "HIGH"), ("CVE-2", "b", "HIGH"))

        asymmetric_before = len(_ids(before_trivy_only))
        symmetric_after = len(_ids(fusion_to_trivy_format(
            fuse_scan_results(after_trivy, after_grype))))
        # 1 -> 2 looks like a regression only because the sets differ in
        # construction; this is the arithmetic the invariant prevents.
        assert asymmetric_before != symmetric_after
