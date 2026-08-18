"""Tests for src.multistage (P4-24)."""
from __future__ import annotations

import pytest


def _scan(*ids):
    return {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": i, "PkgName": "p", "Severity": "MEDIUM"}
        for i in ids
    ]}]}


class TestClassifyCves:
    """classify_cves_by_stage must partition the CVE universe into
    runtime vs build-only based on which stages each CVE appears in.
    """

    def test_runtime_only_when_final_has_cve(self):
        from src.multistage import classify_cves_by_stage, StageScan
        c = classify_cves_by_stage([
            StageScan("builder", is_final=False, scan=_scan("CVE-1", "CVE-2")),
            StageScan("runtime", is_final=True, scan=_scan("CVE-2")),
        ])
        # CVE-2 appears in runtime, so runtime set = {CVE-2}; CVE-1 is
        # build-only.
        assert c.runtime_cves == {"CVE-2"}
        assert c.build_only_cves == {"CVE-1"}

    def test_build_only_when_runtime_clean(self):
        from src.multistage import classify_cves_by_stage, StageScan
        c = classify_cves_by_stage([
            StageScan("builder", is_final=False, scan=_scan("CVE-3", "CVE-4")),
            StageScan("runtime", is_final=True, scan=_scan()),
        ])
        assert c.runtime_cves == set()
        assert c.build_only_cves == {"CVE-3", "CVE-4"}

    def test_cve_to_stages_mapping(self):
        from src.multistage import classify_cves_by_stage, StageScan
        c = classify_cves_by_stage([
            StageScan("a", is_final=False, scan=_scan("CVE-X")),
            StageScan("b", is_final=False, scan=_scan("CVE-X", "CVE-Y")),
            StageScan("c", is_final=True,  scan=_scan("CVE-Y")),
        ])
        assert c.cve_to_stages["CVE-X"] == {"a", "b"}
        assert c.cve_to_stages["CVE-Y"] == {"b", "c"}
        assert c.runtime_cves == {"CVE-Y"}
        assert c.build_only_cves == {"CVE-X"}

    def test_falls_back_to_last_stage_when_no_final(self):
        from src.multistage import classify_cves_by_stage, StageScan
        # Caller forgot to flag any stage as final; we must NOT
        # over-classify every CVE as build-only. Treat the last stage
        # as final.
        c = classify_cves_by_stage([
            StageScan("a", is_final=False, scan=_scan("CVE-A")),
            StageScan("b", is_final=False, scan=_scan("CVE-B")),
        ])
        assert c.runtime_cves == {"CVE-B"}
        assert c.build_only_cves == {"CVE-A"}

    def test_handles_empty_input(self):
        from src.multistage import classify_cves_by_stage
        c = classify_cves_by_stage([])
        assert c.runtime_cves == set()
        assert c.build_only_cves == set()

    def test_uppercases_mixed_case_ids(self):
        from src.multistage import classify_cves_by_stage, StageScan
        c = classify_cves_by_stage([
            StageScan("runtime", is_final=True,
                      scan=_scan("cve-2024-1", "CVE-2024-2")),
        ])
        assert c.runtime_cves == {"CVE-2024-1", "CVE-2024-2"}


class TestSubsetScan:
    """subset_scan_to_cves preserves the surrounding scan structure
    but filters Vulnerabilities to the keep set."""

    def test_subset_keeps_only_listed_ids(self):
        from src.multistage import subset_scan_to_cves
        scan = {
            "ArtifactName": "img",
            "Results": [{
                "Target": "img (debian 12)",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "Severity": "HIGH"},
                    {"VulnerabilityID": "CVE-2", "Severity": "LOW"},
                ],
            }],
        }
        out = subset_scan_to_cves(scan, keep={"CVE-1"})
        assert out["ArtifactName"] == "img"
        assert out["Results"][0]["Target"] == "img (debian 12)"
        ids = [v["VulnerabilityID"] for v in out["Results"][0]["Vulnerabilities"]]
        assert ids == ["CVE-1"]

    def test_subset_does_not_mutate_input(self):
        from src.multistage import subset_scan_to_cves
        scan = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-1"}, {"VulnerabilityID": "CVE-2"},
        ]}]}
        before = len(scan["Results"][0]["Vulnerabilities"])
        _ = subset_scan_to_cves(scan, keep={"CVE-1"})
        after = len(scan["Results"][0]["Vulnerabilities"])
        assert before == after  # input untouched

    def test_subset_with_empty_keep_drops_all(self):
        from src.multistage import subset_scan_to_cves
        scan = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-1"}, {"VulnerabilityID": "CVE-2"},
        ]}]}
        out = subset_scan_to_cves(scan, keep=set())
        assert out["Results"][0]["Vulnerabilities"] == []


class TestDeriveFinalStage:
    """derive_final_stage_aliases picks the right stage given the
    Dockerfile's parsed stage list and an optional --target."""

    def test_no_target_picks_last(self):
        from src.multistage import derive_final_stage_aliases
        stages = [{"alias": "builder"}, {"alias": "runtime"}]
        assert derive_final_stage_aliases(stages) == ["runtime"]

    def test_target_alias_match(self):
        from src.multistage import derive_final_stage_aliases
        stages = [{"alias": "builder"}, {"alias": "runtime"}]
        assert derive_final_stage_aliases(stages, target="builder") == ["builder"]

    def test_unknown_target_falls_back_to_last(self):
        from src.multistage import derive_final_stage_aliases
        stages = [{"alias": "builder"}, {"alias": "runtime"}]
        # Unknown target string: we do NOT raise (the actual build
        # will surface the error); we fall back to the last stage.
        assert derive_final_stage_aliases(stages, target="nope") == ["runtime"]

    def test_empty_stage_list(self):
        from src.multistage import derive_final_stage_aliases
        assert derive_final_stage_aliases([]) == []


class TestSummary:
    def test_summary_shape(self):
        from src.multistage import classify_cves_by_stage, summarise, StageScan
        c = classify_cves_by_stage([
            StageScan("a", is_final=False, scan=_scan("CVE-1")),
            StageScan("b", is_final=True,  scan=_scan()),
        ])
        s = summarise(c)
        assert s["runtime_cve_count"] == 0
        assert s["build_only_cve_count"] == 1
        assert s["build_only_cves"] == ["CVE-1"]
        assert s["cve_to_stages"] == {"CVE-1": ["a"]}
