"""Tests for src.lineage (P4-26)."""
from __future__ import annotations

import json

import pytest


class TestLineageAttestation:
    """build_lineage_predicate / emit_lineage_attestation must produce
    a deterministic, in-toto-shaped predicate that captures the
    predecessor digest, the CVE diff, the posture delta, and the
    evidence snapshot regardless of signing mode."""

    def test_chain_id_is_deterministic(self):
        from src.lineage import build_lineage_predicate
        kwargs = dict(
            subject_ref="reg.example/img@sha256:aaaa" + "0" * 60,
            predecessor_ref="reg.example/img@sha256:bbbb" + "0" * 60,
            cve_diff={"resolved": [], "remaining": [], "new": []},
        )
        a = build_lineage_predicate(**kwargs)
        b = build_lineage_predicate(**kwargs)
        # chain_id is content-derived and stable across runs.
        assert a["predicate"]["chain_id"] == b["predicate"]["chain_id"]
        assert len(a["predicate"]["chain_id"]) == 64  # sha256 hex

    def test_subject_and_predecessor_digests_extracted(self):
        from src.lineage import build_lineage_predicate
        pred = build_lineage_predicate(
            subject_ref="reg/img@sha256:" + "f" * 64,
            predecessor_ref="reg/img@sha256:" + "e" * 64,
            cve_diff={"resolved": [], "remaining": [], "new": []},
        )
        assert pred["subject"][0]["digest"]["sha256"] == "f" * 64
        assert pred["predicate"]["predecessor"]["digest"]["sha256"] == "e" * 64

    def test_missing_digest_does_not_fabricate(self):
        from src.lineage import build_lineage_predicate
        # Tag-only references have no digest. We must NOT invent one.
        pred = build_lineage_predicate(
            subject_ref="reg/img:1.0",
            predecessor_ref="reg/img:0.9",
            cve_diff={"resolved": [], "remaining": [], "new": []},
        )
        assert "digest" not in pred["subject"][0]
        assert "digest" not in pred["predicate"]["predecessor"]

    def test_cve_diff_canonicalised(self):
        from src.lineage import build_lineage_predicate
        # Mixed-case input; we expect uppercased IDs and stable sort.
        diff = {
            "resolved": [
                {"vuln_id": "cve-2024-3", "pkg_name": "openssl",
                 "severity": "high", "installed_version": "1.1.1",
                 "fixed_version": "1.1.2"},
                {"vuln_id": "CVE-2024-1", "pkg_name": "zlib",
                 "severity": "MEDIUM", "installed_version": "1.2",
                 "fixed_version": "1.3"},
            ],
            "remaining": [],
            "new": [],
        }
        pred = build_lineage_predicate(
            subject_ref="reg/img@sha256:" + "a" * 64,
            predecessor_ref="reg/img@sha256:" + "b" * 64,
            cve_diff=diff,
        )
        ids = [c["id"] for c in pred["predicate"]["cve_diff"]["resolved"]]
        assert ids == ["CVE-2024-1", "CVE-2024-3"]  # sorted, uppercased
        for c in pred["predicate"]["cve_diff"]["resolved"]:
            assert c["severity"] == c["severity"].upper()

    def test_emit_writes_canonical_json(self, tmp_path):
        from src.lineage import emit_lineage_attestation
        out = emit_lineage_attestation(
            output_dir=str(tmp_path),
            subject_ref="reg/img@sha256:" + "c" * 64,
            predecessor_ref="reg/img@sha256:" + "d" * 64,
            cve_diff={"resolved": [], "remaining": [], "new": []},
            posture_before={"total": 50.0},
            posture_after={"total": 90.0},
            evidence_snapshot={"epss_sha256": "deadbeef", "kev_sha256": ""},
            scanner_versions={"trivy": "0.69.3"},
            pipeline_config={"accept_threshold": "strict"},
            sign=False,
        )
        assert out["signed"] is False
        with open(out["path"]) as f:
            on_disk = json.load(f)
        assert on_disk["_type"] == "https://in-toto.io/Statement/v1"
        assert on_disk["predicateType"] == "https://autopatch.dev/lineage/v1"
        assert on_disk["predicate"]["posture_delta"]["before"]["total"] == 50.0
        assert on_disk["predicate"]["posture_delta"]["after"]["total"] == 90.0
        assert on_disk["predicate"]["evidence_snapshots"]["epss_sha256"] == "deadbeef"
        assert on_disk["predicate"]["chain_id"] == out["chain_id"]

    def test_emit_overwrites_atomically(self, tmp_path):
        """Two emits to the same dir must leave exactly one file, not
        a half-written .tmp sibling."""
        from src.lineage import emit_lineage_attestation
        for _ in range(2):
            emit_lineage_attestation(
                output_dir=str(tmp_path),
                subject_ref="reg/img@sha256:" + "1" * 64,
                predecessor_ref="reg/img@sha256:" + "2" * 64,
                cve_diff={"resolved": [], "remaining": [], "new": []},
                sign=False,
            )
        files = sorted(p.name for p in tmp_path.iterdir())
        assert files == ["lineage-attestation.json"], files
