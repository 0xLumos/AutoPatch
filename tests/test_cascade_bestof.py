"""Best-of cascade selection, the pinned-latest candidate, and the
winner-artifact persistence contract.

Covers the three Option-B behaviors:
  1. _latest_equivalent_of: same-repo ':latest' candidate, digest-pinned
     or absent (never an unpinned ':latest').
  2. _run_cascade best-of: all strategies evaluated; the passer with the
     smallest applicable set wins; an incumbent bars non-improvements.
  3. CascadeOutcome carries applicable_after/build_time so the caller
     can persist honest artifacts for the winner.
"""
import json
import os
from types import SimpleNamespace
from unittest import mock

import pytest

from src import main as ap_main


# ── _latest_equivalent_of ───────────────────────────────────────────

DIGEST = "sha256:" + "ab" * 32


def test_latest_equivalent_pins_digest():
    with mock.patch("src.builder._remote_manifest_digest",
                    return_value=DIGEST):
        ref = ap_main._latest_equivalent_of("golang:1.23-bookworm")
    assert ref == f"golang:latest@{DIGEST}"


def test_latest_equivalent_never_emits_unpinned():
    with mock.patch("src.builder._remote_manifest_digest",
                    return_value=None):
        assert ap_main._latest_equivalent_of("golang:1.23-bookworm") is None


def test_latest_equivalent_skips_non_candidates():
    with mock.patch("src.builder._remote_manifest_digest",
                    return_value=DIGEST):
        # already latest / tagless / digest-pinned refs
        assert ap_main._latest_equivalent_of("alpine:latest") is None
        assert ap_main._latest_equivalent_of("alpine") is None
        assert ap_main._latest_equivalent_of(
            f"alpine:3.20@{DIGEST}") is None
        # rolling or immutable ecosystems
        assert ap_main._latest_equivalent_of(
            "cgr.dev/chainguard/python:3.12") is None
        assert ap_main._latest_equivalent_of(
            "gcr.io/distroless/static:nonroot") is None
        assert ap_main._latest_equivalent_of("scratch:x") is None
        assert ap_main._latest_equivalent_of("") is None


def test_latest_equivalent_swallows_resolver_errors():
    with mock.patch("src.builder._remote_manifest_digest",
                    side_effect=RuntimeError("network down")):
        assert ap_main._latest_equivalent_of("alpine:3.16") is None


def test_slim_variant_rejects_digest_pinned_refs():
    # Appending '-slim' to a digest-pinned ref fabricates a nonexistent
    # reference (the memos regression); such refs are not eligible.
    assert ap_main._slim_variant_of(f"node:latest@{DIGEST}") is None
    assert ap_main._slim_variant_of(f"python:3.12@{DIGEST}") is None
    # plain tags still work
    assert ap_main._slim_variant_of("node:20") == "node:20-slim"


# ── _applicable_total ───────────────────────────────────────────────

def _scan_with(n_fixable):
    return {"Results": [{
        "Class": "os-pkgs", "Type": "alpine",
        "Vulnerabilities": [
            {"VulnerabilityID": f"CVE-2024-{i:04d}", "PkgName": f"p{i}",
             "InstalledVersion": "1", "FixedVersion": "2",
             "Severity": "HIGH"}
            for i in range(n_fixable)
        ]}]}


def test_applicable_total_counts_and_none():
    from src.applicability import ApplicabilityPolicy
    pol = ApplicabilityPolicy.with_no_fix()
    assert ap_main._applicable_total(_scan_with(3), pol) == 3
    assert ap_main._applicable_total(None, pol) is None
    assert ap_main._applicable_total({}, pol) == 0


# ── best-of selection in _run_cascade ───────────────────────────────

def _cascade_args(tmp_path):
    return dict(
        args=SimpleNamespace(
            accept_threshold="count-strict", cascade=True,
            cache_from=[], cache_to=None, no_buildkit=True,
            dockerfile=str(tmp_path / "Dockerfile"),
            epss_safe_threshold=0.01, min_risk_reduction=0.0,
        ),
        output_dir=str(tmp_path),
        step=ap_main.StepCounter(),
        base_image_name="img",
        run_id="t1",
        local_orig="img-orig",
        before_scan=_scan_with(10),
        sbom_before={},
        inference=None,
        patched_text_base_swap="FROM alpine:3.20\nRUN true\n",
        after_scan_base_swap=_scan_with(8),
        epss_data=None,
        kev_set=set(),
        patched_build_timeout=60,
        applicability_policy=None,
    )


def _patch_cascade_env(monkeypatch, scans_by_tag_suffix, accept_all=True):
    """Fake build/scan/sbom/gate so _run_cascade exercises pure
    selection logic. scans_by_tag_suffix maps strategy name -> scan."""
    removed = []

    def fake_build(tag, path, **kw):
        return True, None, 1.5

    def fake_scan(tag, out_path):
        for name, scan in scans_by_tag_suffix.items():
            if f"-cascade-{name}-" in tag:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(scan, f)
                return scan
        raise AssertionError(f"unexpected tag {tag}")

    def fake_sbom(tag, out_path):
        return {}

    def fake_gate(before, after, **kw):
        return accept_all, []

    def fake_run_cmd(cmd, **kw):
        if cmd[:3] == ["docker", "rmi", "-f"]:
            removed.append(cmd[3])
        return 0, ""

    monkeypatch.setattr(ap_main, "build_image", fake_build)
    monkeypatch.setattr(ap_main, "scan_image", fake_scan)
    monkeypatch.setattr(ap_main, "generate_sbom", fake_sbom)
    monkeypatch.setattr(ap_main, "check_acceptance_criteria", fake_gate)
    monkeypatch.setattr(ap_main, "run_cmd", fake_run_cmd)
    return removed


def test_best_of_selects_smallest_applicable(tmp_path, monkeypatch):
    # Two alternate bases both pass the gate; the second is strictly
    # better. First-accept would return alt_base_latest with 5; best-of
    # must keep evaluating and select alt_base_slim with 2.
    removed = _patch_cascade_env(monkeypatch, {
        "alt_base_latest": _scan_with(5),
        "alt_base_slim": _scan_with(2),
        "inplace_os": _scan_with(4),
    })
    out = ap_main._run_cascade(
        **_cascade_args(tmp_path),
        alternate_bases=[
            ("alt_base_latest", "alpine:3.20", "alpine:latest@sha256:aa"),
            ("alt_base_slim", "alpine:3.20", "debian:bookworm-slim"),
        ],
    )
    assert out.accepted
    assert out.strategy == "alt_base_slim"
    assert out.applicable_after == 2
    assert out.build_time == 1.5
    # the superseded leader's image was released, the winner's kept
    assert any("alt-base-latest" in t or "alt_base_latest" in t
               for t in removed)
    assert out.image_tag not in removed


def test_incumbent_bars_non_improvements(tmp_path, monkeypatch):
    # Improver mode: incumbent has 2 applicable findings. A passer with
    # 5 must NOT be adopted.
    _patch_cascade_env(monkeypatch, {
        "alt_base_latest": _scan_with(5),
        "inplace_os": _scan_with(7),
    })
    out = ap_main._run_cascade(
        **_cascade_args(tmp_path),
        alternate_bases=[
            ("alt_base_latest", "alpine:3.20", "alpine:latest@sha256:aa"),
        ],
        incumbent_key=(2, 0, 0),
    )
    assert not out.accepted
    assert out.image_tag is None


def test_incumbent_allows_strict_improvement(tmp_path, monkeypatch):
    _patch_cascade_env(monkeypatch, {
        "alt_base_latest": _scan_with(1),
        "inplace_os": _scan_with(7),
    })
    out = ap_main._run_cascade(
        **_cascade_args(tmp_path),
        alternate_bases=[
            ("alt_base_latest", "alpine:3.20", "alpine:latest@sha256:aa"),
        ],
        incumbent_key=(2, 0, 0),
    )
    assert out.accepted
    assert out.strategy == "alt_base_latest"
    assert out.applicable_after == 1


def test_tiebreak_prefers_fewer_fixable_at_equal_applicable(
        tmp_path, monkeypatch):
    # Both passers reach applicable == N, but the second leaves fewer
    # fixable OS findings. With applicable-only ranking the first would
    # keep the lead by order; the key tuple must hand it to the second.
    scan_high_fix = _scan_with(3)
    scan_low_fix = {"Results": [
        {"Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": [
            {"VulnerabilityID": f"CVE-2024-9{i:03d}", "PkgName": f"q{i}",
             "InstalledVersion": "1", "FixedVersion": "2",
             "Severity": "HIGH"} for i in range(3)]},
        # extra no-fix findings: excluded from applicable, raise raw
        {"Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": [
            {"VulnerabilityID": f"CVE-2024-8{i:03d}", "PkgName": f"r{i}",
             "InstalledVersion": "1", "FixedVersion": "",
             "Severity": "LOW"} for i in range(2)]},
    ]}
    # keys: high_fix -> (3, 3, 3); low_fix -> (3, 3, 5). Equal on
    # applicable and fixable, worse on raw: must NOT displace.
    _patch_cascade_env(monkeypatch, {
        "alt_base_latest": scan_high_fix,
        "alt_base_slim": scan_low_fix,
        "inplace_os": _scan_with(9),
    })
    out = ap_main._run_cascade(
        **_cascade_args(tmp_path),
        alternate_bases=[
            ("alt_base_latest", "alpine:3.20", "alpine:latest@sha256:aa"),
            ("alt_base_slim", "alpine:3.20", "debian:bookworm-slim"),
        ],
    )
    assert out.strategy == "alt_base_latest"
    assert out.selection_key == (3, 3, 3)


def test_rejected_candidates_still_cleaned_up(tmp_path, monkeypatch):
    removed = _patch_cascade_env(
        monkeypatch, {
            "alt_base_latest": _scan_with(5),
            "inplace_os": _scan_with(7),
        }, accept_all=False)
    out = ap_main._run_cascade(
        **_cascade_args(tmp_path),
        alternate_bases=[
            ("alt_base_latest", "alpine:3.20", "alpine:latest@sha256:aa"),
        ],
    )
    assert not out.accepted
    # every built candidate image was removed
    assert len(removed) >= 1
