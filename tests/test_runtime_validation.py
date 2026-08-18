"""Tests for tiered runtime validation and its acceptance-gate wiring.

All tests here are Docker-free: the tier functions are exercised
through injected results and through the manifest loader, so the suite
runs on any host. Real-Docker coverage lives in
tests/integration/test_runtime_docker.py and auto-skips when the
daemon is unavailable.
"""
from __future__ import annotations

import pytest


def _mk_result(image="img", tiers=None, duration=1.0):
    from src.runtime_validator import RuntimeValidationResult
    r = RuntimeValidationResult(image_ref=image)
    r.tiers = list(tiers or [])
    r.total_duration_s = duration
    return r


def _tier(t, o, detail=""):
    from src.runtime_validator import TierResult
    return TierResult(tier=t, outcome=o, detail=detail)


class TestPredicateSemantics:
    """runtime_ok must be True only when no tier reports a blocking
    failure and the startup tier actually ran."""

    def test_all_tiers_pass(self):
        from src.runtime_validator import Tier, TierOutcome
        r = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.PASS),
            _tier(Tier.INTROSPECTION, TierOutcome.PASS),
            _tier(Tier.APPLICATION, TierOutcome.PASS),
        ])
        assert r.passed
        assert r.first_failure is None

    def test_startup_failure_blocks(self):
        from src.runtime_validator import Tier, TierOutcome
        r = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.FAIL, "exited early"),
        ])
        assert not r.passed
        assert r.first_failure.tier is Tier.STARTUP

    def test_introspection_failure_blocks(self):
        from src.runtime_validator import Tier, TierOutcome
        r = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.PASS),
            _tier(Tier.INTROSPECTION, TierOutcome.FAIL, "loader/ABI failure"),
        ])
        assert not r.passed

    def test_application_failure_blocks(self):
        from src.runtime_validator import Tier, TierOutcome
        r = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.PASS),
            _tier(Tier.INTROSPECTION, TierOutcome.PASS),
            _tier(Tier.APPLICATION, TierOutcome.FAIL, "probe returned 7"),
        ])
        assert not r.passed

    def test_skips_do_not_block(self):
        """An entrypoint that rejects --version, or an image with no
        declared probe, must not be treated as a functional failure."""
        from src.runtime_validator import Tier, TierOutcome
        r = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.PASS),
            _tier(Tier.INTROSPECTION, TierOutcome.SKIP, "no flag accepted"),
            _tier(Tier.APPLICATION, TierOutcome.SKIP, "no probe declared"),
        ])
        assert r.passed

    def test_infrastructure_error_does_not_block(self):
        """A flaky daemon is not the image's fault; ERROR is reported
        but must not silently reject a good remediation."""
        from src.runtime_validator import Tier, TierOutcome
        r = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.ERROR, "docker not available"),
        ])
        assert not r.passed  # startup never ran, so not validated
        assert r.first_failure is None  # but it is not a blocking FAIL

    def test_empty_result_is_not_passed(self):
        r = _mk_result(tiers=[])
        assert not r.passed

    def test_serialization_round_trip(self):
        from src.runtime_validator import Tier, TierOutcome
        r = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.PASS, "held 10s"),
            _tier(Tier.APPLICATION, TierOutcome.SKIP),
        ])
        d = r.to_dict()
        assert d["runtime_ok"] is True
        assert d["tiers"][0]["tier"] == "startup"
        assert d["tiers"][0]["outcome"] == "pass"


class TestDisabledAndMissingDocker:

    def test_disabled_spec_short_circuits(self):
        from src.runtime_validator import validate_image, SmokeSpec
        r = validate_image("whatever:1.0", SmokeSpec(enabled=False))
        assert len(r.tiers) == 1
        assert r.tiers[0].outcome.value == "skip"

    def test_missing_docker_reports_error(self, monkeypatch):
        import src.runtime_validator as rv
        monkeypatch.setattr(rv.shutil, "which", lambda _: None)
        r = rv.validate_image("whatever:1.0")
        assert r.tiers[0].outcome is rv.TierOutcome.ERROR
        assert not r.passed


class TestSummarizer:
    """summarize_results produces exactly the counts reported in the
    paper's runtime-validation table."""

    def test_counts_and_rates(self):
        from src.runtime_validator import Tier, TierOutcome, summarize_results

        def full_pass():
            return _mk_result(tiers=[
                _tier(Tier.STARTUP, TierOutcome.PASS),
                _tier(Tier.INTROSPECTION, TierOutcome.PASS),
                _tier(Tier.APPLICATION, TierOutcome.PASS),
            ], duration=10.0)

        def no_probe():
            return _mk_result(tiers=[
                _tier(Tier.STARTUP, TierOutcome.PASS),
                _tier(Tier.INTROSPECTION, TierOutcome.PASS),
                _tier(Tier.APPLICATION, TierOutcome.SKIP),
            ], duration=8.0)

        def startup_fail():
            return _mk_result(tiers=[
                _tier(Tier.STARTUP, TierOutcome.FAIL),
            ], duration=4.0)

        def probe_fail():
            return _mk_result(tiers=[
                _tier(Tier.STARTUP, TierOutcome.PASS),
                _tier(Tier.INTROSPECTION, TierOutcome.PASS),
                _tier(Tier.APPLICATION, TierOutcome.FAIL),
            ], duration=12.0)

        results = ([full_pass()] * 5 + [no_probe()] * 3
                   + [startup_fail()] * 2 + [probe_fail()] * 1)
        s = summarize_results(results)

        assert s["images_evaluated"] == 11
        assert s["runtime_ok"] == 8          # 5 full + 3 no-probe
        assert s["tier_counts"]["startup"]["pass"] == 9
        assert s["tier_counts"]["startup"]["fail"] == 2
        # Tier-3 denominator excludes SKIPs so the rate is meaningful
        assert s["application_tier_applicable"] == 6   # 5 pass + 1 fail
        assert abs(s["application_tier_pass_rate"] - 5 / 6) < 1e-9

    def test_empty_corpus(self):
        from src.runtime_validator import summarize_results
        s = summarize_results([])
        assert s["images_evaluated"] == 0
        assert s["runtime_ok"] == 0
        assert s["application_tier_pass_rate"] is None


class TestSmokeManifest:

    def test_defaults_apply_to_unlisted_image(self):
        from src.smoke_manifest import manifest_from_dict
        m = manifest_from_dict({
            "defaults": {"startup_hold_s": 7},
            "images": {"nginx": {"network": "bridge"}},
        })
        spec = m.spec_for("totally/unknown:9")
        assert spec.enabled and spec.introspect
        assert spec.startup_hold_s == 7
        assert spec.app_command is None

    def test_tag_stripping_lookup(self):
        from src.smoke_manifest import manifest_from_dict
        m = manifest_from_dict({
            "images": {"postgres": {"app_command": ["pg_isready"]}},
        })
        assert m.spec_for("postgres:13").app_command == ["pg_isready"]
        assert m.spec_for("postgres:15-alpine").app_command == ["pg_isready"]

    def test_string_command_is_split(self):
        from src.smoke_manifest import manifest_from_dict
        m = manifest_from_dict({
            "images": {"x": {"app_command": "sh -c 'echo hi'"}},
        })
        assert m.spec_for("x").app_command == ["sh", "-c", "echo hi"]

    def test_rejects_non_string_command(self):
        from src.smoke_manifest import manifest_from_dict, ManifestError
        with pytest.raises(ManifestError):
            manifest_from_dict({"images": {"x": {"app_command": {"a": 1}}}})

    def test_rejects_bad_network(self):
        from src.smoke_manifest import manifest_from_dict, ManifestError
        with pytest.raises(ManifestError):
            manifest_from_dict({"images": {"x": {"network": "quantum"}}})

    def test_disabled_image_records_skip_reason(self):
        from src.smoke_manifest import manifest_from_dict
        m = manifest_from_dict({
            "images": {"x": {"enabled": False,
                             "skip_reason": "needs external DB"}},
        })
        assert m.spec_for("x").enabled is False
        assert m.skip_reasons["x"] == "needs external DB"

    def test_application_probe_count(self):
        from src.smoke_manifest import manifest_from_dict
        m = manifest_from_dict({
            "images": {
                "a": {"app_command": ["true"]},
                "b": {"app_command": ["true"]},
                "c": {},
            },
        })
        assert m.application_probe_count == 2

    def test_shipped_manifest_loads(self):
        """The manifest published with the dataset must parse and
        declare probes; a broken manifest would silently downgrade
        every Tier-3 result to SKIP."""
        from pathlib import Path
        from src.smoke_manifest import load_manifest
        p = Path(__file__).resolve().parent.parent / "dataset" / "smoke" / "manifest.yaml"
        if not p.is_file():
            pytest.skip("dataset manifest not present in this checkout")
        m = load_manifest(str(p))
        assert len(m) > 0
        assert m.application_probe_count > 0
        # spot-check a well-known entry
        spec = m.spec_for("nginx:1.20")
        assert spec.network == "bridge"
        assert spec.app_command is not None


class TestAcceptanceGateWiring:
    """The gate must reject a candidate whose runtime validation
    failed, regardless of how much the CVE count dropped."""

    @staticmethod
    def _scans():
        before = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": f"CVE-{i}", "PkgName": "p",
             "Severity": "HIGH"} for i in range(10)]}]}
        after = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": f"CVE-{i}", "PkgName": "p",
             "Severity": "HIGH"} for i in range(3)]}]}
        return before, after

    def test_backward_compatible_without_runtime_result(self):
        from src.comparer import check_acceptance_criteria
        before, after = self._scans()
        accepted, _ = check_acceptance_criteria(before, after,
                                                threshold="strict")
        assert accepted

    def test_runtime_pass_still_accepted(self):
        from src.comparer import check_acceptance_criteria
        from src.runtime_validator import Tier, TierOutcome
        before, after = self._scans()
        rt = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.PASS),
            _tier(Tier.INTROSPECTION, TierOutcome.PASS),
        ])
        accepted, feedback = check_acceptance_criteria(
            before, after, threshold="strict", runtime_result=rt)
        assert accepted
        assert any("Runtime validation passed" in f for f in feedback)

    def test_runtime_failure_rejects_despite_cve_drop(self):
        from src.comparer import check_acceptance_criteria
        from src.runtime_validator import Tier, TierOutcome
        before, after = self._scans()
        rt = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.FAIL, "container exited early"),
        ])
        accepted, feedback = check_acceptance_criteria(
            before, after, threshold="strict", runtime_result=rt)
        assert not accepted
        hard = [f for f in feedback if not f.startswith("[WARNING]")]
        assert any("Runtime validation failed" in f for f in hard)

    def test_advisory_mode_warns_instead_of_rejecting(self):
        from src.comparer import check_acceptance_criteria
        from src.runtime_validator import Tier, TierOutcome
        before, after = self._scans()
        rt = _mk_result(tiers=[
            _tier(Tier.STARTUP, TierOutcome.FAIL, "container exited early"),
        ])
        accepted, feedback = check_acceptance_criteria(
            before, after, threshold="strict", runtime_result=rt,
            require_runtime_ok=False)
        assert accepted
        assert any(f.startswith("[WARNING]") and "Runtime validation failed" in f
                   for f in feedback)
