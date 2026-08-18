"""Runtime validation must be wired into the pipeline, not merely present.

The acceptance gate has accepted a ``runtime_result`` parameter for some
time, but nothing in ``main.py`` ever passed one, so the predicate was
dead: ``runtime_result`` was always None and a rebuilt image that could
not start was still reported as a successful remediation. These tests
assert the wiring exists and behaves, so the regression cannot recur
silently.
"""
from __future__ import annotations

import inspect

import pytest


class TestPipelineWiring:

    def test_main_passes_runtime_result_to_the_gate(self):
        """The call site must forward a runtime result, not omit it."""
        import src.main as m
        src = inspect.getsource(m)
        assert "runtime_result=runtime_result" in src, (
            "check_acceptance_criteria is called without runtime_result; "
            "the runtime predicate is dead"
        )

    def test_main_invokes_the_validator(self):
        import src.main as m
        src = inspect.getsource(m)
        assert "from .runtime_validator import validate_image" in src

    def test_cli_exposes_runtime_flags(self):
        import src.main as m
        src = inspect.getsource(m)
        for flag in ("--no-runtime-validation",
                     "--runtime-validation-advisory",
                     "--smoke-manifest"):
            assert flag in src, f"{flag} is not registered"

    def test_gate_signature_accepts_runtime_parameters(self):
        from src.comparer import check_acceptance_criteria
        params = inspect.signature(check_acceptance_criteria).parameters
        assert "runtime_result" in params
        assert "require_runtime_ok" in params
        # Backward compatible: callers that do not validate still work.
        assert params["runtime_result"].default is None
        assert params["require_runtime_ok"].default is True


class TestGateBehaviourEndToEnd:
    """The predicate must actually change the verdict."""

    @staticmethod
    def _scans():
        before = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": f"CVE-{i}", "PkgName": "p",
             "Severity": "HIGH"} for i in range(10)]}]}
        after = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-0", "PkgName": "p",
             "Severity": "HIGH"}]}]}
        return before, after

    @staticmethod
    def _result(outcome):
        from src.runtime_validator import (
            RuntimeValidationResult, TierResult, Tier, TierOutcome,
        )
        r = RuntimeValidationResult(image_ref="img")
        r.tiers = [TierResult(tier=Tier.STARTUP, outcome=outcome,
                              detail="container exited early"
                              if outcome is TierOutcome.FAIL else "held 10s")]
        return r

    def test_startup_failure_rejects_despite_large_cve_drop(self):
        """A 90 percent CVE reduction is not a remediation if the image
        does not start."""
        from src.comparer import check_acceptance_criteria
        from src.runtime_validator import TierOutcome
        before, after = self._scans()
        accepted, feedback = check_acceptance_criteria(
            before, after, threshold="strict",
            runtime_result=self._result(TierOutcome.FAIL),
        )
        assert not accepted
        hard = [f for f in feedback if not f.startswith("[WARNING]")]
        assert any("Runtime validation failed" in f for f in hard)

    def test_startup_pass_accepts_and_records_evidence(self):
        from src.comparer import check_acceptance_criteria
        from src.runtime_validator import TierOutcome
        before, after = self._scans()
        accepted, feedback = check_acceptance_criteria(
            before, after, threshold="strict",
            runtime_result=self._result(TierOutcome.PASS),
        )
        assert accepted
        assert any("Runtime validation passed" in f for f in feedback)

    def test_advisory_mode_downgrades_to_warning(self):
        from src.comparer import check_acceptance_criteria
        from src.runtime_validator import TierOutcome
        before, after = self._scans()
        accepted, feedback = check_acceptance_criteria(
            before, after, threshold="strict",
            runtime_result=self._result(TierOutcome.FAIL),
            require_runtime_ok=False,
        )
        assert accepted
        assert any(f.startswith("[WARNING]") and "Runtime validation failed" in f
                   for f in feedback)

    def test_absent_result_preserves_legacy_behaviour(self):
        from src.comparer import check_acceptance_criteria
        before, after = self._scans()
        accepted, _ = check_acceptance_criteria(before, after,
                                                threshold="strict")
        assert accepted
