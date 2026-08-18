"""The strict gate must implement the paper's Eq. (1), identity-aware.

Eq. (1): Accept(I, I') := BuildSuccess(I')
                          and |V(I')| < |V(I)|
                          and C(I') \\ C(I) = empty
                          and H(I') \\ H(I) = empty

where a finding identity is (CVE identifier, affected component).

The bug this pins: the previous strict gate compared severity COUNTS
and only examined new severe findings when a bucket's count rose. That
permits exactly the masking the paper says the gate prevents: remove
five Criticals, introduce one different Critical, and the 5 -> 1 count
decrease skipped the check entirely, accepting an image that ships a
brand-new Critical. The set difference must be evaluated
unconditionally, and identity must include the component, so a known
CVE newly affecting a different package also rejects.

All scans here are synthetic Trivy-shaped dicts; no scanner runs.
"""
from __future__ import annotations

import pytest

from src.comparer import check_acceptance_criteria


def _scan(*findings):
    """findings: (cve, pkg, severity) triples -> Trivy-shaped scan."""
    return {"Results": [{
        "Target": "t", "Class": "os-pkgs",
        "Vulnerabilities": [
            {"VulnerabilityID": c, "PkgName": p, "Severity": s,
             "InstalledVersion": "1", "FixedVersion": "2", "PkgPath": ""}
            for c, p, s in findings
        ],
    }]}


def _gate(before, after, **kw):
    kw.setdefault("demote_local_av", False)   # Eq. (1) has no demotions
    return check_acceptance_criteria(before, after, threshold="strict", **kw)


class TestMaskingIsRejected:
    """The exact case Eq. (1) exists for."""

    def test_swapped_critical_rejects_despite_count_decrease(self):
        before = _scan(
            ("CVE-1", "a", "CRITICAL"), ("CVE-2", "b", "CRITICAL"),
            ("CVE-3", "c", "CRITICAL"), ("CVE-4", "d", "CRITICAL"),
            ("CVE-5", "e", "CRITICAL"), ("CVE-6", "f", "LOW"),
        )
        # Five criticals removed, ONE DIFFERENT critical introduced.
        # Critical count 5 -> 1 (decreased), total 6 -> 2 (decreased):
        # the old count-based gate accepted this.
        after = _scan(("CVE-9", "z", "CRITICAL"), ("CVE-6", "f", "LOW"))
        accepted, reasons = _gate(before, after)
        assert not accepted
        assert any("CRITICAL" in r and "CVE-9" in r for r in reasons)

    def test_swapped_high_rejects_despite_count_decrease(self):
        before = _scan(("CVE-1", "a", "HIGH"), ("CVE-2", "b", "HIGH"),
                       ("CVE-3", "c", "LOW"))
        after = _scan(("CVE-9", "z", "HIGH"))
        accepted, reasons = _gate(before, after)
        assert not accepted
        assert any("HIGH" in r and "CVE-9" in r for r in reasons)


class TestIdentityIncludesComponent:
    """Identity is (CVE, component), not bare CVE id."""

    def test_same_cve_on_new_component_rejects(self):
        # CVE-1 existed on pkg a; after the swap it also afflicts pkg z.
        # A bare-CVE-id diff calls that "not new"; the paper's identity
        # definition calls it a new Critical finding.
        before = _scan(("CVE-1", "a", "CRITICAL"), ("CVE-2", "b", "LOW"),
                       ("CVE-3", "c", "LOW"))
        after = _scan(("CVE-1", "z", "CRITICAL"))
        accepted, reasons = _gate(before, after)
        assert not accepted
        assert any("CVE-1" in r and "z" in r for r in reasons)

    def test_same_identity_at_new_path_is_not_new(self):
        # PkgPath is excluded from identity: relocation is not a
        # finding. Identity (CVE-1, a) persists; totals must still
        # strictly decrease for acceptance.
        before = {"Results": [{"Class": "os-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "a",
             "Severity": "CRITICAL", "PkgPath": "/old/site-packages"},
            {"VulnerabilityID": "CVE-2", "PkgName": "b",
             "Severity": "LOW", "PkgPath": ""},
        ]}]}
        after = {"Results": [{"Class": "os-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "a",
             "Severity": "CRITICAL", "PkgPath": "/new/site-packages"},
        ]}]}
        accepted, reasons = _gate(before, after)
        assert accepted, reasons


class TestEqOneCoreBehaviour:

    def test_pure_subset_improvement_accepts(self):
        before = _scan(("CVE-1", "a", "CRITICAL"), ("CVE-2", "b", "HIGH"),
                       ("CVE-3", "c", "MEDIUM"), ("CVE-4", "d", "LOW"))
        after = _scan(("CVE-3", "c", "MEDIUM"))
        accepted, reasons = _gate(before, after)
        assert accepted, reasons

    def test_no_identity_decrease_rejects(self):
        before = _scan(("CVE-1", "a", "LOW"), ("CVE-2", "b", "LOW"))
        after = _scan(("CVE-1", "a", "LOW"), ("CVE-2", "b", "LOW"))
        accepted, reasons = _gate(before, after)
        assert not accepted
        assert any("did not decrease" in r for r in reasons)

    def test_new_medium_identity_does_not_reject(self):
        """Eq. (1) constrains Critical and High identities only; a new
        Medium is tolerated when totals strictly decrease."""
        before = _scan(("CVE-1", "a", "HIGH"), ("CVE-2", "b", "MEDIUM"),
                       ("CVE-3", "c", "LOW"))
        after = _scan(("CVE-9", "z", "MEDIUM"))
        accepted, reasons = _gate(before, after)
        assert accepted, reasons

    def test_severity_escalation_of_existing_identity_rejects(self):
        # (CVE-1, a) was High before and is Critical after. It is in
        # C(I') and not in C(I), so under the literal Eq. (1) it is a
        # new Critical finding and rejects.
        before = _scan(("CVE-1", "a", "HIGH"), ("CVE-2", "b", "LOW"),
                       ("CVE-3", "c", "LOW"))
        after = _scan(("CVE-1", "a", "CRITICAL"))
        accepted, reasons = _gate(before, after)
        assert not accepted


class TestDemotionsAreOptInLayer:
    """Operator demotions may downgrade a new identity to a warning,
    but they are not part of Eq. (1) and KEV always blocks."""

    def test_epss_demotion_still_works_when_enabled(self):
        before = _scan(("CVE-1", "a", "CRITICAL"), ("CVE-2", "b", "LOW"),
                       ("CVE-3", "c", "LOW"))
        after = _scan(("CVE-9", "z", "CRITICAL"))
        accepted, reasons = _gate(
            before, after,
            epss_data={"CVE-9": 0.001}, epss_safe_threshold=0.01)
        assert accepted, reasons

    def test_kev_blocks_even_with_low_epss(self):
        before = _scan(("CVE-1", "a", "CRITICAL"), ("CVE-2", "b", "LOW"),
                       ("CVE-3", "c", "LOW"))
        after = _scan(("CVE-9", "z", "CRITICAL"))
        accepted, reasons = _gate(
            before, after,
            epss_data={"CVE-9": 0.001}, epss_safe_threshold=0.01,
            kev_set={"CVE-9"})
        assert not accepted
