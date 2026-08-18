"""Exploitability-class applicability filter for the acceptance gate.

The motivation: the acceptance gate should reason about vulnerabilities
that can affect the container, not the raw scanner output. This replaces
per-package special-casing (the linux-libc-dev problem) with a small set
of general rules. The tests below pin the rules AND their interaction
with the strict gate, including the exact case that motivated it:
linux-libc-dev kernel-header CVEs must not reject a strictly-safer image.
"""
from __future__ import annotations

import pytest

from src.applicability import (
    ApplicabilityPolicy,
    classify_exclusion,
    is_kernel_space,
    partition_applicable,
)
from src.comparer import check_acceptance_criteria
from src.vulnerability_index import VulnRecord


def _rec(cve, pkg, sev="HIGH", fixed="2.0"):
    return VulnRecord(vuln_id=cve, pkg_name=pkg, pkg_path="", severity=sev,
                      installed_version="1.0", fixed_version=fixed)


class TestKernelSpaceRule:

    @pytest.mark.parametrize("pkg,want", [
        ("linux-libc-dev", True),
        ("linux-headers-6.1.0-13-amd64", True),
        ("linux-image-amd64", True),
        ("linux-modules-6.1.0", True),
        ("linux-tools-common", True),
        ("kernel-headers", True),
        ("kernel-devel", True),
        ("kernel-core", True),
        ("linux-lts", True),
        # NOT kernel-space: userspace packages that merely start with a
        # kernel-ish string must not be swept up.
        ("openssl", False),
        ("libc6", False),
        ("linux-pam", False),          # PAM is userspace, not the kernel
        ("util-linux", False),
        ("busybox", False),
    ])
    def test_kernel_classification(self, pkg, want):
        assert is_kernel_space(pkg) is want


class TestClassifyExclusion:

    def test_kernel_excluded_by_default(self):
        p = ApplicabilityPolicy()
        assert classify_exclusion(_rec("CVE-1", "linux-libc-dev"), p) \
            == "kernel-space"

    def test_no_fix_library_default_vs_pipeline_default(self):
        # LIBRARY default (bare ApplicabilityPolicy()) leaves a no-fix
        # userspace finding APPLICABLE: library callers and the Eq. (1)
        # analyses opt in explicitly. The shipped CLI default
        # (--applicability default) constructs with_no_fix(), which
        # excludes it, matching admission-controller practice of gating
        # on findings with an available fix.
        assert classify_exclusion(
            _rec("CVE-1", "openssl", fixed=""), ApplicabilityPolicy()) is None
        assert classify_exclusion(
            _rec("CVE-1", "openssl", fixed=""),
            ApplicabilityPolicy.with_no_fix()) == "no-fix-available"
        # kernel_only() is the previous pipeline default: kernel rule
        # on, no-fix findings kept in the gate.
        p = ApplicabilityPolicy.kernel_only()
        assert classify_exclusion(_rec("CVE-1", "openssl", fixed=""), p) is None
        assert classify_exclusion(_rec("CVE-2", "linux-libc-dev"), p) \
            == "kernel-space"

    def test_kev_overrides_every_exclusion(self):
        p = ApplicabilityPolicy()
        # A kernel CVE that is also on KEV stays gate-relevant.
        assert classify_exclusion(
            _rec("CVE-1", "linux-libc-dev"), p, kev_set={"CVE-1"}) is None
        # A no-fix CVE on KEV likewise stays relevant.
        assert classify_exclusion(
            _rec("CVE-2", "openssl", fixed=""), p, kev_set={"CVE-2"}) is None

    def test_ordinary_finding_is_applicable(self):
        assert classify_exclusion(
            _rec("CVE-1", "openssl", fixed="3.0.14"),
            ApplicabilityPolicy()) is None

    def test_literal_policy_excludes_nothing(self):
        p = ApplicabilityPolicy.literal()
        assert classify_exclusion(_rec("CVE-1", "linux-libc-dev"), p) is None
        assert classify_exclusion(_rec("CVE-2", "x", fixed=""), p) is None

    def test_reachability_rule_is_opt_in(self):
        rec = _rec("CVE-1", "leftpad", fixed="2.0")
        off = ApplicabilityPolicy()
        assert classify_exclusion(rec, off) is None      # reachability off
        on = ApplicabilityPolicy(exclude_unreachable=True,
                                 reachable_packages={"openssl"})
        assert classify_exclusion(rec, on) == "unreachable"

    def test_partition_groups_by_rule(self):
        recs = [_rec("CVE-1", "linux-libc-dev"),
                _rec("CVE-2", "openssl", fixed=""),
                _rec("CVE-3", "openssl", fixed="3.0.14")]
        # Default: only kernel-space fires; the no-fix openssl stays
        # applicable.
        app, excl = partition_applicable(recs, ApplicabilityPolicy())
        assert sorted(r.vuln_id for r in app) == ["CVE-2", "CVE-3"]
        assert {k: [r.vuln_id for r in v] for k, v in excl.items()} == {
            "kernel-space": ["CVE-1"]}
        # With no-fix opted in, both rules fire.
        app2, excl2 = partition_applicable(
            recs, ApplicabilityPolicy.with_no_fix())
        assert [r.vuln_id for r in app2] == ["CVE-3"]
        assert {k: [r.vuln_id for r in v] for k, v in excl2.items()} == {
            "kernel-space": ["CVE-1"], "no-fix-available": ["CVE-2"]}


def _scan(*findings):
    """findings: (cve, pkg, severity, fixed) -> Trivy-shaped scan."""
    return {"Results": [{
        "Target": "t", "Class": "os-pkgs",
        "Vulnerabilities": [
            {"VulnerabilityID": c, "PkgName": p, "Severity": s,
             "InstalledVersion": "1", "FixedVersion": fx, "PkgPath": ""}
            for c, p, s, fx in findings
        ],
    }]}


class TestGateUsesApplicableSet:
    """The motivating end-to-end case."""

    def test_kernel_header_churn_does_not_reject_a_safer_image(self):
        # Before: 1 real High (openssl) + 3 kernel Highs.
        before = _scan(
            ("CVE-OSSL", "openssl", "HIGH", "3.0.14"),
            ("CVE-K1", "linux-libc-dev", "HIGH", ""),
            ("CVE-K2", "linux-libc-dev", "HIGH", ""),
            ("CVE-K3", "linux-libc-dev", "HIGH", ""),
        )
        # After the base bump: openssl fixed (gone), and the newer
        # kernel headers surface DIFFERENT kernel Highs. Under literal
        # Eq. (1) these new kernel identities reject the image; under
        # the default policy they are excluded, leaving zero applicable
        # new High and a strict total decrease.
        after = _scan(
            ("CVE-K4", "linux-libc-dev", "HIGH", ""),
            ("CVE-K5", "linux-libc-dev", "HIGH", ""),
        )
        accepted, reasons = check_acceptance_criteria(
            before, after, threshold="strict", demote_local_av=False)
        assert accepted, reasons

    def test_literal_policy_rejects_the_same_case(self):
        before = _scan(
            ("CVE-OSSL", "openssl", "HIGH", "3.0.14"),
            ("CVE-K1", "linux-libc-dev", "HIGH", ""),
        )
        after = _scan(("CVE-K4", "linux-libc-dev", "HIGH", ""))
        accepted, reasons = check_acceptance_criteria(
            before, after, threshold="strict", demote_local_av=False,
            applicability_policy=ApplicabilityPolicy.literal())
        assert not accepted

    def test_kev_kernel_cve_still_rejects(self):
        """A kernel CVE on KEV is not excluded, so a new one rejects even
        under the default policy: KEV override wins."""
        before = _scan(("CVE-OSSL", "openssl", "HIGH", "3.0.14"),
                       ("CVE-Z", "curl", "LOW", "8.0"))
        after = _scan(("CVE-KEV", "linux-libc-dev", "HIGH", ""))
        accepted, reasons = check_acceptance_criteria(
            before, after, threshold="strict", demote_local_av=False,
            kev_set={"CVE-KEV"})
        assert not accepted

    def test_genuine_new_userspace_high_still_rejects(self):
        """The filter must not blunt the real gate: a new applicable
        (non-kernel, fixable) High still rejects."""
        before = _scan(("CVE-1", "openssl", "HIGH", "3.0.14"),
                       ("CVE-2", "curl", "LOW", "8.0"))
        after = _scan(("CVE-9", "zlib", "HIGH", "1.3"))
        accepted, reasons = check_acceptance_criteria(
            before, after, threshold="strict", demote_local_av=False)
        assert not accepted
        assert any("zlib" in r for r in reasons)


class TestCountStrictPipelineDefault:
    """The operational gate the shipped CLI runs: count-strict over the
    applicable+fixable set (with_no_fix policy), KEV hard-block. These
    pin the exact semantics the A/B experiment gates under."""

    def test_identity_churn_with_improving_counts_admits(self):
        # The freshrss-style base modernization: severe identities churn
        # but every applicable count moves down. identity-strict rejects
        # this; the operational gate admits it.
        before = _scan(
            ("CVE-A", "openssl", "CRITICAL", "3.0.14"),
            ("CVE-B", "curl", "HIGH", "8.5"),
            ("CVE-C", "zlib", "HIGH", "1.3"),
            ("CVE-D", "pcre2", "MEDIUM", "10.43"),
        )
        after = _scan(
            ("CVE-X", "libxml2", "HIGH", "2.12"),   # new identity, fixable
            ("CVE-Y", "sqlite3", "MEDIUM", "3.45"),
        )
        pol = ApplicabilityPolicy.with_no_fix()
        strict_ok, _ = check_acceptance_criteria(
            before, after, threshold="strict", demote_local_av=False,
            applicability_policy=pol)
        count_ok, reasons = check_acceptance_criteria(
            before, after, threshold="count-strict", demote_local_av=False,
            applicability_policy=pol)
        assert not strict_ok       # the Eq. (1) bound rejects the churn
        assert count_ok, reasons   # the operational gate admits it

    def test_unfixable_new_disclosure_does_not_block(self):
        # A newly-disclosed CVE with no fix anywhere (the CVE-2026-53615
        # class) is excluded by the fixable rule: the gate cannot demand
        # action where no action exists. Counts still improve, admit.
        before = _scan(("CVE-A", "openssl", "HIGH", "3.0.14"),
                       ("CVE-B", "curl", "MEDIUM", "8.5"))
        after = _scan(("CVE-NEW", "glibc", "HIGH", ""))  # no fix exists
        accepted, reasons = check_acceptance_criteria(
            before, after, threshold="count-strict", demote_local_av=False,
            applicability_policy=ApplicabilityPolicy.with_no_fix())
        assert accepted, reasons

    def test_new_kev_blocks_even_when_unfixable(self):
        # KEV overrides the fixable exclusion AND blocks count-strict
        # unconditionally: an actively-exploited CVE ships under no
        # policy, fix or no fix.
        before = _scan(("CVE-A", "openssl", "HIGH", "3.0.14"),
                       ("CVE-B", "curl", "MEDIUM", "8.5"))
        after = _scan(("CVE-KEV", "glibc", "HIGH", ""))
        accepted, reasons = check_acceptance_criteria(
            before, after, threshold="count-strict", demote_local_av=False,
            applicability_policy=ApplicabilityPolicy.with_no_fix(),
            kev_set={"CVE-KEV"})
        assert not accepted
        assert any("KEV" in r for r in reasons)

    def test_severity_regression_still_rejects(self):
        # The gate is not a rubber stamp: a rise in applicable fixable
        # HIGH count rejects even though the total drops.
        before = _scan(("CVE-A", "openssl", "HIGH", "3.0.14"),
                       ("CVE-B", "curl", "LOW", "8.5"),
                       ("CVE-C", "zlib", "LOW", "1.3"))
        after = _scan(("CVE-X", "libxml2", "HIGH", "2.12"),
                      ("CVE-Y", "sqlite3", "HIGH", "3.45"))
        accepted, reasons = check_acceptance_criteria(
            before, after, threshold="count-strict", demote_local_av=False,
            applicability_policy=ApplicabilityPolicy.with_no_fix())
        assert not accepted
        assert any("HIGH" in r for r in reasons)

    def test_pure_masking_swap_still_rejects(self):
        # Swap one Critical for another with nothing else changing: the
        # total does not strictly decrease, so count-strict rejects the
        # masking case identity-strict was designed against.
        before = _scan(("CVE-A", "openssl", "CRITICAL", "3.0.14"))
        after = _scan(("CVE-B", "libxml2", "CRITICAL", "2.12"))
        accepted, _ = check_acceptance_criteria(
            before, after, threshold="count-strict", demote_local_av=False,
            applicability_policy=ApplicabilityPolicy.with_no_fix())
        assert not accepted
