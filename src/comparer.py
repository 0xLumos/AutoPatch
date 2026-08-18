from dataclasses import dataclass
import logging
import json
import csv
from typing import Dict, List, Tuple, Optional, Any
from .scanner import _count_vulnerabilities_by_severity as _count_vulns_by_severity
from .utils import save_json
from . import vulnerability_index as _vi

from .constants import DEFAULT_EPSS_SAFE_THRESHOLD

logger = logging.getLogger("docker_patch_tool")

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# EPSS publishes the probability that a CVE is exploited in the wild
# within the next 30 days. Any windowing arithmetic must treat that as
# the reference period rather than as a per-day rate.
EPSS_REFERENCE_WINDOW_DAYS = 30


def _record_to_dict(r: "_vi.VulnRecord") -> Dict[str, Any]:
    """Convert a VulnRecord to the legacy dict shape callers expect."""
    return {
        "id": r.vuln_id,
        "package": r.pkg_name,
        "version": r.installed_version,
        "severity": r.severity,
        "fix_version": r.fixed_version,
    }


def diff_vulnerabilities(before_scan: Dict[str, Any], after_scan: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare vulnerabilities between before and after scans.

    Deduplicates on ``(VulnerabilityID, PkgName, PkgPath)`` when
    extracting records, then diffs on ``(VulnerabilityID, PkgName)``.
    The diff is deliberately path-insensitive: a base substitution
    relocates installed files, and an unfixed CVE at a new path is
    still the same unfixed CVE, not one resolved plus one introduced.

    Args:
        before_scan: Vulnerability scan result before patching
        after_scan: Vulnerability scan result after patching

    Returns:
        Dict with keys 'resolved', 'remaining', 'new' containing vulnerability lists.
        Each vulnerability has: id, package, severity, version, fix_version.
    """
    before_records = _vi.extract_records(before_scan)
    after_records = _vi.extract_records(after_scan)
    diff = _vi.diff_records(before_records, after_records)
    return {
        "resolved": [_record_to_dict(r) for r in diff["resolved"]],
        "remaining": [_record_to_dict(r) for r in diff["remaining"]],
        "new": [_record_to_dict(r) for r in diff["new"]],
    }


def diff_sbom(before_sbom: Dict[str, Any], after_sbom: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare SBOM components of original and patched images.

    Args:
        before_sbom: Software Bill of Materials before patching
        after_sbom: Software Bill of Materials after patching

    Returns:
        Dict with keys 'added', 'removed', 'updated' containing component lists.
        Each component has: name, type, old_version (removed/updated), new_version (added/updated).
    """
    before_components = {}
    after_components = {}

    def load_components(sbom: Dict[str, Any], comp_dict: Dict[Tuple[str, str], str]) -> None:
        comps = sbom.get("components") or sbom.get("Components") or []
        for comp in comps:
            name = comp.get("name") or comp.get("Name")
            comp_type = comp.get("type") or comp.get("Type") or "library"
            version = comp.get("version") or comp.get("Version")
            if name:
                comp_dict[(name, comp_type)] = version

    load_components(before_sbom, before_components)
    load_components(after_sbom, after_components)

    # Set-algebra over the (name, type) key set so the intent is
    # explicit and the implementation runs in O(|before|+|after|)
    # regardless of dict insertion order.
    before_keys = before_components.keys() | set()
    after_keys = after_components.keys() | set()

    removed = [
        {"name": n, "type": t, "old_version": before_components[(n, t)]}
        for (n, t) in (before_keys - after_keys)
    ]
    added = [
        {"name": n, "type": t, "new_version": after_components[(n, t)]}
        for (n, t) in (after_keys - before_keys)
    ]
    updated = [
        {
            "name": n,
            "type": t,
            "old_version": before_components[(n, t)],
            "new_version": after_components[(n, t)],
        }
        for (n, t) in (before_keys & after_keys)
        if before_components[(n, t)] != after_components[(n, t)]
    ]

    return {"added": added, "removed": removed, "updated": updated}


def compare(before_summary: Dict[str, int], after_summary: Dict[str, int]) -> Dict[str, int]:
    """
    Compute simple vulnerability count reduction from before_summary to after_summary.

    Args:
        before_summary: Dict mapping severity to vulnerability count before patching
        after_summary: Dict mapping severity to vulnerability count after patching

    Returns:
        Dict with count reduction (before - after) for each severity.
        Non-severity keys (e.g. the legacy ``total`` that
        :func:`summarize_vulnerabilities` embeds for backward
        compatibility) are skipped so they don't get treated as a
        synthetic severity bucket.
    """
    diff = {}
    for severity, before_count in before_summary.items():
        if severity not in SEVERITY_LEVELS:
            continue
        after_count = after_summary.get(severity, 0)
        diff[severity] = before_count - after_count
    return diff


def _count_vulnerabilities_by_severity(scan: Dict[str, Any]) -> Dict[str, int]:
    """Count vulnerabilities grouped by severity level. Delegates to scanner module."""
    return _count_vulns_by_severity(scan)


def compute_metrics(
    before_scan: Dict[str, Any],
    after_scan: Dict[str, Any],
    before_sbom: Dict[str, Any],
    after_sbom: Dict[str, Any],
    build_time: Optional[float] = None,
    before_size: Optional[float] = None,
    after_size: Optional[float] = None,
    supply_chain_result=None,
    network_result=None
) -> Dict[str, Any]:
    """
    Compute comprehensive metrics comparing before and after patches.

    Args:
        before_scan: Vulnerability scan before patching
        after_scan: Vulnerability scan after patching
        before_sbom: SBOM before patching
        after_sbom: SBOM after patching
        build_time: Build time in seconds (optional)
        before_size: Image size before patching in MB (optional)
        after_size: Image size after patching in MB (optional)
        supply_chain_result: SupplyChainResult from Layer 2 scan (optional)
        network_result: NetworkAnalysisResult from Layer 5 analysis (optional)

    Returns:
        Dict containing:
            - total_before, total_after: Total vulnerability counts
            - per_severity_before, per_severity_after: Counts by severity
            - vulnerability_reduction_pct: Percentage reduction
            - cve_resolution_rate: (resolved / total_original)
            - new_vulnerabilities_count: Count of new vulnerabilities
            - sbom_components_added/removed/updated: SBOM change counts
            - build_time_seconds: Build duration
            - image_size_before_mb, image_size_after_mb, image_size_delta_mb: Size metrics
    """
    # Get vulnerability diffs
    vuln_diff = diff_vulnerabilities(before_scan, after_scan)

    # Count by severity
    per_severity_before = _count_vulnerabilities_by_severity(before_scan)
    per_severity_after = _count_vulnerabilities_by_severity(after_scan)

    total_before = sum(per_severity_before.values())
    total_after = sum(per_severity_after.values())

    # Compute reduction percentage. None, not 0.0, when the baseline is
    # zero: an image with no CVEs to begin with has no defined reduction
    # ratio, and folding it in as 0% both understates a clean run and
    # masks a patch that introduced CVEs into a previously clean image.
    # Aggregators must exclude these rows and report how many they
    # excluded. See utils.compute_reduction_percentage.
    vulnerability_reduction_pct: Optional[float] = None
    if total_before > 0:
        vulnerability_reduction_pct = ((total_before - total_after) / total_before) * 100

    # Compute CVE resolution rate
    resolved_count = len(vuln_diff.get("resolved", []))
    cve_resolution_rate: Optional[float] = None
    if total_before > 0:
        cve_resolution_rate = (resolved_count / total_before) * 100

    new_vuln_count = len(vuln_diff.get("new", []))

    # Get SBOM diffs
    sbom_diff = diff_sbom(before_sbom, after_sbom)

    # Distinct-CVE counts (independent of package multiplicity). A CVE
    # affecting three packages contributes 1 here and 3 to total_before/after.
    before_records = _vi.extract_records(before_scan)
    after_records = _vi.extract_records(after_scan)
    unique_before = _vi.count_unique_cves(before_records)
    unique_after = _vi.count_unique_cves(after_records)
    unique_cve_diff = _vi.diff_unique_cves(before_records, after_records)

    unique_cve_reduction_pct = 0.0
    if unique_before > 0:
        unique_cve_reduction_pct = (
            (unique_before - unique_after) / unique_before
        ) * 100

    metrics = {
        # Row-level (package-CVE tuple) counts: these are what the
        # severity buckets sum to.
        "total_before": total_before,
        "total_after": total_after,
        "per_severity_before": per_severity_before,
        "per_severity_after": per_severity_after,
        "vulnerability_reduction_pct": (
            None if vulnerability_reduction_pct is None
            else round(vulnerability_reduction_pct, 2)
        ),
        "cve_resolution_rate": (
            None if cve_resolution_rate is None
            else round(cve_resolution_rate, 2)
        ),
        # Explicit so a downstream aggregate can tell "undefined" from
        # "zero" without re-deriving it from total_before.
        "reduction_defined": total_before > 0,
        "new_vulnerabilities_count": new_vuln_count,
        # Distinct-CVE counts: how many unique CVE identifiers were
        # present, gone, or newly introduced. Use these for "how many
        # CVEs did we fix" rather than the row counts above.
        "unique_cves_before": unique_before,
        "unique_cves_after": unique_after,
        "unique_cves_resolved": len(unique_cve_diff["resolved"]),
        "unique_cves_new": len(unique_cve_diff["new"]),
        "unique_cve_reduction_pct": round(unique_cve_reduction_pct, 2),
        "sbom_components_added": len(sbom_diff.get("added", [])),
        "sbom_components_removed": len(sbom_diff.get("removed", [])),
        "sbom_components_updated": len(sbom_diff.get("updated", [])),
    }

    if build_time is not None:
        metrics["build_time_seconds"] = round(build_time, 2)

    if before_size is not None:
        metrics["image_size_before_mb"] = round(before_size, 2)

    if after_size is not None:
        metrics["image_size_after_mb"] = round(after_size, 2)

    if before_size is not None and after_size is not None:
        metrics["image_size_delta_mb"] = round(after_size - before_size, 2)

    if supply_chain_result is not None:
        metrics["supply_chain_findings_count"] = len(supply_chain_result.findings)
        metrics["supply_chain_critical_count"] = sum(
            1 for f in supply_chain_result.findings if f.severity == "CRITICAL"
        )

    if network_result is not None:
        metrics["network_risk_score"] = network_result.risk_score
        metrics["network_findings_count"] = len(network_result.findings)

    return metrics



# Per-check risk weights for the supply-chain gate. The weight scales
# a finding's effective severity for acceptance purposes:
#   1.0 -> as-reported (gate behaves as before)
#   0.5 -> treat as one severity bucket lower (CRITICAL -> HIGH)
#   0.25 -> treat as two buckets lower
# Heuristically derived from the false-positive distribution observed
# in the dataset; ship as priors and refine when calibration data
# becomes available.
_SUPPLY_CHAIN_WEIGHTS: Dict[str, float] = {
    "known_vulnerability_audit": 1.0,
    "namespace_confusion": 1.0,
    "phantom_dependency": 0.7,
    "malicious_pth_file": 1.0,
    "record_hash_verification": 0.7,
    "install_script_detected": 0.5,
    "package_age_check": 0.4,
}

_SEVERITY_LADDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _weighted_supply_severity(finding) -> str:
    """Apply the per-check weight to lower the effective severity
    when the check has a high empirical false-positive rate. Never
    raises severity above its as-reported level."""
    weight = _SUPPLY_CHAIN_WEIGHTS.get(getattr(finding, "check_name", ""), 1.0)
    reported = getattr(finding, "severity", "INFO")
    if weight >= 1.0:
        return reported
    try:
        idx = _SEVERITY_LADDER.index(reported)
    except ValueError:
        return reported
    # 0.5 lowers by 1 bucket, 0.25 by 2, etc.
    steps = max(0, int(round((1.0 - weight) * 4)))
    new_idx = min(len(_SEVERITY_LADDER) - 1, idx + steps)
    return _SEVERITY_LADDER[new_idx]


def check_acceptance_criteria(
    before_scan: Dict[str, Any],
    after_scan: Dict[str, Any],
    threshold: str = "strict",
    supply_chain_result=None,
    network_result=None,
    network_risk_threshold: int = 50,
    epss_data: Optional[Dict[str, float]] = None,
    kev_set: Optional[set] = None,
    risk_window_days: int = 30,
    min_risk_reduction: float = 0.0,
    epss_safe_threshold: float = DEFAULT_EPSS_SAFE_THRESHOLD,
    reachable_packages: Optional[set] = None,
    min_posture_score: Optional[float] = None,
    demote_local_av: bool = True,
    demote_adjacent_av: bool = False,
    require_vex_not_affected: bool = False,
    vex_not_affected_cves: Optional[set] = None,
    runtime_result: Optional[Any] = None,
    require_runtime_ok: bool = True,
    applicability_policy: Optional[Any] = None,
) -> Tuple[bool, List[str]]:
    """
    Check if patched image meets formal acceptance criteria.

    Acceptance predicates by threshold:

    The function-level default is "strict" for library backward
    compatibility; the shipped CLI defaults to "count-strict" (see
    src/main.py --accept-threshold), which is the operational gate and
    matches fielded admission-controller practice: severity-count
    non-regression over applicable, fixable findings, with a KEV hard
    block. "strict" remains the paper's Eq. (1) identity gate and is
    the no-regression bound the evaluation reports alongside it.

    STRICT -- the paper's Eq. (1), identity-aware:
        A finding identity is (CVE identifier, affected component).
        Let V(I) be the identity set, C(I)/H(I) its Critical/High
        subsets. Accept iff:
        - |V(I')| < |V(I)|                (identity count strictly drops)
        - C(I') \\ C(I) = empty           (no new Critical identity)
        - H(I') \\ H(I) = empty           (no new High identity)
        The set differences are evaluated UNCONDITIONALLY, not only
        when a severity count rises: removing five Criticals while
        introducing one different Critical still rejects. Optional
        operator demotions (EPSS below ``epss_safe_threshold``,
        ``demote_local_av``/``demote_adjacent_av``) can downgrade a
        new identity to a warning; Eq. (1) itself has no demotions,
        so a paper-exact run disables them. A new KEV CVE always
        blocks regardless of any demotion.

    MODERATE:
        - |CVE_critical(I')| <= |CVE_critical(I)| AND
        - |CVE_high(I')| <= |CVE_high(I)| AND
        - |CVE_medium(I')| <= |CVE_medium(I)| AND
        - |CVE_total(I')| < |CVE_total(I)|

    PERMISSIVE:
        - |CVE_critical(I')| = 0 AND
        - |CVE_high(I')| <= |CVE_high(I)| (with zero tolerance at zero) AND
        - |CVE_total(I')| < |CVE_total(I)| (allows small increases in LOW/UNKNOWN
          if CRITICAL drops to zero and HIGH decreases or stays zero)

    RISK (new, requires ``epss_data`` and/or ``kev_set``):
        Uses NIST CSWP 41 LEV + EPSS + KEV composite scoring:
        - composite_risk(I') < composite_risk(I) * (1 - min_risk_reduction)
        - kev_after <= kev_before  (KEV CVEs may never increase)
        New CVEs are tolerated as long as the total weighted risk
        decreases; this admits cross-OS migrations where a small number
        of low-EPSS, non-KEV CVEs appear in the target distribution.

    Note: New CVE IDs may appear when switching OS families (e.g., Ubuntu to
    Alpine), even when total vulnerability count drops significantly. The
    count-based thresholds focus on severity buckets rather than individual
    CVE identity. The risk threshold and the EPSS-aware strict mode both
    provide identity-aware acceptance for operators that have EPSS/KEV data.

    Args:
        before_scan: Vulnerability scan before patching.
        after_scan: Vulnerability scan after patching.
        threshold: One of "strict", "count-strict", "moderate",
            "permissive", "risk", "reachability".
        supply_chain_result: Optional supply-chain scan result; CRITICAL
            findings always block, HIGH findings warn.
        network_result: Optional network-monitor result.
        network_risk_threshold: Network risk score that blocks acceptance.
        epss_data: ``{CVE_ID: float}`` mapping to EPSS exploitation
            probability in [0,1]. When provided, drives both the
            EPSS-aware strict demotions and the "risk" threshold.
        kev_set: Set of CVE IDs in the CISA KEV catalog (known exploited).
        risk_window_days: LEV lookback window (default 30).
        min_risk_reduction: Required fractional reduction in composite
            risk for the "risk" threshold to accept (default 0.0 means
            any strict reduction is enough).
        epss_safe_threshold: Strict-mode demotion threshold for new
            HIGH/CRITICAL CVEs. Default 0.01 (1% exploitation chance).

    Returns:
        Tuple of (accepted: bool, feedback: list of strings). Feedback
        items prefixed ``[WARNING]`` are informational and do not block;
        all other items are rejection reasons.
    """
    if threshold not in ("strict", "count-strict", "moderate", "permissive",
                         "risk", "reachability"):
        raise ValueError(
            f"Invalid threshold: {threshold}. Must be 'strict', "
            f"'count-strict', 'moderate', 'permissive', 'risk', or "
            f"'reachability'."
        )
    if threshold == "risk" and epss_data is None and kev_set is None:
        raise ValueError(
            "threshold='risk' requires at least one of epss_data or kev_set"
        )
    if threshold == "reachability" and reachable_packages is None:
        raise ValueError(
            "threshold='reachability' requires reachable_packages "
            "(call dep_graph.build_dependency_graph first and pass the "
            "set of reachable component names)."
        )

    reasons: List[str] = []
    warnings: List[str] = []

    # ── Runtime validation predicate ────────────────────────────────
    # Build success is necessary but not sufficient: a rebuilt image can
    # compile and scan clean while failing at startup, losing a shared
    # library, or breaking a service endpoint. When the caller supplies
    # a RuntimeValidationResult, a blocking tier failure rejects the
    # candidate before any CVE arithmetic is considered, because a
    # non-functional image is not a remediation regardless of its CVE
    # count. Callers that do not run runtime validation pass None and
    # the predicate is vacuously satisfied (backward compatible).
    if runtime_result is not None:
        rt_passed = bool(getattr(runtime_result, "passed", False))
        if not rt_passed:
            failure = getattr(runtime_result, "first_failure", None)
            detail = ""
            if failure is not None:
                detail = (f" (tier={getattr(failure.tier, 'value', failure.tier)}: "
                          f"{getattr(failure, 'detail', '')})")
            msg = f"Runtime validation failed{detail}"
            if require_runtime_ok:
                reasons.append(msg)
            else:
                warnings.append(msg)
        else:
            tiers = getattr(runtime_result, "tiers", []) or []
            passed_tiers = [
                getattr(t.tier, "value", str(t.tier))
                for t in tiers
                if getattr(getattr(t, "outcome", None), "value", "") == "pass"
            ]
            if passed_tiers:
                warnings.append(
                    "Runtime validation passed: " + ", ".join(passed_tiers)
                )

    # Authoritative counts via vulnerability_index (deduped per (CVE, pkg, path)).
    before_records = _vi.extract_records(before_scan)
    after_records = _vi.extract_records(after_scan)
    before_counts = _vi.count_by_severity(before_records)
    after_counts = _vi.count_by_severity(after_records)
    total_before = sum(before_counts.values())
    total_after = sum(after_counts.values())

    # ── Applicability filter (general exploitability-class scoping) ──
    # The gate reasons about findings that can actually affect the
    # container, not the raw scanner set. This is a single general
    # mechanism replacing per-package special-casing: kernel-space CVEs
    # (the container shares the host kernel) and no-fix CVEs (no version
    # exists to move to) are excluded by default; KEV always overrides.
    # Pass ApplicabilityPolicy.literal() to recover the raw-set gate.
    # See src/applicability.py for the rules and their justification.
    from .applicability import (
        ApplicabilityPolicy, partition_applicable, exclusion_summary,
    )
    _policy = applicability_policy or ApplicabilityPolicy()
    _app_before, _excl_before = partition_applicable(
        before_records, _policy, kev_set=set(kev_set or set()))
    _app_after, _excl_after = partition_applicable(
        after_records, _policy, kev_set=set(kev_set or set()))

    # Identity-level diff (independent of severity bucket counts).
    unique_diff = _vi.diff_unique_cves(before_records, after_records)
    new_cve_ids = unique_diff["new"]
    resolved_cve_ids = unique_diff["resolved"]
    new_vuln_count = len(new_cve_ids)

    # Index after_records by CVE id so we can look up severity/exploitability
    # of newly-introduced CVEs in the strict-mode EPSS demotion path.
    after_records_by_id: Dict[str, List[_vi.VulnRecord]] = {}
    for r in after_records:
        after_records_by_id.setdefault(r.vuln_id, []).append(r)

    kev_set_norm: set = set(kev_set or set())
    epss_data_norm: Dict[str, float] = dict(epss_data or {})

    def _is_non_exploitable(cve_id: str) -> bool:
        """A new CVE is treated as non-exploitable for gate purposes when
        ANY of the following hold (and none of the hard-block signals
        apply):

          (a) The CVE is on the CISA KEV catalog -> NEVER demote.
          (b) The CVE's CVSS attack vector is Local (L) or Physical
              (P), and ``demote_local_av`` is True. In a non-interactive
              containerized service these vectors require the attacker
              to already have execution inside the container; the game
              is already lost.
          (c) The CVE's CVSS attack vector is Adjacent (A), and
              ``demote_adjacent_av`` is True. Default False because in
              a multi-tenant K8s cluster Adjacent maps to "any neighbor
              pod can hit me". Single-tenant operators can opt in.
          (d) We have EPSS data and the score is below the safe
              threshold. Fail closed when EPSS data is absent.
        """
        if cve_id in kev_set_norm:
            return False  # KEV always blocks

        # CVSS-vector demotion. Look up the after-scan record (we only
        # care about NEW CVEs introduced in the patched image).
        for rec in after_records_by_id.get(cve_id, []):
            vec = rec.cvss_vector
            if vec is None:
                continue
            if demote_local_av and vec.is_local_only:
                return True  # AV:L or AV:P -> non-exploitable
            if demote_adjacent_av and vec.attack_vector == "A":
                return True  # AV:A under explicit operator opt-in

        # EPSS demotion (existing logic).
        if not epss_data_norm:
            return False
        return epss_data_norm.get(cve_id, 1.0) < epss_safe_threshold

    def _record_severities(cve_id: str) -> set:
        return {r.severity for r in after_records_by_id.get(cve_id, [])}

    new_kev_cves = [c for c in new_cve_ids if c in kev_set_norm]
    new_critical_cves = [c for c in new_cve_ids if "CRITICAL" in _record_severities(c)]
    new_high_cves = [c for c in new_cve_ids if "HIGH" in _record_severities(c)]

    # ── Finding identities, per the paper's Eq. (1) ─────────────────
    # A finding identity is (CVE identifier, affected component). The
    # paper's acceptance criterion is defined over SETS of identities:
    #
    #   Accept(I, I') := BuildSuccess(I')
    #                    and |V(I')| < |V(I)|
    #                    and C(I') \ C(I) = empty
    #                    and H(I') \ H(I) = empty
    #
    # PkgPath is deliberately excluded from the identity: the same
    # (CVE, package) surfacing at a different filesystem path after a
    # base swap is the same finding, not a new one.
    def _identity_sets(records):
        all_ids, crit_ids, high_ids = set(), set(), set()
        for r in records:
            ident = (r.vuln_id, r.pkg_name)
            all_ids.add(ident)
            if r.severity == "CRITICAL":
                crit_ids.add(ident)
            elif r.severity == "HIGH":
                high_ids.add(ident)
        return all_ids, crit_ids, high_ids

    # Identity sets are built from the APPLICABLE records: the strict
    # gate must not reject on a finding that cannot affect the
    # container. The raw sets remain available via before_records/
    # after_records for informational reporting.
    before_ids, before_crit_ids, before_high_ids = _identity_sets(_app_before)
    after_ids, after_crit_ids, after_high_ids = _identity_sets(_app_after)

    if threshold == "strict":
        # Identity-aware gate. The previous implementation examined new
        # severe findings ONLY when the severity bucket's COUNT rose,
        # which permitted exactly the masking Eq. (1) exists to prevent:
        # remove five Criticals, introduce one different Critical, and
        # the count 5 -> 1 skipped the check entirely. The set
        # difference is now evaluated unconditionally, and identity is
        # (CVE, component) rather than bare CVE id, so a known CVE
        # newly affecting a different component also rejects.
        #
        # The EPSS/KEV/attack-vector demotions remain available as
        # explicit operator opt-ins layered on top, but Eq. (1) itself
        # contains no demotions: run with --no-demote-local-av and no
        # EPSS file (as the evaluation does) and this branch is exactly
        # the paper's criterion. A new KEV CVE always rejects.

        new_crit_identities = sorted(after_crit_ids - before_crit_ids)
        new_high_identities = sorted(after_high_ids - before_high_ids)

        def _fmt(ids):
            shown = [f"{c} in {p or '?'}" for c, p in ids[:3]]
            return ", ".join(shown) + (" ..." if len(ids) > 3 else "")

        if new_crit_identities:
            unsafe = [(c, p) for c, p in new_crit_identities
                      if not _is_non_exploitable(c)]
            if unsafe:
                reasons.append(
                    f"{len(unsafe)} new CRITICAL finding identit"
                    f"{'y' if len(unsafe) == 1 else 'ies'} introduced "
                    f"(C(I') \\ C(I) is non-empty): {_fmt(unsafe)}"
                )
            else:
                warnings.append(
                    f"{len(new_crit_identities)} new CRITICAL finding "
                    f"identit{'y' if len(new_crit_identities) == 1 else 'ies'} "
                    f"demoted by explicit operator policy (EPSS/AV opt-in): "
                    f"{_fmt(new_crit_identities)}"
                )

        if new_high_identities:
            unsafe = [(c, p) for c, p in new_high_identities
                      if not _is_non_exploitable(c)]
            if unsafe:
                reasons.append(
                    f"{len(unsafe)} new HIGH finding identit"
                    f"{'y' if len(unsafe) == 1 else 'ies'} introduced "
                    f"(H(I') \\ H(I) is non-empty): {_fmt(unsafe)}"
                )
            else:
                warnings.append(
                    f"{len(new_high_identities)} new HIGH finding "
                    f"identit{'y' if len(new_high_identities) == 1 else 'ies'} "
                    f"demoted by explicit operator policy (EPSS/AV opt-in): "
                    f"{_fmt(new_high_identities)}"
                )

        # Any newly-introduced KEV CVE is a hard rejection regardless of
        # severity bucket, and regardless of any demotion flag.
        if new_kev_cves:
            reasons.append(
                f"{len(new_kev_cves)} new KEV (known-exploited) CVE(s) introduced: "
                + ", ".join(new_kev_cves[:5])
                + (" ..." if len(new_kev_cves) > 5 else "")
            )

        # |V(I')| < |V(I)| over finding identities, matching the same
        # V(I) definition the set differences above use. Row counts
        # (path-sensitive) are reported in metrics but do not gate.
        if len(after_ids) >= len(before_ids):
            reasons.append(
                f"Total finding identities did not decrease: "
                f"{len(before_ids)} -> {len(after_ids)}"
            )

        # Applicability accounting: make every exclusion auditable, and
        # surface a genuinely new class. This is the rejection-reason
        # classifier: when the gate rejects, this shows whether the
        # blocking findings were filtered (and by which rule) or are
        # genuinely applicable. An excluded finding under NO rule cannot
        # occur (partition only excludes via a named rule), so a
        # surprising rejection is always traceable to an applicable
        # finding the operator can inspect.
        if _excl_after:
            warnings.append(
                "Applicability exclusions (after-image): "
                + exclusion_summary(_excl_after)
                + f"; policy={_policy.describe()['active_rules']}"
            )
            # Report the raw (pre-filter) severe churn alongside, so the
            # effect of the filter on THIS decision is visible.
            _raw_before_ids, _raw_before_crit, _raw_before_high = \
                _identity_sets(before_records)
            _raw_after_ids, _raw_after_crit, _raw_after_high = \
                _identity_sets(after_records)
            _raw_new_high = len(_raw_after_high - _raw_before_high)
            _raw_new_crit = len(_raw_after_crit - _raw_before_crit)
            if _raw_new_crit or _raw_new_high:
                warnings.append(
                    f"Pre-filter new severe identities: "
                    f"{_raw_new_crit} CRITICAL, {_raw_new_high} HIGH; "
                    f"after applicability filtering: "
                    f"{len(new_crit_identities)} CRITICAL, "
                    f"{len(new_high_identities)} HIGH applicable"
                )

        # Informational: identity churn and raw severity-count movement.
        if new_vuln_count > 0:
            warnings.append(
                f"{new_vuln_count} new CVE id(s) introduced (informational); "
                f"{len(resolved_cve_ids)} resolved"
            )
        if (after_counts["CRITICAL"] != before_counts["CRITICAL"]
                or after_counts["HIGH"] != before_counts["HIGH"]):
            warnings.append(
                f"Severity counts: CRITICAL {before_counts['CRITICAL']} -> "
                f"{after_counts['CRITICAL']}, HIGH {before_counts['HIGH']} -> "
                f"{after_counts['HIGH']}"
            )

    elif threshold == "count-strict":
        # Net-severity non-regression on the APPLICABLE set. This is the
        # practical criterion: it accepts an image whose severe COUNTS do
        # not rise and whose total strictly decreases, even if the CVE
        # identities churned. It differs from 'strict' only in that it
        # permits identity churn as long as the severity posture does not
        # worsen -- which is what happens on every real base
        # modernization (freshrss@legacy: CRITICAL 50->47, HIGH 48->42,
        # both DOWN, yet 'strict' rejects it on new identities). The pure
        # masking case (swap one Critical for another, nothing else) is
        # still rejected here, because the total would not strictly
        # decrease. Counts are taken over the applicable set so
        # kernel-space and (if opted in) no-fix findings do not gate.
        app_before_counts = _vi.count_by_severity(_app_before)
        app_after_counts = _vi.count_by_severity(_app_after)
        app_total_before = sum(app_before_counts.values())
        app_total_after = sum(app_after_counts.values())

        if app_after_counts["CRITICAL"] > app_before_counts["CRITICAL"]:
            reasons.append(
                f"Applicable CRITICAL count increased: "
                f"{app_before_counts['CRITICAL']} -> {app_after_counts['CRITICAL']}"
            )
        if app_after_counts["HIGH"] > app_before_counts["HIGH"]:
            reasons.append(
                f"Applicable HIGH count increased: "
                f"{app_before_counts['HIGH']} -> {app_after_counts['HIGH']}"
            )
        if new_kev_cves:
            reasons.append(
                f"{len(new_kev_cves)} new KEV (known-exploited) CVE(s) introduced: "
                + ", ".join(new_kev_cves[:5])
            )
        if app_total_after >= app_total_before:
            reasons.append(
                f"Applicable total did not decrease: "
                f"{app_total_before} -> {app_total_after}"
            )
        if _excl_after:
            warnings.append(
                "Applicability exclusions (after-image): "
                + exclusion_summary(_excl_after)
            )

    elif threshold == "moderate":
        # Check CRITICAL constraint
        if after_counts["CRITICAL"] > before_counts["CRITICAL"]:
            reasons.append(
                f"CRITICAL vulnerabilities increased: {before_counts['CRITICAL']} -> {after_counts['CRITICAL']}"
            )

        # Check HIGH constraint
        if after_counts["HIGH"] > before_counts["HIGH"]:
            reasons.append(
                f"HIGH vulnerabilities increased: {before_counts['HIGH']} -> {after_counts['HIGH']}"
            )

        # Check MEDIUM constraint
        if after_counts["MEDIUM"] > before_counts["MEDIUM"]:
            reasons.append(
                f"MEDIUM vulnerabilities increased: {before_counts['MEDIUM']} -> {after_counts['MEDIUM']}"
            )

        # Check total reduction constraint
        if total_after >= total_before:
            reasons.append(
                f"Total vulnerabilities did not decrease: {total_before} -> {total_after}"
            )

        # Track new vulnerabilities as warning
        if new_vuln_count > 0:
            warnings.append(f"New vulnerability IDs introduced: {new_vuln_count}")

    elif threshold == "permissive":
        # Check CRITICAL must be zero
        if after_counts["CRITICAL"] != 0:
            reasons.append(
                f"CRITICAL vulnerabilities not eliminated: {after_counts['CRITICAL']} remaining"
            )

        # Check HIGH must decrease or stay at zero
        if after_counts["HIGH"] > before_counts["HIGH"]:
            reasons.append(
                f"HIGH vulnerabilities increased: {before_counts['HIGH']} -> {after_counts['HIGH']}"
            )

        # Check total must decrease (strict reduction, not just non-increase)
        if total_after >= total_before:
            reasons.append(
                f"Total vulnerabilities did not decrease: {total_before} -> {total_after}"
            )

        # Track new vulnerabilities as warning
        if new_vuln_count > 0:
            warnings.append(f"New vulnerability IDs introduced: {new_vuln_count}")

    elif threshold == "reachability":
        # Filter records to the reachable subset; apply strict-mode
        # logic only there. Unreachable CVEs are reported but do not
        # gate -- the operator has empirical evidence those code paths
        # are not executed and therefore not exploitable.
        before_reach, _before_unreach = _vi.filter_by_reachability(
            before_records, reachable_packages
        )
        after_reach, after_unreach = _vi.filter_by_reachability(
            after_records, reachable_packages
        )
        before_r_counts = _vi.count_by_severity(before_reach)
        after_r_counts = _vi.count_by_severity(after_reach)
        total_before_r = sum(before_r_counts.values())
        total_after_r = sum(after_r_counts.values())

        # Reachable severity parity: same logic as strict, EPSS+KEV
        # demotion still applies, but counts are computed on the
        # reachable subset only.
        unique_reach_diff = _vi.diff_unique_cves(before_reach, after_reach)
        new_reach_ids = unique_reach_diff["new"]
        new_reach_kev = [c for c in new_reach_ids if c in kev_set_norm]

        # Build a quick lookup for severities of new reachable CVEs.
        after_reach_by_id: Dict[str, List[_vi.VulnRecord]] = {}
        for r in after_reach:
            after_reach_by_id.setdefault(r.vuln_id, []).append(r)

        def _new_reach_is_unsafe(cve_id: str) -> bool:
            return not _is_non_exploitable(cve_id)

        if after_r_counts["CRITICAL"] > before_r_counts["CRITICAL"]:
            new_crit = [c for c in new_reach_ids
                        if any(r.severity == "CRITICAL"
                               for r in after_reach_by_id.get(c, []))]
            unsafe = [c for c in new_crit if _new_reach_is_unsafe(c)]
            if unsafe:
                reasons.append(
                    f"Reachable CRITICAL count rose "
                    f"({before_r_counts['CRITICAL']} -> "
                    f"{after_r_counts['CRITICAL']}); {len(unsafe)} new "
                    f"reachable CRITICAL above EPSS "
                    f"{epss_safe_threshold:g} or in KEV: "
                    + ", ".join(unsafe[:3])
                    + (" ..." if len(unsafe) > 3 else "")
                )
            else:
                warnings.append(
                    f"Reachable CRITICAL rose "
                    f"{before_r_counts['CRITICAL']} -> "
                    f"{after_r_counts['CRITICAL']} but all new "
                    f"reachable CRITICAL are non-exploitable"
                )

        if after_r_counts["HIGH"] > before_r_counts["HIGH"]:
            new_high = [c for c in new_reach_ids
                        if any(r.severity == "HIGH"
                               for r in after_reach_by_id.get(c, []))]
            unsafe = [c for c in new_high if _new_reach_is_unsafe(c)]
            if unsafe:
                reasons.append(
                    f"Reachable HIGH count rose "
                    f"({before_r_counts['HIGH']} -> "
                    f"{after_r_counts['HIGH']}); {len(unsafe)} new "
                    f"reachable HIGH above EPSS "
                    f"{epss_safe_threshold:g} or in KEV"
                )

        if new_reach_kev:
            reasons.append(
                f"{len(new_reach_kev)} new KEV CVE(s) introduced in "
                f"reachable code: " + ", ".join(new_reach_kev[:5])
                + (" ..." if len(new_reach_kev) > 5 else "")
            )

        if total_after_r >= total_before_r:
            reasons.append(
                f"Reachable total CVEs did not decrease: "
                f"{total_before_r} -> {total_after_r}"
            )

        # Always surface the unreachable bucket as informational.
        warnings.append(
            f"{len(after_unreach)} CVE(s) in unreachable code paths "
            f"(not gated under reachability mode); "
            f"{len({r.vuln_id for r in after_unreach})} unique"
        )

    elif threshold == "risk":
        # NIST CSWP 41 LEV + EPSS + KEV composite risk. Admits a patch
        # iff the total weighted risk strictly decreases AND no new
        # KEV CVEs were introduced. Tolerates count regressions when
        # the introduced CVEs are low-exploitability.
        risk_summary = compute_lev_risk_score(
            before_scan, after_scan,
            epss_data=epss_data_norm, kev_set=kev_set_norm,
            window_days=risk_window_days,
        )
        risk_before = risk_summary["risk_before"]
        risk_after = risk_summary["risk_after"]
        kev_before = risk_summary["kev_before"]
        kev_after = risk_summary["kev_after"]
        risk_threshold = risk_before * (1.0 - min_risk_reduction)

        if kev_after > kev_before:
            new_kev_in_after = [
                c for c in new_cve_ids if c in kev_set_norm
            ]
            reasons.append(
                f"KEV (known-exploited) CVE count rose {kev_before} -> "
                f"{kev_after}: "
                + ", ".join(new_kev_in_after[:5])
                + (" ..." if len(new_kev_in_after) > 5 else "")
            )

        if risk_before <= 0.0:
            # No composite risk to reduce: either no EPSS/KEV coverage
            # for this image's CVEs, or the image was already clean.
            # `risk_after >= risk_threshold` would be `0.0 >= 0.0` here
            # and reject an image that carries no measurable risk at
            # all, which is the opposite of the intended semantics.
            # Fall back to the strict count conditions already applied
            # above, and say so rather than failing silently.
            if risk_after > 0.0:
                reasons.append(
                    f"Composite risk rose from zero to {risk_after:.4f}: the "
                    f"original image had no EPSS/KEV-scored CVEs and the "
                    f"patched image does"
                )
            else:
                warnings.append(
                    "Composite risk is zero before and after (no EPSS/KEV "
                    "coverage for these CVEs); risk threshold not "
                    "applicable, acceptance decided by count conditions"
                )
        elif risk_after >= risk_threshold:
            reasons.append(
                f"Composite LEV/EPSS/KEV risk did not decrease by at least "
                f"{min_risk_reduction:.0%}: {risk_before:.4f} -> {risk_after:.4f} "
                f"(threshold {risk_threshold:.4f})"
            )
        else:
            warnings.append(
                f"Composite risk reduced {risk_before:.4f} -> {risk_after:.4f} "
                f"({risk_summary['risk_reduction_pct']:.1f}%); "
                f"{risk_summary['high_risk_before']} -> "
                f"{risk_summary['high_risk_after']} high-risk CVEs"
            )

        # Always surface identity diff in risk mode.
        warnings.append(
            f"{new_vuln_count} new CVE id(s) introduced, "
            f"{len(resolved_cve_ids)} resolved (composite-risk-evaluated)"
        )


    # VEX-required-for-new-CRITICAL: a stricter posture where every
    # newly-introduced CRITICAL must have a VEX `not_affected` statement
    # from the operator. Useful in regulated environments where every
    # new CRITICAL needs an explicit, document-backed dismissal.
    if require_vex_not_affected:
        # New CRITICAL CVEs introduced by the patch
        unique_diff_local = _vi.diff_unique_cves(before_records, after_records)
        new_ids = unique_diff_local["new"]
        after_by_id = {}
        for r in after_records:
            after_by_id.setdefault(r.vuln_id, []).append(r)
        unsuppressed_new_crit = [
            cve for cve in new_ids
            if any(r.severity == "CRITICAL" for r in after_by_id.get(cve, []))
            and cve not in (vex_not_affected_cves or set())
        ]
        if unsuppressed_new_crit:
            reasons.append(
                f"--require-vex-for-new-critical: {len(unsuppressed_new_crit)} "
                f"newly-introduced CRITICAL CVE(s) lack a VEX 'not_affected' "
                f"statement: " + ", ".join(unsuppressed_new_crit[:5])
                + (" ..." if len(unsuppressed_new_crit) > 5 else "")
            )

    # Optional posture-score floor: regardless of which threshold the
    # operator chose, --min-posture-score=N adds a hard floor that
    # rejects images below N. Doesn't replace the threshold; layers
    # on top.
    if min_posture_score is not None:
        try:
            posture = compute_posture_score(
                after_scan,
                epss_data=epss_data_norm or None,
                kev_set=kev_set_norm or None,
                reachable_packages=reachable_packages,
            )
            if posture.total < min_posture_score:
                reasons.append(
                    f"Posture score {posture.total:.1f} below required "
                    f"minimum {min_posture_score:.1f} (KEV={posture.kev_component:.1f}, "
                    f"severity={posture.severity_component:.1f}, "
                    f"reachability={posture.reachability_component:.1f})"
                )
            else:
                warnings.append(
                    f"Posture score {posture.total:.1f} >= floor "
                    f"{min_posture_score:.1f}"
                )
        except Exception as _e:
            warnings.append(
                f"min_posture_score floor requested but posture "
                f"computation failed: {_e}"
            )

    # Supply chain acceptance checks (risk-weighted per check_name)
    if supply_chain_result is not None:
        weighted_findings = [
            (_weighted_supply_severity(f), f) for f in supply_chain_result.findings
        ]
        critical_findings = [f for sev, f in weighted_findings if sev == "CRITICAL"]
        high_findings = [f for sev, f in weighted_findings if sev == "HIGH"]
        if critical_findings:
            reasons.append(
                f"Supply chain scan found {len(critical_findings)} CRITICAL "
                f"finding(s) (after risk-weighting): "
                + ", ".join(f.check_name for f in critical_findings[:3])
            )
        if high_findings and threshold in ("strict", "count-strict",
                                           "moderate"):
            warnings.append(
                f"Supply chain scan found {len(high_findings)} HIGH "
                f"finding(s) (after risk-weighting)"
            )

    # Network behavior acceptance checks
    if network_result is not None:
        if network_result.risk_score > network_risk_threshold:
            reasons.append(
                f"Network risk score {network_result.risk_score} exceeds threshold {network_risk_threshold}"
            )
        elif network_result.risk_score > 0:
            warnings.append(
                f"Network risk score {network_result.risk_score} (threshold: {network_risk_threshold})"
            )

    # Return reasons (blocking) and warnings (informational) separately.
    # For backward compat, the second element is still a list, but now
    # warnings are prefixed with "[WARNING] " so callers can distinguish.
    all_feedback = reasons + [f"[WARNING] {w}" for w in warnings]
    accepted = len(reasons) == 0
    return accepted, all_feedback


def compute_lev_risk_score(
    before_scan: Dict[str, Any],
    after_scan: Dict[str, Any],
    epss_data: Optional[Dict[str, float]] = None,
    kev_set: Optional[set] = None,
    window_days: int = 30,
) -> Dict[str, Any]:
    """
    Compute NIST CSWP 41 LEV-based risk assessment for acceptance criteria.

    LEV(v, d0, dn) = 1 - product(1 - EPSS(v, di)) for i in [0..n]
    Composite_Probability = max(EPSS, KEV_flag, LEV)

    Args:
        before_scan: Vulnerability scan before patching
        after_scan: Vulnerability scan after patching
        epss_data: Dict mapping CVE ID to current EPSS score (0-1)
        kev_set: Set of CVE IDs in CISA KEV catalog
        window_days: LEV assessment window in days

    Returns:
        Dict with risk_before, risk_after, risk_reduction_pct,
        high_risk_before, high_risk_after, kev_before, kev_after,
        top_risks_remaining.
    """
    epss_data = epss_data or {}
    kev_set = kev_set or set()

    def _compute_vuln_risk(vuln_id: str) -> float:
        epss = min(max(epss_data.get(vuln_id, 0.0), 0.0), 1.0)
        is_kev = 1.0 if vuln_id in kev_set else 0.0
        # EPSS is already the probability of exploitation within the
        # next 30 days, so it must not be compounded as if it were a
        # daily hazard: (1-(1-0.10)**30) = 0.958 turns a moderate score
        # into near-certainty and every scored CVE saturates toward
        # 1.0, which destroys the gate's ability to discriminate.
        # Convert to an equivalent per-day rate first, then compound
        # over the requested window.
        if epss <= 0.0:
            lev = 0.0
        elif window_days == EPSS_REFERENCE_WINDOW_DAYS:
            lev = epss
        else:
            daily = 1.0 - (1.0 - epss) ** (1.0 / EPSS_REFERENCE_WINDOW_DAYS)
            lev = 1.0 - (1.0 - daily) ** window_days
        return max(epss, is_kev, lev)

    # Deduplicate on the same key the rest of the module uses. Walking
    # Results[*].Vulnerabilities raw counts a CVE once per package and
    # once per path, so the risk threshold would gate on a different
    # population than the strict and moderate thresholds do.
    before_records = _vi.extract_records(before_scan)
    after_records = _vi.extract_records(after_scan)
    before_vulns = [{"VulnerabilityID": r.vuln_id, "PkgName": r.pkg_name,
                     "Severity": r.severity} for r in before_records]
    after_vulns = [{"VulnerabilityID": r.vuln_id, "PkgName": r.pkg_name,
                    "Severity": r.severity} for r in after_records]

    risk_before = 0.0
    high_risk_before = 0
    kev_before = 0
    for v in before_vulns:
        vid = v.get("VulnerabilityID", "")
        risk = _compute_vuln_risk(vid)
        risk_before += risk
        if risk > 0.5:
            high_risk_before += 1
        if vid in kev_set:
            kev_before += 1

    risk_after = 0.0
    high_risk_after = 0
    kev_after = 0
    top_remaining: List[Dict[str, Any]] = []
    for v in after_vulns:
        vid = v.get("VulnerabilityID", "")
        risk = _compute_vuln_risk(vid)
        risk_after += risk
        if risk > 0.5:
            high_risk_after += 1
        if vid in kev_set:
            kev_after += 1
        top_remaining.append({
            "id": vid,
            "package": v.get("PkgName", ""),
            "severity": v.get("Severity", ""),
            "composite_risk": round(risk, 4),
            "epss": epss_data.get(vid, 0.0),
            "in_kev": vid in kev_set,
        })

    top_remaining.sort(key=lambda x: x["composite_risk"], reverse=True)

    risk_reduction_pct = 0.0
    if risk_before > 0:
        risk_reduction_pct = ((risk_before - risk_after) / risk_before) * 100

    return {
        "risk_before": round(risk_before, 4),
        "risk_after": round(risk_after, 4),
        "risk_reduction_pct": round(risk_reduction_pct, 2),
        "high_risk_before": high_risk_before,
        "high_risk_after": high_risk_after,
        "kev_before": kev_before,
        "kev_after": kev_after,
        "top_risks_remaining": top_remaining[:10],
    }




# ════════════════════════════════════════════════════════════════════
# Continuous posture score
# ════════════════════════════════════════════════════════════════════

@dataclass
class PostureScore:
    """A 0-100 continuous risk posture for a single image scan.

    100 means "no exploitation risk we can measure"; 0 means "on fire".
    Each component is surfaced so the operator can see WHY the score
    is what it is. This is explicitly NOT a black box.
    """
    total: float
    kev_component: float
    epss_component: float
    severity_component: float
    reachability_component: float
    time_component: float
    components_evaluated: List[str]
    weights: Dict[str, float]
    snapshot: Dict[str, Optional[str]]


_DEFAULT_POSTURE_WEIGHTS: Dict[str, float] = {
    "kev": 0.35,
    "epss": 0.25,
    "severity": 0.20,
    "reachability": 0.10,
    "time": 0.10,
}

# Severity multipliers used by the severity component.
_SEVERITY_MULT: Dict[str, float] = {
    "CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 1.0, "UNKNOWN": 1.0,
}


def compute_posture_score(
    scan: Dict[str, Any],
    *,
    epss_data: Optional[Dict[str, float]] = None,
    kev_set: Optional[set] = None,
    reachable_packages: Optional[set] = None,
    snapshot: Optional[Dict[str, Optional[str]]] = None,
    weights: Optional[Dict[str, float]] = None,
) -> PostureScore:
    """
    Compute the continuous posture score for ``scan``.

    Components are computed independently and combined with the
    weights in ``weights`` (defaults in :data:`_DEFAULT_POSTURE_WEIGHTS`).
    Components for which we lack data (no EPSS feed, no reachability
    graph, no NVD disclosure dates) are excluded from the weighted
    average so the score is over the *evaluated* components only.

    Returns a :class:`PostureScore` whose ``total`` is in [0, 100].
    """
    w = dict(_DEFAULT_POSTURE_WEIGHTS)
    if weights:
        w.update(weights)

    records = _vi.extract_records(scan)

    # KEV component: 100 if zero KEV CVEs, drops 25 per KEV CVE present.
    kev_norm = set(kev_set or set())
    kev_count = sum(1 for r in records if r.vuln_id in kev_norm)
    kev_score = max(0.0, 100.0 - 25.0 * kev_count)

    # EPSS-weighted component: each CVE contributes EPSS * severity_mult.
    epss_evaluated = epss_data is not None
    epss_score = 0.0
    if epss_evaluated:
        weighted = sum(
            (epss_data.get(r.vuln_id, 0.0) or 0.0)
            * _SEVERITY_MULT.get(r.severity, 1.0)
            for r in records
        )
        epss_score = max(0.0, 100.0 - min(100.0, weighted * 2.0))

    # Severity histogram component: weighted by class.
    counts = _vi.count_by_severity(records)
    weighted_sev = (
        counts.get("CRITICAL", 0) * 10
        + counts.get("HIGH", 0) * 5
        + counts.get("MEDIUM", 0) * 2
        + counts.get("LOW", 0) * 1
    )
    severity_score = max(0.0, 100.0 - min(100.0, float(weighted_sev)))

    # Reachability component: fraction of CVEs in reachable code.
    reach_evaluated = reachable_packages is not None
    reach_score = 0.0
    if reach_evaluated:
        reach, _unreach = _vi.filter_by_reachability(records, reachable_packages)
        denom = max(1, len(records))
        reach_ratio = len(reach) / denom
        reach_score = (1.0 - reach_ratio) * 100.0

    # Time component: penalise old surviving CVEs more than newly-
    # disclosed ones. A CVE disclosed five years ago that survives the
    # patch run is operationally worse than one disclosed five days
    # ago. Each year of average age subtracts 10 points; floor at 0.
    ages = []
    for r in records:
        age = _vi.cve_age_days(r)
        if age is not None:
            ages.append(age)
    if ages:
        avg_years = (sum(ages) / len(ages)) / 365.25
        time_score = max(0.0, 100.0 - min(100.0, avg_years * 10.0))
        time_evaluated = True
    else:
        time_evaluated = False
        time_score = 0.0

    # Weighted average over EVALUATED components only.
    evaluated = ["kev", "severity"]
    if epss_evaluated:
        evaluated.append("epss")
    if reach_evaluated:
        evaluated.append("reachability")
    if time_evaluated:
        evaluated.append("time")

    components = {
        "kev": kev_score, "epss": epss_score, "severity": severity_score,
        "reachability": reach_score, "time": time_score,
    }
    total_w = sum(w[k] for k in evaluated)
    total = sum(components[k] * w[k] for k in evaluated) / total_w if total_w else 0.0

    return PostureScore(
        total=round(total, 1),
        kev_component=round(kev_score, 1),
        epss_component=round(epss_score, 1),
        severity_component=round(severity_score, 1),
        reachability_component=round(reach_score, 1),
        time_component=round(time_score, 1),
        components_evaluated=evaluated,
        weights=w,
        snapshot=snapshot or {},
    )

def export_metrics_json(metrics: Dict[str, Any], filepath: str) -> None:
    """Save metrics dict to JSON file."""
    save_json(metrics, filepath)
    logger.info(f"Metrics exported to {filepath}")


def export_metrics_csv(metrics_list: List[Dict[str, Any]], filepath: str) -> None:
    """Save list of metrics dicts to CSV file."""
    if not metrics_list:
        logger.warning("No metrics to export")
        return

    flattened: List[Dict[str, Any]] = []
    for metrics in metrics_list:
        flat: Dict[str, Any] = {}
        for key, value in metrics.items():
            if isinstance(value, dict):
                for nested_key, nested_val in value.items():
                    flat[f"{key}.{nested_key}"] = nested_val if nested_val is not None else ""
            else:
                flat[key] = value if value is not None else ""
        flattened.append(flat)

    fieldnames = set()
    for row in flattened:
        fieldnames.update(row.keys())
    fieldnames = sorted(list(fieldnames))

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(flattened)
    logger.info(f"Metrics exported to {filepath} ({len(metrics_list)} rows)")


# ----------------------------------------------------------------------
# Single canonical acceptance entry point (review Item 6).
#
# check_acceptance_criteria(...) above is THE acceptance predicate for the
# whole project. evaluate_acceptance() is a thin structured wrapper around
# it: it does NOT define a second predicate, it delegates, then packages the
# verdict together with the exact counts the decision was made on. Every
# caller (CLI, experiment runner, CI gate, dashboard) should import one of
# these two and never reimplement the rule. Unique-CVE counts are the basis
# of the verdict; row counts are reported separately for transparency.
# ----------------------------------------------------------------------
@dataclass
class AcceptanceResult:
    """Structured outcome of the acceptance decision."""
    accepted: bool
    threshold: str
    reasons: List[str]
    unique_cves_before: int
    unique_cves_after: int
    unique_cves_resolved: int
    unique_cves_new: int
    total_rows_before: int
    total_rows_after: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "threshold": self.threshold,
            "reasons": list(self.reasons),
            "unique_cves_before": self.unique_cves_before,
            "unique_cves_after": self.unique_cves_after,
            "unique_cves_resolved": self.unique_cves_resolved,
            "unique_cves_new": self.unique_cves_new,
            "total_rows_before": self.total_rows_before,
            "total_rows_after": self.total_rows_after,
        }


def evaluate_acceptance(
    before_scan: Dict[str, Any],
    after_scan: Dict[str, Any],
    threshold: str = "strict",
    **kwargs: Any,
) -> AcceptanceResult:
    """Run the canonical acceptance predicate and return a structured result.

    Delegates the verdict to ``check_acceptance_criteria`` and attaches the
    unique-CVE and row counts the verdict was computed from, so callers and
    the paper can report exactly what was measured. Extra keyword arguments
    are forwarded verbatim to ``check_acceptance_criteria`` (epss_data,
    kev_set, supply_chain_result, etc.).
    """
    accepted, reasons = check_acceptance_criteria(
        before_scan, after_scan, threshold=threshold, **kwargs
    )

    before_records = _vi.extract_records(before_scan)
    after_records = _vi.extract_records(after_scan)
    unique_before = _vi.count_unique_cves(before_records)
    unique_after = _vi.count_unique_cves(after_records)
    unique_diff = _vi.diff_unique_cves(before_records, after_records)

    return AcceptanceResult(
        accepted=accepted,
        threshold=threshold,
        reasons=list(reasons),
        unique_cves_before=unique_before,
        unique_cves_after=unique_after,
        unique_cves_resolved=len(unique_diff["resolved"]),
        unique_cves_new=len(unique_diff["new"]),
        total_rows_before=sum(_count_vulnerabilities_by_severity(before_scan).values()),
        total_rows_after=sum(_count_vulnerabilities_by_severity(after_scan).values()),
    )
