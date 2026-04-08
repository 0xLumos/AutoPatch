import logging
import json
import csv
from typing import Dict, List, Tuple, Optional, Any
from .scanner import _count_vulnerabilities_by_severity as _count_vulns_by_severity
from .utils import save_json

logger = logging.getLogger("docker_patch_tool")

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def diff_vulnerabilities(before_scan: Dict[str, Any], after_scan: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare vulnerabilities between before and after scans.

    Args:
        before_scan: Vulnerability scan result before patching
        after_scan: Vulnerability scan result after patching

    Returns:
        Dict with keys 'resolved', 'remaining', 'new' containing vulnerability lists.
        Each vulnerability has: id, package, severity, version, fix_version.
    """
    def extract_vulns(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for result in scan.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": v.get("VulnerabilityID"),
                    "package": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "severity": v.get("Severity"),
                    "fix_version": v.get("FixedVersion", "")
                })
        return vulns

    before_list = extract_vulns(before_scan)
    after_list = extract_vulns(after_scan)
    before_keys = {(v['id'], v['package']) for v in before_list}
    after_keys = {(v['id'], v['package']) for v in after_list}
    resolved = [v for v in before_list if (v['id'], v['package']) not in after_keys]
    remaining = [v for v in after_list if (v['id'], v['package']) in before_keys]
    new = [v for v in after_list if (v['id'], v['package']) not in before_keys]
    return {"resolved": resolved, "remaining": remaining, "new": new}


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

    added = []
    removed = []
    updated = []

    for (name, comp_type), old_ver in before_components.items():
        if (name, comp_type) not in after_components:
            removed.append({"name": name, "type": comp_type, "old_version": old_ver})
        else:
            new_ver = after_components[(name, comp_type)]
            if old_ver != new_ver:
                updated.append({"name": name, "type": comp_type, "old_version": old_ver, "new_version": new_ver})

    for (name, comp_type), new_ver in after_components.items():
        if (name, comp_type) not in before_components:
            added.append({"name": name, "type": comp_type, "new_version": new_ver})

    return {"added": added, "removed": removed, "updated": updated}


def compare(before_summary: Dict[str, int], after_summary: Dict[str, int]) -> Dict[str, int]:
    """
    Compute simple vulnerability count reduction from before_summary to after_summary.

    Args:
        before_summary: Dict mapping severity to vulnerability count before patching
        after_summary: Dict mapping severity to vulnerability count after patching

    Returns:
        Dict with count reduction (before - after) for each severity.
    """
    diff = {}
    for severity, before_count in before_summary.items():
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

    # Compute reduction percentage
    vulnerability_reduction_pct = 0.0
    if total_before > 0:
        vulnerability_reduction_pct = ((total_before - total_after) / total_before) * 100

    # Compute CVE resolution rate
    resolved_count = len(vuln_diff.get("resolved", []))
    cve_resolution_rate = 0.0
    if total_before > 0:
        cve_resolution_rate = (resolved_count / total_before) * 100

    new_vuln_count = len(vuln_diff.get("new", []))

    # Get SBOM diffs
    sbom_diff = diff_sbom(before_sbom, after_sbom)

    metrics = {
        "total_before": total_before,
        "total_after": total_after,
        "per_severity_before": per_severity_before,
        "per_severity_after": per_severity_after,
        "vulnerability_reduction_pct": round(vulnerability_reduction_pct, 2),
        "cve_resolution_rate": round(cve_resolution_rate, 2),
        "new_vulnerabilities_count": new_vuln_count,
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


def check_acceptance_criteria(
    before_scan: Dict[str, Any],
    after_scan: Dict[str, Any],
    threshold: str = "strict",
    supply_chain_result=None,
    network_result=None,
    network_risk_threshold: int = 50
) -> Tuple[bool, List[str]]:
    """
    Check if patched image meets formal acceptance criteria.

    Acceptance predicates by threshold:

    STRICT (default):
        - |CVE_critical(I')| <= |CVE_critical(I)| AND
        - |CVE_high(I')| <= |CVE_high(I)| AND
        - |CVE_total(I')| < |CVE_total(I)|

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

    Note: New CVE IDs may appear when switching OS families (e.g., Ubuntu to
    Alpine), even when total vulnerability count drops significantly. The
    acceptance criteria therefore focus on severity-level counts rather than
    individual CVE identity, which is the scientifically sound approach for
    cross-OS remediation.

    Args:
        before_scan: Vulnerability scan before patching
        after_scan: Vulnerability scan after patching
        threshold: Acceptance strictness level: "strict", "moderate", or "permissive"

    Returns:
        Tuple of (accepted: bool, reasons: list of rejection reasons if any)
    """
    if threshold not in ("strict", "moderate", "permissive"):
        raise ValueError(f"Invalid threshold: {threshold}. Must be 'strict', 'moderate', or 'permissive'.")

    reasons = []
    warnings = []

    # Count by severity
    before_counts = _count_vulnerabilities_by_severity(before_scan)
    after_counts = _count_vulnerabilities_by_severity(after_scan)
    total_before = sum(before_counts.values())
    total_after = sum(after_counts.values())

    # Get new vulnerability IDs (always track, but only reject on strict/moderate)
    vuln_diff = diff_vulnerabilities(before_scan, after_scan)
    new_vuln_count = len(vuln_diff.get("new", []))

    if threshold == "strict":
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

        # Check total reduction constraint
        if total_after >= total_before:
            reasons.append(
                f"Total vulnerabilities did not decrease: {total_before} -> {total_after}"
            )

        # Track new vulnerabilities as warning
        if new_vuln_count > 0:
            warnings.append(f"New vulnerability IDs introduced: {new_vuln_count}")

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

    # Supply chain acceptance checks
    if supply_chain_result is not None:
        critical_findings = [f for f in supply_chain_result.findings if f.severity == "CRITICAL"]
        high_findings = [f for f in supply_chain_result.findings if f.severity == "HIGH"]
        if critical_findings:
            reasons.append(
                f"Supply chain scan found {len(critical_findings)} CRITICAL finding(s): "
                + ", ".join(f.check_name for f in critical_findings[:3])
            )
        if high_findings and threshold in ("strict", "moderate"):
            warnings.append(
                f"Supply chain scan found {len(high_findings)} HIGH finding(s)"
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

    This implements the LEV (Likely Exploited Vulnerability) equation:
        LEV(v, d0, dn) = 1 - product(1 - EPSS(v, di)) for i in [0..n]

    And the composite probability:
        Composite_Probability = max(EPSS, KEV_flag, LEV)

    The risk score considers not just the count of vulnerabilities but
    their actual exploitation probability, preventing situations where
    a patch removes 50 low-risk CVEs but introduces 1 actively-exploited one.

    Args:
        before_scan: Vulnerability scan before patching
        after_scan: Vulnerability scan after patching
        epss_data: Dict mapping CVE ID to current EPSS score (0-1)
        kev_set: Set of CVE IDs in CISA KEV catalog
        window_days: LEV assessment window in days

    Returns:
        Dict with:
            - risk_before: Total composite risk score before patching
            - risk_after: Total composite risk score after patching
            - risk_reduction_pct: Percentage risk reduction
            - high_risk_before: Count of vulns with composite > 0.5
            - high_risk_after: Count of vulns with composite > 0.5
            - kev_before: Count of KEV vulns before
            - kev_after: Count of KEV vulns after
            - top_risks_remaining: Top 10 highest-risk remaining vulns
    """
    epss_data = epss_data or {}
    kev_set = kev_set or set()

    def _compute_vuln_risk(vuln_id: str) -> float:
        """Compute composite risk for a single vulnerability."""
        epss = epss_data.get(vuln_id, 0.0)
        is_kev = 1.0 if vuln_id in kev_set else 0.0

        # LEV from single EPSS snapshot replicated over window
        lev = 1.0 - ((1.0 - min(epss, 1.0)) ** window_days)

        return max(epss, is_kev, lev)

    def _extract_vulns(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for result in scan.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append(v)
        return vulns

    before_vulns = _extract_vulns(before_scan)
    after_vulns = _extract_vulns(after_scan)

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
    top_remaining = []
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

    # Sort remaining by risk descending
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


def export_metrics_json(metrics: Dict[str, Any], filepath: str) -> None:
    """
    Save metrics dict to JSON file.

    Args:
        metrics: Metrics dictionary from compute_metrics()
        filepath: Output JSON file path
    """
    save_json(metrics, filepath)
    logger.info(f"Metrics exported to {filepath}")


def export_metrics_csv(metrics_list: List[Dict[str, Any]], filepath: str) -> None:
    """
    Save list of metrics dicts to CSV file.

    Args:
        metrics_list: List of metrics dictionaries
        filepath: Output CSV file path
    """
    if not metrics_list:
        logger.warning("No metrics to export")
        return

    # Flatten nested dicts for CSV
    flattened = []
    for metrics in metrics_list:
        flat = {}
        for key, value in metrics.items():
            if isinstance(value, dict):
                # Flatten nested dict with dot notation
                for nested_key, nested_val in value.items():
                    flat[f"{key}.{nested_key}"] = nested_val if nested_val is not None else ""
            else:
                flat[key] = value if value is not None else ""
        flattened.append(flat)

    fieldnames = set()
    for row in flattened:
        fieldnames.update(row.keys())
    fieldnames = sorted(list(fieldnames))

    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flattened)

    logger.info(f"Metrics exported to {filepath}")
