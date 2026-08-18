"""
Dual-Scanner Fusion Engine

Merges vulnerability findings from Trivy and Grype into a unified,
higher-confidence result set. Each vulnerability is classified as:

- CONFIRMED: Found by both scanners (high confidence)
- CONTESTED: Found by only one scanner (needs review)
- EXCLUSIVE_TRIVY / EXCLUSIVE_GRYPE: Scanner-specific finding

The fusion engine also computes composite risk scores using:
- EPSS (Exploit Prediction Scoring System): probability of exploitation
- KEV (CISA Known Exploited Vulnerabilities): boolean exploit-in-wild flag
- CVSS: severity score from NVD
- NIST CSWP 41 LEV: Likely Exploited Vulnerabilities metric

Composite Priority Formula:
    priority = max(EPSS, KEV_flag, LEV) * severity_weight

This prevents noisy low-risk CVEs from dominating remediation decisions
while ensuring actively exploited vulnerabilities are always prioritized.
"""

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("docker_patch_tool")


# Severity weights for composite scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "UNKNOWN": 0.1,
}


@dataclass
class FusedVulnerability:
    """A vulnerability finding with cross-scanner validation status."""
    vuln_id: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str
    description: str = ""

    # Fusion metadata
    found_by_trivy: bool = False
    found_by_grype: bool = False
    classification: str = "UNKNOWN"  # CONFIRMED, CONTESTED, EXCLUSIVE_*

    # Risk scoring
    epss_score: Optional[float] = None
    kev_flag: bool = False
    cvss_score: Optional[float] = None
    lev_score: Optional[float] = None
    composite_priority: float = 0.0

    # Fix metadata
    fix_state: str = "unknown"  # "fixed", "not-fixed", "wont-fix"
    data_sources: List[str] = field(default_factory=list)


@dataclass
class FusionResult:
    """Complete result of merging two scanner outputs."""
    confirmed: List[FusedVulnerability] = field(default_factory=list)
    contested: List[FusedVulnerability] = field(default_factory=list)
    exclusive_trivy: List[FusedVulnerability] = field(default_factory=list)
    exclusive_grype: List[FusedVulnerability] = field(default_factory=list)

    # Summary statistics
    total_unique_cves: int = 0
    confirmed_count: int = 0
    contested_count: int = 0

    # Per-severity counts (across all findings)
    severity_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def all_findings(self) -> List[FusedVulnerability]:
        """All findings, regardless of classification."""
        return self.confirmed + self.contested + self.exclusive_trivy + self.exclusive_grype


def compute_lev(
    epss_scores: List[float],
    window_days: int = 30,
) -> float:
    """
    Compute NIST CSWP 41 LEV (Likely Exploited Vulnerability) metric.

    LEV(v, d0, dn) = 1 - product(1 - EPSS(v, di)) for i in [0..n]

    This represents the cumulative probability that a vulnerability
    will be exploited over a time window, given daily EPSS scores.

    Args:
        epss_scores: List of daily EPSS scores for the vulnerability.
                     If only one score available, it is replicated for window_days.
        window_days: Number of days in the assessment window (default: 30).

    Returns:
        LEV probability (0.0 to 1.0).
    """
    if not epss_scores:
        return 0.0

    # If we only have a single EPSS snapshot, replicate it
    if len(epss_scores) == 1:
        epss_scores = epss_scores * window_days

    # Truncate or pad to window_days
    scores = epss_scores[:window_days]
    if len(scores) < window_days:
        # Pad with the last known score
        scores.extend([scores[-1]] * (window_days - len(scores)))

    # LEV = 1 - product(1 - EPSS_i)
    product = 1.0
    for score in scores:
        product *= (1.0 - min(max(score, 0.0), 1.0))

    return 1.0 - product


def compute_composite_priority(
    severity: str,
    epss_score: Optional[float] = None,
    kev_flag: bool = False,
    lev_score: Optional[float] = None,
    cvss_score: Optional[float] = None,
) -> float:
    """
    Compute composite vulnerability priority score.

    Formula: priority = max(exploitation_signal) * severity_weight

    Where exploitation_signal = max(EPSS, KEV_as_float, LEV)
    And severity_weight comes from the SEVERITY_WEIGHTS table.

    This ensures:
    - Actively exploited vulns (KEV=True) always get top priority
    - High EPSS scores bubble up regardless of CVSS
    - CVSS alone does not drive priority (CVSS inflation is real)

    Args:
        severity: Vulnerability severity level
        epss_score: EPSS probability (0-1)
        kev_flag: Whether vuln is in CISA KEV catalog
        lev_score: Computed LEV score (0-1)
        cvss_score: CVSS base score (0-10)

    Returns:
        Priority score (0.0 to 1.0)
    """
    sev_weight = SEVERITY_WEIGHTS.get(severity.upper(), 0.1)

    # Collect exploitation signals
    signals = []
    if epss_score is not None:
        signals.append(epss_score)
    if kev_flag:
        signals.append(1.0)  # KEV = maximum exploitation probability
    if lev_score is not None:
        signals.append(lev_score)

    # If no exploitation data, fall back to severity-based scoring
    # with a CVSS-adjusted base
    if not signals:
        if cvss_score is not None:
            # Normalize CVSS (0-10) to (0-1) as a weak exploitation proxy
            signals.append(cvss_score / 10.0 * 0.5)  # Capped at 0.5
        else:
            signals.append(sev_weight * 0.3)  # Very low default

    max_signal = max(signals)
    return min(max_signal * sev_weight, 1.0)


def fuse_scan_results(
    trivy_scan: Dict[str, Any],
    grype_scan: Optional[Dict[str, Any]] = None,
    epss_data: Optional[Dict[str, float]] = None,
    kev_set: Optional[Set[str]] = None,
) -> FusionResult:
    """
    Merge Trivy and Grype scan results into a unified finding set.

    The fusion algorithm:
    1. Extract (CVE_ID, package_name) pairs from each scanner
    2. Classify each pair as CONFIRMED or EXCLUSIVE
    3. For EXCLUSIVE findings, mark as CONTESTED (single-scanner only)
    4. Compute composite priority for each finding
    5. Sort by priority descending

    Args:
        trivy_scan: Trivy scan results (standard Trivy JSON format)
        grype_scan: Grype scan results (normalized to Trivy format).
                    If None, fusion degrades to Trivy-only mode.
        epss_data: Optional dict mapping CVE ID to EPSS score
        kev_set: Optional set of CVE IDs in CISA KEV catalog

    Returns:
        FusionResult with classified and prioritized findings
    """
    epss_data = epss_data or {}
    kev_set = kev_set or set()
    result = FusionResult()

    # ---- Extract findings from Trivy ----
    trivy_findings: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for target_result in trivy_scan.get("Results", []):
        for vuln in target_result.get("Vulnerabilities", []):
            key = (vuln.get("VulnerabilityID", ""), vuln.get("PkgName", ""))
            if key[0]:  # Must have a vuln ID
                trivy_findings[key] = vuln

    # ---- Extract findings from Grype (if available) ----
    grype_findings: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if grype_scan:
        for target_result in grype_scan.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                key = (
                    vuln.get("VulnerabilityID", ""),
                    vuln.get("PkgName", ""),
                )
                if key[0]:
                    grype_findings[key] = vuln

    # ---- Merge into unified set ----
    all_keys = set(trivy_findings.keys()) | set(grype_findings.keys())
    unique_cves = set()

    for key in all_keys:
        vuln_id, pkg_name = key
        unique_cves.add(vuln_id)

        in_trivy = key in trivy_findings
        in_grype = key in grype_findings

        # Use whichever scanner has richer data; prefer Trivy as primary
        source = trivy_findings.get(key) or grype_findings.get(key, {})

        severity = source.get("Severity", "UNKNOWN")
        epss = epss_data.get(vuln_id)
        is_kev = vuln_id in kev_set

        # Compute LEV from single EPSS snapshot
        lev = compute_lev([epss], window_days=30) if epss is not None else None

        fused = FusedVulnerability(
            vuln_id=vuln_id,
            package=pkg_name,
            installed_version=source.get("InstalledVersion", ""),
            fixed_version=source.get("FixedVersion", ""),
            severity=severity,
            description=source.get("Description", "")[:300],
            found_by_trivy=in_trivy,
            found_by_grype=in_grype,
            epss_score=epss,
            kev_flag=is_kev,
            cvss_score=source.get("CVSS_Score"),
            lev_score=lev,
            fix_state=source.get("FixState", "unknown"),
        )

        # Classification
        if in_trivy and in_grype:
            fused.classification = "CONFIRMED"
            result.confirmed.append(fused)
        elif in_trivy and not in_grype and grype_scan:
            fused.classification = "EXCLUSIVE_TRIVY"
            result.exclusive_trivy.append(fused)
            result.contested.append(fused)
        elif in_grype and not in_trivy:
            fused.classification = "EXCLUSIVE_GRYPE"
            result.exclusive_grype.append(fused)
            result.contested.append(fused)
        else:
            # Trivy-only mode (no Grype scan provided)
            fused.classification = "CONFIRMED"
            result.confirmed.append(fused)

        # Compute composite priority
        fused.composite_priority = compute_composite_priority(
            severity=severity,
            epss_score=epss,
            kev_flag=is_kev,
            lev_score=lev,
            cvss_score=fused.cvss_score,
        )

    # ---- Sort all lists by priority descending ----
    for lst in [result.confirmed, result.contested,
                result.exclusive_trivy, result.exclusive_grype]:
        lst.sort(key=lambda v: v.composite_priority, reverse=True)

    # ---- Compute summary statistics ----
    result.total_unique_cves = len(unique_cves)
    result.confirmed_count = len(result.confirmed)
    result.contested_count = len(result.contested)

    # Per-severity counts across all findings
    sev_counts: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
    }
    for finding in result.all_findings:
        sev = finding.severity.upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["UNKNOWN"] += 1
    result.severity_counts = sev_counts

    logger.info(
        f"Scanner fusion complete: {result.total_unique_cves} unique CVEs, "
        f"{result.confirmed_count} confirmed, "
        f"{result.contested_count} contested"
    )

    return result


def fusion_to_trivy_format(fusion: FusionResult) -> Dict[str, Any]:
    """
    Convert FusionResult back to Trivy-compatible format.

    This allows the rest of the pipeline (comparer, acceptance criteria)
    to consume fused results without modification.

    Args:
        fusion: FusionResult from fuse_scan_results()

    Returns:
        Dict in Trivy scan JSON format
    """
    vulns = []
    for finding in fusion.all_findings:
        vulns.append({
            "VulnerabilityID": finding.vuln_id,
            "PkgName": finding.package,
            "InstalledVersion": finding.installed_version,
            "FixedVersion": finding.fixed_version,
            "Severity": finding.severity,
            "Description": finding.description,
            "_fusion_classification": finding.classification,
            "_composite_priority": finding.composite_priority,
            "_epss_score": finding.epss_score,
            "_kev_flag": finding.kev_flag,
            "_lev_score": finding.lev_score,
        })

    return {
        "Results": [
            {
                "Target": "fused-scan",
                "Vulnerabilities": vulns,
            }
        ],
        "_fusion_metadata": {
            "total_unique_cves": fusion.total_unique_cves,
            "confirmed_count": fusion.confirmed_count,
            "contested_count": fusion.contested_count,
            "severity_counts": fusion.severity_counts,
        },
    }


def check_sbom_completeness(sbom_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate SBOM completeness against CycloneDX required elements.

    Checks for the 8 primary CycloneDX elements:
    1. metadata (required)
    2. components (required)
    3. services (optional)
    4. dependencies (recommended)
    5. compositions (recommended)
    6. vulnerabilities (optional, populated post-scan)
    7. formulation (optional, build provenance)
    8. annotations (optional)

    Also checks component-level completeness:
    - Every component should have name, version, and purl
    - purl is critical for OS family detection

    Args:
        sbom_data: CycloneDX SBOM as dict

    Returns:
        Dict with:
            - complete: bool (True if all required elements present)
            - score: float (0.0-1.0 completeness ratio)
            - missing_required: list of missing required fields
            - missing_recommended: list of missing recommended fields
            - component_issues: list of component-level problems
            - total_components: int
            - components_with_purl: int
            - purl_coverage_pct: float
    """
    report: Dict[str, Any] = {
        "complete": False,
        "score": 0.0,
        "missing_required": [],
        "missing_recommended": [],
        "component_issues": [],
        "total_components": 0,
        "components_with_purl": 0,
        "purl_coverage_pct": 0.0,
    }

    if not sbom_data:
        report["missing_required"] = ["metadata", "components"]
        return report

    checks_total = 0
    checks_passed = 0

    # ---- Required elements ----

    # metadata
    checks_total += 1
    metadata = sbom_data.get("metadata")
    if metadata:
        checks_passed += 1
    else:
        report["missing_required"].append("metadata")

    # components
    checks_total += 1
    components = sbom_data.get("components", [])
    if components:
        checks_passed += 1
    else:
        report["missing_required"].append("components")

    # ---- Recommended elements ----

    # dependencies
    checks_total += 1
    if sbom_data.get("dependencies"):
        checks_passed += 1
    else:
        report["missing_recommended"].append("dependencies")

    # compositions
    checks_total += 1
    if sbom_data.get("compositions"):
        checks_passed += 1
    else:
        report["missing_recommended"].append("compositions")

    # ---- Optional but valuable ----

    checks_total += 1
    if sbom_data.get("services"):
        checks_passed += 1

    checks_total += 1
    if sbom_data.get("formulation"):
        checks_passed += 1

    # ---- Component-level completeness ----
    report["total_components"] = len(components)
    purl_count = 0
    issues = []

    for i, comp in enumerate(components):
        name = comp.get("name", "")
        version = comp.get("version")
        purl = comp.get("purl", "")

        if not name:
            issues.append(f"Component [{i}] missing 'name'")
        if not version:
            issues.append(f"Component '{name}' missing 'version'")
        if purl:
            purl_count += 1
        else:
            # purl is critical for OS detection
            if i < 5:  # Only report first few to avoid noise
                issues.append(f"Component '{name}' missing 'purl'")

    report["components_with_purl"] = purl_count
    report["purl_coverage_pct"] = (
        (purl_count / len(components) * 100) if components else 0.0
    )
    report["component_issues"] = issues[:20]  # Cap at 20 issues

    # ---- Final scoring ----
    report["score"] = round(checks_passed / checks_total, 2) if checks_total > 0 else 0.0
    report["complete"] = len(report["missing_required"]) == 0

    if report["purl_coverage_pct"] < 50.0 and components:
        logger.warning(
            f"SBOM purl coverage is low ({report['purl_coverage_pct']:.1f}%). "
            f"OS family detection may be unreliable. "
            f"Consider using a scanner that generates richer SBOMs."
        )

    return report
