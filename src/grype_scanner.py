"""
Grype Scanner Module - Secondary Scanner for Dual-Scanner Fusion

Provides vulnerability scanning via Anchore Grype as a second opinion
alongside Trivy. Grype uses its own vulnerability database and matching
algorithms, providing independent confirmation of findings.

Key advantages of dual-scanner approach:
- Different vulnerability databases catch different CVEs
- Cross-validation reduces false positives
- CONTESTED classification for single-scanner-only findings
- Composite EPSS + KEV + CVSS risk scoring per finding

Grype output is normalized to a common format shared with Trivy results,
enabling the fusion engine in scanner.py to merge findings.
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .utils import run_cmd, load_json, save_json

logger = logging.getLogger("docker_patch_tool")


class GrypeError(Exception):
    """Base exception for Grype scanning errors."""
    pass


class GrypeNotFoundError(GrypeError):
    """Raised when Grype binary is not available."""
    pass


class GrypeScanError(GrypeError):
    """Raised when a Grype scan fails."""
    pass


class GrypeDBError(GrypeError):
    """Raised when Grype database operations fail."""
    pass


# Grype severity normalization map.
# Grype uses mixed case and sometimes "Negligible"; normalize to Trivy levels.
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "negligible": "LOW",
    "unknown": "UNKNOWN",
}


def is_grype_available() -> bool:
    """
    Check if Grype is installed and accessible on PATH.

    Returns:
        True if grype binary is found and executable.
    """
    code, _ = run_cmd(["grype", "version"])
    return code == 0


def get_grype_version() -> Optional[str]:
    """
    Get the installed Grype version string.

    Returns:
        Version string (e.g., "0.86.1") or None if detection fails.
    """
    code, output = run_cmd(["grype", "version"])
    if code != 0:
        return None
    match = re.search(r'(\d+\.\d+\.\d+)', output)
    return match.group(1) if match else None


def update_grype_db(retries: int = 2) -> bool:
    """
    Update the Grype vulnerability database.

    Args:
        retries: Number of retry attempts for transient failures.

    Returns:
        True if update succeeds.

    Raises:
        GrypeDBError: If database update fails after retries.
    """
    logger.info("Updating Grype vulnerability database...")
    code, output = run_cmd(["grype", "db", "update"], retries=retries)
    if code != 0:
        raise GrypeDBError(f"Grype DB update failed: {output}")
    logger.info("Grype database updated successfully")
    return True


def scan_image(
    image: str,
    output_path: str,
    retries: int = 2,
    timeout: int = 600,
) -> Dict[str, Any]:
    """
    Run Grype vulnerability scan on a Docker image.

    Produces JSON output in Grype's native format, then normalizes
    it to our common vulnerability format for fusion with Trivy results.

    Args:
        image: Docker image name/tag to scan
        output_path: Path to save raw Grype JSON output
        retries: Number of retries for transient failures
        timeout: Scan timeout in seconds

    Returns:
        Normalized scan results dict with same structure as Trivy output:
        {
            "Results": [
                {
                    "Target": str,
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": str,
                            "PkgName": str,
                            "InstalledVersion": str,
                            "FixedVersion": str,
                            "Severity": str,
                            "Description": str,
                            "DataSource": str,
                            "Scanner": "grype",
                        }
                    ]
                }
            ],
            "scanner": "grype",
            "scanner_version": str,
        }

    Raises:
        GrypeNotFoundError: If Grype is not installed.
        GrypeScanError: If scan fails after retries.
    """
    if not is_grype_available():
        raise GrypeNotFoundError(
            "Grype is not installed. Install from: "
            "https://github.com/anchore/grype/releases"
        )

    logger.info(f"Scanning image '{image}' with Grype (retries={retries})...")

    cmd = [
        "grype", image,
        "-o", "json",
        "--file", output_path,
    ]

    start_time = time.time()
    code, output = run_cmd(cmd, timeout=timeout, retries=retries)
    duration = time.time() - start_time

    if code != 0:
        raise GrypeScanError(
            f"Grype scan failed for {image} after {retries} retries: {output}"
        )

    logger.info(f"Grype scan completed in {duration:.2f}s")

    # Load raw results and normalize
    raw = load_json(output_path)
    if not raw:
        raise GrypeScanError(f"Grype produced empty output for {image}")

    normalized = _normalize_grype_output(raw)
    return normalized


def _normalize_grype_output(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Grype JSON output to match Trivy's structure.

    Grype organizes results differently from Trivy. This function
    converts to a common format so the fusion engine can merge them.

    Grype structure:
    {
        "matches": [
            {
                "vulnerability": { "id": "CVE-...", "severity": "...", ... },
                "artifact": { "name": "...", "version": "...", ... },
                "relatedVulnerabilities": [...],
                "matchDetails": [...]
            }
        ],
        "source": { "type": "image", "target": { ... } },
        "descriptor": { "version": "..." }
    }

    Args:
        raw: Raw Grype JSON output

    Returns:
        Normalized dict matching Trivy's Results structure
    """
    matches = raw.get("matches", [])
    descriptor = raw.get("descriptor", {})
    grype_version = descriptor.get("version", "unknown")

    # Group vulnerabilities by target (package type)
    vulns_by_target: Dict[str, List[Dict[str, Any]]] = {}

    for match in matches:
        vuln_info = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        match_details = match.get("matchDetails", [{}])

        vuln_id = vuln_info.get("id", "")
        raw_severity = vuln_info.get("severity", "Unknown")
        severity = _SEVERITY_MAP.get(raw_severity.lower(), "UNKNOWN")

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        pkg_type = artifact.get("type", "unknown")

        # Extract fixed version from fix info
        fix_info = vuln_info.get("fix", {})
        fix_versions = fix_info.get("versions", [])
        fix_version = fix_versions[0] if fix_versions else ""
        fix_state = fix_info.get("state", "unknown")

        # Extract data source
        data_source = ""
        if match_details:
            data_source = match_details[0].get("searchedBy", {}).get(
                "namespace", ""
            )

        # Extract description from related vulnerabilities
        description = vuln_info.get("description", "")
        if not description:
            related = match.get("relatedVulnerabilities", [])
            if related:
                description = related[0].get("description", "")

        # Extract CVSS and EPSS if available
        cvss_info = vuln_info.get("cvss", [])
        epss_score = None
        cvss_score = None
        if cvss_info:
            for entry in cvss_info:
                score = entry.get("metrics", {}).get("baseScore")
                if score is not None:
                    cvss_score = score
                    break

        # Build normalized vulnerability entry
        normalized_vuln = {
            "VulnerabilityID": vuln_id,
            "PkgName": pkg_name,
            "InstalledVersion": pkg_version,
            "FixedVersion": fix_version,
            "Severity": severity,
            "Description": description[:500] if description else "",
            "DataSource": data_source,
            "Scanner": "grype",
            "FixState": fix_state,
        }

        if cvss_score is not None:
            normalized_vuln["CVSS_Score"] = cvss_score
        if epss_score is not None:
            normalized_vuln["EPSS_Score"] = epss_score

        # Group by package type as target
        target = f"{pkg_type} packages"
        if target not in vulns_by_target:
            vulns_by_target[target] = []
        vulns_by_target[target].append(normalized_vuln)

    # Build Trivy-compatible Results structure
    results = []
    for target_name, vulns in vulns_by_target.items():
        results.append({
            "Target": target_name,
            "Vulnerabilities": vulns,
        })

    return {
        "Results": results,
        "scanner": "grype",
        "scanner_version": grype_version,
    }


def count_vulnerabilities_by_severity(
    scan_results: Dict[str, Any]
) -> Dict[str, int]:
    """
    Count vulnerabilities by severity from normalized Grype results.

    Args:
        scan_results: Normalized scan results (Trivy-compatible format)

    Returns:
        Dict mapping severity to count
    """
    counts = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
    }
    for result in scan_results.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["UNKNOWN"] += 1
    return counts


def extract_cve_list(scan_results: Dict[str, Any]) -> List[str]:
    """
    Extract unique CVE IDs from normalized Grype results.

    Args:
        scan_results: Normalized scan results

    Returns:
        List of unique CVE/vulnerability IDs
    """
    cves = set()
    for result in scan_results.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vid = vuln.get("VulnerabilityID", "")
            if vid:
                cves.add(vid)
    return sorted(cves)


def generate_grype_sbom(
    image: str,
    output_path: str,
    format: str = "cyclonedx-json",
) -> Dict[str, Any]:
    """
    Generate an SBOM using Grype's syft integration.

    Note: Grype uses Syft internally for SBOM generation.
    This provides an independent SBOM that can be compared with Trivy's.

    Args:
        image: Docker image to generate SBOM for
        output_path: Where to save the SBOM JSON
        format: SBOM format (default: cyclonedx-json)

    Returns:
        Parsed SBOM dict
    """
    # Grype itself does not generate SBOMs; Syft does.
    # Check if syft is available as the companion tool.
    code, _ = run_cmd(["syft", "version"])
    if code != 0:
        logger.warning(
            "Syft not found; cannot generate independent SBOM via Grype toolchain. "
            "Using Trivy SBOM only."
        )
        return {}

    logger.info(f"Generating SBOM for '{image}' using Syft...")
    cmd = ["syft", image, "-o", format, "--file", output_path]
    code, output = run_cmd(cmd, timeout=300)

    if code != 0:
        logger.error(f"Syft SBOM generation failed: {output}")
        return {}

    return load_json(output_path)
