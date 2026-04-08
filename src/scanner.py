import logging
from typing import Dict, List, Tuple, Any, Optional
from .utils import run_cmd, load_json

logger = logging.getLogger("docker_patch_tool")

# Error type definitions
class ScanError(Exception):
    """Base exception for scanning errors."""
    pass

class NetworkError(ScanError):
    """Raised when a network-related error occurs during scanning."""
    pass

class DBUpdateError(ScanError):
    """Raised when Trivy database update fails."""
    pass

class ScanExecutionError(ScanError):
    """Raised when scan execution itself fails (not DB-related)."""
    pass

def _is_network_error(output: str) -> bool:
    """
    Determine if error output indicates a network-related issue.

    Args:
        output: Command output/error message

    Returns:
        bool: True if error appears to be network-related
    """
    network_indicators = [
        "connection refused",
        "connection timeout",
        "network is unreachable",
        "name resolution failed",
        "connection reset",
        "EOF",
        "i/o timeout",
        "temporary failure in name resolution",
    ]
    return any(indicator in output.lower() for indicator in network_indicators)

def _is_db_update_error(output: str) -> bool:
    """
    Determine if error output indicates a database update failure.

    Args:
        output: Command output/error message

    Returns:
        bool: True if error appears to be DB update-related
    """
    db_indicators = [
        "database",
        "update failed",
        "db download",
        "download vulnerability database",
        "vulnerability db",
    ]
    return any(indicator in output.lower() for indicator in db_indicators)

def scan_image(image: str, output_path: str, retries: int = 3) -> Dict[str, Any]:
    """
    Run Trivy vulnerability scan on the given image with retry logic.

    Attempts the scan up to 'retries' times to handle transient network issues.
    Saves JSON report to output_path.

    Args:
        image: Docker image name/tag to scan
        output_path: Path where JSON report will be saved
        retries: Number of retry attempts for network failures (default 3)

    Returns:
        dict: Parsed JSON scan results, or empty dict on persistent failure

    Raises:
        NetworkError: If network errors persist after retries
        DBUpdateError: If Trivy database update fails
        ScanExecutionError: If scan fails for other reasons
    """
    logger.info(f"Scanning image '{image}' for vulnerabilities (retries={retries})...")
    cmd = [
        "trivy", "image", "--quiet", "--format", "json",
        "--timeout", "600s",
        "-o", output_path, image
    ]
    code, output = run_cmd(cmd, retries=retries)

    if code != 0:
        logger.error(f"Trivy scan failed for image {image}:\n{output}")

        if _is_network_error(output):
            raise NetworkError(f"Network error during scan of {image}: {output}")
        elif _is_db_update_error(output):
            raise DBUpdateError(f"Database update failed during scan of {image}: {output}")
        else:
            raise ScanExecutionError(f"Scan execution failed for {image}: {output}")

    return load_json(output_path)

def scan_image_detailed(
    image: str, output_path: str, retries: int = 3
) -> Dict[str, Any]:
    """
    Run Trivy vulnerability scan and return detailed results with rich metadata.

    Performs a vulnerability scan and enriches the results with per-severity counts,
    total vulnerability count, complete CVE list, and scan metadata.

    Args:
        image: Docker image name/tag to scan
        output_path: Path where JSON report will be saved
        retries: Number of retry attempts for network failures (default 3)

    Returns:
        dict: Detailed scan results containing:
            - 'raw_results': Complete Trivy JSON output
            - 'severity_counts': Dict with counts per severity level
            - 'total_count': Total number of vulnerabilities found
            - 'cves': List of CVE IDs found
            - 'scan_metadata': Dict with image, output_path, and retry count

    Raises:
        NetworkError: If network errors persist after retries
        DBUpdateError: If Trivy database update fails
        ScanExecutionError: If scan fails for other reasons
    """
    logger.info(f"Performing detailed scan of image '{image}'...")
    scan_json = scan_image(image, output_path, retries=retries)

    severity_counts = _count_vulnerabilities_by_severity(scan_json)
    total_count = sum(severity_counts.values())
    cves = _extract_cve_list(scan_json)

    return {
        "raw_results": scan_json,
        "severity_counts": severity_counts,
        "total_count": total_count,
        "cves": cves,
        "scan_metadata": {
            "image": image,
            "output_path": output_path,
            "retries": retries,
        }
    }

def generate_sbom(image: str, output_path: str, retries: int = 3) -> Dict[str, Any]:
    """
    Generate a SBOM (Software Bill of Materials) for the given image using Trivy.

    Generates SBOM in CycloneDX format with retry logic for network resilience.

    Args:
        image: Docker image name/tag
        output_path: Path where SBOM JSON will be saved
        retries: Number of retry attempts for network failures (default 3)

    Returns:
        dict: Parsed SBOM JSON, or empty dict on persistent failure

    Raises:
        NetworkError: If network errors persist after retries
        DBUpdateError: If Trivy database update fails
        ScanExecutionError: If SBOM generation fails for other reasons
    """
    logger.info(f"Generating SBOM for image '{image}' (retries={retries})...")
    cmd = [
        "trivy", "image", "--format", "cyclonedx",
        "--timeout", "600s",
        "--output", output_path, image
    ]
    code, output = run_cmd(cmd, retries=retries)

    if code != 0:
        logger.error(f"Failed to generate SBOM for {image}:\n{output}")

        if _is_network_error(output):
            raise NetworkError(f"Network error during SBOM generation for {image}: {output}")
        elif _is_db_update_error(output):
            raise DBUpdateError(f"Database update failed during SBOM generation for {image}: {output}")
        else:
            raise ScanExecutionError(f"SBOM generation failed for {image}: {output}")

    return load_json(output_path)

def summarize_vulnerabilities(scan_json: Dict[str, Any]) -> Dict[str, int]:
    """
    Summarize vulnerability counts by severity from a Trivy scan JSON.

    Counts vulnerabilities across all results, including per-severity counts
    and a total count.

    Args:
        scan_json: Parsed Trivy JSON scan results

    Returns:
        dict: Severity counts and total, e.g.:
            {
                "CRITICAL": 5,
                "HIGH": 12,
                "MEDIUM": 23,
                "LOW": 8,
                "UNKNOWN": 0,
                "total": 48
            }
    """
    summary = _count_vulnerabilities_by_severity(scan_json)
    summary["total"] = sum(summary.values())
    return summary

def _count_vulnerabilities_by_severity(scan_json: Dict[str, Any]) -> Dict[str, int]:
    """
    Internal helper to count vulnerabilities by severity level.

    Args:
        scan_json: Parsed Trivy JSON scan results

    Returns:
        dict: Counts per severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
    """
    summary: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for result in scan_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev in summary:
                summary[sev] += 1
            else:
                summary["UNKNOWN"] += 1
    return summary

def _extract_cve_list(scan_json: Dict[str, Any]) -> List[str]:
    """
    Internal helper to extract all CVE IDs from scan results.

    Args:
        scan_json: Parsed Trivy JSON scan results

    Returns:
        list: List of unique CVE IDs found
    """
    cves: List[str] = []
    for result in scan_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID")
            if cve_id:
                cves.append(cve_id)
    return list(set(cves))  # Return unique CVEs

def compute_cve_resolution_rate(
    before_scan: Dict[str, Any], after_scan: Dict[str, Any]
) -> float:
    """
    Calculate the percentage of CVEs that were resolved between two scans.

    Compares CVE lists from before and after remediation to determine
    what percentage of the original vulnerabilities were fixed.

    Args:
        before_scan: Scan results before remediation
        after_scan: Scan results after remediation

    Returns:
        float: Resolution rate as percentage (0-100), e.g., 45.5 means 45.5% resolved

    Raises:
        ValueError: If before_scan has no vulnerabilities
    """
    cves_before = set(_extract_cve_list(before_scan))
    cves_after = set(_extract_cve_list(after_scan))

    if not cves_before:
        logger.warning("No CVEs found in before_scan; resolution rate is undefined")
        return 0.0

    resolved = cves_before - cves_after
    resolution_rate = (len(resolved) / len(cves_before)) * 100.0

    logger.info(
        f"CVE Resolution: {len(resolved)}/{len(cves_before)} CVEs resolved "
        f"({resolution_rate:.1f}%)"
    )

    return resolution_rate
