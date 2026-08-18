import json
import logging
import os
from typing import Dict, List, Tuple, Any, Optional
from .utils import run_cmd, load_json
from . import vulnerability_index as _vi

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

def _validate_scan_json(scan_json: Any, image: str) -> Dict[str, Any]:
    """Validate the shape of a Trivy JSON report at the boundary (Item 8).

    A zero exit code plus a blind ``load_json`` used to trust truncated or
    empty output, which surfaced later as a KeyError far from the cause.
    A valid Trivy report is a dict carrying a ``Results`` list and/or a
    ``SchemaVersion``. ``Results`` may be legitimately absent when an image
    has no scannable targets, so we accept a dict with ``SchemaVersion`` and
    only reject non-dicts or empty payloads.
    """
    if not isinstance(scan_json, dict):
        raise ScanExecutionError(
            f"Trivy returned a non-object JSON report for {image} "
            f"(got {type(scan_json).__name__}); report is malformed or truncated."
        )
    if "Results" not in scan_json and "SchemaVersion" not in scan_json:
        raise ScanExecutionError(
            f"Trivy JSON report for {image} has neither 'Results' nor "
            f"'SchemaVersion'; report is malformed or truncated."
        )
    return scan_json


def get_trivy_db_metadata() -> Dict[str, Optional[str]]:
    """Record the Trivy binary version and vulnerability DB timestamp (Item 8).

    The before/after comparison is only valid if both scans use the same DB
    snapshot. Recording the version and DB ``UpdatedAt`` in the report makes
    the 'zero new CVEs introduced' claim auditable: a reviewer can confirm a
    DB roll did not manufacture an apparent new advisory between the scans.

    Returns a dict with ``trivy_version`` and ``db_updated_at`` (either may be
    None if Trivy is older than the JSON version output or the DB metadata is
    not on disk).
    """
    meta: Dict[str, Optional[str]] = {"trivy_version": None, "db_updated_at": None}
    code, output = run_cmd(["trivy", "--version", "--format", "json"], retries=0)
    if code == 0 and output:
        try:
            data = json.loads(output)
            meta["trivy_version"] = data.get("Version")
            vdb = data.get("VulnerabilityDB") or {}
            meta["db_updated_at"] = vdb.get("UpdatedAt") or vdb.get("DownloadedAt")
        except (json.JSONDecodeError, AttributeError):
            # Older Trivy prints a plain-text version; keep the raw first line.
            meta["trivy_version"] = output.splitlines()[0].strip() if output else None
    return meta


def scan_image(
    image: str,
    output_path: str,
    retries: int = 3,
    skip_db_update: bool = False,
) -> Dict[str, Any]:
    """
    Run Trivy vulnerability scan on the given image with retry logic.

    Attempts the scan up to 'retries' times to handle transient network issues.
    Saves JSON report to output_path.

    Args:
        image: Docker image name/tag to scan
        output_path: Path where JSON report will be saved
        retries: Number of retry attempts for network failures (default 3)
        skip_db_update: If True, pass ``--skip-db-update`` so the scan uses the
            DB snapshot already on disk. The orchestrator runs the BEFORE scan
            with this False (refreshing the DB once) and the AFTER scan with it
            True, so both scans of a run share one identical DB snapshot and the
            before/after delta cannot be polluted by a mid-run DB roll (Item 8).

    Returns:
        dict: Parsed JSON scan results, or empty dict on persistent failure

    Raises:
        NetworkError: If network errors persist after retries
        DBUpdateError: If Trivy database update fails
        ScanExecutionError: If scan fails for other reasons
    """
    logger.info(
        f"Scanning image '{image}' for vulnerabilities "
        f"(retries={retries}, skip_db_update={skip_db_update})..."
    )
    cmd = [
        "trivy", "image", "--quiet", "--format", "json",
        "--timeout", "600s",
    ]
    if skip_db_update:
        cmd.append("--skip-db-update")
    cmd += ["-o", output_path, image]
    code, output = run_cmd(cmd, retries=retries)

    if code != 0:
        logger.error(f"Trivy scan failed for image {image}:\n{output}")

        if _is_db_update_error(output):
            # The DB download flaked. Retry once with the cached DB
            # so a transient mirror outage does not abort the scan.
            logger.warning(
                f"Trivy DB update failed; retrying scan with --skip-db-update: {image}"
            )
            fallback_cmd = cmd if "--skip-db-update" in cmd else cmd[:2] + ["--skip-db-update"] + cmd[2:]
            code, output = run_cmd(fallback_cmd, retries=0)
            if code == 0:
                logger.info(f"Scan succeeded on --skip-db-update fallback: {image}")
                return _validate_scan_json(load_json(output_path), image)
            # Fallback also failed: surface the original error class.
            logger.error(
                f"Trivy --skip-db-update fallback also failed for {image}:\n{output}"
            )
            raise DBUpdateError(
                f"Database update failed during scan of {image} "
                f"(fallback also failed): {output}"
            )
        if _is_network_error(output):
            raise NetworkError(f"Network error during scan of {image}: {output}")
        raise ScanExecutionError(f"Scan execution failed for {image}: {output}")

    return _validate_scan_json(load_json(output_path), image)

def scan_image_detailed(
    image: str, output_path: str, retries: int = 3, skip_db_update: bool = False
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
    scan_json = scan_image(image, output_path, retries=retries, skip_db_update=skip_db_update)

    severity_counts = _count_vulnerabilities_by_severity(scan_json)
    total_count = sum(severity_counts.values())
    unique_cves = _vi.count_unique_cves(_vi.extract_records(scan_json))
    cves = _extract_cve_list(scan_json)

    return {
        "raw_results": scan_json,
        "severity_counts": severity_counts,
        "total_count": total_count,          # deduplicated package-CVE rows
        "total_unique_cves": unique_cves,    # distinct CVE identifiers (Item: report both)
        "cves": cves,
        "scan_metadata": {
            "image": image,
            "output_path": output_path,
            "retries": retries,
            "skip_db_update": skip_db_update,
            "trivy_db": get_trivy_db_metadata(),
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

        if _is_db_update_error(output):
            logger.warning(
                f"Trivy DB update failed; retrying SBOM with --skip-db-update: {image}"
            )
            fallback_cmd = cmd[:1] + cmd[1:2] + ["--skip-db-update"] + cmd[2:]
            code, output = run_cmd(fallback_cmd, retries=0)
            if code == 0:
                logger.info(f"SBOM succeeded on --skip-db-update fallback: {image}")
                return load_json(output_path)
            logger.error(
                f"Trivy --skip-db-update fallback also failed for {image}:\n{output}"
            )
            raise DBUpdateError(
                f"Database update failed during SBOM generation for {image} "
                f"(fallback also failed): {output}"
            )
        if _is_network_error(output):
            raise NetworkError(f"Network error during SBOM generation for {image}: {output}")
        raise ScanExecutionError(f"SBOM generation failed for {image}: {output}")

    return load_json(output_path)

_TOTAL_KEY = "total"


def summarize_vulnerabilities(scan_json: Dict[str, Any]) -> Dict[str, int]:
    """
    Legacy severity-count summarizer.

    Internally delegates to :mod:`vulnerability_index` so callers get
    deduplicated per-(CVE, package, path) counts that match the
    acceptance gate. The legacy return shape is preserved (severity
    buckets plus an in-band ``"total"`` key) for backward compatibility.

    .. deprecated:: 0.2.0
        Prefer :func:`vulnerability_index.summarize` for new code:
        the richer dict separates ``total_rows`` (package-CVE rows)
        from ``total_unique_cves`` (distinct CVE identifiers) so
        reports never confuse the two. This function will be removed
        in 0.4.0.

    Args:
        scan_json: Parsed Trivy JSON scan results.

    Returns:
        Legacy dict: severity buckets plus a ``"total"`` key equal to
        the sum of severities (i.e. package-CVE row count).
    """
    summary = _count_vulnerabilities_by_severity(scan_json)
    # The in-band key is only safe while it cannot collide with a real
    # severity bucket. Trivy has shipped new severity labels before
    # (UNKNOWN was added mid-2.x), so assert the invariant here rather
    # than discover a double-counted total in a published table.
    if _TOTAL_KEY in summary:
        raise AssertionError(
            f"severity bucket named {_TOTAL_KEY!r} collides with the legacy "
            f"in-band total key; use severity_counts() and compute the total "
            f"separately. Buckets seen: {sorted(summary)}"
        )
    summary[_TOTAL_KEY] = sum(summary.values())
    return summary




def severity_counts(scan_json: Dict[str, Any]) -> Dict[str, int]:
    """
    Return severity buckets without an in-band ``total`` key.

    Callers that want to iterate over severities (``for sev, n in
    severity_counts(...).items()``) must use this function rather than
    :func:`summarize_vulnerabilities`, whose return dict embeds a
    ``"total"`` key inside the same mapping for historical reasons.
    """
    return _count_vulnerabilities_by_severity(scan_json)
def _count_vulnerabilities_by_severity(scan_json: Dict[str, Any]) -> Dict[str, int]:
    """
    Internal helper to count vulnerabilities by severity level.

    Counts deduplicated package-CVE rows (one count per unique
    ``(VulnerabilityID, PkgName, PkgPath)`` tuple). The same CVE
    affecting three packages contributes three to the totals; the same
    ``(CVE, package, path)`` emitted in multiple Result sections is
    counted once. Use :func:`vulnerability_index.summarize` for the
    additional ``total_unique_cves`` figure.

    Args:
        scan_json: Parsed Trivy JSON scan results

    Returns:
        dict: Counts per severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
    """
    return _vi.count_by_severity(_vi.extract_records(scan_json))


def _extract_cve_list(scan_json: Dict[str, Any]) -> List[str]:
    """
    Internal helper to extract all unique CVE IDs from scan results.

    Args:
        scan_json: Parsed Trivy JSON scan results

    Returns:
        list: Sorted list of unique CVE IDs found
    """
    return _vi.unique_cve_ids(_vi.extract_records(scan_json))

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
