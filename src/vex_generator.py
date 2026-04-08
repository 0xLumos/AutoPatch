"""
VEX (Vulnerability Exploitability eXchange) Generator

Produces dual-format VEX documents:
1. OpenVEX (https://openvex.dev/) - lightweight, Git-friendly
2. CycloneDX VEX - embedded in CycloneDX SBOM

VEX documents communicate the exploitability status of vulnerabilities
in the context of a specific product/image. After AutoPatch remediates
vulnerabilities, the VEX document records:

- FIXED: Vulnerability was resolved by the patch
- NOT_AFFECTED: Vulnerability exists in the SBOM but is not exploitable
  in this context (e.g., vulnerable function not reachable)
- UNDER_INVESTIGATION: Vulnerability needs manual review

Each VEX statement includes EPSS score in the justification field,
providing risk context for security teams reviewing the output.

Also provides remediation attestation generation for SLSA provenance,
recording what was changed, why, and by whom.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from .utils import save_json

logger = logging.getLogger("docker_patch_tool")


# OpenVEX document structure version
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
OPENVEX_VERSION = 1

# CycloneDX VEX analysis states mapped from our internal states
_CDX_STATUS_MAP = {
    "fixed": "resolved",
    "not_affected": "false_positive",
    "under_investigation": "in_triage",
    "affected": "exploitable",
}


def generate_openvex(
    product_id: str,
    product_name: str,
    statements: List[Dict[str, Any]],
    author: str = "AutoPatch",
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate an OpenVEX document for the patched image.

    Args:
        product_id: OCI image reference or purl of the product
        product_name: Human-readable product name
        statements: List of VEX statements, each containing:
            - vuln_id: CVE ID
            - status: "fixed", "not_affected", "under_investigation", "affected"
            - justification: Why this status was assigned
            - impact_statement: (optional) Additional context
            - epss_score: (optional) EPSS probability
            - action_statement: (optional) What was done to fix it
        author: Document author name
        output_path: If set, saves the document to this path

    Returns:
        OpenVEX document as dict
    """
    doc_id = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    vex_statements = []
    for stmt in statements:
        vex_stmt = {
            "vulnerability": {
                "@id": f"https://nvd.nist.gov/vuln/detail/{stmt['vuln_id']}",
                "name": stmt["vuln_id"],
            },
            "products": [
                {
                    "@id": product_id,
                    "identifiers": {
                        "purl": product_id if product_id.startswith("pkg:") else None,
                    },
                }
            ],
            "status": stmt["status"],
        }

        # Add justification for not_affected
        if stmt.get("justification"):
            vex_stmt["justification"] = stmt["justification"]

        # Add impact statement
        if stmt.get("impact_statement"):
            vex_stmt["impact_statement"] = stmt["impact_statement"]

        # Add action statement for fixed vulns
        if stmt.get("action_statement"):
            vex_stmt["action_statement"] = stmt["action_statement"]

        # Embed EPSS in status_notes (non-standard but useful)
        if stmt.get("epss_score") is not None:
            vex_stmt["status_notes"] = (
                f"EPSS probability: {stmt['epss_score']:.4f} "
                f"(30-day exploitation likelihood)"
            )

        vex_statements.append(vex_stmt)

    doc = {
        "@context": OPENVEX_CONTEXT,
        "@id": doc_id,
        "author": author,
        "role": "automated-remediation-tool",
        "timestamp": timestamp,
        "version": OPENVEX_VERSION,
        "tooling": "AutoPatch/1.0",
        "statements": vex_statements,
    }

    if output_path:
        save_json(doc, output_path)
        logger.info(f"OpenVEX document saved to {output_path}")

    return doc


def generate_cyclonedx_vex(
    sbom_data: Dict[str, Any],
    statements: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate CycloneDX VEX by embedding vulnerability analysis in the SBOM.

    This modifies a copy of the SBOM to include vulnerability analysis
    entries, which is the CycloneDX-native way to express VEX.

    Args:
        sbom_data: Original CycloneDX SBOM dict
        statements: VEX statements (same format as generate_openvex)
        output_path: If set, saves the modified SBOM

    Returns:
        Modified SBOM with VEX data embedded
    """
    import copy
    vex_sbom = copy.deepcopy(sbom_data)

    # Ensure vulnerabilities array exists
    if "vulnerabilities" not in vex_sbom:
        vex_sbom["vulnerabilities"] = []

    for stmt in statements:
        cdx_status = _CDX_STATUS_MAP.get(stmt["status"], "in_triage")

        vuln_entry = {
            "id": stmt["vuln_id"],
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{stmt['vuln_id']}",
            },
            "analysis": {
                "state": cdx_status,
                "justification": stmt.get("justification", ""),
                "detail": stmt.get("impact_statement", ""),
            },
        }

        # Add EPSS as a rating
        if stmt.get("epss_score") is not None:
            vuln_entry["ratings"] = [
                {
                    "source": {"name": "EPSS"},
                    "score": stmt["epss_score"],
                    "method": "other",
                    "vector": f"EPSS:{stmt['epss_score']:.4f}",
                }
            ]

        # Add response for fixed vulns
        if stmt["status"] == "fixed":
            vuln_entry["analysis"]["response"] = ["update"]
            if stmt.get("action_statement"):
                vuln_entry["analysis"]["detail"] = stmt["action_statement"]

        vex_sbom["vulnerabilities"].append(vuln_entry)

    if output_path:
        save_json(vex_sbom, output_path)
        logger.info(f"CycloneDX VEX document saved to {output_path}")

    return vex_sbom


def build_vex_statements_from_diff(
    vuln_diff: Dict[str, List[Dict[str, Any]]],
    epss_data: Optional[Dict[str, float]] = None,
    base_image_change: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Build VEX statements from a vulnerability diff (before vs after patching).

    Args:
        vuln_diff: Output of comparer.diff_vulnerabilities() with keys:
            - resolved: vulns fixed by the patch
            - remaining: vulns still present after patch
            - new: vulns introduced by the patch
        epss_data: Optional CVE -> EPSS score mapping
        base_image_change: Description of base image change (e.g., "debian:10 -> debian:12")

    Returns:
        List of VEX statement dicts ready for generate_openvex/cyclonedx_vex
    """
    epss_data = epss_data or {}
    statements = []

    action = f"Base image upgraded ({base_image_change})" if base_image_change else "Image patched by AutoPatch"

    # Resolved vulnerabilities -> FIXED
    for vuln in vuln_diff.get("resolved", []):
        vid = vuln.get("id", "")
        statements.append({
            "vuln_id": vid,
            "status": "fixed",
            "justification": "vulnerability_not_present",
            "action_statement": action,
            "impact_statement": (
                f"Resolved by upgrading {vuln.get('package', 'unknown')} "
                f"from {vuln.get('version', '?')} "
                f"(fix available in {vuln.get('fix_version', 'newer version')})"
            ),
            "epss_score": epss_data.get(vid),
        })

    # Remaining vulnerabilities -> AFFECTED (still present)
    for vuln in vuln_diff.get("remaining", []):
        vid = vuln.get("id", "")
        fix_ver = vuln.get("fix_version", "")
        if fix_ver:
            status = "affected"
            justification = f"Fix available in {fix_ver} but not applied by current patch strategy"
        else:
            status = "under_investigation"
            justification = "No fix available from upstream; monitoring for future patches"

        statements.append({
            "vuln_id": vid,
            "status": status,
            "justification": justification,
            "impact_statement": (
                f"Package: {vuln.get('package', '?')} "
                f"v{vuln.get('version', '?')} "
                f"(severity: {vuln.get('severity', '?')})"
            ),
            "epss_score": epss_data.get(vid),
        })

    # New vulnerabilities -> UNDER_INVESTIGATION
    for vuln in vuln_diff.get("new", []):
        vid = vuln.get("id", "")
        statements.append({
            "vuln_id": vid,
            "status": "under_investigation",
            "justification": "Vulnerability introduced by base image change; assessing exploitability",
            "impact_statement": (
                f"New finding in {vuln.get('package', '?')} "
                f"v{vuln.get('version', '?')} "
                f"(severity: {vuln.get('severity', '?')})"
            ),
            "epss_score": epss_data.get(vid),
        })

    return statements


def generate_remediation_attestation(
    image_ref: str,
    original_base: str,
    patched_base: str,
    vuln_diff: Dict[str, List[Dict[str, Any]]],
    metrics: Dict[str, Any],
    pipeline_config: Optional[Dict[str, Any]] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a SLSA-compatible remediation attestation predicate.

    This records the full provenance of the remediation action:
    what was changed, why, what tools were used, and the resulting
    security posture improvement.

    Args:
        image_ref: Digest reference of the patched image
        original_base: Original base image FROM value
        patched_base: New base image FROM value
        vuln_diff: Vulnerability diff from comparer
        metrics: Computed metrics from comparer.compute_metrics()
        pipeline_config: Optional pipeline configuration used
        output_path: If set, saves attestation to this path

    Returns:
        SLSA provenance predicate as dict
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    predicate = {
        "_type": "https://autopatch.dev/remediation/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {
                "name": image_ref,
                "digest": {"sha256": image_ref.split("sha256:")[-1] if "sha256:" in image_ref else ""},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://autopatch.dev/remediation/v1",
                "externalParameters": {
                    "original_base_image": original_base,
                    "patched_base_image": patched_base,
                    "remediation_strategy": "sbom-driven-base-image-upgrade",
                },
                "internalParameters": {
                    "pipeline_config": pipeline_config or {},
                },
                "resolvedDependencies": [
                    {
                        "uri": f"docker://{patched_base}",
                        "annotations": {
                            "role": "replacement-base-image",
                        },
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/0xLumos/AutoPatch",
                    "version": "1.0.0",
                },
                "metadata": {
                    "invocationId": f"urn:uuid:{uuid.uuid4()}",
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
            },
            "remediation": {
                "vulnerabilities_resolved": len(vuln_diff.get("resolved", [])),
                "vulnerabilities_remaining": len(vuln_diff.get("remaining", [])),
                "vulnerabilities_introduced": len(vuln_diff.get("new", [])),
                "reduction_percentage": metrics.get("vulnerability_reduction_pct", 0),
                "total_before": metrics.get("total_before", 0),
                "total_after": metrics.get("total_after", 0),
                "per_severity_before": metrics.get("per_severity_before", {}),
                "per_severity_after": metrics.get("per_severity_after", {}),
                "build_time_seconds": metrics.get("build_time_seconds"),
                "image_size_delta_mb": metrics.get("image_size_delta_mb"),
            },
        },
    }

    if output_path:
        save_json(predicate, output_path)
        logger.info(f"Remediation attestation saved to {output_path}")

    return predicate


def generate_formulation_section(
    original_dockerfile: str,
    patched_dockerfile: str,
    original_base: str,
    patched_base: str,
    inference_signals: List[str],
) -> Dict[str, Any]:
    """
    Generate the CycloneDX 'formulation' section for the post-patch SBOM.

    The formulation section records HOW the software was built, providing
    build provenance that complements the component list. This is Fix B3.

    Args:
        original_dockerfile: Content of original Dockerfile
        patched_dockerfile: Content of patched Dockerfile
        original_base: Original base image
        patched_base: New base image
        inference_signals: List of SBOM inference signals used

    Returns:
        Dict suitable for inclusion in CycloneDX SBOM under "formulation"
    """
    return {
        "components": [
            {
                "type": "file",
                "name": "Dockerfile",
                "description": "Patched Dockerfile produced by AutoPatch",
            }
        ],
        "workflows": [
            {
                "uid": f"urn:uuid:{uuid.uuid4()}",
                "name": "autopatch-remediation",
                "description": "Automated vulnerability remediation via base image upgrade",
                "taskTypes": ["build", "test", "deliver"],
                "steps": [
                    {"name": "sbom-generation", "description": "Generate CycloneDX SBOM from original image"},
                    {"name": "os-inference", "description": f"Detected OS family from SBOM (signals: {', '.join(inference_signals[:5])})"},
                    {"name": "base-selection", "description": f"Selected {patched_base} to replace {original_base}"},
                    {"name": "dockerfile-rewrite", "description": "Rewrote Dockerfile FROM directives"},
                    {"name": "rebuild", "description": "Built patched image from rewritten Dockerfile"},
                    {"name": "rescan", "description": "Scanned patched image for remaining vulnerabilities"},
                    {"name": "acceptance-check", "description": "Verified patch meets acceptance criteria"},
                ],
                "inputs": [
                    {"source": {"name": original_base}, "description": "Original base image"},
                ],
                "outputs": [
                    {"source": {"name": patched_base}, "description": "Patched base image"},
                ],
            }
        ],
    }


# ════════════════════════════════════════════════════════════════════
# I3: VEX Consumption on Rescan
# ════════════════════════════════════════════════════════════════════

def load_vex_document(vex_path: str) -> Optional[Dict[str, Any]]:
    """
    Load a VEX document (OpenVEX or CycloneDX VEX) from disk.

    Args:
        vex_path: Path to VEX JSON file

    Returns:
        Parsed VEX document, or None on failure
    """
    try:
        with open(vex_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Loaded VEX document from {vex_path}")
        return data
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load VEX document from {vex_path}: {e}")
        return None


def extract_suppressed_cves(vex_data: Dict[str, Any]) -> Set[str]:
    """
    Extract CVE IDs that should be suppressed (not_affected/fixed) from a VEX document.

    Supports both OpenVEX and CycloneDX VEX formats. A CVE is suppressed if
    its status is "not_affected" or "fixed" -- meaning the VEX producer has
    already determined it is either not exploitable or already remediated.

    Args:
        vex_data: Parsed VEX document

    Returns:
        Set of CVE IDs to suppress from scan results
    """
    suppressed: Set[str] = set()

    if not vex_data:
        return suppressed

    # Detect format
    if "@context" in vex_data and "openvex" in str(vex_data.get("@context", "")):
        # OpenVEX format
        for stmt in vex_data.get("statements", []):
            status = stmt.get("status", "")
            if status in ("not_affected", "fixed"):
                vuln = stmt.get("vulnerability", {})
                vuln_id = vuln.get("name", "") if isinstance(vuln, dict) else str(vuln)
                if vuln_id:
                    suppressed.add(vuln_id)

    elif "vulnerabilities" in vex_data:
        # CycloneDX VEX format (embedded in SBOM or standalone)
        for vuln in vex_data.get("vulnerabilities", []):
            analysis = vuln.get("analysis", {})
            state = analysis.get("state", "")
            # CycloneDX states: "resolved", "false_positive", "not_affected"
            if state in ("resolved", "false_positive", "not_affected"):
                vuln_id = vuln.get("id", "")
                if vuln_id:
                    suppressed.add(vuln_id)

    logger.info(f"VEX suppression: {len(suppressed)} CVEs marked not_affected/fixed")
    return suppressed


def apply_vex_suppression(
    scan_results: Dict[str, Any],
    vex_paths: Optional[List[str]] = None,
    suppressed_cves: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """
    Filter scan results by removing CVEs that are suppressed by VEX documents.

    This is used during the rescan phase: after patching, any CVEs that were
    previously marked as not_affected via VEX should not inflate the "remaining
    vulnerabilities" count.

    Args:
        scan_results: Trivy JSON scan results
        vex_paths: List of paths to VEX documents to load and apply
        suppressed_cves: Pre-computed set of CVE IDs to suppress (alternative to vex_paths)

    Returns:
        Filtered scan results with suppressed CVEs removed
    """
    # Build suppression set from VEX files if not provided directly
    if suppressed_cves is None:
        suppressed_cves = set()

    if vex_paths:
        for path in vex_paths:
            vex_data = load_vex_document(path)
            if vex_data:
                suppressed_cves.update(extract_suppressed_cves(vex_data))

    if not suppressed_cves:
        return scan_results

    # Deep copy to avoid mutating the original
    import copy
    filtered = copy.deepcopy(scan_results)

    total_suppressed = 0
    for result_entry in filtered.get("Results", []):
        vulns = result_entry.get("Vulnerabilities", [])
        if vulns:
            before_count = len(vulns)
            filtered_vulns = [
                v for v in vulns
                if v.get("VulnerabilityID", "") not in suppressed_cves
            ]
            suppressed_count = before_count - len(filtered_vulns)
            total_suppressed += suppressed_count
            result_entry["Vulnerabilities"] = filtered_vulns

    if total_suppressed > 0:
        logger.info(
            f"VEX suppression applied: removed {total_suppressed} known "
            f"not_affected/fixed CVEs from scan results"
        )

    return filtered
