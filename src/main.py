import argparse
import html
import logging
import json
import os
import re
import sys
import tempfile
import time
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Configure the logger (console output format)
logger = logging.getLogger("docker_patch_tool")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Import functions from other modules
from .utils import (
    run_cmd, load_base_mapping, load_json, save_json, save_csv,
    generate_diff, compute_reduction_percentage
)
from .parser import parse_dockerfile_stages
from .builder import build_image, tag_image, push_image, get_image_digest, measure_image_size
from .scanner import (
    scan_image, scan_image_detailed, generate_sbom, summarize_vulnerabilities,
    ScanError, NetworkError, DBUpdateError, ScanExecutionError
)
from .patcher import patch_dockerfile, analyze_sbom, smoke_test_image, migrate_package_commands
from .signer import (
    sign_image, verify_image, generate_attestation, attach_sbom, get_signing_log,
    SigningError, KeyGenerationError, VerificationError
)
from .comparer import (
    diff_vulnerabilities, diff_sbom, compute_metrics, check_acceptance_criteria
)
from .app_patcher import (
    plan_app_patches, format_app_patch_report, export_app_patch_json
)

# Optional imports for new modules (graceful degradation if not available)
try:
    from .dep_graph import (
        build_dependency_graph, get_vulnerability_reachability,
        extract_embedded_vulnerabilities, merge_embedded_with_scan,
        summarize_graph,
    )
except ImportError:
    build_dependency_graph = None

try:
    from .inplace_patcher import generate_inplace_patch, save_inplace_patch
except ImportError:
    generate_inplace_patch = None

try:
    from .vex_generator import apply_vex_suppression
except ImportError:
    apply_vex_suppression = None

try:
    from .supply_chain_scanner import scan_supply_chain, SupplyChainResult
except ImportError:
    scan_supply_chain = None
    SupplyChainResult = None

try:
    from .network_monitor import analyze_network_behavior, NetworkAnalysisResult
except ImportError:
    analyze_network_behavior = None
    NetworkAnalysisResult = None

try:
    from .threat_intel import update_feeds as update_threat_feeds
except ImportError:
    update_threat_feeds = None


@dataclass
class PatchStrategy:
    """A patching strategy to attempt."""
    name: str
    description: str
    patch_kwargs: dict  # kwargs to pass to patch_dockerfile


def _generate_fallback_strategies(
    original_dockerfile: str,
    sbom_before: dict,
    base_mapping: Optional[dict],
    patch_final_only: bool,
) -> list:
    """
    Generate a ranked list of patching strategies to try.

    If the primary strategy fails (e.g., Alpine build fails due to glibc),
    we try progressively safer alternatives.

    Strategy order:
    1. Primary: Full SBOM-driven patch (default behavior)
    2. Slim fallback: Force -slim variants instead of Alpine
    3. Same-OS upgrade: Stay on same OS family, just upgrade version
    """
    strategies = []

    # Strategy 1: Primary (default SBOM-driven)
    strategies.append(PatchStrategy(
        name="primary",
        description="SBOM-driven base image replacement",
        patch_kwargs={
            "sbom_before": sbom_before,
            "base_mapping": base_mapping,
            "patch_final_only": patch_final_only,
        }
    ))

    # Strategy 2: Force slim (no Alpine) via a base_mapping override
    # If the primary chose Alpine and it failed, try slim-bookworm variants
    slim_mapping = base_mapping.copy() if base_mapping else {}
    # We'll populate this dynamically after the first failure
    strategies.append(PatchStrategy(
        name="slim_fallback",
        description="Force slim Debian variants (avoid Alpine/musl)",
        patch_kwargs={
            "sbom_before": sbom_before,
            "base_mapping": slim_mapping,
            "patch_final_only": patch_final_only,
        }
    ))

    return strategies


class StepCounter:
    """Simple step counter for descriptive phase names."""
    def __init__(self):
        self.phase = None

    def set_phase(self, phase_name: str):
        self.phase = phase_name

    def log(self, message: str):
        if self.phase:
            return f"[{self.phase}] {message}"
        return message


def _sanitize_image_name(name: str) -> str:
    """
    Sanitize image name to only allow [a-zA-Z0-9._-].

    Args:
        name: Raw image name from Dockerfile

    Returns:
        Sanitized name safe for Docker commands
    """
    # Allow alphanumeric, dots, hyphens, and forward slashes (for registry paths).
    # Collapse multiple slashes and strip leading/trailing slashes to avoid
    # malformed image references like "//foo/" or "foo//bar".
    sanitized = re.sub(r'[^a-zA-Z0-9._/-]', '', name)
    sanitized = re.sub(r'/+', '/', sanitized).strip('/')
    if not sanitized:
        sanitized = "image"
    return sanitized[:128]  # Limit length


def _infer_os_from_base(image_ref: str) -> Optional[str]:
    """Infer OS family from a base image reference for migration detection."""
    lower = image_ref.lower()
    if "alpine" in lower:
        return "alpine"
    if any(x in lower for x in ["slim", "bookworm", "bullseye", "buster", "stretch"]):
        return "debian"
    if any(x in lower for x in ["ubuntu", "jammy", "focal", "noble"]):
        return "ubuntu"
    if "rocky" in lower:
        return "rocky"
    if "alma" in lower:
        return "alma"
    if "centos" in lower:
        return "centos"
    if "fedora" in lower:
        return "fedora"
    return None


def _validate_github_url(url: str) -> bool:
    """
    Validate GitHub URL format.

    Args:
        url: URL to validate

    Returns:
        True if valid HTTPS URL matching basic pattern, False otherwise
    """
    if not url.startswith("https://"):
        return False

    pattern = r'^https://[a-zA-Z0-9\-.]+/[a-zA-Z0-9\-_.]+/[a-zA-Z0-9\-_.]+'
    return bool(re.match(pattern, url))


def _clone_github_repo(repo_url: str) -> str:
    """
    Clone a GitHub repository to a temporary directory.

    Args:
        repo_url: GitHub URL (e.g., https://github.com/user/repo)

    Returns:
        Path to the cloned directory

    Raises:
        Exception on clone failure
    """
    temp_dir = tempfile.mkdtemp(prefix="autopatch-github-")
    logger.info(f"Cloning repository {repo_url} to {temp_dir}...")

    code, output = run_cmd(["git", "clone", repo_url, temp_dir])
    if code != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {output}")

    return temp_dir


def _find_dockerfile(repo_path: str) -> str:
    """
    Find Dockerfile in a directory (searches recursively).

    Args:
        repo_path: Directory path to search

    Returns:
        Path to Dockerfile

    Raises:
        FileNotFoundError if no Dockerfile found
    """
    # First check root
    root_dockerfile = os.path.join(repo_path, "Dockerfile")
    if os.path.exists(root_dockerfile):
        return root_dockerfile

    # Search recursively
    for root, dirs, files in os.walk(repo_path):
        if "Dockerfile" in files:
            return os.path.join(root, "Dockerfile")

    raise FileNotFoundError(f"No Dockerfile found in {repo_path}")


def _generate_json_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    signing_logs: list,
    supply_chain_result=None,
    network_result=None
) -> str:
    """Generate JSON format report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "base_image_changes": [{"original": o, "new": n} for o, n in base_changes],
        "vulnerabilities_before": before_summary,
        "vulnerabilities_after": after_summary,
        "resolved_vulnerabilities": vulns_diff["resolved"],
        "remaining_vulnerabilities": vulns_diff["remaining"],
        "new_vulnerabilities": vulns_diff["new"],
        "sbom_diff": sbom_diff,
        "metrics": metrics,
        "signing_operations": signing_logs
    }

    if supply_chain_result is not None:
        report["supply_chain_scan"] = {
            "overall_risk": supply_chain_result.overall_risk,
            "findings_count": len(supply_chain_result.findings),
            "findings": [
                {
                    "check": f.check_name,
                    "severity": f.severity,
                    "package": f.package_name,
                    "ecosystem": f.ecosystem,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.recommendation,
                }
                for f in supply_chain_result.findings
            ],
        }

    if network_result is not None:
        report["network_analysis"] = {
            "risk_score": network_result.risk_score,
            "overall_risk": network_result.overall_risk,
            "findings_count": len(network_result.findings),
            "findings": [
                {
                    "detector": f.detector,
                    "severity": f.severity,
                    "indicator": f.target,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in network_result.findings
            ],
            "dns_queries": len(network_result.network_profile.dns_queries) if network_result.network_profile else 0,
            "tcp_connections": len(network_result.network_profile.tcp_connections) if network_result.network_profile else 0,
        }

    return json.dumps(report, indent=2)


def _generate_markdown_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    acceptance_status: bool,
    acceptance_reasons: list,
    patched_dockerfile_path: Optional[str] = None,
    diff_text: Optional[str] = None,
    supply_chain_result=None,
    network_result=None
) -> str:
    """Generate Markdown format report."""
    lines = ["# AutoPatch Report\n"]

    lines.append(f"**Generated:** {datetime.now().isoformat()}\n")

    lines.append("## Summary\n")
    lines.append(f"- **Acceptance Status:** {'ACCEPTED' if acceptance_status else 'REJECTED'}\n")
    if acceptance_reasons:
        rejections = [r for r in acceptance_reasons if not r.startswith("[WARNING]")]
        warnings_list = [r.replace("[WARNING] ", "") for r in acceptance_reasons if r.startswith("[WARNING]")]
        if rejections:
            lines.append("- **Rejection Reasons:**\n")
            for reason in rejections:
                escaped_reason = html.escape(reason)
                lines.append(f"  - {escaped_reason}\n")
        if warnings_list:
            lines.append("- **Warnings:**\n")
            for warning in warnings_list:
                escaped_warning = html.escape(warning)
                lines.append(f"  - {escaped_warning}\n")

    lines.append("## Base Image Changes\n")
    if base_changes:
        for orig, new in base_changes:
            escaped_orig = html.escape(orig)
            escaped_new = html.escape(new)
            lines.append(f"- `{escaped_orig}` -> `{escaped_new}`\n")
    else:
        lines.append("- None\n")

    lines.append("## Vulnerabilities\n")
    lines.append(f"### Before: {before_summary.get('total', 0)} total\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in before_summary:
            lines.append(f"- {sev}: {before_summary[sev]}\n")

    lines.append(f"### After: {after_summary.get('total', 0)} total\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in after_summary:
            lines.append(f"- {sev}: {after_summary[sev]}\n")

    reduction = before_summary.get('total', 0) - after_summary.get('total', 0)
    reduction_pct = compute_reduction_percentage(
        before_summary.get('total', 0), after_summary.get('total', 0)
    )
    lines.append(f"### Reduction: {reduction} CVEs ({reduction_pct:.1f}%)\n")

    lines.append("## CVE Details\n")
    lines.append(f"### Resolved ({len(vulns_diff['resolved'])})\n")
    for v in vulns_diff["resolved"][:10]:
        escaped_id = html.escape(v['id'])
        escaped_pkg = html.escape(v['package'])
        lines.append(f"- {escaped_id} in {escaped_pkg}\n")
    if len(vulns_diff["resolved"]) > 10:
        lines.append(f"- ... and {len(vulns_diff['resolved']) - 10} more\n")

    lines.append(f"### Remaining ({len(vulns_diff['remaining'])})\n")
    for v in vulns_diff["remaining"][:5]:
        escaped_id = html.escape(v['id'])
        escaped_pkg = html.escape(v['package'])
        lines.append(f"- {escaped_id} in {escaped_pkg} ({v['severity']})\n")
    if len(vulns_diff["remaining"]) > 5:
        lines.append(f"- ... and {len(vulns_diff['remaining']) - 5} more\n")

    if vulns_diff["new"]:
        lines.append(f"### New ({len(vulns_diff['new'])})\n")
        for v in vulns_diff["new"][:5]:
            escaped_id = html.escape(v['id'])
            escaped_pkg = html.escape(v['package'])
            lines.append(f"- {escaped_id} in {escaped_pkg} ({v['severity']})\n")
        if len(vulns_diff["new"]) > 5:
            lines.append(f"- ... and {len(vulns_diff['new']) - 5} more\n")

    lines.append("## SBOM Changes\n")
    lines.append(f"- Added: {len(sbom_diff['added'])} components\n")
    lines.append(f"- Removed: {len(sbom_diff['removed'])} components\n")
    lines.append(f"- Updated: {len(sbom_diff['updated'])} components\n")

    if metrics:
        lines.append("## Metrics\n")
        lines.append(f"- Vulnerability Reduction: {metrics.get('vulnerability_reduction_pct', 0):.1f}%\n")
        lines.append(f"- CVE Resolution Rate: {metrics.get('cve_resolution_rate', 0):.1f}%\n")
        if 'build_time_seconds' in metrics:
            lines.append(f"- Build Time: {metrics['build_time_seconds']:.2f}s\n")
        if 'image_size_delta_mb' in metrics:
            lines.append(f"- Image Size Delta: {metrics['image_size_delta_mb']:+.2f}MB\n")

    if supply_chain_result is not None:
        lines.append("## Supply Chain Scan\n")
        lines.append(f"- **Overall Risk:** {supply_chain_result.overall_risk}\n")
        lines.append(f"- **Findings:** {len(supply_chain_result.findings)}\n")
        if supply_chain_result.findings:
            lines.append("\n| Severity | Check | Package | Description |\n")
            lines.append("|----------|-------|---------|-------------|\n")
            for f in supply_chain_result.findings:
                lines.append(
                    f"| {f.severity} | {html.escape(f.check_name)} | "
                    f"{html.escape(f.package_name or 'N/A')} | {html.escape(f.description)} |\n"
                )

    if network_result is not None:
        lines.append("## Network Behavior Analysis\n")
        lines.append(f"- **Risk Score:** {network_result.risk_score}/100\n")
        lines.append(f"- **Overall Risk:** {network_result.overall_risk}\n")
        lines.append(f"- **Findings:** {len(network_result.findings)}\n")
        if network_result.findings:
            lines.append("\n| Severity | Detector | Indicator | Description |\n")
            lines.append("|----------|----------|-----------|-------------|\n")
            for f in network_result.findings:
                lines.append(
                    f"| {f.severity} | {html.escape(f.detector)} | "
                    f"{html.escape(f.target)} | {html.escape(f.description)} |\n"
                )

    if diff_text:
        lines.append("## Dockerfile Changes\n")
        lines.append("```diff\n")
        lines.append(diff_text)
        lines.append("\n```\n")

    return "".join(lines)


def _generate_html_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    acceptance_status: bool,
    acceptance_reasons: list,
    supply_chain_result=None,
    network_result=None
) -> str:
    """Generate HTML format report with HTML escaping for all interpolated values."""
    html_lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<title>AutoPatch Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        "h1 { color: #333; }",
        "h2 { color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; }",
        ".summary { background: #f9f9f9; padding: 10px; border-left: 4px solid #007bff; }",
        ".accepted { color: green; font-weight: bold; }",
        ".rejected { color: red; font-weight: bold; }",
        ".metric { display: inline-block; margin: 10px 20px 10px 0; }",
        "table { border-collapse: collapse; width: 100%; margin: 10px 0; }",
        "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
        "th { background: #f0f0f0; }",
        ".critical { color: red; }",
        ".high { color: orange; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>AutoPatch Report</h1>",
        f"<p><strong>Generated:</strong> {html.escape(datetime.now().isoformat())}</p>",
    ]

    # Summary
    html_lines.append('<div class="summary">')
    status_class = "accepted" if acceptance_status else "rejected"
    status_text = "ACCEPTED" if acceptance_status else "REJECTED"
    html_lines.append(f'<p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>')
    if acceptance_reasons:
        rejections = [r for r in acceptance_reasons if not r.startswith("[WARNING]")]
        warnings_list = [r.replace("[WARNING] ", "") for r in acceptance_reasons if r.startswith("[WARNING]")]
        if rejections:
            html_lines.append("<p><strong>Rejection Reasons:</strong></p><ul>")
            for reason in rejections:
                escaped_reason = html.escape(reason)
                html_lines.append(f"<li>{escaped_reason}</li>")
            html_lines.append("</ul>")
        if warnings_list:
            html_lines.append('<p><strong>Warnings:</strong></p><ul style="color: #856404;">')
            for warning in warnings_list:
                escaped_warning = html.escape(warning)
                html_lines.append(f"<li>{escaped_warning}</li>")
            html_lines.append("</ul>")
    html_lines.append("</div>")

    # Base Changes
    html_lines.append("<h2>Base Image Changes</h2>")
    if base_changes:
        html_lines.append("<ul>")
        for orig, new in base_changes:
            escaped_orig = html.escape(orig)
            escaped_new = html.escape(new)
            html_lines.append(f"<li><code>{escaped_orig}</code> -> <code>{escaped_new}</code></li>")
        html_lines.append("</ul>")
    else:
        html_lines.append("<p>None</p>")

    # Vulnerabilities
    html_lines.append("<h2>Vulnerabilities</h2>")
    html_lines.append("<table>")
    html_lines.append("<tr><th>Severity</th><th>Before</th><th>After</th></tr>")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        before = before_summary.get(sev, 0)
        after = after_summary.get(sev, 0)
        sev_class = "critical" if sev == "CRITICAL" else "high" if sev == "HIGH" else ""
        html_lines.append(
            f'<tr><td class="{sev_class}"><strong>{sev}</strong></td>'
            f'<td>{before}</td><td>{after}</td></tr>'
        )
    html_lines.append("</table>")

    # CVE Summary
    total_before = before_summary.get('total', 0)
    total_after = after_summary.get('total', 0)
    reduction = total_before - total_after
    reduction_pct = compute_reduction_percentage(total_before, total_after)
    html_lines.append(
        f"<p><strong>Total Reduction:</strong> {reduction} CVEs ({reduction_pct:.1f}%)</p>"
    )

    # CVE Details
    html_lines.append("<h2>CVE Details</h2>")
    html_lines.append(f"<p><strong>Resolved:</strong> {len(vulns_diff['resolved'])}</p>")
    html_lines.append(f"<p><strong>Remaining:</strong> {len(vulns_diff['remaining'])}</p>")
    html_lines.append(f"<p><strong>New:</strong> {len(vulns_diff['new'])}</p>")

    # SBOM Changes
    html_lines.append("<h2>SBOM Changes</h2>")
    html_lines.append("<ul>")
    html_lines.append(f"<li>Added: {len(sbom_diff['added'])} components</li>")
    html_lines.append(f"<li>Removed: {len(sbom_diff['removed'])} components</li>")
    html_lines.append(f"<li>Updated: {len(sbom_diff['updated'])} components</li>")
    html_lines.append("</ul>")

    # Metrics
    if metrics:
        html_lines.append("<h2>Metrics</h2>")
        html_lines.append(f'<div class="metric">Vulnerability Reduction: <strong>{metrics.get("vulnerability_reduction_pct", 0):.1f}%</strong></div>')
        html_lines.append(f'<div class="metric">CVE Resolution Rate: <strong>{metrics.get("cve_resolution_rate", 0):.1f}%</strong></div>')
        if 'build_time_seconds' in metrics:
            html_lines.append(f'<div class="metric">Build Time: <strong>{metrics["build_time_seconds"]:.2f}s</strong></div>')
        if 'image_size_delta_mb' in metrics:
            sign = "+" if metrics['image_size_delta_mb'] >= 0 else ""
            html_lines.append(f'<div class="metric">Image Size Delta: <strong>{sign}{metrics["image_size_delta_mb"]:.2f}MB</strong></div>')

    if supply_chain_result is not None:
        html_lines.append("<h2>Supply Chain Scan</h2>")
        risk_color = "red" if supply_chain_result.overall_risk == "CRITICAL" else "orange" if supply_chain_result.overall_risk == "HIGH" else "#333"
        html_lines.append(f'<p><strong>Overall Risk:</strong> <span style="color:{risk_color};font-weight:bold;">{html.escape(supply_chain_result.overall_risk)}</span></p>')
        html_lines.append(f"<p><strong>Findings:</strong> {len(supply_chain_result.findings)}</p>")
        if supply_chain_result.findings:
            html_lines.append("<table><tr><th>Severity</th><th>Check</th><th>Package</th><th>Description</th><th>Remediation</th></tr>")
            for f in supply_chain_result.findings:
                sev_class = "critical" if f.severity == "CRITICAL" else "high" if f.severity == "HIGH" else ""
                html_lines.append(
                    f'<tr><td class="{sev_class}">{html.escape(f.severity)}</td>'
                    f"<td>{html.escape(f.check_name)}</td>"
                    f"<td>{html.escape(f.package_name or 'N/A')}</td>"
                    f"<td>{html.escape(f.description)}</td>"
                    f"<td>{html.escape(f.recommendation or '')}</td></tr>"
                )
            html_lines.append("</table>")

    if network_result is not None:
        html_lines.append("<h2>Network Behavior Analysis</h2>")
        net_color = "red" if network_result.risk_score >= 70 else "orange" if network_result.risk_score >= 40 else "green"
        html_lines.append(f'<p><strong>Risk Score:</strong> <span style="color:{net_color};font-weight:bold;">{network_result.risk_score}/100</span></p>')
        html_lines.append(f'<p><strong>Overall Risk:</strong> {html.escape(network_result.overall_risk)}</p>')
        html_lines.append(f"<p><strong>Findings:</strong> {len(network_result.findings)}</p>")
        if network_result.findings:
            html_lines.append("<table><tr><th>Severity</th><th>Detector</th><th>Indicator</th><th>Description</th></tr>")
            for f in network_result.findings:
                sev_class = "critical" if f.severity == "CRITICAL" else "high" if f.severity == "HIGH" else ""
                html_lines.append(
                    f'<tr><td class="{sev_class}">{html.escape(f.severity)}</td>'
                    f"<td>{html.escape(f.detector)}</td>"
                    f"<td>{html.escape(f.target)}</td>"
                    f"<td>{html.escape(f.description)}</td></tr>"
                )
            html_lines.append("</table>")

    html_lines.extend(["</body>", "</html>"])
    return "\n".join(html_lines)


def main():
    parser = argparse.ArgumentParser(description="Docker Image Auto-Patching Tool")

    # Required flags (one of these two)
    parser.add_argument("--dockerfile", help="Path to the Dockerfile to patch")
    parser.add_argument("--github-url", help="GitHub repository URL (auto-clones and finds Dockerfile)")

    # Registry and signing
    parser.add_argument("--registry", default="localhost:5000", help="Target registry (default: localhost:5000)")
    parser.add_argument(
        "--signing-mode", "--signing",
        choices=["keyless", "key-based", "key", "disabled", "none"],
        default="key",
        help="Signing mode: keyless, key-based/key (default), disabled/none"
    )
    parser.add_argument("--insecure-registry", action="store_true", default=False,
                       help="Allow insecure (HTTP) registry connections")

    # Patching options
    parser.add_argument("--base-mapping", help="JSON/YAML file with base image overrides")
    parser.add_argument("--patch-final-only", action="store_true", help="Only patch final stage")
    parser.add_argument("--accept-threshold",
                       choices=["strict", "moderate", "permissive"],
                       default="strict",
                       help="Acceptance criteria threshold (default: strict)")

    # Logging and output
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--dry-run", action="store_true", help="Generate patched Dockerfile but don't build/push/sign")
    parser.add_argument("--output-dir", default="./autopatch-output", help="Output directory for reports (default: ./autopatch-output)")
    parser.add_argument("--report-format",
                       choices=["json", "markdown", "html"],
                       default="json",
                       help="Report format (default: json)")
    parser.add_argument("--test-cmd", help="Command to test inside patched image")
    parser.add_argument("--smoke-test", action="store_true",
                       help="Run a lightweight smoke test after build to catch runtime crashes (musl/glibc, missing libs)")
    parser.add_argument("--app-patch", action="store_true",
                       help="Enable dependency-aware application-level package patching (pip/npm/gem/composer upgrades)")
    parser.add_argument("--app-patch-critical-only", action="store_true",
                       help="When --app-patch is enabled, only patch CRITICAL and HIGH severity packages")
    parser.add_argument("--ci-mode", action="store_true", help="Output GitHub Actions annotations and appropriate exit codes")

    # Scanner integrity and dual-scanner options
    parser.add_argument("--dual-scanner", action="store_true",
                       help="Enable dual-scanner mode (Trivy + Grype) for higher confidence")
    parser.add_argument("--scanner-checksums",
                       help="JSON file with scanner binary SHA256 checksums for supply chain verification")
    parser.add_argument("--strict-integrity", action="store_true",
                       help="Fail pipeline if scanner binary integrity verification fails")

    # Language override (D3)
    parser.add_argument("--language",
                       help="Override SBOM-detected language (e.g., python, node, golang)")
    parser.add_argument("--language-version",
                       help="Override SBOM-detected language version (e.g., 3.12, 22, 1.23)")

    # VEX and attestation
    parser.add_argument("--generate-vex", action="store_true",
                       help="Generate VEX documents (OpenVEX + CycloneDX) for resolved vulnerabilities")
    parser.add_argument("--generate-attestation", action="store_true",
                       help="Generate SLSA remediation attestation")

    # PR creation
    parser.add_argument("--create-pr", action="store_true",
                       help="Create a GitHub PR with the remediation changes (requires gh CLI)")
    parser.add_argument("--pr-base-branch", default="main",
                       help="Base branch for PR creation (default: main)")
    parser.add_argument("--pr-draft", action="store_true",
                       help="Create PR as draft")

    # In-place patching mode (J1)
    parser.add_argument("--inplace", action="store_true",
                       help="Use in-place patching instead of base image replacement")
    parser.add_argument("--inplace-tier", choices=["os", "app", "both"], default="both",
                       help="In-place patching tier: os, app, or both (default: both)")

    # Dependency graph analysis (B1-B2)
    parser.add_argument("--dep-graph", action="store_true",
                       help="Run dependency graph reachability analysis on SBOM")

    # VEX suppression (I3)
    parser.add_argument("--vex-suppress", nargs="*", metavar="VEX_FILE",
                       help="VEX file(s) to apply as suppression on rescan results")

    # Layer 2: Supply chain integrity scanning
    parser.add_argument("--supply-chain-scan", action="store_true",
                       help="Enable Layer 2 supply chain integrity scanning (phantom deps, .pth files, install scripts)")
    parser.add_argument("--min-package-age-days", type=int, default=7,
                       help="Minimum package age in days for npm age check (default: 7)")

    # Layer 5: Network behavior monitoring
    parser.add_argument("--network-monitor", action="store_true",
                       help="Enable Layer 5 network behavior analysis (C2 detection, DGA, beaconing)")
    parser.add_argument("--network-duration", type=int, default=60,
                       help="Network capture duration in seconds (default: 60)")
    parser.add_argument("--network-test-cmd",
                       help="Command to run inside container during network capture")
    parser.add_argument("--network-risk-threshold", type=int, default=50,
                       help="Network risk score threshold for rejection (0-100, default: 50)")
    parser.add_argument("--threat-intel-dir", default="~/.autopatch/threat_intel",
                       help="Directory for cached threat intelligence feeds")
    parser.add_argument("--allowed-ports",
                       help="Comma-separated list of allowed outbound ports")
    parser.add_argument("--update-threat-feeds", action="store_true",
                       help="Force-refresh threat intelligence feeds before analysis")

    # Backward compat aliases
    parser.add_argument("--output-file", help="[DEPRECATED] Use --output-dir instead")

    args = parser.parse_args()

    # Adjust logging level based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.INFO if args.report_format in ("markdown", "html") else logging.WARNING)

    # Normalize signing mode (handle aliases)
    signing_mode = args.signing_mode
    if signing_mode in ("key-based",):
        signing_mode = "key"
    elif signing_mode in ("disabled",):
        signing_mode = "none"

    # Handle backward compat flags
    report_format = args.report_format or "json"
    output_file = args.output_file

    # Resolve Dockerfile path
    dockerfile_path: Optional[str] = None
    temp_repo_dir: Optional[str] = None

    try:
        if args.github_url:
            if not _validate_github_url(args.github_url):
                logger.error("Invalid GitHub URL format. Must be a valid HTTPS URL (e.g., https://github.com/user/repo)")
                if args.ci_mode:
                    print("::error::Invalid GitHub URL format")
                return 1

            logger.info(f"Cloning GitHub repository: {args.github_url}")
            temp_repo_dir = _clone_github_repo(args.github_url)
            dockerfile_path = _find_dockerfile(temp_repo_dir)
            logger.info(f"Found Dockerfile at: {dockerfile_path}")
        elif args.dockerfile:
            dockerfile_path = args.dockerfile
        else:
            logger.error("Either --dockerfile or --github-url must be provided")
            if args.ci_mode:
                print("::error::Either --dockerfile or --github-url must be provided")
            return 1

        # Read original Dockerfile
        try:
            with open(dockerfile_path, "r", encoding="utf-8") as f:
                original_dockerfile = f.read()
        except Exception as e:
            logger.error(f"Could not read Dockerfile: {e}")
            if args.ci_mode:
                print(f"::error::Could not read Dockerfile: {e}")
            return 1

        # Create output directory
        output_dir = os.path.abspath(args.output_dir)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Output directory: {output_dir}")

        # Parse stages
        stages = parse_dockerfile_stages(original_dockerfile)
        if not stages:
            logger.error("No valid FROM line found in Dockerfile")
            if args.ci_mode:
                print("::error::No valid FROM line found in Dockerfile")
            return 1

        base_image_raw = stages[0]['base_name'].split("/")[-1].lower() or "image"
        base_image_name = _sanitize_image_name(base_image_raw)
        local_orig = f"{base_image_name}-orig"
        local_patched = f"{base_image_name}-patched"
        registry = args.registry.rstrip("/")
        registry_patched = f"{registry}/{base_image_name}-patched:latest"

        logger.info(f"Base image: {stages[0]['base_image']}")

        step = StepCounter()

        # ============================================================================
        # PHASE 1: INPUT
        # ============================================================================
        logger.info(step.log("Input validation complete"))

        # ============================================================================
        # PHASE 1.5: SCANNER INTEGRITY VERIFICATION
        # ============================================================================
        try:
            from .scanner_integrity import verify_all_scanners
            scanners_to_verify = ["trivy"]
            if getattr(args, 'dual_scanner', False):
                scanners_to_verify.append("grype")
            integrity_reports = verify_all_scanners(
                scanners=scanners_to_verify,
                strict=getattr(args, 'strict_integrity', False),
                checksums_file=getattr(args, 'scanner_checksums', None),
            )
            for name, report in integrity_reports.items():
                logger.info(
                    step.log(
                        f"Scanner integrity [{name}]: v{report.version_detected}, "
                        f"checks={report.checks_performed}, "
                        f"passed={'YES' if report.all_checks_passed else 'NO'}"
                    )
                )
                for w in report.warnings:
                    logger.warning(step.log(f"Scanner integrity warning: {w}"))
        except ImportError:
            logger.debug("Scanner integrity module not available, skipping")
        except Exception as e:
            logger.warning(step.log(f"Scanner integrity check failed: {e}"))
            if getattr(args, 'strict_integrity', False):
                return 1

        # ============================================================================
        # PHASE 2: SCAN ORIGINAL
        # ============================================================================

        # Build original image and capture build time
        step.set_phase("SCAN")
        logger.info(step.log("Building original image"))
        success, error_cat, build_time_orig = build_image(local_orig, dockerfile_path)

        if not success:
            logger.error(step.log(f"Failed to build original image ({error_cat})"))
            if args.ci_mode:
                print(f"::error::Failed to build original image: {error_cat}")
            return 1

        logger.info(step.log("Scanning original image for vulnerabilities"))
        try:
            before_scan = scan_image(local_orig, os.path.join(output_dir, "trivy-before.json"))
        except ScanError as e:
            logger.error(step.log(f"Scan failed: {e}"))
            if args.ci_mode:
                print(f"::error::Scan failed: {e}")
            return 1

        before_summary = summarize_vulnerabilities(before_scan)
        logger.info(step.log(f"Vulnerabilities BEFORE: {before_summary}"))

        logger.info(step.log("Generating SBOM for original image"))
        try:
            sbom_before = generate_sbom(local_orig, os.path.join(output_dir, "sbom-before.json"))
        except ScanError as e:
            logger.warning(step.log(f"SBOM generation failed (non-critical): {e}"))
            sbom_before = {}

        # ============================================================================
        # PHASE 3: INFER & PATCH
        # ============================================================================
        step.set_phase("PATCH")
        logger.info(step.log("Analyzing SBOM for OS, language, and compatibility"))
        inference = analyze_sbom(
            sbom_before,
            language_override=getattr(args, 'language', None),
            language_version_override=getattr(args, 'language_version', None),
        )

        # J1: In-place patching mode (alternative to base image replacement)
        if getattr(args, 'inplace', False):
            if generate_inplace_patch is None:
                logger.error(step.log("In-place patching module not available"))
                return 1

            logger.info(step.log(
                f"Using IN-PLACE patching mode (tier={args.inplace_tier})"
            ))
            inplace_result = generate_inplace_patch(
                original_image=local_orig,
                scan_result=before_scan,
                os_family=inference.os_family,
                sbom_data=sbom_before,
                tier=args.inplace_tier,
            )
            patch_path = save_inplace_patch(inplace_result, output_dir)
            if patch_path:
                logger.info(step.log(f"In-place patch Dockerfile saved to {patch_path}"))
            for w in inplace_result.warnings:
                logger.warning(step.log(f"In-place: {w}"))

            if args.dry_run:
                logger.info(step.log("Dry run mode: not building in-place patch"))
                return 0

            # Use the generated patch Dockerfile for the build phase
            patched_text = inplace_result.patch_dockerfile
            patched_dockerfile_path = os.path.join(output_dir, "Dockerfile.patched")
            try:
                with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                    f.write(patched_text)
            except Exception as e:
                logger.error(step.log(f"Failed to write in-place Dockerfile: {e}"))
                return 1

            base_changes = []
            patch_warnings = inplace_result.warnings
            diff_text = ""
            # In-place mode: skip the normal patching flow below

        else:
            # Normal mode: SBOM-driven base image replacement
            logger.info(
                step.log(
                    f"Inference result: OS={inference.os_family}, "
                    f"lang={inference.language}:{inference.language_version}, "
                    f"glibc_needed={inference.needs_glibc}, "
                    f"confidence={inference.confidence:.2f}"
                )
            )
            if inference.needs_glibc:
                logger.info(step.log("glibc dependency detected - will prefer -slim variants over Alpine"))

            logger.info(step.log("Patching Dockerfile using SBOM inference"))
            base_map = load_base_mapping(args.base_mapping) if args.base_mapping else None
            patched_text, base_changes, patch_warnings, diff_text = patch_dockerfile(
                original_dockerfile,
                sbom_before,
                base_mapping=base_map,
                patch_final_only=args.patch_final_only
            )

            for warning in patch_warnings:
                logger.warning(step.log(f"Patch warning: {warning}"))

            patched_dockerfile_path = os.path.join(output_dir, "Dockerfile.patched")
            try:
                with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                    f.write(patched_text)
                logger.info(step.log(f"Patched Dockerfile saved to {patched_dockerfile_path}"))
            except Exception as e:
                logger.error(step.log(f"Failed to write patched Dockerfile: {e}"))
                if args.ci_mode:
                    print(f"::error::Failed to write patched Dockerfile: {e}")
                return 1

        diff_path = os.path.join(output_dir, "dockerfile.diff")
        try:
            with open(diff_path, "w", encoding="utf-8") as f:
                f.write(diff_text)
        except Exception as e:
            logger.warning(step.log(f"Failed to save diff: {e}"))

        if base_changes:
            logger.info(step.log("Base image changes:"))
            for orig, new in base_changes:
                logger.info(step.log(f"  {orig} -> {new}"))

        # ============================================================================
        # PHASE 3b: APPLICATION-LEVEL PATCHING (optional, after base image patch)
        # ============================================================================
        app_patch_result = None
        if args.app_patch:
            step.set_phase("APP-PATCH")
            logger.info(step.log("Analyzing application-level vulnerabilities"))
            app_patch_result = plan_app_patches(
                scan_result=before_scan,
                sbom_data=sbom_before,
                dockerfile_text=patched_text,  # Patch on top of the base-image-patched Dockerfile
                build_context_path=os.path.dirname(os.path.abspath(dockerfile_path)),
                only_critical_high=args.app_patch_critical_only,
            )

            if app_patch_result.total_safe_upgrades > 0:
                logger.info(step.log(
                    f"Found {app_patch_result.total_safe_upgrades} safe app-level upgrades "
                    f"(skipping {app_patch_result.total_conflict_upgrades} conflicting)"
                ))
                # Apply the app-level patches to the Dockerfile
                from .app_patcher import generate_dockerfile_patch
                patched_text, app_commands, app_warnings = generate_dockerfile_patch(
                    patched_text, app_patch_result.upgrade_actions, only_safe=True
                )
                for w in app_warnings:
                    logger.warning(step.log(f"App patch: {w}"))

                # Re-save the patched Dockerfile with app-level upgrades
                try:
                    with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                        f.write(patched_text)
                    logger.info(step.log("Updated patched Dockerfile with app-level upgrades"))
                except Exception as e:
                    logger.error(step.log(f"Failed to update Dockerfile: {e}"))

                # Save app patch report
                app_report = format_app_patch_report(app_patch_result)
                app_report_path = os.path.join(output_dir, "app-patch-report.txt")
                try:
                    with open(app_report_path, "w") as f:
                        f.write(app_report)
                except Exception as e:
                    logger.warning(step.log(f"Failed to save app patch report: {e}"))

                # Save app patch JSON
                app_json = export_app_patch_json(app_patch_result)
                save_json(app_json, os.path.join(output_dir, "app-patch-results.json"))

            else:
                logger.info(step.log("No safe app-level upgrades identified"))
                for w in app_patch_result.warnings:
                    logger.info(step.log(f"  {w}"))

        # Dry-run check
        if args.dry_run:
            logger.info(step.log("DRY-RUN mode - skipping build, push, sign, and scan"))
            logger.info(step.log(f"Patched Dockerfile available at: {patched_dockerfile_path}"))

            report_text = _generate_markdown_report(
                {},
                base_changes,
                before_summary,
                {},
                {"resolved": [], "remaining": [], "new": []},
                {"added": [], "removed": [], "updated": []},
                True,
                [],
                patched_dockerfile_path,
                diff_text
            )
            report_file = os.path.join(output_dir, "report.md")
            with open(report_file, "w") as f:
                f.write(report_text)
            logger.info(step.log(f"Report saved to {report_file}"))
            return 0

        # ============================================================================
        # PHASE 4: BUILD PATCHED (with feedback loop)
        # ============================================================================
        step.set_phase("BUILD")

        max_build_attempts = 2
        build_success = False
        current_patched_text = patched_text
        current_base_changes = base_changes

        for attempt in range(1, max_build_attempts + 1):
            logger.info(step.log(f"Building patched image (attempt {attempt}/{max_build_attempts})"))
            success, error_cat, build_time_patched = build_image(local_patched, patched_dockerfile_path)

            if success:
                # Smoke test if enabled
                if args.smoke_test:
                    logger.info(step.log("Running smoke test on patched image"))
                    smoke_passed, smoke_msg = smoke_test_image(local_patched)
                    if not smoke_passed:
                        logger.warning(step.log(f"Smoke test FAILED: {smoke_msg}"))
                        success = False
                        error_cat = "SMOKE_TEST_FAILED"
                    else:
                        logger.info(step.log(f"Smoke test passed: {smoke_msg}"))

                # Test command if provided
                if success and args.test_cmd:
                    logger.info(step.log(f"Running test command: {args.test_cmd}"))
                    code, output = run_cmd(["docker", "run", "--rm", "--entrypoint", "", local_patched, "sh", "-c", args.test_cmd])
                    if code != 0:
                        logger.warning(step.log(f"Test command failed: {output}"))
                        success = False
                        error_cat = "TEST_CMD_FAILED"
                    else:
                        logger.info(step.log("Test command passed"))

            if success:
                build_success = True
                break

            # Build or test failed -- try fallback strategy
            if attempt < max_build_attempts:
                logger.warning(step.log(
                    f"Build attempt {attempt} failed ({error_cat}). "
                    f"Applying fallback strategy: force slim variants..."
                ))

                # Clean up failed image
                run_cmd(["docker", "rmi", "-f", local_patched])

                # Generate slim fallback: replace Alpine tags with slim equivalents
                slim_overrides = {}
                for orig, new in current_base_changes:
                    if "alpine" in new.lower():
                        slim_new = new.replace("-alpine", "-slim").replace(":alpine", ":slim-bookworm")
                        if slim_new == new:
                            # Handle cases like "alpine:3.21" -> "debian:bookworm-slim"
                            slim_new = "debian:bookworm-slim"
                        slim_overrides[orig] = slim_new
                        logger.info(step.log(f"  Fallback: {new} -> {slim_new}"))

                if slim_overrides:
                    merged_mapping = base_map.copy() if base_map else {}
                    merged_mapping.update(slim_overrides)

                    current_patched_text, current_base_changes, retry_warnings, diff_text = patch_dockerfile(
                        original_dockerfile,
                        sbom_before,
                        base_mapping=merged_mapping,
                        patch_final_only=args.patch_final_only
                    )

                    # Also attempt package manager migration if OS changed
                    for orig, new in current_base_changes:
                        from_os = _infer_os_from_base(orig)
                        to_os = _infer_os_from_base(new)
                        if from_os and to_os and from_os != to_os:
                            try:
                                current_patched_text, migration_changes, migration_warnings = migrate_package_commands(
                                    current_patched_text, from_os, to_os
                                )
                                for w in migration_warnings:
                                    logger.warning(step.log(f"Migration: {w}"))
                            except Exception as e:
                                logger.warning(step.log(f"Package migration skipped: {e}"))

                    for w in retry_warnings:
                        logger.warning(step.log(f"Retry patch warning: {w}"))
                    patch_warnings.extend(retry_warnings)
                    base_changes = current_base_changes

                    try:
                        with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                            f.write(current_patched_text)
                    except Exception as e:
                        logger.error(step.log(f"Failed to write fallback Dockerfile: {e}"))
                        break
                else:
                    logger.error(step.log("No Alpine-based images to fall back from. Cannot retry."))
                    break

        if not build_success:
            logger.error(step.log(f"All {max_build_attempts} build attempts failed"))
            if args.ci_mode:
                print(f"::error::All build attempts failed. Last error: {error_cat}")
            return 1

        # ============================================================================
        # PHASE 4b: SUPPLY CHAIN SCAN (optional, Layer 2)
        # ============================================================================
        supply_chain_result = None
        if getattr(args, 'supply_chain_scan', False):
            if scan_supply_chain is None:
                logger.warning("Supply chain scanner module not available, skipping")
            else:
                step.set_phase("SUPPLY-CHAIN")
                logger.info(step.log("Running supply chain integrity scan"))

                supply_chain_result = scan_supply_chain(
                    image_name=local_patched,
                    dockerfile_path=dockerfile_path,
                    output_dir=output_dir,
                    previous_lockfiles=None,
                    min_package_age_days=getattr(args, 'min_package_age_days', 7),
                )

                logger.info(step.log(
                    f"Supply chain scan: {len(supply_chain_result.findings)} findings, "
                    f"risk={supply_chain_result.overall_risk}"
                ))
                for finding in supply_chain_result.findings:
                    log_fn = logger.error if finding.severity == "CRITICAL" else logger.warning
                    log_fn(step.log(
                        f"  [{finding.severity}] {finding.check_name}: "
                        f"{finding.package_name} - {finding.description}"
                    ))

                # Reject immediately on CRITICAL supply chain findings
                if supply_chain_result.overall_risk == "CRITICAL":
                    logger.error(step.log(
                        "SUPPLY CHAIN CHECK FAILED: CRITICAL findings detected. "
                        "Image rejected before vulnerability evaluation."
                    ))
                    if args.ci_mode:
                        print("::error::Supply chain integrity check failed with CRITICAL findings")
                    run_cmd(["docker", "rmi", "-f", local_orig])
                    run_cmd(["docker", "rmi", "-f", local_patched])
                    return 1

        # ============================================================================
        # PHASE 4c: NETWORK BEHAVIOR ANALYSIS (optional, Layer 5)
        # ============================================================================
        network_result = None
        if getattr(args, 'network_monitor', False):
            if analyze_network_behavior is None:
                logger.warning("Network monitor module not available, skipping")
            else:
                step.set_phase("NETWORK")

                # Update threat feeds if requested
                if getattr(args, 'update_threat_feeds', False) and update_threat_feeds is not None:
                    logger.info(step.log("Updating threat intelligence feeds"))
                    update_threat_feeds(
                        getattr(args, 'threat_intel_dir', '~/.autopatch/threat_intel'),
                        force=True,
                    )

                # Parse allowed ports
                allowed_ports_list = None
                if getattr(args, 'allowed_ports', None):
                    try:
                        allowed_ports_list = [int(p.strip()) for p in args.allowed_ports.split(",")]
                    except ValueError:
                        logger.warning("Invalid --allowed-ports format, using defaults")

                logger.info(step.log(
                    f"Running network behavior analysis "
                    f"(duration={getattr(args, 'network_duration', 60)}s)"
                ))

                network_result = analyze_network_behavior(
                    image_name=local_patched,
                    dockerfile_path=dockerfile_path,
                    output_dir=output_dir,
                    duration_seconds=getattr(args, 'network_duration', 60),
                    test_cmd=getattr(args, 'network_test_cmd', None),
                    threat_intel_dir=getattr(args, 'threat_intel_dir', '~/.autopatch/threat_intel'),
                    allowed_ports=allowed_ports_list,
                )

                logger.info(step.log(
                    f"Network analysis: risk_score={network_result.risk_score}, "
                    f"overall={network_result.overall_risk}, "
                    f"{len(network_result.findings)} findings"
                ))
                for finding in network_result.findings:
                    log_fn = logger.error if finding.severity == "CRITICAL" else logger.warning
                    log_fn(step.log(
                        f"  [{finding.severity}] {finding.detector}: "
                        f"{finding.target} - {finding.description}"
                    ))

                # Reject if risk exceeds threshold
                threshold = getattr(args, 'network_risk_threshold', 50)
                if network_result.risk_score > threshold:
                    logger.error(step.log(
                        f"NETWORK CHECK FAILED: risk_score={network_result.risk_score} "
                        f"exceeds threshold={threshold}. Image rejected."
                    ))
                    if args.ci_mode:
                        print(
                            f"::error::Network behavior analysis detected C2 indicators "
                            f"(risk_score={network_result.risk_score})"
                        )
                    run_cmd(["docker", "rmi", "-f", local_orig])
                    run_cmd(["docker", "rmi", "-f", local_patched])
                    return 1

        # ============================================================================
        # PHASE 5: EVALUATE (scan locally, check acceptance, NO push yet)
        # ============================================================================
        step.set_phase("EVAL")
        logger.info(step.log("Scanning patched image locally for vulnerabilities"))
        try:
            after_scan = scan_image(local_patched, os.path.join(output_dir, "trivy-after.json"))
        except ScanError as e:
            logger.error(step.log(f"Scan failed: {e}"))
            if args.ci_mode:
                print(f"::error::Scan of patched image failed: {e}")
            return 1

        after_summary = summarize_vulnerabilities(after_scan)
        logger.info(step.log(f"Vulnerabilities AFTER: {after_summary}"))

        # I3: Apply VEX suppression to rescan results if VEX files provided
        if getattr(args, 'vex_suppress', None) and apply_vex_suppression is not None:
            logger.info(step.log(f"Applying VEX suppression from {len(args.vex_suppress)} file(s)"))
            after_scan = apply_vex_suppression(after_scan, vex_paths=args.vex_suppress)
            after_summary = summarize_vulnerabilities(after_scan)
            logger.info(step.log(f"Vulnerabilities AFTER (VEX-filtered): {after_summary}"))

        logger.info(step.log("Generating SBOM for patched image"))
        try:
            sbom_after = generate_sbom(local_patched, os.path.join(output_dir, "sbom-after.json"))
        except ScanError as e:
            logger.warning(step.log(f"SBOM generation failed (non-critical): {e}"))
            sbom_after = {}

        # B1-B2: Dependency graph analysis (optional)
        dep_graph_summary = None
        if getattr(args, 'dep_graph', False) and build_dependency_graph is not None:
            logger.info(step.log("Building dependency graph from post-patch SBOM"))
            graph = build_dependency_graph(sbom_after)
            dep_graph_summary = summarize_graph(graph)
            save_json(dep_graph_summary, os.path.join(output_dir, "dep-graph-summary.json"))
            logger.info(step.log(
                f"Dependency graph: {graph.reachable_count} reachable, "
                f"{graph.unreachable_count} unreachable, max depth {graph.max_depth}"
            ))

            # Also extract and merge embedded SBOM vulnerabilities
            embedded_vulns = extract_embedded_vulnerabilities(sbom_after)
            if embedded_vulns:
                logger.info(step.log(f"Found {len(embedded_vulns)} embedded SBOM vulnerabilities"))

        logger.info(step.log("Checking acceptance criteria"))
        accepted, acceptance_reasons = check_acceptance_criteria(
            before_scan, after_scan, threshold=args.accept_threshold
        )
        if accepted:
            logger.info(step.log("ACCEPTANCE CHECK PASSED"))
        else:
            logger.error(step.log("ACCEPTANCE CHECK FAILED"))
            for reason in acceptance_reasons:
                logger.error(step.log(f"  - {reason}"))
            if args.ci_mode:
                for reason in acceptance_reasons:
                    print(f"::error::{reason}")

            # Rejected: cleanup and exit without pushing
            logger.info(step.log("Cleanup (rejected)"))
            run_cmd(["docker", "rmi", "-f", local_orig])
            run_cmd(["docker", "rmi", "-f", local_patched])
            logger.info(step.log("Pipeline failed acceptance check. Not pushing or signing."))
            return 1

        logger.info(step.log("Computing metrics"))
        vulns_diff = diff_vulnerabilities(before_scan, after_scan)
        sbom_diff = diff_sbom(sbom_before or {}, sbom_after or {})

        before_size = measure_image_size(local_orig)
        after_size = measure_image_size(local_patched)

        metrics = compute_metrics(
            before_scan, after_scan,
            sbom_before or {}, sbom_after or {},
            before_size=before_size,
            after_size=after_size,
            build_time=build_time_patched
        )

        # Enrich metrics with supply chain and network results
        if supply_chain_result is not None:
            metrics["supply_chain_findings_count"] = len(supply_chain_result.findings)
            metrics["supply_chain_critical_count"] = sum(
                1 for f in supply_chain_result.findings if f.severity == "CRITICAL"
            )
            metrics["supply_chain_risk"] = supply_chain_result.overall_risk
        if network_result is not None:
            metrics["network_risk_score"] = network_result.risk_score
            metrics["network_findings_count"] = len(network_result.findings)
            metrics["network_overall_risk"] = network_result.overall_risk

        # ============================================================================
        # PHASE 6: PUBLISH (only if accepted)
        # ============================================================================
        step.set_phase("PUSH")
        logger.info(step.log("Tagging and pushing patched image to registry"))
        if not tag_image(local_patched, registry_patched):
            logger.error(step.log("Failed to tag image"))
            if args.ci_mode:
                print("::error::Failed to tag image")
            return 1

        if not push_image(registry_patched, insecure_registry=args.insecure_registry):
            logger.error(step.log("Failed to push image"))
            if args.ci_mode:
                print("::error::Failed to push image")
            return 1

        logger.info(step.log("Retrieving image digest from local image"))
        digest_ref = get_image_digest(local_patched)
        if not digest_ref:
            logger.error(step.log("Could not retrieve image digest"))
            if args.ci_mode:
                print("::error::Could not retrieve image digest")
            return 1
        logger.info(step.log(f"Image digest: {digest_ref}"))

        # Sign and verify
        step.set_phase("SIGN")
        if signing_mode != "none":
            logger.info(step.log(f"Signing image ({signing_mode})"))
            try:
                sign_image(digest_ref, signing_mode, insecure_registry=args.insecure_registry)
                verify_image(digest_ref, signing_mode, insecure_registry=args.insecure_registry)
                logger.info(step.log("Image signed and verified"))
            except (SigningError, VerificationError) as e:
                logger.error(step.log(f"Signing/verification failed: {e}"))
                if args.ci_mode:
                    print(f"::error::Signing failed: {e}")
                return 1

        # Attach SBOM
        if sbom_after and signing_mode != "none":
            logger.info(step.log("Attaching SBOM to image"))
            try:
                attach_sbom(digest_ref, os.path.join(output_dir, "sbom-after.json"), signing_mode, insecure_registry=args.insecure_registry)
                logger.info(step.log("SBOM attached"))
            except Exception as e:
                logger.warning(step.log(f"SBOM attachment failed (non-critical): {e}"))

        # ============================================================================
        # PHASE 7: REPORT
        # ============================================================================
        step.set_phase("REPORT")
        logger.info(step.log("Generating report"))
        if report_format == "json":
            report_text = _generate_json_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, get_signing_log(),
                supply_chain_result=supply_chain_result,
                network_result=network_result
            )
        elif report_format == "markdown":
            report_text = _generate_markdown_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, accepted, acceptance_reasons,
                patched_dockerfile_path, diff_text,
                supply_chain_result=supply_chain_result,
                network_result=network_result
            )
        else:  # html
            report_text = _generate_html_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, accepted, acceptance_reasons,
                supply_chain_result=supply_chain_result,
                network_result=network_result
            )

        logger.info(step.log("Exporting reports"))
        report_ext = {"json": "json", "markdown": "md", "html": "html"}[report_format]
        report_file = os.path.join(output_dir, f"report.{report_ext}")
        try:
            with open(report_file, "w") as f:
                f.write(report_text)
            logger.info(step.log(f"Report saved to {report_file}"))
        except Exception as e:
            logger.error(step.log(f"Failed to save report: {e}"))

        # Print report to stdout
        print(report_text)

        logger.info(step.log("Exporting metrics"))
        metrics_json = os.path.join(output_dir, "metrics.json")
        metrics_csv = os.path.join(output_dir, "metrics.csv")

        try:
            save_json(metrics, metrics_json)
            save_csv([metrics], metrics_csv)
            logger.info(step.log(f"Metrics saved to {metrics_json} and {metrics_csv}"))
        except Exception as e:
            logger.warning(step.log(f"Failed to save metrics: {e}"))

        # Output GitHub Actions annotations if in CI mode
        if args.ci_mode:
            logger.info(step.log("Outputting GitHub Actions annotations"))
            print(f"::notice::Patched image accepted. Vulnerabilities reduced by {metrics.get('vulnerability_reduction_pct', 0):.1f}%")

        # ============================================================================
        # PHASE 8: VEX GENERATION (optional)
        # ============================================================================
        if getattr(args, 'generate_vex', False):
            step.set_phase("VEX")
            logger.info(step.log("Generating VEX documents"))
            try:
                from .vex_generator import (
                    build_vex_statements_from_diff, generate_openvex,
                    generate_cyclonedx_vex
                )
                base_change_desc = " -> ".join([f"{o} -> {n}" for o, n in base_changes]) if base_changes else ""
                vex_statements = build_vex_statements_from_diff(
                    vulns_diff, base_image_change=base_change_desc
                )
                # OpenVEX
                openvex_path = os.path.join(output_dir, "autopatch.openvex.json")
                generate_openvex(
                    product_id=local_patched,
                    product_name=local_patched,
                    statements=vex_statements,
                    output_path=openvex_path,
                )
                logger.info(step.log(f"OpenVEX document saved to {openvex_path}"))

                # CycloneDX VEX
                cdx_vex_path = os.path.join(output_dir, "sbom-after-vex.json")
                sbom_after_path = os.path.join(output_dir, "sbom-after.json")
                if os.path.exists(sbom_after_path):
                    from .utils import load_json as _load_json
                    sbom_after = _load_json(sbom_after_path)
                    generate_cyclonedx_vex(sbom_after, vex_statements, output_path=cdx_vex_path)
                    logger.info(step.log(f"CycloneDX VEX saved to {cdx_vex_path}"))
            except Exception as e:
                logger.warning(step.log(f"VEX generation failed (non-critical): {e}"))

        # ============================================================================
        # PHASE 9: ATTESTATION (optional)
        # ============================================================================
        if getattr(args, 'generate_attestation', False):
            step.set_phase("ATTEST")
            logger.info(step.log("Generating remediation attestation"))
            try:
                from .vex_generator import generate_remediation_attestation
                orig_base_str = base_changes[0][0] if base_changes else ""
                new_base_str = base_changes[0][1] if base_changes else ""
                attestation_path = os.path.join(output_dir, "remediation-attestation.json")
                generate_remediation_attestation(
                    image_ref=local_patched,
                    original_base=orig_base_str,
                    patched_base=new_base_str,
                    vuln_diff=vulns_diff,
                    metrics=metrics,
                    output_path=attestation_path,
                )
                logger.info(step.log(f"Attestation saved to {attestation_path}"))
            except Exception as e:
                logger.warning(step.log(f"Attestation generation failed (non-critical): {e}"))

        # ============================================================================
        # PHASE 10: PR CREATION (optional)
        # ============================================================================
        if getattr(args, 'create_pr', False):
            step.set_phase("PR")
            logger.info(step.log("Creating remediation pull request"))
            try:
                from .pr_creator import create_remediation_pr
                pr_url = create_remediation_pr(
                    dockerfile_path=dockerfile_path,
                    original_base=base_changes[0][0] if base_changes else "",
                    patched_base=base_changes[0][1] if base_changes else "",
                    metrics=metrics,
                    vuln_diff=vulns_diff,
                    original_dockerfile=original_dockerfile,
                    patched_dockerfile=patched_text,
                    acceptance_result=(accepted, acceptance_reasons),
                    base_branch=getattr(args, 'pr_base_branch', 'main'),
                    draft=getattr(args, 'pr_draft', False),
                )
                if pr_url:
                    logger.info(step.log(f"Pull request created: {pr_url}"))
                else:
                    logger.warning(step.log("PR creation skipped or failed"))
            except Exception as e:
                logger.warning(step.log(f"PR creation failed (non-critical): {e}"))

        logger.info(step.log("Cleanup"))
        run_cmd(["docker", "rmi", "-f", local_orig])
        run_cmd(["docker", "rmi", "-f", local_patched])

        logger.info(step.log("Pipeline complete"))
        logger.info(step.log(f"All artifacts saved to: {output_dir}"))

        return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        if args.ci_mode:
            print(f"::error::Unexpected error: {e}")
        return 1

    finally:
        # Cleanup temp repo if cloned
        if temp_repo_dir and os.path.exists(temp_repo_dir):
            logger.debug(f"Cleaning up temporary directory: {temp_repo_dir}")
            shutil.rmtree(temp_repo_dir, ignore_errors=True)


if __name__ == "__main__":
    exit(main())
