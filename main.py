import argparse
import logging
import json

# Configure the logger (console output format)
logger = logging.getLogger("docker_patch_tool")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Import functions from other modules
from .utils import run_cmd, load_base_mapping
from .parser import parse_dockerfile_stages
from .builder import build_image, tag_image, push_image
from .scanner import scan_image, generate_sbom, summarize_vulnerabilities
from .patcher import patch_dockerfile
from .signer import sign_image, verify_image
from .comparer import diff_vulnerabilities, diff_sbom  # (and compare if needed)

def main():
    parser = argparse.ArgumentParser(description="Docker Image Auto-Patching Tool")
    parser.add_argument("--dockerfile", required=True, help="Path to the Dockerfile to patch")
    parser.add_argument("--registry", default="localhost:5000", help="Target registry for the patched image (default: localhost:5000)")
    parser.add_argument("--signing", choices=["none", "key", "keyless"], default="key",
                        help="Signing mode for the patched image: 'none' (no signing), 'key' (local key), or 'keyless' (Sigstore OIDC)")
    parser.add_argument("--patch-final-only", action="store_true", help="Only patch the final stage (skip patching intermediate build stages)")
    parser.add_argument("--base-mapping", help="Path to a JSON/YAML file specifying base image overrides (original -> new base image)")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text",
                        help="Output format for the summary report (text, json, or html)")
    parser.add_argument("--output-file", help="Optional file path to write the summary report")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity (use -vv for debug-level logs)")
    parser.add_argument("--test-cmd", help="Optional shell command to run inside the patched image to test functionality")
    args = parser.parse_args()

    # Adjust logging level based on verbosity and output format
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        # For JSON output, show only warnings/errors by default to keep output clean
        logger.setLevel(logging.INFO if args.format in ("text", "html") else logging.WARNING)

    dockerfile_path = args.dockerfile
    # Read the original Dockerfile content
    try:
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            original_dockerfile = f.read()
    except Exception as e:
        logger.error(f"Could not read Dockerfile at {dockerfile_path}: {e}")
        return 1

    # Determine base image name from the first FROM line
    stages = parse_dockerfile_stages(original_dockerfile)
    if not stages:
        logger.error("No valid FROM line found in Dockerfile.")
        return 1
    base_image_name = stages[0]['base_name'].split("/")[-1].lower() or "image"
    local_orig = f"{base_image_name}-orig"
    local_patched = f"{base_image_name}-patched"
    registry = args.registry.rstrip("/")
    registry_patched = f"{registry}/{base_image_name}-patched:latest"

    logger.info(f"Base image identified: {stages[0]['base_image']} -> will tag as '{base_image_name}'")

    # Build the original image
    if not build_image(local_orig, dockerfile_path):
        return 1

    # Scan original image for vulnerabilities and summarize
    before_scan = scan_image(local_orig, "trivy_before.json")
    before_summary = summarize_vulnerabilities(before_scan)
    logger.info(f"Vulnerabilities BEFORE patching: {before_summary}")
    # Generate SBOM for original image (for OS detection and diff)
    sbom_before = generate_sbom(local_orig, "sbom_before.json")

    # Patch the Dockerfile content
    base_map = load_base_mapping(args.base_mapping) if args.base_mapping else None
    patched_text, base_changes = patch_dockerfile(original_dockerfile, sbom_before, base_mapping=base_map, patch_final_only=args.patch_final_only)
    # Save patched Dockerfile to a new file
    patched_dockerfile_path = "Dockerfile.patched"
    try:
        with open(patched_dockerfile_path, "w", encoding="utf-8") as pf:
            pf.write(patched_text)
    except Exception as e:
        logger.error(f"Failed to write patched Dockerfile: {e}")
        return 1
    if base_changes:
        logger.info("Base image replacements:")
        for old, new in base_changes:
            logger.info(f"  {old} -> {new}")
    else:
        logger.info("No base image changes were made in the patch.")

    # Build the patched image
    if not build_image(local_patched, patched_dockerfile_path):
        return 1

    # If a test command is provided, run it inside the patched image container
    if args.test_cmd:
        logger.info(f"Running test command in patched image: {args.test_cmd}")
        test_cmd = ["docker", "run", "--rm", "--entrypoint", "", local_patched, "sh", "-c", args.test_cmd]
        code, output = run_cmd(test_cmd)
        if code != 0:
            logger.error(f"Test command failed in patched image (exit code {code}):\n{output}")
        else:
            logger.info("Test command succeeded in patched image.")
            logger.debug(f"Test output:\n{output}")

    # Tag and push the patched image to the registry
    if not tag_image(local_patched, registry_patched):
        return 1
    if not push_image(registry_patched):
        return 1

    # Remove local patched image to force using registry image for digest
    run_cmd(["docker", "rmi", "-f", local_patched])
    # Pull the image from registry to get the canonical digest reference
    logger.info("Pulling patched image from registry to obtain digest ...")
    code, output = run_cmd(["docker", "pull", registry_patched])
    if code != 0:
        logger.error(f"Failed to pull image from registry:\n{output}")
        return 1
    # Inspect image to get its digest (e.g., name@sha256:...)
    code, digest_out = run_cmd(["docker", "inspect", "--format={{index .RepoDigests 0}}", registry_patched])
    if code != 0 or "@" not in digest_out:
        logger.error(f"Docker inspect failed to retrieve image digest:\n{digest_out}")
        return 1
    digest_ref = digest_out.strip()
    logger.info(f"Patched image digest reference: {digest_ref}")

    # Sign the image if requested
    if args.signing != "none":
        if not sign_image(digest_ref, args.signing):
            return 1
        if not verify_image(digest_ref, args.signing):
            return 1

    # Optionally attach SBOM to the image in the registry (if signing was used)
    sbom_after = generate_sbom(registry_patched, "sbom_after.json")
    if sbom_after and args.signing != "none":
        logger.info("Attaching SBOM to image in registry ...")
        env = {"COSIGN_EXPERIMENTAL": "1"} if args.signing == "keyless" else {}
        attach_cmd = [
            "cosign", "attach", "sbom",
            "--allow-insecure-registry",
            "--sbom", "sbom_after.json",
            "--type", "cyclonedx",
            digest_ref
        ]
        code, output = run_cmd(attach_cmd, env_override=env)
        if code != 0:
            logger.error(f"SBOM attach failed (non-critical):\n{output}")
        else:
            logger.info("SBOM attached to image in registry.")

    # Scan the patched image (from registry) for vulnerabilities
    after_scan = scan_image(registry_patched, "trivy_after.json")
    after_summary = summarize_vulnerabilities(after_scan)
    logger.info(f"Vulnerabilities AFTER patching: {after_summary}")

    # Compute vulnerability and SBOM differences
    vulns_diff = diff_vulnerabilities(before_scan, after_scan)
    sbom_diff = diff_sbom(sbom_before or {}, sbom_after or {})

    # Prepare a summary report object
    report = {
        "base_image_changes": [ {"original": o, "new": n} for (o, n) in base_changes ],
        "vulnerabilities_before": before_summary,
        "vulnerabilities_after": after_summary,
        "cve_resolved": [f"{v['id']} in {v['package']} (was {v['version']}, fix: {v['fix_version'] or 'n/a'})"
                          for v in vulns_diff["resolved"]],
        "cve_remaining": [f"{v['id']} in {v['package']} (still {v['version']}, severity {v['severity']})"
                          for v in vulns_diff["remaining"]],
        "cve_new": [f"{v['id']} in {v['package']} (introduced, severity {v['severity']})"
                    for v in vulns_diff["new"]],
        "sbom_diff": {
            "added": [f"{comp['name']} ({comp['type']}) {comp['new_version']}" for comp in sbom_diff["added"]],
            "removed": [f"{comp['name']} ({comp['type']}) {comp['old_version']}" for comp in sbom_diff["removed"]],
            "updated": [f"{comp['name']} ({comp['type']}) {comp['old_version']} -> {comp['new_version']}"
                        for comp in sbom_diff["updated"]]
        }
    }

    # Output the summary in the requested format
    if args.format == "json":
        output_data = {
            "base_image_changes": report["base_image_changes"],
            "vulnerabilities_before": before_summary,
            "vulnerabilities_after": after_summary,
            "resolved_vulnerabilities": vulns_diff["resolved"],
            "remaining_vulnerabilities": vulns_diff["remaining"],
            "new_vulnerabilities": vulns_diff["new"],
            "sbom_diff": sbom_diff
        }
        output_json = json.dumps(output_data, indent=2)
        if args.output_file:
            try:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    f.write(output_json)
                logger.info(f"JSON report written to {args.output_file}")
            except Exception as e:
                logger.error(f"Failed to write JSON report to file: {e}")
        # Print JSON to stdout
        print(output_json)

    elif args.format == "html":
        # Generate a simple HTML summary report
        html_lines = []
        html_lines.append("<h1>Docker Image Patching Summary</h1>")
        html_lines.append("<h2>Base Image Changes</h2>")
        if report["base_image_changes"]:
            html_lines.append("<ul>")
            for change in report["base_image_changes"]:
                html_lines.append(f"<li>{change['original']} → {change['new']}</li>")
            html_lines.append("</ul>")
        else:
            html_lines.append("<p>No base image changes.</p>")
        html_lines.append("<h2>Vulnerability Summary</h2>")
        html_lines.append(f"<p><strong>Before:</strong> {before_summary}</p>")
        html_lines.append(f"<p><strong>After:</strong> {after_summary}</p>")
        html_lines.append("<h3>Resolved CVEs</h3>")
        if report["cve_resolved"]:
            html_lines.append("<ul>")
            for item in report["cve_resolved"]:
                html_lines.append(f"<li>{item}</li>")
            html_lines.append("</ul>")
        else:
            html_lines.append("<p>None</p>")
        html_lines.append("<h3>Remaining CVEs</h3>")
        if report["cve_remaining"]:
            html_lines.append("<ul>")
            for item in report["cve_remaining"]:
                html_lines.append(f"<li>{item}</li>")
            html_lines.append("</ul>")
        else:
            html_lines.append("<p>None</p>")
        if report["cve_new"]:
            html_lines.append("<h3>Newly Introduced CVEs</h3><ul>")
            for item in report["cve_new"]:
                html_lines.append(f"<li>{item}</li>")
            html_lines.append("</ul>")
        html_lines.append("<h3>SBOM Differences</h3>")
        html_lines.append("<ul>")
        html_lines.append(f"<li><strong>Added:</strong> {len(sbom_diff['added'])} packages</li>")
        html_lines.append(f"<li><strong>Removed:</strong> {len(sbom_diff['removed'])} packages</li>")
        html_lines.append(f"<li><strong>Updated:</strong> {len(sbom_diff['updated'])} packages</li>")
        html_lines.append("</ul>")
        html_content = "\n".join(html_lines)
        if args.output_file:
            try:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    f.write(html_content)
                logger.info(f"HTML report written to {args.output_file}")
            except Exception as e:
                logger.error(f"Failed to write HTML report: {e}")
        else:
            print(html_content)

    else:
        # Text format summary (console-friendly)
        print("\n=== Patch Summary ===")
        if report["base_image_changes"]:
            print("Base Image Changes:")
            for change in report["base_image_changes"]:
                print(f" - {change['original']} -> {change['new']}")
        else:
            print("Base Image Changes: None")
        print(f"\nVulnerabilities Before: {before_summary}")
        print(f"Vulnerabilities After:  {after_summary}")
        # Detailed CVE differences
        resolved = vulns_diff["resolved"]
        remaining = vulns_diff["remaining"]
        new = vulns_diff["new"]
        print(f"\nResolved CVEs: {len(resolved)}")
        if resolved:
            for v in resolved:
                fix_info = f"fixed in {v['fix_version']}" if v.get('fix_version') else "removed"
                print(f" - {v['id']} in {v['package']} (was {v['version']}, {fix_info})")
        print(f"\nRemaining CVEs: {len(remaining)}")
        if remaining:
            for v in remaining:
                print(f" - {v['id']} in {v['package']} (version {v['version']}, severity {v['severity']})")
        if new:
            print(f"\nNewly Introduced CVEs: {len(new)}")
            for v in new:
                print(f" - {v['id']} in {v['package']} (severity {v['severity']})")
        # SBOM diff summary
        added_count = len(sbom_diff["added"])
        removed_count = len(sbom_diff["removed"])
        updated_count = len(sbom_diff["updated"])
        print(f"\nSBOM Package Differences: +{added_count} added, -{removed_count} removed, {updated_count} updated")
        if updated_count:
            print("Updated packages:")
            for comp in sbom_diff["updated"]:
                print(f" - {comp['name']} ({comp['type']}): {comp['old_version']} -> {comp['new_version']}")
        # Also write text summary to file if requested
        if args.output_file:
            try:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    base_changes_str = ', '.join([f"{c['original']} -> {c['new']}" for c in report['base_image_changes']]) or 'None'
                    f.write(f"Base Image Changes: {base_changes_str}\n")
                    f.write(f"Vulnerabilities Before: {before_summary}\n")
                    f.write(f"Vulnerabilities After: {after_summary}\n")
                    f.write(f"Resolved CVEs ({len(resolved)}): {[v['id'] for v in resolved]}\n")
                    f.write(f"Remaining CVEs ({len(remaining)}): {[v['id'] for v in remaining]}\n")
                    if new:
                        f.write(f"New CVEs ({len(new)}): {[v['id'] for v in new]}\n")
                    f.write(f"SBOM diff - Added: {added_count}, Removed: {removed_count}, Updated: {updated_count}\n")
                logger.info(f"Text summary written to {args.output_file}")
            except Exception as e:
                logger.error(f"Failed to write text report to file: {e}")
    return 0

if __name__ == "__main__":
    exit(main())
