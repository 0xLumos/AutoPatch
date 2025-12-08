import logging
from .utils import run_cmd, load_json

logger = logging.getLogger("docker_patch_tool")

def scan_image(image, output_path):
    """
    Run Trivy vulnerability scan on the given image and save JSON report to output_path.
    Returns the parsed JSON results (dict).
    """
    logger.info(f"Scanning image '{image}' for vulnerabilities ...")
    cmd = ["trivy", "image", "--quiet", "--format", "json", "-o", output_path, image]
    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(f"Trivy scan failed for image {image}:\n{output}")
        return {}
    return load_json(output_path)

def generate_sbom(image, output_path):
    """
    Generate a SBOM (Software Bill of Materials) for the given image using Trivy (CycloneDX format).
    Returns the parsed SBOM JSON.
    """
    logger.info(f"Generating SBOM for image '{image}' ...")
    cmd = ["trivy", "image", "--format", "cyclonedx", "--output", output_path, image]
    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(f"Failed to generate SBOM for {image}:\n{output}")
        return {}
    return load_json(output_path)

def summarize_vulnerabilities(scan_json):
    """
    Summarize vulnerability counts by severity from a Trivy scan JSON.
    Returns a dict of severity counts.
    """
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for result in scan_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "Unknown")
            if sev not in summary:
                summary["Unknown"] += 1
            else:
                summary[sev] += 1
    return summary
