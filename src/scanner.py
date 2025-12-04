from .utils import run_cmd, load_json, log_step


def scan_image(image: str, output_path: str) -> dict:
    log_step(f"Running Trivy scan for {image} → {output_path}")

    cmd = [
        "trivy", "image",
        "--quiet",
        "--format", "json",
        "-o", output_path,
        image
    ]

    code, out = run_cmd(cmd)
    if code != 0:
        print(out)
        return {}

    return load_json(output_path)


def generate_sbom(image: str, output_path: str) -> dict:
    log_step(f"Generating SBOM for {image} → {output_path}")
    cmd = [
        "trivy", "image",
        "--format", "cyclonedx",
        "--output", output_path,
        image
    ]
    code, out = run_cmd(cmd)
    if code != 0:
        print(out)
        return {}

    return load_json(output_path)


def summarize(scan_json: dict) -> dict:
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for result in scan_json.get("Results", []):
        vulns = result.get("Vulnerabilities", [])
        for v in vulns:
            sev = v.get("Severity", "Unknown")
            if sev in summary:
                summary[sev] += 1
            else:
                summary["Unknown"] += 1
    return summary
