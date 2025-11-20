# main.py
"""Main coordinator: build images, scan before+after, patch Dockerfile.

This script is self-contained (no external parser/builder/comparer modules).
It uses scanner.py and patcher.py from the same directory.
"""
from __future__ import annotations
import os
import subprocess
import shutil
import json
import sys
from typing import Dict, Any
from . import patcher, scanner


def run_cmd(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout + (proc.stderr or "")
    except Exception as e:
        return 1, str(e)


def build_image(context_dir: str, tag: str, dockerfile: str) -> bool:
    """
    Build a docker image. Returns True on success.
    """
    if not shutil.which("docker"):
        print("[!] docker binary not found in PATH.")
        return False

    cmd = ["docker", "build", "-f", dockerfile, "-t", tag, context_dir]
    print(f"[+] Building image {tag} with {dockerfile} ...")
    code, out = run_cmd(cmd)
    if code != 0:
        print(f"[!] Docker build failed (code {code}): {out.strip()}")
        return False
    print(f"[+] Docker build succeeded: {tag}")
    return True


def summarize(trivy_json: Dict[str, Any]) -> Dict[str, int]:
    """
    Create a simple summary dict from Trivy JSON:
    { 'Critical': N, 'High': N, 'Medium': N, 'Low': N, 'Unknown': N }
    """
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    if not trivy_json:
        return counts

    for res in trivy_json.get("Results", []):
        for vuln in res.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "Unknown")
            if sev not in counts:
                sev = "Unknown"
            counts[sev] += 1
    return counts


def compare(before: Dict[str, int], after: Dict[str, int]) -> Dict[str, int]:
    """
    Return reductions per severity: before - after
    """
    out = {}
    keys = set(before) | set(after)
    for k in keys:
        out[k] = before.get(k, 0) - after.get(k, 0)
    return out


def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main():
    dockerfile_path = "Dockerfile"
    if not os.path.exists(dockerfile_path):
        print(f"[!] No {dockerfile_path} found in cwd: {os.getcwd()}")
        sys.exit(1)

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        docker_text = f.read()

    base_image, base_tag = patcher.find_base_image(docker_text)
    print(f"[+] Found base image: {base_image}:{base_tag if base_tag else '<none>'}")

    image_name = "autopatch"

    # Build base image
    if not build_image(".", image_name, dockerfile_path):
        print("[!] Aborting because base image build failed.")
        sys.exit(1)

    # Scan before
    before = scanner.scan_image(image_name, "trivy_before.json")
    before_summary = summarize(before)
    print("[+] Trivy BEFORE summary:", before_summary)

    # Propose and apply patch
    unknown_ratio = 0.0
    total = sum(before_summary.values())
    if total:
        unknown_ratio = before_summary["Unknown"] / total

    proposed = patcher.propose_upgrade(base_image, unknown_ratio)
    if proposed:
        print(f"[+] Proposed base upgrade: {proposed}")
        docker_text = patcher.replace_base_image(docker_text, proposed)
        print(f"[+] Replaced base image with: {proposed}")
    else:
        print("[-] No base upgrade proposed; keeping original base.")

    docker_text = patcher.add_apt_upgrade(docker_text)
    patched_path = "Dockerfile.patched"
    with open(patched_path, "w", encoding="utf-8") as f:
        f.write(docker_text)
    print(f"[+] Patched Dockerfile written to {patched_path}")

    patched_image = f"{image_name}-patched"
    if not build_image(".", patched_image, patched_path):
        print("[!] Aborting because patched image build failed.")
        sys.exit(1)

    after = scanner.scan_image(patched_image, "trivy_after.json")
    after_summary = summarize(after)
    print("[+] Trivy AFTER summary:", after_summary)

    comparison = compare(before_summary, after_summary)
    print("[+] Vulnerability reductions (before - after):", comparison)

    if before:
        write_json("trivy_before.json", before)
    if after:
        write_json("trivy_after.json", after)

    print("\n[+] Done. Files produced: Dockerfile.patched, trivy_before.json, trivy_after.json (when available).")



if __name__ == "__main__":
    main()
