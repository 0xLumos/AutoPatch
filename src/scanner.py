from __future__ import annotations
import subprocess
import json
import os
from typing import Tuple, Dict, Any
from .utils import run_cmd, read_json


def scan_image(image_name: str, output_file: str) -> Dict[str, Any]:
    """
    Scan a Docker image with Trivy and save/return JSON results.

    - If trivy fails or isn't present, returns {}.
    - output_file will be overwritten if it exists.
    """
    if not image_name:
        raise ValueError("No image name provided for scanning.")

    if os.path.exists(output_file):
        try:
            os.remove(output_file)
        except Exception:
            pass

    print(f"[+] Running Trivy scan for {image_name} → {output_file}")
    cmd = [
        "trivy",
        "image",
        "--format", "json",
        "--quiet",
        image_name,
        "-o", output_file,
    ]
    code, out = run_cmd(cmd)
    if code != 0:
        print(f"[!] Trivy scan failed (code {code}): {out.strip()}")
        return {}

    try:
        data = read_json(output_file)
        print(f"[+] Scan complete: {len(data.get('Results', []))} Results entries.")
        return data
    except Exception as e:
        print(f"[!] Failed to read/parse {output_file}: {e}")
        return {}
