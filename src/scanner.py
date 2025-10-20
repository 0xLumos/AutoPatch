import os
import json
from .utils import run_cmd

TRIVY_CMD = os.environ.get("TRIVY_CMD", "trivy")


def scan_image(image_name: str, output_json: str = None) -> dict:
    """Run Trivy scan and return parsed JSON results."""
    cmd = [TRIVY_CMD, "image", "-f", "json", image_name]
    if output_json:
        cmd += ["-o", output_json]
        run_cmd(cmd, capture_output=False)
        with open(output_json, "r") as f:
            return json.load(f)
    else:
        _, out = run_cmd(cmd)
        return json.loads(out)