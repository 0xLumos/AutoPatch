import subprocess
import json
from typing import List, Tuple


def run_cmd(cmd: List[str], capture_output: bool = True, check: bool = True) -> Tuple[int, str]:
    result = subprocess.run(cmd, capture_output=capture_output, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {' '.join(cmd)}")
        print("STDERR:", result.stderr)
        raise RuntimeError(result.stderr)
    return result.returncode, result.stdout if capture_output else ""


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)