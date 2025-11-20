import subprocess
import json
from typing import List, Tuple

def run_cmd(cmd: List[str], capture_output: bool = True, check: bool = True) -> Tuple[int, str]:
    if not cmd or any(arg is None for arg in cmd):
        raise ValueError(f"Invalid command: {cmd}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if check and result.returncode != 0:
            print(f"[-] Command failed: {' '.join(cmd)}")
            print("STDERR:", result.stderr)
            raise RuntimeError(result.stderr or "Unknown subprocess error")

        return result.returncode, (result.stdout or "")
    
    except FileNotFoundError:
        print(f"[!] Command not found: {cmd[0]}")
        raise
    except Exception as e:
        print(f"[!] Unexpected error running command {' '.join(cmd)}: {e}")
        raise

def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
