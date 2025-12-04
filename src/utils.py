import subprocess
import json
import os
from datetime import datetime


def log_step(msg):
    # Replace unsupported Windows console characters
    safe_msg = msg.replace("→", "->").replace("↳", "->").replace("✓", "[OK]")

    print(f"[+] {safe_msg}", flush=True)


def log_info(msg: str):
    print(f"INFO:src.patcher: {msg}")


def run_cmd(cmd, env_override=None):
    env = env_override if env_override else None

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=True,
        env=env
    )
    out, err = proc.communicate()
    return proc.returncode, (out + err)


def load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}


def extract_image_name(base_image: str) -> str:
    return base_image.split("/")[-1].lower()
