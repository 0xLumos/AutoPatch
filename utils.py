import subprocess
import json
import os
import logging
from datetime import datetime

# Use the shared logger for console output
logger = logging.getLogger("docker_patch_tool")

def run_cmd(cmd, env_override=None):
    """
    Run a shell command and return (exit_code, output).
    If env_override is provided, it will be merged with the current environment.
    Captures both stdout and stderr.
    """
    env = os.environ.copy()
    if env_override:
        env.update(env_override)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output.strip()
    except Exception as e:
        logger.error(f"Failed to execute command {cmd}: {e}")
        return 1, str(e)

def load_json(path):
    """Load JSON data from a file path, returning an empty dict if any error occurs."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON from {path}: {e}")
        return {}

def save_json(data, path):
    """Save a Python object as JSON to the given file path. Returns True on success."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving JSON to {path}: {e}")
        return False

def load_base_mapping(file_path):
    """
    Load a base image mapping override file (JSON or YAML) into a dict.
    This mapping can override base image upgrades (keys are original base, values are new base).
    """
    if not os.path.exists(file_path):
        logger.error(f"Base image mapping file not found: {file_path}")
        return {}
    ext = os.path.splitext(file_path)[1].lower()
    mapping = {}
    try:
        if ext in (".yml", ".yaml"):
            import yaml  # Requires PyYAML if YAML format is used
            with open(file_path, "r", encoding="utf-8") as f:
                mapping = yaml.safe_load(f)
        elif ext == ".json":
            mapping = load_json(file_path)
        else:
            # Try JSON as default
            mapping = load_json(file_path)
    except Exception as e:
        logger.error(f"Failed to load base image mapping from {file_path}: {e}")
        mapping = {}
    if not isinstance(mapping, dict):
        logger.error("Base image mapping file format invalid (expected key-value mapping).")
        return {}
    return mapping