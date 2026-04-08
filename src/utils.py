import subprocess
import json
import os
import csv
import logging
import time
import difflib
from datetime import datetime
from typing import Tuple, Dict, List, Any, Optional

# Use the shared logger for console output
logger = logging.getLogger("docker_patch_tool")


def run_cmd(
    cmd,
    env_override: Optional[Dict[str, str]] = None,
    timeout: int = 300,
    retries: int = 0,
    backoff_factor: float = 2.0,
) -> Tuple[int, str]:
    """
    Run a shell command and return (exit_code, output).

    Supports retry logic with exponential backoff for transient failures.
    Retries on both non-zero exit codes and timeout exceptions. Fatal
    errors (e.g., command not found via OSError) are NOT retried.

    Args:
        cmd: The command to execute. Can be a string (uses shell=True for
             shell features like pipes/redirects) or a list of strings
             (uses shell=False for proper argument passing).
        env_override: Optional dict of environment variables to merge with current environment.
        timeout: Maximum execution time in seconds (default 300).
        retries: Number of times to retry on failure (default 0). Retries occur on
                 non-zero exit codes and timeout exceptions.
        backoff_factor: Multiplier for exponential backoff between retries (default 2.0).

    Returns:
        Tuple of (exit_code, output_string) where output includes stdout and stderr.
        On fatal error (e.g., command not found), returns (1, error_message).
    """
    env = os.environ.copy()
    if env_override:
        env.update(env_override)

    # CRITICAL: shell=True with a list on POSIX only passes the first
    # element to /bin/sh -c, silently dropping all arguments.
    # Use shell=True only for string commands (which may contain pipes,
    # redirects, etc.), and shell=False for list commands.
    use_shell = isinstance(cmd, str)

    attempt = 0
    max_attempts = retries + 1
    last_output = ""

    while attempt < max_attempts:
        attempt += 1
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout,
                shell=use_shell,
            )
            output = (result.stdout or "") + (result.stderr or "")
            last_output = output.strip()

            # Success -- return immediately
            if result.returncode == 0:
                return 0, last_output

            # Non-zero exit code -- retry if we have attempts left
            if attempt < max_attempts:
                wait_time = backoff_factor ** (attempt - 1)
                logger.warning(
                    f"Command failed with exit code {result.returncode} "
                    f"(attempt {attempt}/{max_attempts}). "
                    f"Retrying in {wait_time:.1f}s: {cmd}"
                )
                time.sleep(wait_time)
            else:
                # Out of retries -- return the failure
                if retries > 0:
                    logger.error(
                        f"Command failed after {max_attempts} attempt(s): {cmd}"
                    )
                return result.returncode, last_output

        except subprocess.TimeoutExpired:
            last_output = f"Command timed out after {timeout}s"
            if attempt < max_attempts:
                wait_time = backoff_factor ** (attempt - 1)
                logger.warning(
                    f"Command timed out (attempt {attempt}/{max_attempts}). "
                    f"Retrying in {wait_time:.1f}s: {cmd}"
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    f"Command timed out after {max_attempts} attempt(s): {cmd}"
                )
                return 1, last_output

        except Exception as e:
            # Non-retryable errors (e.g., command not found) fail immediately
            logger.error(f"Failed to execute command: {cmd}")
            logger.error(f"Error: {type(e).__name__}: {e}")
            return 1, str(e)

    # Should not be reached, but safety net
    return 1, last_output or "Unknown error"


def load_json(path: str) -> Dict[str, Any]:
    """
    Load JSON data from a file path.

    Args:
        path: File path to load from.

    Returns:
        Parsed JSON as a dict. Returns empty dict if file does not exist or
        cannot be parsed.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"JSON file not found: {path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {path}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error loading JSON from {path}: {type(e).__name__}: {e}")
        return {}


def save_json(data: Dict[str, Any], path: str) -> bool:
    """
    Save a Python object as JSON to the given file path.

    Args:
        data: Python object to serialize (typically a dict).
        path: File path to write to.

    Returns:
        True on success, False on failure.
    """
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Saved JSON to {path}")
        return True
    except Exception as e:
        logger.error(f"Error saving JSON to {path}: {type(e).__name__}: {e}")
        return False


def save_csv(data: List[Dict[str, Any]], path: str, fieldnames: Optional[List[str]] = None) -> bool:
    """
    Export a list of dictionaries to a CSV file.

    Args:
        data: List of dictionaries where each dict represents a row.
        path: File path to write CSV to.
        fieldnames: Optional list of column names. If not provided, uses keys
                    from the first row. If no rows exist, returns False.

    Returns:
        True on success, False on failure.
    """
    try:
        if not data:
            logger.warning(f"No data to save to CSV: {path}")
            return False

        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        # Infer fieldnames from first row if not provided
        if fieldnames is None:
            fieldnames = list(data[0].keys())

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

        logger.debug(f"Saved CSV to {path} ({len(data)} rows)")
        return True
    except Exception as e:
        logger.error(f"Error saving CSV to {path}: {type(e).__name__}: {e}")
        return False


def load_base_mapping(file_path: str) -> Dict[str, str]:
    """
    Load a base image mapping override file (JSON or YAML) into a dict.

    This mapping can override base image upgrades where keys are original base
    images and values are replacement base images.

    Args:
        file_path: Path to mapping file (supports .json, .yaml, .yml).

    Returns:
        Dictionary mapping base images. Returns empty dict if file not found,
        invalid format, or parsing fails.
    """
    if not os.path.exists(file_path):
        logger.error(f"Base image mapping file not found: {file_path}")
        return {}

    ext = os.path.splitext(file_path)[1].lower()
    mapping = {}

    try:
        if ext in (".yml", ".yaml"):
            try:
                import yaml  # Requires PyYAML if YAML format is used
            except ImportError:
                logger.error("PyYAML not installed. Cannot parse YAML files.")
                return {}

            with open(file_path, "r", encoding="utf-8") as f:
                mapping = yaml.safe_load(f)

        elif ext == ".json":
            mapping = load_json(file_path)

        else:
            # Try JSON as default for unknown extensions
            logger.debug(f"Unknown extension {ext}, attempting to parse as JSON")
            mapping = load_json(file_path)

    except Exception as e:
        logger.error(f"Failed to load base image mapping from {file_path}: {type(e).__name__}: {e}")
        return {}

    # Validate format
    if not isinstance(mapping, dict):
        logger.error(
            f"Base image mapping file format invalid at {file_path}: "
            f"expected dict/object, got {type(mapping).__name__}"
        )
        return {}

    logger.debug(f"Loaded base image mapping from {file_path} ({len(mapping)} entries)")
    return mapping


def compute_reduction_percentage(before_count: int, after_count: int) -> float:
    """
    Calculate the percentage reduction from before_count to after_count.

    Args:
        before_count: Initial count (numerator for reduction).
        after_count: Final count after reduction.

    Returns:
        Percentage reduction as a float. Returns 0.0 if before_count is 0 or negative.
        A positive result indicates reduction, negative indicates increase.

    Example:
        compute_reduction_percentage(100, 75) returns 25.0 (25% reduction)
        compute_reduction_percentage(100, 150) returns -50.0 (50% increase)
    """
    if before_count <= 0:
        logger.debug("before_count must be positive; returning 0.0")
        return 0.0

    reduction = ((before_count - after_count) / before_count) * 100
    return round(reduction, 2)


def generate_diff(original_text: str, patched_text: str) -> str:
    """
    Generate a unified diff string between original and patched text.

    Args:
        original_text: The original text content.
        patched_text: The patched/modified text content.

    Returns:
        A unified diff string suitable for display or logging. Returns empty string
        if texts are identical.

    Example:
        diff = generate_diff("line1\\nline2", "line1\\nmodified")
        # Returns unified diff format showing the change
    """
    if original_text == patched_text:
        return ""

    try:
        original_lines = original_text.splitlines(keepends=True)
        patched_lines = patched_text.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile="original",
            tofile="patched",
            lineterm="",
        )

        return "\n".join(diff)

    except Exception as e:
        logger.error(f"Error generating diff: {type(e).__name__}: {e}")
        return ""
