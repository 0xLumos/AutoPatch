import subprocess
import json
import os
import csv
import logging
import random
import time
import difflib
from datetime import datetime
from .constants import (
    DEFAULT_RUN_CMD_TIMEOUT_SECONDS, RETRY_BACKOFF_BASE,
)
from typing import Tuple, Dict, List, Any, Optional, Callable

# Use the shared logger for console output
logger = logging.getLogger("docker_patch_tool")


# Patterns indicating transient errors that are safe to retry.
# (Lowercased substring match against combined stdout/stderr.)
_NETWORK_INDICATORS: Tuple[str, ...] = (
    "connection refused",
    "connection timeout",
    "connection timed out",
    "network is unreachable",
    "name resolution failed",
    "temporary failure in name resolution",
    "connection reset",
    "i/o timeout",
    "tls handshake timeout",
    "tls: handshake failure",
    "no such host",
    "tcp dial",
    "503 service unavailable",
    "502 bad gateway",
    "504 gateway timeout",
)
_DB_UPDATE_INDICATORS: Tuple[str, ...] = (
    "db download",
    "download vulnerability database",
    "vulnerability db",
    "update vulnerability db",
    "download db",
)
_RATE_LIMIT_INDICATORS: Tuple[str, ...] = (
    "rate limit",
    "429 too many requests",
    "toomanyrequests",
    "you have reached your pull rate limit",
)


def _default_is_retryable(exit_code: int, output: str) -> bool:
    """
    Decide whether a non-zero subprocess exit is a transient failure
    worth retrying. Returns True for network errors, Trivy/Grype DB
    update failures, and registry rate-limit responses. Returns False
    for everything else (compile errors, malformed args, image not
    found, etc.) which should fail fast.
    """
    low = output.lower()
    if any(ind in low for ind in _NETWORK_INDICATORS):
        return True
    if any(ind in low for ind in _DB_UPDATE_INDICATORS):
        return True
    if any(ind in low for ind in _RATE_LIMIT_INDICATORS):
        return True
    return False


def _backoff_seconds(attempt: int, base: float) -> float:
    """
    Exponential backoff with +/- 25% jitter to avoid thundering-herd
    when several pipelines fail at once against the same upstream.
    """
    raw = base ** (attempt - 1)
    return max(0.0, raw * (1.0 + random.uniform(-0.25, 0.25)))


def utc_now() -> "datetime":
    """Timezone-aware UTC now. Use everywhere instead of bare
    ``datetime.now()`` so report timestamps are unambiguous."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def utc_iso_now() -> str:
    """ISO-8601 UTC timestamp with explicit ``+00:00`` offset."""
    return utc_now().isoformat()


def run_cmd(
    cmd: List[str],
    env_override: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_RUN_CMD_TIMEOUT_SECONDS,
    retries: int = 0,
    backoff_factor: float = RETRY_BACKOFF_BASE,
    is_retryable: Optional[Callable[[int, str], bool]] = None,
) -> Tuple[int, str]:
    """
    Run a subprocess command and return ``(exit_code, output)``.

    Always runs with ``shell=False``. String commands are rejected
    to eliminate shell-injection risk; callers must pass an argv list.

    Retries are bounded by ``retries`` and apply only to:
      * timeouts, and
      * non-zero exits whose output matches the retryable classifier
        (network errors, Trivy/Grype DB-update failures, rate limits).

    Build failures, missing files, malformed arguments, etc. are
    treated as non-retryable and returned immediately.

    Args:
        cmd: argv list. Strings are not supported.
        env_override: optional env vars merged into ``os.environ`` copy.
        timeout: per-attempt timeout in seconds (default 300).
        retries: extra retry attempts on top of the first try (default 0).
        backoff_factor: base for exponential backoff (default 2.0). Final
            wait per attempt is ``backoff_factor**(attempt-1)`` with
            +/- 25% jitter.
        is_retryable: optional override classifier
            ``(exit_code, combined_output) -> bool``. If omitted,
            ``_default_is_retryable`` is used.

    Returns:
        ``(exit_code, combined_stdout_stderr_stripped)``. On unrecoverable
        errors (TypeError from non-list cmd is raised; OSError such as
        command-not-found returns ``(1, error_message)``).

    Raises:
        TypeError: if ``cmd`` is not a ``list`` of ``str``.
    """
    if not isinstance(cmd, list) or not all(isinstance(c, str) for c in cmd):
        raise TypeError(
            "run_cmd requires a list of strings; shell=True / string "
            f"commands are no longer supported (got {type(cmd).__name__})"
        )
    if not cmd:
        raise ValueError("run_cmd requires a non-empty argv list")

    classify = is_retryable or _default_is_retryable

    env = os.environ.copy()
    if env_override:
        env.update(env_override)

    max_attempts = retries + 1
    last_output = ""
    head = cmd[0]

    for attempt in range(1, max_attempts + 1):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                # text=True alone decodes with locale.getpreferredencoding(),
                # which is cp1252 on a default Windows host and ascii under
                # LANG=C in a slim container. Scanner output routinely
                # carries UTF-8 (CVE titles, package descriptions, box-
                # drawing characters in Trivy tables), so the decode either
                # raised UnicodeDecodeError and lost an entire scan, or
                # mojibaked package names and broke the SBOM diff keys.
                # Pin the codec and never abort a scan on one bad byte.
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=timeout,
                shell=False,
            )
            output = (result.stdout or "") + (result.stderr or "")
            last_output = output.strip()

            # Success: return immediately.
            if result.returncode == 0:
                return 0, last_output

            # Non-zero exit: classify before deciding whether to retry.
            if attempt < max_attempts and classify(result.returncode, last_output):
                wait = _backoff_seconds(attempt, backoff_factor)
                logger.warning(
                    "Command failed transiently (exit %d, attempt %d/%d); "
                    "retrying in %.1fs: %s",
                    result.returncode, attempt, max_attempts, wait, head,
                )
                time.sleep(wait)
                continue

            # Either out of attempts or non-retryable: fail fast.
            if attempt < max_attempts:
                logger.debug(
                    "Command failed (exit %d, non-transient); not retrying: %s",
                    result.returncode, head,
                )
            elif retries > 0:
                logger.error(
                    "Command failed after %d attempt(s): %s",
                    max_attempts, head,
                )
            return result.returncode, last_output

        except subprocess.TimeoutExpired:
            last_output = f"Command timed out after {timeout}s"
            if attempt < max_attempts:
                wait = _backoff_seconds(attempt, backoff_factor)
                logger.warning(
                    "Command timed out (attempt %d/%d); retrying in %.1fs: %s",
                    attempt, max_attempts, wait, head,
                )
                time.sleep(wait)
                continue
            logger.error(
                "Command timed out after %d attempt(s): %s",
                max_attempts, head,
            )
            return 1, last_output

        except (OSError, FileNotFoundError) as e:
            # Command not found / permission denied / etc.: never retry.
            logger.error(
                "Failed to execute command %s: %s: %s",
                head, type(e).__name__, e,
            )
            return 1, str(e)
        except Exception as e:  # pragma: no cover - defensive
            logger.error(
                "Unexpected error executing %s: %s: %s",
                head, type(e).__name__, e,
            )
            return 1, str(e)

    # Defensive: control flow above always returns within the loop.
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


def atomic_write_text(content: str, path: str, encoding: str = "utf-8") -> bool:
    """
    Write text to ``path`` atomically: a partial write or crash never
    leaves a corrupt file in place. Implementation: write to a sibling
    tempfile, fsync the data, then ``os.replace`` over the target.

    Returns True on success, False on failure.
    """
    import tempfile
    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix=os.path.basename(path) + ".",
            suffix=".tmp",
            dir=parent,
        )
        try:
            with os.fdopen(fd, "w", encoding=encoding) as f:
                f.write(content)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            os.replace(tmp, path)
            return True
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.error(
            f"atomic_write_text({path}) failed: {type(e).__name__}: {e}"
        )
        return False


def _json_default(obj: Any) -> Any:
    """Fallback encoder for objects ``json`` cannot serialise natively.

    Sets are emitted sorted so the JSON is deterministic across runs;
    an unordered dump would change the file hash between two identical
    scans and break attestation and diffing.
    """
    import dataclasses
    import datetime as _dt
    import decimal
    import enum as _enum
    import pathlib

    if isinstance(obj, (set, frozenset)):
        try:
            return sorted(obj)
        except TypeError:            # mixed types: fall back to str keys
            return sorted(map(str, obj))
    if isinstance(obj, (_dt.datetime, _dt.date, _dt.time)):
        return obj.isoformat()
    if isinstance(obj, _dt.timedelta):
        return obj.total_seconds()
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    if isinstance(obj, pathlib.PurePath):
        return str(obj)
    if isinstance(obj, _enum.Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    return str(obj)


def save_json(data: Dict[str, Any], path: str) -> bool:
    """
    Save a Python object as JSON atomically.

    Uses :func:`atomic_write_text` so a crash mid-write cannot leave a
    half-written report file for downstream parsers.

    Args:
        data: Python object to serialize (typically a dict).
        path: File path to write to.

    Returns:
        True on success, False on failure.
    """
    try:
        # default= is required, not cosmetic. Reports carry values the
        # stdlib encoder rejects outright: datetime (evidence snapshot
        # timestamps), set (KEV identifier sets, reachable-package sets),
        # Path, Decimal, and the module's own dataclass-derived enums.
        # Without it json.dumps raised TypeError, this function returned
        # False, and the run silently produced no report at all, which
        # is the worst possible failure mode for an audit artefact.
        # sort_keys makes the output byte-stable so two runs over the
        # same scan hash identically and can be diffed or attested.
        payload = json.dumps(data, indent=2, sort_keys=True, default=_json_default)
    except Exception as e:
        logger.error(f"Error serialising JSON for {path}: {type(e).__name__}: {e}")
        return False
    if atomic_write_text(payload, path):
        logger.debug(f"Saved JSON to {path}")
        return True
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


def compute_reduction_percentage(
    before_count: int, after_count: int
) -> Optional[float]:
    """
    Calculate the percentage reduction from before_count to after_count.

    Returns ``None`` when the baseline is zero, because the reduction
    ratio is genuinely undefined there: dividing by zero has no answer,
    and the previous behaviour of returning ``0.0`` was actively
    misleading in two directions at once.

      * ``before=0, after=0`` (an already-clean image) was reported as
        "0% reduction" and pulled the reported mean DOWN, understating
        a run that did nothing wrong.
      * ``before=0, after=5`` (the patch INTRODUCED five CVEs into a
        clean image) was also reported as "0% reduction", so a genuine
        regression was indistinguishable from a no-op.

    Both cases must be excluded from an aggregate and counted
    separately, which a caller cannot do if the sentinel is a value
    inside the legal range of the metric. Aggregators should report
    ``n`` alongside the mean so the exclusions are visible.

    Args:
        before_count: Initial count (the denominator).
        after_count: Final count after remediation.

    Returns:
        Percentage reduction, positive for a reduction and negative for
        an increase, or ``None`` if ``before_count <= 0``.

    Example:
        compute_reduction_percentage(100, 75) returns 25.0 (25% reduction)
        compute_reduction_percentage(100, 150) returns -50.0 (50% increase)
        compute_reduction_percentage(0, 0) returns None (undefined)
    """
    if before_count <= 0:
        logger.debug(
            "Reduction undefined for baseline %d (after=%d); returning None "
            "so the caller excludes it from aggregates rather than "
            "recording a spurious 0%%.", before_count, after_count,
        )
        return None

    reduction = ((before_count - after_count) / before_count) * 100
    return round(reduction, 2)


def format_reduction_percentage(
    before_count: int, after_count: int, undefined: str = "n/a"
) -> str:
    """Render a reduction for human-readable reports.

    Wraps :func:`compute_reduction_percentage` so report writers do not
    have to repeat the ``None`` handling, and so an undefined ratio
    prints as "n/a" instead of a fabricated "0.0%".
    """
    pct = compute_reduction_percentage(before_count, after_count)
    return undefined if pct is None else f"{pct:.1f}%"


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
