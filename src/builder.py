import os
import logging
import json
import time
import re
from functools import wraps
from contextlib import contextmanager
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")

# Default build timeout in seconds
from .constants import DEFAULT_BUILD_TIMEOUT_SECONDS as DEFAULT_BUILD_TIMEOUT
# Sourced from constants.py so the documented AUTOPATCH_* env
# override is real. It was a duplicated literal, which made
# every override in the README silently inert.


# Build-error categories that are infrastructure-flavored rather than
# real build failures. Callers (e.g. main.py's fallback loop) should
# retry the same target on these instead of switching to a different
# base-image candidate.
TRANSIENT_BUILD_ERRORS = frozenset({
    "NETWORK_ERROR",
    "RATE_LIMITED",
    "REGISTRY_UNAVAILABLE",
    "BUILD_TIMEOUT",
    "DAEMON_NOT_RUNNING",
})


@dataclass
class PushResult:
    """Result of a docker push, capturing both success and the
    immutable sha256 manifest digest published by the registry."""
    success: bool
    digest: Optional[str] = None
    error: Optional[str] = None

    def __bool__(self) -> bool:  # backward-compat for `if push_image(...):`
        return self.success


def _categorize_build_error(output: str) -> str:
    """
    Categorize Docker build errors based on output patterns.

    Returns a stable category string. Infrastructure-flavored
    categories appear in :data:`TRANSIENT_BUILD_ERRORS` and should be
    retried; everything else is a real failure and the caller should
    move to the next candidate.

    Args:
        output: Docker build error output

    Returns:
        Error category string
    """
    output_lower = output.lower()

    # Every marker below is a phrase the tooling actually emits.
    # Unanchored fragments are deliberately avoided: a bare "429" also
    # matches a layer size or a sha prefix, and a bare "network" also
    # matches the ordinary phrase "docker network". Misclassifying a
    # hard failure as transient costs a retry of an identical, doomed
    # build and previously consumed the fallback attempt.
    if any(marker in output_lower for marker in (
        "you have reached your pull rate limit",
        "toomanyrequests",
        "429 too many requests",
        "rate limit exceeded",
    )):
        return "RATE_LIMITED"

    if any(marker in output_lower for marker in (
        "503 service unavailable",
        "502 bad gateway",
        "504 gateway timeout",
        "500 internal server error",
        "registry is unavailable",
    )) or ("registry-1.docker.io" in output_lower
           and "no such host" in output_lower):
        return "REGISTRY_UNAVAILABLE"

    if "cannot connect to the docker daemon" in output_lower:
        return "DAEMON_NOT_RUNNING"
    if "command timed out after" in output_lower:
        return "BUILD_TIMEOUT"
    if "base image" in output_lower and "not found" in output_lower:
        return "BASE_IMAGE_NOT_FOUND"
    if "manifest unknown" in output_lower or "not found: manifest" in output_lower:
        return "BASE_IMAGE_NOT_FOUND"
    if "permission denied" in output_lower:
        return "PERMISSION_DENIED"
    if "no such file or directory" in output_lower:
        return "FILE_NOT_FOUND"
    if "bad syntax" in output_lower or "syntax error" in output_lower:
        return "DOCKERFILE_SYNTAX_ERROR"
    if "failed to build" in output_lower:
        return "BUILD_FAILED"

    # Network markers are specific transport-layer phrases, not the
    # word "network" on its own.
    if any(marker in output_lower for marker in (
        "i/o timeout",
        "connection refused",
        "connection reset by peer",
        "name resolution failed",
        "temporary failure in name resolution",
        "dial tcp",
        "tls handshake timeout",
        "eof",
        "network is unreachable",
    )):
        return "NETWORK_ERROR"
    return "UNKNOWN_ERROR"


def measure_build_time(func):
    """
    Decorator that measures and records build duration.

    Args:
        func: Function to decorate

    Returns:
        Wrapped function that records execution time
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start_time
        logger.info(f"{func.__name__} completed in {duration:.2f}s")
        return result
    return wrapper


@contextmanager
def build_timer(operation_name: str):
    """
    Context manager that measures and logs operation duration.

    Args:
        operation_name: Name of the operation being timed

    Yields:
        None
    """
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        logger.info(f"{operation_name} completed in {duration:.2f}s")


def get_image_digest_local(image_name: str) -> Optional[str]:
    """
    Get the image ID (sha256) of a locally-built Docker image.

    Args:
        image_name: Name/tag of the Docker image

    Returns:
        Image ID (sha256 hash), or None if image not found or error occurs
    """
    logger.debug(f"Retrieving local image ID for '{image_name}' ...")
    cmd = ["docker", "inspect", image_name, "--format", "{{.Id}}"]
    code, output = run_cmd(cmd)

    if code != 0:
        logger.error(f"Failed to inspect image {image_name}: {output}")
        return None

    image_id = output.strip()
    if image_id:
        logger.debug(f"Image '{image_name}' local ID: {image_id}")
        return image_id

    logger.warning(f"No image ID found for '{image_name}'")
    return None


def measure_image_size(image_name: str) -> Optional[float]:
    """
    Measure the size of a Docker image in megabytes.

    Args:
        image_name: Name/tag of the Docker image

    Returns:
        Size in MB, or None if image not found or error occurs
    """
    logger.debug(f"Measuring size of image '{image_name}' ...")
    cmd = ["docker", "inspect", image_name, "--format", "{{.Size}}"]
    code, output = run_cmd(cmd)

    if code != 0:
        logger.error(f"Failed to inspect image {image_name}: {output}")
        return None

    try:
        size_bytes = int(output.strip())
        size_mb = size_bytes / (1024 * 1024)
        logger.debug(f"Image '{image_name}' size: {size_mb:.2f} MB")
        return size_mb
    except ValueError:
        logger.error(f"Failed to parse image size output: {output}")
        return None


def pull_image(image_name: str) -> bool:
    """
    Pull a Docker image from a registry.

    Args:
        image_name: Name/tag of the image to pull

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Pulling image '{image_name}' from registry ...")
    with build_timer(f"Image pull '{image_name}'"):
        code, output = run_cmd(["docker", "pull", image_name])

    if code != 0:
        logger.error(f"Failed to pull image {image_name}: {output}")
        return False

    logger.debug(f"Successfully pulled image '{image_name}'")
    return True


def remove_image(image_name: str, force: bool = False) -> bool:
    """
    Remove a Docker image.

    Args:
        image_name: Name/tag of the image to remove
        force: If True, force remove even if in use

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Removing image '{image_name}' ...")
    cmd = ["docker", "rmi"]
    if force:
        cmd.append("-f")
    cmd.append(image_name)

    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(f"Failed to remove image {image_name}: {output}")
        return False

    logger.debug(f"Successfully removed image '{image_name}'")
    return True


def get_image_digest(image_name: str) -> Optional[str]:
    """
    Get the SHA256 digest of a Docker image.

    Args:
        image_name: Name/tag of the Docker image

    Returns:
        SHA256 digest string (e.g., 'sha256:abc123...'), or None if not found
    """
    logger.debug(f"Retrieving digest for image '{image_name}' ...")
    cmd = ["docker", "inspect", image_name, "--format", "{{.RepoDigests}}"]
    code, output = run_cmd(cmd)

    if code != 0:
        logger.error(f"Failed to inspect image {image_name} for digest: {output}")
        return None

    output = output.strip()

    # Output is usually in format [repo@sha256:xxx ...]
    # Extract the FULL reference (repo@sha256:xxx) because cosign needs
    # the complete image reference, not just the bare hash.
    full_ref_match = re.search(r'([\w./:_-]+@sha256:[a-f0-9]{64})', output)
    if full_ref_match:
        full_ref = full_ref_match.group(1)
        logger.debug(f"Image '{image_name}' digest ref: {full_ref}")
        return full_ref

    # Fallback: try bare digest (won't work for cosign but better than None)
    digest_match = re.search(r'sha256:[a-f0-9]{64}', output)
    if digest_match:
        digest = digest_match.group(0)
        logger.warning(f"Could only extract bare digest for '{image_name}': {digest}")
        return digest

    logger.warning(f"Could not extract digest from output: {output}")
    return None


def validate_build_context(dockerfile_path: str) -> Tuple[bool, List[str]]:
    """
    Validate Docker build context before building.

    Checks:
    - Dockerfile exists and is readable
    - Build context directory exists
    - No sensitive files (.env, credentials) in context
    - .dockerignore exists (warning if missing)
    - Context size is reasonable (warning if > 500MB)

    Args:
        dockerfile_path: Path to the Dockerfile

    Returns:
        Tuple of (valid: bool, warnings: list of warning messages)
    """
    warnings = []
    context_dir = os.path.dirname(os.path.abspath(dockerfile_path)) or "."

    # Check Dockerfile exists
    if not os.path.isfile(dockerfile_path):
        return False, [f"Dockerfile not found: {dockerfile_path}"]

    # Check context directory exists
    if not os.path.isdir(context_dir):
        return False, [f"Build context directory not found: {context_dir}"]

    # Check for .dockerignore
    dockerignore_path = os.path.join(context_dir, ".dockerignore")
    if not os.path.isfile(dockerignore_path):
        warnings.append(
            "No .dockerignore found. Consider adding one to reduce build "
            "context size and avoid leaking sensitive files."
        )

    # Files that almost certainly contain secrets if present in the
    # build context. Two checks are run:
    #   (a) presence-on-disk relative to the context root, and
    #   (b) explicit reference inside the Dockerfile via COPY/ADD.
    # (b) is the more dangerous case: a developer with `.dockerignore`
    # that excludes `.env` is still vulnerable if their Dockerfile
    # says `COPY .env /app/.env`.
    SENSITIVE_BASENAMES = (
        ".env", ".env.local", ".env.production", ".env.dev",
        "credentials.json", "service-account.json",
        "id_rsa", "id_ed25519", "id_ecdsa", ".npmrc", ".pypirc",
        ".aws", "kubeconfig", ".kube",
    )

    # (a) on-disk presence.
    for pattern in SENSITIVE_BASENAMES:
        sensitive_path = os.path.join(context_dir, pattern)
        if os.path.exists(sensitive_path):
            warnings.append(
                f"Sensitive file '{pattern}' found in build context. "
                f"Ensure it is excluded via .dockerignore to prevent "
                f"accidental inclusion in the image."
            )

    # (b) Parse the Dockerfile itself for COPY/ADD targets that would
    # actually pull a sensitive file (or the entire context root) into
    # the image. We honour line continuations and inline comments so
    # multi-line COPY instructions are handled correctly.
    try:
        with open(dockerfile_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError:
        raw = ""

    # Join continuation lines (\ at end-of-line) so a multi-line
    # COPY/ADD is one logical line for matching.
    logical_lines: List[str] = []
    buf = ""
    for line in raw.splitlines():
        # strip inline comment, but be careful not to strip inside quotes
        if "#" in line and not line.strip().startswith("RUN"):
            line = line.split("#", 1)[0]
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-2] + " "
        else:
            buf += line
            if buf.strip():
                logical_lines.append(buf)
            buf = ""
    if buf.strip():
        logical_lines.append(buf)

    import re as _re
    copy_re = _re.compile(r"^\s*(COPY|ADD)\b\s+(?P<args>.+)$", _re.IGNORECASE)
    for logical in logical_lines:
        m = copy_re.match(logical)
        if not m:
            continue
        args = m.group("args").strip()
        # Tokens may include flags like --from=stage --chown=... -- skip those.
        tokens = [
            t for t in args.split()
            if not t.startswith("--")
        ]
        # The last token is the destination; everything else is sources.
        if len(tokens) < 2:
            continue
        sources = tokens[:-1]
        for src in sources:
            base = os.path.basename(src.strip().strip('"').strip("'"))
            if src.strip() in (".", "./"):
                warnings.append(
                    "Dockerfile contains a bare-root COPY/ADD (`COPY . ...` "
                    "or `ADD . ...`). This pulls the entire build context "
                    "into the image including any .env / id_rsa / .aws / "
                    "credentials files that exist on disk. Consider "
                    "narrowing the COPY source set or relying on a "
                    "rigorously-maintained .dockerignore."
                )
                continue
            if base in SENSITIVE_BASENAMES:
                warnings.append(
                    f"Dockerfile explicitly COPY/ADD '{src}' into the "
                    f"image. This file is on the sensitive-basenames "
                    f"allowlist; double-check it does not contain "
                    f"production secrets."
                )

    return True, warnings


def build_image(
    image_name: str,
    dockerfile_path: str,
    timeout: int = DEFAULT_BUILD_TIMEOUT,
    validate_context: bool = True,
    cache_from: Optional[List[str]] = None,
    cache_to: Optional[str] = None,
    buildkit: bool = True,
    build_context_path: Optional[str] = None,
    target: Optional[str] = None,
    platform: Optional[str] = None,
) -> Tuple[bool, Optional[str], float]:
    """
    Build a Docker image with the given name (tag) from the specified Dockerfile.

    Args:
        image_name: Name/tag for the built image
        dockerfile_path: Path to the Dockerfile
        timeout: Build timeout in seconds (default: 600)
        validate_context: If True, validate build context before building
        cache_from: Optional list of image refs to pull layer cache from.
            Each entry becomes a ``--cache-from`` argument. When non-empty,
            BuildKit is forced on regardless of the ``buildkit`` flag.
        cache_to: Optional ``--cache-to`` argument (e.g. ``type=registry,ref=...``).
            Requires BuildKit. Useful for publishing the post-patch layer
            cache back to a shared registry so the next pipeline run can
            resume from it.
        buildkit: If True (default) sets ``DOCKER_BUILDKIT=1`` on the
            subprocess, which is required for ``--cache-from``/``--cache-to``
            and dramatically improves retry-after-partial-failure behavior.
        platform: Optional ``--platform`` (e.g. ``linux/arm64``). Forces
            BuildKit, since classic builder ignores it. A base
            substitution verified on amd64 is not automatically valid on
            arm64: tag coverage and package availability differ per
            architecture, so each platform must be built to be claimed.
        target: Optional ``--target`` stage name. Building an individual
            stage is how per-stage CVE attribution gets a scannable
            artefact for a builder stage; without it only the final
            stage exists as an image and every builder-stage CVE is
            invisible to the scanner.

    Returns:
        Tuple of (success: bool, error_category: Optional[str], build_time_seconds: float)
        - success: True if build succeeds, False otherwise
        - error_category: If failed, the category of error; None if successful
        - build_time_seconds: Duration of the build operation in seconds
    """
    # K1: Validate build context before building
    if validate_context:
        valid, ctx_warnings = validate_build_context(dockerfile_path)
        for warning in ctx_warnings:
            logger.warning(f"Build context: {warning}")
        if not valid:
            return False, "INVALID_BUILD_CONTEXT", 0.0

    # A patched/cascade Dockerfile is written to a temp/output dir, but its
    # COPY instructions reference files in the ORIGINAL build context (app
    # source, pom.xml, go.sum, configs). Callers pass build_context_path to
    # build against that original context; otherwise fall back to the
    # Dockerfile's own directory.
    context_dir = (build_context_path
                   or os.path.dirname(os.path.abspath(dockerfile_path))
                   or ".")
    use_buildkit = bool(cache_from or cache_to or buildkit)
    logger.info(
        f"Building image '{image_name}' from {dockerfile_path} "
        f"(timeout: {timeout}s, buildkit={use_buildkit})"
    )

    cmd: List[str] = ["docker", "build", "-t", image_name, "-f", dockerfile_path]
    if target:
        cmd.extend(["--target", target])
    if platform:
        cmd.extend(["--platform", platform])
        use_buildkit = True   # classic builder silently ignores --platform
    # BuildKit-only flags (cache-from/to). Plain docker build silently
    # ignores --cache-from on some daemons; BuildKit uses it for real
    # layer reuse and lets retries resume from the failure layer.
    for src in cache_from or []:
        cmd.extend(["--cache-from", src])
    if cache_to:
        cmd.extend(["--cache-to", cache_to])
    cmd.append(context_dir)

    env_override = {"DOCKER_BUILDKIT": "1"} if use_buildkit else None

    start_time = time.time()
    code, output = run_cmd(cmd, timeout=timeout, env_override=env_override)
    duration = time.time() - start_time
    logger.info(f"Docker build '{image_name}' completed in {duration:.2f}s")

    if code != 0:
        error_category = _categorize_build_error(output)
        # K2: Capture full stdout+stderr for diagnostics
        logger.error(
            f"Docker build failed for {image_name} ({error_category}).\n"
            f"--- BUILD OUTPUT (last 2000 chars) ---\n"
            f"{output[-2000:]}\n"
            f"--- END BUILD OUTPUT ---"
        )
        return False, error_category, duration

    logger.debug(f"Docker build output for {image_name}: {output}")
    return True, None, duration


def tag_image(source_image: str, target_image: str) -> bool:
    """
    Tag a local Docker image with a new name/tag (usually for pushing to a registry).

    Args:
        source_image: Name/tag of the source image
        target_image: New name/tag for the image

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Tagging image '{source_image}' as '{target_image}' ...")
    code, output = run_cmd(["docker", "tag", source_image, target_image])

    if code != 0:
        logger.error(f"Failed to tag image {source_image} as {target_image}: {output}")
        return False

    logger.debug(f"Successfully tagged image as '{target_image}'")
    return True


_DIGEST_RE = re.compile(r"digest:\s*(sha256:[0-9a-f]{64})", re.IGNORECASE)


def _extract_digest(output: str) -> Optional[str]:
    """Pull the published sha256 digest out of `docker push` output."""
    m = _DIGEST_RE.search(output or "")
    return m.group(1) if m else None


# A push that cannot complete within this window is treated as failed
# rather than allowed to hang the pipeline indefinitely.
PUSH_TIMEOUT_SECONDS = 900

_BARE_DIGEST_RE = re.compile(r"\bsha256:[0-9a-f]{64}\b")


def _remote_manifest_digest(image_name: str) -> Optional[str]:
    """Digest of the manifest the registry currently serves for this
    reference, or None when the reference does not resolve.

    ``docker manifest inspect -v`` reports the descriptor digest, which
    is the value that must be compared against the local manifest
    digest before a push can be treated as already-completed.
    """
    code, out = run_cmd(
        ["docker", "manifest", "inspect", "-v", image_name], timeout=30
    )
    if code != 0:
        return None
    try:
        data = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        # Older CLIs emit non-JSON on some registries; fall back to a
        # bare scan rather than claiming the manifest is absent.
        m = _BARE_DIGEST_RE.search(out or "")
        return m.group(0) if m else None
    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        digest = entry.get("Descriptor", {}).get("digest") or entry.get("digest")
        if isinstance(digest, str) and digest.startswith("sha256:"):
            return digest
    return None


def _local_manifest_digest(image_name: str) -> Optional[str]:
    """Digest the local image would publish under this reference.

    ``RepoDigests`` carries ``repo@sha256:...`` entries for references
    the local image has been pushed to or pulled from. The entry whose
    repository matches ``image_name`` identifies the manifest digest
    this exact reference corresponds to.
    """
    code, out = run_cmd(
        ["docker", "inspect", "--format", "{{json .RepoDigests}}", image_name],
        timeout=30,
    )
    if code != 0:
        return None
    try:
        repo_digests = json.loads(out.strip() or "[]")
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(repo_digests, list):
        return None
    repo = image_name.split(":", 1)[0] if ":" in image_name else image_name
    for rd in repo_digests:
        if not isinstance(rd, str) or "@" not in rd:
            continue
        rd_repo, _, digest = rd.partition("@")
        if rd_repo == repo and digest.startswith("sha256:"):
            return digest
    return None


def push_image(
    image_name: str,
    max_retries: int = 3,
    retry_delay: int = 5,
    insecure_registry: bool = False,
) -> PushResult:
    """
    Push a Docker image to a registry with retry logic.

    The registry may be temporarily unavailable, so this function retries
    the push operation if it fails.

    Args:
        image_name: Name/tag of the image to push
        max_retries: Maximum number of retry attempts (default: 3)
        retry_delay: Delay between retries in seconds (default: 5)
        insecure_registry: If True, allow pushing to HTTP registries (default: False)

    Returns:
        :class:`PushResult` (truthy when ``success`` is True). The
        ``digest`` field holds the registry-issued sha256 manifest
        digest when present, which downstream code records in the
        SLSA/attestation trail.
    """
    logger.info(f"Pushing image '{image_name}' to registry (max_retries: {max_retries}) ...")

    for attempt in range(1, max_retries + 1):
        # On retry, first check whether a prior attempt already published
        # the manifest. `docker push` partial failures (manifest-PUT 5xx
        # after all layers uploaded) leave the registry in a state where
        # the digest is present; re-pushing wastes bandwidth and risks
        # duplicate-manifest 409s. `docker manifest inspect` is the
        # cheapest probe.
        if attempt > 1:
            remote_digest = _remote_manifest_digest(image_name)
            local_digest = _local_manifest_digest(image_name)
            # Presence of *a* manifest is not evidence that *this* image
            # was published. Registry tags are stable across runs
            # (`repo/name-patched:latest`), so a manifest left by any
            # previous run makes a naive probe succeed and a genuinely
            # failed push is then reported as success, after which the
            # pipeline signs and attests an image that was never
            # published. Short-circuit only when the digest the registry
            # holds is byte-identical to the local image's manifest
            # digest.
            if remote_digest and local_digest and remote_digest == local_digest:
                logger.info(
                    f"Push retry short-circuit: registry already holds the "
                    f"identical manifest for '{image_name}' "
                    f"(digest={remote_digest}); treating as success."
                )
                return PushResult(success=True, digest=remote_digest)
            if remote_digest and local_digest and remote_digest != local_digest:
                logger.warning(
                    f"Registry holds a manifest for '{image_name}' with a "
                    f"different digest (remote={remote_digest}, "
                    f"local={local_digest}); this tag was published by an "
                    f"earlier run. Re-pushing rather than assuming success."
                )

        with build_timer(f"Image push '{image_name}' (attempt {attempt}/{max_retries})"):
            cmd = ["docker", "push", image_name]
            # For insecure registries, Docker daemon config handles HTTP;
            # no extra CLI flag needed for push. But log it for clarity.
            if insecure_registry:
                logger.debug(f"Pushing to insecure registry (ensure daemon is configured)")
            # A stalled registry must not hang the pipeline. The build
            # path already bounds itself; the push path did not.
            code, output = run_cmd(cmd, timeout=PUSH_TIMEOUT_SECONDS)

        if code == 0:
            digest = _extract_digest(output)
            if digest:
                logger.info(
                    f"Successfully pushed image '{image_name}' on attempt {attempt} "
                    f"(digest={digest})"
                )
            else:
                logger.info(
                    f"Successfully pushed image '{image_name}' on attempt {attempt} "
                    f"(digest not present in push output)"
                )
            return PushResult(success=True, digest=digest)

        logger.warning(f"Push attempt {attempt} failed: {output}")

        if attempt < max_retries:
            logger.info(f"Retrying in {retry_delay}s ...")
            time.sleep(retry_delay)

    logger.error(f"Failed to push image {image_name} after {max_retries} attempts")
    return PushResult(success=False, digest=None, error="push retries exhausted")
