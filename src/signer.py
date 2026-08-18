import json
import logging
import os
import time
import enum
import threading
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")


# Custom exception types for better error handling

class SigningMode(str, enum.Enum):
    """Canonical signing-mode values. Subclassing :class:`str` keeps
    ``signing_mode == "key"`` comparisons working for the existing
    string-typed callers."""
    KEYLESS = "keyless"
    KEY = "key"
    NONE = "none"

    @classmethod
    def values(cls):
        return [m.value for m in cls]


class SigningError(Exception):
    """Base exception for signing operations."""
    pass


class KeyGenerationError(SigningError):
    """Raised when Cosign key generation fails."""
    pass


class SignatureError(SigningError):
    """Raised when image signing fails."""
    pass


class VerificationError(SigningError):
    """Raised when signature verification fails."""
    pass


class AttestationError(SigningError):
    """Raised when attestation generation or attachment fails."""
    pass


class SBOMError(SigningError):
    """Raised when SBOM attachment fails."""
    pass


@dataclass
class SigningLog:
    """Structured log entry for signing operations."""
    timestamp: str
    image_ref: str
    signing_mode: str
    operation: str  # "sign", "verify", "attestation", "sbom", etc.
    success: bool
    duration_seconds: float
    error_message: Optional[str] = None


# Global signing log storage (thread-safe)
_signing_logs: List[SigningLog] = []
_signing_logs_lock = threading.Lock()


class UnsealedKeyError(RuntimeError):
    """Raised when COSIGN_PASSWORD is unset and the operator has not
    explicitly opted in to an unsealed key with AUTOPATCH_ALLOW_UNSEALED_KEY=1."""


def _get_cosign_password() -> str:
    """
    Return the Cosign passphrase from ``COSIGN_PASSWORD``.

    A non-empty passphrase is REQUIRED by default for two reasons:
    (1) cosign will write the unencrypted private key to disk if the
    passphrase is empty during ``generate-key-pair``, and (2) every
    subsequent ``cosign sign`` invocation will accept the unsealed key
    without prompting. Both turn a security-tool signing claim into
    signature theatre.

    Operators that legitimately need unsealed keys (e.g. air-gapped CI
    using ephemeral keys discarded at the end of the run) can opt in
    by setting ``AUTOPATCH_ALLOW_UNSEALED_KEY=1``.

    Raises:
        UnsealedKeyError: COSIGN_PASSWORD unset and no explicit opt-in.
    """
    pw = os.environ.get("COSIGN_PASSWORD", "")
    if pw:
        return pw
    if os.environ.get("AUTOPATCH_ALLOW_UNSEALED_KEY") == "1":
        logger.warning(
            "COSIGN_PASSWORD unset but AUTOPATCH_ALLOW_UNSEALED_KEY=1 "
            "is set; proceeding with unsealed key. Private key material "
            "will be readable on disk; do not retain after the run."
        )
        return ""
    raise UnsealedKeyError(
        "COSIGN_PASSWORD is not set. Refusing to use an unsealed signing "
        "key. Set COSIGN_PASSWORD to a non-empty value, or pass "
        "AUTOPATCH_ALLOW_UNSEALED_KEY=1 if you explicitly want a key with "
        "no passphrase (e.g. air-gapped CI with ephemeral keys)."
    )



class KeylessIdentityNotConfigured(RuntimeError):
    """Raised when keyless verification is requested without an explicit
    identity regex configured."""


_DEFAULT_OIDC_ISSUERS = (
    r"https://accounts\.google\.com"
    r"|https://github\.com/login/oauth"
    r"|https://token\.actions\.githubusercontent\.com"
)


def _anchor(pattern: str) -> str:
    """Wrap ``pattern`` so it must match the WHOLE certificate field.

    Cosign passes ``--certificate-*-regexp`` to Go's ``regexp.MatchString``,
    which succeeds on a match anywhere in the string. An unanchored
    issuer pattern such as ``https://token\\.actions\\.githubusercontent\\.com``
    therefore also accepts an attacker-controlled issuer that merely
    contains it, e.g.
    ``https://evil.example/?x=https://token.actions.githubusercontent.com``.
    An OIDC issuer is a URL an adversary can choose freely, so the
    substring match is a real trust-boundary bypass and not a
    theoretical one.

    A pattern is left unchanged ONLY when it is already anchored AND
    has no top-level alternation. Checking ``startswith("^") and
    endswith("$")`` alone is not sufficient and was itself a bypass:
    ``^alpha|beta$`` satisfies that test, but Go parses it as
    ``(^alpha)|(beta$)``, so the second branch matches any string
    ENDING in "beta" from anywhere. An operator writing a perfectly
    reasonable multi-branch identity regexp with outer anchors would
    have got exactly the trust-boundary bypass this function exists to
    prevent. A top-level ``|`` therefore forces the wrap regardless of
    existing anchors, and the redundant anchors inside the group are
    harmless.
    """
    p = pattern.strip()
    if p.startswith("^") and p.endswith("$") and not _has_top_level_alternation(p):
        return p
    return f"^(?:{p})$"


def _has_top_level_alternation(pattern: str) -> bool:
    """True if ``pattern`` contains a ``|`` outside any group or class.

    Only a top-level alternation splits the anchors. ``^(?:a|b)$`` is
    already safe because the ``|`` is inside a group; ``^a|b$`` is not.
    Escaped ``\\|`` is a literal pipe and does not alternate.
    """
    depth = 0
    in_class = False
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2                      # skip the escaped character
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "|" and depth == 0:
            return True
        i += 1
    return False


def _resolve_keyless_issuer() -> str:
    """Return the anchored certificate-oidc-issuer-regexp for cosign."""
    return _anchor(os.environ.get(
        "COSIGN_CERTIFICATE_OIDC_ISSUER_REGEXP", _DEFAULT_OIDC_ISSUERS))


def _resolve_keyless_identity(verbose_op: str = "verify") -> str:
    """Return the certificate-identity-regexp to pass to cosign.

    Refuses the historical default of ``.*`` (any Fulcio identity)
    unless ``AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY=1`` is set, since
    accepting any cert defeats the purpose of keyless verification.
    The returned pattern is anchored for the reason given in
    :func:`_anchor`: an unanchored identity regexp accepts any subject
    that merely contains the trusted one.
    """
    val = os.environ.get("COSIGN_CERTIFICATE_IDENTITY_REGEXP")
    if val and val != ".*":
        return _anchor(val)
    if os.environ.get("AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY") == "1":
        logger.warning(
            "Cosign %s: COSIGN_CERTIFICATE_IDENTITY_REGEXP unset or '.*' "
            "but AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY=1; accepting ANY "
            "Fulcio-signed certificate. Not safe for production.",
            verbose_op,
        )
        return ".*"
    raise KeylessIdentityNotConfigured(
        f"Cosign {verbose_op} requires an explicit identity. Set "
        "COSIGN_CERTIFICATE_IDENTITY_REGEXP to a regex matching the "
        "OIDC subject(s) you trust (e.g. "
        "'^https://github\\.com/your-org/.+@refs/heads/main$'). "
        "To accept any Fulcio identity (NOT RECOMMENDED) set "
        "AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY=1."
    )

def get_signing_log() -> List[Dict[str, Any]]:
    """
    Return the accumulated signing log entries as dictionaries.

    Returns:
        List of signing log entries as dictionaries with all operation details.
    """
    with _signing_logs_lock:
        return [asdict(log) for log in _signing_logs]


def clear_signing_logs() -> None:
    """
    Clear all accumulated signing log entries.

    Useful for testing and batch processing where fresh logs are needed.
    """
    global _signing_logs
    with _signing_logs_lock:
        _signing_logs = []


def _record_signing_log(
    image_ref: str,
    signing_mode: str,
    operation: str,
    success: bool,
    duration_seconds: float,
    error_message: Optional[str] = None
) -> None:
    """
    Record a signing operation to the structured log.

    Args:
        image_ref: Docker image reference.
        signing_mode: "key", "keyless", or "none".
        operation: Type of operation ("sign", "verify", "attestation", "sbom").
        success: Whether the operation succeeded.
        duration_seconds: How long the operation took.
        error_message: Error details if operation failed.
    """
    log_entry = SigningLog(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        image_ref=image_ref,
        signing_mode=signing_mode,
        operation=operation,
        success=success,
        duration_seconds=duration_seconds,
        error_message=error_message
    )
    with _signing_logs_lock:
        _signing_logs.append(log_entry)


def _default_key_dir() -> str:
    """Per-user key directory. Created with 0o700 if it does not exist
    so private key material never lands in a world-readable CWD."""
    base = os.path.expanduser("~/.autopatch/keys")
    os.makedirs(base, mode=0o700, exist_ok=True)
    # Re-tighten in case the dir already existed with looser permissions.
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def ensure_cosign_key(key_dir: Optional[str] = None) -> bool:
    """
    Ensure a local Cosign key pair exists (generate one if not).

    Args:
        key_dir: Directory to store key files. Defaults to
            ``~/.autopatch/keys`` (created with 0o700 if missing).
            The previous default of CWD leaked private key material
            into pipeline workspaces.

    Returns:
        True if a key pair is ready.

    Raises:
        KeyGenerationError: If key generation fails.
        UnsealedKeyError: If COSIGN_PASSWORD is unset and the operator
            has not explicitly opted in to AUTOPATCH_ALLOW_UNSEALED_KEY=1.
    """
    if key_dir is None:
        key_dir = _default_key_dir()
    else:
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        # makedirs' mode is a no-op on a directory that already exists,
        # so an operator pointing --key-dir at a world-readable path got
        # no protection at all. Match what _default_key_dir does.
        try:
            os.chmod(key_dir, 0o700)
        except OSError as e:
            logger.warning("Could not restrict %s to 0700 (%s)", key_dir, e)

    priv_key_path = os.path.join(key_dir, "cosign.key")
    pub_key_path = os.path.join(key_dir, "cosign.pub")

    if os.path.exists(priv_key_path) and os.path.exists(pub_key_path):
        return True

    # Resolving the passphrase BEFORE invoking cosign means we surface
    # UnsealedKeyError to the operator instead of producing an unsealed
    # key on disk.
    passphrase = _get_cosign_password()
    logger.info(f"Generating Cosign key pair in {key_dir}")
    code, output = run_cmd(
        ["cosign", "generate-key-pair", "--output-key-prefix", os.path.join(key_dir, "cosign")],
        env_override={"COSIGN_PASSWORD": passphrase},
    )
    if code != 0:
        error_msg = f"Cosign key generation failed:\n{output}"
        logger.error(error_msg)
        raise KeyGenerationError(error_msg)
    # cosign can exit 0 without producing key material (wrong
    # --output-key-prefix, a read-only mount). Reporting success here
    # deferred the failure to the next `cosign sign`, which then failed
    # with an opaque "no such file or directory" pointing at a path the
    # operator never typed.
    if not (os.path.exists(priv_key_path) and os.path.exists(pub_key_path)):
        raise KeyGenerationError(
            f"cosign exited 0 but no key pair is present at {key_dir} "
            f"(expected cosign.key and cosign.pub). Output:\n{output}"
        )
    # Tighten file mode on the generated private key.
    try:
        os.chmod(priv_key_path, 0o600)
    except OSError as e:
        logger.warning(
            "Could not restrict permissions on %s (%s); the private key "
            "may be readable by other users on this host.", priv_key_path, e,
        )
    return True


def sign_image(
    image_ref: str,
    signing_mode: str,
    insecure_registry: bool = False,
    key_dir: Optional[str] = None
) -> bool:
    """
    Sign the given image reference using Cosign.

    Args:
        image_ref: Docker image reference (digest format recommended).
        signing_mode: "key" for local key, "keyless" for Sigstore keyless (OIDC),
                     "none" to skip signing.
        insecure_registry: If True, allow insecure registries. Defaults to False (secure).
        key_dir: Directory containing Cosign keys (for "key" mode). Defaults to current directory.

    Returns:
        True on successful signing (or if signing skipped with "none").

    Raises:
        SignatureError: If signing fails.
        KeyGenerationError: If key generation fails (for "key" mode).
    """
    start_time = time.time()
    error_message = None

    try:
        if signing_mode == "none":
            # Record this as "skip", NOT as a successful "sign". The
            # signing log is what the report and the reviewer read to
            # decide whether the artefact is signed; a success=True
            # "sign" entry for a run in which cosign was never invoked
            # is a false provenance claim. The return value stays True
            # because skipping is not an error for the caller.
            logger.info("Signing skipped (mode=none).")
            duration = time.time() - start_time
            _record_signing_log(
                image_ref, signing_mode, "skip", True, duration,
                "signing disabled (--signing-mode none); image is UNSIGNED",
            )
            return True

        if signing_mode == "key":
            # Local key signing with environment-driven password.
            # C4 fix: resolve key_dir to the same per-user default that
            # ensure_cosign_key uses BEFORE building priv_key_path. The old
            # code generated the key in ~/.autopatch/keys but then signed
            # with ./cosign.key, so default key-mode signing either failed
            # with "key not found" or silently used a stale leftover key.
            if key_dir is None:
                key_dir = _default_key_dir()
            ensure_cosign_key(key_dir=key_dir)
            priv_key_path = os.path.join(key_dir, "cosign.key")
            logger.info(f"Signing image {image_ref} with Cosign (local key)...")
            env = {"COSIGN_PASSWORD": _get_cosign_password()}
            cmd = ["cosign", "sign", "--yes"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.extend(["--key", priv_key_path, image_ref])
            code, output = run_cmd(cmd, env_override=env, timeout=90)
        elif signing_mode == "keyless":
            # Keyless signing using Sigstore OIDC (Cosign v2+ compatible)
            logger.info(f"Signing image {image_ref} with Cosign (keyless)...")
            env = {"COSIGN_YES": "true"}
            cmd = ["cosign", "sign", "--yes"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.append(image_ref)
            code, output = run_cmd(cmd, env_override=env, timeout=90)
        else:
            _record_signing_log(
                image_ref, str(signing_mode), "sign", False,
                time.time() - start_time,
                f"Unknown signing mode: {signing_mode}",
            )
            raise SignatureError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Image signing failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, signing_mode, "sign", False, duration, error_message)
            raise SignatureError(error_message)

        logger.info("Image signed successfully.")
        _record_signing_log(image_ref, signing_mode, "sign", True, duration)
        return True

    except SignatureError:
        raise
    except (KeyGenerationError, UnsealedKeyError):
        # Key SETUP failure is a different operational problem from a
        # registry rejecting a signature, and a caller branching on the
        # exception type to decide whether to retry or to page a human
        # needs to tell them apart. Re-wrapping both as SignatureError
        # (as the blanket handler below did) made that impossible and
        # contradicted this function's own documented Raises clause.
        duration = time.time() - start_time
        _record_signing_log(image_ref, signing_mode, "sign", False,
                            duration, "key setup failed")
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "sign", False, duration, error_message)
        raise SignatureError(f"Unexpected error during signing: {error_message}")


def verify_image(
    image_ref: str,
    signing_mode: str,
    insecure_registry: bool = False,
    key_dir: Optional[str] = None
) -> bool:
    """
    Verify the signature of the given image reference using Cosign.

    Args:
        image_ref: Docker image reference.
        signing_mode: "key" for local key verification, "keyless" for Sigstore keyless.
        insecure_registry: If True, allow insecure registries. Defaults to False (secure).
        key_dir: Directory containing Cosign public key (for "key" mode). Defaults to current directory.

    Returns:
        True if verification succeeds.

    Raises:
        VerificationError: If verification fails.
    """
    start_time = time.time()
    error_message = None

    try:
        logger.info("Verifying image signature...")
        if signing_mode == "key":
            # C4 fix: read the public key from the same per-user default
            # directory the key pair was generated in, not CWD.
            if key_dir is None:
                key_dir = _default_key_dir()
            pub_key_path = os.path.join(key_dir, "cosign.pub")
            cmd = ["cosign", "verify"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.extend(["--key", pub_key_path, image_ref])
            code, output = run_cmd(cmd, timeout=90)
        elif signing_mode == "keyless":
            # Cosign v2 requires explicit certificate identity for keyless verification.
            # Use regexp matchers to accept any Sigstore OIDC-issued certificate.
            # In production, narrow these to your org's identity and issuer.
            cert_identity = _resolve_keyless_identity("verify")
            cert_issuer = _resolve_keyless_issuer()
            cmd = ["cosign", "verify",
                   "--certificate-identity-regexp", cert_identity,
                   "--certificate-oidc-issuer-regexp", cert_issuer]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.append(image_ref)
            code, output = run_cmd(cmd, timeout=90)
        else:
            raise VerificationError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Signature verification failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, signing_mode, "verify", False, duration, error_message)
            raise VerificationError(error_message)

        logger.info("Signature verification passed.")
        _record_signing_log(image_ref, signing_mode, "verify", True, duration)
        return True

    except VerificationError:
        raise
    except KeylessIdentityNotConfigured:
        # "You have not told me whose signature to trust" is not the
        # same event as "this signature is invalid". Collapsing them
        # meant a misconfigured pipeline looked exactly like a
        # tampered artefact.
        _record_signing_log(image_ref, signing_mode, "verify", False,
                            time.time() - start_time,
                            "keyless identity not configured")
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "verify", False, duration, error_message)
        raise VerificationError(f"Unexpected error during verification: {error_message}")


def generate_attestation(
    image_ref: str,
    predicate_path: str,
    predicate_type: str = "slsaprovenance",
    insecure_registry: bool = False,
    signing_mode: str = "keyless",
    key_dir: Optional[str] = None,
) -> bool:
    """
    Generate and attach an in-toto attestation to the image.

    Args:
        image_ref: Docker image reference (digest format required by cosign).
        predicate_path: Path to the predicate file (JSON).
        predicate_type: Type of attestation predicate (default: "slsaprovenance").
        insecure_registry: If True, allow insecure registries. Defaults to False (secure).
        signing_mode: "key", "keyless", or "none". Previously this function
            took no mode at all: it never passed ``--key``, so a pipeline
            configured for key-based signing silently produced a KEYLESS
            attestation (or failed outright in an environment with no OIDC
            provider), and every log entry claimed mode "keyless"
            regardless of how the run was actually configured. The
            attestation is the artefact a downstream verifier trusts, so
            a mode mismatch between the signature and the log is a
            provenance defect, not a cosmetic one.
        key_dir: Directory holding cosign.key for "key" mode. Defaults to
            the same per-user directory :func:`ensure_cosign_key` uses.

    Returns:
        True if attestation generation succeeds. For ``signing_mode="none"``
        returns False without invoking cosign, because an unsigned
        predicate on disk is not an attestation.

    Raises:
        AttestationError: If attestation generation fails.
    """
    start_time = time.time()
    error_message = None

    try:
        if signing_mode == "none":
            logger.info(
                "Attestation skipped (mode=none); predicate written to "
                "%s but NOT signed or attached.", predicate_path
            )
            _record_signing_log(
                image_ref, "none", "attestation", False,
                time.time() - start_time,
                "signing disabled (--signing-mode none); predicate is UNSIGNED",
            )
            return False

        if signing_mode not in ("key", "keyless"):
            raise AttestationError(f"Unknown signing mode: {signing_mode}")

        if not os.path.exists(predicate_path):
            raise AttestationError(f"Predicate file not found: {predicate_path}")

        logger.info(
            "Generating %s attestation for %s (mode=%s)...",
            predicate_type, image_ref, signing_mode,
        )
        logger.info(f"Using predicate from: {predicate_path}")

        cmd = ["cosign", "attest", "--yes"]
        if insecure_registry:
            cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])

        env: Dict[str, str] = {}
        if signing_mode == "key":
            if key_dir is None:
                key_dir = _default_key_dir()
            ensure_cosign_key(key_dir=key_dir)
            cmd.extend(["--key", os.path.join(key_dir, "cosign.key")])
            env["COSIGN_PASSWORD"] = _get_cosign_password()
        else:
            env["COSIGN_YES"] = "true"

        cmd.extend([
            "--predicate", predicate_path,
            "--type", predicate_type,
            image_ref
        ])
        code, output = run_cmd(cmd, env_override=env, timeout=90)

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Attestation generation failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, signing_mode, "attestation", False, duration, error_message)
            raise AttestationError(error_message)

        logger.info("Attestation generated and attached successfully.")
        _record_signing_log(image_ref, signing_mode, "attestation", True, duration)
        return True

    except AttestationError:
        raise
    except (KeyGenerationError, UnsealedKeyError):
        _record_signing_log(image_ref, signing_mode, "attestation", False,
                            time.time() - start_time, "key setup failed")
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "attestation", False, duration, error_message)
        raise AttestationError(f"Unexpected error during attestation: {error_message}")


def attach_sbom(
    image_ref: str,
    sbom_path: str,
    signing_mode: str,
    insecure_registry: bool = False
) -> bool:
    """
    Attach an SBOM (Software Bill of Materials) to the image.

    Args:
        image_ref: Docker image reference (digest format recommended).
        sbom_path: Path to the SBOM file (typically in SPDX JSON format).
        signing_mode: "key" for local key, "keyless" for Sigstore keyless.
        insecure_registry: If True, allow insecure registries. Defaults to False (secure).

    Returns:
        True if SBOM attachment succeeds.

    Raises:
        SBOMError: If SBOM attachment fails.
    """
    start_time = time.time()
    error_message = None

    try:
        if not os.path.exists(sbom_path):
            raise SBOMError(f"SBOM file not found: {sbom_path}")

        logger.info(f"Attaching SBOM to {image_ref}...")
        logger.info(f"Using SBOM from: {sbom_path}")

        # cosign attach sbom does NOT take --key; it simply attaches the
        # SBOM as an OCI artifact. Signing the SBOM is a separate step.
        if signing_mode in ("key", "keyless"):
            cmd = ["cosign", "attach", "sbom"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.extend(["--sbom", sbom_path, image_ref])
            code, output = run_cmd(cmd, timeout=90)
        else:
            raise SBOMError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"SBOM attachment failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, signing_mode, "sbom", False, duration, error_message)
            raise SBOMError(error_message)

        logger.info("SBOM attached successfully.")
        _record_signing_log(image_ref, signing_mode, "sbom", True, duration)
        return True

    except SBOMError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "sbom", False, duration, error_message)
        raise SBOMError(f"Unexpected error during SBOM attachment: {error_message}")


def verify_attestation(
    image_ref: str,
    signing_mode: str,
    insecure_registry: bool = False,
    key_dir: Optional[str] = None
) -> bool:
    """
    Verify attestations attached to the image.

    Args:
        image_ref: Docker image reference.
        signing_mode: "key" for local key verification, "keyless" for Sigstore keyless.
        insecure_registry: If True, allow insecure registries. Defaults to False (secure).
        key_dir: Directory containing Cosign public key (for "key" mode). Defaults to current directory.

    Returns:
        True if attestation verification succeeds.

    Raises:
        VerificationError: If attestation verification fails.
    """
    start_time = time.time()
    error_message = None

    try:
        logger.info("Verifying image attestations...")
        if signing_mode == "key":
            # C4 fix: read the public key from the same per-user default
            # directory the key pair was generated in, not CWD.
            if key_dir is None:
                key_dir = _default_key_dir()
            pub_key_path = os.path.join(key_dir, "cosign.pub")
            cmd = ["cosign", "verify-attestation"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.extend(["--key", pub_key_path, image_ref])
            code, output = run_cmd(cmd, timeout=90)
        elif signing_mode == "keyless":
            # Cosign v2 requires explicit certificate identity for keyless verification
            cert_identity = _resolve_keyless_identity("verify-attestation")
            cert_issuer = _resolve_keyless_issuer()
            cmd = ["cosign", "verify-attestation",
                   "--certificate-identity-regexp", cert_identity,
                   "--certificate-oidc-issuer-regexp", cert_issuer]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.append(image_ref)
            code, output = run_cmd(cmd, timeout=90)
        else:
            raise VerificationError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Attestation verification failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(
                image_ref, signing_mode, "verify_attestation", False, duration, error_message
            )
            raise VerificationError(error_message)

        logger.info("Attestation verification passed.")
        _record_signing_log(image_ref, signing_mode, "verify_attestation", True, duration)
        return True

    except VerificationError:
        raise
    except KeylessIdentityNotConfigured:
        # "You have not told me whose signature to trust" is not the
        # same event as "this signature is invalid". Collapsing them
        # meant a misconfigured pipeline looked exactly like a
        # tampered artefact.
        _record_signing_log(image_ref, signing_mode, "verify_attestation", False,
                            time.time() - start_time,
                            "keyless identity not configured")
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "verify_attestation", False, duration, error_message)
        raise VerificationError(f"Unexpected error during attestation verification: {error_message}")
