import json
import logging
import os
import time
import threading
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")


# Custom exception types for better error handling
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


def _get_cosign_password() -> str:
    """
    Get the Cosign password from environment or return empty string.

    Returns:
        Cosign password from COSIGN_PASSWORD env var, or empty string.
    """
    pw = os.environ.get("COSIGN_PASSWORD", "")
    if not pw:
        logger.warning("COSIGN_PASSWORD not set; using empty passphrase. "
                      "Set COSIGN_PASSWORD env var for production use.")
    return pw


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


def ensure_cosign_key(key_dir: Optional[str] = None) -> bool:
    """
    Ensure a local Cosign key pair exists (generate one if not).

    Args:
        key_dir: Directory to store key files. Defaults to current directory.

    Returns:
        True if a key pair is ready.

    Raises:
        KeyGenerationError: If key generation fails.
    """
    if key_dir is None:
        key_dir = "."

    priv_key_path = os.path.join(key_dir, "cosign.key")
    pub_key_path = os.path.join(key_dir, "cosign.pub")

    if os.path.exists(priv_key_path) and os.path.exists(pub_key_path):
        return True

    logger.info(f"Generating Cosign key pair in {key_dir} (no passphrase)...")
    code, output = run_cmd(
        ["cosign", "generate-key-pair", "--output-key-prefix", os.path.join(key_dir, "cosign")],
        env_override={"COSIGN_PASSWORD": ""}
    )
    if code != 0:
        error_msg = f"Cosign key generation failed:\n{output}"
        logger.error(error_msg)
        raise KeyGenerationError(error_msg)
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
            logger.info("Signing skipped (mode=none).")
            duration = time.time() - start_time
            _record_signing_log(image_ref, signing_mode, "sign", True, duration)
            return True

        if signing_mode == "key":
            # Local key signing with environment-driven password
            ensure_cosign_key(key_dir=key_dir)
            if key_dir is None:
                key_dir = "."
            priv_key_path = os.path.join(key_dir, "cosign.key")
            logger.info(f"Signing image {image_ref} with Cosign (local key)...")
            env = {"COSIGN_PASSWORD": _get_cosign_password()}
            cmd = ["cosign", "sign", "--yes"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.extend(["--key", priv_key_path, image_ref])
            code, output = run_cmd(cmd, env_override=env)
        elif signing_mode == "keyless":
            # Keyless signing using Sigstore OIDC (Cosign v2+ compatible)
            logger.info(f"Signing image {image_ref} with Cosign (keyless)...")
            env = {"COSIGN_YES": "true"}
            cmd = ["cosign", "sign", "--yes"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.append(image_ref)
            code, output = run_cmd(cmd, env_override=env)
        else:
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
            if key_dir is None:
                key_dir = "."
            pub_key_path = os.path.join(key_dir, "cosign.pub")
            cmd = ["cosign", "verify"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.extend(["--key", pub_key_path, image_ref])
            code, output = run_cmd(cmd)
        elif signing_mode == "keyless":
            # Cosign v2 requires explicit certificate identity for keyless verification.
            # Use regexp matchers to accept any Sigstore OIDC-issued certificate.
            # In production, narrow these to your org's identity and issuer.
            cert_identity = os.environ.get(
                "COSIGN_CERTIFICATE_IDENTITY_REGEXP", ".*"
            )
            cert_issuer = os.environ.get(
                "COSIGN_CERTIFICATE_OIDC_ISSUER_REGEXP",
                "https://accounts\\.google\\.com|https://github\\.com/login/oauth|https://token\\.actions\\.githubusercontent\\.com"
            )
            cmd = ["cosign", "verify",
                   "--certificate-identity-regexp", cert_identity,
                   "--certificate-oidc-issuer-regexp", cert_issuer]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.append(image_ref)
            code, output = run_cmd(cmd)
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
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "verify", False, duration, error_message)
        raise VerificationError(f"Unexpected error during verification: {error_message}")


def generate_attestation(
    image_ref: str,
    predicate_path: str,
    predicate_type: str = "slsaprovenance",
    insecure_registry: bool = False
) -> bool:
    """
    Generate and attach a SLSA provenance attestation to the image.

    Args:
        image_ref: Docker image reference (digest format recommended).
        predicate_path: Path to the predicate file (JSON).
        predicate_type: Type of attestation predicate (default: "slsaprovenance").
        insecure_registry: If True, allow insecure registries. Defaults to False (secure).

    Returns:
        True if attestation generation succeeds.

    Raises:
        AttestationError: If attestation generation fails.
    """
    start_time = time.time()
    error_message = None

    try:
        if not os.path.exists(predicate_path):
            raise AttestationError(f"Predicate file not found: {predicate_path}")

        logger.info(f"Generating {predicate_type} attestation for {image_ref}...")
        logger.info(f"Using predicate from: {predicate_path}")

        cmd = ["cosign", "attest", "--yes"]
        if insecure_registry:
            cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
        cmd.extend([
            "--predicate", predicate_path,
            "--type", predicate_type,
            image_ref
        ])
        code, output = run_cmd(cmd)

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Attestation generation failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, "keyless", "attestation", False, duration, error_message)
            raise AttestationError(error_message)

        logger.info(f"Attestation generated and attached successfully.")
        _record_signing_log(image_ref, "keyless", "attestation", True, duration)
        return True

    except AttestationError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, "keyless", "attestation", False, duration, error_message)
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
            code, output = run_cmd(cmd)
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
            if key_dir is None:
                key_dir = "."
            pub_key_path = os.path.join(key_dir, "cosign.pub")
            cmd = ["cosign", "verify-attestation"]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.extend(["--key", pub_key_path, image_ref])
            code, output = run_cmd(cmd)
        elif signing_mode == "keyless":
            # Cosign v2 requires explicit certificate identity for keyless verification
            cert_identity = os.environ.get(
                "COSIGN_CERTIFICATE_IDENTITY_REGEXP", ".*"
            )
            cert_issuer = os.environ.get(
                "COSIGN_CERTIFICATE_OIDC_ISSUER_REGEXP",
                "https://accounts\\.google\\.com|https://github\\.com/login/oauth|https://token\\.actions\\.githubusercontent\\.com"
            )
            cmd = ["cosign", "verify-attestation",
                   "--certificate-identity-regexp", cert_identity,
                   "--certificate-oidc-issuer-regexp", cert_issuer]
            if insecure_registry:
                cmd.extend(["--allow-insecure-registry", "--allow-http-registry"])
            cmd.append(image_ref)
            code, output = run_cmd(cmd)
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
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "verify_attestation", False, duration, error_message)
        raise VerificationError(f"Unexpected error during attestation verification: {error_message}")
