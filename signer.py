import logging
import os
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")
COSIGN_PRIV_KEY = "cosign.key"
COSIGN_PUB_KEY = "cosign.pub"

def ensure_cosign_key():
    """
    Ensure a local Cosign key pair exists (generate one if not).
    Returns True if a key is ready (cosign.key and cosign.pub in current directory).
    """
    if os.path.exists(COSIGN_PRIV_KEY) and os.path.exists(COSIGN_PUB_KEY):
        return True
    logger.info("Generating Cosign key pair for signing (no passphrase)...")
    env = os.environ.copy()
    env["COSIGN_PASSWORD"] = ""  # auto-confirm empty password
    code, output = run_cmd(["cosign", "generate-key-pair", "--output-key-prefix", "cosign"], env_override=env)
    if code != 0:
        logger.error(f"Cosign key generation failed:\n{output}")
        return False
    return True

def sign_image(image_ref, signing_mode):
    """
    Sign the given image reference (digest format recommended) using Cosign.
    signing_mode: "key" for local key, "keyless" for Sigstore keyless (OIDC).
    Returns True on successful signing (or if signing skipped).
    """
    if signing_mode == "none":
        return True  # not signing
    if signing_mode == "key":
        # Local key signing
        if not ensure_cosign_key():
            return False
        logger.info(f"Signing image {image_ref} with Cosign (local key)...")
        code, output = run_cmd([
            "cosign", "sign", "--allow-insecure-registry", "--key", COSIGN_PRIV_KEY, image_ref
        ])
    else:
        # Keyless signing using OIDC
        logger.info(f"Signing image {image_ref} with Cosign (keyless)...")
        env = {"COSIGN_EXPERIMENTAL": "1"}
        # Use --yes to avoid interactive prompts (non-interactive environment)
        code, output = run_cmd([
            "cosign", "sign", "--yes", "--allow-insecure-registry", image_ref
        ], env_override=env)
    if code != 0:
        logger.error(f"Image signing failed:\n{output}")
        return False
    logger.info("Image signed successfully.")
    return True

def verify_image(image_ref, signing_mode):
    """
    Verify the signature of the given image reference using Cosign.
    signing_mode: "key" or "keyless".
    Returns True if verification succeeds.
    """
    logger.info("Verifying image signature ...")
    if signing_mode == "key":
        cmd = ["cosign", "verify", "--allow-insecure-registry", "--key", COSIGN_PUB_KEY, image_ref]
        code, output = run_cmd(cmd)
    else:
        env = {"COSIGN_EXPERIMENTAL": "1"}
        cmd = ["cosign", "verify", "--allow-insecure-registry", image_ref]
        code, output = run_cmd(cmd, env_override=env)
    if code != 0:
        logger.error(f"Signature verification failed:\n{output}")
        return False
    logger.info("Signature verification passed.")
    return True
