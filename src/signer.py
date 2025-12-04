from .utils import run_cmd, log_step
import os

COSIGN = "cosign"
PRIV = "cosign.key"
PUB = "cosign.pub"


def ensure_keys():
    if os.path.exists(PRIV) and os.path.exists(PUB):
        return True

    log_step("Generating cosign key pair (empty password via environment)...")

    env = os.environ.copy()
    env["COSIGN_PASSWORD"] = ""   # <= IMPORTANT: no prompt

    cmd = [
        COSIGN,
        "generate-key-pair",
        "--output-key-prefix", "cosign"
    ]

    code, out = run_cmd(cmd, env_override=env)

    if code != 0:
        print(out)
        return False

    return True


def sign_digest(digest_ref: str):
    if not ensure_keys():
        return False
    log_step(f"Signing digest {digest_ref} ...")
    code, out = run_cmd([
        COSIGN, "sign",
        "--allow-insecure-registry",
        "--key", PRIV,
        digest_ref
    ])
    if code != 0:
        print(out)
        return False
    log_step("Cosign signing succeeded")
    return True


def verify_digest(digest_ref: str):
    log_step("Verifying signature ...")
    code, out = run_cmd([
        COSIGN, "verify",
        "--allow-insecure-registry",
        "--key", PUB,
        digest_ref
    ])
    if code != 0:
        print(out)
        return False
    log_step("Cosign verification succeeded")
    return True
