import argparse
from .utils import log_step, extract_image_name, run_cmd
from .scanner import scan_image, summarize, generate_sbom
from .patcher import patch_dockerfile, extract_first_base
from .builder import build_image, tag_image, push_image
from .signer import sign_digest, verify_digest
from .comparer import compare
import sys


REGISTRY = "localhost:5000/autopatch"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dockerfile", required=True)
    args = parser.parse_args()

    dockerfile = args.dockerfile

    # --------------------------------------------
    # Read original Dockerfile
    # --------------------------------------------
    with open(dockerfile, "r", encoding="utf-8") as f:
        text = f.read()

    base, tag = extract_first_base(text)
    img_name = extract_image_name(base)

    LOCAL_ORIG = f"{img_name}-orig"
    LOCAL_PATCHED = f"{img_name}-patched"
    REGISTRY_PATCHED = f"{REGISTRY}/{img_name}-patched:latest"

    log_step(f"Found base image: {base}:{tag}")

    # --------------------------------------------
    # Build original image
    # --------------------------------------------
    if not build_image(LOCAL_ORIG, dockerfile):
        log_step("[!] Failed building original image")
        return

    before_json = scan_image(LOCAL_ORIG, "trivy_before.json")
    before_summary = summarize(before_json)
    log_step(f"BEFORE summary: {before_summary}")

    generate_sbom(LOCAL_ORIG, "sbom_before.json")

    # --------------------------------------------
    # Patch Dockerfile → build patched image
    # --------------------------------------------
    patched_text, old, new = patch_dockerfile(text, "sbom_before.json")
    with open("Dockerfile.patched", "w", encoding="utf-8") as f:
        f.write(patched_text)

    log_step(f"Patched Dockerfile uses: {new}")

    if not build_image(LOCAL_PATCHED, "Dockerfile.patched"):
        log_step("[!] Failed to build patched image")
        return

    # --------------------------------------------
    # Tag patched image for registry
    # --------------------------------------------
    log_step(f"Tagging for registry: {LOCAL_PATCHED} → {REGISTRY_PATCHED}")
    if not tag_image(LOCAL_PATCHED, REGISTRY_PATCHED):
        log_step("[!] Tagging failed")
        return

    # --------------------------------------------
    # Push to registry
    # --------------------------------------------
    if not push_image(REGISTRY_PATCHED):
        log_step("[!] Push to registry FAILED")
        return

    # --------------------------------------------
    # CRITICAL FIX: Remove local tag to avoid Docker fallback
    # --------------------------------------------
    log_step("Removing local patched image to force digest resolution from registry...")
    run_cmd(["docker", "rmi", "-f", LOCAL_PATCHED])

    # --------------------------------------------
    # Pull only the registry tag
    # --------------------------------------------
    log_step("Pulling patched image from registry to obtain digest...")
    code, out = run_cmd(["docker", "pull", REGISTRY_PATCHED])
    if code != 0:
        log_step("[!] FAILED to pull from registry!")
        print(out)
        return

    # --------------------------------------------
    # Inspect registry image for correct registry-backed digest
    # --------------------------------------------
    code, out = run_cmd([
        "docker", "inspect",
        "--format={{index .RepoDigests 0}}",
        REGISTRY_PATCHED
    ])

    if code != 0 or "@" not in out:
        log_step("[!] docker inspect FAILED to retrieve digest")
        print(out)
        return

    digest_ref = out.strip()
    log_step(f"Resolved patched image digest ref: {digest_ref}")

    # --------------------------------------------
    # Cosign signature + verification
    # --------------------------------------------
    if not sign_digest(digest_ref):
        log_step("[!] Signing FAILED")
        return

    if not verify_digest(digest_ref):
        log_step("[!] Verification FAILED")
        return

    log_step("Cosign trust verification PASSED.")

    # --------------------------------------------
    # AFTER scan: IMPORTANT — scan registry image, NOT deleted local one
    # --------------------------------------------
    after_json = scan_image(REGISTRY_PATCHED, "trivy_after.json")
    after_summary = summarize(after_json)
    log_step(f"AFTER summary: {after_summary}")

    generate_sbom(LOCAL_PATCHED, "sbom_after.json")

    # --------------------------------------------
    # Vulnerability reduction output
    # --------------------------------------------
    diff = compare(before_summary, after_summary)
    log_step("Vulnerability reduction:")
    print(diff)


if __name__ == "__main__":
    main()
