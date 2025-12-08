import os
import json
import glob
import time

from .utils import run_cmd
from .scanner import scan_image, summarize, generate_sbom
from .patcher import patch_dockerfile


def docker(cmd):
    """Windows-safe docker wrapper"""
    if os.name == "nt":
        cmd[0] = "docker.exe"
    return run_cmd(cmd)


def cleanup(img):
    docker(["docker", "rmi", "-f", img])


def process_image(dockerfile_path):
    """
    FULL WORKFLOW:

    1. Build original image
    2. Vuln scan → BEFORE
    3. SBOM scan → BEFORE
    4. Patch Dockerfile (SBOM-aware)
    5. Build patched image
    6. Vuln scan → AFTER
    7. SBOM scan → AFTER
    8. Compare & save metrics
    """

    name = os.path.basename(dockerfile_path)
    print("\n====================================")
    print(f"[+] Processing {name}")

    # Read Dockerfile
    with open(dockerfile_path, "r", encoding="utf-8") as f:
        df_text = f.read()

    # -------------------------------------------------------
    # 1) BUILD ORIGINAL IMAGE
    # -------------------------------------------------------
    base = name.replace("Dockerfile.", "").replace("_latest", "")
    original_image = f"{base}:latest"

    print(f"[+] Building original image: {original_image}")
    code, _ = docker(["docker", "build", "-t", original_image, "-f", dockerfile_path, "."])
    if code != 0:
        print("[!] Failed to build original image.")
        return

    # -------------------------------------------------------
    # 2) VULN SCAN (BEFORE)
    # -------------------------------------------------------
    before_vuln_file = f"before_{name}.json"
    print("[+] Scanning vulnerabilities (BEFORE)...")
    before_json = scan_image(original_image, before_vuln_file)
    before_summary = summarize(before_json)
    before_total = sum(before_summary.values())

    # -------------------------------------------------------
    # 3) SBOM SCAN (BEFORE)
    # -------------------------------------------------------
    os.makedirs("sboms", exist_ok=True)
    before_sbom_file = os.path.join("sboms", f"sbom_before_{name}.json")

    print("[+] Generating SBOM (BEFORE)...")
    sbom_path = generate_sbom(original_image, before_sbom_file)

    # -------------------------------------------------------
    # 4) PATCH DOCKERFILE (SBOM-AWARE)
    # -------------------------------------------------------
    print("[+] Applying SBOM-aware patching...")

    patched_text, base_before, base_after = patch_dockerfile(
        df_text,
        sbom_path
    )

    os.makedirs("patched_dockerfiles", exist_ok=True)
    patched_df_path = os.path.join(
        "patched_dockerfiles",
        f"Dockerfile.{name}.patched"
    )

    with open(patched_df_path, "w", encoding="utf-8") as f:
        f.write(patched_text)

    print(f"[+] Patched Dockerfile saved → {patched_df_path}")

    # -------------------------------------------------------
    # 5) BUILD PATCHED IMAGE
    # -------------------------------------------------------
    patched_tag = f"{base}_patched_{int(time.time())}"
    print(f"[+] Building patched image: {patched_tag}")

    code, _ = docker(["docker", "build", "-t", patched_tag, "-f", patched_df_path, "."])
    if code != 0:
        print("[!] Failed to build patched image.")
        cleanup(original_image)
        return

    # -------------------------------------------------------
    # 6) VULN SCAN (AFTER)
    # -------------------------------------------------------
    after_vuln_file = f"after_{name}.json"
    print("[+] Scanning vulnerabilities (AFTER)...")
    after_json = scan_image(patched_tag, after_vuln_file)
    after_summary = summarize(after_json)
    after_total = sum(after_summary.values())

    # -------------------------------------------------------
    # 7) SBOM (AFTER)
    # -------------------------------------------------------
    after_sbom_file = os.path.join("sboms", f"sbom_after_{name}.json")
    print("[+] Generating SBOM (AFTER)...")
    generate_sbom(patched_tag, after_sbom_file)

    # -------------------------------------------------------
    # 8) CLEANUP IMAGES
    # -------------------------------------------------------
    print("[+] Removing images...")
    cleanup(original_image)
    cleanup(patched_tag)

    # -------------------------------------------------------
    # 9) SAVE FINAL METRICS
    # -------------------------------------------------------
    os.makedirs("evaluation_results", exist_ok=True)
    out_file = os.path.join("evaluation_results", f"{name}.json")

    results = {
        "image": name,
        "base_before": base_before,
        "base_after": base_after,
        "vulns_before": before_total,
        "vulns_after": after_total,
        "reduction": before_total - after_total,
        "before_breakdown": before_summary,
        "after_breakdown": after_summary,
        "sbom_before_path": before_sbom_file,
        "sbom_after_path": after_sbom_file
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"[✓] Metrics saved → {out_file}")


def run_all():
    dockerfiles = sorted(glob.glob("dockerfiles/Dockerfile.*"))
    print(f"[+] Found {len(dockerfiles)} Dockerfiles")
    for df in dockerfiles:
        try:
            process_image(df)
        except Exception as e:
            print(f"[!] ERROR processing {df}: {e}")


if __name__ == "__main__":
    run_all()
