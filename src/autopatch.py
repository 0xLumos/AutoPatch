# Imports and Configuration
import argparse
import subprocess
import json
import logging
import os
from datetime import datetime

# Configure a basic logger (console output). Verbosity level will be adjusted via CLI.
logger = logging.getLogger("docker_patch_tool")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Utility Functions
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

# Docker Build and Push Operations
def build_image(image_name, dockerfile_path):
    """
    Build a Docker image with the given name (tag) from the specified Dockerfile.
    Returns True if build succeeds, False otherwise.
    """
    context_dir = os.path.dirname(os.path.abspath(dockerfile_path)) or "."
    logger.info(f"Building image '{image_name}' from {dockerfile_path} ...")
    cmd = ["docker", "build", "-t", image_name, "-f", dockerfile_path, context_dir]
    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(f"Docker build failed for {image_name}:\n{output}")
        return False
    logger.debug(f"Docker build output for {image_name}: {output}")
    return True

def tag_image(source_image, target_image):
    """Tag a local Docker image with a new name/tag (usually for pushing to a registry)."""
    logger.info(f"Tagging image '{source_image}' as '{target_image}' ...")
    code, output = run_cmd(["docker", "tag", source_image, target_image])
    if code != 0:
        logger.error(f"Failed to tag image {source_image} as {target_image}: {output}")
        return False
    return True

def push_image(image_name):
    """Push a Docker image to a registry."""
    logger.info(f"Pushing image '{image_name}' to registry ...")
    code, output = run_cmd(["docker", "push", image_name])
    if code != 0:
        logger.error(f"Failed to push image {image_name}:\n{output}")
        return False
    return True

# Dockerfile Parsing and Patching
def parse_dockerfile_stages(dockerfile_text):
    """
    Parse Dockerfile text into a list of stages.
    Each stage is represented as a dict with keys:
      - 'from_line': the original FROM line
      - 'base_image': the base image reference (as in FROM, including tag/digest)
      - 'base_name': the base image repository/name (or stage name if FROM a stage)
      - 'base_tag': tag of the base image (None if not specified or digest used)
      - 'alias': the stage alias if "AS alias" is present (None if not)
      - 'is_stage_alias': True if the base_image is actually a reference to a previous stage
      - 'start_index': line index where this stage's FROM appears
      - 'end_index': line index where this stage ends
      - 'lines': list of all lines in this stage (excluding the FROM line)
      - 'comment': any trailing comment on the FROM line (including the '#')
    """
    lines = dockerfile_text.splitlines()
    stages = []
    known_aliases = set()
    current_stage = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.lower().startswith("from"):
            continue  # skip lines until a FROM is found
        # Finalize the previous stage (if any)
        if current_stage is not None:
            current_stage['end_index'] = i - 1
            # Capture lines belonging to that stage (excluding its FROM)
            if current_stage['start_index'] + 1 <= current_stage['end_index']:
                current_stage['lines'] = lines[current_stage['start_index']+1 : current_stage['end_index']+1]
            else:
                current_stage['lines'] = []
            stages.append(current_stage)
            current_stage = None

        # Parse this FROM line
        comment = ""
        comment_idx = line.find('#')
        if comment_idx != -1:
            comment = line[comment_idx:]
            line_no_comment = line[:comment_idx].strip()
        else:
            line_no_comment = line.strip()
        parts = line_no_comment.split()
        if len(parts) < 2 or parts[0].lower() != "from":
            continue  # not a valid FROM line
        image_ref = parts[1]
        alias_name = None
        if len(parts) >= 4 and parts[2].lower() == "as":
            alias_name = parts[3]
        # Determine if base is a previous stage alias
        is_stage_alias = image_ref in known_aliases
        base_name = image_ref
        base_tag = None
        if is_stage_alias:
            # Base image refers to a previous stage (no tag applicable)
            base_name = image_ref
            base_tag = None
        else:
            # Base image is an external image
            if "@" in image_ref:
                base_name = image_ref.split("@")[0]
                base_tag = None  # digest used, treat as None tag
            elif ":" in image_ref:
                base_name, base_tag = image_ref.split(":", 1)
            else:
                base_name = image_ref
                base_tag = "latest"
        base_name = base_name.strip()
        if base_tag:
            base_tag = base_tag.strip()
        # Create stage entry
        current_stage = {
            'from_line': line,
            'base_image': image_ref,
            'base_name': base_name,
            'base_tag': base_tag,
            'alias': alias_name,
            'is_stage_alias': is_stage_alias,
            'start_index': i,
            'comment': comment
        }
        # Track this stage's alias for future references
        if alias_name:
            known_aliases.add(alias_name)
    # Finalize the last stage after loop
    if current_stage is not None:
        current_stage['end_index'] = len(lines) - 1
        if current_stage['start_index'] + 1 <= current_stage['end_index']:
            current_stage['lines'] = lines[current_stage['start_index']+1 : current_stage['end_index']+1]
        else:
            current_stage['lines'] = []
        stages.append(current_stage)
    return stages

def detect_os_family(sbom_data):
    """
    Detect the OS family from SBOM JSON data (CycloneDX format).
    Returns one of: 'ubuntu', 'debian', 'redhat', 'alpine', or 'unknown'.
    """
    if not sbom_data:
        return "unknown"
    try:
        sbom_str = json.dumps(sbom_data).lower()
    except Exception:
        return "unknown"
    if "ubuntu" in sbom_str:
        return "ubuntu"
    if any(x in sbom_str for x in ["centos", "red hat", "rhel", "rockylinux", "almalinux", "fedora"]):
        return "redhat"
    if "apk-tools" in sbom_str or "musl" in sbom_str:
        return "alpine"
    if "debian" in sbom_str or "dpkg" in sbom_str:
        # Note: Ubuntu also has dpkg, but 'ubuntu' would have been caught above.
        return "debian"
    return "unknown"

def choose_base_image(family):
    """
    Choose an updated base image for the given OS family.
    """
    family = family.lower()
    if family == "ubuntu":
        # Latest LTS Ubuntu
        return "ubuntu:22.04"
    if family == "debian":
        # Latest stable Debian release
        return "debian:bookworm"
    if family == "redhat":
        # Use a RHEL-compatible community image
        return "rockylinux:9"
    if family == "alpine":
        # Latest Alpine release
        return "alpine:3.18"
    # Default fallback
    return "ubuntu:latest"

def patch_dockerfile(dockerfile_text, sbom_before=None, base_mapping=None, patch_final_only=False):
    """
    Patch the Dockerfile text by upgrading base images and inserting upgrade instructions.
    - sbom_before: SBOM data (as dict) of the original image, to assist in OS detection for final stage.
    - base_mapping: dict mapping original base images to override base images (if provided by user).
    - patch_final_only: if True, only patch the final stage, leaving intermediate stages unchanged.
    Returns (patched_dockerfile_text, base_changes_list).
    """
    stages = parse_dockerfile_stages(dockerfile_text)
    if not stages:
        logger.error("No FROM instructions found in Dockerfile.")
        return dockerfile_text, []
    # Determine OS family of final image for more accurate base selection
    final_os_family = detect_os_family(sbom_before) if sbom_before else "unknown"
    patched_lines = []
    base_changes = []
    for idx, stage in enumerate(stages):
        is_final = (idx == len(stages) - 1)
        # If skipping patches on intermediate stages
        if patch_final_only and not is_final:
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue
        # Handle base image replacement/upgrades
        if stage['is_stage_alias']:
            # FROM refers to a previous stage (no external base to replace)
            patched_lines.append(stage['from_line'])
            # If final stage is inheriting from an unpatched stage, apply upgrades in final
            if is_final and patch_final_only:
                family = final_os_family
                patched_lines.append("# PATCHED: Apply OS package upgrades for inherited base")
                if family in ("ubuntu", "debian"):
                    patched_lines.append("RUN apt-get update -y && apt-get dist-upgrade -y || true")
                elif family == "alpine":
                    patched_lines.append("RUN apk update && apk upgrade || true")
                elif family == "redhat":
                    patched_lines.append("RUN yum update -y || true")
                else:
                    patched_lines.append("RUN true")
            # Preserve all other instructions in this stage
            patched_lines.extend(stage['lines'])
        else:
            # External base image stage
            orig_base = stage['base_image']
            base_name = stage['base_name']
            base_tag = stage['base_tag'] or ""
            alias = stage['alias']
            comment = stage['comment'] or ""
            # Choose new base image: check mapping overrides first
            if base_mapping and (orig_base in base_mapping or base_name in base_mapping):
                new_base = base_mapping.get(orig_base, base_mapping.get(base_name))
            else:
                # Auto-select new base
                if is_final and final_os_family != "unknown":
                    # Use OS family detected from original final image SBOM
                    family = final_os_family
                else:
                    # Guess OS family from base image name/tag
                    name_lower = base_name.lower()
                    tag_lower = base_tag.lower()
                    family = "unknown"
                    if "alpine" in name_lower or "alpine" in tag_lower:
                        family = "alpine"
                    elif name_lower in ("ubuntu", "debian") or tag_lower in ["stretch", "buster", "bullseye", "bookworm"]:
                        # If image or tag indicates a Debian/Ubuntu release
                        family = "debian" if name_lower == "debian" or tag_lower in ["stretch", "buster", "bullseye", "bookworm"] else "ubuntu"
                    elif name_lower in ("centos", "rhel", "redhat", "rockylinux", "alma", "almalinux") or any(x in name_lower for x in ["centos", "rhel", "rockylinux", "almalinux"]):
                        family = "redhat"
                    elif name_lower in ("node", "python", "php", "ruby", "golang", "openjdk", "nginx"):
                        # Common official images (assume Debian-based if not explicitly alpine)
                        family = "debian"
                    # If still unknown and this is final stage, use detected final OS family as fallback
                    if family == "unknown" and is_final:
                        family = final_os_family
                new_base = choose_base_image(family)
            base_changes.append((orig_base, new_base))
            # Preserve original indentation and format of FROM line
            indent = ""
            if stage['from_line'].startswith(" ") or stage['from_line'].startswith("\t"):
                # Get leading whitespace up to the word "FROM"
                indent = stage['from_line'][:stage['from_line'].lower().index("from")]
            alias_clause = f" AS {alias}" if alias else ""
            comment_clause = f" {comment}" if comment else ""
            patched_lines.append(f"{indent}FROM {new_base}{alias_clause}{comment_clause}")
            # Insert OS package upgrade RUN instruction for this stage
            patched_lines.append("# PATCHED: Apply OS package upgrades")
            if "ubuntu" in new_base or "debian" in new_base:
                patched_lines.append("RUN apt-get update -y && apt-get dist-upgrade -y || true")
            elif "alpine" in new_base:
                patched_lines.append("RUN apk update && apk upgrade || true")
            elif any(x in new_base for x in ["rockylinux", "centos", "rhel", "alma"]):
                patched_lines.append("RUN yum update -y || true")
            else:
                patched_lines.append("RUN true")
            # Insert language-level dependency upgrade instructions if applicable
            stage_text = "\n".join(stage['lines']).lower()
            # Python/pip upgrades
            if "pip " in stage_text or base_name.lower().startswith("python"):
                patched_lines.append("# PATCHED: Upgrade Python packages")
                patched_lines.append(
                    "RUN pip install -U --no-cache-dir pip && "
                    "pip list --outdated --format=freeze | cut -d= -f1 | xargs -r pip install -U || true"
                )
            # Node.js/npm upgrades
            if "npm " in stage_text or base_name.lower().startswith("node"):
                patched_lines.append("# PATCHED: Upgrade Node.js packages")
                patched_lines.append("RUN npm install -g npm@latest && npm update -y || true")
            # Yarn upgrades
            if "yarn " in stage_text:
                patched_lines.append("# PATCHED: Upgrade Yarn packages")
                patched_lines.append("RUN yarn upgrade || true")
            # Append the rest of the original stage instructions unchanged
            patched_lines.extend(stage['lines'])
    patched_text = "\n".join(patched_lines) + "\n"
    return patched_text, base_changes

# Scanning and SBOM Functions
def scan_image(image, output_path):
    """
    Run Trivy vulnerability scan on the given image and save JSON report to output_path.
    Returns the parsed JSON results (dict).
    """
    logger.info(f"Scanning image '{image}' for vulnerabilities ...")
    cmd = ["trivy", "image", "--quiet", "--format", "json", "-o", output_path, image]
    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(f"Trivy scan failed for image {image}:\n{output}")
        return {}
    return load_json(output_path)

def generate_sbom(image, output_path):
    """
    Generate a SBOM (Software Bill of Materials) for the given image using Trivy (CycloneDX format).
    Returns the parsed SBOM JSON.
    """
    logger.info(f"Generating SBOM for image '{image}' ...")
    cmd = ["trivy", "image", "--format", "cyclonedx", "--output", output_path, image]
    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(f"Failed to generate SBOM for {image}:\n{output}")
        return {}
    return load_json(output_path)

def summarize_vulnerabilities(scan_json):
    """
    Summarize vulnerability counts by severity from a Trivy scan JSON.
    Returns a dict of severity counts.
    """
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for result in scan_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "Unknown")
            if sev not in summary:
                summary["Unknown"] += 1
            else:
                summary[sev] += 1
    return summary

# CVE Diff and SBOM Diff Functions
def diff_vulnerabilities(before_scan, after_scan):
    """
    Compare vulnerabilities between before and after scans.
    Returns a dict with lists of 'resolved', 'remaining', and 'new' vulnerabilities.
    Each vulnerability is represented as a dict with keys: id, package, severity, version, fix_version.
    """
    def extract_vulns(scan):
        vulns = []
        for result in scan.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": v.get("VulnerabilityID"),
                    "package": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "severity": v.get("Severity"),
                    "fix_version": v.get("FixedVersion", "")
                })
        return vulns
    before_list = extract_vulns(before_scan)
    after_list = extract_vulns(after_scan)
    # Create sets of (id, package) for comparison
    before_keys = {(v['id'], v['package']) for v in before_list}
    after_keys = {(v['id'], v['package']) for v in after_list}
    resolved = [v for v in before_list if (v['id'], v['package']) not in after_keys]
    remaining = [v for v in after_list if (v['id'], v['package']) in before_keys]
    new = [v for v in after_list if (v['id'], v['package']) not in before_keys]
    return {"resolved": resolved, "remaining": remaining, "new": new}

def diff_sbom(before_sbom, after_sbom):
    """
    Compare SBOM components of original and patched images.
    Returns dict with lists of 'added', 'removed', and 'updated' components.
    Each component dict has: name, type, [old_version, new_version] as applicable.
    """
    before_components = {}
    after_components = {}
    # Helper to process components list from SBOM
    def load_components(sbom, comp_dict):
        comps = sbom.get("components") or sbom.get("Components") or []
        for comp in comps:
            name = comp.get("name") or comp.get("Name")
            comp_type = comp.get("type") or comp.get("Type") or "library"
            version = comp.get("version") or comp.get("Version")
            if name:
                comp_dict[(name, comp_type)] = version
    load_components(before_sbom, before_components)
    load_components(after_sbom, after_components)
    added = []
    removed = []
    updated = []
    # Compare before and after
    for (name, comp_type), old_ver in before_components.items():
        if (name, comp_type) not in after_components:
            removed.append({"name": name, "type": comp_type, "old_version": old_ver})
        else:
            new_ver = after_components[(name, comp_type)]
            if old_ver != new_ver:
                updated.append({"name": name, "type": comp_type, "old_version": old_ver, "new_version": new_ver})
    for (name, comp_type), new_ver in after_components.items():
        if (name, comp_type) not in before_components:
            added.append({"name": name, "type": comp_type, "new_version": new_ver})
    return {"added": added, "removed": removed, "updated": updated}

# Cosign Signing and Verification
def ensure_cosign_key():
    """
    Ensure a local Cosign key pair exists (generate one if not).
    Returns True if a key is ready (cosign.key and cosign.pub in current directory or environment).
    """
    if os.path.exists("cosign.key") and os.path.exists("cosign.pub"):
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
    signing_mode: "key" for local signing, "keyless" for Sigstore keyless.
    Returns True on successful signing.
    """
    if signing_mode == "none":
        return True  # not signing
    if signing_mode == "key":
        # Local key signing
        if not ensure_cosign_key():
            return False
        logger.info(f"Signing image {image_ref} with Cosign (local key)...")
        code, output = run_cmd([
            "cosign", "sign", "--allow-insecure-registry", "--key", "cosign.key", image_ref
        ])
    else:
        # Keyless signing using OIDC
        logger.info(f"Signing image {image_ref} with Cosign (keyless)...")
        env = {"COSIGN_EXPERIMENTAL": "1"}
        # Use --yes to avoid interactive prompts (assumes non-interactive environment)
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
        cmd = ["cosign", "verify", "--allow-insecure-registry", "--key", "cosign.pub", image_ref]
        code, output = run_cmd(cmd)
    else:
        env = {"COSIGN_EXPERIMENTAL": "1"}
        # For keyless, cosign will verify against transparency log and Fulcio root
        cmd = ["cosign", "verify", "--allow-insecure-registry", image_ref]
        code, output = run_cmd(cmd, env_override=env)
    if code != 0:
        logger.error(f"Signature verification failed:\n{output}")
        return False
    logger.info("Signature verification passed.")
    return True

# Main CLI and Orchestration
def main():
    parser = argparse.ArgumentParser(description="Docker Image Auto-Patching Tool")
    parser.add_argument("--dockerfile", required=True, help="Path to the Dockerfile to patch")
    parser.add_argument("--registry", default="localhost:5000", help="Target registry for the patched image (default: localhost:5000)")
    parser.add_argument("--signing", choices=["none", "key", "keyless"], default="key", 
                        help="Signing mode for the patched image: 'none' (no signing), 'key' (local key), or 'keyless' (Sigstore OIDC)")
    parser.add_argument("--patch-final-only", action="store_true", help="Only patch the final stage (skip patching intermediate build stages)")
    parser.add_argument("--base-mapping", help="Path to a JSON/YAML file specifying base image overrides (original -> new base image)")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text", 
                        help="Output format for the summary report (text, json, or html)")
    parser.add_argument("--output-file", help="Optional file path to write the summary report (in the format specified by --format)")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity (use -vv for debug-level logs)")
    parser.add_argument("--test-cmd", help="Optional command to run inside the patched image container to test functionality")
    args = parser.parse_args()

    # Adjust logging level based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        # Default: INFO for text/html, WARNING for JSON to keep JSON output clean
        logger.setLevel(logging.INFO if args.format in ("text", "html") else logging.WARNING)

    dockerfile_path = args.dockerfile
    # Read the original Dockerfile
    try:
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            original_dockerfile = f.read()
    except Exception as e:
        logger.error(f"Could not read Dockerfile at {dockerfile_path}: {e}")
        return 1

    # Determine image name from first FROM line to tag builds
    stages = parse_dockerfile_stages(original_dockerfile)
    if not stages:
        logger.error("No valid FROM line found in Dockerfile.")
        return 1
    # Use the base name of the first stage's image as image name
    base_image_name = stages[0]['base_name'].split("/")[-1].lower() or "image"
    local_orig = f"{base_image_name}-orig"
    local_patched = f"{base_image_name}-patched"
    registry = args.registry.rstrip("/")
    registry_patched = f"{registry}/{base_image_name}-patched:latest"

    logger.info(f"Base image identified: {stages[0]['base_image']} -> will tag as '{base_image_name}'")

    # Build the original image
    if not build_image(local_orig, dockerfile_path):
        return 1
    # Scan original image for vulnerabilities
    before_scan = scan_image(local_orig, "trivy_before.json")
    before_summary = summarize_vulnerabilities(before_scan)
    logger.info(f"Vulnerabilities BEFORE patching: {before_summary}")
    # Generate SBOM for original image
    sbom_before = generate_sbom(local_orig, "sbom_before.json")

    # Patch the Dockerfile text
    base_map = load_base_mapping(args.base_mapping) if args.base_mapping else None
    patched_text, base_changes = patch_dockerfile(original_dockerfile, sbom_before, base_mapping=base_map, patch_final_only=args.patch_final_only)
    # Save patched Dockerfile to a new file
    patched_dockerfile_path = "Dockerfile.patched"
    try:
        with open(patched_dockerfile_path, "w", encoding="utf-8") as pf:
            pf.write(patched_text)
    except Exception as e:
        logger.error(f"Failed to write patched Dockerfile: {e}")
        return 1
    if base_changes:
        logger.info("Base image replacements:")
        for old, new in base_changes:
            logger.info(f"  {old} -> {new}")
    else:
        logger.info("No base image changes were made in the patch.")

    # Build the patched image
    if not build_image(local_patched, patched_dockerfile_path):
        return 1

    # Optional: run a test command inside the patched image to verify functionality
    if args.test_cmd:
        logger.info(f"Running test command in patched image: {args.test_cmd}")
        test_cmd = ["docker", "run", "--rm", "--entrypoint", "", local_patched, "sh", "-c", args.test_cmd]
        code, output = run_cmd(test_cmd)
        if code != 0:
            logger.error(f"Test command failed in patched image (exit code {code}):\n{output}")
        else:
            logger.info("Test command succeeded in patched image.")
            logger.debug(f"Test output:\n{output}")

    # Tag and push the patched image to the registry (if signing is requested or registry explicitly given)
    if not tag_image(local_patched, registry_patched):
        return 1
    if not push_image(registry_patched):
        return 1

    # Remove local copy of patched image to force using registry for digest
    run_cmd(["docker", "rmi", "-f", local_patched])
    # Pull the image from registry to get the canonical digest reference
    logger.info("Pulling patched image from registry to obtain digest ...")
    code, output = run_cmd(["docker", "pull", registry_patched])
    if code != 0:
        logger.error(f"Failed to pull image from registry:\n{output}")
        return 1
    # Get image digest reference (e.g., <name>@sha256:abcd...)
    code, digest_out = run_cmd([
        "docker", "inspect", "--format={{index .RepoDigests 0}}", registry_patched
    ])
    if code != 0 or "@" not in digest_out:
        logger.error(f"Docker inspect failed to retrieve image digest:\n{digest_out}")
        return 1
    digest_ref = digest_out.strip()
    logger.info(f"Patched image digest reference: {digest_ref}")

    # Sign the image (if not skipped)
    if args.signing != "none":
        if not sign_image(digest_ref, args.signing):
            return 1
        # Verify the signature
        if not verify_image(digest_ref, args.signing):
            return 1

    # (Optional) Attach SBOM as OCI artifact and/or sign SBOM
    # If user wants to attach SBOM to the image in registry
    sbom_after = generate_sbom(registry_patched, "sbom_after.json")
    if sbom_after and args.signing != "none":
        # Attach SBOM to the image in registry using cosign (this stores SBOM as an OCI artifact)
        logger.info("Attaching SBOM to image in registry ...")
        env = {"COSIGN_EXPERIMENTAL": "1"} if args.signing == "keyless" else {}
        attach_cmd = [
            "cosign", "attach", "sbom",
            "--allow-insecure-registry",
            "--sbom", "sbom_after.json",
            "--type", "cyclonedx",
            digest_ref
        ]
        code, output = run_cmd(attach_cmd, env_override=env)
        if code != 0:
            logger.error(f"SBOM attach failed (non-critical):\n{output}")
        else:
            logger.info("SBOM attached to image in registry.")

    # Scan the patched image (from registry) for vulnerabilities
    after_scan = scan_image(registry_patched, "trivy_after.json")
    after_summary = summarize_vulnerabilities(after_scan)
    logger.info(f"Vulnerabilities AFTER patching: {after_summary}")

    # Compute vulnerability differences
    vulns_diff = diff_vulnerabilities(before_scan, after_scan)
    sbom_diff = diff_sbom(sbom_before or {}, sbom_after or {})

    # Prepare summary report
    report = {
        "base_image_changes": [ {"original": o, "new": n} for (o, n) in base_changes ],
        "vulnerabilities_before": before_summary,
        "vulnerabilities_after": after_summary,
        "cve_resolved": [f"{v['id']} in {v['package']} (was {v['version']}, fix: {v['fix_version'] or 'n/a'})"
                          for v in vulns_diff["resolved"]],
        "cve_remaining": [f"{v['id']} in {v['package']} (still {v['version']}, severity {v['severity']})"
                          for v in vulns_diff["remaining"]],
        "cve_new": [f"{v['id']} in {v['package']} (introduced, severity {v['severity']})"
                    for v in vulns_diff["new"]],
        "sbom_diff": {
            "added": [f"{comp['name']} ({comp['type']}) {comp['new_version']}" for comp in sbom_diff["added"]],
            "removed": [f"{comp['name']} ({comp['type']}) {comp['old_version']}" for comp in sbom_diff["removed"]],
            "updated": [f"{comp['name']} ({comp['type']}) {comp['old_version']} -> {comp['new_version']}" 
                        for comp in sbom_diff["updated"]]
        }
    }

    # Output the summary in the requested format
    if args.format == "json":
        output_data = {
            "base_image_changes": report["base_image_changes"],
            "vulnerabilities_before": before_summary,
            "vulnerabilities_after": after_summary,
            "resolved_vulnerabilities": vulns_diff["resolved"],
            "remaining_vulnerabilities": vulns_diff["remaining"],
            "new_vulnerabilities": vulns_diff["new"],
            "sbom_diff": sbom_diff
        }
        output_json = json.dumps(output_data, indent=2)
        if args.output_file:
            try:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    f.write(output_json)
                logger.info(f"JSON report written to {args.output_file}")
            except Exception as e:
                logger.error(f"Failed to write JSON report to file: {e}")
            # Also print JSON to stdout for convenience
            print(output_json)
        else:
            print(output_json)
    elif args.format == "html":
        # Generate a simple HTML summary
        html_lines = []
        html_lines.append("<h1>Docker Image Patching Summary</h1>")
        html_lines.append("<h2>Base Image Changes</h2>")
        if report["base_image_changes"]:
            html_lines.append("<ul>")
            for change in report["base_image_changes"]:
                html_lines.append(f"<li>{change['original']} → {change['new']}</li>")
            html_lines.append("</ul>")
        else:
            html_lines.append("<p>No base image changes.</p>")
        html_lines.append("<h2>Vulnerability Summary</h2>")
        html_lines.append(f"<p><strong>Before:</strong> {before_summary}</p>")
        html_lines.append(f"<p><strong>After:</strong> {after_summary}</p>")
        html_lines.append("<h3>Resolved CVEs</h3>")
        if report["cve_resolved"]:
            html_lines.append("<ul>")
            for item in report["cve_resolved"]:
                html_lines.append(f"<li>{item}</li>")
            html_lines.append("</ul>")
        else:
            html_lines.append("<p>None</p>")
        html_lines.append("<h3>Remaining CVEs</h3>")
        if report["cve_remaining"]:
            html_lines.append("<ul>")
            for item in report["cve_remaining"]:
                html_lines.append(f"<li>{item}</li>")
            html_lines.append("</ul>")
        else:
            html_lines.append("<p>None</p>")
        if report["cve_new"]:
            html_lines.append("<h3>Newly Introduced CVEs</h3><ul>")
            for item in report["cve_new"]:
                html_lines.append(f"<li>{item}</li>")
            html_lines.append("</ul>")
        html_lines.append("<h3>SBOM Differences</h3>")
        html_lines.append("<ul>")
        html_lines.append(f"<li><strong>Added:</strong> {len(sbom_diff['added'])} packages</li>")
        html_lines.append(f"<li><strong>Removed:</strong> {len(sbom_diff['removed'])} packages</li>")
        html_lines.append(f"<li><strong>Updated:</strong> {len(sbom_diff['updated'])} packages</li>")
        html_lines.append("</ul>")
        html_content = "\n".join(html_lines)
        if args.output_file:
            try:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    f.write(html_content)
                logger.info(f"HTML report written to {args.output_file}")
            except Exception as e:
                logger.error(f"Failed to write HTML report: {e}")
        else:
            # Print HTML to stdout
            print(html_content)
    else:
        # Text format summary (console-friendly)
        print("\n=== Patch Summary ===")
        if report["base_image_changes"]:
            print("Base Image Changes:")
            for change in report["base_image_changes"]:
                print(f" - {change['original']} -> {change['new']}")
        else:
            print("Base Image Changes: None")
        print(f"\nVulnerabilities Before: {before_summary}")
        print(f"Vulnerabilities After:  {after_summary}")
        # Detailed CVE diffs
        resolved = vulns_diff["resolved"]
        remaining = vulns_diff["remaining"]
        new = vulns_diff["new"]
        print(f"\nResolved CVEs: {len(resolved)}")
        if resolved:
            for v in resolved:
                fix_info = f"fixed in {v['fix_version']}" if v.get('fix_version') else "removed"
                print(f" - {v['id']} in {v['package']} (was {v['version']}, {fix_info})")
        print(f"\nRemaining CVEs: {len(remaining)}")
        if remaining:
            for v in remaining:
                print(f" - {v['id']} in {v['package']} (version {v['version']}, severity {v['severity']})")
        if new:
            print(f"\nNewly Introduced CVEs: {len(new)}")
            for v in new:
                print(f" - {v['id']} in {v['package']} (severity {v['severity']})")
        # SBOM diff summary
        added_count = len(sbom_diff["added"])
        removed_count = len(sbom_diff["removed"])
        updated_count = len(sbom_diff["updated"])
        print(f"\nSBOM Package Differences: +{added_count} added, -{removed_count} removed, {updated_count} updated")
        if updated_count:
            print("Updated packages:")
            for comp in sbom_diff["updated"]:
                print(f" - {comp['name']} ({comp['type']}): {comp['old_version']} -> {comp['new_version']}")
        if args.output_file:
            # If output file is specified for text, also write the same console output into the file
            try:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    # Write the same summary we printed
                    base_changes_str = ', '.join([f"{c['original']} -> {c['new']}" for c in report['base_image_changes']]) or 'None'
                    f.write(f"Base Image Changes: {base_changes_str}\n")
                    f.write(f"Vulnerabilities Before: {before_summary}\n")
                    f.write(f"Vulnerabilities After: {after_summary}\n")
                    f.write(f"Resolved CVEs ({len(resolved)}): {[v['id'] for v in resolved]}\n")
                    f.write(f"Remaining CVEs ({len(remaining)}): {[v['id'] for v in remaining]}\n")
                    if new:
                        f.write(f"New CVEs ({len(new)}): {[v['id'] for v in new]}\n")
                    f.write(f"SBOM diff - Added: {added_count}, Removed: {removed_count}, Updated: {updated_count}\n")
                logger.info(f"Text summary written to {args.output_file}")
            except Exception as e:
                logger.error(f"Failed to write text report to file: {e}")
    return 0

if __name__ == "__main__":
    exit(main())
