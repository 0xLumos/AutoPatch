import logging
import json
from .parser import parse_dockerfile_stages

logger = logging.getLogger("docker_patch_tool")

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
