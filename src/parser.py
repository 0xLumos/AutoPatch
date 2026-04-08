import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("docker_patch_tool")


def _resolve_variable(value: str, args: Optional[Dict[str, str]]) -> str:
    """
    Resolve Docker ARG variables in a string using provided argument values.

    Handles format: $VAR_NAME or ${VAR_NAME}

    Args:
        value: String potentially containing variable references
        args: Dict mapping ARG names to their values, or None

    Returns:
        String with variables resolved to their values, or original if not found
    """
    if not args:
        return value

    # Handle ${VAR_NAME} format
    def replace_braced(match):
        var_name = match.group(1)
        return args.get(var_name, match.group(0))

    value = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', replace_braced, value)

    # Handle $VAR_NAME format (word boundary)
    def replace_unbraced(match):
        var_name = match.group(1)
        return args.get(var_name, match.group(0))

    value = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)\b', replace_unbraced, value)

    return value


def _extract_copy_from_references(lines: List[str]) -> Set[str]:
    """
    Extract all stage names referenced by COPY --from= instructions.

    Args:
        lines: List of Dockerfile lines

    Returns:
        Set of stage names referenced in COPY --from= directives
    """
    copy_from_refs = set()

    for line in lines:
        # Skip empty lines and comments
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # Handle continuation lines (backslash)
        # For now, simple regex to find --from= anywhere in COPY lines
        if stripped.upper().startswith('COPY'):
            # Match --from=stage_name or --from="stage_name"
            matches = re.findall(r'--from=([^\s"]+)(?:\s|$|")', stripped, re.IGNORECASE)
            for match in matches:
                copy_from_refs.add(match)

    return copy_from_refs


def _is_continuation_line(line: str) -> bool:
    """
    Check if a line ends with a backslash continuation.

    Args:
        line: A Dockerfile line

    Returns:
        True if the line ends with a backslash continuation
    """
    # Remove trailing whitespace but check for backslash before it
    stripped = line.rstrip()
    return stripped.endswith('\\')


def _split_from_line(line: str) -> Tuple[str, str]:
    """
    Split a FROM line into the instruction part and any trailing comment.

    Handles inline comments (text after #) and preserves the comment.
    Does not split if # appears within quotes.

    Args:
        line: A FROM instruction line

    Returns:
        Tuple of (line_without_comment, comment_with_hash)
    """
    # Simple approach: find first # not in quotes
    in_double = False
    in_single = False
    for i, char in enumerate(line):
        if char == '"' and not in_single:
            in_double = not in_double
        elif char == "'" and not in_double:
            in_single = not in_single
        elif char == '#' and not in_double and not in_single:
            return line[:i].rstrip(), line[i:]

    return line.rstrip(), ""


def parse_dockerfile_stages(
    dockerfile_text: str,
    args: Optional[Dict[str, str]] = None
) -> List[Dict]:
    """
    Parse a Dockerfile into a list of build stages.

    Handles:
    - FROM image:tag
    - FROM image@sha256:digest
    - FROM scratch
    - FROM $ARG_VAR (resolves using provided args dict)
    - Multi-stage builds with stage aliases
    - COPY --from= references
    - Inline comments and continuation lines
    - Preserves all lines including blank lines and comments between stages

    Args:
        dockerfile_text: The complete Dockerfile content as a string
        args: Optional dict mapping ARG names to their values for resolving $VAR references

    Returns:
        List of stage dicts, each containing:
        - 'from_line': The original FROM line (with any inline comment)
        - 'base_image': Base image reference as written (may include $VAR before resolution)
        - 'base_name': Resolved base image name/repository or stage alias
        - 'base_tag': Tag string, 'latest' for untagged, None for digest or scratch
        - 'is_scratch': True if FROM scratch
        - 'alias': Stage alias name if "AS alias" present, else None
        - 'is_stage_alias': True if base_image references a previous stage
        - 'copy_from_refs': Set of stage names referenced by COPY --from= in this stage
        - 'start_index': Line index of FROM instruction
        - 'end_index': Line index of last line in this stage
        - 'lines': List of all non-FROM lines in this stage (preserves blanks, comments)
        - 'comment': Trailing comment on FROM line (including the '#'), or empty string
    """
    lines = dockerfile_text.splitlines()
    stages = []
    known_aliases: Set[str] = set()
    current_stage: Optional[Dict] = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Look for FROM instruction (case-insensitive)
        if not stripped.lower().startswith("from"):
            continue

        # Finalize the previous stage if one exists
        if current_stage is not None:
            current_stage['end_index'] = i - 1
            # Capture all lines between FROM and next FROM (or end of file)
            if current_stage['start_index'] + 1 <= current_stage['end_index']:
                current_stage['lines'] = lines[current_stage['start_index'] + 1 : current_stage['end_index'] + 1]
            else:
                current_stage['lines'] = []
            stages.append(current_stage)
            current_stage = None

        # Parse this FROM line
        line_no_comment, comment = _split_from_line(line)
        parts = line_no_comment.split()

        # Validate FROM instruction
        if len(parts) < 2 or parts[0].lower() != "from":
            continue

        # Skip any flags that start with -- (e.g., --platform=linux/arm64)
        # These come immediately after FROM and before the image reference
        image_idx = 1
        while image_idx < len(parts) and parts[image_idx].startswith("--"):
            image_idx += 1

        # Now get the image reference (which may be at index > 1 if flags were present)
        if image_idx >= len(parts):
            continue

        image_ref = parts[image_idx]

        # Resolve variables in image reference
        resolved_image_ref = _resolve_variable(image_ref, args)

        # Extract alias if present (look for "AS alias_name" after the image reference)
        alias_name: Optional[str] = None
        if image_idx + 2 < len(parts) and parts[image_idx + 1].lower() == "as":
            alias_name = parts[image_idx + 2]

        # Determine if this is a scratch image
        is_scratch = resolved_image_ref.lower() == "scratch"

        # Determine if base refers to a previous stage
        is_stage_alias = resolved_image_ref in known_aliases

        # Parse base image name and tag
        base_name = resolved_image_ref
        base_tag: Optional[str] = None

        if is_scratch:
            base_name = "scratch"
            base_tag = None
        elif is_stage_alias:
            # Reference to a previous stage
            base_name = resolved_image_ref
            base_tag = None
        else:
            # External image reference
            if "@" in resolved_image_ref:
                # Digest format: image@sha256:...
                base_name = resolved_image_ref.split("@")[0].strip()
                base_tag = None
            elif ":" in resolved_image_ref:
                # Tag format: image:tag
                base_name, base_tag = resolved_image_ref.split(":", 1)
                base_name = base_name.strip()
                base_tag = base_tag.strip()
            else:
                # No tag or digest specified
                base_name = resolved_image_ref.strip()
                base_tag = "latest"

        # Extract COPY --from= references from this stage's lines
        # (we'll update this after capturing the stage's lines)
        copy_from_refs: Set[str] = set()

        # Create stage entry
        current_stage = {
            'from_line': line,
            'base_image': image_ref,  # Keep original (may have $VAR)
            'base_name': base_name,
            'base_tag': base_tag,
            'is_scratch': is_scratch,
            'alias': alias_name,
            'is_stage_alias': is_stage_alias,
            'copy_from_refs': copy_from_refs,
            'start_index': i,
            'comment': comment
        }

        # Track this stage's alias for future references
        if alias_name:
            known_aliases.add(alias_name)

    # Finalize the last stage
    if current_stage is not None:
        current_stage['end_index'] = len(lines) - 1
        if current_stage['start_index'] + 1 <= current_stage['end_index']:
            current_stage['lines'] = lines[current_stage['start_index'] + 1 : current_stage['end_index'] + 1]
        else:
            current_stage['lines'] = []
        stages.append(current_stage)

    # Post-process: extract COPY --from= references for each stage
    for stage in stages:
        stage['copy_from_refs'] = _extract_copy_from_references(stage['lines'])

    return stages


@dataclass
class RunCommand:
    """Parsed RUN instruction with semantic understanding."""
    line_start: int          # Starting line index in Dockerfile
    line_end: int            # Ending line index (accounts for continuation lines)
    raw_text: str            # Full text of the RUN instruction
    package_manager: Optional[str] = None   # apt-get, apk, yum, dnf, pip, npm, etc.
    packages: List[str] = field(default_factory=list)  # Extracted package names
    is_install: bool = False  # True if this is a package install command
    is_update: bool = False   # True if this is a package list update (apt-get update)
    is_cleanup: bool = False  # True if this is a cleanup (rm -rf /var/lib/apt/lists/*)
    combined_commands: List[str] = field(default_factory=list)  # Individual commands in a && chain


def analyze_run_commands(dockerfile_text: str) -> List[RunCommand]:
    """
    Analyze all RUN instructions in a Dockerfile for semantic understanding.

    Parses RUN commands to detect:
    - Which package manager is used (apt-get, apk, yum, dnf, pip, npm, gem, etc.)
    - What packages are being installed
    - Whether the command is an update, install, or cleanup
    - Multi-command chains (&&)
    - Continuation lines (backslash)

    This enables intelligent package manager migration when switching base images
    (e.g., apt-get -> apk when moving from Debian to Alpine).

    Args:
        dockerfile_text: Complete Dockerfile content

    Returns:
        List of RunCommand instances with parsed details
    """
    lines = dockerfile_text.splitlines()
    run_commands: List[RunCommand] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Look for RUN instruction (case-insensitive)
        if not stripped.upper().startswith('RUN '):
            i += 1
            continue

        # Collect continuation lines
        logical_command = stripped[4:]  # Remove 'RUN ' prefix
        line_start = i

        while _is_continuation_line(lines[i]):
            i += 1
            if i < len(lines):
                next_line = lines[i].strip()
                # Remove the trailing backslash from previous line and concatenate
                logical_command = logical_command.rstrip('\\').rstrip() + ' ' + next_line

        line_end = i

        # Split on && to get individual commands
        sub_commands = [cmd.strip() for cmd in logical_command.split('&&')]
        sub_commands = [cmd for cmd in sub_commands if cmd]  # Filter empty

        # Analyze the logical command
        package_manager: Optional[str] = None
        packages: List[str] = []
        is_install = False
        is_update = False
        is_cleanup = False

        for sub_cmd in sub_commands:
            # Detect package manager and command type
            cmd_lower = sub_cmd.lower()

            if 'apt-get' in cmd_lower or 'apt ' in cmd_lower:
                package_manager = 'apt'
                if 'install' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_apt(sub_cmd))
                elif 'update' in cmd_lower:
                    is_update = True
                elif 'clean' in cmd_lower or 'purge' in cmd_lower:
                    is_cleanup = True

            elif 'apk' in cmd_lower:
                package_manager = 'apk'
                if 'add' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_apk(sub_cmd))
                elif 'update' in cmd_lower:
                    is_update = True
                elif 'del' in cmd_lower:
                    is_cleanup = True

            elif 'yum' in cmd_lower or 'dnf' in cmd_lower:
                package_manager = 'yum' if 'yum' in cmd_lower else 'dnf'
                if 'install' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_yum(sub_cmd))
                elif 'update' in cmd_lower or 'check-update' in cmd_lower:
                    is_update = True
                elif 'clean' in cmd_lower:
                    is_cleanup = True

            elif 'pip' in cmd_lower or 'pip3' in cmd_lower:
                package_manager = 'pip'
                if 'install' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_pip(sub_cmd))

            elif 'npm' in cmd_lower:
                package_manager = 'npm'
                if 'install' in cmd_lower or 'ci' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_npm(sub_cmd))

            elif 'gem' in cmd_lower:
                package_manager = 'gem'
                if 'install' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_gem(sub_cmd))

            elif 'composer' in cmd_lower:
                package_manager = 'composer'
                if 'install' in cmd_lower or 'require' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_composer(sub_cmd))

            elif 'go' in cmd_lower and ('get' in cmd_lower or 'mod' in cmd_lower):
                package_manager = 'go'
                if 'get' in cmd_lower or 'download' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_go(sub_cmd))

            elif 'cargo' in cmd_lower:
                package_manager = 'cargo'
                if 'install' in cmd_lower or 'build' in cmd_lower:
                    is_install = True
                    packages.extend(_extract_packages_cargo(sub_cmd))

        # Create RunCommand instance
        run_cmd = RunCommand(
            line_start=line_start,
            line_end=line_end,
            raw_text=logical_command,
            package_manager=package_manager,
            packages=packages,
            is_install=is_install,
            is_update=is_update,
            is_cleanup=is_cleanup,
            combined_commands=sub_commands
        )
        run_commands.append(run_cmd)

        i += 1

    return run_commands


def _extract_packages_apt(command: str) -> List[str]:
    """Extract package names from apt-get install command."""
    packages = []
    # Look for content after 'install' keyword
    match = re.search(r'install\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(1)
        # Split on whitespace, filter out flags (starting with -)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_apk(command: str) -> List[str]:
    """Extract package names from apk add command."""
    packages = []
    match = re.search(r'add\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(1)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_yum(command: str) -> List[str]:
    """Extract package names from yum/dnf install command."""
    packages = []
    match = re.search(r'install\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(1)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_pip(command: str) -> List[str]:
    """Extract package names from pip install command."""
    packages = []
    match = re.search(r'install\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(1)
        # Handle -r requirements.txt style
        if content.strip().startswith('-r'):
            return packages
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_npm(command: str) -> List[str]:
    """Extract package names from npm install command."""
    packages = []
    match = re.search(r'(install|ci)\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(2)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_gem(command: str) -> List[str]:
    """Extract package names from gem install command."""
    packages = []
    match = re.search(r'install\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(1)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_composer(command: str) -> List[str]:
    """Extract package names from composer install/require command."""
    packages = []
    match = re.search(r'(install|require)\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(2)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_go(command: str) -> List[str]:
    """Extract package names from go get/mod command."""
    packages = []
    match = re.search(r'(get|download)\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(2)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def _extract_packages_cargo(command: str) -> List[str]:
    """Extract package names from cargo install/build command."""
    packages = []
    match = re.search(r'(install|build)\s+(.+)$', command, re.IGNORECASE)
    if match:
        content = match.group(2)
        tokens = content.split()
        packages = [t for t in tokens if not t.startswith('-') and not t.startswith('$')]
    return packages


def detect_package_manager_from_dockerfile(dockerfile_text: str) -> Optional[str]:
    """
    Detect the primary system package manager used in a Dockerfile.

    Returns the most commonly used system package manager:
    'apt', 'apk', 'yum', 'dnf', or None if none detected.

    This is useful for determining OS family from Dockerfile content
    when SBOM is not available.
    """
    run_commands = analyze_run_commands(dockerfile_text)

    # Count package manager occurrences
    pm_counts: Dict[str, int] = {}
    for run_cmd in run_commands:
        if run_cmd.package_manager:
            pm_counts[run_cmd.package_manager] = pm_counts.get(run_cmd.package_manager, 0) + 1

    # Return the most common one
    if pm_counts:
        return max(pm_counts.items(), key=lambda x: x[1])[0]

    return None
