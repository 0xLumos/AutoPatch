import logging

logger = logging.getLogger("docker_patch_tool")

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
