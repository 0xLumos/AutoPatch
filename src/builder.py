from .utils import run_cmd, log_step


import os
from .utils import run_cmd, log_step


def build_image(tag: str, dockerfile: str) -> bool:
    log_step(f"Building image {tag} ...")

    # Determine correct build context = directory containing the Dockerfile
    build_context = os.path.dirname(os.path.abspath(dockerfile))
    if build_context.strip() == "":
        build_context = "."

    code, out = run_cmd([
        "docker", "build",
        "-t", tag,
        "-f", dockerfile,
        build_context  # FIX: use correct directory, not "."
    ])

    if code != 0:
        print(out)
        return False

    log_step("Build succeeded")
    return True


def tag_image(source: str, target: str) -> bool:
    log_step(f"Tagging {source} → {target}")
    code, out = run_cmd(["docker", "tag", source, target])
    if code != 0:
        print(out)
        return False
    return True


def push_image(tag: str) -> bool:
    log_step(f"Pushing patched image to registry {tag} ...")
    code, out = run_cmd(["docker", "push", tag])
    if code != 0:
        print(out)
        return False
    return True
