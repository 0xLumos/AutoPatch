import os
from .utils import run_cmd

DOCKER_CMD = os.environ.get("DOCKER_CMD", "docker")


def build_image(context: str, tag: str, dockerfile_path: str):
    run_cmd([DOCKER_CMD, "build", "-t", tag, "-f", dockerfile_path, context], capture_output=False)
