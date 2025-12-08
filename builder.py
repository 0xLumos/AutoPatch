import os
import logging
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")

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
