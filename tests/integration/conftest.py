"""Shared fixtures and skip-detection for the integration test suite.

Scoped to ``tests/integration/`` only — this conftest does not affect
unit tests living one level up in ``tests/``.
"""
import os
import shutil
import subprocess

import pytest


def _has_docker() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10
        )
        return r.returncode == 0
    except Exception:
        return False


def _has_trivy() -> bool:
    return shutil.which("trivy") is not None


_REQUIREMENTS_OK = _has_docker() and _has_trivy()


def pytest_collection_modifyitems(config, items):
    """Auto-skip ONLY this folder's tests when docker/trivy missing."""
    if _REQUIREMENTS_OK:
        return
    skip = pytest.mark.skip(
        reason="Integration tests require docker daemon + Trivy on PATH"
    )
    here = os.path.dirname(os.path.abspath(__file__))
    for item in items:
        # Only skip tests under tests/integration/
        if here in str(getattr(item, "fspath", "")):
            item.add_marker(skip)


@pytest.fixture
def tiny_alpine_image():
    return "alpine:3.10"


@pytest.fixture
def tiny_dockerfile(tmp_path, tiny_alpine_image):
    df = tmp_path / "Dockerfile"
    df.write_text(f"FROM {tiny_alpine_image}\nRUN echo hello > /tmp/hello\n")
    return str(df)
