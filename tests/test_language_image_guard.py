"""A non-language base must never be redirected to a language image.

The reproduction (drone, main corpus run ab_20260811_155410): the
Dockerfile's clone stage is `FROM alpine/git:2.49.1`. alpine/git bundles
perl as a git dependency, the SBOM shows perl, and the selector proposed
`perl:5.40-alpine`, a tag that does not exist, so the patched build died
at metadata resolution. Same disease as the distro/distroless guards
(gitea -> golang:3.11-alpine, act -> python:3.12-alpine,
headscale -> golang:1.23-bookworm), generalized: the detected language
belongs to the application or the base's own dependencies, never a
reason to swap a non-language base for a toolchain image.

The guard is a post-filter on the final-stage candidate, so it covers
the resolver, the legacy language paths, and arm B AI proposals alike;
operator --base-mapping remains exempt (explicit choice).
"""
from __future__ import annotations

import pytest

from src.patcher import (
    _is_language_image_repo,
    patch_dockerfile,
)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr("src.patcher._get_resolver", lambda: None)


class TestIsLanguageImageRepo:

    @pytest.mark.parametrize("ref,want", [
        ("python:3.12-slim", True),
        ("golang:1.23-bookworm", True),
        ("perl:5.40", True),
        ("node:26-slim", True),
        ("eclipse-temurin:21", True),
        # not language images
        ("alpine/git:2.49.1", False),
        ("alpine:3.21", False),
        ("gcr.io/distroless/base-debian12", False),
        ("nginx:1.27", False),
        ("myorg/customapp:1", False),
    ])
    def test_classification(self, ref, want):
        assert _is_language_image_repo(ref) is want


class TestGuardBlocksLanguageSubstitution:

    def test_utility_base_is_not_rewritten_to_language_image(self):
        """The drone reproduction: whatever the selector proposes for
        alpine/git, the final candidate must not be a language image."""
        df = ("FROM alpine/git:2.49.1\n"
              "RUN git clone https://example.com/repo /src\n"
              'CMD ["git", "daemon"]\n')
        _p, changes, _w, _d = patch_dockerfile(df)
        for _old, new in changes:
            assert not _is_language_image_repo(new), (
                f"non-language base rewritten to language image: {new}")

    def test_language_base_still_upgrades_to_language_image(self):
        """The guard must not block genuine language-image upgrades."""
        df = ("FROM python:3.8-slim\n"
              "COPY app.py /app.py\n"
              'CMD ["python", "/app.py"]\n')
        _p, changes, _w, _d = patch_dockerfile(df)
        if changes:
            assert all(_is_language_image_repo(new)
                       or new.startswith("python")
                       for _old, new in changes)

    def test_operator_mapping_is_exempt(self):
        """An explicit --base-mapping to a language image is an operator
        decision and must be honored."""
        df = ("FROM alpine/git:2.49.1\n"
              'CMD ["git", "daemon"]\n')
        _p, changes, _w, _d = patch_dockerfile(
            df, base_mapping={"alpine/git:2.49.1": "golang:1.23-alpine"})
        assert changes and changes[0][1] == "golang:1.23-alpine"
