"""Regression tests for silent Dockerfile corruption in the parser.

Two defects motivated this file. Both were silent: no exception, no
warning, just a rewritten Dockerfile missing instructions.

  1. Any line whose first four characters were "from" finalized the
     current stage before the line was validated as a real FROM. A
     continuation line ("fromage --install") or a heredoc payload
     ("from os import path") therefore truncated the file, and every
     following instruction was dropped from the reconstructed output.

  2. Everything above the first FROM was discarded, including the
     syntax directive and the global ARG that a "FROM ${BASE}" line
     resolves against, producing a Dockerfile that cannot build.
"""
from __future__ import annotations

import pytest

from src.parser import extract_preamble, parse_dockerfile_stages
from src.patcher import patch_dockerfile


class TestFromWordBoundary:
    """A stage boundary requires the token FROM, not the prefix."""

    def test_continuation_line_beginning_with_from_is_not_a_stage(self):
        df = (
            "FROM debian:11\n"
            "RUN echo hello && \\\n"
            "    fromage --install \\\n"
            "    && echo done\n"
            "COPY app /app\n"
            'CMD ["/app"]\n'
        )
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1
        body = "\n".join(stages[0]["lines"])
        assert "COPY app /app" in body, "instructions after the continuation were dropped"
        assert "CMD" in body

    @pytest.mark.parametrize("word", [
        "fromage", "from_cache", "fromlist", "FROMAGE",
    ])
    def test_words_merely_starting_with_from(self, word):
        df = f"FROM alpine:3.19\nRUN {word} --x \\\n    && true\nCMD [\"/x\"]\n"
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1
        assert "CMD" in "\n".join(stages[0]["lines"])

    def test_bare_from_with_no_argument_is_not_a_stage(self):
        df = "FROM alpine:3.19\nRUN echo from\nCMD [\"/x\"]\n"
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1


class TestHeredocBodies:
    """BuildKit heredoc payloads are arbitrary text, not instructions."""

    def test_python_heredoc_with_import(self):
        df = (
            "FROM python:3.9\n"
            "RUN cat > /app.py <<EOF\n"
            "from os import path\n"
            "print(path)\n"
            "EOF\n"
            'CMD ["python", "/app.py"]\n'
        )
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1, [s["base_name"] for s in stages]
        assert "CMD" in "\n".join(stages[0]["lines"])

    def test_quoted_and_indented_heredoc_forms(self):
        df = (
            "FROM alpine:3.19\n"
            "COPY <<-'EOF' /x.py\n"
            "from sys import argv\n"
            "EOF\n"
            "RUN echo done\n"
        )
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1, [s["base_name"] for s in stages]

    def test_heredoc_terminator_detection(self):
        from src.parser import _heredoc_terminator
        assert _heredoc_terminator("RUN <<EOF") == "EOF"
        assert _heredoc_terminator("RUN cat <<-'END' /f") == "END"
        assert _heredoc_terminator('COPY <<"DATA" /f') == "DATA"
        # Not an instruction that can open a heredoc
        assert _heredoc_terminator("FROM alpine:3.19") is None
        assert _heredoc_terminator("RUN echo hi") is None

    def test_multiple_heredocs_in_one_file(self):
        df = (
            "FROM debian:12\n"
            "RUN cat > /a.py <<EOF\n"
            "from a import b\n"
            "EOF\n"
            "RUN cat > /b.py <<END\n"
            "from c import d\n"
            "END\n"
            "CMD [\"/a\"]\n"
        )
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1, [s["base_name"] for s in stages]


class TestPreamblePreservation:
    """Global state above the first FROM must survive a rewrite."""

    def test_extract_preamble_returns_directive_and_arg(self):
        df = (
            "# syntax=docker/dockerfile:1\n"
            "ARG BASE_IMAGE=python:3.9-slim\n"
            "FROM ${BASE_IMAGE} AS app\n"
            "RUN pip install requests\n"
        )
        pre = extract_preamble(df)
        assert any("syntax=" in line for line in pre)
        assert any("ARG BASE_IMAGE" in line for line in pre)

    def test_extract_preamble_empty_when_from_is_first(self):
        assert extract_preamble("FROM alpine:3.19\nRUN true\n") == []

    def test_extract_preamble_whole_file_when_no_from(self):
        df = "# just a comment\nARG X=1\n"
        assert len(extract_preamble(df)) == 2

    def test_patch_dockerfile_preserves_syntax_directive_and_arg(self):
        df = (
            "# syntax=docker/dockerfile:1\n"
            "ARG BASE_IMAGE=python:3.9-slim\n"
            "FROM ${BASE_IMAGE} AS app\n"
            "RUN pip install requests\n"
        )
        patched, _changes, _warnings, _diff = patch_dockerfile(df)
        assert "syntax=docker/dockerfile:1" in patched, "syntax directive lost"
        assert "ARG BASE_IMAGE" in patched, (
            "global ARG lost; the FROM line that references it can no "
            "longer resolve and the image cannot build"
        )

    def test_patch_dockerfile_preserves_licence_header(self):
        df = (
            "# Copyright 2026 Example Corp\n"
            "# SPDX-License-Identifier: Apache-2.0\n"
            "FROM alpine:3.15\n"
            "RUN echo hi\n"
        )
        patched, _c, _w, _d = patch_dockerfile(df)
        assert "SPDX-License-Identifier" in patched


class TestNoRegressionOnValidFiles:
    """The fixes must not change behaviour on well-formed input."""

    def test_multistage_still_parses(self):
        df = (
            "FROM golang:1.21 AS builder\n"
            "RUN go build -o /app\n"
            "FROM alpine:3.19\n"
            "COPY --from=builder /app /app\n"
        )
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 2
        assert stages[0]["alias"] == "builder"
        assert "builder" in stages[1]["copy_from_refs"]

    def test_platform_flag_still_parses(self):
        df = "FROM --platform=linux/amd64 debian:12 AS base\nRUN true\n"
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1
        assert stages[0]["base_name"] == "debian"
        assert stages[0]["alias"] == "base"

    def test_comment_before_from_does_not_open_a_stage(self):
        df = "# FROM this is a comment\nFROM alpine:3.19\nRUN true\n"
        stages = parse_dockerfile_stages(df)
        assert len(stages) == 1
        assert stages[0]["base_name"] == "alpine"
