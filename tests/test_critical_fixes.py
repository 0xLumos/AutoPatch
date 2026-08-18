"""
Regression tests for the critical fixes from the line-by-line code review
(CODE_REVIEW_IMPROVEMENTS.md). Each test locks in one fix so it cannot
silently regress.

Covered:
  C1  patcher._match_by_image_name_impl  anchored basename matching
  C2  patcher._migrate_run_command       empty-subcommand join filtering
  C3  patcher._conservative_same_image_bump  same-repo builder-stage bump
  C5  parser.analyze_run_commands        trailing-backslash no IndexError
  C7  parser.parse_dockerfile_stages     case-insensitive stage aliases
  plus ARG-FROM, scratch, distroless, normal multistage parsing.
"""
import pytest

from src import parser
from src import patcher


# ----------------------------------------------------------------------
# C5 / C7 and parser edge cases
# ----------------------------------------------------------------------
def test_c5_trailing_backslash_does_not_crash():
    df = "FROM debian:bullseye\nRUN apt-get update && \\"
    # Used to raise IndexError on the final continuation line.
    cmds = parser.analyze_run_commands(df)
    assert isinstance(cmds, list)


def test_c7_lowercase_stage_alias_resolves():
    df = "FROM golang:1.21 AS Builder\nRUN go build\nFROM builder\nCOPY . ."
    stages = parser.parse_dockerfile_stages(df)
    assert stages[1]["is_stage_alias"] is True


def test_c7_mixed_case_chain():
    df = "FROM alpine AS BUILD\nFROM Build AS run\nFROM RUN"
    stages = parser.parse_dockerfile_stages(df)
    assert stages[1]["is_stage_alias"] is True
    assert stages[2]["is_stage_alias"] is True


def test_arg_from_unresolved_is_preserved():
    df = "ARG BASE\nFROM $BASE\nRUN echo hi"
    stages = parser.parse_dockerfile_stages(df)
    assert stages[0]["base_image"] == "$BASE"


def test_scratch_detected():
    stages = parser.parse_dockerfile_stages("FROM scratch\nCOPY app /app")
    assert stages[0]["is_scratch"] is True


def test_distroless_final_stage_and_copy_from():
    df = ("FROM golang:1.21 AS build\nRUN go build -o /app\n"
          "FROM gcr.io/distroless/base\nCOPY --from=build /app /app")
    stages = parser.parse_dockerfile_stages(df)
    assert stages[1]["base_name"] == "gcr.io/distroless/base"
    assert "build" in stages[1]["copy_from_refs"]


# ----------------------------------------------------------------------
# C1 anchored basename matching
# ----------------------------------------------------------------------
@pytest.mark.parametrize("ref,must_not_be", [
    ("docker.io/library/python:3.6", "docker:27-cli"),
    ("registry.example.com/myapp:1.0", "registry:2"),
])
def test_c1_registry_host_not_false_matched(ref, must_not_be):
    assert patcher._match_by_image_name_impl(ref, "default") != must_not_be


def test_c1_python_still_maps_to_python():
    out = patcher._match_by_image_name_impl("docker.io/library/python:3.6", "default")
    assert str(out).startswith("python:")


def test_c1_real_registry_image_still_maps():
    assert patcher._match_by_image_name_impl("registry:2", "default") == "registry:2"


def test_c1_nexus3_digit_suffix_matches():
    assert patcher._match_by_image_name_impl("sonatype/nexus3:3.42", "default") is not None


def test_c1_mongo_express_precedence():
    assert patcher._match_by_image_name_impl("mongo-express:1.0", "default") == "mongo-express:latest"


# ----------------------------------------------------------------------
# C2 empty-subcommand filtering
# ----------------------------------------------------------------------
def test_c2_no_broken_shell_after_migration():
    rc = parser.analyze_run_commands(
        "RUN apt-get update && apt-get install -y curl && apt-get clean"
    )[0]
    out = patcher._migrate_run_command(rc, "apt", "apk", None, [])
    assert "&&  &&" not in out
    assert not out.strip().endswith("&&")
    assert "apk add" in out


# ----------------------------------------------------------------------
# C3 conservative same-image bump for builder stages
# ----------------------------------------------------------------------
def test_c3_unknown_repo_left_untouched():
    assert patcher._conservative_same_image_bump("mycorp/legacyapp:1.0") is None


def test_c3_digest_ref_left_untouched():
    assert patcher._conservative_same_image_bump("golang@sha256:abc") is None


def test_c3_same_repo_bump_preserves_variant(monkeypatch):
    table = {("golang", "1.16"): "1.22", ("python", "3.6"): "3.12"}
    monkeypatch.setattr(
        patcher, "_upgrade_eol_version",
        lambda lang, ver: table.get((lang, ver), ver),
    )
    assert patcher._conservative_same_image_bump("golang:1.16") == ("golang:1.22", 0.85)
    assert patcher._conservative_same_image_bump("golang:1.16-alpine") == ("golang:1.22-alpine", 0.85)
    assert patcher._conservative_same_image_bump("python:3.6-slim") == ("python:3.12-slim", 0.85)
    # Already current: no change.
    assert patcher._conservative_same_image_bump("golang:1.22") is None
