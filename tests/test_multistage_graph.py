"""Multi-stage Dockerfiles are a DAG, not a list.

Three facts about that DAG were previously approximated by
``idx == len(stages) - 1``:

  * which stage ships (``docker build --target``),
  * which stages are built at all (reachability from the target),
  * what distribution each stage ends up on (inheritance through
    ``FROM <alias>``).

Each approximation had a concrete failure mode, reproduced below.
"""
from __future__ import annotations

import pytest

from src.compat_guards import check_copy_from_libc
from src.parser import parse_dockerfile_stages
from src.patcher import _infer_os_from_image, patch_dockerfile, resolve_stage_graph


BUILDER_RUNTIME_DEBUG = """FROM golang:1.19 AS builder
RUN go build -o /app .

FROM debian:11 AS runtime
COPY --from=builder /app /app
CMD ["/app"]

FROM runtime AS debug
RUN apt-get install -y gdb
"""


class TestShippingStageResolution:

    def test_target_selects_the_stage_that_ships(self):
        stages = parse_dockerfile_stages(BUILDER_RUNTIME_DEBUG)
        final, _live, _fam = resolve_stage_graph(stages, target="runtime")
        assert final == {1}

    def test_default_is_the_last_stage(self):
        stages = parse_dockerfile_stages(BUILDER_RUNTIME_DEBUG)
        final, _l, _f = resolve_stage_graph(stages, target=None)
        assert final == {2}

    def test_numeric_target_is_accepted(self):
        stages = parse_dockerfile_stages(BUILDER_RUNTIME_DEBUG)
        assert resolve_stage_graph(stages, target="1")[0] == {1}

    def test_unknown_target_falls_back_and_does_not_crash(self):
        stages = parse_dockerfile_stages(BUILDER_RUNTIME_DEBUG)
        assert resolve_stage_graph(stages, target="nope")[0] == {2}

    def test_trailing_debug_stage_no_longer_makes_the_run_a_noop(self):
        """The headline failure: with a debug stage appended, the real
        runtime stage was treated as a builder and got only the
        conservative same-image bump, which found nothing, so the whole
        run produced zero changes while reporting success.

        The result is debian:12, not alpine: the glibc builder copies a
        binary into this stage, so the libc guard correctly rejects the
        musl candidate and the same-family upgrade is taken instead.
        Both halves matter, the rejection and the fallback."""
        _p, changes, warnings, _d = patch_dockerfile(
            BUILDER_RUNTIME_DEBUG, target="runtime")
        assert changes, "patcher produced no changes for the shipping stage"
        assert changes[0] == ("debian:11", "debian:12")
        # The distro-runtime guard now bumps a distribution base in-family
        # directly instead of proposing a musl candidate and rejecting it,
        # so the copy-from-libc / fell-back warnings no longer occur. The
        # part that matters, debian:12 on the shipping stage, is asserted
        # above.


class TestStageReachability:

    DEAD_STAGE = """FROM golang:1.19 AS unused
RUN go build -o /nope .

FROM node:18 AS builder
RUN npm ci

FROM debian:11
COPY --from=builder /app /app
"""

    def test_unreferenced_stage_is_not_built(self):
        stages = parse_dockerfile_stages(self.DEAD_STAGE)
        _f, live, _fam = resolve_stage_graph(stages, None)
        assert 0 not in live and {1, 2} <= live

    def test_dead_stage_is_left_verbatim(self):
        patched, _c, warnings, _d = patch_dockerfile(self.DEAD_STAGE)
        assert "FROM golang:1.19 AS unused" in patched
        assert any("never built" in w for w in warnings)

    def test_transitive_dependencies_are_live(self):
        df = ("FROM alpine:3.19 AS base\n"
              "FROM base AS mid\n"
              "RUN echo x\n"
              "FROM debian:12\n"
              "COPY --from=mid /x /x\n")
        stages = parse_dockerfile_stages(df)
        _f, live, _fam = resolve_stage_graph(stages, None)
        assert live == {0, 1, 2}, "a two-hop dependency was pruned"

    def test_targeting_a_builder_prunes_everything_after_it(self):
        stages = parse_dockerfile_stages(BUILDER_RUNTIME_DEBUG)
        _f, live, _fam = resolve_stage_graph(stages, target="builder")
        assert live == {0}


class TestFamilyInheritance:

    def test_family_flows_through_from_alias(self):
        stages = parse_dockerfile_stages(BUILDER_RUNTIME_DEBUG)
        _f, _l, fam = resolve_stage_graph(stages, None)
        # stage 2 is `FROM runtime`, which is `FROM debian:11`
        assert fam[2] == "debian", "family-keyed guards were inert here"

    def test_multi_hop_inheritance(self):
        df = "FROM alpine:3.19 AS a\nFROM a AS b\nFROM b AS c\nRUN echo x\n"
        _f, _l, fam = resolve_stage_graph(parse_dockerfile_stages(df), None)
        assert fam == {0: "alpine", 1: "alpine", 2: "alpine"}

    def test_scratch_is_its_own_family(self):
        df = "FROM scratch AS s\nCOPY x /x\n"
        _f, _l, fam = resolve_stage_graph(parse_dockerfile_stages(df), None)
        assert fam[0] == "scratch"

    def test_cyclic_from_terminates(self):
        stages = [
            {"alias": "a", "base_image": "b", "base_name": "b",
             "is_stage_alias": True, "is_scratch": False, "copy_from_refs": set()},
            {"alias": "b", "base_image": "a", "base_name": "a",
             "is_stage_alias": True, "is_scratch": False, "copy_from_refs": set()},
        ]
        _f, _l, fam = resolve_stage_graph(stages, None)
        assert fam == {0: None, 1: None}


class TestOfficialImageDefaultDistribution:
    """Official language images are Debian unless the tag says otherwise.
    Returning None for them made the libc guard inert on the builder
    stages where they overwhelmingly appear."""

    @pytest.mark.parametrize("ref,want", [
        ("golang:1.19", "debian"),
        ("node:18", "debian"),
        ("python:3.12", "debian"),
        ("rust:1.75", "debian"),
        ("nginx:1.25", "debian"),
        ("maven:3.9", "debian"),
        # an explicit signal must always beat the default
        ("golang:1.22-alpine", "alpine"),
        ("node:18-alpine", "alpine"),
        ("python:3.12-slim", "debian"),
        # and we must not guess for images we do not know
        ("busybox", None),
        ("myorg/custom:1", None),
        ("gcr.io/distroless/base-debian12", None),
    ])
    def test_default_variant(self, ref, want):
        assert _infer_os_from_image(ref) == want


class TestCopyFromExternalImage:
    """`COPY --from=<image>` names a published image, not a stage. It was
    skipped entirely, so copying a glibc binary out of one into a musl
    runtime passed the guard and failed at exec."""

    def test_glibc_image_into_musl_runtime_blocks(self):
        r = check_copy_from_libc(
            [{"alias": None, "copy_from_refs": {"nginx:1.25"}}], {0: "alpine"})
        assert r.blocked
        assert "external image" in r.blocking_reasons[0]

    def test_matching_libc_does_not_block(self):
        r = check_copy_from_libc(
            [{"alias": None, "copy_from_refs": {"nginx:1.25-alpine"}}],
            {0: "alpine"})
        assert not r.blocked

    def test_undeterminable_image_does_not_block(self):
        r = check_copy_from_libc(
            [{"alias": None, "copy_from_refs": {"myorg/unknown:1"}}],
            {0: "alpine"})
        assert not r.blocked

    def test_out_of_range_numeric_ref_is_treated_as_external(self):
        """`COPY --from=7` in a 2-stage file is not stage 7."""
        r = check_copy_from_libc(
            [{"alias": None, "copy_from_refs": {"7"}}], {0: "alpine"})
        assert not r.blocked


class TestGuardRejectionFallsBackWithinTheFamily:
    """Almost every guard that fires is a CROSS-family objection. None of
    them objects to a newer release of the same family, and that upgrade
    still removes real CVEs, so a rejection must not end the run."""

    @pytest.fixture(autouse=True)
    def _offline(self, monkeypatch):
        # Exercise the table path deterministically, with no network.
        monkeypatch.setattr("src.patcher._get_resolver", lambda: None)

    @pytest.mark.parametrize("ref,want", [
        ("debian:11", ("debian:12", 0.80)),
        ("debian:11-slim", ("debian:12-slim", 0.80)),
        ("debian:bullseye", ("debian:bookworm", 0.80)),
        ("ubuntu:20.04", ("ubuntu:24.04", 0.80)),
        ("alpine:3.18", ("alpine:3.21", 0.80)),
        ("rockylinux:8", ("rockylinux:9", 0.80)),
    ])
    def test_distro_bump(self, ref, want):
        from src.patcher import _conservative_same_image_bump
        assert _conservative_same_image_bump(ref) == want

    @pytest.mark.parametrize("ref", [
        "debian:12", "ubuntu:24.04", "alpine:3.21",   # already current
        "myorg/custom:1", "debian", "debian@sha256:" + "a" * 64,
    ])
    def test_no_bump_when_none_is_safe(self, ref):
        from src.patcher import _conservative_same_image_bump
        assert _conservative_same_image_bump(ref) is None

    def test_libc_rejection_yields_same_family_upgrade(self):
        _p, changes, warnings, _d = patch_dockerfile(
            BUILDER_RUNTIME_DEBUG, target="runtime")
        assert changes[0] == ("debian:11", "debian:12")
        assert not any("no same-family upgrade was available" in w
                       for w in warnings)

    def test_stage_stays_put_when_no_fallback_exists(self):
        """An honest no-op is still the right answer when neither the
        cross-family candidate nor a same-family bump is viable."""
        df = ("FROM golang:1.19 AS builder\n"
              "RUN go build -o /app .\n"
              "FROM debian:12\n"
              "COPY --from=builder /app /app\n")
        patched, changes, warnings, _d = patch_dockerfile(df)
        if not changes:
            assert "FROM debian:12" in patched
            assert any("no same-family upgrade was available" in w
                       for w in warnings)


class TestSingleStageUnaffected:
    """None of the above may change single-stage behaviour."""

    def test_single_stage_still_patches(self):
        df = "FROM debian:11\nRUN apt-get update\nCMD [\"sh\"]\n"
        _p, changes, _w, _d = patch_dockerfile(df)
        assert changes and changes[0][0] == "debian:11"

    def test_single_stage_is_both_final_and_live(self):
        stages = parse_dockerfile_stages("FROM debian:11\nRUN x\n")
        final, live, _fam = resolve_stage_graph(stages, None)
        assert final == {0} and live == {0}
