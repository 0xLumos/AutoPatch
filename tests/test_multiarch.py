"""Tests for src.multiarch (P4-27)."""
from __future__ import annotations

import pytest


class TestParsePlatforms:
    """parse_platforms must accept comma-separated specs, reject
    unknown / malformed entries, and deduplicate while preserving
    order."""

    def test_single_platform(self):
        from src.multiarch import parse_platforms
        assert parse_platforms("linux/amd64") == ["linux/amd64"]

    def test_two_platforms(self):
        from src.multiarch import parse_platforms
        assert parse_platforms("linux/amd64,linux/arm64") == [
            "linux/amd64", "linux/arm64",
        ]

    def test_preserves_order(self):
        from src.multiarch import parse_platforms
        # Specifying arm64 first must keep arm64 first in output.
        assert parse_platforms("linux/arm64,linux/amd64") == [
            "linux/arm64", "linux/amd64",
        ]

    def test_deduplicates(self):
        from src.multiarch import parse_platforms
        assert parse_platforms("linux/amd64,linux/amd64") == ["linux/amd64"]

    def test_tolerates_whitespace_and_case(self):
        from src.multiarch import parse_platforms
        assert parse_platforms(" Linux/AMD64 , linux/arm64 ") == [
            "linux/amd64", "linux/arm64",
        ]

    def test_rejects_empty(self):
        from src.multiarch import parse_platforms
        with pytest.raises(ValueError):
            parse_platforms("")
        with pytest.raises(ValueError):
            parse_platforms("   ")

    def test_rejects_unknown(self):
        from src.multiarch import parse_platforms
        with pytest.raises(ValueError, match="unknown platform"):
            parse_platforms("windows/amd64")

    def test_rejects_malformed(self):
        from src.multiarch import parse_platforms
        with pytest.raises(ValueError, match="malformed"):
            parse_platforms("not-a-platform")
        with pytest.raises(ValueError, match="malformed"):
            parse_platforms("Linux Amd64")  # space, no slash


class TestAggregateResults:
    """The aggregator must reject the whole release when ANY platform
    fails, never average / negotiate failures away."""

    def _ok(self, platform):
        from src.multiarch import PlatformResult
        return PlatformResult(
            platform=platform,
            image_digest=f"sha256:{platform.replace('/', '-')}",
            accepted=True,
        )

    def _bad(self, platform, why="severity floor"):
        from src.multiarch import PlatformResult
        return PlatformResult(platform=platform, accepted=False, reasons=[why])

    def test_all_accepted_when_every_platform_passes(self):
        from src.multiarch import aggregate_results
        out = aggregate_results([
            self._ok("linux/amd64"), self._ok("linux/arm64"),
        ])
        assert out.all_accepted is True
        assert out.first_failure is None

    def test_one_failure_rejects_release(self):
        from src.multiarch import aggregate_results
        out = aggregate_results([
            self._ok("linux/amd64"), self._bad("linux/arm64"),
        ])
        assert out.all_accepted is False
        assert out.first_failure is not None
        assert out.first_failure.platform == "linux/arm64"

    def test_empty_input_is_not_accepted(self):
        from src.multiarch import aggregate_results
        out = aggregate_results([])
        assert out.all_accepted is False  # vacuous-truth would be wrong


class TestManifestListCommand:
    """The manifest-list argv must be exactly what buildx imagetools
    expects and must refuse to publish when no digests are present."""

    def test_includes_tag_and_digests(self):
        from src.multiarch import (
            build_manifest_list_command, PlatformResult,
        )
        argv = build_manifest_list_command(
            "registry/example/img:v2",
            [
                PlatformResult(platform="linux/amd64",
                               image_digest="sha256:aaaa", accepted=True),
                PlatformResult(platform="linux/arm64",
                               image_digest="sha256:bbbb", accepted=True),
            ],
        )
        assert argv[:4] == ["docker", "buildx", "imagetools", "create"]
        assert "--tag" in argv
        assert argv[argv.index("--tag") + 1] == "registry/example/img:v2"
        assert "sha256:aaaa" in argv
        assert "sha256:bbbb" in argv

    def test_rejects_missing_tag(self):
        from src.multiarch import build_manifest_list_command
        with pytest.raises(ValueError):
            build_manifest_list_command("", [])

    def test_rejects_when_no_digests(self):
        from src.multiarch import (
            build_manifest_list_command, PlatformResult,
        )
        # Both platforms failed: no per-arch digest available, so we
        # must not even attempt to publish a manifest list.
        with pytest.raises(ValueError, match="no per-platform digests"):
            build_manifest_list_command(
                "reg/img:v2",
                [PlatformResult(platform="linux/amd64", accepted=False)],
            )


class TestSummarise:
    def test_includes_per_platform_breakdown(self):
        from src.multiarch import (
            aggregate_results, summarise, PlatformResult,
        )
        out = aggregate_results([
            PlatformResult(platform="linux/amd64",
                           image_digest="sha256:a", accepted=True),
            PlatformResult(platform="linux/arm64", accepted=False,
                           reasons=["new critical CVE"]),
        ])
        out.manifest_ref = None
        s = summarise(out)
        assert s["all_accepted"] is False
        assert s["platform_count"] == 2
        assert s["platforms"][0]["accepted"] is True
        assert s["platforms"][1]["reasons"] == ["new critical CVE"]


class TestBuildxAvailability:
    """ensure_buildx_available uses an injected runner in tests so we
    do not depend on Docker being installed on the test box."""

    def test_returns_true_when_buildx_responds(self, monkeypatch):
        import src.multiarch as ma
        monkeypatch.setattr(ma.shutil, "which", lambda _: "/usr/bin/docker")
        runner = lambda _argv: (0, "github.com/docker/buildx v0.12.0")
        assert ma.ensure_buildx_available(runner=runner) is True

    def test_returns_false_when_buildx_missing(self, monkeypatch):
        import src.multiarch as ma
        monkeypatch.setattr(ma.shutil, "which", lambda _: "/usr/bin/docker")
        runner = lambda _argv: (1, "docker: 'buildx' is not a docker command")
        assert ma.ensure_buildx_available(runner=runner) is False

    def test_returns_false_when_docker_missing(self, monkeypatch):
        import src.multiarch as ma
        monkeypatch.setattr(ma.shutil, "which", lambda _: None)
        assert ma.ensure_buildx_available(runner=lambda _: (0, "")) is False
