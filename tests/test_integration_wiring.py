"""Tests that modules claimed by the paper are reachable from the pipeline.

Three modules (differential_validator, multistage, allowlist_loader) were
fully implemented and unit-tested but never called from main.py. A tested
module that nothing invokes protects nothing: the allow-list did not
constrain a single substitution, and the behavioural-equivalence claim had
no code behind it at runtime.

Also covers the runtime-gate fail-open: a crash inside the validator left
runtime_result=None, which the gate reads as "not evaluated" and passes,
so any validator defect silently converted an enforcing pipeline into a
non-enforcing one.
"""
from __future__ import annotations

import argparse
import inspect

import pytest

from src import main as m
from src.patcher import apply_allowlist_gate, _repo_of


class TestModulesAreReachable:
    """Each module must appear in main.py's call graph, not just on disk."""

    @pytest.mark.parametrize("module,symbol", [
        ("differential_validator", "compare_images"),
        ("multistage", "classify_cves_by_stage"),
        ("grype_scanner", "scan_image"),
        ("scanner_fusion", "fuse_scan_results"),
        ("runtime_validator", "validate_image"),
    ])
    def test_main_imports_the_module(self, module, symbol):
        src = inspect.getsource(m)
        assert f"from .{module} import" in src, (
            f"{module} is never imported by main.py; the capability it "
            f"provides is not in the pipeline"
        )
        assert symbol in src

    def test_patcher_invokes_the_allowlist(self):
        from src import patcher
        src = inspect.getsource(patcher.patch_dockerfile)
        assert "apply_allowlist_gate" in src


class TestAllowlistGate:

    @pytest.mark.parametrize("ref,repo", [
        ("python:3.12-slim", "python"),
        ("gcr.io/distroless/base-debian12:latest", "gcr.io/distroless/base-debian12"),
        ("gcr.io:5000/x/y:tag", "gcr.io:5000/x/y"),
        ("rockylinux:9", "rockylinux"),
        ("app@sha256:" + "a" * 64, "app"),
        ("ubuntu", "ubuntu"),
    ])
    def test_repo_extraction(self, ref, repo):
        assert _repo_of(ref) == repo

    def test_tag_bump_within_a_repository_is_never_gated(self, monkeypatch):
        """Same publisher, same namespace: no new party to trust, so
        requiring an allow-list entry would only block routine upgrades."""
        def boom():
            raise AssertionError("allow-list consulted for a tag bump")

        monkeypatch.setattr("src.allowlist_loader.load_allowlist", boom)
        out, note = apply_allowlist_gate("python:3.9-slim", "python:3.12-slim")
        assert out == "python:3.12-slim"
        assert note is None

    def test_unknown_source_repo_is_permitted_but_flagged(self, monkeypatch):
        from src.allowlist_loader import AllowList
        monkeypatch.setattr("src.allowlist_loader.load_allowlist",
                            lambda **k: AllowList())
        out, note = apply_allowlist_gate("obscure/thing:1", "other/thing:2")
        assert out == "other/thing:2"
        assert note and "unverified" in note

    def test_approved_migration_passes_silently(self, monkeypatch):
        from src.allowlist_loader import AllowList, AllowedTarget
        allow = AllowList(targets={"centos": [AllowedTarget(
            source_repo="centos", target_repo="rockylinux", target_tag="9",
            family="rhel", libc="glibc", verified_digest=None, priority=90)]})
        monkeypatch.setattr("src.allowlist_loader.load_allowlist",
                            lambda **k: allow)
        out, note = apply_allowlist_gate("centos:7", "rockylinux:9")
        assert out == "rockylinux:9" and note is None

    def test_unapproved_target_is_replaced_by_an_approved_one(self, monkeypatch):
        """The substitution an attacker wants: an enumerated source
        repository redirected to a repository nobody vetted."""
        from src.allowlist_loader import AllowList, AllowedTarget
        allow = AllowList(targets={"centos": [AllowedTarget(
            source_repo="centos", target_repo="rockylinux", target_tag="9",
            family=None, libc=None, verified_digest=None, priority=90)]})
        monkeypatch.setattr("src.allowlist_loader.load_allowlist",
                            lambda **k: allow)
        out, note = apply_allowlist_gate("centos:7", "attacker-ns/centos:7")
        assert out == "rockylinux:9"
        assert note and "not an approved alternate" in note

    def test_loader_failure_does_not_crash_the_patch(self, monkeypatch):
        def boom(**k):
            raise RuntimeError("yaml corrupt")

        monkeypatch.setattr("src.allowlist_loader.load_allowlist", boom)
        out, note = apply_allowlist_gate("centos:7", "rockylinux:9")
        assert out == "rockylinux:9"
        assert note and "NOT verified" in note


class TestRuntimeGateFailsClosed:
    """A validator that crashes must not be read as a validator that passed."""

    def test_pipeline_returns_error_when_validation_errors_under_enforcement(self):
        src = inspect.getsource(m)
        assert "runtime_error" in src
        # The enforcement branch must exist and must return non-zero.
        idx = src.index("if runtime_error and _runtime_enforced:")
        window = src[idx:idx + 900]
        assert "return 1" in window, (
            "an errored validator still reaches the acceptance gate, which "
            "treats a missing result as 'not evaluated' and passes"
        )

    def test_advisory_mode_is_the_documented_escape_hatch(self):
        src = inspect.getsource(m)
        idx = src.index("if runtime_error and _runtime_enforced:")
        window = src[idx:idx + 900]
        assert "--runtime-validation-advisory" in window
        assert "--no-runtime-validation" in window


class TestNewFlagsExist:

    @pytest.mark.parametrize("flag", [
        "--no-differential-validation",
        "--multistage-attribution",
        "--target",
        "--dual-scanner",
    ])
    def test_flag_is_registered(self, flag, capsys):
        with pytest.raises(SystemExit):
            m.main(["--help"])
        assert flag in capsys.readouterr().out

    def test_builder_supports_target_for_stage_attribution(self):
        from src.builder import build_image
        assert "target" in inspect.signature(build_image).parameters, (
            "a builder stage is not an image until built with --target, so "
            "per-stage attribution has nothing to scan without it"
        )
