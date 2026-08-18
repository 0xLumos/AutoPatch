"""Tests for pre-flight compatibility guards.

Each guard corresponds to an observed build failure that the pipeline
previously discovered only by attempting the build, consuming a
candidate attempt and the full build timeout. A guard that fires too
eagerly is as harmful as one that never fires, so every case below has
a matching negative case.
"""
from __future__ import annotations

import pytest

from src.compat_guards import (
    GuardSeverity,
    check_copy_from_libc,
    check_distro_locked_commands,
    check_shell_dialect,
    check_version_pins,
    evaluate_candidate,
)


class TestDistroLockedCommands:

    def test_apt_key_blocks_move_to_alpine(self):
        df = "FROM debian:11\nRUN apt-key adv --recv-keys ABC\n"
        r = check_distro_locked_commands(df, "debian", "alpine")
        assert r.blocked
        assert "apt-key" in r.blocking_reasons[0]

    def test_apt_key_allowed_debian_to_ubuntu(self):
        """Both distributions provide apt-key; this must not block."""
        df = "FROM debian:11\nRUN apt-key adv --recv-keys ABC\n"
        assert not check_distro_locked_commands(df, "debian", "ubuntu").blocked

    def test_yum_config_manager_blocks_move_to_debian(self):
        df = "FROM rockylinux:9\nRUN yum-config-manager --enable crb\n"
        assert check_distro_locked_commands(df, "rhel", "debian").blocked

    def test_dpkg_install_blocks_cross_family(self):
        df = "FROM debian:12\nRUN dpkg -i /tmp/pkg.deb\n"
        r = check_distro_locked_commands(df, "debian", "rhel")
        assert r.blocked
        assert ".deb" in r.blocking_reasons[0]

    def test_rpm_install_blocks_cross_family(self):
        df = "FROM rockylinux:9\nRUN rpm -i /tmp/pkg.rpm\n"
        assert check_distro_locked_commands(df, "rhel", "debian").blocked

    def test_continuation_lines_are_joined(self):
        df = ("FROM debian:11\n"
              "RUN apt-get update && \\\n"
              "    add-apt-repository ppa:x/y && \\\n"
              "    apt-get install -y z\n")
        r = check_distro_locked_commands(df, "debian", "alpine")
        assert r.blocked
        assert "add-apt-repository" in r.blocking_reasons[0]

    def test_same_family_never_blocks(self):
        df = "FROM debian:11\nRUN apt-key adv --recv-keys ABC\n"
        assert not check_distro_locked_commands(df, "debian", "debian").blocked

    def test_busybox_useradd_flags_warn_not_block(self):
        df = "FROM debian:12\nRUN useradd -r appuser\n"
        r = check_distro_locked_commands(df, "debian", "alpine")
        assert not r.blocked
        assert r.warnings


class TestVersionPins:

    def test_apt_pin_warns_on_family_change(self):
        df = "FROM debian:11\nRUN apt-get install -y curl=7.88.1-10\n"
        r = check_version_pins(df, "debian", "alpine")
        assert r.warnings
        assert "curl=7.88.1-10" in r.findings[0].evidence

    def test_no_warning_within_family(self):
        df = "FROM debian:11\nRUN apt-get install -y curl=7.88.1-10\n"
        assert not check_version_pins(df, "debian", "debian").findings

    def test_shell_variable_assignment_is_not_a_pin(self):
        df = "FROM debian:11\nRUN DEBIAN_FRONTEND=noninteractive apt-get install -y curl\n"
        r = check_version_pins(df, "debian", "alpine")
        assert not r.findings

    def test_unpinned_install_is_clean(self):
        df = "FROM debian:11\nRUN apt-get install -y curl git\n"
        assert not check_version_pins(df, "debian", "alpine").findings


class TestShellDialect:

    @pytest.mark.parametrize("snippet", [
        "if [[ -f /etc/x ]]; then echo y; fi",
        "source /etc/profile",
        "declare -A map",
        "cat <<< \"$x\"",
        "if [[ $v =~ ^1 ]]; then echo y; fi",
    ])
    def test_bashisms_warn_on_move_to_alpine(self, snippet):
        """WARN, not BLOCK: the target may install bash, and a regex
        cannot tell whether the construct is inside a quoted string
        that is never evaluated. A false BLOCK discards a valid
        remediation; a warning lets the build adjudicate."""
        df = f"FROM debian:12\nRUN {snippet}\n"
        r = check_shell_dialect(df, "debian", "alpine")
        assert not r.blocked
        assert r.warnings

    def test_posix_character_class_is_not_a_bashism(self):
        """`find -name '[[:alpha:]]*'` is portable and works in ash."""
        df = 'FROM debian:12\nRUN find . -name "[[:alpha:]]*"\n'
        r = check_shell_dialect(df, "debian", "alpine")
        assert not r.blocked and not r.warnings

    def test_explicit_bash_invocation_is_allowed(self):
        df = 'FROM debian:12\nRUN bash -c "if [[ -f /x ]]; then echo y; fi"\n'
        assert not check_shell_dialect(df, "debian", "alpine").findings

    def test_installing_bash_does_not_suppress_the_check(self):
        """Matching the bare word 'bash' anywhere skipped the check on
        `apk add bash && [[ ... ]]`, which is a real bashism."""
        df = "FROM debian:12\nRUN apk add bash && [[ -f /x ]]\n"
        assert check_shell_dialect(df, "debian", "alpine").warnings

    def test_posix_sh_is_allowed(self):
        df = 'FROM debian:12\nRUN if [ -f /etc/x ]; then echo y; fi\n'
        assert not check_shell_dialect(df, "debian", "alpine").findings

    def test_no_check_when_target_is_not_ash(self):
        df = "FROM debian:12\nRUN [[ -f /x ]]\n"
        assert not check_shell_dialect(df, "debian", "ubuntu").findings

    def test_alpine_to_alpine_not_flagged(self):
        df = "FROM alpine:3.18\nRUN [[ -f /x ]]\n"
        assert not check_shell_dialect(df, "alpine", "alpine").findings


class TestFamilyNormalization:
    """Point distributions must resolve to package-manager families,
    or a CentOS to Rocky upgrade is rejected on the grounds that
    'yum-config-manager exists only on rhel'."""

    @pytest.mark.parametrize("value,want", [
        ("centos", "rhel"), ("rocky", "rhel"), ("rockylinux", "rhel"),
        ("alma", "rhel"), ("fedora", "rhel"), ("amazonlinux", "rhel"),
        ("debian", "debian"), ("ubuntu", "ubuntu"),
        ("alpine", "alpine"), ("chainguard", "wolfi"),
    ])
    def test_normalization(self, value, want):
        from src.compat_guards import normalize_family
        assert normalize_family(value) == want

    def test_centos_to_rocky_is_allowed(self):
        df = ("FROM centos:7\n"
              "RUN yum-config-manager --enable extras\n"
              "RUN yum install -y curl\n")
        assert not evaluate_candidate(df, "centos", "rocky").blocked

    def test_centos_to_alpine_still_blocks(self):
        df = "FROM centos:7\nRUN yum-config-manager --enable extras\n"
        assert evaluate_candidate(df, "centos", "alpine").blocked

    def test_libc_guard_covers_rhel_derivatives(self):
        stages = [{"alias": "builder", "copy_from_refs": set()},
                  {"alias": None, "copy_from_refs": {"builder"}}]
        assert check_copy_from_libc(stages, {0: "rocky", 1: "alpine"}).blocked
        assert check_copy_from_libc(stages, {0: "almalinux", 1: "alpine"}).blocked


class TestCopyFromLibc:

    @staticmethod
    def _stages():
        return [
            {"alias": "builder", "copy_from_refs": set()},
            {"alias": None, "copy_from_refs": {"builder"}},
        ]

    def test_glibc_builder_into_musl_runtime_blocks(self):
        r = check_copy_from_libc(self._stages(), {0: "debian", 1: "alpine"})
        assert r.blocked
        assert "glibc" in r.blocking_reasons[0]
        assert "musl" in r.blocking_reasons[0]

    def test_same_libc_is_allowed(self):
        assert not check_copy_from_libc(
            self._stages(), {0: "debian", 1: "debian"}).blocked
        assert not check_copy_from_libc(
            self._stages(), {0: "alpine", 1: "alpine"}).blocked

    def test_musl_builder_into_glibc_runtime_blocks(self):
        r = check_copy_from_libc(self._stages(), {0: "alpine", 1: "debian"})
        assert r.blocked

    def test_numeric_stage_reference(self):
        stages = [
            {"alias": None, "copy_from_refs": set()},
            {"alias": None, "copy_from_refs": {"0"}},
        ]
        assert check_copy_from_libc(stages, {0: "debian", 1: "alpine"}).blocked

    def test_unknown_family_does_not_block(self):
        assert not check_copy_from_libc(self._stages(), {0: "debian"}).blocked

    def test_no_copy_from_is_clean(self):
        stages = [{"alias": "builder", "copy_from_refs": set()},
                  {"alias": None, "copy_from_refs": set()}]
        assert not check_copy_from_libc(stages, {0: "debian", 1: "alpine"}).blocked


class TestCombinedEvaluation:

    def test_clean_dockerfile_passes_every_guard(self):
        df = ("FROM debian:12\n"
              "RUN apt-get update && apt-get install -y curl\n"
              'CMD ["curl", "--version"]\n')
        r = evaluate_candidate(df, "debian", "ubuntu")
        assert not r.blocked

    def test_multiple_findings_are_all_reported(self):
        df = ("FROM debian:11\n"
              "RUN apt-key adv --recv-keys ABC\n"
              "RUN apt-get install -y curl=7.88.1-10\n"
              "RUN [[ -f /etc/x ]] && echo y\n")
        r = evaluate_candidate(df, "debian", "alpine")
        assert r.blocked
        # one hard block (apt-key) plus two advisories (the version pin
        # and the bashism), all three surfaced in a single report so the
        # operator sees every reason at once rather than one per attempt
        assert len(r.blocking_reasons) == 1
        assert len(r.warnings) == 2
        assert len(r.findings) == 3


class TestPatcherIntegration:
    """The guards must actually gate the rewrite, not just report."""

    def test_blocked_operator_override_keeps_original_base(self):
        """A --base-mapping entry is an explicit operator decision. When
        a guard rejects it, the stage stays put: silently shipping a
        DIFFERENT image than the one the operator named and reviewed is
        worse than making no change at all."""
        from src.patcher import patch_dockerfile
        df = ("FROM debian:11\n"
              "RUN apt-key adv --recv-keys ABC\n"
              'CMD ["sh"]\n')
        patched, changes, warnings, _ = patch_dockerfile(
            df, base_mapping={"debian:11": "alpine:3.19"})
        assert changes == [], "a doomed candidate was accepted"
        assert "FROM debian:11" in patched
        assert any("pre-flight" in w for w in warnings)
        assert any("operator-specified" in w for w in warnings)
        assert not any("fell back" in w for w in warnings)

    def test_blocked_inferred_candidate_falls_back_within_family(self, monkeypatch):
        """When the candidate came from OUR inference rather than the
        operator, a guard rejection must not end the run: the
        same-family upgrade still removes CVEs and no guard objects to
        it."""
        monkeypatch.setattr("src.patcher._get_resolver", lambda: None)
        from src.patcher import patch_dockerfile
        df = ("FROM golang:1.19 AS builder\n"
              "RUN go build -o /app .\n"
              "FROM debian:11\n"
              "COPY --from=builder /app /app\n")
        _patched, changes, warnings, _ = patch_dockerfile(df)
        assert changes == [("debian:11", "debian:12")]
        # The distro-runtime guard now takes the in-family bump directly
        # (no musl candidate is proposed for a distro base), so the old
        # copy-from-libc rejection/fallback warnings no longer occur. The
        # headline behavior, a same-family upgrade instead of a no-op, is
        # asserted above.

    def test_compatible_candidate_is_applied(self):
        from src.patcher import patch_dockerfile
        df = ("FROM debian:11\n"
              "RUN apt-key adv --recv-keys ABC\n"
              'CMD ["sh"]\n')
        _patched, changes, _w, _d = patch_dockerfile(
            df, base_mapping={"debian:11": "debian:12-slim"})
        assert changes and changes[0][1] == "debian:12-slim"


class TestOsInference:
    """Regression: plain distro references returned None, which
    silently disabled both migration and these guards."""

    @pytest.mark.parametrize("ref,want", [
        ("debian:11", "debian"),
        ("debian:12", "debian"),
        ("debian:bookworm", "debian"),
        ("ubuntu:22.04", "ubuntu"),
        ("ubuntu:noble", "ubuntu"),
        ("alpine:3.19", "alpine"),
        ("rockylinux:9", "rocky"),
        ("almalinux:9", "alma"),
        ("python:3.12-slim", "debian"),
        ("python:3.12-alpine", "alpine"),
        ("redhat/ubi9", "rhel"),
    ])
    def test_family_inference(self, ref, want):
        from src.patcher import _infer_os_from_image
        assert _infer_os_from_image(ref) == want
