"""Tests for behavioural differential validation.

Each test maps to one of the failure modes a reviewer expects a
base-image substitution to be checked against: startup, shared
libraries, runtime behaviour, configuration defaults, networking, and
file permissions.
"""
from __future__ import annotations

import pytest


def _cfg(**over):
    base = {
        "Entrypoint": ["/usr/local/bin/app"],
        "Cmd": None,
        "User": "app",
        "WorkingDir": "/srv",
        "ExposedPorts": {"8080/tcp": {}},
        "Env": ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8",
                "TZ=UTC"],
    }
    base.update(over)
    return {"Config": base}


class TestEntrypointDimension:

    def test_identical_entrypoint_matches(self):
        from src.differential_validator import _cmp_entrypoint, Verdict
        r = _cmp_entrypoint(_cfg(), _cfg())
        assert r.verdict is Verdict.MATCH
        assert not r.is_regression

    def test_changed_entrypoint_is_regression(self):
        from src.differential_validator import _cmp_entrypoint, Verdict
        r = _cmp_entrypoint(_cfg(), _cfg(Entrypoint=["/bin/sh"]))
        assert r.verdict is Verdict.DIVERGED
        assert r.is_regression

    def test_missing_on_both_is_unavailable(self):
        from src.differential_validator import _cmp_entrypoint, Verdict
        empty = {"Config": {"Entrypoint": None, "Cmd": None}}
        r = _cmp_entrypoint(empty, empty)
        assert r.verdict is Verdict.UNAVAILABLE


class TestNetworkingDimension:
    """Reviewer failure mode: breaks networking."""

    def test_same_ports_match(self):
        from src.differential_validator import _cmp_ports, DiffPolicy, Verdict
        r = _cmp_ports(_cfg(), _cfg(), DiffPolicy())
        assert r.verdict is Verdict.MATCH

    def test_lost_port_is_regression(self):
        from src.differential_validator import _cmp_ports, DiffPolicy, Verdict
        r = _cmp_ports(_cfg(), _cfg(ExposedPorts={}), DiffPolicy())
        assert r.verdict is Verdict.DIVERGED
        assert r.is_regression

    def test_policy_can_allow_port_change(self):
        from src.differential_validator import _cmp_ports, DiffPolicy
        r = _cmp_ports(_cfg(), _cfg(ExposedPorts={}),
                       DiffPolicy(require_same_ports=False))
        assert r.benign
        assert not r.is_regression


class TestFilePermissionDimension:
    """Reviewer failure mode: breaks file permissions."""

    def test_same_user_matches(self):
        from src.differential_validator import _cmp_user, DiffPolicy, Verdict
        r = _cmp_user(_cfg(), _cfg(), DiffPolicy())
        assert r.verdict is Verdict.MATCH

    def test_user_change_is_regression(self):
        from src.differential_validator import _cmp_user, DiffPolicy, Verdict
        r = _cmp_user(_cfg(), _cfg(User="root"), DiffPolicy())
        assert r.verdict is Verdict.DIVERGED
        assert r.is_regression
        assert "user" in r.detail.lower()

    def test_default_root_normalization(self):
        """An absent User field means root; comparing absent against
        an explicit 'root' must not report a false divergence."""
        from src.differential_validator import _cmp_user, DiffPolicy, Verdict
        a = {"Config": {}}
        b = {"Config": {"User": "root"}}
        r = _cmp_user(a, b, DiffPolicy())
        assert r.verdict is Verdict.MATCH


class TestConfigurationDefaultsDimension:
    """Reviewer failure mode: changes configuration defaults."""

    def test_locale_change_is_regression(self):
        from src.differential_validator import (_cmp_environment, DiffPolicy,
                                                Verdict)
        r = _cmp_environment(
            _cfg(), _cfg(Env=["PATH=/usr/bin", "LANG=POSIX", "TZ=UTC"]),
            DiffPolicy())
        assert r.verdict is Verdict.DIVERGED
        assert r.is_regression
        assert "LANG" in r.detail

    def test_timezone_change_is_regression(self):
        from src.differential_validator import (_cmp_environment, DiffPolicy,
                                                Verdict)
        r = _cmp_environment(
            _cfg(), _cfg(Env=["PATH=/usr/bin", "LANG=C.UTF-8",
                              "TZ=America/Chicago"]),
            DiffPolicy())
        assert r.is_regression
        assert "TZ" in r.detail

    def test_ssl_cert_var_change_is_regression(self):
        from src.differential_validator import _cmp_environment, DiffPolicy
        r = _cmp_environment(
            _cfg(Env=["SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"]),
            _cfg(Env=["SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt"]),
            DiffPolicy())
        assert r.is_regression

    def test_path_only_change_is_benign(self):
        """Distro layouts legitimately differ; PATH divergence alone
        must not be reported as a behavioural regression."""
        from src.differential_validator import (_cmp_environment, DiffPolicy,
                                                Verdict)
        r = _cmp_environment(
            _cfg(), _cfg(Env=["PATH=/bin:/usr/bin", "LANG=C.UTF-8",
                              "TZ=UTC"]),
            DiffPolicy())
        assert r.verdict is Verdict.MATCH
        assert not r.is_regression

    def test_noncritical_var_change_is_not_a_regression(self):
        from src.differential_validator import _cmp_environment, DiffPolicy
        r = _cmp_environment(
            _cfg(), _cfg(Env=["PATH=/usr/local/bin:/usr/bin:/bin",
                              "LANG=C.UTF-8", "TZ=UTC",
                              "BUILD_ID=xyz"]),
            DiffPolicy())
        assert r.benign
        assert not r.is_regression


class TestWorkdirDimension:
    """Reviewer failure mode: behaves differently at runtime because
    relative paths resolve elsewhere."""

    def test_workdir_change_is_regression(self):
        from src.differential_validator import _cmp_workdir, DiffPolicy, Verdict
        r = _cmp_workdir(_cfg(), _cfg(WorkingDir="/"), DiffPolicy())
        assert r.verdict is Verdict.DIVERGED
        assert r.is_regression


class TestAggregation:

    def _res(self, dims):
        from src.differential_validator import DifferentialResult
        r = DifferentialResult("orig", "patched")
        r.dimensions = list(dims)
        return r

    def test_equivalent_when_no_regressions(self):
        from src.differential_validator import (DimensionResult, Dimension,
                                                Verdict)
        r = self._res([
            DimensionResult(Dimension.USER, Verdict.MATCH),
            DimensionResult(Dimension.ENVIRONMENT, Verdict.MATCH),
            DimensionResult(Dimension.DNS, Verdict.UNAVAILABLE),
        ])
        assert r.equivalent
        assert r.dimensions_compared == 2

    def test_not_equivalent_with_regression(self):
        from src.differential_validator import (DimensionResult, Dimension,
                                                Verdict)
        r = self._res([
            DimensionResult(Dimension.USER, Verdict.MATCH),
            DimensionResult(Dimension.EXPOSED_PORTS, Verdict.DIVERGED),
        ])
        assert not r.equivalent
        assert len(r.regressions) == 1

    def test_benign_divergence_keeps_equivalence(self):
        from src.differential_validator import (DimensionResult, Dimension,
                                                Verdict)
        r = self._res([
            DimensionResult(Dimension.ENVIRONMENT, Verdict.DIVERGED,
                            benign=True),
        ])
        assert r.equivalent

    def test_summary_counts_regressions_per_dimension(self):
        from src.differential_validator import (DimensionResult, Dimension,
                                                Verdict, summarize_differential)
        a = self._res([DimensionResult(Dimension.USER, Verdict.DIVERGED)])
        b = self._res([DimensionResult(Dimension.USER, Verdict.MATCH)])
        s = summarize_differential([a, b])
        assert s["images_compared"] == 2
        assert s["behaviourally_equivalent"] == 1
        assert s["regressions_by_dimension"]["user"] == 1

    def test_serialization(self):
        from src.differential_validator import (DimensionResult, Dimension,
                                                Verdict)
        r = self._res([
            DimensionResult(Dimension.CA_TRUST, Verdict.DIVERGED,
                            original="present", patched="absent",
                            detail="trust store lost"),
        ])
        d = r.to_dict()
        assert d["equivalent"] is False
        assert d["regression_count"] == 1
        assert d["dimensions"][0]["dimension"] == "ca_trust"


class TestDockerAbsent:

    def test_compare_without_docker_is_unavailable(self, monkeypatch):
        import src.differential_validator as dv
        monkeypatch.setattr(dv.shutil, "which", lambda _: None)
        r = dv.compare_images("a:1", "b:1")
        assert r.dimensions[0].verdict is dv.Verdict.UNAVAILABLE
        # No Docker means nothing was compared, so no false "equivalent"
        # claim can be derived from an empty comparison.
        assert r.dimensions_compared == 0
