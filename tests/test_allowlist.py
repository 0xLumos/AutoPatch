"""Tests for AI-assisted allow-list generation, verification, and loading.

The design contract under test: the provider is untrusted, the
verifier is authoritative, and the patching path reads only a
committed artifact. These tests assert that a hallucinated,
mis-claimed, or malicious proposal cannot reach the shipped
allow-list, and that a broken artifact never breaks remediation.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ════════════════════════════════════════════════════════════════════
# Name hygiene: the guard that runs before any network request
# ════════════════════════════════════════════════════════════════════

class TestRepositoryHygiene:

    @pytest.mark.parametrize("repo", [
        "python", "library/python", "myorg/app",
        "gcr.io/distroless/base-debian12",
        "cgr.dev/chainguard/python",
        "quay.io/centos/centos",
    ])
    def test_accepts_allowed_references(self, repo):
        from src.allowlist_providers import is_repo_acceptable
        assert is_repo_acceptable(repo)

    @pytest.mark.parametrize("repo", [
        "evil.example.com/malware",     # unlisted registry host
        "registry.internal/app",        # unlisted registry host
        "localhost:5000/x",             # unlisted registry host
        "python; rm -rf /",             # shell metacharacters
        "../../etc/passwd",             # path traversal
        "UPPERCASE",                    # invalid grammar
        "",                             # empty
        "x" * 300,                      # over length
    ])
    def test_rejects_unsafe_references(self, repo):
        from src.allowlist_providers import is_repo_acceptable
        assert not is_repo_acceptable(repo)

    @pytest.mark.parametrize("tag,ok", [
        ("3.12-slim", True), ("bookworm", True), (None, True),
        ("bad tag", False), ("-leading", False), ("a" * 200, False),
    ])
    def test_tag_grammar(self, tag, ok):
        from src.allowlist_providers import is_tag_acceptable
        assert is_tag_acceptable(tag) is ok

    def test_sanitize_drops_self_and_unsafe(self):
        from src.allowlist_providers import Proposal, sanitize
        props = [
            Proposal("python", "python"),               # self-mapping
            Proposal("python", "evil.example.com/x"),   # bad host
            Proposal("python", "bad name"),             # bad grammar
            Proposal("python", "debian"),               # keeper
        ]
        assert [p.target_repo for p in sanitize(props)] == ["debian"]


# ════════════════════════════════════════════════════════════════════
# Providers
# ════════════════════════════════════════════════════════════════════

class TestProviders:

    def test_heuristic_needs_no_credentials(self):
        from src.allowlist_providers import HeuristicProvider, Profile
        p = HeuristicProvider(curated={"python": ["debian"]})
        out = p.propose("python", Profile("debian", "glibc"))
        assert out
        assert all(x.provider == "heuristic" for x in out)

    def test_null_provider_proposes_nothing(self):
        from src.allowlist_providers import NullProvider, Profile
        assert NullProvider().propose("python", Profile("debian", "glibc")) == []

    def test_auto_falls_back_without_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        from src.allowlist_providers import build_provider
        assert build_provider("auto").name == "heuristic"

    def test_anthropic_requires_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        from src.allowlist_providers import AnthropicProvider
        with pytest.raises(RuntimeError):
            AnthropicProvider()

    def test_prompt_hash_is_stable(self):
        from src.allowlist_providers import prompt_sha256
        a, b = prompt_sha256(), prompt_sha256()
        assert a == b and len(a) == 64

    def test_provider_limit_is_respected(self):
        from src.allowlist_providers import HeuristicProvider, Profile
        p = HeuristicProvider(curated={"x": ["debian", "ubuntu"]})
        assert len(p.propose("x", Profile("debian", "glibc"), limit=1)) == 1


# ════════════════════════════════════════════════════════════════════
# Verification: the layer that makes untrusted proposals safe
# ════════════════════════════════════════════════════════════════════

class TestFamilyCompatibility:

    def test_identical_family_is_compatible(self):
        from src.allowlist_verify import _family_compatible
        assert _family_compatible("debian", "debian")

    def test_deb_family_siblings_are_compatible(self):
        from src.allowlist_verify import _family_compatible
        assert _family_compatible("ubuntu", "debian")
        assert _family_compatible("debian", "ubuntu")

    def test_musl_and_glibc_worlds_are_not_compatible(self):
        from src.allowlist_verify import _family_compatible
        assert not _family_compatible("alpine", "debian")
        assert not _family_compatible("debian", "alpine")

    def test_rhel_does_not_absorb_debian(self):
        from src.allowlist_verify import _family_compatible
        assert not _family_compatible("debian", "rhel")


class TestVerificationFailsClosed:

    def test_no_docker_rejects_at_first_stage(self, monkeypatch):
        import src.allowlist_verify as av
        monkeypatch.setattr(av.shutil, "which", lambda _: None)
        from src.allowlist_providers import Proposal, Profile
        r = av.verify_proposal(Proposal("python", "debian"),
                               Profile("debian", "glibc"))
        assert not r.accepted
        assert r.failed_stage is av.Stage.EXISTENCE

    def test_nonexistent_repository_rejected(self, monkeypatch):
        """A hallucinated repository dies at the tag-listing stage,
        after one cheap request and before any pull."""
        import src.allowlist_verify as av
        monkeypatch.setattr(av.shutil, "which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(av, "_list_tags", lambda repo, timeout_s=30: [])
        from src.allowlist_providers import Proposal, Profile
        r = av.verify_proposal(Proposal("python", "totally/invented"),
                               Profile("debian", "glibc"))
        assert not r.accepted
        assert r.failed_stage is av.Stage.EXISTENCE

    def test_no_stable_tag_rejected(self, monkeypatch):
        import src.allowlist_verify as av
        monkeypatch.setattr(av.shutil, "which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(av, "_list_tags",
                            lambda repo, timeout_s=30: ["latest", "nightly",
                                                        "1.0-rc1"])
        from src.allowlist_providers import Proposal, Profile
        r = av.verify_proposal(Proposal("python", "debian"),
                               Profile("debian", "glibc"))
        assert not r.accepted
        assert r.failed_stage is av.Stage.TAG

    def test_platform_mismatch_rejected(self, monkeypatch):
        import src.allowlist_verify as av
        monkeypatch.setattr(av.shutil, "which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(av, "_list_tags",
                            lambda repo, timeout_s=30: ["12", "12-slim"])
        monkeypatch.setattr(av, "_manifest_platforms",
                            lambda ref, timeout_s=60: ["linux/arm64"])
        from src.allowlist_providers import Proposal, Profile
        r = av.verify_proposal(Proposal("python", "debian"),
                               Profile("debian", "glibc",
                                       platform="linux/amd64"))
        assert not r.accepted
        assert r.failed_stage is av.Stage.PLATFORM

    def test_claimed_family_is_ignored_when_evidence_disagrees(self, monkeypatch):
        """The decisive test: a provider confidently claims the target
        is Debian, the filesystem says Alpine, and the proposal is
        rejected. The provider's claim carries no weight."""
        import src.allowlist_verify as av
        monkeypatch.setattr(av.shutil, "which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(av, "_list_tags",
                            lambda repo, timeout_s=30: ["3.19"])
        monkeypatch.setattr(av, "_manifest_platforms",
                            lambda ref, timeout_s=60: ["linux/amd64"])
        monkeypatch.setattr(av, "_pull", lambda ref, timeout_s=300: True)
        monkeypatch.setattr(av, "_digest", lambda ref: "sha256:deadbeef")
        monkeypatch.setattr(av, "_rmi", lambda ref: None)
        monkeypatch.setattr(
            av, "_check_identity",
            lambda ref, profile: (False, "family mismatch: observed alpine, "
                                         "required debian", "alpine", "musl"),
        )
        from src.allowlist_providers import Proposal, Profile
        prop = Proposal("python", "alpine", claimed_family="debian",
                        claimed_libc="glibc")   # the lie
        r = av.verify_proposal(prop, Profile("debian", "glibc"))
        assert not r.accepted
        assert r.failed_stage is av.Stage.IDENTITY
        assert r.observed_family == "alpine"

    def test_smoke_build_failure_rejected(self, monkeypatch):
        import src.allowlist_verify as av
        monkeypatch.setattr(av.shutil, "which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(av, "_list_tags", lambda repo, timeout_s=30: ["12"])
        monkeypatch.setattr(av, "_manifest_platforms",
                            lambda ref, timeout_s=60: ["linux/amd64"])
        monkeypatch.setattr(av, "_pull", lambda ref, timeout_s=300: True)
        monkeypatch.setattr(av, "_digest", lambda ref: "sha256:abc")
        monkeypatch.setattr(av, "_rmi", lambda ref: None)
        monkeypatch.setattr(av, "_check_identity",
                            lambda ref, p: (True, "ok", "debian", "glibc"))
        monkeypatch.setattr(av, "_check_smoke",
                            lambda ref, timeout_s=300: (False, "build failed"))
        from src.allowlist_providers import Proposal, Profile
        r = av.verify_proposal(Proposal("python", "debian"),
                               Profile("debian", "glibc"))
        assert not r.accepted
        assert r.failed_stage is av.Stage.SMOKE

    def test_fully_valid_proposal_accepted(self, monkeypatch):
        import src.allowlist_verify as av
        monkeypatch.setattr(av.shutil, "which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(av, "_list_tags",
                            lambda repo, timeout_s=30: ["12", "12-slim"])
        monkeypatch.setattr(av, "_manifest_platforms",
                            lambda ref, timeout_s=60: ["linux/amd64"])
        monkeypatch.setattr(av, "_pull", lambda ref, timeout_s=300: True)
        monkeypatch.setattr(av, "_digest", lambda ref: "sha256:feedface")
        monkeypatch.setattr(av, "_rmi", lambda ref: None)
        monkeypatch.setattr(av, "_check_identity",
                            lambda ref, p: (True, "ok", "debian", "glibc"))
        monkeypatch.setattr(av, "_check_smoke",
                            lambda ref, timeout_s=300: (True, "ok"))
        from src.allowlist_providers import Proposal, Profile
        r = av.verify_proposal(Proposal("python", "debian"),
                               Profile("debian", "glibc"))
        assert r.accepted
        assert r.resolved_digest == "sha256:feedface"
        assert r.observed_family == "debian"


class TestVerificationStats:

    def test_counters_are_cumulative(self, monkeypatch):
        import src.allowlist_verify as av
        from src.allowlist_providers import Proposal, Profile

        monkeypatch.setattr(av.shutil, "which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(av, "_manifest_platforms",
                            lambda ref, timeout_s=60: ["linux/amd64"])
        monkeypatch.setattr(av, "_pull", lambda ref, timeout_s=300: True)
        monkeypatch.setattr(av, "_digest", lambda ref: "sha256:x")
        monkeypatch.setattr(av, "_rmi", lambda ref: None)
        monkeypatch.setattr(av, "_check_smoke",
                            lambda ref, timeout_s=300: (True, "ok"))

        # good target verifies; bad target fails identity
        monkeypatch.setattr(av, "_list_tags", lambda repo, timeout_s=30: ["12"])
        monkeypatch.setattr(
            av, "_check_identity",
            lambda ref, p: (True, "ok", "debian", "glibc")
            if ref.startswith("debian") else
            (False, "family mismatch", "alpine", "musl"),
        )

        props = [Proposal("python", "debian"), Proposal("python", "alpine")]
        profile = {"python": Profile("debian", "glibc")}
        results, stats = av.verify_all(props, profile)

        d = stats.as_dict()
        assert d["proposals_total"] == 2
        assert d["passed_existence"] == 2      # both repos listed tags
        assert d["passed_identity"] == 1       # only debian survived
        assert d["accepted"] == 1
        assert d["rejected_by_stage"]["identity"] == 1
        assert 0.0 < d["acceptance_rate"] < 1.0


# ════════════════════════════════════════════════════════════════════
# Loader: last-known-good behaviour
# ════════════════════════════════════════════════════════════════════

def _write_artifact(tmp_path, mappings, *, schema="2.0", bad_hash=False):
    import yaml
    from src.allowlist_loader import _content_hash
    doc = {
        "schema_version": schema,
        "generated_at": "2026-08-07T00:00:00+00:00",
        "generator": {"provider": "anthropic", "model": "claude-sonnet-4-5",
                      "prompt_sha256": "0" * 64, "temperature": 0},
        "verification": {"proposals_total": 10, "accepted": len(mappings)},
        "content_sha256": ("f" * 64) if bad_hash else _content_hash(mappings),
        "mappings": mappings,
    }
    p = tmp_path / "allowlist_generated.yaml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


class TestAllowListLoader:

    def test_loads_valid_generated_artifact(self, tmp_path):
        from src.allowlist_loader import load_allowlist
        p = _write_artifact(tmp_path, {
            "python": [{"target_repo": "debian", "target_tag": "12-slim",
                        "family": "debian", "libc": "glibc",
                        "verified_digest": "sha256:a", "priority": 60}],
        })
        al = load_allowlist(force_reload=True, generated_path=p)
        assert al.source == "generated"
        assert al.provider == "anthropic"
        assert len(al) == 1
        t = al.alternates_for("python")[0]
        assert t.target_ref == "debian:12-slim"

    def test_hash_mismatch_falls_back(self, tmp_path):
        """A tampered or truncated artifact must not be used."""
        from src.allowlist_loader import load_allowlist
        p = _write_artifact(tmp_path, {
            "python": [{"target_repo": "debian", "target_tag": "12"}],
        }, bad_hash=True)
        al = load_allowlist(force_reload=True, generated_path=p)
        assert al.source != "generated"

    def test_unsupported_schema_falls_back(self, tmp_path):
        from src.allowlist_loader import load_allowlist
        p = _write_artifact(tmp_path, {"python": []}, schema="99.0")
        al = load_allowlist(force_reload=True, generated_path=p)
        assert al.source != "generated"

    def test_missing_artifact_falls_back(self, tmp_path):
        from src.allowlist_loader import load_allowlist
        al = load_allowlist(force_reload=True,
                            generated_path=tmp_path / "nope.yaml")
        assert al.source in {"curated", "none"}

    def test_malformed_yaml_falls_back(self, tmp_path):
        from src.allowlist_loader import load_allowlist
        p = tmp_path / "allowlist_generated.yaml"
        p.write_text("{{{ not yaml", encoding="utf-8")
        al = load_allowlist(force_reload=True, generated_path=p)
        assert al.source != "generated"

    def test_alternates_filtered_by_family_and_libc(self, tmp_path):
        from src.allowlist_loader import load_allowlist
        p = _write_artifact(tmp_path, {
            "app": [
                {"target_repo": "debian", "target_tag": "12",
                 "family": "debian", "libc": "glibc", "priority": 50},
                {"target_repo": "alpine", "target_tag": "3.19",
                 "family": "alpine", "libc": "musl", "priority": 90},
            ],
        })
        al = load_allowlist(force_reload=True, generated_path=p)
        glibc_only = al.alternates_for("app", family="debian", libc="glibc")
        assert [t.target_repo for t in glibc_only] == ["debian"]

    def test_ordering_is_deterministic(self, tmp_path):
        from src.allowlist_loader import load_allowlist
        p = _write_artifact(tmp_path, {
            "app": [
                {"target_repo": "b", "target_tag": "1", "priority": 10},
                {"target_repo": "a", "target_tag": "1", "priority": 90},
                {"target_repo": "c", "target_tag": "1", "priority": 90},
            ],
        })
        al = load_allowlist(force_reload=True, generated_path=p)
        order = [t.target_repo for t in al.alternates_for("app")]
        assert order == ["a", "c", "b"]     # priority desc, then repo asc
