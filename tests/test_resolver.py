"""``src/resolver.py`` is the primary base-image selection path, and every
one of its failure modes is silent.

Four properties are load-bearing and none of them was covered:

1. Registry routing. ``gcr.io/distroless/base`` is not a Docker Hub
   repository. Stripping the host and asking registry-1.docker.io for
   ``distroless/base`` returns 404, tag verification fails closed, and the
   candidate is dropped. Distroless and Chainguard images are the
   lowest-CVE targets available, so a routing regression suppresses
   exactly the rewrites that would help most, while the run still reports
   success.
2. Pagination. ``/tags/list`` is paginated and the newest release is
   routinely absent from page one. A truncated listing is
   indistinguishable from a nonexistent tag, so it also presents as a
   rejected upgrade rather than as an error.
3. Fail-closed verification. ``verify_tag`` must return False when the
   registry cannot be reached. An accidental fail-open would let the
   pipeline rewrite a FROM line to a tag that does not exist, which
   breaks the build rather than securing it.
4. Cache scoping. Verifying four candidate tags of ``python`` must issue
   one listing, not four. The previous behaviour tripped Docker Hub's
   anonymous rate limit on a corpus run, and the resulting 429s made
   valid upgrades look invalid.

Nothing here touches the network. Every test either installs a scripted
session object or stubs the token/listing helpers, and an autouse fixture
turns any leaked real call into an immediate failure rather than a DNS
timeout.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import requests

import src.resolver as resolver_mod
from src.resolver import ImageResolver

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_REGISTRY = REPO_ROOT / "src" / "image_registry.yaml"


# ── test doubles ────────────────────────────────────────────────────


class FakeResponse:
    """Minimal stand-in for ``requests.Response``.

    Only the four members ``_list_all_tags`` and ``_registry_token``
    actually touch are implemented, so a test that starts depending on
    something else fails loudly instead of quietly picking up a Mock.
    """

    def __init__(self, status_code=200, payload=None, headers=None,
                 json_ok=True):
        self.status_code = status_code
        self._payload = {} if payload is None else payload
        self.headers = headers or {}
        self._json_ok = json_ok

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        if not self._json_ok:
            raise ValueError("body was not JSON")
        return self._payload


class RecordingSession:
    """Scripted replacement for ``ImageResolver._session``.

    ``handler(url, headers, params, call_number)`` returns a
    :class:`FakeResponse`. Every request is recorded so a test can assert
    on the host that was contacted and on the number of round trips,
    which is how the cache-scoping and pagination-cap regressions are
    detected.
    """

    def __init__(self, handler):
        self._handler = handler
        self.calls = []
        self.headers = {}

    def get(self, url, headers=None, params=None, timeout=None, **kwargs):
        self.calls.append({
            "url": url,
            "headers": dict(headers or {}),
            "params": dict(params or {}),
        })
        return self._handler(url, dict(headers or {}), dict(params or {}),
                             len(self.calls))

    @property
    def urls(self):
        return [c["url"] for c in self.calls]


class FakeInference:
    """Duck-typed ``InferenceResult``. ``resolve`` reads these attributes
    through ``getattr`` with defaults, so a real one is not needed."""

    def __init__(self, os_family="debian", language=None,
                 language_version=None, needs_glibc=True, variant=None,
                 confidence=0.9, warnings=None):
        self.os_family = os_family
        self.language = language
        self.language_version = language_version
        self.needs_glibc = needs_glibc
        self.variant = variant
        self.confidence = confidence
        self.warnings = list(warnings or [])


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Any escape to the real network is a test failure, not a 30 second
    DNS wait. Covers both the module-level ``requests.get`` used by
    ``_get_hub_token`` and any ``requests.Session`` a test forgets to
    replace."""

    def _boom(*args, **kwargs):
        raise AssertionError(
            "resolver test attempted a real network call: %r" % (args,))

    monkeypatch.setattr(resolver_mod.requests, "get", _boom)
    monkeypatch.setattr(requests.Session, "get", _boom)
    monkeypatch.setattr(requests.Session, "request", _boom)


@pytest.fixture
def offline():
    """Resolver over the shipped registry with Hub verification off, so
    ``resolve`` exercises selection logic only."""
    return ImageResolver(enable_hub_verification=False)


@pytest.fixture
def eol_upgrade_on(monkeypatch):
    """Turn on the ``--eol-upgrade`` gate for the duration of a test.

    ``upgrade_eol_version`` reads ``patcher._EOL_UPGRADE_ACTIVE``, which
    is False by default so an operator-pinned tag survives. A test that
    is about the upgrade *mechanism* rather than about the gate has to
    say so explicitly; leaving the gate at its default would make it
    pass for the wrong reason, since a resolver that lost its EOL table
    entirely also returns the version unchanged.
    """
    monkeypatch.setattr("src.patcher._EOL_UPGRADE_ACTIVE", True)


def eol_target(resolver, language, version):
    """The successor the registry under test names for an EOL release.

    Reading it back from the registry keeps the mechanism tests honest
    across a table refresh. Hardcoding the successor turned every one of
    them into a restatement of the current release calendar, so bumping
    python from 3.12 to 3.13 broke tests whose subject was the tag
    format or the libc branch, not the version.
    """
    return resolver.registry["languages"][language]["eol_versions"][version]


def install_session(resolver, handler, monkeypatch, token="tok"):
    """Give a resolver a scripted session and a token that costs nothing.

    Both token paths are stubbed because ``_list_all_tags`` picks one
    based on the registry host, and a test asserting on listing URLs
    should not also have to script the auth handshake.
    """
    session = RecordingSession(handler)
    monkeypatch.setattr(resolver, "_session", session)
    monkeypatch.setattr(resolver, "_get_hub_token", lambda image: token)
    monkeypatch.setattr(resolver, "_registry_token", lambda repo, cfg: token)
    return session


# ── registry routing ────────────────────────────────────────────────


class TestSplitRegistry:
    """A leading component is a host only if it looks like one. Getting
    this wrong in either direction is silently destructive: treat
    ``myorg/app`` as a host and we query https://myorg/v2, treat
    ``gcr.io/x`` as a Hub namespace and we query Docker Hub for a
    repository that does not exist there."""

    @pytest.mark.parametrize("ref,want", [
        ("python", ("", "python")),
        ("grafana/grafana", ("", "grafana/grafana")),
        ("myorg/team/app", ("", "myorg/team/app")),
        ("gcr.io/distroless/base", ("gcr.io", "distroless/base")),
        ("ghcr.io/owner/img", ("ghcr.io", "owner/img")),
        ("quay.io/prometheus/busybox", ("quay.io", "prometheus/busybox")),
        ("cgr.dev/chainguard/static", ("cgr.dev", "chainguard/static")),
        ("registry.k8s.io/pause", ("registry.k8s.io", "pause")),
        ("mcr.microsoft.com/dotnet/aspnet",
         ("mcr.microsoft.com", "dotnet/aspnet")),
        ("public.ecr.aws/lambda/python",
         ("public.ecr.aws", "lambda/python")),
        ("docker.io/library/python", ("docker.io", "library/python")),
        # a port makes it a host even with no dot
        ("localhost:5000/app", ("localhost:5000", "app")),
        ("localhost/app", ("localhost", "app")),
    ])
    def test_split(self, ref, want):
        assert ImageResolver._split_registry(ref) == want


class TestRegistryFor:

    def test_official_hub_image_gets_library_prefix(self, offline):
        api, repo, cfg = offline._registry_for("python")
        assert api == "https://registry-1.docker.io/v2"
        assert repo == "library/python"
        assert cfg is None

    def test_namespaced_hub_image_keeps_its_namespace(self, offline):
        """``library/`` must not be prepended to grafana/grafana, or the
        scope in the bearer token names a repository that does not
        exist and every page 401s."""
        api, repo, cfg = offline._registry_for("grafana/grafana")
        assert (api, repo, cfg) == (
            "https://registry-1.docker.io/v2", "grafana/grafana", None)

    @pytest.mark.parametrize("alias", [
        "docker.io", "index.docker.io", "registry-1.docker.io"])
    def test_hub_aliases_are_not_treated_as_foreign_hosts(self, offline, alias):
        api, repo, cfg = offline._registry_for(f"{alias}/library/python")
        assert api == "https://registry-1.docker.io/v2"
        assert repo == "library/python"
        assert cfg is None

    @pytest.mark.parametrize("ref,api,repo", [
        ("gcr.io/distroless/base", "https://gcr.io/v2", "distroless/base"),
        ("ghcr.io/owner/img", "https://ghcr.io/v2", "owner/img"),
        ("quay.io/prometheus/busybox", "https://quay.io/v2",
         "prometheus/busybox"),
        ("cgr.dev/chainguard/static", "https://cgr.dev/v2",
         "chainguard/static"),
        ("registry.k8s.io/pause", "https://registry.k8s.io/v2", "pause"),
        ("mcr.microsoft.com/dotnet/aspnet", "https://mcr.microsoft.com/v2",
         "dotnet/aspnet"),
        ("public.ecr.aws/lambda/python", "https://public.ecr.aws/v2",
         "lambda/python"),
    ])
    def test_known_hosts_route_to_themselves(self, offline, ref, api, repo):
        got_api, got_repo, cfg = offline._registry_for(ref)
        assert got_api == api
        assert got_repo == repo
        assert cfg is not None, "a non-Hub host must carry its own token cfg"
        assert "docker.io" not in got_api

    def test_no_library_prefix_outside_hub(self, offline):
        """``library/`` is a Docker Hub convention. Applying it to
        registry.k8s.io/pause produces a 404 on a repository that does
        exist."""
        _api, repo, _cfg = offline._registry_for("registry.k8s.io/pause")
        assert repo == "pause"

    def test_unknown_host_is_addressed_directly(self, offline):
        """Silently rewriting an unknown host to Docker Hub would look up
        somebody else's repository under the same name."""
        api, repo, cfg = offline._registry_for("registry.example.com/team/app")
        assert api == "https://registry.example.com/v2"
        assert repo == "team/app"
        assert cfg == {
            "api": "https://registry.example.com/v2",
            "token": "https://registry.example.com/token",
            "service": "registry.example.com",
        }

    def test_mcr_declares_no_token_endpoint(self, offline):
        """MCR serves anonymously. An empty token URL is the signal that
        ``_registry_token`` must not attempt a handshake."""
        _api, _repo, cfg = offline._registry_for("mcr.microsoft.com/x/y")
        assert cfg["token"] == ""

    def test_gcr_reference_never_reaches_docker_hub(self, offline, monkeypatch):
        """End to end: the URL actually requested for a distroless
        candidate must be on gcr.io."""
        session = install_session(
            offline,
            lambda url, h, p, n: FakeResponse(payload={"tags": ["nonroot"]}),
            monkeypatch)
        tags = offline._list_all_tags("gcr.io/distroless/base-debian12")
        assert tags == ["nonroot"]
        assert session.urls[0].startswith(
            "https://gcr.io/v2/distroless/base-debian12/tags/list")
        assert not any("docker.io" in u for u in session.urls)


# ── pagination and auth ─────────────────────────────────────────────


def _link(next_url):
    return {"Link": f'<{next_url}>; rel="next"'}


class TestListAllTagsPagination:

    def test_relative_next_link_is_followed(self, offline, monkeypatch):
        """A registry may return a path-only Link target. Resolving it
        against the api root is what turns page two into a real
        request instead of an invalid URL."""
        pages = {
            1: FakeResponse(
                payload={"tags": ["3.10", "3.11"]},
                headers=_link("/v2/library/python/tags/list?n=1000&last=3.11")),
            2: FakeResponse(payload={"tags": ["3.12", "3.13"]}),
        }
        session = install_session(
            offline, lambda url, h, p, n: pages[n], monkeypatch)
        assert offline._list_all_tags("python") == [
            "3.10", "3.11", "3.12", "3.13"]
        assert session.urls[1] == (
            "https://registry-1.docker.io/v2/library/python/"
            "tags/list?n=1000&last=3.11")

    def test_absolute_next_link_is_used_verbatim(self, offline, monkeypatch):
        nxt = "https://registry-1.docker.io/v2/library/python/tags/list?last=b"
        pages = {
            1: FakeResponse(payload={"tags": ["a"]}, headers=_link(nxt)),
            2: FakeResponse(payload={"tags": ["b"]}),
        }
        session = install_session(
            offline, lambda url, h, p, n: pages[n], monkeypatch)
        assert offline._list_all_tags("python") == ["a", "b"]
        assert session.urls[1] == nxt

    def test_lowercase_link_header_is_honoured(self, offline, monkeypatch):
        """HTTP header names are case insensitive and a plain dict is not,
        so a registry that emits ``link`` must still paginate."""
        pages = {
            1: FakeResponse(payload={"tags": ["a"]},
                            headers={"link": '</v2/x/tags/list?last=a>; rel="next"'}),
            2: FakeResponse(payload={"tags": ["b"]}),
        }
        install_session(offline, lambda url, h, p, n: pages[n], monkeypatch)
        assert offline._list_all_tags("python") == ["a", "b"]

    def test_link_without_rel_next_ends_the_walk(self, offline, monkeypatch):
        """``rel="prev"`` is not an invitation to keep going."""
        session = install_session(
            offline,
            lambda url, h, p, n: FakeResponse(
                payload={"tags": ["a"]},
                headers={"Link": '</v2/x?last=a>; rel="prev"'}),
            monkeypatch)
        assert offline._list_all_tags("python") == ["a"]
        assert len(session.calls) == 1

    def test_max_pages_cap_bounds_the_walk(self, offline, monkeypatch):
        """A registry that always advertises a next page (or a cycle in
        the Link chain) must not spin forever inside a build step."""
        session = install_session(
            offline,
            lambda url, h, p, n: FakeResponse(
                payload={"tags": [f"t{n}"]},
                headers=_link(f"/v2/library/python/tags/list?page={n + 1}")),
            monkeypatch)
        tags = offline._list_all_tags("python", max_pages=3)
        assert len(session.calls) == 3
        assert tags == ["t1", "t2", "t3"]

    def test_non_string_tags_are_dropped(self, offline, monkeypatch):
        """A malformed payload must not put a None into the tag list
        where ``tag in tags`` and the version sort both assume str."""
        install_session(
            offline,
            lambda url, h, p, n: FakeResponse(
                payload={"tags": ["ok", None, 3, {"a": 1}]}),
            monkeypatch)
        assert offline._list_all_tags("python") == ["ok"]

    def test_null_tags_field_is_tolerated(self, offline, monkeypatch):
        install_session(
            offline, lambda url, h, p, n: FakeResponse(payload={"tags": None}),
            monkeypatch)
        assert offline._list_all_tags("python") == []

    def test_first_page_request_asks_for_a_large_page(self, offline, monkeypatch):
        """n=1000 keeps the common repository to a single round trip."""
        session = install_session(
            offline, lambda url, h, p, n: FakeResponse(payload={"tags": []}),
            monkeypatch)
        offline._list_all_tags("python")
        assert session.urls[0].endswith("/library/python/tags/list?n=1000")

    def test_transport_error_returns_what_was_collected(self, offline,
                                                        monkeypatch):
        def handler(url, h, p, n):
            if n == 1:
                return FakeResponse(payload={"tags": ["a"]},
                                    headers=_link("/v2/x?last=a"))
            raise requests.ConnectionError("dns")

        install_session(offline, handler, monkeypatch)
        # Partial rather than an exception: get_available_tags negatively
        # caches an empty result, and verify_tag fails closed on a miss.
        assert offline._list_all_tags("python") == ["a"]

    def test_non_json_body_breaks_the_walk(self, offline, monkeypatch):
        install_session(
            offline,
            lambda url, h, p, n: FakeResponse(payload=None, json_ok=False),
            monkeypatch)
        assert offline._list_all_tags("python") == []


class TestListAllTagsReauth:
    """Hub bearer tokens live 300 seconds. A repository with thousands of
    tags outlives that, so the token expires mid-listing. Breaking on the
    401 returned a partial list, and because verify_tag fails closed the
    upgrade was rejected for a reason that had nothing to do with the
    tag."""

    def test_expired_token_mid_listing_does_not_truncate(self, offline,
                                                         monkeypatch):
        script = {
            1: FakeResponse(payload={"tags": ["a", "b"]},
                            headers=_link("/v2/library/python/tags/list?last=b")),
            2: FakeResponse(status_code=401),
            3: FakeResponse(payload={"tags": ["c", "d"]}),
        }
        minted = []

        def mint(image):
            minted.append(image)
            return f"tok{len(minted)}"

        session = RecordingSession(lambda url, h, p, n: script[n])
        monkeypatch.setattr(offline, "_session", session)
        monkeypatch.setattr(offline, "_get_hub_token", mint)

        assert offline._list_all_tags("python") == ["a", "b", "c", "d"]
        assert len(minted) == 2, "the 401 did not trigger a re-mint"
        # The retry must carry the NEW token; re-sending the dead one
        # would 401 again and this time break out with a short list.
        assert session.calls[2]["headers"]["Authorization"] == "Bearer tok2"
        # The retry re-requests the same page, it is not a skip.
        assert session.urls[1] == session.urls[2]

    def test_reauth_drops_the_cached_token(self, offline, monkeypatch):
        """The token cache keys on ``expires_in``. If the registry
        rejects a token before that deadline (clock skew, revocation),
        the retry must not read the same dead token back out of the
        cache."""
        offline._hub_tokens["repository:library/python:pull"] = (
            "stale", datetime.now().timestamp() + 9999)
        script = {1: FakeResponse(status_code=401),
                  2: FakeResponse(payload={"tags": ["a"]})}
        monkeypatch.setattr(offline, "_session",
                            RecordingSession(lambda url, h, p, n: script[n]))
        monkeypatch.setattr(offline, "_get_hub_token", lambda image: "fresh")
        assert offline._list_all_tags("python") == ["a"]
        assert "repository:library/python:pull" not in offline._hub_tokens

    def test_persistent_401_does_not_loop(self, offline, monkeypatch):
        """One retry, then give up. Without the one-shot budget the
        ``pages -= 1`` rewind makes this an unbounded loop against a
        repository that is simply forbidden."""
        session = install_session(
            offline, lambda url, h, p, n: FakeResponse(status_code=401),
            monkeypatch)
        assert offline._list_all_tags("python") == []
        assert len(session.calls) == 2

    def test_401_with_no_new_token_stops_immediately(self, offline,
                                                     monkeypatch):
        session = RecordingSession(
            lambda url, h, p, n: FakeResponse(status_code=401))
        monkeypatch.setattr(offline, "_session", session)
        monkeypatch.setattr(offline, "_get_hub_token", lambda image: None)
        assert offline._list_all_tags("python") == []
        assert len(session.calls) == 1

    def test_a_good_page_restores_the_retry_budget(self, offline, monkeypatch):
        """A listing long enough to outlive two tokens must still
        complete. The budget is per stretch of failures, not per call."""
        script = {
            1: FakeResponse(payload={"tags": ["a"]}, headers=_link("/v2/p2")),
            2: FakeResponse(status_code=401),
            3: FakeResponse(payload={"tags": ["b"]}, headers=_link("/v2/p3")),
            4: FakeResponse(status_code=401),
            5: FakeResponse(payload={"tags": ["c"]}),
        }
        install_session(offline, lambda url, h, p, n: script[n], monkeypatch)
        assert offline._list_all_tags("python") == ["a", "b", "c"]

    def test_no_token_means_no_authorization_header(self, offline, monkeypatch):
        """Anonymous registries reject a ``Bearer None`` header outright."""
        session = RecordingSession(
            lambda url, h, p, n: FakeResponse(payload={"tags": ["x"]}))
        monkeypatch.setattr(offline, "_session", session)
        monkeypatch.setattr(offline, "_get_hub_token", lambda image: None)
        offline._list_all_tags("python")
        assert "Authorization" not in session.calls[0]["headers"]

    def test_403_is_not_retried(self, offline, monkeypatch):
        """Only 401 means "your token is stale". Retrying a 403 doubles
        the traffic against a registry that already said no."""
        session = install_session(
            offline, lambda url, h, p, n: FakeResponse(status_code=403),
            monkeypatch)
        assert offline._list_all_tags("python") == []
        assert len(session.calls) == 1


class TestTokenAcquisition:

    def test_hub_scope_is_per_repository(self, offline, monkeypatch):
        """One Hub token authorises one ``repository:<repo>:pull`` scope.
        Reusing python's token for node 401s on every page."""
        seen = []

        def fake_get(url, params=None, timeout=None, **kw):
            seen.append((url, dict(params or {})))
            return FakeResponse(payload={"token": f"t{len(seen)}",
                                         "expires_in": 300})

        monkeypatch.setattr(resolver_mod.requests, "get", fake_get)
        assert offline._get_hub_token("python") == "t1"
        assert offline._get_hub_token("grafana/grafana") == "t2"
        assert seen[0][1]["scope"] == "repository:library/python:pull"
        assert seen[1][1]["scope"] == "repository:grafana/grafana:pull"

    def test_hub_token_is_cached_per_scope(self, offline, monkeypatch):
        calls = []

        def fake_get(url, params=None, timeout=None, **kw):
            calls.append(params)
            return FakeResponse(payload={"token": "t", "expires_in": 300})

        monkeypatch.setattr(resolver_mod.requests, "get", fake_get)
        offline._get_hub_token("python")
        offline._get_hub_token("python")
        assert len(calls) == 1

    def test_expired_hub_token_is_refetched(self, offline, monkeypatch):
        """``expires_in`` is honoured rather than a hardcoded 5 minutes,
        and the 5 second skew margin means a token expiring right now is
        already considered dead."""
        calls = []

        def fake_get(url, params=None, timeout=None, **kw):
            calls.append(params)
            return FakeResponse(payload={"token": "t", "expires_in": 1})

        monkeypatch.setattr(resolver_mod.requests, "get", fake_get)
        offline._get_hub_token("python")
        offline._get_hub_token("python")
        assert len(calls) == 2

    def test_hub_token_error_is_not_fatal(self, offline, monkeypatch):
        def boom(*a, **k):
            raise requests.ConnectionError("no route")

        monkeypatch.setattr(resolver_mod.requests, "get", boom)
        assert offline._get_hub_token("python") is None

    def test_registry_token_sends_scope_and_service(self, offline, monkeypatch):
        session = RecordingSession(
            lambda url, h, p, n: FakeResponse(
                payload={"token": "T", "expires_in": 600}))
        monkeypatch.setattr(offline, "_session", session)
        cfg = ImageResolver._REGISTRY_ENDPOINTS["gcr.io"]
        assert offline._registry_token("distroless/base", cfg) == "T"
        assert session.calls[0]["url"] == "https://gcr.io/v2/token"
        assert session.calls[0]["params"] == {
            "scope": "repository:distroless/base:pull", "service": "gcr.io"}

    def test_registry_token_accepts_access_token_alias(self, offline,
                                                       monkeypatch):
        """GHCR answers with ``access_token`` rather than ``token``."""
        monkeypatch.setattr(offline, "_session", RecordingSession(
            lambda url, h, p, n: FakeResponse(payload={"access_token": "A"})))
        cfg = ImageResolver._REGISTRY_ENDPOINTS["ghcr.io"]
        assert offline._registry_token("owner/img", cfg) == "A"

    def test_registry_token_is_cached_per_service_and_scope(self, offline,
                                                            monkeypatch):
        session = RecordingSession(
            lambda url, h, p, n: FakeResponse(
                payload={"token": "T", "expires_in": 600}))
        monkeypatch.setattr(offline, "_session", session)
        cfg = ImageResolver._REGISTRY_ENDPOINTS["quay.io"]
        offline._registry_token("a/b", cfg)
        offline._registry_token("a/b", cfg)
        offline._registry_token("c/d", cfg)
        assert len(session.calls) == 2, "token cache ignored the repo scope"

    def test_anonymous_registry_makes_no_token_request(self, offline,
                                                       monkeypatch):
        session = RecordingSession(lambda url, h, p, n: FakeResponse())
        monkeypatch.setattr(offline, "_session", session)
        cfg = ImageResolver._REGISTRY_ENDPOINTS["mcr.microsoft.com"]
        assert offline._registry_token("dotnet/aspnet", cfg) is None
        assert session.calls == []

    def test_registry_token_failure_is_not_fatal(self, offline, monkeypatch):
        def boom(*a, **k):
            raise requests.ConnectionError("refused")

        session = RecordingSession(boom)
        monkeypatch.setattr(offline, "_session", session)
        cfg = ImageResolver._REGISTRY_ENDPOINTS["cgr.dev"]
        assert offline._registry_token("chainguard/static", cfg) is None

    def test_non_hub_listing_uses_the_registry_token_path(self, offline,
                                                          monkeypatch):
        """A cgr.dev listing must not ask auth.docker.io for a token."""
        monkeypatch.setattr(offline, "_session", RecordingSession(
            lambda url, h, p, n: FakeResponse(payload={"tags": ["latest"]})))
        monkeypatch.setattr(offline, "_registry_token",
                            lambda repo, cfg: "REG")
        monkeypatch.setattr(
            offline, "_get_hub_token",
            lambda image: pytest.fail("Hub token used for a cgr.dev image"))
        assert offline._list_all_tags("cgr.dev/chainguard/static") == ["latest"]

    def test_invalidate_token_targets_the_right_cache_slot(self, offline):
        cfg = ImageResolver._REGISTRY_ENDPOINTS["quay.io"]
        offline._hub_tokens["regtoken::quay.io::repository:a/b:pull"] = (
            "x", 1e12)
        offline._hub_tokens["repository:library/python:pull"] = ("y", 1e12)
        offline._invalidate_token("a/b", cfg, "quay.io/a/b")
        assert "regtoken::quay.io::repository:a/b:pull" not in offline._hub_tokens
        assert "repository:library/python:pull" in offline._hub_tokens


# ── verify_tag ──────────────────────────────────────────────────────


class TestVerifyTag:

    def test_digest_reference_needs_no_listing(self, offline, monkeypatch):
        """A digest pins content directly. Listing tags for it is pure
        latency, and on a repository whose tags are not listable it would
        fail closed on a reference that is already immutable."""
        monkeypatch.setattr(
            offline, "get_available_tags",
            lambda *a, **k: pytest.fail("digest ref triggered a tag listing"))
        assert offline.verify_tag(
            "python@sha256:" + "a" * 64) is True

    def test_empty_reference_is_false(self, offline):
        assert offline.verify_tag("") is False

    def test_present_tag_verifies(self, offline, monkeypatch):
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.12-slim", "3.13-slim"])
        assert offline.verify_tag("python:3.13-slim") is True

    def test_absent_tag_is_rejected(self, offline, monkeypatch):
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.12-slim"])
        assert offline.verify_tag("python:3.99-slim") is False

    def test_untagged_reference_checks_latest(self, offline, monkeypatch):
        seen = {}

        def fake(name, limit=None):
            seen["name"] = name
            return ["latest"]

        monkeypatch.setattr(offline, "get_available_tags", fake)
        assert offline.verify_tag("alpine") is True
        assert seen["name"] == "alpine"

    def test_port_in_host_is_not_mistaken_for_a_tag(self, offline, monkeypatch):
        """``localhost:5000/app`` has a colon but no tag. Splitting on the
        last colon of the whole reference would ask for repository
        ``localhost`` at tag ``5000/app``."""
        seen = {}

        def fake(name, limit=None):
            seen["name"] = name
            return ["latest"]

        monkeypatch.setattr(offline, "get_available_tags", fake)
        assert offline.verify_tag("localhost:5000/app") is True
        assert seen["name"] == "localhost:5000/app"

    def test_unreachable_registry_fails_closed(self, offline, monkeypatch):
        """An empty listing means "could not confirm", and committing a
        FROM rewrite to an unconfirmed tag breaks the build."""
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: [])
        assert offline.verify_tag("python:3.13-slim") is False

    def test_fail_open_is_the_explicit_escape_hatch(self, offline, monkeypatch):
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: [])
        assert offline.verify_tag("python:3.13-slim", fail_open=True) is True

    def test_exception_fails_closed(self, offline, monkeypatch):
        def boom(name, limit=None):
            raise RuntimeError("registry exploded")

        monkeypatch.setattr(offline, "get_available_tags", boom)
        assert offline.verify_tag("python:3.13-slim") is False
        assert offline.verify_tag("python:3.13-slim", fail_open=True) is True

    def test_candidates_in_one_repo_share_a_single_listing(self, offline,
                                                           monkeypatch):
        """The regression this guards: four candidate tags of ``python``
        issued four paginated walks of a repository with thousands of
        tags. On a 100-Dockerfile corpus that tripped Hub's anonymous
        rate limit, and the resulting 429s made valid upgrades look
        invalid."""
        calls = []

        def fake_list(name, max_pages=20):
            calls.append(name)
            return ["3.11-slim", "3.12-slim", "3.13-slim", "3.13"]

        monkeypatch.setattr(offline, "_list_all_tags", fake_list)
        for tag in ("3.11-slim", "3.12-slim", "3.13-slim", "3.13"):
            assert offline.verify_tag(f"python:{tag}") is True
        assert calls == ["python"]

    def test_different_repositories_are_listed_separately(self, offline,
                                                          monkeypatch):
        """The flip side: a cache key that ignored the repository would
        answer node's question with python's tags."""
        calls = []

        def fake_list(name, max_pages=20):
            calls.append(name)
            return {"python": ["3.13-slim"], "node": ["22-alpine"]}[name]

        monkeypatch.setattr(offline, "_list_all_tags", fake_list)
        assert offline.verify_tag("python:3.13-slim") is True
        assert offline.verify_tag("node:22-alpine") is True
        assert offline.verify_tag("node:3.13-slim") is False
        assert calls == ["python", "node"]

    def test_result_is_memoised_per_reference(self, offline, monkeypatch):
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.13-slim"])
        assert offline.verify_tag("python:3.13-slim") is True
        # Once cached, the answer must survive the backend going away.
        monkeypatch.setattr(
            offline, "get_available_tags",
            lambda name, limit=None: pytest.fail("cache miss on a hot entry"))
        assert offline.verify_tag("python:3.13-slim") is True

    def test_non_hub_candidate_is_verified_against_its_own_registry(
            self, offline, monkeypatch):
        session = install_session(
            offline,
            lambda url, h, p, n: FakeResponse(payload={"tags": ["nonroot"]}),
            monkeypatch)
        assert offline.verify_tag(
            "gcr.io/distroless/base-debian12:nonroot") is True
        assert all(u.startswith("https://gcr.io/") for u in session.urls)


# ── get_available_tags and caching ──────────────────────────────────


class TestGetAvailableTags:

    def test_listing_is_cached(self, offline, monkeypatch):
        calls = []

        def fake_list(name, max_pages=20):
            calls.append(name)
            return ["a", "b"]

        monkeypatch.setattr(offline, "_list_all_tags", fake_list)
        assert offline.get_available_tags("python") == ["a", "b"]
        assert offline.get_available_tags("python") == ["a", "b"]
        assert len(calls) == 1

    def test_cached_list_is_copied_not_aliased(self, offline, monkeypatch):
        """A caller mutating the returned list must not corrupt the cache
        for every later candidate in the run."""
        monkeypatch.setattr(offline, "_list_all_tags",
                            lambda name, max_pages=20: ["a", "b"])
        first = offline.get_available_tags("python")
        first.append("injected")
        assert offline.get_available_tags("python") == ["a", "b"]

    def test_limit_is_applied_after_the_full_listing(self, offline, monkeypatch):
        """The cap must never be pushed down into the registry request.
        Truncating at the source drops the newest release, which sorts
        late, and verify_tag then rejects a perfectly good upgrade."""
        seen = []

        def fake_list(name, max_pages=20):
            seen.append(name)
            return ["3.10", "3.11", "3.12", "3.13"]

        monkeypatch.setattr(offline, "_list_all_tags", fake_list)
        assert offline.get_available_tags("python", limit=2) == ["3.10", "3.11"]
        # The whole listing is what got cached, so the late-sorting tag is
        # still reachable without a second round trip.
        assert offline.get_available_tags("python") == [
            "3.10", "3.11", "3.12", "3.13"]
        assert len(seen) == 1

    def test_empty_result_is_negatively_cached_for_a_short_window(
            self, offline, monkeypatch):
        """A repository that does not resolve must not be re-attempted for
        every candidate in a corpus run, but a transient outage must
        recover well inside the normal one hour TTL."""
        calls = []

        def fake_list(name, max_pages=20):
            calls.append(name)
            return []

        monkeypatch.setattr(offline, "_list_all_tags", fake_list)
        assert offline.get_available_tags("nope/nope") == []
        assert offline.get_available_tags("nope/nope") == []
        assert len(calls) == 1

        key = offline._cache_key("available_tags", "nope/nope")
        _value, ts = offline._cache[key]
        remaining = offline.cache_ttl - (datetime.now().timestamp() - ts)
        assert 100 < remaining <= 120, (
            "negative entries must expire in about two minutes, not the "
            "full positive TTL")

    def test_negative_cache_expires_and_the_repo_is_retried(self, offline,
                                                            monkeypatch):
        calls = []

        def fake_list(name, max_pages=20):
            calls.append(name)
            return [] if len(calls) == 1 else ["latest"]

        monkeypatch.setattr(offline, "_list_all_tags", fake_list)
        assert offline.get_available_tags("flaky/repo") == []
        key = offline._cache_key("available_tags", "flaky/repo")
        value, ts = offline._cache[key]
        offline._cache[key] = (value, ts - 200)   # push past the 120s window
        assert offline.get_available_tags("flaky/repo") == ["latest"]
        assert len(calls) == 2

    def test_listing_exception_yields_empty_and_is_not_cached(self, offline,
                                                              monkeypatch):
        calls = []

        def fake_list(name, max_pages=20):
            calls.append(name)
            raise RuntimeError("boom")

        monkeypatch.setattr(offline, "_list_all_tags", fake_list)
        assert offline.get_available_tags("python") == []
        assert offline.get_available_tags("python") == []
        assert len(calls) == 2, "an exception must not become a cached answer"


class TestCacheKeysAndTTL:

    def test_namespaces_do_not_collide(self, offline):
        """verify_tag and available_tags cache different value types under
        the same image name. A shared key would return a bool where a
        list is expected."""
        assert (offline._cache_key("verify_tag", "python")
                != offline._cache_key("available_tags", "python"))

    def test_key_is_deterministic_and_argument_sensitive(self, offline):
        assert (offline._cache_key("hub_api", "u")
                == offline._cache_key("hub_api", "u"))
        assert (offline._cache_key("hub_api", "u")
                != offline._cache_key("hub_api", "v"))

    def test_missing_key_is_invalid(self, offline):
        assert offline._is_cache_valid("nothing-here") is False

    def test_fresh_entry_is_valid(self, offline):
        offline._cache["k"] = ("v", datetime.now().timestamp())
        assert offline._is_cache_valid("k") is True

    def test_entry_past_the_ttl_is_invalid(self, offline):
        offline._cache["k"] = (
            "v", datetime.now().timestamp() - offline.cache_ttl - 1)
        assert offline._is_cache_valid("k") is False

    def test_ttl_boundary_uses_a_strict_comparison(self, offline):
        offline._cache["k"] = ("v", datetime.now().timestamp() - 10)
        offline.cache_ttl = 10
        assert offline._is_cache_valid("k") is False

    def test_zero_ttl_disables_the_cache(self, offline, monkeypatch):
        """An operator setting AUTOPATCH_RESOLVER_CACHE_TTL=0 expects
        every lookup to hit the registry, not a permanently warm cache."""
        offline.cache_ttl = 0
        calls = []
        monkeypatch.setattr(
            offline, "_list_all_tags",
            lambda name, max_pages=20: calls.append(name) or ["a"])
        offline.get_available_tags("python")
        offline.get_available_tags("python")
        assert len(calls) == 2


# ── registry loading ────────────────────────────────────────────────


class TestLoadRegistry:

    def test_shipped_registry_loads(self):
        r = ImageResolver(enable_hub_verification=False)
        assert r.registry, "the shipped image_registry.yaml did not load"
        for section in ("languages", "infrastructure", "os_bases",
                        "package_managers"):
            assert section in r.registry, f"missing section {section}"

    def test_malformed_yaml_raises_rather_than_disabling_the_resolver(
            self, tmp_path):
        """Treating a broken registry as empty silently degrades every
        rewrite in the run to the OS-family fallback, with no diagnostic
        beyond a log line nobody reads."""
        bad = tmp_path / "image_registry.yaml"
        bad.write_text("languages:\n  python:\n   - [unclosed\n",
                       encoding="utf-8")
        with pytest.raises(RuntimeError) as exc:
            ImageResolver(registry_path=str(bad),
                          enable_hub_verification=False)
        assert "malformed" in str(exc.value)

    def test_non_mapping_top_level_raises(self, tmp_path):
        """A YAML list parses cleanly but every ``registry.get`` on it
        raises AttributeError deep inside resolution."""
        bad = tmp_path / "image_registry.yaml"
        bad.write_text("- python\n- node\n", encoding="utf-8")
        with pytest.raises(RuntimeError) as exc:
            ImageResolver(registry_path=str(bad),
                          enable_hub_verification=False)
        assert "mapping" in str(exc.value)

    def test_missing_file_returns_empty_registry(self, tmp_path):
        r = ImageResolver(registry_path=str(tmp_path / "absent.yaml"),
                          enable_hub_verification=False)
        assert r.registry == {}

    def test_empty_file_is_an_empty_registry_not_a_crash(self, tmp_path):
        path = tmp_path / "image_registry.yaml"
        path.write_text("", encoding="utf-8")
        r = ImageResolver(registry_path=str(path),
                          enable_hub_verification=False)
        assert r.registry == {}

    def test_default_path_is_beside_the_module(self):
        r = ImageResolver(enable_hub_verification=False)
        assert Path(r.registry_path).resolve() == SHIPPED_REGISTRY.resolve()


class TestRegistryStaleness:

    @staticmethod
    def _bare_resolver(tmp_path, registry):
        r = ImageResolver(registry_path=str(tmp_path / "absent.yaml"),
                          enable_hub_verification=False)
        r.registry = registry
        return r

    def test_old_registry_warns(self, tmp_path, caplog):
        """Stale image metadata means AutoPatch recommends versions that
        are themselves EOL, which is worse than recommending nothing."""
        r = self._bare_resolver(tmp_path, {"last_updated": "2000-01"})
        with caplog.at_level(logging.WARNING, logger="docker_patch_tool"):
            r._check_registry_staleness()
        assert any("days old" in m for m in caplog.messages)

    def test_metadata_block_is_also_read(self, tmp_path, caplog):
        r = self._bare_resolver(
            tmp_path, {"metadata": {"last_updated": "2001-05-03"}})
        with caplog.at_level(logging.WARNING, logger="docker_patch_tool"):
            r._check_registry_staleness()
        assert any("days old" in m for m in caplog.messages)

    def test_recent_registry_is_silent(self, tmp_path, caplog):
        recent = (datetime.now() - timedelta(days=5)).date().isoformat()
        r = self._bare_resolver(tmp_path, {"last_updated": recent})
        with caplog.at_level(logging.WARNING, logger="docker_patch_tool"):
            r._check_registry_staleness()
        assert not any("days old" in m for m in caplog.messages)

    def test_missing_timestamp_warns(self, tmp_path, caplog):
        r = self._bare_resolver(tmp_path, {"languages": {}})
        with caplog.at_level(logging.WARNING, logger="docker_patch_tool"):
            r._check_registry_staleness()
        assert any("no last_updated" in m for m in caplog.messages)

    def test_unparseable_timestamp_warns_but_does_not_raise(self, tmp_path,
                                                            caplog):
        r = self._bare_resolver(tmp_path, {"last_updated": "last tuesday"})
        with caplog.at_level(logging.WARNING, logger="docker_patch_tool"):
            r._check_registry_staleness()
        assert any("Could not parse" in m for m in caplog.messages)

    def test_shipped_timestamp_is_parseable(self, caplog):
        """A YYYY-MM date is the shipped format; if the day-padding branch
        regresses, staleness detection stops working entirely and nobody
        notices because the failure is a debug-level shrug."""
        r = ImageResolver(enable_hub_verification=False)
        with caplog.at_level(logging.WARNING, logger="docker_patch_tool"):
            r._check_registry_staleness()
        assert not any("Could not parse" in m for m in caplog.messages)
        assert not any("no last_updated" in m for m in caplog.messages)


# ── resolution ──────────────────────────────────────────────────────


class TestResolveInfrastructure:

    def test_database_image_is_recognised(self, offline):
        image, conf, meta = offline.resolve(
            "postgres:12", FakeInference(os_family="debian"))
        assert image == "postgres:17-alpine"
        assert conf == 0.85
        assert meta["strategy_used"] == "infrastructure"
        assert meta["fallback_used"] is False

    def test_priority_breaks_a_substring_collision(self, offline):
        """``mongo`` is a substring of ``mongo-express``. Without the
        priority sort the answer depends on dict iteration order, and
        rewriting mongo-express to a mongo server image produces a
        container that starts and does nothing useful."""
        image, _c, meta = offline.resolve(
            "mongo-express:1.0", FakeInference())
        assert image == "mongo-express:latest"
        assert meta["strategy_used"] == "infrastructure"

    def test_registry_host_is_stripped_before_matching(self, offline):
        """A mirrored reference names the same software."""
        image, _c, meta = offline.resolve(
            "docker.io/library/nginx:1.20", FakeInference())
        assert image == "nginx:stable-alpine"
        assert meta["strategy_used"] == "infrastructure"

    def test_infrastructure_beats_language_detection(self, offline):
        """The php in a wordpress image is not the thing being shipped.
        Rewriting wordpress to php:8.3-cli deletes the application."""
        image, _c, meta = offline.resolve(
            "wordpress:5-php7.4-apache",
            FakeInference(language="php", language_version="7.4"))
        assert meta["strategy_used"] == "infrastructure"
        assert image == "wordpress:6-php8.3-apache"

    def test_top_level_entry_shape_is_supported(self, tmp_path):
        """The flattener accepts both a category of entries and a bare
        entry at the top level. Only the nested shape is exercised by the
        shipped file, so the other branch is untested in production."""
        path = tmp_path / "image_registry.yaml"
        path.write_text(
            "infrastructure:\n"
            "  widget:\n"
            "    patterns: ['widget']\n"
            "    target: 'widget:2'\n"
            "    priority: 50\n",
            encoding="utf-8")
        r = ImageResolver(registry_path=str(path),
                          enable_hub_verification=False)
        assert r._resolve_infrastructure("widget") == ("widget:2", 0.85)

    def test_trailing_colon_pattern_matches_the_bare_name(self, offline):
        """``_resolve_infrastructure`` is handed the image name with the
        tag already stripped, so the cloud_native ``registry`` entry,
        whose only pattern is ``registry:``, could never fire. It was
        dead configuration, and ``registry:2`` fell through to the
        OS-family fallback, which replaces the Docker distribution server
        with a bare debian base. The trailing colon is now read as an
        anchor rather than as a literal character."""
        entry = offline.registry["infrastructure"]["cloud_native"]["registry"]
        assert any(p.endswith(":") for p in entry["patterns"])
        image, conf, meta = offline.resolve(
            "registry:2", FakeInference(os_family="debian"))
        assert meta["strategy_used"] == "infrastructure"
        assert image == "registry:2"
        assert conf == 0.85

    def test_trailing_colon_pattern_stays_anchored_to_the_name(self, offline):
        """The colon was written to stop that entry matching every
        reference merely containing the word "registry". Deleting the
        colon and keeping the substring test would have fixed the miss
        above by rewriting unrelated images to the distribution server,
        so the anchoring has to survive the fix. A namespaced reference
        still names the same software."""
        assert offline._resolve_infrastructure("registryfoo") is None
        assert offline._resolve_infrastructure("my-registry") is None
        assert offline._resolve_infrastructure("myorg/registry") == (
            "registry:2", 0.85)


class TestResolveLanguage:

    def test_eol_version_is_upgraded_only_when_the_gate_is_open(self, offline,
                                                                monkeypatch):
        """Both halves of the ``--eol-upgrade`` contract in one place.
        The resolver used to upgrade unconditionally while the patcher
        honoured the toggle, so whether an operator's pin survived
        depended on which resolution strategy happened to win, which is
        not something the operator can predict or control."""
        inf = FakeInference(language="python", language_version="3.8")

        monkeypatch.setattr("src.patcher._EOL_UPGRADE_ACTIVE", False)
        image, conf, meta = offline.resolve("python:3.8", inf)
        assert image == "python:3.8-slim"
        assert conf == 0.7
        assert meta["strategy_used"] == "language"

        monkeypatch.setattr("src.patcher._EOL_UPGRADE_ACTIVE", True)
        want = eol_target(offline, "python", "3.8")
        image, conf, meta = offline.resolve("python:3.8", inf)
        assert image == f"python:{want}-slim"
        assert want != "3.8"
        assert conf == 0.7
        assert meta["strategy_used"] == "language"

    def test_musl_target_selects_the_alpine_format(self, offline,
                                                   eol_upgrade_on):
        want = eol_target(offline, "python", "3.8")
        image, _c, _m = offline.resolve(
            "python:3.8",
            FakeInference(language="python", language_version="3.8",
                          needs_glibc=False))
        assert image == f"python:{want}-alpine"

    def test_glibc_target_prefers_slim_over_the_full_runtime(self, offline,
                                                             eol_upgrade_on):
        """Both satisfy the glibc constraint, but a full Debian runtime
        ships roughly a hundred more OS packages than its -slim sibling,
        and each carries its own CVE rows. Picking the full image gave up
        a free reduction on every glibc target."""
        want = eol_target(offline, "node", "16")
        image, _c, _m = offline.resolve(
            "node:16", FakeInference(language="node", language_version="16"))
        assert image == f"node:{want}-slim"

    def test_php_variant_is_preserved(self, offline, eol_upgrade_on):
        """php-fpm behind nginx and php-apache are not interchangeable;
        rewriting one to the other breaks the request path."""
        want = eol_target(offline, "php", "7.4")
        image, _c, _m = offline.resolve(
            "php:7.4-fpm",
            FakeInference(language="php", language_version="7.4",
                          variant="fpm"))
        assert image == f"php:{want}-fpm"

    def test_php_apache_variant_is_preserved(self, offline, eol_upgrade_on):
        want = eol_target(offline, "php", "7.4")
        image, _c, _m = offline.resolve(
            "php:7.4-apache",
            FakeInference(language="php", language_version="7.4",
                          variant="apache"))
        assert image == f"php:{want}-apache"

    def test_java_builder_keeps_a_jdk(self, offline, eol_upgrade_on):
        """A jre has no javac. Rewriting a maven/gradle build stage to a
        jre-only image makes the build fail, not the image safer."""
        want = eol_target(offline, "openjdk", "8")
        image, _c, _m = offline.resolve(
            "openjdk:8-jdk",
            FakeInference(language="openjdk", language_version="8",
                          variant="jdk"))
        assert image == f"eclipse-temurin:{want}-jdk-jammy"

    def test_java_builder_on_musl_keeps_a_jdk(self, offline, eol_upgrade_on):
        want = eol_target(offline, "openjdk", "8")
        image, _c, _m = offline.resolve(
            "openjdk:8-jdk",
            FakeInference(language="openjdk", language_version="8",
                          variant="jdk", needs_glibc=False))
        assert image == f"eclipse-temurin:{want}-jdk-alpine"

    def test_java_runtime_gets_a_jre(self, offline, eol_upgrade_on):
        want = eol_target(offline, "openjdk", "11")
        image, _c, _m = offline.resolve(
            "openjdk:11-jre",
            FakeInference(language="openjdk", language_version="11"))
        assert image == f"eclipse-temurin:{want}-jre-jammy"

    def test_confidence_drops_when_the_version_came_from_the_tag(self, offline):
        """0.7 means the SBOM told us the version. 0.6 means we guessed it
        from the tag string, and the caller uses that gap to decide
        whether to trust the rewrite."""
        image, conf, meta = offline.resolve(
            "python:3.9", FakeInference(language="python",
                                        language_version=None))
        assert meta["strategy_used"] == "language"
        assert image == "python:3.9-slim"
        assert conf == 0.6

    def test_eol_upgrade_is_skipped_for_a_tag_derived_version(
            self, offline, eol_upgrade_on):
        """Pins a known bug, so the gate is deliberately open: with it
        shut the assertion would hold for the wrong reason.
        ``_resolve_language`` applies the EOL table only to the version
        handed in by inference. When the version has to be recovered
        from the tag instead, the upgrade never runs, so a python:3.7
        image with no SBOM version is rewritten to another EOL python
        even though the operator asked for upgrades."""
        assert "3.7" in offline.registry["languages"]["python"]["eol_versions"]
        image, _c, _m = offline.resolve(
            "python:3.7", FakeInference(language="python",
                                        language_version=None))
        assert image == "python:3.7-slim"

    def test_unknown_language_falls_through(self, offline):
        image, _c, meta = offline.resolve(
            "cobol:1", FakeInference(language="cobol", os_family="debian"))
        assert meta["strategy_used"] == "os_family"
        assert image == "debian:bookworm-slim"

    def test_versionless_reference_uses_the_registry_current_stable(self,
                                                                    offline):
        """The last-resort version read was ``default_version`` while the
        shipped registry spells that field ``current_stable``, so a bare
        ``rust`` reference ended up with no version at all and language
        resolution gave up. The reference then dropped to the OS-family
        default, which deletes the toolchain the image exists to
        provide."""
        rust = offline.registry["languages"]["rust"]
        assert "current_stable" in rust
        assert "default_version" not in rust
        image, conf, meta = offline.resolve(
            "rust", FakeInference(language="rust", os_family="debian"))
        assert meta["strategy_used"] == "language"
        assert image == f"rust:{rust['current_stable']}-slim"
        assert conf == 0.6


class TestResolveByImageName:

    def test_shipped_registry_reaches_this_path(self, offline,
                                                eol_upgrade_on):
        """``_resolve_by_image_name`` looked for ``image_name_patterns``
        in each language entry while the shipped registry spells that
        field ``patterns``, so nothing ever matched and step 3 of resolve
        was dead code. The tag-format lookup was wrong in the same way:
        it asked for ``glibc``, which the registry does not define
        either, so the glibc branch produced nothing even once a pattern
        matched."""
        for cfg in offline.registry["languages"].values():
            assert "image_name_patterns" not in cfg
        want = eol_target(offline, "python", "3.8")
        assert offline._resolve_by_image_name("python:3.8", False) == (
            f"python:{want}-alpine", 0.6)
        assert offline._resolve_by_image_name("python:3.8", True) == (
            f"python:{want}-slim", 0.6)

    def test_step_three_is_reachable_end_to_end(self, offline,
                                                eol_upgrade_on):
        """Newly live path. Inference that names no language used to skip
        from the infrastructure check straight to the OS family, so a
        python:3.8 image with an unrecognised runtime became a bare
        debian base and lost the interpreter. Step 3 now recovers the
        version from the tag and applies the EOL table to it."""
        want = eol_target(offline, "python", "3.8")
        image, conf, meta = offline.resolve(
            "python:3.8", FakeInference(language=None, os_family="debian"))
        assert meta["strategy_used"] == "image_name_pattern"
        assert meta["fallback_used"] is True
        assert image == f"python:{want}-slim"
        assert conf == 0.6

    def test_step_three_preserves_the_pin_when_the_gate_is_shut(self, offline):
        """Step 3 reaches the EOL table through the same gated helper as
        every other path. Left ungated it would silently move a pinned
        interpreter whenever inference failed to name the language,
        which is precisely the case the operator has least visibility
        into."""
        image, _c, meta = offline.resolve(
            "python:3.8", FakeInference(language=None, os_family="debian"))
        assert meta["strategy_used"] == "image_name_pattern"
        assert image == "python:3.8-slim"

    def test_step_three_honours_the_libc_constraint(self, offline,
                                                    eol_upgrade_on):
        """The same reference on a musl target has to land on alpine. A
        tag-format lookup that ignored ``needs_glibc`` would hand a glibc
        binary a musl base, which fails at exec time rather than build
        time."""
        want = eol_target(offline, "python", "3.8")
        image, _c, meta = offline.resolve(
            "python:3.8",
            FakeInference(language=None, os_family="debian",
                          needs_glibc=False))
        assert meta["strategy_used"] == "image_name_pattern"
        assert image == f"python:{want}-alpine"

    def test_legacy_pattern_key_is_still_accepted(self, tmp_path,
                                                  eol_upgrade_on):
        """``image_name_patterns`` and ``glibc`` are kept as aliases so an
        operator's custom registry written against the old spellings goes
        on resolving after the shipped one was corrected. The versions
        here are literals because the subject is the custom registry
        written inline below, not the shipped table."""
        path = tmp_path / "image_registry.yaml"
        path.write_text(
            "languages:\n"
            "  python:\n"
            "    image_name_patterns: ['python']\n"
            "    tag_formats:\n"
            "      alpine: 'python:{version}-alpine'\n"
            "      glibc: 'python:{version}-slim'\n"
            "    eol_versions:\n"
            "      '3.8': '3.12'\n",
            encoding="utf-8")
        r = ImageResolver(registry_path=str(path),
                          enable_hub_verification=False)
        assert r._resolve_by_image_name("python:3.8", True) == (
            "python:3.12-slim", 0.6)
        assert r._resolve_by_image_name("python:3.8", False) == (
            "python:3.12-alpine", 0.6)


class TestResolveByOsFamily:

    @pytest.mark.parametrize("family,want", [
        ("centos", "rockylinux:9"),
        ("rhel", "rockylinux:9"),
        ("alma", "almalinux:9"),
        ("fedora", "fedora:41"),
        ("ubuntu", "ubuntu:24.04"),
        ("debian", "debian:bookworm-slim"),
        ("amazon", "amazonlinux:2023"),
        ("oracle", "oraclelinux:9"),
    ])
    def test_family_mapping(self, offline, family, want):
        image, conf, meta = offline.resolve(
            f"{family}:7", FakeInference(os_family=family, language=None))
        assert image == want
        assert conf == 0.3
        assert meta["strategy_used"] == "os_family"
        assert meta["fallback_used"] is True

    def test_musl_target_prefers_the_musl_tag(self, offline):
        image, _c, _m = offline.resolve(
            "alpine:3.16",
            FakeInference(os_family="alpine", needs_glibc=False))
        assert image == "alpine:3.21"

    def test_glibc_need_never_yields_a_musl_only_base(self, offline):
        """The RHEL entries expose only a glibc tag. A picker that fell
        through to ``next(iter(values))`` on the wrong branch could hand a
        glibc binary a musl base, which fails at exec time, not build
        time."""
        picked, _c = offline._resolve_by_os_family("centos", True)
        assert picked == "rockylinux:9"

    def test_unknown_family_falls_back_to_debian(self, offline):
        image, _c, _m = offline.resolve(
            "weirdos:1", FakeInference(os_family="plan9", language=None))
        assert image == "debian:bookworm-slim"

    def test_legacy_bare_string_entry_is_accepted(self, tmp_path):
        """Older registries stored a plain tag instead of a libc map."""
        path = tmp_path / "image_registry.yaml"
        path.write_text("os_bases:\n  debian: 'debian:bookworm'\n",
                        encoding="utf-8")
        r = ImageResolver(registry_path=str(path),
                          enable_hub_verification=False)
        assert r._resolve_by_os_family("debian", True) == ("debian:bookworm", 0.3)

    def test_documentation_only_entry_never_becomes_an_image_name(self):
        """The immutable-OS entries in os_bases carry a ``note`` and no
        tag, and ``_pick`` used to end in ``next(iter(entry.values()))``,
        so the prose came back as though it were an image reference.
        Nothing downstream validates what the resolver returns, so the
        only thing standing between that and ``FROM Immutable OS - use
        AWS SSM for updates`` in a generated Dockerfile was
        patcher.IMMUTABLE_OS_FAMILIES short-circuiting earlier; any other
        caller of the resolver got the prose. ``_pick`` now reads the
        libc keys only and rejects a value that is not a plausible
        reference, so the entry yields the generic fallback."""
        r = ImageResolver(enable_hub_verification=False)
        entry = r.registry["os_bases"]["bottlerocket"]
        assert "note" in entry
        assert not {"glibc", "musl"} & set(entry)
        for needs_glibc in (True, False):
            picked, conf = r._resolve_by_os_family("bottlerocket", needs_glibc)
            assert picked == "debian:bookworm-slim"
            assert conf == 0.3

    def test_every_os_family_resolves_to_a_reference_shaped_string(self,
                                                                   offline):
        """A returned value goes into a FROM line unchecked, so no
        os_bases entry may produce something with a space in it whatever
        the libc constraint."""
        for family in offline.registry["os_bases"]:
            for needs_glibc in (True, False):
                picked, _c = offline._resolve_by_os_family(family, needs_glibc)
                assert picked and " " not in picked, (family, needs_glibc)

    def test_no_registry_uses_the_hardcoded_pair(self, tmp_path):
        r = ImageResolver(registry_path=str(tmp_path / "absent.yaml"),
                          enable_hub_verification=False)
        assert r._resolve_by_os_family("debian", True) == ("ubuntu:22.04", 0.3)
        assert r._resolve_by_os_family("alpine", False) == ("alpine:latest", 0.3)


class TestResolveMetadata:

    def test_inference_warnings_are_carried_through(self, offline):
        inf = FakeInference(os_family="debian", warnings=["low signal"])
        _i, _c, meta = offline.resolve("debian:11", inf)
        assert meta["warnings"] == ["low signal"]

    def test_warnings_list_is_copied_not_aliased(self, offline):
        """Appending resolver warnings to the caller's list would mutate
        the inference record that later stages also read."""
        inf = FakeInference(os_family="debian", warnings=["a"])
        _i, _c, meta = offline.resolve("debian:11", inf)
        meta["warnings"].append("b")
        assert inf.warnings == ["a"]

    def test_verification_is_skipped_when_disabled(self, offline, monkeypatch):
        monkeypatch.setattr(
            offline, "verify_tag",
            lambda *a, **k: pytest.fail("verification ran while disabled"))
        _i, _c, meta = offline.resolve("postgres:12", FakeInference())
        assert meta["verified"] is False

    def test_verification_result_is_reported(self, monkeypatch):
        r = ImageResolver(enable_hub_verification=True)
        monkeypatch.setattr(r, "verify_tag", lambda *a, **k: True)
        _i, _c, meta = r.resolve("postgres:12", FakeInference())
        assert meta["verified"] is True

    def test_unverifiable_language_tag_loses_confidence(self, monkeypatch,
                                                        eol_upgrade_on):
        """The caller gates on confidence. A tag we could not confirm must
        not be handed over at the same 0.7 as one we did."""
        r = ImageResolver(enable_hub_verification=True)
        monkeypatch.setattr(r, "verify_tag", lambda *a, **k: False)
        want = eol_target(r, "python", "3.8")
        image, conf, meta = r.resolve(
            "python:3.8", FakeInference(language="python",
                                        language_version="3.8"))
        assert image == f"python:{want}-slim"
        assert conf == 0.6
        assert meta["verified"] is False


# ── version helpers ─────────────────────────────────────────────────


class TestFindBestVersion:

    def test_highest_patch_on_the_same_major_wins(self, offline, monkeypatch):
        """Staying on the major branch is what makes the upgrade safe to
        apply without reading the application's code."""
        monkeypatch.setattr(
            offline, "get_available_tags",
            lambda name, limit=None: ["2.7", "3.9", "3.11-slim", "3.12",
                                      "3.10-alpine", "4.0"])
        assert offline.find_best_version("python", "3.8", "python") == "3.12"

    def test_non_numeric_tags_are_ignored(self, offline, monkeypatch):
        monkeypatch.setattr(
            offline, "get_available_tags",
            lambda name, limit=None: ["latest", "slim-bookworm", "alpine",
                                      "3.12"])
        assert offline.find_best_version("python", "3.8", "python") == "3.12"

    def test_patch_levels_sort_numerically_not_lexically(self, offline,
                                                         monkeypatch):
        """String ordering puts 3.9 above 3.10, which would recommend a
        downgrade."""
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.9.1", "3.9.10",
                                                      "3.9.2"])
        assert offline.find_best_version("python", "3.9", "python") == "3.9.10"

    def test_empty_listing_yields_none(self, offline, monkeypatch):
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: [])
        assert offline.find_best_version("python", "3.8", "python") is None

    def test_unparseable_current_version_yields_none(self, offline, monkeypatch):
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.12"])
        assert offline.find_best_version("python", "latest", "python") is None

    def test_no_matching_major_falls_back_to_the_registry(self, offline,
                                                          monkeypatch):
        """The fallback read ``default_version``, which the shipped
        registry does not define (it spells the field ``current_stable``),
        so a major branch that no longer exists upstream returned None.
        That is exactly the EOL case the tool is for, and the caller was
        left holding the version it started with."""
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.12", "3.13"])
        stable = offline.registry["languages"]["python"]["current_stable"]
        assert "default_version" not in offline.registry["languages"]["python"]
        assert offline.find_best_version("python", "2.7", "python") == stable

    def test_prerelease_patch_tag_is_skipped_not_fatal(self, offline,
                                                       monkeypatch):
        """Docker Hub publishes tags such as ``3.13.0rc1``. The
        major-version filter accepts them (int("3") succeeds) but the
        sort key called int("0rc1"), and the ValueError escaped
        find_best_version instead of being skipped the way the filter
        skips other unparseable tags. A single prerelease anywhere in a
        listing took down the whole resolution path."""
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.12", "3.13.0rc1"])
        assert offline.find_best_version("python", "3.12", "python") == "3.12"

    def test_prerelease_only_branch_yields_none(self, offline, monkeypatch):
        """Skipping the unparseable tags can empty the candidate list. A
        branch whose only tags are release candidates has nothing safe to
        recommend, and returning the rc would ship a prerelease."""
        monkeypatch.setattr(offline, "get_available_tags",
                            lambda name, limit=None: ["3.13.0rc1",
                                                      "3.13.0rc2"])
        assert offline.find_best_version("python", "3.13", "python") is None


class TestEolAndVersionExtraction:

    @pytest.mark.parametrize("lang,version,is_eol", [
        ("python", "2.7", True),
        ("python", "3.8", True),
        ("node", "16", True),
        ("openjdk", "8", True),
        ("php", "5.6", True),
        ("golang", "1.19", True),
        ("PYTHON", "3.8", True),         # language lookup is case folded
        ("cobol", "1", False),           # unknown language, unchanged
    ])
    def test_eol_upgrade(self, offline, eol_upgrade_on, lang, version,
                         is_eol):
        """Subject is the lookup, not the release calendar, so the
        expected successor is read back out of the registry. The
        ``!= version`` half is what stops that becoming vacuous: a
        registry row that mapped a dead release onto itself, or a lookup
        that silently returned its argument, would still be caught."""
        got = offline.upgrade_eol_version(lang, version)
        if is_eol:
            want = eol_target(offline, lang.lower(), version)
            assert got == want
            assert got != version
        else:
            assert got == version

    def test_gate_shut_preserves_an_operator_pin(self, offline):
        """Default state, and the reason this function reads the toggle
        at all. ``--eol-upgrade`` is documented as opt-in, but the
        resolver used to upgrade regardless, so a pinned tag survived
        only if the patcher path happened to be the one that resolved
        it."""
        assert offline.upgrade_eol_version("python", "3.8") == "3.8"
        assert offline.upgrade_eol_version("node", "16") == "16"

    def test_a_supported_release_is_left_alone(self, offline, eol_upgrade_on):
        """The table is a list of dead releases, not an instruction to
        jump to latest. A currently supported version must come back
        untouched even with the gate open, and no language may list its
        own current_stable as EOL, which would make the upgrade
        non-terminating."""
        for lang, cfg in offline.registry["languages"].items():
            stable = cfg["current_stable"]
            assert stable not in cfg.get("eol_versions", {}), lang
            assert offline.upgrade_eol_version(lang, stable) == stable

    def test_no_registry_leaves_the_version_alone(self, tmp_path,
                                                  eol_upgrade_on):
        """Gate deliberately open: with it shut this would pass even if
        the missing-registry guard were deleted."""
        r = ImageResolver(registry_path=str(tmp_path / "absent.yaml"),
                          enable_hub_verification=False)
        assert r.upgrade_eol_version("python", "2.7") == "2.7"

    @pytest.mark.parametrize("ref,lang,want", [
        ("python:3.8-slim", "python", "3.8"),
        ("python:3.11-alpine", "python", "3.11"),
        ("python:3.9-bookworm", "python", "3.9"),
        ("node:18-alpine", "node", "18"),
        ("node:18.20.4", "node", "18"),       # major only for node
        ("golang:1.21-bullseye", "golang", "1.21"),
        ("openjdk:11-jre-slim", "openjdk", "11"),
        ("php:7.4-fpm", "php", "7.4"),
        ("python:latest", "python", None),
        ("python", "python", None),
        ("myorg/python:bookworm", "python", None),
    ])
    def test_version_extraction(self, offline, ref, lang, want):
        assert offline._extract_version_from_tag(ref, lang) == want

    @pytest.mark.parametrize("version,lang,want", [
        ("18.20.4", "node", "18"),        # major_only
        ("3.11.9", "python", "3.11"),     # major_minor
        ("3", "python", "3"),             # nothing to trim
    ])
    def test_normalisation_follows_the_registry_style(self, offline, version,
                                                      lang, want):
        assert offline._normalize_version(version, lang) == want


class TestPackageMigration:

    def test_apt_to_apk_mapping(self, offline):
        mapping = offline.get_package_migration("debian", "alpine")
        assert mapping["build-essential"] == "build-base"
        assert mapping["libc6-dev"] == "musl-dev"

    def test_ubuntu_shares_the_apt_mapping(self, offline):
        assert (offline.get_package_migration("ubuntu", "alpine")
                == offline.get_package_migration("debian", "alpine"))

    def test_apt_to_dnf_mapping(self, offline):
        mapping = offline.get_package_migration("debian", "rocky")
        assert mapping["libssl-dev"] == "openssl-devel"

    def test_unmapped_direction_is_none_not_a_wrong_answer(self, offline):
        """There is no apk_to_apt table. Returning the apt_to_apk one
        reversed would rename packages to names that do not exist."""
        assert offline.get_package_migration("alpine", "debian") is None

    def test_unknown_os_is_none(self, offline):
        assert offline.get_package_migration("debian", "plan9") is None


# ── hub api helper ──────────────────────────────────────────────────


class TestHubApiGet:

    def test_response_is_cached(self, offline, monkeypatch):
        session = install_session(
            offline, lambda url, h, p, n: FakeResponse(payload={"ok": True}),
            monkeypatch)
        assert offline._hub_api_get("https://example/x") == {"ok": True}
        assert offline._hub_api_get("https://example/x") == {"ok": True}
        assert len(session.calls) == 1

    def test_http_error_returns_none(self, offline, monkeypatch):
        install_session(
            offline, lambda url, h, p, n: FakeResponse(status_code=500),
            monkeypatch)
        assert offline._hub_api_get("https://example/x") is None

    def test_bad_json_returns_none(self, offline, monkeypatch):
        install_session(
            offline,
            lambda url, h, p, n: FakeResponse(json_ok=False),
            monkeypatch)
        assert offline._hub_api_get("https://example/x") is None

    def test_failures_are_not_cached(self, offline, monkeypatch):
        """Caching a transient 500 would suppress the retry for an hour."""
        session = install_session(
            offline, lambda url, h, p, n: FakeResponse(status_code=503),
            monkeypatch)
        offline._hub_api_get("https://example/x")
        offline._hub_api_get("https://example/x")
        assert len(session.calls) == 2
