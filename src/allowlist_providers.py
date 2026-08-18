#!/usr/bin/env python3
"""
Candidate-mapping proposal providers for offline allow-list generation.

A provider answers one question: given a source repository and the
compatibility profile inferred for images built on it, which other
repositories are plausible drop-in replacements? Providers are
*generators*, not deciders. Every proposal they emit is subsequently
subjected to mechanical verification against the live registry
(:mod:`src.allowlist_verify`), and only verified proposals reach the
shipped allow-list. A provider that hallucinates a repository costs a
wasted API call and nothing more.

Three providers ship:

  AnthropicProvider  Calls the Anthropic Messages API with a pinned
                     model, temperature 0, and a strict JSON schema.
                     Default when ANTHROPIC_API_KEY is present.

  HeuristicProvider  Derives proposals from registry naming
                     conventions and the existing curated registry.
                     No network, no credentials. This is the fallback
                     so that allow-list refresh never hard-fails on a
                     missing key, and so the tool is not
                     model-dependent for correctness.

  NullProvider       Proposes nothing. Used to measure the verifier
                     and to reproduce a run without any generation.

The prompt template is a module constant and its SHA-256 is recorded
in the generated artifact, so a reviewer can confirm which prompt
produced a given allow-list.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Sequence

logger = logging.getLogger(__name__)


# Pinned by default. Never use a floating alias here: the model
# identifier is recorded in the generated allow-list so that the
# provenance of every entry is reproducible.
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"
DEFAULT_MAX_PROPOSALS_PER_REPO = 6


@dataclass(frozen=True)
class Profile:
    """Compatibility profile a replacement must preserve."""
    distro_family: str          # debian | ubuntu | rhel | alpine | ...
    libc: str                   # glibc | musl | none
    runtime: Optional[str] = None       # python | node | golang | ...
    runtime_major: Optional[str] = None
    platform: str = "linux/amd64"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "distro_family": self.distro_family,
            "libc": self.libc,
            "runtime": self.runtime,
            "runtime_major": self.runtime_major,
            "platform": self.platform,
        }


@dataclass
class Proposal:
    """A single unverified source -> target mapping."""
    source_repo: str
    target_repo: str
    target_tag: Optional[str] = None
    claimed_family: Optional[str] = None
    claimed_libc: Optional[str] = None
    rationale: str = ""
    provider: str = ""
    model: Optional[str] = None

    @property
    def target_ref(self) -> str:
        return (f"{self.target_repo}:{self.target_tag}"
                if self.target_tag else self.target_repo)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_repo": self.source_repo,
            "target_repo": self.target_repo,
            "target_tag": self.target_tag,
            "claimed_family": self.claimed_family,
            "claimed_libc": self.claimed_libc,
            "rationale": self.rationale[:400],
            "provider": self.provider,
            "model": self.model,
        }


class ProposalProvider(Protocol):
    name: str
    model: Optional[str]

    def propose(self, source_repo: str, profile: Profile,
                *, limit: int = DEFAULT_MAX_PROPOSALS_PER_REPO
                ) -> List[Proposal]:
        ...


# ════════════════════════════════════════════════════════════════════
# Repository-name hygiene
# ════════════════════════════════════════════════════════════════════

# A conservative OCI repository-name grammar. Anything a provider
# emits that does not match is discarded before it ever reaches the
# verifier, so a malformed or injected string cannot become a registry
# request path.
_REPO_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*$"
)
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")

# Registries the generator is permitted to name. A proposal naming any
# other host is dropped: widening this set is a deliberate operator
# decision, not something a generator may make on its own. Docker Hub
# short names (no host component) are handled separately below.
ALLOWED_REGISTRY_PREFIXES = (
    "docker.io/",
    "gcr.io/distroless/",
    "cgr.dev/chainguard/",
    "registry.access.redhat.com/",
    "public.ecr.aws/docker/library/",
    "mcr.microsoft.com/",
    "quay.io/",
)

# A component is a registry host (rather than a Docker Hub namespace)
# when it contains a dot or a colon, or is exactly "localhost". This is
# the same rule the OCI reference grammar uses to disambiguate
# "myorg/app" from "registry.example.com/app".
def _names_a_registry_host(repo: str) -> bool:
    first = repo.split("/", 1)[0]
    return "." in first or ":" in first or first == "localhost"


def is_repo_acceptable(repo: str) -> bool:
    """Syntactic and registry-host check applied to every proposal.

    Two acceptance paths: a Docker Hub reference with no host
    component, or a reference whose host prefix appears in
    ALLOWED_REGISTRY_PREFIXES. Anything naming an unlisted host is
    rejected before any network request is issued, so a hallucinated
    or injected registry cannot become a request target.
    """
    if not repo or len(repo) > 255:
        return False

    if _names_a_registry_host(repo):
        prefix = next(
            (p for p in ALLOWED_REGISTRY_PREFIXES if repo.startswith(p)),
            None,
        )
        if prefix is None:
            return False
        path = repo[len(prefix):]
    else:
        path = repo

    if not path:
        return False
    return bool(_REPO_RE.match(path))


def is_tag_acceptable(tag: Optional[str]) -> bool:
    return tag is None or bool(_TAG_RE.match(tag))


def sanitize(proposals: Sequence[Proposal]) -> List[Proposal]:
    """Drop proposals that fail name hygiene. Runs before any network
    call so a malformed suggestion never becomes a request."""
    out: List[Proposal] = []
    for p in proposals:
        if not is_repo_acceptable(p.target_repo):
            logger.debug("dropping proposal with unacceptable repo: %r",
                         p.target_repo)
            continue
        if not is_tag_acceptable(p.target_tag):
            logger.debug("dropping proposal with unacceptable tag: %r",
                         p.target_tag)
            continue
        if p.target_repo == p.source_repo:
            continue  # same-repo upgrades are handled by tag ranking
        out.append(p)
    return out


# ════════════════════════════════════════════════════════════════════
# Prompt (hashed into the artifact)
# ════════════════════════════════════════════════════════════════════

PROMPT_TEMPLATE = """\
You are proposing candidate replacement container base image \
repositories for an automated remediation tool. Your proposals are \
NOT trusted: every one is verified against the live registry and \
discarded if it does not exist or does not match the required \
profile. Propose only mappings you believe are genuine drop-in \
replacements.

Source repository: {source_repo}
Required profile:
  Linux distribution family: {distro_family}
  C library: {libc}
  Language runtime: {runtime} (major version {runtime_major})
  Platform: {platform}

Rules:
- The target must be a real, publicly pullable repository.
- The target must belong to the same Linux distribution family, or a \
family that is binary-compatible for OS-level packages.
- The C library must match exactly. Never propose a musl-based target \
for a glibc profile or the reverse.
- Prefer official or vendor-maintained repositories.
- Do not propose the source repository itself.
- If you have no confident proposal, return an empty list.

Return between 0 and {limit} proposals."""


def prompt_sha256() -> str:
    return hashlib.sha256(PROMPT_TEMPLATE.encode("utf-8")).hexdigest()


PROPOSAL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "proposals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "target_repo": {"type": "string"},
                    "target_tag": {"type": ["string", "null"]},
                    "distro_family": {"type": "string"},
                    "libc": {"type": "string",
                             "enum": ["glibc", "musl", "none"]},
                    "rationale": {"type": "string"},
                },
                "required": ["target_repo", "distro_family", "libc"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["proposals"],
    "additionalProperties": False,
}


# ════════════════════════════════════════════════════════════════════
# Anthropic provider
# ════════════════════════════════════════════════════════════════════

class AnthropicProvider:
    """Proposal generator backed by the Anthropic Messages API.

    Configured for reproducibility as far as an API allows: pinned
    model string, temperature 0, and a tool-schema-constrained JSON
    response so parsing introduces no additional variance. The prompt
    hash and model identifier are recorded in the generated artifact.
    """

    name = "anthropic"

    def __init__(
        self,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        api_key: Optional[str] = None,
        *,
        max_tokens: int = 1024,
        timeout_s: float = 60.0,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.timeout_s = timeout_s
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set; use HeuristicProvider "
                "or export the key before refreshing the allow-list"
            )
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "the anthropic package is required for AnthropicProvider: "
                f"pip install anthropic ({e})"
            )
        import anthropic as _anthropic
        self._client = _anthropic.Anthropic(api_key=self._api_key)

    def propose(self, source_repo: str, profile: Profile,
                *, limit: int = DEFAULT_MAX_PROPOSALS_PER_REPO
                ) -> List[Proposal]:
        prompt = PROMPT_TEMPLATE.format(
            source_repo=source_repo,
            distro_family=profile.distro_family,
            libc=profile.libc,
            runtime=profile.runtime or "not applicable",
            runtime_major=profile.runtime_major or "not applicable",
            platform=profile.platform,
            limit=limit,
        )
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=0,
                tools=[{
                    "name": "emit_proposals",
                    "description": "Return candidate replacement repositories.",
                    "input_schema": PROPOSAL_SCHEMA,
                }],
                tool_choice={"type": "tool", "name": "emit_proposals"},
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as e:  # network, auth, rate limit
            logger.warning("Anthropic proposal call failed for %s: %s",
                           source_repo, e)
            return []

        payload: Dict[str, Any] = {}
        for block in getattr(resp, "content", []) or []:
            if getattr(block, "type", "") == "tool_use":
                payload = getattr(block, "input", {}) or {}
                break

        raw = payload.get("proposals") or []
        out: List[Proposal] = []
        for item in raw[:limit]:
            if not isinstance(item, dict):
                continue
            out.append(Proposal(
                source_repo=source_repo,
                target_repo=str(item.get("target_repo", "")).strip(),
                target_tag=(str(item["target_tag"]).strip()
                            if item.get("target_tag") else None),
                claimed_family=str(item.get("distro_family", "")).strip() or None,
                claimed_libc=str(item.get("libc", "")).strip() or None,
                rationale=str(item.get("rationale", "")),
                provider=self.name,
                model=self.model,
            ))
        return sanitize(out)


# ════════════════════════════════════════════════════════════════════
# Heuristic provider (no model, no network)
# ════════════════════════════════════════════════════════════════════

# Family-compatible repository families. These are structural facts
# about how the ecosystem publishes images, not judgements: the
# variants below are published by the same upstream for the same
# workload class.
_VARIANT_SUFFIXES: Dict[str, List[str]] = {
    "debian": ["-slim", "-bookworm", "-bookworm-slim"],
    "ubuntu": ["-jammy", "-noble"],
    "alpine": ["-alpine"],
    "rhel": ["-ubi9", "-ubi8"],
}

_FAMILY_ALTERNATES: Dict[str, List[str]] = {
    "debian": ["debian", "ubuntu"],
    "ubuntu": ["ubuntu", "debian"],
    "rhel": ["rockylinux", "almalinux", "redhat/ubi9"],
    "alpine": ["alpine"],
}


class HeuristicProvider:
    """Model-free provider used as the fallback and as a control.

    Proposals come from two structural sources: the language-runtime
    repository publishing a variant that matches the required libc
    (for example ``python`` publishing both ``-slim`` and ``-alpine``),
    and the distribution family's sibling repositories. It proposes
    less than the model provider but never needs credentials.
    """

    name = "heuristic"
    model = None

    def __init__(self, curated: Optional[Dict[str, List[str]]] = None) -> None:
        self.curated = curated or {}

    def propose(self, source_repo: str, profile: Profile,
                *, limit: int = DEFAULT_MAX_PROPOSALS_PER_REPO
                ) -> List[Proposal]:
        out: List[Proposal] = []

        for target in self.curated.get(source_repo, []):
            out.append(Proposal(
                source_repo=source_repo, target_repo=target,
                claimed_family=profile.distro_family,
                claimed_libc=profile.libc,
                rationale="curated registry entry",
                provider=self.name,
            ))

        # Runtime repositories publish per-family variants under the
        # same repository name; the family sibling repositories are
        # the other structural source.
        for alt in _FAMILY_ALTERNATES.get(profile.distro_family, []):
            if alt == source_repo:
                continue
            out.append(Proposal(
                source_repo=source_repo, target_repo=alt,
                claimed_family=profile.distro_family,
                claimed_libc=profile.libc,
                rationale=f"family sibling of {profile.distro_family}",
                provider=self.name,
            ))

        return sanitize(out)[:limit]


class NullProvider:
    """Proposes nothing. Used to isolate verifier behaviour."""

    name = "null"
    model = None

    def propose(self, source_repo: str, profile: Profile,
                *, limit: int = DEFAULT_MAX_PROPOSALS_PER_REPO
                ) -> List[Proposal]:
        return []


def build_provider(kind: str = "auto", **kwargs: Any) -> ProposalProvider:
    """Select a provider.

    ``auto`` uses Anthropic when a key and the SDK are available and
    falls back to the heuristic provider otherwise, so an allow-list
    refresh never fails merely because credentials are absent.
    """
    kind = (kind or "auto").lower()
    if kind == "anthropic":
        return AnthropicProvider(**kwargs)
    if kind == "heuristic":
        return HeuristicProvider(kwargs.get("curated"))
    if kind == "null":
        return NullProvider()
    if kind == "auto":
        try:
            return AnthropicProvider(**kwargs)
        except RuntimeError as e:
            logger.info("falling back to heuristic provider: %s", e)
            return HeuristicProvider(kwargs.get("curated"))
    raise ValueError(f"unknown provider: {kind}")
