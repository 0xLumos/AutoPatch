#!/usr/bin/env python3
"""
Read-side of the generated allow-list.

The patching path consults this module and nothing else: it reads a
committed YAML artifact and never contacts a model provider or the
proposal machinery. Precedence is:

  1. src/allowlist_generated.yaml  (verified, machine-generated)
  2. src/image_registry.yaml       (curated, hand-maintained)

If the generated artifact is missing, malformed, or fails its own
content hash, the loader logs the condition and falls back to the
curated registry, so a bad refresh can never break remediation. This
is the last-known-good policy: the shipped file is always valid, and a
failed refresh simply leaves the previous one in force.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_GENERATED_PATH = Path(__file__).parent / "allowlist_generated.yaml"
SUPPORTED_SCHEMA_VERSIONS = {"2.0"}


@dataclass(frozen=True)
class AllowedTarget:
    source_repo: str
    target_repo: str
    target_tag: Optional[str]
    family: Optional[str]
    libc: Optional[str]
    verified_digest: Optional[str]
    priority: int = 50

    @property
    def target_ref(self) -> str:
        return (f"{self.target_repo}:{self.target_tag}"
                if self.target_tag else self.target_repo)


@dataclass
class AllowList:
    targets: Dict[str, List[AllowedTarget]] = field(default_factory=dict)
    source: str = "none"          # generated | curated | none
    generated_at: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    content_sha256: Optional[str] = None
    verification: Dict[str, Any] = field(default_factory=dict)

    def alternates_for(
        self,
        repo: str,
        *,
        family: Optional[str] = None,
        libc: Optional[str] = None,
    ) -> List[AllowedTarget]:
        """Approved alternates for ``repo``, optionally constrained to
        a family and libc. Ordering is deterministic: priority
        descending, then target repository, then tag."""
        out = list(self.targets.get(repo, []))
        if family:
            out = [t for t in out if t.family in (None, family)]
        if libc:
            out = [t for t in out if t.libc in (None, libc)]
        out.sort(key=lambda t: (-t.priority, t.target_repo,
                                t.target_tag or ""))
        return out

    def __len__(self) -> int:
        return sum(len(v) for v in self.targets.values())


def _content_hash(mappings: Dict[str, Any]) -> str:
    blob = json.dumps(mappings, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_generated(path: Path) -> Optional[AllowList]:
    if not path.is_file():
        logger.debug("generated allow-list not present at %s", path)
        return None
    try:
        import yaml
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        logger.warning("generated allow-list unreadable (%s); "
                       "falling back to curated registry", e)
        return None

    version = str(doc.get("schema_version", ""))
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        logger.warning("generated allow-list has unsupported schema "
                       "version %r; falling back to curated registry",
                       version)
        return None

    mappings = doc.get("mappings") or {}
    if not isinstance(mappings, dict):
        logger.warning("generated allow-list mappings malformed; "
                       "falling back to curated registry")
        return None

    declared = doc.get("content_sha256")
    actual = _content_hash(mappings)
    if declared and declared != actual:
        logger.warning(
            "generated allow-list content hash mismatch "
            "(declared %s, actual %s); refusing to use it and falling "
            "back to curated registry", str(declared)[:16], actual[:16],
        )
        return None

    targets: Dict[str, List[AllowedTarget]] = {}
    for source, entries in mappings.items():
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            targets.setdefault(str(source), []).append(AllowedTarget(
                source_repo=str(source),
                target_repo=str(e.get("target_repo", "")),
                target_tag=(str(e["target_tag"])
                            if e.get("target_tag") else None),
                family=e.get("family"),
                libc=e.get("libc"),
                verified_digest=e.get("verified_digest"),
                priority=int(e.get("priority", 50)),
            ))

    gen = doc.get("generator") or {}
    return AllowList(
        targets=targets,
        source="generated",
        generated_at=doc.get("generated_at"),
        provider=gen.get("provider"),
        model=gen.get("model"),
        content_sha256=actual,
        verification=doc.get("verification") or {},
    )


# Wolfi/Chainguard equivalents by source runtime. These make the
# cascade's alt_base_wolfi candidates VERIFIED cross-repo migrations
# instead of permitted-but-unverified ones. They live here, not in
# image_registry.yaml, so the resolver's primary ranking never sees
# them: they are reachable only when something (the cascade) proposes
# them, and every proposal still passes build + scan + acceptance.
# Priority 30 keeps them below every curated mapping (50), so the
# allow-list gate never substitutes them over a curated target.
_WOLFI_EQUIVALENTS: Dict[str, Tuple[str, str]] = {
    "python": ("cgr.dev/chainguard/python", "latest"),
    "node": ("cgr.dev/chainguard/node", "latest"),
    "ruby": ("cgr.dev/chainguard/ruby", "latest"),
    "golang": ("cgr.dev/chainguard/go", "latest"),
    "php": ("cgr.dev/chainguard/php", "latest"),
    "openjdk": ("cgr.dev/chainguard/jdk", "latest"),
    "eclipse-temurin": ("cgr.dev/chainguard/jdk", "latest"),
    "debian": ("cgr.dev/chainguard/wolfi-base", "latest"),
    "ubuntu": ("cgr.dev/chainguard/wolfi-base", "latest"),
    "alpine": ("cgr.dev/chainguard/wolfi-base", "latest"),
}


def _append_wolfi_equivalents(
        targets: Dict[str, List[AllowedTarget]]) -> None:
    for source, (repo, tag) in _WOLFI_EQUIVALENTS.items():
        targets.setdefault(source, []).append(AllowedTarget(
            source_repo=source,
            target_repo=repo,
            target_tag=tag,
            family="wolfi",
            libc="glibc",
            verified_digest=None,
            priority=30,
        ))


def _load_curated() -> AllowList:
    """Fallback: derive alternates from the curated registry so the
    tool still functions with no generated artifact at all."""
    targets: Dict[str, List[AllowedTarget]] = {}
    try:
        from .resolver import ImageResolver
        registry = ImageResolver().registry or {}
    except Exception as e:
        logger.debug("curated registry unavailable: %s", e)
        return AllowList(source="none")

    infra = registry.get("infrastructure") or {}
    for _category, entries in infra.items():
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            spec = spec or {}
            target = spec.get("target")
            if not target:
                continue
            repo, _, tag = str(target).partition(":")
            for pattern in (spec.get("patterns") or [name]):
                targets.setdefault(str(pattern), []).append(AllowedTarget(
                    source_repo=str(pattern),
                    target_repo=repo,
                    target_tag=tag or None,
                    family=None,
                    libc=None,
                    verified_digest=None,
                    priority=int(spec.get("priority", 50)),
                ))
    _append_wolfi_equivalents(targets)
    return AllowList(targets=targets, source="curated")


_cached: Optional[AllowList] = None


def load_allowlist(*, force_reload: bool = False,
                   generated_path: Optional[Path] = None) -> AllowList:
    """Load the allow-list, preferring the verified generated artifact
    and falling back to the curated registry. Cached per process."""
    global _cached
    if _cached is not None and not force_reload:
        return _cached

    # AUTOPATCH_ALLOWLIST_SOURCE=curated skips the generated artifact.
    # The generated allow-list is AI-proposed (then mechanically
    # verified), so an experiment arm that claims to involve no model
    # anywhere must be able to pin the curated table; without this
    # switch the "no AI" arm would silently consume AI output through
    # the allow-list and the comparison would be contaminated.
    _source = os.environ.get("AUTOPATCH_ALLOWLIST_SOURCE", "").strip().lower()
    if _source == "curated":
        allow = _load_curated()
        logger.info(
            "AUTOPATCH_ALLOWLIST_SOURCE=curated: using the curated "
            "allow-list (%d mappings); the generated artifact is ignored",
            len(allow),
        )
        _cached = allow
        return allow

    path = generated_path or _GENERATED_PATH
    allow = _load_generated(path)
    if allow is not None:
        logger.info(
            "Using generated allow-list (%d mappings, provider=%s, "
            "model=%s, generated_at=%s)",
            len(allow), allow.provider, allow.model, allow.generated_at,
        )
    else:
        allow = _load_curated()
        logger.info("Using curated allow-list (%d mappings)", len(allow))

    _cached = allow
    return allow
