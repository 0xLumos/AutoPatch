#!/usr/bin/env python3
"""
Regenerate the verified cross-repository allow-list.

This runs offline, on a schedule, never during a patch. It proposes
candidate repository mappings with a provider (Anthropic by default),
subjects every proposal to mechanical verification against the live
registry, and writes only verified mappings into a versioned artifact
carrying its own content hash and the full verification counters.

The patching path reads the committed artifact and never contacts a
model provider. If this job fails for any reason, the previously
committed artifact remains in force, so a provider outage cannot
affect remediation.

Usage
-----
    export ANTHROPIC_API_KEY=...
    python tools/refresh_allowlist.py \
        --seed data/seed_repositories.yaml \
        --out src/allowlist_generated.yaml

    # no credentials: heuristic proposals only, still fully verified
    python tools/refresh_allowlist.py --provider heuristic

    # measure the verifier alone (no proposals at all)
    python tools/refresh_allowlist.py --provider null
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.allowlist_providers import (  # noqa: E402
    DEFAULT_ANTHROPIC_MODEL,
    Profile,
    Proposal,
    build_provider,
    prompt_sha256,
)
from src.allowlist_verify import verify_all  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
)
logger = logging.getLogger("refresh_allowlist")

SCHEMA_VERSION = "2.0"


def _load_seed(path: Path) -> Dict[str, Profile]:
    """Seed file maps a source repository to the profile any
    replacement must preserve."""
    import yaml
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    repos = data.get("repositories") or {}
    out: Dict[str, Profile] = {}
    for repo, spec in repos.items():
        spec = spec or {}
        out[str(repo)] = Profile(
            distro_family=str(spec.get("distro_family", "debian")),
            libc=str(spec.get("libc", "glibc")),
            runtime=spec.get("runtime"),
            runtime_major=(str(spec["runtime_major"])
                           if spec.get("runtime_major") is not None else None),
            platform=str(spec.get("platform", "linux/amd64")),
        )
    return out


def _content_hash(mappings: Dict[str, Any]) -> str:
    blob = json.dumps(mappings, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _write_artifact(
    out_path: Path,
    mappings: Dict[str, List[Dict[str, Any]]],
    *,
    provider_name: str,
    model: Optional[str],
    stats: Dict[str, Any],
    smoke_enabled: bool,
) -> None:
    import yaml

    doc: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": {
            "provider": provider_name,
            "model": model,
            "prompt_sha256": prompt_sha256(),
            "temperature": 0,
            "smoke_build_enabled": smoke_enabled,
        },
        "verification": stats,
        "content_sha256": _content_hash(mappings),
        "mappings": mappings,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(
            "# GENERATED FILE. Do not edit by hand.\n"
            "# Produced by tools/refresh_allowlist.py. Every mapping in\n"
            "# this file was verified against the live registry: the\n"
            "# repository exists, publishes the required platform, and\n"
            "# the pulled image's distribution and libc families were\n"
            "# confirmed by filesystem fingerprinting rather than by\n"
            "# any provider's claim. The patching path reads this file\n"
            "# and never contacts a model provider.\n"
        )
        yaml.safe_dump(doc, f, sort_keys=False, width=100)
    tmp.replace(out_path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="data/seed_repositories.yaml")
    ap.add_argument("--out", default="src/allowlist_generated.yaml")
    ap.add_argument("--provider", default="auto",
                    choices=["auto", "anthropic", "heuristic", "null"])
    ap.add_argument("--model", default=DEFAULT_ANTHROPIC_MODEL)
    ap.add_argument("--limit-per-repo", type=int, default=6)
    ap.add_argument("--max-repos", type=int, default=None,
                    help="process at most N source repositories")
    ap.add_argument("--no-smoke", action="store_true",
                    help="skip the smoke-build stage (faster, weaker)")
    ap.add_argument("--report", default=None,
                    help="write the per-proposal verification log here")
    args = ap.parse_args()

    seed_path = Path(args.seed)
    if not seed_path.is_file():
        logger.error("seed file not found: %s", seed_path)
        return 1
    profiles = _load_seed(seed_path)
    if args.max_repos:
        profiles = dict(list(profiles.items())[: args.max_repos])
    logger.info("Loaded %d source repositories from %s",
                len(profiles), seed_path)

    try:
        provider = build_provider(args.provider, model=args.model)
    except Exception as e:
        logger.error("could not construct provider: %s", e)
        return 1
    logger.info("Provider: %s (model=%s)", provider.name,
                getattr(provider, "model", None))

    # ── Proposal phase ──────────────────────────────────────────────
    proposals: List[Proposal] = []
    for repo, profile in profiles.items():
        got = provider.propose(repo, profile, limit=args.limit_per_repo)
        logger.info("  %-40s %d proposals", repo, len(got))
        proposals.extend(got)
    logger.info("Total proposals: %d", len(proposals))

    # ── Verification phase ──────────────────────────────────────────
    results, stats = verify_all(
        proposals, profiles, run_smoke=not args.no_smoke,
    )

    # ── Artifact ────────────────────────────────────────────────────
    mappings: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        if not r.accepted:
            continue
        entry = {
            "target": f"{r.proposal.target_repo}:{r.resolved_tag}",
            "target_repo": r.proposal.target_repo,
            "target_tag": r.resolved_tag,
            "family": r.observed_family,
            "libc": r.observed_libc,
            "verified_digest": r.resolved_digest,
            "priority": 50,
        }
        mappings.setdefault(r.proposal.source_repo, []).append(entry)

    # Deterministic ordering so regenerating with the same verified
    # set produces a byte-identical file.
    for src in mappings:
        mappings[src].sort(key=lambda e: (e["target_repo"], e["target_tag"] or ""))
    mappings = {k: mappings[k] for k in sorted(mappings)}

    out_path = Path(args.out)
    _write_artifact(
        out_path, mappings,
        provider_name=provider.name,
        model=getattr(provider, "model", None),
        stats=stats.as_dict(),
        smoke_enabled=not args.no_smoke,
    )

    if args.report:
        rp = Path(args.report)
        rp.parent.mkdir(parents=True, exist_ok=True)
        with open(rp, "w", encoding="utf-8") as f:
            json.dump([r.as_dict() for r in results], f,
                      indent=2, sort_keys=True)
        logger.info("Wrote verification log to %s", rp)

    d = stats.as_dict()
    logger.info("=" * 60)
    logger.info("proposals            %d", d["proposals_total"])
    logger.info("  passed existence   %d", d["passed_existence"])
    logger.info("  passed tag         %d", d["passed_tag"])
    logger.info("  passed platform    %d", d["passed_platform"])
    logger.info("  passed identity    %d", d["passed_identity"])
    logger.info("  passed smoke       %d", d["passed_smoke"])
    logger.info("accepted             %d (%.1f%%)", d["accepted"],
                100.0 * d["acceptance_rate"])
    logger.info("rejected by stage    %s", d["rejected_by_stage"])
    logger.info("source repos mapped  %d", len(mappings))
    logger.info("=" * 60)
    logger.info("Wrote %s", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
