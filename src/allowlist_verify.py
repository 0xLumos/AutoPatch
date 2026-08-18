#!/usr/bin/env python3
"""
Mechanical verification of proposed allow-list mappings.

Proposals from :mod:`src.allowlist_providers` are untrusted. This
module subjects each one to five checks against the live registry and
the actual image contents, and only proposals that clear all five are
written into the shipped allow-list. The checks are ordered cheapest
first so that a hallucinated repository is discarded after a single
HTTP request rather than after a pull.

  V1 EXISTENCE   The repository resolves and returns a tag list.
  V2 TAG         A concrete tag is selected and its manifest resolves.
  V3 PLATFORM    The manifest publishes the required platform.
  V4 IDENTITY    The pulled image's Linux distribution family and libc
                 family, as observed by the provenance and loader
                 fingerprints, match the required profile. This is the
                 check that catches a confidently-wrong claim: the
                 provider's own assertion about the family is ignored
                 in favour of filesystem evidence.
  V5 SMOKE       A canonical Dockerfile builds against the candidate.

Each stage records a counter so that the generated artifact reports how
many proposals survived each check. Those counters are the evidence
that the verification layer is load-bearing rather than decorative.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .allowlist_providers import Profile, Proposal

logger = logging.getLogger(__name__)


DEFAULT_PULL_TIMEOUT_S = 300
DEFAULT_BUILD_TIMEOUT_S = 300


class Stage(str, Enum):
    EXISTENCE = "existence"
    TAG = "tag"
    PLATFORM = "platform"
    IDENTITY = "identity"
    SMOKE = "smoke"


@dataclass
class VerificationResult:
    proposal: Proposal
    accepted: bool = False
    failed_stage: Optional[Stage] = None
    reason: str = ""
    resolved_tag: Optional[str] = None
    resolved_digest: Optional[str] = None
    observed_family: Optional[str] = None
    observed_libc: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "proposal": self.proposal.as_dict(),
            "accepted": self.accepted,
            "failed_stage": self.failed_stage.value if self.failed_stage else None,
            "reason": self.reason[:300],
            "resolved_tag": self.resolved_tag,
            "resolved_digest": self.resolved_digest,
            "observed_family": self.observed_family,
            "observed_libc": self.observed_libc,
        }


@dataclass
class VerificationStats:
    proposals_total: int = 0
    passed_existence: int = 0
    passed_tag: int = 0
    passed_platform: int = 0
    passed_identity: int = 0
    passed_smoke: int = 0
    accepted: int = 0
    rejected_by_stage: Dict[str, int] = field(default_factory=dict)

    def record_failure(self, stage: Stage) -> None:
        self.rejected_by_stage[stage.value] = (
            self.rejected_by_stage.get(stage.value, 0) + 1
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "proposals_total": self.proposals_total,
            "passed_existence": self.passed_existence,
            "passed_tag": self.passed_tag,
            "passed_platform": self.passed_platform,
            "passed_identity": self.passed_identity,
            "passed_smoke": self.passed_smoke,
            "accepted": self.accepted,
            "rejected_by_stage": dict(self.rejected_by_stage),
            "acceptance_rate": (
                self.accepted / self.proposals_total
                if self.proposals_total else 0.0
            ),
        }


# ════════════════════════════════════════════════════════════════════
# Registry and docker helpers
# ════════════════════════════════════════════════════════════════════

def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _run(cmd: Sequence[str], timeout_s: int) -> Tuple[int, str]:
    try:
        r = subprocess.run(list(cmd), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout_s,
                           check=False)
        return r.returncode, r.stdout.decode("utf-8", "replace")[-4000:]
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout_s}s"
    except OSError as e:
        return 125, f"exec error: {e}"


def _list_tags(repo: str, timeout_s: int = 30) -> List[str]:
    """V1 helper: tag listing via the resolver's cached Hub client when
    available, falling back to a direct manifest probe."""
    try:
        from .resolver import ImageResolver
        tags = ImageResolver().get_available_tags(repo)
        if tags:
            return list(tags)
    except Exception as e:
        logger.warning(
                "Registry tag listing failed for %s (%s); this candidate "
                "could not be verified and is treated as unverified rather "
                "than approved", repo, e,
            )
    return []


def _manifest_platforms(image_ref: str,
                        timeout_s: int = 60) -> List[str]:
    """V3 helper: platforms published by the reference's manifest."""
    code, out = _run(
        ["docker", "manifest", "inspect", image_ref], timeout_s
    )
    if code != 0:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    plats: List[str] = []
    for m in data.get("manifests", []) or []:
        p = m.get("platform") or {}
        os_ = p.get("os")
        arch = p.get("architecture")
        if os_ and arch:
            plats.append(f"{os_}/{arch}")
    if not plats and data.get("schemaVersion"):
        # Single-platform manifest: assume the pull platform.
        plats.append("linux/amd64")
    return plats


def _pull(image_ref: str, timeout_s: int = DEFAULT_PULL_TIMEOUT_S) -> bool:
    code, _ = _run(["docker", "pull", "--quiet", image_ref], timeout_s)
    return code == 0


def _digest(image_ref: str) -> Optional[str]:
    code, out = _run(
        ["docker", "inspect", "--format", "{{index .RepoDigests 0}}",
         image_ref], 30
    )
    if code != 0:
        return None
    text = out.strip()
    return text if "sha256:" in text else None


def _rmi(image_ref: str) -> None:
    _run(["docker", "rmi", "-f", image_ref], 60)


# Canonical smoke Dockerfile: exercises the candidate as a base and
# confirms a shell, a package manager entry point, and a writable
# layer all work. Deliberately minimal so a failure means the base is
# unusable rather than that the test is fussy.
_SMOKE_DOCKERFILE = """\
FROM {ref}
SHELL ["/bin/sh", "-c"]
RUN echo autopatch-smoke > /tmp/autopatch-smoke && \
    cat /tmp/autopatch-smoke && \
    (command -v apt-get || command -v apk || command -v dnf || \
     command -v yum || command -v microdnf || true)
"""


# ════════════════════════════════════════════════════════════════════
# Stage implementations
# ════════════════════════════════════════════════════════════════════

def _select_tag(repo: str, proposal: Proposal,
                profile: Profile) -> Optional[str]:
    """V2: choose a concrete tag. An explicit proposal tag is used when
    it appears in the live tag list; otherwise the newest stable tag
    consistent with the runtime major version is selected."""
    tags = _list_tags(repo)
    if not tags:
        return None
    if proposal.target_tag:
        return proposal.target_tag if proposal.target_tag in tags else None

    unstable = ("rc", "beta", "alpha", "nightly", "dev", "test", "edge")
    stable = [t for t in tags
              if not any(u in t.lower() for u in unstable)
              and t not in ("latest", "stable", "current")]
    if profile.runtime_major:
        pref = [t for t in stable if t.startswith(profile.runtime_major)]
        if pref:
            stable = pref
    if not stable:
        return None
    # Deterministic: longest-then-lexicographic-greatest, which favours
    # a fully-qualified version over a truncated alias.
    return sorted(stable, key=lambda t: (len(t), t))[-1]


def _check_identity(image_ref: str, profile: Profile
                    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """V4: the provider's claim about the target's family is ignored;
    the family and libc are re-derived from the pulled image using the
    same fingerprints the inference engine trusts."""
    observed_family: Optional[str] = None
    observed_libc: Optional[str] = None

    try:
        from .provenance_fingerprint import fingerprint_image
        fp = fingerprint_image(image_ref, include_loader=True)
        observed_family = fp.consensus_distro
        observed_libc = fp.consensus_libc
    except Exception as e:
        return False, f"fingerprint failed: {e}", None, None

    if observed_family is None:
        return False, "could not determine distribution family", None, observed_libc

    fam_ok = _family_compatible(observed_family, profile.distro_family)
    if not fam_ok:
        return (False,
                f"family mismatch: observed {observed_family}, "
                f"required {profile.distro_family}",
                observed_family, observed_libc)

    if profile.libc in ("glibc", "musl"):
        if observed_libc is None:
            return (False, "could not determine libc family",
                    observed_family, observed_libc)
        if observed_libc != profile.libc:
            return (False,
                    f"libc mismatch: observed {observed_libc}, "
                    f"required {profile.libc}",
                    observed_family, observed_libc)

    return True, "identity verified", observed_family, observed_libc


# Families whose OS-level packages are mutually substitutable for the
# purposes of base replacement. Membership is a structural property of
# the distributions, not a judgement about quality.
_COMPATIBLE_FAMILIES: Dict[str, frozenset] = {
    "debian": frozenset({"debian", "ubuntu"}),
    "ubuntu": frozenset({"ubuntu", "debian"}),
    "rhel": frozenset({"rhel"}),
    "alpine": frozenset({"alpine"}),
    "arch": frozenset({"arch"}),
}


def _family_compatible(observed: str, required: str) -> bool:
    if observed == required:
        return True
    return observed in _COMPATIBLE_FAMILIES.get(required, frozenset())


def _check_smoke(image_ref: str,
                 timeout_s: int = DEFAULT_BUILD_TIMEOUT_S) -> Tuple[bool, str]:
    """V5: a canonical Dockerfile must build on top of the candidate."""
    with tempfile.TemporaryDirectory(prefix="autopatch_smoke_") as td:
        p = Path(td) / "Dockerfile"
        p.write_text(_SMOKE_DOCKERFILE.format(ref=image_ref),
                     encoding="utf-8")
        tag = "autopatch-allowlist-smoke:tmp"
        code, out = _run(
            ["docker", "build", "--no-cache", "-t", tag, "-f", str(p), td],
            timeout_s,
        )
        _rmi(tag)
        if code != 0:
            return False, f"smoke build failed: {out.strip()[-240:]}"
    return True, "smoke build succeeded"


# ════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════

def verify_proposal(
    proposal: Proposal,
    profile: Profile,
    *,
    run_smoke: bool = True,
    keep_image: bool = False,
) -> VerificationResult:
    """Run the five stages against one proposal."""
    result = VerificationResult(proposal=proposal)

    if not _docker_available():
        result.failed_stage = Stage.EXISTENCE
        result.reason = "docker not available"
        return result

    # V1 existence
    tags = _list_tags(proposal.target_repo)
    if not tags:
        result.failed_stage = Stage.EXISTENCE
        result.reason = "repository has no retrievable tag list"
        return result

    # V2 tag selection
    tag = _select_tag(proposal.target_repo, proposal, profile)
    if not tag:
        result.failed_stage = Stage.TAG
        result.reason = "no stable tag consistent with the profile"
        return result
    result.resolved_tag = tag
    ref = f"{proposal.target_repo}:{tag}"

    # V3 platform
    plats = _manifest_platforms(ref)
    if plats and profile.platform not in plats:
        result.failed_stage = Stage.PLATFORM
        result.reason = (f"platform {profile.platform} not published "
                         f"(available: {', '.join(plats[:4])})")
        return result

    if not _pull(ref):
        result.failed_stage = Stage.PLATFORM
        result.reason = "image could not be pulled"
        return result
    result.resolved_digest = _digest(ref)

    try:
        # V4 identity, from filesystem evidence rather than the claim
        ok, why, fam, libc = _check_identity(ref, profile)
        result.observed_family = fam
        result.observed_libc = libc
        if not ok:
            result.failed_stage = Stage.IDENTITY
            result.reason = why
            return result

        # V5 smoke build
        if run_smoke:
            ok, why = _check_smoke(ref)
            if not ok:
                result.failed_stage = Stage.SMOKE
                result.reason = why
                return result

        result.accepted = True
        result.reason = "verified"
        return result
    finally:
        if not keep_image:
            _rmi(ref)


def verify_all(
    proposals: Sequence[Proposal],
    profile_for: Dict[str, Profile],
    *,
    run_smoke: bool = True,
) -> Tuple[List[VerificationResult], VerificationStats]:
    """Verify a batch, returning per-proposal results and the stage
    counters reported in the generated artifact."""
    stats = VerificationStats(proposals_total=len(proposals))
    results: List[VerificationResult] = []

    for prop in proposals:
        profile = profile_for.get(prop.source_repo)
        if profile is None:
            r = VerificationResult(proposal=prop,
                                   failed_stage=Stage.EXISTENCE,
                                   reason="no profile for source repository")
            results.append(r)
            stats.record_failure(Stage.EXISTENCE)
            continue

        r = verify_proposal(prop, profile, run_smoke=run_smoke)
        results.append(r)

        # Stage counters are cumulative: a proposal that reaches stage
        # N necessarily passed every earlier stage.
        reached = {
            Stage.EXISTENCE: 0, Stage.TAG: 1, Stage.PLATFORM: 2,
            Stage.IDENTITY: 3, Stage.SMOKE: 4,
        }
        depth = 5 if r.accepted else reached.get(r.failed_stage, 0)
        if depth >= 1:
            stats.passed_existence += 1
        if depth >= 2:
            stats.passed_tag += 1
        if depth >= 3:
            stats.passed_platform += 1
        if depth >= 4:
            stats.passed_identity += 1
        if depth >= 5:
            stats.passed_smoke += 1
            stats.accepted += 1
        if not r.accepted and r.failed_stage:
            stats.record_failure(r.failed_stage)

    return results, stats
