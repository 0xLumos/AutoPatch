#!/usr/bin/env python3
"""
P4-24: Multi-stage SBOM / CVE reasoning.

In a multi-stage Dockerfile (``FROM ... AS builder`` followed by
``FROM ... AS runtime``) the CVEs that ship to production are ONLY
those present in the *final* stage. Vulnerabilities in build-stage
binaries (compilers, toolchains, scratch artefacts) cannot run in
production unless an explicit ``COPY --from=builder`` brings them
across. Treating every stage's CVE list as equally risky inflates
the gate's false-reject rate and pressures operators to "fix" build
tooling that has no runtime exposure.

This module provides the pure-function plumbing to:

  * enumerate the stages of a Dockerfile (delegating to the existing
    :mod:`parser` module);
  * map a list of per-stage scan results into the union of
    "*runtime CVEs*" (CVEs present in the final stage) and
    "*build-only CVEs*" (CVEs present somewhere else but absent
    from the final stage);
  * subset an existing scan dict to the *runtime CVEs* only, so the
    existing acceptance gate can be applied without modification.

The orchestration that actually invokes ``docker build --target`` per
stage lives in the runner / main.py; this module is intentionally
I/O-free so it is unit-testable.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StageScan:
    """A per-stage scan result.

    ``stage`` is the stage's alias or its numeric index when no alias
    was declared. ``is_final`` is True for the stage that runs in
    production (typically the last ``FROM`` line, but multi-target
    builds may pick an explicit alias).
    """
    stage: str
    is_final: bool
    scan: Mapping[str, Any]


@dataclass
class StageClassification:
    """Runtime vs build-only partition of the CVE set."""
    runtime_cves: Set[str] = field(default_factory=set)
    build_only_cves: Set[str] = field(default_factory=set)
    # Mapping CVE -> stages where it appears, for debugging /
    # attestation. Even build-only CVEs carry this so reviewers can
    # see which stage introduced them.
    cve_to_stages: Dict[str, Set[str]] = field(default_factory=dict)


def _extract_cve_ids(scan: Mapping[str, Any]) -> Set[str]:
    """Pull the upper-cased CVE id set out of a Trivy-style scan dict.

    Tolerant to missing keys, malformed entries, and mixed-case ids.
    Returns the empty set on garbage input rather than raising.
    """
    out: Set[str] = set()
    results = scan.get("Results") if isinstance(scan, Mapping) else None
    if not isinstance(results, list):
        return out
    for res in results:
        if not isinstance(res, Mapping):
            continue
        for v in res.get("Vulnerabilities") or []:
            if not isinstance(v, Mapping):
                continue
            cve = v.get("VulnerabilityID") or v.get("vulnerability_id")
            if isinstance(cve, str) and cve:
                out.add(cve.upper())
    return out


def classify_cves_by_stage(
    stages: Iterable[StageScan],
) -> StageClassification:
    """Classify CVEs into runtime vs build-only across stages.

    A CVE is *runtime* iff it appears in any stage flagged
    ``is_final=True``. Everything else is *build-only*. When the
    caller flags multiple stages as final (legal — a multi-target
    build can ship more than one image), the union of those stages'
    CVE sets is the runtime set.
    """
    stage_list = list(stages)
    final_stages = [s for s in stage_list if s.is_final]
    if not final_stages:
        # Defensive: with no explicit final stage, treat the last one
        # as final so we never over-classify everything as build-only.
        if stage_list:
            stage_list[-1] = StageScan(
                stage=stage_list[-1].stage,
                is_final=True,
                scan=stage_list[-1].scan,
            )
            final_stages = [stage_list[-1]]

    runtime: Set[str] = set()
    for s in final_stages:
        runtime |= _extract_cve_ids(s.scan)

    all_cves: Set[str] = set()
    cve_to_stages: Dict[str, Set[str]] = {}
    for s in stage_list:
        ids = _extract_cve_ids(s.scan)
        all_cves |= ids
        for cve in ids:
            cve_to_stages.setdefault(cve, set()).add(s.stage)

    build_only = all_cves - runtime
    return StageClassification(
        runtime_cves=runtime,
        build_only_cves=build_only,
        cve_to_stages=cve_to_stages,
    )


def subset_scan_to_cves(
    scan: Mapping[str, Any],
    keep: Set[str],
) -> Dict[str, Any]:
    """Return a deep-ish copy of ``scan`` keeping only Vulnerabilities
    whose ``VulnerabilityID`` is in ``keep``. The rest of the
    structure is preserved verbatim so the existing comparer can
    consume the result without any code changes.

    A clean copy is returned, leaving the input untouched so the
    caller may also keep the full scan for the report.
    """
    out: Dict[str, Any] = {}
    for k, v in scan.items():
        if k != "Results":
            out[k] = v
    results_in = scan.get("Results") or []
    results_out: List[Dict[str, Any]] = []
    for res in results_in:
        if not isinstance(res, Mapping):
            results_out.append(res)  # type: ignore[arg-type]
            continue
        new_res = dict(res)
        vulns_in = res.get("Vulnerabilities") or []
        new_res["Vulnerabilities"] = [
            v for v in vulns_in
            if isinstance(v, Mapping)
            and (v.get("VulnerabilityID") or "").upper() in keep
        ]
        results_out.append(new_res)
    out["Results"] = results_out
    return out


def summarise(classification: StageClassification) -> Dict[str, Any]:
    """Compact JSON-friendly summary for the report and attestation."""
    return {
        "runtime_cve_count": len(classification.runtime_cves),
        "build_only_cve_count": len(classification.build_only_cves),
        "build_only_cves": sorted(classification.build_only_cves),
        "cve_to_stages": {
            cve: sorted(stgs)
            for cve, stgs in sorted(classification.cve_to_stages.items())
        },
    }


def derive_final_stage_aliases(
    parsed_stages: Iterable[Mapping[str, Any]],
    target: Optional[str] = None,
) -> List[str]:
    """Given the stage records returned by :mod:`parser` (each a dict
    with ``alias`` / ``from_line``), decide which stage(s) should be
    treated as ``is_final``.

    Behaviour:
      * If ``target`` is set (e.g. ``--target runtime``), that single
        stage is final.
      * Else, the last stage in the file is final (Docker's default).
    """
    stages = list(parsed_stages)
    if not stages:
        return []
    if target:
        # Match by alias first, else by numeric index.
        for s in stages:
            if (s.get("alias") or "") == target:
                return [target]
        if target.isdigit():
            idx = int(target)
            if 0 <= idx < len(stages):
                alias = stages[idx].get("alias") or str(idx)
                return [alias]
        # Unknown target: fall through to last-stage default. This
        # never raises because the build step will catch the unknown
        # target with a clear error of its own.
    last = stages[-1]
    return [last.get("alias") or str(len(stages) - 1)]
