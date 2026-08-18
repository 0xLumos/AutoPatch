#!/usr/bin/env python3
"""
P4-26: Lineage / attestation chain.

A *lineage attestation* is an in-toto-style predicate that links
the patched image back to the image it replaced. Compared to the
SLSA remediation attestation already emitted by
:func:`src.vex_generator.generate_remediation_attestation`, the
lineage predicate is always produced (regardless of signing mode)
and carries enough state to verify a chain of remediations
end-to-end without re-running the pipeline:

  * ``predecessor.digest``        the prior image's sha256, so a
                                   verifier can walk back through
                                   the attestation chain
  * ``subject.digest``            the patched image's sha256
  * ``cve_diff``                  resolved / remaining / introduced
                                   CVEs in canonical form
  * ``posture_delta``             ``before`` / ``after`` posture
                                   components and total
  * ``evidence_snapshots``        sha256 of the EPSS + KEV files
                                   used, plus scanner versions
  * ``chain_id``                  deterministic id linking the two
                                   subjects (``sha256(predecessor ||
                                   subject)``); makes chain joins
                                   trivial without parsing nested
                                   fields

Signing is delegated to :func:`src.signer.generate_attestation` if
the caller has a non-``none`` signing mode. The predicate is
ALWAYS written to disk, even with ``--signing-mode none`` and
``--dry-run``, so reviewers and ops teams have a verifiable
artifact for every run.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)


_PREDICATE_TYPE = "https://autopatch.dev/lineage/v1"
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def _digest_from_ref(image_ref: str) -> str:
    """Extract the sha256 hex from a reference like
    ``registry/foo@sha256:abcd...`` or ``foo:tag``. Returns an empty
    string when no digest is present rather than fabricating one."""
    if not image_ref:
        return ""
    marker = "sha256:"
    idx = image_ref.find(marker)
    if idx == -1:
        return ""
    return image_ref[idx + len(marker):].split()[0].strip()


def _stable_hash(*parts: str) -> str:
    """Deterministic chain id: sha256 of the concatenated parts.

    Used for ``chain_id`` so two attestations from the same
    predecessor->subject pair always produce the same id, even when
    invocation timestamps differ.
    """
    h = hashlib.sha256()
    for part in parts:
        h.update((part or "").encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def _canonical_cve_list(items: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Reduce a list of vulnerability records to a stable, minimal
    form suitable for attestation. Sorts deterministically so two
    runs over the same input produce byte-identical output."""
    out: List[Dict[str, Any]] = []
    for it in items or []:
        if not isinstance(it, Mapping):
            continue
        rec = {
            "id": str(it.get("vuln_id") or it.get("id") or "").upper(),
            "pkg": str(it.get("pkg_name") or it.get("package") or ""),
            "severity": str(it.get("severity") or "").upper(),
            "installed_version": str(it.get("installed_version") or ""),
            "fixed_version": str(it.get("fixed_version") or ""),
        }
        if not rec["id"]:
            continue
        out.append(rec)
    out.sort(key=lambda r: (r["id"], r["pkg"], r["installed_version"]))
    return out


def _file_sha256(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    try:
        p = Path(path)
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return None


def build_lineage_predicate(
    *,
    subject_ref: str,
    predecessor_ref: str,
    cve_diff: Mapping[str, List[Mapping[str, Any]]],
    posture_before: Optional[Mapping[str, Any]] = None,
    posture_after: Optional[Mapping[str, Any]] = None,
    evidence_snapshot: Optional[Mapping[str, Any]] = None,
    scanner_versions: Optional[Mapping[str, str]] = None,
    pipeline_config: Optional[Mapping[str, Any]] = None,
    provenance: Optional[Mapping[str, Any]] = None,
    invocation_id: Optional[str] = None,
    started_on: Optional[str] = None,
    finished_on: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an in-toto v1 Statement carrying the lineage predicate.

    The shape is compatible with cosign's ``attest --type custom
    --predicate <file>`` flow, and the predicate body is
    self-describing so it can be consumed without out-of-band
    schema knowledge.
    """
    subject_digest = _digest_from_ref(subject_ref)
    predecessor_digest = _digest_from_ref(predecessor_ref)
    chain_id = _stable_hash(predecessor_digest, subject_digest)

    now = datetime.now(timezone.utc).isoformat()
    started = started_on or now
    finished = finished_on or now
    inv = invocation_id or f"urn:uuid:{uuid.uuid4()}"

    statement: Dict[str, Any] = {
        "_type": _STATEMENT_TYPE,
        "predicateType": _PREDICATE_TYPE,
        "subject": [
            {
                "name": subject_ref,
                # Only emit a digest entry when we actually have one;
                # downstream verifiers reject empty-string digests.
                **({"digest": {"sha256": subject_digest}} if subject_digest else {}),
            }
        ],
        "predicate": {
            "schema_version": "1.0",
            "chain_id": chain_id,
            "predecessor": {
                "name": predecessor_ref,
                **({"digest": {"sha256": predecessor_digest}} if predecessor_digest else {}),
            },
            "cve_diff": {
                "resolved": _canonical_cve_list(list(cve_diff.get("resolved", []))),
                "remaining": _canonical_cve_list(list(cve_diff.get("remaining", []))),
                "introduced": _canonical_cve_list(list(cve_diff.get("new", []))),
            },
            "posture_delta": {
                "before": dict(posture_before or {}),
                "after": dict(posture_after or {}),
            },
            "evidence_snapshots": dict(evidence_snapshot or {}),
            "scanner_versions": dict(scanner_versions or {}),
            "pipeline_config": dict(pipeline_config or {}),
            "provenance": dict(provenance or {}),
            "runDetails": {
                "builder": {
                    "id": "https://github.com/0xLumos/AutoPatch",
                    "version": "1.0.0",
                },
                "metadata": {
                    "invocationId": inv,
                    "startedOn": started,
                    "finishedOn": finished,
                },
            },
        },
    }

    return statement


def write_lineage_predicate(
    predicate: Mapping[str, Any],
    output_path: str,
) -> str:
    """Write the lineage predicate to disk as canonical JSON.

    Returns the absolute path to the written file. Always uses
    ``sort_keys=True`` so two runs over the same input produce
    byte-identical files (useful for golden tests and for
    detecting drift in CI).
    """
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # We use atomic write semantics: write to a tmp file in the same
    # directory and rename, so an interrupted run never leaves a
    # half-written attestation on disk.
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(predicate, f, sort_keys=True, indent=2)
        f.write("\n")
    tmp.replace(p)
    logger.info("Lineage predicate written to %s", p)
    return str(p)


def emit_lineage_attestation(
    *,
    output_dir: str,
    subject_ref: str,
    predecessor_ref: str,
    cve_diff: Mapping[str, List[Mapping[str, Any]]],
    posture_before: Optional[Mapping[str, Any]] = None,
    posture_after: Optional[Mapping[str, Any]] = None,
    evidence_snapshot: Optional[Mapping[str, Any]] = None,
    scanner_versions: Optional[Mapping[str, str]] = None,
    pipeline_config: Optional[Mapping[str, Any]] = None,
    provenance: Optional[Mapping[str, Any]] = None,
    sign: bool = False,
    insecure_registry: bool = False,
    signing_mode: str = "keyless",
) -> Dict[str, Any]:
    """Build, persist, and optionally attach the lineage predicate.

    Returns a dict with ``path`` (where the predicate was written),
    ``chain_id`` (the deterministic chain link), and ``signed``
    (whether cosign attested the predicate).

    This function never raises on signing failures; the unsigned
    predicate on disk is the contract, signing is best-effort so a
    misconfigured Sigstore Fulcio does not block a successful
    remediation.
    """
    predicate = build_lineage_predicate(
        subject_ref=subject_ref,
        predecessor_ref=predecessor_ref,
        cve_diff=cve_diff,
        posture_before=posture_before,
        posture_after=posture_after,
        evidence_snapshot=evidence_snapshot,
        scanner_versions=scanner_versions,
        pipeline_config=pipeline_config,
        provenance=provenance,
    )
    out_path = str(Path(output_dir) / "lineage-attestation.json")
    write_lineage_predicate(predicate, out_path)

    signed = False
    if sign and subject_ref and "sha256:" in subject_ref:
        try:
            # Lazy import so the module is usable without cosign
            # available (unit tests, dry-run mode, CI without the
            # signing toolchain installed).
            from .signer import generate_attestation
            signed = generate_attestation(
                image_ref=subject_ref,
                predicate_path=out_path,
                predicate_type="custom",
                insecure_registry=insecure_registry,
                signing_mode=signing_mode,
            )
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(
                "Lineage attestation signing failed (non-critical): %s", e
            )
            signed = False

    return {
        "path": out_path,
        "chain_id": predicate["predicate"]["chain_id"],
        "signed": signed,
    }
