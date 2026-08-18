#!/usr/bin/env python3
"""Corpus quality gate: build-once + headroom screening.

Mandatory before a batch runs (evaluation-corpus rule): an entry gets a
manifest slot only if
  (1) its ORIGINAL image builds, and
  (2) the selector proposes a real base change for it (headroom).

Both are established by one `src.main --dry-run` per entry: the dry-run
builds the original for the SBOM (check 1) and writes dockerfile.diff,
whose changed FROM line is check 2. Everything dropped is logged in
attrition.json with the reason; nothing is silently discarded.

Only legacy-stratum entries are screened and admitted here: the current
stratum is measured by the main corpus run and duplicating it in a
supplementary batch would double-count images without adding
information.

State is kept in <out>/state.json keyed by (project, ref_sha), so
re-invoking with additional workdirs (top-up collections at other
cutoffs) screens only entries not yet seen. Survivors are capped
(default 20) in screening order; the cap is recorded, never silent.

Usage:
    python experiments/screen_corpus.py WORKDIR [WORKDIR ...] \
        --out screened_2yr [--cap 20] [--timeout 3600]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_entries(workdir: Path):
    doc = json.loads((workdir / "manifest.json").read_text(encoding="utf-8"))
    return doc.get("entries") if isinstance(doc, dict) else doc


def _diff_has_base_change(diff_path: Path) -> bool:
    """True if any '- FROM x' / '+ FROM y' pair actually differs."""
    if not diff_path.is_file():
        return False
    removed, added = [], []
    for ln in diff_path.read_text(encoding="utf-8",
                                  errors="replace").splitlines():
        if ln.startswith("- FROM "):
            removed.append(ln[7:].strip())
        elif ln.startswith("+ FROM "):
            added.append(ln[7:].strip())
    return any(r != a for r, a in zip(removed, added))


def _prune_docker():
    """The screening builds are disposable the moment the verdict is
    recorded; same bounded-disk policy as the experiment runner.

    Never fatal: a prune that times out (observed after a very large
    build) must not kill the screening run, it just leaves cleanup to
    the next round. This exact failure once crashed screening at
    164/180 and silently starved the batch extensions.
    """
    for cmd in (["docker", "container", "prune", "-f"],
                ["docker", "system", "prune", "-af", "--volumes"],
                ["docker", "builder", "prune", "-af"]):
        try:
            subprocess.run(cmd, capture_output=True, timeout=900)
        except (subprocess.TimeoutExpired, OSError):
            continue


def _screen_one(entry: dict, scratch: Path, timeout: int) -> dict:
    """Run one dry-run; return a verdict record."""
    outdir = scratch / entry["name"]
    shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "src.main",
        "--dockerfile", entry["dockerfile"],
        "--context", entry.get("context")
        or str(Path(entry["dockerfile"]).parent),
        "--output-dir", str(outdir),
        "--signing-mode", "none",
        "--dry-run",
        "--eol-upgrade",
    ]
    rec = {"name": entry["name"], "project": entry.get("project"),
           "ref": entry.get("ref"), "ref_sha": entry.get("ref_sha"),
           "started": _now()}
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), timeout=timeout,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        out = (proc.stdout or "") + (proc.stderr or "")
        rec["wall_seconds"] = round(time.time() - t0, 1)
        if "Failed to build original image" in out:
            rec["verdict"] = "drop"
            rec["reason"] = "original_build_failed"
        elif not _diff_has_base_change(outdir / "dockerfile.diff"):
            rec["verdict"] = "drop"
            rec["reason"] = "no_headroom"
        else:
            rec["verdict"] = "pass"
            rec["reason"] = ""
    except subprocess.TimeoutExpired:
        rec["wall_seconds"] = round(time.time() - t0, 1)
        rec["verdict"] = "drop"
        rec["reason"] = f"screen_timeout_{timeout}s"
    rec["finished"] = _now()
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("workdirs", nargs="+")
    ap.add_argument("--out", required=True,
                    help="Screened-corpus dir: gets manifest.json "
                         "(survivors), attrition.json, state.json")
    ap.add_argument("--cap", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    scratch = out / "screen_runs"
    state_p = out / "state.json"
    state = (json.loads(state_p.read_text(encoding="utf-8"))
             if state_p.is_file() else {"screened": {}})

    entries, seen_keys = [], set()
    for wd in args.workdirs:
        for e in _load_entries(Path(wd).resolve()) or []:
            if e.get("stratum") != "legacy":
                continue
            key = f"{e.get('project')}@{e.get('ref_sha')}"
            if key in seen_keys:      # same tag reached via two cutoffs
                continue
            seen_keys.add(key)
            # Normalize the entry name to project@tag. The collector
            # names every legacy entry "<project>@legacy", so the same
            # project surviving at two cutoffs would collide in the
            # batch runner's per-image artifact dirs (out/<name>/armA),
            # silently clobbering scans. Unique names are a batch-
            # correctness requirement, not cosmetics.
            ref = (e.get("ref") or "").strip()
            if e.get("project") and ref:
                e = {**e, "name": f"{e['project']}@{ref}"}
            entries.append((key, e))

    for key, e in entries:
        if key in state["screened"]:
            continue
        passes = sum(1 for r in state["screened"].values()
                     if r["verdict"] == "pass")
        if passes >= args.cap:
            state["screened"][key] = {
                "name": e["name"], "verdict": "drop",
                "reason": f"survivor_cap_{args.cap}_reached"}
            continue
        print(f"[screen] {e['name']} ({e.get('ref')}) ...", flush=True)
        rec = _screen_one(e, scratch, args.timeout)
        rec["entry"] = e
        state["screened"][key] = rec
        state_p.write_text(json.dumps(state, indent=1), encoding="utf-8")
        print(f"    -> {rec['verdict']}"
              f"{(' (' + rec['reason'] + ')') if rec['reason'] else ''}"
              f" in {rec.get('wall_seconds', 0)}s", flush=True)
        _prune_docker()

    survivors = [r["entry"] for r in state["screened"].values()
                 if r["verdict"] == "pass" and "entry" in r]
    attrition = [{k: r.get(k) for k in
                  ("name", "ref", "ref_sha", "reason", "wall_seconds")}
                 for r in state["screened"].values()
                 if r["verdict"] == "drop"]
    (out / "manifest.json").write_text(json.dumps({
        "criteria_version": "2.1-screened",
        "screened": _now(),
        "screen_rule": "original builds once AND selector proposes a real "
                       "base change; legacy stratum only; drops logged in "
                       "attrition.json; survivor cap " + str(args.cap),
        "entries": survivors,
    }, indent=2), encoding="utf-8")
    (out / "attrition.json").write_text(
        json.dumps(attrition, indent=2), encoding="utf-8")
    print(f"\nsurvivors: {len(survivors)} | dropped: {len(attrition)} "
          f"| manifest: {out / 'manifest.json'}")


if __name__ == "__main__":
    main()
