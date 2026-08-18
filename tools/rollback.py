#!/usr/bin/env python3
"""Restore the pre-patch state recorded in a run's rollback.json.

AutoPatch never destroys anything: the original Dockerfile is left
untouched on disk and the patched image is a separate tag. What CAN
drift after a run is everything around those two facts, and this tool
walks them back:

  1. If the on-disk Dockerfile no longer matches the recorded SHA-256
     (someone applied Dockerfile.patched over it, or a PR was merged),
     it is restored from the byte-identical copy the manifest points at.
  2. The patched local image tag is removed, so `docker run` of the
     app tag cannot silently resolve to the patched image.
  3. The original image digest is printed in a form a deployment
     system can consume, because image rollback in production is a
     REDEPLOY of the previous digest, not a mutation of anything.

What this tool deliberately does not do: touch a registry, revert a
git commit, or roll a Kubernetes Deployment. Those actions belong to
systems with their own auth and their own audit trails; a security
tool quietly driving them is how rollback becomes a second incident.
It prints the exact commands instead.

Usage:
    python tools/rollback.py <output_dir>/rollback.json [--dry-run]

Exit codes: 0 restored (or nothing to do), 1 manifest missing or
invalid, 2 restoration attempted and failed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _run(argv: list) -> tuple:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifest", help="Path to a run's rollback.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what would be done without doing it")
    args = ap.parse_args(argv)

    mpath = Path(args.manifest)
    if mpath.is_dir():
        mpath = mpath / "rollback.json"
    if not mpath.is_file():
        print(f"error: no rollback manifest at {mpath}", file=sys.stderr)
        return 1
    try:
        m = json.loads(mpath.read_text(encoding="utf-8"))
    except ValueError as e:
        print(f"error: manifest is not valid JSON: {e}", file=sys.stderr)
        return 1
    if m.get("schema") != "autopatch/rollback/v1":
        print(f"error: unrecognised schema {m.get('schema')!r}",
              file=sys.stderr)
        return 1

    orig = m.get("original") or {}
    patched = m.get("patched") or {}
    failures = 0

    # ── 1. Dockerfile ───────────────────────────────────────────────
    df = orig.get("dockerfile_path")
    want_sha = orig.get("dockerfile_sha256") or ""
    if df and want_sha:
        dfp = Path(df)
        if not dfp.is_file():
            print(f"[dockerfile] MISSING: {df}")
            failures += 1
        elif _sha256(dfp) == want_sha:
            print(f"[dockerfile] unchanged since the run; nothing to restore")
        else:
            # The manifest's sibling Dockerfile.patched is the patched
            # text; the ORIGINAL bytes live in the run's output dir as
            # the input the pipeline read. We keep a copy there for
            # exactly this moment.
            backup = mpath.parent / "Dockerfile.original"
            if backup.is_file() and _sha256(backup) == want_sha:
                if args.dry_run:
                    print(f"[dockerfile] would restore {df} from {backup}")
                else:
                    shutil.copyfile(backup, dfp)
                    ok = _sha256(dfp) == want_sha
                    print(f"[dockerfile] restored from backup: "
                          f"{'verified' if ok else 'HASH MISMATCH'}")
                    if not ok:
                        failures += 1
            else:
                print(f"[dockerfile] drifted from {want_sha[:12]}... and no "
                      f"verifiable backup found at {backup}. If this repo "
                      f"is under git: git checkout -- {df}")
                failures += 1

    # ── 2. Patched local image tag ──────────────────────────────────
    ptag = patched.get("image_tag")
    if ptag:
        code, _ = _run(["docker", "image", "inspect", ptag])
        if code != 0:
            print(f"[image] patched tag {ptag} not present locally; "
                  f"nothing to remove")
        elif args.dry_run:
            print(f"[image] would remove local tag {ptag}")
        else:
            code, out = _run(["docker", "rmi", ptag])
            if code == 0:
                print(f"[image] removed local tag {ptag}")
            else:
                print(f"[image] could not remove {ptag}: {out.strip()[:200]}")
                failures += 1

    # ── 3. Deployment guidance ──────────────────────────────────────
    odigest = orig.get("image_digest")
    print()
    print("Deployment rollback (manual, by design):")
    if odigest:
        print(f"  previous known-good image: {odigest}")
        print(f"  kubernetes: kubectl set image deployment/<name> "
              f"<container>={odigest}")
        print(f"  compose:    pin image: {odigest} and redeploy")
    else:
        print("  no original digest was recorded (the original image was "
              "not built or inspectable during the run); recover the "
              "previous digest from your registry or deployment history")
    if m.get("accepted"):
        print("  note: this run PASSED acceptance; roll back only if a "
              "problem surfaced after deployment")
    else:
        print("  note: this run FAILED acceptance and should never have "
              "been deployed; if it was, treat that as the incident")

    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
