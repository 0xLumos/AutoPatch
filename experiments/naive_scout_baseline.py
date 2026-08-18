#!/usr/bin/env python3
"""Naive :latest and Docker Scout baselines over the screened corpus.

Mode naive: rewrite every FROM tag to :latest, rebuild from the same
context, rescan, and evaluate the identical acceptance gate the
AutoPatch batches used (count-strict over the applicable set).

Mode scout: build the original, then record Docker Scout's advisory
output (docker scout recommendations); Scout performs no remediation,
so the measurements are advisory coverage and the recommended base,
for agreement analysis against AutoPatch's chosen candidates.

Usage:
    python experiments/naive_scout_baseline.py --mode naive --out DIR
    python experiments/naive_scout_baseline.py --mode scout --out DIR
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.applicability import ApplicabilityPolicy          # noqa: E402
from src.comparer import check_acceptance_criteria          # noqa: E402

FROM_RE = re.compile(
    r"^(\s*FROM\s+(?:--platform=\S+\s+)?)(\S+?)(:(\S+?))?"
    r"((?:\s+AS\s+\S+)?\s*)$", re.IGNORECASE)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sh(cmd, timeout, log=None):
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    if log is not None:
        prev = log.read_text(encoding="utf-8") if log.is_file() else ""
        log.write_text(prev + f"\n$ {' '.join(cmd)}\n"
                       + (r.stdout or "") + (r.stderr or ""),
                       encoding="utf-8")
    return r


def vuln_count(scan):
    return sum(len(x.get("Vulnerabilities") or [])
               for x in (scan.get("Results") or []))


def naive_rewrite(text):
    out = []
    for ln in text.splitlines():
        m = FROM_RE.match(ln)
        if m and m.group(2).lower() not in ("scratch",):
            # keep stage-alias references (bare names without : or /)
            base = m.group(2)
            if ":" in base or "/" in base or "." in base or m.group(3):
                ln = f"{m.group(1)}{base}:latest{m.group(5) or ''}"
        out.append(ln)
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["naive", "scout"], required=True)
    ap.add_argument("--corpus", default="screened_2yr")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=2700)
    args = ap.parse_args()

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    results = out / "results.jsonl"
    done = set()
    if results.is_file():
        for ln in results.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                done.add(json.loads(ln)["image"])

    entries = json.loads(Path(args.corpus, "manifest.json")
                         .read_text(encoding="utf-8"))["entries"]
    policy = ApplicabilityPolicy.with_no_fix()

    for i, e in enumerate(entries, 1):
        name = e["name"]
        if name in done:
            continue
        print(f"[{i}/{len(entries)}] {args.mode} {name} ...", flush=True)
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        log = d / "run.log"
        rec = {"image": name, "strategy": args.mode, "started": _now(),
               "ref_sha": e.get("ref_sha")}
        t0 = time.time()
        orig = f"{args.mode}orig-{i}"
        patched = f"{args.mode}new-{i}"
        try:
            b = sh(["docker", "build", "-t", orig,
                    "-f", e["dockerfile"], e["context"]],
                   args.timeout, log)
            if b.returncode != 0:
                rec.update(exit_code=1, status="original_build_failed")
                raise StopIteration

            if args.mode == "scout":
                r = sh(["docker", "scout", "recommendations", orig],
                       600, log)
                txt = (r.stdout or "") + (r.stderr or "")
                (d / "scout.txt").write_text(txt, encoding="utf-8")
                errored = bool(re.search(
                    r"(?i)(disk quota exceeded|failed to (load|copy|"
                    r"index)|unable to detect input|permission denied)",
                    txt))
                if errored:
                    rec.update(exit_code=1, status="scout_index_error")
                    raise StopIteration
                # Scout indexed the image. Its recommendations output
                # lists a "Recommended tag" / base update when one exists.
                recommends = bool(
                    re.search(r"(?i)recommended tag", txt)
                    or re.search(r"(?i)update to.*(newer|latest)", txt))
                rec.update(exit_code=0, status="advisory_recorded",
                           scout_exit=r.returncode,
                           recommends_update=recommends)
                raise StopIteration

            s1 = sh(["trivy", "image", "--scanners", "vuln",
                     "--format", "json",
                     "-o", str(d / "trivy-before.json"), orig], 900, log)
            if s1.returncode != 0:
                rec.update(exit_code=1, status="scan_before_failed")
                raise StopIteration
            df_text = Path(e["dockerfile"]).read_text(encoding="utf-8",
                                                      errors="replace")
            (d / "Dockerfile.naive").write_text(naive_rewrite(df_text),
                                                encoding="utf-8")
            b2 = sh(["docker", "build", "-t", patched,
                     "-f", str(d / "Dockerfile.naive"), e["context"]],
                    args.timeout, log)
            if b2.returncode != 0:
                rec.update(exit_code=1, status="patched_build_failed")
                raise StopIteration
            s2 = sh(["trivy", "image", "--scanners", "vuln",
                     "--format", "json",
                     "-o", str(d / "trivy-after.json"), patched],
                    900, log)
            if s2.returncode != 0:
                rec.update(exit_code=1, status="scan_after_failed")
                raise StopIteration
            before = json.loads((d / "trivy-before.json")
                                .read_text(encoding="utf-8"))
            after = json.loads((d / "trivy-after.json")
                               .read_text(encoding="utf-8"))
            accepted, feedback = check_acceptance_criteria(
                before, after, threshold="count-strict",
                applicability_policy=policy, demote_local_av=False)
            rec.update(exit_code=0 if accepted else 1,
                       status="accepted" if accepted else "gate_rejected",
                       before=vuln_count(before), after=vuln_count(after),
                       feedback=feedback[-6:])
        except StopIteration:
            pass
        except subprocess.TimeoutExpired:
            rec.update(exit_code=1, status="timeout")
        rec["wall_seconds"] = round(time.time() - t0, 1)
        rec["finished"] = _now()
        with open(results, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        for t in (orig, patched):
            subprocess.run(["docker", "rmi", "-f", t],
                           capture_output=True, timeout=120)
        subprocess.run(["docker", "image", "prune", "-f"],
                       capture_output=True, timeout=300)
    print(f"{args.mode} baseline complete")


if __name__ == "__main__":
    main()
