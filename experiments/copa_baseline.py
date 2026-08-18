#!/usr/bin/env python3
"""Copacetic baseline over the screened corpus.

For every screened survivor: build the original from its Dockerfile,
scan it, run `copa patch` on the built image, rescan, and evaluate the
IDENTICAL acceptance gate the AutoPatch batches used (count-strict over
the applicable set, kernel-space and no-fix excluded, KEV hard-block,
no demotions). Records to results.jsonl; resumable; artifacts persisted
per image; bases kept between runs.

Usage:
    python experiments/copa_baseline.py --corpus screened_2yr \
        --out results/copa_<stamp> [--addr docker-container://buildkitd]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.applicability import ApplicabilityPolicy          # noqa: E402
from src.comparer import check_acceptance_criteria          # noqa: E402


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sh(cmd, timeout, log=None):
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    if log is not None:
        log.write_text((log.read_text(encoding="utf-8")
                        if log.is_file() else "")
                       + f"\n$ {' '.join(cmd)}\n" + (r.stdout or "")
                       + (r.stderr or ""), encoding="utf-8")
    return r


def vuln_count(scan):
    return sum(len(x.get("Vulnerabilities") or [])
               for x in (scan.get("Results") or []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="screened_2yr")
    ap.add_argument("--out", required=True)
    ap.add_argument("--addr", default="docker-container://buildkitd")
    ap.add_argument("--registry", default="localhost:5000",
                    help="local registry buildkit can pull the built "
                         "original from; copa cannot read a bare local "
                         "daemon tag through buildkit")
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
        print(f"[{i}/{len(entries)}] copa {name} ...", flush=True)
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        log = d / "run.log"
        rec = {"image": name, "strategy": "copacetic",
               "started": _now(), "ref_sha": e.get("ref_sha")}
        t0 = time.time()
        reg_ref = f"{args.registry}/copaorig-{i}:latest"
        patched = f"copapatched-{i}:latest"
        try:
            b = sh(["docker", "build", "-t", reg_ref,
                    "-f", e["dockerfile"], e["context"]],
                   args.timeout, log)
            if b.returncode != 0:
                rec.update(exit_code=1, status="original_build_failed")
                raise StopIteration
            # copa reads the input through buildkit, which cannot see a
            # bare local daemon tag; push to the local registry first.
            p = sh(["docker", "push", reg_ref], 600, log)
            if p.returncode != 0:
                rec.update(exit_code=1, status="registry_push_failed")
                raise StopIteration
            s1 = sh(["trivy", "image", "--scanners", "vuln",
                     "--format", "json",
                     "-o", str(d / "trivy-before.json"), reg_ref],
                    900, log)
            if s1.returncode != 0:
                rec.update(exit_code=1, status="scan_before_failed")
                raise StopIteration
            c = sh(["copa", "patch", "-i", reg_ref,
                    "-r", str(d / "trivy-before.json"),
                    "-t", patched, "--addr", args.addr,
                    "--timeout", "20m"],
                   1500, log)
            ctxt = (c.stdout or "") + (c.stderr or "")
            if c.returncode != 0:
                # "0 patched" on a minimal image (no OS packages, e.g.
                # a Go binary on scratch/distroless) is a legitimate
                # copa NON-RESULT, not a harness error: copa patches OS
                # packages in place and has nothing to do here.
                if "0 patched" in ctxt or "no patchable" in ctxt.lower():
                    rec.update(exit_code=1, status="copa_no_os_packages")
                else:
                    rec.update(exit_code=1, status="copa_failed")
                raise StopIteration
            s2 = sh(["trivy", "image", "--scanners", "vuln",
                     "--format", "json",
                     "-o", str(d / "trivy-after.json"), patched],
                    900, log)
            if s2.returncode != 0 or not (d / "trivy-after.json").is_file():
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
        # scrub run tags, keep base images and the buildkitd/registry
        for t in (reg_ref, patched):
            subprocess.run(["docker", "rmi", "-f", t],
                           capture_output=True, timeout=120)
        subprocess.run(["docker", "image", "prune", "-f"],
                       capture_output=True, timeout=300)
    print("copa baseline complete")


if __name__ == "__main__":
    main()
