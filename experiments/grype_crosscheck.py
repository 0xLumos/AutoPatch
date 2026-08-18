#!/usr/bin/env python3
"""Cross-scanner robustness check with Grype.

For every image ADMITTED by the base-swap batch, rebuild the original
and the accepted patched image from the persisted Dockerfiles, scan
both with Grype, and record reductions under both scanners side by
side. Addresses the scanner-relativity threat with measurement instead
of a caveat: if reductions hold under an independent scanner and
vulnerability database, they are not artifacts of Trivy's.

Usage:
    python experiments/grype_crosscheck.py \
        --batch results/ab2yr_base_20260811_221744 \
        --corpus screened_2yr --out results/grype_<stamp>
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


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


def trivy_count(p):
    try:
        d = json.loads(Path(p).read_text(encoding="utf-8"))
        return sum(len(x.get("Vulnerabilities") or [])
                   for x in (d.get("Results") or []))
    except Exception:
        return None


def grype_count(p):
    try:
        d = json.loads(Path(p).read_text(encoding="utf-8"))
        return len(d.get("matches") or [])
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", required=True)
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

    manifest = {e["name"]: e for e in json.loads(
        Path(args.corpus, "manifest.json").read_text(encoding="utf-8"))
        ["entries"]}
    batch = Path(args.batch)
    admits = []
    for ln in (batch / "results.jsonl").read_text(
            encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        r = json.loads(ln)
        if r.get("exit_code") == 0 and r["image"] in manifest:
            admits.append(r["image"])

    for i, name in enumerate(admits, 1):
        if name in done:
            continue
        print(f"[{i}/{len(admits)}] grype {name} ...", flush=True)
        e = manifest[name]
        srcdir = batch / name / "armA"
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        log = d / "run.log"
        rec = {"image": name, "started": _now()}
        t0 = time.time()
        orig = f"gorig-{i}"
        pat = f"gpat-{i}"
        try:
            b1 = sh(["docker", "build", "-t", orig,
                     "-f", e["dockerfile"], e["context"]],
                    args.timeout, log)
            b2 = sh(["docker", "build", "-t", pat,
                     "-f", str(srcdir / "Dockerfile.patched"),
                     e["context"]], args.timeout, log)
            if b1.returncode != 0 or b2.returncode != 0:
                rec.update(status="rebuild_failed")
            else:
                sh(["grype", f"docker:{orig}", "-o", "json",
                    "--file", str(d / "grype-before.json")], 1200, log)
                sh(["grype", f"docker:{pat}", "-o", "json",
                    "--file", str(d / "grype-after.json")], 1200, log)
                gb = grype_count(d / "grype-before.json")
                ga = grype_count(d / "grype-after.json")
                tb = trivy_count(srcdir / "trivy-before.json")
                ta = trivy_count(srcdir / "trivy-after.json")
                rec.update(status="ok", grype_before=gb, grype_after=ga,
                           trivy_before=tb, trivy_after=ta)
                if gb and ga is not None and gb > 0:
                    rec["grype_reduction_pct"] = round(
                        100.0 * (gb - ga) / gb, 1)
                if tb and ta is not None and tb > 0:
                    rec["trivy_reduction_pct"] = round(
                        100.0 * (tb - ta) / tb, 1)
        except subprocess.TimeoutExpired:
            rec.update(status="timeout")
        rec["wall_seconds"] = round(time.time() - t0, 1)
        rec["finished"] = _now()
        with open(results, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        for t in (orig, pat):
            subprocess.run(["docker", "rmi", "-f", t],
                           capture_output=True, timeout=120)
        subprocess.run(["docker", "image", "prune", "-f"],
                       capture_output=True, timeout=300)
    print("grype cross-check complete")


if __name__ == "__main__":
    main()
