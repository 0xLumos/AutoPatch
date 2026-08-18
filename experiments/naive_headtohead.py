#!/usr/bin/env python3
"""Why naive :latest looks good: status breakdown + head-to-head
against AutoPatch on the images naive got accepted (applicable basis).
"""
import glob
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.expanduser("~/AutoPatch"))
from src import vulnerability_index as vi
from src.applicability import ApplicabilityPolicy, partition_applicable

R = os.path.expanduser("~/AutoPatch/results")
CAS = f"{R}/ab2yr_cascade_20260812_001147"
NAIVE = f"{R}/naive_20260812_175330"
POLICY = ApplicabilityPolicy.with_no_fix()


def load(p):
    try:
        return json.load(open(p))
    except Exception:
        return None


def app_total(scan):
    recs = vi.extract_records(scan)
    app, _ = partition_applicable(recs, POLICY, kev_set=set())
    return len(app)


def resolve_after(img):
    d = f"{CAS}/{img}/armA"
    rep = load(f"{d}/report.json")
    want = (rep or {}).get("metrics", {}).get("total_after")
    cands = [f"{d}/trivy-after.json"] + sorted(
        glob.glob(f"{d}/trivy-cascade-*.json"))
    fb = None
    for p in cands:
        s = load(p)
        if not s:
            continue
        if fb is None:
            fb = s
        if want is not None and len(vi.extract_records(s)) == want:
            return s
    return fb


nrows = [json.loads(l) for l in open(f"{NAIVE}/results.jsonl")
         if l.strip()]
print("=== naive status breakdown ===")
print(dict(Counter(r["status"] for r in nrows)))
print()
print("=== head-to-head on naive-accepted images (applicable basis) ===")
print(f"{'image':26s} {'naive%':>7s} {'ap%':>7s}  ap_admitted new_base")
arows = {json.loads(l)["image"]: json.loads(l)
         for l in open(f"{CAS}/results.jsonl") if l.strip()}
for r in nrows:
    if r.get("status") != "accepted":
        continue
    img = r["image"]
    nb = load(f"{NAIVE}/{img}/trivy-before.json")
    na = load(f"{NAIVE}/{img}/trivy-after.json")
    nred = "?"
    if nb and na:
        b, a = app_total(nb), app_total(na)
        nred = f"{100.0 * (1 - a / b):.1f}" if b else "0"
    ar = arows.get(img)
    ap_admit = bool(ar and ar["exit_code"] == 0)
    apred = "-"
    if ap_admit:
        ab = load(f"{CAS}/{img}/armA/trivy-before.json")
        aa = resolve_after(img)
        if ab and aa:
            b2, a2 = app_total(ab), app_total(aa)
            apred = f"{100.0 * (1 - a2 / b2):.1f}" if b2 else "0"
    # what tag did naive move to / from
    df = ""
    try:
        orig = open(f"{NAIVE}/{img}/Dockerfile.original").read()
        first = [l for l in orig.splitlines()
                 if l.strip().upper().startswith("FROM")]
        df = first[0].strip()[:44] if first else ""
    except Exception:
        pass
    print(f"{img:26s} {nred:>7s} {apred:>7s}  {str(ap_admit):5s} {df}")
print()
print("=== naive non-accepted reasons with detail ===")
for r in nrows:
    if r.get("status") != "accepted":
        print(f"{r['image']:26s} {r['status']}")
