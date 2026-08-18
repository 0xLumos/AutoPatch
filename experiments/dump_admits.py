#!/usr/bin/env python3
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/AutoPatch"))
from src import vulnerability_index as vi
from src.applicability import ApplicabilityPolicy, partition_applicable

R = os.path.expanduser("~/AutoPatch/results")
CAS = f"{R}/ab2yr_cascade_20260812_001147"
POLICY = ApplicabilityPolicy.with_no_fix()


def app_total(p):
    try:
        scan = json.load(open(p))
    except Exception:
        return None
    recs = vi.extract_records(scan)
    app, _ = partition_applicable(recs, POLICY, kev_set=set())
    return len(app)


rows = [json.loads(l) for l in open(f"{CAS}/results.jsonl") if l.strip()]
vals = []
for r in rows:
    img = r["image"]
    if r["exit_code"] != 0:
        vals.append(0.0)
        continue
    b = app_total(f"{CAS}/{img}/armA/trivy-before.json")
    a = app_total(f"{CAS}/{img}/armA/trivy-after.json")
    red = 100.0 * (1 - a / b) if b else 0.0
    vals.append(red)
    print(f"{img:28s} app {b:>5} -> {a:>5}  red {red:6.1f}%")
vals.sort()
import numpy as np
print("\nn =", len(vals), " median all =", np.median(vals))
print("sorted:", [round(v, 1) for v in vals])
