#!/usr/bin/env python3
"""Bare-OS controlled-corpus table: per image, base change, applicable
and raw before/after, decision with reason. Same gate basis as
Table II.
"""
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.expanduser("~/AutoPatch"))
from src import vulnerability_index as vi
from src.applicability import ApplicabilityPolicy, partition_applicable

B = os.path.expanduser("~/AutoPatch/results/bareos_20260812_005804")
POLICY = ApplicabilityPolicy.with_no_fix()


def load(p):
    try:
        return json.load(open(p))
    except Exception:
        return None


def app_total(scan):
    if not scan:
        return None
    recs = vi.extract_records(scan)
    app, _ = partition_applicable(recs, POLICY, kev_set=set())
    return len(app), len(recs)


rows = [json.loads(l) for l in open(f"{B}/results.jsonl") if l.strip()]
out = []
for r in rows:
    img = r["image"]
    d = f"{B}/{img}/armA"
    b = load(f"{d}/trivy-before.json")
    ab = app_total(b)
    acc = r["exit_code"] == 0
    entry = {"image": img, "accepted": acc,
             "app_before": ab[0] if ab else None,
             "raw_before": ab[1] if ab else None}
    if acc:
        rep = r.get("report") or load(f"{d}/report.json") or {}
        bic = rep.get("base_image_changes") or []
        entry["from"] = bic[0]["original"] if bic else "?"
        entry["to"] = bic[0]["new"] if bic else "?"
        want = rep.get("metrics", {}).get("total_after")
        cands = [f"{d}/trivy-after.json"] + sorted(
            glob.glob(f"{d}/trivy-cascade-*.json"))
        a = None
        for p in cands:
            s = load(p)
            if not s:
                continue
            if a is None:
                a = s
            if want is not None and len(vi.extract_records(s)) == want:
                a = s
                break
        aa = app_total(a)
        entry["app_after"] = aa[0] if aa else None
        entry["raw_after"] = aa[1] if aa else None
    else:
        # decline reason from run.log
        reason = "?"
        try:
            log = open(f"{d}/run.log", encoding="utf-8",
                       errors="replace").read()
            errs = re.findall(r"\[ERROR\] \[EVAL\]\s+- (.+)", log)
            if errs:
                reason = "; ".join(sorted(set(e.strip() for e in errs)))
            elif re.search(r"No eligible candidate|no successor|"
                           r"NoEligibleCandidate", log, re.I):
                reason = "no eligible successor"
            elif re.search(r"already.*(clean|0 vulnerabilities)|"
                           r"zero.CVE", log, re.I):
                reason = "already clean"
            elif re.search(r"LowConfidence", log):
                reason = "low confidence"
            else:
                tail = [l for l in log.splitlines()
                        if "[ERROR]" in l][-3:]
                reason = " | ".join(tail) if tail else "see log"
        except Exception:
            pass
        entry["reason"] = reason[:180]
    out.append(entry)

for e in out:
    if e["accepted"]:
        ar = (100.0 * (1 - e["app_after"] / e["app_before"])
              if e["app_before"] else None)
        rr = (100.0 * (1 - e["raw_after"] / e["raw_before"])
              if e["raw_before"] else None)
        print(f"ACCEPT  {e['image']:20s} {e.get('from','?'):16s}->"
              f" {e.get('to','?'):16s} app {e['app_before']}->"
              f"{e['app_after']}"
              f" ({ar:.0f}%)" if ar is not None else "", end="")
        if rr is not None:
            print(f"  raw {e['raw_before']}->{e['raw_after']} ({rr:.0f}%)")
        else:
            print()
    else:
        print(f"DECLINE {e['image']:20s} app_before="
              f"{e['app_before']} raw_before={e['raw_before']}")
        print(f"        reason: {e.get('reason')}")
json.dump(out, open(f"{B}/bareos_table.json", "w"), indent=1)
print("\nwrote", f"{B}/bareos_table.json")
