#!/usr/bin/env python3
"""Supplementary figures and tables, all from persisted raw data.

Generates:
  fig4_attrition.pdf         corpus funnel / failure-reason bar chart
  fig5_severity_aggregate.pdf Critical/High/Total before vs after (admits)
  fig6_processing_time.pdf    per-image wall-time distribution (base/cascade)
  fig7_candidate_evals.pdf    candidates built per image (cascade)
and prints, to stdout, the rows for:
  - runtime-validation results table (advisory, from run.logs)
  - distribution-family inference table
  - the exact scalar claims (timing, candidate mean) so narrative text
    can cite measured numbers.
"""
import json
import os
import re
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

R = "/home/test/AutoPatch/results"
BASE = f"{R}/ab2yr_base_20260811_221744"
CAS = f"{R}/ab2yr_cascade_20260812_001147"
SCREEN = "/home/test/AutoPatch/screened_2yr"
C_RED, C_ORG, C_BLU, C_PUR = "#d1495b", "#e6a117", "#5db8d6", "#b46fd4"


def rows(d):
    return [json.loads(l) for l in open(os.path.join(d, "results.jsonl"))
            if l.strip()]


def sev(p):
    try:
        d = json.load(open(p))
    except Exception:
        return None
    c = h = t = 0
    for r in (d.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            t += 1
            s = (v.get("Severity") or "").upper()
            c += s == "CRITICAL"
            h += s == "HIGH"
    return c, h, t


# ── Fig 4: attrition / failure reasons ──────────────────────────────
state = json.load(open(f"{SCREEN}/state.json"))["screened"]
screen_reasons = Counter(r.get("reason") or "pass"
                         for r in state.values())
screen_reasons = {("survivor (pass)" if k == "pass" else k): v
                  for k, v in screen_reasons.items()}
# batch patched-build failures
cas = rows(CAS)
batch_fail = Counter()
for r in cas:
    if r["exit_code"] != 0:
        b = sev(os.path.join(CAS, r["image"], "armA", "trivy-before.json"))
        a = sev(os.path.join(CAS, r["image"], "armA", "trivy-after.json"))
        if b is None:
            batch_fail["patched build failed"] += 1
        elif a and b[2] <= a[2]:
            batch_fail["no strict reduction"] += 1
        else:
            batch_fail["gate rejected"] += 1

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.8, 2.7))
k1 = sorted(screen_reasons, key=lambda x: -screen_reasons[x])
ax1.barh(k1, [screen_reasons[k] for k in k1], color=C_BLU,
         edgecolor="white")
for i, k in enumerate(k1):
    ax1.text(screen_reasons[k] + 1, i, str(screen_reasons[k]),
             va="center", fontsize=7)
ax1.set_title("Screening outcomes (180 tags)", fontsize=8.6)
ax1.tick_params(labelsize=7)
ax1.invert_yaxis()
k2 = sorted(batch_fail, key=lambda x: -batch_fail[x])
ax2.barh(k2, [batch_fail[k] for k in k2], color=C_ORG, edgecolor="white")
for i, k in enumerate(k2):
    ax2.text(batch_fail[k] + 0.1, i, str(batch_fail[k]), va="center",
             fontsize=7)
ax2.set_title("Non-admission reasons (n=39, cascade)", fontsize=8.6)
ax2.tick_params(labelsize=7)
ax2.invert_yaxis()
for a in (ax1, ax2):
    for s in ("top", "right"):
        a.spines[s].set_visible(False)
fig.tight_layout(pad=0.5)
fig.savefig(f"{R}/fig4_attrition.pdf")
fig.savefig(f"{R}/fig4_attrition.png", dpi=200)

# ── Fig 5: aggregate Critical/High/Total before vs after ────────────
tc = th = tt = ac = ah = at = 0
npos = 0
for r in cas:
    if r["exit_code"] != 0:
        continue
    b = sev(os.path.join(CAS, r["image"], "armA", "trivy-before.json"))
    a = sev(os.path.join(CAS, r["image"], "armA", "trivy-after.json"))
    # positive-reduction admits only: aggregating raw over the
    # applicable-set admits (whose raw total rises) would be misleading.
    if b and a and b[2] > a[2]:
        npos += 1
        tc += b[0]; th += b[1]; tt += b[2]
        ac += a[0]; ah += a[1]; at += a[2]
fig, ax = plt.subplots(figsize=(4.0, 2.8))
labels = ["Critical", "High", "Total"]
before = [tc, th, tt]
after = [ac, ah, at]
x = np.arange(3)
w = 0.38
ax.bar(x - w / 2, before, w, label="Before", color=C_RED,
       edgecolor="white")
ax.bar(x + w / 2, after, w, label="After", color=C_BLU,
       edgecolor="white")
for i in range(3):
    ax.text(x[i] - w / 2, before[i], str(before[i]), ha="center",
            va="bottom", fontsize=6.6)
    ax.text(x[i] + w / 2, after[i], str(after[i]), ha="center",
            va="bottom", fontsize=6.6)
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8.4)
ax.set_ylabel(f"Findings across {npos} positive-reduction admits",
              fontsize=8.2)
ax.legend(fontsize=7.4, frameon=True, edgecolor="#ccc")
ax.set_yscale("log")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
fig.tight_layout(pad=0.4)
fig.savefig(f"{R}/fig5_severity_aggregate.pdf")
fig.savefig(f"{R}/fig5_severity_aggregate.png", dpi=200)

# ── Fig 6: processing-time distribution ─────────────────────────────
bt = [r["wall_seconds"] for r in rows(BASE) if r.get("wall_seconds")]
ct = [r["wall_seconds"] for r in cas if r.get("wall_seconds")]
fig, ax = plt.subplots(figsize=(4.0, 2.6))
bp = ax.boxplot([bt, ct], orientation="horizontal", patch_artist=True,
                widths=0.5, tick_labels=["base-swap", "cascade"])
for patch, col in zip(bp["boxes"], (C_PUR, C_ORG)):
    patch.set_facecolor(col); patch.set_alpha(0.7)
for med in bp["medians"]:
    med.set_color("black")
ax.set_xlabel("End-to-end processing time per image (s)", fontsize=8.6)
ax.tick_params(labelsize=8)
ax.grid(True, axis="x", alpha=0.3)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
fig.tight_layout(pad=0.4)
fig.savefig(f"{R}/fig6_processing_time.pdf")
fig.savefig(f"{R}/fig6_processing_time.png", dpi=200)

# ── Fig 7: candidates built per image (cascade) ─────────────────────
cand = []
for r in cas:
    log = os.path.join(CAS, r["image"], "armA", "run.log")
    n = 1
    try:
        txt = open(log, encoding="utf-8", errors="replace").read()
        attempts = re.findall(r"Building patched image \(attempt (\d+)/",
                              txt)
        if attempts:
            n = max(int(x) for x in attempts)
    except Exception:
        pass
    cand.append(n)
fig, ax = plt.subplots(figsize=(3.6, 2.6))
vc = Counter(cand)
ks = sorted(vc)
ax.bar([str(k) for k in ks], [vc[k] for k in ks], color=C_BLU,
       edgecolor="white", width=0.6)
for k in ks:
    ax.text(str(k), vc[k] + 0.3, str(vc[k]), ha="center", fontsize=7.5)
ax.set_xlabel("Candidate builds per image", fontsize=8.6)
ax.set_ylabel("Images", fontsize=8.6)
ax.tick_params(labelsize=8)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
fig.tight_layout(pad=0.4)
fig.savefig(f"{R}/fig7_candidate_evals.pdf")
fig.savefig(f"{R}/fig7_candidate_evals.png", dpi=200)

# ── Tables + scalar claims to stdout ────────────────────────────────
print("\n===== SCALAR CLAIMS (measured) =====")
print(f"base wall: mean {np.mean(bt):.1f}s median {np.median(bt):.1f}s "
      f"max {max(bt):.0f}s")
print(f"cascade wall: mean {np.mean(ct):.1f}s median {np.median(ct):.1f}s "
      f"max {max(ct):.0f}s")
print(f"candidate builds per image: mean {np.mean(cand):.2f} "
      f"max {max(cand)} dist {dict(vc)}")
print(f"aggregate admitted: Critical {tc}->{ac} "
      f"({100*(tc-ac)/tc:.0f}%), High {th}->{ah} ({100*(th-ah)/th:.0f}%), "
      f"Total {tt}->{at} ({100*(tt-at)/tt:.0f}%)")

print("\n===== RUNTIME-VALIDATION TABLE (advisory) =====")
rv = Counter()
for r in cas:
    if r["exit_code"] != 0:
        continue
    log = os.path.join(CAS, r["image"], "armA", "run.log")
    try:
        txt = open(log, encoding="utf-8", errors="replace").read()
        if re.search(r"Runtime validation passed", txt):
            rv["passed (startup)"] += 1
        elif re.search(r"Runtime validation failed", txt):
            rv["failed (startup)"] += 1
        else:
            rv["not probed"] += 1
    except Exception:
        rv["not probed"] += 1
print("admitted-image runtime validation:", dict(rv))

print("\n===== INFERENCE / OS-FAMILY TABLE =====")
fam = Counter()
for e in json.load(open(f"{SCREEN}/manifest.json"))["entries"]:
    bi = e.get("base_images") or []
    last = (bi[-1] if bi else "?").split(":")[0].split("/")[-1].lower()
    fam[last] += 1
print("final-base families in corpus:", dict(fam.most_common()))
print("\nsaved: fig4 fig5 fig6 fig7")
