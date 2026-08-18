#!/usr/bin/env python3
"""figS4 with log-verified non-admission classification for the final
batch: build failures identified from the runner's own error marker,
already-clean images by their zero-finding before-scan, gate
rejections as the remainder."""
import json
import os
import re
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = os.path.expanduser("~/AutoPatch/results")
CAS = f"{R}/ab2yr_bestk_20260813_030142"
SCREEN = os.path.expanduser("~/AutoPatch/screened_2yr")
OUT = f"{R}/styled"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Liberation Serif", "DejaVu Serif"],
    "axes.grid": True,
    "grid.color": "#d9d9d9",
    "grid.linewidth": 0.6,
    "axes.linewidth": 0.8,
    "axes.edgecolor": "#444444",
})
C_CYAN, C_GOLD = "#4DBEEE", "#E8A33C"

state = json.load(open(f"{SCREEN}/state.json"))["screened"]
_LABELS = {
    "pass": "survivor (evaluated)",
    "original_build_failed": "original build failed",
    "no_headroom": "no remediation headroom",
}
scr = Counter()
for v in state.values():
    r = v.get("reason") or "pass"
    scr[_LABELS.get(r, r)] += 1

fail = Counter()
for rec in [json.loads(l) for l in open(f"{CAS}/results.jsonl")]:
    if rec["exit_code"] == 0:
        continue
    img = rec["image"]
    d = f"{CAS}/{img}/armA"
    try:
        log = open(f"{d}/run.log", encoding="utf-8",
                   errors="replace").read()
    except Exception:
        log = ""
    before = None
    try:
        s = json.load(open(f"{d}/trivy-before.json"))
        before = sum(len(x.get("Vulnerabilities") or [])
                     for x in (s.get("Results") or []))
    except Exception:
        pass
    if re.search(r"All \d+ build attempts failed", log) or \
            not os.path.exists(f"{d}/trivy-after.json"):
        fail["patched build failed"] += 1
    elif before == 0:
        fail["no findings to remediate"] += 1
    else:
        fail["gate rejected"] += 1

print("screening:", dict(scr))
print("non-admission:", dict(fail))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.6))
k1 = sorted(scr, key=lambda k: -scr[k])
ax1.barh(k1, [scr[k] for k in k1], color=C_CYAN, edgecolor="#444",
         linewidth=0.4)
for i, k in enumerate(k1):
    ax1.text(scr[k] + 1.2, i, str(scr[k]), va="center", fontsize=7.5)
ax1.set_title("Screening outcomes (181 tags)", fontsize=9)
ax1.invert_yaxis()
k2 = sorted(fail, key=lambda k: -fail[k])
ax2.barh(k2, [fail[k] for k in k2], color=C_GOLD, edgecolor="#444",
         linewidth=0.4)
for i, k in enumerate(k2):
    ax2.text(fail[k] + 0.12, i, str(fail[k]), va="center", fontsize=7.5)
ax2.set_title("Non-admission reasons (n=39)", fontsize=9)
ax2.invert_yaxis()
for a0 in (ax1, ax2):
    a0.tick_params(labelsize=7.5)
    a0.set_axisbelow(True)
    a0.grid(axis="y", visible=False)
fig.tight_layout(pad=0.6)
fig.savefig(f"{OUT}/figS4_attrition.pdf")
fig.savefig(f"{OUT}/figS4_attrition.png", dpi=220)
print("saved corrected figS4")
