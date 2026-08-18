#!/usr/bin/env python3
"""Table II (strategy comparison) + all paper figures in the clean
curve style of the professor's sample: serif fonts, boxed axes, light
grid, marker curves, compact framed legend.

Everything is computed from persisted raw data on one consistent basis:
raw Trivy totals per image, gated (non-accepted = 0%) over the n=39
corpus. Outputs land in ~/AutoPatch/results/styled/.
"""
import json
import os
import re
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

R = os.path.expanduser("~/AutoPatch/results")
CAS = f"{R}/ab2yr_bestk_20260813_030142"
BASE = f"{R}/ab2yr_base_20260811_221744"
COPA = f"{R}/copa_20260812_175331"
NAIVE = f"{R}/naive_20260812_175330"
SCREEN = os.path.expanduser("~/AutoPatch/screened_2yr")
OUT = f"{R}/styled"
os.makedirs(OUT, exist_ok=True)

# ── sample style ────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Liberation Serif", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    "axes.grid": True,
    "grid.color": "#d9d9d9",
    "grid.linewidth": 0.6,
    "axes.linewidth": 0.8,
    "axes.edgecolor": "#444444",
    "legend.frameon": True,
    "legend.edgecolor": "#999999",
    "legend.framealpha": 1.0,
})
C_CYAN, C_OLIVE, C_PURP, C_GOLD = "#4DBEEE", "#AFA83B", "#B05CD8", "#E8A33C"
MK = dict(markerfacecolor="white", markeredgewidth=1.1, markersize=4.5)


def rows(p):
    return [json.loads(l) for l in open(p) if l.strip()]


def sev(p):
    try:
        d = json.load(open(p))
    except Exception:
        return None
    c = h = t = 0
    for r0 in (d.get("Results") or []):
        for v in (r0.get("Vulnerabilities") or []):
            t += 1
            s = (v.get("Severity") or "").upper()
            c += s == "CRITICAL"
            h += s == "HIGH"
    return c, h, t


# ── gated per-image reductions, raw-total basis ─────────────────────
def autopatch_series(batch):
    out = {}
    for r in rows(f"{batch}/results.jsonl"):
        img = r["image"]
        if r["exit_code"] != 0:
            out[img] = {"acc": False, "red": 0.0}
            continue
        b = sev(f"{batch}/{img}/armA/trivy-before.json")
        a = sev(f"{batch}/{img}/armA/trivy-after.json")
        if not b or a is None or b[2] == 0:
            out[img] = {"acc": False, "red": 0.0}
            continue
        out[img] = {"acc": True, "red": 100.0 * (1 - a[2] / b[2]),
                    "b": b, "a": a}
    return out


def baseline_series(d):
    out = {}
    for r in rows(f"{d}/results.jsonl"):
        img = r["image"]
        if r.get("status") == "accepted" and r.get("before"):
            out[img] = {"acc": True,
                        "red": 100.0 * (1 - r["after"] / r["before"]),
                        "b": (None, None, r["before"]),
                        "a": (None, None, r["after"])}
        else:
            out[img] = {"acc": False, "red": 0.0}
    return out


ap = autopatch_series(CAS)
cp = baseline_series(COPA)
nv = baseline_series(NAIVE)
n = len(ap)
sc = {img: {"acc": False, "red": 0.0} for img in ap}   # scout: advisory


def stats(series):
    accs = [v["red"] for v in series.values() if v["acc"]]
    alls = [v["red"] if v["acc"] else 0.0 for v in series.values()]
    if not accs:
        return dict(n_acc=0, med_acc=None, mean_acc=None,
                    med_all=float(np.median(alls)), agg=None)
    sb = sum(v["b"][2] for v in series.values() if v["acc"])
    sa = sum(v["a"][2] for v in series.values() if v["acc"])
    return dict(n_acc=len(accs),
                med_acc=float(np.median(accs)),
                mean_acc=float(np.mean(accs)),
                med_all=float(np.median(alls)),
                agg=100.0 * (1 - sa / sb),
                sum_before=sb, sum_after=sa)


tbl = {"n": n,
       "autopatch": stats(ap), "copacetic": stats(cp),
       "naive": stats(nv),
       "scout": dict(n_acc=0, med_acc=None, mean_acc=None,
                     med_all=0.0, agg=None)}
json.dump(tbl, open(f"{OUT}/table2.json", "w"), indent=1)

print("===== TABLE II (raw-total basis, gated, n=%d) =====" % n)
for k in ("scout", "naive", "copacetic", "autopatch"):
    s = tbl[k]
    def f(x):
        return "--" if x is None else f"{x:.1f}"
    print(f"{k:10s} acc {s['n_acc']}/{n}  medAcc {f(s['med_acc'])}  "
          f"meanAcc {f(s['mean_acc'])}  medAll {f(s['med_all'])}  "
          f"agg {f(s['agg'])}")
neg_admits = [(i, round(v["red"], 1)) for i, v in ap.items()
              if v["acc"] and v["red"] <= 0]
print("autopatch admits with non-positive raw reduction:", neg_admits)

# ── Fig 1: comparison survival curves ───────────────────────────────
xs = np.arange(0, 101, 5)


def surv(series):
    vals = [v["red"] if v["acc"] else 0.0 for v in series.values()]
    return [100.0 * sum(v > x for v in vals) / len(vals) for x in xs]


fig, ax = plt.subplots(figsize=(3.6, 2.9))
for series, lab, col, mk in (
        (ap, "AutoPatch", C_GOLD, "^"),
        (cp, "Copacetic", C_PURP, "v"),
        (nv, "Naive :latest", C_OLIVE, "s"),
        (sc, "Docker Scout (advisory)", C_CYAN, "o")):
    ax.plot(xs, surv(series), color=col, marker=mk, linewidth=1.5,
            label=lab, **MK)
ax.set_xlabel("Vulnerability-count reduction threshold $x$ (%)",
              fontsize=8.5)
ax.set_ylabel("Images with reduction $>x$ (%)", fontsize=8.5)
ax.set_xlim(0, 100)
ax.set_ylim(0, 70)
ax.tick_params(labelsize=8)
ax.legend(fontsize=6.6, loc="upper right", borderpad=0.4,
          labelspacing=0.3, handlelength=1.8)
fig.tight_layout(pad=0.4)
fig.savefig(f"{OUT}/figS1_comparison.pdf")
fig.savefig(f"{OUT}/figS1_comparison.png", dpi=220)

# ── Fig 2: admission across policy ladder ───────────────────────────
sweep = json.load(open(f"{CAS}/policy_sweep.json"))["admit_rate"]["ALL"]
crits = ["identity-strict", "count-strict", "moderate"]
pols = [("literal", C_CYAN, "o"), ("kernel-only", C_PURP, "s"),
        ("default", C_GOLD, "^")]
fig, ax = plt.subplots(figsize=(3.6, 2.9))
for pol, col, mk in pols:
    ys = []
    for c in crits:
        m = re.match(r"(\d+)/(\d+)", sweep[c][pol])
        ys.append(100.0 * int(m.group(1)) / int(m.group(2)))
    ax.plot(range(len(crits)), ys, color=col, marker=mk, linewidth=1.5,
            label=f"applicability: {pol}", **MK)
ax.set_xticks(range(len(crits)))
ax.set_xticklabels(["identity-\nstrict", "count-\nstrict", "moderate"],
                   fontsize=8)
ax.set_ylabel("Admission rate (%)", fontsize=8.5)
ax.set_xlabel("Acceptance criterion", fontsize=8.5)
ax.tick_params(labelsize=8)
ax.legend(fontsize=6.8, loc="lower right", borderpad=0.4,
          labelspacing=0.3)
fig.tight_layout(pad=0.4)
fig.savefig(f"{OUT}/figS2_admission.pdf")
fig.savefig(f"{OUT}/figS2_admission.png", dpi=220)

# ── Fig 3: per-image severity reduction (admits, bars restyled) ─────
admits = [(i, v) for i, v in ap.items() if v["acc"] and v["red"] > 0]
admits.sort(key=lambda kv: -kv[1]["red"])
names = [i.split("@")[0] for i, _ in admits]
crit_r, high_r, tot_r = [], [], []
for i, v in admits:
    b, a = v["b"], v["a"]
    crit_r.append(100 * (1 - a[0] / b[0]) if b[0] else np.nan)
    high_r.append(100 * (1 - a[1] / b[1]) if b[1] else np.nan)
    tot_r.append(v["red"])
x = np.arange(len(admits))
fig, ax = plt.subplots(figsize=(7.0, 2.7))
ax.bar(x - 0.27, crit_r, 0.27, label="Critical", color=C_PURP,
       edgecolor="white", linewidth=0.3)
ax.bar(x, high_r, 0.27, label="High", color=C_GOLD,
       edgecolor="white", linewidth=0.3)
ax.bar(x + 0.27, tot_r, 0.27, label="Total", color=C_CYAN,
       edgecolor="white", linewidth=0.3)
ax.set_xticks(x)
ax.set_xticklabels(names, rotation=45, ha="right", fontsize=6.6)
ax.set_ylabel("Reduction (%)", fontsize=8.5)
ax.tick_params(axis="y", labelsize=8)
ax.legend(fontsize=7, loc="upper right", ncol=3, borderpad=0.4)
ax.set_axisbelow(True)
fig.tight_layout(pad=0.4)
fig.savefig(f"{OUT}/figS3_severity_perimage.pdf")
fig.savefig(f"{OUT}/figS3_severity_perimage.png", dpi=220)

# ── Fig 4: attrition / non-admission (restyled bars) ────────────────
state = json.load(open(f"{SCREEN}/state.json"))["screened"]
scr = Counter(r.get("reason") or "survivor (pass)" for r in state.values())
scr = {("survivor (pass)" if k == "pass" else k): v for k, v in scr.items()}
batch_fail = Counter()
for r in rows(f"{CAS}/results.jsonl"):
    if r["exit_code"] != 0:
        b = sev(f"{CAS}/{r['image']}/armA/trivy-before.json")
        a = sev(f"{CAS}/{r['image']}/armA/trivy-after.json")
        if b is None:
            batch_fail["patched build failed"] += 1
        elif a and b[2] <= a[2]:
            batch_fail["no strict reduction"] += 1
        else:
            batch_fail["gate rejected"] += 1
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.6))
k1 = sorted(scr, key=lambda k: -scr[k])
ax1.barh(k1, [scr[k] for k in k1], color=C_CYAN, edgecolor="#444",
         linewidth=0.4)
for i, k in enumerate(k1):
    ax1.text(scr[k] + 1.2, i, str(scr[k]), va="center", fontsize=7.5)
ax1.set_title("Screening outcomes", fontsize=9)
ax1.invert_yaxis()
k2 = sorted(batch_fail, key=lambda k: -batch_fail[k])
ax2.barh(k2, [batch_fail[k] for k in k2], color=C_GOLD,
         edgecolor="#444", linewidth=0.4)
for i, k in enumerate(k2):
    ax2.text(batch_fail[k] + 0.12, i, str(batch_fail[k]), va="center",
             fontsize=7.5)
ax2.set_title("Non-admission reasons", fontsize=9)
ax2.invert_yaxis()
for a0 in (ax1, ax2):
    a0.tick_params(labelsize=7.5)
    a0.set_axisbelow(True)
    a0.grid(axis="y", visible=False)
fig.tight_layout(pad=0.6)
fig.savefig(f"{OUT}/figS4_attrition.pdf")
fig.savefig(f"{OUT}/figS4_attrition.png", dpi=220)

# ── Fig 5: aggregate severity before/after (restyled) ───────────────
tc = th = tt = ac2 = ah = at = 0
for i, v in admits:
    b, a = v["b"], v["a"]
    tc += b[0]; th += b[1]; tt += b[2]
    ac2 += a[0]; ah += a[1]; at += a[2]
fig, ax = plt.subplots(figsize=(3.6, 2.9))
x = np.arange(3)
w = 0.36
ax.bar(x - w / 2, [tc, th, tt], w, label="Before", color=C_PURP,
       edgecolor="white")
ax.bar(x + w / 2, [ac2, ah, at], w, label="After", color=C_CYAN,
       edgecolor="white")
for i in range(3):
    ax.text(x[i] - w / 2, [tc, th, tt][i], str([tc, th, tt][i]),
            ha="center", va="bottom", fontsize=7)
    ax.text(x[i] + w / 2, [ac2, ah, at][i], str([ac2, ah, at][i]),
            ha="center", va="bottom", fontsize=7)
ax.set_xticks(x)
ax.set_xticklabels(["Critical", "High", "Total"], fontsize=8.5)
ax.set_ylabel("Reported findings (log scale)", fontsize=8.5)
ax.set_yscale("log")
ax.tick_params(axis="y", labelsize=8)
ax.legend(fontsize=7.2, loc="upper left", borderpad=0.4)
ax.set_axisbelow(True)
fig.tight_layout(pad=0.4)
fig.savefig(f"{OUT}/figS5_severity_aggregate.pdf")
fig.savefig(f"{OUT}/figS5_severity_aggregate.png", dpi=220)

# ── Fig 6: processing-time CDF curves ───────────────────────────────
bt = sorted(r["wall_seconds"] for r in rows(f"{BASE}/results.jsonl")
            if r.get("wall_seconds"))
ct = sorted(r["wall_seconds"] for r in rows(f"{CAS}/results.jsonl")
            if r.get("wall_seconds"))
fig, ax = plt.subplots(figsize=(3.6, 2.9))
for vals, lab, col, mk in ((bt, "Base swap", C_CYAN, "o"),
                           (ct, "With cascade", C_GOLD, "^")):
    ys = 100.0 * np.arange(1, len(vals) + 1) / len(vals)
    ax.plot(vals, ys, color=col, marker=mk, linewidth=1.5, label=lab,
            markevery=3, **MK)
ax.set_xlabel("End-to-end processing time per image (s)", fontsize=8.5)
ax.set_ylabel("Images processed within $t$ (%)", fontsize=8.5)
ax.set_ylim(0, 102)
ax.tick_params(labelsize=8)
ax.legend(fontsize=7.2, loc="lower right", borderpad=0.4)
fig.tight_layout(pad=0.4)
fig.savefig(f"{OUT}/figS6_processing_time.pdf")
fig.savefig(f"{OUT}/figS6_processing_time.png", dpi=220)

print("saved styled figs to", OUT)
