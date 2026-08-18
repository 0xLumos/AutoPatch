#!/usr/bin/env python3
"""Table II + comparison/severity figures on the GATE basis.

The live gate is count-strict over the applicable finding set
(--applicability default = kernel-space + no-fix excluded). Raw totals
are reported alongside for the divergence footnote. Baseline strategies
(Copacetic, naive) are re-evaluated through the actual
check_acceptance_criteria implementation so all rows share one gate.
AutoPatch admits are the pipeline's real decisions (exit code 0).
"""
import json
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.expanduser("~/AutoPatch"))
from src import vulnerability_index as vi          # noqa: E402
from src.applicability import (                     # noqa: E402
    ApplicabilityPolicy, partition_applicable)
from src.comparer import check_acceptance_criteria  # noqa: E402

R = os.path.expanduser("~/AutoPatch/results")
CAS = f"{R}/ab2yr_cascade_20260812_001147"
COPA = f"{R}/copa_20260812_175331"
NAIVE = f"{R}/naive_20260812_175330"
OUT = f"{R}/styled"
POLICY = ApplicabilityPolicy.with_no_fix()

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


def load(p):
    try:
        return json.load(open(p))
    except Exception:
        return None


def counts(scan):
    """(crit, high, total) on applicable and raw bases."""
    recs = vi.extract_records(scan)
    app, _ = partition_applicable(recs, POLICY, kev_set=set())

    def trio(rs):
        c = sum(1 for r in rs if (r.severity or "").upper() == "CRITICAL")
        h = sum(1 for r in rs if (r.severity or "").upper() == "HIGH")
        return c, h, len(rs)
    return trio(app), trio(recs)


def gate(before, after):
    ok, _ = check_acceptance_criteria(
        before, after, threshold="count-strict",
        applicability_policy=POLICY, demote_local_av=False,
        require_runtime_ok=False)
    return ok


series = {}


def resolve_after_scan(img):
    """The accepted candidate's scan. When a cascade strategy wins,
    trivy-after.json is stale (the rejected base-swap candidate);
    the winner's scan lives in trivy-cascade-<strategy>.json. Match
    report.json's authoritative total_after to pick the right file.
    """
    import glob as _g
    d = f"{CAS}/{img}/armA"
    rep = load(f"{d}/report.json")
    want = (rep or {}).get("metrics", {}).get("total_after")
    cands = [f"{d}/trivy-after.json"] + sorted(
        _g.glob(f"{d}/trivy-cascade-*.json"))
    fallback = None
    for p in cands:
        s = load(p)
        if not s:
            continue
        if fallback is None:
            fallback = (p, s)
        if want is not None and len(vi.extract_records(s)) == want:
            return p, s
    return fallback if fallback else (None, None)


# AutoPatch: pipeline's real decisions
ap = {}
for r in rows(f"{CAS}/results.jsonl"):
    img = r["image"]
    if r["exit_code"] != 0:
        ap[img] = {"acc": False, "red": 0.0}
        continue
    b = load(f"{CAS}/{img}/armA/trivy-before.json")
    apath, a = resolve_after_scan(img)
    if apath and not apath.endswith("trivy-after.json"):
        print(f"[cascade-winner scan] {img}: {os.path.basename(apath)}")
    if not b or not a:
        ap[img] = {"acc": False, "red": 0.0}
        continue
    (bc, bh, bt), (rbc, rbh, rbt) = counts(b)
    (ac_, ah, at), (rac, rah, rat) = counts(a)
    ap[img] = {"acc": True,
               "red": 100.0 * (1 - at / bt) if bt else 0.0,
               "app_b": (bc, bh, bt), "app_a": (ac_, ah, at),
               "raw_b": (rbc, rbh, rbt), "raw_a": (rac, rah, rat)}
series["autopatch"] = ap


def baseline(d):
    out = {}
    for r in rows(f"{d}/results.jsonl"):
        img = r["image"]
        b = load(f"{d}/{img}/trivy-before.json")
        a = load(f"{d}/{img}/trivy-after.json")
        if not b or not a:
            out[img] = {"acc": False, "red": 0.0}
            continue
        (bc, bh, bt), rawb = counts(b)
        (ac_, ah, at), rawa = counts(a)
        acc = gate(b, a)
        out[img] = {"acc": acc,
                    "red": (100.0 * (1 - at / bt) if bt else 0.0)
                    if acc else 0.0,
                    "app_b": (bc, bh, bt), "app_a": (ac_, ah, at),
                    "raw_b": rawb, "raw_a": rawa}
        if not acc:
            out[img]["red"] = 0.0
    # images missing from the dir entirely default to non-accepted
    for img in series["autopatch"]:
        out.setdefault(img, {"acc": False, "red": 0.0})
    return out


series["copacetic"] = baseline(COPA)
series["naive"] = baseline(NAIVE)
series["scout"] = {img: {"acc": False, "red": 0.0}
                   for img in series["autopatch"]}
n = len(series["autopatch"])


def stats(sr):
    accs = [v["red"] for v in sr.values() if v["acc"]]
    alls = [v["red"] if v["acc"] else 0.0 for v in sr.values()]
    if not accs:
        return dict(n_acc=0, med_acc=None, mean_acc=None,
                    med_all=float(np.median(alls)), agg=None,
                    agg_raw=None)
    ab = sum(v["app_b"][2] for v in sr.values() if v["acc"])
    aa = sum(v["app_a"][2] for v in sr.values() if v["acc"])
    rb = sum(v["raw_b"][2] for v in sr.values() if v["acc"])
    ra = sum(v["raw_a"][2] for v in sr.values() if v["acc"])
    return dict(n_acc=len(accs), med_acc=float(np.median(accs)),
                mean_acc=float(np.mean(accs)),
                med_all=float(np.median(alls)),
                agg=100.0 * (1 - aa / ab),
                agg_raw=100.0 * (1 - ra / rb),
                app_before=ab, app_after=aa,
                raw_before=rb, raw_after=ra)


tbl = {k: stats(v) for k, v in series.items()}
tbl["n"] = n
json.dump(tbl, open(f"{OUT}/table2_applicable.json", "w"), indent=1)

print(f"===== TABLE II (gate basis: applicable set, gated, n={n}) =====")
for k in ("scout", "naive", "copacetic", "autopatch"):
    s = tbl[k]
    def f(x):
        return "--" if x is None else f"{x:.1f}"
    print(f"{k:10s} acc {s['n_acc']}/{n}  medAcc {f(s['med_acc'])}  "
          f"meanAcc {f(s['mean_acc'])}  medAll {f(s['med_all'])}  "
          f"agg {f(s['agg'])}  (raw agg {f(s.get('agg_raw'))})")

# severity aggregates over AutoPatch admits, applicable basis
adm = [(i, v) for i, v in ap.items() if v["acc"]]
Bc = sum(v["app_b"][0] for _, v in adm)
Bh = sum(v["app_b"][1] for _, v in adm)
Bt = sum(v["app_b"][2] for _, v in adm)
Ac = sum(v["app_a"][0] for _, v in adm)
Ah = sum(v["app_a"][1] for _, v in adm)
At = sum(v["app_a"][2] for _, v in adm)
print(f"admits severity (applicable): Crit {Bc}->{Ac}, High {Bh}->{Ah}, "
      f"Total {Bt}->{At}")

# ── figS1: comparison survival curves (gate basis) ──────────────────
xs = np.arange(0, 101, 5)


def surv(sr):
    vals = [v["red"] if v["acc"] else 0.0 for v in sr.values()]
    return [100.0 * sum(x0 > x for x0 in vals) / len(vals) for x in xs]


fig, ax = plt.subplots(figsize=(3.6, 2.9))
for key, lab, col, mk in (
        ("autopatch", "AutoPatch", C_GOLD, "^"),
        ("copacetic", "Copacetic", C_PURP, "v"),
        ("naive", "Naive :latest", C_OLIVE, "s"),
        ("scout", "Docker Scout (advisory)", C_CYAN, "o")):
    ax.plot(xs, surv(series[key]), color=col, marker=mk, linewidth=1.5,
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

# ── figS3: per-image severity reduction, admits, applicable basis ───
adm.sort(key=lambda kv: -kv[1]["red"])
names = [i.replace("@", " ") for i, _ in adm]
crit_r, high_r, tot_r = [], [], []
for i, v in adm:
    b, a = v["app_b"], v["app_a"]
    crit_r.append(100 * (1 - a[0] / b[0]) if b[0] else np.nan)
    high_r.append(100 * (1 - a[1] / b[1]) if b[1] else np.nan)
    tot_r.append(v["red"])
x = np.arange(len(adm))
fig, ax = plt.subplots(figsize=(7.0, 2.7))
ax.bar(x - 0.27, crit_r, 0.27, label="Critical", color=C_PURP,
       edgecolor="white", linewidth=0.3)
ax.bar(x, high_r, 0.27, label="High", color=C_GOLD,
       edgecolor="white", linewidth=0.3)
ax.bar(x + 0.27, tot_r, 0.27, label="Total", color=C_CYAN,
       edgecolor="white", linewidth=0.3)
ax.set_xticks(x)
ax.set_xticklabels(names, rotation=45, ha="right", fontsize=6.0)
ax.set_ylabel("Reduction, applicable set (%)", fontsize=8.5)
ax.tick_params(axis="y", labelsize=8)
ax.legend(fontsize=7, loc="upper right", ncol=3, borderpad=0.4)
ax.set_axisbelow(True)
fig.tight_layout(pad=0.4)
fig.savefig(f"{OUT}/figS3_severity_perimage.pdf")
fig.savefig(f"{OUT}/figS3_severity_perimage.png", dpi=220)

# ── figS5: aggregate severity before/after, applicable basis ────────
fig, ax = plt.subplots(figsize=(3.6, 2.9))
x = np.arange(3)
w = 0.36
ax.bar(x - w / 2, [Bc, Bh, Bt], w, label="Before", color=C_PURP,
       edgecolor="white")
ax.bar(x + w / 2, [Ac, Ah, At], w, label="After", color=C_CYAN,
       edgecolor="white")
for i in range(3):
    ax.text(x[i] - w / 2, [Bc, Bh, Bt][i], str([Bc, Bh, Bt][i]),
            ha="center", va="bottom", fontsize=7)
    ax.text(x[i] + w / 2, [Ac, Ah, At][i], str([Ac, Ah, At][i]),
            ha="center", va="bottom", fontsize=7)
ax.set_xticks(x)
ax.set_xticklabels(["Critical", "High", "Total"], fontsize=8.5)
ax.set_ylabel("Applicable findings (log scale)", fontsize=8.5)
ax.set_yscale("log")
ax.tick_params(axis="y", labelsize=8)
ax.legend(fontsize=7.2, loc="upper left", borderpad=0.4)
ax.set_axisbelow(True)
fig.tight_layout(pad=0.4)
fig.savefig(f"{OUT}/figS5_severity_aggregate.pdf")
fig.savefig(f"{OUT}/figS5_severity_aggregate.png", dpi=220)

print("saved figS1/figS3/figS5 (gate basis) to", OUT)
