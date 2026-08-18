#!/usr/bin/env python3
"""Fig. 1 (architecture) v2: replaces the old two-panel architecture
figure. Changes against the version circulated on 01/08:

- Stage chain matches the pipeline as implemented: SBOM-driven
  inference and candidate selection appear (they were missing), the
  acceptance gate is its own stage (it was buried inside 'Comparison'),
  and runtime validation is shown before signing (sign-then-validate
  was wrong).
- The gate stage names the actual criterion (count-strict over the
  applicable set, KEV hard block) instead of a generic 'comparison'.
- Decline/rollback is drawn as a first-class outcome; the old figure
  implied every image ends in the registry.
- Vector PDF for the paper plus PNG for slides/Slack.

Run from any cwd:  python3 figures/fig_architecture_v2.py
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

FIGS = Path(__file__).parent

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.08,
})

CORAL  = "#FFC8B4"   # external I/O
TEAL   = "#7CD0BD"   # pipeline stage
BLUE   = "#A8D5E2"   # decision / gate
PURPLE = "#D7BDE2"   # optional
REDD   = "#FFA8A8"   # decline path
BORDER = "#1B1B1B"


def _box(ax, cx, cy, w, h, title, lines, fill, title_fs=8.0, body_fs=6.4):
    ax.add_patch(FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.06",
        facecolor=fill, edgecolor=BORDER, linewidth=1.0, zorder=3))
    if lines:
        ax.text(cx, cy + h / 2 - 0.16, title, ha="center", va="top",
                fontsize=title_fs, fontweight="bold", zorder=4)
        ax.text(cx, cy + h / 2 - 0.40, "\n".join(lines), ha="center",
                va="top", fontsize=body_fs, zorder=4, linespacing=1.25)
    else:
        ax.text(cx, cy, title, ha="center", va="center",
                fontsize=title_fs, fontweight="bold", zorder=4)


def _arrow(ax, p0, p1, label=None, color=BORDER, ls="-", lw=1.1,
           label_dy=0.10, fs=6.4):
    ax.add_patch(FancyArrowPatch(
        p0, p1, arrowstyle="-|>", mutation_scale=9,
        linewidth=lw, linestyle=ls, color=color, zorder=2,
        shrinkA=2, shrinkB=2))
    if label:
        mx, my = (p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2
        ax.text(mx, my + label_dy, label, ha="center", va="bottom",
                fontsize=fs, style="italic", zorder=4)


def render():
    fig_w, fig_h = 10.6, 4.15
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_xlim(0, fig_w)
    ax.set_ylim(0, fig_h)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    # ── Top band: CI/CD context ─────────────────────────────────────
    ty = fig_h - 0.85
    _box(ax, 1.05, ty, 1.6, 0.85, "Git push /\nregistry event", [], CORAL)
    _box(ax, 3.45, ty, 2.1, 0.85, "CI/CD trigger",
         ["GitHub Actions", "(autopatch job)"], TEAL, body_fs=6.8)
    _box(ax, 6.05, ty, 2.3, 0.85, "AutoPatch engine",
         ["src/main.py, one run", "per image"], TEAL, body_fs=6.8)
    _box(ax, 9.15, ty, 2.2, 0.85, "Registry",
         ["ECR / Docker Hub /", "private"], CORAL, body_fs=6.8)

    _arrow(ax, (1.85, ty), (2.40, ty))
    _arrow(ax, (4.50, ty), (4.90, ty))
    _arrow(ax, (7.20, ty), (8.05, ty), label="signed image,\nadmits only",
           fs=6.0, label_dy=0.06)
    # decline outcome from engine
    _box(ax, 6.05, ty - 1.00, 2.3, 0.50, "Decline + rollback manifest",
         [], REDD, title_fs=6.8)
    _arrow(ax, (6.05, ty - 0.43), (6.05, ty - 0.75))
    ax.text(6.28, ty - 0.59, "gate rejects", ha="left", va="center",
            fontsize=5.8, style="italic", zorder=4)

    # ── Bottom band: stage chain inside the engine ──────────────────
    stages = [
        ("Scan #1 + SBOM", [
            "build original image",
            "Trivy scan (baseline)",
            "CycloneDX SBOM"], TEAL),
        ("SBOM inference", [
            "distro family, runtime,",
            "libc (musl/glibc)",
            "confidence score"], TEAL),
        ("Candidate selection", [
            "allow-listed bases",
            "filter: OS, libc, version",
            "rank: recency, safety"], TEAL),
        ("Rewrite + rebuild", [
            "FROM-line only",
            "multi-stage aware",
            "next candidate on fail"], TEAL),
        ("Scan #2 + gate", [
            "Trivy re-scan",
            "count-strict, applicable",
            "set; KEV hard block"], BLUE),
        ("Runtime validation", [
            "container starts",
            "entrypoint probe",
            "app smoke (opt.)"], BLUE),
        ("Sign + publish", [
            "Cosign digest sign",
            "VEX statements",
            "push on admit only"], PURPLE),
    ]
    n = len(stages)
    bw, bh = 1.34, 1.28
    gap = (fig_w - 0.5 - n * bw) / (n - 1)
    by = 0.95
    xs = [0.25 + bw / 2 + i * (bw + gap) for i in range(n)]
    for (title, lines, fill), cx in zip(stages, xs):
        _box(ax, cx, by, bw, bh, title, lines, fill,
             title_fs=6.7, body_fs=5.9)
    for i in range(n - 1):
        _arrow(ax, (xs[i] + bw / 2, by), (xs[i + 1] - bw / 2, by))

    # engine expands into the stage chain
    ax.plot([4.90, 0.25, 0.25], [ty - 0.43, ty - 0.43, by + bh / 2 + 0.25],
            color=BORDER, linewidth=0.8, linestyle=":", zorder=1)
    ax.plot([7.20, fig_w - 0.15, fig_w - 0.15],
            [ty - 0.43, ty - 0.43, by + bh / 2 + 0.25],
            color=BORDER, linewidth=0.8, linestyle=":", zorder=1)
    ax.text(2.55, by + bh / 2 + 0.30,
            "inside the engine (per image)", ha="center", va="bottom",
            fontsize=6.6, style="italic")

    for ext in ("pdf", "png"):
        fig.savefig(FIGS / f"fig_architecture_v2.{ext}")
    plt.close(fig)
    print("wrote", FIGS / "fig_architecture_v2.pdf", "and .png")


if __name__ == "__main__":
    render()
