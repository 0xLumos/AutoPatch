#!/usr/bin/env python3
"""Paired A/B experiment: deterministic vs Claude-proposed base selection.

Design, stated up front because the design IS the result's validity:

**Paired, interleaved runs.** For every Dockerfile the two arms run
back-to-back (A then B) on the same host, before moving to the next
image. Vulnerability databases and registries drift by the hour; a
sequential all-A-then-all-B design would confound the arm with time.
Pairing also gives the analysis per-image deltas, which is a far
stronger statistic than two independent means.

**One variable.** Arm A is the deterministic registry-driven selector.
Arm B is identical except the candidate for the shipping stage is
proposed by Claude (pinned model, temperature 0, disk-cached). The
allow-list gate, compatibility guards, glibc floor, build, scan,
runtime validation and acceptance criterion are byte-identical. Arm A
additionally pins AUTOPATCH_ALLOWLIST_SOURCE=curated so no AI output
reaches it through the allow-list either.

**Fallbacks are data, not noise.** When arm B's proposer fails or its
proposal is rejected, the run falls back to deterministic selection.
Those runs are still recorded under arm B with source=ai-fallback,
because "how often does the model produce something usable" is one of
the experiment's questions. Excluding them would be survivorship bias,
which this codebase has had enough of.

**Nothing here simulates anything.** Every number in the summary comes
from a real build and a real scan through src/main.py, the actual
implementation. If a run fails, the failure is recorded; it is not
imputed.

Usage:
    python experiments/run_ab_experiment.py \
        --corpus dataset/corpus --out results/ab_run1 \
        [--arms A,B] [--limit N] [--timeout 1800] [--ai-cache-only]

The corpus directory contains one subdirectory per image, each with a
Dockerfile (the layout collect_real_dockerfiles.py produces).
Progress is checkpointed after every run, so the experiment resumes
cleanly if the host restarts; rerunning the same command skips
completed (image, arm) pairs.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _discover_corpus(corpus_dir: Path) -> list:
    """Prefer the collector's manifest; fall back to directory layout.

    The manifest is authoritative because it carries the selection
    provenance (stratum, pinned SHA, criteria version) that the
    summary republishes. The bare-directory fallback exists only for
    ad-hoc smoke corpora.
    """
    manifest = corpus_dir / "manifest.json"
    if manifest.is_file():
        doc = json.loads(manifest.read_text(encoding="utf-8"))
        # criteria_version 2.0 wraps entries; the 1.x manifest was a
        # bare list. Accept both so old collections stay runnable.
        raw = doc.get("entries") if isinstance(doc, dict) else doc
        entries = []
        for e in raw or []:
            if Path(e.get("dockerfile", "")).is_file():
                entries.append({
                    "name": e["name"],
                    "dockerfile": e["dockerfile"],
                    "context": e.get("context", str(corpus_dir)),
                    "stratum": e.get("stratum", "current"),
                    "ref_sha": e.get("ref_sha"),
                })
            else:
                print(f"warning: manifest entry {e.get('name')} points at "
                      f"a missing Dockerfile; skipped", file=sys.stderr)
        return entries
    entries = []
    for sub in sorted(p for p in corpus_dir.iterdir() if p.is_dir()):
        df = sub / "Dockerfile"
        if df.is_file():
            entries.append({"name": sub.name, "dockerfile": str(df),
                            "context": str(sub), "stratum": "current",
                            "ref_sha": None})
    return entries


def _run_one(entry: dict, arm: str, out_dir: Path, timeout: int,
             ai_cache_only: bool, cascade: bool = False) -> dict:
    """Execute src/main.py once for one (image, arm) pair.

    Returns the record for the results log. Never raises: an
    infrastructure failure is a recorded outcome.
    """
    run_dir = out_dir / entry["name"] / f"arm{arm}"
    run_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "src.main",
        "--dockerfile", entry["dockerfile"],
        # Build against the repo-root context recorded in the manifest,
        # not the Dockerfile's own directory. Many projects keep their
        # real Dockerfile in a subdirectory (docker/, scripts/, ...) and
        # COPY from the repo root; without this the baseline build fails
        # ("/go.sum not found", "/Gemfile.lock not found") and the image
        # becomes a spurious decline instead of a real measurement.
        "--context", entry.get("context") or str(Path(entry["dockerfile"]).parent),
        "--output-dir", str(run_dir),
        "--signing-mode", "none",
        "--report-format", "json",
        # Advisory runtime validation for the corpus: these are
        # arbitrary public Dockerfiles with no smoke manifests, and a
        # hard runtime gate would mostly measure our probe coverage
        # rather than the selector. The tier outcomes are still
        # recorded per run and reported. This matches the paper, which
        # scopes the acceptance criterion to Eq. (1) and reports
        # runtime validation as future work.
        "--runtime-validation-advisory",
        # The gate stated explicitly so it lands in the per-run command
        # and the provenance. count-strict is the operational criterion
        # and matches fielded admission-controller practice: over the
        # applicable finding set, CRITICAL and HIGH counts must not
        # rise, the total must strictly decrease, and any new KEV
        # (known-exploited) CVE blocks unconditionally. The identity
        # gate (--accept-threshold strict, the paper's Eq. (1)) is the
        # no-regression BOUND and is recomputed post-hoc for every run
        # by experiments/policy_sweep.py from the persisted scans, so
        # nothing is lost by not gating on it live.
        "--accept-threshold", "count-strict",
        # No demotions: demote_local_av defaults ON in the CLI (an
        # operator convenience); the evaluation must run the bare
        # criterion or the reported gate is not the published gate. No
        # EPSS file is passed for the same reason.
        "--no-demote-local-av",
        # Applicability policy stated explicitly so it lands in the
        # per-run command and the provenance. 'default' scopes out
        # host-kernel CVEs (the container shares the host kernel; stops
        # linux-libc-dev kernel-header churn from false-rejecting
        # strictly-safer images) and no-fix findings (no version exists
        # to move to; fielded admission gates require an available
        # fix). KEV overrides both. Re-run with --applicability
        # kernel-only to keep no-fix findings gated, or literal for the
        # raw-scanner sensitivity analysis; both are also recomputed
        # post-hoc by policy_sweep.py.
        "--applicability", "default",
        # EOL version upgrading is OFF by default because in production
        # an operator-pinned python:3.8 is a decision to respect. This
        # experiment measures remediation of STALE images: the legacy
        # stratum is pinned-EOL bases by construction, and with the
        # gate shut every python:X/node:X legacy image declines with
        # all of its CVEs untouched (changedetection@legacy: 2005
        # OS-package CVEs left in place because python:3.8-slim was
        # never allowed to move). The acceptance gate, the build, and
        # runtime validation still guard the result of the bump.
        "--eol-upgrade",
        # The evaluation VM runs no registry. Publishing the accepted
        # image is not part of the measurement; without this flag the
        # first ACCEPTED image in a run dies in the push phase (exit 1
        # against localhost:5000), which silently converted admissions
        # into declines. That path never executed before the count-strict
        # gate because no image had ever been accepted.
        "--no-push",
    ]
    if cascade:
        # With-cascade configuration: after the primary candidate fails
        # the gate, try ranked alternates (slim variant, Wolfi
        # equivalent) and finally in-place OS upgrades, each fully
        # rebuilt, rescanned, and gated. Run the same corpus once
        # without and once with this flag to attribute the gain.
        cmd.append("--cascade")
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if arm == "A":
        # No model output anywhere in this arm, including via the
        # generated (AI-proposed) allow-list.
        env["AUTOPATCH_ALLOWLIST_SOURCE"] = "curated"
    else:
        cmd.append("--ai-propose")
        if ai_cache_only:
            cmd.append("--ai-cache-only")

    rec = {"image": entry["name"], "arm": arm,
           "stratum": entry.get("stratum", "current"),
           "ref_sha": entry.get("ref_sha"),
           "started": _now(), "cmd": " ".join(cmd)}
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, cwd=str(REPO_ROOT), env=env, timeout=timeout,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace",
        )
        rec["exit_code"] = proc.returncode
        (run_dir / "run.log").write_text(
            (proc.stdout or "") + "\n===STDERR===\n" + (proc.stderr or ""),
            encoding="utf-8")
    except subprocess.TimeoutExpired:
        rec["exit_code"] = None
        rec["error"] = f"timeout after {timeout}s"
    except OSError as e:
        rec["exit_code"] = None
        rec["error"] = f"{type(e).__name__}: {e}"
    rec["wall_seconds"] = round(time.time() - t0, 1)

    # Harvest the artefacts the pipeline itself wrote. The runner
    # trusts those files, not its own parsing of stdout.
    for artefact, key in (("report.json", "report"),
                          ("metrics.json", "metrics"),
                          ("selector-decision.json", "selector"),
                          ("rollback.json", "rollback")):
        p = run_dir / artefact
        if p.is_file():
            try:
                rec[key] = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                rec[f"{key}_error"] = "unparseable"

    # Save-then-scrub, in that order, after EVERY image. The results
    # (trivy before/after, SBOMs, diff, run.log, results.jsonl) are
    # already persisted above; everything Docker created for this image
    # is disposable the moment they are on disk. The previous policy
    # preserved the build cache for speed and pruned only when free
    # space dipped, which let usage ratchet upward across images; on a
    # sparse (growable) virtual disk every transient high-water mark
    # also became PERMANENT host-side .vmdk growth, which eventually
    # filled the host and froze the VM mid-run. Bounded disk beats fast
    # builds: wipe images, containers and the whole build cache each
    # time, then fstrim so the freed blocks are handed back to the
    # hypervisor instead of staying allocated in the .vmdk.
    #
    # Historical context for the old cache-preserving policy:
    #   * A blanket `docker builder prune` after every run reclaims the
    #     most space, but it forces every subsequent image to build cold.
    #     Cold-cache Go/Rust compiles take 20+ minutes EACH, and a run
    #     does two builds (original + patched), so blanket pruning turned
    #     a ~5 min gitea run into ~45 min and risked exceeding the
    #     per-run timeout entirely.
    #   * Keeping the cache makes the patched build reuse the original
    #     build's layers and makes the next image with a shared base
    #     start warm, which is most of the corpus.
    # That trade was rejected after it froze a full run: speed is
    # recoverable, a wedged host is not.
    try:
        # 1) Stop and remove anything still running for this image.
        ps = subprocess.run(["docker", "ps", "-q"], capture_output=True,
                            text=True, timeout=60)
        for cid in (ps.stdout or "").split():
            subprocess.run(["docker", "kill", cid], capture_output=True,
                           timeout=60)
        subprocess.run(["docker", "container", "prune", "-f"],
                       capture_output=True, timeout=60)

        # 2) Remove this run's tagged images, dangling layers, volumes
        # and the whole build cache, but KEEP pulled base images. The
        # all-images scrub was born on the 40G disk; on 120G the bases
        # cost a few GB and deleting them made every run re-pull, which
        # exhausted the Docker Hub anonymous pull budget (100/6h) and
        # killed an entire batch with 429s in seconds. Base images are
        # shared, content-addressed, and bounded; the churn lives in the
        # build cache and run tags, which still go.
        rb = rec.get("rollback") or {}
        for side in ("patched", "original"):
            tag = (rb.get(side) or {}).get("image_tag")
            if tag:
                subprocess.run(["docker", "rmi", "-f", tag],
                               capture_output=True, timeout=120)
        subprocess.run(["docker", "image", "prune", "-f"],
                       capture_output=True, timeout=300)
        subprocess.run(["docker", "volume", "prune", "-f"],
                       capture_output=True, timeout=300)
        subprocess.run(["docker", "builder", "prune", "-af"],
                       capture_output=True, timeout=600)
        rec["builder_pruned"] = True

        # 3) Hand the freed blocks back to the hypervisor. Inside the
        # guest `rm` only marks blocks free; on a sparse .vmdk they stay
        # allocated on the host until the filesystem TRIMs them. Needs a
        # NOPASSWD sudoers entry for fstrim (set up at deploy time);
        # recorded, never fatal.
        trim = subprocess.run(["sudo", "-n", "fstrim", "/"],
                              capture_output=True, text=True, timeout=300)
        rec["fstrimmed"] = (trim.returncode == 0)

        df = subprocess.run(["df", "-BG", "--output=avail", "/"],
                            capture_output=True, text=True, timeout=20)
        try:
            rec["disk_avail_after_gb"] = int(
                df.stdout.strip().splitlines()[-1].strip().rstrip("G"))
        except (ValueError, IndexError, AttributeError):
            rec["disk_avail_after_gb"] = None
    except (OSError, subprocess.TimeoutExpired) as e:
        rec["prune_warning"] = f"{type(e).__name__}: {e}"
    rec["finished"] = _now()
    return rec


def _reduction(rec):
    """Candidate reduction: what the patch achieves, measured whether or
    not the acceptance gate admitted it. None when the baseline had 0
    CVEs (ratio undefined) or no patched build was produced."""
    m = rec.get("metrics") or {}
    return m.get("vulnerability_reduction_pct")


def _built(rec) -> bool:
    """A patched image was produced and rescanned (metrics exist). A
    baseline-build failure or a no-candidate decline yields no metrics."""
    return bool(rec.get("metrics"))


def _accepted(rec) -> bool:
    """The configured acceptance gate admitted the transformation
    (count-strict over the applicable set, KEV hard-block; see the
    per-run cmd for the exact flags). Recorded in rollback.json by the
    pipeline itself. Admission under other criteria (identity-strict,
    other applicability policies) is recomputed post-hoc by
    experiments/policy_sweep.py from the persisted scans."""
    return bool((rec.get("rollback") or {}).get("accepted"))


def _stats(xs):
    if not xs:
        return {"n": 0}
    out = {"n": len(xs), "mean": round(statistics.mean(xs), 2),
           "median": round(statistics.median(xs), 2),
           "min": round(min(xs), 2), "max": round(max(xs), 2),
           "regressions": sum(1 for x in xs if x < 0)}
    if len(xs) > 1:
        out["stdev"] = round(statistics.stdev(xs), 2)
    return out


def _arm_block(recs: list) -> dict:
    """Everything the paper needs for one arm, over one set of records.

    The critical distinction, and the reason this run looked like a
    failure until it was split out:

      * CANDIDATE reduction is measured on every image that BUILT,
        regardless of the gate. It answers "how much CVE exposure does
        base remediation remove". changedetection@legacy 2051 -> 1130
        (45%) counts here whether or not it was admitted.
      * ADMITTED reduction is measured only on images the strict
        Eq. (1) gate accepted. It answers "how much can be auto-applied
        with zero new severe findings". Bumping a years-old base to
        current almost always introduces one or two new Critical/High
        identities from the target distribution, which the literal
        criterion rejects, so this set is small BY DESIGN.

    Reporting only admit-rate makes the tool look like it does nothing;
    reporting only candidate reduction overstates what is safe to ship
    unattended. The paper needs both, so both are here.
    """
    total = len(recs)
    built = [r for r in recs if _built(r)]
    accepted = [r for r in recs if _accepted(r)]
    cand = [_reduction(r) for r in built if _reduction(r) is not None]
    adm = [_reduction(r) for r in accepted if _reduction(r) is not None]
    return {
        "images": total,
        "build_rate": round(len(built) / total, 3) if total else None,
        "admit_rate": round(len(accepted) / total, 3) if total else None,
        "n_built": len(built),
        "n_accepted": len(accepted),
        "candidate_reduction_pct": _stats(cand),
        "admitted_reduction_pct": _stats(adm),
    }


def _summarise(records: list) -> dict:
    by_image: dict = {}
    for r in records:
        by_image.setdefault(r["image"], {})[r["arm"]] = r

    # Flatten to per-arm record lists, and split each arm by stratum so
    # the current/legacy story (legacy builds rarely, current builds
    # reliably) is legible rather than blended into one misleading rate.
    per_arm: dict = {}
    ai_fallbacks = 0
    paired_deltas = []
    for image, pair in sorted(by_image.items()):
        for arm, r in pair.items():
            per_arm.setdefault(arm, []).append(r)
        b = pair.get("B")
        if b and (b.get("selector") or {}).get("arm") == "ai-fallback":
            ai_fallbacks += 1
        ra, rb = pair.get("A"), pair.get("B")
        if ra and rb:
            da, db = _reduction(ra), _reduction(rb)
            if da is not None and db is not None:
                paired_deltas.append({"image": image, "A": da, "B": db,
                                      "delta_B_minus_A": round(db - da, 2)})

    def _by_stratum(recs):
        out = {"ALL": _arm_block(recs)}
        for strat in sorted({r.get("stratum", "current") for r in recs}):
            out[strat] = _arm_block(
                [r for r in recs if r.get("stratum", "current") == strat])
        return out

    deltas = [d["delta_B_minus_A"] for d in paired_deltas]
    summary = {
        "generated": _now(),
        "images_total": len(by_image),
        "arms": {arm: _by_stratum(recs) for arm, recs in sorted(per_arm.items())},
        "paired": {
            "n": len(paired_deltas),
            "delta_B_minus_A": _stats(deltas),
            "B_better": sum(1 for d in deltas if d > 0),
            "A_better": sum(1 for d in deltas if d < 0),
            "ties": sum(1 for d in deltas if d == 0),
            "per_image": paired_deltas,
        },
        "arm_B_ai_fallbacks": ai_fallbacks,
        "note": (
            "candidate_reduction_pct is measured over all BUILT images "
            "regardless of the acceptance gate; it is the headline "
            "'how much does base remediation reduce OS-layer CVE "
            "exposure' number. admitted_reduction_pct is measured over "
            "images the operational count-strict gate accepted: over "
            "applicable findings (host-kernel and no-fix excluded, KEV "
            "never excluded), CRITICAL and HIGH counts non-increasing, "
            "total strictly decreasing, any new KEV CVE a hard block. "
            "Admission under the identity-strict Eq. (1) bound and "
            "under other applicability policies is recomputed post-hoc "
            "by experiments/policy_sweep.py from the persisted scans. "
            "Both are reported so neither overstates nor understates "
            "the method. Reductions with an undefined baseline (0 CVEs) "
            "are excluded; regressions are retained."
        ),
    }
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--arms", default="A,B")
    ap.add_argument("--limit", type=int, default=0,
                    help="Take the first N entries. Note the manifest is "
                         "interleaved current/legacy per project, so a small "
                         "--limit spans both strata but NOT necessarily both "
                         "single- and multi-stage, since the leading projects "
                         "are all multi-stage. Use --only for a hand-picked "
                         "representative pilot.")
    ap.add_argument("--only", default="",
                    help="Comma-separated name substrings; keep only entries "
                         "whose name matches one. Matches the project name, "
                         "so 'gitea' selects both gitea and gitea@legacy. Use "
                         "this to build a pilot that deliberately spans "
                         "single- and multi-stage images. Applied before "
                         "--limit.")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="Per-run wall clock cap in seconds (default 1800)")
    ap.add_argument("--ai-cache-only", action="store_true")
    ap.add_argument("--cascade", action="store_true",
                    help="Enable the alternate-strategy cascade in "
                         "src.main for every run (ranked alternate "
                         "bases, then in-place OS upgrade). Off by "
                         "default so base-swap-only and with-cascade "
                         "results can be attributed separately.")
    args = ap.parse_args(argv)

    corpus = _discover_corpus(Path(args.corpus))
    if args.only:
        wanted = [s.strip().lower() for s in args.only.split(",") if s.strip()]
        corpus = [e for e in corpus
                  if any(w in e["name"].lower() for w in wanted)]
        print(f"--only kept {len(corpus)} entries matching {wanted}")
    if args.limit:
        corpus = corpus[:args.limit]
    if not corpus:
        print(f"error: no Dockerfiles under {args.corpus}", file=sys.stderr)
        return 1
    arms = [a.strip().upper() for a in args.arms.split(",") if a.strip()]

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"

    # Resume support: a completed (image, arm) pair is one that already
    # has a line in results.jsonl. Append-only, checkpointed per run.
    done = set()
    if results_path.is_file():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                done.add((r["image"], r["arm"]))
            except (ValueError, KeyError):
                continue
    if done:
        print(f"resuming: {len(done)} (image, arm) pairs already complete")

    records = []
    total = len(corpus) * len(arms)
    i = 0
    for entry in corpus:
        # Interleave arms per image so registry and DB drift cannot
        # masquerade as an arm effect.
        for arm in arms:
            i += 1
            if (entry["name"], arm) in done:
                continue
            print(f"[{i}/{total}] {entry['name']} arm {arm} ...", flush=True)
            rec = _run_one(entry, arm, out_dir, args.timeout,
                           args.ai_cache_only, cascade=args.cascade)
            with open(results_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            records.append(rec)
            status = ("ok" if rec.get("exit_code") == 0
                      else rec.get("error") or f"exit {rec.get('exit_code')}")
            print(f"    -> {status} in {rec['wall_seconds']}s", flush=True)

    # Summary always recomputed over the FULL log, including resumed
    # history, so a partial rerun cannot produce a partial summary.
    all_records = []
    for line in results_path.read_text(encoding="utf-8").splitlines():
        try:
            all_records.append(json.loads(line))
        except ValueError:
            continue
    summary = _summarise(all_records)
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items()
                      if k != "paired"} |
                     {"paired_n": summary["paired"]["n"],
                      "delta": summary["paired"]["delta_B_minus_A"]},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
