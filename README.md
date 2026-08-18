# AutoPatch

**SBOM-guided remediation of cloud-native container images, with best-of candidate selection under a strict acceptance gate.**

AutoPatch patches container images by reading what is actually installed (the CycloneDX SBOM), inferring a compatible newer base image, rewriting the `FROM` line, rebuilding, rescanning, and refusing to publish unless the rebuilt image strictly improves its vulnerability profile. Among all candidates that pass the gate, it keeps the one that most reduces the applicable finding set, so acceptance is a floor and selection continues toward the largest safe reduction.

This repository contains the full implementation, test suite, experiment harnesses, result data, and figure-generation scripts backing the paper *AutoPatch: SBOM-Guided Remediation of Cloud-Native Container Images*.

## Headline results

Evaluated on 39 real-world `linux/amd64` images that survived a reproducible build-and-headroom screen of 181 legacy Dockerfiles (plus an 18-image controlled bare-OS corpus):

| Metric | Value |
|---|---|
| Accepted transformations | 26 of 39 (Copacetic 12, naive `:latest` 13) |
| Median / mean reduction, accepted (applicable set) | 57.1% / 50.7% |
| Aggregate reduction, accepted | 65.2% (2,825 to 984 findings) |
| Median reduction, full corpus | 48.1% (both baselines 0%) |
| Applicable Critical / High findings | down 82.4% / 57.6% |
| Fixable OS-layer findings removed | 100.0% (3,092 to 0), on every accepted image |
| vs naive `:latest` | equal or larger reduction on every image it can remediate (Wilcoxon W=0, p<0.001) |
| Mean end-to-end time | 213 s per image, 3.2 candidate builds per admit |

The post-remediation residual is bounded by the mechanism, not the tool: 91% of remaining findings have no released fix anywhere, and 9% are application-layer dependencies that base substitution cannot reach by construction.

## How it works

```
Dockerfile -> build original -> Trivy scan -> SBOM -> compatibility inference
                                                            |
                                          ranked candidates (in-family bump,
                                          slim variant, Wolfi equivalent,
                                          digest-pinned current stable)
                                                            |
                              build + scan each -> acceptance gate (Eq. 1)
                                                            |
                          keep BEST passer by key (applicable, fixable-OS, raw)
                                                            |
                              accepted -> sign + publish     rejected -> decline
                                                             with rollback manifest
```

The acceptance gate admits a candidate only when the rebuild succeeds, the applicable vulnerability count strictly decreases, and no new Critical- or High-severity finding is introduced. The applicable set excludes kernel-space packages (shared with the host, unpatchable from inside a container) and findings with no released fix anywhere; CISA KEV entries are never excluded. When an accepted candidate still leaves applicable or fixable findings, an improver pass evaluates the remaining ranked alternates and adopts one only if it strictly improves the selection key, so an accepted outcome can never get worse.

## Installation

Requirements: Linux host, Docker Engine 24+ (evaluated on 29.1) with BuildKit, [Trivy](https://trivy.dev) 0.72+, Python 3.10+.

```bash
git clone https://github.com/0xLumos/AutoPatch.git
cd AutoPatch
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

For the analysis and figure scripts additionally:

```bash
pip install -r requirements-dev.txt
```

Optional tools for baselines and checks: [Copacetic](https://github.com/project-copacetic/copacetic) 0.14, Docker Scout CLI 1.23, [Grype](https://github.com/anchore/grype) 0.117, [Cosign](https://docs.sigstore.dev/cosign) for signing.

## Usage

Remediate one image from its Dockerfile:

```bash
python -m src.main \
  --dockerfile path/to/Dockerfile \
  --context path/to/build/context \
  --output-dir out/myimage \
  --accept-threshold count-strict \
  --applicability default \
  --cascade \
  --runtime-validation-advisory \
  --signing-mode none --no-push
```

This is the exact configuration used in the evaluation (see the `cmd` field of any record in `results/ab2yr_bestk_*/results.jsonl`). Key flags:

| Flag | Effect |
|---|---|
| `--accept-threshold count-strict` | severity-count non-regression over the applicable set, total must strictly decrease, KEV hard block (`strict` gives the identity-level Eq. 1 gate) |
| `--applicability default` | exclude kernel-space and no-fix findings from the gate (`literal` recovers the raw-scanner gate, `kernel-only` keeps no-fix findings) |
| `--cascade` | ranked fallback candidates on build failure, alternate strategies on rejection, and the best-of improver pass on acceptance |
| `--eol-upgrade` | allow major-version bumps for end-of-life bases |
| `--signing-mode keyless` | Cosign keyless signing plus SBOM attestation on accepted images |

Every run writes a self-contained output directory: original and patched Dockerfiles, before/after scans and SBOMs, `report.json` with metrics, `rollback.json` with the exact digests needed to revert, and a `run.log`.

Run the test suite (1,189 tests):

```bash
python -m pytest tests/
```

## Reproducing the paper

All numbers, tables, and figures in the paper are generated by scripts in this repository from the data in `results/`. The pipeline, end to end:

**1. Corpus construction.** `data/seed_repositories.yaml` seeds the harvest. `experiments/collect_real_dockerfiles.py` collects Dockerfile tags from public GitHub repositories whose pinned bases are 18 to 30 months old. `experiments/screen_corpus.py` rebuilds every tag in its original form and applies the headroom gate; `screened_2yr/manifest.json` and `screened_2yr/state.json` pin the exact 39-image corpus and the full screening funnel (181 = 106 build-failed + 36 no-headroom + 39 survivors).

**2. Main run.** `experiments/run_ab_experiment.py --corpus screened_2yr --out results/<dir> --arms A --timeout 5400 --cascade` processes the corpus one image at a time with per-image scrubbing and a pinned Trivy database snapshot. The published run is `results/ab2yr_bestk_20260813_030142/`.

**3. Baselines.** `experiments/copa_baseline.py` (Copacetic in-place patching via a local registry), `experiments/naive_scout_baseline.py --mode naive` (blind `:latest` rewrite) and `--mode scout` (advisory), each judged by the same acceptance gate implementation. `experiments/grype_crosscheck.py` rebuilds accepted images and rescans with Grype.

**4. Analysis.** `experiments/make_table2_applicable.py` computes the strategy comparison table on the gate basis, resolving each admit's true after-scan (a cascade winner's scan lives beside the primary's). `experiments/ceiling_analysis.py` computes the fixable-OS capture rate and residual decomposition. `experiments/naive_headtohead.py` produces the per-image matched comparison. The `*_bestk.py` variants are the exact copies pinned to the published run directory. `bestk_final_analysis.txt` is the verbatim output backing the paper's tables.

**5. Figures.** `experiments/make_table2_and_styled_figs.py` and `experiments/fix_fig4.py` regenerate every figure into `results/styled/` (survival curves, per-image severity, aggregate severity, corpus funnel, processing-time distribution, admission-policy matrix).

Paper-to-artifact map:

| Paper element | Backing data | Generator |
|---|---|---|
| Table: strategy comparison | `results/styled/table2_applicable.json` | `make_table2_applicable.py` |
| Table: bare-OS corpus | `results/bareos_20260812_005804/bareos_table.json` | `bareos_table.py` |
| Table: startup probe | run logs in the bestk directory | `prose facts` block in analysis output |
| Fig: survival curves | gated per-image reductions | `make_table2_applicable.py` |
| Fig: corpus funnel | `screened_2yr/state.json` + bestk logs | `fix_fig4.py` |
| Fig: processing time | `results/*/results.jsonl` wall times | `make_table2_and_styled_figs.py` |
| 100% fixable-OS claim | before/after scans of all 26 admits | `ceiling_analysis.py` |
| Wilcoxon tests | gated per-image values, n=39 pairs | analysis output (scipy) |

Notes for exact reproduction: scan results depend on the Trivy vulnerability database snapshot, so absolute counts drift as advisories are published; the paper's snapshot dates are 2026-08-12/13. Per-image raw scan JSONs for the baseline runs are large and excluded from the repository; the per-batch `results.jsonl`, summaries, and sweep files are included, and full raw archives are available from the authors on request.

## Repository layout

```
src/                 the tool: pipeline (main.py), patcher, comparer (acceptance gate),
                     applicability policy, inference, builder, scanner, signer, registries
tests/               1,189-test suite, including gate, guards, and best-of regression tests
experiments/         corpus collection, screening, batch runner, baselines, analysis, figures
tools/               allowlist refresh, rollback helper
data/                corpus seed list
screened_2yr/        pinned corpus manifest + screening state (the exact 39 images)
results/             per-batch results.jsonl, summaries, policy sweeps, analysis outputs,
                     bare-OS table data, final figures (results/styled/)
dockerfiles/         sample Dockerfiles used by tests
.github/workflows/   CI, allowlist refresh, and pipeline workflows
```

## Limitations

The gate verifies build success and vulnerability reduction; runtime validation is a startup-level advisory probe (tiered smoke testing is future work). Reduction values are scanner-relative (Trivy primary, Grype cross-check). Application-layer dependencies bundled with the application are out of reach for base substitution by construction.

## License

MIT. See [LICENSE](LICENSE).
