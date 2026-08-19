# AutoPatch

**SBOM-guided remediation of cloud-native container images, with best-of candidate selection under a strict acceptance gate.**

AutoPatch patches container images by reading what is actually installed (the CycloneDX SBOM), inferring a compatible newer base image, rewriting the `FROM` line, rebuilding, rescanning, and refusing to publish unless the rebuilt image strictly improves its vulnerability profile. Among all candidates that pass the gate, it keeps the one that most reduces the applicable finding set: acceptance is a floor, and selection continues toward the largest safe reduction.

This repository contains the full implementation, test suite, experiment harnesses, result data, and figure-generation scripts backing the paper *AutoPatch: SBOM-Guided Remediation of Cloud-Native Container Images* (in preparation for the International Workshop on Secure Cloud Continuum, IEEE CloudCom 2026).

## Contents

- [Headline results](#headline-results)
- [How it works](#how-it-works)
- [The acceptance gate](#the-acceptance-gate)
- [Installation](#installation)
- [Usage](#usage)
- [Output artifacts](#output-artifacts)
- [Reproducing the paper](#reproducing-the-paper)
- [Repository layout](#repository-layout)
- [Results directory guide](#results-directory-guide)
- [Limitations](#limitations)
- [License](#license)

## Headline results

Evaluated on 39 real-world `linux/amd64` images that survived a reproducible build-and-headroom screen of 181 legacy Dockerfiles, plus an 18-image controlled bare-OS corpus:

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
Dockerfile -> build original -> Trivy scan -> CycloneDX SBOM
                                                   |
                        compatibility inference (distro family, runtime,
                        libc, confidence) from purls + image metadata
                                                   |
                        ranked candidates: in-family bump, slim variant,
                        Wolfi equivalent, digest-pinned current stable
                                                   |
                        build + scan each -> acceptance gate (Eq. 1)
                                                   |
                    keep BEST passer by key (applicable, fixable-OS, raw)
                                                   |
                    accepted -> sign + publish      rejected -> decline with
                                                    rollback manifest
```

The pipeline runs once per image, in phases:

1. **Build and scan.** The original image is built and scanned with Trivy against a database snapshot pinned at run start, so a mid-run advisory release cannot pollute any before/after delta.
2. **Inference.** Four signals are extracted: distribution family from package URL prefixes (`pkg:apk/`, `pkg:deb/`, `pkg:rpm/`) with component-name disambiguation, language runtime from SBOM components and image metadata, libc implementation (so a glibc-dependent image is never migrated onto musl), and an aggregate confidence score. Below the confidence threshold, no transformation is attempted.
3. **Candidate selection and rewrite.** Candidates come from the original repository and an approved registry map, filtered by family, libc, and stability guards. Only the `FROM` line changes; the rewrite preserves the operator's build.
4. **Gate and best-of selection.** Every candidate that builds is scanned and judged by the same acceptance criterion. Passers are ranked by the lexicographic key *(applicable findings, remaining fixable OS findings, raw findings)*, and only the leader survives. If the primary candidate is rejected, a cascade tries alternate bases (slim variant, Wolfi equivalent, digest-pinned current stable) and an in-place OS upgrade strategy. If the primary is accepted but leaves findings on the table, an improver pass runs the same alternates and adopts one only if it strictly improves the key, so an accepted outcome can never get worse.
5. **Publish or decline.** Accepted images can be signed with Cosign (keyless or key-based) with the SBOM attached as a signed attestation. Declines leave the original untouched and write a rollback manifest with the exact digests needed to revert anything.

## The acceptance gate

A candidate `I'` for original `I` is accepted only when all of the following hold:

1. the rebuild succeeds;
2. the applicable vulnerability count strictly decreases: `|V(I')| < |V(I)|`;
3. no new Critical-severity finding identity is introduced;
4. no new High-severity finding identity is introduced;
5. any newly introduced finding listed in the CISA KEV catalog is an unconditional reject.

**The applicable finding set** excludes two classes the gate should not reason about: kernel-space packages (a container shares the host kernel and cannot patch it) and findings for which no fixed version has been released anywhere (nothing any tool can do). KEV-listed findings are never excluded. This prevents both false rejections, where a newer base discloses hundreds of unfixable advisories while every fixable finding disappears (see the debian:9 to debian:12 row of the bare-OS table: raw count rises 71 to 168 while applicable falls 2 to 0), and false acceptances built on unpatchable noise.

Gate policies available via `--accept-threshold`: `count-strict` (the evaluated default, severity-count non-regression over the applicable set), `strict` (identity-level, the paper's Eq. 1 verbatim), `moderate`, `permissive`, and `risk` (EPSS/KEV-weighted composite). Applicability policies via `--applicability`: `default` (kernel-space and no-fix excluded), `kernel-only`, `literal` (raw scanner set).

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

Optional tools for baselines and checks: [Copacetic](https://github.com/project-copacetic/copacetic) 0.14, Docker Scout CLI 1.23, [Grype](https://github.com/anchore/grype) 0.117, [Cosign](https://docs.sigstore.dev/cosign) for signing. A pinned runtime image is available via the included `Dockerfile` (`docker build -t autopatch:dev .`; mount the host Docker socket to run).

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

This is the exact configuration used in the evaluation (see the `cmd` field of any record in `results/ab2yr_bestk_*/results.jsonl`).

| Flag | Effect |
|---|---|
| `--dockerfile`, `--context` | the Dockerfile to remediate and its build context |
| `--accept-threshold` | gate policy; `count-strict` is the evaluated default |
| `--applicability` | which findings the gate reasons about; `default` excludes kernel-space and no-fix |
| `--cascade` | ranked fallbacks on build failure, alternate strategies on rejection, best-of improver on acceptance |
| `--eol-upgrade` | allow major-version bumps for end-of-life bases |
| `--runtime-validation-advisory` | startup probe reported as advisory rather than blocking |
| `--signing-mode` | `none`, `keyless`, or key-based Cosign signing of accepted images |
| `--no-push` | evaluate and report without publishing |
| `--base-mapping` | operator-supplied YAML overriding candidate selection per base |
| `--patch-final-only`, `--target` | control which stages of a multi-stage build are rewritten |
| `--platforms` | verify the accepted candidate across architectures before accepting |
| `--dry-run` | stop after the rewrite; print the diff without building |

Exit code 0 means a transformation was accepted; 1 means declined or failed, with reasons in the log and report.

Run the test suite (1,189 tests):

```bash
python -m pytest tests/
```

## Output artifacts

Every run writes a self-contained output directory:

| File | Content |
|---|---|
| `Dockerfile.original` / `Dockerfile.patched` / `dockerfile.diff` | the rewrite, before and after |
| `trivy-before.json` / `trivy-after.json` | scans of the original and the ACCEPTED candidate |
| `trivy-cascade-<strategy>.json` | scans of alternate candidates the cascade evaluated |
| `sbom-before.json` / `sbom-after.json` | CycloneDX SBOMs |
| `report.json` | metrics: totals, per-severity counts, resolved/remaining/new findings, SBOM diff |
| `rollback.json` | exact digests and paths needed to revert the change |
| `runtime-validation.json` | startup-probe outcome |
| `provenance.json`, `lineage-attestation.json` | inference evidence and attestation material |
| `run.log` | the full decision trail |

## Reproducing the paper

All numbers, tables, and figures are generated by scripts in this repository from the data in `results/`. End to end:

**1. Corpus construction.** `data/seed_repositories.yaml` seeds the harvest. `experiments/collect_real_dockerfiles.py` collects Dockerfile tags from public GitHub repositories whose pinned bases are 18 to 30 months old. `experiments/screen_corpus.py` rebuilds every tag in its original form and applies the headroom gate. `screened_2yr/manifest.json` and `screened_2yr/state.json` pin the exact 39-image corpus and the full screening funnel: 181 tags = 106 original-build failures + 36 without applicable findings + 39 survivors.

**2. Main run.** `experiments/run_ab_experiment.py --corpus screened_2yr --out results/<dir> --arms A --timeout 5400 --cascade` processes the corpus one image at a time with per-image scrubbing and a pinned Trivy database. The published run is `results/ab2yr_bestk_20260813_030142/`. Checkpoint: 39 records in `results.jsonl`, 26 with exit code 0.

**3. Baselines.** `experiments/copa_baseline.py` (Copacetic via a local registry), `experiments/naive_scout_baseline.py --mode naive` and `--mode scout`, each judged by the same gate implementation. `experiments/grype_crosscheck.py` rebuilds accepted images and rescans with Grype; direction agreed with Trivy on every measured change.

**4. Analysis.** `experiments/make_table2_applicable.py` computes the strategy table on the gate basis, resolving each admit's true after-scan (a cascade winner's scan lives beside the primary's). `experiments/ceiling_analysis.py` computes the fixable-OS capture rate (checkpoint: 3,092 to 0, 100.0%) and residual decomposition (91% no-fix, 9% application-layer). `experiments/naive_headtohead.py` produces the per-image matched comparison. The `*_bestk.py` variants are pinned to the published run directory, and `bestk_final_analysis.txt` is their verbatim output.

**5. Figures.** `experiments/make_table2_and_styled_figs.py` and `experiments/fix_fig4.py` regenerate every evaluation figure into `results/styled/`; `figures/fig_architecture_v2.py` draws the architecture diagram.

Paper-to-artifact map:

| Paper element | Backing data | Generator |
|---|---|---|
| Strategy comparison table | `results/styled/table2_applicable.json` | `make_table2_applicable.py` |
| Bare-OS corpus table | `results/bareos_20260812_005804/bareos_table.json` | `bareos_table.py` |
| Survival-curve figure | gated per-image reductions | `make_table2_applicable.py` |
| Corpus funnel figure | `screened_2yr/state.json` + run logs | `fix_fig4.py` |
| Processing-time figure | `results/*/results.jsonl` wall times | `make_table2_and_styled_figs.py` |
| 100% fixable-OS claim | before/after scans of all 26 admits | `ceiling_analysis.py` |
| Wilcoxon tests | gated per-image values, n=39 pairs | analysis output (scipy) |

Reproduction notes: scan counts depend on the Trivy database snapshot, so absolute numbers drift as advisories are published (the paper's snapshots are 2026-08-12/13); acceptance decisions and relative comparisons are far more stable. Per-image raw scan JSONs for the baseline runs are large and excluded from the repository; the per-batch `results.jsonl`, summaries, and sweep files are included, and full raw archives are available from the authors on request.

## Repository layout

```
src/                 the tool
  main.py              pipeline orchestration: build, scan, infer, rewrite,
                       gate, cascade, improver, publish
  patcher.py           candidate selection and Dockerfile rewriting, with
                       compatibility guards (family, libc, language images)
  comparer.py          the acceptance gate (check_acceptance_criteria)
  applicability.py     applicable-set policy (kernel-space, no-fix, KEV)
  builder.py, scanner.py, signer.py, resolver.py, ...
  image_registry.yaml  curated candidate registry
tests/               1,189-test suite (gate, guards, best-of selection, ...)
experiments/         corpus collection, screening, batch runner, baselines,
                     analysis, statistics, figure generation
tools/               allowlist refresh, rollback helper
data/                corpus seed list
screened_2yr/        pinned corpus manifest + screening state
results/             per-batch results, summaries, sweeps, final figures
dockerfiles/         sample Dockerfiles used by the test suite
figures/             the paper's architecture diagram and its generator
```

## Results directory guide

| Directory | What it is |
|---|---|
| `results/ab2yr_bestk_20260813_030142/` | the published main run (39 images, cascade + best-of) |
| `results/ab2yr_base_*/`, `results/ab2yr_cascade_*/` | earlier base-swap-only and first-cascade batches, kept for provenance |
| `results/bareos_*/` | the 18-image controlled bare-OS corpus |
| `results/copa_*/`, `results/naive_*/`, `results/scout_*/`, `results/grype_*/` | baseline runs |
| `results/styled/` | final figures (PDF + PNG) and the strategy-table data |
| `bestk_final_analysis.txt` | verbatim output of the full analysis suite over the published run |

## Limitations

The gate verifies build success and vulnerability reduction; runtime validation is a startup-level advisory probe, and tiered application-specific smoke testing is future work. Reduction values are scanner-relative (Trivy primary, Grype cross-check agreeing on direction). Application-layer dependencies bundled with the application are out of reach for base substitution by construction, and findings without a released fix are out of reach for every tool.

## License

MIT. See [LICENSE](LICENSE).
