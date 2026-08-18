#!/usr/bin/env python3
"""
Phase 3 / item P3-19 — Logistic regression calibration of inference weights.

Reads the labeled dataset (one row per image with the SBOM signals
observed and the ground-truth label "did the patched image work and
pass acceptance"), fits a logistic regression, and writes the resulting
coefficients back to ``src/inference_calibration.json``.

Inputs
------
The labeled dataset is a CSV with columns:

    image, os_family_purl, os_family_metadata, os_family_contradiction,
    language_from_sbom, language_override, libc_explicit, variant_detected,
    label

Each signal column is 0/1; ``label`` is 1 when the SBOM-driven inference
produced a Dockerfile that built and passed acceptance, else 0.

If ``--dataset`` is omitted the script can also derive features from a
directory of SBOM JSONs by calling :func:`src.patcher.analyze_sbom` on
each and using the produced ``signals`` list to derive the 0/1 features;
ground-truth labels still need to come from a labels CSV.

Usage
-----
    python experiments/fit_inference_calibration.py \\
        --dataset experiments/labeled_features.csv \\
        --output  src/inference_calibration.json

Dependencies
------------
    pip install scikit-learn pandas
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

# Feature columns expected in the labeled dataset, in the order they
# enter the model. Order is preserved when writing back the weights.
FEATURES = [
    "os_family_purl",
    "os_family_metadata",
    "os_family_contradiction",
    "language_from_sbom",
    "language_override",
    "libc_explicit",
    "variant_detected",
]


def fit(dataset_csv: str) -> Dict[str, float]:
    try:
        import pandas as pd
        from sklearn.linear_model import LogisticRegression
    except ImportError as e:
        raise SystemExit(
            "fit_inference_calibration requires pandas + scikit-learn:\n"
            "    pip install pandas scikit-learn\n"
            f"(import failed: {e})"
        )
    df = pd.read_csv(dataset_csv)
    missing = [c for c in FEATURES + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"Dataset is missing columns: {missing}")
    X = df[FEATURES].values
    y = df["label"].values

    # No regularisation; we have few features and want raw coefficients.
    model = LogisticRegression(penalty=None, solver="lbfgs", max_iter=1000)
    model.fit(X, y)

    coefs = dict(zip(FEATURES, model.coef_[0].tolist()))
    coefs["__intercept__"] = float(model.intercept_[0])

    # Print a quick report.
    print("Fitted coefficients:")
    for name in FEATURES:
        print(f"  {name:30s} {coefs[name]:+.4f}")
    print(f"  intercept                      {coefs['__intercept__']:+.4f}")
    print(f"  train accuracy:                 {model.score(X, y):.3f}")
    print(f"  n samples:                      {len(df)}")
    return coefs


def write_calibration(coefs: Dict[str, float], output_json: str) -> None:
    """Write coefficients back to inference_calibration.json in the
    shape patcher._load_inference_calibration expects."""
    intercept = coefs.pop("__intercept__", -0.5)
    out = {
        "_comment": (
            "Per-signal log-likelihood weights for InferenceResult.confidence. "
            "Fitted via logistic regression on the labeled dataset. "
            "See experiments/fit_inference_calibration.py."
        ),
        "schema_version": "1.0",
        "fit_method": "logistic_regression",
        "fit_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "fit_dataset": "labeled_features.csv",
        "weights": coefs,
        "default_intercept": intercept,
        "min_confidence_threshold": 0.50,
    }
    Path(output_json).parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote calibrated weights to {output_json}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True,
                        help="Labeled features CSV (see module docstring)")
    parser.add_argument("--output", default="src/inference_calibration.json",
                        help="Output JSON path (overwrites)")
    args = parser.parse_args()

    coefs = fit(args.dataset)
    write_calibration(coefs, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
