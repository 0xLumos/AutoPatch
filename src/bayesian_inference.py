#!/usr/bin/env python3
"""
P5-3: Bayesian network for image-identity signal fusion.

A small directed graphical model over three latent variables fused
from the diverse signals collected by :mod:`src.provenance_fingerprint`
plus the SBOM-derived signals already used by :mod:`src.patcher`.

Latent variables (the things we want to infer):

    D  -- distro identity   (debian, ubuntu, alpine, ...)
    L  -- libc family        (glibc, musl, none, unknown)
    T  -- tampering bit       (0 = honest image, 1 = SBOM/metadata
                               channel was adversarially rewritten)

Graph:

    D -> L                                   (libc CPT, P(L|D))
    D -> every identity signal S_i           (each S_i is an emission)
    T -> every LOW-TRUST signal S_i          (tampering corrupts only
                                              the spoofable channel)
    L -> loader_libc observation             (high-trust libc emission)

We deliberately do NOT model the upstream-image node ``U`` that an
earlier draft of this module sketched. Modelling ``U`` would make the
filesystem-derived signals conditionally independent only given ``U``;
collapsing it makes them conditionally independent given ``D`` instead.
That is an approximation -- two filesystem signals that both derive
from the same upstream layer are not truly independent -- but it keeps
inference exact and cheap, and the residual correlation is dominated by
the per-signal strength terms. The code and this docstring describe the
same graph; there is no hidden ``U``.

Why T corrupts only the low-trust channel
------------------------------------------
The realistic attacker rewrites the cheap-to-forge signals (SBOM purls,
component names, ``/etc/os-release``, image config) but cannot rewrite
the structural filesystem signals (package-db layout, ``PT_INTERP``,
layer digests) without breaking the image. So ``T=1`` flattens the
emission of every LOW-TRUST signal toward uninformative, while
HIGH-TRUST signals stay truthful. This makes tampering *generatively*
detectable: when the high-trust and low-trust channels disagree, no
single ``D`` explains both under ``T=0``, but ``T=1`` explains the
low-trust channel as attacker-chosen noise. We therefore obtain
``P(T=1 | obs)`` from the joint posterior rather than from a post-hoc
disagreement heuristic, and the MAP distro under tampering follows the
high-trust signals automatically.

Inference
---------
Exact enumeration over the joint table ``D x T x L`` (10 x 2 x 4 = 80
cells). For a graph this small variable elimination is overkill; we sum
log-likelihoods with the log-sum-exp trick and read off the marginals.
No dependency on pgmpy or pomegranate.

Calibration
-----------
Every numeric parameter (priors, the libc CPT, per-signal strengths,
the tamper-flattening factor) lives in ``bayesian_calibration.yaml``
shipped beside this module, with embedded defaults as a fallback when
PyYAML is unavailable. The active parameter set is content-hashed
(:data:`CALIBRATION_SHA256`) so it can be pinned and attested the same
way scanner binaries are in :mod:`src.scanner_integrity`.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# Value spaces
# ════════════════════════════════════════════════════════════════════

# Concrete distros we model plus the "unknown" catch-all. The catch-all
# never appears as an *observed* value; it only carries prior mass for
# images whose evidence matches nothing.
DISTROS: Tuple[str, ...] = (
    "debian", "ubuntu", "rhel", "alpine", "arch", "gentoo",
    "nixos", "wolfi", "distroless", "unknown",
)
CONCRETE_DISTROS: Tuple[str, ...] = tuple(d for d in DISTROS if d != "unknown")
LIBCS: Tuple[str, ...] = ("glibc", "musl", "none", "unknown")

# Distro families. A *family-level* signal (one that physically cannot
# distinguish members of a family -- e.g. a dpkg database is identical
# on Debian and Ubuntu) is scored at family granularity, so it gives
# equal likelihood to every member instead of arbitrarily favouring one.
# This is the fix for the historical "every Ubuntu image classified as
# Debian" bug.
FAMILIES: Dict[str, Tuple[str, ...]] = {
    "deb":     ("debian", "ubuntu", "distroless"),
    "rpm":     ("rhel",),
    "apk":     ("alpine", "wolfi"),
    "pacman":  ("arch",),
    "portage": ("gentoo",),
    "nix":     ("nixos",),
}
DISTRO_TO_FAMILY: Dict[str, str] = {
    d: fam for fam, members in FAMILIES.items() for d in members
}
_NUM_FAMILIES = len(FAMILIES)
_PROB_FLOOR = 1e-12


# ════════════════════════════════════════════════════════════════════
# Calibration: defaults embedded here, overridable via YAML
# ════════════════════════════════════════════════════════════════════

# Prior over D. Approximates Docker Hub population frequency so an image
# with weak evidence is biased toward the empirical population.
_DEFAULT_DISTRO_PRIOR: Dict[str, float] = {
    "debian":     0.30,
    "ubuntu":     0.20,
    "rhel":       0.10,
    "alpine":     0.20,
    "arch":       0.02,
    "gentoo":     0.01,
    "nixos":      0.01,
    "wolfi":      0.03,
    "distroless": 0.07,
    "unknown":    0.06,
}

_DEFAULT_TAMPER_PRIOR: float = 0.02

# P(L | D): per-distro libc conditional.
_DEFAULT_LIBC_CPT: Dict[str, Dict[str, float]] = {
    "debian":     {"glibc": 0.99, "musl": 0.005, "none": 0.005, "unknown": 0.0},
    "ubuntu":     {"glibc": 0.99, "musl": 0.005, "none": 0.005, "unknown": 0.0},
    "rhel":       {"glibc": 0.99, "musl": 0.005, "none": 0.005, "unknown": 0.0},
    "alpine":     {"glibc": 0.01, "musl": 0.98,  "none": 0.01,  "unknown": 0.0},
    "wolfi":      {"glibc": 0.97, "musl": 0.02,  "none": 0.01,  "unknown": 0.0},
    "arch":       {"glibc": 0.99, "musl": 0.005, "none": 0.005, "unknown": 0.0},
    "gentoo":     {"glibc": 0.95, "musl": 0.04,  "none": 0.01,  "unknown": 0.0},
    "nixos":      {"glibc": 0.99, "musl": 0.005, "none": 0.005, "unknown": 0.0},
    "distroless": {"glibc": 0.70, "musl": 0.05,  "none": 0.25,  "unknown": 0.0},
    "unknown":    {"glibc": 0.50, "musl": 0.25,  "none": 0.10,  "unknown": 0.15},
}

# Per-signal emission parameters.
#   strength   : P(signal emits the truthful value | not tampered). The
#                error mass (1 - strength) is spread across the other
#                values of the signal's observation space.
#   resolution : "distro" -> the signal can name a specific distro;
#                "family" -> it can only name the family (scored over
#                family tokens, so no within-family penalty).
#   trust      : "high" -> structural/filesystem signal, truthful even
#                under tampering; "low" -> spoofable, flattened by T=1.
_DEFAULT_SIGNALS: Dict[str, Dict[str, Any]] = {
    "layer_match":  {"strength": 0.95, "resolution": "distro", "trust": "high"},
    "pkgdb":        {"strength": 0.90, "resolution": "family", "trust": "high"},
    "topology":     {"strength": 0.80, "resolution": "family", "trust": "high"},
    "loader":       {"strength": 0.88, "resolution": "distro", "trust": "high"},
    "purl":         {"strength": 0.85, "resolution": "family", "trust": "low"},
    "compname":     {"strength": 0.70, "resolution": "distro", "trust": "low"},
    "trivy_result": {"strength": 0.80, "resolution": "distro", "trust": "low"},
    "os_release":   {"strength": 0.75, "resolution": "distro", "trust": "low"},
    "config":       {"strength": 0.55, "resolution": "family", "trust": "low"},
}

# Emission tunables.
#   within_family_error_share : fraction of a distro-level signal's
#       error mass that lands on same-family siblings (the rest goes to
#       other families). Captures that a misfiring distro signal is more
#       likely to name a cousin than a stranger.
#   tamper_signal_retention   : residual informativeness of a LOW-TRUST
#       signal under T=1. 0.0 = attacker fully controls it; small >0
#       keeps a sliver of signal so a single forged value does not
#       instantly flip the tamper posterior.
#   loader_libc_strength      : accuracy of the PT_INTERP libc readout.
_DEFAULT_EMISSION: Dict[str, float] = {
    "within_family_error_share": 0.5,
    "tamper_signal_retention":   0.15,
    "loader_libc_strength":      0.95,
}

# Decision thresholds (kept out of code so they can be tuned against a
# labelled validation set / ROC rather than hard-coded).
_DEFAULT_THRESHOLDS: Dict[str, float] = {
    "high_confidence_distro":   0.70,
    "high_confidence_max_tamper": 0.30,
    "likely_tampered":          0.50,
}

CALIBRATION_VERSION = "p5.3-2"


def _embedded_calibration() -> Dict[str, Any]:
    return {
        "version": CALIBRATION_VERSION,
        "distro_prior": dict(_DEFAULT_DISTRO_PRIOR),
        "tamper_prior": _DEFAULT_TAMPER_PRIOR,
        "libc_cpt": {k: dict(v) for k, v in _DEFAULT_LIBC_CPT.items()},
        "signals": {k: dict(v) for k, v in _DEFAULT_SIGNALS.items()},
        "emission": dict(_DEFAULT_EMISSION),
        "thresholds": dict(_DEFAULT_THRESHOLDS),
    }


def _canonical_hash(calibration: Dict[str, Any]) -> str:
    """Stable content hash over the active parameters, excluding any
    self-referential hash field."""
    payload = {k: v for k, v in calibration.items() if k != "sha256_self"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _load_calibration() -> Dict[str, Any]:
    """Load calibration from ``bayesian_calibration.yaml`` if present and
    PyYAML is installed, otherwise fall back to the embedded defaults.

    If the YAML carries a ``sha256_self`` field it is verified against
    the hash of the remaining parameters; a mismatch is logged as a
    warning (possible config tampering) but does not abort -- the loaded
    values are still used, and the active hash is recomputed and exposed
    via :data:`CALIBRATION_SHA256`.
    """
    cal = _embedded_calibration()

    yaml_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "bayesian_calibration.yaml"
    )
    try:
        import yaml  # type: ignore
    except ImportError:
        logger.debug("PyYAML unavailable; using embedded Bayesian calibration.")
        return cal

    if not os.path.isfile(yaml_path):
        return cal

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning(
            "Failed to load %s (%s: %s); using embedded calibration.",
            yaml_path, type(e).__name__, e,
        )
        return cal

    if not isinstance(data, dict):
        return cal

    # Shallow-merge the known sections so a partial YAML only overrides
    # what it specifies.
    for key in ("version", "tamper_prior"):
        if key in data:
            cal[key] = data[key]
    for section in ("distro_prior", "libc_cpt", "signals", "emission",
                    "thresholds"):
        if isinstance(data.get(section), dict):
            cal[section].update(data[section])

    expected = data.get("sha256_self")
    if expected:
        actual = _canonical_hash({**cal, "sha256_self": None})
        if actual != expected:
            logger.warning(
                "bayesian_calibration.yaml sha256_self mismatch "
                "(expected %s, got %s); parameters may have been "
                "modified outside the attested set.", expected, actual,
            )
    return cal


_CALIBRATION = _load_calibration()
CALIBRATION_SHA256 = _canonical_hash(_CALIBRATION)

_DISTRO_PRIOR: Dict[str, float] = _CALIBRATION["distro_prior"]
_TAMPER_PRIOR: float = float(_CALIBRATION["tamper_prior"])
_LIBC_CPT: Dict[str, Dict[str, float]] = _CALIBRATION["libc_cpt"]
_SIGNALS: Dict[str, Dict[str, Any]] = _CALIBRATION["signals"]
_EMISSION: Dict[str, float] = _CALIBRATION["emission"]
_THRESHOLDS: Dict[str, float] = _CALIBRATION["thresholds"]


def calibration_fingerprint() -> Dict[str, str]:
    """Return the active calibration version and content hash for
    inclusion in the lineage attestation."""
    return {"version": str(_CALIBRATION.get("version", CALIBRATION_VERSION)),
            "sha256": CALIBRATION_SHA256}


# ════════════════════════════════════════════════════════════════════
# Result + observation types
# ════════════════════════════════════════════════════════════════════

@dataclass
class BayesianPosterior:
    distro: str                          # MAP estimate of D
    distro_probability: float            # P(D=distro | obs)
    distro_distribution: Dict[str, float]
    libc: str                            # MAP estimate of L
    libc_probability: float
    tamper_probability: float            # P(T=1 | obs)
    evidence_loglik: float = 0.0         # log P(obs) under the model
    evidence_used: List[str] = field(default_factory=list)
    calibration_sha256: str = CALIBRATION_SHA256

    @property
    def high_confidence(self) -> bool:
        return (self.distro_probability >= _THRESHOLDS["high_confidence_distro"]
                and self.tamper_probability
                <= _THRESHOLDS["high_confidence_max_tamper"])

    @property
    def likely_tampered(self) -> bool:
        return self.tamper_probability >= _THRESHOLDS["likely_tampered"]


@dataclass
class Observations:
    """Distro-mapped observations from each signal. Each field is the
    distro family the signal claims to have observed, or None when the
    signal did not fire on this image."""
    sbom_purl: Optional[str] = None
    sbom_compname: Optional[str] = None
    trivy_result_type: Optional[str] = None
    layer_match: Optional[str] = None
    config_path_style: Optional[str] = None
    pkgdb_family: Optional[str] = None
    topology_distro: Optional[str] = None
    os_release_id: Optional[str] = None
    loader_distro: Optional[str] = None
    loader_libc: Optional[str] = None


# Map each Observations field to the signal key in _SIGNALS.
_FIELD_TO_SIGNAL: Tuple[Tuple[str, str], ...] = (
    ("sbom_purl",         "purl"),
    ("sbom_compname",     "compname"),
    ("trivy_result_type", "trivy_result"),
    ("layer_match",       "layer_match"),
    ("config_path_style", "config"),
    ("pkgdb_family",      "pkgdb"),
    ("topology_distro",   "topology"),
    ("os_release_id",     "os_release"),
    ("loader_distro",     "loader"),
)


# ════════════════════════════════════════════════════════════════════
# Emission model: genuine likelihoods P(observation | D, T)
# ════════════════════════════════════════════════════════════════════

def _emission_distro_level(observed: str, distro: str, strength: float) -> float:
    """P(observed | D=distro) for a signal that names a concrete distro.

    The truthful value gets ``strength``; the error mass is split between
    same-family siblings and other distros per ``within_family_error_share``.
    Normalised over CONCRETE_DISTROS, so it is a real probability.
    """
    if distro == "unknown":
        return 1.0 / len(CONCRETE_DISTROS)  # uninformative for the catch-all

    err = 1.0 - strength
    fam = DISTRO_TO_FAMILY.get(distro)
    siblings = [d for d in FAMILIES.get(fam, ()) if d != distro] if fam else []
    others = [d for d in CONCRETE_DISTROS
              if d != distro and d not in siblings]

    beta = _EMISSION["within_family_error_share"]
    fam_mass = beta * err if siblings else 0.0
    oth_mass = err - fam_mass

    if observed == distro:
        return strength
    if observed in siblings:
        return fam_mass / len(siblings)
    if observed in others:
        return oth_mass / len(others) if others else _PROB_FLOOR
    return _PROB_FLOOR


def _emission_family_level(observed: str, distro: str, strength: float) -> float:
    """P(observed | D=distro) for a signal that can only name a family.

    Scored over family tokens: every member of the observed family gets
    the same likelihood, so a deb-family observation favours Debian and
    Ubuntu equally instead of penalising one of them.
    """
    if distro == "unknown":
        return 1.0 / _NUM_FAMILIES
    obs_fam = DISTRO_TO_FAMILY.get(observed)
    true_fam = DISTRO_TO_FAMILY.get(distro)
    if obs_fam is None or true_fam is None:
        return _PROB_FLOOR
    if obs_fam == true_fam:
        return strength
    return (1.0 - strength) / (_NUM_FAMILIES - 1)


def _signal_emission(signal_key: str, observed: str, distro: str,
                     tamper: int) -> float:
    """P(observed | D, T) for one identity signal.

    HIGH-TRUST signals are unaffected by tampering (T does not point at
    them). LOW-TRUST signals are flattened toward uniform when T=1, with
    ``tamper_signal_retention`` controlling how much true signal remains.
    """
    spec = _SIGNALS[signal_key]
    strength = float(spec["strength"])
    if spec["resolution"] == "family":
        p_clean = _emission_family_level(observed, distro, strength)
        space = _NUM_FAMILIES
    else:
        p_clean = _emission_distro_level(observed, distro, strength)
        space = len(CONCRETE_DISTROS)

    if tamper == 1 and spec["trust"] == "low":
        retention = _EMISSION["tamper_signal_retention"]
        uniform = 1.0 / space
        return (1.0 - retention) * uniform + retention * p_clean
    return p_clean


def _libc_emission(observed_libc: str, libc: str, strength: float) -> float:
    """P(loader_libc observation | L). High-trust, so unaffected by T."""
    if libc == "unknown":
        return 1.0 / len(LIBCS)
    if observed_libc == libc:
        return strength
    return (1.0 - strength) / (len(LIBCS) - 1)


# ════════════════════════════════════════════════════════════════════
# Inference
# ════════════════════════════════════════════════════════════════════

def _logsumexp(values: List[float]) -> float:
    if not values:
        return float("-inf")
    m = max(values)
    if m == float("-inf"):
        return float("-inf")
    return m + math.log(sum(math.exp(v - m) for v in values))


def infer(observations: Observations) -> BayesianPosterior:
    """Compute the joint posterior over (D, T, L) given observations and
    return the marginals.

    Inference is exact enumeration over the |D| x |T| x |L| table. We
    accumulate log P(D) + log P(T) + log P(L|D) + sum_i log P(S_i|D,T)
    + log P(loader_libc | L), then read off:

        P(D | obs) = sum_{T,L} joint
        P(L | obs) = sum_{D,T} joint
        P(T=1| obs)= sum_{D,L} joint at T=1
        log P(obs) = log-sum-exp of all cells   (the evidence)
    """
    # Collect the firing identity signals once.
    active: List[Tuple[str, str]] = []  # (signal_key, observed_value)
    for field_name, signal_key in _FIELD_TO_SIGNAL:
        value = getattr(observations, field_name)
        if value is None:
            continue
        spec = _SIGNALS[signal_key]
        # Guard against values outside the modelled space.
        if spec["resolution"] == "distro" and value not in CONCRETE_DISTROS:
            continue
        if spec["resolution"] == "family" and value not in DISTRO_TO_FAMILY:
            continue
        active.append((signal_key, value))

    obs_libc = observations.loader_libc
    if obs_libc is not None and obs_libc not in LIBCS:
        obs_libc = None
    libc_strength = _EMISSION["loader_libc_strength"]

    # Enumerate the joint in log-space.
    cells: Dict[Tuple[str, int, str], float] = {}
    for distro in DISTROS:
        log_prior_d = math.log(max(_DISTRO_PRIOR.get(distro, 1e-6), _PROB_FLOOR))
        for tamper in (0, 1):
            log_prior_t = math.log(
                _TAMPER_PRIOR if tamper == 1 else (1.0 - _TAMPER_PRIOR)
            )
            log_sig = 0.0
            for signal_key, value in active:
                p = _signal_emission(signal_key, value, distro, tamper)
                log_sig += math.log(max(p, _PROB_FLOOR))
            for libc in LIBCS:
                p_l = _LIBC_CPT.get(distro, {}).get(libc, 0.0)
                log_l = math.log(max(p_l, _PROB_FLOOR))
                if obs_libc is not None:
                    log_l += math.log(
                        max(_libc_emission(obs_libc, libc, libc_strength),
                            _PROB_FLOOR)
                    )
                cells[(distro, tamper, libc)] = (
                    log_prior_d + log_prior_t + log_sig + log_l
                )

    log_z = _logsumexp(list(cells.values()))

    # Marginals.
    distro_dist: Dict[str, float] = {d: 0.0 for d in DISTROS}
    libc_dist: Dict[str, float] = {l: 0.0 for l in LIBCS}
    tamper_mass = 0.0
    for (distro, tamper, libc), logp in cells.items():
        p = math.exp(logp - log_z)
        distro_dist[distro] += p
        libc_dist[libc] += p
        if tamper == 1:
            tamper_mass += p

    distro_label, distro_prob = max(distro_dist.items(), key=lambda kv: kv[1])
    libc_label, libc_prob = max(libc_dist.items(), key=lambda kv: kv[1])

    evidence_used: List[str] = []
    for field_name, _ in _FIELD_TO_SIGNAL:
        v = getattr(observations, field_name)
        if v is not None:
            evidence_used.append(f"{field_name}={v}")
    if observations.loader_libc is not None:
        evidence_used.append(f"loader_libc={observations.loader_libc}")

    return BayesianPosterior(
        distro=distro_label,
        distro_probability=distro_prob,
        distro_distribution=distro_dist,
        libc=libc_label,
        libc_probability=libc_prob,
        tamper_probability=tamper_mass,
        evidence_loglik=log_z,
        evidence_used=evidence_used,
        calibration_sha256=CALIBRATION_SHA256,
    )


# ════════════════════════════════════════════════════════════════════
# Adapter: ProvenanceFingerprint + SBOM signals -> Observations
# ════════════════════════════════════════════════════════════════════

def observations_from_fingerprint(
    fp: Any,
    *,
    sbom_purl_distro: Optional[str] = None,
    sbom_compname_distro: Optional[str] = None,
    trivy_result_distro: Optional[str] = None,
) -> Observations:
    """Convert a ProvenanceFingerprint (from
    :mod:`src.provenance_fingerprint`) plus optional SBOM-derived signals
    into an Observations record. Each field is normalised to a known
    DISTROS value or left None.

    Note: ``pkgdb_family`` is intentionally mapped to a single distro
    label here (e.g. dpkg -> "debian"); the inference engine treats the
    pkgdb signal as *family-level*, so that label is scored across the
    whole deb family and never penalises Ubuntu.
    """
    from .provenance_fingerprint import _normalize_distro

    obs = Observations()

    if sbom_purl_distro:
        obs.sbom_purl = _normalize_distro(sbom_purl_distro)
    if sbom_compname_distro:
        obs.sbom_compname = _normalize_distro(sbom_compname_distro)
    if trivy_result_distro:
        obs.trivy_result_type = _normalize_distro(trivy_result_distro)

    if fp is not None:
        if fp.layer_match:
            obs.layer_match = _normalize_distro(fp.layer_match.distro)
        if fp.config and fp.config.path_style:
            obs.config_path_style = _normalize_distro(fp.config.path_style)
        if fp.pkgdb and fp.pkgdb.family:
            family_to_distro = {
                "dpkg": "debian", "rpm": "rhel", "apk": "alpine",
                "pacman": "arch", "portage": "gentoo",
            }
            obs.pkgdb_family = family_to_distro.get(fp.pkgdb.family)
        if fp.topology and fp.topology.distro_hint:
            obs.topology_distro = _normalize_distro(
                fp.topology.distro_hint.split("-")[0]
            )
        if fp.os_release and fp.os_release.id:
            obs.os_release_id = _normalize_distro(fp.os_release.id)
        if fp.loader_fingerprint is not None:
            if fp.loader_fingerprint.distro_hint:
                obs.loader_distro = _normalize_distro(
                    fp.loader_fingerprint.distro_hint
                )
            if fp.loader_fingerprint.libc_family:
                obs.loader_libc = fp.loader_fingerprint.libc_family

    return obs
