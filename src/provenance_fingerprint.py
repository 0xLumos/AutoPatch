#!/usr/bin/env python3
"""
P5-1: Multi-tier image provenance fingerprinting.

Five tiers of evidence about a container image's identity, each
independently observable without executing any code from inside the
image:

  T0: OCI layer-digest ancestry against a known-base-image index
  T1: Image config metadata (architecture, PATH ordering, labels, env)
  T2: Package-manager database presence and contents
  T3: Filesystem topology (usrmerge, package config dirs, /bin/sh)
  T4: /etc/os-release plus corroborating release files

The tiers are diverse on purpose: T0 and T1 are pure metadata, T2 and
T3 are filesystem-derived, T4 is a single canonical file. An attacker
who spoofs one tier still has to spoof the others, and the
inter-tier-agreement score the Bayesian network reads is precisely
that disagreement signal.

Loader fingerprinting (PT_INTERP and ld.so configs) lives in
:mod:`src.loader_fingerprint` and is consumed here as a sixth signal
when present.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# Tier 0: OCI layer-digest ancestry
# ════════════════════════════════════════════════════════════════════

# Curated index of known upstream base-image layer digests. In
# production this is refreshed nightly from registry crawlers; for the
# paper's evaluation the index is a static JSON shipped with the repo
# (see data/base_image_layers.json) and loaded lazily.
_LAYER_INDEX_PATH = Path(__file__).parent / "base_image_layers.json"


@dataclass(frozen=True)
class BaseImageMatch:
    upstream_ref: str          # e.g. "debian:12.4-slim"
    distro: str                # e.g. "debian"
    version: str               # e.g. "12"
    matched_layer_sha256: str  # the layer digest that matched
    confidence: float = 1.0    # 1.0 for exact match


def _load_layer_index() -> Dict[str, Dict[str, str]]:
    """Load the layer index from disk. Returns empty dict if missing
    (the rest of the pipeline still works, just without Tier 0)."""
    try:
        with open(_LAYER_INDEX_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _get_image_layers(image_ref: str, *, timeout_s: int = 20) -> List[str]:
    """Return the layer digest stack (lowest first) for image_ref.

    Uses ``docker inspect`` rather than ``docker save`` so we never
    touch the image filesystem. Returns an empty list when Docker is
    unavailable or the image cannot be inspected.
    """
    if not shutil.which("docker"):
        return []
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format",
             "{{json .RootFS.Layers}}", image_ref],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s, check=False,
        )
        if r.returncode != 0:
            return []
        layers = json.loads(r.stdout.decode("utf-8", "replace"))
        return [l for l in layers if isinstance(l, str)]
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        logger.debug("docker inspect layers failed: %s", e)
        return []


def _match_layer_ancestry(layers: List[str]) -> Optional[BaseImageMatch]:
    """For the given layer stack, return the lowest layer that appears
    in the known-base-image index, or None when no layer matches."""
    if not layers:
        return None
    idx = _load_layer_index()
    if not idx:
        return None
    # Walk from the lowest layer upward; the first match wins because
    # higher layers belong to the image's build, not the base.
    for layer in layers:
        entry = idx.get(layer)
        if entry:
            return BaseImageMatch(
                upstream_ref=entry.get("ref", "unknown"),
                distro=entry.get("distro", "unknown"),
                version=entry.get("version", "unknown"),
                matched_layer_sha256=layer,
                confidence=1.0,
            )
    return None


# ════════════════════════════════════════════════════════════════════
# Tier 1: Image config metadata
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ConfigSignals:
    architecture: Optional[str] = None
    os: Optional[str] = None
    path_env: Optional[str] = None
    path_style: Optional[str] = None   # "debian"|"rhel"|"alpine"|None
    user: Optional[str] = None
    base_image_label: Optional[str] = None
    history_count: int = 0


# Per-distro PATH ordering signatures (these are the default PATH
# inherited from the upstream base image config, before the operator's
# Dockerfile adds anything).
_PATH_STYLES: Dict[str, str] = {
    # Debian/Ubuntu standard layout
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin": "debian",
    # RHEL/CentOS/Fedora layout
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin": "rhel",
    # Alpine minimal layout
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin": "alpine",
}


def _inspect_image_config(image_ref: str, *, timeout_s: int = 20) -> ConfigSignals:
    if not shutil.which("docker"):
        return ConfigSignals()
    try:
        r = subprocess.run(
            ["docker", "inspect", image_ref],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s, check=False,
        )
        if r.returncode != 0:
            return ConfigSignals()
        data = json.loads(r.stdout.decode("utf-8", "replace"))
        if not data or not isinstance(data, list):
            return ConfigSignals()
        entry = data[0]
        cfg = entry.get("Config") or {}
        env_list = cfg.get("Env") or []
        path_env = None
        for kv in env_list:
            if isinstance(kv, str) and kv.startswith("PATH="):
                path_env = kv[5:]
                break
        labels = cfg.get("Labels") or {}
        return ConfigSignals(
            architecture=entry.get("Architecture"),
            os=entry.get("Os"),
            path_env=path_env,
            path_style=_PATH_STYLES.get(path_env or ""),
            user=cfg.get("User"),
            base_image_label=labels.get(
                "org.opencontainers.image.base.name"
            ),
            history_count=len(entry.get("RootFS", {}).get("Layers") or []),
        )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        logger.debug("docker inspect config failed: %s", e)
        return ConfigSignals()


# ════════════════════════════════════════════════════════════════════
# Tier 2: Package-manager database presence
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class PackageDbSignal:
    family: Optional[str] = None    # "dpkg"|"rpm"|"apk"|"pacman"|"portage"|"nixos"
    distro_hint: Optional[str] = None  # narrower hint when derivable
    installed_count: int = 0
    sample_packages: Tuple[str, ...] = ()


_PKGDB_PATHS: Dict[str, Tuple[str, str]] = {
    "/var/lib/dpkg/status":            ("dpkg",    ""),
    "/var/lib/rpm/Packages":           ("rpm",     ""),
    "/var/lib/rpm/rpmdb.sqlite":       ("rpm",     "rhel9+"),
    "/lib/apk/db/installed":           ("apk",     "alpine"),
    "/etc/apk/world":                  ("apk",     "alpine"),
    "/var/lib/pacman/local/ALPM_DB_VERSION": ("pacman", "arch"),
    "/etc/portage":                    ("portage", "gentoo"),
}


def _scan_pkgdb(extract_dir: Path) -> PackageDbSignal:
    """Inspect already-extracted files under ``extract_dir`` and
    return the package database signal."""
    found_family: Optional[str] = None
    distro_hint: Optional[str] = None
    sample: List[str] = []
    installed_count = 0

    # Check well-known files
    for probe, (family, hint) in _PKGDB_PATHS.items():
        local = extract_dir / probe.lstrip("/")
        if local.exists():
            found_family = family
            if hint:
                distro_hint = hint
            break

    # Dpkg status parsing (textual, simple)
    if found_family == "dpkg":
        f = extract_dir / "var/lib/dpkg/status"
        if f.is_file():
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                pkgs = re.findall(r"^Package:\s*(\S+)", text, re.MULTILINE)
                installed_count = len(pkgs)
                sample = pkgs[:10]
            except OSError:
                pass

    # Apk world parsing (one package per line)
    if found_family == "apk":
        f = extract_dir / "etc/apk/world"
        if f.is_file():
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
                pkgs = [ln.split("=", 1)[0].strip() for ln in lines if ln.strip()]
                installed_count = len(pkgs)
                sample = pkgs[:10]
            except OSError:
                pass

    return PackageDbSignal(
        family=found_family,
        distro_hint=distro_hint,
        installed_count=installed_count,
        sample_packages=tuple(sample),
    )


# ════════════════════════════════════════════════════════════════════
# Tier 3: Filesystem topology
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TopologySignal:
    usrmerge: Optional[bool] = None
    repo_config_style: Optional[str] = None   # "apt"|"yum"|"apk"|"pacman"|None
    ca_bundle_style: Optional[str] = None     # "debian"|"rhel"|None
    sh_target: Optional[str] = None
    distro_hint: Optional[str] = None


# Topology probes: a small set of paths whose existence pattern is
# diagnostic. Each tuple is (path, what its presence implies).
_TOPOLOGY_DIRS = (
    ("/etc/apt/sources.list",            "apt"),
    ("/etc/apt/sources.list.d",          "apt"),
    ("/etc/yum.repos.d",                 "yum"),
    ("/etc/dnf",                         "yum"),
    ("/etc/apk/repositories",            "apk"),
    ("/etc/pacman.conf",                 "pacman"),
    ("/etc/portage",                     "portage"),
)

_CA_BUNDLES = (
    ("/etc/ssl/certs/ca-certificates.crt", "debian"),
    ("/etc/pki/tls/certs/ca-bundle.crt",   "rhel"),
    ("/etc/ssl/cert.pem",                  "alpine"),
)


def _scan_topology(extract_dir: Path) -> TopologySignal:
    """Inspect filesystem topology probes from extracted files."""
    repo_style: Optional[str] = None
    for probe, style in _TOPOLOGY_DIRS:
        local = extract_dir / probe.lstrip("/")
        if local.exists():
            repo_style = style
            break

    ca_style: Optional[str] = None
    for probe, style in _CA_BUNDLES:
        local = extract_dir / probe.lstrip("/")
        if local.exists():
            ca_style = style
            break

    # /bin/sh target (symlink resolution is best-effort because docker
    # cp resolves symlinks when copying; we read the symlink target if
    # the extracted entry is a symlink, otherwise we leave it None).
    sh_target: Optional[str] = None
    sh = extract_dir / "bin/sh"
    if sh.is_symlink():
        try:
            sh_target = str(sh.readlink())
        except OSError:
            sh_target = None

    # Usrmerge detection: in usrmerged distros, /bin is a symlink to
    # /usr/bin. In non-usrmerged (older Alpine, busybox), they are
    # distinct directories.
    usrmerge: Optional[bool] = None
    bin_dir = extract_dir / "bin"
    if bin_dir.is_symlink():
        usrmerge = True
    elif bin_dir.is_dir():
        usrmerge = False

    # Compose a distro hint from the converging signals
    hint: Optional[str] = None
    if repo_style == "apt" and ca_style == "debian":
        hint = "debian-family"
    elif repo_style == "yum" and ca_style == "rhel":
        hint = "rhel-family"
    elif repo_style == "apk":
        hint = "alpine"
    elif repo_style == "pacman":
        hint = "arch"

    return TopologySignal(
        usrmerge=usrmerge,
        repo_config_style=repo_style,
        ca_bundle_style=ca_style,
        sh_target=sh_target,
        distro_hint=hint,
    )


# ════════════════════════════════════════════════════════════════════
# Tier 4: /etc/os-release
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class OsReleaseSignal:
    id: Optional[str] = None
    id_like: Optional[str] = None
    version_id: Optional[str] = None
    name: Optional[str] = None
    pretty_name: Optional[str] = None


def _parse_os_release(extract_dir: Path) -> OsReleaseSignal:
    for rel in ("etc/os-release", "usr/lib/os-release"):
        f = extract_dir / rel
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fields: Dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip().strip('"').strip("'")
        if fields:
            return OsReleaseSignal(
                id=fields.get("ID"),
                id_like=fields.get("ID_LIKE"),
                version_id=fields.get("VERSION_ID"),
                name=fields.get("NAME"),
                pretty_name=fields.get("PRETTY_NAME"),
            )
    return OsReleaseSignal()


# ════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════

@dataclass
class ProvenanceFingerprint:
    layer_match: Optional[BaseImageMatch] = None
    config: ConfigSignals = field(default_factory=ConfigSignals)
    pkgdb: PackageDbSignal = field(default_factory=PackageDbSignal)
    topology: TopologySignal = field(default_factory=TopologySignal)
    os_release: OsReleaseSignal = field(default_factory=OsReleaseSignal)
    loader_fingerprint: Optional[Any] = None  # LoaderFingerprint when computed
    tiers_observed: Tuple[str, ...] = ()
    consensus_distro: Optional[str] = None
    consensus_libc: Optional[str] = None
    inter_tier_agreement: float = 0.0
    fingerprint_hash: Optional[str] = None
    evidence: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict for the attestation."""
        return {
            "layer_match": (
                {
                    "upstream_ref": self.layer_match.upstream_ref,
                    "distro": self.layer_match.distro,
                    "version": self.layer_match.version,
                    "matched_layer": self.layer_match.matched_layer_sha256,
                } if self.layer_match else None
            ),
            "config": {
                "architecture": self.config.architecture,
                "os": self.config.os,
                "path_style": self.config.path_style,
            },
            "pkgdb": {
                "family": self.pkgdb.family,
                "installed_count": self.pkgdb.installed_count,
            },
            "topology": {
                "repo_config_style": self.topology.repo_config_style,
                "ca_bundle_style": self.topology.ca_bundle_style,
                "usrmerge": self.topology.usrmerge,
            },
            "os_release": {
                "id": self.os_release.id,
                "version_id": self.os_release.version_id,
                "id_like": self.os_release.id_like,
            },
            "tiers_observed": list(self.tiers_observed),
            "consensus_distro": self.consensus_distro,
            "consensus_libc": self.consensus_libc,
            "inter_tier_agreement": self.inter_tier_agreement,
        }


# Exact alias -> canonical family. Substring matching is deliberately
# NOT used here. A previous implementation fell back to
# `any(member in value for member in members)`, and because the rhel
# member set contains the two-character token "ol", every value
# containing those letters collapsed to rhel: "wolfi" and "distroless"
# both normalized to "rhel", making two separately-modelled distros
# unreachable in the Bayesian network downstream.
_DISTRO_ALIASES: Dict[str, str] = {
    # Debian family
    "debian": "debian", "raspbian": "debian",
    # Ubuntu is deb-family but a distinct distribution
    "ubuntu": "ubuntu", "linuxmint": "ubuntu", "pop": "ubuntu",
    "elementary": "ubuntu", "neon": "ubuntu",
    # RHEL family
    "rhel": "rhel", "redhat": "rhel", "red hat": "rhel",
    "centos": "rhel", "rocky": "rhel", "rockylinux": "rhel",
    "alma": "rhel", "almalinux": "rhel", "fedora": "rhel",
    "ol": "rhel", "oracle": "rhel", "oraclelinux": "rhel",
    "amzn": "rhel", "amazon": "rhel", "amazonlinux": "rhel",
    "scientific": "rhel",
    # Alpine (musl)
    "alpine": "alpine",
    # Wolfi and Chainguard are glibc undistros with apk tooling; they
    # are modelled separately because their libc differs from Alpine.
    "wolfi": "wolfi", "chainguard": "wolfi", "cgr": "wolfi",
    # Distroless is its own identity, not a member of any family
    "distroless": "distroless",
    # Others
    "arch": "arch", "archlinux": "arch", "manjaro": "arch",
    "gentoo": "gentoo",
    "nixos": "nixos", "nix": "nixos",
    "suse": "suse", "opensuse": "suse", "sles": "suse",
    "photon": "photon",
    "mariner": "mariner", "azurelinux": "mariner",
    "busybox": "busybox",
}


def _normalize_distro(value: Optional[str]) -> Optional[str]:
    """Collapse a distro identifier into its canonical family.

    Matching is exact against a curated alias table, then against the
    leading dash- or space-delimited token (so "debian-family" and
    "Red Hat Enterprise Linux" resolve). An unrecognised value is
    returned lowercased rather than being forced into a family, so the
    caller can see that it was not modelled instead of acting on a
    silently wrong classification.
    """
    if not value:
        return None
    v = value.strip().lower()
    if v in _DISTRO_ALIASES:
        return _DISTRO_ALIASES[v]

    # Progressive prefix match over delimiter-separated tokens. This
    # resolves "debian-family" from "debian" and "Red Hat Enterprise
    # Linux" from the two-token alias "red hat", while still refusing
    # to match on an arbitrary substring.
    tokens = re.split(r"[-_/ ]+", v)
    for take in range(len(tokens), 0, -1):
        candidate = " ".join(tokens[:take])
        if candidate in _DISTRO_ALIASES:
            return _DISTRO_ALIASES[candidate]
    return v


def _compute_consensus(fp: ProvenanceFingerprint) -> Tuple[Optional[str], Optional[str], float]:
    """Compute consensus distro family + libc + agreement score across
    all observed tiers. Agreement is in [0, 1]."""
    votes_distro: List[str] = []
    votes_libc: List[str] = []

    if fp.layer_match:
        d = _normalize_distro(fp.layer_match.distro)
        if d:
            votes_distro.append(d)

    if fp.pkgdb.family:
        family_to_distro = {
            "dpkg": "debian", "rpm": "rhel", "apk": "alpine",
            "pacman": "arch", "portage": "gentoo",
        }
        d = family_to_distro.get(fp.pkgdb.family)
        if d:
            votes_distro.append(d)
        # libc inferred from package manager family
        if fp.pkgdb.family == "apk":
            votes_libc.append("musl")
        elif fp.pkgdb.family in {"dpkg", "rpm", "pacman"}:
            votes_libc.append("glibc")

    if fp.topology.distro_hint:
        d = _normalize_distro(fp.topology.distro_hint.split("-")[0])
        if d:
            votes_distro.append(d)

    if fp.os_release.id:
        d = _normalize_distro(fp.os_release.id)
        if d:
            votes_distro.append(d)

    if fp.config.path_style:
        d = _normalize_distro(fp.config.path_style)
        if d:
            votes_distro.append(d)

    if fp.loader_fingerprint is not None:
        if fp.loader_fingerprint.libc_family:
            votes_libc.append(fp.loader_fingerprint.libc_family)
        if fp.loader_fingerprint.distro_hint:
            d = _normalize_distro(fp.loader_fingerprint.distro_hint)
            if d:
                votes_distro.append(d)

    def _consensus(votes: List[str]) -> Tuple[Optional[str], float]:
        if not votes:
            return None, 0.0
        counts: Dict[str, int] = {}
        for v in votes:
            counts[v] = counts.get(v, 0) + 1
        winner = max(counts.items(), key=lambda kv: kv[1])
        agree = winner[1] / len(votes)
        return winner[0], agree

    distro, d_agree = _consensus(votes_distro)
    libc, l_agree = _consensus(votes_libc)
    # Overall agreement is the lower of the two so a disagreement on
    # either axis pulls the combined score down.
    overall = min(d_agree if votes_distro else 1.0,
                  l_agree if votes_libc else 1.0)
    return distro, libc, overall


def _docker_create(image_ref: str, timeout_s: int) -> Optional[str]:
    if not shutil.which("docker"):
        return None
    try:
        r = subprocess.run(
            ["docker", "create", "--entrypoint", "/bin/true", image_ref],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s, check=False,
        )
        if r.returncode != 0:
            return None
        return r.stdout.decode("ascii", "replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return None


def _docker_cp(container_id: str, src: str, dst: Path, timeout_s: int) -> bool:
    try:
        r = subprocess.run(
            ["docker", "cp", f"{container_id}:{src}", str(dst)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s, check=False,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _docker_rm(container_id: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", container_id],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


# Paths to extract for filesystem-derived tiers
_EXTRACT_PATHS = (
    "/etc/os-release", "/usr/lib/os-release",
    "/var/lib/dpkg/status", "/var/lib/rpm",
    "/lib/apk/db/installed", "/etc/apk/world", "/etc/apk/repositories",
    "/etc/apt", "/etc/yum.repos.d", "/etc/dnf", "/etc/pacman.conf",
    "/etc/portage",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/bin", "/sbin",
)


def fingerprint_image(
    image_ref: str,
    *,
    include_loader: bool = True,
    timeout_s: int = 45,
) -> ProvenanceFingerprint:
    """Build a ProvenanceFingerprint for ``image_ref``.

    No code from inside the image is executed at any point. Returns
    a fingerprint with whichever tiers could be observed; tiers that
    fail to extract leave their slot empty rather than aborting the
    fingerprint.
    """
    fp = ProvenanceFingerprint()
    tiers_observed: List[str] = []
    evidence: List[str] = []

    # Tier 0: OCI layer ancestry
    layers = _get_image_layers(image_ref, timeout_s=timeout_s)
    fp.layer_match = _match_layer_ancestry(layers)
    if fp.layer_match:
        tiers_observed.append("T0")
        evidence.append(
            f"T0: matched upstream {fp.layer_match.upstream_ref} "
            f"via layer {fp.layer_match.matched_layer_sha256[:16]}..."
        )

    # Tier 1: image config metadata
    fp.config = _inspect_image_config(image_ref, timeout_s=timeout_s)
    if fp.config.architecture or fp.config.path_env:
        tiers_observed.append("T1")
        if fp.config.path_style:
            evidence.append(f"T1: PATH style is {fp.config.path_style}")
        if fp.config.architecture:
            evidence.append(f"T1: architecture {fp.config.architecture}")

    # Tiers 2/3/4 require filesystem extraction
    cid = _docker_create(image_ref, timeout_s)
    if cid:
        try:
            with tempfile.TemporaryDirectory(prefix="autopatch_pfp_") as td:
                tdp = Path(td)
                for src in _EXTRACT_PATHS:
                    rel = src.lstrip("/")
                    dst = tdp / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    _docker_cp(cid, src, dst, timeout_s)

                fp.pkgdb = _scan_pkgdb(tdp)
                if fp.pkgdb.family:
                    tiers_observed.append("T2")
                    evidence.append(
                        f"T2: package db {fp.pkgdb.family} "
                        f"({fp.pkgdb.installed_count} packages)"
                    )

                fp.topology = _scan_topology(tdp)
                if (fp.topology.repo_config_style
                        or fp.topology.ca_bundle_style):
                    tiers_observed.append("T3")
                    if fp.topology.distro_hint:
                        evidence.append(
                            f"T3: filesystem topology = {fp.topology.distro_hint}"
                        )

                fp.os_release = _parse_os_release(tdp)
                if fp.os_release.id:
                    tiers_observed.append("T4")
                    evidence.append(
                        f"T4: /etc/os-release ID={fp.os_release.id} "
                        f"VERSION_ID={fp.os_release.version_id}"
                    )
        finally:
            _docker_rm(cid)

    # Optional loader signal
    if include_loader:
        try:
            from .loader_fingerprint import fingerprint_image as loader_fp
            lfp = loader_fp(image_ref, timeout_s=timeout_s)
            if not lfp.empty:
                fp.loader_fingerprint = lfp
                tiers_observed.append("T5")
                if lfp.libc_family:
                    evidence.append(
                        f"T5: PT_INTERP says libc={lfp.libc_family}"
                    )
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("loader fingerprint failed: %s", e)

    fp.tiers_observed = tuple(tiers_observed)
    fp.evidence = tuple(evidence)
    fp.consensus_distro, fp.consensus_libc, fp.inter_tier_agreement = (
        _compute_consensus(fp)
    )

    # Stable content hash for the lineage attestation
    fp.fingerprint_hash = hashlib.sha256(
        json.dumps(fp.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    return fp


def fingerprint_from_extracted(
    extract_dir: Path,
    *,
    image_config: Optional[Mapping[str, Any]] = None,
    layer_stack: Optional[List[str]] = None,
) -> ProvenanceFingerprint:
    """Test-only entrypoint: build a fingerprint from already-extracted
    paths. Avoids Docker so unit tests run on any host."""
    fp = ProvenanceFingerprint()
    evidence: List[str] = []
    tiers: List[str] = []

    if layer_stack:
        fp.layer_match = _match_layer_ancestry(layer_stack)
        if fp.layer_match:
            tiers.append("T0")

    if image_config:
        path_env = None
        for kv in (image_config.get("Env") or []):
            if isinstance(kv, str) and kv.startswith("PATH="):
                path_env = kv[5:]
        fp.config = ConfigSignals(
            architecture=image_config.get("Architecture"),
            os=image_config.get("Os"),
            path_env=path_env,
            path_style=_PATH_STYLES.get(path_env or ""),
        )
        if fp.config.architecture:
            tiers.append("T1")

    fp.pkgdb = _scan_pkgdb(Path(extract_dir))
    if fp.pkgdb.family:
        tiers.append("T2")

    fp.topology = _scan_topology(Path(extract_dir))
    if fp.topology.repo_config_style or fp.topology.ca_bundle_style:
        tiers.append("T3")

    fp.os_release = _parse_os_release(Path(extract_dir))
    if fp.os_release.id:
        tiers.append("T4")

    fp.tiers_observed = tuple(tiers)
    fp.evidence = tuple(evidence)
    fp.consensus_distro, fp.consensus_libc, fp.inter_tier_agreement = (
        _compute_consensus(fp)
    )
    fp.fingerprint_hash = hashlib.sha256(
        json.dumps(fp.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return fp
