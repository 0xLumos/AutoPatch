#!/usr/bin/env python3
"""
Differential validation: original image versus remediated image.

The tiered predicate in :mod:`src.runtime_validator` establishes that
the remediated image starts and responds. It does not establish that
the remediated image behaves like the image it replaced. A base-image
substitution can produce a container that starts cleanly yet:

  * exposes a different set of ports,
  * runs as a different user or with a different working directory,
  * inherits a different default environment (locale, PATH, TZ,
    language-runtime variables),
  * resolves its entrypoint to a different binary,
  * changes ownership or mode on the application's own files,
  * loses outbound DNS or TLS trust because the CA bundle moved.

Each of those is invisible to a CVE scanner and to a build. This
module observes the same properties on both images and reports the
divergences, so the paper can state which behavioural dimensions were
compared rather than claiming unqualified functional correctness.

Two classes of observation, with different trust properties, and the
difference matters:

*Configuration dimensions* (entrypoint, exposed ports, user, working
directory, environment) are read from ``docker inspect``. The image
never executes, so these observations are trustworthy against a
hostile image.

*Runtime probe dimensions* (TLS trust, DNS, file modes, shared
libraries) are obtained by running a command AutoPatch supplies inside
a container started from the image. The command is ours, but the
``sh``, ``stat``, ``ldd`` and ``getent`` binaries that execute it come
from the image. A deliberately hostile image can therefore ship
binaries that report whatever it likes, and these dimensions must not
be read as an integrity guarantee. They are a regression check against
an image assumed non-adversarial, which is the actual threat model for
base-image remediation: the risk being managed is an upstream
substitution that breaks the workload, not an attacker who controls
the image and is trying to fool the analyzer. Adversarial detection is
the job of :mod:`src.provenance_fingerprint`, which extracts files
with ``docker cp`` and parses them on the host without executing
anything.

Probe containers run with no network, all capabilities dropped, a
read-only root filesystem, a pid limit and a memory limit, so a
misbehaving image cannot affect the host regardless.
"""
from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


DEFAULT_PROBE_TIMEOUT_S: int = 25


class Dimension(str, Enum):
    """Behavioural dimensions compared between the two images."""
    ENTRYPOINT = "entrypoint"          # ENTRYPOINT/CMD resolution
    EXPOSED_PORTS = "exposed_ports"    # declared listening surface
    USER = "user"                      # runtime UID/GID
    WORKDIR = "workdir"
    ENVIRONMENT = "environment"        # locale, TZ, runtime vars
    CA_TRUST = "ca_trust"              # TLS trust store presence
    DNS = "dns"                        # name resolution capability
    FILE_MODES = "file_modes"          # ownership/permissions on app paths
    SHARED_LIBS = "shared_libs"        # dynamic dependencies resolvable


class Verdict(str, Enum):
    MATCH = "match"           # same on both images
    DIVERGED = "diverged"     # differs; may or may not be benign
    UNAVAILABLE = "unavailable"  # could not observe on one/both images


@dataclass
class DimensionResult:
    dimension: Dimension
    verdict: Verdict
    original: Optional[str] = None
    patched: Optional[str] = None
    detail: str = ""
    benign: bool = False   # divergence explicitly allowed by policy

    @property
    def is_regression(self) -> bool:
        return self.verdict is Verdict.DIVERGED and not self.benign


@dataclass
class DifferentialResult:
    original_ref: str
    patched_ref: str
    dimensions: List[DimensionResult] = field(default_factory=list)

    def get(self, d: Dimension) -> Optional[DimensionResult]:
        for r in self.dimensions:
            if r.dimension is d:
                return r
        return None

    @property
    def regressions(self) -> List[DimensionResult]:
        return [r for r in self.dimensions if r.is_regression]

    @property
    def equivalent(self) -> bool:
        """True when no dimension diverged in a non-benign way. This is
        deliberately named `equivalent` rather than `correct`: it is
        equivalence over the observed dimensions, not proof of
        functional correctness."""
        return not self.regressions

    @property
    def dimensions_compared(self) -> int:
        return sum(1 for r in self.dimensions
                   if r.verdict is not Verdict.UNAVAILABLE)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_ref": self.original_ref,
            "patched_ref": self.patched_ref,
            "equivalent": self.equivalent,
            "dimensions_compared": self.dimensions_compared,
            "regression_count": len(self.regressions),
            "dimensions": [
                {
                    "dimension": r.dimension.value,
                    "verdict": r.verdict.value,
                    "original": r.original,
                    "patched": r.patched,
                    "detail": r.detail,
                    "benign": r.benign,
                }
                for r in self.dimensions
            ],
        }


@dataclass
class DiffPolicy:
    """Which divergences are acceptable.

    Base-image substitution legitimately changes some things: the OS
    version string moves, the package set differs, image size changes.
    Those are the point of the transformation. The policy separates
    expected divergence from behavioural regression.
    """
    # Environment variables whose divergence is expected and benign.
    benign_env_keys: Tuple[str, ...] = (
        "PATH",            # distro layouts differ legitimately
        "HOSTNAME",
        "container",
        "DEBIAN_FRONTEND",
    )
    # Environment variables whose divergence is a regression: these
    # change application behaviour rather than image provenance.
    critical_env_keys: Tuple[str, ...] = (
        "LANG", "LC_ALL", "TZ",
        "PYTHONPATH", "PYTHONIOENCODING",
        "NODE_PATH", "NODE_ENV",
        "JAVA_HOME", "CLASSPATH",
        "GEM_HOME", "GEM_PATH",
        "GOPATH", "GOROOT",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    )
    require_same_user: bool = True
    require_same_workdir: bool = True
    require_same_ports: bool = True
    require_ca_trust: bool = True
    require_dns: bool = False   # needs network; off by default
    # Paths whose ownership/mode are compared when present.
    file_mode_paths: Tuple[str, ...] = ("/app", "/usr/src/app", "/srv",
                                        "/var/www", "/opt/app")


# ════════════════════════════════════════════════════════════════════
# Observation helpers
# ════════════════════════════════════════════════════════════════════

def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _inspect(image_ref: str, timeout_s: int = 20) -> Dict[str, Any]:
    try:
        r = subprocess.run(
            ["docker", "inspect", image_ref],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s, check=False,
        )
        if r.returncode != 0:
            return {}
        data = json.loads(r.stdout.decode("utf-8", "replace"))
        return data[0] if isinstance(data, list) and data else {}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        logger.debug("inspect failed for %s: %s", image_ref, e)
        return {}


def _probe(
    image_ref: str,
    argv: Sequence[str],
    *,
    network: str = "none",
    timeout_s: int = DEFAULT_PROBE_TIMEOUT_S,
) -> Tuple[int, str]:
    """Run an AutoPatch-supplied command inside a throwaway container
    built from ``image_ref``.

    The command is ours, but it is interpreted by the image's own
    shell and utilities, so the *result* is only as trustworthy as the
    image. See the module docstring: these probes detect breakage, not
    adversarial behaviour. The containment flags below exist so that a
    broken or hostile image cannot affect the host either way.
    """
    name = f"autopatch_diff_{uuid.uuid4().hex[:10]}"
    cmd = [
        "docker", "run", "--rm", "--name", name,
        "--network", network,
        "--pids-limit", "128",
        "--memory", "384m",
        "--memory-swap", "384m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        # A probe never needs to write to the image filesystem. tmpfs
        # on /tmp keeps tools that insist on scratch space working.
        "--read-only",
        "--tmpfs", "/tmp:size=16m",
        "--entrypoint", argv[0],
        image_ref,
    ] + list(argv[1:])
    try:
        r = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout_s, check=False,
        )
        return r.returncode, r.stdout.decode("utf-8", "replace")[-4000:]
    except subprocess.TimeoutExpired:
        # The CLI is dead but the daemon may still hold the container,
        # so the cleanup below is what actually reclaims it.
        return 124, "timeout"
    except OSError as e:
        return 125, f"exec error: {e}"
    finally:
        # `--rm` covers the normal exit; this covers timeout and kill.
        # It must never raise out of the finally block, or a slow
        # daemon would discard a probe result that was already
        # obtained.
        try:
            subprocess.run(["docker", "rm", "-f", name],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            logger.debug("probe container %s cleanup did not complete", name)


def _env_map(cfg: Mapping[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for kv in (cfg.get("Env") or []):
        if isinstance(kv, str) and "=" in kv:
            k, _, v = kv.partition("=")
            out[k] = v
    return out


def _norm_list(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(x) for x in value)
    return str(value)


# ════════════════════════════════════════════════════════════════════
# Dimension comparisons (configuration-derived)
# ════════════════════════════════════════════════════════════════════

def _cmp_entrypoint(o: Mapping, p: Mapping) -> DimensionResult:
    oc, pc = o.get("Config") or {}, p.get("Config") or {}
    o_ep, o_cmd = _norm_list(oc.get("Entrypoint")), _norm_list(oc.get("Cmd"))
    p_ep, p_cmd = _norm_list(pc.get("Entrypoint")), _norm_list(pc.get("Cmd"))
    # Build the comparison strings only after establishing that at
    # least one image declares something; otherwise the separator
    # itself would look like content and turn "nothing declared" into
    # a spurious MATCH.
    if not any((o_ep, o_cmd, p_ep, p_cmd)):
        return DimensionResult(Dimension.ENTRYPOINT, Verdict.UNAVAILABLE,
                               detail="neither image declares ENTRYPOINT/CMD")
    ov = f"{o_ep} | {o_cmd}".strip()
    pv = f"{p_ep} | {p_cmd}".strip()
    if ov == pv:
        return DimensionResult(Dimension.ENTRYPOINT, Verdict.MATCH,
                               original=ov, patched=pv)
    return DimensionResult(
        Dimension.ENTRYPOINT, Verdict.DIVERGED, original=ov, patched=pv,
        detail="entrypoint or command resolution changed",
    )


def _cmp_ports(o: Mapping, p: Mapping, policy: DiffPolicy) -> DimensionResult:
    oc, pc = o.get("Config") or {}, p.get("Config") or {}
    ov = sorted((oc.get("ExposedPorts") or {}).keys())
    pv = sorted((pc.get("ExposedPorts") or {}).keys())
    if not ov and not pv:
        return DimensionResult(Dimension.EXPOSED_PORTS, Verdict.UNAVAILABLE,
                               detail="no ports declared on either image")
    if ov == pv:
        return DimensionResult(Dimension.EXPOSED_PORTS, Verdict.MATCH,
                               original=",".join(ov), patched=",".join(pv))
    return DimensionResult(
        Dimension.EXPOSED_PORTS, Verdict.DIVERGED,
        original=",".join(ov), patched=",".join(pv),
        detail="declared listening surface changed",
        benign=not policy.require_same_ports,
    )


def _cmp_user(o: Mapping, p: Mapping, policy: DiffPolicy) -> DimensionResult:
    ov = str((o.get("Config") or {}).get("User") or "root")
    pv = str((p.get("Config") or {}).get("User") or "root")
    if ov == pv:
        return DimensionResult(Dimension.USER, Verdict.MATCH,
                               original=ov, patched=pv)
    return DimensionResult(
        Dimension.USER, Verdict.DIVERGED, original=ov, patched=pv,
        detail="container runs as a different user; file permissions "
               "and privilege posture may change",
        benign=not policy.require_same_user,
    )


def _cmp_workdir(o: Mapping, p: Mapping, policy: DiffPolicy) -> DimensionResult:
    ov = str((o.get("Config") or {}).get("WorkingDir") or "/")
    pv = str((p.get("Config") or {}).get("WorkingDir") or "/")
    if ov == pv:
        return DimensionResult(Dimension.WORKDIR, Verdict.MATCH,
                               original=ov, patched=pv)
    return DimensionResult(
        Dimension.WORKDIR, Verdict.DIVERGED, original=ov, patched=pv,
        detail="working directory changed; relative paths may break",
        benign=not policy.require_same_workdir,
    )


def _cmp_environment(o: Mapping, p: Mapping,
                     policy: DiffPolicy) -> DimensionResult:
    oe = _env_map(o.get("Config") or {})
    pe = _env_map(p.get("Config") or {})
    changed: List[str] = []
    for key in sorted(set(oe) | set(pe)):
        if key in policy.benign_env_keys:
            continue
        if oe.get(key) != pe.get(key):
            changed.append(f"{key}: {oe.get(key)!r} -> {pe.get(key)!r}")
    critical = [c for c in changed
                if c.split(":", 1)[0] in policy.critical_env_keys]
    if not changed:
        return DimensionResult(Dimension.ENVIRONMENT, Verdict.MATCH,
                               detail="no behavioural env changes")
    return DimensionResult(
        Dimension.ENVIRONMENT, Verdict.DIVERGED,
        original="; ".join(sorted(oe)), patched="; ".join(sorted(pe)),
        detail=("critical: " + "; ".join(critical[:6])) if critical
               else ("non-critical: " + "; ".join(changed[:6])),
        # Only variables that steer application behaviour count as a
        # regression; provenance-ish variables do not.
        benign=not critical,
    )


# ════════════════════════════════════════════════════════════════════
# Dimension comparisons (runtime-derived)
# ════════════════════════════════════════════════════════════════════

_CA_PROBE = ["sh", "-c",
             "for f in /etc/ssl/certs/ca-certificates.crt "
             "/etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do "
             "[ -s \"$f\" ] && echo present && exit 0; done; "
             "echo absent"]

_DNS_PROBE = ["sh", "-c",
              "getent hosts example.com >/dev/null 2>&1 && echo resolves "
              "|| echo unresolved"]


def _cmp_ca_trust(orig: str, patched: str,
                  policy: DiffPolicy) -> DimensionResult:
    oc, oout = _probe(orig, _CA_PROBE)
    pc, pout = _probe(patched, _CA_PROBE)
    if oc not in (0,) or pc not in (0,):
        return DimensionResult(Dimension.CA_TRUST, Verdict.UNAVAILABLE,
                               detail="CA probe could not run on one image")
    ov, pv = oout.strip().split()[-1], pout.strip().split()[-1]
    if ov == pv:
        return DimensionResult(Dimension.CA_TRUST, Verdict.MATCH,
                               original=ov, patched=pv)
    return DimensionResult(
        Dimension.CA_TRUST, Verdict.DIVERGED, original=ov, patched=pv,
        detail="TLS trust store availability changed; outbound HTTPS "
               "may fail in the remediated image",
        benign=not policy.require_ca_trust,
    )


def _cmp_dns(orig: str, patched: str, policy: DiffPolicy) -> DimensionResult:
    if not policy.require_dns:
        return DimensionResult(Dimension.DNS, Verdict.UNAVAILABLE,
                               detail="DNS comparison disabled by policy")
    oc, oout = _probe(orig, _DNS_PROBE, network="bridge")
    pc, pout = _probe(patched, _DNS_PROBE, network="bridge")
    if oc != 0 or pc != 0:
        return DimensionResult(Dimension.DNS, Verdict.UNAVAILABLE,
                               detail="DNS probe could not run")
    ov, pv = oout.strip().split()[-1], pout.strip().split()[-1]
    if ov == pv:
        return DimensionResult(Dimension.DNS, Verdict.MATCH,
                               original=ov, patched=pv)
    return DimensionResult(
        Dimension.DNS, Verdict.DIVERGED, original=ov, patched=pv,
        detail="name resolution capability changed",
    )


def _cmp_file_modes(orig: str, patched: str,
                    policy: DiffPolicy) -> DimensionResult:
    paths = " ".join(shlex.quote(p) for p in policy.file_mode_paths)
    probe = ["sh", "-c",
             f"for d in {paths}; do [ -e \"$d\" ] && "
             f"printf '%s ' \"$d\" && (stat -c '%U:%G:%a' \"$d\" 2>/dev/null "
             f"|| stat -f '%Su:%Sg:%Lp' \"$d\" 2>/dev/null) ; done"]
    oc, oout = _probe(orig, probe)
    pc, pout = _probe(patched, probe)
    if oc != 0 or pc != 0:
        return DimensionResult(Dimension.FILE_MODES, Verdict.UNAVAILABLE,
                               detail="stat probe unavailable in image")
    ov, pv = oout.strip(), pout.strip()
    if not ov and not pv:
        return DimensionResult(Dimension.FILE_MODES, Verdict.UNAVAILABLE,
                               detail="no application directories present")
    if ov == pv:
        return DimensionResult(Dimension.FILE_MODES, Verdict.MATCH,
                               original=ov[:200], patched=pv[:200])
    return DimensionResult(
        Dimension.FILE_MODES, Verdict.DIVERGED,
        original=ov[:200], patched=pv[:200],
        detail="ownership or mode changed on application paths",
    )


# The probe must distinguish three outcomes that the previous
# implementation collapsed into one:
#
#   "ldd absent"        -> UNAVAILABLE (static, musl-only, distroless)
#   "ldd ran, 0 missing"-> a real observation
#   "ldd ran, N missing"-> a real observation
#
# The earlier pipeline ended in `grep -c ... || echo 0`, and because
# `grep -c` exits 1 when it matches nothing, `echo 0` always ran and
# `sh -c` always exited 0. The UNAVAILABLE branch was therefore
# unreachable, and on an image without ldd both sides parsed as 0 and
# the dimension reported MATCH without having checked anything. A
# sentinel line makes the three cases separable.
_LDD_PROBE = ["sh", "-c",
              "command -v ldd >/dev/null 2>&1 || { echo AUTOPATCH_NO_LDD; exit 0; }; "
              "t=$(readlink -f /proc/1/exe 2>/dev/null); "
              "[ -x \"$t\" ] || t=/bin/sh; "
              "out=$(ldd \"$t\" 2>&1) || { echo AUTOPATCH_LDD_FAILED; exit 0; }; "
              "printf 'AUTOPATCH_MISSING=%s\\n' "
              "\"$(printf '%s\\n' \"$out\" | grep -c 'not found')\""]


def _parse_ldd_probe(out: str) -> Optional[int]:
    """Return the count of unresolved libraries, or None when the
    observation could not be made."""
    text = (out or "").strip()
    if not text or "AUTOPATCH_NO_LDD" in text or "AUTOPATCH_LDD_FAILED" in text:
        return None
    for line in reversed(text.splitlines()):
        if line.startswith("AUTOPATCH_MISSING="):
            try:
                return int(line.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None


def _cmp_shared_libs(orig: str, patched: str) -> DimensionResult:
    """Verify that the image's principal binary still resolves its
    dynamic dependencies. A 'not found' line from ldd is the signature
    of the lost-shared-library failure mode, which is the most common
    way a base substitution produces an image that builds but cannot
    run."""
    oc, oout = _probe(orig, _LDD_PROBE)
    pc, pout = _probe(patched, _LDD_PROBE)
    if oc != 0 or pc != 0:
        return DimensionResult(
            Dimension.SHARED_LIBS, Verdict.UNAVAILABLE,
            detail="probe could not execute in one or both images")

    ov = _parse_ldd_probe(oout)
    pv = _parse_ldd_probe(pout)
    if ov is None or pv is None:
        # Genuinely not observable (static binary, musl without ldd,
        # distroless). Reporting UNAVAILABLE is the honest answer;
        # reporting MATCH would assert an equivalence never tested.
        return DimensionResult(
            Dimension.SHARED_LIBS, Verdict.UNAVAILABLE,
            detail="ldd unavailable in one or both images "
                   "(static, musl-only, or distroless)")

    if pv <= ov:
        return DimensionResult(Dimension.SHARED_LIBS, Verdict.MATCH,
                               original=str(ov), patched=str(pv),
                               detail="no new unresolved libraries")
    return DimensionResult(
        Dimension.SHARED_LIBS, Verdict.DIVERGED,
        original=str(ov), patched=str(pv),
        detail=f"remediated image has {pv - ov} newly unresolved "
               f"shared librar{'y' if pv - ov == 1 else 'ies'}",
    )


# ════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════

def compare_images(
    original_ref: str,
    patched_ref: str,
    policy: Optional[DiffPolicy] = None,
    *,
    include_runtime_probes: bool = True,
) -> DifferentialResult:
    """Compare the two images across the behavioural dimensions.

    Configuration dimensions are always compared (cheap, metadata
    only). Runtime probe dimensions are compared when
    ``include_runtime_probes`` is set and Docker is available.
    """
    policy = policy or DiffPolicy()
    result = DifferentialResult(original_ref=original_ref,
                                patched_ref=patched_ref)

    if not _docker_available():
        result.dimensions.append(DimensionResult(
            Dimension.ENTRYPOINT, Verdict.UNAVAILABLE,
            detail="docker not available"))
        return result

    o, p = _inspect(original_ref), _inspect(patched_ref)
    if not o or not p:
        result.dimensions.append(DimensionResult(
            Dimension.ENTRYPOINT, Verdict.UNAVAILABLE,
            detail="one or both images could not be inspected"))
        return result

    result.dimensions.append(_cmp_entrypoint(o, p))
    result.dimensions.append(_cmp_ports(o, p, policy))
    result.dimensions.append(_cmp_user(o, p, policy))
    result.dimensions.append(_cmp_workdir(o, p, policy))
    result.dimensions.append(_cmp_environment(o, p, policy))

    if include_runtime_probes:
        result.dimensions.append(_cmp_ca_trust(original_ref, patched_ref, policy))
        result.dimensions.append(_cmp_file_modes(original_ref, patched_ref, policy))
        result.dimensions.append(_cmp_shared_libs(original_ref, patched_ref))
        result.dimensions.append(_cmp_dns(original_ref, patched_ref, policy))

    return result


def summarize_differential(
    results: Sequence[DifferentialResult],
) -> Dict[str, Any]:
    """Aggregate per-dimension outcomes across a corpus, for the
    paper's behavioural-equivalence table."""
    per_dim: Dict[str, Dict[str, int]] = {
        d.value: {v.value: 0 for v in Verdict} for d in Dimension
    }
    equivalent = 0
    for r in results:
        if r.equivalent:
            equivalent += 1
        for dr in r.dimensions:
            per_dim[dr.dimension.value][dr.verdict.value] += 1

    total = len(results)
    return {
        "images_compared": total,
        "behaviourally_equivalent": equivalent,
        "equivalence_rate": (equivalent / total) if total else 0.0,
        "regressions_by_dimension": {
            dim: counts["diverged"] for dim, counts in per_dim.items()
        },
        "per_dimension": per_dim,
    }
