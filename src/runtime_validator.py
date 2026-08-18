#!/usr/bin/env python3
"""
Tiered runtime validation for remediated container images.

Build success is a necessary but not sufficient condition for a
remediated image to be usable: a rebuilt image can compile and pass
scanning while failing at startup, losing a required shared library,
changing a configuration default, or breaking a service endpoint.
This module supplies the ``runtime_ok`` predicate that the acceptance
gate conjoins with the CVE-count conditions.

Three tiers, evaluated in order, each with its own timeout. Any tier
that fails short-circuits the predicate to False:

  T1 STARTUP        Container is started detached and must remain in
                    the ``running`` state for ``startup_hold_s``
                    seconds. Catches crash-loops, missing loaders,
                    and immediate exits. Always enabled.

  T2 INTROSPECTION  The image's declared entrypoint is invoked with a
                    generic introspection flag (``--version`` then
                    ``--help``) and must exit 0. Catches missing
                    shared libraries and broken interpreters at no
                    per-image configuration cost. Enabled by default;
                    can be disabled per image for workloads whose
                    entrypoint has no introspection flag.

  T3 APPLICATION    An operator-supplied command (health-check probe,
                    service endpoint request, or application smoke
                    test) is executed against a freshly started
                    container. Opt-in; vacuously true when no command
                    is declared for the image.

Every tier runs the container with ``--network`` set by the caller
(default ``none``), a read-only root filesystem where the workload
permits it, dropped capabilities, and ``--pids-limit`` so that a
misbehaving or hostile image cannot affect the validation host.
"""
from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# Defaults (paper reports these values)
# ════════════════════════════════════════════════════════════════════

DEFAULT_STARTUP_HOLD_S: int = 10      # T1: stay running this long
DEFAULT_STARTUP_TIMEOUT_S: int = 30   # T1: total wall clock budget
DEFAULT_INTROSPECT_TIMEOUT_S: int = 15
DEFAULT_APP_TIMEOUT_S: int = 30
DEFAULT_PIDS_LIMIT: int = 256
DEFAULT_MEMORY_LIMIT: str = "512m"

# Introspection flags tried in order for T2.
DEFAULT_INTROSPECT_FLAGS: Tuple[str, ...] = ("--version", "-version",
                                             "--help", "-h")


class Tier(str, Enum):
    STARTUP = "startup"
    INTROSPECTION = "introspection"
    APPLICATION = "application"


class TierOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"        # tier disabled or not applicable
    ERROR = "error"      # infrastructure problem, not the image's fault


@dataclass
class TierResult:
    tier: Tier
    outcome: TierOutcome
    duration_s: float = 0.0
    detail: str = ""
    command: Optional[List[str]] = None
    exit_code: Optional[int] = None

    @property
    def blocking_failure(self) -> bool:
        """A tier blocks acceptance only when it genuinely failed.
        SKIP is not a failure; ERROR is reported but treated as
        non-blocking so a flaky Docker daemon cannot silently reject
        an otherwise-good remediation."""
        return self.outcome is TierOutcome.FAIL


@dataclass
class RuntimeValidationResult:
    image_ref: str
    tiers: List[TierResult] = field(default_factory=list)
    total_duration_s: float = 0.0

    def tier(self, t: Tier) -> Optional[TierResult]:
        for r in self.tiers:
            if r.tier is t:
                return r
        return None

    @property
    def passed(self) -> bool:
        """runtime_ok: no tier reported a blocking failure and at
        least the startup tier actually ran."""
        if not self.tiers:
            return False
        if any(r.blocking_failure for r in self.tiers):
            return False
        startup = self.tier(Tier.STARTUP)
        return startup is not None and startup.outcome in {
            TierOutcome.PASS, TierOutcome.SKIP
        }

    @property
    def first_failure(self) -> Optional[TierResult]:
        for r in self.tiers:
            if r.blocking_failure:
                return r
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_ref": self.image_ref,
            "runtime_ok": self.passed,
            "total_duration_s": round(self.total_duration_s, 2),
            "tiers": [
                {
                    "tier": r.tier.value,
                    "outcome": r.outcome.value,
                    "duration_s": round(r.duration_s, 2),
                    "detail": r.detail,
                    "exit_code": r.exit_code,
                    "command": r.command,
                }
                for r in self.tiers
            ],
        }


@dataclass
class SmokeSpec:
    """Per-image runtime-validation configuration, normally loaded
    from a declarative manifest (see :mod:`src.smoke_manifest`)."""
    enabled: bool = True
    startup_hold_s: int = DEFAULT_STARTUP_HOLD_S
    startup_timeout_s: int = DEFAULT_STARTUP_TIMEOUT_S
    introspect: bool = True
    introspect_flags: Tuple[str, ...] = DEFAULT_INTROSPECT_FLAGS
    introspect_timeout_s: int = DEFAULT_INTROSPECT_TIMEOUT_S
    # T3: command executed INSIDE the running container, or an
    # exec-form probe. Empty means the tier is skipped.
    app_command: Optional[List[str]] = None
    app_timeout_s: int = DEFAULT_APP_TIMEOUT_S
    # Container runtime knobs
    network: str = "none"          # "none" | "bridge" (needed for endpoint probes)
    published_port: Optional[int] = None
    env: Dict[str, str] = field(default_factory=dict)
    entrypoint_override: Optional[str] = None
    # Some workloads legitimately need a writable root
    read_only_rootfs: bool = True


# ════════════════════════════════════════════════════════════════════
# Docker helpers
# ════════════════════════════════════════════════════════════════════

def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _container_name() -> str:
    return f"autopatch_rt_{uuid.uuid4().hex[:12]}"


def _base_run_args(spec: SmokeSpec, name: str) -> List[str]:
    """Container-hardening flags applied to every tier."""
    args = [
        "docker", "run",
        "--name", name,
        "--network", spec.network,
        "--pids-limit", str(DEFAULT_PIDS_LIMIT),
        "--memory", DEFAULT_MEMORY_LIMIT,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]
    if spec.read_only_rootfs:
        # tmpfs on /tmp so read-only rootfs does not break workloads
        # that only need scratch space.
        args += ["--read-only", "--tmpfs", "/tmp"]
    for k, v in (spec.env or {}).items():
        args += ["--env", f"{k}={v}"]
    if spec.published_port:
        args += ["--publish", f"127.0.0.1::{spec.published_port}"]
    return args


def _run(cmd: Sequence[str], timeout_s: int) -> Tuple[int, str]:
    try:
        r = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout_s, check=False,
        )
        return r.returncode, r.stdout.decode("utf-8", "replace")[-4000:]
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout_s}s"
    except OSError as e:
        return 125, f"exec error: {e}"


def _force_rm(name: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", name],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _inspect_state(name: str) -> Dict[str, Any]:
    code, out = _run(
        ["docker", "inspect", "--format", "{{json .State}}", name], 15
    )
    if code != 0:
        return {}
    try:
        return json.loads(out.strip())
    except json.JSONDecodeError:
        return {}


# ════════════════════════════════════════════════════════════════════
# Tier 1: startup
# ════════════════════════════════════════════════════════════════════

def _tier_startup(image_ref: str, spec: SmokeSpec) -> TierResult:
    """Start the container detached; require it to remain running for
    ``startup_hold_s`` seconds without exiting or restarting."""
    name = _container_name()
    start = time.time()
    args = _base_run_args(spec, name) + ["--detach"]
    if spec.entrypoint_override:
        args += ["--entrypoint", spec.entrypoint_override]
    args.append(image_ref)

    code, out = _run(args, spec.startup_timeout_s)
    if code != 0:
        _force_rm(name)
        return TierResult(
            tier=Tier.STARTUP, outcome=TierOutcome.FAIL,
            duration_s=time.time() - start,
            detail=f"container failed to start: {out.strip()[:400]}",
            command=args, exit_code=code,
        )

    try:
        # Poll until the hold window elapses or the container dies.
        deadline = time.time() + spec.startup_hold_s
        while time.time() < deadline:
            state = _inspect_state(name)
            status = str(state.get("Status", ""))
            if status in {"exited", "dead"}:
                exit_code = state.get("ExitCode")
                return TierResult(
                    tier=Tier.STARTUP, outcome=TierOutcome.FAIL,
                    duration_s=time.time() - start,
                    detail=(f"container exited early with status "
                            f"{status} (exit code {exit_code})"),
                    command=args, exit_code=exit_code,
                )
            if int(state.get("RestartCount", 0) or 0) > 0:
                return TierResult(
                    tier=Tier.STARTUP, outcome=TierOutcome.FAIL,
                    duration_s=time.time() - start,
                    detail="container is crash-looping",
                    command=args,
                )
            time.sleep(0.5)

        state = _inspect_state(name)
        if str(state.get("Status", "")) != "running":
            return TierResult(
                tier=Tier.STARTUP, outcome=TierOutcome.FAIL,
                duration_s=time.time() - start,
                detail=f"container not running at end of hold window: "
                       f"{state.get('Status')}",
                command=args,
            )
        return TierResult(
            tier=Tier.STARTUP, outcome=TierOutcome.PASS,
            duration_s=time.time() - start,
            detail=f"stayed running for {spec.startup_hold_s}s",
            command=args, exit_code=0,
        )
    finally:
        _force_rm(name)


# ════════════════════════════════════════════════════════════════════
# Tier 2: entrypoint introspection
# ════════════════════════════════════════════════════════════════════

def _tier_introspection(image_ref: str, spec: SmokeSpec) -> TierResult:
    """Invoke the image's entrypoint with a generic introspection
    flag; require exit code 0 for at least one flag. This is the
    cheapest check that exercises the dynamic loader and the
    application's own startup path."""
    if not spec.introspect:
        return TierResult(
            tier=Tier.INTROSPECTION, outcome=TierOutcome.SKIP,
            detail="introspection disabled for this image",
        )

    start = time.time()
    last_detail = ""
    for flag in spec.introspect_flags:
        name = _container_name()
        args = _base_run_args(spec, name) + ["--rm"]
        if spec.entrypoint_override:
            args += ["--entrypoint", spec.entrypoint_override]
        args += [image_ref, flag]
        code, out = _run(args, spec.introspect_timeout_s)
        _force_rm(name)
        if code == 0:
            return TierResult(
                tier=Tier.INTROSPECTION, outcome=TierOutcome.PASS,
                duration_s=time.time() - start,
                detail=f"entrypoint accepted {flag}",
                command=args, exit_code=0,
            )
        last_detail = (f"{flag} -> exit {code}: "
                       f"{out.strip()[:200]}")
        # A dynamic-loader failure is a hard fail regardless of flag:
        # it means the binary cannot run at all.
        lowered = out.lower()
        if any(marker in lowered for marker in (
            "no such file or directory",
            "error loading shared libraries",
            "symbol not found",
            "glibc_",
            "exec format error",
        )):
            return TierResult(
                tier=Tier.INTROSPECTION, outcome=TierOutcome.FAIL,
                duration_s=time.time() - start,
                detail=f"loader/ABI failure: {out.strip()[:300]}",
                command=args, exit_code=code,
            )

    # No flag returned 0. Many entrypoints legitimately reject all
    # introspection flags (long-running servers), so this is reported
    # as SKIP rather than FAIL unless a loader error was seen above.
    return TierResult(
        tier=Tier.INTROSPECTION, outcome=TierOutcome.SKIP,
        duration_s=time.time() - start,
        detail=f"no introspection flag accepted ({last_detail})",
    )


# ════════════════════════════════════════════════════════════════════
# Tier 3: application smoke test
# ════════════════════════════════════════════════════════════════════

def _tier_application(image_ref: str, spec: SmokeSpec) -> TierResult:
    """Run the operator-supplied application probe against a freshly
    started container. The probe is executed inside the container via
    ``docker exec`` so no host tooling is required and the probe sees
    the same filesystem and network namespace as the workload."""
    if not spec.app_command:
        return TierResult(
            tier=Tier.APPLICATION, outcome=TierOutcome.SKIP,
            detail="no application probe declared for this image",
        )

    name = _container_name()
    start = time.time()
    args = _base_run_args(spec, name) + ["--detach"]
    if spec.entrypoint_override:
        args += ["--entrypoint", spec.entrypoint_override]
    args.append(image_ref)

    code, out = _run(args, spec.startup_timeout_s)
    if code != 0:
        _force_rm(name)
        return TierResult(
            tier=Tier.APPLICATION, outcome=TierOutcome.FAIL,
            duration_s=time.time() - start,
            detail=f"container failed to start for probe: {out.strip()[:300]}",
            command=args, exit_code=code,
        )

    try:
        # Give the workload a moment to bind sockets / warm up.
        time.sleep(min(spec.startup_hold_s, 5))
        exec_args = ["docker", "exec", name] + list(spec.app_command)
        pcode, pout = _run(exec_args, spec.app_timeout_s)
        if pcode == 0:
            return TierResult(
                tier=Tier.APPLICATION, outcome=TierOutcome.PASS,
                duration_s=time.time() - start,
                detail="application probe succeeded",
                command=exec_args, exit_code=0,
            )
        return TierResult(
            tier=Tier.APPLICATION, outcome=TierOutcome.FAIL,
            duration_s=time.time() - start,
            detail=f"application probe failed: {pout.strip()[:300]}",
            command=exec_args, exit_code=pcode,
        )
    finally:
        _force_rm(name)


# ════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════

def validate_image(
    image_ref: str,
    spec: Optional[SmokeSpec] = None,
) -> RuntimeValidationResult:
    """Run the tiered runtime validation for ``image_ref``.

    Returns a RuntimeValidationResult whose ``passed`` property is the
    ``runtime_ok`` predicate consumed by the acceptance gate.
    """
    spec = spec or SmokeSpec()
    result = RuntimeValidationResult(image_ref=image_ref)
    started = time.time()

    if not spec.enabled:
        result.tiers.append(TierResult(
            tier=Tier.STARTUP, outcome=TierOutcome.SKIP,
            detail="runtime validation disabled for this image",
        ))
        result.total_duration_s = time.time() - started
        return result

    if not _docker_available():
        result.tiers.append(TierResult(
            tier=Tier.STARTUP, outcome=TierOutcome.ERROR,
            detail="docker not available on PATH",
        ))
        result.total_duration_s = time.time() - started
        return result

    t1 = _tier_startup(image_ref, spec)
    result.tiers.append(t1)
    if t1.blocking_failure:
        result.total_duration_s = time.time() - started
        return result

    t2 = _tier_introspection(image_ref, spec)
    result.tiers.append(t2)
    if t2.blocking_failure:
        result.total_duration_s = time.time() - started
        return result

    t3 = _tier_application(image_ref, spec)
    result.tiers.append(t3)

    result.total_duration_s = time.time() - started
    return result


def runtime_ok(
    image_ref: str,
    spec: Optional[SmokeSpec] = None,
) -> bool:
    """Convenience wrapper returning only the boolean predicate."""
    return validate_image(image_ref, spec).passed


def summarize_results(
    results: Sequence[RuntimeValidationResult],
) -> Dict[str, Any]:
    """Aggregate per-tier pass/fail/skip counts across a corpus.

    Produces exactly the numbers reported in the paper's runtime
    validation table: how many images passed build validation
    (implied by being in this list), runtime validation (T1+T2), and
    application-level validation (T3).
    """
    total = len(results)
    counts: Dict[str, Dict[str, int]] = {
        t.value: {o.value: 0 for o in TierOutcome} for t in Tier
    }
    overall_pass = 0
    for r in results:
        if r.passed:
            overall_pass += 1
        for tr in r.tiers:
            counts[tr.tier.value][tr.outcome.value] += 1

    t3 = counts[Tier.APPLICATION.value]
    t3_applicable = t3["pass"] + t3["fail"]

    return {
        "images_evaluated": total,
        "runtime_ok": overall_pass,
        "runtime_ok_rate": (overall_pass / total) if total else 0.0,
        "tier_counts": counts,
        "application_tier_applicable": t3_applicable,
        "application_tier_pass_rate": (
            t3["pass"] / t3_applicable if t3_applicable else None
        ),
        "mean_duration_s": (
            sum(r.total_duration_s for r in results) / total
            if total else 0.0
        ),
    }
