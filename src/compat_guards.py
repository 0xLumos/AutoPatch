#!/usr/bin/env python3
"""
Pre-flight compatibility guards for base-image substitution.

A candidate that fails any guard here would have produced a build
failure minutes later, or worse, an image that builds and then breaks
at runtime. Rejecting it up front converts a ten-minute timeout into an
instant candidate switch, which is the cheapest available improvement
to both build-success rate and wall-clock cost.

Four guards, each addressing an observed failure mode:

  1. DISTRO-LOCKED COMMANDS
     ``migrate_package_commands`` rewrites package-manager verbs
     (apt-get to apk and so on). It does not rewrite ``apt-key``,
     ``add-apt-repository``, ``dpkg -i``, ``update-alternatives``,
     ``debconf-set-selections``, RPM's ``yum-config-manager``, or
     distro-specific ``useradd`` flags. Those survive the rewrite
     verbatim and fail on the target.

  2. VERSION-PINNED PACKAGES
     ``curl=7.88.1-10`` is a valid Debian pin and an invalid Alpine
     one (apk uses ``=7.88.1-r0``). Carrying a pin across a family
     boundary guarantees "unable to select packages".

  3. SHELL DIALECT
     Debian and RHEL ship bash as /bin/sh-compatible enough for most
     scripts; Alpine ships busybox ash. ``[[ ]]``, ``source``,
     arrays, and ``function`` keyword syntax break there.

  4. COPY --from ACROSS A LIBC BOUNDARY
     A binary compiled in a glibc builder stage and copied into a musl
     runtime stage links against a loader that does not exist. The
     image builds; the entrypoint segfaults. This is a hard reject,
     not a warning.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


class GuardSeverity(str, Enum):
    BLOCK = "block"      # candidate cannot work; reject it
    WARN = "warn"        # likely to work, operator should know


# Callers name distributions at different granularities: the patcher's
# `_infer_os_from_image` returns point distributions (centos, rocky,
# alma, fedora) while the guards reason about package-manager families.
# Without this normalization a CentOS to Rocky upgrade, which is the
# canonical legacy-remediation case, was rejected because
# "yum-config-manager exists only on rhel" and "rocky" is not the
# string "rhel". Normalize every family at the boundary so the guards
# compare like with like.
_FAMILY_ALIASES: Dict[str, str] = {
    "debian": "debian", "raspbian": "debian",
    "ubuntu": "ubuntu", "linuxmint": "ubuntu", "pop": "ubuntu",
    "rhel": "rhel", "redhat": "rhel", "centos": "rhel",
    "rocky": "rhel", "rockylinux": "rhel", "alma": "rhel",
    "almalinux": "rhel", "fedora": "rhel", "oracle": "rhel",
    "oraclelinux": "rhel", "amazonlinux": "rhel", "amzn": "rhel",
    "alpine": "alpine",
    "wolfi": "wolfi", "chainguard": "wolfi",
    "arch": "arch", "archlinux": "arch", "manjaro": "arch",
    "suse": "suse", "opensuse": "suse", "sles": "suse",
    "gentoo": "gentoo",
    "distroless": "distroless",
}


def normalize_family(value: Optional[str]) -> Optional[str]:
    """Collapse a distribution name to its package-manager family."""
    if not value:
        return None
    return _FAMILY_ALIASES.get(value.strip().lower(), value.strip().lower())


@dataclass
class GuardFinding:
    guard: str
    severity: GuardSeverity
    detail: str
    evidence: str = ""
    line_no: Optional[int] = None

    def __str__(self) -> str:
        loc = f" (line {self.line_no})" if self.line_no else ""
        return f"[{self.severity.value}] {self.guard}{loc}: {self.detail}"


@dataclass
class GuardReport:
    findings: List[GuardFinding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(f.severity is GuardSeverity.BLOCK for f in self.findings)

    @property
    def blocking_reasons(self) -> List[str]:
        return [str(f) for f in self.findings
                if f.severity is GuardSeverity.BLOCK]

    @property
    def warnings(self) -> List[str]:
        return [str(f) for f in self.findings
                if f.severity is GuardSeverity.WARN]

    def extend(self, other: "GuardReport") -> "GuardReport":
        self.findings.extend(other.findings)
        return self


# ════════════════════════════════════════════════════════════════════
# Guard 1: distro-locked commands
# ════════════════════════════════════════════════════════════════════

# Commands that exist only in one distribution family and that the
# package-manager migration does not translate. Mapping is
# command -> families that provide it.
_DISTRO_LOCKED: Dict[str, Set[str]] = {
    # Debian/Ubuntu only
    "apt-key":                 {"debian", "ubuntu"},
    "add-apt-repository":      {"debian", "ubuntu"},
    "apt-add-repository":      {"debian", "ubuntu"},
    "dpkg-reconfigure":        {"debian", "ubuntu"},
    "debconf-set-selections":  {"debian", "ubuntu"},
    "update-alternatives":     {"debian", "ubuntu"},
    "dpkg-divert":             {"debian", "ubuntu"},
    "install-info":            {"debian", "ubuntu"},
    # RHEL family only
    "yum-config-manager":      {"rhel"},
    "dnf-config-manager":      {"rhel"},
    "rpm-ostree":              {"rhel"},
    "subscription-manager":    {"rhel"},
    "authconfig":              {"rhel"},
    # Alpine only
    "apk-tools":               {"alpine", "wolfi"},
    "setup-alpine":            {"alpine"},
    "rc-update":               {"alpine"},
    "rc-service":              {"alpine"},
}

# `dpkg -i` and `rpm -i` install a package file directly; the file
# itself is family-specific even when the verb is translated.
_PACKAGE_FILE_INSTALL = (
    (re.compile(r"\bdpkg\s+(?:-i|--install)\b"), {"debian", "ubuntu"}, ".deb"),
    (re.compile(r"\brpm\s+(?:-i|-U|--install|--upgrade)\b"), {"rhel"}, ".rpm"),
)

# useradd/groupadd flags that differ between shadow-utils (Debian,
# RHEL) and busybox (Alpine).
_BUSYBOX_INCOMPATIBLE_FLAGS = (
    ("useradd", ("--no-log-init", "-r", "--system", "--badnames")),
    ("groupadd", ("-r", "--system")),
    ("usermod", ("--append", "-a")),
)


def _iter_run_lines(dockerfile_text: str):
    """Yield ``(line_no, logical_command)`` for each RUN instruction,
    joining continuation lines into one logical command."""
    lines = dockerfile_text.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped.lower().startswith("run "):
            i += 1
            continue
        start = i
        buf = [stripped[4:]]
        while buf[-1].rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            buf[-1] = buf[-1].rstrip().rstrip("\\")
            buf.append(lines[i].strip())
        yield start + 1, " ".join(buf)
        i += 1


def check_distro_locked_commands(
    dockerfile_text: str,
    from_family: str,
    to_family: str,
) -> GuardReport:
    """Reject a family change when the Dockerfile uses commands that
    only exist in the source family."""
    report = GuardReport()
    from_family = normalize_family(from_family) or ""
    to_family = normalize_family(to_family) or ""
    if not to_family or from_family == to_family:
        return report

    for line_no, cmd in _iter_run_lines(dockerfile_text):
        tokens = set(re.findall(r"[A-Za-z0-9_.-]+", cmd))

        for locked, families in _DISTRO_LOCKED.items():
            if locked in tokens and to_family not in families:
                report.findings.append(GuardFinding(
                    guard="distro-locked-command",
                    severity=GuardSeverity.BLOCK,
                    detail=(f"'{locked}' exists only on "
                            f"{'/'.join(sorted(families))} and would not "
                            f"be present on {to_family}"),
                    evidence=cmd[:160],
                    line_no=line_no,
                ))

        for pattern, families, ext in _PACKAGE_FILE_INSTALL:
            if pattern.search(cmd) and to_family not in families:
                report.findings.append(GuardFinding(
                    guard="package-file-install",
                    severity=GuardSeverity.BLOCK,
                    detail=(f"installs a {ext} package file directly, which "
                            f"{to_family} cannot consume"),
                    evidence=cmd[:160],
                    line_no=line_no,
                ))

        if to_family in {"alpine"}:
            for tool, flags in _BUSYBOX_INCOMPATIBLE_FLAGS:
                if tool in tokens:
                    used = [f for f in flags if f in cmd.split()]
                    if used:
                        report.findings.append(GuardFinding(
                            guard="busybox-flag",
                            severity=GuardSeverity.WARN,
                            detail=(f"'{tool} {' '.join(used)}' uses "
                                    f"shadow-utils flags that busybox "
                                    f"{tool} does not accept"),
                            evidence=cmd[:160],
                            line_no=line_no,
                        ))
    return report


# ════════════════════════════════════════════════════════════════════
# Guard 2: version pins
# ════════════════════════════════════════════════════════════════════

# apt: name=1.2.3-4   |   apk: name=1.2.3-r0   |   dnf: name-1.2.3
_APT_PIN_RE = re.compile(
    r"\b([a-z0-9][a-z0-9+._-]*)=([0-9][^\s'\"]*)"
)


def check_version_pins(
    dockerfile_text: str,
    from_family: str,
    to_family: str,
) -> GuardReport:
    """A pinned package version is family-specific. Carrying it across
    a family boundary produces "unable to select packages"."""
    report = GuardReport()
    from_family = normalize_family(from_family) or ""
    to_family = normalize_family(to_family) or ""
    if not to_family or from_family == to_family:
        return report

    for line_no, cmd in _iter_run_lines(dockerfile_text):
        lowered = cmd.lower()
        if not any(pm in lowered for pm in
                   ("apt-get install", "apt install", "apk add",
                    "yum install", "dnf install")):
            continue
        pins = _APT_PIN_RE.findall(cmd)
        # Filter out shell assignments (FOO=bar) which are not pins.
        pins = [(n, v) for n, v in pins if not n.isupper()]
        if pins:
            sample = ", ".join(f"{n}={v}" for n, v in pins[:3])
            report.findings.append(GuardFinding(
                guard="version-pin",
                severity=GuardSeverity.WARN,
                detail=(f"{len(pins)} pinned package version(s) will not "
                        f"resolve on {to_family} "
                        f"(different version scheme); pins should be "
                        f"stripped or translated"),
                evidence=sample,
                line_no=line_no,
            ))
    return report


# ════════════════════════════════════════════════════════════════════
# Guard 3: shell dialect
# ════════════════════════════════════════════════════════════════════

_BASHISMS = (
    # `[[` must not match a POSIX character class such as
    # `find . -name '[[:alpha:]]*'`, which is portable and works in
    # ash. Require that the `[[` is not immediately followed by `:`.
    (re.compile(r"\[\[(?!:)"), "[[ ]] test syntax"),
    (re.compile(r"(?<![\w-])source\s+\S"), "'source' builtin (use '.')"),
    (re.compile(r"\bfunction\s+\w+\s*\(\s*\)"), "'function' keyword"),
    (re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\[[0-9@*]"), "array expansion"),
    (re.compile(r"<<<"), "here-string"),
    (re.compile(r"\bshopt\b"), "shopt builtin"),
    (re.compile(r"=~"), "regex match operator"),
    (re.compile(r"\bdeclare\s+-[aA]\b"), "declare -a/-A"),
)

# Invoking bash explicitly makes the construct portable, provided bash
# is installed on the target. Matching the bare word `bash` anywhere
# in the command was too permissive: `RUN apk add bash && [[ -f /x ]]`
# skipped the check entirely. Require an actual invocation form.
_EXPLICIT_BASH_RE = re.compile(
    r"(?:^|[|;&]\s*|\s)(?:/(?:usr/)?bin/)?bash\s+(?:-\S+\s+)*-c\b"
    r"|^\s*(?:/(?:usr/)?bin/)?bash\s+\S+\.sh\b"
)

# Families whose default /bin/sh is not bash-compatible.
_ASH_FAMILIES = {"alpine", "wolfi"}


def check_shell_dialect(
    dockerfile_text: str,
    from_family: str,
    to_family: str,
) -> GuardReport:
    """RUN commands are executed with /bin/sh. Moving to a family whose
    /bin/sh is busybox ash breaks bash-only syntax."""
    report = GuardReport()
    from_family = normalize_family(from_family) or ""
    to_family = normalize_family(to_family) or ""
    if to_family not in _ASH_FAMILIES or from_family in _ASH_FAMILIES:
        return report

    for line_no, cmd in _iter_run_lines(dockerfile_text):
        # An explicit `bash -c` is portable provided bash is installed
        # on the target, so it is not a dialect problem.
        if _EXPLICIT_BASH_RE.search(cmd):
            continue
        for pattern, label in _BASHISMS:
            if pattern.search(cmd):
                # WARN rather than BLOCK. Shell-dialect detection is
                # heuristic in both directions: a regex cannot know
                # whether the target image installs bash, nor whether
                # a construct sits inside a single-quoted string that
                # is never evaluated. A false BLOCK silently discards
                # a valid remediation, which is worse than a warning
                # the build itself will confirm or refute in minutes.
                report.findings.append(GuardFinding(
                    guard="shell-dialect",
                    severity=GuardSeverity.WARN,
                    detail=(f"uses {label}, which busybox ash on "
                            f"{to_family} does not support; the build "
                            f"will fail unless bash is installed"),
                    evidence=cmd[:160],
                    line_no=line_no,
                ))
                break
    return report


# ════════════════════════════════════════════════════════════════════
# Guard 4: COPY --from across a libc boundary
# ════════════════════════════════════════════════════════════════════

_LIBC_OF_FAMILY: Dict[str, str] = {
    # Point distributions are listed alongside their families so a
    # caller that has not normalized still gets a correct answer. A
    # missing key silently disabled this guard for every RHEL
    # derivative, which is where cross-family rewrites are most
    # common.
    "debian": "glibc", "raspbian": "glibc",
    "ubuntu": "glibc", "linuxmint": "glibc",
    "rhel": "glibc", "redhat": "glibc", "centos": "glibc",
    "rocky": "glibc", "rockylinux": "glibc",
    "alma": "glibc", "almalinux": "glibc", "fedora": "glibc",
    "oracle": "glibc", "oraclelinux": "glibc", "amazonlinux": "glibc",
    "arch": "glibc", "archlinux": "glibc",
    "wolfi": "glibc", "chainguard": "glibc",
    "suse": "glibc", "opensuse": "glibc",
    "alpine": "musl",
}


def _family_of_external_ref(ref: str) -> Optional[str]:
    """Distribution family of an image referenced by ``COPY --from=``.

    Imported lazily to keep this module free of a hard dependency on
    the patcher, which imports this one.
    """
    try:
        from .patcher import _infer_os_from_image
    except Exception as e:                 # pragma: no cover
        # Returning None reads downstream as "unknown family", which
        # makes the libc guard pass. That is a fail-OPEN on a guard
        # whose entire purpose is to stop a glibc binary landing in a
        # musl runtime, so it is at least made visible.
        logger.warning(
            "Cannot resolve the family of COPY --from=%s (%s); the libc "
            "boundary for this copy is UNCHECKED", ref, e,
        )
        return None
    return _infer_os_from_image(str(ref))


def check_copy_from_libc(
    stages: Sequence[Dict],
    stage_family_after: Dict[int, str],
) -> GuardReport:
    """Reject a rewrite that would make a ``COPY --from`` cross a libc
    boundary.

    A binary produced in a glibc stage embeds ``/lib64/ld-linux...``
    as its interpreter. Copied into a musl runtime, that path does not
    exist: the image builds successfully and then fails at exec with
    "no such file or directory", which is the single most confusing
    way a base substitution can break a workload.
    """
    report = GuardReport()
    alias_to_index: Dict[str, int] = {}
    for idx, st in enumerate(stages):
        alias = st.get("alias")
        if alias:
            alias_to_index[str(alias).lower()] = idx

    for idx, st in enumerate(stages):
        dest_family = normalize_family(stage_family_after.get(idx))
        if not dest_family:
            continue
        dest_libc = _LIBC_OF_FAMILY.get(dest_family)
        if not dest_libc:
            continue
        for ref in (st.get("copy_from_refs") or set()):
            key = str(ref).lower()
            src_idx = alias_to_index.get(key)
            src_desc: str
            if src_idx is not None:
                src_family = normalize_family(stage_family_after.get(src_idx))
                src_desc = f"stage {src_idx}"
            elif key.isdigit() and int(key) < len(stages):
                src_idx = int(key)
                src_family = normalize_family(stage_family_after.get(src_idx))
                src_desc = f"stage {src_idx}"
            else:
                # An EXTERNAL image reference, not a stage alias:
                # `COPY --from=nginx:1.25 /etc/nginx/... /etc/nginx/`.
                # This was skipped outright, so copying a glibc binary
                # out of a published image into a musl runtime passed
                # the guard and produced the exact "no such file or
                # directory" exec failure the guard exists to prevent.
                # The distribution is inferred from the reference the
                # same way a FROM line is.
                src_family = normalize_family(_family_of_external_ref(ref))
                src_desc = f"external image '{ref}'"
            if not src_family:
                continue
            src_libc = _LIBC_OF_FAMILY.get(src_family)
            if src_libc and src_libc != dest_libc:
                report.findings.append(GuardFinding(
                    guard="copy-from-libc",
                    severity=GuardSeverity.BLOCK,
                    detail=(f"stage {idx} ({dest_family}/{dest_libc}) copies "
                            f"artifacts from {src_desc} "
                            f"({src_family}/{src_libc}); a binary built "
                            f"against {src_libc} cannot execute under "
                            f"{dest_libc}"),
                    evidence=f"COPY --from={ref}",
                ))
    return report


# ════════════════════════════════════════════════════════════════════
# Combined entry point
# ════════════════════════════════════════════════════════════════════

def evaluate_candidate(
    dockerfile_text: str,
    from_family: str,
    to_family: str,
    *,
    stages: Optional[Sequence[Dict]] = None,
    stage_family_after: Optional[Dict[int, str]] = None,
) -> GuardReport:
    """Run every guard for one candidate transformation.

    Returns a report whose ``blocked`` property tells the caller to
    skip this candidate and try the next one.
    """
    report = GuardReport()
    report.extend(check_distro_locked_commands(
        dockerfile_text, from_family, to_family))
    report.extend(check_version_pins(
        dockerfile_text, from_family, to_family))
    report.extend(check_shell_dialect(
        dockerfile_text, from_family, to_family))
    if stages is not None and stage_family_after:
        report.extend(check_copy_from_libc(stages, stage_family_after))

    if report.blocked:
        logger.info(
            "Candidate %s -> %s rejected by pre-flight guards: %s",
            from_family, to_family, "; ".join(report.blocking_reasons[:3]),
        )
    return report
