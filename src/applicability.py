"""General exploitability/applicability filtering for the acceptance gate.

The problem this solves: a vulnerability scanner reports every CVE that
version-matches an installed package, but not every reported CVE is
exploitable through a container image. Gating on the raw scanner set
means the gate rejects strictly-safer images over findings that cannot
be exploited, and "fixing" that one package at a time (linux-libc-dev,
then the next, then the next) does not scale.

This module replaces package-name special-casing with a small set of
GENERAL rules keyed on exploitability class, not identity. Each rule
answers one principled question about whether a finding can affect the
container, and each is logged by name so a rejection is auditable and a
genuinely new class announces itself rather than hiding.

The four rules, in the order they are checked:

  KEV override (always first): a CVE on the CISA Known Exploited
    Vulnerabilities catalog is exploited in the wild and is NEVER
    excluded by any rule below. This bounds the aggressiveness of the
    whole filter: the worst case an exclusion can cause is admitting a
    non-KEV finding.

  1. kernel-space: the container shares the HOST kernel, so a CVE in a
     kernel package (linux-libc-dev, linux-headers-*, kernel-devel, ...)
     is not reachable through the image. Matched by pattern, so future
     kernel packages are covered without edits. Default ON: unimpeachable.

  2. no-fix-available: the scanner reports no FixedVersion, so no base
     choice -- or any tool -- can remediate it; there is no version
     without it to move to. The shipped pipeline enables this rule by
     default (--applicability default in src/main.py): fielded
     admission controllers (Kyverno, Sysdig, Microsoft Defender) gate
     on vulnerabilities WITH an available fix for exactly this reason,
     because a gate cannot demand action where no action exists. The
     dataclass field below still defaults to False so that library
     callers, tests, and the paper's Eq. (1) analyses opt in
     explicitly; the exclusion is always reported per run, never
     silent, and KEV overrides it (an actively-exploited no-fix
     finding stays in the gate).

  3. unreachable: no code path from the entrypoint reaches the package
     (from dep_graph reachability). Default OFF: requires a dependency
     graph and is reported as a sensitivity analysis, not the headline.

  4. low-exploitability: EPSS below a threshold and not in KEV. Default
     OFF: requires EPSS data and is likewise a sensitivity analysis.

ApplicabilityPolicy.literal() disables all filtering, recovering the
raw-scanner-set behaviour of the paper's literal Eq. (1).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# Kernel-space package patterns across Debian/Ubuntu (linux-*), RHEL/
# Fedora (kernel*), and Alpine (linux-lts/virt). Anchored regexes, not
# a name list, so a new kernel package variant is covered automatically.
_KERNEL_PKG_PATTERNS = [re.compile(p) for p in (
    r"^linux-libc-dev$",
    r"^linux-headers(-.*)?$",
    r"^linux-image(-.*)?$",
    r"^linux-kbuild(-.*)?$",
    r"^linux-source(-.*)?$",
    r"^linux-modules(-.*)?$",
    r"^linux-compiler(-.*)?$",
    r"^linux-tools(-.*)?$",
    r"^linux(-lts|-virt|-grsec|-rpi|-firmware.*)?$",
    r"^kernel(-.*)?$",              # kernel, kernel-headers, kernel-devel, kernel-core
    r"^kernel-headers$",
    r"^kernel-devel$",
)]


def is_kernel_space(pkg_name: str) -> bool:
    """True if ``pkg_name`` is a host-kernel package (headers, image,
    modules, tools). The container does not run this kernel."""
    p = (pkg_name or "").strip().lower()
    return any(rx.match(p) for rx in _KERNEL_PKG_PATTERNS)


@dataclass
class ApplicabilityPolicy:
    """Which exploitability-class rules exclude a finding from the gate.

    Defaults encode the two industry-standard, review-defensible rules
    (kernel-space, no-fix). The two evidence-dependent rules are off by
    default and intended as reported sensitivity analyses.
    """
    exclude_kernel_space: bool = True
    # no-fix defaults to False at the LIBRARY level so tests and the
    # Eq. (1) sensitivity analyses opt in explicitly; the shipped CLI
    # enables it by default (see src/main.py --applicability), matching
    # admission-controller practice of gating on findings with an
    # available fix. Wherever it is active the exclusion is reported
    # per run, and KEV always overrides it.
    exclude_no_fix: bool = False
    exclude_unreachable: bool = False
    exclude_low_exploitability: bool = False
    epss_threshold: float = 0.01
    reachable_packages: Optional[Set[str]] = None
    epss_data: Optional[Dict[str, float]] = None

    @classmethod
    def literal(cls) -> "ApplicabilityPolicy":
        """No filtering: the gate sees the raw scanner set, i.e. the
        literal reading of the paper's Eq. (1)."""
        return cls(exclude_kernel_space=False, exclude_no_fix=False,
                   exclude_unreachable=False, exclude_low_exploitability=False)

    @classmethod
    def with_no_fix(cls) -> "ApplicabilityPolicy":
        """Kernel-space plus no-fix exclusion. This is what the shipped
        CLI default (--applicability default) constructs."""
        return cls(exclude_kernel_space=True, exclude_no_fix=True)

    @classmethod
    def kernel_only(cls) -> "ApplicabilityPolicy":
        """Kernel-space exclusion only; no-fix findings stay in the
        gate. The pipeline's previous default, kept for sensitivity
        analyses (--applicability kernel-only)."""
        return cls(exclude_kernel_space=True, exclude_no_fix=False)

    def describe(self) -> Dict[str, object]:
        """Machine-readable record of the active policy, for the
        experiment provenance and the paper's methods section."""
        active = []
        if self.exclude_kernel_space:
            active.append("kernel-space")
        if self.exclude_no_fix:
            active.append("no-fix-available")
        if self.exclude_unreachable and self.reachable_packages is not None:
            active.append("unreachable")
        if self.exclude_low_exploitability and self.epss_data is not None:
            active.append(f"low-exploitability(epss<{self.epss_threshold:g})")
        return {"active_rules": active,
                "kev_override": True}


def classify_exclusion(
    record, policy: ApplicabilityPolicy, kev_set: Optional[Set[str]] = None,
) -> Optional[str]:
    """Return the name of the first rule excluding ``record`` from gate
    relevance, or None if the finding is applicable and the gate must
    reason about it.

    ``record`` is a vulnerability_index.VulnRecord (duck-typed on
    ``vuln_id``, ``pkg_name``, ``fixed_version``).
    """
    # KEV overrides every exclusion. Actively-exploited findings are
    # never filtered, whatever package they sit in.
    if kev_set and record.vuln_id in kev_set:
        return None

    if policy.exclude_kernel_space and is_kernel_space(record.pkg_name):
        return "kernel-space"

    if policy.exclude_no_fix and not (record.fixed_version or "").strip():
        return "no-fix-available"

    if (policy.exclude_unreachable and policy.reachable_packages is not None):
        reachable = {p.lower() for p in policy.reachable_packages}
        if (record.pkg_name or "").lower() not in reachable:
            return "unreachable"

    if (policy.exclude_low_exploitability and policy.epss_data is not None):
        if policy.epss_data.get(record.vuln_id, 1.0) < policy.epss_threshold:
            return "low-exploitability"

    return None


def partition_applicable(
    records, policy: ApplicabilityPolicy, kev_set: Optional[Set[str]] = None,
) -> Tuple[list, Dict[str, list]]:
    """Split ``records`` into (applicable, {rule: [excluded records]}).

    The applicable list is what the acceptance gate reasons about; the
    excluded map is what makes a rejection explainable -- "16 new HIGH,
    16 excluded kernel-space, 0 applicable" -- and what surfaces a new
    class when a rejection has excluded records under no rule at all.
    """
    applicable: list = []
    excluded: Dict[str, list] = {}
    for r in records:
        rule = classify_exclusion(r, policy, kev_set)
        if rule is None:
            applicable.append(r)
        else:
            excluded.setdefault(rule, []).append(r)
    return applicable, excluded


def exclusion_summary(excluded: Dict[str, list]) -> str:
    """One-line human summary of an exclusion map, for gate feedback."""
    if not excluded:
        return "none"
    return ", ".join(f"{rule}: {len(recs)}"
                     for rule, recs in sorted(excluded.items()))
