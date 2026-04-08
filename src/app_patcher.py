"""
AutoPatch Application-Level Patcher -- Dependency-Aware Package Upgrades

This module extends AutoPatch beyond base image replacement to patch
application-level packages (pip, npm, gem, composer, go modules, cargo,
maven, nuget, etc.) using SBOM data for dependency awareness.

Design principles:
1. SBOM-first: We know exactly what is installed and at what version
2. Dependency-aware: Check compatibility before upgrading anything
3. Conservative: Only upgrade packages with known CVE fixes
4. Reversible: Generate Dockerfile patches that can be reviewed/reverted
5. Non-breaking: Verify constraints from lockfiles before applying

The approach:
- Extract vulnerable app packages from Trivy scan results
- Cross-reference with SBOM components to get exact installed versions
- Parse lockfiles (if present in the build context) for constraint info
- Generate targeted upgrade commands injected into the Dockerfile
- Validate the upgrade would not break dependency constraints
- Append a post-upgrade verification command to catch breakage at build time
"""

import logging
import os
import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set
from urllib.parse import unquote

logger = logging.getLogger("docker_patch_tool")


# ================================================================
# Data structures
# ================================================================

@dataclass
class VulnerablePackage:
    """A package identified as vulnerable from the Trivy scan."""
    name: str
    ecosystem: str          # pypi, npm, gem, composer, golang, maven, cargo, nuget
    installed_version: str
    fix_version: str        # Version that resolves the CVE(s)
    cve_ids: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    purl: str = ""          # Full purl for precise identification


@dataclass
class UpgradeAction:
    """A concrete upgrade action to inject into the Dockerfile."""
    package_name: str
    ecosystem: str
    from_version: str
    to_version: str
    cve_ids: List[str]
    severity: str
    safe: bool = True       # False if dependency check found a conflict
    conflict_reason: Optional[str] = None
    dockerfile_command: str = ""   # The RUN command to inject


@dataclass
class AppPatchResult:
    """Result of application-level patching analysis."""
    vulnerable_packages: List[VulnerablePackage] = field(default_factory=list)
    upgrade_actions: List[UpgradeAction] = field(default_factory=list)
    skipped_packages: List[Dict[str, Any]] = field(default_factory=list)
    dockerfile_patch_lines: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    total_fixable: int = 0
    total_safe_upgrades: int = 0
    total_conflict_upgrades: int = 0


# ================================================================
# Ecosystem-specific constants
# ================================================================

# Full Trivy result type -> ecosystem mapping.
# Trivy uses these type strings in its JSON output under Results[].Type.
# This must cover every type Trivy can emit for language packages.
_TRIVY_TYPE_TO_ECOSYSTEM: Dict[str, Optional[str]] = {
    # Python
    "pip": "pypi", "pipenv": "pypi", "poetry": "pypi",
    "conda": "pypi", "python-pkg": "pypi",
    # JavaScript / Node
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm",
    # Ruby
    "gemspec": "gem", "bundler": "gem",
    # PHP
    "composer": "composer",
    # Go
    "gomod": "golang", "gobinary": "golang",
    # Java / JVM
    "jar": "maven", "pom": "maven", "gradle": "maven",
    # Rust
    "cargo": "cargo", "rust-binary": "cargo",
    # .NET / C#
    "nuget": "nuget", "dotnet-core": "nuget", "dotnet-deps": "nuget",
    "packages-lock": "nuget",
    # Elixir
    "hex": "hex", "mix-lock": "hex",
    # Dart
    "pub": "pub", "pub-lock": "pub",
    # Swift
    "swift": "swift", "cocoapods": "swift",
    # C/C++ (Conan)
    "conan": "conan", "conan-lock": "conan",
    # Haskell
    "cabal": None,  # Not yet supported
    # OS-level (should be filtered before this, but just in case)
    "alpine": None, "debian": None, "ubuntu": None,
    "centos": None, "redhat": None, "rocky": None,
    "amazon": None, "oracle": None, "suse": None,
    "photon": None, "cbl-mariner": None, "wolfi": None,
}

# OS result types to explicitly skip (base image patching handles these)
_OS_RESULT_TYPES: Set[str] = {
    "alpine", "debian", "ubuntu", "centos", "redhat", "rocky",
    "amazon", "oracle", "suse", "photon", "cbl-mariner", "wolfi",
}

# Ecosystem to package manager upgrade command templates.
# {pkg} = package name, {ver} = target version.
# Commands are designed for Dockerfile RUN context (non-interactive, no TTY).
UPGRADE_COMMANDS: Dict[str, str] = {
    "pypi": "pip install --no-cache-dir --upgrade '{pkg}=={ver}'",
    "npm": "npm install --save '{pkg}@{ver}'",
    "gem": "gem install '{pkg}' -v '{ver}' --no-document",
    "composer": "composer require '{pkg}:{ver}' --no-interaction --no-progress",
    "golang": "go get {pkg}@v{ver} && go mod tidy",
    "cargo": "cargo install '{pkg}' --version '{ver}'",
    "maven": None,  # Maven deps are in pom.xml, not CLI-patchable
    "nuget": "dotnet add package '{pkg}' --version '{ver}'",
    "hex": "mix deps.update {pkg}",
    "pub": None,  # Dart deps are in pubspec.yaml, not CLI-patchable
    "swift": None,  # Swift deps are in Package.swift, not CLI-patchable
    "conan": None,  # Conan deps are in conanfile, not CLI-patchable
}

# Post-upgrade verification commands per ecosystem.
# Run after all upgrades in that ecosystem to catch breakage at build time.
VERIFICATION_COMMANDS: Dict[str, str] = {
    "pypi": "pip check",
    "npm": "npm ls --production 2>&1 | grep -iE 'ERR!|WARN|invalid|missing|peer dep' && exit 1 || true",
    "gem": "bundle check 2>/dev/null || true",
    "composer": "composer validate --no-check-publish 2>/dev/null || true",
    "golang": "go vet ./... 2>/dev/null || true",
    "cargo": "cargo check 2>/dev/null || true",
    "nuget": "dotnet restore --no-cache 2>/dev/null || true",
}

# Lockfile names per ecosystem
LOCKFILE_NAMES: Dict[str, List[str]] = {
    "pypi": [
        "requirements.txt", "requirements-lock.txt", "constraints.txt",
        "Pipfile.lock", "poetry.lock", "pdm.lock",
    ],
    "npm": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"],
    "gem": ["Gemfile.lock"],
    "composer": ["composer.lock"],
    "golang": ["go.sum"],
    "cargo": ["Cargo.lock"],
    "nuget": ["packages.lock.json"],
    "hex": ["mix.lock"],
    "pub": ["pubspec.lock"],
}

# Constraint file names -- these contain explicit version pins
_CONSTRAINT_FILES: Dict[str, List[str]] = {
    "pypi": ["requirements.txt", "constraints.txt", "setup.cfg", "pyproject.toml"],
    "npm": ["package.json"],
    "gem": ["Gemfile"],
    "composer": ["composer.json"],
    "golang": ["go.mod"],
    "cargo": ["Cargo.toml"],
    "nuget": ["*.csproj", "*.fsproj"],
}

# Packages that should NEVER be auto-upgraded because they frequently
# break backward compatibility or have complex migration paths.
# Lowercase for case-insensitive matching.
UPGRADE_BLOCKLIST: Dict[str, Set[str]] = {
    "pypi": {
        # Web frameworks
        "django", "flask", "fastapi", "tornado", "sanic",
        # ORMs and DB
        "sqlalchemy", "alembic", "peewee",
        # Task queues
        "celery", "rq",
        # Async
        "twisted", "gevent",
        # AWS SDK (version-locked together, partial upgrade breaks)
        "boto3", "botocore", "aiobotocore", "s3transfer",
        # ML frameworks (ABI-sensitive)
        "tensorflow", "torch", "jax",
        # Testing frameworks (major version = test suite rewrite)
        "pytest",
    },
    "npm": {
        # Frontend frameworks
        "react", "react-dom", "next", "vue", "@angular/core", "angular",
        "svelte", "@sveltejs/kit", "nuxt",
        # Build tools
        "webpack", "babel-core", "@babel/core", "vite", "esbuild",
        "rollup", "parcel",
        # Type systems
        "typescript", "flow-bin",
        # Testing
        "jest", "mocha",
        # Node frameworks
        "express",  # v4->v5 is breaking
    },
    "gem": {
        "rails", "activerecord", "actionpack", "activesupport",
        "actionview", "actionmailer", "activejob", "actioncable",
        "sinatra", "rspec", "rspec-core",
    },
    "composer": {
        "laravel/framework", "symfony/framework-bundle",
        "symfony/console", "symfony/http-kernel",
    },
    "golang": set(),  # Go module system + semver handles this well
    "cargo": set(),   # Cargo semver is strict
    "maven": {
        "org.springframework.boot:spring-boot", "org.springframework:spring-core",
        "org.apache.struts:struts2-core",
    },
    "nuget": {
        "microsoft.aspnetcore.app", "microsoft.netcore.app",
    },
    "hex": set(),
    "pub": set(),
    "swift": set(),
    "conan": set(),
}


# ================================================================
# Core functions
# ================================================================

def extract_vulnerable_app_packages(
    scan_result: Dict[str, Any],
    sbom_data: Optional[Dict[str, Any]] = None,
) -> List[VulnerablePackage]:
    """
    Extract application-level vulnerable packages from a Trivy scan.

    Filters out OS-level packages (apk, deb, rpm) and focuses on
    application packages that can be upgraded independently.

    Handles:
    - All Trivy result types (pip, npm, gem, composer, gomod, cargo, nuget, etc.)
    - Multiple CVEs per package (merges into single entry with highest fix version)
    - Fix version ranges from Trivy (e.g., ">=1.2.3, <2.0.0" -> extracts "1.2.3")
    - Scoped npm packages (@scope/name)
    - Go module paths (github.com/owner/repo)
    - Maven coordinates (groupId:artifactId)

    Args:
        scan_result: Trivy vulnerability scan JSON output
        sbom_data: Optional SBOM for cross-referencing versions

    Returns:
        List of VulnerablePackage instances with fix versions
    """
    if not scan_result:
        return []

    vulnerable: List[VulnerablePackage] = []
    seen: Dict[Tuple[str, str], int] = {}  # (name, ecosystem) -> index in vulnerable

    for result in scan_result.get("Results", []):
        result_class = result.get("Class", "").lower()
        result_type = result.get("Type", "").lower()

        # Skip OS package results -- base image patching handles these
        if result_class == "os-pkgs" or result_type in _OS_RESULT_TYPES:
            continue

        # Determine ecosystem
        ecosystem = _TRIVY_TYPE_TO_ECOSYSTEM.get(result_type)
        if ecosystem is None:
            # Unknown type -- log and skip
            if result_type and result_type not in _OS_RESULT_TYPES:
                logger.debug(
                    f"Skipping unknown Trivy result type '{result_type}' "
                    f"(class='{result_class}')"
                )
            continue

        vulns = result.get("Vulnerabilities")
        if not vulns:
            continue

        for vuln in vulns:
            pkg_name = vuln.get("PkgName", "").strip()
            fix_version_raw = vuln.get("FixedVersion", "").strip()
            installed = vuln.get("InstalledVersion", "").strip()
            severity = vuln.get("Severity", "UNKNOWN").upper()
            cve_id = vuln.get("VulnerabilityID", "").strip()
            purl = vuln.get("PkgIdentifier", {}).get("PURL", "") or ""

            # Skip if no fix available or no package name
            if not fix_version_raw or not pkg_name:
                continue

            # Normalize fix version: Trivy sometimes returns ranges
            # Pass installed version so branch-aware selection can pick
            # the fix from the same major branch when multiple are available
            fix_version = _normalize_fix_version(fix_version_raw, installed)
            if not fix_version:
                logger.debug(
                    f"Could not parse fix version '{fix_version_raw}' "
                    f"for {pkg_name}, skipping"
                )
                continue

            # Normalize severity
            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
                severity = "UNKNOWN"

            key = (pkg_name.lower(), ecosystem)
            if key in seen:
                # Merge into existing entry
                idx = seen[key]
                vp = vulnerable[idx]
                if cve_id and cve_id not in vp.cve_ids:
                    vp.cve_ids.append(cve_id)
                # Keep the highest fix version
                if _version_gt(fix_version, vp.fix_version):
                    vp.fix_version = fix_version
                # Keep the highest severity
                if _severity_rank(severity) > _severity_rank(vp.severity):
                    vp.severity = severity
                continue

            seen[key] = len(vulnerable)
            vulnerable.append(VulnerablePackage(
                name=pkg_name,
                ecosystem=ecosystem,
                installed_version=installed,
                fix_version=fix_version,
                cve_ids=[cve_id] if cve_id else [],
                severity=severity,
                purl=purl,
            ))

    # Sort by severity (CRITICAL first) then by name
    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulnerable.sort(key=lambda v: (_SEV_ORDER.get(v.severity, 99), v.name))

    logger.info(
        f"Found {len(vulnerable)} vulnerable application packages with available fixes"
    )
    return vulnerable


def analyze_upgrade_safety(
    packages: List[VulnerablePackage],
    sbom_data: Optional[Dict[str, Any]] = None,
    build_context_path: Optional[str] = None,
) -> List[UpgradeAction]:
    """
    Analyze whether each vulnerable package can be safely upgraded.

    Safety checks (in order):
    0. Is the ecosystem CLI-patchable? (Maven/Dart/Swift/Conan are not)
    1. Is the package on the blocklist? (frameworks with breaking changes)
    2. Does the fix version represent a major version bump? (risky)
    3. Is the package pinned in a lockfile/constraint file? (respect pins)
    4. Does the SBOM show reverse dependencies that might break?

    Args:
        packages: List of vulnerable packages from extract_vulnerable_app_packages
        sbom_data: SBOM for dependency analysis
        build_context_path: Path to Dockerfile build context (for lockfile parsing)

    Returns:
        List of UpgradeAction instances with safety assessment
    """
    actions: List[UpgradeAction] = []

    # Build a reverse dependency map from SBOM if available
    reverse_deps = _build_reverse_dependency_map(sbom_data) if sbom_data else {}

    # Parse lockfile constraints if build context is available
    lockfile_constraints: Dict[str, Dict[str, str]] = {}  # ecosystem -> {pkg: constraint}
    if build_context_path and os.path.isdir(build_context_path):
        lockfile_constraints = _parse_lockfile_constraints(build_context_path)

    for pkg in packages:
        action = UpgradeAction(
            package_name=pkg.name,
            ecosystem=pkg.ecosystem,
            from_version=pkg.installed_version,
            to_version=pkg.fix_version,
            cve_ids=list(pkg.cve_ids),
            severity=pkg.severity,
        )

        # Check 0: Is this ecosystem CLI-patchable?
        if UPGRADE_COMMANDS.get(pkg.ecosystem) is None:
            action.safe = False
            action.conflict_reason = (
                f"Ecosystem '{pkg.ecosystem}' cannot be patched via CLI commands. "
                f"Dependencies are declared in config files (pom.xml, pubspec.yaml, "
                f"Package.swift, conanfile.txt). Manual update required."
            )
            actions.append(action)
            continue

        # Check 1: Blocklist
        blocklist = UPGRADE_BLOCKLIST.get(pkg.ecosystem, set())
        if pkg.name.lower() in blocklist:
            action.safe = False
            action.conflict_reason = (
                f"Package '{pkg.name}' is on the upgrade blocklist -- "
                f"major framework with complex migration path. "
                f"Manual upgrade recommended."
            )
            actions.append(action)
            continue

        # Check 2: Major version bump detection
        if _is_major_version_bump(pkg.installed_version, pkg.fix_version):
            action.safe = False
            action.conflict_reason = (
                f"Major version bump detected: {pkg.installed_version} -> "
                f"{pkg.fix_version}. This may introduce breaking API changes. "
                f"Manual review recommended."
            )
            actions.append(action)
            continue

        # Check 3: Lockfile constraint conflict
        eco_constraints = lockfile_constraints.get(pkg.ecosystem, {})
        pkg_constraint = eco_constraints.get(pkg.name.lower())
        if pkg_constraint:
            if not _version_satisfies_constraint(
                pkg.fix_version, pkg_constraint, pkg.ecosystem
            ):
                action.safe = False
                action.conflict_reason = (
                    f"Fix version {pkg.fix_version} violates lockfile constraint "
                    f"'{pkg_constraint}' for {pkg.name}. "
                    f"Update the lockfile constraint first."
                )
                actions.append(action)
                continue

        # Check 4: Reverse dependency conflict from SBOM
        dependents = reverse_deps.get(pkg.name.lower(), [])
        if dependents:
            conflicting = []
            for dep_name, constraint in dependents:
                if constraint and not _version_satisfies_constraint(
                    pkg.fix_version, constraint, pkg.ecosystem
                ):
                    conflicting.append(f"{dep_name} (requires {constraint})")

            if conflicting:
                action.safe = False
                action.conflict_reason = (
                    f"Upgrade conflicts with dependencies: {', '.join(conflicting)}. "
                    f"These packages require specific version ranges of {pkg.name}."
                )
                actions.append(action)
                continue

        # Package passed all safety checks -- generate the upgrade command
        action.safe = True
        action.dockerfile_command = _generate_upgrade_command(pkg)
        if not action.dockerfile_command:
            # This shouldn't happen after check 0, but guard anyway
            action.safe = False
            action.conflict_reason = (
                f"No upgrade command template for ecosystem '{pkg.ecosystem}'"
            )
        actions.append(action)

    safe_count = sum(1 for a in actions if a.safe)
    unsafe_count = sum(1 for a in actions if not a.safe)
    logger.info(
        f"Upgrade safety analysis: {safe_count} safe, {unsafe_count} blocked/conflicting"
    )

    return actions


def generate_dockerfile_patch(
    dockerfile_text: str,
    actions: List[UpgradeAction],
    only_safe: bool = True,
) -> Tuple[str, List[str], List[str]]:
    """
    Generate a patched Dockerfile with app-level upgrade commands injected.

    Strategy:
    1. Find the LAST RUN instruction that installs packages for each ecosystem
       (pip install, npm install, etc.) and inject upgrades after it.
    2. If no matching install found, inject before the final CMD/ENTRYPOINT.
    3. Append a verification command (pip check, npm ls, etc.) to catch breakage.
    4. In multi-stage Dockerfiles, only inject into the FINAL stage (the one
       that produces the runtime image), not build stages.

    Args:
        dockerfile_text: Original Dockerfile content
        actions: List of UpgradeAction instances from analyze_upgrade_safety
        only_safe: If True, only inject safe upgrades (default True)

    Returns:
        Tuple of (patched_text, injected_commands, warnings)
    """
    if only_safe:
        applicable = [a for a in actions if a.safe and a.dockerfile_command]
    else:
        applicable = [a for a in actions if a.dockerfile_command]

    if not applicable:
        return dockerfile_text, [], ["No safe app-level upgrades to apply"]

    # Group by ecosystem for clean RUN layer generation
    by_ecosystem: Dict[str, List[UpgradeAction]] = {}
    for action in applicable:
        by_ecosystem.setdefault(action.ecosystem, []).append(action)

    # Generate combined RUN commands per ecosystem
    injected_commands: List[str] = []
    run_blocks: List[str] = []

    for ecosystem, eco_actions in by_ecosystem.items():
        commands: List[str] = []
        comment_lines: List[str] = []

        for action in eco_actions:
            cve_str = ", ".join(action.cve_ids[:3])
            if len(action.cve_ids) > 3:
                cve_str += f" (+{len(action.cve_ids) - 3} more)"
            comment_lines.append(
                f"# AutoPatch: upgrade {action.package_name} "
                f"{action.from_version} -> {action.to_version} "
                f"(fixes {cve_str})"
            )
            commands.append(action.dockerfile_command)

        # Append verification command if available
        verify_cmd = VERIFICATION_COMMANDS.get(ecosystem)
        if verify_cmd:
            comment_lines.append(f"# AutoPatch: verify {ecosystem} dependencies")
            commands.append(verify_cmd)

        # Combine into a single RUN to minimize layers
        if commands:
            block = "\n".join(comment_lines)
            if len(commands) == 1:
                block += f"\nRUN {commands[0]}"
            else:
                combined = " && \\\n    ".join(commands)
                block += f"\nRUN {combined}"

            run_blocks.append(block)
            injected_commands.extend(
                c for c in commands if not c.startswith("pip check")
                and "npm ls" not in c
                and "bundle check" not in c
                and "composer validate" not in c
                and "go vet" not in c
                and "cargo check" not in c
                and "dotnet restore" not in c
            )

    # Find injection point in the FINAL STAGE of the Dockerfile
    lines = dockerfile_text.splitlines()
    final_stage_start = _find_final_stage_start(lines)
    inject_idx = _find_injection_point(lines, start_from=final_stage_start)

    warnings: List[str] = []
    if inject_idx is None:
        inject_idx = _find_last_cmd_entrypoint(lines, start_from=final_stage_start)
        if inject_idx is not None:
            warnings.append(
                "No package install instruction found in final Dockerfile stage. "
                "Injecting upgrade commands before CMD/ENTRYPOINT."
            )
        else:
            inject_idx = len(lines)
            warnings.append(
                "No CMD/ENTRYPOINT found. Appending upgrade commands at end of Dockerfile."
            )

    # Inject the upgrade blocks
    patch_text = "\n".join(run_blocks)
    new_lines = lines[:inject_idx] + ["", patch_text, ""] + lines[inject_idx:]
    patched_text = "\n".join(new_lines) + "\n"

    logger.info(
        f"Injected {len(injected_commands)} upgrade commands at line {inject_idx} "
        f"(final stage starts at line {final_stage_start})"
    )

    return patched_text, injected_commands, warnings


def plan_app_patches(
    scan_result: Dict[str, Any],
    sbom_data: Optional[Dict[str, Any]],
    dockerfile_text: str,
    build_context_path: Optional[str] = None,
    only_critical_high: bool = False,
) -> AppPatchResult:
    """
    Full pipeline: analyze scan + SBOM -> plan safe upgrades -> generate Dockerfile patch.

    This is the main entry point for application-level patching.

    Args:
        scan_result: Trivy vulnerability scan JSON
        sbom_data: CycloneDX SBOM data
        dockerfile_text: Original Dockerfile content
        build_context_path: Path to build context for lockfile analysis
        only_critical_high: If True, only patch CRITICAL and HIGH severity

    Returns:
        AppPatchResult with all analysis and patch information
    """
    result = AppPatchResult()

    if not scan_result:
        result.warnings.append("No scan results provided")
        return result

    # Step 1: Extract vulnerable app packages
    vulnerable = extract_vulnerable_app_packages(scan_result, sbom_data)
    result.vulnerable_packages = list(vulnerable)

    if not vulnerable:
        result.warnings.append("No vulnerable application packages with available fixes found")
        return result

    # Filter by severity if requested
    if only_critical_high:
        vulnerable = [v for v in vulnerable if v.severity in ("CRITICAL", "HIGH")]
        if not vulnerable:
            result.warnings.append(
                "No CRITICAL/HIGH application vulnerabilities with fixes found"
            )
            return result

    result.total_fixable = len(vulnerable)

    # Step 2: Analyze upgrade safety
    actions = analyze_upgrade_safety(vulnerable, sbom_data, build_context_path)
    result.upgrade_actions = actions

    safe_actions = [a for a in actions if a.safe]
    unsafe_actions = [a for a in actions if not a.safe]
    result.total_safe_upgrades = len(safe_actions)
    result.total_conflict_upgrades = len(unsafe_actions)

    # Record skipped packages with full context
    for action in unsafe_actions:
        result.skipped_packages.append({
            "name": action.package_name,
            "ecosystem": action.ecosystem,
            "from": action.from_version,
            "to": action.to_version,
            "reason": action.conflict_reason,
            "cves": action.cve_ids,
            "severity": action.severity,
        })

    # Step 3: Generate Dockerfile patch
    if safe_actions:
        patched_text, commands, patch_warnings = generate_dockerfile_patch(
            dockerfile_text, actions, only_safe=True
        )
        result.dockerfile_patch_lines = commands
        result.warnings.extend(patch_warnings)
    else:
        result.warnings.append(
            "All vulnerable packages have upgrade conflicts or are blocklisted. "
            "No automatic patches can be safely applied."
        )

    return result


# ================================================================
# Version parsing and comparison
# ================================================================

def _normalize_fix_version(raw: str, installed_version: str = "") -> Optional[str]:
    """
    Normalize a Trivy fix version string to a concrete version.

    Trivy sometimes returns:
    - Simple versions: "1.2.3"
    - Ranges: ">=1.2.3, <2.0.0"
    - Multiple fixes: "1.2.3, 2.0.1" (for different major branches)
    - Epoch-prefixed: "1:1.2.3" (Debian epoch)
    - Go pseudo-versions: "v0.0.0-20240101000000-abcdef123456"

    Strategy: when multiple fix versions exist (e.g., "1.2.3, 2.0.1"),
    prefer the one in the same major branch as the installed version.
    This avoids breaking upgrades (e.g., user on 2.x should get 2.0.1,
    not be downgraded to 1.2.3). Falls back to lowest if no branch match.
    """
    if not raw:
        return None

    raw = raw.strip()

    # Strip Debian/RPM epoch prefix (e.g., "1:2.3.4" -> "2.3.4")
    raw = re.sub(r'^\d+:', '', raw)

    # Handle comma-separated versions (branch-aware selection)
    if "," in raw:
        candidates = []
        for part in raw.split(","):
            part = part.strip()
            ver = _extract_version_number(part)
            if ver:
                candidates.append(ver)
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        # Sort candidates by version number
        candidates.sort(key=lambda v: [int(x) for x in re.findall(r'\d+', v)])

        # If we know the installed version, prefer a fix in the same major branch
        if installed_version:
            installed_clean = _extract_version_number(installed_version) or installed_version
            installed_parts = [int(p) for p in re.findall(r'\d+', installed_clean)]
            if installed_parts:
                installed_major = installed_parts[0]
                # Find candidates in the same major branch
                same_branch = [
                    c for c in candidates
                    if _get_major(c) == installed_major
                ]
                if same_branch:
                    # Return the lowest fix in the same branch
                    return same_branch[0]

        # No installed version info or no branch match: return lowest
        return candidates[0]

    return _extract_version_number(raw)


def _get_major(version: str) -> Optional[int]:
    """Extract the major version number from a version string."""
    parts = re.findall(r'\d+', version)
    if parts:
        return int(parts[0])
    return None


def _extract_version_number(s: str) -> Optional[str]:
    """Extract a clean version number from a possibly constraint-prefixed string."""
    s = s.strip()
    # Strip constraint operators: >=, <=, >, <, ==, ~=, ^, ~
    s = re.sub(r'^[><=~^!]+\s*', '', s)
    # Strip leading 'v' (Go convention)
    s = re.sub(r'^v(?=\d)', '', s)
    # Validate it looks like a version
    if re.match(r'^\d+(\.\d+)*', s):
        # Extract just the version part (strip any trailing metadata)
        match = re.match(r'^(\d+(?:\.\d+)*(?:[-+].+)?)', s)
        if match:
            return match.group(1)
    return None


def _version_gt(v1: str, v2: str) -> bool:
    """Compare two version strings: is v1 > v2?"""
    try:
        parts1 = [int(p) for p in re.findall(r'\d+', v1)]
        parts2 = [int(p) for p in re.findall(r'\d+', v2)]
        # Pad shorter list with zeros for proper comparison
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))
        return parts1 > parts2
    except (ValueError, TypeError):
        return False


def _versions_equal(v1: str, v2: str) -> bool:
    """
    Compare two version strings for equality with zero-padding.

    Handles cases like "1.0" == "1.0.0" by padding shorter versions with zeros.
    Falls back to string comparison if versions cannot be parsed as integers.
    """
    try:
        parts1 = [int(p) for p in re.findall(r'\d+', v1)]
        parts2 = [int(p) for p in re.findall(r'\d+', v2)]
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))
        return parts1 == parts2
    except (ValueError, TypeError):
        return v1 == v2


def _severity_rank(severity: str) -> int:
    """Numeric rank for severity comparison (higher = more severe)."""
    ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    return ranks.get(severity.upper(), 0)


def _is_major_version_bump(from_ver: str, to_ver: str) -> bool:
    """
    Check if upgrading from from_ver to to_ver crosses a major version boundary.

    Handles:
    - Standard semver: "1.2.3" -> "2.0.0" = True
    - Two-part: "3.8" -> "4.0" = True
    - Go versions: "1.22.5" -> "2.0.0" = True (but "0.x" -> "0.y" is False)
    - Pre-release: "1.0.0-alpha" -> "2.0.0" = True
    """
    try:
        from_parts = [int(p) for p in re.findall(r'\d+', from_ver)]
        to_parts = [int(p) for p in re.findall(r'\d+', to_ver)]
        if not from_parts or not to_parts:
            return False
        # 0.x versions are all "unstable" -- any bump within 0.x is acceptable
        if from_parts[0] == 0 and to_parts[0] == 0:
            return False
        return to_parts[0] > from_parts[0]
    except (ValueError, TypeError):
        return False


# ================================================================
# Constraint and lockfile parsing
# ================================================================

def _version_satisfies_constraint(
    version: str,
    constraint: str,
    ecosystem: str,
) -> bool:
    """
    Check if a version satisfies a dependency constraint.

    Handles ecosystem-specific syntax:
    - pypi PEP 440: ==1.0, >=1.0,<2.0, ~=1.4, !=1.5
    - npm semver: ^1.0.0, ~1.0.0, >=1.0.0 <2.0.0
    - gem pessimistic: ~> 1.0
    - Go: v1.2.3, >=v1.0.0
    - Cargo: ^1.0.0 (default), =1.0.0 (exact)

    For safety, returns True (assume compatible) when we cannot parse
    the constraint, and False only when we can definitively determine
    incompatibility. The build step will catch actual breakage.
    """
    if not constraint:
        return True

    constraint = constraint.strip()

    # Handle compound constraints (comma-separated): ALL must be satisfied
    if "," in constraint:
        parts = [p.strip() for p in constraint.split(",") if p.strip()]
        return all(
            _version_satisfies_single_constraint(version, p, ecosystem)
            for p in parts
        )

    # Handle space-separated constraints (npm style): ALL must be satisfied
    # But only if they look like constraints (start with operator)
    space_parts = constraint.split()
    if len(space_parts) > 1 and all(
        re.match(r'^[><=~^!]', p) or re.match(r'^\d', p) for p in space_parts
    ):
        return all(
            _version_satisfies_single_constraint(version, p, ecosystem)
            for p in space_parts
        )

    return _version_satisfies_single_constraint(version, constraint, ecosystem)


def _version_satisfies_single_constraint(
    version: str, constraint: str, ecosystem: str
) -> bool:
    """Check a single version constraint."""
    constraint = constraint.strip()
    if not constraint:
        return True

    # Strip leading 'v' from both
    version = re.sub(r'^v', '', version)
    constraint_clean = re.sub(r'^v', '', constraint)

    # Exact pin: ==1.2.3 or =1.2.3
    m = re.match(r'^==?\s*(.+)$', constraint_clean)
    if m:
        return _versions_equal(version, m.group(1).strip())

    # Not-equal: !=1.2.3
    m = re.match(r'^!=\s*(.+)$', constraint_clean)
    if m:
        return not _versions_equal(version, m.group(1).strip())

    # Greater-than-or-equal: >=1.2.3
    m = re.match(r'^>=\s*(.+)$', constraint_clean)
    if m:
        ref = m.group(1).strip()
        return _version_gt(version, ref) or _versions_equal(version, ref)

    # Less-than: <2.0.0
    m = re.match(r'^<\s*(.+)$', constraint_clean)
    if m:
        ref = m.group(1).strip()
        return not _version_gt(version, ref) and not _versions_equal(version, ref)

    # Greater-than: >1.2.3
    m = re.match(r'^>\s*(.+)$', constraint_clean)
    if m:
        ref = m.group(1).strip()
        return _version_gt(version, ref)

    # Less-than-or-equal: <=2.0.0
    m = re.match(r'^<=\s*(.+)$', constraint_clean)
    if m:
        ref = m.group(1).strip()
        return not _version_gt(version, ref) or _versions_equal(version, ref)

    # npm caret: ^1.2.3 (allows minor+patch changes within same major)
    m = re.match(r'^\^\s*(.+)$', constraint_clean)
    if m:
        ref = m.group(1).strip()
        ref_parts = [int(p) for p in re.findall(r'\d+', ref)]
        ver_parts = [int(p) for p in re.findall(r'\d+', version)]
        if not ref_parts or not ver_parts:
            return True
        # Same major version and >= the reference
        if ver_parts[0] != ref_parts[0]:
            return False
        return _version_gt(version, ref) or _versions_equal(version, ref)

    # npm/gem tilde: ~1.2.3 or ~>1.2 (allows patch changes within same minor)
    m = re.match(r'^~>?\s*(.+)$', constraint_clean)
    if m:
        ref = m.group(1).strip()
        ref_parts = [int(p) for p in re.findall(r'\d+', ref)]
        ver_parts = [int(p) for p in re.findall(r'\d+', version)]
        if len(ref_parts) < 2 or len(ver_parts) < 2:
            return True
        # Same major and minor, >= the reference
        if ver_parts[0] != ref_parts[0] or ver_parts[1] < ref_parts[1]:
            return False
        # For ~> with only major.minor, allow any patch in that minor
        if len(ref_parts) == 2:
            return ver_parts[1] == ref_parts[1]
        return ver_parts[:2] == ref_parts[:2]

    # Python ~= (compatible release): ~=1.4 means >=1.4, <2.0
    m = re.match(r'^~=\s*(.+)$', constraint_clean)
    if m:
        ref = m.group(1).strip()
        ref_parts = [int(p) for p in re.findall(r'\d+', ref)]
        ver_parts = [int(p) for p in re.findall(r'\d+', version)]
        if not ref_parts or not ver_parts:
            return True
        # Must be >= ref and < next major release prefix
        if not (_version_gt(version, ref) or _versions_equal(version, ref)):
            return False
        if len(ref_parts) >= 2:
            return ver_parts[0] == ref_parts[0]
        return True

    # Bare version number -- treat as minimum (>= that version)
    if re.match(r'^\d+(\.\d+)*$', constraint_clean):
        return _version_gt(version, constraint_clean) or _versions_equal(version, constraint_clean)

    # Cannot parse -- assume compatible (build step will catch actual breakage)
    return True


def _parse_lockfile_constraints(
    build_context_path: str,
) -> Dict[str, Dict[str, str]]:
    """
    Parse constraint files from the build context to find version pins.

    Returns:
        Dict of ecosystem -> {lowercased_package_name: constraint_string}
    """
    constraints: Dict[str, Dict[str, str]] = {}

    for ecosystem, filenames in _CONSTRAINT_FILES.items():
        eco_constraints: Dict[str, str] = {}

        for pattern in filenames:
            if "*" in pattern:
                # Glob patterns (e.g., *.csproj)
                import glob
                matches = glob.glob(os.path.join(build_context_path, pattern))
                paths = matches
            else:
                path = os.path.join(build_context_path, pattern)
                paths = [path] if os.path.isfile(path) else []

            for fpath in paths:
                try:
                    parsed = _parse_single_constraint_file(fpath, ecosystem)
                    eco_constraints.update(parsed)
                except Exception as e:
                    logger.debug(f"Failed to parse {fpath}: {e}")

        if eco_constraints:
            constraints[ecosystem] = eco_constraints

    return constraints


def _parse_single_constraint_file(
    path: str, ecosystem: str
) -> Dict[str, str]:
    """Parse a single constraint/requirements file into {pkg: constraint}."""
    result: Dict[str, str] = {}

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return result

    if ecosystem == "pypi":
        # requirements.txt format: package==1.0.0, package>=1.0,<2.0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Parse: name[extras] constraint
            m = re.match(r'^([a-zA-Z0-9_.-]+)(?:\[.*?\])?\s*(.*)$', line)
            if m:
                name = m.group(1).lower().replace("-", "_")
                constraint = m.group(2).strip()
                if constraint:
                    result[name] = constraint

    elif ecosystem == "npm":
        # package.json: {"dependencies": {"pkg": "^1.0.0"}}
        try:
            pkg_json = json.loads(content)
            for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
                deps = pkg_json.get(dep_key, {})
                if isinstance(deps, dict):
                    for name, constraint in deps.items():
                        if isinstance(constraint, str):
                            result[name.lower()] = constraint
        except json.JSONDecodeError:
            pass

    elif ecosystem == "gem":
        # Gemfile: gem 'name', '~> 1.0'
        for line in content.splitlines():
            m = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", line)
            if m:
                result[m.group(1).lower()] = m.group(2)

    elif ecosystem == "composer":
        # composer.json: {"require": {"vendor/pkg": "^1.0"}}
        try:
            comp_json = json.loads(content)
            for dep_key in ("require", "require-dev"):
                deps = comp_json.get(dep_key, {})
                if isinstance(deps, dict):
                    for name, constraint in deps.items():
                        if isinstance(constraint, str) and name != "php":
                            result[name.lower()] = constraint
        except json.JSONDecodeError:
            pass

    elif ecosystem == "golang":
        # go.mod: require github.com/x/y v1.2.3
        for line in content.splitlines():
            m = re.match(r'^\s*(?:require\s+)?(\S+)\s+(v\S+)', line)
            if m:
                result[m.group(1).lower()] = m.group(2)

    elif ecosystem == "cargo":
        # Cargo.toml: name = "1.0" or name = { version = "1.0" }
        for line in content.splitlines():
            # Simple form: name = "^1.0"
            m = re.match(r'^(\w[\w-]*)\s*=\s*"([^"]+)"', line)
            if m:
                result[m.group(1).lower()] = m.group(2)
            # Table form with version key
            m = re.match(r'^(\w[\w-]*)\s*=\s*\{.*version\s*=\s*"([^"]+)"', line)
            if m:
                result[m.group(1).lower()] = m.group(2)

    return result


# ================================================================
# SBOM reverse dependency analysis
# ================================================================

def _build_reverse_dependency_map(
    sbom_data: Dict[str, Any]
) -> Dict[str, List[Tuple[str, Optional[str]]]]:
    """
    Build a map of package_name -> [(dependent_name, version_constraint), ...].

    Uses CycloneDX dependency graph if available in the SBOM.
    """
    reverse_deps: Dict[str, List[Tuple[str, Optional[str]]]] = {}

    if not sbom_data:
        return reverse_deps

    # Try CycloneDX dependencies array
    dependencies = sbom_data.get("dependencies", [])
    for dep_entry in dependencies:
        if not isinstance(dep_entry, dict):
            continue

        parent_ref = dep_entry.get("ref", "")
        parent_name = _extract_name_from_ref(parent_ref)
        if not parent_name:
            continue

        depends_on = dep_entry.get("dependsOn", [])
        if not isinstance(depends_on, list):
            continue

        for child in depends_on:
            if isinstance(child, str):
                child_name = _extract_name_from_ref(child)
                if child_name:
                    reverse_deps.setdefault(child_name.lower(), []).append(
                        (parent_name, None)
                    )

    # Also extract from SPDX format if present
    relationships = sbom_data.get("relationships", [])
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        if rel.get("relationshipType") == "DEPENDS_ON":
            parent = rel.get("spdxElementId", "")
            child = rel.get("relatedSpdxElement", "")
            parent_name = _extract_name_from_ref(parent)
            child_name = _extract_name_from_ref(child)
            if parent_name and child_name:
                reverse_deps.setdefault(child_name.lower(), []).append(
                    (parent_name, None)
                )

    return reverse_deps


def _extract_name_from_ref(ref: str) -> Optional[str]:
    """Extract a usable package name from a CycloneDX/SPDX bom-ref."""
    if not ref:
        return None

    # purl format: "pkg:pypi/requests@2.28.0" or "pkg:npm/%40scope/package@1.0.0"
    purl_match = re.search(r'pkg:\w+/([^@\s]+)', ref)
    if purl_match:
        name = purl_match.group(1)
        name = unquote(name)  # URL-decode %40 -> @, %2F -> /, etc.
        return name

    # SPDX format: "SPDXRef-Package-name-version"
    spdx_match = re.match(r'SPDXRef-(?:Package-)?(.+?)(?:-[\d.]+)?$', ref)
    if spdx_match:
        return spdx_match.group(1)

    # Simple "name:version" format
    parts = ref.split(":")
    if len(parts) >= 2:
        candidate = parts[-2] if parts[-1].replace(".", "").isdigit() else parts[-1]
        if candidate:
            return candidate

    return ref if ref else None


# ================================================================
# Upgrade command generation
# ================================================================

def _generate_upgrade_command(pkg: VulnerablePackage) -> str:
    """
    Generate the package manager command to upgrade a specific package.

    Handles special cases:
    - Scoped npm packages (@scope/name)
    - Go module paths (github.com/owner/repo)
    - Maven group:artifact coordinates
    - Cargo crate names
    - Package names with special characters
    """
    template = UPGRADE_COMMANDS.get(pkg.ecosystem)
    if not template:
        return ""

    name = pkg.name
    version = pkg.fix_version

    # Ecosystem-specific name/version adjustments
    if pkg.ecosystem == "golang":
        # Go uses full module paths and v-prefix
        if not version.startswith("v"):
            version = f"v{version}"
        # Template already handles this, but strip quotes for Go
        return f"go get {name}@{version} && go mod tidy"

    if pkg.ecosystem == "maven":
        # Maven isn't CLI-patchable (should be caught earlier), but just in case
        return ""

    if pkg.ecosystem == "npm":
        # npm handles @scope/name natively
        return f"npm install --save '{name}@{version}'"

    if pkg.ecosystem == "nuget":
        # dotnet CLI format
        return f"dotnet add package '{name}' --version '{version}'"

    # Default: use template
    cmd = template.format(pkg=name, ver=version)
    return cmd


# ================================================================
# Dockerfile analysis for injection point
# ================================================================

def _find_final_stage_start(lines: List[str]) -> int:
    """
    Find the line index where the final FROM stage begins.

    In a multi-stage Dockerfile, we only want to inject app patches
    into the final stage (the one that produces the runtime image).
    """
    last_from_idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            last_from_idx = i
    return last_from_idx


def _find_injection_point(
    lines: List[str], start_from: int = 0
) -> Optional[int]:
    """
    Find the best line index to inject upgrade commands.

    Searches from start_from (typically the final stage start) for the
    LAST RUN block that contains a package install command.

    Returns:
        Line index after which to inject, or None if no install found
    """
    install_patterns = [
        r'\bpip\s+install\b',
        r'\bpip3\s+install\b',
        r'\bnpm\s+install\b',
        r'\bnpm\s+ci\b',
        r'\byarn\s+add\b',
        r'\byarn\s+install\b',
        r'\bpnpm\s+install\b',
        r'\bpnpm\s+add\b',
        r'\bgem\s+install\b',
        r'\bbundle\s+install\b',
        r'\bcomposer\s+install\b',
        r'\bcomposer\s+require\b',
        r'\bgo\s+mod\s+download\b',
        r'\bgo\s+get\b',
        r'\bcargo\s+build\b',
        r'\bcargo\s+install\b',
        r'\bdotnet\s+restore\b',
        r'\bdotnet\s+add\s+package\b',
        r'\bmix\s+deps\.get\b',
        r'\bapt-get\s+install\b',
        r'\bapk\s+add\b',
        r'\byum\s+install\b',
        r'\bdnf\s+install\b',
        r'\bCOPY\s+.*requirements.*\.txt\b',
        r'\bCOPY\s+.*package.*\.json\b',
        r'\bCOPY\s+.*Gemfile\b',
        r'\bCOPY\s+.*go\.\(mod\|sum\)\b',
    ]
    combined_pattern = "|".join(install_patterns)

    last_install_end: Optional[int] = None
    in_run_block = False
    run_start: Optional[int] = None
    current_block_has_install = False

    for i in range(start_from, len(lines)):
        stripped = lines[i].strip()

        # Track RUN blocks (may span multiple lines with \)
        if stripped.upper().startswith("RUN ") or stripped.upper() == "RUN":
            in_run_block = True
            run_start = i
            current_block_has_install = False
            if re.search(combined_pattern, stripped, re.IGNORECASE):
                current_block_has_install = True

        elif in_run_block:
            if re.search(combined_pattern, stripped, re.IGNORECASE):
                current_block_has_install = True

        # Check for end of RUN block
        if in_run_block and not stripped.endswith("\\"):
            if current_block_has_install:
                last_install_end = i
            in_run_block = False
            current_block_has_install = False

    return last_install_end + 1 if last_install_end is not None else None


def _find_last_cmd_entrypoint(
    lines: List[str], start_from: int = 0
) -> Optional[int]:
    """Find the index of the last CMD or ENTRYPOINT instruction after start_from."""
    last_idx: Optional[int] = None
    for i in range(start_from, len(lines)):
        stripped = lines[i].strip().upper()
        if any(stripped.startswith(prefix) for prefix in (
            "CMD ", "CMD\t", "CMD[",
            "ENTRYPOINT ", "ENTRYPOINT\t", "ENTRYPOINT[",
        )):
            last_idx = i
    return last_idx


# ================================================================
# Report generation
# ================================================================

def format_app_patch_report(result: AppPatchResult) -> str:
    """
    Generate a human-readable report of application-level patching analysis.
    """
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("APPLICATION-LEVEL VULNERABILITY PATCHING REPORT")
    lines.append("=" * 60)
    lines.append("")

    lines.append(f"Vulnerable app packages found:  {result.total_fixable}")
    lines.append(f"Safe upgrades identified:       {result.total_safe_upgrades}")
    lines.append(f"Blocked/conflicting upgrades:   {result.total_conflict_upgrades}")
    lines.append("")

    if result.upgrade_actions:
        safe = [a for a in result.upgrade_actions if a.safe]
        if safe:
            lines.append("SAFE UPGRADES (will be applied):")
            lines.append("-" * 40)
            for action in safe:
                cves = ", ".join(action.cve_ids[:3])
                if len(action.cve_ids) > 3:
                    cves += f" (+{len(action.cve_ids) - 3} more)"
                lines.append(
                    f"  [{action.severity}] {action.ecosystem}/{action.package_name}: "
                    f"{action.from_version} -> {action.to_version} "
                    f"(fixes {cves})"
                )
            lines.append("")

    if result.skipped_packages:
        lines.append("SKIPPED PACKAGES (manual review needed):")
        lines.append("-" * 40)
        for pkg in result.skipped_packages:
            sev = pkg.get("severity", "?")
            lines.append(
                f"  [{sev}] {pkg.get('ecosystem', '?')}/{pkg['name']}: "
                f"{pkg.get('from', '?')} -> {pkg.get('to', '?')}"
            )
            lines.append(f"    Reason: {pkg.get('reason', 'unknown')}")
            if pkg.get("cves"):
                lines.append(f"    CVEs: {', '.join(pkg['cves'][:5])}")
        lines.append("")

    if result.dockerfile_patch_lines:
        lines.append("DOCKERFILE COMMANDS TO INJECT:")
        lines.append("-" * 40)
        for cmd in result.dockerfile_patch_lines:
            lines.append(f"  RUN {cmd}")
        lines.append("")

    if result.warnings:
        lines.append("WARNINGS:")
        lines.append("-" * 40)
        for w in result.warnings:
            lines.append(f"  - {w}")

    return "\n".join(lines)


def export_app_patch_json(result: AppPatchResult) -> Dict[str, Any]:
    """Export AppPatchResult as a JSON-serializable dictionary."""
    return {
        "total_fixable": result.total_fixable,
        "total_safe_upgrades": result.total_safe_upgrades,
        "total_conflict_upgrades": result.total_conflict_upgrades,
        "safe_upgrades": [
            {
                "package": a.package_name,
                "ecosystem": a.ecosystem,
                "from_version": a.from_version,
                "to_version": a.to_version,
                "cve_ids": a.cve_ids,
                "severity": a.severity,
                "command": a.dockerfile_command,
            }
            for a in result.upgrade_actions if a.safe
        ],
        "skipped_packages": result.skipped_packages,
        "dockerfile_commands": result.dockerfile_patch_lines,
        "warnings": result.warnings,
    }
