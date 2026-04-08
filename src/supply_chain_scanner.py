"""
Layer 2: Supply Chain Integrity Scanner for AutoPatch.

Runs six checks against a built container image, targeting the exact attack
techniques used in real-world supply chain compromises:

  - TeamPCP/Trivy Docker Hub credential theft (March 2026, CVE-2026-33634)
  - Axios npm phantom dependency attack (March 2026)
  - LiteLLM .pth auto-execute attack (March 2026)

Checks:
  1. Known vulnerability audit (pip-audit / npm audit)
  2. Phantom dependency detection (lockfile vs source imports)
  3. Install script detection (npm hasInstallScript on new deps)
  4. Malicious .pth file detection (Python auto-execute payloads)
  5. Provenance verification (RECORD hash integrity)
  6. Package age check (npm registry publish date)
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")

# npm registry rate limit: 10 queries/sec
_NPM_RATE_LIMIT_INTERVAL = 0.1  # seconds between requests

# Known non-imported packages (devDependencies, CLI tools, type stubs)
PHANTOM_ALLOWLIST: Set[str] = {
    # JavaScript/TypeScript
    "types", "@types", "typescript", "ts-node", "eslint", "prettier",
    "webpack", "babel", "jest", "mocha", "chai", "nyc", "istanbul",
    "nodemon", "concurrently", "cross-env", "rimraf", "husky",
    "lint-staged", "commitlint", "@commitlint", "standard-version",
    "semantic-release", "tslib", "core-js", "@babel",
    # Python
    "pytest", "flake8", "black", "mypy", "isort", "pylint", "autopep8",
    "yapf", "bandit", "safety", "coverage", "tox", "nox", "invoke",
    "pre-commit", "sphinx", "setuptools", "wheel", "pip", "twine",
    "build", "flit", "poetry", "pipenv", "virtualenv",
}

# Dangerous patterns in .pth files
_PTH_DANGEROUS_PATTERNS = [
    re.compile(r"^\s*import\s+", re.MULTILINE),
    re.compile(r"exec\s*\(", re.MULTILINE),
    re.compile(r"eval\s*\(", re.MULTILINE),
    re.compile(r"subprocess", re.MULTILINE),
    re.compile(r"os\.system\s*\(", re.MULTILINE),
    re.compile(r"base64\.b(?:16|32|64|85)decode", re.MULTILINE),
    re.compile(r"__import__\s*\(", re.MULTILINE),
]

# Common locations to search for manifests inside containers
_CONTAINER_SEARCH_PATHS = [
    "/app",
    "/usr/src/app",
    "/opt",
    "/home",
    "/srv",
    "/var/www",
]


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class AppVulnerability:
    """A vulnerability found by pip-audit or npm audit."""
    package_name: str
    ecosystem: str  # "python" or "javascript"
    installed_version: str
    fix_version: str
    vuln_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    dependency_path: str
    is_direct: bool


@dataclass
class ManifestInfo:
    """Info about a package manifest found in the container."""
    path: str
    manifest_type: str  # "requirements.txt", "package-lock.json", etc.
    ecosystem: str


@dataclass
class SupplyChainFinding:
    """A finding from one of the six supply chain checks."""
    check_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    package_name: str
    ecosystem: str
    description: str
    evidence: str
    recommendation: str


@dataclass
class SupplyChainResult:
    """Aggregate result of all supply chain checks."""
    findings: List[SupplyChainFinding] = field(default_factory=list)
    manifests_found: List[ManifestInfo] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    checks_run: List[str] = field(default_factory=list)
    overall_risk: str = "SAFE"  # SAFE, LOW, MEDIUM, HIGH, CRITICAL

    def add_finding(self, finding: SupplyChainFinding) -> None:
        self.findings.append(finding)
        self._update_risk()

    def _update_risk(self) -> None:
        severities = [f.severity for f in self.findings]
        if "CRITICAL" in severities:
            self.overall_risk = "CRITICAL"
        elif "HIGH" in severities:
            self.overall_risk = "HIGH"
        elif "MEDIUM" in severities:
            self.overall_risk = "MEDIUM"
        elif "LOW" in severities:
            self.overall_risk = "LOW"
        else:
            self.overall_risk = "SAFE"


# ============================================================================
# Container filesystem extraction
# ============================================================================

def _extract_container_fs(image_name: str, extract_dir: str) -> bool:
    """
    Extract files from a container image into a local directory.

    Creates a temporary container, copies files from known locations,
    then removes the container.

    Returns True if extraction succeeded.
    """
    container_name = f"autopatch_extract_{os.getpid()}"

    try:
        # Create container without starting it
        code, output = run_cmd(
            ["docker", "create", "--name", container_name, image_name],
            timeout=60,
        )
        if code != 0:
            logger.warning(f"Failed to create extraction container: {output}")
            return False

        # Get WORKDIR from image inspect
        code, inspect_out = run_cmd(
            ["docker", "inspect", "--format", "{{.Config.WorkingDir}}", container_name],
            timeout=15,
        )
        workdir = inspect_out.strip().strip("'\"") if code == 0 else ""
        search_paths = list(_CONTAINER_SEARCH_PATHS)
        if workdir and workdir not in search_paths:
            search_paths.insert(0, workdir)

        extracted_any = False
        for container_path in search_paths:
            local_dest = os.path.join(extract_dir, container_path.lstrip("/"))
            os.makedirs(local_dest, exist_ok=True)
            code, _ = run_cmd(
                ["docker", "cp", f"{container_name}:{container_path}/.", local_dest],
                timeout=120,
            )
            if code == 0:
                extracted_any = True

        # Also extract site-packages for .pth file scanning
        site_packages_targets = [
            "/usr/local/lib/python*/site-packages",
            "/usr/lib/python*/site-packages",
        ]
        # Use docker exec with find to locate site-packages dirs
        code, find_out = run_cmd(
            ["docker", "run", "--rm", "--entrypoint", "",
             image_name, "find", "/usr/local/lib", "/usr/lib",
             "-maxdepth", "3", "-name", "site-packages", "-type", "d"],
            timeout=30,
        )
        if code == 0 and find_out.strip():
            for sp_path in find_out.strip().splitlines():
                sp_path = sp_path.strip()
                if sp_path and "site-packages" in sp_path:
                    local_sp = os.path.join(extract_dir, sp_path.lstrip("/"))
                    os.makedirs(local_sp, exist_ok=True)
                    run_cmd(
                        ["docker", "cp", f"{container_name}:{sp_path}/.", local_sp],
                        timeout=120,
                    )
                    extracted_any = True

        return extracted_any

    except Exception as e:
        logger.warning(f"Container extraction failed: {e}")
        return False
    finally:
        # Cleanup container
        run_cmd(["docker", "rm", "-f", container_name], timeout=15)


def _find_manifests(extract_dir: str, ecosystems: List[str]) -> List[ManifestInfo]:
    """Find package manifest files in the extracted filesystem."""
    manifests = []
    manifest_patterns = {
        "python": [
            ("requirements.txt", "requirements.txt"),
            ("Pipfile.lock", "pipfile_lock"),
            ("poetry.lock", "poetry_lock"),
            ("setup.py", "setup_py"),
        ],
        "javascript": [
            ("package-lock.json", "package-lock.json"),
            ("yarn.lock", "yarn_lock"),
            ("package.json", "package.json"),
        ],
    }

    for root, dirs, files in os.walk(extract_dir):
        # Skip node_modules internals, .git, __pycache__
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__", ".tox")]
        for filename in files:
            for eco in ecosystems:
                for pattern_name, manifest_type in manifest_patterns.get(eco, []):
                    if filename == pattern_name:
                        full_path = os.path.join(root, filename)
                        manifests.append(ManifestInfo(
                            path=full_path,
                            manifest_type=manifest_type,
                            ecosystem=eco,
                        ))
    return manifests


# ============================================================================
# Check 1: Known vulnerability audit
# ============================================================================

def _check_known_vulns(
    extract_dir: str,
    manifests: List[ManifestInfo],
    result: SupplyChainResult,
) -> None:
    """Run pip-audit and npm audit against discovered manifests."""
    result.checks_run.append("known_vulnerability_audit")

    for manifest in manifests:
        if manifest.ecosystem == "python" and manifest.manifest_type == "requirements.txt":
            _run_pip_audit(manifest.path, result)
        elif manifest.ecosystem == "javascript" and manifest.manifest_type == "package-lock.json":
            _run_npm_audit(os.path.dirname(manifest.path), result)


def _run_pip_audit(requirements_path: str, result: SupplyChainResult) -> None:
    """Run pip-audit on a requirements.txt file."""
    if not shutil.which("pip-audit"):
        logger.warning("pip-audit not installed, skipping Python vulnerability audit")
        return

    try:
        code, output = run_cmd(
            ["pip-audit", "--requirement", requirements_path, "--format", "json",
             "--desc", "--output", "-"],
            timeout=120,
        )
        if code not in (0, 1):
            # code 1 means vulnerabilities found (normal)
            logger.warning(f"pip-audit failed with code {code}")
            return

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.warning("Failed to parse pip-audit JSON output")
            return

        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            vulns = dep.get("vulns", [])
            for vuln in vulns:
                severity = _map_pip_audit_severity(vuln.get("aliases", []))
                finding = SupplyChainFinding(
                    check_name="known_vulnerability_audit",
                    severity=severity,
                    package_name=dep.get("name", ""),
                    ecosystem="python",
                    description=vuln.get("description", vuln.get("id", "")),
                    evidence=f"Installed: {dep.get('version', '?')}, "
                             f"Fix: {vuln.get('fix_versions', ['?'])}",
                    recommendation=f"Upgrade {dep.get('name')} to {vuln.get('fix_versions', ['latest'])}",
                )
                result.add_finding(finding)

    except Exception as e:
        logger.warning(f"pip-audit execution failed: {e}")


def _run_npm_audit(package_dir: str, result: SupplyChainResult) -> None:
    """Run npm audit on a directory containing package-lock.json."""
    if not shutil.which("npm"):
        logger.warning("npm not installed, skipping JavaScript vulnerability audit")
        return

    try:
        code, output = run_cmd(
            ["npm", "audit", "--json"],
            timeout=120,
            env_override={"HOME": os.environ.get("HOME", "/tmp")},
        )
        # npm audit returns non-zero when vulns found
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.warning("Failed to parse npm audit JSON output")
            return

        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln_info in vulnerabilities.items():
            severity = (vuln_info.get("severity", "medium") or "medium").upper()
            via = vuln_info.get("via", [])
            desc_parts = []
            for v in via:
                if isinstance(v, dict):
                    desc_parts.append(v.get("title", v.get("url", "")))
                elif isinstance(v, str):
                    desc_parts.append(v)

            finding = SupplyChainFinding(
                check_name="known_vulnerability_audit",
                severity=severity,
                package_name=pkg_name,
                ecosystem="javascript",
                description="; ".join(desc_parts)[:500],
                evidence=f"Range: {vuln_info.get('range', '?')}, "
                         f"isDirect: {vuln_info.get('isDirect', False)}",
                recommendation=f"Run `npm audit fix` or upgrade {pkg_name}",
            )
            result.add_finding(finding)

    except Exception as e:
        logger.warning(f"npm audit execution failed: {e}")


def _map_pip_audit_severity(aliases: List[str]) -> str:
    """Map pip-audit aliases to severity. Defaults to HIGH."""
    # pip-audit does not directly provide severity; we default to HIGH
    # since known vulnerabilities warrant attention.
    return "HIGH"


# ============================================================================
# Check 2: Phantom dependency detection
# ============================================================================

def _check_phantom_deps(
    extract_dir: str,
    manifests: List[ManifestInfo],
    result: SupplyChainResult,
) -> None:
    """Detect dependencies declared in lockfiles but never imported in source."""
    result.checks_run.append("phantom_dependency_detection")

    for manifest in manifests:
        if manifest.ecosystem == "javascript" and manifest.manifest_type == "package-lock.json":
            _check_phantom_npm(manifest.path, extract_dir, result)
        elif manifest.ecosystem == "python" and manifest.manifest_type == "requirements.txt":
            _check_phantom_python(manifest.path, extract_dir, result)


def _check_phantom_npm(lockfile_path: str, extract_dir: str, result: SupplyChainResult) -> None:
    """Detect phantom npm dependencies."""
    try:
        with open(lockfile_path, "r") as f:
            lockdata = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to parse {lockfile_path}: {e}")
        return

    # Extract direct dependency names from package-lock.json
    # In lockfileVersion 2/3, direct deps are in "packages"."".dependencies
    deps: Set[str] = set()
    root_pkg = lockdata.get("packages", {}).get("", {})
    for dep_key in ("dependencies", "devDependencies"):
        deps.update(root_pkg.get(dep_key, {}).keys())

    # Fallback to top-level dependencies field
    if not deps:
        deps.update(lockdata.get("dependencies", {}).keys())

    if not deps:
        return

    # Scan source files for imports
    project_dir = os.path.dirname(lockfile_path)
    imported_packages = _scan_js_imports(project_dir)

    for dep_name in deps:
        # Skip scoped packages in allowlist and known dev tools
        base_name = dep_name.split("/")[0] if dep_name.startswith("@") else dep_name
        if base_name in PHANTOM_ALLOWLIST or dep_name in PHANTOM_ALLOWLIST:
            continue
        # Skip @types/ packages
        if dep_name.startswith("@types/"):
            continue

        if dep_name not in imported_packages and base_name not in imported_packages:
            finding = SupplyChainFinding(
                check_name="phantom_dependency_detection",
                severity="HIGH",
                package_name=dep_name,
                ecosystem="javascript",
                description=(
                    f"Package '{dep_name}' is declared in package-lock.json but "
                    f"never imported in any .js/.ts/.mjs/.cjs file. This matches "
                    f"the Axios phantom dependency attack pattern (March 2026)."
                ),
                evidence=f"Lockfile: {lockfile_path}, no require/import found in source",
                recommendation=(
                    f"Verify that '{dep_name}' is intentionally included. "
                    f"If not, remove it from package.json and regenerate the lockfile."
                ),
            )
            result.add_finding(finding)


def _check_phantom_python(requirements_path: str, extract_dir: str, result: SupplyChainResult) -> None:
    """Detect phantom Python dependencies."""
    try:
        with open(requirements_path, "r") as f:
            lines = f.readlines()
    except OSError:
        return

    # Extract package names from requirements.txt
    deps: Set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle name[extras]==version, name>=version, etc.
        pkg_name = re.split(r"[>=<!\[;]", line)[0].strip().lower()
        if pkg_name:
            # Normalize: underscores and hyphens are interchangeable in Python
            deps.add(pkg_name.replace("-", "_"))

    if not deps:
        return

    # Scan source files for imports
    project_dir = os.path.dirname(requirements_path)
    imported_packages = _scan_python_imports(project_dir)

    for dep_name in deps:
        if dep_name in PHANTOM_ALLOWLIST:
            continue
        # Normalize for import matching
        import_name = dep_name.replace("-", "_").lower()
        if import_name not in imported_packages:
            finding = SupplyChainFinding(
                check_name="phantom_dependency_detection",
                severity="HIGH",
                package_name=dep_name,
                ecosystem="python",
                description=(
                    f"Package '{dep_name}' is declared in requirements.txt but "
                    f"never imported in any .py file."
                ),
                evidence=f"Requirements: {requirements_path}, no import found in source",
                recommendation=(
                    f"Verify that '{dep_name}' is intentionally included. "
                    f"If not, remove it from requirements.txt."
                ),
            )
            result.add_finding(finding)


def _scan_js_imports(project_dir: str) -> Set[str]:
    """Scan .js/.ts/.mjs/.cjs files for require/import statements."""
    imported: Set[str] = set()
    extensions = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
    require_pattern = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
    import_pattern = re.compile(r"""(?:import|from)\s+['"]([^'"]+)['"]""")

    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "build")]
        for filename in files:
            if not any(filename.endswith(ext) for ext in extensions):
                continue
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for match in require_pattern.finditer(content):
                    pkg = _extract_npm_package_name(match.group(1))
                    if pkg:
                        imported.add(pkg)
                for match in import_pattern.finditer(content):
                    pkg = _extract_npm_package_name(match.group(1))
                    if pkg:
                        imported.add(pkg)
            except OSError:
                continue

    return imported


def _scan_python_imports(project_dir: str) -> Set[str]:
    """Scan .py files for import statements."""
    imported: Set[str] = set()
    import_pattern = re.compile(
        r"^\s*(?:import|from)\s+(\w+)", re.MULTILINE
    )

    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".tox", ".venv", "venv")]
        for filename in files:
            if not filename.endswith(".py"):
                continue
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for match in import_pattern.finditer(content):
                    pkg_name = match.group(1).lower().replace("-", "_")
                    imported.add(pkg_name)
            except OSError:
                continue

    return imported


def _extract_npm_package_name(module_specifier: str) -> Optional[str]:
    """Extract the npm package name from a require/import specifier."""
    if not module_specifier:
        return None
    # Skip relative imports
    if module_specifier.startswith(".") or module_specifier.startswith("/"):
        return None
    # Scoped packages: @scope/name
    if module_specifier.startswith("@"):
        parts = module_specifier.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return module_specifier
    # Regular packages: name or name/subpath
    return module_specifier.split("/")[0]


# ============================================================================
# Check 3: Install script detection (npm)
# ============================================================================

def _check_install_scripts(
    manifests: List[ManifestInfo],
    previous_lockfiles: Optional[Dict[str, str]],
    result: SupplyChainResult,
) -> None:
    """Detect npm packages with install scripts, especially new ones."""
    result.checks_run.append("install_script_detection")

    for manifest in manifests:
        if manifest.manifest_type != "package-lock.json":
            continue

        try:
            with open(manifest.path, "r") as f:
                lockdata = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        # Get current packages with install scripts
        current_install_scripts = _extract_install_script_packages(lockdata)

        # Determine which are new (not in previous lockfile)
        previous_packages: Set[str] = set()
        has_previous = False
        if previous_lockfiles:
            # Try to find a matching previous lockfile by path suffix
            for prev_path, prev_content in previous_lockfiles.items():
                if prev_path.endswith("package-lock.json"):
                    try:
                        prev_data = json.loads(prev_content)
                        previous_packages = set(_extract_install_script_packages(prev_data).keys())
                        has_previous = True
                    except json.JSONDecodeError:
                        pass
                    break

        for pkg_name, script_info in current_install_scripts.items():
            is_new = has_previous and pkg_name not in previous_packages
            severity = "HIGH" if is_new else "MEDIUM"

            description = (
                f"Package '{pkg_name}' has hasInstallScript: true"
            )
            if is_new:
                description += " and is NEW (not in previous lockfile)"

            finding = SupplyChainFinding(
                check_name="install_script_detection",
                severity=severity,
                package_name=pkg_name,
                ecosystem="javascript",
                description=description,
                evidence=f"Script types: {script_info}",
                recommendation=(
                    f"Review the install scripts of '{pkg_name}' before deployment. "
                    f"New packages with install scripts are a common supply chain vector."
                ),
            )
            result.add_finding(finding)


def _extract_install_script_packages(lockdata: dict) -> Dict[str, str]:
    """Extract packages with hasInstallScript from package-lock.json."""
    packages_with_scripts: Dict[str, str] = {}

    # lockfileVersion 2/3 uses "packages"
    packages = lockdata.get("packages", {})
    for pkg_path, pkg_info in packages.items():
        if not pkg_path or pkg_path == "":
            continue  # Skip root package
        if pkg_info.get("hasInstallScript"):
            # Extract package name from path (node_modules/name)
            name = pkg_path.replace("node_modules/", "").split("node_modules/")[-1]
            scripts = []
            if "scripts" in pkg_info:
                for script_key in ("preinstall", "install", "postinstall", "prepare"):
                    if script_key in pkg_info.get("scripts", {}):
                        scripts.append(script_key)
            packages_with_scripts[name] = ", ".join(scripts) if scripts else "hasInstallScript=true"

    # Fallback for lockfileVersion 1
    if not packages_with_scripts:
        deps = lockdata.get("dependencies", {})
        for name, info in deps.items():
            if isinstance(info, dict) and info.get("hasInstallScript"):
                packages_with_scripts[name] = "hasInstallScript=true"

    return packages_with_scripts


# ============================================================================
# Check 4: Malicious .pth file detection (Python)
# ============================================================================

def _check_pth_files(extract_dir: str, result: SupplyChainResult) -> None:
    """
    Scan site-packages for .pth files containing executable code.

    A legitimate .pth file contains only path entries (one directory per line).
    The LiteLLM attack (March 2026) used litellm_init.pth with import statements
    that executed on every Python interpreter startup.
    """
    result.checks_run.append("pth_file_detection")

    pth_files_found = 0

    for root, dirs, files in os.walk(extract_dir):
        for filename in files:
            if not filename.endswith(".pth"):
                continue

            # Only check .pth files in site-packages directories
            if "site-packages" not in root:
                continue

            filepath = os.path.join(root, filename)
            pth_files_found += 1

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            # Check each line and each dangerous pattern
            dangerous_lines = []
            for line_num, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                for pattern in _PTH_DANGEROUS_PATTERNS:
                    if pattern.search(stripped):
                        dangerous_lines.append((line_num, stripped, pattern.pattern))

            if dangerous_lines:
                # Determine severity based on what was found
                has_import = any("import" in pat for _, _, pat in dangerous_lines)
                has_exec = any(kw in pat for _, _, pat in dangerous_lines
                               for kw in ("exec", "eval", "subprocess", "os.system", "base64"))

                severity = "CRITICAL"  # Any executable .pth is critical

                evidence_lines = [f"  Line {ln}: {code}" for ln, code, _ in dangerous_lines[:5]]
                if len(dangerous_lines) > 5:
                    evidence_lines.append(f"  ... and {len(dangerous_lines) - 5} more")

                # Get relative path within site-packages for clarity
                rel_path = filepath
                if "site-packages" in filepath:
                    rel_path = filepath[filepath.index("site-packages"):]

                finding = SupplyChainFinding(
                    check_name="pth_file_detection",
                    severity=severity,
                    package_name=filename.replace(".pth", ""),
                    ecosystem="python",
                    description=(
                        f"Malicious .pth file detected: {rel_path} contains "
                        f"executable code ({len(dangerous_lines)} dangerous lines). "
                        f"This matches the LiteLLM auto-execute attack pattern."
                    ),
                    evidence="\n".join(evidence_lines),
                    recommendation=(
                        f"Remove {filename} from site-packages immediately. "
                        f"Investigate the package that installed it."
                    ),
                )
                result.add_finding(finding)

    logger.debug(f"Scanned {pth_files_found} .pth files in site-packages")


# ============================================================================
# Check 5: Provenance verification
# ============================================================================

def _check_provenance(
    extract_dir: str,
    manifests: List[ManifestInfo],
    result: SupplyChainResult,
) -> None:
    """
    Verify installed package integrity via RECORD hash checking.

    For Python: checks .dist-info/RECORD files against actual file hashes.
    For npm: runs npm audit signatures if available.
    """
    result.checks_run.append("provenance_verification")

    # Python RECORD verification
    _verify_python_records(extract_dir, result)

    # npm signature verification
    for manifest in manifests:
        if manifest.manifest_type == "package-lock.json":
            _verify_npm_signatures(os.path.dirname(manifest.path), result)


def _verify_python_records(extract_dir: str, result: SupplyChainResult) -> None:
    """Verify Python package RECORD files against actual file hashes."""
    for root, dirs, files in os.walk(extract_dir):
        if not root.endswith(".dist-info"):
            continue
        if "RECORD" not in files:
            continue

        record_path = os.path.join(root, "RECORD")
        dist_info_name = os.path.basename(root)
        package_name = dist_info_name.split("-")[0] if "-" in dist_info_name else dist_info_name

        # The parent of .dist-info is the site-packages dir
        site_packages_dir = os.path.dirname(root)

        try:
            with open(record_path, "r") as f:
                reader = csv.reader(f)
                tampered_files = []
                for row in reader:
                    if len(row) < 2:
                        continue
                    rel_path = row[0]
                    hash_spec = row[1]

                    if not hash_spec or rel_path.endswith(".dist-info/RECORD"):
                        continue

                    # Parse hash: "sha256=base64hash"
                    if "=" not in hash_spec:
                        continue
                    algo, expected_hash = hash_spec.split("=", 1)
                    if algo != "sha256":
                        continue

                    # Compute actual hash
                    file_path = os.path.join(site_packages_dir, rel_path)
                    if not os.path.exists(file_path):
                        continue  # File might have been excluded from extraction

                    try:
                        import base64
                        actual_hash = _compute_file_hash_b64(file_path)
                        if actual_hash != expected_hash:
                            tampered_files.append(rel_path)
                    except Exception:
                        continue

                if tampered_files:
                    finding = SupplyChainFinding(
                        check_name="provenance_verification",
                        severity="CRITICAL",
                        package_name=package_name,
                        ecosystem="python",
                        description=(
                            f"Package '{package_name}' has {len(tampered_files)} file(s) "
                            f"that do not match their RECORD hashes. This indicates "
                            f"post-install tampering."
                        ),
                        evidence=f"Tampered files: {', '.join(tampered_files[:5])}",
                        recommendation=(
                            f"Reinstall '{package_name}' from a trusted source. "
                            f"Investigate how the files were modified."
                        ),
                    )
                    result.add_finding(finding)

        except (OSError, csv.Error) as e:
            logger.debug(f"Failed to verify RECORD for {dist_info_name}: {e}")


def _compute_file_hash_b64(filepath: str) -> str:
    """Compute SHA256 hash of a file, returning URL-safe base64 (no padding)."""
    import base64
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode("ascii")


def _verify_npm_signatures(package_dir: str, result: SupplyChainResult) -> None:
    """Run npm audit signatures if npm is available."""
    if not shutil.which("npm"):
        return

    try:
        code, output = run_cmd(
            ["npm", "audit", "signatures"],
            timeout=60,
        )
        if code != 0 and "invalid" in output.lower():
            finding = SupplyChainFinding(
                check_name="provenance_verification",
                severity="HIGH",
                package_name="(multiple)",
                ecosystem="javascript",
                description="npm audit signatures found packages with invalid signatures",
                evidence=output[:500],
                recommendation="Investigate packages with invalid registry signatures",
            )
            result.add_finding(finding)
    except Exception as e:
        logger.debug(f"npm audit signatures failed: {e}")


# ============================================================================
# Check 6: Package age check (npm)
# ============================================================================

def _check_package_age(
    manifests: List[ManifestInfo],
    min_age_days: int,
    result: SupplyChainResult,
) -> None:
    """
    Check npm package publish dates against minimum age threshold.

    The Axios attack used a version published only hours before the attack.
    Flagging recently-published versions catches this pattern.
    """
    result.checks_run.append("package_age_check")

    session = _create_npm_session()

    for manifest in manifests:
        if manifest.manifest_type != "package-lock.json":
            continue

        try:
            with open(manifest.path, "r") as f:
                lockdata = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        # Extract package name -> version from lockfile
        packages = _extract_package_versions(lockdata)
        checked = 0

        for pkg_name, version in packages.items():
            if checked > 0 and checked % 10 == 0:
                # Brief pause every 10 requests for rate limiting
                time.sleep(0.1)

            publish_date = _get_npm_publish_date(session, pkg_name, version)
            if publish_date is None:
                continue

            checked += 1
            age_days = (datetime.now(timezone.utc) - publish_date).days

            if age_days < min_age_days:
                finding = SupplyChainFinding(
                    check_name="package_age_check",
                    severity="MEDIUM",
                    package_name=pkg_name,
                    ecosystem="javascript",
                    description=(
                        f"Package '{pkg_name}@{version}' was published only "
                        f"{age_days} day(s) ago (threshold: {min_age_days} days). "
                        f"Recently-published versions carry higher supply chain risk."
                    ),
                    evidence=f"Published: {publish_date.isoformat()}, version: {version}",
                    recommendation=(
                        f"Verify that '{pkg_name}@{version}' is legitimate. "
                        f"Consider pinning to a more established version."
                    ),
                )
                result.add_finding(finding)

            # Rate limit: max 10 queries/sec
            time.sleep(_NPM_RATE_LIMIT_INTERVAL)


def _create_npm_session() -> requests.Session:
    """Create session for npm registry queries with retry."""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _extract_package_versions(lockdata: dict) -> Dict[str, str]:
    """Extract {package_name: version} from package-lock.json."""
    result: Dict[str, str] = {}

    # lockfileVersion 2/3
    packages = lockdata.get("packages", {})
    for pkg_path, info in packages.items():
        if not pkg_path or pkg_path == "":
            continue
        name = pkg_path.replace("node_modules/", "").split("node_modules/")[-1]
        version = info.get("version", "")
        if name and version:
            result[name] = version

    # Fallback for lockfileVersion 1
    if not result:
        deps = lockdata.get("dependencies", {})
        for name, info in deps.items():
            if isinstance(info, dict):
                result[name] = info.get("version", "")

    return result


def _get_npm_publish_date(
    session: requests.Session,
    package_name: str,
    version: str,
) -> Optional[datetime]:
    """Query npm registry for the publish date of a specific package version."""
    # URL-encode scoped packages (@scope/name)
    encoded_name = package_name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded_name}/{version}"

    try:
        resp = session.get(url, timeout=10)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()

        # The "time" field might not be in the version-specific endpoint.
        # Fall back to the full package metadata if needed.
        publish_time = data.get("time")
        if not publish_time:
            # Try the abbreviated metadata
            url_full = f"https://registry.npmjs.org/{encoded_name}"
            resp_full = session.get(url_full, timeout=10, headers={"Accept": "application/json"})
            if resp_full.status_code == 200:
                full_data = resp_full.json()
                time_map = full_data.get("time", {})
                publish_time = time_map.get(version)
                if publish_time:
                    return datetime.fromisoformat(publish_time.replace("Z", "+00:00"))
            return None

        if isinstance(publish_time, str):
            return datetime.fromisoformat(publish_time.replace("Z", "+00:00"))

    except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
        logger.debug(f"Failed to query npm registry for {package_name}@{version}: {e}")

    return None


# ============================================================================
# Main entry point
# ============================================================================

def scan_supply_chain(
    image_name: str,
    dockerfile_path: str,
    output_dir: str,
    previous_lockfiles: Optional[Dict[str, str]] = None,
    min_package_age_days: int = 7,
    ecosystems: Optional[List[str]] = None,
) -> SupplyChainResult:
    """
    Run all six supply chain integrity checks against a container image.

    Args:
        image_name: Docker image name/tag to scan.
        dockerfile_path: Path to the Dockerfile (for context).
        output_dir: Directory for scan artifacts.
        previous_lockfiles: Dict mapping lockfile paths to their previous content,
                            used for install script diff detection.
        min_package_age_days: Minimum age in days for npm packages (default 7).
        ecosystems: List of ecosystems to check (default ["python", "javascript"]).

    Returns:
        SupplyChainResult with all findings, manifests, and risk assessment.
    """
    if ecosystems is None:
        ecosystems = ["python", "javascript"]

    result = SupplyChainResult()
    start_time = time.time()

    logger.info(f"Starting supply chain scan for {image_name}")
    logger.info(f"Ecosystems: {ecosystems}")

    # Create extraction directory
    extract_dir = tempfile.mkdtemp(prefix="autopatch_scs_")

    try:
        # Extract container filesystem
        logger.info("Extracting container filesystem for analysis...")
        if not _extract_container_fs(image_name, extract_dir):
            logger.warning("Container extraction failed, supply chain scan will be limited")

        # Discover manifests
        manifests = _find_manifests(extract_dir, ecosystems)
        result.manifests_found = manifests
        logger.info(f"Found {len(manifests)} package manifests")
        for m in manifests:
            logger.debug(f"  {m.ecosystem}: {m.manifest_type} at {m.path}")

        # Check 1: Known vulnerability audit
        if manifests:
            logger.info("Check 1: Known vulnerability audit...")
            _check_known_vulns(extract_dir, manifests, result)

        # Check 2: Phantom dependency detection
        if manifests:
            logger.info("Check 2: Phantom dependency detection...")
            _check_phantom_deps(extract_dir, manifests, result)

        # Check 3: Install script detection (npm only)
        if "javascript" in ecosystems:
            logger.info("Check 3: Install script detection...")
            _check_install_scripts(manifests, previous_lockfiles, result)

        # Check 4: Malicious .pth file detection (Python only)
        if "python" in ecosystems:
            logger.info("Check 4: Malicious .pth file detection...")
            _check_pth_files(extract_dir, result)

        # Check 5: Provenance verification
        logger.info("Check 5: Provenance verification...")
        _check_provenance(extract_dir, manifests, result)

        # Check 6: Package age check (npm only)
        if "javascript" in ecosystems and manifests:
            logger.info("Check 6: Package age check...")
            _check_package_age(manifests, min_package_age_days, result)

    except Exception as e:
        logger.error(f"Supply chain scan encountered an error: {e}")
    finally:
        # Cleanup extraction directory
        try:
            shutil.rmtree(extract_dir, ignore_errors=True)
        except Exception:
            pass

    result.scan_duration_seconds = round(time.time() - start_time, 2)

    # Log summary
    severity_counts = {}
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    logger.info(
        f"Supply chain scan complete in {result.scan_duration_seconds}s: "
        f"{len(result.findings)} findings, risk={result.overall_risk}"
    )
    for sev, count in sorted(severity_counts.items()):
        logger.info(f"  {sev}: {count}")

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    results_path = os.path.join(output_dir, "supply-chain-scan.json")
    try:
        with open(results_path, "w") as f:
            json.dump(_result_to_dict(result), f, indent=2)
        logger.info(f"Supply chain scan results saved to {results_path}")
    except Exception as e:
        logger.warning(f"Failed to save supply chain results: {e}")

    return result


def _result_to_dict(result: SupplyChainResult) -> dict:
    """Convert SupplyChainResult to a JSON-serializable dictionary."""
    return {
        "overall_risk": result.overall_risk,
        "scan_duration_seconds": result.scan_duration_seconds,
        "checks_run": result.checks_run,
        "total_findings": len(result.findings),
        "manifests_found": [
            {"path": m.path, "type": m.manifest_type, "ecosystem": m.ecosystem}
            for m in result.manifests_found
        ],
        "findings": [
            {
                "check_name": f.check_name,
                "severity": f.severity,
                "package_name": f.package_name,
                "ecosystem": f.ecosystem,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
    }
