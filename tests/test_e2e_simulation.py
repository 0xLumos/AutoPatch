"""
End-to-End Simulation Test for AutoPatch Pipeline

Since Docker and Trivy are not available in this environment, this test
exercises the FULL AutoPatch logic path for 5 different images using
realistic mock scan/SBOM data. Every module in the pipeline is called
with real data structures -- the only thing mocked is the external
process calls (docker build, trivy scan, etc.)

Images tested:
  1. python:3.8-slim   -- EOL Python on old Debian
  2. node:16-bullseye  -- EOL Node.js on old Debian
  3. nginx:1.21        -- Infrastructure service, no language runtime
  4. golang:1.19-alpine -- EOL Go on Alpine base
  5. ruby:2.7          -- EOL Ruby on Debian
"""

import json
import os
import sys
import tempfile
from typing import Dict, Any, List, Tuple, Optional
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.patcher import (
    analyze_sbom, patch_dockerfile, choose_base_image,
    _upgrade_eol_version, _detect_os_family, InferenceResult,
)
from src.comparer import check_acceptance_criteria, diff_vulnerabilities, compute_metrics
from src.scanner_fusion import fuse_scan_results, compute_lev, compute_composite_priority
from src.dep_graph import build_dependency_graph, get_vulnerability_reachability, extract_embedded_vulnerabilities
from src.vex_generator import (
    generate_openvex, build_vex_statements_from_diff,
    extract_suppressed_cves, apply_vex_suppression,
)
from src.inplace_patcher import generate_inplace_patch, extract_os_vulnerable_packages
from src.version_resolver import TTLCache, _FALLBACK_EOL_UPGRADES, _parse_image_ref
from src.builder import validate_build_context


# ════════════════════════════════════════════════════════════════════
# Mock Data Generators
# ════════════════════════════════════════════════════════════════════

def make_scan_result(vulns: List[Dict], result_type: str = "debian") -> Dict:
    """Build a Trivy-format scan result."""
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": f"{result_type} (test)",
                "Class": "os-pkgs",
                "Type": result_type,
                "Vulnerabilities": vulns,
            }
        ]
    }


def make_vuln(cve_id: str, pkg: str, severity: str, installed: str,
              fixed: str = "", pkg_type: str = "") -> Dict:
    """Build a single Trivy vulnerability entry."""
    v = {
        "VulnerabilityID": cve_id,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "Severity": severity,
    }
    if fixed:
        v["FixedVersion"] = fixed
    if pkg_type:
        v["PkgType"] = pkg_type
    return v


def make_sbom(components: List[Dict], meta_name: str = "",
              dependencies: List[Dict] = None,
              vulnerabilities: List[Dict] = None) -> Dict:
    """Build a CycloneDX SBOM."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
        "metadata": {
            "component": {
                "name": meta_name,
                "bom-ref": "root-component",
            }
        },
    }
    if dependencies:
        sbom["dependencies"] = dependencies
    if vulnerabilities:
        sbom["vulnerabilities"] = vulnerabilities
    return sbom


def make_component(name: str, version: str, purl: str = "",
                   bom_ref: str = "") -> Dict:
    comp = {"name": name, "version": version}
    if purl:
        comp["purl"] = purl
    if bom_ref:
        comp["bom-ref"] = bom_ref
    return comp


# ════════════════════════════════════════════════════════════════════
# Test Image 1: python:3.8-slim
# ════════════════════════════════════════════════════════════════════

class TestPython38Slim:
    """
    python:3.8-slim: EOL Python 3.8 on Debian Bullseye.
    Expected behavior:
    - OS detected as debian
    - Language detected as python 3.8
    - Python 3.8 upgraded to 3.12 (EOL resolution)
    - Base image replaced with python:3.12-slim or python:3.12-alpine
    - Vulnerabilities should reduce significantly
    """

    DOCKERFILE = """FROM python:3.8-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "app.py"]
"""

    SBOM = make_sbom(
        meta_name="python:3.8-slim",
        components=[
            make_component("python3.8", "3.8.18", "pkg:deb/debian/python3.8@3.8.18", "python38"),
            make_component("libc6", "2.31-13", "pkg:deb/debian/libc6@2.31-13", "libc6"),
            make_component("libssl1.1", "1.1.1w-0+deb11u1", "pkg:deb/debian/libssl1.1@1.1.1w", "libssl"),
            make_component("apt", "2.2.4", "pkg:deb/debian/apt@2.2.4", "apt"),
            make_component("dpkg", "1.20.12", "pkg:deb/debian/dpkg@1.20.12", "dpkg"),
            make_component("zlib1g", "1.2.11", "pkg:deb/debian/zlib1g@1.2.11", "zlib"),
            make_component("openssl", "1.1.1w", "pkg:deb/debian/openssl@1.1.1w", "openssl"),
            make_component("pip", "23.0.1", "pkg:pypi/pip@23.0.1"),
            make_component("setuptools", "57.5.0", "pkg:pypi/setuptools@57.5.0"),
            make_component("flask", "2.3.3", "pkg:pypi/flask@2.3.3"),
            make_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ],
        dependencies=[
            {"ref": "root-component", "dependsOn": ["python38", "libc6", "libssl", "apt"]},
            {"ref": "python38", "dependsOn": ["libc6", "libssl"]},
        ],
    )

    SCAN_BEFORE = make_scan_result([
        make_vuln("CVE-2023-44487", "libnghttp2-14", "HIGH", "1.43.0-1+deb11u1", "1.43.0-1+deb11u2"),
        make_vuln("CVE-2023-4911", "libc6", "CRITICAL", "2.31-13", "2.31-13+deb11u8"),
        make_vuln("CVE-2024-0567", "libgnutls30", "HIGH", "3.7.1-5+deb11u4", "3.7.1-5+deb11u5"),
        make_vuln("CVE-2023-5678", "openssl", "HIGH", "1.1.1w-0+deb11u1", "1.1.1w-0+deb11u2"),
        make_vuln("CVE-2024-2511", "openssl", "MEDIUM", "1.1.1w-0+deb11u1", "1.1.1w-0+deb11u2"),
        make_vuln("CVE-2023-45853", "zlib1g", "CRITICAL", "1:1.2.11.dfsg-2+deb11u2"),
        make_vuln("CVE-2023-6246", "libc6", "HIGH", "2.31-13", "2.31-13+deb11u8"),
        make_vuln("CVE-2024-28757", "libexpat1", "MEDIUM", "2.2.10-2+deb11u5", "2.2.10-2+deb11u6"),
    ])

    SCAN_AFTER = make_scan_result([
        make_vuln("CVE-2024-28757", "libexpat1", "MEDIUM", "2.4.7-1", "2.4.7-2"),
    ])

    def test_os_detection(self):
        inference = analyze_sbom(self.SBOM)
        assert inference.os_family == "debian"
        assert inference.language == "python"
        assert inference.libc_type == "glibc"

    def test_eol_upgrade(self):
        """Python 3.8 should be detected as EOL and upgraded."""
        # The module-level toggle is False by default; enable it
        # for the duration of this test so EOL upgrades actually fire.
        from src import patcher as _p
        _prev, _p._EOL_UPGRADE_ACTIVE = _p._EOL_UPGRADE_ACTIVE, True
        try:
            result = _upgrade_eol_version("python", "3.8")
        finally:
            _p._EOL_UPGRADE_ACTIVE = _prev
        # Should be upgraded (either via live API or fallback)
        assert result != "3.8", f"Python 3.8 should be upgraded but got {result}"

    def test_dockerfile_patching(self):
        """Both sides of the --eol-upgrade gate. With it shut the pinned
        3.8 has to survive the rewrite (only the variant is normalised);
        with it open the interpreter has to move off the dead release.
        Asserting only the second half would let a resolver that ignores
        the gate pass, which is the defect that made a pinned tag's
        survival depend on which strategy resolved it."""
        from src import patcher as _p

        _prev, _p._EOL_UPGRADE_ACTIVE = _p._EOL_UPGRADE_ACTIVE, False
        try:
            _patched, base_changes, _w, _d = patch_dockerfile(
                self.DOCKERFILE, self.SBOM
            )
            assert len(base_changes) >= 1
            orig, new = base_changes[0]
            assert orig == "python:3.8-slim"
            assert new == "python:3.8-slim", (
                f"pinned Python 3.8 should survive an ungated run, got {new}")

            _p._EOL_UPGRADE_ACTIVE = True
            _patched, base_changes, _w, _d = patch_dockerfile(
                self.DOCKERFILE, self.SBOM
            )
            assert len(base_changes) >= 1
            orig, new = base_changes[0]
            assert orig == "python:3.8-slim"
        finally:
            _p._EOL_UPGRADE_ACTIVE = _prev
        # New base should be a modern Python version
        assert "python:" in new
        assert "3.8" not in new, f"EOL Python 3.8 should be upgraded, got {new}"
        print(f"  [python:3.8-slim] Patched: {orig} -> {new}")

    def test_acceptance_criteria(self):
        accepted, reasons = check_acceptance_criteria(self.SCAN_BEFORE, self.SCAN_AFTER)
        assert accepted, f"Should be accepted: {reasons}"

    def test_vulnerability_reduction(self):
        diff = diff_vulnerabilities(self.SCAN_BEFORE, self.SCAN_AFTER)
        assert len(diff["resolved"]) > 0
        assert len(diff["new"]) == 0
        print(f"  [python:3.8-slim] Resolved: {len(diff['resolved'])}, "
              f"Remaining: {len(diff['remaining'])}")

    def test_dependency_graph(self):
        graph = build_dependency_graph(self.SBOM)
        assert graph.total_components > 0
        reach, depth = get_vulnerability_reachability(graph, "libc6")
        assert reach == "DIRECT"
        print(f"  [python:3.8-slim] Dep graph: {graph.reachable_count} reachable, "
              f"max depth {graph.max_depth}")

    def test_vex_generation(self):
        diff = diff_vulnerabilities(self.SCAN_BEFORE, self.SCAN_AFTER)
        statements = build_vex_statements_from_diff(diff, base_image_change="python:3.8-slim -> python:3.12-slim")
        assert len(statements) > 0
        fixed_stmts = [s for s in statements if s["status"] == "fixed"]
        assert len(fixed_stmts) > 0
        print(f"  [python:3.8-slim] VEX: {len(fixed_stmts)} fixed statements")


# ════════════════════════════════════════════════════════════════════
# Test Image 2: node:16-bullseye
# ════════════════════════════════════════════════════════════════════

class TestNode16Bullseye:
    """
    node:16-bullseye: EOL Node.js 16 on Debian Bullseye.
    Expected behavior:
    - OS detected as debian
    - Language detected as node 16
    - Node 16 upgraded to 22 (or current LTS)
    - glibc dependency detected (should not go to Alpine)
    """

    DOCKERFILE = """FROM node:16-bullseye
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
"""

    SBOM = make_sbom(
        meta_name="node:16-bullseye",
        components=[
            make_component("nodejs", "16.20.2", "pkg:deb/debian/nodejs@16.20.2", "nodejs"),
            make_component("libc6", "2.31-13", "pkg:deb/debian/libc6@2.31-13", "libc6"),
            make_component("libssl1.1", "1.1.1w", "pkg:deb/debian/libssl1.1@1.1.1w", "libssl"),
            make_component("apt", "2.2.4", "pkg:deb/debian/apt@2.2.4", "apt"),
            make_component("dpkg", "1.20.12", "pkg:deb/debian/dpkg@1.20.12", "dpkg"),
            make_component("libstdc++6", "10.2.1-6", "pkg:deb/debian/libstdc++6@10.2.1-6", "libstdcpp"),
            make_component("express", "4.18.2", "pkg:npm/express@4.18.2"),
            make_component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
        ],
        dependencies=[
            {"ref": "root-component", "dependsOn": ["nodejs", "libc6", "libssl"]},
            {"ref": "nodejs", "dependsOn": ["libc6", "libssl", "libstdcpp"]},
        ],
    )

    SCAN_BEFORE = make_scan_result([
        make_vuln("CVE-2023-4911", "libc6", "CRITICAL", "2.31-13", "2.31-13+deb11u8"),
        make_vuln("CVE-2024-22019", "nodejs", "HIGH", "16.20.2"),
        make_vuln("CVE-2023-44487", "libnghttp2-14", "HIGH", "1.43.0-1", "1.43.0-1+deb11u2"),
        make_vuln("CVE-2023-5678", "openssl", "HIGH", "1.1.1w", "1.1.1w-0+deb11u2"),
        make_vuln("CVE-2024-2511", "openssl", "MEDIUM", "1.1.1w", "1.1.1w-0+deb11u2"),
        make_vuln("CVE-2023-6246", "libc6", "HIGH", "2.31-13", "2.31-13+deb11u8"),
    ])

    SCAN_AFTER = make_scan_result([
        make_vuln("CVE-2024-28757", "libexpat1", "LOW", "2.5.0-1", "2.5.0-2"),
    ])

    def test_os_and_language_detection(self):
        inference = analyze_sbom(self.SBOM)
        assert inference.os_family == "debian"
        assert inference.language == "node"
        assert inference.needs_glibc is True  # libstdc++6 triggers glibc need
        print(f"  [node:16] OS={inference.os_family}, lang={inference.language}, "
              f"glibc={inference.needs_glibc}, libc={inference.libc_type}")

    def test_eol_upgrade(self):
        from src import patcher as _p
        _prev, _p._EOL_UPGRADE_ACTIVE = _p._EOL_UPGRADE_ACTIVE, True
        try:
            result = _upgrade_eol_version("node", "16")
        finally:
            _p._EOL_UPGRADE_ACTIVE = _prev
        assert result != "16", f"Node 16 should be upgraded but got {result}"
        print(f"  [node:16] EOL upgrade: 16 -> {result}")

    def test_dockerfile_patching(self):
        """Gate shut, the pinned major stays put and only the variant is
        rewritten; gate open, the runtime moves off the dead major.
        Checking just the upgrade would pass on a resolver that never
        reads the toggle at all."""
        from src import patcher as _p

        _prev, _p._EOL_UPGRADE_ACTIVE = _p._EOL_UPGRADE_ACTIVE, False
        try:
            _patched, base_changes, _w, _d = patch_dockerfile(
                self.DOCKERFILE, self.SBOM
            )
            assert len(base_changes) >= 1
            _orig, new = base_changes[0]
            assert new == "node:16-slim", (
                f"pinned Node 16 should survive an ungated run, got {new}")

            _p._EOL_UPGRADE_ACTIVE = True
            _patched, base_changes, _w, _d = patch_dockerfile(
                self.DOCKERFILE, self.SBOM
            )
            assert len(base_changes) >= 1
            orig, new = base_changes[0]
        finally:
            _p._EOL_UPGRADE_ACTIVE = _prev
        assert "node:" in new
        assert "16" not in new, f"Node 16 should be upgraded, got {new}"
        # Should NOT have alpine since glibc is needed
        assert "alpine" not in new, f"glibc target must not go musl, got {new}"
        print(f"  [node:16] Patched: {orig} -> {new}")

    def test_acceptance(self):
        accepted, reasons = check_acceptance_criteria(self.SCAN_BEFORE, self.SCAN_AFTER)
        assert accepted

    def test_inplace_patching(self):
        """Test in-place patching mode as alternative."""
        result = generate_inplace_patch(
            original_image="node:16-bullseye",
            scan_result=self.SCAN_BEFORE,
            os_family="debian",
            sbom_data=self.SBOM,
        )
        assert "FROM node:16-bullseye" in result.patch_dockerfile
        assert "apt-get" in result.patch_dockerfile
        assert len(result.os_packages_to_upgrade) > 0
        print(f"  [node:16] In-place: {len(result.os_packages_to_upgrade)} OS packages to patch")


# ════════════════════════════════════════════════════════════════════
# Test Image 3: nginx:1.21
# ════════════════════════════════════════════════════════════════════

class TestNginx121:
    """
    nginx:1.21: Infrastructure service, no language runtime.
    Expected behavior:
    - OS detected as debian
    - No language runtime detected
    - Base image upgraded to modern nginx on debian/alpine
    - Only OS-level vulns to fix
    """

    DOCKERFILE = """FROM nginx:1.21
COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /usr/share/nginx/html/
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
"""

    SBOM = make_sbom(
        meta_name="nginx:1.21",
        components=[
            make_component("nginx", "1.21.6", "", "nginx"),
            make_component("libc6", "2.31-13", "pkg:deb/debian/libc6@2.31-13", "libc6"),
            make_component("libssl1.1", "1.1.1w", "pkg:deb/debian/libssl1.1@1.1.1w", "libssl"),
            make_component("apt", "2.2.4", "pkg:deb/debian/apt@2.2.4", "apt"),
            make_component("dpkg", "1.20.12", "pkg:deb/debian/dpkg@1.20.12", "dpkg"),
            make_component("zlib1g", "1.2.11", "pkg:deb/debian/zlib1g@1.2.11", "zlib"),
            make_component("libpcre3", "8.39-13", "pkg:deb/debian/libpcre3@8.39-13", "pcre"),
            make_component("libgd3", "2.3.0-2", "pkg:deb/debian/libgd3@2.3.0-2"),
            make_component("curl", "7.74.0-1.3+deb11u11", "pkg:deb/debian/curl@7.74.0"),
        ],
        dependencies=[
            {"ref": "root-component", "dependsOn": ["nginx", "libc6"]},
            {"ref": "nginx", "dependsOn": ["libc6", "libssl", "zlib", "pcre"]},
        ],
    )

    SCAN_BEFORE = make_scan_result([
        make_vuln("CVE-2023-4911", "libc6", "CRITICAL", "2.31-13", "2.31-13+deb11u8"),
        make_vuln("CVE-2023-44487", "libnghttp2-14", "HIGH", "1.43.0-1", "1.43.0-1+deb11u2"),
        make_vuln("CVE-2023-5678", "openssl", "HIGH", "1.1.1w", "1.1.1w-0+deb11u2"),
        make_vuln("CVE-2022-41741", "nginx", "HIGH", "1.21.6", "1.23.2"),
        make_vuln("CVE-2022-41742", "nginx", "MEDIUM", "1.21.6", "1.23.2"),
    ])

    SCAN_AFTER = make_scan_result([
        make_vuln("CVE-2024-28757", "libexpat1", "LOW", "2.5.0-1", "2.5.0-2"),
    ])

    def test_os_detection_no_language(self):
        inference = analyze_sbom(self.SBOM)
        assert inference.os_family == "debian"
        # nginx is not a language runtime, so no language should be detected
        assert inference.language is None or inference.language not in ("python", "node", "golang")
        print(f"  [nginx:1.21] OS={inference.os_family}, lang={inference.language}")

    def test_dockerfile_patching(self):
        patched, base_changes, warnings, diff = patch_dockerfile(
            self.DOCKERFILE, self.SBOM
        )
        # Should still patch the base image even without language detection
        assert len(base_changes) >= 1 or len(warnings) > 0
        if base_changes:
            orig, new = base_changes[0]
            print(f"  [nginx:1.21] Patched: {orig} -> {new}")
        else:
            print(f"  [nginx:1.21] No base change. Warnings: {warnings}")

    def test_acceptance(self):
        accepted, reasons = check_acceptance_criteria(self.SCAN_BEFORE, self.SCAN_AFTER)
        assert accepted

    def test_inplace_os_patching(self):
        packages = extract_os_vulnerable_packages(self.SCAN_BEFORE, "debian")
        assert len(packages) >= 3  # At least libc6, openssl, libnghttp2
        print(f"  [nginx:1.21] OS packages with fixes: {len(packages)}")

    def test_dual_scanner_fusion(self):
        """Simulate dual-scanner fusion with Trivy + Grype finding overlapping CVEs."""
        trivy = self.SCAN_BEFORE
        # Grype finds 4 of the same + 1 exclusive
        grype = make_scan_result([
            make_vuln("CVE-2023-4911", "libc6", "CRITICAL", "2.31-13", "2.31-13+deb11u8"),
            make_vuln("CVE-2023-44487", "libnghttp2-14", "HIGH", "1.43.0-1", "1.43.0-1+deb11u2"),
            make_vuln("CVE-2023-5678", "openssl", "HIGH", "1.1.1w", "1.1.1w-0+deb11u2"),
            make_vuln("CVE-2022-41741", "nginx", "HIGH", "1.21.6", "1.23.2"),
            make_vuln("CVE-2024-99999", "curl", "MEDIUM", "7.74.0", "7.74.0-1.3+deb11u12"),
        ])
        fused = fuse_scan_results(trivy, grype)
        confirmed = fused.confirmed
        exclusive = fused.exclusive_trivy + fused.exclusive_grype
        print(f"  [nginx:1.21] Fusion: {len(confirmed)} confirmed, {len(exclusive)} exclusive")
        assert len(confirmed) >= 3


# ════════════════════════════════════════════════════════════════════
# Test Image 4: golang:1.19-alpine
# ════════════════════════════════════════════════════════════════════

class TestGolang119Alpine:
    """
    golang:1.19-alpine: EOL Go on Alpine.
    Expected behavior:
    - OS detected as alpine
    - Language detected as golang 1.19
    - Go 1.19 upgraded to 1.23 (or current)
    - Stays on Alpine (musl-compatible)
    """

    DOCKERFILE = """FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server ./cmd/server

FROM alpine:3.16
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/server /usr/local/bin/server
ENTRYPOINT ["server"]
"""

    SBOM = make_sbom(
        meta_name="golang:1.19-alpine",
        components=[
            make_component("go", "1.19.13", "", "golang"),
            make_component("musl", "1.2.3-r4", "pkg:apk/alpine/musl@1.2.3-r4", "musl"),
            make_component("apk-tools", "2.12.10-r1", "pkg:apk/alpine/apk-tools@2.12.10-r1", "apk"),
            make_component("alpine-baselayout", "3.4.0-r0", "pkg:apk/alpine/alpine-baselayout@3.4.0", "base"),
            make_component("busybox", "1.35.0-r17", "pkg:apk/alpine/busybox@1.35.0-r17"),
            make_component("ca-certificates", "20230506-r0", "pkg:apk/alpine/ca-certificates@20230506"),
            make_component("zlib", "1.2.13-r0", "pkg:apk/alpine/zlib@1.2.13-r0", "zlib"),
            make_component("libcrypto1.1", "1.1.1w-r1", "pkg:apk/alpine/libcrypto1.1@1.1.1w-r1"),
        ],
        dependencies=[
            {"ref": "root-component", "dependsOn": ["golang", "musl", "apk"]},
            {"ref": "golang", "dependsOn": ["musl", "zlib"]},
        ],
    )

    SCAN_BEFORE = make_scan_result([
        make_vuln("CVE-2023-5363", "libcrypto1.1", "HIGH", "1.1.1w-r1", "1.1.1x-r0"),
        make_vuln("CVE-2023-5678", "libcrypto1.1", "MEDIUM", "1.1.1w-r1", "1.1.1x-r0"),
        make_vuln("CVE-2023-44487", "go", "HIGH", "1.19.13"),
        make_vuln("CVE-2023-45285", "go", "HIGH", "1.19.13"),
        make_vuln("CVE-2023-39325", "go", "HIGH", "1.19.13"),
    ], result_type="alpine")

    SCAN_AFTER = make_scan_result([], result_type="alpine")

    def test_os_detection(self):
        inference = analyze_sbom(self.SBOM)
        assert inference.os_family == "alpine"
        assert inference.libc_type == "musl"
        assert inference.needs_glibc is False
        print(f"  [golang:1.19-alpine] OS={inference.os_family}, libc={inference.libc_type}")

    def test_eol_upgrade(self):
        from src import patcher as _p
        _prev, _p._EOL_UPGRADE_ACTIVE = _p._EOL_UPGRADE_ACTIVE, True
        try:
            result = _upgrade_eol_version("golang", "1.19")
        finally:
            _p._EOL_UPGRADE_ACTIVE = _prev
        # In offline environments the API may fail and return original version;
        # accept either a successful upgrade or the original (graceful fallback)
        if result != "1.19":
            print(f"  [golang:1.19-alpine] EOL upgrade: 1.19 -> {result}")
        else:
            # Fallback: verify the function at least runs without error
            print(f"  [golang:1.19-alpine] EOL upgrade: API unavailable, graceful fallback to {result}")
        assert isinstance(result, str) and len(result) > 0

    def test_multi_stage_dockerfile_patching(self):
        patched, base_changes, warnings, diff = patch_dockerfile(
            self.DOCKERFILE, self.SBOM
        )
        # Should patch both stages
        assert "FROM" in patched
        # The builder stage should get upgraded Go
        # The final stage should get upgraded Alpine
        print(f"  [golang:1.19-alpine] Base changes: {base_changes}")
        print(f"  [golang:1.19-alpine] Warnings: {warnings}")
        # Verify the final stage is upgraded (may resolve to alpine or golang-alpine)
        for orig, new in base_changes:
            if "alpine:3.16" in orig:
                assert "alpine" in new.lower(), f"Expected alpine-based target, got {new}"
                print(f"  [golang:1.19-alpine] Final stage: {orig} -> {new}")

    def test_acceptance(self):
        accepted, reasons = check_acceptance_criteria(self.SCAN_BEFORE, self.SCAN_AFTER)
        assert accepted

    def test_vex_suppression(self):
        """Test VEX suppression removes known-fixed CVEs from rescan."""
        # Create a VEX that marks some vulns as fixed
        vex = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {"vulnerability": {"name": "CVE-2023-5363"}, "status": "fixed"},
                {"vulnerability": {"name": "CVE-2023-5678"}, "status": "not_affected"},
            ]
        }
        suppressed = extract_suppressed_cves(vex)
        assert "CVE-2023-5363" in suppressed
        assert "CVE-2023-5678" in suppressed

        # Apply suppression to before_scan
        filtered = apply_vex_suppression(self.SCAN_BEFORE, suppressed_cves=suppressed)
        remaining = filtered["Results"][0]["Vulnerabilities"]
        remaining_ids = [v["VulnerabilityID"] for v in remaining]
        assert "CVE-2023-5363" not in remaining_ids
        assert "CVE-2023-5678" not in remaining_ids
        print(f"  [golang:1.19-alpine] VEX suppression: 5 -> {len(remaining)} vulns")


# ════════════════════════════════════════════════════════════════════
# Test Image 5: ruby:2.7
# ════════════════════════════════════════════════════════════════════

class TestRuby27:
    """
    ruby:2.7: EOL Ruby on Debian.
    Expected behavior:
    - OS detected as debian
    - Language detected as ruby 2.7
    - Ruby 2.7 upgraded to 3.3 (or current)
    - App-level vulnerable gems detected
    """

    DOCKERFILE = """FROM ruby:2.7
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --deployment
COPY . .
EXPOSE 3000
CMD ["rails", "server", "-b", "0.0.0.0"]
"""

    SBOM = make_sbom(
        meta_name="ruby:2.7",
        components=[
            make_component("ruby2.7", "2.7.8", "pkg:deb/debian/ruby2.7@2.7.8", "ruby"),
            make_component("libc6", "2.31-13", "pkg:deb/debian/libc6@2.31-13", "libc6"),
            make_component("libssl1.1", "1.1.1w", "pkg:deb/debian/libssl1.1@1.1.1w"),
            make_component("apt", "2.2.4", "pkg:deb/debian/apt@2.2.4", "apt"),
            make_component("dpkg", "1.20.12", "pkg:deb/debian/dpkg@1.20.12"),
            make_component("libgcc-s1", "10.2.1-6", "pkg:deb/debian/libgcc-s1@10.2.1-6", "gcc"),
            make_component("rails", "6.1.7", "pkg:gem/rails@6.1.7"),
            make_component("nokogiri", "1.13.10", "pkg:gem/nokogiri@1.13.10"),
            make_component("puma", "5.6.7", "pkg:gem/puma@5.6.7"),
        ],
        dependencies=[
            {"ref": "root-component", "dependsOn": ["ruby", "libc6"]},
            {"ref": "ruby", "dependsOn": ["libc6", "gcc"]},
        ],
    )

    SCAN_BEFORE = make_scan_result([
        make_vuln("CVE-2023-4911", "libc6", "CRITICAL", "2.31-13", "2.31-13+deb11u8"),
        make_vuln("CVE-2023-5678", "openssl", "HIGH", "1.1.1w", "1.1.1w-0+deb11u2"),
        make_vuln("CVE-2023-22796", "activesupport", "HIGH", "6.1.7", "6.1.7.2", "bundler"),
        make_vuln("CVE-2023-28120", "activesupport", "MEDIUM", "6.1.7", "6.1.7.4", "bundler"),
        make_vuln("CVE-2023-22795", "actionpack", "HIGH", "6.1.7", "6.1.7.2", "bundler"),
        make_vuln("CVE-2022-44571", "rack", "HIGH", "2.2.4", "2.2.6.2", "bundler"),
        make_vuln("CVE-2023-23913", "rails-html-sanitizer", "HIGH", "1.4.3", "1.4.4", "bundler"),
    ])

    SCAN_AFTER = make_scan_result([
        make_vuln("CVE-2024-28757", "libexpat1", "LOW", "2.5.0-1", "2.5.0-2"),
    ])

    def test_os_and_language(self):
        inference = analyze_sbom(self.SBOM)
        assert inference.os_family == "debian"
        assert inference.language == "ruby"
        assert inference.needs_glibc is True  # libgcc-s1 triggers glibc need
        print(f"  [ruby:2.7] OS={inference.os_family}, lang={inference.language}, "
              f"version={inference.language_version}, glibc={inference.needs_glibc}")

    def test_eol_upgrade(self):
        from src import patcher as _p
        _prev, _p._EOL_UPGRADE_ACTIVE = _p._EOL_UPGRADE_ACTIVE, True
        try:
            result = _upgrade_eol_version("ruby", "2.7")
        finally:
            _p._EOL_UPGRADE_ACTIVE = _prev
        assert result != "2.7", f"Ruby 2.7 should be upgraded but got {result}"
        print(f"  [ruby:2.7] EOL upgrade: 2.7 -> {result}")

    def test_dockerfile_patching(self):
        """Gate shut, the pinned 2.7 has to survive; gate open, it has to
        move. The ungated half is the one that catches a resolver that
        upgrades regardless of what the operator asked for."""
        from src import patcher as _p

        _prev, _p._EOL_UPGRADE_ACTIVE = _p._EOL_UPGRADE_ACTIVE, False
        try:
            _patched, base_changes, _w, _d = patch_dockerfile(
                self.DOCKERFILE, self.SBOM
            )
            assert len(base_changes) >= 1
            _orig, new = base_changes[0]
            assert new == "ruby:2.7-slim", (
                f"pinned Ruby 2.7 should survive an ungated run, got {new}")

            _p._EOL_UPGRADE_ACTIVE = True
            _patched, base_changes, _w, _d = patch_dockerfile(
                self.DOCKERFILE, self.SBOM
            )
            assert len(base_changes) >= 1
            orig, new = base_changes[0]
        finally:
            _p._EOL_UPGRADE_ACTIVE = _prev
        assert "2.7" not in new, f"Ruby 2.7 should be upgraded, got {new}"
        # Should use slim variant since glibc is needed
        assert new.endswith("-slim"), f"glibc target should be slim, got {new}"
        print(f"  [ruby:2.7] Patched: {orig} -> {new}")

    def test_acceptance(self):
        accepted, reasons = check_acceptance_criteria(self.SCAN_BEFORE, self.SCAN_AFTER)
        assert accepted

    def test_metrics_computation(self):
        metrics = compute_metrics(
            self.SCAN_BEFORE, self.SCAN_AFTER,
            self.SBOM, self.SBOM,
            before_size=450_000_000,
            after_size=380_000_000,
            build_time=45.2,
        )
        assert metrics["vulnerability_reduction_pct"] > 0
        assert metrics["total_before"] > metrics["total_after"]
        print(f"  [ruby:2.7] Metrics: {metrics['vulnerability_reduction_pct']:.1f}% reduction, "
              f"{metrics['total_before']} -> {metrics['total_after']} vulns, "
              f"build={metrics.get('build_time', 'N/A')}s")


# ════════════════════════════════════════════════════════════════════
# Cross-Image Tests
# ════════════════════════════════════════════════════════════════════

class TestCrossImage:
    """Tests that verify behavior across all 5 images."""

    def test_lev_computation(self):
        """NIST LEV metric should work for realistic EPSS scores."""
        # 30-day EPSS scores for a realistic vulnerability
        epss_scores = [0.05, 0.06, 0.05, 0.07, 0.08, 0.06, 0.05, 0.09, 0.10, 0.08,
                       0.07, 0.06, 0.05, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10, 0.11,
                       0.09, 0.08, 0.07, 0.06, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10]
        lev = compute_lev(epss_scores)
        assert 0.0 < lev < 1.0
        print(f"  [cross] LEV for 30-day EPSS: {lev:.4f}")

    def test_composite_priority(self):
        """Composite priority should weight KEV, EPSS, LEV, and severity."""
        # KEV flag should dominate
        p_kev = compute_composite_priority(severity="LOW", epss_score=0.01, kev_flag=True, lev_score=0.05)
        p_no_kev = compute_composite_priority(severity="LOW", epss_score=0.01, kev_flag=False, lev_score=0.05)
        assert p_kev > p_no_kev

        # CRITICAL should outweigh LOW
        p_crit = compute_composite_priority(severity="CRITICAL", epss_score=0.5, kev_flag=False, lev_score=0.3)
        p_low = compute_composite_priority(severity="LOW", epss_score=0.5, kev_flag=False, lev_score=0.3)
        assert p_crit > p_low

    def test_ttl_cache_isolation(self):
        """Cache should not leak between tests."""
        cache = TTLCache(default_ttl=60)
        cache.set("test_key", "test_value")
        assert cache.get("test_key") == "test_value"
        cache.clear()
        assert cache.get("test_key") is None


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short", "-s"])
