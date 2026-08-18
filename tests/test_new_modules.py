"""
Comprehensive test suite for AutoPatch new modules.

Tests cover:
- OS family inference (unit tests for each distro family)
- libc type detection
- Immutable OS gating
- Language detection with overrides
- Dual-scanner fusion
- SBOM completeness validation
- NIST LEV computation
- VEX generation
- Builder context validation
- Acceptance criteria edge cases
- ARG resolution in FROM directives
"""

import json
import os
import sys
import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ============================================================================
# OS Family Detection Tests (C1-C6)
# ============================================================================

class TestOSFamilyDetection:
    """Test universal 3-layer OS family detection."""

    def _detect(self, purls, comp_names, meta_name="", comp_count=50):
        from src.patcher import _detect_os_family
        return _detect_os_family(purls, comp_names, meta_name, comp_count)

    def test_alpine_from_apk_purls(self):
        assert self._detect(["pkg:apk/alpine/musl@1.2.4"], ["musl", "apk-tools"]) == "alpine"

    def test_debian_from_deb_purls(self):
        assert self._detect(["pkg:deb/debian/libc6@2.36"], ["apt", "dpkg"]) == "debian"

    def test_ubuntu_from_deb_purls(self):
        assert self._detect(["pkg:deb/ubuntu/libc6@2.35"], ["ubuntu-keyring", "apt"]) == "ubuntu"

    def test_rhel_default_for_rpm(self):
        assert self._detect(["pkg:rpm/rhel/glibc@2.34"], ["glibc"]) == "rhel"

    def test_rocky_from_rpm_purls(self):
        assert self._detect(["pkg:rpm/rocky/glibc@2.34"], ["rocky-release"]) == "rocky"

    def test_alma_from_rpm_purls(self):
        assert self._detect(["pkg:rpm/alma/glibc@2.34"], ["almalinux-release"]) == "alma"

    def test_centos_from_rpm_purls(self):
        assert self._detect(["pkg:rpm/centos/glibc@2.17"], ["centos-release"]) == "centos"

    def test_fedora_from_rpm_purls(self):
        assert self._detect(["pkg:rpm/fedora/glibc@2.38"], ["fedora-release"]) == "fedora"

    def test_amazon_linux_from_metadata(self):
        assert self._detect(["pkg:rpm/amzn/glibc@2.26"], ["glibc"], meta_name="amazonlinux:2023") == "amazon"

    def test_oracle_linux_from_components(self):
        assert self._detect(["pkg:rpm/ol/glibc@2.34"], ["oraclelinux-release"]) == "oracle"

    def test_opensuse_from_components(self):
        assert self._detect(["pkg:rpm/suse/glibc@2.31"], ["opensuse-release"]) == "opensuse"

    def test_photon_from_components(self):
        assert self._detect(["pkg:rpm/photon/glibc@2.32"], ["photon-release"]) == "photon"

    def test_mariner_from_components(self):
        assert self._detect(["pkg:rpm/mariner/glibc@2.35"], ["mariner-release"]) == "mariner"

    def test_azure_linux_as_mariner(self):
        assert self._detect(["pkg:rpm/azurelinux/glibc@2.35"], ["azurelinux-release"]) == "mariner"

    def test_wolfi_from_apk_with_glibc(self):
        assert self._detect(["pkg:apk/wolfi/glibc@2.38"], ["glibc", "wolfi-baselayout"]) == "wolfi"

    def test_distroless_from_metadata(self):
        assert self._detect(["pkg:deb/debian/base-files@12"], [], meta_name="distroless/static") == "distroless"

    def test_distroless_from_few_deb_no_apt(self):
        assert self._detect(["pkg:deb/debian/base-files@12"], ["base-files"], comp_count=10) == "distroless"

    def test_windows_from_nuget(self):
        assert self._detect(["pkg:nuget/system.text@4.3.0"], ["nanoserver"]) == "windows"

    def test_scratch_detection(self):
        assert self._detect([], [], comp_count=0) == "unknown"

    def test_immutable_bottlerocket(self):
        # Deliberate trade-off from the cos-substring fix: immutable-OS
        # detection is gated behind "no mutable package DB present", so an
        # immutable OS that surfaces pkg:rpm/ (Bottlerocket, Fedora CoreOS
        # via rpm-ostree) classifies as its package family instead. False
        # positives (microcosm -> cos) were catastrophic for this corpus;
        # this false negative is harmless since no corpus Dockerfile uses
        # a host-OS base. Without a package DB the detection still works
        # (covered in tests/test_immutable_os_detection.py).
        assert self._detect(["pkg:rpm/bottlerocket/glibc@2.34"], ["bottlerocket-release"], meta_name="bottlerocket") == "rhel"
        assert self._detect([], ["bottlerocket-release"], meta_name="bottlerocket") == "bottlerocket"

    def test_unknown_empty(self):
        assert self._detect([], []) == "unknown"


# ============================================================================
# libc Type Detection Tests (E1-E2)
# ============================================================================

class TestLibcDetection:
    """Test libc type detection from SBOM."""

    def _detect(self, comp_names, purls, os_family):
        from src.patcher import _detect_libc_type
        return _detect_libc_type(comp_names, purls, os_family)

    def test_musl_direct(self):
        assert self._detect(["musl", "apk-tools"], [], "alpine") == "musl"

    def test_glibc_direct(self):
        assert self._detect(["glibc", "libc-bin"], [], "debian") == "glibc"

    def test_glibc_from_libc6(self):
        assert self._detect(["libc6", "apt"], [], "ubuntu") == "glibc"

    def test_infer_from_os_family_debian(self):
        assert self._detect([], ["pkg:deb/debian/base-files@12"], "debian") == "glibc"

    def test_infer_from_os_family_alpine(self):
        assert self._detect([], ["pkg:apk/alpine/apk-tools@2.14"], "alpine") == "musl"

    def test_infer_from_os_family_amazon(self):
        assert self._detect([], [], "amazon") == "glibc"

    def test_unknown_with_no_data(self):
        assert self._detect([], [], "unknown") == "unknown"


# ============================================================================
# Immutable OS Gating Tests
# ============================================================================

class TestImmutableOS:
    """Test that immutable OS families are properly gated."""

    def test_immutable_returns_zero_confidence(self):
        from src.patcher import InferenceResult, choose_base_image
        inference = InferenceResult(
            os_family="bottlerocket",
            is_immutable=True,
        )
        new_base, confidence = choose_base_image(inference, "bottlerocket:1.0")
        assert confidence == 0.0
        assert new_base == "bottlerocket:1.0"  # Returns original unchanged


# ============================================================================
# Scanner Fusion Tests (A3)
# ============================================================================

class TestScannerFusion:
    """Test dual-scanner fusion engine."""

    def test_confirmed_when_both_scanners_agree(self):
        from src.scanner_fusion import fuse_scan_results
        trivy = {"Results": [{"Target": "test", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-1234", "PkgName": "openssl", "InstalledVersion": "1.1.1", "FixedVersion": "1.1.1u", "Severity": "HIGH"}
        ]}]}
        grype = {"Results": [{"Target": "test", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-1234", "PkgName": "openssl", "InstalledVersion": "1.1.1", "FixedVersion": "1.1.1u", "Severity": "HIGH"}
        ]}]}
        result = fuse_scan_results(trivy, grype)
        assert result.confirmed_count == 1
        assert result.contested_count == 0
        assert result.confirmed[0].classification == "CONFIRMED"

    def test_contested_when_trivy_only(self):
        from src.scanner_fusion import fuse_scan_results
        trivy = {"Results": [{"Target": "test", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-1234", "PkgName": "openssl", "InstalledVersion": "1.1.1", "FixedVersion": "1.1.1u", "Severity": "HIGH"}
        ]}]}
        grype = {"Results": []}
        result = fuse_scan_results(trivy, grype)
        assert result.contested_count == 1
        assert result.exclusive_trivy[0].classification == "EXCLUSIVE_TRIVY"

    def test_trivy_only_mode(self):
        from src.scanner_fusion import fuse_scan_results
        trivy = {"Results": [{"Target": "test", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-1234", "PkgName": "openssl", "InstalledVersion": "1.1.1", "FixedVersion": "1.1.1u", "Severity": "HIGH"}
        ]}]}
        # No grype scan provided
        result = fuse_scan_results(trivy, None)
        assert result.confirmed_count == 1  # Defaults to confirmed in single-scanner mode

    def test_kev_boosts_priority(self):
        from src.scanner_fusion import fuse_scan_results
        trivy = {"Results": [{"Target": "test", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-1234", "PkgName": "openssl", "InstalledVersion": "1.1.1", "FixedVersion": "1.1.1u", "Severity": "MEDIUM"},
            {"VulnerabilityID": "CVE-2024-5678", "PkgName": "curl", "InstalledVersion": "7.68", "FixedVersion": "7.69", "Severity": "HIGH"},
        ]}]}
        kev = {"CVE-2024-1234"}  # Medium severity but actively exploited
        result = fuse_scan_results(trivy, None, kev_set=kev)
        # KEV vuln should have higher priority despite lower severity
        all_findings = result.all_findings
        kev_finding = [f for f in all_findings if f.vuln_id == "CVE-2024-1234"][0]
        non_kev_finding = [f for f in all_findings if f.vuln_id == "CVE-2024-5678"][0]
        assert kev_finding.composite_priority > non_kev_finding.composite_priority


# ============================================================================
# NIST LEV Computation Tests (J2)
# ============================================================================

class TestNISTLEV:
    """Test NIST CSWP 41 LEV metric computation."""

    def test_lev_zero_epss(self):
        from src.scanner_fusion import compute_lev
        assert compute_lev([0.0], window_days=30) == 0.0

    def test_lev_perfect_epss(self):
        from src.scanner_fusion import compute_lev
        assert compute_lev([1.0], window_days=30) == 1.0

    def test_lev_moderate_epss(self):
        from src.scanner_fusion import compute_lev
        # EPSS of 0.05 over 30 days
        lev = compute_lev([0.05], window_days=30)
        # Should be significantly higher than single-day EPSS
        assert lev > 0.05
        assert lev < 1.0

    def test_lev_empty_scores(self):
        from src.scanner_fusion import compute_lev
        assert compute_lev([], window_days=30) == 0.0

    def test_lev_accumulates_over_time(self):
        from src.scanner_fusion import compute_lev
        lev_7 = compute_lev([0.01], window_days=7)
        lev_30 = compute_lev([0.01], window_days=30)
        lev_90 = compute_lev([0.01], window_days=90)
        assert lev_7 < lev_30 < lev_90


# ============================================================================
# SBOM Completeness Tests (A4)
# ============================================================================

class TestSBOMCompleteness:
    """Test SBOM completeness validation."""

    def test_empty_sbom(self):
        from src.scanner_fusion import check_sbom_completeness
        result = check_sbom_completeness({})
        assert not result["complete"]
        assert "metadata" in result["missing_required"]
        assert "components" in result["missing_required"]

    def test_complete_sbom(self):
        from src.scanner_fusion import check_sbom_completeness
        sbom = {
            "metadata": {"component": {"name": "test"}},
            "components": [
                {"name": "pkg1", "version": "1.0", "purl": "pkg:deb/debian/pkg1@1.0"}
            ],
            "dependencies": [{"ref": "pkg1"}],
            "compositions": [{"aggregate": "complete"}],
        }
        result = check_sbom_completeness(sbom)
        assert result["complete"]
        assert result["score"] > 0.5

    def test_low_purl_coverage_warning(self):
        from src.scanner_fusion import check_sbom_completeness
        sbom = {
            "metadata": {"component": {"name": "test"}},
            "components": [
                {"name": "pkg1", "version": "1.0"},
                {"name": "pkg2", "version": "2.0"},
                {"name": "pkg3", "version": "3.0"},
            ],
        }
        result = check_sbom_completeness(sbom)
        assert result["purl_coverage_pct"] == 0.0


# ============================================================================
# VEX Generation Tests (I2)
# ============================================================================

class TestVEXGeneration:
    """Test VEX document generation."""

    def test_openvex_structure(self):
        from src.vex_generator import generate_openvex
        statements = [
            {
                "vuln_id": "CVE-2024-1234",
                "status": "fixed",
                "justification": "vulnerability_not_present",
                "action_statement": "Base image upgraded",
            }
        ]
        doc = generate_openvex("pkg:docker/test@sha256:abc", "test-image", statements)
        assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert len(doc["statements"]) == 1
        assert doc["statements"][0]["status"] == "fixed"

    def test_vex_statements_from_diff(self):
        from src.vex_generator import build_vex_statements_from_diff
        diff = {
            "resolved": [
                {"id": "CVE-2024-1", "package": "openssl", "version": "1.1.1", "severity": "HIGH", "fix_version": "1.1.1u"}
            ],
            "remaining": [
                {"id": "CVE-2024-2", "package": "curl", "version": "7.68", "severity": "MEDIUM", "fix_version": "7.69"}
            ],
            "new": [],
        }
        stmts = build_vex_statements_from_diff(diff)
        assert len(stmts) == 2
        assert stmts[0]["status"] == "fixed"
        assert stmts[1]["status"] == "affected"


# ============================================================================
# Acceptance Criteria Edge Cases
# ============================================================================

class TestAcceptanceCriteria:
    """Test acceptance criteria edge cases."""

    def test_strict_rejects_equal_total(self):
        from src.comparer import check_acceptance_criteria
        before = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "Severity": "HIGH"},
        ]}]}
        after = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-2", "Severity": "HIGH"},
        ]}]}
        accepted, reasons = check_acceptance_criteria(before, after, "strict")
        assert not accepted  # Same count, should reject

    def test_strict_accepts_reduced_total(self):
        from src.comparer import check_acceptance_criteria
        before = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-2", "Severity": "MEDIUM"},
        ]}]}
        after = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-3", "Severity": "LOW"},
        ]}]}
        accepted, reasons = check_acceptance_criteria(before, after, "strict")
        assert accepted

    def test_permissive_requires_zero_critical(self):
        from src.comparer import check_acceptance_criteria
        before = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL"},
            {"VulnerabilityID": "CVE-2", "Severity": "HIGH"},
        ]}]}
        after = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-3", "Severity": "CRITICAL"},
        ]}]}
        accepted, reasons = check_acceptance_criteria(before, after, "permissive")
        assert not accepted  # Critical still present


# ============================================================================
# ARG Resolution Tests (G3)
# ============================================================================

class TestARGResolution:
    """Test Dockerfile ARG resolution in FROM directives."""

    def test_resolve_simple_arg(self):
        from src.patcher import _resolve_arg_in_from
        dockerfile = 'ARG BASE_IMAGE=python:3.12-slim\nFROM $BASE_IMAGE'
        result = _resolve_arg_in_from("$BASE_IMAGE", dockerfile)
        assert result == "python:3.12-slim"

    def test_resolve_quoted_arg(self):
        from src.patcher import _resolve_arg_in_from
        dockerfile = 'ARG BASE_IMAGE="node:22-alpine"\nFROM $BASE_IMAGE'
        result = _resolve_arg_in_from("$BASE_IMAGE", dockerfile)
        assert result == "node:22-alpine"

    def test_unresolvable_arg(self):
        from src.patcher import _resolve_arg_in_from
        dockerfile = 'FROM $UNKNOWN_VAR'
        result = _resolve_arg_in_from("$UNKNOWN_VAR", dockerfile)
        assert result is None

    def test_resolve_braced_syntax(self):
        from src.patcher import _resolve_arg_in_from
        dockerfile = 'ARG IMG=golang:1.23\nFROM ${IMG}'
        result = _resolve_arg_in_from("${IMG}", dockerfile)
        assert result == "golang:1.23"


# ============================================================================
# Composite Priority Tests
# ============================================================================

class TestCompositePriority:
    """Test composite vulnerability priority scoring."""

    def test_kev_always_highest(self):
        from src.scanner_fusion import compute_composite_priority
        priority = compute_composite_priority("MEDIUM", kev_flag=True)
        assert priority > 0.4  # KEV makes even MEDIUM severity high priority

    def test_high_epss_boosts(self):
        from src.scanner_fusion import compute_composite_priority
        low_epss = compute_composite_priority("HIGH", epss_score=0.01)
        high_epss = compute_composite_priority("HIGH", epss_score=0.9)
        assert high_epss > low_epss

    def test_severity_weight_matters(self):
        from src.scanner_fusion import compute_composite_priority
        critical = compute_composite_priority("CRITICAL", epss_score=0.5)
        low = compute_composite_priority("LOW", epss_score=0.5)
        assert critical > low


# ============================================================================
# Builder Context Validation Tests (K1)
# ============================================================================

class TestBuilderValidation:
    """Test build context validation."""

    def test_nonexistent_dockerfile(self, tmp_path):
        from src.builder import validate_build_context
        valid, warnings = validate_build_context(str(tmp_path / "nonexistent"))
        assert not valid

    def test_valid_context(self, tmp_path):
        from src.builder import validate_build_context
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine:3.21\n")
        valid, warnings = validate_build_context(str(df))
        assert valid

    def test_warns_about_env_file(self, tmp_path):
        from src.builder import validate_build_context
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine:3.21\n")
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=value\n")
        valid, warnings = validate_build_context(str(df))
        assert valid
        assert any(".env" in w for w in warnings)


# ============================================================================
# Version Resolver Tests (F1-F4)
# ============================================================================

class TestTTLCache:
    """Test the TTL cache implementation."""

    def test_set_and_get(self):
        from src.version_resolver import TTLCache
        cache = TTLCache(default_ttl=60)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_missing_key_returns_none(self):
        from src.version_resolver import TTLCache
        cache = TTLCache(default_ttl=60)
        assert cache.get("nonexistent") is None

    def test_expired_entry_returns_none(self):
        from src.version_resolver import TTLCache
        cache = TTLCache(default_ttl=60)
        cache.set("key1", "value1", ttl=0)  # Already expired
        import time
        time.sleep(0.01)
        assert cache.get("key1") is None

    def test_invalidate(self):
        from src.version_resolver import TTLCache
        cache = TTLCache(default_ttl=60)
        cache.set("key1", "value1")
        cache.invalidate("key1")
        assert cache.get("key1") is None

    def test_clear(self):
        from src.version_resolver import TTLCache
        cache = TTLCache(default_ttl=60)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        assert cache.size == 0

    def test_size(self):
        from src.version_resolver import TTLCache
        cache = TTLCache(default_ttl=60)
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.size == 2


class TestProductSlugMap:
    """Test that product slugs are configured correctly."""

    def test_known_languages_have_slugs(self):
        from src.version_resolver import _PRODUCT_SLUG_MAP
        for lang in ["python", "node", "golang", "ruby", "php", "openjdk"]:
            assert lang in _PRODUCT_SLUG_MAP

    def test_unknown_language_returns_none(self):
        from src.version_resolver import _PRODUCT_SLUG_MAP
        assert "brainfuck" not in _PRODUCT_SLUG_MAP


class TestFallbackEOL:
    """The table AutoPatch falls back on when endoflife.date cannot be
    reached, which on an air-gapped runner is every single run."""

    @staticmethod
    def _as_tuple(version):
        return tuple(int(part) for part in version.split("."))

    @pytest.mark.parametrize("lang,eol_version", [
        ("python", "3.8"),
        ("node", "16"),
    ])
    def test_fallback_names_a_live_successor(self, lang, eol_version):
        """Naming the expected successor made this a restatement of the
        release calendar, so a routine table refresh broke a test whose
        real subject is the table's shape. What has to hold is that a
        dead release maps forward onto something the same table does not
        also call dead, otherwise the upgrade lands on another EOL
        runtime and the run still reports success."""
        from src.version_resolver import _FALLBACK_EOL_UPGRADES
        table = _FALLBACK_EOL_UPGRADES[lang]
        target = table[eol_version]
        assert target not in table, (
            f"{lang} {eol_version} upgrades to {target}, which the same "
            f"table lists as EOL")
        assert self._as_tuple(target) > self._as_tuple(eol_version)

    def test_every_row_points_forward_and_out_of_the_table(self):
        """Same property across the whole table. A row that maps a
        version onto itself, or backwards, or onto another EOL entry, is
        a silent downgrade or a no-op that presents as a successful
        patch."""
        from src.version_resolver import _FALLBACK_EOL_UPGRADES
        for lang, table in _FALLBACK_EOL_UPGRADES.items():
            for eol_version, target in table.items():
                assert target not in table, (lang, eol_version, target)
                assert (self._as_tuple(target)
                        > self._as_tuple(eol_version)), (
                    lang, eol_version, target)

    def test_the_yaml_file_is_the_table_that_gets_loaded(self):
        """The hardcoded backstop in version_resolver.py exists only for
        an install shipped without the YAML file. If the loader quietly
        fell through to it, an operator would edit eol_fallback.yaml,
        see no change in behaviour, and get no warning about it."""
        import yaml
        from src.version_resolver import _FALLBACK_EOL_UPGRADES
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "src", "eol_fallback.yaml")
        with open(path, "r", encoding="utf-8") as f:
            shipped = yaml.safe_load(f)
        for lang, entries in shipped.items():
            assert _FALLBACK_EOL_UPGRADES[str(lang)] == {
                str(k): str(v) for k, v in entries.items()}


class TestImageRefParsing:
    """Test Docker image reference parsing."""

    def test_simple_image(self):
        from src.version_resolver import _parse_image_ref
        repo, tag = _parse_image_ref("python:3.12-slim")
        assert repo == "library/python"
        assert tag == "3.12-slim"

    def test_official_image_no_tag(self):
        from src.version_resolver import _parse_image_ref
        repo, tag = _parse_image_ref("nginx")
        assert repo == "library/nginx"
        assert tag == "latest"

    def test_org_image(self):
        from src.version_resolver import _parse_image_ref
        repo, tag = _parse_image_ref("myorg/myapp:1.0")
        assert repo == "myorg/myapp"
        assert tag == "1.0"


# ============================================================================
# Dependency Graph Tests (B1-B2)
# ============================================================================

class TestDependencyGraph:
    """Test dependency graph reachability analysis."""

    def _make_sbom(self, components, dependencies, root_ref=None):
        sbom = {"components": components, "dependencies": dependencies}
        if root_ref:
            sbom["metadata"] = {"component": {"bom-ref": root_ref}}
        return sbom

    def test_empty_sbom(self):
        from src.dep_graph import build_dependency_graph
        result = build_dependency_graph({})
        assert result.total_components == 0

    def test_linear_dependency_chain(self):
        from src.dep_graph import build_dependency_graph
        comps = [
            {"bom-ref": "root", "name": "myapp", "version": "1.0"},
            {"bom-ref": "dep1", "name": "flask", "version": "3.0"},
            {"bom-ref": "dep2", "name": "werkzeug", "version": "3.0"},
        ]
        deps = [
            {"ref": "root", "dependsOn": ["dep1"]},
            {"ref": "dep1", "dependsOn": ["dep2"]},
        ]
        sbom = self._make_sbom(comps, deps, root_ref="root")
        result = build_dependency_graph(sbom)

        assert result.total_components == 3
        assert result.reachable_count == 3
        assert result.unreachable_count == 0
        assert result.max_depth == 2
        assert result.nodes["root"].reachability == "ROOT"
        assert result.nodes["dep1"].reachability == "DIRECT"
        assert result.nodes["dep2"].reachability == "TRANSITIVE"

    def test_unreachable_component(self):
        from src.dep_graph import build_dependency_graph
        comps = [
            {"bom-ref": "root", "name": "myapp", "version": "1.0"},
            {"bom-ref": "dep1", "name": "flask", "version": "3.0"},
            {"bom-ref": "orphan", "name": "unused-lib", "version": "1.0"},
        ]
        deps = [
            {"ref": "root", "dependsOn": ["dep1"]},
        ]
        sbom = self._make_sbom(comps, deps, root_ref="root")
        result = build_dependency_graph(sbom)

        assert result.unreachable_count == 1
        assert result.nodes["orphan"].reachability == "UNREACHABLE"

    def test_reachability_weight(self):
        from src.dep_graph import compute_reachability_weight
        assert compute_reachability_weight(0) == 1.0
        assert compute_reachability_weight(1) == 1.0
        assert compute_reachability_weight(2) == 0.8
        assert compute_reachability_weight(5) == 0.4
        assert compute_reachability_weight(-1) == 0.1

    def test_vulnerability_reachability_lookup(self):
        from src.dep_graph import build_dependency_graph, get_vulnerability_reachability
        comps = [
            {"bom-ref": "root", "name": "myapp", "version": "1.0"},
            {"bom-ref": "dep1", "name": "flask", "version": "3.0"},
        ]
        deps = [{"ref": "root", "dependsOn": ["dep1"]}]
        sbom = self._make_sbom(comps, deps, root_ref="root")
        graph = build_dependency_graph(sbom)

        reach, depth = get_vulnerability_reachability(graph, "flask")
        assert reach == "DIRECT"
        assert depth == 1

        reach, depth = get_vulnerability_reachability(graph, "unknown-pkg")
        assert reach == "UNREACHABLE"
        assert depth == -1


class TestEmbeddedVulnerabilities:
    """Test embedded SBOM vulnerability extraction."""

    def test_extract_cyclonedx_vulns(self):
        from src.dep_graph import extract_embedded_vulnerabilities
        sbom = {
            "vulnerabilities": [
                {
                    "id": "CVE-2024-1234",
                    "source": {"name": "NVD"},
                    "ratings": [{"severity": "HIGH"}],
                    "affects": [{"ref": "comp1"}],
                    "cwes": [79],
                },
                {
                    "id": "CVE-2024-5678",
                    "source": {"name": "GitHub"},
                    "ratings": [{"severity": "CRITICAL"}],
                    "affects": [],
                },
            ]
        }
        vulns = extract_embedded_vulnerabilities(sbom)
        assert len(vulns) == 2
        assert vulns[0].vuln_id == "CVE-2024-1234"
        assert vulns[0].severity == "HIGH"
        assert vulns[1].severity == "CRITICAL"

    def test_empty_sbom_returns_empty(self):
        from src.dep_graph import extract_embedded_vulnerabilities
        assert extract_embedded_vulnerabilities({}) == []
        assert extract_embedded_vulnerabilities({"vulnerabilities": []}) == []


class TestMergeEmbeddedWithScan:
    """Test merging SBOM vulnerabilities with scanner findings."""

    def test_merge_adds_sbom_only(self):
        from src.dep_graph import extract_embedded_vulnerabilities, merge_embedded_with_scan
        scan_cves = {
            "CVE-2024-1111": {"id": "CVE-2024-1111", "severity": "HIGH"},
        }
        embedded = [
            type("EV", (), {
                "vuln_id": "CVE-2024-9999",
                "source_name": "NVD",
                "severity": "MEDIUM",
                "description": "test",
                "affected_refs": [],
                "affected_versions": [],
                "recommendation": "",
                "cwes": [],
            })()
        ]
        merged = merge_embedded_with_scan(scan_cves, embedded)
        assert "CVE-2024-9999" in merged
        assert merged["CVE-2024-9999"]["classification"] == "SBOM_ONLY"


# ============================================================================
# VEX Suppression Tests (I3)
# ============================================================================

class TestVEXSuppression:
    """Test VEX-based scan result suppression."""

    def test_extract_openvex_suppressed(self):
        from src.vex_generator import extract_suppressed_cves
        vex = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {"vulnerability": {"name": "CVE-2024-1111"}, "status": "fixed"},
                {"vulnerability": {"name": "CVE-2024-2222"}, "status": "not_affected"},
                {"vulnerability": {"name": "CVE-2024-3333"}, "status": "affected"},
            ]
        }
        suppressed = extract_suppressed_cves(vex)
        assert "CVE-2024-1111" in suppressed
        assert "CVE-2024-2222" in suppressed
        assert "CVE-2024-3333" not in suppressed

    def test_extract_cyclonedx_vex_suppressed(self):
        from src.vex_generator import extract_suppressed_cves
        vex = {
            "vulnerabilities": [
                {"id": "CVE-2024-1111", "analysis": {"state": "resolved"}},
                {"id": "CVE-2024-2222", "analysis": {"state": "false_positive"}},
                {"id": "CVE-2024-3333", "analysis": {"state": "exploitable"}},
            ]
        }
        suppressed = extract_suppressed_cves(vex)
        assert "CVE-2024-1111" in suppressed
        assert "CVE-2024-2222" in suppressed
        assert "CVE-2024-3333" not in suppressed

    def test_apply_vex_suppression(self):
        from src.vex_generator import apply_vex_suppression
        scan = {
            "Results": [
                {
                    "Type": "debian",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-1111", "PkgName": "openssl"},
                        {"VulnerabilityID": "CVE-2024-2222", "PkgName": "curl"},
                        {"VulnerabilityID": "CVE-2024-3333", "PkgName": "zlib"},
                    ]
                }
            ]
        }
        suppressed = {"CVE-2024-1111", "CVE-2024-2222"}
        filtered = apply_vex_suppression(scan, suppressed_cves=suppressed)
        remaining = filtered["Results"][0]["Vulnerabilities"]
        assert len(remaining) == 1
        assert remaining[0]["VulnerabilityID"] == "CVE-2024-3333"

    def test_empty_vex_no_change(self):
        from src.vex_generator import apply_vex_suppression
        scan = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1111"}]}]}
        filtered = apply_vex_suppression(scan, suppressed_cves=set())
        assert len(filtered["Results"][0]["Vulnerabilities"]) == 1


# ============================================================================
# In-Place Patcher Tests (J1)
# ============================================================================

class TestInPlacePatcher:
    """Test in-place patching mode."""

    def test_extract_os_vulnerable_packages(self):
        from src.inplace_patcher import extract_os_vulnerable_packages
        scan = {
            "Results": [
                {
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.11",
                            "FixedVersion": "3.0.13",
                            "Severity": "HIGH",
                            "VulnerabilityID": "CVE-2024-1234",
                        },
                        {
                            "PkgName": "curl",
                            "InstalledVersion": "7.88",
                            "FixedVersion": "",  # No fix
                            "Severity": "MEDIUM",
                            "VulnerabilityID": "CVE-2024-5678",
                        },
                    ]
                }
            ]
        }
        packages = extract_os_vulnerable_packages(scan, "debian")
        assert len(packages) == 1
        assert packages[0]["name"] == "openssl"

    def test_generate_os_patch_commands_debian(self):
        from src.inplace_patcher import generate_os_patch_commands
        packages = [
            {"name": "openssl", "fix_version": "3.0.13"},
            {"name": "curl", "fix_version": "7.90"},
        ]
        commands, warnings = generate_os_patch_commands(packages, "debian")
        assert any("apt-get update" in c for c in commands)
        assert any("openssl" in c for c in commands)

    def test_generate_os_patch_commands_alpine(self):
        from src.inplace_patcher import generate_os_patch_commands
        packages = [{"name": "musl", "fix_version": "1.2.5"}]
        commands, warnings = generate_os_patch_commands(packages, "alpine")
        assert any("apk" in c for c in commands)

    def test_generate_os_patch_unknown_os(self):
        from src.inplace_patcher import generate_os_patch_commands
        commands, warnings = generate_os_patch_commands([], "windows")
        assert len(commands) == 0
        assert len(warnings) > 0

    def test_generate_inplace_patch_creates_dockerfile(self):
        from src.inplace_patcher import generate_inplace_patch
        scan = {
            "Results": [
                {
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.11",
                            "FixedVersion": "3.0.13",
                            "Severity": "HIGH",
                            "VulnerabilityID": "CVE-2024-1234",
                        },
                    ]
                }
            ]
        }
        result = generate_inplace_patch(
            original_image="debian:bookworm",
            scan_result=scan,
            os_family="debian",
        )
        assert "FROM debian:bookworm" in result.patch_dockerfile
        assert "apt-get" in result.patch_dockerfile

    def test_save_inplace_patch(self, tmp_path):
        from src.inplace_patcher import InPlacePatchResult, save_inplace_patch
        result = InPlacePatchResult(
            patch_dockerfile="FROM test:latest\nRUN echo hello\n"
        )
        path = save_inplace_patch(result, str(tmp_path))
        assert path is not None
        assert os.path.exists(path)


# ============================================================================
# Graph Summary Tests
# ============================================================================

class TestGraphSummary:
    """Test dependency graph summary generation."""

    def test_summarize_graph(self):
        from src.dep_graph import build_dependency_graph, summarize_graph
        comps = [
            {"bom-ref": "root", "name": "app", "version": "1.0"},
            {"bom-ref": "d1", "name": "dep1", "version": "2.0"},
        ]
        deps = [{"ref": "root", "dependsOn": ["d1"]}]
        sbom = {"components": comps, "dependencies": deps,
                "metadata": {"component": {"bom-ref": "root"}}}
        graph = build_dependency_graph(sbom)
        summary = summarize_graph(graph)
        assert summary["total_components"] == 2
        assert summary["reachable"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
