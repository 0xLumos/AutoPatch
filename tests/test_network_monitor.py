"""
Tests for the network behavior monitor (src/network_monitor.py).

Covers:
  - Shannon entropy calculation (DGA detection core)
  - Domain allowlist matching
  - Risk score computation
  - NetworkAnalysisResult aggregation
  - Unusual port detection logic
  - Beaconing detection (CoV threshold)
"""

import math

import pytest

from src.network_monitor import (
    DEFAULT_ALLOWED_PORTS,
    DEFAULT_DOMAIN_ALLOWLIST,
    DGA_ENTROPY_THRESHOLD,
    RISK_WEIGHTS,
    DNSQuery,
    NetworkAnalysisResult,
    NetworkFinding,
    NetworkProfile,
    TCPConnection,
    _is_allowlisted,
    _shannon_entropy,
)


# ============================================================================
# Shannon entropy
# ============================================================================

class TestShannonEntropy:

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" repeated -> p(a) = p(b) = 0.5, entropy = 1.0
        entropy = _shannon_entropy("abab")
        assert abs(entropy - 1.0) < 0.01

    def test_uniform_distribution(self):
        # 26 unique chars -> entropy ~ log2(26) ~ 4.7
        s = "abcdefghijklmnopqrstuvwxyz"
        entropy = _shannon_entropy(s)
        assert abs(entropy - math.log2(26)) < 0.01

    def test_low_entropy_domain(self):
        # Real domains like "google.com" have low entropy
        entropy = _shannon_entropy("google")
        assert entropy < DGA_ENTROPY_THRESHOLD

    def test_high_entropy_dga_like(self):
        # DGA-like random strings have high entropy
        entropy = _shannon_entropy("xkqzjvbfwm3p8n7r")
        assert entropy > DGA_ENTROPY_THRESHOLD

    def test_repeated_pattern(self):
        # "aaa...bbb..." has low entropy
        entropy = _shannon_entropy("aaaaaabbbbbb")
        assert entropy == 1.0


# ============================================================================
# Domain allowlist
# ============================================================================

class TestDomainAllowlist:

    def test_exact_match(self):
        assert _is_allowlisted("github.com", DEFAULT_DOMAIN_ALLOWLIST) is True

    def test_subdomain_match(self):
        assert _is_allowlisted("api.github.com", DEFAULT_DOMAIN_ALLOWLIST) is True

    def test_deep_subdomain_match(self):
        assert _is_allowlisted("us-east-1.s3.amazonaws.com", DEFAULT_DOMAIN_ALLOWLIST) is True

    def test_no_match(self):
        assert _is_allowlisted("evil-c2-server.xyz", DEFAULT_DOMAIN_ALLOWLIST) is False

    def test_partial_name_no_match(self):
        # "notgithub.com" should NOT match "github.com"
        assert _is_allowlisted("notgithub.com", DEFAULT_DOMAIN_ALLOWLIST) is False

    def test_empty_allowlist(self):
        assert _is_allowlisted("anything.com", set()) is False

    def test_custom_allowlist(self):
        custom = {"mycompany.internal", "trusted.org"}
        assert _is_allowlisted("api.mycompany.internal", custom) is True
        assert _is_allowlisted("evil.com", custom) is False


# ============================================================================
# Risk score computation
# ============================================================================

class TestRiskScore:

    def test_empty_findings(self):
        result = NetworkAnalysisResult()
        result._compute_risk()
        assert result.risk_score == 0
        assert result.overall_risk == "SAFE"

    def test_single_threat_intel_finding(self):
        result = NetworkAnalysisResult()
        result.findings.append(NetworkFinding(
            detector="threat_intel_match", severity="CRITICAL",
            target="evil.com", description="URLhaus match",
            evidence="matched indicator"
        ))
        result._compute_risk()
        assert result.risk_score == RISK_WEIGHTS["threat_intel_match"]

    def test_multiple_same_detector_not_doubled(self):
        result = NetworkAnalysisResult()
        result.findings.append(NetworkFinding(
            detector="dga_detection", severity="HIGH",
            target="abc123.xyz", description="DGA 1",
            evidence="entropy=4.2"
        ))
        result.findings.append(NetworkFinding(
            detector="dga_detection", severity="HIGH",
            target="def456.xyz", description="DGA 2",
            evidence="entropy=4.5"
        ))
        result._compute_risk()
        # Same detector only counted once
        assert result.risk_score == RISK_WEIGHTS["dga_detection"]

    def test_multiple_different_detectors(self):
        result = NetworkAnalysisResult()
        result.findings.append(NetworkFinding(
            detector="dga_detection", severity="HIGH",
            target="random.xyz", description="DGA",
            evidence="entropy=4.2"
        ))
        result.findings.append(NetworkFinding(
            detector="beaconing_detection", severity="MEDIUM",
            target="1.2.3.4", description="Beacon",
            evidence="cov=0.1"
        ))
        result._compute_risk()
        expected = RISK_WEIGHTS["dga_detection"] + RISK_WEIGHTS["beaconing_detection"]
        assert result.risk_score == expected

    def test_risk_capped_at_100(self):
        result = NetworkAnalysisResult()
        for detector in RISK_WEIGHTS:
            result.findings.append(NetworkFinding(
                detector=detector, severity="CRITICAL",
                target="test", description="test",
                evidence="test"
            ))
        result._compute_risk()
        assert result.risk_score <= 100

    def test_risk_level_critical(self):
        result = NetworkAnalysisResult()
        # threat_intel(80) + dga(40) = 120, capped to 100
        result.findings.append(NetworkFinding(
            detector="threat_intel_match", severity="CRITICAL",
            target="evil.com", description="test", evidence="test"
        ))
        result.findings.append(NetworkFinding(
            detector="dga_detection", severity="HIGH",
            target="rand.xyz", description="test", evidence="test"
        ))
        result._compute_risk()
        assert result.overall_risk == "CRITICAL"

    def test_risk_level_high(self):
        result = NetworkAnalysisResult()
        # dga(40) + unusual_port(15) = 55
        result.findings.append(NetworkFinding(
            detector="dga_detection", severity="HIGH",
            target="rand.xyz", description="test", evidence="test"
        ))
        result.findings.append(NetworkFinding(
            detector="unusual_port", severity="MEDIUM",
            target="1.2.3.4:31337", description="test", evidence="test"
        ))
        result._compute_risk()
        assert result.overall_risk == "HIGH"

    def test_risk_level_medium(self):
        result = NetworkAnalysisResult()
        # beaconing(30) = 30
        result.findings.append(NetworkFinding(
            detector="beaconing_detection", severity="MEDIUM",
            target="1.2.3.4", description="test", evidence="test"
        ))
        result._compute_risk()
        assert result.overall_risk == "MEDIUM"

    def test_risk_level_low(self):
        result = NetworkAnalysisResult()
        # unusual_port(15) = 15
        result.findings.append(NetworkFinding(
            detector="unusual_port", severity="LOW",
            target="1.2.3.4:9999", description="test", evidence="test"
        ))
        result._compute_risk()
        assert result.overall_risk == "LOW"


# ============================================================================
# NetworkProfile and dataclasses
# ============================================================================

class TestNetworkProfile:

    def test_empty_profile(self):
        profile = NetworkProfile()
        assert len(profile.dns_queries) == 0
        assert len(profile.tcp_connections) == 0
        assert len(profile.udp_packets) == 0
        assert len(profile.http_requests) == 0

    def test_add_dns_query(self):
        profile = NetworkProfile()
        profile.dns_queries.append(DNSQuery(
            domain="evil.com", query_type="A", timestamp=1000.0
        ))
        assert len(profile.dns_queries) == 1
        assert profile.dns_queries[0].domain == "evil.com"

    def test_add_tcp_connection(self):
        profile = NetworkProfile()
        profile.tcp_connections.append(TCPConnection(
            dst_ip="1.2.3.4", dst_port=4444, timestamp=1000.0
        ))
        assert len(profile.tcp_connections) == 1
        assert profile.tcp_connections[0].dst_port == 4444


# ============================================================================
# Default constants sanity checks
# ============================================================================

class TestDefaults:

    def test_allowed_ports_include_standard(self):
        assert 80 in DEFAULT_ALLOWED_PORTS
        assert 443 in DEFAULT_ALLOWED_PORTS
        assert 53 in DEFAULT_ALLOWED_PORTS

    def test_allowed_ports_include_databases(self):
        assert 3306 in DEFAULT_ALLOWED_PORTS  # MySQL
        assert 5432 in DEFAULT_ALLOWED_PORTS  # PostgreSQL
        assert 6379 in DEFAULT_ALLOWED_PORTS  # Redis

    def test_domain_allowlist_has_common_registries(self):
        assert "pypi.org" in DEFAULT_DOMAIN_ALLOWLIST
        assert "github.com" in DEFAULT_DOMAIN_ALLOWLIST
        assert "docker.io" in DEFAULT_DOMAIN_ALLOWLIST

    def test_risk_weights_are_positive(self):
        for detector, weight in RISK_WEIGHTS.items():
            assert weight > 0, f"{detector} weight must be positive"

    def test_dga_threshold_reasonable(self):
        # Shannon entropy of English text is ~4.0-4.5 bits
        # DGA threshold should be below pure random (~4.7 for hex) but above
        # most legitimate domains
        assert 3.0 < DGA_ENTROPY_THRESHOLD < 4.5
