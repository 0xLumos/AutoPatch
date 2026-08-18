"""
Tests for the threat intelligence feed manager (src/threat_intel.py).

Covers:
  - URLhaus CSV parsing
  - ThreatFox JSON parsing
  - IOC lookup (domain, IP, URL match and miss)
  - Cache freshness checks
  - Domain extraction from URLs
"""

import json
import os
import tempfile
import time

import pytest

from src.threat_intel import (
    ThreatIntelDB,
    ThreatMatch,
    _extract_domain_from_url,
    _is_cache_fresh,
    _parse_threatfox_json,
    _parse_urlhaus_csv,
    check_ioc,
    load_feeds,
)


# ============================================================================
# Domain extraction
# ============================================================================

class TestDomainExtraction:

    def test_http_url(self):
        assert _extract_domain_from_url("http://evil.com/malware.exe") == "evil.com"

    def test_https_url(self):
        assert _extract_domain_from_url("https://bad.example.org/path?q=1") == "bad.example.org"

    def test_url_with_port(self):
        assert _extract_domain_from_url("http://evil.com:8080/shell") == "evil.com"

    def test_no_protocol(self):
        assert _extract_domain_from_url("evil.com/path") == "evil.com"

    def test_empty_string(self):
        assert _extract_domain_from_url("") is None

    def test_case_normalization(self):
        assert _extract_domain_from_url("http://EVIL.COM/path") == "evil.com"


# ============================================================================
# Cache freshness
# ============================================================================

class TestCacheFreshness:

    def test_missing_file_not_fresh(self, tmp_path):
        assert _is_cache_fresh(str(tmp_path / "nonexistent.csv")) is False

    def test_fresh_file(self, tmp_path):
        f = tmp_path / "feed.csv"
        f.write_text("data")
        assert _is_cache_fresh(str(f), max_age=3600) is True

    def test_stale_file(self, tmp_path):
        f = tmp_path / "feed.csv"
        f.write_text("data")
        # Set mtime to 2 hours ago
        old_time = time.time() - 7200
        os.utime(str(f), (old_time, old_time))
        assert _is_cache_fresh(str(f), max_age=3600) is False


# ============================================================================
# URLhaus CSV parsing
# ============================================================================

SAMPLE_URLHAUS_CSV = """# URLhaus CSV feed
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1234","2026-01-01","http://evil.example.com/malware.bin","online","2026-01-01","malware_download","emotet","https://urlhaus.abuse.ch/url/1234/","reporter1"
"1235","2026-01-02","http://bad.test.org:8080/dropper.exe","offline","2026-01-02","malware_download","cobalt_strike","https://urlhaus.abuse.ch/url/1235/","reporter2"
"""


class TestUrlhausParsing:

    def test_parse_csv_entries(self, tmp_path):
        csv_file = tmp_path / "urlhaus_recent.csv"
        csv_file.write_text(SAMPLE_URLHAUS_CSV)
        db = ThreatIntelDB()
        _parse_urlhaus_csv(str(csv_file), db)
        assert db.urlhaus_entries == 2
        assert "evil.example.com" in db.domains
        assert "bad.test.org" in db.domains

    def test_url_indexed(self, tmp_path):
        csv_file = tmp_path / "urlhaus_recent.csv"
        csv_file.write_text(SAMPLE_URLHAUS_CSV)
        db = ThreatIntelDB()
        _parse_urlhaus_csv(str(csv_file), db)
        assert "http://evil.example.com/malware.bin" in db.urls

    def test_skips_comments(self, tmp_path):
        csv_file = tmp_path / "urlhaus_recent.csv"
        csv_file.write_text("# just a comment\n# another comment\n")
        db = ThreatIntelDB()
        _parse_urlhaus_csv(str(csv_file), db)
        assert db.urlhaus_entries == 0

    def test_missing_file(self):
        db = ThreatIntelDB()
        _parse_urlhaus_csv("/nonexistent/path.csv", db)
        assert db.urlhaus_entries == 0


# ============================================================================
# ThreatFox JSON parsing
# ============================================================================

SAMPLE_THREATFOX_JSON = {
    "query_status": "ok",
    "data": [
        {
            "ioc": "evil-c2.example.com",
            "ioc_type": "domain",
            "malware_printable": "Emotet",
            "threat_type": "botnet_cc",
            "confidence_level": 90,
            "reference": "https://threatfox.abuse.ch/ioc/12345/",
        },
        {
            "ioc": "192.168.1.100:4444",
            "ioc_type": "ip:port",
            "malware_printable": "CobaltStrike",
            "threat_type": "payload_delivery",
            "confidence_level": 80,
            "reference": "",
        },
        {
            "ioc": "http://dropper.test.org/payload",
            "ioc_type": "url",
            "malware_printable": "QakBot",
            "threat_type": "payload_delivery",
            "confidence_level": 40,
            "reference": "",
        },
    ],
}


class TestThreatfoxParsing:

    def test_parse_domain_ioc(self, tmp_path):
        json_file = tmp_path / "threatfox_iocs.json"
        json_file.write_text(json.dumps(SAMPLE_THREATFOX_JSON))
        db = ThreatIntelDB()
        _parse_threatfox_json(str(json_file), db)
        assert "evil-c2.example.com" in db.domains

    def test_parse_ip_ioc(self, tmp_path):
        json_file = tmp_path / "threatfox_iocs.json"
        json_file.write_text(json.dumps(SAMPLE_THREATFOX_JSON))
        db = ThreatIntelDB()
        _parse_threatfox_json(str(json_file), db)
        assert "192.168.1.100" in db.ips

    def test_parse_url_ioc(self, tmp_path):
        json_file = tmp_path / "threatfox_iocs.json"
        json_file.write_text(json.dumps(SAMPLE_THREATFOX_JSON))
        db = ThreatIntelDB()
        _parse_threatfox_json(str(json_file), db)
        assert "http://dropper.test.org/payload" in db.urls

    def test_confidence_mapping(self, tmp_path):
        json_file = tmp_path / "threatfox_iocs.json"
        json_file.write_text(json.dumps(SAMPLE_THREATFOX_JSON))
        db = ThreatIntelDB()
        _parse_threatfox_json(str(json_file), db)
        # 90 confidence -> high
        match = db.domains["evil-c2.example.com"][0]
        assert match.confidence == "high"

    def test_entry_count(self, tmp_path):
        json_file = tmp_path / "threatfox_iocs.json"
        json_file.write_text(json.dumps(SAMPLE_THREATFOX_JSON))
        db = ThreatIntelDB()
        _parse_threatfox_json(str(json_file), db)
        assert db.threatfox_entries == 3

    def test_missing_file(self):
        db = ThreatIntelDB()
        _parse_threatfox_json("/nonexistent/path.json", db)
        assert db.threatfox_entries == 0

    def test_malformed_json(self, tmp_path):
        json_file = tmp_path / "threatfox_iocs.json"
        json_file.write_text("{invalid json")
        db = ThreatIntelDB()
        _parse_threatfox_json(str(json_file), db)
        assert db.threatfox_entries == 0


# ============================================================================
# IOC lookup
# ============================================================================

class TestIOCLookup:

    def _build_db(self, tmp_path):
        csv_file = tmp_path / "urlhaus_recent.csv"
        csv_file.write_text(SAMPLE_URLHAUS_CSV)
        json_file = tmp_path / "threatfox_iocs.json"
        json_file.write_text(json.dumps(SAMPLE_THREATFOX_JSON))
        db = ThreatIntelDB()
        _parse_urlhaus_csv(str(csv_file), db)
        _parse_threatfox_json(str(json_file), db)
        return db

    def test_domain_match(self, tmp_path):
        db = self._build_db(tmp_path)
        result = check_ioc(db, "evil-c2.example.com")
        assert result is not None
        assert result.source == "threatfox"
        assert result.indicator_type == "domain"

    def test_ip_match(self, tmp_path):
        db = self._build_db(tmp_path)
        result = check_ioc(db, "192.168.1.100")
        assert result is not None
        assert result.indicator_type == "ip"

    def test_url_match(self, tmp_path):
        db = self._build_db(tmp_path)
        result = check_ioc(db, "http://evil.example.com/malware.bin")
        assert result is not None
        assert result.source == "urlhaus"

    def test_domain_from_url_fallback(self, tmp_path):
        db = self._build_db(tmp_path)
        # URL not in db, but domain is
        result = check_ioc(db, "http://evil.example.com/other-path")
        assert result is not None
        assert result.indicator_type == "domain"

    def test_miss(self, tmp_path):
        db = self._build_db(tmp_path)
        result = check_ioc(db, "safe.example.com")
        assert result is None

    def test_empty_db(self):
        db = ThreatIntelDB()
        result = check_ioc(db, "evil.example.com")
        assert result is None

    def test_empty_indicator(self, tmp_path):
        db = self._build_db(tmp_path)
        result = check_ioc(db, "")
        assert result is None

    def test_highest_confidence_returned(self, tmp_path):
        db = ThreatIntelDB()
        # Add two matches with different confidence
        low = ThreatMatch(
            indicator="test.com", indicator_type="domain", source="urlhaus",
            malware_family="test", threat_type="test", confidence="low",
            reference=""
        )
        high = ThreatMatch(
            indicator="test.com", indicator_type="domain", source="threatfox",
            malware_family="test", threat_type="test", confidence="high",
            reference=""
        )
        db.domains["test.com"] = [low, high]
        result = check_ioc(db, "test.com")
        assert result.confidence == "high"


# ============================================================================
# ThreatIntelDB properties
# ============================================================================

class TestThreatIntelDB:

    def test_empty_db(self):
        db = ThreatIntelDB()
        assert db.is_empty is True
        assert db.total_indicators == 0

    def test_non_empty_db(self):
        db = ThreatIntelDB()
        db.domains["evil.com"] = [ThreatMatch(
            indicator="evil.com", indicator_type="domain", source="test",
            malware_family="test", threat_type="test", confidence="high",
            reference=""
        )]
        assert db.is_empty is False
        assert db.total_indicators == 1


# ============================================================================
# load_feeds integration
# ============================================================================

class TestLoadFeeds:

    def test_load_empty_dir(self, tmp_path):
        db = load_feeds(str(tmp_path))
        assert db.is_empty is True
        # last_updated describes the DATA, so with no feed files there
        # is nothing to timestamp. It used to be set to datetime.now(),
        # which made an empty (or months-old) database look freshly
        # updated in the report, the one field a reader would check
        # before trusting "no malicious indicators found".
        assert db.last_updated is None
        assert db.feed_age_seconds is None
        assert db.is_stale is True

    def test_stale_cache_is_flagged_not_relabelled_fresh(self, tmp_path):
        import os
        import time
        p = tmp_path / "urlhaus_recent.csv"
        p.write_text(
            '"1","2026-01-01 00:00:00","http://bad.example/x","online",'
            '"","malware","tag","https://urlhaus.abuse.ch/url/1/","rep"\n'
        )
        old = time.time() - 30 * 86400
        os.utime(p, (old, old))

        db = load_feeds(str(tmp_path))
        assert db.is_stale is True
        assert db.feed_age_seconds > 29 * 86400
        assert db.last_updated is not None
        assert not db.last_updated.startswith(
            time.strftime("%Y-%m-%d", time.gmtime())), (
            "a 30-day-old cache reported today's date as its data timestamp"
        )

        os.utime(p, None)
        assert load_feeds(str(tmp_path)).is_stale is False

    def test_load_with_data(self, tmp_path):
        (tmp_path / "urlhaus_recent.csv").write_text(SAMPLE_URLHAUS_CSV)
        (tmp_path / "threatfox_iocs.json").write_text(json.dumps(SAMPLE_THREATFOX_JSON))
        db = load_feeds(str(tmp_path))
        assert db.is_empty is False
        assert db.urlhaus_entries == 2
        assert db.threatfox_entries == 3
