"""
Threat intelligence feed manager for AutoPatch supply chain analysis.

Downloads, caches, and queries URLhaus and ThreatFox feeds to identify
known-malicious domains, IPs, and URLs contacted by container images.

Feeds are cached locally and re-downloaded only when stale (>24 hours).
Network failures are handled gracefully -- an empty DB is returned so
the pipeline continues without threat intel rather than crashing.
"""

import csv
import io
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("docker_patch_tool")

# Feed URLs
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Cache staleness threshold in seconds (24 hours)
CACHE_MAX_AGE_SECONDS = 86400

# Request timeout in seconds
REQUEST_TIMEOUT = 30


@dataclass
class ThreatMatch:
    """A match against a threat intelligence indicator."""
    indicator: str
    indicator_type: str  # "domain", "ip", "url"
    source: str  # "urlhaus" or "threatfox"
    malware_family: str
    threat_type: str
    confidence: str  # "high", "medium", "low"
    reference: str  # URL to the original report


@dataclass
class ThreatIntelDB:
    """In-memory threat intelligence database loaded from cached feeds."""
    domains: Dict[str, List[ThreatMatch]] = field(default_factory=dict)
    ips: Dict[str, List[ThreatMatch]] = field(default_factory=dict)
    urls: Dict[str, List[ThreatMatch]] = field(default_factory=dict)
    last_updated: Optional[str] = None
    urlhaus_entries: int = 0
    threatfox_entries: int = 0

    @property
    def total_indicators(self) -> int:
        return len(self.domains) + len(self.ips) + len(self.urls)

    @property
    def is_empty(self) -> bool:
        return self.total_indicators == 0


def _create_session() -> requests.Session:
    """Create an HTTP session with retry logic and exponential backoff."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,  # 1s, 2s, 4s
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _cache_path(cache_dir: str, filename: str) -> str:
    """Return the full path for a cached feed file."""
    return os.path.join(cache_dir, filename)


def _is_cache_fresh(filepath: str, max_age: int = CACHE_MAX_AGE_SECONDS) -> bool:
    """Check if a cached file exists and is younger than max_age seconds."""
    if not os.path.exists(filepath):
        return False
    mtime = os.path.getmtime(filepath)
    age = time.time() - mtime
    return age < max_age


def _extract_domain_from_url(url: str) -> Optional[str]:
    """Extract the domain (hostname) from a URL string."""
    try:
        # Strip protocol
        if "://" in url:
            url = url.split("://", 1)[1]
        # Strip path, port, query
        host = url.split("/")[0].split("?")[0].split(":")[0]
        if host:
            return host.lower()
    except Exception:
        pass
    return None


def _download_urlhaus(cache_dir: str, session: requests.Session) -> bool:
    """
    Download the URLhaus recent CSV feed and save to cache.

    Returns True on success, False on failure.
    """
    filepath = _cache_path(cache_dir, "urlhaus_recent.csv")
    try:
        logger.info("Downloading URLhaus CSV feed...")
        resp = session.get(URLHAUS_CSV_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(resp.text)
        logger.info(f"URLhaus feed saved ({len(resp.text)} bytes)")
        return True
    except requests.RequestException as e:
        logger.warning(f"Failed to download URLhaus feed: {e}")
        return False


def _download_threatfox(cache_dir: str, session: requests.Session) -> bool:
    """
    Download the ThreatFox IOC feed (last 30 days) and save to cache.

    Returns True on success, False on failure.
    """
    filepath = _cache_path(cache_dir, "threatfox_iocs.json")
    try:
        logger.info("Downloading ThreatFox IOC feed...")
        payload = {"query": "get_iocs", "days": 30}
        resp = session.post(
            THREATFOX_API_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f)
        entry_count = len(data.get("data", []) or [])
        logger.info(f"ThreatFox feed saved ({entry_count} IOCs)")
        return True
    except requests.RequestException as e:
        logger.warning(f"Failed to download ThreatFox feed: {e}")
        return False
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Failed to parse ThreatFox response: {e}")
        return False


def update_feeds(cache_dir: str, force: bool = False) -> bool:
    """
    Download URLhaus CSV and ThreatFox JSON feeds, saving to cache_dir.

    Only re-downloads if cache is older than 24 hours, unless force=True.

    Args:
        cache_dir: Directory to store cached feed files.
        force: If True, re-download even if cache is fresh.

    Returns:
        True if at least one feed was successfully updated or already fresh.
    """
    cache_dir = os.path.expanduser(cache_dir)
    os.makedirs(cache_dir, exist_ok=True)

    session = _create_session()
    any_success = False

    urlhaus_path = _cache_path(cache_dir, "urlhaus_recent.csv")
    if force or not _is_cache_fresh(urlhaus_path):
        if _download_urlhaus(cache_dir, session):
            any_success = True
    else:
        logger.debug("URLhaus cache is fresh, skipping download")
        any_success = True

    threatfox_path = _cache_path(cache_dir, "threatfox_iocs.json")
    if force or not _is_cache_fresh(threatfox_path):
        if _download_threatfox(cache_dir, session):
            any_success = True
    else:
        logger.debug("ThreatFox cache is fresh, skipping download")
        any_success = True

    return any_success


def _parse_urlhaus_csv(filepath: str, db: ThreatIntelDB) -> None:
    """Parse URLhaus CSV into the ThreatIntelDB."""
    if not os.path.exists(filepath):
        return

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning(f"Failed to read URLhaus CSV: {e}")
        return

    count = 0
    for line in content.splitlines():
        # Skip comment lines (start with #) and empty lines
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            # CSV columns: id, dateadded, url, url_status, last_online,
            #              threat, tags, urlhaus_link, reporter
            reader = csv.reader(io.StringIO(line))
            row = next(reader)
            if len(row) < 8:
                continue

            url = row[2].strip('"').strip()
            threat_type = row[5].strip('"').strip()
            tags = row[6].strip('"').strip()
            reference = row[7].strip('"').strip()

            if not url:
                continue

            match_info = ThreatMatch(
                indicator=url,
                indicator_type="url",
                source="urlhaus",
                malware_family=tags or "unknown",
                threat_type=threat_type or "malware_download",
                confidence="high",
                reference=reference,
            )

            # Index by URL
            url_lower = url.lower()
            db.urls.setdefault(url_lower, []).append(match_info)

            # Also index by domain
            domain = _extract_domain_from_url(url)
            if domain:
                domain_match = ThreatMatch(
                    indicator=domain,
                    indicator_type="domain",
                    source="urlhaus",
                    malware_family=tags or "unknown",
                    threat_type=threat_type or "malware_download",
                    confidence="high",
                    reference=reference,
                )
                db.domains.setdefault(domain, []).append(domain_match)

            count += 1
        except (csv.Error, StopIteration):
            continue

    db.urlhaus_entries = count


def _parse_threatfox_json(filepath: str, db: ThreatIntelDB) -> None:
    """Parse ThreatFox JSON into the ThreatIntelDB."""
    if not os.path.exists(filepath):
        return

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Failed to parse ThreatFox JSON: {e}")
        return

    iocs = data.get("data", [])
    if not isinstance(iocs, list):
        return

    count = 0
    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue

        ioc_value = ioc.get("ioc", "").strip()
        ioc_type = ioc.get("ioc_type", "").strip()
        malware = ioc.get("malware_printable", "unknown")
        threat = ioc.get("threat_type", "")
        confidence_level = ioc.get("confidence_level", 0)
        reference = ioc.get("reference", "")

        if not ioc_value:
            continue

        conf = "high" if confidence_level >= 75 else "medium" if confidence_level >= 50 else "low"

        if ioc_type in ("domain", "hostname"):
            match_info = ThreatMatch(
                indicator=ioc_value.lower(),
                indicator_type="domain",
                source="threatfox",
                malware_family=malware,
                threat_type=threat,
                confidence=conf,
                reference=reference or "",
            )
            db.domains.setdefault(ioc_value.lower(), []).append(match_info)
            count += 1

        elif ioc_type == "ip:port":
            # Extract IP from "ip:port" format
            ip_part = ioc_value.split(":")[0] if ":" in ioc_value else ioc_value
            match_info = ThreatMatch(
                indicator=ip_part,
                indicator_type="ip",
                source="threatfox",
                malware_family=malware,
                threat_type=threat,
                confidence=conf,
                reference=reference or "",
            )
            db.ips.setdefault(ip_part, []).append(match_info)
            count += 1

        elif ioc_type == "url":
            match_info = ThreatMatch(
                indicator=ioc_value,
                indicator_type="url",
                source="threatfox",
                malware_family=malware,
                threat_type=threat,
                confidence=conf,
                reference=reference or "",
            )
            db.urls.setdefault(ioc_value.lower(), []).append(match_info)

            # Also index by domain
            domain = _extract_domain_from_url(ioc_value)
            if domain:
                domain_match = ThreatMatch(
                    indicator=domain,
                    indicator_type="domain",
                    source="threatfox",
                    malware_family=malware,
                    threat_type=threat,
                    confidence=conf,
                    reference=reference or "",
                )
                db.domains.setdefault(domain, []).append(domain_match)

            count += 1

    db.threatfox_entries = count


def load_feeds(cache_dir: str) -> ThreatIntelDB:
    """
    Load cached threat intelligence feeds into an in-memory database.

    If no cached feeds exist, returns an empty ThreatIntelDB. The caller
    should check db.is_empty and log a warning if needed.

    Args:
        cache_dir: Directory containing cached feed files.

    Returns:
        ThreatIntelDB populated with indicators from cached feeds.
    """
    cache_dir = os.path.expanduser(cache_dir)
    db = ThreatIntelDB()

    urlhaus_path = _cache_path(cache_dir, "urlhaus_recent.csv")
    _parse_urlhaus_csv(urlhaus_path, db)

    threatfox_path = _cache_path(cache_dir, "threatfox_iocs.json")
    _parse_threatfox_json(threatfox_path, db)

    db.last_updated = datetime.now(timezone.utc).isoformat()
    logger.info(
        f"Threat intel loaded: {db.total_indicators} indicators "
        f"(URLhaus={db.urlhaus_entries}, ThreatFox={db.threatfox_entries})"
    )
    return db


def check_ioc(db: ThreatIntelDB, indicator: str) -> Optional[ThreatMatch]:
    """
    Check a domain, IP, or URL against the threat intelligence database.

    Args:
        db: Loaded ThreatIntelDB instance.
        indicator: Domain name, IP address, or URL to check.

    Returns:
        ThreatMatch if found, None otherwise. Returns the highest-confidence
        match if multiple exist.
    """
    if not indicator or db.is_empty:
        return None

    indicator_lower = indicator.strip().lower()

    # Check domains
    if indicator_lower in db.domains:
        matches = db.domains[indicator_lower]
        # Return highest confidence match
        for conf in ("high", "medium", "low"):
            for m in matches:
                if m.confidence == conf:
                    return m
        return matches[0]

    # Check IPs
    if indicator_lower in db.ips:
        matches = db.ips[indicator_lower]
        for conf in ("high", "medium", "low"):
            for m in matches:
                if m.confidence == conf:
                    return m
        return matches[0]

    # Check URLs
    if indicator_lower in db.urls:
        matches = db.urls[indicator_lower]
        for conf in ("high", "medium", "low"):
            for m in matches:
                if m.confidence == conf:
                    return m
        return matches[0]

    # Also try matching the domain portion if indicator looks like a URL
    domain = _extract_domain_from_url(indicator)
    if domain and domain in db.domains:
        matches = db.domains[domain]
        for conf in ("high", "medium", "low"):
            for m in matches:
                if m.confidence == conf:
                    return m
        return matches[0]

    return None
