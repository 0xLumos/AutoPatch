"""
Threat intelligence feed manager for AutoPatch supply chain analysis.

Downloads, caches, and queries URLhaus and ThreatFox feeds to identify
known-malicious domains, IPs, and URLs contacted by container images.

Feeds are cached locally and re-downloaded only when stale (>24 hours).
Network failures are handled gracefully -- an empty DB is returned so
the pipeline continues without threat intel rather than crashing.
"""

import csv
import re
import io
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("docker_patch_tool")

# Feed URLs
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Cache staleness threshold in seconds (24 hours)
from .constants import THREAT_INTEL_CACHE_TTL_SECONDS as CACHE_MAX_AGE_SECONDS
# Sourced from constants.py so the documented AUTOPATCH_* env
# override is real. It was a duplicated literal, which made
# every override in the README silently inert.

# Request timeout in seconds
REQUEST_TIMEOUT = 30



@dataclass
class FeedUpdateResult:
    """Per-feed update outcome from :func:`update_feeds`.

    The bool fields ``downloaded`` and ``used_cache`` are mutually
    exclusive; callers can read ``downloaded`` to decide whether a
    visibly-fresh banner makes sense, or ``cache_age_seconds`` to
    surface "indicators are N hours old" in the report.
    """
    urlhaus_downloaded: bool = False
    urlhaus_used_cache: bool = False
    urlhaus_cache_age_seconds: Optional[float] = None
    threatfox_downloaded: bool = False
    threatfox_used_cache: bool = False
    threatfox_cache_age_seconds: Optional[float] = None

    def any_succeeded(self) -> bool:
        return (
            self.urlhaus_downloaded or self.urlhaus_used_cache
            or self.threatfox_downloaded or self.threatfox_used_cache
        )

    def __bool__(self) -> bool:
        return self.any_succeeded()

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
    # ISO timestamp of the DATA (oldest feed file mtime), not of the
    # load call. None when no feed file was found.
    last_updated: Optional[str] = None
    feed_age_seconds: Optional[float] = None
    # True when the newest data we hold is older than CACHE_MAX_AGE_SECONDS.
    # A caller that reports "no malicious indicators found" MUST surface
    # this, or absence of evidence reads as evidence of absence.
    is_stale: bool = True
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


# A DNS name (letters, digits, hyphen, dot) or an IP literal. IPv6
# hostnames come back from urlsplit without their brackets, hence the
# colon branch.
_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$"
    r"|^[0-9a-f:]+$"
)


def _extract_domain_from_url(url: str) -> Optional[str]:
    """Extract the hostname from a URL string.

    The hand-rolled version this replaces split on ``:`` to strip the
    port, which silently truncated two shapes that appear throughout
    the URLhaus feed:

    * **userinfo** ``http://user:pass@malware.example/x`` produced
      ``"user"``. The malicious host was indexed under a garbage key,
      so a later lookup for ``malware.example`` never matched and a
      known-bad domain was reported clean.
    * **IPv6 literals** ``http://[2001:db8::1]:8080/`` produced ``"["``.

    ``urlsplit`` implements RFC 3986 and gets both right. Scheme-less
    entries (also common in the feed) are given one so ``netloc`` is
    populated rather than the whole string landing in ``path``.
    """
    if not url:
        return None
    try:
        candidate = url.strip()
        if "//" not in candidate.split("?", 1)[0]:
            candidate = "//" + candidate
        host = urlsplit(candidate, scheme="http").hostname
    except ValueError:
        # urlsplit raises on malformed IPv6 brackets and bad ports
        return None
    if not host:
        return None
    # Strip the FQDN root label: "evil.com." and "evil.com" resolve to
    # the same host, and the feed contains both forms.
    host = host.rstrip(".").lower()
    # Reject anything that is not a syntactically valid host. Feed rows
    # are third-party input and do contain junk; without this check a
    # malformed line is indexed as a "domain" and inflates the
    # indicator count with entries nothing can ever match.
    if not host or not _HOST_RE.match(host):
        return None
    return host


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


def update_feeds(cache_dir: str, force: bool = False) -> FeedUpdateResult:
    """
    Download URLhaus CSV and ThreatFox JSON feeds, saving to cache_dir.

    Only re-downloads if cache is older than 24 hours, unless force=True.

    Args:
        cache_dir: Directory to store cached feed files.
        force: If True, re-download even if cache is fresh.

    Returns:
        :class:`FeedUpdateResult` describing each feed's outcome and
        cache age. ``bool(result)`` is True iff at least one feed
        ended in a usable state (downloaded or fresh-cache).
    """
    cache_dir = os.path.expanduser(cache_dir)
    os.makedirs(cache_dir, exist_ok=True)

    session = _create_session()
    out = FeedUpdateResult()

    def _age_secs(p: str) -> Optional[float]:
        try:
            return max(0.0, time.time() - os.path.getmtime(p))
        except OSError:
            return None

    urlhaus_path = _cache_path(cache_dir, "urlhaus_recent.csv")
    if force or not _is_cache_fresh(urlhaus_path):
        if _download_urlhaus(cache_dir, session):
            out.urlhaus_downloaded = True
            out.urlhaus_cache_age_seconds = _age_secs(urlhaus_path)
    else:
        logger.debug("URLhaus cache is fresh, skipping download")
        out.urlhaus_used_cache = True
        out.urlhaus_cache_age_seconds = _age_secs(urlhaus_path)

    threatfox_path = _cache_path(cache_dir, "threatfox_iocs.json")
    if force or not _is_cache_fresh(threatfox_path):
        if _download_threatfox(cache_dir, session):
            out.threatfox_downloaded = True
            out.threatfox_cache_age_seconds = _age_secs(threatfox_path)
    else:
        logger.debug("ThreatFox cache is fresh, skipping download")
        out.threatfox_used_cache = True
        out.threatfox_cache_age_seconds = _age_secs(threatfox_path)

    return out


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

    # last_updated must describe the DATA, not this function call.
    # Setting it to datetime.now() reported a three-month-old cache as
    # freshly updated in every report and attestation, which is the one
    # field a reader would use to judge whether "no threat indicators
    # matched" means anything. Derive it from the oldest feed file we
    # actually read, and refuse to imply freshness we do not have.
    mtimes = []
    for label, path in (("urlhaus", urlhaus_path), ("threatfox", threatfox_path)):
        try:
            mtimes.append((label, os.path.getmtime(path)))
        except OSError:
            continue

    if mtimes:
        oldest_label, oldest = min(mtimes, key=lambda kv: kv[1])
        db.last_updated = datetime.fromtimestamp(
            oldest, tz=timezone.utc).isoformat()
        db.feed_age_seconds = max(0.0, time.time() - oldest)
        db.is_stale = db.feed_age_seconds >= CACHE_MAX_AGE_SECONDS
        if db.is_stale:
            logger.warning(
                "Threat intel feed '%s' is %.1f hours old (threshold %.1f h). "
                "Indicators published since then are NOT in this database; "
                "a clean result does not mean the image is clean. Run with "
                "--update-threat-feeds or pass force=True to refresh.",
                oldest_label, db.feed_age_seconds / 3600.0,
                CACHE_MAX_AGE_SECONDS / 3600.0,
            )
    else:
        db.last_updated = None
        db.feed_age_seconds = None
        db.is_stale = True
        logger.warning(
            "No threat intel feed files found under %s; the database is "
            "empty and every IOC check will return no match.", cache_dir,
        )

    logger.info(
        "Threat intel loaded: %d indicators (URLhaus=%d, ThreatFox=%d), "
        "data timestamp %s%s",
        db.total_indicators, db.urlhaus_entries, db.threatfox_entries,
        db.last_updated, " [STALE]" if db.is_stale else "",
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
