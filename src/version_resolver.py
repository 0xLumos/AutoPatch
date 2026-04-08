"""
AutoPatch Dynamic Version Resolution (F1-F4)

Replaces hardcoded EOL version mappings with live resolution using:
  1. endoflife.date API for EOL status and latest supported versions
  2. Docker Hub (OCI Distribution Spec) tag listing for image tag validation
  3. In-memory TTL cache to avoid hammering upstream APIs per pipeline run

Design rationale:
  - endoflife.date is the most comprehensive, machine-readable EOL database.
    It covers 300+ products with structured JSON. No authentication needed.
  - Docker Hub's v2 tags/list endpoint (OCI Distribution Spec) is the
    authoritative source for whether a specific image:tag actually exists.
  - TTL cache with 6h default keeps a single pipeline run fast while
    ensuring daily runs pick up new releases within a working day.
"""

import logging
import time
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")


# ════════════════════════════════════════════════════════════════════
# TTL Cache (F3)
# ════════════════════════════════════════════════════════════════════

@dataclass
class _CacheEntry:
    """Single cache entry with expiry timestamp."""
    data: Any
    expires_at: float


class TTLCache:
    """
    Simple in-memory cache with per-key TTL expiry.

    Thread safety: not thread-safe. AutoPatch runs single-threaded
    per pipeline invocation, so no locking overhead is needed.
    """

    def __init__(self, default_ttl: int = 21600):
        """
        Args:
            default_ttl: Default time-to-live in seconds (default: 6 hours)
        """
        self._store: Dict[str, _CacheEntry] = {}
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        """Return cached value if present and not expired, else None."""
        entry = self._store.get(key)
        if entry is None:
            return None
        if time.time() > entry.expires_at:
            del self._store[key]
            return None
        return entry.data

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store value with TTL. Uses default_ttl if ttl is None."""
        actual_ttl = ttl if ttl is not None else self._default_ttl
        self._store[key] = _CacheEntry(
            data=value,
            expires_at=time.time() + actual_ttl,
        )

    def invalidate(self, key: str) -> None:
        """Remove a specific key from cache."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Drop all cached entries."""
        self._store.clear()

    @property
    def size(self) -> int:
        """Number of entries (including possibly-expired ones)."""
        return len(self._store)


# Module-level cache instance shared across all resolution calls
_cache = TTLCache(default_ttl=21600)  # 6 hours


def get_cache() -> TTLCache:
    """Return the module-level cache (for testing or manual invalidation)."""
    return _cache


# ════════════════════════════════════════════════════════════════════
# endoflife.date API Client (F1)
# ════════════════════════════════════════════════════════════════════

# Mapping from AutoPatch language identifiers to endoflife.date product slugs.
# The API uses lowercase product names as URL path segments.
_PRODUCT_SLUG_MAP = {
    "python": "python",
    "node": "nodejs",
    "golang": "go",
    "ruby": "ruby",
    "php": "php",
    "openjdk": "java",
    "rust": "rust",
    "perl": "perl",
    "erlang": "erlang",
    "elixir": "elixir",
    "dotnet": "dotnet",
}


@dataclass
class CycleInfo:
    """Parsed release cycle from endoflife.date."""
    cycle: str           # e.g. "3.12", "22", "1.23"
    latest: str          # e.g. "3.12.8"
    eol: Any             # True, False, or date string "2025-10-01"
    lts: Any             # True, False, or date string
    release_date: str    # e.g. "2024-10-07"
    is_eol: bool = False # Computed: is this cycle currently EOL?


def _fetch_json_via_curl(url: str, timeout: int = 15) -> Optional[Any]:
    """
    Fetch JSON from a URL using curl. We use curl instead of requests/urllib
    to avoid adding a Python dependency -- curl is present on every CI image
    and every Linux distribution.

    Args:
        url: URL to fetch
        timeout: HTTP timeout in seconds

    Returns:
        Parsed JSON object, or None on any failure
    """
    cache_key = f"http:{url}"
    cached = _cache.get(cache_key)
    if cached is not None:
        logger.debug(f"Cache hit for {url}")
        return cached

    cmd = [
        "curl", "-sfL",
        "--max-time", str(timeout),
        "-H", "Accept: application/json",
        url,
    ]
    code, output = run_cmd(cmd, timeout=timeout + 5)
    if code != 0:
        logger.warning(f"HTTP fetch failed for {url}: exit {code}")
        return None

    try:
        data = json.loads(output)
        _cache.set(cache_key, data)
        return data
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Invalid JSON from {url}: {e}")
        return None


def fetch_eol_cycles(language: str) -> List[CycleInfo]:
    """
    Fetch all release cycles for a language from endoflife.date.

    Args:
        language: AutoPatch language identifier (e.g. "python", "node")

    Returns:
        List of CycleInfo sorted by cycle version descending (newest first).
        Returns empty list on API failure.
    """
    slug = _PRODUCT_SLUG_MAP.get(language)
    if not slug:
        logger.debug(f"No endoflife.date slug for language '{language}'")
        return []

    url = f"https://endoflife.date/api/{slug}.json"
    data = _fetch_json_via_curl(url)
    if not data or not isinstance(data, list):
        return []

    cycles = []
    for entry in data:
        eol_val = entry.get("eol", False)
        # eol can be True, False, or a date string like "2025-10-01"
        if isinstance(eol_val, bool):
            is_eol = eol_val
        elif isinstance(eol_val, str):
            # Date string: compare with today
            try:
                from datetime import datetime
                eol_date = datetime.strptime(eol_val, "%Y-%m-%d")
                is_eol = datetime.now() > eol_date
            except ValueError:
                is_eol = False
        else:
            is_eol = False

        cycles.append(CycleInfo(
            cycle=str(entry.get("cycle", "")),
            latest=str(entry.get("latest", entry.get("cycle", ""))),
            eol=eol_val,
            lts=entry.get("lts", False),
            release_date=str(entry.get("releaseDate", "")),
            is_eol=is_eol,
        ))

    return cycles


def get_latest_supported_version(language: str) -> Optional[str]:
    """
    Get the latest non-EOL version cycle for a language.

    Prefers the newest LTS release if available, otherwise the newest
    non-EOL release.

    Args:
        language: AutoPatch language identifier

    Returns:
        Version string (e.g. "3.12", "22"), or None if API unavailable
    """
    cache_key = f"latest:{language}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    cycles = fetch_eol_cycles(language)
    if not cycles:
        return None

    # Filter to non-EOL cycles
    active = [c for c in cycles if not c.is_eol]
    if not active:
        logger.warning(f"All {language} cycles appear EOL per endoflife.date")
        return None

    # Prefer LTS if available
    lts_cycles = [c for c in active if c.lts not in (False, None, "")]
    target = lts_cycles[0] if lts_cycles else active[0]

    result = target.cycle
    _cache.set(cache_key, result, ttl=21600)
    logger.info(f"Latest supported {language} version: {result} (LTS={target.lts})")
    return result


def is_version_eol(language: str, version: str) -> Optional[bool]:
    """
    Check if a specific version of a language is past end-of-life.

    Args:
        language: AutoPatch language identifier
        version: Version string to check (e.g. "3.8", "16")

    Returns:
        True if EOL, False if supported, None if unknown (API failure)
    """
    cycles = fetch_eol_cycles(language)
    if not cycles:
        return None

    # Normalize version for matching -- endoflife.date uses major.minor
    # or just major depending on the product
    for c in cycles:
        if c.cycle == version:
            return c.is_eol

    # Try partial match: "3.8" matches "3.8", "16" matches "16"
    # Also handle node-style where version is just major
    for c in cycles:
        if version.startswith(c.cycle) or c.cycle.startswith(version):
            return c.is_eol

    logger.debug(f"Version {version} not found in {language} cycles")
    return None


# ════════════════════════════════════════════════════════════════════
# Docker Hub Tag Validation (F2)
# ════════════════════════════════════════════════════════════════════

def _parse_image_ref(image_ref: str) -> Tuple[str, str]:
    """
    Parse an image reference into (repository, tag).

    Handles:
      python:3.12-slim  ->  (library/python, 3.12-slim)
      nginx:latest      ->  (library/nginx, latest)
      ghcr.io/foo/bar:v1 -> (foo/bar, v1)  [non-Docker-Hub, skipped]
      myorg/myapp:1.0   ->  (myorg/myapp, 1.0)

    Returns:
        (repository, tag) tuple. Tag defaults to "latest" if absent.
    """
    # Split off tag
    if ":" in image_ref and not image_ref.startswith("sha256:"):
        repo, tag = image_ref.rsplit(":", 1)
    else:
        repo, tag = image_ref, "latest"

    # Add library/ prefix for official images (single-segment names)
    if "/" not in repo:
        repo = f"library/{repo}"

    return repo, tag


def validate_dockerhub_tag(image_ref: str) -> Optional[bool]:
    """
    Check whether a specific image:tag exists on Docker Hub using
    the OCI Distribution Spec v2 tags/list endpoint.

    This does NOT pull the image -- it only checks the tag manifest exists.

    Args:
        image_ref: Full image reference (e.g. "python:3.12-slim")

    Returns:
        True if tag exists, False if not found, None if API unavailable
        or image is not on Docker Hub.
    """
    repo, tag = _parse_image_ref(image_ref)

    # Only validate Docker Hub images -- skip third-party registries
    if "." in repo.split("/")[0]:
        logger.debug(f"Skipping tag validation for non-Docker-Hub image: {image_ref}")
        return None

    cache_key = f"tags:{repo}"
    tags = _cache.get(cache_key)

    if tags is None:
        # Fetch tag list from Docker Hub
        # Docker Hub's v2 API requires a token for even public repos
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        token_data = _fetch_json_via_curl(token_url)
        if not token_data or "token" not in token_data:
            logger.warning(f"Failed to get Docker Hub token for {repo}")
            return None

        token = token_data["token"]
        # Fetch tags list -- limit to 1000 to avoid massive responses
        tags_url = f"https://registry-1.docker.io/v2/{repo}/tags/list"
        cmd = [
            "curl", "-sfL",
            "--max-time", "15",
            "-H", f"Authorization: Bearer {token}",
            "-H", "Accept: application/json",
            tags_url,
        ]
        code, output = run_cmd(cmd, timeout=20)
        if code != 0:
            logger.warning(f"Failed to fetch tags for {repo}")
            return None

        try:
            tags_data = json.loads(output)
            tags = set(tags_data.get("tags", []))
            # Cache for 6 hours
            _cache.set(cache_key, tags, ttl=21600)
        except (json.JSONDecodeError, ValueError):
            return None

    exists = tag in tags
    logger.debug(f"Tag validation: {image_ref} -> {'exists' if exists else 'NOT FOUND'}")
    return exists


def find_best_matching_tag(
    repo: str,
    desired_version: str,
    variant: Optional[str] = None,
    os_family: Optional[str] = None,
) -> Optional[str]:
    """
    Find the best matching tag for a desired version on Docker Hub.

    Strategy:
      1. Try exact match: {version}-{variant} (e.g. "3.12-slim")
      2. Try version only: {version} (e.g. "3.12")
      3. Try with OS suffix: {version}-{os_family} (e.g. "3.12-bookworm")
      4. Try minor version variants if full version given

    Args:
        repo: Docker Hub repository (e.g. "library/python")
        desired_version: Target version (e.g. "3.12")
        variant: Optional image variant (e.g. "slim", "alpine", "bullseye")
        os_family: Optional OS family for tag suffix

    Returns:
        Best matching tag string, or None if no match found
    """
    cache_key = f"tags:{repo}"
    tags = _cache.get(cache_key)

    if tags is None:
        # Need to fetch tags first
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        token_data = _fetch_json_via_curl(token_url)
        if not token_data or "token" not in token_data:
            return None

        token = token_data["token"]
        tags_url = f"https://registry-1.docker.io/v2/{repo}/tags/list"
        cmd = [
            "curl", "-sfL",
            "--max-time", "15",
            "-H", f"Authorization: Bearer {token}",
            "-H", "Accept: application/json",
            tags_url,
        ]
        code, output = run_cmd(cmd, timeout=20)
        if code != 0:
            return None

        try:
            tags_data = json.loads(output)
            tags = set(tags_data.get("tags", []))
            _cache.set(cache_key, tags, ttl=21600)
        except (json.JSONDecodeError, ValueError):
            return None

    if not tags:
        return None

    # Build candidate tags in preference order
    candidates = []
    if variant:
        candidates.append(f"{desired_version}-{variant}")
    candidates.append(desired_version)
    if os_family:
        os_suffix_map = {
            "debian": "bookworm",
            "ubuntu": "jammy",
            "alpine": "alpine",
        }
        os_suffix = os_suffix_map.get(os_family, os_family)
        candidates.append(f"{desired_version}-{os_suffix}")
        if variant:
            candidates.append(f"{desired_version}-{os_suffix}-{variant}")

    # Also try slim variant as it is commonly preferred
    if variant != "slim":
        candidates.append(f"{desired_version}-slim")

    for candidate in candidates:
        if candidate in tags:
            logger.debug(f"Found matching tag: {repo}:{candidate}")
            return candidate

    logger.debug(f"No matching tag found for {repo} version {desired_version}")
    return None


# ════════════════════════════════════════════════════════════════════
# Dynamic EOL Upgrade (F4 -- replaces hardcoded _EOL_UPGRADES)
# ════════════════════════════════════════════════════════════════════

# Hardcoded fallback -- used ONLY when endoflife.date API is unreachable.
# This ensures offline/air-gapped environments still get reasonable upgrades.
# Last updated: 2026-03
_FALLBACK_EOL_UPGRADES = {
    "python": {"2.7": "3.12", "3.6": "3.12", "3.7": "3.12", "3.8": "3.12"},
    "node": {"12": "22", "14": "22", "16": "22", "18": "22"},
    "golang": {"1.20": "1.23", "1.21": "1.23"},
    "ruby": {"2.7": "3.3", "3.0": "3.3"},
    "php": {"7.4": "8.3", "8.0": "8.3"},
    "openjdk": {"8": "21", "11": "21"},
    "rust": {"1.70": "1.85"},
    "dotnet": {"6.0": "8.0", "7.0": "8.0"},
}


def resolve_eol_upgrade(language: str, version: str) -> Tuple[str, str]:
    """
    Determine if a language version is EOL and return the upgrade target.

    Resolution strategy:
      1. Query endoflife.date API for live EOL status
      2. If EOL, get the latest supported version from the API
      3. If API unavailable, fall back to hardcoded mappings
      4. If version is not EOL, return it unchanged

    Args:
        language: AutoPatch language identifier (e.g. "python", "node")
        version: Current version string (e.g. "3.8", "16")

    Returns:
        Tuple of (resolved_version, source) where source is one of:
          "live"     -- resolved from endoflife.date API
          "fallback" -- resolved from hardcoded fallback table
          "current"  -- version is not EOL, returned unchanged
    """
    # Try live API first
    eol_status = is_version_eol(language, version)

    if eol_status is True:
        # Version is EOL -- find the latest supported version
        latest = get_latest_supported_version(language)
        if latest:
            logger.info(
                f"[live] {language} {version} is EOL, upgrading to {latest}"
            )
            return latest, "live"

        # API returned EOL but couldn't find latest -- use fallback
        fallback_map = _FALLBACK_EOL_UPGRADES.get(language, {})
        if version in fallback_map:
            target = fallback_map[version]
            logger.info(
                f"[fallback] {language} {version} is EOL, upgrading to {target}"
            )
            return target, "fallback"

        logger.warning(
            f"{language} {version} is EOL but no upgrade target found "
            f"(API and fallback both failed). Keeping original version."
        )
        return version, "current"

    elif eol_status is False:
        # Version is actively supported
        logger.debug(f"{language} {version} is still supported (per endoflife.date)")
        return version, "current"

    else:
        # API unavailable (eol_status is None) -- use fallback
        fallback_map = _FALLBACK_EOL_UPGRADES.get(language, {})
        if version in fallback_map:
            target = fallback_map[version]
            logger.info(
                f"[fallback] API unavailable; {language} {version} -> {target} "
                f"(from hardcoded fallback)"
            )
            return target, "fallback"

        # Not in fallback either -- assume current
        return version, "current"
