"""
AutoPatch Image Resolver -- Data-Driven Base Image Selection

Replaces the hardcoded if/elif chains in patcher.py with a queryable,
data-driven image resolution layer backed by a YAML registry.

Key capabilities:
1. Load image mappings from YAML registry (image_registry.yaml)
2. Resolve best replacement image using inference + registry data
3. Verify tags exist on Docker Hub before committing
4. Cache Hub API responses to avoid repeated requests
5. Score candidates and fall back intelligently
"""

import logging
import os
import json
import re
import requests
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, NamedTuple
from urllib.parse import urlencode

logger = logging.getLogger("docker_patch_tool")


class InferenceResultLike:
    """Duck-typed InferenceResult for type hints. Accepts any object with these attributes."""
    os_family: str
    language: Optional[str]
    language_version: Optional[str]
    needs_glibc: bool
    variant: Optional[str]
    confidence: float
    warnings: List[str]


class RegistryEntry(NamedTuple):
    """Represents an image entry in the registry."""
    name: str
    priority: int
    versions: Dict[str, str]
    tag_formats: Dict[str, str]
    eol_versions: Dict[str, str]


class ImageResolver:
    """
    Data-driven base image resolver backed by YAML registry.

    Loads image mappings from a YAML registry and resolves the best
    replacement base image using SBOM inference + registry data.
    Optionally verifies tags against Docker Hub API.
    """

    def __init__(
        self,
        registry_path: Optional[str] = None,
        cache_ttl: int = 3600,
        enable_hub_verification: bool = True
    ):
        """
        Initialize ImageResolver with registry and cache.

        Args:
            registry_path: Path to image_registry.yaml (defaults to same directory)
            cache_ttl: Cache time-to-live in seconds (default 3600 = 1 hour)
            enable_hub_verification: Whether to verify tags on Docker Hub
        """
        self.cache_ttl = cache_ttl
        self.enable_hub_verification = enable_hub_verification
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._hub_token: Optional[str] = None
        self._hub_token_expiry: Optional[float] = None

        # Set default registry path
        if registry_path is None:
            registry_path = os.path.join(
                os.path.dirname(__file__), "image_registry.yaml"
            )

        self.registry_path = registry_path
        self.registry = self._load_registry(registry_path)

        if not self.registry:
            logger.warning(
                f"No registry loaded from {registry_path}. "
                "ImageResolver will use fallback behavior."
            )

        # Check registry staleness
        self._check_registry_staleness()

    def _check_registry_staleness(self) -> None:
        """Check if registry data is stale (older than 6 months)."""
        if not self.registry:
            return

        last_updated = (
            self.registry.get("metadata", {}).get("last_updated")
            or self.registry.get("last_updated")
        )
        if not last_updated:
            logger.warning("Registry has no last_updated timestamp")
            return

        try:
            # Handle partial dates like "2026-03" by appending day
            date_str = str(last_updated)
            if len(date_str) == 7:  # "YYYY-MM"
                date_str += "-01"
            last_updated_dt = datetime.fromisoformat(date_str)
            age = datetime.now() - last_updated_dt
            if age > timedelta(days=180):
                logger.warning(
                    f"Registry is {age.days} days old (last updated {last_updated}). "
                    "Image metadata may be stale."
                )
        except (ValueError, TypeError):
            logger.warning(f"Could not parse registry last_updated: {last_updated}")

    def _load_registry(self, path: str) -> Dict[str, Any]:
        """
        Load and validate YAML registry.

        Args:
            path: Path to image_registry.yaml

        Returns:
            Parsed registry dict, or empty dict if load fails
        """
        if not os.path.exists(path):
            logger.warning(f"Registry file not found: {path}")
            return {}

        try:
            import yaml
        except ImportError:
            logger.error(
                "PyYAML not installed. Cannot load image_registry.yaml. "
                "Install with: pip install pyyaml"
            )
            return {}

        try:
            with open(path, 'r') as f:
                registry = yaml.safe_load(f) or {}
            logger.info(f"Loaded registry from {path}")
            return registry
        except Exception as e:
            logger.error(f"Failed to load registry from {path}: {e}")
            return {}

    def resolve(
        self,
        original_base: str,
        inference: InferenceResultLike
    ) -> Tuple[str, float, Dict[str, Any]]:
        """
        Main entry point: resolve best replacement image.

        Resolution order:
        1. Check if infrastructure image (use _resolve_infrastructure)
        2. If language detected in inference, use _resolve_language
        3. Fall back to _resolve_by_image_name (pattern matching from registry)
        4. Last resort: _resolve_by_os_family

        Args:
            original_base: Original FROM value (e.g., "python:3.8", "ubuntu:20.04")
            inference: InferenceResult with os_family, language, language_version,
                      needs_glibc, variant, confidence, warnings

        Returns:
            Tuple of (new_image, confidence, metadata_dict) where metadata_dict has:
            - strategy_used: Which resolution path was used
            - verified: Whether tag was verified on Docker Hub
            - fallback_used: If true, we fell back to less confident method
            - warnings: List of warning strings
        """
        metadata = {
            "strategy_used": None,
            "verified": False,
            "fallback_used": False,
            "warnings": list(inference.warnings) if hasattr(inference, 'warnings') else []
        }

        original_lower = original_base.lower()
        image_name_part = original_lower.split(":")[0].split("/")[-1]

        # Step 1: Check if infrastructure image
        infra_result = self._resolve_infrastructure(image_name_part)
        if infra_result:
            new_image, confidence = infra_result
            metadata["strategy_used"] = "infrastructure"
            if self.enable_hub_verification:
                metadata["verified"] = self.verify_tag(new_image)
            return new_image, confidence, metadata

        # Step 2: If language detected, use language-based resolution
        language = getattr(inference, 'language', None)
        if language:
            lang_result = self._resolve_language(
                language,
                getattr(inference, 'language_version', None),
                inference,
                original_base
            )
            if lang_result:
                new_image, confidence = lang_result
                metadata["strategy_used"] = "language"
                if self.enable_hub_verification:
                    metadata["verified"] = self.verify_tag(new_image)
                return new_image, confidence, metadata

        # Step 3: Pattern matching on image name
        needs_glibc = getattr(inference, 'needs_glibc', False)
        name_result = self._resolve_by_image_name(original_lower, needs_glibc)
        if name_result:
            new_image, confidence = name_result
            metadata["strategy_used"] = "image_name_pattern"
            metadata["fallback_used"] = True
            if self.enable_hub_verification:
                metadata["verified"] = self.verify_tag(new_image)
            return new_image, confidence, metadata

        # Step 4: OS family only
        os_family = getattr(inference, 'os_family', 'unknown')
        new_image, confidence = self._resolve_by_os_family(os_family, needs_glibc)
        metadata["strategy_used"] = "os_family"
        metadata["fallback_used"] = True
        if self.enable_hub_verification:
            metadata["verified"] = self.verify_tag(new_image)
        return new_image, confidence, metadata

    def _resolve_infrastructure(self, image_name_part: str) -> Optional[Tuple[str, float]]:
        """
        Look up infrastructure (non-language-runtime) image.

        Infrastructure images are databases, web servers, message queues, CI tools,
        and CMS applications. They should not be treated as language runtimes.

        Args:
            image_name_part: Image name without registry/tag (e.g., "postgres", "nginx")

        Returns:
            Tuple of (target_image, 0.85) or None if not found
        """
        if not self.registry:
            return None

        infrastructure = self.registry.get("infrastructure", {})
        if not infrastructure:
            return None

        # Flatten the nested category structure into a flat list of entries
        flat_entries = []
        for category_name, category_data in infrastructure.items():
            if isinstance(category_data, dict):
                # Check if this is a category (has nested image dicts) or a direct entry
                if "patterns" in category_data:
                    # Direct entry at top level
                    flat_entries.append((category_name, category_data))
                else:
                    # Category containing nested image entries
                    for image_key, image_data in category_data.items():
                        if isinstance(image_data, dict) and "patterns" in image_data:
                            flat_entries.append((image_key, image_data))

        # Sort by priority (highest first) to handle substring collisions
        flat_entries.sort(key=lambda x: x[1].get("priority", 0), reverse=True)

        image_name_lower = image_name_part.lower()
        for infra_key, infra_data in flat_entries:
            patterns = infra_data.get("patterns", [])
            for pattern in patterns:
                if pattern in image_name_lower:
                    target = infra_data.get("target")
                    if target:
                        return target, 0.85
        return None

    def _resolve_language(
        self,
        language: str,
        version: Optional[str],
        inference: InferenceResultLike,
        original_base: str
    ) -> Optional[Tuple[str, float]]:
        """
        Resolve based on detected language and version.

        Applies EOL upgrade if needed, chooses tag format based on glibc requirement,
        handles language-specific variants (PHP fpm/apache), and formats tag.
        Optionally verifies tag exists on Docker Hub.

        Args:
            language: Detected language (e.g., "python", "node")
            version: Version string from SBOM (e.g., "3.8", "14.2.0") or None
            inference: Full InferenceResult
            original_base: Original FROM value for context

        Returns:
            Tuple of (image_tag, confidence) or None if resolution fails
        """
        if not self.registry:
            return None

        languages = self.registry.get("languages", {})
        lang_config = languages.get(language.lower())
        if not lang_config:
            return None

        # Start with provided version
        resolved_version = version

        # Apply EOL upgrade if version is end-of-life
        if resolved_version:
            resolved_version = self.upgrade_eol_version(language, resolved_version)

        # If we still don't have a version, try extracting from original tag
        if not resolved_version:
            resolved_version = self._extract_version_from_tag(original_base, language)

        # If still no version, use default from registry
        if not resolved_version:
            resolved_version = lang_config.get("default_version")

        if not resolved_version:
            logger.warning(f"No version available for language {language}")
            return None

        # Choose tag format based on glibc needs
        needs_glibc = getattr(inference, 'needs_glibc', False)
        variant = getattr(inference, 'variant', None)

        tag_formats = lang_config.get("tag_formats", {})
        if needs_glibc:
            tag_template = tag_formats.get("glibc") or tag_formats.get("slim") or tag_formats.get("default")
        else:
            tag_template = tag_formats.get("alpine") or tag_formats.get("slim") or tag_formats.get("default")

        if not tag_template:
            logger.warning(f"No tag format found for language {language}")
            return None

        # Handle language-specific variants (PHP fpm/apache)
        if language.lower() == "php" and variant:
            if variant in ["fpm", "apache"]:
                tag_template = tag_formats.get(f"_{variant}", tag_template)

        # Format the tag: {image}:{version}-{variant}
        try:
            base_image = lang_config.get("image", language)
            image_tag = tag_template.format(
                image=base_image,
                version=resolved_version,
                variant=variant or ""
            ).rstrip("-")
        except (KeyError, ValueError) as e:
            logger.error(f"Failed to format tag for {language}: {e}")
            return None

        # Verify tag exists if enabled
        if self.enable_hub_verification:
            if not self.verify_tag(image_tag):
                logger.warning(f"Tag verification failed for {image_tag}")
                # Still return it but caller can see it wasn't verified
                return image_tag, 0.6

        confidence = 0.7 if resolved_version and version else 0.6
        return image_tag, confidence

    def _resolve_by_image_name(
        self,
        original_lower: str,
        needs_glibc: bool
    ) -> Optional[Tuple[str, float]]:
        """
        Pattern match on image name to find best replacement.

        Iterates over ALL language entries in registry, checks if any pattern
        matches original_lower, extracts version from tag using regex,
        applies EOL upgrade, and builds tag from format templates.

        Args:
            original_lower: Lowercased original FROM value
            needs_glibc: Whether glibc is required

        Returns:
            Tuple of (image_tag, 0.6) or None if no match found
        """
        if not self.registry:
            return None

        languages = self.registry.get("languages", {})
        for lang_name, lang_config in languages.items():
            patterns = lang_config.get("image_name_patterns", [])
            for pattern in patterns:
                if pattern in original_lower:
                    # Found a match
                    version = self._extract_version_from_tag(original_lower, lang_name)
                    if not version:
                        version = lang_config.get("default_version")

                    if not version:
                        continue

                    # Apply EOL upgrade
                    version = self.upgrade_eol_version(lang_name, version)

                    # Get tag format
                    tag_formats = lang_config.get("tag_formats", {})
                    tag_template = tag_formats.get("glibc" if needs_glibc else "alpine")
                    if not tag_template:
                        tag_template = tag_formats.get("slim")

                    if not tag_template:
                        continue

                    try:
                        base_image = lang_config.get("image", lang_name)
                        image_tag = tag_template.format(
                            image=base_image,
                            version=version,
                            variant=""
                        ).rstrip("-")
                        return image_tag, 0.6
                    except (KeyError, ValueError):
                        continue

        return None

    def _resolve_by_os_family(
        self,
        os_family: str,
        needs_glibc: bool
    ) -> Tuple[str, float]:
        """
        Last resort: select base image by OS family only.

        Uses os_bases section of registry to return appropriate base for the
        OS family.

        Args:
            os_family: OS family (e.g., "debian", "alpine", "rhel")
            needs_glibc: Whether glibc is required

        Returns:
            Tuple of (base_image, 0.3)
        """
        if not self.registry:
            # Hardcoded fallback if no registry
            return "ubuntu:22.04" if needs_glibc else "alpine:latest", 0.3

        os_bases = self.registry.get("os_bases", {})
        os_family_lower = (os_family or "unknown").lower()

        # If glibc needed, prefer -slim variants
        if needs_glibc:
            # Try to find slim variant
            for key in [f"{os_family_lower}-slim", "debian-slim", "ubuntu-slim"]:
                if key in os_bases:
                    return os_bases[key], 0.3

        # Otherwise use regular base
        base_image = os_bases.get(os_family_lower)
        if base_image:
            return base_image, 0.3

        # Ultimate fallback
        return os_bases.get("debian", "debian:bookworm"), 0.3

    def verify_tag(self, image_ref: str) -> bool:
        """
        Check if tag exists on Docker Hub via v2 API.

        Uses /v2/library/{name}/tags/list for official images and
        /v2/{namespace}/{name}/tags/list for namespaced images.
        Caches results with TTL.

        Args:
            image_ref: Image reference (e.g., "python:3.11-slim", "node:18-alpine")

        Returns:
            True if tag exists, False if not, True on network error (fail-open)
        """
        # Parse image reference
        if not image_ref:
            return False

        cache_key = self._cache_key("verify_tag", image_ref)
        if self._is_cache_valid(cache_key):
            cached, _ = self._cache[cache_key]
            return cached

        # Split into image name and tag
        if ":" in image_ref:
            image_name, tag = image_ref.rsplit(":", 1)
        else:
            image_name = image_ref
            tag = "latest"

        # Remove registry prefix if present
        if "/" in image_name:
            parts = image_name.split("/")
            if "." in parts[0] or parts[0] == "localhost":
                # Has registry, remove it
                image_name = "/".join(parts[1:])

        # Check if it's a library image (official)
        if "/" not in image_name:
            # Official image
            url = f"https://registry-1.docker.io/v2/library/{image_name}/tags/list"
        else:
            # Namespaced image
            url = f"https://registry-1.docker.io/v2/{image_name}/tags/list"

        try:
            # Get auth token if needed
            token = self._get_hub_token(image_name)
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            response = self._hub_api_get(url, headers)
            if response is None:
                # Network error, fail open
                logger.debug(f"Network error verifying {image_ref}, assuming valid")
                return True

            tags = response.get("tags", [])
            exists = tag in tags

            # Cache result
            self._cache[cache_key] = (exists, datetime.now().timestamp())

            if not exists:
                logger.warning(f"Tag not found on Docker Hub: {image_ref}")

            return exists

        except Exception as e:
            logger.warning(f"Error verifying tag {image_ref}: {e}")
            # Fail open
            return True

    def get_available_tags(self, image_name: str, limit: int = 50) -> List[str]:
        """
        Fetch available tags from Docker Hub for the given image.

        Caches results.

        Args:
            image_name: Image name (e.g., "python", "node")
            limit: Maximum number of tags to return

        Returns:
            List of tag strings
        """
        cache_key = self._cache_key("available_tags", image_name, str(limit))
        if self._is_cache_valid(cache_key):
            cached, _ = self._cache[cache_key]
            return cached

        # Build URL
        if "/" not in image_name:
            url = f"https://registry-1.docker.io/v2/library/{image_name}/tags/list?n={limit}"
        else:
            url = f"https://registry-1.docker.io/v2/{image_name}/tags/list?n={limit}"

        try:
            token = self._get_hub_token(image_name)
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            response = self._hub_api_get(url, headers)
            if response is None:
                return []

            tags = response.get("tags", [])
            self._cache[cache_key] = (tags, datetime.now().timestamp())
            return tags

        except Exception as e:
            logger.error(f"Error fetching tags for {image_name}: {e}")
            return []

    def find_best_version(
        self,
        image_name: str,
        current_version: str,
        language: str
    ) -> Optional[str]:
        """
        Given current version and available tags, find best upgrade.

        Prefers same major branch, falls back to latest stable from registry.
        Uses semver comparison.

        Args:
            image_name: Docker image name (e.g., "python")
            current_version: Current version string (e.g., "3.8")
            language: Language name (e.g., "python")

        Returns:
            Best version string or None
        """
        available = self.get_available_tags(image_name)
        if not available:
            return None

        # Parse current major version
        try:
            current_major = int(current_version.split(".")[0])
        except (ValueError, IndexError):
            return None

        # Find all tags matching the major version
        matching_versions = []
        for tag in available:
            # Extract version from tag (e.g., "3.11-slim" -> "3.11")
            tag_clean = tag.split("-")[0]
            try:
                tag_major = int(tag_clean.split(".")[0])
                if tag_major == current_major:
                    matching_versions.append(tag_clean)
            except (ValueError, IndexError):
                continue

        if matching_versions:
            # Sort and return highest patch version
            matching_versions.sort(key=lambda v: tuple(map(int, v.split("."))))
            return matching_versions[-1]

        # Fallback: check registry for latest stable
        if self.registry:
            langs = self.registry.get("languages", {})
            lang_config = langs.get(language.lower(), {})
            return lang_config.get("default_version")

        return None

    def upgrade_eol_version(self, language: str, version: str) -> str:
        """
        Check registry for EOL version and upgrade if needed.

        Checks registry eol_versions section. Also checks staleness of registry data.

        Args:
            language: Language name (e.g., "python")
            version: Version string (e.g., "3.8")

        Returns:
            Upgraded version or original if not EOL
        """
        if not self.registry:
            return version

        languages = self.registry.get("languages", {})
        lang_config = languages.get(language.lower(), {})
        eol_versions = lang_config.get("eol_versions", {})

        upgraded = eol_versions.get(version)
        if upgraded:
            logger.info(f"EOL version {language}:{version} upgraded to {upgraded}")
            return upgraded

        return version

    def get_package_migration(self, from_os: str, to_os: str) -> Optional[Dict[str, str]]:
        """
        Get package name mapping for OS migration.

        Returns package name mapping for OS migration (e.g., apt packages to apk packages).
        Uses package_managers section of registry.

        Args:
            from_os: Source OS family (e.g., "debian")
            to_os: Target OS family (e.g., "alpine")

        Returns:
            Dict mapping from_package -> to_package, or None if not found
        """
        if not self.registry:
            return None

        pm_section = self.registry.get("package_managers", {})

        # Map OS families to package manager names
        os_to_pm = {
            "debian": "apt", "ubuntu": "apt",
            "alpine": "apk",
            "centos": "yum", "rhel": "yum", "rocky": "dnf",
            "alma": "dnf", "fedora": "dnf",
        }

        from_pm = os_to_pm.get(from_os.lower())
        to_pm = os_to_pm.get(to_os.lower())

        if not from_pm or not to_pm:
            logger.warning(f"No package manager mapping for {from_os} -> {to_os}")
            return None

        migration_key = f"{from_pm}_to_{to_pm}"
        return pm_section.get(migration_key)

    def _extract_version_from_tag(self, tag_lower: str, language: str) -> Optional[str]:
        """
        Extract version number from docker tag string.

        Handles language-specific patterns (node uses major only, python uses major.minor).

        Args:
            tag_lower: Lowercased tag string (e.g., "python:3.8-slim")
            language: Language name for pattern matching

        Returns:
            Version string or None
        """
        # Remove everything after last colon to get base image
        if ":" in tag_lower:
            tag_part = tag_lower.rsplit(":", 1)[1]
        else:
            tag_part = tag_lower

        # Remove variant suffixes
        tag_part = re.sub(r'-(slim|alpine|bookworm|bullseye|stretch).*$', '', tag_part)

        # Language-specific extraction patterns
        patterns = {
            "python": r'^(\d+\.\d+)',
            "node": r'^(\d+)',
            "golang": r'^(\d+\.\d+)',
            "ruby": r'^(\d+\.\d+)',
            "php": r'^(\d+\.\d+)',
            "openjdk": r'^(\d+)',
        }

        pattern = patterns.get(language.lower(), r'^(\d+(?:\.\d+)*)')
        match = re.match(pattern, tag_part)
        if match:
            return match.group(1)

        return None

    def _normalize_version(self, version: str, language: str) -> str:
        """
        Normalize version to appropriate format for the language.

        Uses version_style from registry (major_only vs major_minor).

        Args:
            version: Raw version string
            language: Language name

        Returns:
            Normalized version string
        """
        if not self.registry:
            return version

        languages = self.registry.get("languages", {})
        lang_config = languages.get(language.lower(), {})
        version_style = lang_config.get("version_style", "major_minor")

        parts = version.split(".")
        if version_style == "major_only" and len(parts) >= 1:
            return parts[0]
        elif version_style == "major_minor" and len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"

        return version

    def _hub_api_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Cached Docker Hub API call with error handling.

        Args:
            url: Full API URL
            headers: Optional HTTP headers (including auth)

        Returns:
            Parsed JSON response or None on error
        """
        cache_key = self._cache_key("hub_api", url)
        if self._is_cache_valid(cache_key):
            cached, _ = self._cache[cache_key]
            return cached

        try:
            if headers is None:
                headers = {}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            self._cache[cache_key] = (data, datetime.now().timestamp())
            return data
        except requests.RequestException as e:
            logger.debug(f"Hub API request failed for {url}: {e}")
            return None
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug(f"Failed to parse Hub API response: {e}")
            return None

    def _get_hub_token(self, image: str) -> Optional[str]:
        """
        Get Docker Hub authentication token.

        Fetches anonymous token from auth.docker.io for pulling images.
        Handles both official (library) and namespaced images.

        Args:
            image: Image name (e.g., "python" or "grafana/grafana")

        Returns:
            Auth token string or None
        """
        # Check if token is still valid in cache
        if self._hub_token and self._hub_token_expiry:
            if datetime.now().timestamp() < self._hub_token_expiry:
                return self._hub_token

        # Determine scope
        if "/" in image:
            scope = f"repository:{image}:pull"
        else:
            scope = f"repository:library/{image}:pull"

        try:
            url = "https://auth.docker.io/token"
            params = {
                "service": "registry.docker.io",
                "scope": scope
            }
            response = requests.get(
                url,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            self._hub_token = data.get("token")
            # Tokens typically valid for a few minutes, cache for 5 minutes
            self._hub_token_expiry = datetime.now().timestamp() + 300
            return self._hub_token
        except Exception as e:
            logger.debug(f"Failed to get Hub token: {e}")
            return None

    def _cache_key(self, *args: str) -> str:
        """
        Generate cache key from arguments.

        Args:
            *args: Components to hash

        Returns:
            Hex string cache key
        """
        combined = ":".join(str(arg) for arg in args)
        return hashlib.md5(combined.encode()).hexdigest()

    def _is_cache_valid(self, key: str) -> bool:
        """
        Check if cached entry is still valid (within TTL).

        Args:
            key: Cache key

        Returns:
            True if entry exists and is valid
        """
        if key not in self._cache:
            return False

        _, timestamp = self._cache[key]
        age = datetime.now().timestamp() - timestamp
        return age < self.cache_ttl
