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

from .constants import RESOLVER_CACHE_TTL_SECONDS

logger = logging.getLogger("docker_patch_tool")

# A registry value is usable as a FROM reference only if it looks like
# one. os_bases carries documentation strings alongside real tags
# ("Immutable OS - use AWS SSM for updates"), and nothing downstream
# validates what the resolver returns.
_IMAGE_REF_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*"           # first path component
    r"(?:[/][a-z0-9]+(?:[._-][a-z0-9]+)*)*"    # further components
    r"(?::[\w][\w.-]*)?(?:@sha256:[a-f0-9]{64})?$"
)


def _looks_like_image_ref(value: str) -> bool:
    """True if ``value`` is plausibly an OCI image reference."""
    v = (value or "").strip()
    # A space is the giveaway for prose; no valid reference contains one.
    return bool(v) and " " not in v and bool(_IMAGE_REF_RE.match(v.lower()))


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
        cache_ttl: int = RESOLVER_CACHE_TTL_SECONDS,
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
        # Per-scope token cache. Hub issues a Bearer token bound to a
        # specific repository:<repo>:pull scope; a token cached for one
        # repo cannot be reused against another. Map scope -> (token,
        # expiry_epoch).
        self._hub_tokens: Dict[str, Tuple[str, float]] = {}

        # One pooled session for every registry call. Without it each
        # tag check pays a fresh TLS handshake, which dominates
        # wall-clock on a corpus that shares base repositories. Retries
        # cover the transient status codes a registry emits under load;
        # `respect_retry_after_header` honours rate-limit backoff
        # instead of hammering through it.
        self._session = requests.Session()
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            retry = Retry(
                total=3,
                backoff_factor=1.5,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD"]),
                respect_retry_after_header=True,
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry,
                                  pool_connections=8, pool_maxsize=16)
            self._session.mount("https://", adapter)
            self._session.mount("http://", adapter)
        except Exception as e:  # pragma: no cover - urllib3 API drift
            logger.debug("registry retry adapter unavailable: %s", e)
        self._session.headers.update({"User-Agent": "AutoPatch/1.0"})

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
        except FileNotFoundError:
            logger.warning(
                "image_registry.yaml not found at %s; resolver will fall back "
                "to OS-only selection.", path,
            )
            return {}
        except yaml.YAMLError as e:
            # A malformed registry must NOT be silently treated as empty:
            # it would disable image selection across the entire run with
            # no obvious diagnostic. Re-raise wrapped so callers see it.
            raise RuntimeError(
                f"image_registry.yaml is malformed at {path}: {e}. "
                f"Fix the YAML or move the file aside; refusing to silently "
                f"disable the resolver."
            ) from e
        if not isinstance(registry, dict):
            raise RuntimeError(
                f"image_registry.yaml top level must be a mapping; got "
                f"{type(registry).__name__} from {path}."
            )
        logger.info(f"Loaded registry from {path}")
        return registry

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
                # `image_name_part` arrives with the tag already
                # stripped, so a registry pattern written with a
                # trailing colon (the `registry:` entry is the one in
                # the shipped file, spelled that way to avoid matching
                # every reference containing the word "registry") could
                # never match anything and the entry was inert.
                # Comparing against the colon-stripped pattern keeps the
                # author's disambiguating intent by anchoring it to the
                # END of the name instead.
                pat = pattern.lower()
                if pat.endswith(":"):
                    stem = pat[:-1]
                    matched = (image_name_lower == stem
                               or image_name_lower.endswith("/" + stem))
                else:
                    matched = pat in image_name_lower
                if matched:
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
            # The registry field is `current_stable`; `default_version`
            # does not exist in it, so a bare `FROM rust` fell through
            # to the generic OS-family default instead of resolving to
            # the current stable runtime.
            resolved_version = (lang_config.get("current_stable")
                                or lang_config.get("default_version"))

        if not resolved_version:
            logger.warning(f"No version available for language {language}")
            return None

        # Choose tag format based on glibc needs
        needs_glibc = getattr(inference, 'needs_glibc', False)
        variant = getattr(inference, 'variant', None)

        tag_formats = lang_config.get("tag_formats", {})
        if needs_glibc:
            # Prefer the slim variant over the full one. Both satisfy
            # the glibc constraint, but a full Debian runtime ships
            # roughly a hundred more OS packages than its -slim sibling
            # at the same version, and each of those packages carries
            # its own CVE rows. Selecting "glibc" (full) first therefore
            # gave up a large, free reduction on every glibc target.
            tag_template = (tag_formats.get("slim")
                            or tag_formats.get("glibc")
                            or tag_formats.get("default"))
        else:
            tag_template = (tag_formats.get("alpine")
                            or tag_formats.get("slim")
                            or tag_formats.get("default"))

        if not tag_template:
            logger.warning(f"No tag format found for language {language}")
            return None

        # Handle language-specific variants (PHP fpm/apache). The registry
        # keys are "apache"/"fpm" (no underscore), so look them up directly.
        if language.lower() == "php" and variant:
            if variant in ["fpm", "apache"]:
                tag_template = tag_formats.get(variant, tag_template)

        # Preserve JDK for Java build images: a jre has no javac/maven, so a
        # builder (mvn/gradle) must not be rewritten to a jre-only image.
        if language.lower() == "openjdk" and variant == "jdk":
            jdk_key = "_jdk_alpine" if not needs_glibc else "_jdk"
            tag_template = tag_formats.get(jdk_key) or tag_formats.get("_jdk", tag_template)

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
            # The registry spells this field `patterns`. Reading
            # `image_name_patterns` matched nothing in the shipped
            # image_registry.yaml, which made this entire resolution
            # step (step 3 of resolve()) unreachable for every input.
            # `image_name_patterns` is still accepted so an operator's
            # custom registry using the old spelling keeps working.
            patterns = (lang_config.get("patterns")
                        or lang_config.get("image_name_patterns")
                        or [])
            for pattern in patterns:
                if pattern in original_lower:
                    # Found a match
                    version = self._extract_version_from_tag(original_lower, lang_name)
                    if not version:
                        version = (lang_config.get("current_stable")
                                   or lang_config.get("default_version"))

                    if not version:
                        continue

                    # Apply EOL upgrade
                    version = self.upgrade_eol_version(lang_name, version)

                    # Get tag format
                    tag_formats = lang_config.get("tag_formats", {})
                    # The registry defines `default` and `alpine`. Asking
                    # for `glibc` missed every entry, so even with the
                    # pattern key corrected the glibc branch produced
                    # nothing. `glibc` is kept as an alias for custom
                    # registries that use it.
                    tag_template = (
                        (tag_formats.get("default") or tag_formats.get("glibc"))
                        if needs_glibc else tag_formats.get("alpine")
                    ) or tag_formats.get("default")
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

        def _pick(entry):
            """Each os_bases entry is a {libc: tag} dict in the YAML
            registry. Pick the right tag, preferring glibc when the
            caller needs it; fall back to musl, then any value, and
            finally a hardcoded debian:bookworm last resort."""
            if isinstance(entry, str):
                # Legacy registry format with a bare string tag.
                return entry
            if not isinstance(entry, dict):
                return None
            # ONLY the libc keys hold image references. The final
            # `next(iter(entry.values()))` fallback used to accept any
            # value in the mapping, and several os_bases entries carry
            # documentation instead of a tag, so
            # _resolve_by_os_family("bottlerocket", True) returned the
            # string "Immutable OS - use AWS SSM for updates" as an
            # image name with confidence 0.3. Nothing downstream
            # validates that, so it was one short-circuit away from
            # being emitted as a FROM line.
            picked = (entry.get("glibc") or entry.get("musl")) if needs_glibc \
                else (entry.get("musl") or entry.get("glibc"))
            if picked and _looks_like_image_ref(picked):
                return picked
            return None

        # If glibc needed, prefer -slim variants
        if needs_glibc:
            for key in [f"{os_family_lower}-slim", "debian-slim", "ubuntu-slim"]:
                if key in os_bases:
                    picked = _pick(os_bases[key])
                    if picked:
                        return picked, 0.3

        # Otherwise use regular base for the OS family
        entry = os_bases.get(os_family_lower)
        if entry is not None:
            picked = _pick(entry)
            if picked:
                return picked, 0.3

        # Ultimate fallback
        debian_entry = os_bases.get("debian")
        picked = _pick(debian_entry) if debian_entry is not None else None
        return picked or "debian:bookworm", 0.3

    def verify_tag(self, image_ref: str, fail_open: bool = False) -> bool:
        """
        Check if tag exists on Docker Hub via v2 API.

        Uses /v2/library/{name}/tags/list for official images and
        /v2/{namespace}/{name}/tags/list for namespaced images.
        Caches results with TTL.

        Args:
            image_ref: Image reference (e.g., "python:3.11-slim", "node:18-alpine")
            fail_open: If True, network/registry errors return True
                (preserves legacy behavior). Default False: a registry
                that we cannot reach is treated as a verification
                failure so the pipeline never commits to rewriting to
                an unverifiable tag.

        Returns:
            True if tag is verified present. False if the tag does not
            exist, OR (when fail_open is False) if the registry call
            failed.
        """
        # Parse image reference
        if not image_ref:
            return False

        cache_key = self._cache_key("verify_tag", image_ref)
        if self._is_cache_valid(cache_key):
            cached, _ = self._cache[cache_key]
            return cached

        # Split into image name and tag. A digest reference pins the
        # content directly and needs no tag lookup.
        if "@" in image_ref:
            return True
        if ":" in image_ref.rsplit("/", 1)[-1]:
            image_name, tag = image_ref.rsplit(":", 1)
        else:
            image_name = image_ref
            tag = "latest"

        try:
            # Full, paginated listing against the reference's OWN
            # registry. The previous implementation stripped the
            # registry host and queried Docker Hub for every reference,
            # so gcr.io/distroless and cgr.dev/chainguard candidates
            # 404ed and were rejected by the fail-closed path below;
            # those are precisely the lowest-CVE targets available.
            # Route through get_available_tags, NOT _list_all_tags.
            #
            # verify_tag is called once per candidate, and candidates for
            # one image share a repository: verifying python:3.11-slim,
            # 3.12-slim, 3.13-slim and 3.13 issued four independent
            # paginated walks of the python repository. That repository
            # has thousands of tags, so each walk is several HTTP round
            # trips, and a 100-Dockerfile corpus run generated enough
            # traffic to hit Docker Hub's anonymous rate limit. The
            # resulting 429s made _list_all_tags return partial or empty
            # lists, verify_tag failed closed, and valid upgrades were
            # rejected: a performance defect that presented as a
            # correctness defect. get_available_tags memoises the
            # listing per repository for cache_ttl.
            tags = self.get_available_tags(image_name)
            if not tags:
                # Registry unreachable or repository absent. Fail CLOSED
                # by default so we never silently commit to a tag we
                # could not verify. Operators that explicitly want the
                # old fail-open behavior (e.g. for offline
                # cache-warming) can pass fail_open=True.
                if fail_open:
                    logger.warning(
                        f"verify_tag({image_ref}): registry unreachable, "
                        f"fail_open=True -> assuming valid"
                    )
                    return True
                logger.warning(
                    f"verify_tag({image_ref}): registry unreachable or "
                    f"repository absent, failing closed"
                )
                return False

            exists = tag in tags

            # Cache result
            self._cache[cache_key] = (exists, datetime.now().timestamp())

            if not exists:
                logger.warning(
                    f"Tag not found in registry: {image_ref} "
                    f"({len(tags)} tags listed)"
                )

            return exists

        except Exception as e:
            # Registry errors are also fail-closed by default. See
            # docstring for the fail_open escape hatch.
            if fail_open:
                logger.warning(
                    f"verify_tag({image_ref}): {type(e).__name__}: {e}; "
                    f"fail_open=True -> assuming valid"
                )
                return True
            logger.warning(
                f"verify_tag({image_ref}): {type(e).__name__}: {e}; "
                f"failing closed"
            )
            return False

    def get_available_tags(self, image_name: str,
                           limit: Optional[int] = None) -> List[str]:
        """
        Fetch available tags for the given image from its registry.

        Follows pagination and routes to the correct registry host, so
        non-Hub references (gcr.io/distroless, cgr.dev/chainguard,
        quay.io) resolve instead of 404ing against Docker Hub. Results
        are cached for ``cache_ttl``.

        Args:
            image_name: Image reference without tag. May include a
                registry host, e.g. "python", "grafana/grafana", or
                "gcr.io/distroless/base-debian12".
            limit: Optional cap on the number of tags returned. The cap
                is applied *after* the full listing is retrieved, so a
                newer release is never lost merely because it sorts
                late on the registry's first page.

        Returns:
            List of tag strings (possibly empty).
        """
        cache_key = self._cache_key("available_tags", image_name)
        if self._is_cache_valid(cache_key):
            cached, _ = self._cache[cache_key]
            return list(cached[:limit]) if limit else list(cached)

        try:
            tags = self._list_all_tags(image_name)
        except Exception as e:
            logger.error(f"Error fetching tags for {image_name}: {e}")
            return []

        if not tags:
            # Negatively cache for a short window so a corpus run does
            # not re-attempt a repository that does not resolve, while
            # still recovering from a transient outage well inside the
            # normal TTL.
            self._cache[cache_key] = (
                [], datetime.now().timestamp() - self.cache_ttl + 120
            )
            return []

        self._cache[cache_key] = (tags, datetime.now().timestamp())
        return list(tags[:limit]) if limit else list(tags)

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
            # Sort and return the highest patch version.
            #
            # The key used to be `tuple(map(int, v.split(".")))`, and
            # Docker Hub publishes prerelease tags such as "3.13.0rc1".
            # The major filter above accepts those (int("3") succeeds),
            # so the ValueError from int("0rc1") escaped find_best_version
            # entirely and took down the resolution path, rather than
            # skipping one unparseable tag the way the filter does.
            def _version_key(v: str):
                parts = []
                for component in v.split("."):
                    try:
                        parts.append(int(component))
                    except ValueError:
                        return None      # prerelease or junk: not comparable
                return tuple(parts)

            comparable = [(k, v) for k, v in
                          ((_version_key(v), v) for v in matching_versions)
                          if k is not None]
            if not comparable:
                return None
            comparable.sort(key=lambda kv: kv[0])
            return comparable[-1][1]

        # Fallback: check registry for latest stable
        if self.registry:
            langs = self.registry.get("languages", {})
            lang_config = langs.get(language.lower(), {})
            return (lang_config.get("current_stable")
                    or lang_config.get("default_version"))

        return None

    def upgrade_eol_version(self, language: str, version: str) -> str:
        """
        Check registry for EOL version and upgrade if needed.

        Checks registry eol_versions section. Also checks staleness of registry data.

        Args:
            language: Language name (e.g., "python")
            version: Version string (e.g., "3.8")

        Returns:
            Upgraded version or original if not EOL.

        Honours the same ``--eol-upgrade`` gate the patcher uses. There
        were two independent EOL paths: ``patcher._upgrade_eol_version``
        checked ``_EOL_UPGRADE_ACTIVE`` (so an operator-pinned tag was
        preserved by default, as the flag's documentation promises)
        while this one did not. Whether a pinned version survived
        therefore depended on which resolution strategy happened to
        win, which is not a decision the operator can predict or
        control. Reading the same toggle makes the documented default
        actually hold.
        """
        if not self.registry:
            return version

        try:
            from .patcher import _EOL_UPGRADE_ACTIVE
        except Exception:      # pragma: no cover - circular-import guard
            _EOL_UPGRADE_ACTIVE = False
        if not _EOL_UPGRADE_ACTIVE:
            logger.debug(
                "EOL upgrade for %s:%s skipped; operator-pinned versions are "
                "preserved unless --eol-upgrade is set.", language, version,
            )
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
            response = self._session.get(url, headers=headers, timeout=10)
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

    # ── Registry routing ────────────────────────────────────────────
    #
    # A reference such as "gcr.io/distroless/base-debian12" names a
    # registry that is not Docker Hub. Stripping the host and querying
    # registry-1.docker.io for "distroless/base-debian12" 404s, and
    # because tag verification fails closed, the candidate is rejected.
    # Distroless and Chainguard images are the lowest-CVE targets
    # available, so misrouting them suppresses exactly the
    # transformations that would reduce vulnerabilities most.

    # Hosts whose token endpoint and API root differ from Docker Hub.
    _REGISTRY_ENDPOINTS: Dict[str, Dict[str, str]] = {
        "gcr.io": {
            "api": "https://gcr.io/v2",
            "token": "https://gcr.io/v2/token",
            "service": "gcr.io",
        },
        "ghcr.io": {
            "api": "https://ghcr.io/v2",
            "token": "https://ghcr.io/token",
            "service": "ghcr.io",
        },
        "quay.io": {
            "api": "https://quay.io/v2",
            "token": "https://quay.io/v2/auth",
            "service": "quay.io",
        },
        "cgr.dev": {
            "api": "https://cgr.dev/v2",
            "token": "https://cgr.dev/token",
            "service": "cgr.dev",
        },
        "registry.k8s.io": {
            "api": "https://registry.k8s.io/v2",
            "token": "https://registry.k8s.io/v2/token",
            "service": "registry.k8s.io",
        },
        "mcr.microsoft.com": {
            "api": "https://mcr.microsoft.com/v2",
            "token": "",          # anonymous, no token endpoint
            "service": "",
        },
        "public.ecr.aws": {
            "api": "https://public.ecr.aws/v2",
            "token": "https://public.ecr.aws/token",
            "service": "public.ecr.aws",
        },
    }

    @staticmethod
    def _split_registry(image_name: str) -> Tuple[str, str]:
        """Split a reference into ``(registry_host, repository_path)``.

        A leading component is a registry host only when it contains a
        dot or a colon, or is exactly ``localhost``; this is the same
        rule the OCI distribution spec uses to tell ``myorg/app`` from
        ``registry.example.com/app``. Docker Hub is returned as an
        empty host so callers can apply the ``library/`` prefix rule.
        """
        if "/" not in image_name:
            return "", image_name
        head, _, rest = image_name.partition("/")
        if "." in head or ":" in head or head == "localhost":
            return head, rest
        return "", image_name

    def _registry_for(self, image_name: str) -> Tuple[str, str, Optional[Dict[str, str]]]:
        """Return ``(api_root, repository_path, endpoint_cfg)``.

        ``endpoint_cfg`` is None for Docker Hub, where the existing
        token flow applies.
        """
        host, repo = self._split_registry(image_name)
        if not host or host in ("docker.io", "index.docker.io",
                                "registry-1.docker.io"):
            # Docker Hub: official images live under library/.
            if "/" not in repo:
                repo = f"library/{repo}"
            return "https://registry-1.docker.io/v2", repo, None
        cfg = self._REGISTRY_ENDPOINTS.get(host)
        if cfg is None:
            # Unknown host: address it directly rather than silently
            # rewriting the request to Docker Hub.
            return f"https://{host}/v2", repo, {
                "api": f"https://{host}/v2",
                "token": f"https://{host}/token",
                "service": host,
            }
        return cfg["api"], repo, cfg

    def _invalidate_token(
        self, repo: str, cfg: Optional[Dict[str, str]], image_name: str
    ) -> None:
        """Drop the cached bearer token for this repository.

        Needed because the token cache keys on ``expires_in``, and a
        registry may reject a token before that deadline (clock skew,
        server-side revocation, a rotated signing key). Without an
        explicit invalidation the 401 retry re-reads the same dead token
        from the cache and 401s again.
        """
        if cfg:
            scope = f"repository:{repo}:pull"
            self._hub_tokens.pop(
                f"regtoken::{cfg.get('service', '')}::{scope}", None)
        else:
            hub_scope = (
                f"repository:{image_name}:pull" if "/" in image_name
                else f"repository:library/{image_name}:pull"
            )
            self._hub_tokens.pop(hub_scope, None)

    def _registry_token(self, repo: str, cfg: Dict[str, str]) -> Optional[str]:
        """Fetch an anonymous pull token from a non-Hub registry."""
        token_url = cfg.get("token") or ""
        if not token_url:
            return None
        scope = f"repository:{repo}:pull"
        cache_key = f"regtoken::{cfg.get('service', '')}::{scope}"
        cached = self._hub_tokens.get(cache_key)
        if cached:
            token, expiry = cached
            if datetime.now().timestamp() < expiry - 5:
                return token
        try:
            params = {"scope": scope}
            if cfg.get("service"):
                params["service"] = cfg["service"]
            resp = self._session.get(token_url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            token = data.get("token") or data.get("access_token")
            if not token:
                return None
            ttl = int(data.get("expires_in", 300) or 300)
            self._hub_tokens[cache_key] = (
                token, datetime.now().timestamp() + ttl
            )
            return token
        except (requests.RequestException, ValueError, TypeError) as e:
            logger.debug("token fetch failed for %s: %s", repo, e)
            return None

    def _list_all_tags(self, image_name: str,
                       max_pages: int = 20) -> List[str]:
        """Return every tag for ``image_name``, following pagination.

        The OCI distribution spec paginates ``/tags/list`` and signals
        the next page in an RFC 5988 ``Link`` header. A single
        unpaginated request returns the registry's default page in
        lexical order, so for a repository with thousands of tags the
        newest release is frequently absent: ``3.13-slim`` simply is
        not on page one. Every such miss is a rejected upgrade, because
        tag verification fails closed.
        """
        api_root, repo, cfg = self._registry_for(image_name)

        def _mint_token() -> Optional[str]:
            return (self._registry_token(repo, cfg) if cfg
                    else self._get_hub_token(image_name))

        token = _mint_token()
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        tags: List[str] = []
        url: Optional[str] = f"{api_root}/{repo}/tags/list?n=1000"
        pages = 0
        reauthed = False
        while url and pages < max_pages:
            pages += 1
            try:
                resp = self._session.get(url, headers=headers, timeout=15)
                # Registry bearer tokens are short-lived (Docker Hub
                # issues 300s). A repository with thousands of tags takes
                # more than one token lifetime to page through, so the
                # token expired mid-listing and every remaining page
                # 401ed. The loop then broke with a PARTIAL tag list,
                # and because verify_tag fails closed on a missing tag,
                # a perfectly valid upgrade target was rejected purely
                # because it sorted onto a late page. Re-mint once and
                # retry the same page.
                if resp.status_code == 401 and not reauthed:
                    reauthed = True
                    self._invalidate_token(repo, cfg, image_name)
                    token = _mint_token()
                    if token:
                        headers = {"Authorization": f"Bearer {token}"}
                        logger.debug(
                            "tag listing for %s got 401 on page %d; "
                            "re-authenticated and retrying",
                            image_name, pages,
                        )
                        pages -= 1          # the retry is not a new page
                        continue
                resp.raise_for_status()
                payload = resp.json()
            except (requests.RequestException, ValueError) as e:
                logger.debug("tag listing failed for %s at %s: %s",
                             image_name, url, e)
                break
            reauthed = False   # a good page resets the one-shot budget
            page_tags = payload.get("tags") or []
            tags.extend(t for t in page_tags if isinstance(t, str))

            link = resp.headers.get("Link") or resp.headers.get("link")
            url = None
            if link and 'rel="next"' in link:
                start = link.find("<")
                end = link.find(">", start + 1)
                if start != -1 and end != -1:
                    nxt = link[start + 1:end]
                    url = (nxt if nxt.startswith("http")
                           else f"{api_root.rsplit('/v2', 1)[0]}{nxt}")
        if pages >= max_pages:
            logger.debug("tag listing for %s stopped at the %d-page cap",
                         image_name, max_pages)
        return tags

    def _get_hub_token(self, image: str) -> Optional[str]:
        """
        Get a Docker Hub Bearer token scoped to the given repository.

        Each Hub token is valid for ONE ``repository:<repo>:pull``
        scope; reusing a token across different repos produces 401s
        because the embedded scope doesn't match. Cache per scope and
        honour the registry's ``expires_in`` so we refresh on the real
        boundary rather than a hard-coded 5 minutes.

        Args:
            image: Image name (e.g. "python" or "grafana/grafana").

        Returns:
            Auth token string or None on error.
        """
        scope = (
            f"repository:{image}:pull"
            if "/" in image
            else f"repository:library/{image}:pull"
        )

        cached = self._hub_tokens.get(scope)
        if cached:
            token, expiry = cached
            # Refresh slightly before actual expiry to dodge clock skew.
            if datetime.now().timestamp() < expiry - 5:
                return token

        try:
            response = requests.get(
                "https://auth.docker.io/token",
                params={"service": "registry.docker.io", "scope": scope},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
            token = data.get("token")
            if not token:
                return None
            # Hub returns expires_in (seconds). Fall back to 300 if absent.
            try:
                ttl = float(data.get("expires_in") or 300)
            except (TypeError, ValueError):
                ttl = 300.0
            self._hub_tokens[scope] = (token, datetime.now().timestamp() + ttl)
            return token
        except Exception as e:
            logger.debug(f"Failed to get Hub token for scope {scope}: {e}")
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
