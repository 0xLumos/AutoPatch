#!/usr/bin/env python3
"""
Declarative per-image runtime-validation manifests.

The manifest is the artifact a reviewer needs in order to reproduce
the runtime-validation results: it states, for every evaluated image,
exactly which startup hold, introspection policy, and application
probe were used. It is published alongside the dataset (see the paper's
Data Availability section).

Manifest format (YAML), one file per corpus or a single combined file:

    version: 1
    defaults:
      startup_hold_s: 10
      introspect: true
      network: none
      read_only_rootfs: true

    images:
      "nginx:1.20":
        network: bridge
        published_port: 80
        app_command: ["sh", "-c", "wget -qO- http://127.0.0.1:80/ >/dev/null"]

      "postgres:13":
        network: bridge
        env:
          POSTGRES_PASSWORD: validation
        startup_hold_s: 20
        app_command: ["pg_isready", "-U", "postgres"]

      "golang:1.19-alpine":
        introspect: true          # `go version` responds to --version
        app_command: null         # no application probe

      "some/legacy-image:1.0":
        enabled: false            # runtime validation intentionally skipped
        skip_reason: "requires external database not present in harness"

Resolution order for each field: per-image value, then manifest
``defaults``, then the module-level defaults in
:mod:`src.runtime_validator`.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .runtime_validator import (
    DEFAULT_APP_TIMEOUT_S,
    DEFAULT_INTROSPECT_FLAGS,
    DEFAULT_INTROSPECT_TIMEOUT_S,
    DEFAULT_STARTUP_HOLD_S,
    DEFAULT_STARTUP_TIMEOUT_S,
    SmokeSpec,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


class ManifestError(ValueError):
    """Raised when a manifest is structurally invalid. Validation is
    strict on purpose: a typo in a probe command would otherwise
    silently downgrade a tier to SKIP and inflate the reported
    pass rate."""


def _coerce_command(value: Any, image: str) -> Optional[List[str]]:
    """Application probes must be exec-form (a list of argv tokens).
    A bare string is accepted and split with shlex, but a dict or a
    nested list is rejected."""
    if value is None:
        return None
    if isinstance(value, str):
        import shlex
        parts = shlex.split(value)
        if not parts:
            raise ManifestError(f"{image}: empty app_command string")
        return parts
    if isinstance(value, list):
        if not value:
            return None
        if not all(isinstance(x, str) for x in value):
            raise ManifestError(
                f"{image}: app_command list must contain only strings"
            )
        return list(value)
    raise ManifestError(
        f"{image}: app_command must be a string or list of strings, "
        f"got {type(value).__name__}"
    )


def _spec_from_mapping(
    image: str,
    entry: Mapping[str, Any],
    defaults: Mapping[str, Any],
) -> SmokeSpec:
    def pick(key: str, fallback: Any) -> Any:
        if key in entry:
            return entry[key]
        if key in defaults:
            return defaults[key]
        return fallback

    network = str(pick("network", "none"))
    if network not in {"none", "bridge", "host"}:
        raise ManifestError(
            f"{image}: network must be none|bridge|host, got {network!r}"
        )

    app_command = _coerce_command(pick("app_command", None), image)

    # An application probe cannot work with --network none unless it
    # only touches the filesystem. We do not try to guess; we warn.
    if app_command and network == "none":
        probe = " ".join(app_command).lower()
        if any(tok in probe for tok in ("curl", "wget", "http://",
                                        "nc ", "pg_isready", "redis-cli")):
            logger.warning(
                "%s: application probe looks network-dependent but "
                "network is 'none'; set network: bridge if the probe "
                "needs a socket", image,
            )

    port = pick("published_port", None)
    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ManifestError(f"{image}: published_port must be an integer")

    env_raw = pick("env", {}) or {}
    if not isinstance(env_raw, Mapping):
        raise ManifestError(f"{image}: env must be a mapping")
    env = {str(k): str(v) for k, v in env_raw.items()}

    flags = pick("introspect_flags", None)
    if flags is None:
        introspect_flags = DEFAULT_INTROSPECT_FLAGS
    elif isinstance(flags, list) and all(isinstance(f, str) for f in flags):
        introspect_flags = tuple(flags)
    else:
        raise ManifestError(
            f"{image}: introspect_flags must be a list of strings"
        )

    return SmokeSpec(
        enabled=bool(pick("enabled", True)),
        startup_hold_s=int(pick("startup_hold_s", DEFAULT_STARTUP_HOLD_S)),
        startup_timeout_s=int(pick("startup_timeout_s",
                                   DEFAULT_STARTUP_TIMEOUT_S)),
        introspect=bool(pick("introspect", True)),
        introspect_flags=introspect_flags,
        introspect_timeout_s=int(pick("introspect_timeout_s",
                                      DEFAULT_INTROSPECT_TIMEOUT_S)),
        app_command=app_command,
        app_timeout_s=int(pick("app_timeout_s", DEFAULT_APP_TIMEOUT_S)),
        network=network,
        published_port=port,
        env=env,
        entrypoint_override=pick("entrypoint", None),
        read_only_rootfs=bool(pick("read_only_rootfs", True)),
    )


class SmokeManifest:
    """Loaded manifest with per-image spec lookup."""

    def __init__(
        self,
        specs: Dict[str, SmokeSpec],
        defaults: Mapping[str, Any],
        skip_reasons: Optional[Dict[str, str]] = None,
    ) -> None:
        self._specs = specs
        self._defaults = dict(defaults)
        self.skip_reasons = skip_reasons or {}

    def __len__(self) -> int:
        return len(self._specs)

    def __contains__(self, image: str) -> bool:
        return image in self._specs

    @property
    def images(self) -> List[str]:
        return sorted(self._specs)

    def spec_for(self, image_ref: str) -> SmokeSpec:
        """Return the spec for ``image_ref``.

        Lookup is exact first, then by repository (dropping the tag),
        then falls back to a defaults-only spec so that an image absent
        from the manifest still receives Tier 1 and Tier 2 validation.
        """
        if image_ref in self._specs:
            return self._specs[image_ref]
        repo = image_ref.split("@", 1)[0].rsplit(":", 1)[0]
        if repo in self._specs:
            return self._specs[repo]
        return _spec_from_mapping(image_ref, {}, self._defaults)

    @property
    def application_probe_count(self) -> int:
        """How many images declare a Tier-3 probe. The paper reports
        this so the Tier-3 pass rate has a stated denominator."""
        return sum(1 for s in self._specs.values() if s.app_command)


def load_manifest(path: str) -> SmokeManifest:
    """Load and validate a YAML smoke manifest."""
    try:
        import yaml
    except ImportError as e:  # pragma: no cover
        raise ManifestError(f"PyYAML required to load manifests: {e}")

    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"manifest not found: {path}")

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise ManifestError(f"invalid YAML in {path}: {e}")

    if not isinstance(data, Mapping):
        raise ManifestError(f"{path}: top level must be a mapping")

    version = data.get("version", SCHEMA_VERSION)
    if int(version) != SCHEMA_VERSION:
        raise ManifestError(
            f"{path}: unsupported manifest version {version}, "
            f"expected {SCHEMA_VERSION}"
        )

    defaults = data.get("defaults") or {}
    if not isinstance(defaults, Mapping):
        raise ManifestError(f"{path}: defaults must be a mapping")

    images = data.get("images") or {}
    if not isinstance(images, Mapping):
        raise ManifestError(f"{path}: images must be a mapping")

    specs: Dict[str, SmokeSpec] = {}
    skip_reasons: Dict[str, str] = {}
    for image, entry in images.items():
        entry = entry or {}
        if not isinstance(entry, Mapping):
            raise ManifestError(f"{image}: entry must be a mapping")
        specs[str(image)] = _spec_from_mapping(str(image), entry, defaults)
        if not specs[str(image)].enabled:
            skip_reasons[str(image)] = str(
                entry.get("skip_reason", "unspecified")
            )

    logger.info(
        "Loaded smoke manifest %s: %d images, %d with application probes",
        path, len(specs),
        sum(1 for s in specs.values() if s.app_command),
    )
    return SmokeManifest(specs, defaults, skip_reasons)


def manifest_from_dict(data: Mapping[str, Any]) -> SmokeManifest:
    """Build a manifest from an already-parsed mapping (test path)."""
    defaults = data.get("defaults") or {}
    images = data.get("images") or {}
    specs = {
        str(k): _spec_from_mapping(str(k), v or {}, defaults)
        for k, v in images.items()
    }
    skips = {
        str(k): str((v or {}).get("skip_reason", "unspecified"))
        for k, v in images.items()
        if not (v or {}).get("enabled", True)
    }
    return SmokeManifest(specs, defaults, skips)
