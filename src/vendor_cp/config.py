"""Vendor-control-plane settings.

The DATABASE lives with the kernel (`dotmac_kernel.config.settings.database_url`):
there is exactly ONE control-plane database and the kernel owns the engine
(deny-case D1). This module adds only the vendor-specific knobs — chiefly the
provider mode, which is `fake` in this phase and FAILS STARTUP for anything else
(deny-case D3).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ProductionConfigurationError(RuntimeError):
    """The process would start with a production-unsafe identity or mode."""


@dataclass(frozen=True, slots=True)
class ProductReleasePin:
    """Exact artifact and product-manifest identities selected by an operator."""

    artifact_digest: str
    product_manifest_digest: str

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.artifact_digest) is None:
            raise ValueError(
                "artifact_digest must be 'sha256:' plus 64 lowercase hex digits"
            )
        if _SHA256_RE.fullmatch(self.product_manifest_digest) is None:
            raise ValueError(
                "product_manifest_digest must be 'sha256:' plus 64 lowercase "
                "hex digits"
            )


@dataclass(frozen=True)
class VendorSettings:
    """Vendor-only configuration (the kernel owns DB / auth / security config)."""

    provider_mode: str  # only "fake" is permitted in this phase
    # Exact product release evidence. Capability codes do not live here: the
    # adapter derives them only from the canonical document attested for the
    # exact artifact digest.
    product_release_pins: tuple[tuple[str, ProductReleasePin], ...] = ()
    product_manifest_directory: Path = Path("/run/dotmac/product-manifests")
    # WS8 licence signing (see vendor_cp.licensing.signer). "ephemeral" (an
    # in-memory keypair, dev/test only) or "configured" (a real key read from
    # licence_signing_key_file). Ephemeral is the DEFAULT so a missing
    # configuration cannot silently become a real issuer; an unknown mode fails
    # loudly rather than falling back.
    licence_signing_mode: str = "ephemeral"
    # `configured` mode only. Path to a file holding the base64url raw Ed25519
    # private key, whose CANONICAL source is OpenBao
    # (secret/dotmac/licensing/signing-key). Deployment contract (2026-08-02):
    # issuance runs on ONE designated instance; keys at
    # /run/secrets/dotmac/vendor-control-plane/licence-signing/<key-id>.key,
    # materialised by deploy tooling with a 0700 dir, 0600 service-owned files,
    # atomic replacement, read-only container mount; manual materialisation is
    # break-glass only. Never committed, logged, or stored in the database.
    # The key is read ONCE at startup, so any key change needs a CONTROLLED
    # RESTART. The key id is advertised in every envelope so deployments can
    # select the right verification key.
    licence_signing_key_file: str = ""
    licence_signing_key_id: str = ""
    # OPTIONAL rotation overlap: while set, every document is ALSO signed with
    # this second key, so deployments holding either the old or the new keyring
    # can verify. Retire the old key once the fleet has the new one, then unset.
    licence_overlap_key_file: str = ""
    licence_overlap_key_id: str = ""
    # Delivery transport. "logging" (default) records what would be sent;
    # "offline_bundle" renders a self-contained artifact for an air-gapped
    # site. Networked transports are a separate, credentialed slice.
    licence_delivery_mode: str = "logging"


def load_vendor_settings() -> VendorSettings:
    """Read vendor settings from the environment with safe defaults."""
    mode = os.getenv("VENDOR_PROVIDER_MODE", "fake").strip().lower()
    legacy = os.getenv("VENDOR_OFFERED_CAPABILITIES", "").strip()
    if legacy:
        raise ValueError(
            "VENDOR_OFFERED_CAPABILITIES is unscoped and no longer accepted; "
            "supply VENDOR_PRODUCT_RELEASE_PINS_JSON"
        )
    raw_capabilities = os.getenv("VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON")
    if raw_capabilities is not None:
        raise ValueError(
            "VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON is no longer accepted; "
            "supply exact product release pins"
        )
    raw_pins = os.getenv("VENDOR_PRODUCT_RELEASE_PINS_JSON", "{}")
    try:
        parsed = json.loads(raw_pins)
    except json.JSONDecodeError as exc:
        raise ValueError("VENDOR_PRODUCT_RELEASE_PINS_JSON must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("VENDOR_PRODUCT_RELEASE_PINS_JSON must be an object")
    product_release_pins: list[tuple[str, ProductReleasePin]] = []
    for product_code, document in parsed.items():
        if (
            not isinstance(product_code, str)
            or not product_code
            or product_code != product_code.strip()
        ):
            raise ValueError("product release pin keys must be non-blank strings")
        if not isinstance(document, dict) or set(document) != {
            "artifact_digest",
            "product_manifest_digest",
        }:
            raise ValueError(
                f"release pin for product {product_code!r} must contain exactly "
                "artifact_digest and product_manifest_digest"
            )
        if not all(isinstance(value, str) for value in document.values()):
            raise ValueError(
                f"release pin digests for product {product_code!r} must be strings"
            )
        product_release_pins.append(
            (
                product_code,
                ProductReleasePin(
                    artifact_digest=document["artifact_digest"],
                    product_manifest_digest=document["product_manifest_digest"],
                ),
            )
        )
    signing = os.getenv("VENDOR_LICENCE_SIGNING_MODE", "ephemeral").strip().lower()
    return VendorSettings(
        provider_mode=mode,
        product_release_pins=tuple(product_release_pins),
        product_manifest_directory=Path(
            os.getenv(
                "VENDOR_PRODUCT_MANIFEST_DIRECTORY",
                "/run/dotmac/product-manifests",
            )
        ),
        licence_signing_mode=signing,
        licence_signing_key_file=os.getenv("VENDOR_LICENCE_SIGNING_KEY_FILE", ""),
        licence_signing_key_id=os.getenv("VENDOR_LICENCE_SIGNING_KEY_ID", ""),
        licence_overlap_key_file=os.getenv("VENDOR_LICENCE_OVERLAP_KEY_FILE", ""),
        licence_overlap_key_id=os.getenv("VENDOR_LICENCE_OVERLAP_KEY_ID", ""),
        licence_delivery_mode=os.getenv("VENDOR_LICENCE_DELIVERY_MODE", "logging")
        .strip()
        .lower(),
    )


def validate_runtime_configuration(
    settings: VendorSettings, *, environment: str
) -> None:
    """Validate modes whose failure must happen at boot, not first use.

    The provider laboratory is the only implementation in every environment.
    Production additionally requires a stable configured issuer: an ephemeral
    key makes every restart a silent fleet-wide identity rotation.
    """
    if settings.provider_mode != "fake":
        raise ProductionConfigurationError(
            f"provider_mode={settings.provider_mode!r} is not permitted; "
            "only the fake laboratory provider exists in this phase"
        )
    if settings.licence_signing_mode not in {"ephemeral", "configured"}:
        raise ProductionConfigurationError(
            f"licence_signing_mode={settings.licence_signing_mode!r} is unknown"
        )
    if settings.licence_delivery_mode not in {"logging", "offline_bundle"}:
        raise ProductionConfigurationError(
            f"licence_delivery_mode={settings.licence_delivery_mode!r} is unknown"
        )
    if environment.strip().lower() == "production" and (
        settings.licence_signing_mode != "configured"
    ):
        raise ProductionConfigurationError(
            "production requires VENDOR_LICENCE_SIGNING_MODE='configured'; "
            "an ephemeral issuer changes identity on every process restart"
        )


vendor_settings = load_vendor_settings()


__all__ = [
    "ProductionConfigurationError",
    "ProductReleasePin",
    "VendorSettings",
    "load_vendor_settings",
    "validate_runtime_configuration",
    "vendor_settings",
]
