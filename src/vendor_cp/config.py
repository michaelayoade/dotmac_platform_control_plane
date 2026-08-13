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
from dataclasses import dataclass


@dataclass(frozen=True)
class VendorSettings:
    """Vendor-only configuration (the kernel owns DB / auth / security config)."""

    provider_mode: str  # only "fake" is permitted in this phase
    # Temporary shadow input, qualified by target product. It is not a signed or
    # digest-verified product publication; the release-bound snapshot adapter
    # must replace it before allocation authority moves out of Vendor.
    product_manifest_capabilities: tuple[tuple[str, tuple[str, ...]], ...] = ()
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
            "supply VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON"
        )
    raw_catalogues = os.getenv("VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON", "{}")
    try:
        parsed = json.loads(raw_catalogues)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON must be valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise ValueError("VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON must be an object")
    product_catalogues: list[tuple[str, tuple[str, ...]]] = []
    for product_code, codes in parsed.items():
        if (
            not isinstance(product_code, str)
            or not product_code
            or product_code != product_code.strip()
        ):
            raise ValueError("product catalogue keys must be non-blank strings")
        if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
            raise ValueError(
                f"capabilities for product {product_code!r} must be a JSON string list"
            )
        normalized = tuple(codes)
        if any(not code or code != code.strip() for code in normalized):
            raise ValueError(
                f"capabilities for product {product_code!r} must be non-blank "
                "and trimmed"
            )
        if len(set(normalized)) != len(normalized):
            raise ValueError(
                f"capabilities for product {product_code!r} must be unique"
            )
        product_catalogues.append((product_code, normalized))
    signing = os.getenv("VENDOR_LICENCE_SIGNING_MODE", "ephemeral").strip().lower()
    return VendorSettings(
        provider_mode=mode,
        product_manifest_capabilities=tuple(product_catalogues),
        licence_signing_mode=signing,
        licence_signing_key_file=os.getenv("VENDOR_LICENCE_SIGNING_KEY_FILE", ""),
        licence_signing_key_id=os.getenv("VENDOR_LICENCE_SIGNING_KEY_ID", ""),
        licence_overlap_key_file=os.getenv("VENDOR_LICENCE_OVERLAP_KEY_FILE", ""),
        licence_overlap_key_id=os.getenv("VENDOR_LICENCE_OVERLAP_KEY_ID", ""),
        licence_delivery_mode=os.getenv("VENDOR_LICENCE_DELIVERY_MODE", "logging")
        .strip()
        .lower(),
    )


vendor_settings = load_vendor_settings()
