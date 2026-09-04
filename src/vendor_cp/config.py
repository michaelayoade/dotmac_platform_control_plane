"""Vendor-control-plane settings.

The DATABASE lives with the kernel (`dotmac_kernel.config.settings.database_url`):
there is exactly ONE control-plane database and the kernel owns the engine
(deny-case D1). This module adds only the vendor-specific knobs — chiefly the
provider mode, which is `fake` in this phase and FAILS STARTUP for anything else
(deny-case D3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from vendor_cp.product_release_pins import (
    ProductReleasePin,
    parse_product_release_pins,
)


class ProductionConfigurationError(RuntimeError):
    """The process would start with a production-unsafe identity or mode."""


@dataclass(frozen=True)
class VendorSettings:
    """Vendor-only configuration (the kernel owns DB / auth / security config)."""

    provider_mode: str  # only "fake" is permitted in this phase
    # Exact product release evidence. Capability codes do not live here: the
    # adapter derives them only from the canonical document attested for the
    # exact artifact digest.
    product_release_pins: tuple[tuple[str, ProductReleasePin], ...] = ()
    product_manifest_directory: Path = Path("/run/dotmac/product-manifests")
    # WS8 licence signing (see vendor_cp.licensing.signing_adapter). "ephemeral" (an
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
    # The platform outbox relay (`vendor_cp.relay`). The DSN is the
    # `platform_outbox_dispatcher` role's — a THIRD ROLE on the one
    # control-plane database, never a second database (deny case D1). Empty is
    # the default and is fail-closed: `relay drain` REFUSES rather than
    # reporting that it drained nothing, because a green zero from an
    # unconfigured relay is the silence this subsystem exists to end.
    relay_dispatcher_database_url: str = ""
    # How long a platform outbox event may sit pending-and-due before the relay
    # is judged not to be draining. Comfortably above the retry backoff floor:
    # a failing event is legitimately due-and-undelivered for a moment on each
    # attempt, and that is a retry, not a stall.
    relay_overdue_seconds: int = 300
    # How long a CLAIMED row may hold its lease before the claim is judged
    # abandoned. Defaults to the kernel `RelayPolicy.stale_lease_seconds`
    # value and must never be TIGHTER than it: a window shorter than the
    # relay's own reclaim window would report a stale lease the relay still
    # considers live, which is an alert for a healthy system.
    relay_stale_lease_seconds: int = 300


def _positive_seconds(name: str, *, default: int) -> int:
    """A duration knob, or a refusal — never a silent fallback to the default.

    An unparseable or non-positive threshold is a configuration mistake, and
    the failure mode of accepting it is the worst one available here: a zero or
    negative window makes every pending event instantly overdue, so the relay
    health surface goes permanently red and an operator learns to ignore it.
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        seconds = int(raw)
    except ValueError as error:
        raise ProductionConfigurationError(
            f"{name}={raw!r} is not an integer number of seconds"
        ) from error
    if seconds <= 0:
        raise ProductionConfigurationError(
            f"{name}={seconds} must be positive; a non-positive window makes "
            "every pending event instantly overdue"
        )
    return seconds


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
    product_release_pins = parse_product_release_pins(raw_pins)
    signing = os.getenv("VENDOR_LICENCE_SIGNING_MODE", "ephemeral").strip().lower()
    return VendorSettings(
        provider_mode=mode,
        product_release_pins=product_release_pins,
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
        relay_dispatcher_database_url=os.getenv(
            "VENDOR_RELAY_DISPATCHER_DATABASE_URL", ""
        ).strip(),
        relay_overdue_seconds=_positive_seconds(
            "VENDOR_RELAY_OVERDUE_SECONDS", default=300
        ),
        relay_stale_lease_seconds=_positive_seconds(
            "VENDOR_RELAY_STALE_LEASE_SECONDS", default=300
        ),
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
