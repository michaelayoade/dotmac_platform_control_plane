"""Configuration canaries for exact product-release catalogue pins."""

from __future__ import annotations

import pytest

from vendor_cp.config import load_vendor_settings


def test_product_release_pins_bind_artifact_and_manifest_digests(monkeypatch) -> None:
    monkeypatch.delenv("VENDOR_OFFERED_CAPABILITIES", raising=False)
    monkeypatch.delenv("VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON", raising=False)
    monkeypatch.setenv(
        "VENDOR_PRODUCT_RELEASE_PINS_JSON",
        '{"dotmac-sub":{"artifact_digest":"sha256:'
        + "a" * 64
        + '","product_manifest_digest":"sha256:'
        + "b" * 64
        + '"}}',
    )
    settings = load_vendor_settings()
    assert len(settings.product_release_pins) == 1
    product_code, pin = settings.product_release_pins[0]
    assert product_code == "dotmac-sub"
    assert pin.artifact_digest == f"sha256:{'a' * 64}"
    assert pin.product_manifest_digest == f"sha256:{'b' * 64}"


def test_legacy_flat_catalogue_config_is_refused(monkeypatch) -> None:
    monkeypatch.setenv("VENDOR_OFFERED_CAPABILITIES", "subscriber.read")
    with pytest.raises(ValueError, match="unscoped and no longer accepted"):
        load_vendor_settings()


def test_raw_capability_list_config_is_refused(monkeypatch) -> None:
    monkeypatch.delenv("VENDOR_OFFERED_CAPABILITIES", raising=False)
    monkeypatch.setenv("VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON", "{}")
    with pytest.raises(ValueError, match="no longer accepted"):
        load_vendor_settings()


@pytest.mark.parametrize(
    "payload",
    (
        "[]",
        '{"dotmac-sub":"sha256:abc"}',
        '{"dotmac-sub":{}}',
        '{"dotmac-sub":{"artifact_digest":"sha256:'
        + "a" * 64
        + '","product_manifest_digest":"sha256:'
        + "A" * 64
        + '"}}',
        '{" dotmac-sub":{"artifact_digest":"sha256:'
        + "a" * 64
        + '","product_manifest_digest":"sha256:'
        + "b" * 64
        + '"}}',
    ),
)
def test_malformed_product_release_pin_is_refused(monkeypatch, payload: str) -> None:
    monkeypatch.delenv("VENDOR_OFFERED_CAPABILITIES", raising=False)
    monkeypatch.delenv("VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON", raising=False)
    monkeypatch.setenv("VENDOR_PRODUCT_RELEASE_PINS_JSON", payload)
    with pytest.raises(ValueError):
        load_vendor_settings()
