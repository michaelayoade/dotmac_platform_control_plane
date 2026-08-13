"""Configuration canaries for the product-qualified capability adapter."""

from __future__ import annotations

import pytest

from vendor_cp.config import load_vendor_settings


def test_structured_catalogue_config_is_product_qualified(monkeypatch) -> None:
    monkeypatch.delenv("VENDOR_OFFERED_CAPABILITIES", raising=False)
    monkeypatch.setenv(
        "VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON",
        '{"dotmac-sub":["subscriber.read"],"dotmac-erp":["invoice.read"]}',
    )
    settings = load_vendor_settings()
    assert dict(settings.product_manifest_capabilities) == {
        "dotmac-sub": ("subscriber.read",),
        "dotmac-erp": ("invoice.read",),
    }


def test_legacy_flat_catalogue_config_is_refused(monkeypatch) -> None:
    monkeypatch.setenv("VENDOR_OFFERED_CAPABILITIES", "subscriber.read")
    with pytest.raises(ValueError, match="unscoped and no longer accepted"):
        load_vendor_settings()


@pytest.mark.parametrize(
    "payload",
    (
        "[]",
        '{"dotmac-sub":"subscriber.read"}',
        '{"dotmac-sub":[" subscriber.read"]}',
        '{"dotmac-sub":["subscriber.read","subscriber.read"]}',
    ),
)
def test_malformed_product_catalogue_config_is_refused(
    monkeypatch, payload: str
) -> None:
    monkeypatch.delenv("VENDOR_OFFERED_CAPABILITIES", raising=False)
    monkeypatch.setenv("VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON", payload)
    with pytest.raises(ValueError):
        load_vendor_settings()
