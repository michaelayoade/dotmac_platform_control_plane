"""Production boot refuses disposable identity and unreadable key custody."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vendor_cp import assembly
from vendor_cp.config import ProductionConfigurationError, VendorSettings
from vendor_cp.licensing import signer as signer_module


def _configured_settings(key_file: str) -> VendorSettings:
    return VendorSettings(
        provider_mode="fake",
        licence_signing_mode="configured",
        licence_signing_key_file=key_file,
        licence_signing_key_id="vendor-prod-1",
    )


def _write_key(tmp_path) -> str:
    material = Ed25519PrivateKey.generate().private_bytes_raw()
    path = tmp_path / "primary.key"
    path.write_text(base64.urlsafe_b64encode(material).rstrip(b"=").decode())
    return str(path)


def test_production_refuses_an_ephemeral_issuer_before_composition(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(
        assembly,
        "vendor_settings",
        VendorSettings(provider_mode="fake", licence_signing_mode="ephemeral"),
    )

    with pytest.raises(ProductionConfigurationError, match="configured"):
        assembly.build_spec()


def test_production_loads_the_configured_key_during_boot(tmp_path, monkeypatch) -> None:
    missing = str(tmp_path / "missing.key")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(assembly, "vendor_settings", _configured_settings(missing))

    with pytest.raises(signer_module.SigningKeyUnavailableError, match=missing):
        assembly.build_spec()


def test_runtime_holds_the_key_loaded_at_boot(tmp_path, monkeypatch) -> None:
    key_file = _write_key(tmp_path)
    settings = _configured_settings(key_file)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(assembly, "vendor_settings", settings)

    assembly.build_spec()
    boot_signer = signer_module.runtime_licence_signers()[0]
    (tmp_path / "primary.key").unlink()

    assert signer_module.runtime_licence_signers()[0] is boot_signer


def test_production_refuses_a_real_provisioning_provider(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(
        assembly,
        "vendor_settings",
        VendorSettings(
            provider_mode="aws",
            licence_signing_mode="configured",
            licence_signing_key_file="not-reached",
            licence_signing_key_id="not-reached",
        ),
    )

    with pytest.raises(ProductionConfigurationError, match="provider_mode"):
        assembly.build_spec()
