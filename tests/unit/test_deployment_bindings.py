from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotmac_deployment_control import (
    AUTHORIZATION_PURPOSE,
    AuthorizationEnvelopeRefusedError,
    AuthorizationSignature,
    AuthorizationSignerIdentity,
    AuthorizedImage,
    ImageDigestV1,
    PublicKeyFingerprintV1,
    issue_authorization_envelope,
)
from dotmac_deployment_foundation import PreconditionFailed
from dotmac_deployment_foundation.engine import Effects

from vendor_cp.deployment.bindings import (
    AUTHORIZATION_DOCUMENT_SCHEMA,
    ControlAuthorizationAdapter,
    Ed25519AuthorizationVerifier,
    PublicVerificationIdentity,
    execution_bindings,
)
from vendor_cp.deployment.effects import PlatformCpComposeHostEffects


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class _AuthorizationSigner:
    def __init__(self, private: Ed25519PrivateKey) -> None:
        public = _b64url(private.public_key().public_bytes_raw())
        self._private = private
        self.identity = AuthorizationSignerIdentity(
            key_id="platform-authorization-2026-09",
            algorithm="ed25519",
            public_key_fingerprint=PublicKeyFingerprintV1.from_public_key_b64(
                public
            ).canonical,
        )

    def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
        return AuthorizationSignature(
            key_id=self.identity.key_id,
            algorithm=self.identity.algorithm,
            public_key_fingerprint=self.identity.public_key_fingerprint,
            signature=_b64url(self._private.sign(canonical_bytes)),
            purpose=AUTHORIZATION_PURPOSE,
        )


def _identity(private: Ed25519PrivateKey) -> PublicVerificationIdentity:
    public = _b64url(private.public_key().public_bytes_raw())
    return PublicVerificationIdentity(
        key_id="platform-authorization-2026-09",
        algorithm="ed25519",
        purpose=AUTHORIZATION_PURPOSE,
        public_key_b64url=public,
        public_key_fingerprint=PublicKeyFingerprintV1.from_public_key_b64(
            public
        ).canonical,
    )


def _material(private: Ed25519PrivateKey) -> dict[str, object]:
    now = datetime.now(UTC)
    envelope = issue_authorization_envelope(
        {
            "authorization_id": "0d31f253-5cb1-4c5c-ae2e-c7107602978d",
            "execution_sequence": 4,
            "rollout_ref": "platform-cp-first-cutover",
            "plan_id": "504bad13-0dfc-47e2-a274-9873b1798e18",
            "target_id": "50629257-f62d-4b5d-badb-493df7c0344f",
            "target_ref": "vendor-cp-prod",
            "product_code": "dotmac_vendor_control_plane",
            "environment": "production",
            "operation": "deploy",
            "release_ref": "platform-cp@candidate",
            "authorized_images": (
                AuthorizedImage(
                    service="app",
                    repository="ghcr.io/michaelayoade/dotmac_platform_control_plane",
                    digest=ImageDigestV1.parse("sha256:" + "a" * 64),
                ),
            ),
            "plan_digest": "sha256:" + "b" * 64,
            "descriptor_digest": "sha256:" + "c" * 64,
            "execution_plan_digest": "sha256:" + "d" * 64,
            "approval_policy_code": "production-change",
            "approval_policy_version": 3,
            "approval_decision_ref": "approval-42",
            "approval_decision_status": "granted",
            "approved_at": now,
            "issued_at": now,
            "expires_at": now + timedelta(minutes=30),
        },
        signer=_AuthorizationSigner(private),
    )
    return {
        "schema": AUTHORIZATION_DOCUMENT_SCHEMA,
        "authorization_envelope": envelope.as_mapping(),
        "attempt_no": 2,
    }


def test_a10_delivery_material_becomes_the_exact_foundation_receipt() -> None:
    private = Ed25519PrivateKey.generate()
    adapter = ControlAuthorizationAdapter(
        Ed25519AuthorizationVerifier(_identity(private))
    )

    receipt = adapter.attest(_material(private))

    assert receipt["target_ref"] == "vendor-cp-prod"
    assert receipt["execution_sequence"] == 4
    assert receipt["attempt_no"] == 2
    assert receipt["control_plan_digest"] == "sha256:" + "b" * 64
    assert receipt["descriptor_digest"] == "sha256:" + "c" * 64
    assert receipt["execution_plan_digest"] == "sha256:" + "d" * 64
    assert receipt["control_version"] == "0.1.0a10"
    assert adapter.target == "vendor-cp-prod"


def test_signature_mutation_refuses_before_a_target_is_available() -> None:
    private = Ed25519PrivateKey.generate()
    adapter = ControlAuthorizationAdapter(
        Ed25519AuthorizationVerifier(_identity(private))
    )
    material = _material(private)
    envelope = material["authorization_envelope"]
    assert isinstance(envelope, dict)
    envelope["signature"] = _b64url(b"x" * 64)

    with pytest.raises(AuthorizationEnvelopeRefusedError):
        adapter.attest(material)
    with pytest.raises(PreconditionFailed, match="before an authorization"):
        _ = adapter.target


def test_public_identity_file_refuses_a_different_purpose(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    identity = _identity(private)
    path = tmp_path / "authorization-verification.json"
    path.write_text(
        json.dumps(
            {
                "schema": "PlatformCpPublicVerificationIdentity.v1",
                "key_id": identity.key_id,
                "algorithm": identity.algorithm,
                "purpose": "target_execution_observation",
                "public_key_b64url": identity.public_key_b64url,
                "public_key_fingerprint": identity.public_key_fingerprint,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PreconditionFailed, match="declares purpose"):
        PublicVerificationIdentity.read(
            path,
            purpose=AUTHORIZATION_PURPOSE,
            expected_owner_uid=path.stat().st_uid,
        )


def test_public_identity_file_refuses_a_symlink(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    identity = _identity(private)
    real = tmp_path / "real.json"
    real.write_text(
        json.dumps(
            {
                "schema": "PlatformCpPublicVerificationIdentity.v1",
                "key_id": identity.key_id,
                "algorithm": identity.algorithm,
                "purpose": identity.purpose,
                "public_key_b64url": identity.public_key_b64url,
                "public_key_fingerprint": identity.public_key_fingerprint,
            }
        ),
        encoding="utf-8",
    )
    link = tmp_path / "link.json"
    link.symlink_to(real)

    with pytest.raises(PreconditionFailed, match="unreadable"):
        PublicVerificationIdentity.read(
            link,
            purpose=AUTHORIZATION_PURPOSE,
            expected_owner_uid=real.stat().st_uid,
        )


def test_public_identity_file_refuses_writable_or_wrong_owner(
    tmp_path: Path,
) -> None:
    private = Ed25519PrivateKey.generate()
    identity = _identity(private)
    path = tmp_path / "identity.json"
    path.write_text(
        json.dumps(
            {
                "schema": "PlatformCpPublicVerificationIdentity.v1",
                "key_id": identity.key_id,
                "algorithm": identity.algorithm,
                "purpose": identity.purpose,
                "public_key_b64url": identity.public_key_b64url,
                "public_key_fingerprint": identity.public_key_fingerprint,
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o660)
    with pytest.raises(PreconditionFailed, match="group/other writable"):
        PublicVerificationIdentity.read(
            path,
            purpose=AUTHORIZATION_PURPOSE,
            expected_owner_uid=path.stat().st_uid,
        )
    path.chmod(0o600)
    with pytest.raises(PreconditionFailed, match="owned by uid"):
        PublicVerificationIdentity.read(
            path,
            purpose=AUTHORIZATION_PURPOSE,
            expected_owner_uid=path.stat().st_uid + 1,
        )


def test_execution_bindings_do_not_read_trust_paths_from_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "VENDOR_DEPLOYMENT_AUTHORIZATION_PUBLIC_KEY_FILE",
        str(tmp_path / "attacker-controlled.json"),
    )
    monkeypatch.setenv(
        "VENDOR_RELEASE_EVIDENCE_PUBLIC_KEY_FILE",
        str(tmp_path / "attacker-controlled-release.json"),
    )
    with pytest.raises(PreconditionFailed) as refused:
        execution_bindings()
    assert "/etc/dotmac/platform-cp/authorization-verification.json" in str(
        refused.value
    )


def test_the_platform_proxy_exposes_every_a5_effect() -> None:
    assert isinstance(
        object.__new__(PlatformCpComposeHostEffects),
        Effects,
    )


def test_no_private_key_field_exists_on_a_public_identity() -> None:
    assert "private_key" not in PublicVerificationIdentity.__dataclass_fields__
    assert "private_key_b64url" not in PublicVerificationIdentity.__dataclass_fields__
