"""Pinned identities, release-evidence policy and Control security install.

Control and Foundation are replaced at the import boundary by small stand-ins
that record what the assembly passes them (hosted conformance owns their own
validation); signatures and fingerprints are real Ed25519 / SHA-256.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment import control_security
from vendor_cp.deployment.control_security import (
    AUTHORIZATION_IDENTITY_ENV,
    DISPATCH_IDENTITY_ENV,
    install_control_verification,
)
from vendor_cp.deployment.release_evidence_policy import (
    RELEASE_EVIDENCE_IDENTITY_ENV,
    RELEASE_EVIDENCE_REPOSITORY_ENV,
    release_evidence_trust,
)
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import (
    IDENTITY_SCHEMA,
    AuthorizationEd25519Verifier,
    DispatchEd25519Verifier,
    HostAdmissionPresentationEd25519Verifier,
    PinnedVerificationIdentity,
    ReleaseEvidenceEd25519Verifier,
)

_UID = os.getuid()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _fingerprint(public_b64: str) -> str:
    raw = base64.urlsafe_b64decode(public_b64 + "=" * (-len(public_b64) % 4))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class _FingerprintV1:
    def __init__(self, canonical: str) -> None:
        self.canonical = canonical

    @classmethod
    def from_public_key_b64(cls, value: str) -> _FingerprintV1:
        return cls(_fingerprint(value))


@pytest.fixture
def control(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = ModuleType("dotmac_deployment_control")
    module.PublicKeyFingerprintV1 = _FingerprintV1  # type: ignore[attr-defined]
    module.AUTHORIZATION_PURPOSE = "deployment_authorization"  # type: ignore[attr-defined]
    module.DISPATCH_PURPOSE = "deployment_dispatch"  # type: ignore[attr-defined]
    module.HOST_ADMISSION_PRESENTATION_PURPOSE = "presentation.v1"  # type: ignore[attr-defined]
    module.installed = []  # type: ignore[attr-defined]

    def install_admission(**kwargs: Any) -> None:
        module.installed.append(("admission", kwargs))  # type: ignore[attr-defined]

    def install_consumption(**kwargs: Any) -> None:
        module.installed.append(("consumption", kwargs))  # type: ignore[attr-defined]

    module.install_host_admission_security = install_admission  # type: ignore[attr-defined]
    module.install_foundation_consumption_security = install_consumption  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dotmac_deployment_control", module)
    monkeypatch.setattr(control_security, "_INSTALLED", None)
    return module


class _Keyed:
    def __init__(self, tmp_path: Path, *, purpose: str, key_id: str = "key-1") -> None:
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_b64 = _b64(raw)
        self.key_id, self.purpose = key_id, purpose
        self.document: dict[str, Any] = {
            "schema": IDENTITY_SCHEMA,
            "key_id": key_id,
            "algorithm": "ed25519",
            "purpose": purpose,
            "public_key_b64url": self.public_b64,
            "public_key_fingerprint": _fingerprint(self.public_b64),
        }
        self.path = tmp_path / f"{purpose}-{key_id}.json"
        self.write()

    def write(self, **overrides: Any) -> Path:
        self.path.write_text(json.dumps({**self.document, **overrides}))
        self.path.chmod(0o644)
        return self.path

    def sign(self, message: bytes) -> str:
        return _b64(self.private.sign(message))

    def load(self) -> PinnedVerificationIdentity:
        return PinnedVerificationIdentity.read(
            str(self.path), purpose=self.purpose, what="identity", owner_uid=_UID
        )


def _refusal(call: Any) -> FoundationBindingsUnavailable:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        call()
    assert "SECRET-MARKER" not in str(caught.value)
    return caught.value


# ── pinned identity ─────────────────────────────────────────────────────────


def test_a_proven_identity_verifies_only_its_own_signatures(
    control: ModuleType, tmp_path: Path
) -> None:
    keyed = _Keyed(tmp_path, purpose="deployment_authorization")
    identity = keyed.load()
    verifier = AuthorizationEd25519Verifier(identity)
    message = b"statement"
    args: dict[str, Any] = {
        "key_id": "key-1",
        "algorithm": "ed25519",
        "purpose": "deployment_authorization",
        "public_key_fingerprint": identity.public_key_fingerprint,
        "canonical_bytes": message,
        "signature": keyed.sign(message),
    }
    assert verifier.verify(**args) is True
    for field, value in (
        ("key_id", "other"),
        ("algorithm", "rsa"),
        ("purpose", "deployment_dispatch"),
        ("public_key_fingerprint", "sha256:" + "0" * 64),
        ("canonical_bytes", b"tampered"),
        ("signature", _b64(b"\x01" * 64)),
        ("signature", keyed.sign(message) + "="),
        ("signature", "not base64!"),
        ("signature", ""),
    ):
        assert verifier.verify(**{**args, field: value}) is False, field


def test_a_signature_from_another_key_does_not_verify(
    control: ModuleType, tmp_path: Path
) -> None:
    keyed = _Keyed(tmp_path, purpose="deployment_dispatch")
    stranger = Ed25519PrivateKey.generate()
    identity = keyed.load()
    verifier = DispatchEd25519Verifier(identity)
    assert not verifier.verify_dispatch(
        key_id="key-1",
        algorithm="ed25519",
        purpose="deployment_dispatch",
        public_key_fingerprint=identity.public_key_fingerprint,
        canonical_bytes=b"m",
        signature=_b64(stranger.sign(b"m")),
    )


@pytest.mark.parametrize(
    ("overrides", "phrase"),
    [
        ({"schema": "Other.v1"}, "not a"),
        ({"purpose": "deployment_dispatch"}, "different purpose"),
        ({"algorithm": "rsa"}, "unsupported algorithm"),
        ({"key_id": " "}, "key id"),
        ({"public_key_b64url": "AAAA"}, "non-canonical public key"),
        ({"public_key_fingerprint": "sha256:" + "0" * 64}, "does not identify"),
        ({"extra": "SECRET-MARKER"}, "closed contract"),
    ],
)
def test_identity_document_defects_refuse(
    control: ModuleType, tmp_path: Path, overrides: dict[str, Any], phrase: str
) -> None:
    keyed = _Keyed(tmp_path, purpose="deployment_authorization")
    keyed.write(**overrides)
    refused = _refusal(keyed.load)
    assert refused.code is TargetRefusal.VERIFICATION_IDENTITY_REFUSED
    assert phrase in str(refused)
    assert str(tmp_path) not in str(refused)


def test_identity_file_conditions_refuse(control: ModuleType, tmp_path: Path) -> None:
    keyed = _Keyed(tmp_path, purpose="deployment_authorization")
    # wrong owner
    refused = _refusal(
        lambda: PinnedVerificationIdentity.read(
            str(keyed.path),
            purpose=keyed.purpose,
            what="identity",
            owner_uid=_UID + 1,
        )
    )
    assert "owner" in str(refused)
    # a directory anyone else can write to could swap the file under us
    tmp_path.chmod(0o770)
    assert "directory" in str(_refusal(keyed.load))
    tmp_path.chmod(0o700)
    # group/other writable
    keyed.path.chmod(0o666)
    assert "writable" in str(_refusal(keyed.load))
    keyed.path.chmod(0o644)
    # symlink is not a regular file
    link = tmp_path / "link.json"
    link.symlink_to(keyed.path)
    assert "regular file" in str(
        _refusal(
            lambda: PinnedVerificationIdentity.read(
                str(link), purpose=keyed.purpose, what="identity", owner_uid=_UID
            )
        )
    )
    # oversize
    keyed.path.write_text(" " * (16 * 1024 + 1))
    keyed.path.chmod(0o644)
    assert "size bound" in str(_refusal(keyed.load))
    # not JSON / not an object
    keyed.path.write_text("not json SECRET-MARKER")
    assert "JSON" in str(_refusal(keyed.load))
    keyed.path.write_text("[]")
    assert "closed contract" in str(_refusal(keyed.load))
    # absent
    keyed.path.unlink()
    assert "cannot be read" in str(_refusal(keyed.load))


def test_identity_refuses_when_control_fingerprint_derivation_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, control: ModuleType
) -> None:
    keyed = _Keyed(tmp_path, purpose="deployment_authorization")
    monkeypatch.setitem(sys.modules, "dotmac_deployment_control", None)
    assert "fingerprint derivation" in str(_refusal(keyed.load))


# ── presentation verifier ───────────────────────────────────────────────────


def test_presentation_verifier_proves_key_purpose_and_fingerprint(
    control: ModuleType,
) -> None:
    private = Ed25519PrivateKey.generate()
    public = _b64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    verifier = HostAdmissionPresentationEd25519Verifier(expected_purpose="p.v1")
    args: dict[str, Any] = {
        "key_id": "k",
        "algorithm": "ed25519",
        "purpose": "p.v1",
        "public_key_fingerprint": _fingerprint(public),
        "public_key_b64": public,
        "canonical_bytes": b"statement",
        "signature": _b64(private.sign(b"statement")),
    }
    assert verifier.verify_host_admission_presentation(**args) is True
    for field, value in (
        ("algorithm", "rsa"),
        ("purpose", "other"),
        ("key_id", ""),
        ("public_key_b64", "AAAA"),
        ("public_key_fingerprint", "sha256:" + "0" * 64),
        ("canonical_bytes", b"tampered"),
        ("signature", _b64(b"\x02" * 64)),
    ):
        assert (
            verifier.verify_host_admission_presentation(**{**args, field: value})
            is False
        ), field


# ── release-evidence policy ─────────────────────────────────────────────────


def _foundation_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ModuleType("dotmac_deployment_foundation")

    class _Policy:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    module.TrustPolicy = _Policy  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", module)


def test_release_evidence_trust_is_exactly_the_pinned_identity_and_repository(
    control: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _foundation_policy(monkeypatch)
    keyed = _Keyed(tmp_path, purpose="platform_release_evidence", key_id="re-1")
    env = {
        RELEASE_EVIDENCE_IDENTITY_ENV: str(keyed.path),
        RELEASE_EVIDENCE_REPOSITORY_ENV: "example-org/example-repo",
    }
    policy, verifier = release_evidence_trust(env, owner_uid=_UID)
    assert policy.accepted_key_ids == frozenset({"re-1"})
    assert policy.repository == "example-org/example-repo"
    assert isinstance(verifier, ReleaseEvidenceEd25519Verifier)
    message = b"canonical evidence"
    signature = keyed.sign(message)
    assert verifier.verify(key_id="re-1", message=message, signature=signature)
    assert not verifier.verify(key_id="other", message=message, signature=signature)
    assert not verifier.verify(key_id="re-1", message=b"x", signature=signature)


@pytest.mark.parametrize(
    "missing", [RELEASE_EVIDENCE_IDENTITY_ENV, RELEASE_EVIDENCE_REPOSITORY_ENV]
)
def test_missing_policy_inputs_refuse_naming_what_is_missing(
    control: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing: str
) -> None:
    _foundation_policy(monkeypatch)
    keyed = _Keyed(tmp_path, purpose="platform_release_evidence")
    env = {
        RELEASE_EVIDENCE_IDENTITY_ENV: str(keyed.path),
        RELEASE_EVIDENCE_REPOSITORY_ENV: "example-org/example-repo",
    }
    del env[missing]
    refused = _refusal(lambda: release_evidence_trust(env, owner_uid=_UID))
    assert refused.code is TargetRefusal.EVIDENCE_POLICY_INCOMPLETE
    assert missing in str(refused)


@pytest.mark.parametrize("repository", ["noslash", "a/b/c", "a b/c", "/x", "x/"])
def test_a_malformed_repository_refuses(
    control: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    repository: str,
) -> None:
    _foundation_policy(monkeypatch)
    keyed = _Keyed(tmp_path, purpose="platform_release_evidence")
    env = {
        RELEASE_EVIDENCE_IDENTITY_ENV: str(keyed.path),
        RELEASE_EVIDENCE_REPOSITORY_ENV: repository,
    }
    refused = _refusal(lambda: release_evidence_trust(env, owner_uid=_UID))
    assert refused.code is TargetRefusal.EVIDENCE_POLICY_INCOMPLETE


def test_a_wrong_purpose_identity_cannot_be_the_release_evidence_identity(
    control: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _foundation_policy(monkeypatch)
    keyed = _Keyed(tmp_path, purpose="deployment_authorization")
    env = {
        RELEASE_EVIDENCE_IDENTITY_ENV: str(keyed.path),
        RELEASE_EVIDENCE_REPOSITORY_ENV: "example-org/example-repo",
    }
    refused = _refusal(lambda: release_evidence_trust(env, owner_uid=_UID))
    assert refused.code is TargetRefusal.VERIFICATION_IDENTITY_REFUSED
    assert "different purpose" in str(refused)


def test_missing_foundation_refuses_typed(
    control: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", None)
    keyed = _Keyed(tmp_path, purpose="platform_release_evidence")
    env = {
        RELEASE_EVIDENCE_IDENTITY_ENV: str(keyed.path),
        RELEASE_EVIDENCE_REPOSITORY_ENV: "example-org/example-repo",
    }
    refused = _refusal(lambda: release_evidence_trust(env, owner_uid=_UID))
    assert refused.code is TargetRefusal.FOUNDATION_MISSING


# ── Control security install ────────────────────────────────────────────────


def _control_env(tmp_path: Path) -> tuple[dict[str, str], _Keyed, _Keyed]:
    authorization = _Keyed(tmp_path, purpose="deployment_authorization", key_id="a-1")
    dispatch = _Keyed(tmp_path, purpose="deployment_dispatch", key_id="d-1")
    env = {
        AUTHORIZATION_IDENTITY_ENV: str(authorization.path),
        DISPATCH_IDENTITY_ENV: str(dispatch.path),
    }
    return env, authorization, dispatch


def test_both_control_installs_run_with_the_database_clock_and_real_verifiers(
    control: ModuleType, tmp_path: Path
) -> None:
    env, authorization, dispatch = _control_env(tmp_path)
    sentinel = object()
    install_control_verification(env, clock=lambda: sentinel, owner_uid=_UID)  # type: ignore[arg-type,return-value]
    kinds = [kind for kind, _ in control.installed]  # type: ignore[attr-defined]
    assert kinds == ["admission", "consumption"]
    admission = control.installed[0][1]  # type: ignore[attr-defined]
    consumption = control.installed[1][1]  # type: ignore[attr-defined]
    assert isinstance(admission["verifier"], HostAdmissionPresentationEd25519Verifier)
    assert isinstance(
        consumption["authorization_verifier"], AuthorizationEd25519Verifier
    )
    assert isinstance(consumption["dispatch_verifier"], DispatchEd25519Verifier)
    # One clock object, answering from the supplied source (the DB clock).
    assert admission["clock"] is consumption["clock"]
    assert admission["clock"].now() is sentinel
    # And the dispatch verifier is the dispatch identity's, not the authorization's.
    message = b"dispatch"
    identity = dispatch.load()
    assert consumption["dispatch_verifier"].verify_dispatch(
        key_id="d-1",
        algorithm="ed25519",
        purpose="deployment_dispatch",
        public_key_fingerprint=identity.public_key_fingerprint,
        canonical_bytes=message,
        signature=dispatch.sign(message),
    )
    assert not consumption["authorization_verifier"].verify(
        key_id="a-1",
        algorithm="ed25519",
        purpose="deployment_authorization",
        public_key_fingerprint=authorization.load().public_key_fingerprint,
        canonical_bytes=message,
        signature=dispatch.sign(message),
    )


@pytest.mark.parametrize("missing", [AUTHORIZATION_IDENTITY_ENV, DISPATCH_IDENTITY_ENV])
def test_a_missing_identity_refuses_naming_it_and_installs_nothing(
    control: ModuleType, tmp_path: Path, missing: str
) -> None:
    env, _, _ = _control_env(tmp_path)
    del env[missing]
    refused = _refusal(
        lambda: install_control_verification(env, clock=lambda: None, owner_uid=_UID)  # type: ignore[arg-type,return-value]
    )
    assert refused.code is TargetRefusal.VERIFICATION_IDENTITY_MISSING
    assert missing in str(refused)
    assert control.installed == []  # type: ignore[attr-defined]


def test_an_unloadable_identity_installs_nothing(
    control: ModuleType, tmp_path: Path
) -> None:
    env, authorization, _ = _control_env(tmp_path)
    authorization.write(purpose="deployment_dispatch")
    refused = _refusal(
        lambda: install_control_verification(env, clock=lambda: None, owner_uid=_UID)  # type: ignore[arg-type,return-value]
    )
    assert refused.code is TargetRefusal.VERIFICATION_IDENTITY_REFUSED
    assert control.installed == []  # type: ignore[attr-defined]


def test_missing_control_refuses_typed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(sys.modules, "dotmac_deployment_control", None)
    monkeypatch.setattr(control_security, "_INSTALLED", None)
    env, _, _ = _control_env(tmp_path)
    refused = _refusal(
        lambda: install_control_verification(env, clock=lambda: None, owner_uid=_UID)  # type: ignore[arg-type,return-value]
    )
    assert refused.code is TargetRefusal.CONTROL_SECURITY_REFUSED


def test_repeat_install_is_idempotent_for_the_same_identities_only(
    control: ModuleType, tmp_path: Path
) -> None:
    env, authorization, _ = _control_env(tmp_path)
    install_control_verification(env, clock=lambda: None, owner_uid=_UID)  # type: ignore[arg-type,return-value]
    install_control_verification(env, clock=lambda: None, owner_uid=_UID)  # type: ignore[arg-type,return-value]
    assert len(control.installed) == 2  # type: ignore[attr-defined]
    other = _Keyed(tmp_path, purpose="deployment_authorization", key_id="a-2")
    refused = _refusal(
        lambda: install_control_verification(
            {**env, AUTHORIZATION_IDENTITY_ENV: str(other.path)},
            clock=lambda: None,  # type: ignore[arg-type,return-value]
            owner_uid=_UID,
        )
    )
    assert refused.code is TargetRefusal.CONTROL_SECURITY_REFUSED
    assert len(control.installed) == 2  # type: ignore[attr-defined]


def test_control_refusing_the_install_is_a_typed_refusal(
    control: ModuleType, tmp_path: Path
) -> None:
    def already(**_kwargs: Any) -> None:
        raise RuntimeError("host-admission security is already installed")

    control.install_host_admission_security = already  # type: ignore[attr-defined]
    env, _, _ = _control_env(tmp_path)
    refused = _refusal(
        lambda: install_control_verification(env, clock=lambda: None, owner_uid=_UID)  # type: ignore[arg-type,return-value]
    )
    assert refused.code is TargetRefusal.CONTROL_SECURITY_REFUSED


def test_identities_load_without_installing_anything(
    control: ModuleType, tmp_path: Path
) -> None:
    env, authorization, dispatch = _control_env(tmp_path)
    loaded = control_security.load_control_identities(env, owner_uid=_UID)
    assert loaded.authorization.key_id == "a-1" and loaded.dispatch.key_id == "d-1"
    assert control.installed == []  # type: ignore[attr-defined]
    # And a pre-loaded pair is what gets installed, not a second read.
    authorization.path.unlink()
    install_control_verification(
        env,
        clock=lambda: None,
        owner_uid=_UID,
        identities=loaded,  # type: ignore[arg-type,return-value]
    )
    assert [kind for kind, _ in control.installed] == ["admission", "consumption"]  # type: ignore[attr-defined]


@pytest.mark.parametrize("missing", [AUTHORIZATION_IDENTITY_ENV, DISPATCH_IDENTITY_ENV])
def test_loading_without_an_identity_refuses_naming_it(
    control: ModuleType, tmp_path: Path, missing: str
) -> None:
    env, _, _ = _control_env(tmp_path)
    del env[missing]
    refused = _refusal(
        lambda: control_security.load_control_identities(env, owner_uid=_UID)
    )
    assert refused.code is TargetRefusal.VERIFICATION_IDENTITY_MISSING
    assert missing in str(refused)
