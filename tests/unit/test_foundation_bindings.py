"""Foundation execution-bindings composition (Gate 2 source readiness).

The verifier and trust-policy derivation are real production code paths;
the pair composition runs through the real approval-guarded composer
against the installed Control wheel, with test sources at the CP
boundary exactly as the V3 provider tests do. Foundation itself is not
a CP dependency, so its `ExecutionBindings` dataclass is stubbed at the
import boundary — the stub records constructor kwargs, proving the
wiring (provider name, both pair members) without pretending to prove
Foundation's own validation, which hosted conformance/Gate 3 owns.
"""

from __future__ import annotations

import base64
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy.orm import Session

from vendor_cp.deployment.foundation_bindings import (
    ENTRY_POINT_NAME,
    Ed25519AttestationVerifier,
    FoundationBindingsUnavailable,
    bindings,
    build_execution_bindings,
    trust_policy_from_resolved_context,
)
from vendor_cp.deployment.host_admission_adapter import (
    FoundationHostV3Bindings,
    HostAdmissionObservation,
)


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_ed25519_verifier_accepts_a_real_signature() -> None:
    key = Ed25519PrivateKey.generate()
    message = b"envelope signed bytes"
    signature = base64.b64encode(key.sign(message)).decode("ascii")
    verifier = Ed25519AttestationVerifier()
    assert verifier.verify(
        public_key=_raw_public(key),
        algorithm="ed25519",
        message=message,
        signature=signature,
    )


def test_ed25519_verifier_refuses_tampering_and_wrong_shapes() -> None:
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    message = b"envelope signed bytes"
    signature = base64.b64encode(key.sign(message)).decode("ascii")
    verifier = Ed25519AttestationVerifier()
    assert not verifier.verify(
        public_key=_raw_public(key),
        algorithm="ed25519",
        message=b"tampered",
        signature=signature,
    )
    assert not verifier.verify(
        public_key=_raw_public(other),
        algorithm="ed25519",
        message=message,
        signature=signature,
    )
    assert not verifier.verify(
        public_key=_raw_public(key),
        algorithm="hmac-sha256",
        message=message,
        signature=signature,
    )
    assert not verifier.verify(
        public_key=b"short",
        algorithm="ed25519",
        message=message,
        signature=signature,
    )
    assert not verifier.verify(
        public_key=_raw_public(key),
        algorithm="ed25519",
        message=message,
        signature="not base64!!",
    )


def test_trust_policy_derivation_maps_resolved_context_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, Any] = {}

    class _Root:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class _Policy:
        def __init__(self, **kwargs: Any) -> None:
            recorded.update(kwargs)

    fake = ModuleType("dotmac_deployment_foundation")
    fake.AttestationTrustRootV2 = _Root  # type: ignore[attr-defined]
    fake.AttestationTrustPolicy = _Policy  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", fake)

    instant = datetime(2026, 11, 7, tzinfo=UTC)

    def _root(version: str) -> SimpleNamespace:
        return SimpleNamespace(
            public_key_fingerprint="a" * 16,
            public_key_base64="a2V5",
            purpose="candidate",
            custody_domain="ci",
            issuer="cp",
            key_id="k1",
            algorithm="ed25519",
            root_version=version,
            not_before=instant,
            not_after=instant,
            revoked=False,
        )

    resolved = SimpleNamespace(
        candidate_root=_root("v1"),
        installed_root=_root("v2"),
        candidate_audience="aud-c",
        installed_audience="aud-i",
    )
    trust_policy_from_resolved_context(resolved)
    candidate = recorded["candidate_roots"][0]
    assert candidate.kwargs["trust_root_version"] == "v1"
    assert candidate.kwargs["not_before"] == "2026-11-07T00:00:00Z"
    assert recorded["installed_roots"][0].kwargs["trust_root_version"] == "v2"
    assert recorded["candidate_audience"] == "aud-c"
    assert recorded["installed_audience"] == "aud-i"


def _fake_foundation() -> FoundationHostV3Bindings:
    return FoundationHostV3Bindings(
        admit_host_source=lambda **_: (object(), object()),
        trust_policy_from_context=lambda _: object(),
        verifier=object(),
        trace_type=object,  # type: ignore[arg-type]
        pair_result_type=object,  # type: ignore[arg-type]
        consumption_request_type=object,  # type: ignore[arg-type]
        execution_context_type=object,  # type: ignore[arg-type]
    )


def test_build_execution_bindings_wires_the_approved_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, Any] = {}

    class _Bindings:
        def __init__(self, **kwargs: Any) -> None:
            recorded.update(kwargs)
            self.__dict__.update(kwargs)

    package = ModuleType("dotmac_deployment_foundation")
    submodule = ModuleType("dotmac_deployment_foundation.execution_bindings")
    submodule.ExecutionBindings = _Bindings  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", package)
    monkeypatch.setitem(
        sys.modules, "dotmac_deployment_foundation.execution_bindings", submodule
    )

    result = build_execution_bindings(
        sessions=lambda: Session(),
        host_admission=lambda: HostAdmissionObservation(
            uuid4(), "presentation", object(), object()
        ),
        execution_context=lambda: object(),
        clock=lambda: datetime(2026, 11, 7, tzinfo=UTC),
        foundation=_fake_foundation(),
    )
    assert result.provider == ENTRY_POINT_NAME  # type: ignore[attr-defined]
    assert recorded["deployment_admission_provider"] is not None
    assert recorded["authorization_v3_provider"] is not None
    assert (
        recorded["deployment_admission_provider"]
        is not recorded["authorization_v3_provider"]
    )


def test_factory_refuses_closed_naming_missing_startup_inputs() -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        bindings(environ={})
    message = str(caught.value)
    assert "CP_FOUNDATION_PLATFORM_DATABASE_URL" in message
    assert "host_admission observer" in message
    assert "execution_context observer" in message


def test_factory_with_dsn_still_refuses_on_missing_observers_only() -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        bindings(
            environ={
                "CP_FOUNDATION_PLATFORM_DATABASE_URL": (
                    "postgresql+psycopg://u:p@127.0.0.1:1/cp"
                )
            }
        )
    message = str(caught.value)
    assert "CP_FOUNDATION_PLATFORM_DATABASE_URL" not in message
    assert "host_admission observer" in message
    # The DSN value itself is never echoed.
    assert "127.0.0.1" not in message


def test_entry_point_declared_exactly_once_with_matching_name() -> None:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    plugins = document["tool"]["poetry"]["plugins"][
        "dotmac_deployment_foundation.execution_bindings"
    ]
    assert plugins == {
        ENTRY_POINT_NAME: "vendor_cp.deployment.foundation_bindings:bindings"
    }
    assert ENTRY_POINT_NAME != "compose-host"
