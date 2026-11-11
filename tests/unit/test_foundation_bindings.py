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
import json
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
from dotmac_deployment_control import (
    HostAdmissionPresentationStatementV1,
    HostAdmissionPresentationV1,
)
from sqlalchemy.orm import Session

from vendor_cp.deployment.foundation_bindings import (
    ENTRY_POINT_NAME,
    EXECUTION_CONTEXT_MATERIALS_ENV,
    HOST_ADMISSION_MATERIALS_ENV,
    Ed25519AttestationVerifier,
    FoundationBindingsUnavailable,
    bindings,
    build_execution_bindings,
    execution_context_source,
    host_admission_source,
    trust_policy_from_resolved_context,
)
from vendor_cp.deployment.foundation_execution_approval import (
    compose_approved_foundation_v3_providers,
)
from vendor_cp.deployment.host_admission_adapter import (
    FoundationHostV3Bindings,
    FoundationV3Sources,
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
    assert "DATABASE_URL" in message
    assert "PLATFORM_DATABASE_URL" in message
    assert "host_admission observer" in message
    assert "execution_context observer" in message


def test_factory_with_session_materials_refuses_on_observers_only() -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        bindings(
            environ={
                "DATABASE_URL": "postgresql+psycopg://u:p@127.0.0.1:1/cp",
                "PLATFORM_DATABASE_URL": ("postgresql+psycopg://u:p@127.0.0.1:1/cp"),
            }
        )
    message = str(caught.value)
    assert "DATABASE_URL" not in message
    assert "host_admission observer" in message
    # DSN values themselves are never echoed.
    assert "127.0.0.1" not in message


# ── observer startup materials ──────────────────────────────────────────────


def _stub_envelope(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    seen: list[Any] = []

    class _Envelope:
        def __init__(self, document: Any) -> None:
            self.document = document

        @classmethod
        def from_mapping(cls, value: object) -> _Envelope:
            seen.append(value)
            return cls(value)

    package = ModuleType("dotmac_deployment_foundation")
    package.AttestationEnvelopeV2 = _Envelope  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", package)
    return seen


def _presentation_document(presentation_id: str = "synthetic-first") -> dict[str, Any]:
    # Encoded synthetic bytes satisfy the wire shape only, never authenticity.
    return HostAdmissionPresentationV1(
        statement=HostAdmissionPresentationStatementV1(
            presentation_id=presentation_id,
            key_id="synthetic-key",
            dispatch_id="synthetic-dispatch",
            candidate_attestation_envelope_digest="sha256:" + "a" * 64,
            installed_attestation_envelope_digest="sha256:" + "b" * 64,
            issued_at=datetime(2026, 11, 7, tzinfo=UTC),
            expires_at=datetime(2026, 11, 7, 0, 5, tzinfo=UTC),
        ),
        signature=base64.urlsafe_b64encode(bytes(64)).decode("ascii").rstrip("="),
    ).as_mapping()


def _admission_document(attempt_id: object) -> dict[str, Any]:
    return {
        "attempt_id": str(attempt_id),
        "presentation": _presentation_document(),
        "candidate": {"schema": "candidate-envelope"},
        "installed": {"schema": "installed-envelope"},
    }


def test_host_admission_source_reads_materials_fresh_and_typed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _stub_envelope(monkeypatch)
    path = tmp_path / "admission.json"
    first, second = uuid4(), uuid4()
    path.write_text(json.dumps(_admission_document(first)), encoding="utf-8")
    source = host_admission_source(str(path))

    observed = source()
    assert isinstance(observed, HostAdmissionObservation)
    assert observed.attempt_id == first
    assert type(observed.presentation) is HostAdmissionPresentationV1
    assert observed.presentation.as_mapping() == _presentation_document()
    assert observed.candidate.document == {"schema": "candidate-envelope"}  # type: ignore[attr-defined]
    assert seen == [{"schema": "candidate-envelope"}, {"schema": "installed-envelope"}]

    refreshed = _admission_document(second)
    refreshed["presentation"] = _presentation_document("synthetic-second")
    refreshed["presentation"]["signature"] = (
        base64.urlsafe_b64encode(bytes([1]) * 64).decode("ascii").rstrip("=")
    )
    path.write_text(json.dumps(refreshed), encoding="utf-8")
    next_observed = source()
    assert next_observed.attempt_id == second
    assert type(next_observed.presentation) is HostAdmissionPresentationV1
    assert next_observed.presentation.as_mapping() == refreshed["presentation"]
    assert next_observed.presentation != observed.presentation


def test_materials_observer_passes_real_control_type_to_fixed_resolver(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import dotmac_deployment_control as control

    _stub_envelope(monkeypatch)
    attempt_id = uuid4()
    path = tmp_path / "admission.json"
    path.write_text(json.dumps(_admission_document(attempt_id)), encoding="utf-8")
    observed: list[HostAdmissionPresentationV1] = []

    class _ResolvedBoundaryReached(Exception):
        pass

    def resolve(_db: Session, *, attempt_id: object, presentation: object) -> object:
        assert attempt_id == expected_attempt
        assert type(presentation) is HostAdmissionPresentationV1
        assert presentation.as_mapping() == _presentation_document()
        observed.append(presentation)
        # Stop at the resolver boundary: this does not certify admission.
        raise _ResolvedBoundaryReached

    expected_attempt = attempt_id
    monkeypatch.setattr(control, "resolve_host_admission_context", resolve)
    providers = compose_approved_foundation_v3_providers(
        foundation=_fake_foundation(),
        sources=FoundationV3Sources(
            sessions=lambda: Session(),
            host_admission=host_admission_source(str(path)),
            execution_context=lambda: object(),
            clock=lambda: datetime(2026, 11, 7, tzinfo=UTC),
        ),
    )
    with pytest.raises(_ResolvedBoundaryReached):
        providers.host_source.admit_host_source()
    assert len(observed) == 1


@pytest.mark.parametrize(
    "presentation",
    [
        "SECRET-MARKER",
        json.dumps(_presentation_document()),
        None,
        [],
        42,
        {},
        {"statement": _presentation_document()["statement"]},
        {**_presentation_document(), "extra": "SECRET-MARKER"},
        {**_presentation_document(), "statement": "SECRET-MARKER"},
        {**_presentation_document(), "signature": "SECRET-MARKER=="},
        {**_presentation_document(), "signature": {"secret": "SECRET-MARKER"}},
    ],
)
def test_host_admission_source_refuses_malformed_presentation_without_diagnostics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, presentation: object
) -> None:
    import traceback

    seen = _stub_envelope(monkeypatch)
    document = {**_admission_document(uuid4()), "presentation": presentation}
    path = tmp_path / "admission.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FoundationBindingsUnavailable, match="presentation") as caught:
        host_admission_source(str(path))()
    assert "SECRET-MARKER" not in "".join(traceback.format_exception(caught.value))
    assert str(tmp_path) not in str(caught.value)
    assert seen == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extra", "SECRET-MARKER"),
        ("schema", "SECRET-MARKER"),
        ("version", True),
        ("purpose", "SECRET-MARKER"),
        ("audience", "SECRET-MARKER"),
        ("presentation_id", {"secret": "SECRET-MARKER"}),
        ("candidate_attestation_envelope_digest", "SECRET-MARKER"),
        ("issued_at", "SECRET-MARKER"),
        ("expires_at", None),
    ],
)
def test_host_admission_source_delegates_nested_schema_refusals(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str, value: object
) -> None:
    _stub_envelope(monkeypatch)
    document = _admission_document(uuid4())
    document["presentation"]["statement"][field] = value
    path = tmp_path / "admission.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FoundationBindingsUnavailable, match="presentation") as caught:
        host_admission_source(str(path))()
    assert "SECRET-MARKER" not in str(caught.value)


def test_host_admission_source_refuses_missing_nested_statement_field(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_envelope(monkeypatch)
    document = _admission_document(uuid4())
    del document["presentation"]["statement"]["key_id"]
    path = tmp_path / "admission.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FoundationBindingsUnavailable, match="presentation"):
        host_admission_source(str(path))()


@pytest.mark.parametrize(
    "document",
    [
        {**_admission_document(uuid4()), "extra": "SECRET-MARKER"},
        {**_admission_document(uuid4()), "attempt_id": "not-a-uuid"},
        {**_admission_document(uuid4()), "presentation": "  "},
        {"attempt_id": str(uuid4())},
    ],
)
def test_host_admission_source_refuses_closed_without_echoing_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, document: dict[str, Any]
) -> None:
    import json

    _stub_envelope(monkeypatch)
    path = tmp_path / "admission.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        host_admission_source(str(path))()
    assert "SECRET-MARKER" not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


def test_execution_context_source_constructs_exact_type_and_refuses_extra_keys(
    tmp_path: Path,
) -> None:
    import dataclasses
    import json

    @dataclasses.dataclass(frozen=True)
    class _Context:
        target_id: str
        target_ref: str
        host_id: str

    path = tmp_path / "context.json"
    document = {"target_id": "7", "target_ref": "lane3-target", "host_id": "host-1"}
    path.write_text(json.dumps(document), encoding="utf-8")
    source = execution_context_source(str(path), _Context)
    assert source() == _Context(**document)

    path.write_text(json.dumps({**document, "surprise": "x"}), encoding="utf-8")
    with pytest.raises(FoundationBindingsUnavailable):
        source()


def test_factory_names_observer_material_envs_without_echoing_paths(
    tmp_path: Path,
) -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        bindings(
            environ={
                "DATABASE_URL": "postgresql+psycopg://u:p@127.0.0.1:1/cp",
                "PLATFORM_DATABASE_URL": "postgresql+psycopg://u:p@127.0.0.1:1/cp",
                HOST_ADMISSION_MATERIALS_ENV: str(tmp_path / "absent-a.json"),
                EXECUTION_CONTEXT_MATERIALS_ENV: str(tmp_path / "absent-c.json"),
            }
        )
    message = str(caught.value)
    assert HOST_ADMISSION_MATERIALS_ENV in message
    assert "host_admission observer" in message
    assert str(tmp_path) not in message


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
