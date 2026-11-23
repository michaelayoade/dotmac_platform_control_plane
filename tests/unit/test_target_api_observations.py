"""`POST observations`: the envelope must be the caller's own (review ruling 5)."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from dotmac_kernel import PlatformAuditEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import select
from sqlalchemy.orm import Session
from target_api_support import (
    BASE,
    TARGET,
    StaticDirectory,
    b64u,
    build_runtime,
    client_for,
    record,
    request_headers,
    send,
)

from vendor_cp.deployment.target_api.consumption import (
    ConsumptionService,
    MaterialsHandler,
    ObservationHandler,
    TargetApiHandlers,
    UnwiredBackend,
)
from vendor_cp.deployment.target_api.credentials import (
    OBSERVATION_MISMATCH_ACTION,
    ControlObservationSink,
)

_SEED = bytes(range(1, 33))
_RESPONSE_SEED = b64u(bytes(range(100, 132)))


class _Refused(Exception):
    pass


def _pub() -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.from_private_bytes(_SEED)
    return b64u(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _post(db: Session, parse: Any, forwarded: list[Any]) -> Any:
    def fake_record(session: Session, command: Any) -> Any:
        forwarded.append(command)
        return SimpleNamespace(
            disposition="accepted",
            changed_state=False,
            attempt_id="a-1",
            receipt_id=None,
            verdict=None,
        )

    runtime = build_runtime(
        directory=StaticDirectory(record(public_key_b64u=_pub())),
        response_seed=_RESPONSE_SEED,
        handlers=TargetApiHandlers(
            consumption=ConsumptionService(UnwiredBackend()),
            materials=MaterialsHandler(None),
            observations=ObservationHandler(
                ControlObservationSink(parse=parse, record=fake_record)
            ),
        ),
        session=db,
    )
    path = f"{BASE}/targets/{TARGET}/observations"
    body = b'{"statement":{},"signature":"s"}'
    return send(
        client_for(runtime),
        method="POST",
        path=path,
        body=body,
        headers=request_headers(
            b64u(_SEED), method="POST", path=path, body=body, nonce=f"{1:032x}"
        ),
    )


def _parse_as(key_id: str, target_ref: str) -> Any:
    return lambda body: SimpleNamespace(
        statement=SimpleNamespace(key_id=key_id, target_ref=target_ref)
    )


def _audit(db: Session) -> list[PlatformAuditEvent]:
    return list(
        db.scalars(
            select(PlatformAuditEvent).where(
                PlatformAuditEvent.action == OBSERVATION_MISMATCH_ACTION
            )
        )
    )


def test_an_observation_for_the_callers_own_credential_and_target_is_forwarded(
    db: Session,
) -> None:
    forwarded: list[Any] = []
    response = _post(db, _parse_as("cred-0001", TARGET), forwarded)
    assert response.status_code == 200
    assert len(forwarded) == 1
    assert forwarded[0].actor_ref == "target-credential:cred-0001"
    assert _audit(db) == []


@pytest.mark.parametrize(
    ("key_id", "target_ref"),
    [
        ("cred-0002", TARGET),
        ("cred-0001", "dotmac-erp-v2/production/host-b"),
    ],
)
def test_observation_principal_mismatch_is_a_signed_403_with_an_audit_row(
    db: Session, key_id: str, target_ref: str
) -> None:
    forwarded: list[Any] = []
    response = _post(db, _parse_as(key_id, target_ref), forwarded)
    assert response.status_code == 403
    assert response.json()["error"] == "observation_principal_mismatch"
    assert "X-Dotmac-Response-Signature" in response.headers
    assert forwarded == []
    (event,) = _audit(db)
    assert event.entity_id == "cred-0001"
    assert event.details["claimed_key_id"] == key_id
    assert event.details["claimed_target_ref"] == target_ref


def test_an_unparseable_body_is_still_forwarded_to_control(db: Session) -> None:
    from dotmac_deployment_control import ExecutionObservationRefusedError

    def parse(body: bytes) -> Any:
        raise ExecutionObservationRefusedError.__new__(ExecutionObservationRefusedError)

    forwarded: list[Any] = []
    response = _post(db, parse, forwarded)
    assert response.status_code == 200
    assert len(forwarded) == 1
    assert _audit(db) == []
