"""ROUTE-level tests for `POST .../withdrawal-conflicts/{outcome_id}/resolve`.

Auth is exercised, not overridden, for the 401 case — everything else follows
`tests/unit/test_licence_routes.py`'s own pattern: `require_platform_admin` is
overridden so what is under test is this adapter, not the kernel's guard.

`resolve_conflict` itself is monkeypatched at the name the router imports:
`ApprovalWithdrawalOutcome`/`ApprovalWithdrawalConflictResolution` use
PostgreSQL-only column types and cannot be created on the in-memory SQLite
engine (`tests/unit/test_withdrawal_outcomes.py`'s own docstring) — the real
row, real second-resolve-collides proof is
`tests/migration/test_withdrawal_health.py`. This file proves the ADAPTER:
that it authenticates, that it calls the one owner, and that the owner's two
refusals reach the client as 404/409 rather than 500.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.errors import register_error_handlers
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from vendor_cp.relay import withdrawal_router
from vendor_cp.relay.withdrawal_outcomes import (
    ConflictAlreadyResolved,
    ConflictNotResolvable,
    ConflictOutcomeNotFound,
    RecordedConflictResolution,
    WithdrawalResolution,
)

OUTCOME_ID = uuid.uuid4()


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    register_error_handlers(application)
    application.include_router(withdrawal_router.router)
    return application


@pytest.fixture
def authenticated_client(app: FastAPI) -> Iterator[TestClient]:
    admin = PlatformAdmin(id=uuid.uuid4(), email="ops@dotmac.io", password_hash="x")
    app.dependency_overrides[get_platform_db] = lambda: object()
    app.dependency_overrides[require_platform_admin] = lambda: admin
    with TestClient(app) as client:
        yield client


def _resolution() -> RecordedConflictResolution:
    return RecordedConflictResolution(
        id=uuid.uuid4(),
        outcome_id=OUTCOME_ID,
        resolution=WithdrawalResolution.DISMISSED,
        actor_ref="platform_admin:x",
        reason="reviewed",
        redrive_ref=None,
        recorded_at=datetime(2026, 9, 27, tzinfo=UTC),
    )


def test_no_admin_is_unauthorized(app: FastAPI) -> None:
    """The real `require_platform_admin`, unoverridden: no bearer token, 401."""
    app.dependency_overrides[get_platform_db] = lambda: object()
    with TestClient(app) as client:
        response = client.post(
            f"/platform/relay/withdrawal-conflicts/{OUTCOME_ID}/resolve",
            json={"resolution": "dismissed", "reason": "x"},
        )
    assert response.status_code == 401


def test_an_authenticated_admin_resolves(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def _fake_resolve(db: Session, **kwargs: object) -> RecordedConflictResolution:
        captured.update(kwargs)
        return _resolution()

    monkeypatch.setattr(withdrawal_router, "resolve_conflict", _fake_resolve)
    response = authenticated_client.post(
        f"/platform/relay/withdrawal-conflicts/{OUTCOME_ID}/resolve",
        json={"resolution": "dismissed", "reason": "reviewed and safe"},
    )
    assert response.status_code == 200
    assert response.json()["resolution"] == "dismissed"
    # The actor came from the AUTHENTICATED admin, never a client-supplied field.
    assert "platform_admin:" in captured["actor_ref"]


def test_a_second_resolve_is_a_conflict(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fake_resolve(db: Session, **kwargs: object) -> RecordedConflictResolution:
        raise ConflictAlreadyResolved(
            f"withdrawal outcome {OUTCOME_ID} was already resolved"
        )

    monkeypatch.setattr(withdrawal_router, "resolve_conflict", _fake_resolve)
    response = authenticated_client.post(
        f"/platform/relay/withdrawal-conflicts/{OUTCOME_ID}/resolve",
        json={"resolution": "dismissed", "reason": "reviewed and safe"},
    )
    assert response.status_code == 409


def test_an_unknown_outcome_is_not_found(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fake_resolve(db: Session, **kwargs: object) -> RecordedConflictResolution:
        raise ConflictOutcomeNotFound(f"no withdrawal outcome {OUTCOME_ID} exists")

    monkeypatch.setattr(withdrawal_router, "resolve_conflict", _fake_resolve)
    response = authenticated_client.post(
        f"/platform/relay/withdrawal-conflicts/{OUTCOME_ID}/resolve",
        json={"resolution": "dismissed", "reason": "reviewed and safe"},
    )
    assert response.status_code == 404


def test_a_non_conflict_outcome_is_a_conflict_response(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fake_resolve(db: Session, **kwargs: object) -> RecordedConflictResolution:
        raise ConflictNotResolvable(
            f"withdrawal outcome {OUTCOME_ID} is 'applied', not security_conflict"
        )

    monkeypatch.setattr(withdrawal_router, "resolve_conflict", _fake_resolve)
    response = authenticated_client.post(
        f"/platform/relay/withdrawal-conflicts/{OUTCOME_ID}/resolve",
        json={"resolution": "dismissed", "reason": "reviewed and safe"},
    )
    assert response.status_code == 409


def test_an_empty_reason_is_rejected_before_the_owner_is_called(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def _fake_resolve(db: Session, **kwargs: object) -> RecordedConflictResolution:
        nonlocal called
        called = True
        return _resolution()

    monkeypatch.setattr(withdrawal_router, "resolve_conflict", _fake_resolve)
    response = authenticated_client.post(
        f"/platform/relay/withdrawal-conflicts/{OUTCOME_ID}/resolve",
        json={"resolution": "dismissed", "reason": ""},
    )
    assert response.status_code == 422
    assert called is False
