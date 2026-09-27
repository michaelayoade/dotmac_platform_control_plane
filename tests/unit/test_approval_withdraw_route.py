"""ROUTE-level tests for `POST .../approvals/requests/{request_id}/withdraw`
(F-C2, the platform-operator withdrawal path).

Follows `tests/unit/test_licence_routes.py`'s pattern: auth is overridden for
everything except the 401 case, which exercises the real
`require_platform_admin` (`tests/unit/test_withdrawal_conflict_resolution_route.py`
does the same for its own route). The adapter is monkeypatched at the name the
router imports it through, so what's under test here is the route: that it
authenticates, carries the actor from the admin rather than the body, and maps
the adapter's errors to 404/409 rather than 500.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from dotmac_kernel import ConflictError, NotFoundError, PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.errors import register_error_handlers
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter
from vendor_cp.approvals.router import router

REQUEST_ID = uuid.uuid4()
URL = f"/platform/vendor/approvals/requests/{REQUEST_ID}/withdraw"
BODY = {
    "authority_ref": "authority-1",
    "reason": "no longer needed",
    "external_ref": "ext-1",
}


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    register_error_handlers(application)
    application.include_router(router)
    return application


@pytest.fixture
def authenticated_client(app: FastAPI) -> Iterator[TestClient]:
    admin = PlatformAdmin(id=uuid.uuid4(), email="ops@dotmac.io", password_hash="x")
    app.dependency_overrides[get_platform_db] = lambda: object()
    app.dependency_overrides[require_platform_admin] = lambda: admin
    with TestClient(app) as client:
        yield client


def _view() -> adapter.RequestView:
    return adapter.RequestView(
        request_id=REQUEST_ID,
        state="withdrawn",
        satisfied=False,
        satisfied_levels=0,
        total_levels=1,
        reason="withdrawn",
    )


def test_no_admin_is_unauthorized(app: FastAPI) -> None:
    """The real `require_platform_admin`, unoverridden: no bearer token, 401."""
    app.dependency_overrides[get_platform_db] = lambda: object()
    with TestClient(app) as client:
        response = client.post(URL, json=BODY)
    assert response.status_code == 401


def test_an_authenticated_admin_withdraws(
    authenticated_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def _fake_withdraw(
        db: Session, command: adapter.WithdrawRequestCommand
    ) -> adapter.RequestView:
        captured["command"] = command
        return _view()

    monkeypatch.setattr(adapter, "withdraw_request", _fake_withdraw)
    response = authenticated_client.post(URL, json=BODY)
    assert response.status_code == 200
    assert response.json()["state"] == "withdrawn"
    command = captured["command"]
    assert isinstance(command, adapter.WithdrawRequestCommand)
    assert command.request_id == REQUEST_ID
    assert command.authority_ref == BODY["authority_ref"]
    assert command.reason == BODY["reason"]
    assert command.external_ref == BODY["external_ref"]


def test_actor_id_comes_from_the_admin_not_the_body(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def _fake_withdraw(
        db: Session, command: adapter.WithdrawRequestCommand
    ) -> adapter.RequestView:
        captured["actor_id"] = command.actor_id
        return _view()

    monkeypatch.setattr(adapter, "withdraw_request", _fake_withdraw)
    response = authenticated_client.post(
        URL, json={**BODY, "actor_id": str(uuid.uuid4())}
    )
    assert response.status_code == 200
    assert captured["actor_id"] is not None


def test_an_unknown_request_is_not_found(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(
        db: Session, command: adapter.WithdrawRequestCommand
    ) -> adapter.RequestView:
        raise NotFoundError(f"approval request {REQUEST_ID} not found")

    monkeypatch.setattr(adapter, "withdraw_request", _raise)
    response = authenticated_client.post(URL, json=BODY)
    assert response.status_code == 404


def test_a_refused_withdrawal_is_a_conflict(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(
        db: Session, command: adapter.WithdrawRequestCommand
    ) -> adapter.RequestView:
        raise ConflictError(f"approval request {REQUEST_ID} cannot be withdrawn")

    monkeypatch.setattr(adapter, "withdraw_request", _raise)
    response = authenticated_client.post(URL, json=BODY)
    assert response.status_code == 409


@pytest.mark.parametrize("field", ["authority_ref", "reason", "external_ref"])
def test_a_blank_field_is_rejected_before_the_adapter_is_called(
    authenticated_client: TestClient, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    called = False

    def _fake_withdraw(
        db: Session, command: adapter.WithdrawRequestCommand
    ) -> adapter.RequestView:
        nonlocal called
        called = True
        return _view()

    monkeypatch.setattr(adapter, "withdraw_request", _fake_withdraw)
    response = authenticated_client.post(URL, json={**BODY, field: ""})
    assert response.status_code == 422
    assert called is False
