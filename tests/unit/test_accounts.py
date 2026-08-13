"""Unit tests for the platform-level vendor `AccountService` (option A).

Uses the kernel's SUPPORTED testing kit (in-memory SQLite; no RLS — platform
tables have none anyway). Proves the three guarantees the service must hold:
idempotent create (via `process_once_platform`), an audit record per real
creation (via `write_platform_audit_event`), and a genuine external_ref conflict
being rejected (not silently deduped).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from dotmac_kernel import ConflictError, PlatformAdmin, PlatformAuditEvent
from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.accounts import service
from vendor_cp.accounts.models import AccountStatus, VendorAccount


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


def _admin(session: Session) -> PlatformAdmin:
    admin = PlatformAdmin(email="ops@dotmac.io", password_hash="x", is_active=True)
    session.add(admin)
    session.flush()
    return admin


def _cmd(**over: object) -> service.CreateAccountCommand:
    base: dict[str, object] = {
        "command_id": "cmd-1",
        "external_ref": "acct-001",
        "display_name": "Acme ISP",
    }
    base.update(over)
    return service.CreateAccountCommand(**base)  # type: ignore[arg-type]


def test_create_account_persists_and_audits(session: Session) -> None:
    admin = _admin(session)
    result = service.create_account(session, _cmd(actor_admin_id=admin.id))

    assert not result.was_duplicate
    assert result.account.external_ref == "acct-001"
    assert result.account.status == AccountStatus.ACTIVE

    row = session.get(VendorAccount, result.account.id)
    assert row is not None and row.display_name == "Acme ISP"

    events = (
        session.execute(
            select(PlatformAuditEvent).where(
                PlatformAuditEvent.entity_id == str(result.account.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].action == "vendor.account.created"
    assert events[0].actor_admin_id == admin.id
    assert events[0].details["external_ref"] == "acct-001"


def test_create_account_is_idempotent_on_command_id(session: Session) -> None:
    first = service.create_account(session, _cmd())
    second = service.create_account(session, _cmd())  # same command_id

    assert not first.was_duplicate
    assert second.was_duplicate
    assert second.account.id == first.account.id

    # Exactly one account, one inbox record, one audit event — no double effect.
    assert session.scalar(select(func.count()).select_from(VendorAccount)) == 1
    recorded = session.scalar(
        select(func.count()).select_from(PlatformIdempotencyRecord)
    )
    assert recorded == 1
    assert session.scalar(select(func.count()).select_from(PlatformAuditEvent)) == 1


def test_duplicate_external_ref_under_a_new_command_is_a_conflict(
    session: Session,
) -> None:
    service.create_account(session, _cmd(command_id="cmd-a", external_ref="dup"))
    with pytest.raises(ConflictError):
        service.create_account(session, _cmd(command_id="cmd-b", external_ref="dup"))


def test_get_and_list_accounts(session: Session) -> None:
    a = service.create_account(session, _cmd(command_id="c1", external_ref="r1"))
    service.create_account(session, _cmd(command_id="c2", external_ref="r2"))

    fetched = service.get_account(session, a.account.id)
    assert fetched is not None and fetched.external_ref == "r1"

    refs = {v.external_ref for v in service.list_accounts(session)}
    assert refs == {"r1", "r2"}
