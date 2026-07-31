"""Unit tests for the TENANT-scoped vendor `AccountService` (option C spike).

Mirrors option A's tests but for the tenant-scoped shape: idempotency is keyed on
`(tenant_id, command_id)`, audit rows are tenant-scoped, and — the distinguishing
behaviour — the same `external_ref` may exist in TWO different tenants (uniqueness
is composite), which is exactly why this model needs a tenant to hang accounts
off. Uses the kernel testing kit (SQLite; no RLS — cross-tenant leakage is proven
on Postgres in the kernel, not here).
"""

from __future__ import annotations

from collections.abc import Iterator
from uuid import UUID

import pytest
from dotmac_kernel import AuditEvent, ConflictError, Tenant
from dotmac_kernel.messaging.models import InboxRecord
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


def _tenant(session: Session, slug: str) -> Tenant:
    t = Tenant(slug=slug, name=slug.title())
    session.add(t)
    session.flush()
    return t


def _cmd(tenant_id: UUID, **over: object) -> service.CreateAccountCommand:
    base: dict[str, object] = {
        "command_id": "cmd-1",
        "tenant_id": tenant_id,
        "external_ref": "acct-001",
        "display_name": "Acme ISP",
    }
    base.update(over)
    return service.CreateAccountCommand(**base)  # type: ignore[arg-type]


def test_create_account_persists_and_audits(session: Session) -> None:
    tenant = _tenant(session, "t1")
    result = service.create_account(session, _cmd(tenant.id))

    assert not result.was_duplicate
    assert result.account.tenant_id == tenant.id
    assert result.account.status == AccountStatus.ACTIVE

    row = session.get(VendorAccount, result.account.id)
    assert row is not None and row.tenant_id == tenant.id

    events = (
        session.execute(
            select(AuditEvent).where(AuditEvent.entity_id == str(result.account.id))
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].tenant_id == tenant.id
    assert events[0].action == "vendor.account.created"


def test_create_account_is_idempotent_on_tenant_and_command_id(
    session: Session,
) -> None:
    tenant = _tenant(session, "t1")
    first = service.create_account(session, _cmd(tenant.id))
    second = service.create_account(session, _cmd(tenant.id))  # same key

    assert not first.was_duplicate
    assert second.was_duplicate
    assert second.account.id == first.account.id

    assert session.scalar(select(func.count()).select_from(VendorAccount)) == 1
    assert session.scalar(select(func.count()).select_from(InboxRecord)) == 1
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_same_external_ref_in_two_tenants_is_allowed(session: Session) -> None:
    """The tenant-scoped distinction: `external_ref` is unique only WITHIN a
    tenant, so two tenants may each own an account with the same ref."""
    t1 = _tenant(session, "t1")
    t2 = _tenant(session, "t2")
    a1 = service.create_account(session, _cmd(t1.id, command_id="c1"))
    a2 = service.create_account(session, _cmd(t2.id, command_id="c2"))
    assert a1.account.id != a2.account.id
    assert a1.account.external_ref == a2.account.external_ref == "acct-001"


def test_duplicate_external_ref_within_a_tenant_is_a_conflict(
    session: Session,
) -> None:
    tenant = _tenant(session, "t1")
    service.create_account(session, _cmd(tenant.id, command_id="c1"))
    with pytest.raises(ConflictError):
        service.create_account(session, _cmd(tenant.id, command_id="c2"))
