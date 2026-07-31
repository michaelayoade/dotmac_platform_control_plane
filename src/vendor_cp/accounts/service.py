"""Vendor `AccountService` — TENANT-scoped variant (option C spike).

The architectural contrast with option A: every operation is scoped to a
`tenant_id` and uses the kernel's TENANT-scoped primitives:
- **Idempotency** — `process_once` with a `CommandEnvelope`, keyed on
  `(tenant_id, command_id)` (not `command_id` alone).
- **Audit** — `write_audit_event`, recording against `(tenant_id,
  actor_party_id)` in the tenant audit trail.

That `tenant_id` has to come from somewhere — and a vendor account has no
natural tenant. See `docs/spikes/slice3-accounts-tenant.md`. Same
transaction-authority contract as option A (receives a `Session`; only
add/flush).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from dotmac_kernel import ConflictError, write_audit_event
from dotmac_kernel.messaging import CommandEnvelope, process_once
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.accounts.models import AccountStatus, VendorAccount

_COMMAND_TYPE_CREATE = "vendor.account.create"


@dataclass(frozen=True, slots=True)
class CreateAccountCommand:
    """Create a tenant-scoped vendor account. Idempotency key is `(tenant_id,
    command_id)`. `actor_party_id` is the tenant party performing the action."""

    command_id: str
    tenant_id: UUID
    external_ref: str
    display_name: str
    actor_party_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class AccountView:
    """Typed read model returned across the service boundary."""

    id: UUID
    tenant_id: UUID
    external_ref: str
    display_name: str
    status: str


@dataclass(frozen=True, slots=True)
class CreateAccountResult:
    account: AccountView
    was_duplicate: bool


def _account_view(row: VendorAccount) -> AccountView:
    return AccountView(
        id=row.id,
        tenant_id=row.tenant_id,
        external_ref=row.external_ref,
        display_name=row.display_name,
        status=row.status,
    )


def create_account(db: Session, command: CreateAccountCommand) -> CreateAccountResult:
    """Create a tenant-scoped vendor account idempotently, with a tenant audit
    record. Raises `ConflictError` if a DIFFERENT command creates an account with
    an `external_ref` that already exists WITHIN THE SAME TENANT."""

    def handler(session: Session, env: CommandEnvelope) -> Mapping[str, object]:
        existing = session.execute(
            select(VendorAccount).where(
                VendorAccount.tenant_id == env.tenant_id,
                VendorAccount.external_ref == command.external_ref,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(
                f"vendor account {command.external_ref!r} already exists in tenant "
                f"{env.tenant_id}"
            )
        account = VendorAccount(
            tenant_id=env.tenant_id,
            external_ref=command.external_ref,
            display_name=command.display_name,
            status=AccountStatus.ACTIVE,
        )
        session.add(account)
        session.flush()
        write_audit_event(
            session,
            tenant_id=env.tenant_id,
            actor_party_id=env.actor_party_id,
            action="vendor.account.created",
            entity_type="vendor_account",
            entity_id=str(account.id),
            details={
                "external_ref": account.external_ref,
                "display_name": account.display_name,
            },
        )
        return {
            "account_id": str(account.id),
            "tenant_id": str(account.tenant_id),
            "external_ref": account.external_ref,
            "display_name": account.display_name,
            "status": account.status,
        }

    envelope = CommandEnvelope(
        command_id=command.command_id,
        command_type=_COMMAND_TYPE_CREATE,
        tenant_id=command.tenant_id,
        actor_party_id=command.actor_party_id,
    )
    outcome = process_once(db, envelope, handler)
    r = outcome.result
    return CreateAccountResult(
        account=AccountView(
            id=UUID(str(r["account_id"])),
            tenant_id=UUID(str(r["tenant_id"])),
            external_ref=str(r["external_ref"]),
            display_name=str(r["display_name"]),
            status=str(r["status"]),
        ),
        was_duplicate=outcome.was_duplicate,
    )


def get_account(db: Session, account_id: UUID) -> AccountView | None:
    row = db.get(VendorAccount, account_id)
    return _account_view(row) if row is not None else None


def list_accounts(db: Session, tenant_id: UUID) -> list[AccountView]:
    rows = db.execute(
        select(VendorAccount)
        .where(VendorAccount.tenant_id == tenant_id)
        .order_by(VendorAccount.created_at)
    ).scalars()
    return [_account_view(r) for r in rows]


__all__ = [
    "CreateAccountCommand",
    "AccountView",
    "CreateAccountResult",
    "create_account",
    "get_account",
    "list_accounts",
]
