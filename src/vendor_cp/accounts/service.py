"""Vendor `AccountService` — the one owner of vendor-account state transitions.

Platform-level, so it builds on the kernel's PLATFORM-scoped primitives:
- **Idempotency** — `process_once_platform` runs a create AT MOST ONCE per
  `command_id` (globally unique, no tenant); a retried command replays the
  recorded result instead of creating a second account.
- **Audit** — `write_platform_audit_event` records the action against the acting
  `PlatformAdmin` in the platform audit trail.

Transaction-authority contract (kernel `db.py`): every function RECEIVES a
`Session` and only `add`/`flush`; it never constructs a session or
`commit`/`rollback` — the route (via `get_platform_db`) owns that boundary.
Typed commands and outcomes throughout (no bare dicts across the boundary).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from dotmac_kernel import ConflictError, write_platform_audit_event
from dotmac_kernel.messaging import process_once_platform
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.accounts.models import AccountStatus, VendorAccount

_COMMAND_TYPE_CREATE = "vendor.account.create"


# ── typed contracts ──────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class CreateAccountCommand:
    """Create a vendor account. `command_id` is the idempotency key: retrying the
    same `command_id` replays the first result. `actor_admin_id` is the platform
    admin performing the action (recorded in the audit trail; may be None for a
    system action)."""

    command_id: str
    external_ref: str
    display_name: str
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class AccountView:
    """A read model of a vendor account — the typed outcome returned across the
    service boundary (never the ORM row, never a bare dict)."""

    id: UUID
    external_ref: str
    display_name: str
    status: str


@dataclass(frozen=True, slots=True)
class CreateAccountResult:
    """Outcome of `create_account`. `was_duplicate` is True when a prior create
    with the same `command_id` was replayed rather than run again."""

    account: AccountView
    was_duplicate: bool


def _account_view(row: VendorAccount) -> AccountView:
    return AccountView(
        id=row.id,
        external_ref=row.external_ref,
        display_name=row.display_name,
        status=row.status,
    )


def create_account(db: Session, command: CreateAccountCommand) -> CreateAccountResult:
    """Create a vendor account idempotently, with an audit record.

    Raises `ConflictError` if a DIFFERENT command tries to create an account with
    an `external_ref` that already exists (a genuine conflict — distinct from an
    idempotent retry of the same `command_id`, which replays)."""

    def handler(session: Session) -> Mapping[str, object]:
        existing = session.execute(
            select(VendorAccount).where(
                VendorAccount.external_ref == command.external_ref
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(
                f"vendor account with external_ref {command.external_ref!r} "
                "already exists"
            )
        account = VendorAccount(
            external_ref=command.external_ref,
            display_name=command.display_name,
            status=AccountStatus.ACTIVE,
        )
        session.add(account)
        session.flush()
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
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
            "external_ref": account.external_ref,
            "display_name": account.display_name,
            "status": account.status,
        }

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_COMMAND_TYPE_CREATE,
        handler=handler,
    )
    r = outcome.result
    return CreateAccountResult(
        account=AccountView(
            id=UUID(str(r["account_id"])),
            external_ref=str(r["external_ref"]),
            display_name=str(r["display_name"]),
            status=str(r["status"]),
        ),
        was_duplicate=outcome.was_duplicate,
    )


def get_account(db: Session, account_id: UUID) -> AccountView | None:
    row = db.get(VendorAccount, account_id)
    return _account_view(row) if row is not None else None


def list_accounts(db: Session) -> list[AccountView]:
    rows = db.execute(
        select(VendorAccount).order_by(VendorAccount.created_at)
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
