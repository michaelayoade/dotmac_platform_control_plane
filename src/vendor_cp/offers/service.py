"""`OfferVersionService` — the one owner of immutable priced offer versions.

Platform-level, so it builds on the kernel's platform-scoped primitives
(idempotent `process_once_platform`, audited `write_platform_audit_event`) like
`AccountService`. Enforces the offer contract:

- **Immutable**: publishing a `(offer_code, version)` that already exists is a
  `ConflictError` — a version is never edited; a change is a new version.
- **Exact Money**: the price is `Money` (never float), stored as a quantized
  decimal string + ISO-4217 code and reconstructed losslessly.
- **Declared capabilities**: every granted capability code must be declared by an
  installed module (WS1 `CapabilityCatalogue.require`) — an offer may not invent a
  capability code.

Transaction-authority contract: receives a `Session` (via `get_platform_db`) and
only add/flush; the route owns commit. Typed commands/outcomes (no bare dicts).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from dotmac_kernel import (
    CapabilityCatalogue,
    ConflictError,
    Money,
    currency,
    write_platform_audit_event,
)
from dotmac_kernel.messaging import process_once_platform
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.offers.models import OfferVersion

_COMMAND_TYPE_PUBLISH = "vendor.offer_version.publish"


@dataclass(frozen=True, slots=True)
class PublishOfferVersionCommand:
    """Publish an immutable offer version. `command_id` is the idempotency key.
    `price` is exact `Money`; `capability_codes` must all be declared (WS1)."""

    command_id: str
    offer_code: str
    version: int
    price: Money
    capability_codes: tuple[str, ...]
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class OfferVersionView:
    """Typed read model of a published offer version."""

    id: UUID
    offer_code: str
    version: int
    price: Money
    capability_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PublishResult:
    offer_version: OfferVersionView
    was_duplicate: bool


def _view(row: OfferVersion) -> OfferVersionView:
    return OfferVersionView(
        id=row.id,
        offer_code=row.offer_code,
        version=row.version,
        price=Money.of(row.amount, currency(row.currency_code)),
        capability_codes=tuple(row.capability_codes),
    )


def publish_offer_version(
    db: Session,
    command: PublishOfferVersionCommand,
    *,
    catalogue: CapabilityCatalogue,
) -> PublishResult:
    """Publish an offer version idempotently, with an audit record. Raises
    `ConflictError` if `(offer_code, version)` already exists (immutable) OR — via
    the catalogue — `UndeclaredCapabilityError` for an undeclared code."""
    for code in command.capability_codes:
        catalogue.require(code)

    def handler(session: Session) -> Mapping[str, object]:
        existing = session.execute(
            select(OfferVersion).where(
                OfferVersion.offer_code == command.offer_code,
                OfferVersion.version == command.version,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(
                f"offer version {command.offer_code!r} v{command.version} already "
                "exists — versions are immutable"
            )
        row = OfferVersion(
            offer_code=command.offer_code,
            version=command.version,
            amount=str(command.price.amount),
            currency_code=command.price.currency.code,
            capability_codes=list(command.capability_codes),
        )
        session.add(row)
        session.flush()
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.offer_version.published",
            entity_type="offer_version",
            entity_id=str(row.id),
            details={
                "offer_code": row.offer_code,
                "version": row.version,
                "amount": row.amount,
                "currency": row.currency_code,
            },
        )
        return {"id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_COMMAND_TYPE_PUBLISH,
        handler=handler,
    )
    row = db.execute(
        select(OfferVersion).where(
            OfferVersion.offer_code == command.offer_code,
            OfferVersion.version == command.version,
        )
    ).scalar_one()
    return PublishResult(offer_version=_view(row), was_duplicate=outcome.was_duplicate)


def get_offer_version(
    db: Session, *, offer_code: str, version: int
) -> OfferVersionView | None:
    row = db.execute(
        select(OfferVersion).where(
            OfferVersion.offer_code == offer_code,
            OfferVersion.version == version,
        )
    ).scalar_one_or_none()
    return _view(row) if row is not None else None


def list_offer_versions(db: Session, *, offer_code: str) -> list[OfferVersionView]:
    rows = db.execute(
        select(OfferVersion)
        .where(OfferVersion.offer_code == offer_code)
        .order_by(OfferVersion.version)
    ).scalars()
    return [_view(r) for r in rows]


__all__ = [
    "PublishOfferVersionCommand",
    "OfferVersionView",
    "PublishResult",
    "publish_offer_version",
    "get_offer_version",
    "list_offer_versions",
]
