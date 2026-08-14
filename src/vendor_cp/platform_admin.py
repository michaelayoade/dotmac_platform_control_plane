"""Assembly policy for bootstrapping the kernel-owned platform identity.

The kernel owns ``PlatformAdmin``, password hashing, and the transaction
boundary. This service owns only the Vendor Control Plane's create-or-rotate
decision so operator entry points stay thin and importable tests exercise the
same installed code that production invokes.
"""

from __future__ import annotations

from dataclasses import dataclass

from dotmac_kernel import PlatformAdmin, hash_password
from sqlalchemy import func, select
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True)
class PlatformAdminUpsertResult:
    """Outcome of one create-or-rotate decision."""

    admin: PlatformAdmin
    created: bool


def upsert_platform_admin(
    db: Session, *, email: str, password: str, is_active: bool = True
) -> PlatformAdminUpsertResult:
    """Create or rotate one case-insensitive platform identity."""
    normalized = email.strip().lower()
    admin = db.scalars(
        select(PlatformAdmin).where(func.lower(PlatformAdmin.email) == normalized)
    ).first()
    created = admin is None
    if admin is None:
        admin = PlatformAdmin(
            email=normalized,
            password_hash=hash_password(password),
            is_active=is_active,
        )
        db.add(admin)
    else:
        admin.password_hash = hash_password(password)
        admin.is_active = is_active
    db.flush()
    return PlatformAdminUpsertResult(admin=admin, created=created)
