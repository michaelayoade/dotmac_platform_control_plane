#!/usr/bin/env python
"""Bootstrap or rotate a platform admin through the kernel-owned DB boundary.

This is the Vendor assembly's operator adapter for the platform identity the
kernel owns. There is deliberately no HTTP self-registration path. Passwords
are prompted and never accepted on argv.
"""

from __future__ import annotations

import argparse
import getpass

from dotmac_kernel import PlatformAdmin, hash_password
from dotmac_kernel.db import platform_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session


def upsert_admin(
    db: Session, *, email: str, password: str, is_active: bool = True
) -> PlatformAdmin:
    """Create or rotate one case-insensitive platform identity."""
    normalized = email.strip().lower()
    admin = db.scalars(
        select(PlatformAdmin).where(func.lower(PlatformAdmin.email) == normalized)
    ).first()
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
    return admin


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("email", help="Admin email (unique, case-insensitive)")
    parser.add_argument(
        "--inactive",
        action="store_true",
        help="Create or update the identity as inactive",
    )
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    if not password:
        parser.error("empty password")
    if getpass.getpass("Confirm password: ") != password:
        parser.error("passwords do not match")

    with platform_session() as db:
        existed = db.scalars(
            select(PlatformAdmin).where(
                func.lower(PlatformAdmin.email) == args.email.strip().lower()
            )
        ).first()
        admin = upsert_admin(
            db,
            email=args.email,
            password=password,
            is_active=not args.inactive,
        )
        state = "inactive" if args.inactive else "active"
        action = "updated" if existed is not None else "created"
        identity = admin.email

    print(f"Platform admin {identity} {action} ({state}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
