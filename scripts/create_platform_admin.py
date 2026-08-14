#!/usr/bin/env python
"""Bootstrap or rotate a platform admin through the kernel-owned DB boundary.

This is the Vendor assembly's operator adapter for the platform identity the
kernel owns. There is deliberately no HTTP self-registration path. Passwords
are prompted and never accepted on argv.
"""

from __future__ import annotations

import argparse
import getpass

from dotmac_kernel.db import platform_session

from vendor_cp.platform_admin import upsert_platform_admin


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
        result = upsert_platform_admin(
            db,
            email=args.email,
            password=password,
            is_active=not args.inactive,
        )
        state = "inactive" if args.inactive else "active"
        action = "created" if result.created else "updated"
        identity = result.admin.email

    print(f"Platform admin {identity} {action} ({state}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
