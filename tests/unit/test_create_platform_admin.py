"""The operator CLI preserves the kernel platform-identity contract."""

from __future__ import annotations

from dotmac_kernel import PlatformAdmin, verify_password
from dotmac_kernel.testing import create_test_engine, isolated_session
from scripts.create_platform_admin import upsert_admin


def test_upsert_normalizes_identity_and_rotates_in_place() -> None:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as db:
            created = upsert_admin(
                db,
                email="  Operator@Dotmac.IO ",
                password="first-password",
            )
            created_id = created.id
            assert created.email == "operator@dotmac.io"
            assert verify_password("first-password", created.password_hash)

            updated = upsert_admin(
                db,
                email="OPERATOR@DOTMAC.IO",
                password="replacement-password",
                is_active=False,
            )

            assert updated.id == created_id
            assert not updated.is_active
            assert verify_password("replacement-password", updated.password_hash)
            assert db.query(PlatformAdmin).count() == 1
    finally:
        engine.dispose()
