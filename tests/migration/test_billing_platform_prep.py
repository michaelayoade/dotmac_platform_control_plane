"""Live proof for Vendor CP's platform-only Billing preparation."""

from __future__ import annotations

from alembic import command
from dotmac_billing.models import PLATFORM_TABLES, TENANT_TABLES
from dotmac_kernel.planes import ModulePlane
from sqlalchemy import create_engine, text

from vendor_cp.migration_bindings import ASSEMBLY_MODULE_PLANES
from vendor_cp.migrations import make_alembic_config

SCHEMA = "mod_billing"
LINK_TABLES = {
    "billing_vendor_account_links": "vendor_accounts",
    "billing_contract_links": "contracts",
}
TABLE_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")


def _upgrade(url: str) -> None:
    command.upgrade(make_alembic_config(url), "heads")


def _relations(url: str, schema: str) -> frozenset[str]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return frozenset(
                connection.execute(
                    text(
                        "SELECT c.relname FROM pg_class c "
                        "JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = :schema AND c.relkind = 'r'"
                    ),
                    {"schema": schema},
                ).scalars()
            )
    finally:
        engine.dispose()


def test_vendor_installs_only_billing_platform_tables(scratch_db: str) -> None:
    _upgrade(scratch_db)
    selected = {
        ModulePlane(plane)
        for selection in ASSEMBLY_MODULE_PLANES
        if selection.module == "billing"
        for plane in selection.planes
    }
    relations = _relations(scratch_db, SCHEMA)
    assert selected == {ModulePlane.PLATFORM}
    assert set(PLATFORM_TABLES) <= relations
    assert not set(TENANT_TABLES) & relations

    engine = create_engine(scratch_db)
    try:
        with engine.connect() as connection:
            tenant_count = connection.execute(
                text("SELECT count(*) FROM tenants")
            ).scalar()
            assert tenant_count == 0
    finally:
        engine.dispose()


def test_product_links_are_platform_shaped_and_target_the_right_plane(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db)
    engine = create_engine(scratch_db)
    try:
        with engine.connect() as connection:
            for table_name, subject_table in LINK_TABLES.items():
                columns = set(
                    connection.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema = 'public' AND table_name = :table"
                        ),
                        {"table": table_name},
                    ).scalars()
                )
                assert "tenant_id" not in columns

                rls = connection.execute(
                    text(
                        "SELECT c.relrowsecurity, c.relforcerowsecurity "
                        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = 'public' AND c.relname = :table"
                    ),
                    {"table": table_name},
                ).one()
                assert tuple(rls) == (False, False)

                targets = set(
                    connection.execute(
                        text(
                            "SELECT rn.nspname, r.relname FROM pg_constraint con "
                            "JOIN pg_class t ON t.oid = con.conrelid "
                            "JOIN pg_namespace tn ON tn.oid = t.relnamespace "
                            "JOIN pg_class r ON r.oid = con.confrelid "
                            "JOIN pg_namespace rn ON rn.oid = r.relnamespace "
                            "WHERE con.contype = 'f' AND tn.nspname = 'public' "
                            "AND t.relname = :table"
                        ),
                        {"table": table_name},
                    ).all()
                )
                assert targets == {
                    (SCHEMA, "platform_billing_accounts"),
                    ("public", subject_table),
                }

                qualified = f"public.{table_name}"
                assert not any(
                    connection.execute(
                        text("SELECT has_table_privilege('app_user', :table, :p)"),
                        {"table": qualified, "p": privilege},
                    ).scalar_one()
                    for privilege in TABLE_PRIVILEGES
                )
                assert all(
                    connection.execute(
                        text("SELECT has_table_privilege('platform_api', :table, :p)"),
                        {"table": qualified, "p": privilege},
                    ).scalar_one()
                    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE")
                )
                assert not any(
                    connection.execute(
                        text(
                            "SELECT coalesce(bool_or(has_column_privilege("
                            "'app_user', :table, column_name, :p)), false) "
                            "FROM information_schema.columns "
                            "WHERE table_schema = 'public' AND table_name = :name"
                        ),
                        {"table": qualified, "name": table_name, "p": privilege},
                    ).scalar_one()
                    for privilege in COLUMN_PRIVILEGES
                )
    finally:
        engine.dispose()
