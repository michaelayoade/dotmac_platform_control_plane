"""The composed Billing and Subscriptions PLATFORM planes stay read-only."""

from __future__ import annotations

from collections.abc import Mapping
from uuid import uuid4

import pytest
from alembic import command
from dotmac_billing import module as billing_module
from dotmac_kernel.planes import ModulePlane
from dotmac_subscriptions import module as subscriptions_module
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from vendor_cp.commercial_shadow_readiness import (
    observe_commercial_shadow_readiness,
)
from vendor_cp.migration_bindings import ASSEMBLY_MODULE_PLANES
from vendor_cp.migrations import make_alembic_config

ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"
WRITE_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})

MODULE_TABLES: Mapping[str, tuple[str, ...]] = {
    "mod_billing": tuple(billing_module.platform_tables),
    "mod_subscriptions": tuple(subscriptions_module.platform_tables),
}
TENANT_TABLES: Mapping[str, tuple[str, ...]] = {
    "mod_billing": tuple(billing_module.tables),
    "mod_subscriptions": tuple(subscriptions_module.tables),
}


def _upgrade(url: str) -> None:
    command.upgrade(make_alembic_config(url), "heads")


def _query(url: str, statement: str, **parameters: object):
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return connection.execute(text(statement), parameters).scalar()
    finally:
        engine.dispose()


def _holds(url: str, role: str, relation: str, privilege: str) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    return bool(_query(url, statement, role=role, rel=relation, priv=privilege))


def test_commercial_modules_select_only_the_platform_plane() -> None:
    selected = {
        selection.module: {ModulePlane(plane) for plane in selection.planes}
        for selection in ASSEMBLY_MODULE_PLANES
        if selection.module in {"billing", "subscriptions"}
    }
    assert selected == {
        "billing": {ModulePlane.PLATFORM},
        "subscriptions": {ModulePlane.PLATFORM},
    }


def test_selected_tables_exist_and_tenant_tables_do_not(scratch_db: str) -> None:
    _upgrade(scratch_db)
    for schema, tables in MODULE_TABLES.items():
        assert tables
        for table in tables:
            assert _query(
                scratch_db,
                "SELECT to_regclass(:relation) IS NOT NULL",
                relation=f"{schema}.{table}",
            )
    for schema, tables in TENANT_TABLES.items():
        assert tables
        for table in tables:
            assert not _query(
                scratch_db,
                "SELECT to_regclass(:relation) IS NOT NULL",
                relation=f"{schema}.{table}",
            )


@pytest.mark.parametrize(
    ("schema", "table"),
    [(schema, table) for schema, tables in MODULE_TABLES.items() for table in tables],
)
def test_online_role_is_read_only_and_tenant_role_is_denied(
    scratch_db: str, schema: str, table: str
) -> None:
    _upgrade(scratch_db)
    relation = f"{schema}.{table}"
    assert _holds(scratch_db, ONLINE_ROLE, relation, "SELECT")
    assert not [
        privilege
        for privilege in WRITE_PRIVILEGES
        if _holds(scratch_db, ONLINE_ROLE, relation, privilege)
    ]
    assert not [
        privilege
        for privilege in ("SELECT", *WRITE_PRIVILEGES)
        if _holds(scratch_db, TENANT_ROLE, relation, privilege)
    ]


def test_privilege_reader_detects_a_column_level_write(scratch_db: str) -> None:
    _upgrade(scratch_db)
    relation = "mod_billing.platform_billing_accounts"
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "GRANT UPDATE (id) ON mod_billing.platform_billing_accounts "
                    "TO platform_api"
                )
            )
        assert _holds(scratch_db, ONLINE_ROLE, relation, "UPDATE")
        with engine.begin() as connection:
            connection.execute(
                text(
                    "REVOKE UPDATE (id) ON mod_billing.platform_billing_accounts "
                    "FROM platform_api"
                )
            )
    finally:
        engine.dispose()

    assert not _holds(scratch_db, ONLINE_ROLE, relation, "UPDATE")


def test_shadow_tables_start_empty(scratch_db: str) -> None:
    _upgrade(scratch_db)
    populated = {
        f"{schema}.{table}": int(
            _query(scratch_db, f"SELECT count(*) FROM {schema}.{table}") or 0  # noqa: S608
        )
        for schema, tables in MODULE_TABLES.items()
        for table in tables
    }
    assert populated and not {name: count for name, count in populated.items() if count}


def test_readiness_report_separates_source_mapping_from_target_population(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db)
    offer_id = uuid4()
    agreement_id = uuid4()
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO public.offer_versions
                        (id, product_code, offer_code, version, amount,
                         currency_code, capability_codes)
                    VALUES (:id, 'dotmac-sub', 'starter', 1, '10.00', 'USD',
                            '["billing.use"]'::jsonb)
                    """
                ),
                {"id": offer_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO mod_agreements.agreements
                        (id, reference, agreement_family_id, agreement_version,
                         counterparty_ref, agreement_type, status,
                         effective_date, expiry_date, record_version)
                    VALUES (:id, 'test-agreement', :family_id, 1,
                            'test-counterparty', 'software_subscription',
                            'draft', DATE '2026-01-01', DATE '2026-12-31', 1)
                    """
                ),
                {"id": agreement_id, "family_id": uuid4()},
            )
            for line_no, offer_ref, amount in (
                (1, str(offer_id), "10.00"),
                (2, str(uuid4()), "10.00"),
                (3, str(offer_id), "11.00"),
            ):
                connection.execute(
                    text(
                        """
                        INSERT INTO mod_agreements.agreement_lines
                            (id, agreement_id, line_no, product_code,
                             offer_ref, capability_code, quantity,
                             unit_amount, unit_currency_code)
                        VALUES (:id, :agreement_id, :line_no, 'dotmac-sub',
                                :offer_ref, 'billing.use', 1, :amount, 'USD')
                        """
                    ),
                    {
                        "id": uuid4(),
                        "agreement_id": agreement_id,
                        "line_no": line_no,
                        "offer_ref": offer_ref,
                        "amount": amount,
                    },
                )
            connection.execute(
                text(
                    """
                    INSERT INTO mod_billing.platform_billing_accounts
                        (id, external_account_ref, currency, minor_units)
                    VALUES (:id, 'test-account', 'USD', 2)
                    """
                ),
                {"id": uuid4()},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO mod_subscriptions.platform_offers
                        (id, code, name, status)
                    VALUES (:id, 'test-offer', 'Test offer', 'draft')
                    """
                ),
                {"id": uuid4()},
            )

        with Session(engine) as db:
            report = observe_commercial_shadow_readiness(db)
            assert report.source_completeness.offer_versions == 1
            assert report.source_completeness.agreement_headers == 1
            assert report.source_completeness.agreement_lines == 3
            assert report.source_mapping.agreement_lines_without_resolved_offer == 1
            assert report.source_mapping.agreement_lines_with_frozen_offer_mismatch == 1
            assert report.source_mapping.blocker_count == 2
            assert report.billing_target.rows == 1
            assert report.billing_target.populated_tables == 1
            assert report.subscriptions_target.rows == 1
            assert report.subscriptions_target.populated_tables == 1
            assert (
                db.execute(text("SHOW transaction_isolation")).scalar_one()
                == "repeatable read"
            )
            assert db.execute(text("SHOW transaction_read_only")).scalar_one() == "on"

            with pytest.raises(DBAPIError, match="read-only transaction"):
                db.execute(
                    text(
                        """
                        INSERT INTO mod_billing.platform_billing_accounts
                            (id, external_account_ref, currency, minor_units)
                        VALUES (:id, 'forbidden', 'USD', 2)
                        """
                    ),
                    {"id": uuid4()},
                )
    finally:
        engine.dispose()
