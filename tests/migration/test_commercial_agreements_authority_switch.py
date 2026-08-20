"""The fail-closed greenfield Commercial Agreements authority switch."""

from __future__ import annotations

import uuid

import pytest
from alembic import command
from sqlalchemy import create_engine, text

from vendor_cp.migrations import make_alembic_config

PRE_SWITCH_TARGETS = (
    "rl_0001_release_artifacts",
    "cg_0001_agreements",
    "v014_allocations_authority",
)
SWITCH_REVISION = "v015_agreements_authority"
LEGACY_TABLES = ("contracts", "contract_lines")
MODULE_TABLES = (
    "mod_agreements.agreements",
    "mod_agreements.agreement_lines",
    "mod_agreements.agreement_events",
)


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _upgrade_to_pre_switch(url: str) -> None:
    for target in PRE_SWITCH_TARGETS:
        _upgrade(url, target)


def _exists(url: str, qualified: str) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return bool(
                connection.execute(
                    text("SELECT to_regclass(:name) IS NOT NULL"),
                    {"name": qualified},
                ).scalar()
            )
    finally:
        engine.dispose()


def _seed_legacy_contract(url: str) -> None:
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            offer_id = uuid.uuid4()
            contract_id = uuid.uuid4()
            connection.execute(
                text(
                    "INSERT INTO public.offer_versions "
                    "(id, product_code, offer_code, version, amount, "
                    "currency_code, capability_codes) VALUES "
                    "(:id, 'dotmac-sub', 'legacy', 1, '10.00', 'USD', "
                    "CAST('[\"cap.a\"]' AS jsonb))"
                ),
                {"id": offer_id},
            )
            connection.execute(
                text(
                    "INSERT INTO public.contracts "
                    "(id, product_code, customer_ref, legal_entity, "
                    "currency_code, term_start, term_end, status) VALUES "
                    "(:id, 'dotmac-sub', 'counterparty-1', 'Dotmac Ltd', "
                    "'USD', DATE '2026-01-01', DATE '2026-12-31', 'draft')"
                ),
                {"id": contract_id},
            )
            connection.execute(
                text(
                    "INSERT INTO public.contract_lines "
                    "(id, contract_id, offer_version_id, offer_code, "
                    "offer_version, capability_code, quantity) VALUES "
                    "(:id, :contract_id, :offer_id, 'legacy', 1, 'cap.a', 1)"
                ),
                {
                    "id": uuid.uuid4(),
                    "contract_id": contract_id,
                    "offer_id": offer_id,
                },
            )
    finally:
        engine.dispose()


def test_a_populated_legacy_estate_stops_the_switch(scratch_db: str) -> None:
    _upgrade_to_pre_switch(scratch_db)
    _seed_legacy_contract(scratch_db)

    with pytest.raises(RuntimeError, match="requires an EMPTY legacy estate"):
        _upgrade(scratch_db, SWITCH_REVISION)

    for table in LEGACY_TABLES:
        assert _exists(scratch_db, f"public.{table}")
    for table in MODULE_TABLES:
        assert _exists(scratch_db, table)


def test_the_same_switch_succeeds_when_the_measured_premise_holds(
    scratch_db: str,
) -> None:
    _upgrade_to_pre_switch(scratch_db)
    _upgrade(scratch_db, SWITCH_REVISION)

    for table in LEGACY_TABLES:
        assert not _exists(scratch_db, f"public.{table}")
    for table in MODULE_TABLES:
        assert _exists(scratch_db, table)


def test_a_fresh_composed_database_has_only_the_module_owner(scratch_db: str) -> None:
    _upgrade(scratch_db)
    for table in LEGACY_TABLES:
        assert not _exists(scratch_db, f"public.{table}")
    for table in MODULE_TABLES:
        assert _exists(scratch_db, table)


def test_the_authority_switch_refuses_downgrade(scratch_db: str) -> None:
    _upgrade(scratch_db)
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        command.downgrade(make_alembic_config(scratch_db), "v014_allocations_authority")
