"""The fail-closed greenfield Licensing issuer authority switch."""

from __future__ import annotations

import uuid

import pytest
from alembic import command
from sqlalchemy import create_engine, text

from vendor_cp.migrations import make_alembic_config

PRE_SWITCH_TARGETS = (
    "rl_0001_release_artifacts",
    "li_0001_licensing",
    "v015_agreements_authority",
)
SWITCH_REVISION = "v016_licensing_authority"
LEGACY_ISSUER_TABLES = (
    "licence_signing_keys",
    "licences",
    "licence_issuances",
    "licence_revocation_entries",
    "licence_revocation_lists",
)
RETAINED_DELIVERY_TABLES = (
    "licence_delivery_targets",
    "licence_deliveries",
    "licence_delivery_states",
    "licence_delivery_attempts",
    "licence_ack_records",
)
MODULE_TABLES = (
    "mod_licensing.signing_keys",
    "mod_licensing.licences",
    "mod_licensing.licence_issuances",
    "mod_licensing.licence_acknowledgements",
    "mod_licensing.revocations",
    "mod_licensing.revocation_lists",
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


def _seed_public_key(url: str) -> None:
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO public.licence_signing_keys "
                    "(id, key_id, public_key_b64, status) "
                    "VALUES (:id, 'legacy-public-1', 'public-material', 'active')"
                ),
                {"id": uuid.uuid4()},
            )
    finally:
        engine.dispose()


def _seed_delivery_evidence(url: str) -> uuid.UUID:
    ack_id = uuid.uuid4()
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO public.licence_ack_records "
                    "(id, licence_id, licence_version, digest, status, disposition) "
                    "VALUES (:id, 'unknown-lineage', 1, 'unknown-digest', "
                    "'rejected', 'unknown_licence')"
                ),
                {"id": ack_id},
            )
    finally:
        engine.dispose()
    return ack_id


def test_a_populated_legacy_issuer_stops_the_switch(scratch_db: str) -> None:
    _upgrade_to_pre_switch(scratch_db)
    _seed_public_key(scratch_db)

    with pytest.raises(RuntimeError, match="requires an EMPTY legacy issuer estate"):
        _upgrade(scratch_db, SWITCH_REVISION)

    for table in LEGACY_ISSUER_TABLES:
        assert _exists(scratch_db, f"public.{table}")
    for table in MODULE_TABLES:
        assert _exists(scratch_db, table)


def test_the_switch_retires_only_the_issuer_and_preserves_delivery_evidence(
    scratch_db: str,
) -> None:
    _upgrade_to_pre_switch(scratch_db)
    ack_id = _seed_delivery_evidence(scratch_db)
    _upgrade(scratch_db, SWITCH_REVISION)

    for table in LEGACY_ISSUER_TABLES:
        assert not _exists(scratch_db, f"public.{table}")
    for table in RETAINED_DELIVERY_TABLES:
        assert _exists(scratch_db, f"public.{table}")
    for table in MODULE_TABLES:
        assert _exists(scratch_db, table)

    engine = create_engine(scratch_db)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT id FROM public.licence_ack_records WHERE id=:id"),
                    {"id": ack_id},
                ).scalar_one()
                == ack_id
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_constraint c "
                        "JOIN pg_class t ON t.oid=c.conrelid "
                        "JOIN pg_namespace n ON n.oid=t.relnamespace "
                        "JOIN pg_attribute a ON a.attrelid=t.oid "
                        "AND a.attnum=ANY(c.conkey) "
                        "WHERE c.contype='f' AND n.nspname='public' "
                        "AND t.relname='licence_deliveries' "
                        "AND a.attname='issuance_id'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()


def test_a_fresh_composed_database_has_one_issuer_owner(scratch_db: str) -> None:
    _upgrade(scratch_db)
    for table in LEGACY_ISSUER_TABLES:
        assert not _exists(scratch_db, f"public.{table}")
    for table in MODULE_TABLES:
        assert _exists(scratch_db, table)


def test_the_authority_switch_refuses_downgrade(scratch_db: str) -> None:
    _upgrade(scratch_db)
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        command.downgrade(make_alembic_config(scratch_db), "v015_agreements_authority")
