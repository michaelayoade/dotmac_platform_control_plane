"""Dedicated PostgreSQL proofs of the private Alembic connection boundary.

Issuance is isolated here to exercise actual historical DDL/transactions. The
retained-stage and real restore acceptance belongs to the host composition
suite; these tests do not claim an authorized host transition occurred.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest
import sqlalchemy
from alembic import command
from sqlalchemy import create_engine, event, text

from vendor_cp import migrations
from vendor_cp.deployment.image_heads import composed_effective_heads


@pytest.fixture
def historical(scratch_db):
    command.upgrade(
        migrations.make_alembic_config(scratch_db), "v016_licensing_authority"
    )
    engine = create_engine(scratch_db)
    try:
        yield engine
    finally:
        engine.dispose()


def _config(connection):
    config = migrations.deploy_config(None)
    permission = object()
    source = tuple(sorted(migrations._source_heads(connection)))
    migrations._TRANSITION_PERMISSIONS[permission] = (
        connection,
        connection.get_transaction(),
        source,
        composed_effective_heads(config),
        "test-tree",
    )
    config.attributes["connection"] = connection
    config.attributes["_cp_migration_tree_digest"] = "test-tree"
    config.attributes["_cp_transition_permission"] = permission
    return config, permission


def test_historical_upgrade_uses_exact_connection_and_caller_transaction(
    historical, monkeypatch
):
    with historical.connect() as connection:
        with connection.begin() as transaction:
            config, permission = _config(connection)
            expected = composed_effective_heads(config)
            forbid_engine = Mock(side_effect=AssertionError("opened a second engine"))
            monkeypatch.setattr(sqlalchemy, "engine_from_config", forbid_engine)
            command.upgrade(config, "heads")
            forbid_engine.assert_not_called()
            assert connection.get_transaction() is transaction
            assert tuple(sorted(migrations._source_heads(connection))) == expected
            assert permission not in migrations._TRANSITION_PERMISSIONS
        # Generic repeat deploy is eligible once the barrier has been reached.
        with connection.begin():
            config = migrations.deploy_config(None)
            config.attributes["connection"] = connection
            command.upgrade(config, "heads")
    with historical.connect() as connection:
        assert tuple(sorted(migrations._source_heads(connection))) == expected


def test_failed_postcondition_rolls_back_entire_historical_upgrade(
    historical, monkeypatch
):
    from vendor_cp import data_governance

    enforce = data_governance.enforce_retention

    def reject_commit(connection):
        enforce(connection)
        raise RuntimeError("rollback canary")

    monkeypatch.setattr(data_governance, "enforce_retention", reject_commit)
    with historical.connect() as connection:
        source = migrations._source_heads(connection)
        catalogue = text(
            "SELECT n.nspname, c.relname, c.relkind FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
            "ORDER BY 1, 2, 3"
        )
        before = connection.execute(catalogue).all()
        connection.rollback()
        with pytest.raises(RuntimeError, match="rollback canary"):
            with connection.begin():
                config, permission = _config(connection)
                command.upgrade(config, "heads")
        assert permission not in migrations._TRANSITION_PERMISSIONS
        assert migrations._source_heads(connection) == source
        assert connection.execute(catalogue).all() == before


def test_wrong_connection_refuses_historical_source_before_ddl(historical):
    with historical.connect() as bound, historical.connect() as other:
        with bound.begin(), other.begin():
            config, permission = _config(bound)
            config.attributes["connection"] = other
            statements = []

            def capture(_conn, _cursor, statement, *_):
                statements.append(statement.lstrip().split()[0].upper())

            event.listen(other, "before_cursor_execute", capture)
            with pytest.raises(migrations.MigrationTransitionRefused, match="drift"):
                command.upgrade(config, "heads")
            assert permission not in migrations._TRANSITION_PERMISSIONS
            assert not set(statements) & {
                "CREATE",
                "ALTER",
                "DROP",
                "INSERT",
                "UPDATE",
                "DELETE",
                "GRANT",
                "REVOKE",
            }
