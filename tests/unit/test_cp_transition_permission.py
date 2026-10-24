"""The historical exception is an opaque, single-use transaction capability."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from alembic.config import Config

from vendor_cp import migrations
from vendor_cp.deployment import image_heads


@pytest.fixture
def context(tmp_path, monkeypatch):
    versions = tmp_path / "versions"
    versions.mkdir()
    barrier = migrations.DEPLOYMENT_CONTROL_BARRIER
    for revision, parent in (("before", None), (barrier, "before")):
        (versions / f"{revision}.py").write_text(
            f"revision={revision!r}\ndown_revision={parent!r}\n"
            "depends_on=None\nbranch_labels=None\n"
        )
    config = Config()
    config.set_main_option("script_location", str(tmp_path))
    connection = Mock()
    connection.dialect = SimpleNamespace(name="postgresql")
    transaction = object()
    connection.get_transaction.return_value = transaction
    monkeypatch.setattr(migrations, "_source_heads", lambda _: ("before",))
    monkeypatch.setattr(image_heads, "composed_effective_heads", lambda _: (barrier,))
    return connection, transaction, config


def issue(context):
    connection, transaction, config = context
    permission = object()
    migrations._TRANSITION_PERMISSIONS[permission] = (
        connection,
        transaction,
        ("before",),
        (migrations.DEPLOYMENT_CONTROL_BARRIER,),
        "test-tree",
    )
    config.attributes["_cp_migration_tree_digest"] = "test-tree"
    config.attributes["_cp_transition_permission"] = permission
    return permission


def test_exact_connection_transaction_permission_is_consumed(context):
    permission = issue(context)
    connection, _, config = context
    migrations.require_deploy_transition(connection, config)
    assert permission not in migrations._TRANSITION_PERMISSIONS
    with pytest.raises(migrations.MigrationTransitionRefused, match="consumed"):
        migrations.require_deploy_transition(connection, config)


@pytest.mark.parametrize(
    "changed", ["connection", "transaction", "source", "target", "tree"]
)
def test_wrong_connection_or_drift_consumes_and_refuses(context, monkeypatch, changed):
    permission = issue(context)
    connection, _, config = context
    if changed == "connection":
        connection = Mock(dialect=SimpleNamespace(name="postgresql"))
    elif changed == "transaction":
        connection.get_transaction.return_value = object()
    elif changed == "tree":
        config.attributes["_cp_migration_tree_digest"] = "different-tree"
    elif changed == "source":
        # Use the capability directly to isolate drift from graph validation.
        with pytest.raises(migrations.MigrationTransitionRefused, match="drift"):
            migrations._consume_transition_permission(
                connection, config, ("changed",), permission
            )
        assert permission not in migrations._TRANSITION_PERMISSIONS
        return
    else:
        monkeypatch.setattr(image_heads, "composed_effective_heads", lambda _: ("new",))
    with pytest.raises(migrations.MigrationTransitionRefused, match="drift"):
        migrations.require_deploy_transition(connection, config)
    assert permission not in migrations._TRANSITION_PERMISSIONS


@pytest.mark.parametrize("forged", [True, False, "allow", {"approved": True}, object()])
def test_config_cannot_forge_private_permission(context, forged):
    connection, _, config = context
    config.attributes["_cp_transition_permission"] = forged
    with pytest.raises(migrations.MigrationTransitionRefused, match="permission"):
        migrations.require_deploy_transition(connection, config)


def test_generic_deploy_has_no_historical_exception(context):
    connection, _, config = context
    with pytest.raises(migrations.MigrationTransitionRefused, match="before DDL"):
        migrations.require_deploy_transition(connection, config)


def test_supplied_connection_config_does_not_replace_process_dsns(monkeypatch):
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "unchanged-migration")
    monkeypatch.setenv("DATABASE_URL", "unchanged-runtime")
    migrations.deploy_config(None)
    import os

    assert os.environ["MIGRATION_DATABASE_URL"] == "unchanged-migration"
    assert os.environ["DATABASE_URL"] == "unchanged-runtime"


def test_explicit_root_config_ignores_generic_ambient_root(tmp_path, monkeypatch):
    (tmp_path / "alembic.ini").write_text("[alembic]\n")
    monkeypatch.setenv(migrations.MIGRATION_ROOT_ENV_VAR, str(tmp_path / "foreign"))
    config = migrations.make_alembic_config(None, root=tmp_path)
    assert config.get_main_option("script_location") == str(tmp_path / "alembic")
    assert config.get_main_option("version_locations").endswith(
        str(tmp_path / "alembic" / "versions")
    )


@pytest.mark.parametrize("driver_autocommit", [True, False])
def test_observer_requires_actual_driver_autocommit_not_option_hint(driver_autocommit):
    from vendor_cp.deploy_agent.contracts import ContractError

    connection, observer = Mock(), Mock()
    for item in (connection, observer):
        item.dialect = SimpleNamespace(name="postgresql")
        item.engine.url = SimpleNamespace(host="/run/postgresql", port=5432)
        item.get_execution_options.return_value = {}
    connection.in_transaction.return_value = True
    connection.in_nested_transaction.return_value = False
    connection.connection.dbapi_connection.autocommit = False
    observer.connection.dbapi_connection.autocommit = driver_autocommit
    connection.execute.side_effect = RuntimeError("reached independent identity read")
    if driver_autocommit:
        with pytest.raises(RuntimeError, match="independent identity read"):
            migrations._observe_transition_connection(connection, observer, {}, Mock())
        connection.execute.assert_called_once()
    else:
        with pytest.raises(ContractError, match="fence_observer_autocommit_required"):
            migrations._observe_transition_connection(connection, observer, {}, Mock())
        connection.execute.assert_not_called()
