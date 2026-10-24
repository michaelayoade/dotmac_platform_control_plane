"""Real PostgreSQL proofs for the bounded supported-deploy refusal guard.

Run on the dedicated test server using the existing scratch_db fixture/roles.
Direct rehearsal upgrades intentionally remain available to construct sources;
these tests do not implement or authorize the protected D16 transition.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from alembic import command
from sqlalchemy import Connection, create_engine, event, text
from sqlalchemy.engine import Engine, make_url

from vendor_cp.cli.commands import admin_migrate
from vendor_cp.cli.exits import ExitCode, Refusal
from vendor_cp.data_governance import DataGovernanceRefusal
from vendor_cp.migrations import (
    DEPLOYMENT_CONTROL_BARRIER,
    deploy_config,
    make_alembic_config,
)


@contextmanager
def _connect(url: str) -> Iterator[Connection]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            yield connection
    finally:
        engine.dispose()


def _catalog(url: str) -> tuple[tuple[object, ...], ...]:
    with _connect(url) as connection:
        return tuple(
            tuple(row)
            for row in connection.execute(
                text(
                    "SELECT n.nspname, c.relname, c.relkind, a.attname, "
                    "a.atttypid, a.attnotnull FROM pg_catalog.pg_class c "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                    "LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid "
                    "AND a.attnum > 0 AND NOT a.attisdropped "
                    "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
                    "AND n.nspname NOT LIKE 'pg_toast%' "
                    "ORDER BY n.nspname, c.relname, a.attnum"
                )
            )
        )


def _heads(url: str) -> tuple[str, ...]:
    with _connect(url) as connection:
        if (
            connection.execute(
                text("SELECT to_regclass('public.alembic_version')")
            ).scalar_one()
            is None
        ):
            return ()
        return tuple(
            connection.execute(
                text("SELECT version_num FROM public.alembic_version ORDER BY 1")
            ).scalars()
        )


def _assert_cli_refuses_without_ddl(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    before_catalog, before_heads = _catalog(url), _heads(url)
    statements: list[str] = []

    def capture(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        statements.append(statement)

    monkeypatch.setenv("MIGRATION_DATABASE_URL", url)
    event.listen(Engine, "before_cursor_execute", capture)
    try:
        with pytest.raises(Refusal) as caught:
            admin_migrate(argparse.Namespace(target="heads"))
    finally:
        event.remove(Engine, "before_cursor_execute", capture)
    assert caught.value.code == "owner.migration_transition_refused"
    assert caught.value.exit_code == ExitCode.REFUSED
    assert statements  # The guard inspected the live source.
    assert not any(
        statement.lstrip().split()[0].upper()
        in {
            "CREATE",
            "ALTER",
            "DROP",
            "TRUNCATE",
            "INSERT",
            "UPDATE",
            "DELETE",
            "GRANT",
            "REVOKE",
        }
        for statement in statements
    )
    assert _catalog(url) == before_catalog
    assert _heads(url) == before_heads


def test_old_live_head_refuses_before_any_ddl(
    scratch_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    command.upgrade(make_alembic_config(scratch_db), "v016_licensing_authority")
    assert "v016_licensing_authority" in _heads(scratch_db)
    _assert_cli_refuses_without_ddl(scratch_db, monkeypatch)
    before_catalog, before_heads = _catalog(scratch_db), _heads(scratch_db)
    environment = os.environ.copy()
    environment["MIGRATION_DATABASE_URL"] = scratch_db
    executable = shutil.which("dotmac-platform")
    assert executable is not None
    # Resolve the fixed installed console script; no caller-supplied executable.
    result = subprocess.run(  # noqa: S603
        [executable, "--format", "json", "admin", "migrate"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 3
    assert (
        json.loads(result.stdout)["refusal_code"]
        == "owner.migration_transition_refused"
    )
    assert _catalog(scratch_db) == before_catalog
    assert _heads(scratch_db) == before_heads


@pytest.mark.parametrize("version_table", [False, True])
@pytest.mark.parametrize("relation", ["table", "view"])
def test_populated_unversioned_database_refuses(
    scratch_db: str,
    monkeypatch: pytest.MonkeyPatch,
    version_table: bool,
    relation: str,
) -> None:
    with _connect(scratch_db) as connection:
        connection.execute(text("CREATE SCHEMA unversioned_estate"))
        if relation == "table":
            connection.execute(
                text("CREATE TABLE unversioned_estate.kept (value text)")
            )
            connection.execute(
                text("INSERT INTO unversioned_estate.kept VALUES ('preserved')")
            )
        else:
            connection.execute(
                text(
                    "CREATE VIEW unversioned_estate.kept AS "
                    "SELECT 'preserved'::text AS value"
                )
            )
        if version_table:
            connection.execute(
                text(
                    "CREATE TABLE public.alembic_version "
                    "(version_num varchar(64) PRIMARY KEY)"
                )
            )
        connection.commit()
    _assert_cli_refuses_without_ddl(scratch_db, monkeypatch)
    with _connect(scratch_db) as connection:
        assert (
            connection.execute(
                text("SELECT value FROM unversioned_estate.kept")
            ).scalar_one()
            == "preserved"
        )


@pytest.mark.parametrize("empty_version_table", [False, True])
def test_genuinely_fresh_database_can_deploy(
    scratch_db: str, empty_version_table: bool
) -> None:
    if empty_version_table:
        with _connect(scratch_db) as connection:
            connection.execute(
                text(
                    "CREATE TABLE public.alembic_version "
                    "(version_num varchar(64) PRIMARY KEY)"
                )
            )
            connection.commit()
    command.upgrade(deploy_config(scratch_db), "heads")
    assert _heads(scratch_db)
    # Repetition proves already-composed state is allowed too.
    command.upgrade(deploy_config(scratch_db), "heads")


def test_database_already_at_barrier_can_complete_composition(scratch_db: str) -> None:
    command.upgrade(make_alembic_config(scratch_db), DEPLOYMENT_CONTROL_BARRIER)
    assert DEPLOYMENT_CONTROL_BARRIER in _heads(scratch_db)
    command.upgrade(deploy_config(scratch_db), "heads")
    assert _heads(scratch_db)


def test_unknown_live_version_row_refuses(
    scratch_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _connect(scratch_db) as connection:
        connection.execute(
            text(
                "CREATE TABLE public.alembic_version "
                "(version_num varchar(64) PRIMARY KEY)"
            )
        )
        connection.execute(
            text("INSERT INTO public.alembic_version VALUES ('not_in_installed_graph')")
        )
        connection.commit()
    _assert_cli_refuses_without_ddl(scratch_db, monkeypatch)


def test_shadow_version_table_cannot_change_the_public_transition_decision(
    scratch_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    command.upgrade(make_alembic_config(scratch_db), "v016_licensing_authority")
    with _connect(scratch_db) as connection:
        connection.execute(text("CREATE SCHEMA shadow"))
        connection.execute(
            text("CREATE TABLE shadow.alembic_version (version_num varchar(64))")
        )
        connection.execute(
            text("INSERT INTO shadow.alembic_version VALUES (:revision)"),
            {"revision": DEPLOYMENT_CONTROL_BARRIER},
        )
        connection.commit()
    shadow_url = (
        make_url(scratch_db)
        .update_query_dict({"options": "-csearch_path=shadow,public"})
        .render_as_string(hide_password=False)
    )
    _assert_cli_refuses_without_ddl(shadow_url, monkeypatch)

    # The inverse proves the executor and composed-head postcondition use the
    # same public table: a stale shadow cannot cause replay on a complete DB.
    command.upgrade(make_alembic_config(scratch_db), "heads")
    before_public = _heads(scratch_db)
    with _connect(scratch_db) as connection:
        connection.execute(
            text("UPDATE shadow.alembic_version SET version_num = :revision"),
            {"revision": "v016_licensing_authority"},
        )
        connection.commit()
    # The existing catalogue gate must still reject the deliberately planted
    # unclassified table, after migration and composed-head checks complete.
    with pytest.raises(DataGovernanceRefusal, match="shadow.alembic_version"):
        command.upgrade(deploy_config(shadow_url), "heads")
    assert _heads(scratch_db) == before_public
    with _connect(scratch_db) as connection:
        assert (
            connection.execute(
                text("SELECT version_num FROM shadow.alembic_version")
            ).scalar_one()
            == "v016_licensing_authority"
        )
