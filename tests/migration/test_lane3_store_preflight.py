"""The v023 preflight and the read-only `lane3_store_preflight` command.

Each case builds a SCRATCH database that looks like production before the deploy
(`mod_deploy`, the append-only guard exactly as v020 creates it, a non-superuser
migration role that owns `mod_deploy`), breaks ONE precondition, and shows that the
migration refuses by name BEFORE any DDL (no `cp_lane3` schema afterwards) and that
the command reports the same failure. No Foundation and no composed lineage needed.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from vendor_cp.deployment import lane3_store_integrity as integrity
from vendor_cp.deployment import lane3_store_preflight as preflight

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "alembic" / "versions" / "v023_lane3_store.py"
V020 = ROOT / "alembic" / "versions" / "v020_withdrawal_outcomes.py"


def _guard_sql() -> str:
    """The guard function's statement, exactly as v020 hands it to `op.execute`."""
    for node in ast.walk(ast.parse(V020.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and "FUNCTION public.forbid_mutation_of_append_only_table"
            in node.args[0].value
        ):
            return node.args[0].value
    raise AssertionError("v020 no longer defines the guard")


def _migration() -> Any:
    spec = importlib.util.spec_from_file_location("v023_for_preflight_test", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Scratch:
    def __init__(self, postgres_url: str) -> None:
        self.url = postgres_url
        self.name = "vcp_pre_" + uuid.uuid4().hex[:10]
        self.role = "l3pre_" + uuid.uuid4().hex[:10]
        self.server = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        with self.server.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{self.name}"'))
            conn.execute(
                text(f'CREATE ROLE "{self.role}" LOGIN NOSUPERUSER NOCREATEROLE')
            )
            conn.execute(
                text(f'GRANT CREATE ON DATABASE "{self.name}" TO "{self.role}"')
            )
        self.engine = create_engine(
            make_url(postgres_url).set(database=self.name),
            isolation_level="AUTOCOMMIT",
        )
        self.sql(
            "CREATE SCHEMA mod_deploy",
            f'ALTER SCHEMA mod_deploy OWNER TO "{self.role}"',
        )
        with self.engine.begin() as conn:
            conn.execute(text(_guard_sql()))

    def sql(self, *statements: str) -> None:
        with self.engine.connect() as conn:
            for statement in statements:
                conn.exec_driver_sql(statement)

    def rows(self, sql: str, **params: Any) -> list[Any]:
        with self.engine.connect() as conn:
            return list(conn.execute(text(sql), params).all())

    def migrate(self, module: Any) -> None:
        """Run `upgrade()` as the (non-superuser) migration role."""
        plain = create_engine(make_url(self.url).set(database=self.name))
        try:
            with plain.begin() as conn:
                conn.exec_driver_sql(f'SET LOCAL ROLE "{self.role}"')
                with Operations.context(MigrationContext.configure(conn)):
                    module.upgrade()
        finally:
            plain.dispose()

    def schema_exists(self) -> bool:
        return bool(self.rows("SELECT 1 FROM pg_namespace WHERE nspname = 'cp_lane3'"))

    def checks(self) -> dict[str, bool]:
        with self.engine.connect() as conn:
            done = preflight.run_preflight(
                lambda sql, params=None: conn.execute(text(sql), params or {}).all(),
                role=self.role,
                migration_path=MIGRATION,
            )
        return dict(done)

    def close(self) -> None:
        self.engine.dispose()
        with self.server.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :n AND pid <> pg_backend_pid()"
                ),
                {"n": self.name},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{self.name}"'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{self.role}"'))
        self.server.dispose()


@pytest.fixture
def scratch(postgres_url: str) -> Iterator[Scratch]:
    s = Scratch(postgres_url)
    try:
        yield s
    finally:
        s.close()


def test_a_database_that_meets_every_precondition_passes_and_the_migration_runs(
    scratch: Scratch,
) -> None:
    checks = scratch.checks()
    assert checks and all(checks.values()), checks
    scratch.migrate(_migration())
    assert scratch.schema_exists()
    # one owner, and it is the role that ran the migration
    owners = scratch.rows(_owner_names_sql())
    assert {r[0] for r in owners} == {scratch.role}
    # afterwards the command correctly reports the schema as present
    assert scratch.checks()["schema-cp_lane3-absent"] is False


def _owner_names_sql() -> str:
    return integrity._OWNERS_SQL


def _event_trigger(s: Scratch) -> None:
    s.sql(
        "CREATE FUNCTION public.l3_evt() RETURNS event_trigger LANGUAGE plpgsql "
        "AS $$ BEGIN NULL; END $$",
        "CREATE EVENT TRIGGER l3_evt_trg ON ddl_command_start "
        "EXECUTE FUNCTION public.l3_evt()",
    )


_BREAKS: list[tuple[str, Any, str, str]] = [
    (
        "superuser",
        lambda s: s.sql(f'ALTER ROLE "{s.role}" SUPERUSER'),
        "migration-role-is-superuser",
        "migration-role-nosuperuser",
    ),
    (
        "createrole",
        lambda s: s.sql(f'ALTER ROLE "{s.role}" CREATEROLE'),
        "migration-role-has-createrole",
        "migration-role-nocreaterole",
    ),
    ("event_trigger", _event_trigger, "event-triggers-exist", "no-event-triggers"),
    (
        "default_acl_global",
        lambda s: s.sql(
            f'ALTER DEFAULT PRIVILEGES FOR ROLE "{s.role}" GRANT SELECT ON TABLES '
            "TO PUBLIC"
        ),
        "default-privileges-would-apply",
        "no-default-privileges-apply",
    ),
    (
        "guard_changed",
        lambda s: s.sql(
            "CREATE OR REPLACE FUNCTION public.forbid_mutation_of_append_only_table() "
            "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$"
        ),
        "append-only-guard-changed",
        "append-only-guard-digest-matches-pin",
    ),
    (
        "guard_absent",
        lambda s: s.sql("DROP FUNCTION public.forbid_mutation_of_append_only_table()"),
        "append-only-guard-absent",
        "append-only-guard-exists",
    ),
    (
        "schema_exists",
        lambda s: s.sql("CREATE SCHEMA cp_lane3"),
        "schema-already-exists",
        "schema-cp_lane3-absent",
    ),
]


@pytest.mark.parametrize(
    ("break_it", "migration_name", "check_name"),
    [pytest.param(b[1], b[2], b[3], id=b[0]) for b in _BREAKS],
)
def test_each_broken_precondition_is_refused_before_any_ddl_and_reported(
    scratch: Scratch, break_it: Any, migration_name: str, check_name: str
) -> None:
    break_it(scratch)
    existed = scratch.schema_exists()
    with pytest.raises(RuntimeError, match=migration_name):
        scratch.migrate(_migration())
    # nothing was created: the schema is as it was, and holds no object
    assert scratch.schema_exists() is existed
    assert (
        scratch.rows(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = "
            "c.relnamespace WHERE n.nspname = 'cp_lane3'"
        )[0][0]
        == 0
    )
    assert scratch.checks()[check_name] is False


def test_another_server_major_is_refused_by_the_migration_and_the_command(
    scratch: Scratch,
) -> None:
    module = _migration()
    module.PREFLIGHT_MAJOR = 17
    with pytest.raises(RuntimeError, match="server-major-not-16"):
        scratch.migrate(module)
    assert not scratch.schema_exists()
    # the command reads the same constant from the migration it loads
    with scratch.engine.connect() as conn:
        done = dict(
            preflight.run_preflight(
                lambda sql, params=None: conn.execute(text(sql), params or {}).all(),
                role=scratch.role,
                migration_path=_with_major(17),
            )
        )
    assert done["server-major-16"] is False


def _with_major(major: int) -> Path:
    import tempfile

    target = Path(tempfile.mkdtemp()) / "v023_lane3_store.py"
    source = MIGRATION.read_text(encoding="utf-8")
    assert "PREFLIGHT_MAJOR = 16" in source
    target.write_text(
        source.replace("PREFLIGHT_MAJOR = 16", f"PREFLIGHT_MAJOR = {major}")
    )
    return target


def test_the_migration_refuses_an_object_not_owned_by_the_migrating_role(
    scratch: Scratch,
) -> None:
    module = _migration()
    module.OWNER_NOT_MIGRATOR_SQL = "SELECT 1"
    with pytest.raises(RuntimeError, match="not owned by the migrating role"):
        scratch.migrate(module)
    assert not scratch.schema_exists()  # the whole upgrade rolled back


def test_the_owner_query_counts_a_foreign_owner_after_the_fact(
    scratch: Scratch,
) -> None:
    module = _migration()
    scratch.migrate(module)
    sql = module.OWNER_NOT_MIGRATOR_SQL.replace("current_user", f"'{scratch.role}'")
    assert scratch.rows(sql)[0][0] == 0
    scratch.sql(
        f'CREATE ROLE "{scratch.role}_x"',
        f'ALTER TABLE cp_lane3.run_bindings OWNER TO "{scratch.role}_x"',
    )
    try:
        assert scratch.rows(sql)[0][0] >= 1
    finally:
        scratch.sql(
            f'ALTER TABLE cp_lane3.run_bindings OWNER TO "{scratch.role}"',
            f'DROP ROLE "{scratch.role}_x"',
        )


def test_the_pins_agree_and_the_commands_sql_is_read_only() -> None:
    module = _migration()
    assert (
        module.PUBLIC_GUARD_SHA256
        == integrity.PUBLIC_FUNCTIONS["public.forbid_mutation_of_append_only_table()"]
    )
    for name in dir(preflight):
        value = getattr(preflight, name)
        if name.endswith("_SQL") and isinstance(value, str):
            assert value.lstrip().upper().startswith(("SELECT", "SHOW")), name
    for name in dir(module):
        value = getattr(module, name)
        if name.startswith("PREFLIGHT_") and name.endswith("_SQL"):
            assert value.lstrip().upper().startswith(("SELECT", "SHOW")), name


def test_the_command_prints_only_names_and_booleans_and_exits_by_the_result(
    scratch: Scratch, capsys: pytest.CaptureFixture[str]
) -> None:
    dsn = (
        make_url(scratch.url)
        .set(database=scratch.name)
        .render_as_string(hide_password=False)
    )
    env = {preflight.ADMIN_DSN_ENV: dsn}
    assert preflight.main(["--role", scratch.role], env, migration_path=MIGRATION) == 0
    out = capsys.readouterr().out
    line = re.compile(r"^(ok|FAIL|info) [A-Za-z0-9_.-]+(=[A-Za-z0-9_.-]+)?$")
    assert out.strip() and all(line.fullmatch(x) for x in out.splitlines()), out
    assert f"info mod_deploy_owner={scratch.role}" in out
    assert "info role_superuser=false" in out
    assert dsn not in out
    # a failing precondition: non-zero exit and a FAIL line, still only names
    scratch.sql(f'ALTER ROLE "{scratch.role}" CREATEROLE')
    assert preflight.main(["--role", scratch.role], env, migration_path=MIGRATION) == 2
    out = capsys.readouterr().out
    assert "FAIL migration-role-nocreaterole" in out
    assert all(line.fullmatch(x) for x in out.splitlines()), out
    # no DSN: refuses without a value; an unreachable one is 4, class name only
    assert preflight.main([], {}) == 2
    assert (
        preflight.main(
            ["--role", "x"],
            {preflight.ADMIN_DSN_ENV: "postgresql+psycopg://u:secretpw@127.0.0.1:1/x"},
        )
        == 4
    )
    assert "secretpw" not in capsys.readouterr().err
