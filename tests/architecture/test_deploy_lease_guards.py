"""WP5c guards that need no database (DESIGN-rev3 2.6.2, 6.3).

* `v024_deploy_lease` is EXPAND-ONLY and grants exactly what 2.6.2 allows: USAGE on
  its own schema and EXECUTE on its five functions, to the CP runtime role, and
  nothing in `cp_lane3`; it never creates a role, never alters a default privilege,
  never drops or alters an object, and never identifies a caller by `session_user`
  (the W-i identity shift is explicit, not accidental).
* the lease client and handlers hold no engine, DSN or Foundation import: they
  speak through the request's own session.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "alembic" / "versions" / "v024_deploy_lease.py"
DEPLOYMENT = ROOT / "src" / "vendor_cp" / "deployment"
CLIENT_MODULES = (
    "deploy_lease.py",
    "deploy_lease_handlers.py",
    "deploy_lease_consume.py",
)


def _module() -> object:
    spec = importlib.util.spec_from_file_location("v024_guard", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _statements() -> list[str]:
    module = _module()
    return [
        *module.TABLES_SQL,  # type: ignore[attr-defined]
        *module.TRIGGER_FUNCTIONS_SQL,  # type: ignore[attr-defined]
        *module.TRIGGERS_SQL,  # type: ignore[attr-defined]
        *module.FUNCTIONS_SQL,  # type: ignore[attr-defined]
    ]


def test_the_migration_creates_only_in_its_own_schema() -> None:
    created = [
        s
        for s in _statements()
        if re.match(r"CREATE (TABLE|FUNCTION|TRIGGER)", s) is not None
    ]
    assert len(created) >= 8
    for statement in created:
        head = statement.split("(", 1)[0]
        assert (
            "cp_deploy_lease." in statement.split(" AS ")[0]
            or " ON cp_deploy_lease." in head
        ), statement[:80]
        assert "CREATE TABLE cp_lane3." not in statement
        assert "CREATE FUNCTION cp_lane3." not in statement
        assert " ON cp_lane3." not in head


def test_the_migration_is_expand_only_and_creates_no_role() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    for forbidden in (
        "CREATE ROLE",
        "ALTER ROLE",
        "ALTER DEFAULT PRIVILEGES",
        "DROP ",
        "ALTER TABLE",
        "ALTER FUNCTION",
        "ALTER SCHEMA",
        "CREATE OR REPLACE",
        "session_user",
        "SET ROLE",
        "EXECUTE format",
    ):
        assert forbidden not in code.split('"""', 2)[-1], forbidden


def test_the_only_grants_are_usage_on_own_schema_and_execute_on_five_functions() -> (
    None
):
    module = _module()
    source = MIGRATION.read_text(encoding="utf-8")
    grants = re.findall(r'f?"(GRANT [^"]+)"', source)
    assert sorted(grants) == sorted(
        [
            "GRANT USAGE ON SCHEMA {SCHEMA} TO {RUNTIME_ROLE}",
            "GRANT EXECUTE ON FUNCTION {SCHEMA}.{signature} TO {RUNTIME_ROLE}",
        ]
    )
    assert module.SCHEMA == "cp_deploy_lease"  # type: ignore[attr-defined]
    assert module.RUNTIME_ROLE == "platform_api"  # type: ignore[attr-defined]
    functions = module.RUNTIME_ROLE_FUNCTIONS  # type: ignore[attr-defined]
    assert sorted(f.split("(")[0] for f in functions) == [
        "deploy_acquire",
        "deploy_covers",
        "deploy_release",
        "deploy_renew",
        "deploy_standing",
    ]
    assert "GRANT" not in "".join(_statements())


def test_every_function_is_definer_pinned_and_refuses_with_the_lease_sqlstate() -> None:
    module = _module()
    for statement in module.FUNCTIONS_SQL:  # type: ignore[attr-defined]
        assert "SECURITY DEFINER SET search_path = pg_catalog, pg_temp" in statement
        assert "EXECUTE " not in statement.split("$$")[1]  # no dynamic SQL
        for raised in re.findall(r"RAISE EXCEPTION[^;]*;", statement):
            assert "ERRCODE = 'L3001'" in raised


def test_the_deploy_class_never_touches_a_rehearsal_table_but_the_shared_row_lock() -> (
    None
):
    module = _module()
    for statement in module.FUNCTIONS_SQL:  # type: ignore[attr-defined]
        for name in re.findall(r"cp_lane3\.([a-z_0-9]+)", statement):
            assert name in {
                "host_current_lease",
                "host_leases",
                "host_lease_releases",
                "store_now",
            }, name
        for write in re.findall(
            r"(?:INSERT INTO|UPDATE|DELETE FROM) (cp_lane3\.[a-z_]+)", statement
        ):
            assert write == "cp_lane3.host_current_lease", write


def test_the_lease_client_and_handlers_hold_no_engine_dsn_or_foundation_import() -> (
    None
):
    for name in CLIENT_MODULES:
        text = (DEPLOYMENT / name).read_text(encoding="utf-8")
        for forbidden in (
            "create_engine",
            "sessionmaker",
            "dotmac_deployment_foundation",
            "DATABASE_URL",
            "LANE3_LEASE_DATABASE_URL",
        ):
            assert forbidden not in text, (name, forbidden)
