"""CP-1..CP-4/6 guards that read the source rather than a database.

* `v023_lane3_store` is EXPAND-ONLY: it creates, never drops, never alters an
  existing object, never creates a role (a prod deploy must not fail on one, F-G),
  never widens a default privilege, and refuses downgrade (retained evidence).
* No Lane 3 operator module generates, holds or reads a private key, and none takes
  a secret by argv: a secret arrives through a held file or stdin (AGENTS rule 21).
* No SECURITY DEFINER body uses dynamic SQL, and every one pins its `search_path`.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "alembic" / "versions" / "v023_lane3_store.py"
DEPLOYMENT = ROOT / "src" / "vendor_cp" / "deployment"
LANE3_MODULES = ("lane3_e10", "lane3_record", "lease_role_spec", "lease_role_check")


def _migration() -> object:
    spec = importlib.util.spec_from_file_location("v023_lane3_store", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _statements() -> list[str]:
    module = _migration()
    out: list[str] = []
    for name in (
        "CLOCK_SQL",
        "TABLES_SQL",
        "TRIGGER_FUNCTIONS_SQL",
        "TRIGGERS_SQL",
        "BINDING_FUNCTIONS_SQL",
        "LEASE_FUNCTIONS_SQL",
    ):
        out.extend(getattr(module, name))
    return out


def test_the_migration_only_creates() -> None:
    statements = _statements()
    assert len(statements) > 40
    for statement in statements:
        assert re.match(
            r"CREATE (TABLE|FUNCTION) cp_lane3\.|CREATE TRIGGER \w+ .* ON cp_lane3\.",
            statement,
        ), statement[:60]
        for forbidden in (
            "DROP ",
            "ALTER ",
            "CREATE ROLE",
            "CREATE USER",
            "GRANT ",
            "REPLICA IDENTITY",
        ):
            assert forbidden not in statement, (forbidden, statement[:60])


def test_the_migration_source_never_alters_an_existing_object_or_a_role() -> None:
    import inspect

    module = _migration()
    code = inspect.getsource(module.upgrade) + "\n".join(_statements())  # type: ignore[attr-defined]
    for forbidden in (
        "CREATE ROLE",
        "ALTER ROLE",
        "ALTER DEFAULT PRIVILEGES",
        "DROP TABLE",
        "DROP SCHEMA",
        "ALTER TABLE",
        "public.platform_idempotency_records",
        "mod_deploy.attestation_enrolments SET",
    ):
        assert forbidden not in code, forbidden
    # It WRITES `cp_lane3` and only READS Control's registry, nothing else.
    for statement in _statements():
        for written in re.findall(
            r"(?:INSERT INTO|UPDATE)\s+([a-z_0-9]+\.[a-z_0-9]+)", statement
        ):
            assert written.startswith("cp_lane3."), written
        for read in re.findall(
            r"(?:FROM|JOIN)\s+([a-z_0-9]+)\.([a-z_0-9]+)", statement
        ):
            schema = read[0]
            alias = len(schema) <= 3 or schema.startswith(("v_", "p_"))
            assert alias or schema in {"cp_lane3", "mod_deploy", "pg_catalog"}, read


def test_the_downgrade_is_refused() -> None:
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        _migration().downgrade()  # type: ignore[attr-defined]


def test_every_definer_function_pins_its_search_path_and_uses_no_dynamic_sql() -> None:
    definers = [s for s in _statements() if "SECURITY DEFINER" in s]
    assert len(definers) >= 11
    for statement in definers:
        assert "SET search_path = pg_catalog, cp_lane3, pg_temp" in statement
        body = statement.split("AS $$", 1)[1]
        assert not re.search(r"\bEXECUTE\b", body), statement[:80]
        assert "format(" not in body.lower()


def test_every_function_the_migration_creates_is_revoked_from_public() -> None:
    module = _migration()
    created = {
        m.group(1)
        for statement in _statements()
        for m in re.finditer(r"CREATE FUNCTION cp_lane3\.([a-z_0-9]+)\(", statement)
    }
    revoked = {
        signature.split("(")[0]
        for signature in (*module.LEASE_ROLE_FUNCTIONS, *module.INTERNAL_FUNCTIONS)  # type: ignore[attr-defined]
    }
    assert created == revoked


@pytest.mark.parametrize("name", LANE3_MODULES)
def test_no_lane3_operator_module_generates_or_holds_a_private_key(name: str) -> None:
    source = (DEPLOYMENT / f"{name}.py").read_text(encoding="utf-8")
    for forbidden in (
        "generate(",
        "private_bytes",
        "PRIVATE KEY",
        "load_pem_private_key",
        "Ed25519PrivateKey",
        "from_private_bytes",
    ):
        assert forbidden not in source, (name, forbidden)


_SECRET_WORDS = (
    "secret",
    "token",
    "password",
    "passwd",
    "private",
    "dsn",
    "credential-value",
)


@pytest.mark.parametrize("name", ["lane3_e10", "lane3_record"])
def test_no_lane3_parser_takes_a_secret_by_argv(name: str) -> None:
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    module = importlib.import_module(f"vendor_cp.deployment.{name}")
    if name == "lane3_e10":
        parser = module._build_parser()
    else:
        # `lane3_record` builds its parser inside `main`; read its option strings.
        source = (DEPLOYMENT / "lane3_record.py").read_text(encoding="utf-8")
        options = re.findall(r'add_argument\("(--[a-z0-9-]+)"', source)
        assert options
        for option in options:
            assert not any(word in option for word in _SECRET_WORDS), option
        return
    options: list[str] = []

    def collect(p: argparse.ArgumentParser) -> None:
        for action in p._actions:
            options.extend(action.option_strings)
            if isinstance(action, argparse._SubParsersAction):
                for sub in action.choices.values():
                    collect(sub)

    collect(parser)
    assert options
    for option in options:
        assert not any(word in option for word in _SECRET_WORDS), option
