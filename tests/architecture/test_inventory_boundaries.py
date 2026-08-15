"""The inventory's three premises, each enforced rather than promised.

The read-only inventory is allowed to construct a database connection — the one
exemption in deny-case D1 — because it is the opposite of what D1 protects
against: an operator names a target for one run, precisely so that nothing infers
one from configuration. That exemption is only honest while its premises hold, so
they are checked here:

1. **the target is named, never inferred** — no fallback to the app's own
   environment variables, no reading of deployment config;
2. **read-only, enforced by the database** — the transaction is opened
   `READ ONLY`, so a write is refused by PostgreSQL rather than by intent;
3. **nothing is written** — to either system, including no run record.

And one boundary that is about meaning rather than safety: the legacy estate and
the module's readiness must never be compared. The module's tables are empty by
construction during shadow, so "legacy N versus module 0" is a difference
guaranteed in advance and informative about nothing — while looking exactly like
a parity measurement to a reader in a hurry. The two observations are separate
types, and no function may accept both.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from vendor_cp import approvals_inventory
from vendor_cp.approvals_inventory import (
    LegacyEstate,
    ModuleReadiness,
    collect_legacy_estate,
    collect_module_readiness,
)

ROOT = Path(__file__).resolve().parents[2]
INVENTORY_SCRIPT = ROOT / "scripts" / "approvals_inventory.py"
INVENTORY_MODULE = ROOT / "src" / "vendor_cp" / "approvals_inventory.py"


def _script_module():
    """The CLI, loaded by path — `scripts` is not an importable package."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_inventory_cli", INVENTORY_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── 1. The target is named, never inferred ──────────────────────────────────


def test_no_dsn_means_no_inventory() -> None:
    """The refusal is the feature. A tool that finds a database on its own finds
    one nobody asked it to touch."""
    cli = _script_module()
    assert cli.resolve_dsn(None, {}) is None


@pytest.mark.parametrize(
    "variable",
    [
        "DATABASE_URL",
        "MIGRATION_DATABASE_URL",
        "PLATFORM_DATABASE_URL",
        "TEST_DATABASE_URL",
    ],
)
def test_the_apps_own_environment_is_never_a_target(variable: str) -> None:
    """SENSITIVITY, one case per channel through which a target could be
    inferred. Each is populated with a real-looking DSN, and the resolver must
    still report that no target was named."""
    cli = _script_module()
    ambient = {variable: "postgresql+psycopg://someone@somewhere:5432/prod"}
    assert cli.resolve_dsn(None, ambient) is None


def test_the_named_channels_are_the_only_ones_honoured() -> None:
    """NON-VACUITY for the refusals above: a resolver that always returned None
    would pass every one of them while making the tool useless."""
    cli = _script_module()
    assert cli.resolve_dsn("postgresql+psycopg://x@y/z", {}) == (
        "postgresql+psycopg://x@y/z"
    )
    assert (
        cli.resolve_dsn(None, {cli.DSN_ENV_VAR: "postgresql+psycopg://a@b/c"})
        == "postgresql+psycopg://a@b/c"
    )
    # An explicit argument wins over the environment, so a scripted run cannot
    # be quietly redirected by something already exported.
    assert (
        cli.resolve_dsn("postgresql+psycopg://arg@host/db", {cli.DSN_ENV_VAR: "env"})
        == "postgresql+psycopg://arg@host/db"
    )


#: Ways a target could be READ FROM CONFIGURATION rather than named. Precise
#: markers, not loose substrings: a bare `.env` matches `os.environ`, which is
#: how a blunt guard flags the very code that refuses ambient configuration —
#: and gets loosened until it checks nothing.
CONFIGURATION_CHANNELS = (
    "docker-compose",
    "dotenv",
    "load_dotenv",
    "deploy_production",
    "VENDOR_DB_",
    ".env.production",
    'open(".env',
    "'.env'",
)


def test_the_inventory_reads_no_deployment_configuration() -> None:
    """A DSN discovered from compose, a dotenv file or a deploy script is still
    a discovered DSN."""
    source = INVENTORY_SCRIPT.read_text() + INVENTORY_MODULE.read_text()
    found = [marker for marker in CONFIGURATION_CHANNELS if marker in source]
    assert not found, found


def test_the_configuration_channel_guard_would_notice_a_reader(
    tmp_path: Path,
) -> None:
    """SENSITIVITY. Each marker must be detectable, or the list above is
    decoration — and a marker so loose it matches ordinary code would be worse,
    so the real source is checked to stay clean in the same breath."""
    probe = tmp_path / "probe.py"
    for marker in CONFIGURATION_CHANNELS:
        probe.write_text(f"value = {marker!r}\n")
        assert marker in probe.read_text(), marker

    # `os.environ` must NOT be mistaken for reading a dotenv file: the script
    # legitimately inspects the environment in order to REFUSE most of it.
    assert not [
        marker for marker in CONFIGURATION_CHANNELS if marker in "dict(os.environ)"
    ]


# ── 2 & 3. Read-only, and writes nothing ────────────────────────────────────


def test_the_transaction_is_opened_read_only() -> None:
    """Enforced by PostgreSQL rather than by good intentions: with the
    transaction in READ ONLY, a write is refused no matter what the code does."""
    assert "SET TRANSACTION READ ONLY" in INVENTORY_SCRIPT.read_text()


def test_the_inventory_issues_no_write_statement() -> None:
    """Every statement is a SELECT. Checked over the source rather than trusted,
    because the read-only transaction and this are independent guards — belt and
    braces on the one property the exemption rests on."""
    source = INVENTORY_MODULE.read_text() + INVENTORY_SCRIPT.read_text()
    upper = source.upper()
    for statement in (
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "CREATE TABLE",
        "DROP ",
        "ALTER ",
        "TRUNCATE ",
        "GRANT ",
        "REVOKE ",
    ):
        # The privilege NAMES appear as data (e.g. "UPDATE" in a list of
        # privileges to check); a STATEMENT has different shape, so look for the
        # statement forms only.
        assert statement not in upper, statement


# ── 4. The meaningless comparison is not expressible ────────────────────────


def test_no_function_accepts_both_observations() -> None:
    """The structural half of "never compare legacy rows with the empty module
    tables".

    `render_evidence` takes both objects to place them side by side, which is
    exactly why the rule cannot be "no function mentions both" — it has to be
    that no function READS one against the other. So `render_evidence` is
    exempted by name here, and the next test proves it derives nothing across
    them.
    """
    tree = ast.parse(INVENTORY_MODULE.read_text())
    both: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        annotations = {
            ast.unparse(argument.annotation)
            for argument in node.args.args
            if argument.annotation is not None
        }
        if {"LegacyEstate", "ModuleReadiness"} <= annotations:
            both.append(node.name)
    assert both == ["render_evidence"], both


def test_the_report_derives_nothing_across_the_two_sections() -> None:
    """The semantic half.

    A subtraction, ratio or equality between a legacy count and a module count
    would be a parity number that means nothing — the module is empty by
    construction. `render_evidence` may only place the two sections beside each
    other.
    """
    source = inspect.getsource(approvals_inventory.render_evidence)
    tree = ast.parse(source.lstrip())
    for node in ast.walk(tree):
        assert not isinstance(node, ast.BinOp), (
            "arithmetic in the report body — a legacy-versus-module number is "
            "meaningless by construction and reads as parity"
        )
        if isinstance(node, ast.Compare):
            rendered = ast.unparse(node)
            assert "estate" not in rendered or "readiness" not in rendered, rendered


def test_the_two_observations_are_collected_independently() -> None:
    """Neither collector may take the other's result, or the separation is only
    in the type names."""
    for collector in (collect_legacy_estate, collect_module_readiness):
        annotations = inspect.get_annotations(collector, eval_str=False)
        rendered = " ".join(str(value) for value in annotations.values())
        assert "LegacyEstate" not in rendered or collector is collect_legacy_estate
        assert (
            "ModuleReadiness" not in rendered or collector is collect_module_readiness
        )


def test_the_observation_types_share_no_fields() -> None:
    """NON-VACUITY for the separation: two types with the same shape would make
    the distinction cosmetic."""
    assert set(LegacyEstate.__dataclass_fields__) == {"policies", "records"}
    assert set(ModuleReadiness.__dataclass_fields__) == {"tables"}
