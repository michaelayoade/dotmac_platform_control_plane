"""The composed approvals module is READ-ONLY, and provably so.

`ap_0001_approvals` grants `platform_api` full DML on its platform tables the
moment it runs; vendor `v012` takes it away. The shadow phase is safe because
those two never commit separately — not because anyone remembers to run them
together.

## Why the intermediate state is proved STRUCTURALLY

The tempting canary is to watch from a second connection and confirm the DML
grant is never visible. That observation is race-prone in the direction that
matters: it can only ever say "I did not happen to see it", and a sampler that
looks at the wrong moment reports success. Worse, it would pass just as happily
against a build where the grant IS briefly committed and the sample landed
outside the window.

So the absence of a committed intermediate state is established by the three
things that MAKE it absent, each of which is a fact rather than an observation:

1. the composed upgrade runs in ONE transaction — `transaction_per_migration` is
   set to `False` explicitly in `alembic/env.py`, so an uncommitted intermediate
   state is the only kind there is;
2. the deploy entrypoint refuses any target but composed `heads`, so the one
   reachable way to commit after `ap_0001_approvals` — an ordinary
   `alembic upgrade ap_0001_approvals` — is closed;
3. a failure anywhere in the composition rolls back the WHOLE thing, proved
   end-to-end below by making one fail.

Together those say the grant cannot be committed. An observation would have said
only that it was not seen.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from dotmac_approvals.models import PLATFORM_TABLES
from sqlalchemy import create_engine, text

from vendor_cp.migrations import (
    COMPOSED_TARGET,
    composed_version_locations,
    deploy_config,
    deploy_target_refusal,
    make_alembic_config,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "mod_approvals"
ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"

# Revoked by `v012`. SELECT is deliberately absent — the shadow comparison reads
# these tables.
WRITE_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")

# PostgreSQL grants only these four per column; asking `has_any_column_privilege`
# about the others is an error rather than a `false`.
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _holds(url: str, role: str, table: str, privilege: str) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    text(statement),
                    {"role": role, "rel": f"{SCHEMA}.{table}", "priv": privilege},
                ).scalar()
            )
    finally:
        engine.dispose()


def _schema_exists(url: str) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    text("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=:n)"),
                    {"n": SCHEMA},
                ).scalar()
            )
    finally:
        engine.dispose()


# ── 1. Single transaction, stated where a reader can see it ─────────────────


def test_the_composed_upgrade_runs_in_one_transaction() -> None:
    """The whole guarantee rests on this one setting, so it is written down
    rather than inherited. A default nobody wrote down is a default nobody
    notices changing."""
    env_source = (ROOT / "alembic" / "env.py").read_text()
    assert "transaction_per_migration=False" in env_source

    # And it is inside the ONLINE configure call, not a comment or the offline
    # path — the offline path emits SQL and commits nothing.
    online = env_source[env_source.index("def run_migrations_online") :]
    assert "transaction_per_migration=False" in online


# ── 2. The deploy path refuses a partial upgrade ────────────────────────────


def test_the_deploy_path_refuses_a_partial_target() -> None:
    """The reachable hole, closed.

    `alembic upgrade ap_0001_approvals` stops after the module's own migration
    and COMMITS the DML grant. Nothing about that command looks dangerous, which
    is why the refusal is a decision in the code rather than a note in a
    runbook.
    """
    for target in ("ap_0001_approvals", "v011_product_identity", "kernel@head"):
        refusal = deploy_target_refusal(target)
        assert refusal is not None, target
        assert "ap_0001_approvals" in refusal
        assert "one transaction" in refusal


def test_the_deploy_path_accepts_composed_heads() -> None:
    """NON-VACUITY. A rule that refused everything would pass the test above
    while making the deploy path unusable."""
    assert COMPOSED_TARGET == "heads"
    assert deploy_target_refusal(COMPOSED_TARGET) is None


def test_the_deploy_config_requires_composed_heads_in_transaction() -> None:
    """The outcome assertion, not just the action: `env.py` is told to verify on
    the live connection that every composed lineage reached its head, so a
    half-composed database rolls back rather than committing.

    The rehearsals' own config deliberately does NOT carry the flag — a partial
    upgrade is exactly what they exist to drive.
    """
    url = "postgresql+psycopg://x:x@127.0.0.1:5432/unused"
    assert deploy_config(url).attributes.get("require_composed_heads") is True
    assert make_alembic_config(url).attributes.get("require_composed_heads") is None


# ── 3. A failure anywhere rolls the whole composition back ──────────────────


def test_a_failure_after_the_module_rolls_back_its_tables(
    scratch_db: str, tmp_path: Path
) -> None:
    """END-TO-END proof that the intermediate state cannot commit.

    A synthetic revision that raises is appended after the vendor head. Because
    the whole composition is one transaction, the failure must take the module's
    schema down with it — if `mod_approvals` survives, the module's CREATE and
    its DML GRANT committed independently, which is exactly the state `v012`
    exists to prevent.
    """
    failing = "9999_synthetic_failure"
    (tmp_path / f"{failing}.py").write_text(
        f"revision = '{failing}'\n"
        "down_revision = 'v012_approvals_shadow_readonly'\n"
        "branch_labels = None\n"
        "depends_on = None\n"
        "def upgrade():\n"
        "    raise RuntimeError('synthetic failure inside the composed upgrade')\n"
        "def downgrade():\n    pass\n"
    )
    config = make_alembic_config(scratch_db)
    config.set_main_option(
        "version_locations", f"{composed_version_locations()} {tmp_path}"
    )

    with pytest.raises(RuntimeError, match="synthetic failure"):
        command.upgrade(config, "heads")

    assert not _schema_exists(scratch_db), (
        "the module schema survived a failed composition, so its CREATE and its "
        "DML GRANT committed on their own — the shadow restriction is not atomic"
    )


def test_the_rollback_canary_would_notice_a_surviving_schema(
    scratch_db: str,
) -> None:
    """SENSITIVITY for the test above: the same reader must SEE the schema when
    the composition succeeds. Otherwise `not _schema_exists(...)` would pass for
    a reader that can never find anything."""
    _upgrade(scratch_db)
    assert _schema_exists(scratch_db)


# ── 4. After a successful upgrade: SELECT-only, no tenant access, empty ─────


@pytest.mark.parametrize("table", PLATFORM_TABLES)
def test_the_online_role_is_select_only(scratch_db: str, table: str) -> None:
    """Both halves. The negative alone would be satisfied by a table nobody can
    read, which is not the contract: the shadow comparison READS these tables,
    and a phase that cannot read what it shadows is not a shadow phase."""
    _upgrade(scratch_db)

    assert _holds(
        scratch_db, ONLINE_ROLE, table, "SELECT"
    ), f"{ONLINE_ROLE} cannot read {table}; the shadow comparison needs it"
    held = [
        privilege
        for privilege in WRITE_PRIVILEGES
        if _holds(scratch_db, ONLINE_ROLE, table, privilege)
    ]
    assert not held, f"{ONLINE_ROLE} still holds {held} on {table}"


@pytest.mark.parametrize("table", PLATFORM_TABLES)
def test_the_tenant_role_has_no_access_at_all(scratch_db: str, table: str) -> None:
    _upgrade(scratch_db)
    held = [
        privilege
        for privilege in ("SELECT", *WRITE_PRIVILEGES)
        if _holds(scratch_db, TENANT_ROLE, table, privilege)
    ]
    assert not held, f"{TENANT_ROLE} holds {held} on {table}"


def test_the_privilege_reader_would_notice_a_granted_write(scratch_db: str) -> None:
    """SENSITIVITY for the negatives above, which are all assertions that a list
    is empty — precisely the shape a broken reader satisfies."""
    _upgrade(scratch_db)
    table = PLATFORM_TABLES[0]
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(f"GRANT INSERT ON {SCHEMA}.{table} TO {ONLINE_ROLE}")  # noqa: S608
            )
        assert _holds(scratch_db, ONLINE_ROLE, table, "INSERT")
        with engine.begin() as conn:
            conn.execute(
                text(f"REVOKE INSERT ON {SCHEMA}.{table} FROM {ONLINE_ROLE}")  # noqa: S608
            )
    finally:
        engine.dispose()

    assert not _holds(scratch_db, ONLINE_ROLE, table, "INSERT")


@pytest.mark.parametrize("table", PLATFORM_TABLES)
def test_the_module_tables_are_empty(scratch_db: str, table: str) -> None:
    """Nothing writes them during shadow. The legacy service is still the
    authority, and this phase reads only."""
    _upgrade(scratch_db)
    engine = create_engine(scratch_db)
    try:
        with engine.connect() as conn:
            count = conn.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.{table}")  # noqa: S608
            ).scalar()
    finally:
        engine.dispose()
    assert count == 0, f"{table} holds {count} rows during a read-only shadow phase"
