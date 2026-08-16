"""Vendor lineage — transfer allocation authority to `dotmac-entitlement-allocation`.

The last local writer in this assembly. Release Catalog already owned its write
path and Approvals moved in `v013`; this completes the set.

## Greenfield, on the same observation

A direct authorized check against the designated sole target found
`TARGET_ABSENT` — no Compose `db` service, no data volume — so there is no
allocation estate to seal, compare or migrate. That is an observation, not an
inference, and it is re-checked here anyway: emptiness is the premise the switch
rests on, so this migration verifies it under lock and raises otherwise. A row
means the premise was wrong, and nothing then happens — no grant, no drop.

## Why ACCESS EXCLUSIVE, taken up front

Step (5) DROPs these tables and `DROP TABLE` takes `ACCESS EXCLUSIVE`. Taking a
weaker lock first and escalating later is how deadlocks are made: two
transactions can each hold `SHARE` and each wait for the other to release it
before either can escalate. So the strongest lock this migration needs is
acquired ONCE, before anything is read — which also makes the emptiness check
meaningful, because under it "empty when checked" and "empty when dropped" are
the same statement.

Lock order is a separate invariant. The retired writer acquired the parent
`allocations` table before its child `allocation_entries`; this migration locks
in that same order so a writer already holding the parent is never made to wait
on a child lock held by the migration. Drop order is the reverse because the
child foreign key must disappear first.

Revision ID: v014_allocations_authority
Revises: v013_approvals_authority_switch
Create Date: 2026-08-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v014_allocations_authority"
down_revision = "v013_approvals_authority_switch"
branch_labels = None
# A REAL cross-lineage edge, and it must be stated.
#
# An earlier draft set this to None, reasoning that `ea_0001_allocations` was
# "already an ancestor" because the module lineage is composed alongside the
# vendor one. That is false, and the distinction is the point of a composed
# graph: composed ALONGSIDE means both lineages are in the revision map, not
# that either is ordered before the other. With no edge, Alembic is free to run
# this revision first — and it did, issuing `GRANT ... ON mod_ealloc.allocations`
# against a schema the module had not created yet.
#
# Approvals needed no equivalent edge only because `v012` already depended on
# `ap_0001_approvals`. Nothing in the vendor lineage has ever depended on
# `ea_0001_allocations`, so here the edge is load-bearing.
depends_on = "ea_0001_allocations"

#: The table holding the one foreign key that reaches INTO the legacy estate
#: from outside it. The constraint NAME is discovered from the catalog rather
#: than assumed: a guessed name silently does nothing under
#: `DROP CONSTRAINT IF EXISTS`, and the failure would then surface as an
#: unexplained "cannot drop table" three statements later.
DEPENDENT_TABLE = "licence_issuances"

#: Lock in the writer's parent-before-child order. Dropping must use the reverse
#: order because the child carries the foreign key.
LOCK_TABLES = ("allocations", "allocation_entries")
DROP_TABLES = ("allocation_entries", "allocations")

MODULE_SCHEMA = "mod_ealloc"
MODULE_TABLES = ("allocations", "allocation_entries")

ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"

#: The module's database-enforced immutability contract. The online role may
#: create and read an allocation, then make the one-way seal decision; it may not
#: rewrite business facts, update entries, or delete either row.
REQUIRED_TABLE_PRIVILEGES = ("SELECT", "INSERT")
FORBIDDEN_TABLE_PRIVILEGES = (
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
ALL_TABLE_PRIVILEGES = (
    *REQUIRED_TABLE_PRIVILEGES,
    *FORBIDDEN_TABLE_PRIVILEGES,
)
ALLOCATION_UPDATE_COLUMNS = frozenset({"sealed", "updated_at"})

#: PostgreSQL grants only these per column; asking `has_any_column_privilege`
#: about the others is an error rather than a `false`.
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def upgrade() -> None:
    connection = op.get_bind()

    # (1) The strongest lock this migration needs, taken once and up front.
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"public.{table}" for table in LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )

    # (2) The premise, checked. Fail closed.
    _require_empty(connection)

    # (3) Normalize to the MODULE'S access contract. A broad UPDATE or DELETE
    #     grant would let raw SQL bypass its immutable-parent and append-defence
    #     design. Table-level REVOKE also clears column grants in PostgreSQL, so
    #     this starts from no direct privilege and adds the exact online shape.
    for table in MODULE_TABLES:
        op.execute(
            f"REVOKE ALL PRIVILEGES ON TABLE {MODULE_SCHEMA}.{table} "
            f"FROM {ONLINE_ROLE};"
        )
        op.execute(
            f"GRANT SELECT, INSERT ON {MODULE_SCHEMA}.{table} TO {ONLINE_ROLE};"
        )
    op.execute(
        "GRANT UPDATE (sealed, updated_at) ON "
        f"{MODULE_SCHEMA}.allocations TO {ONLINE_ROLE};"
    )

    # (4) Verify the EFFECTIVE outcome, both directions, before committing.
    _verify_privileges(connection)

    # (5) Release the one constraint that reaches INTO the legacy estate from
    #     outside it. `licence_issuances.allocation_id` pointed at
    #     `public.allocations`; the allocation it names now lives in
    #     `mod_ealloc`, and no foreign key may cross into a module's schema
    #     (ADR-0023) — a module's tables are its own, and a constraint pointing
    #     at them would make this assembly's DDL depend on the module's. The
    #     column stays as an OPAQUE reference, and the rule that actually
    #     matters — one issued version per staged allocation — is a unique
    #     constraint on `licence_issuances` and is untouched.
    #
    #     Without this, step (6) fails: PostgreSQL refuses to drop a table a
    #     foreign key still depends on.
    _drop_foreign_keys_into_legacy(connection)

    # (6) Drop the legacy estate. Empty by (2), and still empty because (1) has
    #     not been released.
    for table in DROP_TABLES:
        op.execute(f"DROP TABLE public.{table};")


def downgrade() -> None:
    """Refuse.

    Recreating the legacy tables would restore a writer that no longer exists in
    the code, and revoking the module's grants would leave the running authority
    unable to write. Neither half is a state this assembly can serve, and
    production policy forbids schema downgrade regardless.
    """
    raise RuntimeError(
        "v014_allocations_authority cannot be downgraded: the legacy "
        "allocation writer no longer exists in the code, so restoring its tables "
        "would produce a database no running version can serve."
    )


def _drop_foreign_keys_into_legacy(connection: object) -> None:
    """Release every FK from `licence_issuances` into the legacy estate.

    Discovered, not named: the constraint's identifier is whatever PostgreSQL
    assigned, and `DROP CONSTRAINT IF EXISTS` on a guessed name would succeed
    while doing nothing — turning a precise failure here into a confusing
    "cannot drop table" later.
    """
    rows = connection.execute(  # type: ignore[attr-defined]
        sa.text(
            "SELECT c.conname FROM pg_constraint c "
            "JOIN pg_class t ON t.oid = c.conrelid "
            "JOIN pg_class r ON r.oid = c.confrelid "
            "JOIN pg_namespace tn ON tn.oid = t.relnamespace "
            "JOIN pg_namespace rn ON rn.oid = r.relnamespace "
            "WHERE c.contype = 'f' AND tn.nspname = 'public' "
            "AND t.relname = :dependent AND rn.nspname = 'public' "
            "AND r.relname = ANY(:targets)"
        ),
        {"dependent": DEPENDENT_TABLE, "targets": list(DROP_TABLES)},
    ).scalars()
    for name in rows:
        op.execute(f'ALTER TABLE public.{DEPENDENT_TABLE} DROP CONSTRAINT "{name}";')


def _require_empty(connection: object) -> None:
    """Both legacy tables hold nothing. The switch is valid only if so."""
    populated: list[str] = []
    for table in DROP_TABLES:
        count = connection.execute(  # type: ignore[attr-defined]
            sa.text(f"SELECT count(*) FROM public.{table}")  # noqa: S608
        ).scalar_one()
        if count:
            populated.append(f"{table}={count}")
    if populated:
        raise RuntimeError(
            "the greenfield allocation authority switch requires an EMPTY legacy "
            f"estate, and these tables hold rows: {', '.join(populated)}. Nothing "
            "has been changed. A populated estate needs a sealed cutover with "
            "parity (ADR-0031's protocol), not this migration."
        )


def _verify_privileges(connection: object) -> None:
    """Assert the exact EFFECTIVE privilege shape, including column grants.

    Issuing a GRANT or REVOKE proves only that a statement ran. Effective access
    can still arrive through PUBLIC, role inheritance, or a column-level grant.
    The verification therefore distinguishes table UPDATE from the two allowed
    allocation columns and checks every live column, not a hand-maintained list.
    """
    failures: list[str] = []
    for table in MODULE_TABLES:
        qualified = f"{MODULE_SCHEMA}.{table}"
        columns = _columns(connection, qualified)

        for privilege in REQUIRED_TABLE_PRIVILEGES:
            if not _table_holds(connection, ONLINE_ROLE, qualified, privilege):
                failures.append(f"{ONLINE_ROLE} lacks {privilege} on {qualified}")

        for privilege in FORBIDDEN_TABLE_PRIVILEGES:
            if _table_holds(connection, ONLINE_ROLE, qualified, privilege):
                failures.append(
                    f"{ONLINE_ROLE} holds table {privilege} on {qualified}"
                )

        allowed_updates = (
            ALLOCATION_UPDATE_COLUMNS if table == "allocations" else frozenset()
        )
        missing_columns = allowed_updates.difference(columns)
        if missing_columns:
            failures.append(
                f"{qualified} lacks allowed update columns {sorted(missing_columns)}"
            )
        for column in columns:
            holds_update = _column_holds(
                connection, ONLINE_ROLE, qualified, column, "UPDATE"
            )
            if holds_update != (column in allowed_updates):
                expectation = (
                    "must hold" if column in allowed_updates else "must not hold"
                )
                failures.append(
                    f"{ONLINE_ROLE} {expectation} UPDATE on {qualified}.{column}"
                )
            if _column_holds(
                connection, ONLINE_ROLE, qualified, column, "REFERENCES"
            ):
                failures.append(
                    f"{ONLINE_ROLE} holds REFERENCES on {qualified}.{column}"
                )

        for privilege in ALL_TABLE_PRIVILEGES:
            if _holds_any(connection, TENANT_ROLE, qualified, privilege):
                failures.append(f"{TENANT_ROLE} holds {privilege} on {qualified}")

    if failures:
        raise RuntimeError(
            "allocation authority transfer did not take effect: " + "; ".join(failures)
        )


def _columns(connection: object, qualified: str) -> tuple[str, ...]:
    return tuple(
        connection.execute(  # type: ignore[attr-defined]
            sa.text(
                "SELECT attname FROM pg_attribute "
                "WHERE attrelid = to_regclass(:rel) "
                "AND attnum > 0 AND NOT attisdropped ORDER BY attnum"
            ),
            {"rel": qualified},
        ).scalars()
    )


def _table_holds(
    connection: object, role: str, qualified: str, privilege: str
) -> bool:
    return bool(
        connection.execute(  # type: ignore[attr-defined]
            sa.text("SELECT has_table_privilege(:role, :rel, :priv)"),
            {"role": role, "rel": qualified, "priv": privilege},
        ).scalar()
    )


def _column_holds(
    connection: object,
    role: str,
    qualified: str,
    column: str,
    privilege: str,
) -> bool:
    return bool(
        connection.execute(  # type: ignore[attr-defined]
            sa.text("SELECT has_column_privilege(:role, :rel, :column, :priv)"),
            {"role": role, "rel": qualified, "column": column, "priv": privilege},
        ).scalar()
    )


def _holds_any(
    connection: object, role: str, qualified: str, privilege: str
) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    return bool(
        connection.execute(  # type: ignore[attr-defined]
            sa.text(statement),
            {"role": role, "rel": qualified, "priv": privilege},
        ).scalar()
    )
