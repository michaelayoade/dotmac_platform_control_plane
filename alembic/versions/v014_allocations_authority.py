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
# `ea_0001_allocations` is already an ancestor: the vendor root depends on the
# kernel, and the module lineage is composed alongside it. Naming it again would
# add an edge that says nothing new.
depends_on = None

#: The table holding the one foreign key that reaches INTO the legacy estate
#: from outside it. The constraint NAME is discovered from the catalog rather
#: than assumed: a guessed name silently does nothing under
#: `DROP CONSTRAINT IF EXISTS`, and the failure would then surface as an
#: unexplained "cannot drop table" three statements later.
DEPENDENT_TABLE = "licence_issuances"

#: Dropped in dependency order — entries carry the FK to allocations.
LEGACY_TABLES = ("allocation_entries", "allocations")

MODULE_SCHEMA = "mod_ealloc"
MODULE_TABLES = ("allocations", "allocation_entries")

ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"

#: What the online role needs to OPERATE the module now that it is the authority.
GRANTED = ("SELECT", "INSERT", "UPDATE", "DELETE")

#: Never granted. Metadata and destructive privileges are not part of running an
#: allocation workflow.
NEVER_GRANTED = ("TRUNCATE", "REFERENCES", "TRIGGER")

#: PostgreSQL grants only these per column; asking `has_any_column_privilege`
#: about the others is an error rather than a `false`.
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def upgrade() -> None:
    connection = op.get_bind()

    # (1) The strongest lock this migration needs, taken once and up front.
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"public.{table}" for table in LEGACY_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )

    # (2) The premise, checked. Fail closed.
    _require_empty(connection)

    # (3) Hand the online role the access it needs to operate the module.
    for table in MODULE_TABLES:
        op.execute(
            f"GRANT {', '.join(GRANTED)} ON {MODULE_SCHEMA}.{table} "
            f"TO {ONLINE_ROLE};"
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
    for table in LEGACY_TABLES:
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
        {"dependent": DEPENDENT_TABLE, "targets": list(LEGACY_TABLES)},
    ).scalars()
    for name in rows:
        op.execute(f'ALTER TABLE public.{DEPENDENT_TABLE} DROP CONSTRAINT "{name}";')


def _require_empty(connection: object) -> None:
    """Both legacy tables hold nothing. The switch is valid only if so."""
    populated: list[str] = []
    for table in LEGACY_TABLES:
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
    """Assert the OUTCOME of the grant, both directions.

    Issuing `GRANT` is not proof the privilege arrived, any more than issuing
    `REVOKE` proves one has gone: a grant reaching a role through `PUBLIC` or an
    inherited role is invisible to the statement and visible to
    `has_table_privilege`.
    """
    failures: list[str] = []
    for table in MODULE_TABLES:
        qualified = f"{MODULE_SCHEMA}.{table}"

        for privilege in GRANTED:
            if not _holds(connection, ONLINE_ROLE, qualified, privilege):
                failures.append(f"{ONLINE_ROLE} lacks {privilege} on {qualified}")

        for privilege in NEVER_GRANTED:
            if _holds(connection, ONLINE_ROLE, qualified, privilege):
                failures.append(f"{ONLINE_ROLE} holds {privilege} on {qualified}")

        for privilege in (*GRANTED, *NEVER_GRANTED):
            if _holds(connection, TENANT_ROLE, qualified, privilege):
                failures.append(f"{TENANT_ROLE} holds {privilege} on {qualified}")

    if failures:
        raise RuntimeError(
            "allocation authority transfer did not take effect: " + "; ".join(failures)
        )


def _holds(connection: object, role: str, qualified: str, privilege: str) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    return bool(
        connection.execute(  # type: ignore[attr-defined]
            sa.text(statement),
            {"role": role, "rel": qualified, "priv": privilege},
        ).scalar()
    )
