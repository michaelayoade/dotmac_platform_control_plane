"""Vendor lineage — transfer approval authority to `dotmac-approvals`.

The shadow phase ends here. `dotmac_approvals` becomes the authority, the online
platform role regains write access to its tables, and Vendor's legacy approval
tables are dropped.

## This is a GREENFIELD switch, and it is valid only because the tables are empty

ADR-0004 originally specified a sealed cutover with parity measurement — correct
for a running system with approval history to preserve. Vendor CP turned out not
to be one: the read-only inventory reported `TARGET_ABSENT` against the
designated sole target (no Compose `db` service, no data volume), so there is no
legacy estate to seal, compare or migrate.

Empty is therefore the premise the whole switch rests on, and it is CHECKED here
rather than assumed. If either table holds a row, this migration raises and the
transaction rolls back: no grant moves, no column appears, and nothing is
dropped. A non-empty table means the premise was wrong, and the correct response
to a wrong premise is to stop.

## Why ACCESS EXCLUSIVE, taken up front

Step (5) DROPs these tables, and `DROP TABLE` takes `ACCESS EXCLUSIVE`. Taking a
weaker lock first and escalating later is how deadlocks are made: two
transactions can both hold `SHARE` and then both wait for the other to release it
before either can escalate, and neither ever does.

So the strongest lock this migration will need is acquired ONCE, at the start,
before anything is read. That also makes the emptiness check meaningful — under
`ACCESS EXCLUSIVE` nothing else can insert a row between the count and the drop,
so "empty when checked" and "empty when dropped" are the same statement.

Revision ID: v013_approvals_authority_switch
Revises: v012_approvals_shadow_readonly
Create Date: 2026-08-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v013_approvals_authority_switch"
down_revision = "v012_approvals_shadow_readonly"
branch_labels = None
# v012 already depends on `ap_0001_approvals`, so the module's tables exist by
# the time this runs. Naming it again would add an edge that says nothing new.
depends_on = None

LEGACY_TABLES = ("approval_policies", "approval_records")

MODULE_SCHEMA = "mod_approvals"
MODULE_TABLES = (
    "platform_approval_policies",
    "platform_approval_requests",
    "platform_approval_decisions",
)

ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"

#: What the online role needs to OPERATE the module now that it is the
#: authority — the same set `ap_0001_approvals` grants, restored after v012 took
#: it away for the shadow phase.
GRANTED = ("SELECT", "INSERT", "UPDATE", "DELETE")

#: Never granted, in either phase. Metadata and destructive privileges are not
#: part of running an approval workflow.
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

    # (2) The premise, checked. Fail closed: a row here means the greenfield
    #     assumption was wrong, and nothing below should happen.
    _require_empty(connection)

    # (3) Hand the online role its write access back.
    for table in MODULE_TABLES:
        op.execute(
            f"GRANT {', '.join(GRANTED)} ON {MODULE_SCHEMA}.{table} "
            f"TO {ONLINE_ROLE};"
        )

    # (4) Verify the EFFECTIVE outcome, in both directions, before committing.
    _verify_privileges(connection)

    # (5) The contract's approval now hangs on a module request.
    op.add_column(
        "contracts",
        sa.Column("approval_request_id", sa.Uuid(), nullable=True),
    )

    # (6) Drop the legacy estate. Empty by (2), and still empty because (1) has
    #     not been released.
    for table in LEGACY_TABLES:
        op.execute(f"DROP TABLE public.{table};")


def downgrade() -> None:
    """Refuse.

    Recreating the legacy tables would recreate a writer that no longer exists in
    the code, and revoking the module's grants would leave the running authority
    unable to write. Neither half is a state this assembly can operate, and
    production policy forbids schema downgrade regardless.

    An authority moves forward, deliberately, or not at all.
    """
    raise RuntimeError(
        "v013_approvals_authority_switch cannot be downgraded: the legacy writer "
        "no longer exists in the code, so restoring its tables would produce a "
        "database no running version can serve. Move the authority forward "
        "deliberately instead of stepping a revision backwards."
    )


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
            "the greenfield authority switch requires an EMPTY legacy estate, "
            f"and these tables hold rows: {', '.join(populated)}. Nothing has "
            "been changed. A populated estate needs the sealed cutover with "
            "parity that ADR-0004 describes, not this migration."
        )


def _verify_privileges(connection: object) -> None:
    """Assert the OUTCOME of the grant, both directions.

    Issuing `GRANT` is not proof the privilege arrived, any more than issuing
    `REVOKE` proved one had gone: this is the same check v012 made, pointed the
    other way. `has_table_privilege` OR `has_any_column_privilege` answers
    "effectively holds", which is what makes an inherited or `PUBLIC` grant
    visible.
    """
    failures: list[str] = []
    for table in MODULE_TABLES:
        qualified = f"{MODULE_SCHEMA}.{table}"

        # The online role must now hold everything it needs to operate...
        for privilege in GRANTED:
            if not _holds(connection, ONLINE_ROLE, qualified, privilege):
                failures.append(f"{ONLINE_ROLE} lacks {privilege} on {qualified}")

        # ...and nothing beyond it.
        for privilege in NEVER_GRANTED:
            if _holds(connection, ONLINE_ROLE, qualified, privilege):
                failures.append(f"{ONLINE_ROLE} holds {privilege} on {qualified}")

        # The tenant role is unchanged by this migration and must stay out.
        for privilege in (*GRANTED, *NEVER_GRANTED):
            if _holds(connection, TENANT_ROLE, qualified, privilege):
                failures.append(f"{TENANT_ROLE} holds {privilege} on {qualified}")

    if failures:
        raise RuntimeError(
            "approval authority transfer did not take effect: " + "; ".join(failures)
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
