"""Vendor lineage — hold the composed approvals module READ-ONLY during shadow.

`ap_0001_approvals` grants `platform_api` `SELECT, INSERT, UPDATE, DELETE` on the
module's platform tables the moment it runs. That is correct for an assembly
where the module IS the approval authority. It is wrong here, and this migration
is the correction.

## Why Vendor owns this, and does not ask the module to change

`ModulePlane.PLATFORM` selects **storage shape** — which of a dual-plane module's
tables get built. It says nothing about whether the composing assembly has
acquired **write authority** over them. Those are different questions with
different owners:

- storage shape is a property of the composition, which the module and the
  assembly agree on through `ModulePlaneSelection`;
- write authority is a property of Vendor's MIGRATION STATE. Shadow-versus-active
  is Vendor's position in an authority cutover (ADR-0004), and no other adopter
  shares it.

So a greenfield adopter should keep the module's normal write grants — it is the
authority from its first day. A brownfield adopter in shadow owns its own
restriction, which is this file. Asking the module for an `a5` that weakened its
grants would push one product's migration state into a shared contract, and every
future adopter would inherit a restriction that describes Vendor's situation
rather than theirs.

## Why the transient grant never becomes visible

`depends_on` orders this revision after `ap_0001_approvals`, and Vendor's Alembic
environment configures `transaction_per_migration=False` explicitly, so the whole
composed upgrade — the module's CREATE and GRANT, then this REVOKE — is ONE
transaction. The grant exists only inside it. The COMMITTED database moves
directly from "no module tables" to "module tables that `platform_api` may only
read".

Anything that could break that ordering breaks the guarantee, which is why
``dotmac-platform admin migrate`` refuses to upgrade to anything but composed heads: an
ordinary `alembic upgrade ap_0001_approvals` would otherwise stop after the
module's own migration and commit the DML grant.

## What this does NOT do

It writes no row and reads no business data. The module's tables stay EMPTY and
`vendor_cp.approvals` remains the sole authoritative writer until the cutover
transaction in ADR-0004 § 3.1 — which is also where these grants are restored.

Revision ID: v012_approvals_shadow_readonly
Revises: v011_product_identity
Create Date: 2026-08-15
"""

from __future__ import annotations

from alembic import op

revision = "v012_approvals_shadow_readonly"
down_revision = "v011_product_identity"
branch_labels = None

# A REAL cross-lineage edge, and the one place this assembly authors one against
# a module: the revoke is meaningless before the tables exist, and Alembic's own
# ordering is what makes "same transaction" true rather than hopeful.
depends_on = "ap_0001_approvals"

MODULE_SCHEMA = "mod_approvals"

# The module's PLATFORM plane — the only plane this assembly selected, and so the
# only tables that exist here. Literals, not an import: a migration is a snapshot
# of an accepted decision, and a list that changed shape under it later would
# silently change what was revoked.
PLATFORM_TABLES = (
    "platform_approval_policies",
    "platform_approval_requests",
    "platform_approval_decisions",
)

# Every write and DDL privilege. SELECT is deliberately absent: the shadow
# comparison and the cutover preflight both READ these tables, and a module whose
# state cannot be inspected cannot be compared against.
#
# REFERENCES and TRIGGER are revoked even though `ap_0001_approvals` never grants
# them, so the statement is exhaustive by construction rather than by knowing
# today's grants. TRUNCATE likewise: it empties a table without being
# INSERT/UPDATE/DELETE.
REVOKED = ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")

ONLINE_PLATFORM_ROLE = "platform_api"
TENANT_ROLE = "app_user"

# PostgreSQL only grants these four per COLUMN, and `has_any_column_privilege`
# rejects any other privilege outright. So the column-level question is asked
# only where it is a legal question — the kernel's own catalogue query makes the
# same split, for the same reason.
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def upgrade() -> None:
    for table in PLATFORM_TABLES:
        qualified = f"{MODULE_SCHEMA}.{table}"
        op.execute(
            f"REVOKE {', '.join(REVOKED)} ON {qualified} "
            f"FROM {ONLINE_PLATFORM_ROLE};"
        )
        # The module already revokes ALL from the tenant role. Repeating it is
        # cheap and makes this migration's end state complete on its own, rather
        # than true only in combination with a file it does not own.
        op.execute(f"REVOKE ALL ON {qualified} FROM {TENANT_ROLE};")

    _verify_effective_privileges()


def downgrade() -> None:
    """Refuse. Stepping this revision backwards would recreate TWO WRITERS.

    An earlier draft restored the module's `SELECT, INSERT, UPDATE, DELETE`
    grants here, reasoning — correctly — about the LOCAL question: a downgrade
    undoes its own migration, and the state before this one is the state
    `ap_0001_approvals` left. That reasoning never reached the system question,
    and the answer to it is different: while `vendor_cp.approvals` is still the
    authoritative writer, handing `platform_api` write access to the module's
    tables is exactly the two-writer state this whole shadow phase exists to
    prevent. A correct local undo produced an incorrect global state.

    Production policy already forbids schema downgrade, so the honest
    implementation is to fail closed rather than to implement a path nobody may
    take and everybody may misread.

    The grants ARE restored — deliberately, once, inside the sealed cutover
    transaction (ADR-0004 § 3.1), which is also where the legacy writer is
    quiesced and the authority actually moves. Never as a side effect of
    stepping a revision backwards.

    Raising leaves nothing half-done: the composed upgrade runs in one
    transaction, so this rolls back with everything else and the database keeps
    both its grants and its revision state exactly as they were.
    """
    raise RuntimeError(
        "v012_approvals_shadow_readonly cannot be downgraded: restoring the "
        "module's DML grants would give platform_api write access to tables "
        "vendor_cp.approvals still owns, recreating the two-writer state the "
        "shadow phase prevents. The grants are restored in the sealed cutover "
        "transaction (ADR-0004 § 3.1), not by stepping backwards."
    )


def _verify_effective_privileges() -> None:
    """Assert the OUTCOME, in the same transaction, before it can commit.

    Issuing a REVOKE is not proof the privilege is gone: a grant reaching the
    role through PUBLIC, or through a role it inherits, survives it. So the end
    state is checked rather than assumed, and a survivor raises — which, because
    the whole composition is one transaction, rolls back the module's tables
    along with everything else.

    `has_table_privilege` OR `has_any_column_privilege` is the same pair the
    composed live-catalogue audit uses; the column-level half is what catches a
    `GRANT UPDATE (state)` that a table-level inquiry reports as revoked.
    """
    connection = op.get_bind()
    failures: list[str] = []

    for table in PLATFORM_TABLES:
        qualified = f"{MODULE_SCHEMA}.{table}"

        for privilege in REVOKED:
            if _holds(connection, ONLINE_PLATFORM_ROLE, qualified, privilege):
                failures.append(
                    f"{ONLINE_PLATFORM_ROLE} still holds {privilege} on {qualified}"
                )

        # The POSITIVE half. Without it an over-broad revoke here would leave the
        # module unreadable, and every negative assertion above would still pass
        # — a shadow phase that cannot read the thing it is shadowing.
        if not _holds(connection, ONLINE_PLATFORM_ROLE, qualified, "SELECT"):
            failures.append(
                f"{ONLINE_PLATFORM_ROLE} cannot SELECT {qualified}; the shadow "
                "comparison reads these tables"
            )

        for privilege in ("SELECT", *REVOKED):
            if _holds(connection, TENANT_ROLE, qualified, privilege):
                failures.append(f"{TENANT_ROLE} still holds {privilege} on {qualified}")

    if failures:
        raise RuntimeError(
            "approvals shadow restriction did not take effect: " + "; ".join(failures)
        )


def _holds(connection: object, role: str, qualified: str, privilege: str) -> bool:
    """Does `role` EFFECTIVELY hold `privilege` on `qualified`?

    Both functions answer "effectively holds", which is what makes an inherited
    or `PUBLIC` grant visible rather than invisible. The column-level half is
    asked only for the four privileges PostgreSQL grants per column; asking it
    about DELETE, TRUNCATE or TRIGGER is an error, not a `false`.
    """
    from sqlalchemy import text

    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"

    return bool(
        connection.execute(  # type: ignore[attr-defined]
            text(statement),
            {"role": role, "rel": qualified, "priv": privilege},
        ).scalar()
    )
