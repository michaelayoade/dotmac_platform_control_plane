"""Transfer commercial-agreement authority to the published module.

Vendor is a greenfield assembly: the authorized target observation found no
database service or volume, so there is no legacy contract estate to migrate.
That observation is a premise, not a waiver. This revision rechecks it under
the strongest lock needed for the drop and refuses a populated estate without
changing either owner.

`ACCESS EXCLUSIVE` is acquired parent-before-child, matching the retired
writer's lock order. It is held from the emptiness check through the reverse
child-before-parent drop, so "empty when measured" and "empty when retired"
are one transactionally stable statement.

Revision ID: v015_agreements_authority
Revises: v014_allocations_authority
Create Date: 2026-08-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v015_agreements_authority"
down_revision = "v014_allocations_authority"
branch_labels = None

# The module lineage is independently composed. This edge is the load-bearing
# statement that its tables exist before Vendor retires the local owner.
depends_on = "cg_0001_agreements"

LOCK_TABLES = ("contracts", "contract_lines")
DROP_TABLES = ("contract_lines", "contracts")


def upgrade() -> None:
    connection = op.get_bind()
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"public.{table}" for table in LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    _require_empty(connection)
    for table in DROP_TABLES:
        op.execute(f"DROP TABLE public.{table};")


def downgrade() -> None:
    """Refuse to recreate tables for an owner the running code has retired."""
    raise RuntimeError(
        "v015_agreements_authority cannot be downgraded: the legacy "
        "contract writer no longer exists, so restoring its tables would create "
        "a second authority no running version can serve."
    )


def _require_empty(connection: object) -> None:
    populated: list[str] = []
    for table in DROP_TABLES:
        count = connection.execute(  # type: ignore[attr-defined]
            sa.text(f"SELECT count(*) FROM public.{table}")  # noqa: S608
        ).scalar_one()
        if count:
            populated.append(f"{table}={count}")
    if populated:
        raise RuntimeError(
            "the greenfield Commercial Agreements authority switch requires "
            "an EMPTY legacy estate, and these tables hold rows: "
            f"{', '.join(populated)}. Nothing has been changed. A populated "
            "estate requires a sealed migration with parity, not this revision."
        )
