"""Transfer Licensing issuer authority to the published module.

The designated Vendor target was directly observed as absent, so no issuer
estate exists to copy.  This revision rechecks that premise under lock.  A
single legacy row aborts the switch: signed envelopes must be migrated
byte-for-byte, only public key material may move, and revocation-list versions
must continue.  Those obligations require a separate populated-estate
migration; silently dropping or rebuilding any artifact is forbidden.

Vendor's delivery projection is a separate owner.  Its tables and evidence
remain, while the foreign key into the retired issuer is replaced by an opaque
issuance reference resolved through the typed module adapter.

Revision ID: v016_licensing_authority
Revises: v015_agreements_authority
Create Date: 2026-08-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v016_licensing_authority"
down_revision = "v015_agreements_authority"
branch_labels = None

# The module lineage must exist before the local issuer is retired.
depends_on = "li_0001_licensing"

LEGACY_ISSUER_TABLES = (
    "licence_signing_keys",
    "licences",
    "licence_issuances",
    "licence_revocation_entries",
    "licence_revocation_lists",
)

# Parent-before-child, matching the retired writers.  Delivery is locked too:
# its foreign key is detached in this transaction and no staged row may race
# between the premise check and that detach.
LOCK_TABLES = (
    "licence_signing_keys",
    "licences",
    "licence_issuances",
    "licence_revocation_entries",
    "licence_revocation_lists",
    "licence_deliveries",
)

DROP_TABLES = (
    "licence_revocation_lists",
    "licence_revocation_entries",
    "licence_issuances",
    "licences",
    "licence_signing_keys",
)

DELIVERY_TABLE = "licence_deliveries"


def upgrade() -> None:
    connection = op.get_bind()
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"public.{table}" for table in LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    _require_empty(connection)
    _drop_delivery_foreign_keys(connection)
    for table in DROP_TABLES:
        op.execute(f"DROP TABLE public.{table};")


def downgrade() -> None:
    raise RuntimeError(
        "v016_licensing_authority cannot be downgraded: the legacy issuer "
        "writer no longer exists, and recreating its tables would restore a "
        "second licensing authority."
    )


def _require_empty(connection: object) -> None:
    populated: list[str] = []
    for table in LEGACY_ISSUER_TABLES:
        count = connection.execute(  # type: ignore[attr-defined]
            sa.text(f"SELECT count(*) FROM public.{table}")  # noqa: S608
        ).scalar_one()
        if count:
            populated.append(f"{table}={count}")
    if populated:
        raise RuntimeError(
            "the greenfield Licensing authority switch requires an EMPTY "
            "legacy issuer estate, and these tables hold rows: "
            f"{', '.join(populated)}. Nothing has been changed. A populated "
            "estate requires a byte-preserving envelope migration, public-only "
            "key transfer and continuous revocation-list lineage."
        )


def _drop_delivery_foreign_keys(connection: object) -> None:
    """Detach every delivery FK into the retired issuer, discovered by catalog."""
    rows = connection.execute(  # type: ignore[attr-defined]
        sa.text(
            "SELECT c.conname FROM pg_constraint c "
            "JOIN pg_class t ON t.oid = c.conrelid "
            "JOIN pg_class r ON r.oid = c.confrelid "
            "JOIN pg_namespace tn ON tn.oid = t.relnamespace "
            "JOIN pg_namespace rn ON rn.oid = r.relnamespace "
            "WHERE c.contype = 'f' AND tn.nspname = 'public' "
            "AND t.relname = :dependent AND rn.nspname = 'public' "
            "AND r.relname = 'licence_issuances'"
        ),
        {"dependent": DELIVERY_TABLE},
    ).scalars()
    for name in rows:
        op.execute(f'ALTER TABLE public.{DELIVERY_TABLE} DROP CONSTRAINT "{name}";')
