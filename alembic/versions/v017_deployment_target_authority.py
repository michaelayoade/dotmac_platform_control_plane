"""Seal the independent delivery-target registration path (ADR-0011).

`mod_deploy.deployment_targets` becomes the authority for deployment-target
identity. What survives in `public.licence_delivery_targets` is a rebuildable
projection reconciled from that owner, and ADR-0010 retires it with the rest of
the delivery estate.

## What this revision does NOT do, and why

It does not DROP the table. ADR-0010 owns that, and taking it here would merge
two cutovers and lose the mirror/seal/activate proof one of them needs.

It does not revoke `INSERT` or `UPDATE`. ADR-0011 § 4 was amended before this
was written: a full write-revoke makes the projection unwritable, and
`projection._authorised_target` resolves staging against a projection row — so
an unwritable projection makes staging permanently impossible, which is removing
the delivery path rather than preserving it. ADR-0010 § 1 requires the existing
behaviour preserved until its own cutover. The reconciler needs both privileges.

`DELETE` IS revoked, and that one is not a compromise: a projection is rebuilt
from its authority, never deleted. A role holding `DELETE` on a projection can
only destroy evidence.

So the single-writer guarantee here is provenance plus an architecture ratchet,
not a privilege — `vendor_cp.deployment.adapter.DeploymentTargetFacts` can only
be built from a record the module returned. That is weaker than a grant and is
recorded as such rather than described as a seal it is not.

## Locking

All five delivery tables, in a fixed order, even though only two carry the
measured premise. A seal means nothing if the rest of the estate can move under
it, and a fixed order is what stops two concurrent runs deadlocking by taking
them in opposite directions.

The recheck covers RELATIONSHIPS as well as counts. A table-count-only check
passes on a dangling `target_id`, which is exactly the state a half-migrated
estate would be in.

Revision ID: v017_deployment_target_authority
Revises: v016_licensing_authority
Create Date: 2026-08-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v017_deployment_target_authority"
down_revision = "v016_licensing_authority"
branch_labels = None

# The module lineage must exist before Vendor's registry stops being authority.
depends_on = "dc_0001_deployment_control"

#: Fixed, declared order. Never reorder: two concurrent runs taking these in
#: opposite directions deadlock, and the order is the only thing preventing it.
LOCK_TABLES = (
    "licence_deliveries",
    "licence_delivery_states",
    "licence_delivery_targets",
    "licence_delivery_attempts",
    "licence_ack_records",
)

PROJECTION_TABLE = "licence_delivery_targets"
ONLINE_ROLE = "platform_api"
REVOKED_PRIVILEGE = "DELETE"

#: Counts AND relationships. Each is a distinct way the estate could be
#: non-empty, and a check that only counted rows would pass on the third.
EMPTINESS_PROBES: tuple[tuple[str, str], ...] = (
    (
        "licence_delivery_targets",
        "SELECT count(*) FROM public.licence_delivery_targets",
    ),
    ("licence_deliveries", "SELECT count(*) FROM public.licence_deliveries"),
    (
        "licence_delivery_states",
        "SELECT count(*) FROM public.licence_delivery_states",
    ),
    (
        "licence_delivery_attempts",
        "SELECT count(*) FROM public.licence_delivery_attempts",
    ),
    ("licence_ack_records", "SELECT count(*) FROM public.licence_ack_records"),
    (
        "deliveries_bound_to_a_target",
        "SELECT count(*) FROM public.licence_deliveries WHERE target_id IS NOT NULL",
    ),
    (
        "deliveries_naming_a_target_ref",
        "SELECT count(*) FROM public.licence_deliveries WHERE target_ref <> ''",
    ),
    (
        "dangling_target_id",
        "SELECT count(*) FROM public.licence_deliveries d "
        "WHERE d.target_id IS NOT NULL AND NOT EXISTS ("
        "SELECT 1 FROM public.licence_delivery_targets t WHERE t.id = d.target_id)",
    ),
    (
        "dangling_target_ref",
        "SELECT count(*) FROM public.licence_deliveries d "
        "WHERE d.target_ref <> '' AND NOT EXISTS ("
        "SELECT 1 FROM public.licence_delivery_targets t "
        "WHERE t.target_ref = d.target_ref)",
    ),
)


def upgrade() -> None:
    connection = op.get_bind()
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"public.{table}" for table in LOCK_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    _require_empty(connection)
    # Inside the same transaction, so it lands BEFORE the locks release. The
    # registration route stays mounted while this runs; checking emptiness under
    # a lock and then releasing it with a writer still live preserves exactly
    # the race the check exists to close.
    op.execute(
        f"REVOKE {REVOKED_PRIVILEGE} ON public.{PROJECTION_TABLE} "
        f"FROM {ONLINE_ROLE};"
    )
    _verify_revoked(connection)


def downgrade() -> None:
    raise RuntimeError(
        "v017_deployment_target_authority cannot be downgraded: restoring "
        "DELETE on the delivery-target projection would hand a second authority "
        "the ability to destroy rows it does not own. mod_deploy is the "
        "authority for deployment-target identity."
    )


def _require_empty(connection: object) -> None:
    populated: list[str] = []
    for name, statement in EMPTINESS_PROBES:
        count = connection.execute(sa.text(statement)).scalar_one()  # type: ignore[attr-defined]
        if count:
            populated.append(f"{name}={count}")
    if populated:
        raise RuntimeError(
            "the ADR-0011 delivery-target seal requires an EMPTY delivery "
            f"estate, and these probes are non-zero: {', '.join(populated)}. "
            "Nothing has been changed. A populated estate requires the "
            "backfill/compare/writer-switch path in ADR-0011 § 4, which "
            "preserves immutable identities and the customer binding."
        )


def _verify_revoked(connection: object) -> None:
    """Prove the effective outcome in BOTH directions, as v012/v013 did.

    `has_table_privilege` answers what the role can actually do, including
    privileges reached through membership — which a `pg_class.relacl` read would
    miss. Asserting the revoke took AND that reads still work is what keeps this
    from silently sealing more than intended.
    """
    can_delete = connection.execute(  # type: ignore[attr-defined]
        sa.text(
            "SELECT has_table_privilege(:role, :table, 'DELETE')",
        ),
        {"role": ONLINE_ROLE, "table": f"public.{PROJECTION_TABLE}"},
    ).scalar_one()
    if can_delete:
        raise RuntimeError(
            f"{ONLINE_ROLE} still holds DELETE on {PROJECTION_TABLE} after the "
            "revoke — the privilege is probably held through a role grant this "
            "revision did not touch. Refusing to report a seal that did not take."
        )
    for privilege in ("SELECT", "INSERT", "UPDATE"):
        retained = connection.execute(  # type: ignore[attr-defined]
            sa.text("SELECT has_table_privilege(:role, :table, :privilege)"),
            {
                "role": ONLINE_ROLE,
                "table": f"public.{PROJECTION_TABLE}",
                "privilege": privilege,
            },
        ).scalar_one()
        if not retained:
            raise RuntimeError(
                f"{ONLINE_ROLE} lost {privilege} on {PROJECTION_TABLE}. The "
                "reconciler needs INSERT and UPDATE and staging needs SELECT; "
                "a projection nothing can rebuild is a broken delivery path, "
                "not a sealed one (ADR-0010 s 1)."
            )
