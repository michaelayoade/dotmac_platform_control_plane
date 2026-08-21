"""The ONE seam between this assembly and `dotmac-deployment-control`.

Typed, no `Any`, and read-only in this slice: it resolves a deployment target
from the module and converts it into the narrow set of facts Vendor's delivery
projection is allowed to hold. It writes nothing to `mod_deploy` — registering a
target, setting desired state and requesting a rollout are the module's own
commands, and Vendor has no operator surface for them yet.

## Why this type exists at all

`reconcile_delivery_target` could have taken `target_ref` and `customer_ref` as
strings. Then any caller could supply them, and the projection would be
independently registered again the moment somebody added a route — which is the
exact regression ADR-0011 exists to end. `DeploymentTargetFacts` can only be
constructed here, from a `TargetView` the module returned, so the projection's
values have a provenance the type system carries.

That is the whole enforcement mechanism, and it is weaker than a database grant.
ADR-0011 § 4 says so plainly: `platform_api` keeps `INSERT`/`UPDATE` on
`licence_delivery_targets` because the reconciler needs them, so what stops an
independent write is this seam plus an architecture ratchet, not a privilege.
Only `DELETE` is revoked — a projection is rebuilt, never deleted.

## Status mapping, and the one that fails closed

`REGISTERED` means the module knows the target and it has no desired state yet.
It maps to Vendor `SUSPENDED`, not `ACTIVE`: a target that is not converging on
anything must not receive a licence, and mapping "known" onto "eligible" would
be exactly the registration-is-authorisation confusion `_authorised_target` was
written to refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from dotmac_deployment_control import TargetStatus as ModuleTargetStatus
from dotmac_deployment_control import get_target
from dotmac_kernel.errors import NotFoundError
from sqlalchemy.orm import Session

from vendor_cp.licensing.delivery_models import TargetStatus

#: Module standing -> delivery eligibility. Total over the module's enum: a new
#: member added upstream fails the lookup rather than defaulting to eligible.
_STATUS: dict[str, TargetStatus] = {
    ModuleTargetStatus.ACTIVE.value: TargetStatus.ACTIVE,
    ModuleTargetStatus.SUSPENDED.value: TargetStatus.SUSPENDED,
    ModuleTargetStatus.DECOMMISSIONED.value: TargetStatus.RETIRED,
    ModuleTargetStatus.REGISTERED.value: TargetStatus.SUSPENDED,
}


@dataclass(frozen=True)
class DeploymentTargetFacts:
    """What the delivery projection may hold about a deployment target.

    Constructible only by `resolve_target` below. Four fields, and the absence
    of a fifth is deliberate: `connection_ref` is transport metadata the module
    does not own and must not invent, so a reconciled row carries `None` there
    until ADR-0010 moves delivery to the Integrator and the column goes with it.
    """

    target_id: UUID
    target_ref: str
    customer_ref: str
    status: TargetStatus


def resolve_target(db: Session, target_id: UUID) -> DeploymentTargetFacts:
    """Read the authoritative deployment target, or refuse.

    `NotFoundError` rather than a silent `None`: a caller asking to reconcile a
    target the fleet owner has never heard of is asking for a destination to be
    invented, which is what this cutover removes.
    """
    view = get_target(db, target_id)
    if view is None:
        raise NotFoundError(
            f"deployment target {target_id} is not registered in mod_deploy — "
            "a delivery destination is reconciled from the fleet owner, never "
            "registered independently"
        )
    status = _STATUS.get(view.status)
    if status is None:
        raise NotFoundError(
            f"deployment target {view.target_ref!r} has standing "
            f"{view.status!r}, which this assembly has no delivery mapping "
            "for — refusing rather than assuming it may receive a licence"
        )
    return DeploymentTargetFacts(
        target_id=view.id,
        target_ref=view.target_ref,
        customer_ref=view.subject_ref,
        status=status,
    )


__all__ = ["DeploymentTargetFacts", "resolve_target"]
