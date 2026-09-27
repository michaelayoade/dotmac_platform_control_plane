"""Thin platform-admin HTTP adapter over `resolve_conflict`.

Same shape as `vendor_cp.contracts.router` (hard rule 6): validate, authorise,
delegate. `resolve_conflict` is the one owner; this router adds no policy of
its own beyond mapping its two refusals onto HTTP status.

The actor is the AUTHENTICATED platform admin, exactly as
`vendor_cp.contracts.router` establishes `actor_admin_id` from `admin.id` —
never a client-supplied field, which is the CLI's own reason for not shipping
a `resolve` command (see `vendor_cp.cli.commands.withdrawal_conflicts_list`).
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import ConflictError, NotFoundError, PlatformAdmin
from dotmac_kernel.deps import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from vendor_cp.relay.withdrawal_outcomes import (
    ConflictOutcomeNotFound,
    ConflictResolutionRefusal,
    resolve_conflict,
)
from vendor_cp.relay.withdrawal_schemas import (
    ConflictResolutionResponse,
    ResolveWithdrawalConflictRequest,
)

router = APIRouter(prefix="/platform/relay/withdrawal-conflicts", tags=["relay"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post("/{outcome_id}/resolve", response_model=ConflictResolutionResponse)
def resolve(
    outcome_id: UUID,
    body: ResolveWithdrawalConflictRequest,
    admin: Admin,
    db: Db,
) -> ConflictResolutionResponse:
    try:
        value = resolve_conflict(
            db,
            outcome_id=outcome_id,
            resolution=body.resolution,
            actor_ref=f"platform_admin:{admin.id}",
            reason=body.reason,
            redrive_ref=body.redrive_ref,
        )
    except ConflictOutcomeNotFound as exc:
        raise NotFoundError(str(exc)) from exc
    except ConflictResolutionRefusal as exc:
        # Not a `security_conflict`, or already resolved: a state conflict.
        raise ConflictError(str(exc)) from exc
    return ConflictResolutionResponse.of(value)


__all__ = ["router"]
