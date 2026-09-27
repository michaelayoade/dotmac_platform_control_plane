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
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.relay.withdrawal_outcomes import (
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

#: `resolve_conflict`'s own refusal text, split by which HTTP status it earns.
#: See that function's docstring: these are the only two reasons it raises.
_NOT_FOUND_PREFIX = "no withdrawal outcome"


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
    except ConflictResolutionRefusal as exc:
        message = str(exc)
        if message.startswith(_NOT_FOUND_PREFIX):
            raise NotFoundError(message) from exc
        # Not a `security_conflict` (a clean terminal disposition already
        # reached) — a state conflict, not a missing resource.
        raise ConflictError(message) from exc
    except IntegrityError as exc:
        # `outcome_id` is unique on the resolution table (append-only): a
        # second resolve for the same outcome collides here rather than
        # overwriting the first human's decision — see `resolve_conflict`'s
        # own docstring. A state conflict, not a validation fault.
        raise ConflictError(
            f"withdrawal outcome {outcome_id} was already resolved"
        ) from exc
    return ConflictResolutionResponse.of(value)


__all__ = ["router"]
