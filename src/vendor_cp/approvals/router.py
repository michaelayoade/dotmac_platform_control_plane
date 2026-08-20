"""Approvals JSON API — a thin, platform-admin-only adapter over the module.

Publish a policy revision, record a decision on an open request, and read a
request's state. Every route delegates to `vendor_cp.approvals.adapter`; nothing
here touches `dotmac_approvals` directly, and nothing here decides anything.

Requests are OPENED by the subject's owner through `vendor_cp.contracts.adapter`,
not through this API. An approval request with no subject would be a request for
nothing, and the owner is what knows the content digest to bind it to.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter
from vendor_cp.approvals.schemas import (
    PolicyResponse,
    PublishPolicyRequest,
    RecordDecisionRequest,
    RequestResponse,
)

router = APIRouter(prefix="/platform/vendor/approvals", tags=["approvals"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post(
    "/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED
)
def publish_policy(body: PublishPolicyRequest, _admin: Admin, db: Db) -> PolicyResponse:
    return PolicyResponse.of(
        adapter.publish_policy_version(
            db,
            adapter.PublishPolicyCommand(
                command_id=body.command_id,
                policy_code=body.policy_code,
                version=body.version,
                quorum=body.quorum,
                allow_self_approval=body.allow_self_approval,
            ),
        )
    )


@router.post("/decisions", response_model=RequestResponse)
def record_decision(
    body: RecordDecisionRequest, admin: Admin, db: Db
) -> RequestResponse:
    """The acting platform admin is the approver — the guard IS the eligibility
    rule, which is why the actor is taken from it rather than from the body."""
    return RequestResponse.of(
        adapter.record_decision(
            db,
            adapter.RecordDecisionCommand(
                command_id=body.command_id,
                request_id=body.request_id,
                approver_id=admin.id,
                content_hash=body.content_hash,
                approve=body.approve,
            ),
        )
    )


@router.get("/requests/{request_id}", response_model=RequestResponse)
def read_request(request_id: UUID, _admin: Admin, db: Db) -> RequestResponse:
    return RequestResponse.of(adapter.evaluate_request(db, request_id=request_id))


__all__ = ["router"]
