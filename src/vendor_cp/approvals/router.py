"""Approvals JSON API — a thin, platform-admin-only adapter.

Publish a policy version, record an approval (the acting platform admin is the
approver), and evaluate the quorum for a content hash. Delegates to
`ApprovalPolicyService`; `ConflictError` (immutable policy) → 409.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.approvals import service
from vendor_cp.approvals.schemas import (
    EvaluateResponse,
    PolicyResponse,
    PublishPolicyRequest,
    RecordApprovalRequest,
    RecordApprovalResponse,
)

router = APIRouter(prefix="/platform/vendor/approvals", tags=["approvals"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post(
    "/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED
)
def publish_policy(body: PublishPolicyRequest, admin: Admin, db: Db) -> PolicyResponse:
    policy = service.publish_policy_version(
        db,
        service.PublishPolicyCommand(
            command_id=body.command_id,
            policy_code=body.policy_code,
            version=body.version,
            quorum=body.quorum,
            allow_self_approval=body.allow_self_approval,
            actor_admin_id=admin.id,
        ),
    )
    return PolicyResponse.of(policy)


@router.post("", response_model=RecordApprovalResponse)
def record_approval(
    body: RecordApprovalRequest, admin: Admin, db: Db
) -> RecordApprovalResponse:
    record = service.record_approval(
        db,
        service.RecordApprovalCommand(
            command_id=body.command_id,
            policy_code=body.policy_code,
            policy_version=body.policy_version,
            subject_type=body.subject_type,
            subject_id=body.subject_id,
            content_hash=body.content_hash,
            approver_id=admin.id,
        ),
    )
    return RecordApprovalResponse(id=record.id)


@router.get("/evaluate", response_model=EvaluateResponse)
def evaluate(
    policy_code: str,
    policy_version: int,
    subject_type: str,
    subject_id: str,
    content_hash: str,
    _admin: Admin,
    db: Db,
    submitter_id: UUID | None = None,
) -> EvaluateResponse:
    return EvaluateResponse.of(
        service.evaluate(
            db,
            policy_code=policy_code,
            policy_version=policy_version,
            subject_type=subject_type,
            subject_id=subject_id,
            content_hash=content_hash,
            submitter_id=submitter_id,
        )
    )


__all__ = ["router"]
