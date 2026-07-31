"""Typed request/response models for the approvals API (no bare dicts)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.approvals.models import ApprovalPolicy
from vendor_cp.approvals.service import ApprovalDecision


class PublishPolicyRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    policy_code: str = Field(min_length=1, max_length=120)
    version: int = Field(ge=1)
    quorum: int = Field(ge=1)
    allow_self_approval: bool = False


class PolicyResponse(BaseModel):
    id: UUID
    policy_code: str
    version: int
    quorum: int
    allow_self_approval: bool

    @classmethod
    def of(cls, p: ApprovalPolicy) -> PolicyResponse:
        return cls(
            id=p.id,
            policy_code=p.policy_code,
            version=p.version,
            quorum=p.quorum,
            allow_self_approval=p.allow_self_approval,
        )


class RecordApprovalRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    policy_code: str = Field(min_length=1, max_length=120)
    policy_version: int = Field(ge=1)
    subject_type: str = Field(min_length=1, max_length=120)
    subject_id: str = Field(min_length=1, max_length=200)
    content_hash: str = Field(min_length=1, max_length=128)


class RecordApprovalResponse(BaseModel):
    """Ack for a recorded approval (idempotent: same id on replay)."""

    id: UUID


class EvaluateResponse(BaseModel):
    satisfied: bool
    quorum: int
    distinct_approvers: int
    reason: str

    @classmethod
    def of(cls, d: ApprovalDecision) -> EvaluateResponse:
        return cls(
            satisfied=d.satisfied,
            quorum=d.quorum,
            distinct_approvers=d.distinct_approvers,
            reason=d.reason,
        )


__all__ = [
    "PublishPolicyRequest",
    "PolicyResponse",
    "RecordApprovalRequest",
    "RecordApprovalResponse",
    "EvaluateResponse",
]
