"""Typed request/response models for the approvals API (no bare dicts).

Shapes follow the module's model, which is a REQUEST lifecycle: a request is
opened against an exact policy revision and content digest by the subject's
owner, and approvers then decide on that request. Vendor's old shape had no
request at all — approvals were counted directly against a `(subject, digest)`
tuple — so these are the module's concepts named in Vendor's API.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.approvals.adapter import PolicyView, RequestView


class PublishPolicyRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    policy_code: str = Field(min_length=1, max_length=120)
    version: int = Field(ge=1)
    quorum: int = Field(ge=1)
    allow_self_approval: bool = False


class PolicyResponse(BaseModel):
    policy_code: str
    version: int
    quorum: int
    allow_self_approval: bool

    @classmethod
    def of(cls, view: PolicyView) -> PolicyResponse:
        return cls(
            policy_code=view.policy_code,
            version=view.version,
            quorum=view.quorum,
            allow_self_approval=view.allow_self_approval,
        )


class RecordDecisionRequest(BaseModel):
    """One approver's decision on an open request, bound to the content.

    `content_hash` is not decoration: the module refuses a decision whose digest
    no longer matches the request's, so an approver cannot approve content that
    has changed under them.
    """

    command_id: str = Field(min_length=1, max_length=200)
    request_id: UUID
    content_hash: str = Field(min_length=1, max_length=128)
    approve: bool = True


class RequestResponse(BaseModel):
    """An approval request's current state."""

    request_id: UUID
    state: str
    satisfied: bool
    satisfied_levels: int
    total_levels: int
    reason: str

    @classmethod
    def of(cls, view: RequestView) -> RequestResponse:
        return cls(
            request_id=view.request_id,
            state=view.state,
            satisfied=view.satisfied,
            satisfied_levels=view.satisfied_levels,
            total_levels=view.total_levels,
            reason=view.reason,
        )


__all__ = [
    "PolicyResponse",
    "PublishPolicyRequest",
    "RecordDecisionRequest",
    "RequestResponse",
]
