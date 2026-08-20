"""The typed seam between Vendor and the `dotmac-approvals` module.

`dotmac-approvals` is the approval authority now. This is the only place Vendor
speaks to it: routes and services call these commands, never the module's
functions directly, so the mapping from Vendor's vocabulary to the module's lives
in one reviewable file.

Typed all the way through — no `Any` at the seam. Commands and views are frozen
dataclasses, the session is a real `Session`, and the module's own value types
(`PolicyRevision`, `Actor`, `Evaluation`) are used rather than dictionaries. A
caller that gets the shape wrong gets a type error, not a row in the wrong shape.

## What the mapping is, and where it came from

The eligibility mapping is the one ADR-0004 § 2 declared while the cutover was
still being designed: Vendor's rule is "any authenticated platform admin may
approve", which is coarse but real, and it maps onto a single-level policy whose
approver is the assembly-owned `PLATFORM_ADMIN_ROLE_ID` role. Every approver
holds that role by construction, because the routes are guarded by
`require_platform_admin`. Digests translate through the same declared function,
since Vendor stores bare hex and the module requires `sha256:`-prefixed.

Those declarations were written before there was any code to use them. They are
used here unchanged, which is the point of having written them down.

## At-most-once is the adapter's job

ADR-0004 § 4 recorded this as an obligation on whatever replaced the legacy
service, and this is that thing. The module REFUSES a duplicate decision
(`DuplicateDecision`); the kernel's `process_once_platform` REPLAYS a duplicate
command and returns the original answer. Vendor's callers retry commands, so the
adapter wraps every mutation in the kernel primitive — a retried request gets its
original outcome instead of an error about a decision it already made.

Transaction authority stays with the caller: the module flushes and never
commits, and nothing here opens a session.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from dotmac_approvals import (
    Actor,
    ApprovalLevel,
    ApprovalState,
    ApproverKind,
    DecisionAction,
    Evaluation,
    PolicyRevision,
)
from dotmac_approvals.models import (
    PlatformApprovalDecision,
    PlatformApprovalRequest,
)
from dotmac_approvals.service import (
    evaluate_platform_approval,
    publish_platform_policy_version,
    record_platform_decision,
    request_platform_approval,
)
from dotmac_kernel import ConflictError
from dotmac_kernel.messaging import process_once_platform
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.approvals_authority import PLATFORM_ADMIN_ROLE_ID, translate_digest

_CMD_PUBLISH = "vendor.approval_policy.publish"
_CMD_OPEN = "vendor.approval_request.open"
_CMD_DECIDE = "vendor.approval_decision.record"

#: The role every Vendor approver holds by construction — the routes are guarded
#: by `require_platform_admin`, so appearing as an approver at all means the
#: guard passed.
_PLATFORM_ADMIN_ROLE = UUID(PLATFORM_ADMIN_ROLE_ID)


# ── Commands ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PublishPolicyCommand:
    command_id: str
    policy_code: str
    version: int
    quorum: int
    allow_self_approval: bool


@dataclass(frozen=True, slots=True)
class OpenRequestCommand:
    """Open an approval request for one subject at one exact content digest."""

    command_id: str
    policy_code: str
    policy_version: int
    subject_type: str
    subject_id: str
    content_hash: str
    requested_by: UUID


@dataclass(frozen=True, slots=True)
class RecordDecisionCommand:
    """One approver's decision on an open request, bound to the content."""

    command_id: str
    request_id: UUID
    approver_id: UUID
    content_hash: str
    approve: bool = True


# ── Views ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PolicyView:
    policy_code: str
    version: int
    quorum: int
    allow_self_approval: bool


@dataclass(frozen=True, slots=True)
class RequestView:
    """An approval request's state, in Vendor's own terms.

    `satisfied` is derived from the module's `ApprovalState`, not recomputed:
    the module owns the decision, and a second opinion here would be a second
    authority.
    """

    request_id: UUID
    state: str
    satisfied: bool
    satisfied_levels: int
    total_levels: int
    reason: str

    @classmethod
    def of(cls, request_id: UUID, evaluation: Evaluation) -> RequestView:
        return cls(
            request_id=request_id,
            state=str(evaluation.state),
            satisfied=evaluation.state is ApprovalState.APPROVED,
            satisfied_levels=evaluation.satisfied_levels,
            total_levels=evaluation.total_levels,
            reason=evaluation.reason,
        )


@dataclass(frozen=True, slots=True)
class ApprovedRequestEvidence:
    """The exact approval fact a subject owner may act on.

    This is evidence, not a second evaluation: state comes from the Approvals
    module and every identity/digest field is copied from its authoritative
    request and immutable decisions.
    """

    request_id: UUID
    policy_code: str
    policy_version: int
    content_hash: str
    decided_at: datetime
    approver_refs: tuple[str, ...]


# ── Operations ──────────────────────────────────────────────────────────────


def _revision(command: PublishPolicyCommand) -> PolicyRevision:
    """Vendor's policy shape as the module's `PolicyRevision`.

    One level, because Vendor never expressed sequencing. The approver is the
    platform-admin ROLE rather than a named person, which is exactly what
    "any authenticated platform admin may approve" means once written as data.
    """
    return PolicyRevision(
        policy_code=command.policy_code,
        version=command.version,
        levels=(
            ApprovalLevel(
                sequence=1,
                approver_kind=ApproverKind.ROLE,
                approver_id=PLATFORM_ADMIN_ROLE_ID,
                quorum=command.quorum,
            ),
        ),
        allow_self_approval=command.allow_self_approval,
    )


def publish_policy_version(db: Session, command: PublishPolicyCommand) -> PolicyView:
    """Publish an immutable policy revision. Idempotent by command id."""

    def handler(session: Session) -> Mapping[str, object]:
        publish_platform_policy_version(session, revision=_revision(command))
        return {"policy_code": command.policy_code, "version": command.version}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CMD_PUBLISH,
        handler=handler,
    )
    return PolicyView(
        policy_code=command.policy_code,
        version=command.version,
        quorum=command.quorum,
        allow_self_approval=command.allow_self_approval,
    )


def open_request(db: Session, command: OpenRequestCommand) -> RequestView:
    """Open a request against an exact policy revision and content digest.

    The module carries its own idempotency key as well; both are the command id,
    so a retry is a no-op at either layer rather than a second request.
    """

    def handler(session: Session) -> Mapping[str, object]:
        outcome = request_platform_approval(
            session,
            policy_code=command.policy_code,
            policy_version=command.policy_version,
            subject_type=command.subject_type,
            subject_id=command.subject_id,
            content_digest=translate_digest(command.content_hash),
            requested_by=command.requested_by,
            idempotency_key=command.command_id,
        )
        return {"request_id": str(outcome.request_id)}

    # `ProcessOutcome.result` carries the handler's recorded result whether it
    # ran now or was replayed, so both paths read the same way — and the state
    # reported is the request's CURRENT one, not the one it had when opened.
    processed = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CMD_OPEN,
        handler=handler,
    )
    return evaluate_request(db, request_id=UUID(str(processed.result["request_id"])))


def record_decision(db: Session, command: RecordDecisionCommand) -> RequestView:
    """Record one approver's decision, then report the request's new state.

    The module refuses a duplicate decision; `process_once_platform` makes a
    RETRIED command replay instead — the obligation ADR-0004 § 4 recorded.
    """

    def handler(session: Session) -> Mapping[str, object]:
        record_platform_decision(
            session,
            request_id=command.request_id,
            actor=Actor(
                actor_id=command.approver_id,
                role_ids=frozenset({_PLATFORM_ADMIN_ROLE}),
            ),
            action=(
                DecisionAction.APPROVE if command.approve else DecisionAction.REJECT
            ),
            content_digest=translate_digest(command.content_hash),
        )
        return {"request_id": str(command.request_id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CMD_DECIDE,
        handler=handler,
    )
    return evaluate_request(db, request_id=command.request_id)


def evaluate_request(db: Session, *, request_id: UUID) -> RequestView:
    """Is this request approved? Read-only; the module owns the answer."""
    return RequestView.of(
        request_id, evaluate_platform_approval(db, request_id=request_id)
    )


def approved_request_evidence(
    db: Session,
    *,
    request_id: UUID,
    subject_type: str,
    subject_id: str,
    content_hash: str,
) -> ApprovedRequestEvidence:
    """Return content-bound approved evidence for one exact subject.

    Commercial Agreements is handed this value and checks it against its own
    frozen digest. Vendor does not turn an approval status into a writable
    agreement state; the agreement module performs that guarded transition.
    """
    request = db.get(PlatformApprovalRequest, request_id)
    if request is None:
        raise ConflictError(f"approval request {request_id} not found")
    expected_digest = translate_digest(content_hash)
    mismatches: list[str] = []
    if request.subject_type != subject_type:
        mismatches.append("subject_type")
    if request.subject_id != subject_id:
        mismatches.append("subject_id")
    if request.content_digest != expected_digest:
        mismatches.append("content_digest")
    if mismatches:
        raise ConflictError(
            f"approval request {request_id} does not bind to this agreement "
            f"({', '.join(mismatches)})"
        )

    evaluation = evaluate_platform_approval(db, request_id=request_id)
    if evaluation.state is not ApprovalState.APPROVED:
        raise ConflictError(
            f"approval request {request_id} is {evaluation.state}, not approved"
        )
    if request.completed_at is None:
        raise ConflictError(
            f"approval request {request_id} is approved without completed_at"
        )

    approvers = tuple(
        str(actor_id)
        for actor_id in db.scalars(
            select(PlatformApprovalDecision.actor_id)
            .where(
                PlatformApprovalDecision.request_id == request_id,
                PlatformApprovalDecision.action == str(DecisionAction.APPROVE),
            )
            .order_by(
                PlatformApprovalDecision.decided_at,
                PlatformApprovalDecision.id,
            )
        )
    )
    if not approvers:
        raise ConflictError(
            f"approval request {request_id} is approved without approval decisions"
        )
    return ApprovedRequestEvidence(
        request_id=request_id,
        policy_code=request.policy_code,
        policy_version=request.policy_version,
        content_hash=content_hash,
        decided_at=request.completed_at,
        approver_refs=approvers,
    )


__all__ = [
    "ApprovedRequestEvidence",
    "OpenRequestCommand",
    "PolicyView",
    "PublishPolicyCommand",
    "RecordDecisionCommand",
    "RequestView",
    "approved_request_evidence",
    "evaluate_request",
    "open_request",
    "publish_policy_version",
    "record_decision",
]
