"""`ApprovalPolicyService` — versioned policy + content-bound approvals + quorum.

Platform-level, built on the kernel's platform-scoped primitives (idempotent
`process_once_platform`, audited `write_platform_audit_event`).

- `publish_policy_version` — an IMMUTABLE policy version (republish → conflict).
- `record_approval` — one approver approving a `(subject, content_hash)`.
  Idempotent and distinct-by-construction (re-approving the same content is a
  no-op; the unique constraint prevents a double count).
- `evaluate` — is the distinct-actor quorum satisfied for THIS content hash under
  the policy version? **Fails closed**: a missing policy is `satisfied=False`,
  reason `policy_not_found` — never an implicit approval. Content-bound: a
  different `content_hash` (the content changed) has its own, separate approvals.

Transaction-authority contract: receives a `Session` and only add/flush; the
route owns commit. Typed commands/outcomes throughout.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from dotmac_kernel import ConflictError, write_platform_audit_event
from dotmac_kernel.messaging import process_once_platform
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.approvals.models import ApprovalPolicy, ApprovalRecord

_CMD_PUBLISH = "vendor.approval_policy.publish"
_CMD_APPROVE = "vendor.approval.record"


@dataclass(frozen=True, slots=True)
class PublishPolicyCommand:
    command_id: str
    policy_code: str
    version: int
    quorum: int
    allow_self_approval: bool = False
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class RecordApprovalCommand:
    command_id: str
    policy_code: str
    policy_version: int
    subject_type: str
    subject_id: str
    content_hash: str
    approver_id: UUID


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """Explainable outcome of `evaluate`. `reason` is a stable code:
    `satisfied` | `insufficient_quorum` | `policy_not_found`."""

    satisfied: bool
    quorum: int
    distinct_approvers: int
    reason: str


def publish_policy_version(
    db: Session, command: PublishPolicyCommand
) -> ApprovalPolicy:
    """Publish an immutable approval-policy version. Raises `ConflictError` if
    `(policy_code, version)` already exists."""
    if command.quorum < 1:
        raise ConflictError("quorum must be at least 1")

    def handler(session: Session) -> Mapping[str, object]:
        existing = session.execute(
            select(ApprovalPolicy).where(
                ApprovalPolicy.policy_code == command.policy_code,
                ApprovalPolicy.version == command.version,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(
                f"approval policy {command.policy_code!r} v{command.version} "
                "already exists — policy versions are immutable"
            )
        row = ApprovalPolicy(
            policy_code=command.policy_code,
            version=command.version,
            quorum=command.quorum,
            allow_self_approval=command.allow_self_approval,
        )
        session.add(row)
        session.flush()
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.approval_policy.published",
            entity_type="approval_policy",
            entity_id=str(row.id),
            details={
                "policy_code": row.policy_code,
                "version": row.version,
                "quorum": row.quorum,
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CMD_PUBLISH,
        handler=handler,
    )
    return db.execute(
        select(ApprovalPolicy).where(
            ApprovalPolicy.policy_code == command.policy_code,
            ApprovalPolicy.version == command.version,
        )
    ).scalar_one()


def record_approval(db: Session, command: RecordApprovalCommand) -> ApprovalRecord:
    """Record an approver's approval of a `(subject, content_hash)`. Idempotent:
    re-approving the same content by the same approver is a no-op."""

    def _find(session: Session) -> ApprovalRecord | None:
        return session.execute(
            select(ApprovalRecord).where(
                ApprovalRecord.policy_code == command.policy_code,
                ApprovalRecord.policy_version == command.policy_version,
                ApprovalRecord.subject_type == command.subject_type,
                ApprovalRecord.subject_id == command.subject_id,
                ApprovalRecord.content_hash == command.content_hash,
                ApprovalRecord.approver_id == command.approver_id,
            )
        ).scalar_one_or_none()

    def handler(session: Session) -> Mapping[str, object]:
        existing = _find(session)
        if existing is not None:
            return {"id": str(existing.id)}
        row = ApprovalRecord(
            policy_code=command.policy_code,
            policy_version=command.policy_version,
            subject_type=command.subject_type,
            subject_id=command.subject_id,
            content_hash=command.content_hash,
            approver_id=command.approver_id,
        )
        session.add(row)
        session.flush()
        write_platform_audit_event(
            session,
            actor_admin_id=command.approver_id,
            action="vendor.approval.recorded",
            entity_type=command.subject_type,
            entity_id=command.subject_id,
            details={
                "policy_code": command.policy_code,
                "policy_version": command.policy_version,
                "content_hash": command.content_hash,
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CMD_APPROVE,
        handler=handler,
    )
    row = _find(db)
    if row is None:  # unreachable: handler inserted it or it already existed
        raise RuntimeError("approval record missing after record_approval")
    return row


def evaluate(
    db: Session,
    *,
    policy_code: str,
    policy_version: int,
    subject_type: str,
    subject_id: str,
    content_hash: str,
    submitter_id: UUID | None = None,
) -> ApprovalDecision:
    """Is the distinct-actor quorum satisfied for this content hash? Fails closed
    on a missing policy. When self-approval is disallowed, the submitter's own
    approval does not count."""
    policy = db.execute(
        select(ApprovalPolicy).where(
            ApprovalPolicy.policy_code == policy_code,
            ApprovalPolicy.version == policy_version,
        )
    ).scalar_one_or_none()
    if policy is None:
        return ApprovalDecision(False, 0, 0, "policy_not_found")

    stmt = select(func.count(func.distinct(ApprovalRecord.approver_id))).where(
        ApprovalRecord.policy_code == policy_code,
        ApprovalRecord.policy_version == policy_version,
        ApprovalRecord.subject_type == subject_type,
        ApprovalRecord.subject_id == subject_id,
        ApprovalRecord.content_hash == content_hash,
    )
    if not policy.allow_self_approval and submitter_id is not None:
        stmt = stmt.where(ApprovalRecord.approver_id != submitter_id)
    distinct = int(db.scalar(stmt) or 0)

    satisfied = distinct >= policy.quorum
    return ApprovalDecision(
        satisfied=satisfied,
        quorum=policy.quorum,
        distinct_approvers=distinct,
        reason="satisfied" if satisfied else "insufficient_quorum",
    )


__all__ = [
    "PublishPolicyCommand",
    "RecordApprovalCommand",
    "ApprovalDecision",
    "publish_policy_version",
    "record_approval",
    "evaluate",
]
