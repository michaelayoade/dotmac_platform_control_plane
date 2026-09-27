"""Protected rehearsal-issuer composition, without a deployment rollout.

The approval transaction must commit before a different transaction calls
``issue_authorization``. Control owns plan standing and issuer issuance;
Approvals owns the decision and its durable withdrawal event. Control and
Approvals are imported inside functions, so this leaf stays import-light; both
exact wheels (Control 0.1.0a16, Approvals 0.1.0a8) are published and pinned.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Final, Protocol, cast
from uuid import UUID

from dotmac_kernel.messaging import ClaimedPlatformEvent
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.deployment.rehearsal_issuer_seam import RehearsalIssuerInvocation
from vendor_cp.relay.approval_router import (
    ApprovalWithdrawalResult,
    RetryableWithdrawal,
)
from vendor_cp.relay.withdrawal_outcomes import WithdrawalDisposition

if TYPE_CHECKING:
    from vendor_cp.approvals.adapter import HeldPlatformApproval

PLAN_PURPOSE: Final = "rehearsal_issuer_operation"
ISSUER_OPERATION: Final = "deploy"
SUBJECT_TYPE: Final = "rehearsal_issuer_plan.v1"
SIGNER_PURPOSE: Final = "deployment_rehearsal_issuer"
SIGNER_OPENBAO_PATH: Final = "secret/dotmac/platform-cp/rehearsal-issuer/signing-key"


@dataclass(frozen=True, slots=True)
class ProposeIssuerPlan:
    command_id: str
    target_id: UUID
    descriptor_digest: str
    execution_plan_digest: str
    approval_policy_code: str
    approval_policy_version: int
    expected_desired_revision: int | None = None
    actor_ref: str | None = None


class PlanFacts(Protocol):
    id: UUID
    purpose: str
    operation: str | None
    execution_plan_digest: str | None
    plan_digest: str | None
    approval_policy_code: str | None
    approval_policy_version: int | None
    approval_decision_ref: str | None
    #: Read by `classify_approval_withdrawal`'s pre-read and status branches
    #: only; every other function above ignores these three.
    status: str
    approval_decision_status: str | None
    approval_revocation_ref: str | None


def _subject(plan: PlanFacts) -> str:
    """Canonical, bounded Approvals subject; the content hash is separate."""
    plan_id = plan.id
    purpose = plan.purpose
    operation = plan.operation
    digest = plan.execution_plan_digest
    if not isinstance(plan_id, UUID) or purpose != PLAN_PURPOSE:
        raise ValueError("expected a rehearsal-issuer Control plan")
    if operation != ISSUER_OPERATION or not isinstance(digest, str):
        raise ValueError("issuer plan lacks its explicit execution binding")
    if (
        len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ValueError("issuer plan has no canonical execution-plan digest")
    subject = f"v1|{plan_id}|{purpose}|{operation}|{digest}"
    if len(subject) > 200:
        raise ValueError(
            "issuer approval subject exceeds Approvals' 200-character limit"
        )
    return subject


def _plan(db: object, plan_id: UUID) -> PlanFacts:
    plan = import_module("dotmac_deployment_control").get_plan(db, plan_id)
    if plan is None:
        raise ValueError(f"Control plan {plan_id} does not exist")
    _subject(plan)
    return cast(PlanFacts, plan)


def propose_issuer_plan(db: object, request: ProposeIssuerPlan) -> object:
    """Freeze Control's plan with explicit purpose and execution binding."""
    control = import_module("dotmac_deployment_control")

    plan = control.propose_plan(
        db,
        control.ProposePlanCommand(
            command_id=request.command_id,
            target_id=request.target_id,
            operation=ISSUER_OPERATION,
            descriptor_digest=request.descriptor_digest,
            execution_plan_digest=request.execution_plan_digest,
            purpose=PLAN_PURPOSE,
            requires_approval=True,
            approval_policy_code=request.approval_policy_code,
            approval_policy_version=request.approval_policy_version,
            expected_desired_revision=request.expected_desired_revision,
            actor_ref=request.actor_ref,
        ),
    )
    _subject(cast(PlanFacts, plan))
    return plan


def open_issuer_approval(
    db: Session, *, command_id: str, plan_id: UUID, requested_by: UUID
) -> object:
    """Open the real platform request against the exact frozen plan."""
    from vendor_cp.approvals.adapter import OpenRequestCommand, open_request
    from vendor_cp.approvals_authority import bare_content_hash

    plan = _plan(db, plan_id)
    if (
        not plan.plan_digest
        or not plan.approval_policy_code
        or plan.approval_policy_version is None
    ):
        raise ValueError("issuer plan lacks its digest or approval policy")
    return open_request(
        db,
        OpenRequestCommand(
            command_id=command_id,
            policy_code=plan.approval_policy_code,
            policy_version=plan.approval_policy_version,
            subject_type=SUBJECT_TYPE,
            subject_id=_subject(plan),
            content_hash=bare_content_hash(plan.plan_digest),
            requested_by=requested_by,
        ),
    )


def approve_issuer_plan(
    db: Session,
    *,
    command_id: str,
    plan_id: UUID,
    approval_request_id: UUID,
    expected_plan_version: int | None = None,
    actor_ref: str | None = None,
) -> object:
    """Carry Approvals' held decision into Control, under the same lock.

    `held_transition` locks the platform approval request FOR SHARE and holds
    that lock through `control.approve_plan` and into the caller's own
    commit — the barrier, not the relay, is what makes this safe against a
    concurrent withdrawal.

    A non-authorizing receipt (`issuer_receipts.py`) is written in the SAME
    transaction as `control.approve_plan`, keyed by `command_id` and a
    fingerprint of this request. It never bypasses or replaces the hold
    above: a NEW command id still takes the hold and refuses exactly as
    before. It only lets a retry of an ALREADY-COMMITTED command, made after
    a later withdrawal, report that fact (`IssuerCommandCommittedButWithdrawn`)
    instead of a bare "not held" with no explanation.
    """
    control = import_module("dotmac_deployment_control")

    from vendor_cp.approvals.adapter import ApprovalNotHeld
    from vendor_cp.deployment.approval_barrier import held_transition
    from vendor_cp.deployment.issuer_receipts import (
        APPROVE_PLAN,
        IssuerCommandCommittedButWithdrawn,
        IssuerCommandReused,
        IssuerReceiptMismatch,
        find_receipt,
        record_receipt,
        request_fingerprint,
    )

    plan = _plan(db, plan_id)
    if not plan.plan_digest:
        raise ValueError("issuer plan has no frozen digest")

    fingerprint = request_fingerprint(
        APPROVE_PLAN,
        {
            "command_id": command_id,
            "plan_id": plan_id,
            "approval_request_id": approval_request_id,
            "expected_plan_version": expected_plan_version,
            "actor_ref": actor_ref,
        },
    )
    receipt = find_receipt(db, command_id)
    if receipt is not None and (
        receipt.verb != APPROVE_PLAN or receipt.request_fingerprint != fingerprint
    ):
        raise IssuerCommandReused(
            f"command id {command_id!r} was already used for a different "
            "approve_plan request"
        )

    def transition(held: HeldPlatformApproval) -> object:
        result = control.approve_plan(
            db,
            control.ApprovePlanCommand(
                command_id=command_id,
                plan_id=plan_id,
                evidence=control.ApprovalEvidence(
                    policy_code=held.policy_code,
                    policy_version=held.policy_version,
                    decision_ref=str(held.request_id),
                    content_digest=plan.plan_digest,
                    decided_at=held.decided_at,
                    approver_refs=tuple(
                        str(approver_id) for approver_id in held.approver_ids
                    ),
                    decision_status="granted",
                    operation=plan.operation,
                    execution_plan_digest=plan.execution_plan_digest,
                ),
                expected_version=expected_plan_version,
                actor_ref=actor_ref,
            ),
        )
        if (
            result.id != plan_id
            or result.status != "approved"
            or result.approval_decision_ref != str(held.request_id)
        ):
            raise IssuerReceiptMismatch(
                f"command id {command_id!r} approve_plan call returned "
                f"id={result.id!r} status={result.status!r} "
                f"approval_decision_ref={result.approval_decision_ref!r}, "
                f"which does not match the request it was made under"
            )
        control_ref = str(result.id)
        existing = find_receipt(db, command_id)
        if existing is not None:
            if (
                existing.verb != APPROVE_PLAN
                or existing.request_fingerprint != fingerprint
            ):
                raise IssuerCommandReused(
                    f"command id {command_id!r} was already used for a "
                    "different approve_plan request"
                )
            if existing.plan_id != plan_id or existing.control_ref != control_ref:
                raise IssuerReceiptMismatch(
                    f"command id {command_id!r} recorded plan_id "
                    f"{existing.plan_id!r} control_ref {existing.control_ref!r}, "
                    f"but this approve_plan call produced plan_id {plan_id!r} "
                    f"control_ref {control_ref!r}"
                )
        if existing is None:
            record_receipt(
                db,
                command_id=command_id,
                verb=APPROVE_PLAN,
                fingerprint=fingerprint,
                plan_id=plan_id,
                approval_request_id=approval_request_id,
                control_ref=control_ref,
            )
        return result

    try:
        return held_transition(
            db,
            request_id=approval_request_id,
            subject_type=SUBJECT_TYPE,
            subject_id=_subject(plan),
            content_digest=plan.plan_digest,
            transition=transition,
        )
    except ApprovalNotHeld as exc:
        if receipt is not None:
            raise IssuerCommandCommittedButWithdrawn(
                command_id, APPROVE_PLAN, receipt.control_ref
            ) from exc
        raise


def issue_authorization(db: Session, invocation: RehearsalIssuerInvocation) -> object:
    """Issue in a new transaction, under the same approval hold as approval.

    The caller owns the commit. A withdrawal after the approval transaction
    committed but before this one commits is exactly the window
    `held_transition` closes: the hold's arguments come only from Control's
    own frozen plan (never the invocation), so the lock covers precisely the
    decision issuance depends on. After issuance returns — still inside the
    hold, still before the caller's commit — the plan is re-read and its
    decision ref and digest compared against what was held. Under Control
    0.1.0a16 those fields are immutable once a plan is approved (approval
    requires PROPOSED) and Control re-checks standing under its own plan lock,
    so this comparison is defence in depth. It fails loudly if a future
    Control could re-bind a plan's decision between the unlocked pre-read and
    the hold.

    A non-authorizing receipt (`issuer_receipts.py`) is written in the SAME
    transaction as `control.issue_rehearsal_issuer_authorization_for_plan`,
    keyed by `command_id` and a fingerprint of `invocation.to_control_request()`
    (deterministic — it carries only `command_id`, `plan_id`, and an optional
    `actor_ref`, none of which vary between a genuine retry and its original).
    `control_ref` is the authorization's own `statement.authorization_id`,
    never the signed envelope itself. A NEW command id still takes the hold
    and refuses exactly as before; only a retry of an ALREADY-COMMITTED
    command, made after a later withdrawal, is reported via
    `IssuerCommandCommittedButWithdrawn` instead of a bare "not held".
    """
    control = import_module("dotmac_deployment_control")

    from vendor_cp.approvals.adapter import ApprovalNotHeld
    from vendor_cp.deployment.approval_barrier import held_transition
    from vendor_cp.deployment.issuer_receipts import (
        ISSUE_AUTHORIZATION,
        IssuerCommandCommittedButWithdrawn,
        IssuerCommandReused,
        IssuerReceiptMismatch,
        find_receipt,
        record_receipt,
        request_fingerprint,
    )

    plan_id = invocation.command.plan_id
    command_id = invocation.command.command_id
    plan = _plan(db, plan_id)
    if not plan.approval_decision_ref:
        raise ValueError(f"issuer plan {plan_id} has no recorded approval decision")
    try:
        request_id = UUID(plan.approval_decision_ref)
    except ValueError as exc:
        raise ValueError(
            f"issuer plan {plan_id} approval_decision_ref "
            f"{plan.approval_decision_ref!r} is not a UUID"
        ) from exc
    if not plan.plan_digest:
        raise ValueError(f"issuer plan {plan_id} has no frozen digest")
    expected_decision_ref = plan.approval_decision_ref
    expected_plan_digest = plan.plan_digest

    fingerprint = request_fingerprint(
        ISSUE_AUTHORIZATION, dict(invocation.to_control_request())
    )
    receipt = find_receipt(db, command_id)
    if receipt is not None and (
        receipt.verb != ISSUE_AUTHORIZATION
        or receipt.request_fingerprint != fingerprint
    ):
        raise IssuerCommandReused(
            f"command id {command_id!r} was already used for a different "
            "issue_authorization request"
        )

    def transition(held: HeldPlatformApproval) -> object:
        result = control.issue_rehearsal_issuer_authorization_for_plan(
            db,
            dict(invocation.to_control_request()),
            harness_evidence_document=invocation.harness_evidence_document,
        )
        reread = _plan(db, plan_id)
        if (
            reread.approval_decision_ref != expected_decision_ref
            or reread.plan_digest != expected_plan_digest
        ):
            raise ValueError(
                f"issuer plan {plan_id} approval standing changed during issuance"
            )
        control_ref = result.statement.authorization_id
        existing = find_receipt(db, command_id)
        if existing is not None:
            if (
                existing.verb != ISSUE_AUTHORIZATION
                or existing.request_fingerprint != fingerprint
            ):
                raise IssuerCommandReused(
                    f"command id {command_id!r} was already used for a "
                    "different issue_authorization request"
                )
            if existing.plan_id != plan_id or existing.control_ref != control_ref:
                raise IssuerReceiptMismatch(
                    f"command id {command_id!r} recorded plan_id "
                    f"{existing.plan_id!r} control_ref {existing.control_ref!r}, "
                    f"but this issue_authorization call produced plan_id "
                    f"{plan_id!r} control_ref {control_ref!r}"
                )
        if existing is None:
            record_receipt(
                db,
                command_id=command_id,
                verb=ISSUE_AUTHORIZATION,
                fingerprint=fingerprint,
                plan_id=plan_id,
                approval_request_id=request_id,
                control_ref=control_ref,
            )
        return result

    try:
        return held_transition(
            db,
            request_id=request_id,
            subject_type=SUBJECT_TYPE,
            subject_id=_subject(plan),
            content_digest=plan.plan_digest,
            transition=transition,
        )
    except ApprovalNotHeld as exc:
        if receipt is not None:
            raise IssuerCommandCommittedButWithdrawn(
                command_id, ISSUE_AUTHORIZATION, receipt.control_ref
            ) from exc
        raise


def _conflict(
    reason_code: str,
    *,
    coordinates: Mapping[str, object] | None = None,
    evidence: Mapping[str, object] | None = None,
) -> ApprovalWithdrawalResult:
    return ApprovalWithdrawalResult(
        disposition=WithdrawalDisposition.SECURITY_CONFLICT,
        reason_code=reason_code,
        coordinates=coordinates or {},
        evidence=evidence or {},
    )


def _revoked_pre_read(
    plan: PlanFacts, *, plan_id: UUID, request_id: UUID, event_id: UUID
) -> ApprovalWithdrawalResult | None:
    """Standing revocation state, checked BEFORE calling `revoke_plan_approval`.

    `None` means the plan's approval still stands and the caller should go on
    to attempt the revocation itself.
    """
    if plan.approval_decision_status != "revoked":
        return None
    own_ref = f"approval.withdrawn:{event_id}"
    coordinates: dict[str, object] = {
        "plan_id": plan_id,
        "approval_request_id": request_id,
        "withdrawal_ref": str(event_id),
    }
    if plan.approval_revocation_ref == own_ref:
        return ApprovalWithdrawalResult(
            disposition=WithdrawalDisposition.ALREADY_APPLIED,
            reason_code="already_applied",
            coordinates=coordinates,
            evidence={"approval_revocation_ref": plan.approval_revocation_ref},
        )
    return ApprovalWithdrawalResult(
        disposition=WithdrawalDisposition.SUPERSEDED_BY_REVOCATION,
        reason_code="superseded_by_revocation",
        coordinates=coordinates,
        evidence={
            "approval_revocation_ref": plan.approval_revocation_ref,
            "withdrawal_ref": own_ref,
        },
    )


def classify_approval_withdrawal(
    db: Session, event: ClaimedPlatformEvent
) -> ApprovalWithdrawalResult:
    """Classify one `approval.withdrawn` event against the frozen issuer plan.

    Returns a terminal `ApprovalWithdrawalResult` for the router to record, or
    raises `RetryableWithdrawal` when the database itself is the obstacle.
    The Control call — the one domain consequence this handler owns — happens
    HERE, inside the router's delivery transaction; the caller commits.
    """
    payload = event.payload
    if payload.get("subject_type") != SUBJECT_TYPE:
        return _conflict(
            "subject_type_mismatch",
            evidence={"subject_type": payload.get("subject_type")},
        )

    try:
        subject_id = str(payload["subject_id"])
        version, plan_id_text, purpose, operation, digest = subject_id.split("|")
        if version != "v1" or purpose != PLAN_PURPOSE or operation != ISSUER_OPERATION:
            raise ValueError("unexpected issuer approval subject")
        plan_id = UUID(plan_id_text)
    except (KeyError, ValueError):
        return _conflict(
            "malformed_subject", evidence={"subject_id": payload.get("subject_id")}
        )

    try:
        control = import_module("dotmac_deployment_control")
        plan = cast(PlanFacts, control.get_plan(db, plan_id))
    except OperationalError as exc:
        raise RetryableWithdrawal("database_unavailable") from exc
    if plan is None:
        return _conflict("plan_not_found", coordinates={"plan_id": plan_id})
    try:
        _subject(plan)
    except ValueError:
        return _conflict("plan_not_found", coordinates={"plan_id": plan_id})

    if subject_id != _subject(plan) or digest != plan.execution_plan_digest:
        return _conflict(
            "subject_mismatch",
            coordinates={"plan_id": plan_id},
            evidence={"subject_id": subject_id, "expected_subject": _subject(plan)},
        )
    if not plan.plan_digest or payload.get("content_digest") != plan.plan_digest:
        return _conflict(
            "digest_mismatch",
            coordinates={"plan_id": plan_id},
            evidence={
                "content_digest": payload.get("content_digest"),
                "plan_digest": plan.plan_digest,
            },
        )

    try:
        request_id = UUID(str(payload["request_id"]))
        withdrawal_id = UUID(str(payload["withdrawal_id"]))
    except (KeyError, ValueError):
        return _conflict("missing_ids", coordinates={"plan_id": plan_id})

    if withdrawal_id != event.id:
        return _conflict(
            "withdrawal_id_mismatch",
            coordinates={"plan_id": plan_id, "approval_request_id": request_id},
            evidence={"withdrawal_id": str(withdrawal_id), "event_id": str(event.id)},
        )
    if (
        payload.get("policy_code") != plan.approval_policy_code
        or payload.get("policy_version") != plan.approval_policy_version
    ):
        return _conflict(
            "policy_mismatch",
            coordinates={"plan_id": plan_id, "approval_request_id": request_id},
        )
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return _conflict(
            "missing_reason",
            coordinates={"plan_id": plan_id, "approval_request_id": request_id},
        )

    coordinates: dict[str, object] = {
        "plan_id": plan_id,
        "approval_request_id": request_id,
        "withdrawal_ref": str(event.id),
    }

    pre_read = _revoked_pre_read(
        plan, plan_id=plan_id, request_id=request_id, event_id=event.id
    )
    if pre_read is not None:
        return pre_read

    if plan.status == "approved" and plan.approval_decision_ref != str(request_id):
        return ApprovalWithdrawalResult(
            disposition=WithdrawalDisposition.NOT_CARRIED,
            reason_code="decision_not_carried",
            coordinates=coordinates,
            evidence={"approval_decision_ref": plan.approval_decision_ref},
        )

    try:
        control.revoke_plan_approval(
            db,
            control.RevokePlanApprovalCommand(
                command_id=f"rehearsal-issuer:withdrawal:{event.id}",
                plan_id=plan_id,
                revocation_ref=f"approval.withdrawn:{event.id}",
                reason=reason,
            ),
        )
    except control.TransitionRefusedError:
        # The race: revoked between the pre-read above and this call. Re-read
        # and apply the same revoked rules against the now-current row.
        reread = cast(PlanFacts, control.get_plan(db, plan_id))
        raced = _revoked_pre_read(
            reread, plan_id=plan_id, request_id=request_id, event_id=event.id
        )
        if raced is not None:
            return raced
        return _conflict(
            "unexpected_plan_state",
            coordinates=coordinates,
            evidence={"status": reread.status},
        )
    except control.ExpectedStateError as exc:
        status = exc.actual_status
        if status == "cancelled":
            return ApprovalWithdrawalResult(
                disposition=WithdrawalDisposition.CANCELLED_BEFORE_EXECUTION,
                reason_code="cancelled_before_execution",
                coordinates=coordinates,
                evidence={"status": status},
            )
        if status == "proposed":
            return ApprovalWithdrawalResult(
                disposition=WithdrawalDisposition.NOT_CARRIED,
                reason_code="never_approved",
                coordinates=coordinates,
                evidence={"status": status},
            )
        if status == "superseded":
            return ApprovalWithdrawalResult(
                disposition=WithdrawalDisposition.NOT_CARRIED,
                reason_code="plan_superseded",
                coordinates=coordinates,
                evidence={"status": status},
            )
        return _conflict(
            "unexpected_plan_state",
            coordinates=coordinates,
            evidence={"status": status},
        )
    except OperationalError as exc:
        raise RetryableWithdrawal("database_unavailable") from exc

    return ApprovalWithdrawalResult(
        disposition=WithdrawalDisposition.APPLIED,
        reason_code="applied",
        coordinates=coordinates,
        evidence={},
    )
