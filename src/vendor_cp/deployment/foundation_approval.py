"""Foundation execution's Approvals subject and synchronous Control barriers.

Control owns the frozen plan and transitions; Approvals owns standing. Every
function uses the caller's transaction and never commits. The finalization
barrier is installed at startup into the import-light host adapter.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Final, TypeVar, cast
from uuid import UUID

from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from dotmac_deployment_control import (
        AuthorizationSigner,
        AuthorizationVerifier,
        DeliveryIntent,
        DispatchSigner,
        PlanView,
        RolloutView,
    )
    from dotmac_kernel.messaging import ClaimedPlatformEvent

    from vendor_cp.approvals.adapter import HeldPlatformApproval, RequestView
    from vendor_cp.relay.approval_router import ApprovalWithdrawalResult

PLAN_PURPOSE: Final = "foundation_execution"
SUBJECT_TYPE: Final = "foundation_execution_plan.v1"
T = TypeVar("T")


class FoundationApprovalUnavailable(ValueError):
    """The frozen Foundation plan cannot identify a real approval subject."""


def subject_id(plan: PlanView) -> str:
    from vendor_cp.approvals_authority import bare_content_hash

    if (
        not isinstance(plan.id, UUID)
        or plan.purpose != PLAN_PURPOSE
        or plan.operation not in {"deploy", "rollback"}
        or plan.requires_approval is not True
        or plan.execution_plan_digest is None
        or plan.plan_digest is None
        or not plan.approval_policy_code
        or plan.approval_policy_version is None
    ):
        raise FoundationApprovalUnavailable(
            "Foundation plan approval binding unavailable"
        )
    bare_content_hash(plan.execution_plan_digest)
    bare_content_hash(cast(str, plan.plan_digest))
    subject = (
        f"v1|{plan.id}|{plan.purpose}|{plan.operation}|{plan.execution_plan_digest}"
    )
    if len(subject) > 200:
        raise FoundationApprovalUnavailable("Foundation approval subject too long")
    return subject


def _plan(db: Session, plan_id: UUID) -> PlanView:
    from dotmac_deployment_control import get_plan

    plan = get_plan(db, plan_id)
    if plan is None:
        raise FoundationApprovalUnavailable("Foundation Control plan unavailable")
    subject_id(plan)
    return plan


def open_foundation_approval(
    db: Session,
    *,
    command_id: str,
    plan_id: UUID,
    requested_by: UUID,
) -> RequestView:
    from vendor_cp.approvals.adapter import OpenRequestCommand, open_request
    from vendor_cp.approvals_authority import bare_content_hash

    plan = _plan(db, plan_id)
    return open_request(
        db,
        OpenRequestCommand(
            command_id=command_id,
            policy_code=cast(str, plan.approval_policy_code),
            policy_version=cast(int, plan.approval_policy_version),
            subject_type=SUBJECT_TYPE,
            subject_id=subject_id(plan),
            content_hash=bare_content_hash(cast(str, plan.plan_digest)),
            requested_by=requested_by,
        ),
    )


def _same_binding(before: PlanView, after: PlanView) -> None:
    if (
        subject_id(before) != subject_id(after)
        or before.plan_digest != after.plan_digest
        or before.approval_policy_code != after.approval_policy_code
        or before.approval_policy_version != after.approval_policy_version
        or before.approval_decision_ref != after.approval_decision_ref
    ):
        raise FoundationApprovalUnavailable("Foundation approval binding changed")


def approve_foundation_plan(
    db: Session,
    *,
    command_id: str,
    plan_id: UUID,
    approval_request_id: UUID,
    expected_plan_version: int | None = None,
    actor_ref: str | None = None,
) -> PlanView:
    import dotmac_deployment_control as control

    from vendor_cp.deployment.approval_barrier import held_transition

    plan = _plan(db, plan_id)

    def transition(held: HeldPlatformApproval) -> PlanView:
        current = _plan(db, plan_id)
        _same_binding(plan, current)
        if (held.policy_code, held.policy_version) != (
            current.approval_policy_code,
            current.approval_policy_version,
        ):
            raise FoundationApprovalUnavailable("Foundation approval policy mismatch")
        return control.approve_plan(
            db,
            control.ApprovePlanCommand(
                command_id=command_id,
                plan_id=plan_id,
                evidence=control.ApprovalEvidence(
                    policy_code=held.policy_code,
                    policy_version=held.policy_version,
                    decision_ref=str(held.request_id),
                    content_digest=cast(str, current.plan_digest),
                    decided_at=held.decided_at,
                    approver_refs=(),
                    decision_status="granted",
                    operation=current.operation,
                    execution_plan_digest=current.execution_plan_digest,
                ),
                expected_version=expected_plan_version,
                actor_ref=actor_ref,
            ),
        )

    return held_transition(
        db,
        request_id=approval_request_id,
        subject_type=SUBJECT_TYPE,
        subject_id=subject_id(plan),
        content_digest=cast(str, plan.plan_digest),
        transition=transition,
    )


def hold_foundation_transition(
    db: Session,
    *,
    plan_id: UUID,
    transition: Callable[[HeldPlatformApproval], T],
) -> T:
    """Hold the carried decision before any Control lock, through caller commit."""
    from vendor_cp.deployment.approval_barrier import held_transition

    plan = _plan(db, plan_id)
    try:
        request_id = UUID(str(plan.approval_decision_ref))
    except ValueError as exc:
        raise FoundationApprovalUnavailable(
            "Foundation decision reference unavailable"
        ) from exc

    def checked(held: HeldPlatformApproval) -> T:
        current = _plan(db, plan_id)
        _same_binding(plan, current)
        if (held.policy_code, held.policy_version) != (
            current.approval_policy_code,
            current.approval_policy_version,
        ):
            raise FoundationApprovalUnavailable("Foundation approval policy mismatch")
        return transition(held)

    return held_transition(
        db,
        request_id=request_id,
        subject_type=SUBJECT_TYPE,
        subject_id=subject_id(plan),
        content_digest=cast(str, plan.plan_digest),
        transition=checked,
    )


def request_foundation_rollout(
    db: Session,
    *,
    command_id: str,
    rollout_ref: str,
    plan_id: UUID,
    authorization_expires_at: datetime,
    signer: AuthorizationSigner,
    reason: str | None = None,
    actor_ref: str | None = None,
) -> RolloutView:
    import dotmac_deployment_control as control

    def transition(held: HeldPlatformApproval) -> RolloutView:
        return control.request_rollout(
            db,
            control.RequestRolloutCommand(
                command_id=command_id,
                rollout_ref=rollout_ref,
                plan_id=plan_id,
                authorization_expires_at=authorization_expires_at,
                reason=reason,
                actor_ref=actor_ref,
            ),
            signer=signer,
        )

    # The common wrapper validates the immutable tuple again inside the hold.
    held_transition = hold_foundation_transition
    return held_transition(db, plan_id=plan_id, transition=transition)


def dispatch_foundation_attempt(
    db: Session,
    *,
    command_id: str,
    rollout_id: UUID,
    verifier: AuthorizationVerifier,
    dispatch_signer: DispatchSigner,
    actor_ref: str | None = None,
) -> DeliveryIntent:
    import dotmac_deployment_control as control

    rollout = control.get_rollout(db, rollout_id)
    if rollout is None:
        raise FoundationApprovalUnavailable("Foundation rollout unavailable")

    def transition(held: HeldPlatformApproval) -> DeliveryIntent:
        current = control.get_rollout(db, rollout_id)
        if current is None or current.plan_id != rollout.plan_id:
            raise FoundationApprovalUnavailable("Foundation rollout binding changed")
        return control.dispatch_attempt(
            db,
            command_id=command_id,
            rollout_id=rollout_id,
            verifier=verifier,
            dispatch_signer=dispatch_signer,
            actor_ref=actor_ref,
        )

    held_transition = hold_foundation_transition
    return held_transition(db, plan_id=rollout.plan_id, transition=transition)


def classify_foundation_approval_withdrawal(
    db: Session,
    event: ClaimedPlatformEvent,
) -> ApprovalWithdrawalResult:
    """Converge withdrawal through Control; router owns append-only outcomes.

    A WITHDRAWN refusal from the synchronous seam proves the subject/digest
    under Approvals' shared row lock. No Control write precedes that lock.
    """
    import dotmac_deployment_control as control

    from vendor_cp.approvals.adapter import ApprovalHoldRefusal, ApprovalNotHeld
    from vendor_cp.deployment.approval_barrier import held_transition
    from vendor_cp.relay.approval_router import ApprovalWithdrawalResult
    from vendor_cp.relay.withdrawal_outcomes import WithdrawalDisposition as D

    def result(
        disposition: D, reason: str, **evidence: object
    ) -> ApprovalWithdrawalResult:
        return ApprovalWithdrawalResult(disposition, reason, coordinates, evidence)

    coordinates: dict[str, object] = {}
    payload = event.payload
    try:
        version, plan_text, purpose, operation, digest = str(
            payload["subject_id"]
        ).split("|")
        plan_id = UUID(plan_text)
        request_id = UUID(str(payload["request_id"]))
        withdrawal_id = UUID(str(payload["withdrawal_id"]))
    except (KeyError, ValueError):
        return result(D.SECURITY_CONFLICT, "malformed_subject")
    coordinates.update(
        plan_id=plan_id, approval_request_id=request_id, withdrawal_ref=str(event.id)
    )
    if payload.get("subject_type") != SUBJECT_TYPE or withdrawal_id != event.id:
        return result(D.SECURITY_CONFLICT, "withdrawal_coordinate_mismatch")
    try:
        plan = _plan(db, plan_id)
    except FoundationApprovalUnavailable:
        return result(D.SECURITY_CONFLICT, "plan_binding_unavailable")
    if (
        version != "v1"
        or purpose != PLAN_PURPOSE
        or operation != plan.operation
        or digest != plan.execution_plan_digest
        or payload["subject_id"] != subject_id(plan)
        or payload.get("content_digest") != plan.plan_digest
        or payload.get("policy_code") != plan.approval_policy_code
        or payload.get("policy_version") != plan.approval_policy_version
    ):
        return result(D.SECURITY_CONFLICT, "withdrawal_binding_mismatch")
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return result(D.SECURITY_CONFLICT, "missing_reason")

    def still_approved(held: HeldPlatformApproval) -> None:
        raise FoundationApprovalUnavailable("withdrawal request still stands approved")

    try:
        held_transition(
            db,
            request_id=request_id,
            subject_type=SUBJECT_TYPE,
            subject_id=subject_id(plan),
            content_digest=cast(str, plan.plan_digest),
            transition=still_approved,
        )
    except ApprovalNotHeld as exc:
        if exc.code is not ApprovalHoldRefusal.WITHDRAWN:
            return result(D.SECURITY_CONFLICT, "withdrawal_not_established")
    except FoundationApprovalUnavailable:
        return result(D.SECURITY_CONFLICT, "withdrawal_not_established")

    # The request is permanently withdrawn and locked; it cannot be carried
    # by a concurrent approval. Re-read current owner state after that proof.
    current = _plan(db, plan_id)
    if current.approval_decision_ref != str(request_id):
        return result(
            D.NOT_CARRIED,
            "decision_not_carried",
            approval_decision_ref=current.approval_decision_ref,
        )
    own_ref = f"approval.withdrawn:{event.id}"

    def standing_result(current: PlanView) -> ApprovalWithdrawalResult | None:
        if current.approval_decision_status == "revoked":
            same = current.approval_revocation_ref == own_ref
            return result(
                D.ALREADY_APPLIED if same else D.SUPERSEDED_BY_REVOCATION,
                "already_applied" if same else "superseded_by_revocation",
                approval_revocation_ref=current.approval_revocation_ref,
            )
        if current.status == "cancelled":
            return result(D.CANCELLED_BEFORE_EXECUTION, "cancelled_before_execution")
        if current.status == "superseded":
            return result(D.NOT_CARRIED, "plan_superseded")
        return None

    classified = standing_result(current)
    if classified is not None:
        return classified
    actor_id = payload.get("actor_id")
    actor_ref = str(actor_id) if actor_id is not None else None
    try:
        control.revoke_plan_approval(
            db,
            control.RevokePlanApprovalCommand(
                command_id=f"foundation-execution:withdrawal:{event.id}",
                plan_id=plan_id,
                revocation_ref=own_ref,
                reason=reason,
                actor_ref=actor_ref,
            ),
        )
    except (control.TransitionRefusedError, control.ExpectedStateError):
        classified = standing_result(_plan(db, plan_id))
        if classified is not None:
            return classified
        return result(D.SECURITY_CONFLICT, "unexpected_plan_state")
    return result(D.APPLIED, "applied", authority_ref=payload.get("authority_ref"))
