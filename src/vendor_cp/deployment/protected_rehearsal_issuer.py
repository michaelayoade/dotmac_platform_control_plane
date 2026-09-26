"""Protected rehearsal-issuer composition, without a deployment rollout.

The approval transaction must commit before a different transaction calls
``issue_authorization``. Control owns plan standing and issuer issuance;
Approvals owns the decision and its durable withdrawal event. Imports of the
successor APIs remain inside functions until their exact wheels are published.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Final, Protocol, cast
from uuid import UUID

from dotmac_kernel.messaging import ClaimedPlatformEvent
from sqlalchemy.orm import Session

from vendor_cp.deployment.rehearsal_issuer_seam import RehearsalIssuerInvocation

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
    """Carry Approvals' genuine decision into Control, without a rollout."""
    control = import_module("dotmac_deployment_control")

    from vendor_cp.approvals.adapter import approved_request_evidence
    from vendor_cp.approvals_authority import bare_content_hash

    plan = _plan(db, plan_id)
    if not plan.plan_digest:
        raise ValueError("issuer plan has no frozen digest")
    evidence = approved_request_evidence(
        db,
        request_id=approval_request_id,
        subject_type=SUBJECT_TYPE,
        subject_id=_subject(plan),
        content_hash=bare_content_hash(plan.plan_digest),
    )
    return control.approve_plan(
        db,
        control.ApprovePlanCommand(
            command_id=command_id,
            plan_id=plan_id,
            evidence=control.ApprovalEvidence(
                policy_code=evidence.policy_code,
                policy_version=evidence.policy_version,
                decision_ref=str(evidence.request_id),
                content_digest=plan.plan_digest,
                decided_at=evidence.decided_at,
                approver_refs=evidence.approver_refs,
                decision_status="granted",
                operation=plan.operation,
                execution_plan_digest=plan.execution_plan_digest,
            ),
            expected_version=expected_plan_version,
            actor_ref=actor_ref,
        ),
    )


def issue_authorization(db: object, invocation: RehearsalIssuerInvocation) -> object:
    """Issue in a new transaction after the approval transaction has committed.

    The caller owns the commit. Control verifies standing and signed harness
    evidence before it writes the issuer authorization ledger.
    """
    control = import_module("dotmac_deployment_control")
    return control.issue_rehearsal_issuer_authorization_for_plan(
        db,
        dict(invocation.to_control_request()),
        harness_evidence_document=invocation.harness_evidence_document,
    )


def apply_approval_withdrawal(db: Session, event: ClaimedPlatformEvent) -> object:
    """Project a claimed Approvals outbox row in the kernel delivery transaction."""
    payload = event.payload
    if event.event_type != "approval.withdrawn" or payload.get("state") != "withdrawn":
        raise ValueError("expected an approval.withdrawn event")
    if payload.get("subject_type") != SUBJECT_TYPE:
        raise ValueError("withdrawal is for another subject type")
    try:
        subject_id = str(payload["subject_id"])
        version, plan_id_text, purpose, operation, digest = subject_id.split("|")
        if version != "v1" or purpose != PLAN_PURPOSE or operation != ISSUER_OPERATION:
            raise ValueError("unexpected issuer approval subject")
        plan_id = UUID(plan_id_text)
    except (KeyError, ValueError) as exc:
        raise ValueError("withdrawal has no canonical issuer approval subject") from exc
    plan = _plan(db, plan_id)
    if subject_id != _subject(plan) or digest != plan.execution_plan_digest:
        raise ValueError("withdrawal subject differs from the frozen plan")
    if not plan.plan_digest or payload.get("content_digest") != plan.plan_digest:
        raise ValueError("withdrawal digest differs from the frozen plan")
    try:
        request_id = UUID(str(payload["request_id"]))
        withdrawal_id = UUID(str(payload["withdrawal_id"]))
    except (KeyError, ValueError) as exc:
        raise ValueError("withdrawal lacks durable evidence ids") from exc
    if withdrawal_id != event.id:
        raise ValueError("withdrawal id differs from the claimed outbox row")
    if plan.approval_decision_ref != str(request_id):
        raise ValueError("withdrawal is for another approval decision")
    if (
        payload.get("policy_code") != plan.approval_policy_code
        or payload.get("policy_version") != plan.approval_policy_version
    ):
        raise ValueError("withdrawal policy differs from the frozen plan")
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("withdrawal has no reason")
    control = import_module("dotmac_deployment_control")
    return control.revoke_plan_approval(
        db,
        control.RevokePlanApprovalCommand(
            command_id=f"rehearsal-issuer:withdrawal:{event.id}",
            plan_id=plan_id,
            revocation_ref=f"approval.withdrawn:{event.id}",
            reason=reason,
        ),
    )


class ApprovalWithdrawalConsumer:
    """Relay transport for the Approvals event affecting issuer plan standing."""

    def deliver(self, event: ClaimedPlatformEvent, platform_db: Session) -> None:
        if event.event_type == "approval.withdrawn":
            if event.payload.get("subject_type") != SUBJECT_TYPE:
                return
            apply_approval_withdrawal(platform_db, event)
