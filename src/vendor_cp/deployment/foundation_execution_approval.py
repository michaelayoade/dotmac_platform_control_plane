"""CP's source-only Foundation execution approval composition.

Approvals owns standing; Control owns the frozen plan and all transitions.
Every consuming transition keeps Approvals' hold through the caller's commit.
Nothing here installs a CLI/provider or authorizes a live execution.

Each lifecycle stage uses its own caller-owned transaction. Commit or roll
back proposal/approval/rollout before entering the next stage: a transaction
already holding Control locks must never acquire a later Approvals hold.
Approvals has no TTL; authorization expiry remains Control's separate check.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from importlib import import_module
from typing import TYPE_CHECKING, Protocol, cast
from uuid import UUID

from sqlalchemy.orm import Session

from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.deployment.approval_barrier import held_transition

if TYPE_CHECKING:
    from vendor_cp.approvals.adapter import HeldPlatformApproval
    from vendor_cp.deployment.host_admission_adapter import (
        FoundationHostV3Bindings,
        FoundationV3ProviderPair,
        FoundationV3Sources,
    )

SUBJECT_TYPE = "foundation_execution_plan.v1"
PLAN_PURPOSE = "foundation_execution"


class PlanFacts(Protocol):
    id: UUID
    purpose: str
    operation: str | None
    execution_plan_digest: str | None
    plan_digest: str | None
    requires_approval: bool
    approval_policy_code: str | None
    approval_policy_version: int | None
    approval_decision_ref: str | None


class ExecutionContext(Protocol):
    plan_id: str


class ExecutionRequest(Protocol):
    expected_context: ExecutionContext


def foundation_approval_subject(plan: PlanFacts) -> str:
    """Versioned owner subject, separate from Control's content digest."""
    if not isinstance(plan.id, UUID) or plan.purpose != PLAN_PURPOSE:
        raise ValueError("expected a Foundation execution Control plan")
    if plan.operation not in {"deploy", "rollback"}:
        raise ValueError("Foundation plan lacks an explicit operation")
    bare_content_hash(plan.execution_plan_digest or "")
    bare_content_hash(plan.plan_digest or "")
    if plan.requires_approval is not True:
        raise ValueError("Foundation execution composition requires approval")
    if not plan.approval_policy_code or plan.approval_policy_version is None:
        raise ValueError("Foundation plan lacks an approval policy")
    subject = (
        f"v1|{plan.id}|{plan.purpose}|{plan.operation}|{plan.execution_plan_digest}"
    )
    if len(subject) > 200:
        raise ValueError("Foundation approval subject exceeds owner limit")
    return subject


def _plan(db: Session, plan_id: UUID) -> PlanFacts:
    plan = import_module("dotmac_deployment_control").get_plan(db, plan_id)
    if plan is None:
        raise ValueError("Foundation Control plan does not exist")
    foundation_approval_subject(plan)
    return cast(PlanFacts, plan)


@dataclass(frozen=True, slots=True)
class ProposeFoundationPlan:
    command_id: str
    target_id: UUID
    operation: str
    descriptor_digest: str
    execution_plan_digest: str
    approval_policy_code: str
    approval_policy_version: int
    expected_desired_revision: int | None = None
    actor_ref: str | None = None


def propose_foundation_plan(db: Session, request: ProposeFoundationPlan) -> object:
    """Freeze the Foundation-rendered binding using Control's public owner."""
    control = import_module("dotmac_deployment_control")
    if request.operation not in {"deploy", "rollback"}:
        raise ValueError("unsupported Foundation execution operation")
    bare_content_hash(request.execution_plan_digest)
    plan = control.propose_plan(
        db,
        control.ProposePlanCommand(
            command_id=request.command_id,
            target_id=request.target_id,
            operation=request.operation,
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
    foundation_approval_subject(plan)
    if (
        plan.target_id != request.target_id
        or plan.operation != request.operation
        or plan.execution_plan_digest != request.execution_plan_digest
        or plan.descriptor_digest != request.descriptor_digest
        or plan.approval_policy_code != request.approval_policy_code
        or plan.approval_policy_version != request.approval_policy_version
    ):
        raise ValueError("proposal command replay differs from the requested plan")
    return plan


def open_foundation_approval(
    db: Session, *, command_id: str, plan_id: UUID, requested_by: UUID
) -> object:
    from vendor_cp.approvals.adapter import OpenRequestCommand, open_request

    plan = _plan(db, plan_id)
    return open_request(
        db,
        OpenRequestCommand(
            command_id=command_id,
            policy_code=cast(str, plan.approval_policy_code),
            policy_version=cast(int, plan.approval_policy_version),
            subject_type=SUBJECT_TYPE,
            subject_id=foundation_approval_subject(plan),
            content_hash=bare_content_hash(plan.plan_digest or ""),
            requested_by=requested_by,
        ),
    )


def _check_binding(plan: PlanFacts, held: HeldPlatformApproval) -> None:
    if (
        plan.approval_policy_code != held.policy_code
        or plan.approval_policy_version != held.policy_version
    ):
        raise ValueError("held approval policy differs from frozen Control policy")


def approve_foundation_plan(
    db: Session, *, command_id: str, plan_id: UUID, approval_request_id: UUID
) -> object:
    control = import_module("dotmac_deployment_control")
    plan = _plan(db, plan_id)

    def transition(held: HeldPlatformApproval) -> object:
        _check_binding(plan, held)
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
                    approver_refs=tuple(str(actor) for actor in held.approver_ids),
                    decision_status="granted",
                    operation=plan.operation,
                    execution_plan_digest=plan.execution_plan_digest,
                ),
            ),
        )
        if (
            result.id != plan_id
            or result.approval_decision_ref != str(held.request_id)
            or result.plan_digest != plan.plan_digest
        ):
            raise ValueError("approval command replay differs from the held plan")
        return result

    return held_transition(
        db,
        request_id=approval_request_id,
        subject_type=SUBJECT_TYPE,
        subject_id=foundation_approval_subject(plan),
        content_digest=cast(str, plan.plan_digest),
        transition=transition,
    )


def _request_id(plan: PlanFacts) -> UUID:
    try:
        return UUID(plan.approval_decision_ref or "")
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("Foundation plan lacks a genuine approval request") from exc


def request_foundation_rollout(
    db: Session,
    *,
    command_id: str,
    plan_id: UUID,
    rollout_ref: str,
    authorization_expires_at: datetime,
    signer: object,
) -> object:
    control = import_module("dotmac_deployment_control")
    plan = _plan(db, plan_id)
    request_id = _request_id(plan)

    def transition(held: HeldPlatformApproval) -> object:
        _check_binding(plan, held)
        result = control.request_rollout(
            db,
            control.RequestRolloutCommand(
                command_id=command_id,
                plan_id=plan_id,
                rollout_ref=rollout_ref,
                authorization_expires_at=authorization_expires_at,
            ),
            signer=signer,
        )
        if result.plan_id != plan_id or result.rollout_ref != rollout_ref:
            raise ValueError("rollout command replay differs from the held plan")
        return result

    return held_transition(
        db,
        request_id=request_id,
        subject_type=SUBJECT_TYPE,
        subject_id=foundation_approval_subject(plan),
        content_digest=cast(str, plan.plan_digest),
        transition=transition,
    )


def dispatch_foundation_attempt(
    db: Session,
    *,
    command_id: str,
    rollout_id: UUID,
    verifier: object,
    dispatch_signer: object,
) -> object:
    """Stage Control's dispatch under the approval bound to its rollout plan."""
    control = import_module("dotmac_deployment_control")
    rollout = control.get_rollout(db, rollout_id)
    if rollout is None:
        raise ValueError("Foundation rollout does not exist")
    plan = _plan(db, rollout.plan_id)

    def transition(held: HeldPlatformApproval) -> object:
        _check_binding(plan, held)
        return control.dispatch_attempt(
            db,
            command_id=command_id,
            rollout_id=rollout_id,
            verifier=verifier,
            dispatch_signer=dispatch_signer,
        )

    return held_transition(
        db,
        request_id=_request_id(plan),
        subject_type=SUBJECT_TYPE,
        subject_id=foundation_approval_subject(plan),
        content_digest=cast(str, plan.plan_digest),
        transition=transition,
    )


def finalize_foundation_dispatch(
    db: Session,
    *,
    context: object,
    foreign_evidence: object,
    execution: ExecutionRequest,
) -> object:
    """Startup-bound finalizer; no caller assertion is approval authority.

    Unlocked public pre-read precedes the hold. Control rechecks the complete
    execution coordinate under its target -> plan -> rollout locks. The hold
    remains in this same Session through the provider's single commit.
    """
    control = import_module("dotmac_deployment_control")
    plan = _plan(db, UUID(str(execution.expected_context.plan_id)))
    request_id = _request_id(plan)

    def transition(held: HeldPlatformApproval) -> object:
        _check_binding(plan, held)
        return control.admit_and_consume_host_admission(
            db, context=context, foreign_evidence=foreign_evidence, execution=execution
        )

    return held_transition(
        db,
        request_id=request_id,
        subject_type=SUBJECT_TYPE,
        subject_id=foundation_approval_subject(plan),
        content_digest=cast(str, plan.plan_digest),
        transition=transition,
    )


def compose_approved_foundation_v3_providers(
    *, foundation: FoundationHostV3Bindings, sources: FoundationV3Sources
) -> FoundationV3ProviderPair:
    """Source-only startup factory; neither request nor caller selects Control.

    Protected startup composes these source objects. This callable does not
    install a provider, enable RecoveryExecutor or activate a runtime lane.
    """
    from vendor_cp.deployment.host_admission_adapter import (
        ControlFoundationV3Bindings,
        _compose_approval_guarded_providers,
    )

    control = import_module("dotmac_deployment_control")
    return _compose_approval_guarded_providers(
        control=ControlFoundationV3Bindings(
            resolve_context=control.resolve_host_admission_context,
            finalize=finalize_foundation_dispatch,
            attest_pair=control.attest_foundation_execution_pair,
            lookup_committed=control.lookup_foundation_execution_consumption,
            get_plan=control.get_plan,
            foreign_root_type=control.HostAdmissionForeignRootV1,
            foreign_evidence_type=control.HostAdmissionForeignVerificationEvidenceV1,
            execution_context_type=control.FoundationExecutionContextV1,
            consumption_request_type=control.FoundationDispatchConsumptionV1,
        ),
        foundation=foundation,
        sources=sources,
        held_finalizer=finalize_foundation_dispatch,
    )
