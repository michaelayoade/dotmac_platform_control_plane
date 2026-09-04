"""The ONE seam between this assembly and `dotmac-deployment-control`.

Typed, no `Any`. It resolves a deployment target from the module and converts
it into the narrow set of facts Vendor's delivery projection is allowed to hold,
and it presents the module's own commands to an operator. Registering a target,
setting desired state, proposing, approving and requesting a rollout remain the
MODULE's commands throughout: this file builds their arguments and carries their
answers back, and decides none of them.

## Why this type exists at all

`reconcile_delivery_target` could have taken `target_ref` and `customer_ref` as
strings. Then any caller could supply them, and the projection would be
independently registered again the moment somebody added a route — which is the
exact regression ADR-0011 exists to end. `DeploymentTargetFacts` can only be
constructed here, from a `TargetView` the module returned, so the projection's
values have a provenance the type system carries.

That is the whole enforcement mechanism, and it is weaker than a database grant.
ADR-0011 § 4 says so plainly: `platform_api` keeps `INSERT`/`UPDATE` on
`licence_delivery_targets` because the reconciler needs them, so what stops an
independent write is this seam plus an architecture ratchet, not a privilege.
Only `DELETE` is revoked — a projection is rebuilt, never deleted.

## Status mapping, and the one that fails closed

`REGISTERED` means the module knows the target and it has no desired state yet.
It maps to Vendor `SUSPENDED`, not `ACTIVE`: a target that is not converging on
anything must not receive a licence, and mapping "known" onto "eligible" would
be exactly the registration-is-authorisation confusion `_authorised_target` was
written to refuse.

## The operator workflow (ADR-0013), added below

This seam was read-only until ADR-0013, and the docstring that said so named
the reason: Vendor had no operator surface for the module's own commands, so no
authorization receipt could be produced anywhere in the fleet. ADR-0013 fixes
that here, and fixes it as a WORKFLOW rather than as an owner. What this file is
permitted to do is ADR § 2's list, as amended by A6. The original items keep
their numbers — a renumbering would make every citation of "§ 2 item 2" point
somewhere else — and the two A6 added come first in the operator's order because
they bring the SUBJECT of an authorization into existence:

- **A6 item 1** — call `register_target`, which names a destination this plane
  is responsible for;
- **A6 item 2** — call `set_desired_state`, which declares what that destination
  should converge on;
- **§ 2 item 1** — call `propose_plan`, which freezes a snapshot and computes
  its digest;
- **§ 2 item 2** — carry an `ApprovalEvidence` produced by `dotmac-approvals`
  into `approve_plan`;
- **§ 2 item 3** — call `request_rollout`;
- **§ 2 item 4** — read `get_plan` / `get_rollout` / `get_target` / `drift` for
  display.

§ 2's four could only ever act on a target somebody else had already created,
and nobody else was ever going to: `propose_plan` freezes A TARGET's desired
state, so with no way to register one there was nothing to freeze and
`authorize_deployment` had no reachable path to a plan.

The A6 items mutate `mod_deploy` and are still not decisions taken here: the
module owns idempotency on `target_ref`, the desired-revision bump, the
`REGISTERED` -> `ACTIVE` promotion and the refusal to declare a desired state
for a decommissioned target. This file re-implements none of the four.

What a plan contains, whether a transition is legal, whether the evidence binds,
what the receipt says and how drift is judged all stay upstream. **The test of a
design error is ADR § 2's:** if a change here would require this assembly to
decide *how a target is changed*, the change belongs in the module.

Two consequences of that rule are easy to get wrong and are therefore stated:

**Digests are carried, never normalized.** Deployment Control's own parser warns
that "a consumer that normalizes has forked this parser, and the fork surfaces
as a false 'the plan changed'". So the value handed back to `approve_plan` is
the module's own frozen string, byte for byte. The only translation performed is
into the APPROVALS module's vocabulary, through the declared
`vendor_cp.approvals_authority.bare_content_hash`, and its result never travels
back the other way.

**No `approved_by`.** `ApprovalEvidence.approver_refs` stays empty. Approver
identity lives once, in `dotmac-approvals`, reachable through `decision_ref`; a
name copied alongside a reference is a second copy of an identity that can drift
from the decision it claims to describe.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final
from uuid import UUID

from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    DesiredDeployment,
    PlanView,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RolloutView,
    SetDesiredStateCommand,
    TargetView,
    approve_plan,
    drift,
    get_plan,
    get_rollout,
    get_target,
    propose_plan,
    register_target,
    request_rollout,
    set_desired_state,
)
from dotmac_deployment_control import DriftReport as ModuleDriftReport
from dotmac_deployment_control import TargetStatus as ModuleTargetStatus
from dotmac_kernel import NotFoundError
from sqlalchemy.orm import Session

from vendor_cp.approvals.adapter import approved_request_evidence
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.identity import (
    AUTHORITY_DISTRIBUTION,
    DISTRIBUTION,
    authority_version,
    require_version,
)
from vendor_cp.licensing.delivery_models import TargetStatus

#: Module standing -> delivery eligibility. Total over the module's enum: a new
#: member added upstream fails the lookup rather than defaulting to eligible.
_STATUS: dict[str, TargetStatus] = {
    ModuleTargetStatus.ACTIVE.value: TargetStatus.ACTIVE,
    ModuleTargetStatus.SUSPENDED.value: TargetStatus.SUSPENDED,
    ModuleTargetStatus.DECOMMISSIONED.value: TargetStatus.RETIRED,
    ModuleTargetStatus.REGISTERED.value: TargetStatus.SUSPENDED,
}


@dataclass(frozen=True)
class DeploymentTargetFacts:
    """What the delivery projection may hold about a deployment target.

    Constructible only by `resolve_target` below. Four fields, and the absence
    of a fifth is deliberate: `connection_ref` is transport metadata the module
    does not own and must not invent, so a reconciled row carries `None` there
    until ADR-0010 moves delivery to the Integrator and the column goes with it.
    """

    target_id: UUID
    target_ref: str
    customer_ref: str
    status: TargetStatus


def resolve_target(db: Session, target_id: UUID) -> DeploymentTargetFacts:
    """Read the authoritative deployment target, or refuse.

    `NotFoundError` rather than a silent `None`: a caller asking to reconcile a
    target the fleet owner has never heard of is asking for a destination to be
    invented, which is what this cutover removes.
    """
    view = get_target(db, target_id)
    if view is None:
        raise NotFoundError(
            f"deployment target {target_id} is not registered in mod_deploy — "
            "a delivery destination is reconciled from the fleet owner, never "
            "registered independently"
        )
    status = _STATUS.get(view.status)
    if status is None:
        raise NotFoundError(
            f"deployment target {view.target_ref!r} has standing "
            f"{view.status!r}, which this assembly has no delivery mapping "
            "for — refusing rather than assuming it may receive a licence"
        )
    return DeploymentTargetFacts(
        target_id=view.id,
        target_ref=view.target_ref,
        customer_ref=view.subject_ref,
        status=status,
    )


# ── The operator workflow (ADR-0013) ────────────────────────────────────────

#: What an approval request over a deployment plan is ABOUT, in the approvals
#: module's subject vocabulary. One constant, because the value is written when
#: the request is opened and re-checked when the evidence is carried, and two
#: spellings of it would make the second check pass for the wrong reason.
PLAN_SUBJECT_TYPE: Final[str] = "deployment_plan"


class DeploymentIdentityMismatch(ValueError):
    """The caller bound this authorization to something the module did not freeze.

    Deliberately not a refusal by the owner. The module was never asked: the
    assembly compared what the operator asserted against what the plan actually
    holds and stopped first. Keeping that distinct is the same lesson
    `0.1.0a4` taught from the other side — a mismatch reported as a policy
    refusal sends the wrong person to investigate.
    """


@dataclass(frozen=True, slots=True)
class ProposePlanRequest:
    """Freeze a target's current desired state under a named approval policy."""

    command_id: str
    target_id: UUID
    approval_policy_code: str
    approval_policy_version: int
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ProposedPlan:
    """A frozen plan, plus the one derived value the approvals seam needs.

    `plan_digest` is the module's own canonical string, untouched.
    `approval_content_hash` is the same digest in the bare-hex form
    `dotmac-approvals` speaks, derived through the declared translation and used
    for nothing else. Both are present because a caller needs the first to
    approve the plan and the second to open the request, and computing either
    from the other at the call site is how a fork of the parser starts.
    """

    plan_id: UUID
    target_id: UUID
    sequence: int
    status: str
    desired_revision: int
    record_version: int
    plan_digest: str
    approval_content_hash: str
    approval_policy_code: str
    approval_policy_version: int
    subject_type: str = PLAN_SUBJECT_TYPE


@dataclass(frozen=True, slots=True)
class AuthorizeRequest:
    """Carry an approvals decision into a frozen plan, then request its rollout."""

    command_id: str
    plan_id: UUID
    approval_request_id: UUID
    rollout_ref: str
    reason: str | None = None
    actor_ref: str | None = None
    #: Optional integrity binding. When present it is compared BYTE FOR BYTE
    #: against the module's frozen digest, and a difference stops the command
    #: before the module is asked anything.
    expected_plan_digest: str | None = None
    expected_plan_version: int | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationReceipt:
    """What one authorization bound, as the issuer observed it.

    `authorization_ref` is the rollout id. It is the fleet's authorization run
    identity: the middle term a deployment foundation binds between the
    canonical descriptor and its own execution report, and the reason this
    command exists at all.

    Every version here is read from INSTALLED DISTRIBUTION METADATA. The
    published `dotmac-deployment-control 0.1.0a4` carried
    `__version__ = "0.1.0a2"`, so a fingerprint taken from a module attribute
    would have written the wrong authority version into the receipt that exists
    to make the authorization auditable.
    """

    authorization_ref: str
    rollout_id: UUID
    rollout_ref: str
    rollout_status: str
    plan_id: UUID
    plan_digest: str
    plan_status: str
    target_id: UUID
    desired_revision: int
    approval_policy_code: str
    approval_policy_version: int
    approval_decision_ref: str
    approved_at: datetime
    issuer: str
    issuer_version: str
    authority: str
    authority_version: str


def read_target(db: Session, target_id: UUID) -> TargetView:
    """The module's own view of a target, for display."""
    view = get_target(db, target_id)
    if view is None:
        raise NotFoundError(f"deployment target {target_id} is not registered")
    return view


def read_plan(db: Session, plan_id: UUID) -> PlanView:
    """The module's own view of a plan and its approval standing."""
    view = get_plan(db, plan_id)
    if view is None:
        raise NotFoundError(f"deployment plan {plan_id} does not exist")
    return view


def read_rollout(db: Session, rollout_id: UUID) -> RolloutView:
    """The module's own view of a rollout and every attempt at it."""
    view = get_rollout(db, rollout_id)
    if view is None:
        raise NotFoundError(f"rollout {rollout_id} does not exist")
    return view


def read_drift(db: Session, target_id: UUID) -> ModuleDriftReport:
    """The module's computed difference between rolled-out and observed state.

    `None` from the module means one thing and one thing only: **the target row
    does not exist**. Verified against the pinned owner rather than inferred —
    `drift()` returns `None` on `db.get(DeploymentTarget, target_id) is None`
    and on nothing else.

    ## What this docstring used to claim, and why it was wrong

    It said a `None` meant "the target has no rollout to compare against", and
    refused with a message saying so. That condition never fires. A target with
    no successful rollout gets a real `DriftReport` whose
    `rolled_out_release_ref` and `rolled_out_revision` are `None` — so the only
    caller who ever saw that refusal was one naming a target that had been
    deleted or never registered, and they were told something else entirely.

    The underlying worry was legitimate: a caller must not read "no drift" off a
    target nothing has ever deployed to. But the owner already answers it, and
    answers it better than an exception could. `DriftReport.drifted` is `False`
    when `rolled_out_revision is None` — its own docstring says *"Silence is not
    drift"* — and `never_observed` is kept deliberately separate from `drifted`,
    because a target that has never reported is unknown rather than wrong.

    So the interpretation is DROPPED rather than restated. This adapter refuses
    the condition the owner actually signals and assigns no meaning the owner
    did not; a caller distinguishing "deployed and matching" from "nothing
    rolled out yet" reads `rolled_out_revision` and `never_observed`, which are
    the owner's words for it.
    """
    report = drift(db, target_id)
    if report is None:
        raise NotFoundError(f"deployment target {target_id} does not exist")
    return report


# ── The target's own lifecycle (ADR-0013 amendment A6) ──────────────────────


@dataclass(frozen=True, slots=True)
class TargetRegistrationRequest:
    """Name a deployment this control plane becomes responsible for.

    Five facts, and every one of them is the operator's own statement about a
    destination that already exists in the world. Nothing is derived here: a
    `target_ref` this assembly invented would be a destination nobody agreed to,
    which is the failure the read seam above refuses from the other end. (Named
    by description rather than by symbol on purpose — the reconciliation ratchet
    counts occurrences, and raising a call-site count for a docstring would
    leave room for a real new caller underneath it.)
    """

    command_id: str
    target_ref: str
    subject_ref: str
    product_code: str
    environment: str
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class DesiredStateRequest:
    """Declare what an already-registered target should converge on.

    `spec` is opaque here for the same reason it is opaque upstream: reading it
    would make this assembly a second authority on what a deployment IS, which
    belongs to the product's deployment profile. It is carried as the operator
    wrote it and frozen, unread, into the plan digest.

    `DesiredDeployment` has a fourth field this request deliberately does NOT
    carry: the brand-profile reference. Brand Profiles is deferred here by
    ADR-0007 § 6, this assembly composes no brand module and holds no brand
    record — measured, and ratcheted at zero — so an operator flag naming one
    would be a surface for something that is not composed. It stays at the
    module's own default until the deferral lifts.
    """

    command_id: str
    target_id: UUID
    release_ref: str
    spec: Mapping[str, object] = field(default_factory=dict)
    licence_ref: str | None = None
    #: Optional optimistic-concurrency binding, compared upstream against the
    #: target's `record_version`. A mismatch is the MODULE's refusal, not ours.
    expected_version: int | None = None
    actor_ref: str | None = None


def register_deployment_target(
    db: Session, request: TargetRegistrationRequest
) -> TargetView:
    """Ask the module to record a target. ADR-0013 A6 item 1.

    The module's own view is returned unchanged, and it deliberately carries no
    created-versus-already-present flag. `register_target` is idempotent on
    `target_ref`: a second call with the same reference returns the existing
    target. This assembly could compare the returned id against something it
    remembered and report "created", but that comparison would be a claim the
    owner never made, and a retry of a command whose first attempt succeeded
    would then print a different answer for an identical outcome.

    A registered target is NOT an authorized one. It has no desired state yet,
    which is why `_STATUS` above maps `REGISTERED` onto Vendor `SUSPENDED` —
    registration-is-authorisation is the exact confusion that mapping refuses,
    and the same refusal has to hold at the end that CREATES the registration.
    """
    return register_target(
        db,
        RegisterTargetCommand(
            command_id=request.command_id,
            target_ref=request.target_ref,
            subject_ref=request.subject_ref,
            product_code=request.product_code,
            environment=request.environment,
            actor_ref=request.actor_ref,
        ),
    )


def set_target_desired_state(db: Session, request: DesiredStateRequest) -> TargetView:
    """Declare what the target should converge on. ADR-0013 A6 item 2.

    Every consequence of this call is the module's. It bumps `desired_revision`
    unconditionally — even when the values are unchanged — because the revision
    records that a DECISION was taken; it promotes a `REGISTERED` target to
    `ACTIVE`; and it refuses a decommissioned one. None of those three is
    re-implemented, re-checked or reported differently here, because a second
    copy of any of them would eventually disagree with the first.

    In particular there is no local "has anything actually changed?" comparison.
    That is the seductive one — it looks like an optimisation and it is a
    second answer to whether a plan is worth proposing, which is upstream's.
    """
    return set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=request.command_id,
            target_id=request.target_id,
            desired=DesiredDeployment(
                release_ref=request.release_ref,
                spec=dict(request.spec),
                licence_ref=request.licence_ref,
                # No brand reference: see `DesiredStateRequest` above.
            ),
            expected_version=request.expected_version,
            actor_ref=request.actor_ref,
        ),
    )


def propose_deployment_plan(db: Session, request: ProposePlanRequest) -> ProposedPlan:
    """Ask the module to freeze the target's desired state. ADR-0013 § 2 item 1.

    `requires_approval` is hard-wired to `True`. It is a parameter upstream, and
    a flag here that could turn it off would be this assembly deciding an
    authorization is unnecessary — a policy decision, and the exact one the
    issuer must never own.
    """
    view = propose_plan(
        db,
        ProposePlanCommand(
            command_id=request.command_id,
            target_id=request.target_id,
            requires_approval=True,
            approval_policy_code=request.approval_policy_code,
            approval_policy_version=request.approval_policy_version,
            actor_ref=request.actor_ref,
        ),
    )
    digest = view.plan_digest
    if not digest:
        raise NotFoundError(
            f"deployment plan {view.id} was proposed without a frozen digest, so "
            "there is nothing an approval could bind to"
        )
    return ProposedPlan(
        plan_id=view.id,
        target_id=view.target_id,
        sequence=view.sequence,
        status=view.status,
        desired_revision=view.desired_revision,
        record_version=view.record_version,
        plan_digest=digest,
        approval_content_hash=bare_content_hash(digest),
        approval_policy_code=view.approval_policy_code or "",
        approval_policy_version=view.approval_policy_version or 0,
    )


def authorize_deployment(
    db: Session, request: AuthorizeRequest
) -> AuthorizationReceipt:
    """Approve a frozen plan on carried evidence, then request its rollout.

    ADR-0013 § 2 items 2 and 3, in one operator step because they are one
    operator intent: *this approved plan may now be deployed*. Splitting them
    would leave an approved plan with no rollout as a routine state, which is a
    deployment somebody believes is authorized and nothing is executing.

    ## Two derived command ids, and why they are not one

    `process_once_platform` keys at-most-once execution on the command id alone
    — `operation_name` is recorded, not part of the key. Passing the operator's
    id to both steps would make the second REPLAY the first's recorded result
    and never run, so the rollout would silently not happen and the command
    would report success. The derived suffixes keep both steps idempotent under
    the operator's single id, which is what a retry of this command needs.
    """
    plan = read_plan(db, request.plan_id)
    frozen = plan.plan_digest
    if not frozen:
        raise NotFoundError(
            f"deployment plan {plan.id} has no frozen digest; propose it before "
            "authorizing it"
        )
    if request.expected_plan_digest and request.expected_plan_digest != frozen:
        raise DeploymentIdentityMismatch(
            f"this authorization was bound to plan digest "
            f"{request.expected_plan_digest!r}, and plan {plan.id} holds "
            f"{frozen!r}. No approval was carried and the module was not asked: "
            "confirm which plan you meant."
        )

    evidence = approved_request_evidence(
        db,
        request_id=request.approval_request_id,
        subject_type=PLAN_SUBJECT_TYPE,
        subject_id=str(plan.id),
        content_hash=bare_content_hash(frozen),
    )

    approved = approve_plan(
        db,
        ApprovePlanCommand(
            command_id=f"{request.command_id}:approve",
            plan_id=plan.id,
            evidence=ApprovalEvidence(
                policy_code=evidence.policy_code,
                policy_version=evidence.policy_version,
                decision_ref=str(evidence.request_id),
                # The module's own frozen string, carried across untouched.
                content_digest=frozen,
                decided_at=evidence.decided_at,
                # Stays empty. ADR-0013 § 3: approver identity lives once, in
                # `dotmac-approvals`, reachable through `decision_ref`.
            ),
            expected_version=request.expected_plan_version,
            actor_ref=request.actor_ref,
        ),
    )

    rollout = request_rollout(
        db,
        RequestRolloutCommand(
            command_id=f"{request.command_id}:rollout",
            rollout_ref=request.rollout_ref,
            plan_id=plan.id,
            reason=request.reason,
            actor_ref=request.actor_ref,
        ),
    )

    approved_at = approved.approved_at or evidence.decided_at
    return AuthorizationReceipt(
        authorization_ref=str(rollout.id),
        rollout_id=rollout.id,
        rollout_ref=rollout.rollout_ref,
        rollout_status=rollout.status,
        plan_id=approved.id,
        plan_digest=frozen,
        plan_status=approved.status,
        target_id=approved.target_id,
        desired_revision=approved.desired_revision,
        approval_policy_code=evidence.policy_code,
        approval_policy_version=evidence.policy_version,
        approval_decision_ref=str(evidence.request_id),
        approved_at=approved_at,
        issuer=DISTRIBUTION,
        issuer_version=require_version(),
        authority=AUTHORITY_DISTRIBUTION,
        authority_version=authority_version(),
    )


__all__ = [
    "PLAN_SUBJECT_TYPE",
    "AuthorizationReceipt",
    "AuthorizeRequest",
    "DeploymentIdentityMismatch",
    "DeploymentTargetFacts",
    "DesiredStateRequest",
    "ProposePlanRequest",
    "ProposedPlan",
    "TargetRegistrationRequest",
    "authorize_deployment",
    "propose_deployment_plan",
    "read_drift",
    "read_plan",
    "read_rollout",
    "read_target",
    "register_deployment_target",
    "resolve_target",
    "set_target_desired_state",
]
