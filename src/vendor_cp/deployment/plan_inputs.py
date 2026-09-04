"""One immutable reference, five derived plan inputs, and no silent value.

`dotmac_platform_control_plane` ADR-0013 amendment A6.4 (cited with its
repository on the clause's own instruction — `dotmac_governance` has an
unrelated ADR 0013):

    Target, desired state, profile digest, authorized images and
    execution-plan inputs are derived from one immutable reference. No
    independently supplied value may silently join the plan.

This module is the mechanism. Before it, `render_execution_plan` took `target`
and the authorized image as caller-supplied arguments beside a descriptor —
accepted, used, covered by the digest, and recorded in no provenance. That is
precisely the residue the clause defines as SILENT.

## The reference is the authorization, not a new identity

`authorization_ref` is the Control rollout id, and `vendor_cp.deployment.adapter`
already describes it as the middle term binding the canonical descriptor to the
foundation's execution report. Minting a second identity for the same
authorization would leave a control plane with two answers to what was
authorized, whatever the second one was called — so the reference this resolver
takes is the one that already exists.

It is immutable, so the derivation is repeatable: the same reference yields the
same five values, and a digest over them identifies one set of inputs rather
than one invocation.

## Five values, five refusals, never one aggregate

The clause names five individually so a reader cannot discharge it by checking
one, and this module refuses the same way. Each input that cannot be derived
raises with ITS OWN code naming which of the five it was, and a caller learns
immediately rather than discovering later that a plan was assembled around a
value nobody supplied.

## `silently` is the enforceable half

Three loud routes, and the residue between them is the violation:

* **Derived** — resolved from the reference, and the value records that as its
  provenance. The ordinary path.
* **Refused** — an input that cannot be derived raises, naming which. Nothing
  reaches a digest.
* **Recorded as an override** — accepted, but only through an explicit override
  that is carried into the plan AND the receipt, so a plan states which of its
  inputs did not come from the reference.

The check follows directly and `verify_no_silent_value` performs it: every one
of the five carries a provenance, and any provenance that is not the reference
must appear in the declared overrides. A value with no provenance at all is the
violation, and it is detectable without knowing what the value means.

This is deliberately not a ban on overrides. A ceremony with no exception path
grows an undeclared one, which is the shape the clause exists to end.

## The profile digest refuses today, BY NAME

`PROFILE_DIGEST` is the thirteen-concern application foundation profile, and no
such document exists in this artifact yet. It is therefore a typed, named
absence — not omitted from the five, not defaulted, and above all not `""`.

That last one is measured rather than hypothetical: the Foundation's
`discover_profile()` returns `None` in every environment, so
`_application_profile_digest()` returns the empty string, and all three of its
call sites put that empty string into every plan. An empty digest is a
syntactically perfect value naming nothing, so every gate that checks only
presence reads green. Reintroducing it one layer up would be the same defect
with a longer paper trail.

When the profile document lands, this value starts resolving without a change to
this module's shape.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.orm import Session

from vendor_cp.deployment.adapter import read_plan, read_rollout, read_target

__all__ = [
    "REFUSAL_CODES",
    "Override",
    "PlanInput",
    "PlanInputRefused",
    "Provenance",
    "ResolvedPlanInputs",
    "ResolvedValue",
    "resolve_plan_inputs",
    "verify_no_silent_value",
]


class PlanInput(StrEnum):
    """The five values A6.4 names, as machine names rather than a phrase.

    Named individually and checked individually. A single `PLAN_INPUTS` member
    would let a caller satisfy the clause by deriving one of them.
    """

    TARGET = "target"
    DESIRED_STATE = "desired_state"
    PROFILE_DIGEST = "profile_digest"
    AUTHORIZED_IMAGES = "authorized_images"
    EXECUTION_PLAN_INPUTS = "execution_plan_inputs"


class Provenance(StrEnum):
    """Where a value came from. Every value has one; that is the point."""

    #: Resolved from the immutable reference. The ordinary path.
    DERIVED_FROM_REFERENCE = "derived_from_reference"
    #: Accepted from outside the reference through a DECLARED override, which
    #: must also appear in `ResolvedPlanInputs.overrides`.
    DECLARED_OVERRIDE = "declared_override"


#: Every refusal this resolver can emit. One per input, plus the two that are
#: about the reference itself rather than about any single value.
#:
#: A code is a permanent identifier: it may be retired, never reassigned, because
#: an operator's runbook branches on it.
REFUSAL_CODES: Final[frozenset[str]] = frozenset(
    {
        "plan_input.reference_unknown",
        "plan_input.reference_unapproved",
        *(f"plan_input.{member.value}_underivable" for member in PlanInput),
    }
)


class PlanInputRefused(Exception):
    """One plan input could not be derived, and the refusal says which.

    `input` is `None` only for the two reference-level refusals, where no single
    value is at fault because none could be attempted.
    """

    def __init__(self, code: str, message: str, *, input: PlanInput | None) -> None:
        super().__init__(message)
        if code not in REFUSAL_CODES:  # pragma: no cover - guarded by a test
            raise AssertionError(f"undeclared plan-input refusal code {code!r}")
        self.code = code
        self.message = message
        self.input = input


@dataclass(frozen=True, slots=True)
class Override:
    """One value the caller supplies instead of deriving it.

    `reason` is required and may not be blank. An override with no stated reason
    is an undeclared exception with a field attached: the whole purpose of this
    route is that a plan STATES which of its inputs did not come from the
    reference, and an approver reading it sees the exception without having to
    reconstruct it.
    """

    input: PlanInput
    value: str
    reason: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("an override with no value is an absence, not an override")
        if not self.reason.strip():
            raise ValueError(
                "an override must state why it is not derived from the reference"
            )


@dataclass(frozen=True, slots=True)
class ResolvedValue:
    """One of the five, its value, and where that value came from."""

    input: PlanInput
    value: str
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class ResolvedPlanInputs:
    """The five values resolved from one reference, with their provenance.

    `overrides` is the plan's own record of which inputs did not come from the
    reference. It is carried into the plan AND the receipt from this one place,
    so the two cannot disagree — an override present in one and absent from the
    other is a silent value again, just with a longer paper trail.
    """

    authorization_ref: str
    values: tuple[ResolvedValue, ...]
    overrides: tuple[Override, ...] = ()

    def of(self, input: PlanInput) -> ResolvedValue:
        for value in self.values:
            if value.input is input:
                return value
        raise KeyError(input)

    @property
    def derived(self) -> tuple[ResolvedValue, ...]:
        return tuple(
            value
            for value in self.values
            if value.provenance is Provenance.DERIVED_FROM_REFERENCE
        )


def _snapshot_string(snapshot: Mapping[str, object], key: str) -> str | None:
    """A string field of the frozen plan snapshot, or `None` if it is absent,
    empty or not a string. Empty is absent: a blank release reference is a
    syntactically perfect value naming nothing."""
    raw = snapshot.get(key)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw


def resolve_plan_inputs(
    db: Session,
    authorization_ref: str,
    *,
    overrides: Sequence[Override] = (),
) -> ResolvedPlanInputs:
    """Derive the five plan inputs from one immutable authorization reference.

    READ ONLY. It resolves; it writes nothing and decides nothing about whether
    a deployment should proceed.

    Raises `PlanInputRefused` naming which of the five could not be derived. An
    input covered by a declared override is not derived and is not refused — it
    is recorded, with its provenance, and carried into the plan and the receipt.
    """
    declared = {override.input: override for override in overrides}
    if len(declared) != len(overrides):
        raise ValueError("two overrides name the same plan input")

    try:
        rollout_id = UUID(authorization_ref)
    except ValueError as error:
        raise PlanInputRefused(
            "plan_input.reference_unknown",
            f"{authorization_ref!r} is not an authorization reference",
            input=None,
        ) from error

    rollout = read_rollout(db, rollout_id)
    plan = read_plan(db, rollout.plan_id)
    target = read_target(db, plan.target_id)

    # The approval is what makes the reference an AUTHORIZATION rather than a
    # proposal. Deriving five values from an unapproved plan would produce a
    # perfectly self-consistent input set that nobody agreed to.
    if plan.approval_decision_ref is None or plan.approved_at is None:
        raise PlanInputRefused(
            "plan_input.reference_unapproved",
            f"plan {plan.id} carries no approval decision, so the rollout it "
            "belongs to is not an authorization to derive from",
            input=None,
        )

    snapshot = plan.snapshot
    candidates: dict[PlanInput, str | None] = {
        PlanInput.TARGET: target.target_ref or None,
        # The FROZEN snapshot, not the target's current desired state. A plan
        # authorizes what it froze; reading the target now would let a
        # desired-state edit after approval join the plan unnoticed.
        PlanInput.DESIRED_STATE: (f"{plan.desired_revision}" if snapshot else None),
        # Named absence. See the module docstring: not omitted, not defaulted,
        # and specifically never the empty string.
        PlanInput.PROFILE_DIGEST: None,
        PlanInput.AUTHORIZED_IMAGES: _snapshot_string(snapshot, "release_ref"),
        PlanInput.EXECUTION_PLAN_INPUTS: plan.plan_digest,
    }

    reasons: Final[dict[PlanInput, str]] = {
        PlanInput.TARGET: (
            f"the plan's target {plan.target_id} carries no target reference"
        ),
        PlanInput.DESIRED_STATE: (
            f"plan {plan.id} froze an empty snapshot, so it authorizes no "
            "desired state"
        ),
        PlanInput.PROFILE_DIGEST: (
            "no application foundation profile document exists in this "
            "artifact, so there is nothing to digest. This refusal is the "
            "correct answer until the thirteen-concern profile lands; an empty "
            "digest here would be a value naming nothing that every "
            "presence-only gate reads as green"
        ),
        PlanInput.AUTHORIZED_IMAGES: (
            f"plan {plan.id}'s frozen snapshot names no release reference"
        ),
        PlanInput.EXECUTION_PLAN_INPUTS: (
            f"plan {plan.id} has no frozen digest, so what it authorizes is not "
            "identified"
        ),
    }

    values: list[ResolvedValue] = []
    for member in PlanInput:
        override = declared.get(member)
        if override is not None:
            values.append(
                ResolvedValue(member, override.value, Provenance.DECLARED_OVERRIDE)
            )
            continue
        derived = candidates[member]
        if derived is None:
            raise PlanInputRefused(
                f"plan_input.{member.value}_underivable",
                reasons[member],
                input=member,
            )
        values.append(ResolvedValue(member, derived, Provenance.DERIVED_FROM_REFERENCE))

    resolved = ResolvedPlanInputs(
        authorization_ref=authorization_ref,
        values=tuple(values),
        overrides=tuple(overrides),
    )
    verify_no_silent_value(resolved)
    return resolved


def verify_no_silent_value(resolved: ResolvedPlanInputs) -> None:
    """A6.4's enforceable check, performed rather than described.

    For each of the five the plan carries a provenance, and any provenance that
    is not the reference must appear in the declared overrides. A value with no
    provenance at all is the violation, and it is detectable without knowing
    what the value means.

    Raises `ValueError` rather than `PlanInputRefused`: this is a structural
    invariant of an already-assembled input set, not a verdict about a
    reference, and conflating the two would let a caller catch a refusal and
    swallow a violation.

    There is deliberately NO "declared override that reached no input" check.
    Every override names a `PlanInput`, and a complete set contains all five, so
    that condition is unreachable unless the set is already incomplete — in
    which case the check above fires first. A third branch would be defensive
    code no test could reach honestly, and a test that appeared to cover it
    would be passing for the wrong reason.
    """
    present = {value.input for value in resolved.values}
    missing = sorted(member.value for member in PlanInput if member not in present)
    if missing:
        raise ValueError(f"plan inputs carry no provenance at all: {missing}")

    overridden = {override.input for override in resolved.overrides}
    undeclared = sorted(
        value.input.value
        for value in resolved.values
        if value.provenance is Provenance.DECLARED_OVERRIDE
        and value.input not in overridden
    )
    if undeclared:
        raise ValueError(
            "these inputs did not come from the reference and are not in the "
            f"plan's declared overrides: {undeclared}"
        )
