"""Derive the five A6.4 terms a rehearsal-issuer authorization subject needs,
from one immutable reference and one rendered candidate -- READ ONLY.

`plan_inputs.resolve_plan_inputs` is ALL-OR-NOTHING: it derives all five of
target, desired state, profile digest, authorized images and execution-plan
inputs, or it refuses, naming which one it could not derive. `PROFILE_DIGEST`
is UNCONDITIONALLY undrivable there today -- no per-target profile document
exists in this artifact yet (see that module's own docstring, "The profile
digest refuses today, BY NAME") -- and `PlanInput` iterates in an order that
reaches `PROFILE_DIGEST` third, before `AUTHORIZED_IMAGES` and
`EXECUTION_PLAN_INPUTS` are even considered. So calling `resolve_plan_inputs`
with no override always raises, and getting anything out of it at all
requires a real, declared `Override` for `PROFILE_DIGEST`.

## The override is not a placeholder

`derive_rehearsal_issuer_terms` supplies exactly the value it is going to use
anyway: `rendered.descriptor_digest`, the Foundation's own canonical
descriptor digest for this candidate. Nothing about this override is thrown
away -- it is the real value the returned terms carry as `profile_digest`,
recorded honestly as an override because `plan_inputs.py`'s own resolver
could not derive it.

## `execution_plan_digest` is a deliberate SUBSTITUTION, not a passthrough

`plan_inputs.py`'s own resolver marks `EXECUTION_PLAN_INPUTS` as
`DERIVED_FROM_REFERENCE`, using `plan.plan_digest` -- Control's frozen
DESIRED-STATE snapshot digest. This function discards that value. Lane 3's own
precondition requires the real `ExecutionPlanDigestV1`, which `plan.plan_digest`
is not, so this function uses `rendered.execution_plan_digest` instead -- the
Foundation's own execution-plan digest for the same rendered candidate.

Because the value actually used is different from what `plan_inputs.py`'s own
bookkeeping resolved, the OUTER (C1-facing) provenance for `execution_plan` is
reported as `"override"`, with a reason naming exactly this substitution --
even though `plan_inputs.py`'s own internal `Provenance` called it
`DERIVED_FROM_REFERENCE`. The two provenance vocabularies answer different
questions: `plan_inputs.Provenance` describes where a value `plan_inputs.py`
resolved came from; this module's outer provenance describes where the value
this module ACTUALLY USED came from. Silently passing through the inner
verdict about a value that was discarded would be exactly the kind of "silent
value" A6.4 exists to forbid, just relocated one layer up.

## `target_id`, by the same lookup chain `resolve_plan_inputs` already uses

`resolve_plan_inputs` reaches a target internally via
`authorization_ref -> rollout -> plan -> target`
(`read_rollout` then `read_plan` then `read_target`, keyed off
`rollout.plan_id` and `plan.target_id`). `PlanInput.TARGET` resolves to
`target.target_ref`, a string -- not the target's id. This function needs the
id too, so it reuses the identical `adapter.read_rollout`/`adapter.read_plan`
calls rather than inventing a second lookup: `read_rollout(db,
UUID(authorization_ref)).plan_id`, then `read_plan(db, plan_id).target_id`.

This function is READ ONLY: it queries `db`, writes nothing, signs nothing,
and has no other side effect.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from vendor_cp.deployment.adapter import read_plan, read_rollout
from vendor_cp.deployment.candidate import RenderedCandidate
from vendor_cp.deployment.plan_inputs import (
    Override,
    PlanInput,
    Provenance,
    resolve_plan_inputs,
)
from vendor_cp.deployment.rehearsal_issuer_adapter import RehearsalIssuerTerms

__all__ = ["derive_rehearsal_issuer_terms"]

#: `plan_inputs.Provenance` -> this module's outer, C1-facing provenance
#: vocabulary. A passthrough for the three values that genuinely stayed what
#: `plan_inputs.py` resolved (`target`, `desired_state`, `authorized_images`).
_OUTER_PROVENANCE: dict[Provenance, str] = {
    Provenance.DERIVED_FROM_REFERENCE: "derived",
    Provenance.DECLARED_OVERRIDE: "override",
}

#: The reason recorded for the `PROFILE_DIGEST` override handed to
#: `resolve_plan_inputs`, and the same reason carried into the returned
#: terms' `profile` provenance entry.
_PROFILE_OVERRIDE_REASON = (
    "no per-target profile document exists in plan_inputs.py's own "
    "resolution scope yet; this rehearsal-issuer subject's profile digest "
    "instead uses the Foundation's canonical descriptor digest from the "
    "rendered candidate, itself derived from the same authorization_ref "
    "chain via render_candidate"
)

#: The reason recorded for the `execution_plan` provenance entry: CP1
#: discards `plan_inputs.py`'s own `EXECUTION_PLAN_INPUTS` resolution
#: (`plan.plan_digest`, a desired-state snapshot digest) and uses the
#: Foundation's real execution-plan digest instead, because Lane 3's own
#: precondition (`lane3_authorization.py`'s
#: `middle_term_is_the_execution_plan_digest`) requires it.
_EXECUTION_PLAN_SUBSTITUTION_REASON = (
    "plan_inputs.py's own resolver marks execution_plan_inputs as derived "
    "using plan.plan_digest, Control's frozen desired-state snapshot digest "
    "-- not the real execution-plan digest Lane 3's own precondition "
    "requires. This subject instead carries rendered.execution_plan_digest, "
    "the Foundation's own execution-plan digest for the same rendered "
    "candidate, so the value actually used did not come from the reference "
    "and is reported here as an override rather than as the derivation "
    "plan_inputs.py recorded for the value it was not used"
)


def derive_rehearsal_issuer_terms(
    db: Session,
    authorization_ref: str,
    *,
    rendered: RenderedCandidate,
) -> RehearsalIssuerTerms:
    """The five A6.4 terms for one rehearsal-issuer lease's comparison
    subject, derived from `authorization_ref` and `rendered` together.

    READ ONLY -- see the module docstring for the override this function must
    supply to get anything out of `resolve_plan_inputs` at all, and for the
    deliberate `execution_plan_digest` substitution.
    """
    profile_override = Override(
        input=PlanInput.PROFILE_DIGEST,
        value=rendered.descriptor_digest,
        reason=_PROFILE_OVERRIDE_REASON,
    )
    resolved = resolve_plan_inputs(db, authorization_ref, overrides=[profile_override])

    target_value = resolved.of(PlanInput.TARGET)
    desired_state_value = resolved.of(PlanInput.DESIRED_STATE)
    authorized_images_value = resolved.of(PlanInput.AUTHORIZED_IMAGES)

    # Same lookup chain `resolve_plan_inputs` already performs internally to
    # reach a target -- reused, not reinvented. `PlanInput.TARGET` resolves to
    # `target.target_ref`, a string, never the target's id.
    rollout = read_rollout(db, UUID(authorization_ref))
    plan = read_plan(db, rollout.plan_id)
    target_id = str(plan.target_id)

    declared_overrides = {"profile", "execution_plan"}
    for key, value in (
        ("target", target_value),
        ("desired_state", desired_state_value),
        ("authorized_images", authorized_images_value),
    ):
        if value.provenance is Provenance.DECLARED_OVERRIDE:
            declared_overrides.add(key)

    provenance = {
        "target": _OUTER_PROVENANCE[target_value.provenance],
        "desired_state": _OUTER_PROVENANCE[desired_state_value.provenance],
        "authorized_images": _OUTER_PROVENANCE[authorized_images_value.provenance],
        # Passthrough of what plan_inputs.py itself recorded -- honest, since
        # its own resolver could not derive this and needed the override.
        "profile": "override",
        # The deliberate substitution described in the module docstring, NOT
        # a passthrough of plan_inputs.py's own `EXECUTION_PLAN_INPUTS`
        # verdict, because that value is discarded rather than used.
        "execution_plan": "override",
    }

    return RehearsalIssuerTerms(
        immutable_reference=authorization_ref,
        target_id=target_id,
        target_ref=target_value.value,
        desired_state_digest=desired_state_value.value,
        profile_digest=rendered.descriptor_digest,
        # Today's plan_inputs.py only derives one image reference.
        authorized_image_digests=(authorized_images_value.value,),
        execution_plan_digest=rendered.execution_plan_digest,
        provenance=provenance,
        declared_overrides=frozenset(declared_overrides),
    )
