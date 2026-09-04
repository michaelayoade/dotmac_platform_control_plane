"""Five plan inputs, five refusals, and no value that joins the plan silently.

`dotmac_platform_control_plane` ADR-0013 amendment A6.4 names five values
individually, and it does so precisely *so a reader cannot discharge the clause
by checking one*. A resolver that has only ever been observed refusing on a
malformed reference has not been shown to distinguish them, so each of the five
is planted separately here and must produce its own code.

The positive control matters as much: a reference from which everything IS
derivable must resolve cleanly, or the five refusals above are satisfied by a
function that refuses unconditionally.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Iterator

import pytest
from dotmac_kernel import NotFoundError
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.deployment import adapter
from vendor_cp.deployment.plan_inputs import (
    REFUSAL_CODES,
    Override,
    PlanInput,
    PlanInputRefused,
    Provenance,
    ResolvedPlanInputs,
    ResolvedValue,
    resolve_plan_inputs,
    verify_no_silent_value,
)

#: The profile document does not exist in this artifact yet, so a fully derived
#: resolution is impossible today and every positive case declares this override.
#: That is not a workaround — it is the override route being exercised, and it
#: disappears on its own when the thirteen-concern profile lands.
PROFILE_OVERRIDE = Override(
    input=PlanInput.PROFILE_DIGEST,
    value="sha256:" + "0" * 64,
    reason="the application foundation profile document does not exist yet",
)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _authorized(db: Session) -> str:
    """Drive the REAL chain to a real authorization reference.

    Register a target, declare its desired state, publish a policy, freeze a
    plan, decide the approval, authorize. Nothing is inserted by hand: the
    reference under test has to be the one production would produce, or this
    tests a fixture rather than the resolver.
    """
    target = adapter.register_deployment_target(
        db,
        adapter.TargetRegistrationRequest(
            command_id=f"register-{uuid.uuid4()}",
            target_ref=f"vendor-cp-{uuid.uuid4().hex[:8]}",
            subject_ref="dotmac-sub",
            product_code="dotmac-sub",
            environment="production",
        ),
    )
    adapter.set_target_desired_state(
        db,
        adapter.DesiredStateRequest(
            command_id=f"desired-{uuid.uuid4()}",
            target_id=target.id,
            release_ref="ghcr.io/example@sha256:" + "a" * 64,
            spec={"replicas": 1},
        ),
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"policy-{uuid.uuid4()}",
            policy_code="deployment",
            version=1,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    plan = adapter.propose_deployment_plan(
        db,
        adapter.ProposePlanRequest(
            command_id=f"propose-{uuid.uuid4()}",
            target_id=target.id,
            approval_policy_code="deployment",
            approval_policy_version=1,
        ),
    )
    request = approvals.open_request(
        db,
        approvals.OpenRequestCommand(
            command_id=f"open-{uuid.uuid4()}",
            policy_code="deployment",
            policy_version=1,
            subject_type="deployment_plan",
            subject_id=str(plan.plan_id),
            content_hash=plan.approval_content_hash,
            requested_by=uuid.uuid4(),
        ),
    )
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"decide-{uuid.uuid4()}",
            request_id=request.request_id,
            approver_id=uuid.uuid4(),
            content_hash=plan.approval_content_hash,
        ),
    )
    receipt = adapter.authorize_deployment(
        db,
        adapter.AuthorizeRequest(
            command_id=f"authorize-{uuid.uuid4()}",
            plan_id=plan.plan_id,
            approval_request_id=request.request_id,
            rollout_ref=f"rollout-{uuid.uuid4().hex[:8]}",
        ),
    )
    return receipt.authorization_ref


def _refusal(db: Session, reference: str, **kwargs: object) -> PlanInputRefused:
    with pytest.raises(PlanInputRefused) as caught:
        resolve_plan_inputs(db, reference, **kwargs)  # type: ignore[arg-type]
    return caught.value


# ── the positive control comes first, because everything below needs it ─────


def test_a_derivable_reference_resolves_every_input_with_provenance(
    db: Session,
) -> None:
    """NON-VACUITY for all five plants. A resolver that refused unconditionally
    would satisfy every refusal test in this file."""
    resolved = resolve_plan_inputs(db, _authorized(db), overrides=[PROFILE_OVERRIDE])

    assert {value.input for value in resolved.values} == set(PlanInput)
    derived = {value.input for value in resolved.derived}
    assert derived == set(PlanInput) - {PlanInput.PROFILE_DIGEST}
    # Every one of the five carries a provenance. That is the structural half of
    # A6.4: a value with none is the violation.
    assert all(isinstance(v.provenance, Provenance) for v in resolved.values)
    assert resolved.of(PlanInput.TARGET).value.startswith("vendor-cp-")
    assert resolved.of(PlanInput.AUTHORIZED_IMAGES).value.startswith("ghcr.io/")


# ── five inputs, five distinct codes ────────────────────────────────────────


def test_the_profile_digest_refuses_by_name_and_is_never_an_empty_string(
    db: Session,
) -> None:
    """The fifth value, and the one that refuses TODAY.

    The Foundation's own `discover_profile()` returns `None` in every
    environment, so its `_application_profile_digest()` yields `""` and every
    plan carries an empty digest — a syntactically perfect value naming nothing,
    which every presence-only gate reads as green. This refuses instead.
    """
    refusal = _refusal(db, _authorized(db))
    assert refusal.input is PlanInput.PROFILE_DIGEST
    assert refusal.code == "plan_input.profile_digest_underivable"
    assert "empty digest" in refusal.message


@pytest.mark.parametrize(
    ("input", "field", "broken"),
    [
        (PlanInput.TARGET, "target_ref", ""),
        (PlanInput.EXECUTION_PLAN_INPUTS, "plan_digest", None),
        (PlanInput.AUTHORIZED_IMAGES, "snapshot", {"replicas": 1}),
        (PlanInput.DESIRED_STATE, "snapshot", {}),
    ],
    ids=["target", "execution-plan-inputs", "authorized-images", "desired-state"],
)
def test_each_input_refuses_with_its_own_code(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
    input: PlanInput,
    field: str,
    broken: object,
) -> None:
    """One plant per input, and each must be told apart from the others.

    The owner's own typed views are used and one field is emptied, because what
    is under test is the resolver's DISCRIMINATION — that it can say which of
    the five is missing, not merely that something is.
    """
    reference = _authorized(db)
    reader = "read_target" if field == "target_ref" else "read_plan"
    original = getattr(adapter, reader)

    def _broken(session: Session, identifier: uuid.UUID) -> object:
        return dataclasses.replace(original(session, identifier), **{field: broken})

    monkeypatch.setattr(f"vendor_cp.deployment.plan_inputs.{reader}", _broken)

    refusal = _refusal(db, reference, overrides=[PROFILE_OVERRIDE])
    assert refusal.input is input
    assert refusal.code == f"plan_input.{input.value}_underivable"


def test_the_five_refusal_codes_are_distinct_and_declared() -> None:
    """A shared code would let two different failures look like one, which is
    the aggregate refusal A6.4's five-way naming exists to prevent."""
    per_input = {f"plan_input.{member.value}_underivable" for member in PlanInput}
    assert len(per_input) == len(PlanInput)
    assert per_input <= REFUSAL_CODES
    assert len(REFUSAL_CODES) == len(PlanInput) + 2  # plus the two reference-level


# ── refusals about the REFERENCE, which name no single input ────────────────


def test_a_malformed_reference_names_no_input(db: Session) -> None:
    """`input` is None here on purpose: no single value is at fault, because
    none could be attempted."""
    refusal = _refusal(db, "not-a-reference")
    assert refusal.code == "plan_input.reference_unknown"
    assert refusal.input is None


def test_an_unknown_reference_is_refused_by_the_owner(db: Session) -> None:
    with pytest.raises(NotFoundError):
        resolve_plan_inputs(db, str(uuid.uuid4()))


def test_an_unapproved_plan_is_not_an_authorization(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deriving five values from a plan nobody approved would produce a
    perfectly self-consistent input set that no authority agreed to."""
    reference = _authorized(db)
    original = adapter.read_plan
    monkeypatch.setattr(
        "vendor_cp.deployment.plan_inputs.read_plan",
        lambda s, i: dataclasses.replace(
            original(s, i), approval_decision_ref=None, approved_at=None
        ),
    )
    refusal = _refusal(db, reference)
    assert refusal.code == "plan_input.reference_unapproved"
    assert refusal.input is None


# ── the override route, and the invariant that keeps it loud ────────────────


def test_an_override_is_recorded_with_its_own_provenance(db: Session) -> None:
    resolved = resolve_plan_inputs(db, _authorized(db), overrides=[PROFILE_OVERRIDE])
    value = resolved.of(PlanInput.PROFILE_DIGEST)
    assert value.provenance is Provenance.DECLARED_OVERRIDE
    assert value.value == PROFILE_OVERRIDE.value
    # Carried into the plan AND the receipt from ONE place, so the two cannot
    # disagree. In one and not the other it is a silent value again, with a
    # longer paper trail.
    assert resolved.overrides == (PROFILE_OVERRIDE,)


def test_an_override_must_say_why() -> None:
    """An override with no stated reason is an undeclared exception with a field
    attached. An approver reading the plan must see the exception without having
    to reconstruct it."""
    with pytest.raises(ValueError, match="why"):
        Override(input=PlanInput.TARGET, value="somewhere", reason="   ")
    with pytest.raises(ValueError, match="absence"):
        Override(input=PlanInput.TARGET, value="", reason="a reason")


def test_two_overrides_for_one_input_are_refused(db: Session) -> None:
    second = dataclasses.replace(PROFILE_OVERRIDE, value="sha256:" + "1" * 64)
    with pytest.raises(ValueError, match="same plan input"):
        resolve_plan_inputs(db, _authorized(db), overrides=[PROFILE_OVERRIDE, second])


# ── A6.4's enforceable check, performed rather than described ───────────────


def test_a_value_that_did_not_come_from_the_reference_must_be_declared() -> None:
    """THE VIOLATION, PLANTED. An overridden value whose override is not in the
    plan's declared list is exactly the residue A6.4 defines as silent:
    accepted, used, covered by the digest, and in neither the refusal path nor
    the plan's own provenance record."""
    smuggled = ResolvedPlanInputs(
        authorization_ref=str(uuid.uuid4()),
        values=tuple(
            ResolvedValue(member, "x", Provenance.DERIVED_FROM_REFERENCE)
            if member is not PlanInput.TARGET
            else ResolvedValue(member, "elsewhere", Provenance.DECLARED_OVERRIDE)
            for member in PlanInput
        ),
        overrides=(),
    )
    with pytest.raises(ValueError, match="declared overrides"):
        verify_no_silent_value(smuggled)


def test_a_value_with_no_provenance_at_all_is_the_violation() -> None:
    """Detectable without knowing what the value means, which is what makes the
    check mechanical."""
    incomplete = ResolvedPlanInputs(
        authorization_ref=str(uuid.uuid4()),
        values=tuple(
            ResolvedValue(member, "x", Provenance.DERIVED_FROM_REFERENCE)
            for member in PlanInput
            if member is not PlanInput.AUTHORIZED_IMAGES
        ),
    )
    with pytest.raises(ValueError, match="no provenance at all"):
        verify_no_silent_value(incomplete)


def test_an_override_can_never_reach_no_input(db: Session) -> None:
    """Why `verify_no_silent_value` has two branches and not three.

    Every override names a `PlanInput` and a complete set contains all five, so
    "a declared override that changed nothing" is unreachable unless the set is
    already incomplete — which the missing-provenance branch catches first. This
    asserts that premise rather than leaving a third defensive branch no test
    could reach honestly, and which a test could only appear to cover.
    """
    resolved = resolve_plan_inputs(db, _authorized(db), overrides=[PROFILE_OVERRIDE])
    reached = {value.input for value in resolved.values}
    assert all(override.input in reached for override in resolved.overrides)
    assert reached == set(PlanInput)


def test_a_clean_resolution_passes_the_check(db: Session) -> None:
    """NON-VACUITY for the three violations above."""
    verify_no_silent_value(
        resolve_plan_inputs(db, _authorized(db), overrides=[PROFILE_OVERRIDE])
    )
