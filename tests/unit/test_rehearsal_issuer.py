"""`derive_rehearsal_issuer_terms`'s override-and-substitution discipline,
proved against fakes for `resolve_plan_inputs`/`adapter.read_rollout`/
`adapter.read_plan` -- this module is the HEAVY half and is exercised through
its own module attributes (`rehearsal_issuer.resolve_plan_inputs`, etc.),
never against a real database.
"""

from __future__ import annotations

from uuid import uuid4

from vendor_cp.deployment import rehearsal_issuer
from vendor_cp.deployment.candidate import RenderedCandidate
from vendor_cp.deployment.plan_inputs import (
    Override,
    PlanInput,
    Provenance,
    ResolvedPlanInputs,
    ResolvedValue,
)


class _FakeRolloutView:
    def __init__(self, plan_id: object) -> None:
        self.plan_id = plan_id


class _FakePlanView:
    def __init__(self, target_id: object) -> None:
        self.target_id = target_id


def _fake_resolved(
    authorization_ref: str,
    overrides: tuple[Override, ...],
    *,
    execution_plan_value: str = "plan-digest-from-plan-inputs",
) -> ResolvedPlanInputs:
    return ResolvedPlanInputs(
        authorization_ref=authorization_ref,
        values=(
            ResolvedValue(
                PlanInput.TARGET, "target-ref-1", Provenance.DERIVED_FROM_REFERENCE
            ),
            ResolvedValue(
                PlanInput.DESIRED_STATE, "7", Provenance.DERIVED_FROM_REFERENCE
            ),
            ResolvedValue(
                PlanInput.PROFILE_DIGEST,
                next(o.value for o in overrides if o.input is PlanInput.PROFILE_DIGEST),
                Provenance.DECLARED_OVERRIDE,
            ),
            ResolvedValue(
                PlanInput.AUTHORIZED_IMAGES,
                "release-ref-1",
                Provenance.DERIVED_FROM_REFERENCE,
            ),
            ResolvedValue(
                PlanInput.EXECUTION_PLAN_INPUTS,
                execution_plan_value,
                Provenance.DERIVED_FROM_REFERENCE,
            ),
        ),
        overrides=overrides,
    )


def _rendered(
    *,
    descriptor_digest: str = "sha256:" + "a" * 64,
    execution_plan_digest: str = "sha256:" + "b" * 64,
) -> RenderedCandidate:
    return RenderedCandidate(
        descriptor_digest=descriptor_digest,
        execution_plan_digest=execution_plan_digest,
        canonical_plan_bytes=b"{}",
    )


def _patch_lookup_chain(monkeypatch, plan_id: object, target_id: object) -> None:
    monkeypatch.setattr(
        rehearsal_issuer,
        "read_rollout",
        lambda db, rollout_id: _FakeRolloutView(plan_id),
    )
    monkeypatch.setattr(
        rehearsal_issuer, "read_plan", lambda db, pid: _FakePlanView(target_id)
    )


def test_the_override_handed_to_resolve_plan_inputs_carries_the_descriptor_digest(
    monkeypatch,
) -> None:
    """The override is not a throwaway: its `value` IS `rendered.descriptor_digest`,
    the same value CP1 goes on to use as the subject's `profile_digest`."""
    captured_overrides: list[tuple[Override, ...]] = []

    def _fake_resolve_plan_inputs(db, authorization_ref, *, overrides=()):
        overrides = tuple(overrides)
        captured_overrides.append(overrides)
        return _fake_resolved(authorization_ref, overrides)

    monkeypatch.setattr(
        rehearsal_issuer, "resolve_plan_inputs", _fake_resolve_plan_inputs
    )
    _patch_lookup_chain(monkeypatch, plan_id=uuid4(), target_id=uuid4())

    rendered = _rendered()
    authorization_ref = str(uuid4())

    rehearsal_issuer.derive_rehearsal_issuer_terms(
        db=object(), authorization_ref=authorization_ref, rendered=rendered
    )

    [overrides] = captured_overrides
    [override] = overrides
    assert override.input is PlanInput.PROFILE_DIGEST
    assert override.value == rendered.descriptor_digest
    assert override.reason.strip()


def test_the_returned_profile_and_execution_plan_digests_come_from_rendered(
    monkeypatch,
) -> None:
    """`plan_inputs.py`'s own resolver marks `EXECUTION_PLAN_INPUTS` as
    DERIVED using `plan.plan_digest` -- an obviously different sentinel here.
    The returned terms must carry `rendered.execution_plan_digest` instead,
    proving the substitution is real rather than incidental equality."""

    def _fake_resolve_plan_inputs(db, authorization_ref, *, overrides=()):
        overrides = tuple(overrides)
        return _fake_resolved(
            authorization_ref,
            overrides,
            execution_plan_value="SENTINEL-PLAN-DIGEST-NEVER-USED",
        )

    monkeypatch.setattr(
        rehearsal_issuer, "resolve_plan_inputs", _fake_resolve_plan_inputs
    )
    _patch_lookup_chain(monkeypatch, plan_id=uuid4(), target_id=uuid4())

    rendered = _rendered()
    terms = rehearsal_issuer.derive_rehearsal_issuer_terms(
        db=object(), authorization_ref=str(uuid4()), rendered=rendered
    )

    assert terms.execution_plan_digest == rendered.execution_plan_digest
    assert terms.execution_plan_digest != "SENTINEL-PLAN-DIGEST-NEVER-USED"
    assert terms.profile_digest == rendered.descriptor_digest


def test_authorized_image_digests_is_a_one_element_tuple(monkeypatch) -> None:
    def _fake_resolve_plan_inputs(db, authorization_ref, *, overrides=()):
        return _fake_resolved(authorization_ref, tuple(overrides))

    monkeypatch.setattr(
        rehearsal_issuer, "resolve_plan_inputs", _fake_resolve_plan_inputs
    )
    _patch_lookup_chain(monkeypatch, plan_id=uuid4(), target_id=uuid4())

    terms = rehearsal_issuer.derive_rehearsal_issuer_terms(
        db=object(), authorization_ref=str(uuid4()), rendered=_rendered()
    )

    assert terms.authorized_image_digests == ("release-ref-1",)
    assert isinstance(terms.authorized_image_digests, tuple)
    assert len(terms.authorized_image_digests) == 1


def test_the_provenance_mapping_reports_profile_and_execution_plan_as_override(
    monkeypatch,
) -> None:
    """`target`/`desired_state`/`authorized_images` pass through whatever
    `resolved` itself reported; `profile`/`execution_plan` are always
    reported as `"override"` at the outer, C1-facing layer."""

    def _fake_resolve_plan_inputs(db, authorization_ref, *, overrides=()):
        return _fake_resolved(authorization_ref, tuple(overrides))

    monkeypatch.setattr(
        rehearsal_issuer, "resolve_plan_inputs", _fake_resolve_plan_inputs
    )
    _patch_lookup_chain(monkeypatch, plan_id=uuid4(), target_id=uuid4())

    terms = rehearsal_issuer.derive_rehearsal_issuer_terms(
        db=object(), authorization_ref=str(uuid4()), rendered=_rendered()
    )

    assert terms.provenance == {
        "target": "derived",
        "desired_state": "derived",
        "authorized_images": "derived",
        "profile": "override",
        "execution_plan": "override",
    }
    assert terms.declared_overrides == frozenset({"profile", "execution_plan"})


def test_target_id_comes_from_the_same_rollout_then_plan_lookup_chain(
    monkeypatch,
) -> None:
    """`target_id` is read via `read_rollout(...).plan_id` then
    `read_plan(...).target_id` -- the identical chain `resolve_plan_inputs`
    uses internally, reused rather than reinvented."""
    plan_id = uuid4()
    target_id = uuid4()
    captured_rollout_ids: list[object] = []
    captured_plan_ids: list[object] = []

    def _fake_read_rollout(db, rollout_id):
        captured_rollout_ids.append(rollout_id)
        return _FakeRolloutView(plan_id)

    def _fake_read_plan(db, pid):
        captured_plan_ids.append(pid)
        return _FakePlanView(target_id)

    def _fake_resolve_plan_inputs(db, authorization_ref, *, overrides=()):
        return _fake_resolved(authorization_ref, tuple(overrides))

    monkeypatch.setattr(
        rehearsal_issuer, "resolve_plan_inputs", _fake_resolve_plan_inputs
    )
    monkeypatch.setattr(rehearsal_issuer, "read_rollout", _fake_read_rollout)
    monkeypatch.setattr(rehearsal_issuer, "read_plan", _fake_read_plan)

    authorization_ref = str(uuid4())
    terms = rehearsal_issuer.derive_rehearsal_issuer_terms(
        db=object(), authorization_ref=authorization_ref, rendered=_rendered()
    )

    assert terms.target_id == str(target_id)
    assert str(captured_rollout_ids[0]) == authorization_ref
    assert captured_plan_ids == [plan_id]


def test_derived_terms_are_read_only_and_carry_the_authorization_ref_unchanged(
    monkeypatch,
) -> None:
    def _fake_resolve_plan_inputs(db, authorization_ref, *, overrides=()):
        return _fake_resolved(authorization_ref, tuple(overrides))

    monkeypatch.setattr(
        rehearsal_issuer, "resolve_plan_inputs", _fake_resolve_plan_inputs
    )
    _patch_lookup_chain(monkeypatch, plan_id=uuid4(), target_id=uuid4())

    authorization_ref = str(uuid4())
    terms = rehearsal_issuer.derive_rehearsal_issuer_terms(
        db=object(), authorization_ref=authorization_ref, rendered=_rendered()
    )

    assert terms.immutable_reference == authorization_ref
    assert terms.target_ref == "target-ref-1"
    assert terms.desired_state_digest == "7"
