"""`read_drift` must refuse the condition the OWNER signals, not one we invented.

The defect this file exists to prevent, in one sentence: the adapter documented
that a `None` from `dotmac_deployment_control.drift` meant *"the target has no
rollout to compare against"* and refused with a message saying so — and that
condition never fires. Verified against the pinned owner (`0.1.0a6`) rather than
taken second-hand: `drift()` returns `None` when
`db.get(DeploymentTarget, target_id) is None`, and on nothing else.

So a target with no successful rollout got a real report, and the only caller
who ever saw the refusal was one naming a target that did not exist — told
something else entirely. A consumer assigning meaning the owner did not.

**Both directions, because the broken code passed a one-sided test.** Asserting
only that a missing target raises would have been green throughout the defect's
whole life; the assertion that actually bites is the one below it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from dotmac_kernel import NotFoundError
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.deployment import adapter


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _registered(db: Session) -> adapter.TargetView:
    """A target that exists and has never had a rollout — the case the old
    docstring described and the old code never actually produced."""
    return adapter.register_deployment_target(
        db,
        adapter.TargetRegistrationRequest(
            command_id=f"register-{uuid.uuid4()}",
            target_ref=f"vendor-cp-{uuid.uuid4().hex[:8]}",
            subject_ref="dotmac-sub",
            product_code="dotmac-sub",
            environment="production",
        ),
    )


def test_a_target_with_no_rollout_is_reported_not_refused(db: Session) -> None:
    """THE ASSERTION THE DEFECT WOULD HAVE FAILED.

    A registered target that has never been deployed to is a perfectly ordinary
    state, and the owner returns a real report for it. Refusing here would deny
    an operator the read at exactly the moment it is most useful — before the
    first deployment.
    """
    target = _registered(db)
    report = adapter.read_drift(db, target.id)

    assert report.rolled_out_release_ref is None
    assert report.rolled_out_revision is None
    # The owner's own answer to the worry the old docstring raised. `drifted` is
    # False because nothing was rolled out — "Silence is not drift" — and
    # `never_observed` is kept separate so a fresh target is not a drift
    # incident. That is why this adapter now assigns no meaning of its own.
    assert report.drifted is False
    assert report.never_observed is True


def test_a_missing_target_is_refused(db: Session) -> None:
    """The other direction, and the ONLY condition that produces `None`."""
    with pytest.raises(NotFoundError) as refused:
        adapter.read_drift(db, uuid.uuid4())
    assert "does not exist" in str(refused.value)


def test_the_refusal_does_not_describe_a_rollout(db: Session) -> None:
    """The regression guard, pointed at the wrong EXPLANATION rather than at the
    wrong behaviour.

    A future edit could restore the old prose while keeping the correct raise
    condition, and every other assertion here would still pass. What made the
    original defect expensive was the message an operator read, so that is what
    this pins: the refusal describes a missing target and says nothing about
    rollouts or plans.
    """
    with pytest.raises(NotFoundError) as refused:
        adapter.read_drift(db, uuid.uuid4())
    message = str(refused.value).lower()
    assert "rolled-out plan" not in message
    assert "rollout" not in message
    assert "absence of drift" not in message


def test_the_owner_still_returns_none_only_for_a_missing_target(
    db: Session,
) -> None:
    """The premise this whole repair rests on, asserted against the OWNER.

    Every claim above is downstream of `drift()` returning `None` for exactly
    one condition. If a later pin changes that — say it starts returning `None`
    for a target with no rollout after all — this adapter's refusal silently
    acquires a second meaning and the docstring becomes wrong again. Reading the
    owner directly here is what makes that a failure rather than a surprise.
    """
    from dotmac_deployment_control import drift

    target = _registered(db)
    assert drift(db, target.id) is not None
    assert drift(db, uuid.uuid4()) is None
