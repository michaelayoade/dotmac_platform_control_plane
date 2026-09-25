"""Foundation-execution propose/authorize fail closed until Gate 3.

ADR-0013 A6.4 (ratified 2026-09-25) requires every plan input to be DERIVED
from one immutable reference. Under Control 0.1.0a15 a proposal must carry its
operation, descriptor digest and execution-plan digest, and a rollout needs an
authorization expiry and an injected signer. This assembly derives none of them
before Gate 3, so both operator steps refuse with one typed error, before any
Control call and before any database read. Nothing is inferred, defaulted or
taken from the caller.

The protected rehearsal-issuer path supplies its own independently defined
inputs and is proven by the disposable harness, not here.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.cli.exits import ExitCode
from vendor_cp.cli.runtime import translate
from vendor_cp.deployment import adapter
from vendor_cp.deployment.adapter import PlanInputDerivationUnavailable

CODE = "a6_4_derivation_not_available"


class _NoDatabase:
    """A `db` that fails the test on ANY use, proving no read happens first."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the refusal touched the database: db.{name}")


@pytest.fixture
def control_is_never_called(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every Control write command fails the test if it is reached."""
    import dotmac_deployment_control as control

    def _reached(*_: object, **__: object) -> None:
        raise AssertionError("Control was asked; the refusal must come first")

    for name in ("propose_plan", "approve_plan", "request_rollout"):
        monkeypatch.setattr(control, name, _reached)
        if hasattr(adapter, name):
            monkeypatch.setattr(adapter, name, _reached)


@pytest.mark.usefixtures("control_is_never_called")
def test_propose_refuses_before_control_or_the_database() -> None:
    with pytest.raises(PlanInputDerivationUnavailable) as caught:
        adapter.propose_deployment_plan(
            _NoDatabase(),  # type: ignore[arg-type]
            adapter.ProposePlanRequest(
                command_id="propose-1",
                target_id=uuid.uuid4(),
                approval_policy_code="deployment",
                approval_policy_version=1,
            ),
        )
    assert caught.value.code == CODE
    assert "A6.4" in str(caught.value)
    assert "Gate 3" in str(caught.value)


@pytest.mark.usefixtures("control_is_never_called")
def test_authorize_refuses_before_control_or_the_database() -> None:
    with pytest.raises(PlanInputDerivationUnavailable) as caught:
        adapter.authorize_deployment(
            _NoDatabase(),  # type: ignore[arg-type]
            adapter.AuthorizeRequest(
                command_id="authorize-1",
                plan_id=uuid.uuid4(),
                approval_request_id=uuid.uuid4(),
                rollout_ref="rollout-1",
                # An operator-supplied digest changes nothing: there is no
                # caller-supplied route into a Foundation-execution plan.
                expected_plan_digest="sha256:" + "0" * 64,
            ),
        )
    assert caught.value.code == CODE


def test_the_cli_carries_it_out_as_an_absence_not_a_refusal() -> None:
    """Exit 4: nothing refused and the derivation arrives at Gate 3, so the
    same command may succeed later. Exit 3 would tell an operator to stop."""
    verdict = translate(PlanInputDerivationUnavailable("missing"))
    assert verdict.code == "evidence.plan_input_derivation_unavailable"
    assert verdict.exit_code is ExitCode.UNAVAILABLE


# ── non-vacuity: the refusal is scoped, not "everything raises" ────────────


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def test_registration_and_reads_still_reach_control(db: Session) -> None:
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
    assert adapter.read_target(db, target.id).id == target.id
