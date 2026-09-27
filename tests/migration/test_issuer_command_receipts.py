"""A real-PostgreSQL conformance proof of the D18-C issuer command receipt.

`approve_issuer_plan` and `issue_authorization` take the Approvals hold
(`held_transition`) BEFORE calling Control, so a same-command-id retry of a
COMMITTED command, made after a later withdrawal, was refused as "not held:
withdrawn" with nothing saying the command had committed. `issuer_receipts.py`
is the append-only, non-authorizing fix: a receipt written in the SAME
transaction as Control's call, keyed by command id and request fingerprint,
pointing only at Control's result id — never its signed envelope.

Everything below runs against a migrated scratch database, seeded only through
Vendor CP's own public seams (`propose_issuer_plan`, `open_issuer_approval`,
`approve_issuer_plan`, the Approvals adapter), mirroring
`test_approval_barrier_conformance.py`'s and `test_withdrawal_outcomes_store.py`'s
own fixtures — `tests` is not a package, so the minimal seeding helpers are
copied here rather than imported.

Michael's six required cases, each named below:

- (a) same-ID/different-payload -> `IssuerCommandReused`, Control never called;
- (b) concurrent retries of the identical command -> exactly one receipt row,
  no `IntegrityError` escapes;
- (c) a rollback after Control's call leaves no receipt (and no plan change);
- (d) withdrawal-first: a NEW command id is refused as "not held", no receipt;
- (e) a retry of an already-committed command after withdrawal ->
  `IssuerCommandCommittedButWithdrawn`, naming only command_id/verb/control_ref;
- (f) a planted receipt disagreeing with Control's own result ->
  `IssuerReceiptMismatch`, failing closed.

Plus the append-only triggers, the grants, and the downgrade refusal.
"""

# ruff: noqa: S101

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator
from unittest import mock

import dotmac_approvals
import dotmac_deployment_control as control
import pytest
from alembic import command
from dotmac_approvals import Actor, ApprovalState
from dotmac_deployment_control import (
    DesiredDeployment,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    register_target,
    set_desired_state,
)
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.deployment.issuer_receipts import (
    APPROVE_PLAN,
    IssuerCommandCommittedButWithdrawn,
    IssuerCommandReceipt,
    IssuerCommandReused,
    IssuerReceiptMismatch,
    find_receipt,
    record_receipt,
    request_fingerprint,
)
from vendor_cp.deployment.protected_rehearsal_issuer import (
    ProposeIssuerPlan,
    approve_issuer_plan,
    open_issuer_approval,
    propose_issuer_plan,
)
from vendor_cp.migrations import make_alembic_config

PLATFORM_ROLE = "platform_api"
ADMIN_ROLE = "app_admin"

_DESCRIPTOR_DIGEST = "sha256:" + "ab" * 32
_EXECUTION_DIGEST = "sha256:" + "cd" * 32
_POLICY_CODE = "deployment.production"
_POLICY_VERSION = 1
_LOCK_WAIT = 10


# ── the database under test, and seeding through CP's own public seams ──────


@pytest.fixture
def engine(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Engine]:
    command.upgrade(make_alembic_config(scratch_db), "heads")
    with create_engine(scratch_db).connect() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    eng = create_engine(url_for(scratch_db, database, user=PLATFORM_ROLE), future=True)
    yield eng
    eng.dispose()


@pytest.fixture
def admin_engine(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Engine]:
    with create_engine(scratch_db).connect() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    eng = create_engine(url_for(scratch_db, database, user=ADMIN_ROLE), future=True)
    yield eng
    eng.dispose()


def _seed(engine: Engine) -> tuple[uuid.UUID, uuid.UUID]:
    """A real, proposed-and-decided rehearsal-issuer plan: (plan_id,
    approval_request_id). Every row is written by the real production call
    chain, never inserted by hand -- copied from
    `test_approval_barrier_conformance.py`'s own `_seed`."""
    suffix = uuid.uuid4().hex[:12]
    with Session(engine) as db:
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=uuid.uuid4().hex,
                target_ref=f"issuer-receipt-{suffix}",
                subject_ref=f"subject-{suffix}",
                product_code="dotmac_sub",
                environment="rehearsal",
            ),
        )
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=uuid.uuid4().hex,
                target_id=target.id,
                desired=DesiredDeployment(
                    release_ref="dotmac_sub@rehearsal", spec={"replicas": 1}, images=[]
                ),
            ),
        )
        plan = propose_issuer_plan(
            db,
            ProposeIssuerPlan(
                command_id=uuid.uuid4().hex,
                target_id=target.id,
                descriptor_digest=_DESCRIPTOR_DIGEST,
                execution_plan_digest=_EXECUTION_DIGEST,
                approval_policy_code=_POLICY_CODE,
                approval_policy_version=_POLICY_VERSION,
            ),
        )
        approvals.publish_policy_version(
            db,
            approvals.PublishPolicyCommand(
                command_id=uuid.uuid4().hex,
                policy_code=_POLICY_CODE,
                version=_POLICY_VERSION,
                quorum=1,
                allow_self_approval=False,
            ),
        )
        opened = open_issuer_approval(
            db,
            command_id=uuid.uuid4().hex,
            plan_id=plan.id,
            requested_by=uuid.uuid4(),
        )
        approvals.record_decision(
            db,
            approvals.RecordDecisionCommand(
                command_id=uuid.uuid4().hex,
                request_id=opened.request_id,
                approver_id=uuid.uuid4(),
                content_hash=bare_content_hash(plan.plan_digest),
            ),
        )
        db.commit()
    return plan.id, opened.request_id


@pytest.fixture
def seeded(engine: Engine) -> tuple[uuid.UUID, uuid.UUID]:
    return _seed(engine)


def _withdraw(db: Session, *, request_id: uuid.UUID, external_ref: str) -> object:
    return dotmac_approvals.withdraw_platform_approval(
        db,
        request_id=request_id,
        actor=Actor(actor_id=uuid.uuid4()),
        authority_ref="ops-ticket-d18c",
        reason="D18-C conformance proof",
        external_ref=external_ref,
    )


# ── (a) same-ID/different-payload gives IssuerCommandReused ─────────────────


def test_a_same_command_id_with_a_different_payload_is_refused_before_control(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    command_id = f"approve-{uuid.uuid4()}"
    with Session(engine) as db:
        approve_issuer_plan(
            db, command_id=command_id, plan_id=plan_id, approval_request_id=request_id
        )
        db.commit()

    approve_calls: list[object] = []
    real_approve_plan = control.approve_plan

    def counting_approve_plan(db: Session, cmd: object) -> object:
        approve_calls.append(cmd)
        return real_approve_plan(db, cmd)

    with (
        Session(engine) as db,
        mock.patch.object(control, "approve_plan", counting_approve_plan),
    ):
        with pytest.raises(IssuerCommandReused):
            approve_issuer_plan(
                db,
                command_id=command_id,
                plan_id=plan_id,
                approval_request_id=request_id,
                expected_plan_version=999,
            )
        db.rollback()
    assert approve_calls == [], "Control was called for a reused command id"


# ── (b) concurrent retries produce exactly one receipt ───────────────────────


def test_b_concurrent_retries_of_the_identical_command_leave_one_receipt(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    command_id = f"approve-{uuid.uuid4()}"
    fingerprint = request_fingerprint(
        APPROVE_PLAN,
        {
            "command_id": command_id,
            "plan_id": plan_id,
            "approval_request_id": request_id,
            "expected_plan_version": None,
            "actor_ref": None,
        },
    )
    control_ref = str(plan_id)

    ready = threading.Event()
    proceed = threading.Event()
    results: list[IssuerCommandReceipt] = []
    errors: list[BaseException] = []

    def run_a() -> None:
        try:
            with Session(engine) as db:
                row = record_receipt(
                    db,
                    command_id=command_id,
                    verb=APPROVE_PLAN,
                    fingerprint=fingerprint,
                    plan_id=plan_id,
                    approval_request_id=request_id,
                    control_ref=control_ref,
                )
                ready.set()
                proceed.wait(timeout=_LOCK_WAIT)
                db.commit()
            results.append(row)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            errors.append(exc)

    def run_b() -> None:
        try:
            assert ready.wait(timeout=_LOCK_WAIT), "A never reached its pause point"
            # B's INSERT blocks on A's uncommitted, still-open unique-index
            # entry until A resolves, then either succeeds (A rolled back) or
            # collides (A committed) -- exactly the real concurrent-retry race.
            with Session(engine) as db:
                row = record_receipt(
                    db,
                    command_id=command_id,
                    verb=APPROVE_PLAN,
                    fingerprint=fingerprint,
                    plan_id=plan_id,
                    approval_request_id=request_id,
                    control_ref=control_ref,
                )
                db.commit()
            results.append(row)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            errors.append(exc)

    thread_a = threading.Thread(target=run_a)
    thread_b = threading.Thread(target=run_b)
    thread_a.start()
    thread_b.start()
    try:
        assert ready.wait(timeout=_LOCK_WAIT), "session A never reached its pause point"
    finally:
        proceed.set()
        thread_a.join(timeout=_LOCK_WAIT)
        thread_b.join(timeout=_LOCK_WAIT)

    assert not errors, f"a concurrent retry raised unexpectedly: {errors!r}"
    assert len(results) == 2
    assert results[0].id == results[1].id, "the two retries did not converge on one row"

    with Session(engine) as db:
        count = db.scalar(
            select(func.count())
            .select_from(IssuerCommandReceipt)
            .where(IssuerCommandReceipt.command_id == command_id)
        )
    assert count == 1


# ── (c) a rollback after Control leaves no receipt ───────────────────────────


def test_c_a_rollback_after_control_leaves_no_receipt_and_no_plan_change(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    command_id = f"approve-{uuid.uuid4()}"
    with Session(engine) as db:
        approve_issuer_plan(
            db, command_id=command_id, plan_id=plan_id, approval_request_id=request_id
        )
        db.rollback()

    with Session(engine) as db:
        assert find_receipt(db, command_id) is None
        plan = control.get_plan(db, plan_id)
    assert plan is not None
    assert plan.status == "proposed", plan.status
    assert plan.approval_decision_ref is None


# ── (d) withdrawal-first: a NEW command id refuses, no receipt ──────────────


def test_d_withdrawal_first_refuses_a_new_command_and_writes_no_receipt(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    with Session(engine) as db:
        outcome = _withdraw(
            db, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    new_command_id = f"approve-{uuid.uuid4()}"
    with Session(engine) as db:
        with pytest.raises(dotmac_approvals.ApprovalNotHeld) as refused:
            approve_issuer_plan(
                db,
                command_id=new_command_id,
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        db.rollback()
    assert refused.value.code is dotmac_approvals.ApprovalHoldRefusal.WITHDRAWN

    with Session(engine) as db:
        assert find_receipt(db, new_command_id) is None


# ── (e) a retry of a committed command, after withdrawal, reports the commit ─


def test_e_a_retry_after_withdrawal_reports_the_commit_without_the_envelope(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    command_id = f"approve-{uuid.uuid4()}"
    with Session(engine) as db:
        approve_issuer_plan(
            db, command_id=command_id, plan_id=plan_id, approval_request_id=request_id
        )
        db.commit()

    with Session(engine) as db:
        outcome = _withdraw(
            db, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    with Session(engine) as db:
        with pytest.raises(IssuerCommandCommittedButWithdrawn) as refused:
            approve_issuer_plan(
                db,
                command_id=command_id,
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        db.rollback()

    exc = refused.value
    assert exc.command_id == command_id
    assert exc.verb == APPROVE_PLAN
    assert exc.control_ref == str(plan_id)
    # ONLY these three fields -- never Control's signed envelope or any other
    # result field.
    assert vars(exc) == {
        "command_id": command_id,
        "verb": APPROVE_PLAN,
        "control_ref": str(plan_id),
    }
    assert exc.args == (str(exc),)


# ── (f) a planted receipt disagreeing with Control fails closed ─────────────


def test_f_a_journal_control_mismatch_fails_closed(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    command_id = f"approve-{uuid.uuid4()}"
    fingerprint = request_fingerprint(
        APPROVE_PLAN,
        {
            "command_id": command_id,
            "plan_id": plan_id,
            "approval_request_id": request_id,
            "expected_plan_version": None,
            "actor_ref": None,
        },
    )
    # Planted as `platform_api` -- `engine` connects as that role, matching
    # the grant this migration gives it.
    with Session(engine) as db:
        db.add(
            IssuerCommandReceipt(
                command_id=command_id,
                verb=APPROVE_PLAN,
                request_fingerprint=fingerprint,
                plan_id=plan_id,
                approval_request_id=request_id,
                control_ref=str(uuid.uuid4()),  # deliberately wrong
            )
        )
        db.commit()

    with Session(engine) as db:
        with pytest.raises(IssuerReceiptMismatch):
            approve_issuer_plan(
                db,
                command_id=command_id,
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        db.rollback()

    with Session(engine) as db:
        plan = control.get_plan(db, plan_id)
    assert plan is not None
    assert plan.status == "proposed", plan.status
    assert plan.approval_decision_ref is None


# ── append-only triggers and grants ──────────────────────────────────────────


def test_app_admin_cannot_update_delete_or_truncate_the_receipts_table(
    engine: Engine, admin_engine: Engine
) -> None:
    with Session(engine) as db:
        row = record_receipt(
            db,
            command_id=f"approve-{uuid.uuid4()}",
            verb=APPROVE_PLAN,
            fingerprint="sha256:" + "11" * 32,
            plan_id=uuid.uuid4(),
            approval_request_id=uuid.uuid4(),
            control_ref=str(uuid.uuid4()),
        )
        db.commit()

    with admin_engine.connect() as conn:
        with pytest.raises(ProgrammingError, match="append-only"):
            conn.execute(
                text(
                    "UPDATE issuer_command_receipts SET control_ref = 'x' "
                    "WHERE id = :id"
                ),
                {"id": row.id},
            )
        conn.rollback()
        with pytest.raises(ProgrammingError, match="append-only"):
            conn.execute(
                text("DELETE FROM issuer_command_receipts WHERE id = :id"),
                {"id": row.id},
            )
        conn.rollback()
        with pytest.raises(ProgrammingError, match="append-only"):
            conn.execute(text("TRUNCATE issuer_command_receipts"))
        conn.rollback()


def test_platform_api_gets_permission_denied_on_update_or_delete(
    engine: Engine,
) -> None:
    with Session(engine) as db:
        row = record_receipt(
            db,
            command_id=f"approve-{uuid.uuid4()}",
            verb=APPROVE_PLAN,
            fingerprint="sha256:" + "22" * 32,
            plan_id=uuid.uuid4(),
            approval_request_id=uuid.uuid4(),
            control_ref=str(uuid.uuid4()),
        )
        db.commit()

    with engine.connect() as conn:
        with pytest.raises(ProgrammingError, match="permission denied"):
            conn.execute(
                text(
                    "UPDATE issuer_command_receipts SET control_ref = 'x' "
                    "WHERE id = :id"
                ),
                {"id": row.id},
            )
        conn.rollback()
        with pytest.raises(ProgrammingError, match="permission denied"):
            conn.execute(
                text("DELETE FROM issuer_command_receipts WHERE id = :id"),
                {"id": row.id},
            )
        conn.rollback()


# ── downgrade refusal ─────────────────────────────────────────────────────


def test_downgrade_is_refused_while_receipt_rows_remain(
    engine: Engine, scratch_db: str
) -> None:
    with Session(engine) as db:
        record_receipt(
            db,
            command_id=f"approve-{uuid.uuid4()}",
            verb=APPROVE_PLAN,
            fingerprint="sha256:" + "33" * 32,
            plan_id=uuid.uuid4(),
            approval_request_id=uuid.uuid4(),
            control_ref=str(uuid.uuid4()),
        )
        db.commit()

    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        command.downgrade(make_alembic_config(scratch_db), "v020_withdrawal_outcomes")
