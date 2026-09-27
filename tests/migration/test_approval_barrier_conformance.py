"""A real-PostgreSQL conformance proof of `approval_barrier.held_transition`.

C2 S1 put `approve_issuer_plan` behind `vendor_cp.deployment.approval_barrier
.held_transition`: it takes Approvals' `hold_platform_approval` (FOR SHARE),
runs Control's `approve_plan` in the SAME transaction while still holding it,
and never commits — the caller's single commit is what releases both the
Approvals row lock and Control's plan-row lock together.

That claim is only provable with a real lock manager, two real sessions and a
real blocking wait — the in-memory SQLite unit suite cannot take a row lock at
all, so this lives here rather than under `tests/unit`. Everything below runs
against a migrated scratch PostgreSQL database, through the real installed
Control 0.1.0a16 and Approvals 0.1.0a8, seeded only through Vendor CP's own
public seams (`propose_issuer_plan`, `open_issuer_approval`,
`vendor_cp.approvals.adapter`) — no hand-inserted rows.

Michael's five acceptance conditions (C2), each landed in its own commit,
T3 and T5 first (the minimum useful commit):

- T3 — a withdrawal attempted while the hold is open times out; released, it
  succeeds; and a third session can then take the Control plan row's lock
  NOWAIT, proving ONE commit released both locks together.
- T5 — SENSITIVITY for T3: plant an intermediate commit inside the hold and
  show the T3 proof itself now fails, so T3 is not vacuously green.
- T1 — the hold and the transition observe the same `txid_current()` and
  `pg_backend_pid()`: one transaction, one connection.
- T2 — no commit fires between the hold and `approve_issuer_plan` returning,
  exactly one after the caller's own commit; while A is paused a peer's
  `FOR UPDATE NOWAIT` on the approval row is refused (55P03) and its
  `FOR SHARE NOWAIT` succeeds, so the lock is really held and really shared.
- T4 — the reverse race: a withdrawal that commits FIRST makes the later
  `approve_issuer_plan` raise `ApprovalNotHeld(WITHDRAWN)`, and the Control
  plan is left unapproved.

Every blocking wait below is bounded (a `lock_timeout`, a NOWAIT probe, a
`Thread.join` timeout) so a real regression here fails fast instead of hanging
CI.
"""

# ruff: noqa: S101

from __future__ import annotations

import sys
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Final
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
    get_target,
    install_rehearsal_issuer_security,
    register_target,
    set_desired_state,
)
from dotmac_deployment_control.models import RehearsalIssuerAuthorizationRecord
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.deployment import approval_barrier
from vendor_cp.deployment.protected_rehearsal_issuer import (
    ProposeIssuerPlan,
    approve_issuer_plan,
    issue_authorization,
    open_issuer_approval,
    propose_issuer_plan,
)
from vendor_cp.deployment.rehearsal_issuer_seam import (
    RehearsalIssuerCommand,
    RehearsalIssuerInvocation,
)
from vendor_cp.migrations import make_alembic_config

#: `rehearsal_issuer_harness` lives outside `src/` and outside `tests/`
#: (pytest's own `testpaths = ["tests"]` in `pyproject.toml`), so this file
#: reaches its disposable Ed25519 signer/verifier classes the same way
#: `tests/architecture/test_rehearsal_issuer_harness_boundary.py` does: a
#: scoped `sys.path` insert around one import, never a permanent path change.
_REPO_ROOT: Final = Path(__file__).resolve().parents[2]

#: The online runtime role, same as `test_platform_relay_drain.py`'s
#: `PLATFORM_ROLE`. `scratch_db` already grants it CONNECT; the module
#: migrations grant it whatever table access it needs. No role question
#: blocked this proof, so nothing here falls back to the migration owner.
PLATFORM_ROLE: Final = "platform_api"

_DESCRIPTOR_DIGEST: Final = "sha256:" + "ab" * 32
_EXECUTION_DIGEST: Final = "sha256:" + "cd" * 32
_POLICY_CODE: Final = "deployment.production"
_POLICY_VERSION: Final = 1
_LOCK_WAIT: Final = 10


# ── the database under test ─────────────────────────────────────────────────


@contextmanager
def _connect(url: str) -> Iterator[object]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


@pytest.fixture
def engine(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Engine]:
    """A migrated scratch database, connected as the real online platform role."""
    command.upgrade(make_alembic_config(scratch_db), "heads")
    with _connect(scratch_db) as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    eng = create_engine(url_for(scratch_db, database, user=PLATFORM_ROLE), future=True)
    yield eng
    eng.dispose()


# ── seeding, through Vendor CP's own public seams only ──────────────────────


def _seed(engine: Engine) -> tuple[uuid.UUID, uuid.UUID]:
    """A real, approved rehearsal-issuer plan: (plan_id, approval_request_id).

    Every row below is written by the real production call chain — Control's
    `register_target`/`set_desired_state`, Vendor CP's own
    `propose_issuer_plan`/`open_issuer_approval`, and the Approvals adapter's
    `publish_policy_version`/`record_decision` — never inserted by hand.
    """
    suffix = uuid.uuid4().hex[:12]
    with Session(engine) as db:
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=uuid.uuid4().hex,
                target_ref=f"approval-barrier-{suffix}",
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


@pytest.fixture
def issuer_security() -> Iterator[tuple[object, object]]:
    """Install disposable, in-process rehearsal-issuer security for exactly
    one test, and uninstall it before the next.

    `install_rehearsal_issuer_security` is process-global, install-once state
    inside Control (a second call without a reset raises `RuntimeError`) --
    exactly the harness's own precondition
    (`rehearsal_issuer_harness/runtime.py::install_disposable_security`).
    Resetting through the private `_reset_rehearsal_issuer_security_for_tests`
    after every test keeps that footprint scoped to this fixture alone: no
    other test in this module, or any other module in this suite, ever
    observes rehearsal-issuer security installed. No secret or real key is
    involved -- the keys are freshly generated, disposable Ed25519 pairs,
    held only in this process's memory for the life of one test.
    """
    from dotmac_deployment_control.rehearsal_issuer_issuance import (
        _reset_rehearsal_issuer_security_for_tests,
    )

    sys.path.insert(0, str(_REPO_ROOT))
    try:
        from rehearsal_issuer_harness.security import (
            AuthorizationSecurity,
            HarnessSecurity,
        )
    finally:
        sys.path.remove(str(_REPO_ROOT))

    authorization = AuthorizationSecurity()
    harness = HarnessSecurity()
    install_rehearsal_issuer_security(
        signer=authorization,
        authorization_verifier=authorization,
        harness_verifier=harness,
        authorization_ttl=timedelta(hours=1),
    )
    try:
        yield authorization, harness
    finally:
        _reset_rehearsal_issuer_security_for_tests()


def _target_ref_for(engine: Engine, plan_id: uuid.UUID) -> str:
    """Look up the plan's own frozen target_ref from Control's read side --
    issuance refuses a harness-evidence `target_ref` that does not match it.
    """
    with Session(engine) as db:
        plan = control.get_plan(db, plan_id)
        assert plan is not None
        target = get_target(db, plan.target_id)
        assert target is not None
    return target.target_ref


def _harness_evidence(
    harness: object, target_ref: str
) -> tuple[str, dict[str, object]]:
    """Build signed harness evidence exactly as
    `rehearsal_issuer_harness/test_issuer.py::_evidence` does."""
    lease_id = f"lease-{uuid.uuid4()}"
    return lease_id, harness.document(lease_id=lease_id, target_ref=target_ref)


def _approve_and_commit(
    engine: Engine, plan_id: uuid.UUID, request_id: uuid.UUID
) -> None:
    """Turn a `seeded` (proposed, decided) plan into an APPROVED one, the
    precondition `issue_authorization` needs (a recorded
    `approval_decision_ref`)."""
    with Session(engine) as db:
        approve_issuer_plan(
            db,
            command_id=f"approve-{uuid.uuid4()}",
            plan_id=plan_id,
            approval_request_id=request_id,
        )
        db.commit()


def _withdraw(db: Session, *, request_id: uuid.UUID, external_ref: str) -> object:
    return dotmac_approvals.withdraw_platform_approval(
        db,
        request_id=request_id,
        actor=Actor(actor_id=uuid.uuid4()),
        authority_ref="ops-ticket-c2",
        reason="C2 conformance proof",
        external_ref=external_ref,
    )


# ── T3 (+ T5 sensitivity) ────────────────────────────────────────────────────


def _prove_the_barrier_holds(
    engine: Engine, plan_id: uuid.UUID, request_id: uuid.UUID
) -> None:
    """Drive session A through the hold with a real pause, and prove:

    - a concurrent withdrawal under a bounded `lock_timeout` blocks and times
      out while A is paused (T3, first half);
    - released, that same withdrawal (retried without a timeout) succeeds
      (T3, second half);
    - a third session can then take `FOR UPDATE NOWAIT` on the Control plan
      row A held, proving A's ONE commit released both locks together
      (T3, third half).

    Every failure here is a plain `assert` (never `pytest.raises`), so that
    T5 can plant a defect and show this exact function fails with
    `AssertionError` — not a different exception shape.
    """
    mutated = threading.Event()
    release = threading.Event()
    approve_result: list[object] = []
    approve_error: list[BaseException] = []
    real_approve_plan = control.approve_plan

    def paused_approve_plan(db: Session, cmd: object) -> object:
        result = real_approve_plan(db, cmd)
        mutated.set()
        release.wait(timeout=_LOCK_WAIT)
        return result

    def run_a() -> None:
        try:
            with (
                Session(engine) as db_a,
                mock.patch.object(control, "approve_plan", paused_approve_plan),
            ):
                result = approve_issuer_plan(
                    db_a,
                    command_id=f"approve-{uuid.uuid4()}",
                    plan_id=plan_id,
                    approval_request_id=request_id,
                )
                db_a.commit()
            approve_result.append(result)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            approve_error.append(exc)

    thread_a = threading.Thread(target=run_a)
    thread_a.start()
    try:
        assert mutated.wait(
            timeout=_LOCK_WAIT
        ), "session A never reached its pause point"

        timed_out = False
        sqlstate: str | None = None
        with Session(engine) as db_b:
            db_b.execute(text("SET LOCAL lock_timeout = '500ms'"))
            try:
                _withdraw(
                    db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
                )
            except OperationalError as exc:
                timed_out = True
                sqlstate = getattr(exc.orig, "sqlstate", None)
            db_b.rollback()
        assert timed_out, "a withdrawal under A's hold did not block at all"
        assert (
            sqlstate == "55P03"
        ), f"expected a lock-timeout SQLSTATE, got {sqlstate!r}"

        # Condition 4, the HELD half: while A is paused after the Control
        # mutation and before its commit, Control's plan row is still locked
        # by A. (The released half is the NOWAIT probe after the commit.)
        plan_sqlstate: str | None = None
        with Session(engine) as db_c:
            try:
                db_c.execute(
                    text(
                        "SELECT id FROM mod_deploy.deployment_plans "
                        "WHERE id = :id FOR UPDATE NOWAIT"
                    ),
                    {"id": plan_id},
                )
            except OperationalError as exc:
                plan_sqlstate = getattr(exc.orig, "sqlstate", None)
            db_c.rollback()
        assert plan_sqlstate == "55P03", (
            "Control's plan row was not locked while A's transaction was open "
            f"(sqlstate {plan_sqlstate!r})"
        )
    finally:
        release.set()
        thread_a.join(timeout=_LOCK_WAIT)

    assert not approve_error, f"session A failed: {approve_error!r}"
    assert approve_result, "session A never returned"

    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    with Session(engine) as db_c:
        row = db_c.execute(
            text(
                "SELECT id FROM mod_deploy.deployment_plans "
                "WHERE id = :id FOR UPDATE NOWAIT"
            ),
            {"id": plan_id},
        ).scalar_one()
        assert row == plan_id
        db_c.rollback()


def test_t3_a_single_commit_releases_the_approvals_lock_and_the_plan_lock_together(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    _prove_the_barrier_holds(engine, plan_id, request_id)


def test_t5_an_intermediate_commit_inside_the_hold_breaks_the_t3_proof(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    """SENSITIVITY for T3. Plant the exact defect `held_transition` exists to
    prevent — the hold committing before the transition runs — by wrapping
    the `hold_platform_approval` name `approval_barrier` resolves. The T3
    proof above must then fail, not pass for the wrong reason.
    """
    plan_id, request_id = seeded
    real_hold = approvals.hold_approval

    def hold_then_commit(db: Session, **kwargs: object) -> object:
        held = real_hold(db, **kwargs)
        db.commit()
        return held

    # The barrier's own post-hold check now catches this at runtime (see
    # `test_t5b_...`). Neutralise that check here so this test measures what it
    # exists to measure: the T3 lock proof ITSELF fails on a planted commit.
    with (
        mock.patch.object(approvals, "hold_approval", hold_then_commit),
        mock.patch.object(
            approval_barrier, "_require_the_hold_is_still_open", lambda _db: None
        ),
    ):
        # Match the SPECIFIC failure: the withdrawal was no longer blocked. Any
        # other AssertionError (e.g. A never reaching its pause) is not the
        # sensitivity this test exists to measure.
        with pytest.raises(AssertionError, match="did not block"):
            _prove_the_barrier_holds(engine, plan_id, request_id)


def test_t5b_the_barrier_refuses_at_runtime_when_the_hold_was_committed(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    """The same planted commit, with the barrier's runtime check live: the
    transaction id the row lock assigned is gone, so `held_transition` refuses
    with `ApprovalBarrierUnavailable`, Control is never asked, and the plan
    stays proposed."""
    plan_id, request_id = seeded
    real_hold = approvals.hold_approval
    approve_calls: list[object] = []
    real_approve_plan = control.approve_plan

    def hold_then_commit(db: Session, **kwargs: object) -> object:
        held = real_hold(db, **kwargs)
        db.commit()
        return held

    def counting_approve_plan(db: Session, cmd: object) -> object:
        approve_calls.append(cmd)
        return real_approve_plan(db, cmd)

    with (
        Session(engine) as db,
        mock.patch.object(approvals, "hold_approval", hold_then_commit),
        mock.patch.object(control, "approve_plan", counting_approve_plan),
    ):
        with pytest.raises(approval_barrier.ApprovalBarrierUnavailable):
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        db.rollback()
    assert approve_calls == []
    with Session(engine) as db_c:
        plan = control.get_plan(db_c, plan_id)
    assert plan is not None
    assert plan.status == "proposed", plan.status


# ── T1 ────────────────────────────────────────────────────────────────────


def test_t1_the_hold_and_the_transition_run_in_the_same_transaction(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    captured: dict[str, tuple[int, int]] = {}
    real_hold = approvals.hold_approval
    real_approve_plan = control.approve_plan

    def observing_hold(db: Session, **kwargs: object) -> object:
        held = real_hold(db, **kwargs)
        row = db.execute(text("SELECT txid_current(), pg_backend_pid()")).one()
        captured["hold"] = (int(row[0]), int(row[1]))
        return held

    def observing_approve_plan(db: Session, cmd: object) -> object:
        result = real_approve_plan(db, cmd)
        row = db.execute(text("SELECT txid_current(), pg_backend_pid()")).one()
        captured["transition"] = (int(row[0]), int(row[1]))
        return result

    with (
        Session(engine) as db,
        mock.patch.object(approvals, "hold_approval", observing_hold),
        mock.patch.object(control, "approve_plan", observing_approve_plan),
    ):
        approve_issuer_plan(
            db,
            command_id=f"approve-{uuid.uuid4()}",
            plan_id=plan_id,
            approval_request_id=request_id,
        )
        db.commit()

    assert captured.keys() == {"hold", "transition"}
    assert captured["hold"] == captured["transition"], (
        "the hold and the transition observed different (txid, pid) pairs — "
        "they did not run in the same transaction on the same connection"
    )


# ── T2 ────────────────────────────────────────────────────────────────────


def test_t2_no_intermediate_commit_and_a_peer_observes_the_row_lock(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    plan_id, request_id = seeded
    commits: list[int] = []
    mutated = threading.Event()
    release = threading.Event()
    approve_result: list[object] = []
    approve_error: list[BaseException] = []
    real_approve_plan = control.approve_plan

    def paused_approve_plan(db: Session, cmd: object) -> object:
        assert not commits, "a commit happened before the transition ran"
        result = real_approve_plan(db, cmd)
        mutated.set()
        release.wait(timeout=_LOCK_WAIT)
        return result

    # Count REAL database COMMITs only. SQLAlchemy's Session `after_commit`
    # also fires when a SAVEPOINT is released (Control's `process_once_platform`
    # uses one), which is not a commit. The engine-level `commit` event fires
    # only for a root transaction's COMMIT. A dedicated engine for session A
    # keeps B's probes out of the count.
    engine_a = create_engine(engine.url, future=True)
    event.listen(engine_a, "commit", lambda _conn: commits.append(1))

    def run_a() -> None:
        try:
            with (
                Session(engine_a) as db_a,
                mock.patch.object(control, "approve_plan", paused_approve_plan),
            ):
                result = approve_issuer_plan(
                    db_a,
                    command_id=f"approve-{uuid.uuid4()}",
                    plan_id=plan_id,
                    approval_request_id=request_id,
                )
                assert (
                    not commits
                ), "approve_issuer_plan committed before returning to its caller"
                db_a.commit()
            approve_result.append(result)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            approve_error.append(exc)

    thread_a = threading.Thread(target=run_a)
    thread_a.start()
    try:
        assert mutated.wait(
            timeout=_LOCK_WAIT
        ), "session A never reached its pause point"

        # An uncontended row lock lives in the tuple header, not in `pg_locks`
        # (only the relation-level RowShareLock appears there, and it is the
        # same for FOR SHARE and FOR UPDATE). So observe it the way PostgreSQL
        # exposes it: an exclusive NOWAIT probe on the exact row must be
        # refused (55P03), while a shared NOWAIT probe succeeds — the lock A
        # holds is SHARE, not UPDATE, and it is really held.
        exclusive_sqlstate: str | None = None
        with Session(engine) as db_b:
            try:
                db_b.execute(
                    text(
                        "SELECT id FROM mod_approvals.platform_approval_requests "
                        "WHERE id = :id FOR UPDATE NOWAIT"
                    ),
                    {"id": request_id},
                )
            except OperationalError as exc:
                exclusive_sqlstate = getattr(exc.orig, "sqlstate", None)
            db_b.rollback()
        assert exclusive_sqlstate == "55P03", (
            "session B could take the approval row FOR UPDATE while A's hold was "
            f"open (sqlstate {exclusive_sqlstate!r}): the hold is not held"
        )
        with Session(engine) as db_b:
            shared = db_b.execute(
                text(
                    "SELECT id FROM mod_approvals.platform_approval_requests "
                    "WHERE id = :id FOR SHARE NOWAIT"
                ),
                {"id": request_id},
            ).scalar_one()
            db_b.rollback()
        assert shared == request_id

        with Session(engine) as db_b:
            relation_lock = db_b.execute(
                text(
                    "SELECT 1 FROM pg_locks "
                    "WHERE locktype = 'relation' AND mode = 'RowShareLock' "
                    "AND relation = "
                    "'mod_approvals.platform_approval_requests'::regclass "
                    "AND granted AND pid <> pg_backend_pid()"
                )
            ).first()
            db_b.rollback()
        assert relation_lock is not None, (
            "no peer session holds a RowShareLock on "
            "mod_approvals.platform_approval_requests while A's hold is open"
        )
    finally:
        release.set()
        thread_a.join(timeout=_LOCK_WAIT)

    assert not approve_error, f"session A failed: {approve_error!r}"
    assert approve_result
    engine_a.dispose()
    assert (
        len(commits) == 1
    ), f"expected exactly one commit after the caller's own commit, got {len(commits)}"


# ── T4 ────────────────────────────────────────────────────────────────────


def test_t4_a_withdrawal_that_commits_first_makes_the_hold_refuse(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    """The reverse ordering of T3: the withdrawal wins the row lock and commits
    before A starts. A's hold must refuse `withdrawn`, Control must never be
    asked to approve, and the plan must still be unapproved afterwards."""
    plan_id, request_id = seeded
    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    approve_calls: list[object] = []
    real_approve_plan = control.approve_plan

    def counting_approve_plan(db: Session, cmd: object) -> object:
        approve_calls.append(cmd)
        return real_approve_plan(db, cmd)

    with (
        Session(engine) as db_a,
        mock.patch.object(control, "approve_plan", counting_approve_plan),
    ):
        with pytest.raises(dotmac_approvals.ApprovalNotHeld) as refused:
            approve_issuer_plan(
                db_a,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        db_a.rollback()
    assert refused.value.code is dotmac_approvals.ApprovalHoldRefusal.WITHDRAWN
    assert approve_calls == [], "Control was asked to approve a withdrawn decision"

    with Session(engine) as db_c:
        plan = control.get_plan(db_c, plan_id)
    assert plan is not None
    assert plan.status == "proposed", plan.status
    assert plan.approval_decision_ref is None


# ── I3 (issuance barrier) ───────────────────────────────────────────────────


def _prove_the_issuance_barrier_holds(
    engine: Engine,
    plan_id: uuid.UUID,
    request_id: uuid.UUID,
    invocation: RehearsalIssuerInvocation,
) -> None:
    """`_prove_the_barrier_holds`'s proof, at `issue_authorization` instead of
    `approve_issuer_plan`: the SAME approval hold, taken at the rollout-
    equivalent site, must block a concurrent withdrawal and a peer's NOWAIT
    probe on Control's plan row while it is open, and release both together
    on session A's single commit.

    Every failure here is a plain `assert`, so a sensitivity test can plant a
    defect and show this exact function fails with `AssertionError`.
    """
    mutated = threading.Event()
    release = threading.Event()
    issue_result: list[object] = []
    issue_error: list[BaseException] = []
    real_issue = control.issue_rehearsal_issuer_authorization_for_plan

    def paused_issue(
        db: Session, request: object, *, harness_evidence_document: object
    ) -> object:
        result = real_issue(
            db, request, harness_evidence_document=harness_evidence_document
        )
        mutated.set()
        release.wait(timeout=_LOCK_WAIT)
        return result

    def run_a() -> None:
        try:
            with (
                Session(engine) as db_a,
                mock.patch.object(
                    control,
                    "issue_rehearsal_issuer_authorization_for_plan",
                    paused_issue,
                ),
            ):
                result = issue_authorization(db_a, invocation)
                db_a.commit()
            issue_result.append(result)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            issue_error.append(exc)

    thread_a = threading.Thread(target=run_a)
    thread_a.start()
    try:
        assert mutated.wait(
            timeout=_LOCK_WAIT
        ), "session A never reached its pause point"

        timed_out = False
        sqlstate: str | None = None
        with Session(engine) as db_b:
            db_b.execute(text("SET LOCAL lock_timeout = '500ms'"))
            try:
                _withdraw(
                    db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
                )
            except OperationalError as exc:
                timed_out = True
                sqlstate = getattr(exc.orig, "sqlstate", None)
            db_b.rollback()
        assert timed_out, "a withdrawal under A's issuance hold did not block at all"
        assert (
            sqlstate == "55P03"
        ), f"expected a lock-timeout SQLSTATE, got {sqlstate!r}"

        plan_sqlstate: str | None = None
        with Session(engine) as db_c:
            try:
                db_c.execute(
                    text(
                        "SELECT id FROM mod_deploy.deployment_plans "
                        "WHERE id = :id FOR UPDATE NOWAIT"
                    ),
                    {"id": plan_id},
                )
            except OperationalError as exc:
                plan_sqlstate = getattr(exc.orig, "sqlstate", None)
            db_c.rollback()
        assert plan_sqlstate == "55P03", (
            "Control's plan row was not locked while A's issuance transaction "
            f"was open (sqlstate {plan_sqlstate!r})"
        )
    finally:
        release.set()
        thread_a.join(timeout=_LOCK_WAIT)

    assert not issue_error, f"session A failed: {issue_error!r}"
    assert issue_result, "session A never returned"

    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN


def test_i3_issuance_holds_the_same_barrier_as_approval(
    seeded: tuple[uuid.UUID, uuid.UUID],
    engine: Engine,
    issuer_security: tuple[object, object],
) -> None:
    plan_id, request_id = seeded
    _approve_and_commit(engine, plan_id, request_id)

    _, harness = issuer_security
    target_ref = _target_ref_for(engine, plan_id)
    _, evidence = _harness_evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(f"issue-{uuid.uuid4()}", plan_id, "operator-rehearsal"),
        evidence,
    )
    _prove_the_issuance_barrier_holds(engine, plan_id, request_id, invocation)


def test_i5_an_intermediate_commit_inside_the_issuance_hold_breaks_the_i3_proof(
    seeded: tuple[uuid.UUID, uuid.UUID],
    engine: Engine,
    issuer_security: tuple[object, object],
) -> None:
    """SENSITIVITY for I3, mirroring T5 at the issuance site: plant the exact
    defect `held_transition` exists to prevent -- the hold committing before
    the transition runs -- by wrapping the `hold_platform_approval` name
    `approval_barrier` resolves. The I3 proof above must then fail, not pass
    for the wrong reason.
    """
    plan_id, request_id = seeded
    _approve_and_commit(engine, plan_id, request_id)

    _, harness = issuer_security
    target_ref = _target_ref_for(engine, plan_id)
    _, evidence = _harness_evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(f"issue-{uuid.uuid4()}", plan_id, "operator-rehearsal"),
        evidence,
    )

    real_hold = approvals.hold_approval

    def hold_then_commit(db: Session, **kwargs: object) -> object:
        held = real_hold(db, **kwargs)
        db.commit()
        return held

    # As in T5: neutralise the barrier's runtime post-hold check so this
    # measures that the I3 lock proof itself fails on a planted commit.
    with (
        mock.patch.object(approvals, "hold_approval", hold_then_commit),
        mock.patch.object(
            approval_barrier, "_require_the_hold_is_still_open", lambda _db: None
        ),
    ):
        # Match the SPECIFIC failure: the withdrawal was no longer blocked.
        # Any other AssertionError (e.g. A never reaching its pause) is not
        # the sensitivity this test exists to measure.
        with pytest.raises(AssertionError, match="did not block"):
            _prove_the_issuance_barrier_holds(engine, plan_id, request_id, invocation)


def test_i1_the_hold_and_the_issuance_run_in_the_same_transaction(
    seeded: tuple[uuid.UUID, uuid.UUID],
    engine: Engine,
    issuer_security: tuple[object, object],
) -> None:
    plan_id, request_id = seeded
    _approve_and_commit(engine, plan_id, request_id)

    _, harness = issuer_security
    target_ref = _target_ref_for(engine, plan_id)
    _, evidence = _harness_evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(f"issue-{uuid.uuid4()}", plan_id, "operator-rehearsal"),
        evidence,
    )

    captured: dict[str, tuple[int, int]] = {}
    real_hold = approvals.hold_approval
    real_issue = control.issue_rehearsal_issuer_authorization_for_plan

    def observing_hold(db: Session, **kwargs: object) -> object:
        held = real_hold(db, **kwargs)
        row = db.execute(text("SELECT txid_current(), pg_backend_pid()")).one()
        captured["hold"] = (int(row[0]), int(row[1]))
        return held

    def observing_issue(
        db: Session, request: object, *, harness_evidence_document: object
    ) -> object:
        result = real_issue(
            db, request, harness_evidence_document=harness_evidence_document
        )
        row = db.execute(text("SELECT txid_current(), pg_backend_pid()")).one()
        captured["transition"] = (int(row[0]), int(row[1]))
        return result

    with (
        Session(engine) as db,
        mock.patch.object(approvals, "hold_approval", observing_hold),
        mock.patch.object(
            control, "issue_rehearsal_issuer_authorization_for_plan", observing_issue
        ),
    ):
        issue_authorization(db, invocation)
        db.commit()

    assert captured.keys() == {"hold", "transition"}
    assert captured["hold"] == captured["transition"], (
        "the hold and the issuance transition observed different (txid, pid) "
        "pairs -- they did not run in the same transaction on the same "
        "connection"
    )


# ── I2 (issuance) ────────────────────────────────────────────────────────


def test_i2_no_intermediate_commit_at_issuance_and_exactly_one_after(
    seeded: tuple[uuid.UUID, uuid.UUID],
    engine: Engine,
    issuer_security: tuple[object, object],
) -> None:
    """T2's proof, at `issue_authorization` instead of `approve_issuer_plan`:
    zero real COMMITs happen between the hold and the caller's own return, and
    exactly one fires after the caller's own commit. A dedicated engine for
    session A keeps session B's probes out of the count, same as T2."""
    plan_id, request_id = seeded
    _approve_and_commit(engine, plan_id, request_id)

    _, harness = issuer_security
    target_ref = _target_ref_for(engine, plan_id)
    _, evidence = _harness_evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(f"issue-{uuid.uuid4()}", plan_id, "operator-rehearsal"),
        evidence,
    )

    commits: list[int] = []
    mutated = threading.Event()
    release = threading.Event()
    issue_result: list[object] = []
    issue_error: list[BaseException] = []
    real_issue = control.issue_rehearsal_issuer_authorization_for_plan

    def paused_issue(
        db: Session, request: object, *, harness_evidence_document: object
    ) -> object:
        assert not commits, "a commit happened before the issuance transition ran"
        result = real_issue(
            db, request, harness_evidence_document=harness_evidence_document
        )
        mutated.set()
        release.wait(timeout=_LOCK_WAIT)
        return result

    engine_a = create_engine(engine.url, future=True)
    event.listen(engine_a, "commit", lambda _conn: commits.append(1))

    def run_a() -> None:
        try:
            with (
                Session(engine_a) as db_a,
                mock.patch.object(
                    control,
                    "issue_rehearsal_issuer_authorization_for_plan",
                    paused_issue,
                ),
            ):
                result = issue_authorization(db_a, invocation)
                assert (
                    not commits
                ), "issue_authorization committed before returning to its caller"
                db_a.commit()
            issue_result.append(result)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            issue_error.append(exc)

    thread_a = threading.Thread(target=run_a)
    thread_a.start()
    try:
        assert mutated.wait(
            timeout=_LOCK_WAIT
        ), "session A never reached its pause point"
    finally:
        release.set()
        thread_a.join(timeout=_LOCK_WAIT)

    assert not issue_error, f"session A failed: {issue_error!r}"
    assert issue_result
    engine_a.dispose()
    assert (
        len(commits) == 1
    ), f"expected exactly one commit after the caller's own commit, got {len(commits)}"


# ── I4 (issuance) ────────────────────────────────────────────────────────


def test_i4_a_withdrawal_that_commits_first_makes_issuance_refuse(
    seeded: tuple[uuid.UUID, uuid.UUID],
    engine: Engine,
    issuer_security: tuple[object, object],
) -> None:
    """T4's proof, at issuance: a withdrawal that commits before
    `issue_authorization` starts must make the hold refuse `withdrawn`,
    Control's issuance entry point must never be called, and Control's issuer
    ledger must gain no new row for this plan."""
    plan_id, request_id = seeded
    _approve_and_commit(engine, plan_id, request_id)

    _, harness = issuer_security
    target_ref = _target_ref_for(engine, plan_id)
    _, evidence = _harness_evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(f"issue-{uuid.uuid4()}", plan_id, "operator-rehearsal"),
        evidence,
    )

    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    issue_calls: list[object] = []
    real_issue = control.issue_rehearsal_issuer_authorization_for_plan

    def counting_issue(
        db: Session, request: object, *, harness_evidence_document: object
    ) -> object:
        issue_calls.append(request)
        return real_issue(
            db, request, harness_evidence_document=harness_evidence_document
        )

    with (
        Session(engine) as db_a,
        mock.patch.object(
            control, "issue_rehearsal_issuer_authorization_for_plan", counting_issue
        ),
    ):
        with pytest.raises(dotmac_approvals.ApprovalNotHeld) as refused:
            issue_authorization(db_a, invocation)
        db_a.rollback()
    assert refused.value.code is dotmac_approvals.ApprovalHoldRefusal.WITHDRAWN
    assert issue_calls == [], "Control was asked to issue on a withdrawn decision"

    with Session(engine) as db_c:
        count = db_c.scalar(
            select(func.count())
            .select_from(RehearsalIssuerAuthorizationRecord)
            .where(RehearsalIssuerAuthorizationRecord.plan_id == plan_id)
        )
    assert count == 0, "issuance created a ledger row despite the withdrawal"


# ── A1 ────────────────────────────────────────────────────────────────────


def test_a1_an_autocommit_session_is_refused_before_any_mutation(
    seeded: tuple[uuid.UUID, uuid.UUID], engine: Engine
) -> None:
    """`held_transition`'s AUTOCOMMIT refusal, exercised at the real
    `approve_issuer_plan` call site against a real connection -- not a unit
    stub of `get_isolation_level()`. A FOR SHARE lock on an AUTOCOMMIT
    connection ends with its own statement, so `_require_transactional` must
    refuse before `hold_approval` (and therefore the transition) ever runs,
    leaving the plan exactly as `seeded` left it.
    """
    plan_id, request_id = seeded
    autocommit_engine = engine.execution_options(isolation_level="AUTOCOMMIT")
    with Session(autocommit_engine) as db:
        with pytest.raises(approval_barrier.ApprovalBarrierUnavailable):
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )

    with Session(engine) as db_c:
        plan = control.get_plan(db_c, plan_id)
    assert plan is not None
    assert plan.status == "proposed", plan.status
    assert plan.approval_decision_ref is None
