"""D18-D: real-PostgreSQL proof, an approval withdrawal invalidates an
issued-but-unconsumed rehearsal-issuer authorization.

Control owns the refusal (`RehearsalIssuerIssuanceRefusedError`); CP's own
issuance receipts are the index of what CP itself issued
(`issuer_receipts.issued_authorization_refs`); a completed (spent)
authorization stays history, untouched, by name.

Stated plainly (scenario 3): when a caller bypasses CP's barrier entirely and
calls Control's `stage_rehearsal_issuer_consumption` directly, Control refuses
on the PLAN's no-longer-standing approval (`APPROVAL_NOT_STANDING`) -- this
check runs BEFORE Control ever re-checks the authorization row's own revoked
state. The authorization ledger's `REVOKED` state (proved via
`_authorization_row` in every scenario here) is therefore defence in depth,
not the primary barrier: even if the ledger row had not yet been marked
revoked, `APPROVAL_NOT_STANDING` alone would already refuse the consumption.

The seeding, issuance, harness-evidence and drain helpers below are copied,
not imported (`tests` is not a package): `migrated`/`_connect`/`_sessions`/
`_composition`/`_withdrawal_rows`/`_withdraw`/`_propose_issuer`/
`issuer_security`/`_target_ref_for`/`_harness_evidence` mirror
`test_withdrawal_convergence.py`, which itself mirrors
`test_approval_barrier_conformance.py`.
"""

# ruff: noqa: S101

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Final
from unittest import mock

import dotmac_deployment_control as control
import pytest
from alembic import command
from dotmac_deployment_control import (
    DesiredDeployment,
    RegisterTargetCommand,
    RehearsalIssuerIssuanceRefusalCode,
    RehearsalIssuerIssuanceRefusedError,
    SetDesiredStateCommand,
    get_target,
    install_rehearsal_issuer_security,
    register_target,
    set_desired_state,
)
from dotmac_deployment_control.models import (
    RehearsalIssuerAuthorizationRecord,
    RehearsalIssuerAuthorizationState,
)
from dotmac_kernel.messaging import (
    ClaimedPlatformEvent,
    OutboxStatus,
    PlatformOutboxEvent,
)
from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.deployment.protected_rehearsal_issuer import (
    AuthorizationPlanMismatch,
    ProposeIssuerPlan,
    approve_issuer_plan,
    consume_authorization,
    issue_authorization,
    open_issuer_approval,
    propose_issuer_plan,
)
from vendor_cp.deployment.rehearsal_issuer_seam import (
    RehearsalIssuerCommand,
    RehearsalIssuerInvocation,
)
from vendor_cp.migrations import make_alembic_config
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.relay.approval_router import ApprovalEventRouter
from vendor_cp.relay.runner import PlatformEventConsumers, RelayComposition, drain_once
from vendor_cp.relay.withdrawal_outcomes import (
    WithdrawalDisposition,
    outcomes_for_event,
)

PRODUCT = "dotmac-sub"
CAPABILITIES = ("cap.a", "cap.b")
DISPATCHER_ROLE = "platform_outbox_dispatcher"
PLATFORM_ROLE = "platform_api"
ISSUER_DESCRIPTOR_DIGEST = "sha256:" + "ab" * 32
ISSUER_EXECUTION_DIGEST = "sha256:" + "cd" * 32
ISSUER_POLICY_CODE = "deployment.withdrawal-revokes-authorizations"
ISSUER_POLICY_VERSION = 1

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]

#: A bounded `Thread.join` wait, matching `test_withdrawal_convergence.py`.
_LOCK_WAIT: Final = 10


@pytest.fixture
def migrated(scratch_db: str, url_for: Callable[..., str]) -> Iterator[tuple[str, str]]:
    command.upgrade(make_alembic_config(scratch_db), "heads")
    with _connect(scratch_db) as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(
            text(f'GRANT CONNECT ON DATABASE "{database}" TO {DISPATCHER_ROLE}')
        )
        conn.commit()
    yield (
        url_for(scratch_db, database, user=PLATFORM_ROLE),
        url_for(scratch_db, database, user=DISPATCHER_ROLE),
    )


@contextmanager
def _connect(url: str) -> Iterator[object]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


@contextmanager
def _sessions(url: str) -> Iterator[DatabaseRuntime]:
    runtime = DatabaseRuntime.from_urls(database_url=url, platform_database_url=url)
    try:
        yield runtime
    finally:
        runtime.platform_engine.dispose()
        runtime.engine.dispose()


def _catalogue() -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({PRODUCT: CAPABILITIES})


class _FixedCatalogueConsumer(ContractEventConsumer):
    def _catalogues(self, platform_db: Session) -> ProductCapabilityCatalogues:
        return _catalogue()


def _composition(dispatcher_url: str, platform: DatabaseRuntime) -> RelayComposition:
    dispatcher = DatabaseRuntime.from_urls(
        database_url=dispatcher_url,
        platform_database_url=dispatcher_url,
        pool_size=1,
        max_overflow=0,
        platform_pool_size=1,
        platform_max_overflow=0,
    )
    return RelayComposition(
        dispatcher_sessions=dispatcher.platform_session_factory,
        delivery_sessions=platform.platform_session_factory,
        transport=PlatformEventConsumers(
            contracts=_FixedCatalogueConsumer(), approvals=ApprovalEventRouter()
        ),
    )


def _withdrawal_rows(db: Session) -> list[PlatformOutboxEvent]:
    return list(
        db.execute(
            select(PlatformOutboxEvent)
            .where(PlatformOutboxEvent.event_type == "approval.withdrawn")
            .order_by(PlatformOutboxEvent.created_at)
        ).scalars()
    )


def _withdraw(
    db: Session, *, request_id: uuid.UUID, actor_id: uuid.UUID | None = None
) -> object:
    """The real operator path (F-C2, D18-A) — never the bare module call."""
    return approvals.withdraw_request(
        db,
        approvals.WithdrawRequestCommand(
            request_id=request_id,
            actor_id=actor_id or uuid.uuid4(),
            authority_ref="ops-ticket-d18d",
            reason="D18-D authorization-revocation proof",
            external_ref=f"withdraw-{uuid.uuid4()}",
        ),
    )


def _propose_issuer(db: Session, *, suffix: str) -> tuple[uuid.UUID, uuid.UUID, str]:
    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=uuid.uuid4().hex,
            target_ref=f"withdrawal-revokes-{suffix}",
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
            descriptor_digest=ISSUER_DESCRIPTOR_DIGEST,
            execution_plan_digest=ISSUER_EXECUTION_DIGEST,
            approval_policy_code=ISSUER_POLICY_CODE,
            approval_policy_version=ISSUER_POLICY_VERSION,
        ),
    )
    # A STABLE command_id, not `uuid.uuid4().hex`: `publish_policy_version` is
    # "idempotent by command id" (its own docstring) via
    # `process_once_platform`, which REPLAYS a duplicate command id rather
    # than re-executing it. `ISSUER_POLICY_CODE`/`ISSUER_POLICY_VERSION` are
    # module-level constants shared by every plan this helper proposes, so a
    # test proposing a SECOND plan in the same database (e.g. a P1/P2
    # scenario) must reuse this exact id to replay the first publish rather
    # than attempt a second one -- policy revisions are immutable, and a
    # fresh random id here would hit `PolicyVersionExists` on the second call.
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"publish-{ISSUER_POLICY_CODE}-v{ISSUER_POLICY_VERSION}",
            policy_code=ISSUER_POLICY_CODE,
            version=ISSUER_POLICY_VERSION,
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
    return plan.id, opened.request_id, plan.plan_digest


@pytest.fixture
def issuer_security() -> Iterator[tuple[object, object]]:
    """Copied from `test_withdrawal_convergence.py` / `test_approval_barrier_
    conformance.py` — see either module's own fixture for the full rationale."""
    import sys

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


def _target_ref_for(db: Session, plan_id: uuid.UUID) -> str:
    plan = control.get_plan(db, plan_id)
    assert plan is not None
    target = get_target(db, plan.target_id)
    assert target is not None
    return target.target_ref


def _harness_evidence(harness: object, target_ref: str) -> dict[str, object]:
    lease_id = f"lease-{uuid.uuid4()}"
    return harness.document(lease_id=lease_id, target_ref=target_ref)


def _consumption_evidence(
    harness: object, target_ref: str, issued: object
) -> dict[str, object]:
    """Fresh harness evidence for CONSUMING `issued`: the SAME lease the
    authorization binds (a different lease is refused as
    `LEASE_MISMATCH`/`ENVELOPE_MISMATCH` before any standing or state
    check), with a later `issued_at` than the issuance evidence (an
    identical or older one is `STALE_HARNESS_EVIDENCE`)."""
    return harness.document(lease_id=issued.statement.lease_id, target_ref=target_ref)


def _authorization_row(
    db: Session, authorization_id: str
) -> RehearsalIssuerAuthorizationRecord:
    return db.execute(
        select(RehearsalIssuerAuthorizationRecord).where(
            RehearsalIssuerAuthorizationRecord.authorization_id == authorization_id
        )
    ).scalar_one()


def _issue(
    db: Session, harness: object, plan_id: uuid.UUID, *, command_id: str
) -> object:
    """Issue one authorization for `plan_id` and return Control's parsed
    envelope (`.as_mapping()`/`.statement.authorization_id`)."""
    target_ref = _target_ref_for(db, plan_id)
    evidence = _harness_evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(command_id, plan_id, "operator-rehearsal"), evidence
    )
    return issue_authorization(db, invocation)


# ── 1: issued, withdrawn, drained, revoked ───────────────────────────────────


def test_issued_withdrawn_drained_revoked(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-1")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            issued = _issue(db, harness, plan_id, command_id=f"issue-{uuid.uuid4()}")
            authorization_id = issued.statement.authorization_id

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)

        drain_once(
            worker_id="d18d-scenario-1",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id

            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.REVOKED.value
            assert record.revocation_ref == f"approval.withdrawn:{event_id}"
            assert record.revoked_at is not None
            assert record.spent_at is None

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.APPLIED
            assert outcome.evidence["authorizations_revoked"] == [authorization_id]
            assert outcome.evidence["authorizations_not_revocable"] == []


# ── 2: later use refused through CP (the barrier) ────────────────────────────


def test_later_use_refused_through_cp_barrier(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    from vendor_cp.approvals.adapter import ApprovalHoldRefusal, ApprovalNotHeld

    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-2")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            issued = _issue(db, harness, plan_id, command_id=f"issue-{uuid.uuid4()}")
            authorization_document = issued.as_mapping()

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)
        drain_once(
            worker_id="d18d-scenario-2",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            target_ref = _target_ref_for(db, plan_id)
            fresh_evidence = _consumption_evidence(harness, target_ref, issued)
            with pytest.raises(ApprovalNotHeld) as refused:
                consume_authorization(
                    db,
                    plan_id=plan_id,
                    authorization_document=authorization_document,
                    harness_evidence_document=fresh_evidence,
                )
            db.rollback()
        assert refused.value.code is ApprovalHoldRefusal.WITHDRAWN


# ── 3: later use refused by Control's OWN authority, bypassing the barrier ──


def test_later_use_refused_by_controls_own_authority_bypassing_the_barrier(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-3")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            issued = _issue(db, harness, plan_id, command_id=f"issue-{uuid.uuid4()}")
            authorization_document = issued.as_mapping()
            authorization_id = issued.statement.authorization_id

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)
        drain_once(
            worker_id="d18d-scenario-3",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            target_ref = _target_ref_for(db, plan_id)
            fresh_evidence = _consumption_evidence(harness, target_ref, issued)
            # Direct call to Control's own entry point -- no held_transition,
            # no CP barrier at all. Pinned: `_standing_plan_terms` refuses the
            # plan's no-longer-standing approval BEFORE Control ever re-checks
            # the authorization row's own revoked state (lines 682-835 of
            # dotmac_deployment_control's rehearsal_issuer_issuance.py, Control
            # a16).
            with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
                control.stage_rehearsal_issuer_consumption(
                    db,
                    authorization_document=authorization_document,
                    harness_evidence_document=fresh_evidence,
                )
            db.rollback()
        assert (
            refused.value.code
            is RehearsalIssuerIssuanceRefusalCode.APPROVAL_NOT_STANDING
        )

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.REVOKED.value


# ── 4: a completed action is preserved as history ────────────────────────────


def test_a_completed_action_is_preserved_as_history(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-4")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            issued = _issue(db, harness, plan_id, command_id=f"issue-{uuid.uuid4()}")
            authorization_document = issued.as_mapping()
            authorization_id = issued.statement.authorization_id

        with platform.platform_session() as db:
            target_ref = _target_ref_for(db, plan_id)
            consumption_evidence = _consumption_evidence(harness, target_ref, issued)
            consume_authorization(
                db,
                plan_id=plan_id,
                authorization_document=authorization_document,
                harness_evidence_document=consumption_evidence,
            )

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.SPENT.value
            spent_at = record.spent_at
            assert spent_at is not None

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)
        drain_once(
            worker_id="d18d-scenario-4",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            event_id = row.id

            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.SPENT.value
            assert record.spent_at == spent_at
            assert record.revocation_ref is None

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.APPLIED
            assert outcome.evidence["authorizations_revoked"] == []
            assert outcome.evidence["authorizations_not_revocable"] == [
                authorization_id
            ]


# ── 5: a consumption in flight versus a withdrawal (a genuine race) ─────────


def test_a_consumption_in_flight_versus_a_withdrawal_is_a_genuine_race(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        engine = platform.platform_engine
        with Session(engine) as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-5")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
            db.commit()
        with Session(engine) as db:
            issued = _issue(db, harness, plan_id, command_id=f"issue-{uuid.uuid4()}")
            db.commit()
            authorization_document = issued.as_mapping()
            authorization_id = issued.statement.authorization_id

        with Session(engine) as db:
            target_ref = _target_ref_for(db, plan_id)
        consumption_evidence = _consumption_evidence(harness, target_ref, issued)

        mutated = threading.Event()
        release = threading.Event()
        consume_result: list[object] = []
        consume_error: list[BaseException] = []
        real_stage = control.stage_rehearsal_issuer_consumption

        def paused_stage(db: Session, **kwargs: object) -> object:
            result = real_stage(db, **kwargs)
            mutated.set()
            release.wait(timeout=_LOCK_WAIT)
            return result

        def run_consume() -> None:
            try:
                with (
                    Session(engine) as db_c,
                    mock.patch.object(
                        control, "stage_rehearsal_issuer_consumption", paused_stage
                    ),
                ):
                    result = consume_authorization(
                        db_c,
                        plan_id=plan_id,
                        authorization_document=authorization_document,
                        harness_evidence_document=consumption_evidence,
                    )
                    db_c.commit()
                consume_result.append(result)
            except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
                consume_error.append(exc)

        thread_c = threading.Thread(target=run_consume)
        thread_c.start()
        try:
            assert mutated.wait(
                timeout=_LOCK_WAIT
            ), "consumption never reached its pause point"

            timed_out = False
            sqlstate: str | None = None
            with Session(engine) as db_w:
                db_w.execute(text("SET LOCAL lock_timeout = '500ms'"))
                try:
                    _withdraw(db_w, request_id=request_id)
                except OperationalError as exc:
                    timed_out = True
                    sqlstate = getattr(exc.orig, "sqlstate", None)
                db_w.rollback()
            assert timed_out, "a withdrawal did not block on the in-flight consumption"
            assert (
                sqlstate == "55P03"
            ), f"expected a lock-timeout SQLSTATE, got {sqlstate!r}"
        finally:
            release.set()
            thread_c.join(timeout=_LOCK_WAIT)

        assert not consume_error, f"consumption failed: {consume_error!r}"
        assert consume_result, "consumption never returned"

        with Session(engine) as db_w:
            _withdraw(db_w, request_id=request_id)
            db_w.commit()

        drain_once(
            worker_id="d18d-scenario-5",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            event_id = row.id

            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.SPENT.value

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.APPLIED
            assert outcome.evidence["authorizations_revoked"] == []
            assert outcome.evidence["authorizations_not_revocable"] == [
                authorization_id
            ]


# ── 6: replay ─────────────────────────────────────────────────────────────


def test_a_replayed_delivery_is_a_no_op_and_does_not_call_control_revoke_again(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-6")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            issued = _issue(db, harness, plan_id, command_id=f"issue-{uuid.uuid4()}")
            authorization_id = issued.statement.authorization_id

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)

        drain_once(
            worker_id="d18d-scenario-6",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id
            claimed = ClaimedPlatformEvent(
                id=row.id,
                event_type=row.event_type,
                payload=dict(row.payload),
                attempts=row.attempts,
                correlation_id=row.correlation_id,
            )
            outcomes_before = outcomes_for_event(db, event_id)
            assert len(outcomes_before) == 1

            # The identical claimed event, delivered directly through the
            # router a second time -- the same shape
            # `test_a_replayed_delivery_after_settlement_is_a_no_op`
            # (test_withdrawal_convergence.py) uses for the agreement subject.
            # Wrapping (not stubbing) Control's own
            # `revoke_rehearsal_issuer_authorization` proves the replay never
            # reaches Control's revocation at all -- `call_count == 0`.
            real_revoke = control.revoke_rehearsal_issuer_authorization
            with mock.patch.object(
                control, "revoke_rehearsal_issuer_authorization", wraps=real_revoke
            ) as spy:
                ApprovalEventRouter().deliver(claimed, db)
                db.commit()
            assert spy.call_count == 0, "a settled replay must not call Control again"

        with platform.platform_session() as db:
            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1, "the replay must not add a second outcome row"

            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.REVOKED.value


# ── 7: consumption binds to the DOCUMENT's own plan, not the caller's ───────


def test_consuming_a_withdrawn_plans_authorization_under_a_different_plan_id_is_refused(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    """Fix 1: P1 is approved and standing. P2 is approved, issued, withdrawn
    but NOT YET DRAINED (still ISSUED in Control's own ledger). A caller
    presenting P2's authorization document under `plan_id=P1` must be refused
    by `AuthorizationPlanMismatch` before any hold or Control call -- P1's
    standing hold must never authorize spending P2's authority -- and P2's
    authorization must stay ISSUED, untouched.

    Positive control (round-2 correction): with P2's OWN document, fresh P2
    evidence, and `plan_id=P2` (not P1), a direct call to Control's own
    `stage_rehearsal_issuer_consumption` -- bypassing CP's plan-match check
    and barrier entirely -- SUCCEEDS in this window (run inside a SAVEPOINT
    and rolled back). This proves the plan-mismatch check above is the ONLY
    thing refusing the P1 case: P2's document, evidence and ledger row were
    never otherwise unconsumable.

    Draining the outstanding withdrawal afterwards still revokes P2's
    authorization."""
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id_1, request_id_1, _digest_1 = _propose_issuer(db, suffix="d18d-7-p1")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id_1,
                approval_request_id=request_id_1,
            )
        with platform.platform_session() as db:
            plan_id_2, request_id_2, _digest_2 = _propose_issuer(db, suffix="d18d-7-p2")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id_2,
                approval_request_id=request_id_2,
            )
        with platform.platform_session() as db:
            issued_2 = _issue(
                db, harness, plan_id_2, command_id=f"issue-{uuid.uuid4()}"
            )
            authorization_document_2 = issued_2.as_mapping()
            authorization_id_2 = issued_2.statement.authorization_id

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id_2)
        # Deliberately NOT drained yet: P2's authorization is still ISSUED in
        # Control's own ledger at this point.

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id_2)
            assert record.state == RehearsalIssuerAuthorizationState.ISSUED.value

            target_ref_2 = _target_ref_for(db, plan_id_2)
            fresh_evidence = _consumption_evidence(harness, target_ref_2, issued_2)
            with pytest.raises(AuthorizationPlanMismatch) as excinfo:
                consume_authorization(
                    db,
                    plan_id=plan_id_1,
                    authorization_document=authorization_document_2,
                    harness_evidence_document=fresh_evidence,
                )
            db.rollback()
        assert excinfo.value.plan_id == plan_id_1
        assert excinfo.value.document_plan_ref == str(plan_id_2)

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id_2)
            assert record.state == RehearsalIssuerAuthorizationState.ISSUED.value

        # Positive control: P2's OWN document under `plan_id=P2` would have
        # been consumable -- proving fix 1's refusal in the P1 case above is
        # the plan-match check, not some other reason P2's authority happens
        # to be unusable. Inside a SAVEPOINT, rolled back immediately.
        with platform.platform_session() as db:
            target_ref_2 = _target_ref_for(db, plan_id_2)
            positive_control_evidence = _consumption_evidence(
                harness, target_ref_2, issued_2
            )
            savepoint = db.begin_nested()
            staged = control.stage_rehearsal_issuer_consumption(
                db,
                authorization_document=authorization_document_2,
                harness_evidence_document=positive_control_evidence,
            )
            assert staged.authorization_id == authorization_id_2
            savepoint.rollback()
            db.rollback()

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id_2)
            assert record.state == RehearsalIssuerAuthorizationState.ISSUED.value

        drain_once(
            worker_id="d18d-scenario-7",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id_2)
            assert record.state == RehearsalIssuerAuthorizationState.REVOKED.value


# ── 8: one plan, two authorizations -- one spent, one issued ───────────────


def test_one_plan_with_a_spent_and_an_issued_authorization_after_withdraw(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    """Item 6's test gap: a plan with TWO authorizations, one already consumed
    (spent) and one still issued. After withdraw and drain, the spent one is
    unchanged history and the issued one is revoked."""
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-8")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            spent_issued = _issue(
                db, harness, plan_id, command_id=f"issue-spent-{uuid.uuid4()}"
            )
            spent_document = spent_issued.as_mapping()
            spent_id = spent_issued.statement.authorization_id
        with platform.platform_session() as db:
            still_issued = _issue(
                db, harness, plan_id, command_id=f"issue-still-{uuid.uuid4()}"
            )
            still_issued_id = still_issued.statement.authorization_id

        with platform.platform_session() as db:
            target_ref = _target_ref_for(db, plan_id)
            consumption_evidence = _consumption_evidence(
                harness, target_ref, spent_issued
            )
            consume_authorization(
                db,
                plan_id=plan_id,
                authorization_document=spent_document,
                harness_evidence_document=consumption_evidence,
            )

        with platform.platform_session() as db:
            record = _authorization_row(db, spent_id)
            assert record.state == RehearsalIssuerAuthorizationState.SPENT.value
            spent_at = record.spent_at

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)
        drain_once(
            worker_id="d18d-scenario-8",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            event_id = row.id

            spent_record = _authorization_row(db, spent_id)
            assert spent_record.state == RehearsalIssuerAuthorizationState.SPENT.value
            assert spent_record.spent_at == spent_at
            assert spent_record.revocation_ref is None

            still_record = _authorization_row(db, still_issued_id)
            assert still_record.state == RehearsalIssuerAuthorizationState.REVOKED.value
            assert still_record.revocation_ref == f"approval.withdrawn:{event_id}"

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.APPLIED
            assert outcome.evidence["authorizations_revoked"] == [still_issued_id]
            assert outcome.evidence["authorizations_not_revocable"] == [spent_id]


# ── 9: the window before drain -- refusal comes from Approvals, not Control ─


def test_the_window_before_drain_is_refused_by_approvals_not_control(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    """Round-2 correction: before the withdrawal is DRAINED, Control's OWN
    plan-approval row is untouched -- only Approvals' platform_approval_
    request row is marked withdrawn, synchronously, the moment `_withdraw`
    commits. This pins WHERE the refusal comes from in that window:

    (a) `consume_authorization` (through CP's barrier) is refused by
        `ApprovalNotHeld`/`WITHDRAWN` -- Approvals' hold, not Control. The
        ledger row stays ISSUED.
    (b) A DIRECT call to `control.stage_rehearsal_issuer_consumption`,
        bypassing CP's barrier entirely, SUCCEEDS in this same window:
        nothing has told Control the approval was withdrawn yet, so it has
        no reason to refuse. Run inside a SAVEPOINT and rolled back
        immediately, so this never actually spends the authorization -- it
        only proves (a)'s refusal is Approvals' barrier, not Control's own
        authority (contrast with scenario 3, which calls Control directly
        AFTER draining and IS refused, on `APPROVAL_NOT_STANDING`).

    Only after draining does Control's plan get revoked and the ledger row
    become REVOKED. Evidence reuses `issued.statement.lease_id`
    (`_consumption_evidence`)."""
    from vendor_cp.approvals.adapter import ApprovalHoldRefusal, ApprovalNotHeld

    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18d-9")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            issued = _issue(db, harness, plan_id, command_id=f"issue-{uuid.uuid4()}")
            authorization_document = issued.as_mapping()
            authorization_id = issued.statement.authorization_id

        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)
        # Deliberately NOT drained: Control's own plan-approval row is still
        # untouched at this point.

        # (a) CP's barrier refuses -- Approvals, not Control.
        with platform.platform_session() as db:
            target_ref = _target_ref_for(db, plan_id)
            fresh_evidence_a = _consumption_evidence(harness, target_ref, issued)
            with pytest.raises(ApprovalNotHeld) as refused:
                consume_authorization(
                    db,
                    plan_id=plan_id,
                    authorization_document=authorization_document,
                    harness_evidence_document=fresh_evidence_a,
                )
            db.rollback()
        assert refused.value.code is ApprovalHoldRefusal.WITHDRAWN

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.ISSUED.value

        # (b) Control's own authority, bypassed entirely, still SUCCEEDS in
        # this window -- the refusal in (a) was Approvals' barrier, not
        # Control's. Inside a SAVEPOINT, rolled back immediately.
        with platform.platform_session() as db:
            target_ref = _target_ref_for(db, plan_id)
            fresh_evidence_b = _consumption_evidence(harness, target_ref, issued)
            savepoint = db.begin_nested()
            staged = control.stage_rehearsal_issuer_consumption(
                db,
                authorization_document=authorization_document,
                harness_evidence_document=fresh_evidence_b,
            )
            assert staged.authorization_id == authorization_id
            savepoint.rollback()
            db.rollback()

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.ISSUED.value

        drain_once(
            worker_id="d18d-scenario-9",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            record = _authorization_row(db, authorization_id)
            assert record.state == RehearsalIssuerAuthorizationState.REVOKED.value
