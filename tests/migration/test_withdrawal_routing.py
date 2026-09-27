"""Real-PostgreSQL proofs of terminal withdrawal outcomes and replay (C2 S4-B2b).

Michael's point 12: prove the six terminal dispositions and event replay
against real PostgreSQL, plus atomicity (consequence + outcome row + event-id
record commit together), that `retryable` leaves nothing durable, and that
`security_conflict` is recorded while delivery still returns normally.

Where possible this drives the real kernel drain (`drain_once` with a
`RelayComposition` whose dispatcher and delivery DSNs are the scratch DB's
roles — the pattern `test_platform_relay_drain.py` uses). Two cases
(constructed conflicting/manufactured events) drive `ApprovalEventRouter
.deliver` directly in a session the test commits itself, because the real
production paths that would produce those exact payloads either don't exist
(a second approval of an identical digest) or would require re-implementing
the outbox trigger by hand — noted at each such test.

No `test_agreement_approval_barrier.py` exists on this branch, so agreement
seeding reuses `test_platform_relay_drain.py::_activate_an_agreement`'s
pattern (contracts + approvals adapters, no hand-inserted rows); issuer
seeding reuses `test_approval_barrier_conformance.py::_seed`'s pattern (its
`issuer_security` fixture is not needed here — issuance itself is out of
scope).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime
from typing import Any
from unittest import mock

import dotmac_approvals
import dotmac_deployment_control as control
import pytest
from alembic import command
from dotmac_approvals import Actor
from dotmac_commercial_agreements import get as ca_get
from dotmac_deployment_control import (
    DesiredDeployment,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    register_target,
    set_desired_state,
)
from dotmac_kernel.messaging import ClaimedPlatformEvent, OutboxStatus, PlatformOutboxEvent
from dotmac_kernel.messaging.outbox import enqueue_platform_event
from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.contracts import adapter as agreements
from vendor_cp.contracts import adapter as contracts_adapter
from vendor_cp.contracts_authority import APPROVAL_SUBJECT_TYPE
from vendor_cp.deployment.protected_rehearsal_issuer import (
    SUBJECT_TYPE as ISSUER_SUBJECT_TYPE,
)
from vendor_cp.deployment.protected_rehearsal_issuer import (
    ProposeIssuerPlan,
    approve_issuer_plan,
    open_issuer_approval,
    propose_issuer_plan,
)
from vendor_cp.migrations import make_alembic_config
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion
from vendor_cp.relay import approval_router
from vendor_cp.relay.approval_router import ApprovalEventRouter
from vendor_cp.relay.runner import PlatformEventConsumers, RelayComposition, drain_once
from vendor_cp.relay.withdrawal_outcomes import WithdrawalDisposition, outcomes_for_event

PRODUCT = "dotmac-sub"
CAPABILITIES = ("cap.a", "cap.b")
DISPATCHER_ROLE = "platform_outbox_dispatcher"
PLATFORM_ROLE = "platform_api"
POLICY_CODE = "commercial"
POLICY_VERSION = 1
ISSUER_DESCRIPTOR_DIGEST = "sha256:" + "ab" * 32
ISSUER_EXECUTION_DIGEST = "sha256:" + "cd" * 32
ISSUER_POLICY_CODE = "deployment.withdrawal-proof"
ISSUER_POLICY_VERSION = 1


# ── the database under test (same shape as test_platform_relay_drain.py) ────


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


# ── the real composed transport, catalogue pinned exactly as the drain test ─


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


def _withdrawal_row(db: Session) -> PlatformOutboxEvent:
    """The one `approval.withdrawn` outbox row a real withdrawal enqueued."""
    return db.execute(
        select(PlatformOutboxEvent).where(
            PlatformOutboxEvent.event_type == "approval.withdrawn"
        )
    ).scalar_one()


def _withdraw(db: Session, *, request_id: uuid.UUID, external_ref: str) -> object:
    return dotmac_approvals.withdraw_platform_approval(
        db,
        request_id=request_id,
        actor=Actor(actor_id=uuid.uuid4()),
        authority_ref="ops-ticket-s4b2b",
        reason="C2 S4-B2b withdrawal outcome proof",
        external_ref=external_ref,
    )


# ── agreement seeding, through Vendor CP's own public seams only ───────────


def _propose_and_approve_agreement(db: Session) -> agreements.ContractView:
    """Draft -> propose -> decide -> approve one real agreement.

    Mirrors `test_platform_relay_drain.py::_activate_an_agreement` up to (not
    including) activation, since several cases here need only an APPROVED
    agreement.
    """
    db.add(
        OfferVersion(
            product_code=PRODUCT,
            offer_code="off",
            version=1,
            amount="10.00",
            currency_code="USD",
            capability_codes=list(CAPABILITIES),
        )
    )
    db.flush()
    catalogues = _catalogue()
    draft = agreements.create_draft(
        db,
        agreements.CreateDraftCommand(
            command_id=f"draft-{uuid.uuid4()}",
            reference=f"AGR-{uuid.uuid4()}",
            product_code=PRODUCT,
            counterparty_ref="cust-42",
            agreement_type="software_subscription",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(agreements.LineInput("off", 1, "cap.a", quantity=2),),
        ),
        catalogues=catalogues,
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"policy-{uuid.uuid4()}",
            policy_code=POLICY_CODE,
            version=POLICY_VERSION,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    proposed = agreements.propose(
        db,
        agreements.ProposeCommand(
            command_id=f"propose-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_policy_code=POLICY_CODE,
            approval_policy_version=POLICY_VERSION,
            requested_by=uuid.uuid4(),
        ),
        catalogues=catalogues,
    )
    assert proposed.approval_request_id is not None
    assert proposed.content_hash is not None
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"decision-{uuid.uuid4()}",
            request_id=proposed.approval_request_id,
            approver_id=uuid.uuid4(),
            content_hash=proposed.content_hash,
        ),
    )
    return agreements.approve(
        db,
        agreements.ApprovalCommand(
            command_id=f"approve-{uuid.uuid4()}",
            agreement_id=proposed.id,
            approval_request_id=proposed.approval_request_id,
        ),
    )


def _activate(db: Session, approved: agreements.ContractView) -> agreements.ContractView:
    assert approved.approval_request_id is not None
    return agreements.activate(
        db,
        agreements.ActivateCommand(
            command_id=f"activate-{uuid.uuid4()}",
            agreement_id=approved.id,
            approval_request_id=approved.approval_request_id,
            activation_rule="countersigned",
            activation_reference="signature-42",
            activation_satisfied_at=datetime.now(UTC),
        ),
    )


# ── issuer plan seeding, through Vendor CP's own public seams only ─────────


def _propose_issuer(db: Session, *, suffix: str) -> tuple[uuid.UUID, uuid.UUID, str]:
    """A real, decided-but-not-necessarily-approved rehearsal-issuer plan.

    Mirrors `test_approval_barrier_conformance.py::_seed`; the
    `issuer_security` fixture it also installs is not needed here.
    """
    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=uuid.uuid4().hex,
            target_ref=f"withdrawal-outcome-{suffix}",
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
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=uuid.uuid4().hex,
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


# ── 1: agreement `applied` · 2: replay · 3: changed payload under one id ────


def test_agreement_withdrawal_applies_then_replays_then_conflicts_on_change(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db)
            active = _activate(db, approved)
        with platform.platform_session() as db:
            assert active.approval_request_id is not None
            _withdraw(
                db,
                request_id=active.approval_request_id,
                external_ref=f"withdraw-{uuid.uuid4()}",
            )

        # 1. `applied`, through the real kernel drain.
        drain_once(
            worker_id="withdrawal-test",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            view = ca_get(db, active.id)
            assert view is not None
            assert view.approval_withdrawn is True
            assert view.status == "active"

            row = _withdrawal_row(db)
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.APPLIED
            assert outcome.event_id == event_id
            assert outcome.agreement_id == active.id
            assert outcome.approval_request_id == active.approval_request_id
            assert outcome.withdrawal_ref is not None

            claimed = ClaimedPlatformEvent(
                id=row.id,
                event_type=row.event_type,
                payload=dict(row.payload),
                attempts=row.attempts,
                correlation_id=row.correlation_id,
            )

            # 2. Replay: the identical claimed event, delivered directly.
            ApprovalEventRouter().deliver(claimed, db)
            db.commit()

        with platform.platform_session() as db:
            replayed = outcomes_for_event(db, event_id)
            assert len(replayed) == 1, "a replay must not write a second row"
            assert replayed[0].disposition is WithdrawalDisposition.APPLIED

            # 3. The same event id, a mutated payload: security_conflict, and
            # CA is not asked again (still exactly one withdrawal in CA).
            mutated_payload = dict(claimed.payload)
            mutated_payload["reason"] = "a different reason than what was recorded"
            mutated = ClaimedPlatformEvent(
                id=claimed.id,
                event_type=claimed.event_type,
                payload=mutated_payload,
                attempts=claimed.attempts,
                correlation_id=claimed.correlation_id,
            )
            ApprovalEventRouter().deliver(mutated, db)
            db.commit()

        with platform.platform_session() as db:
            after_conflict = outcomes_for_event(db, event_id)
            assert len(after_conflict) == 2
            conflict_row = after_conflict[1]
            assert conflict_row.disposition is WithdrawalDisposition.SECURITY_CONFLICT
            assert conflict_row.reason_code == "payload_changed_under_event_id"

            # CA still shows exactly the one withdrawal from step 1 — the
            # conflict path never called the CA handler again.
            view_after = ca_get(db, active.id)
            assert view_after is not None
            assert view_after.approval_withdrawn is True


# ── 4: issuer `applied` ──────────────────────────────────────────────────────


def test_issuer_withdrawal_revokes_the_plan_approval_and_records_applied(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="applied")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            _withdraw(
                db, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
            )

        drain_once(
            worker_id="withdrawal-test",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_row(db)
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id

            plan = control.get_plan(db, plan_id)
            assert plan is not None
            assert plan.approval_revocation_ref == f"approval.withdrawn:{event_id}"

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.APPLIED
            assert outcome.plan_id == plan_id
            assert outcome.approval_request_id == request_id


# ── 5: issuer `not_carried`, never approved ─────────────────────────────────


def test_issuer_withdrawal_of_a_never_approved_plan_is_not_carried(
    migrated: tuple[str, str],
) -> None:
    """The request was decided (approved by Approvals) but Vendor CP never
    carried it into Control (`approve_issuer_plan` was never called) — the
    plan is still `proposed`."""
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="never-approved")
        with platform.platform_session() as db:
            _withdraw(
                db, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
            )

        drain_once(
            worker_id="withdrawal-test",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_row(db)
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.NOT_CARRIED
            assert outcome.reason_code == "never_approved"

            plan = control.get_plan(db, plan_id)
            assert plan is not None
            assert plan.status == "proposed"
            assert plan.approval_decision_ref is None


# ── 6: agreement `not_carried`, `decision_not_carried` ──────────────────────


def test_agreement_withdrawal_of_a_different_approved_request_is_not_carried(
    migrated: tuple[str, str],
) -> None:
    """An agreement approved under request A; a withdrawal citing a different
    (never actually opened) approved request B for the same subject and
    digest. Approvals refuses a second request at an identical content
    digest for the same subject (it is the same decision, not a new one), so
    there is no real production call chain that produces this exact claimed
    event — this drives `ApprovalEventRouter.deliver` directly with a
    constructed event, as the packet allows.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db)
            assert approved.approval_request_id is not None
            assert approved.content_hash is not None

            other_request_id = uuid.uuid4()
            event = ClaimedPlatformEvent(
                id=uuid.uuid4(),
                event_type="approval.withdrawn",
                payload={
                    "request_id": str(other_request_id),
                    "subject_type": APPROVAL_SUBJECT_TYPE,
                    "subject_id": str(approved.id),
                    "policy_code": POLICY_CODE,
                    "policy_version": POLICY_VERSION,
                    "content_digest": f"sha256:{approved.content_hash}",
                    "state": "withdrawn",
                    "withdrawal_id": str(uuid.uuid4()),
                    "reason": "withdrawing a request this agreement never bound",
                    "effective_at": datetime.now(UTC).isoformat(),
                    "external_ref": f"withdraw-{uuid.uuid4()}",
                },
                attempts=1,
                correlation_id=None,
            )
            ApprovalEventRouter().deliver(event, db)
            db.commit()

        with platform.platform_session() as db:
            outcomes = outcomes_for_event(db, event.id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            assert outcome.disposition is WithdrawalDisposition.NOT_CARRIED
            assert outcome.reason_code == "decision_not_carried"
            assert outcome.agreement_id == approved.id

            view = ca_get(db, approved.id)
            assert view is not None
            assert view.approval_withdrawn is False
            assert view.status == "approved"
