"""D18-B: real-PostgreSQL proof, withdrawal event to settlement (Michael, D18).

C2 is not operationally complete until the full path is proved on real
PostgreSQL: CP operator withdrawal (`vendor_cp.approvals.adapter
.withdraw_request`, F-C2) -> the Approvals `a8` trigger (outbox row id ==
withdrawal id) -> the kernel relay drain (`drain_once`, a real
`RelayComposition`) -> `ApprovalEventRouter` -> the Control/CA consequence ->
the append-only CP outcome (`vendor_cp.relay.withdrawal_outcomes`) -> kernel
settlement. This file proves that path end to end, including races, replay,
conflicts and readiness — never through a mocked handler.

The seeding and composition helpers below are copied, not imported (`tests`
is not a package): `migrated`/`_sessions`/`_composition`/`_withdrawal_rows`/
`_propose_and_approve_agreement`/`_activate`/`_propose_issuer` mirror
`test_withdrawal_routing.py`; `_observe` mirrors `test_withdrawal_health.py`;
the issuer-issuance helpers (`issuer_security`, `_target_ref_for`,
`_harness_evidence`) mirror `test_approval_barrier_conformance.py`.
"""

# ruff: noqa: S101

from __future__ import annotations

import sys
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Final
from unittest import mock

import dotmac_deployment_control as control
import pytest
from alembic import command
from dotmac_deployment_control import (
    DesiredDeployment,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    get_target,
    install_rehearsal_issuer_security,
    register_target,
    set_desired_state,
)
from dotmac_kernel import ConflictError, PlatformAdmin
from dotmac_kernel.config import settings
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.errors import register_error_handlers
from dotmac_kernel.messaging import (
    ClaimedPlatformEvent,
    OutboxStatus,
    PlatformOutboxEvent,
    RelayPolicy,
)
from dotmac_kernel.platform_auth import require_platform_admin
from dotmac_kernel.session_runtime import DatabaseRuntime
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals.adapter import ApprovalHoldRefusal, ApprovalNotHeld
from vendor_cp.approvals.router import router as approvals_router
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.contracts import adapter as agreements
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
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion
from vendor_cp.readiness.service import ReadinessDetail, check_readiness
from vendor_cp.relay.approval_router import ApprovalEventRouter
from vendor_cp.relay.health import RelayVerdict, relay_health
from vendor_cp.relay.runner import PlatformEventConsumers, RelayComposition, drain_once
from vendor_cp.relay.withdrawal_outcomes import (
    WithdrawalDisposition,
    WithdrawalResolution,
    outcomes_for_event,
    resolve_conflict,
)

PRODUCT = "dotmac-sub"
CAPABILITIES = ("cap.a", "cap.b")
DISPATCHER_ROLE = "platform_outbox_dispatcher"
PLATFORM_ROLE = "platform_api"
POLICY_CODE = "commercial"
POLICY_VERSION = 1
ISSUER_DESCRIPTOR_DIGEST = "sha256:" + "ab" * 32
ISSUER_EXECUTION_DIGEST = "sha256:" + "cd" * 32
ISSUER_POLICY_CODE = "deployment.withdrawal-convergence"
ISSUER_POLICY_VERSION = 1
WINDOW = timedelta(seconds=300)
HEARTBEAT_WINDOW = timedelta(seconds=120)
SETTLED_WINDOW = timedelta(seconds=600)

#: `rehearsal_issuer_harness` lives outside `src/` and `tests/`, reached the
#: same scoped way `test_approval_barrier_conformance.py` reaches it.
_REPO_ROOT: Final = Path(__file__).resolve().parents[2]


# ── the database under test (same shape as test_withdrawal_routing.py) ──────


#: A short base backoff for scenario 6, so the retry becomes due through the
#: relay's OWN backoff rather than by editing the kernel outbox row.
_FAST_RETRY: Final = RelayPolicy(base_backoff_seconds=0.2, max_backoff_seconds=1.0)
_RETRY_DEADLINE_SECONDS: Final = 15.0


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
    """Every `approval.withdrawn` outbox row, oldest first."""
    return list(
        db.execute(
            select(PlatformOutboxEvent)
            .where(PlatformOutboxEvent.event_type == "approval.withdrawn")
            .order_by(PlatformOutboxEvent.created_at)
        ).scalars()
    )


def _observe(db: Session, *, now: datetime | None = None):
    return relay_health(
        db,
        now=now or datetime.now(UTC),
        overdue_after=WINDOW,
        stale_lease_after=WINDOW,
        heartbeat_stale_after=HEARTBEAT_WINDOW,
        settled_within=SETTLED_WINDOW,
    )


def _ready(db: Session) -> object:
    return check_readiness(
        db,
        now=datetime.now(UTC),
        overdue_after=WINDOW,
        stale_lease_after=WINDOW,
        heartbeat_stale_after=HEARTBEAT_WINDOW,
        settled_within=SETTLED_WINDOW,
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
            authority_ref="ops-ticket-d18b",
            reason="D18-B end-to-end convergence proof",
            external_ref=f"withdraw-{uuid.uuid4()}",
        ),
    )


# ── agreement seeding, through Vendor CP's own public seams only ───────────


def _propose_and_approve_agreement(
    db: Session, *, offer_code: str
) -> agreements.ContractView:
    db.add(
        OfferVersion(
            product_code=PRODUCT,
            offer_code=offer_code,
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
            lines=(agreements.LineInput(offer_code, 1, "cap.a", quantity=2),),
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


def _activate(
    db: Session, approved: agreements.ContractView
) -> agreements.ContractView:
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


def _suspend(db: Session, agreement_id: uuid.UUID) -> agreements.ContractView:
    return agreements.suspend(
        db,
        agreements.TransitionCommand(
            command_id=f"suspend-{uuid.uuid4()}",
            agreement_id=agreement_id,
            reason="D18-B convergence proof",
        ),
    )


def _reinstate(db: Session, agreement_id: uuid.UUID) -> agreements.ContractView:
    return agreements.reinstate(
        db,
        agreements.TransitionCommand(
            command_id=f"reinstate-{uuid.uuid4()}",
            agreement_id=agreement_id,
        ),
    )


# ── issuer plan seeding, through Vendor CP's own public seams only ─────────


def _propose_issuer(db: Session, *, suffix: str) -> tuple[uuid.UUID, uuid.UUID, str]:
    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=uuid.uuid4().hex,
            target_ref=f"withdrawal-convergence-{suffix}",
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


# ── rehearsal-issuer issuance harness, mirroring
# test_approval_barrier_conformance.py's own fixture ─────────────────────────


@pytest.fixture
def issuer_security() -> Iterator[tuple[object, object]]:
    """Install disposable, in-process rehearsal-issuer security for exactly
    one test. See `test_approval_barrier_conformance.py::issuer_security` for
    the full rationale; this is the same fixture, copied because `tests` is
    not a package."""
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


# ── 1: issuer, end to end through the operator path ─────────────────────────


def test_issuer_withdrawal_end_to_end_revokes_and_refuses_later_issuance(
    migrated: tuple[str, str],
    issuer_security: tuple[object, object],
) -> None:
    platform_url, dispatcher_url = migrated
    _, harness = issuer_security
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            plan_id, request_id, _digest = _propose_issuer(db, suffix="d18b-issuer")
            approve_issuer_plan(
                db,
                command_id=f"approve-{uuid.uuid4()}",
                plan_id=plan_id,
                approval_request_id=request_id,
            )
        with platform.platform_session() as db:
            _withdraw(db, request_id=request_id)

        with platform.platform_session() as db:
            rows = _withdrawal_rows(db)
            assert len(rows) == 1
            assert rows[0].id == uuid.UUID(str(rows[0].payload["withdrawal_id"]))

        drain_once(
            worker_id="d18b-convergence",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id

            plan = control.get_plan(db, plan_id)
            assert plan is not None
            assert plan.approval_revocation_ref == f"approval.withdrawn:{event_id}"

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            assert outcomes[0].disposition is WithdrawalDisposition.APPLIED

            health = _observe(db)
            assert health.withdrawal_failing == 0
            assert health.withdrawal_dead == 0
            assert health.unresolved_withdrawal_conflicts == 0

            report = _ready(db)
            assert report.ready is True
            assert report.detail is ReadinessDetail.READY

            # A later issuance for this plan is refused: the approval request
            # this plan depends on is withdrawn, so `held_transition`'s
            # `hold_platform_approval` refuses before Control's issuance
            # entry point is ever reached.
            target_ref = _target_ref_for(db, plan_id)
            evidence = _harness_evidence(harness, target_ref)
            invocation = RehearsalIssuerInvocation(
                RehearsalIssuerCommand(
                    f"issue-{uuid.uuid4()}", plan_id, "operator-rehearsal"
                ),
                evidence,
            )
            with pytest.raises(ApprovalNotHeld) as refused:
                issue_authorization(db, invocation)
            db.rollback()
        assert refused.value.code is ApprovalHoldRefusal.WITHDRAWN


# ── 2: agreement, end to end through the operator path ──────────────────────


def test_agreement_withdrawal_end_to_end_records_standing_agreement_stays_active(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db, offer_code="off-scn2")
            active = _activate(db, approved)
        with platform.platform_session() as db:
            assert active.approval_request_id is not None
            _withdraw(db, request_id=active.approval_request_id)

        drain_once(
            worker_id="d18b-convergence",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            assert outcomes[0].disposition is WithdrawalDisposition.APPLIED

            view = agreements.get(db, active.id)
            assert view is not None
            assert view.approval_withdrawn is True
            assert view.status == "active", "standing, not lifecycle, was recorded"

        # A later suspend, then reinstate, is refused: the decision behind the
        # agreement is permanently withdrawn.
        with platform.platform_session() as db:
            _suspend(db, active.id)
        with platform.platform_session() as db:
            with pytest.raises(ConflictError, match="not held: withdrawn"):
                _reinstate(db, active.id)
            db.rollback()


# ── 3(a): withdraw-first — activate is refused; drain settles a terminal,
# not-yet-active outcome ─────────────────────────────────────────────────────


def test_withdraw_first_refuses_activate_then_drains_to_a_settled_terminal_outcome(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db, offer_code="off-scn3a")
        with platform.platform_session() as db:
            assert approved.approval_request_id is not None
            _withdraw(db, request_id=approved.approval_request_id)

        # Withdraw-first: the later activate is refused by the barrier —
        # Commercial Agreements is never asked to activate a withdrawn
        # decision.
        with platform.platform_session() as db:
            with pytest.raises(ConflictError, match="not held: withdrawn"):
                _activate(db, approved)
            db.rollback()

        drain_once(
            worker_id="d18b-convergence",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert (
                row.status == OutboxStatus.SENT.value
            ), "the row settles even though the agreement never activated"
            event_id = row.id

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            outcome = outcomes[0]
            # CA's own `record_approval_withdrawal` records standing against
            # the approval decision, not the agreement's lifecycle status —
            # an approved-but-not-yet-active agreement withdrawal maps
            # through the identical `RECORDED` branch as the active case
            # (`vendor_cp.contracts.adapter._WITHDRAWAL_OUTCOME_MAP`).
            assert outcome.disposition is WithdrawalDisposition.APPLIED
            assert outcome.reason_code == "recorded"
            assert outcome.agreement_id == approved.id

            view = agreements.get(db, approved.id)
            assert view is not None
            assert view.approval_withdrawn is True
            assert view.status == "approved", "still not-yet-active"


# ── 3(b): transition-first — activate commits, then withdraw+drain applies ──


def test_activate_first_then_withdraw_drains_applied_agreement_stays_active(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db, offer_code="off-scn3b")
            active = _activate(db, approved)
        assert active.status == "active"

        with platform.platform_session() as db:
            assert active.approval_request_id is not None
            _withdraw(db, request_id=active.approval_request_id)

        drain_once(
            worker_id="d18b-convergence",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.SENT.value
            event_id = row.id

            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            assert outcomes[0].disposition is WithdrawalDisposition.APPLIED

            view = agreements.get(db, active.id)
            assert view is not None
            assert view.approval_withdrawn is True
            assert view.status == "active"


# ── 4: replay through the router — a no-op, no second CA call ───────────────


def test_a_replayed_delivery_after_settlement_is_a_no_op(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db, offer_code="off-scn4")
            active = _activate(db, approved)
        with platform.platform_session() as db:
            assert active.approval_request_id is not None
            _withdraw(db, request_id=active.approval_request_id)

        drain_once(
            worker_id="d18b-convergence",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
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
            # router a second time.
            ApprovalEventRouter().deliver(claimed, db)
            db.commit()

        with platform.platform_session() as db:
            replayed = outcomes_for_event(db, event_id)
            assert len(replayed) == 1, "a replay must not write a second row"
            assert replayed[0].disposition is WithdrawalDisposition.APPLIED

            view = agreements.get(db, active.id)
            assert view is not None
            assert (
                view.approval_withdrawn is True
            ), "CA was not asked to withdraw a second time"


# ── 5: changed payload -> conflict -> health/readiness red -> resolved ──────


def test_a_changed_payload_conflicts_then_resolution_clears_health_and_readiness(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db, offer_code="off-scn5")
            active = _activate(db, approved)
        with platform.platform_session() as db:
            assert active.approval_request_id is not None
            _withdraw(db, request_id=active.approval_request_id)

        drain_once(
            worker_id="d18b-convergence",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            event_id = row.id
            mutated_payload = dict(row.payload)
            mutated_payload["reason"] = "a different reason than what was recorded"
            mutated = ClaimedPlatformEvent(
                id=row.id,
                event_type=row.event_type,
                payload=mutated_payload,
                attempts=row.attempts,
                correlation_id=row.correlation_id,
            )
            ApprovalEventRouter().deliver(mutated, db)
            db.commit()

        with platform.platform_session() as db:
            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 2
            conflict = outcomes[1]
            assert conflict.disposition is WithdrawalDisposition.SECURITY_CONFLICT

            health = _observe(db)
            assert health.verdict is RelayVerdict.WITHDRAWAL_CONFLICT_UNRESOLVED
            assert health.unresolved_withdrawal_conflicts == 1

            report = _ready(db)
            assert report.ready is False
            assert report.detail is ReadinessDetail.WITHDRAWAL_CONFLICT_UNRESOLVED

        with platform.platform_session() as db:
            resolve_conflict(
                db,
                outcome_id=conflict.id,
                resolution=WithdrawalResolution.DISMISSED,
                actor_ref="platform-admin:d18b",
                reason="reviewed: benign reason-field drift, no re-application needed",
            )

        with platform.platform_session() as db:
            health = _observe(db)
            assert health.verdict is not RelayVerdict.WITHDRAWAL_CONFLICT_UNRESOLVED
            assert health.unresolved_withdrawal_conflicts == 0

            report = _ready(db)
            assert report.ready is True
            assert report.detail is ReadinessDetail.READY


# ── 6: retry (a real retryable failure), then recovery, through the relay ──


def test_a_retryable_failure_then_recovery_through_the_real_relay(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db, offer_code="off-scn6")
            active = _activate(db, approved)
        with platform.platform_session() as db:
            assert active.approval_request_id is not None
            _withdraw(db, request_id=active.approval_request_id)

        with mock.patch.object(
            agreements,
            "module_record_approval_withdrawal",
            side_effect=OperationalError("statement", {}, Exception("db unavailable")),
        ):
            drain_once(
                worker_id="d18b-convergence",
                composition=_composition(dispatcher_url, platform),
                policy=_FAST_RETRY,
            )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.PENDING.value
            assert row.attempts == 1
            event_id = row.id
            assert outcomes_for_event(db, event_id) == ()

            health = _observe(db)
            assert health.verdict is RelayVerdict.WITHDRAWAL_DELIVERY_FAILING
            assert health.withdrawal_failing == 1

        # NO kernel row is edited. The relay's own backoff (a short
        # `base_backoff_seconds`, the kernel's own policy knob) makes the row
        # due again; the test polls the REAL drain until it is claimed and
        # delivered, bounded so a regression fails instead of hanging.
        deadline = time.monotonic() + _RETRY_DEADLINE_SECONDS
        while True:
            report = drain_once(
                worker_id="d18b-convergence",
                composition=_composition(dispatcher_url, platform),
                policy=_FAST_RETRY,
            )
            with platform.platform_session() as db:
                if outcomes_for_event(db, event_id):
                    break
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the retry never delivered within {_RETRY_DEADLINE_SECONDS}s "
                    f"(last drain report: {report!r})"
                )
            time.sleep(0.2)

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.SENT.value
            outcomes = outcomes_for_event(db, event_id)
            assert len(outcomes) == 1
            assert outcomes[0].disposition is WithdrawalDisposition.APPLIED

            health = _observe(db)
            assert health.verdict is not RelayVerdict.WITHDRAWAL_DELIVERY_FAILING
            assert health.withdrawal_failing == 0


# ── 7: the CP route, not just the adapter ────────────────────────────────────


def test_the_withdraw_route_drains_to_an_applied_outcome(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    admin = PlatformAdmin(id=uuid.uuid4(), email="ops@dotmac.io", password_hash="x")
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            approved = _propose_and_approve_agreement(db, offer_code="off-scn7")
            active = _activate(db, approved)
        assert active.approval_request_id is not None

        app = FastAPI()
        register_error_handlers(app)
        app.include_router(approvals_router)
        app.dependency_overrides[get_platform_db] = platform.platform_request_session
        app.dependency_overrides[require_platform_admin] = lambda: admin

        host = settings.platform_root_domain
        url = (
            f"http://{host}/platform/vendor/approvals/requests/"
            f"{active.approval_request_id}/withdraw"
        )
        with TestClient(app) as client:
            response = client.post(
                url,
                json={
                    "authority_ref": "ops-ticket-d18b-route",
                    "reason": "D18-B route-level convergence proof",
                    "external_ref": f"withdraw-{uuid.uuid4()}",
                },
            )
        assert response.status_code == 200
        assert response.json()["state"] == "withdrawn"

        drain_once(
            worker_id="d18b-convergence",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            row = _withdrawal_rows(db)[0]
            assert row.status == OutboxStatus.SENT.value
            outcomes = outcomes_for_event(db, row.id)
            assert len(outcomes) == 1
            assert outcomes[0].disposition is WithdrawalDisposition.APPLIED

            view = agreements.get(db, active.id)
            assert view is not None
            assert view.approval_withdrawn is True
