"""Hosted PostgreSQL: real Foundation subject, Approvals locks and convergence.

This suite exercises installed pinned owners. It does not establish canonical
profile admission or a receipt-producing Foundation deployment.
"""

# ruff: noqa: S101
from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import dotmac_deployment_control as control
import pytest
from alembic import command
from dotmac_kernel.messaging import ClaimedPlatformEvent, PlatformOutboxEvent
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.deployment.foundation_approval import (
    SUBJECT_TYPE,
    FoundationApprovalUnavailable,
    approve_foundation_plan,
    dispatch_foundation_attempt,
    hold_foundation_transition,
    open_foundation_approval,
    request_foundation_rollout,
    subject_id,
)
from vendor_cp.migrations import make_alembic_config
from vendor_cp.relay.approval_router import ApprovalEventRouter
from vendor_cp.relay.withdrawal_outcomes import (
    WithdrawalDisposition,
    outcomes_for_event,
)


@pytest.fixture
def engine(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Engine]:
    command.upgrade(make_alembic_config(scratch_db), "heads")
    owner = create_engine(scratch_db)
    with owner.connect() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    owner.dispose()
    online = create_engine(url_for(scratch_db, database, user="platform_api"))
    yield online
    online.dispose()


def _seed(engine: Engine, *, operation: str = "deploy") -> tuple[UUID, UUID]:
    suffix = uuid4().hex
    with Session(engine) as db:
        target = control.register_target(
            db,
            control.RegisterTargetCommand(
                command_id=uuid4().hex,
                target_ref=f"foundation-approval-{suffix}",
                subject_ref=f"subject-{suffix}",
                product_code="dotmac_sub",
                environment="rehearsal",
            ),
        )
        control.set_desired_state(
            db,
            control.SetDesiredStateCommand(
                command_id=uuid4().hex,
                target_id=target.id,
                desired=control.DesiredDeployment(
                    release_ref="dotmac_sub@rehearsal",
                    spec={"replicas": 1},
                    images=[],
                ),
            ),
        )
        plan = control.propose_plan(
            db,
            control.ProposePlanCommand(
                command_id=uuid4().hex,
                target_id=target.id,
                operation=operation,
                descriptor_digest="sha256:" + "ab" * 32,
                execution_plan_digest="sha256:" + "cd" * 32,
                purpose="foundation_execution",
                requires_approval=True,
                approval_policy_code="foundation.hosted",
                approval_policy_version=1,
            ),
        )
        approvals.publish_policy_version(
            db,
            approvals.PublishPolicyCommand(
                command_id=uuid4().hex,
                policy_code="foundation.hosted",
                version=1,
                quorum=1,
                allow_self_approval=False,
            ),
        )
        opened = open_foundation_approval(
            db, command_id=uuid4().hex, plan_id=plan.id, requested_by=uuid4()
        )
        approvals.record_decision(
            db,
            approvals.RecordDecisionCommand(
                command_id=uuid4().hex,
                request_id=opened.request_id,
                approver_id=uuid4(),
                content_hash=bare_content_hash(plan.plan_digest),
            ),
        )
        db.commit()
    return plan.id, opened.request_id


def _withdraw(db: Session, request_id: UUID) -> None:
    approvals.withdraw_request(
        db,
        approvals.WithdrawRequestCommand(
            request_id=request_id,
            actor_id=uuid4(),
            authority_ref="hosted-test",
            reason="Hosted withdrawal proof",
            external_ref=uuid4().hex,
        ),
    )


@pytest.mark.parametrize("operation", ["deploy", "rollback"])
def test_real_approval_has_distinct_subject_and_one_caller_commit(engine, operation):
    plan_id, request_id = _seed(engine, operation=operation)
    commits = []
    with Session(engine) as db:
        event.listen(db, "after_commit", lambda _: commits.append("commit"))
        approved = approve_foundation_plan(
            db, command_id=uuid4().hex, plan_id=plan_id, approval_request_id=request_id
        )
        assert approved.status == "approved"
        assert approved.approval_decision_ref == str(request_id)
        assert subject_id(approved).startswith(f"v1|{plan_id}|foundation_execution|")
        assert SUBJECT_TYPE != "rehearsal_issuer_plan.v1"
        assert commits == []
        db.commit()
        assert commits == ["commit"]


@pytest.mark.parametrize("approved_first", [False, True])
def test_withdrawal_first_refuses_approval_or_later_carried_transition(
    engine, approved_first
):
    plan_id, request_id = _seed(engine)
    if approved_first:
        with Session(engine) as db:
            approve_foundation_plan(
                db,
                command_id=uuid4().hex,
                plan_id=plan_id,
                approval_request_id=request_id,
            )
            db.commit()
    with Session(engine) as db:
        _withdraw(db, request_id)
        db.commit()
    calls = []
    with Session(engine) as db, pytest.raises(approvals.ApprovalNotHeld) as refused:
        if approved_first:
            hold_foundation_transition(
                db, plan_id=plan_id, transition=lambda _: calls.append("transition")
            )
        else:
            approve_foundation_plan(
                db,
                command_id=uuid4().hex,
                plan_id=plan_id,
                approval_request_id=request_id,
            )
    assert refused.value.code is approvals.ApprovalHoldRefusal.WITHDRAWN
    assert calls == []


def test_live_carried_barrier_blocks_withdrawal_until_caller_commit(engine):
    plan_id, request_id = _seed(engine)
    with Session(engine) as db:
        approve_foundation_plan(
            db, command_id=uuid4().hex, plan_id=plan_id, approval_request_id=request_id
        )
        db.commit()
    with Session(engine) as db:

        def transition(_):
            with Session(engine) as peer:
                peer.execute(text("SET LOCAL lock_timeout = '500ms'"))
                with pytest.raises(OperationalError) as refused:
                    _withdraw(peer, request_id)
                assert getattr(refused.value.orig, "sqlstate", None) == "55P03"
                peer.rollback()
            return "held"

        assert (
            hold_foundation_transition(db, plan_id=plan_id, transition=transition)
            == "held"
        )
        db.commit()
    with Session(engine) as db:
        _withdraw(db, request_id)
        db.commit()


def test_withdrawal_router_revokes_and_replays_exact_event_then_conflicts(engine):
    plan_id, request_id = _seed(engine)
    with Session(engine) as db:
        approve_foundation_plan(
            db, command_id=uuid4().hex, plan_id=plan_id, approval_request_id=request_id
        )
        db.commit()
    with Session(engine) as db:
        _withdraw(db, request_id)
        db.commit()
    with Session(engine) as db:
        row = db.scalars(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "approval.withdrawn"
            )
        ).one()
        claimed = ClaimedPlatformEvent(
            id=row.id,
            event_type=row.event_type,
            payload=dict(row.payload),
            attempts=row.attempts,
            correlation_id=row.correlation_id,
        )
        ApprovalEventRouter().deliver(claimed, db)
        db.commit()
        assert control.get_plan(db, plan_id).approval_decision_status == "revoked"
        assert (
            outcomes_for_event(db, row.id)[0].disposition
            == WithdrawalDisposition.APPLIED
        )
        ApprovalEventRouter().deliver(claimed, db)
        db.commit()
        assert len(outcomes_for_event(db, row.id)) == 1
        changed = ClaimedPlatformEvent(
            id=claimed.id,
            event_type=claimed.event_type,
            payload={**claimed.payload, "reason": "changed"},
            attempts=0,
            correlation_id=None,
        )
        ApprovalEventRouter().deliver(changed, db)
        db.commit()
        assert len(outcomes_for_event(db, row.id)) == 2
        assert any(
            o.disposition == WithdrawalDisposition.SECURITY_CONFLICT
            for o in outcomes_for_event(db, row.id)
        )


def test_approval_exempt_plan_is_not_a_foundation_approval_subject(engine):
    from dataclasses import replace

    plan_id, _ = _seed(engine)
    with Session(engine) as db:
        plan = control.get_plan(db, plan_id)
        with pytest.raises(FoundationApprovalUnavailable):
            subject_id(replace(plan, requires_approval=False))


@pytest.mark.parametrize(
    "changed",
    [
        {"purpose": "rehearsal_issuer_operation"},
        {"operation": "recover"},
        {"execution_plan_digest": "sha256:" + "A" * 64},
        {"plan_digest": None},
        {"approval_policy_code": None},
        {"approval_policy_version": None},
    ],
)
def test_subject_refuses_missing_or_wrong_frozen_terms(engine, changed):
    from dataclasses import replace

    plan_id, _ = _seed(engine)
    with Session(engine) as db:
        with pytest.raises(ValueError):
            subject_id(replace(control.get_plan(db, plan_id), **changed))


def test_sibling_withdrawal_is_not_carried_and_does_not_revoke_selected_decision(
    engine,
):
    plan_id, request_id = _seed(engine)
    with Session(engine) as db:
        plan = control.get_plan(db, plan_id)
        sibling = open_foundation_approval(
            db, command_id=uuid4().hex, plan_id=plan_id, requested_by=uuid4()
        )
        approvals.record_decision(
            db,
            approvals.RecordDecisionCommand(
                command_id=uuid4().hex,
                request_id=sibling.request_id,
                approver_id=uuid4(),
                content_hash=bare_content_hash(plan.plan_digest),
            ),
        )
        approve_foundation_plan(
            db, command_id=uuid4().hex, plan_id=plan_id, approval_request_id=request_id
        )
        db.commit()
        _withdraw(db, sibling.request_id)
        db.commit()
        row = db.scalars(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "approval.withdrawn"
            )
        ).one()
        claimed = ClaimedPlatformEvent(
            id=row.id,
            event_type=row.event_type,
            payload=dict(row.payload),
            attempts=0,
            correlation_id=None,
        )
        ApprovalEventRouter().deliver(claimed, db)
        db.commit()
        assert (
            outcomes_for_event(db, row.id)[0].disposition
            == WithdrawalDisposition.NOT_CARRIED
        )
        assert control.get_plan(db, plan_id).approval_decision_status == "granted"


class _SignedAuthorityPorts:
    """Ephemeral HMAC test signers; actual owner DTOs and verification ports.

    These exercise the released signed-envelope lifecycle and signature
    checking. They are not asymmetric-custody or production-key evidence.
    """

    def __init__(self) -> None:
        self.authorization_key = hashlib.sha256(uuid4().bytes).digest()
        self.dispatch_key = hashlib.sha256(uuid4().bytes).digest()
        self.authorization_calls = 0
        self.dispatch_calls = 0
        self.verification_calls = 0
        self.identity = control.AuthorizationSignerIdentity(
            key_id="hosted-authorization-" + uuid4().hex,
            algorithm="test-hmac-sha256",
            public_key_fingerprint=self._fingerprint(self.authorization_key),
        )
        self.dispatch_identity = control.DispatchSignerIdentity(
            key_id="hosted-dispatch-" + uuid4().hex,
            algorithm="test-hmac-sha256",
            public_key_fingerprint=self._fingerprint(self.dispatch_key),
        )
        assert (
            self.identity.public_key_fingerprint
            != self.dispatch_identity.public_key_fingerprint
        )

    @staticmethod
    def _fingerprint(key: bytes) -> str:
        encoded = base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")
        return control.PublicKeyFingerprintV1.from_public_key_b64(encoded).canonical

    def sign(self, canonical_bytes: bytes) -> control.AuthorizationSignature:
        self.authorization_calls += 1
        identity = self.identity
        return control.AuthorizationSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key_fingerprint=identity.public_key_fingerprint,
            signature=hmac.new(
                self.authorization_key, canonical_bytes, hashlib.sha256
            ).hexdigest(),
        )

    def sign_dispatch(self, canonical_bytes: bytes) -> control.DispatchSignature:
        self.dispatch_calls += 1
        identity = self.dispatch_identity
        return control.DispatchSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key_fingerprint=identity.public_key_fingerprint,
            signature=hmac.new(
                self.dispatch_key, canonical_bytes, hashlib.sha256
            ).hexdigest(),
        )

    def verify(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        self.verification_calls += 1
        identity = self.identity
        expected = hmac.new(
            self.authorization_key, canonical_bytes, hashlib.sha256
        ).hexdigest()
        return (key_id, algorithm, purpose, public_key_fingerprint) == (
            identity.key_id,
            identity.algorithm,
            identity.purpose,
            identity.public_key_fingerprint,
        ) and hmac.compare_digest(expected, signature)


@dataclass
class _Stage:
    plan_id: UUID
    request_id: UUID
    ports: _SignedAuthorityPorts
    rollout_ref: str
    rollout_id: UUID | None = None


def _seed_stage(engine: Engine, stage: str) -> _Stage:
    plan_id, request_id = _seed(engine)
    fixture = _Stage(plan_id, request_id, _SignedAuthorityPorts(), uuid4().hex)
    if stage != "approve":
        with Session(engine) as db:
            approve_foundation_plan(
                db,
                command_id=uuid4().hex,
                plan_id=plan_id,
                approval_request_id=request_id,
            )
            db.commit()
    if stage == "dispatch":
        with Session(engine) as db:
            rollout = _run_stage(db, "rollout", fixture)
            fixture.rollout_id = rollout.id
            db.commit()
    return fixture


def _run_stage(db: Session, stage: str, fixture: _Stage):
    if stage == "approve":
        return approve_foundation_plan(
            db,
            command_id=uuid4().hex,
            plan_id=fixture.plan_id,
            approval_request_id=fixture.request_id,
        )
    if stage == "rollout":
        return request_foundation_rollout(
            db,
            command_id=uuid4().hex,
            rollout_ref=fixture.rollout_ref,
            plan_id=fixture.plan_id,
            authorization_expires_at=datetime.now(UTC) + timedelta(hours=1),
            signer=fixture.ports,
        )
    assert stage == "dispatch" and fixture.rollout_id is not None
    return dispatch_foundation_attempt(
        db,
        command_id=uuid4().hex,
        rollout_id=fixture.rollout_id,
        verifier=fixture.ports,
        dispatch_signer=fixture.ports,
    )


@pytest.mark.parametrize("stage", ["approve", "rollout", "dispatch"])
def test_owner_transition_first_holds_withdrawal_until_single_commit(engine, stage):
    fixture = _seed_stage(engine, stage)
    commits = []
    with Session(engine) as db:
        event.listen(db, "after_commit", lambda _: commits.append("commit"))
        transitioned = _run_stage(db, stage, fixture)
        assert transitioned is not None and commits == []
        with Session(engine) as peer:
            peer.execute(text("SET LOCAL lock_timeout = '500ms'"))
            with pytest.raises(OperationalError) as refused:
                _withdraw(peer, fixture.request_id)
            assert getattr(refused.value.orig, "sqlstate", None) == "55P03"
            peer.rollback()
        assert commits == []
        db.commit()
        assert commits == ["commit"]
    with Session(engine) as peer:
        _withdraw(peer, fixture.request_id)
        peer.commit()
    if stage in {"rollout", "dispatch"}:
        assert fixture.ports.authorization_calls == 1
    if stage == "dispatch":
        assert fixture.ports.dispatch_calls == 1
        assert fixture.ports.verification_calls >= 1


@pytest.mark.parametrize("stage", ["approve", "rollout", "dispatch"])
def test_withdrawal_first_refuses_real_owner_transition_without_signed_output(
    engine, stage
):
    fixture = _seed_stage(engine, stage)
    auth_before = fixture.ports.authorization_calls
    dispatch_before = fixture.ports.dispatch_calls
    with Session(engine) as peer:
        _withdraw(peer, fixture.request_id)
        peer.commit()
    with Session(engine) as db:
        with pytest.raises(approvals.ApprovalNotHeld) as refused:
            _run_stage(db, stage, fixture)
        assert refused.value.code is approvals.ApprovalHoldRefusal.WITHDRAWN
        db.rollback()
    assert fixture.ports.authorization_calls == auth_before
    assert fixture.ports.dispatch_calls == dispatch_before
    with Session(engine) as db:
        plan = control.get_plan(db, fixture.plan_id)
        assert plan.status == ("proposed" if stage == "approve" else "approved")
        if stage == "dispatch":
            assert len(control.get_rollout(db, fixture.rollout_id).attempts) == 0
