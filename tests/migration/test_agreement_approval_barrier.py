"""A real-PostgreSQL conformance proof of the agreement approval barrier.

S4-A put Commercial Agreements' `approve`, `activate` and `reinstate`
(`vendor_cp.contracts.adapter`) behind
`vendor_cp.deployment.approval_barrier.held_transition`, mirroring the C2 S1
proof this file's sibling (`test_approval_barrier_conformance.py`) already
gives the rehearsal-issuer site. That claim is only provable with a real lock
manager, two real sessions and a real blocking wait, so it lives here rather
than under `tests/unit` — seeded only through Vendor CP's own public seams
(`vendor_cp.contracts.adapter.create_draft`/`propose`, the approvals adapter's
policy/request/decision helpers, then `approve`/`activate`/`reinstate`
themselves), never a hand-inserted row.

Michael's binding rulings (2026-09-27), each proved below:

- withdrawal-first must refuse the later transition (approve, activate,
  reinstate);
- transition-first may commit, after which the withdrawal records standing
  without reversing the lifecycle;
- approve holds the request through Control's — here, Commercial Agreements'
  — transition and the caller's commit, the same one-session-one-transaction
  shape `held_transition` gives the rehearsal issuer.

Every blocking wait below is bounded (a `lock_timeout`, a `Thread.join`
timeout) so a real regression here fails fast instead of hanging CI.
"""

# ruff: noqa: S101

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime
from typing import Final
from unittest import mock

import dotmac_approvals
import pytest
from alembic import command
from dotmac_approvals import Actor, ApprovalState
from dotmac_kernel import ConflictError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import adapter as agreements
from vendor_cp.migrations import make_alembic_config
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion

#: The online runtime role, same as `test_approval_barrier_conformance.py`'s
#: `PLATFORM_ROLE`. `scratch_db` already grants it CONNECT; the module
#: migrations grant it whatever table access it needs.
PLATFORM_ROLE: Final = "platform_api"

_PRODUCT: Final = "dotmac_sub"
_POLICY_CODE: Final = "commercial.production"
_POLICY_VERSION: Final = 1
_LOCK_WAIT: Final = 10


# ── the database under test ─────────────────────────────────────────────────


@pytest.fixture
def engine(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Engine]:
    """A migrated scratch database, connected as the real online platform role."""
    command.upgrade(make_alembic_config(scratch_db), "heads")
    made = create_engine(scratch_db)
    with made.connect() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    made.dispose()
    eng = create_engine(url_for(scratch_db, database, user=PLATFORM_ROLE), future=True)
    yield eng
    eng.dispose()


# ── seeding, through Vendor CP's own public seams only ──────────────────────


def _catalogue() -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({_PRODUCT: ("cap.a",)})


def _seed_offer(engine: Engine, *, code: str) -> None:
    with Session(engine) as db:
        db.add(
            OfferVersion(
                product_code=_PRODUCT,
                offer_code=code,
                version=1,
                amount="19.99",
                currency_code="USD",
                capability_codes=["cap.a"],
            )
        )
        db.commit()


def _draft(db: Session, *, offer_code: str) -> agreements.ContractView:
    return agreements.create_draft(
        db,
        agreements.CreateDraftCommand(
            command_id=f"draft-{uuid.uuid4()}",
            reference=f"AGR-{uuid.uuid4()}",
            product_code=_PRODUCT,
            counterparty_ref="counterparty-1",
            agreement_type="software_subscription",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(agreements.LineInput(offer_code, 1, "cap.a"),),
        ),
        catalogues=_catalogue(),
    )


def _proposed(
    db: Session, agreement_id: uuid.UUID, *, requested_by: uuid.UUID | None = None
) -> agreements.ContractView:
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"policy-{uuid.uuid4()}",
            policy_code=_POLICY_CODE,
            version=_POLICY_VERSION,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    return agreements.propose(
        db,
        agreements.ProposeCommand(
            command_id=f"propose-{uuid.uuid4()}",
            agreement_id=agreement_id,
            approval_policy_code=_POLICY_CODE,
            approval_policy_version=_POLICY_VERSION,
            requested_by=requested_by or uuid.uuid4(),
        ),
        catalogues=_catalogue(),
    )


def _decide(db: Session, proposed: agreements.ContractView) -> None:
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


def _seed(engine: Engine, *, offer_code: str) -> tuple[uuid.UUID, uuid.UUID]:
    """A real, proposed-and-decided agreement: (agreement_id, request_id).

    Every row below is written by the real production call chain — Vendor
    CP's own `create_draft`/`propose` and the approvals adapter's
    `publish_policy_version`/`record_decision` — never inserted by hand.
    """
    _seed_offer(engine, code=offer_code)
    with Session(engine) as db:
        draft = _draft(db, offer_code=offer_code)
        proposed = _proposed(db, draft.id)
        _decide(db, proposed)
        db.commit()
    assert proposed.approval_request_id is not None
    return draft.id, proposed.approval_request_id


def _approve_and_commit(
    engine: Engine, agreement_id: uuid.UUID, request_id: uuid.UUID
) -> agreements.ContractView:
    with Session(engine) as db:
        value = agreements.approve(
            db,
            agreements.ApprovalCommand(
                command_id=f"approve-{uuid.uuid4()}",
                agreement_id=agreement_id,
                approval_request_id=request_id,
            ),
        )
        db.commit()
    return value


def _activate_and_commit(
    engine: Engine, agreement_id: uuid.UUID, request_id: uuid.UUID
) -> agreements.ContractView:
    with Session(engine) as db:
        value = agreements.activate(
            db,
            agreements.ActivateCommand(
                command_id=f"activate-{uuid.uuid4()}",
                agreement_id=agreement_id,
                approval_request_id=request_id,
                activation_rule="countersigned",
                activation_reference="countersignature-1",
                activation_satisfied_at=datetime.now(UTC),
            ),
        )
        db.commit()
    return value


def _suspend_and_commit(
    engine: Engine, agreement_id: uuid.UUID
) -> agreements.ContractView:
    with Session(engine) as db:
        value = agreements.suspend(
            db,
            agreements.TransitionCommand(
                command_id=f"suspend-{uuid.uuid4()}",
                agreement_id=agreement_id,
                reason="C2 conformance proof",
            ),
        )
        db.commit()
    return value


def _withdraw(db: Session, *, request_id: uuid.UUID, external_ref: str) -> object:
    return dotmac_approvals.withdraw_platform_approval(
        db,
        request_id=request_id,
        actor=Actor(actor_id=uuid.uuid4()),
        authority_ref="ops-ticket-c2",
        reason="C2 conformance proof",
        external_ref=external_ref,
    )


def _status(engine: Engine, agreement_id: uuid.UUID) -> str:
    with Session(engine) as db:
        value = agreements.get(db, agreement_id)
    assert value is not None
    return value.status


# ── approve: withdrawal-first refuses ───────────────────────────────────────


def test_a_withdrawal_committed_first_makes_approve_refuse(
    engine: Engine,
) -> None:
    agreement_id, request_id = _seed(engine, offer_code="off-approve-refuse")

    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    approve_calls: list[object] = []
    real_module_approve = agreements.module_approve

    def counting_module_approve(db: Session, cmd: object) -> object:
        approve_calls.append(cmd)
        return real_module_approve(db, cmd)

    with (
        Session(engine) as db_a,
        mock.patch.object(agreements, "module_approve", counting_module_approve),
    ):
        with pytest.raises(ConflictError, match="not held: withdrawn"):
            agreements.approve(
                db_a,
                agreements.ApprovalCommand(
                    command_id=f"approve-{uuid.uuid4()}",
                    agreement_id=agreement_id,
                    approval_request_id=request_id,
                ),
            )
        db_a.rollback()
    assert approve_calls == [], "the module was asked to approve a withdrawn decision"
    assert _status(engine, agreement_id) == "proposed"


# ── approve in flight: a concurrent withdrawal blocks, then succeeds ────────


def _prove_the_approve_barrier_holds(
    engine: Engine, agreement_id: uuid.UUID, request_id: uuid.UUID
) -> None:
    """Drive session A through the hold with a real pause, and prove:

    - a concurrent withdrawal under a bounded `lock_timeout` blocks and times
      out while A is paused;
    - released, that same withdrawal (retried without a timeout) succeeds —
      A's single commit released the row lock.

    Every failure here is a plain `assert`, matching
    `test_approval_barrier_conformance.py::_prove_the_barrier_holds`.
    """
    mutated = threading.Event()
    release = threading.Event()
    approve_result: list[object] = []
    approve_error: list[BaseException] = []
    real_module_approve = agreements.module_approve

    def paused_module_approve(db: Session, cmd: object) -> object:
        result = real_module_approve(db, cmd)
        mutated.set()
        release.wait(timeout=_LOCK_WAIT)
        return result

    def run_a() -> None:
        try:
            with (
                Session(engine) as db_a,
                mock.patch.object(agreements, "module_approve", paused_module_approve),
            ):
                result = agreements.approve(
                    db_a,
                    agreements.ApprovalCommand(
                        command_id=f"approve-{uuid.uuid4()}",
                        agreement_id=agreement_id,
                        approval_request_id=request_id,
                    ),
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


def test_an_approve_in_flight_blocks_a_concurrent_withdrawal_until_commit(
    engine: Engine,
) -> None:
    agreement_id, request_id = _seed(engine, offer_code="off-approve-inflight")
    _prove_the_approve_barrier_holds(engine, agreement_id, request_id)


# ── activate: withdrawal-first refuses ──────────────────────────────────────


def test_activate_withdraw_first_is_refused_and_the_agreement_stays_approved(
    engine: Engine,
) -> None:
    agreement_id, request_id = _seed(engine, offer_code="off-activate-refuse")
    _approve_and_commit(engine, agreement_id, request_id)

    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    activate_calls: list[object] = []
    real_module_activate = agreements.module_activate

    def counting_module_activate(db: Session, cmd: object) -> object:
        activate_calls.append(cmd)
        return real_module_activate(db, cmd)

    with (
        Session(engine) as db_a,
        mock.patch.object(agreements, "module_activate", counting_module_activate),
    ):
        with pytest.raises(ConflictError, match="not held: withdrawn"):
            agreements.activate(
                db_a,
                agreements.ActivateCommand(
                    command_id=f"activate-{uuid.uuid4()}",
                    agreement_id=agreement_id,
                    approval_request_id=request_id,
                    activation_rule="countersigned",
                    activation_reference="countersignature-1",
                    activation_satisfied_at=datetime.now(UTC),
                ),
            )
        db_a.rollback()
    assert (
        activate_calls == []
    ), "the module was asked to activate on a withdrawn decision"
    assert _status(engine, agreement_id) == "approved"


# ── reinstate: withdrawal-first refuses ─────────────────────────────────────


def test_reinstate_withdraw_first_is_refused_and_the_agreement_stays_suspended(
    engine: Engine,
) -> None:
    agreement_id, request_id = _seed(engine, offer_code="off-reinstate-refuse")
    _approve_and_commit(engine, agreement_id, request_id)
    _activate_and_commit(engine, agreement_id, request_id)
    _suspend_and_commit(engine, agreement_id)
    assert _status(engine, agreement_id) == "suspended"

    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    reinstate_calls: list[object] = []
    real_module_reinstate = agreements.module_reinstate

    def counting_module_reinstate(db: Session, cmd: object) -> object:
        reinstate_calls.append(cmd)
        return real_module_reinstate(db, cmd)

    with (
        Session(engine) as db_a,
        mock.patch.object(agreements, "module_reinstate", counting_module_reinstate),
    ):
        with pytest.raises(ConflictError, match="not held: withdrawn"):
            agreements.reinstate(
                db_a,
                agreements.TransitionCommand(
                    command_id=f"reinstate-{uuid.uuid4()}",
                    agreement_id=agreement_id,
                ),
            )
        db_a.rollback()
    assert (
        reinstate_calls == []
    ), "the module was asked to reinstate on a withdrawn decision"
    assert _status(engine, agreement_id) == "suspended"


# ── transition-first, then withdrawal: standing recorded, not reversed ──────


def test_activate_committed_first_then_withdrawal_leaves_the_agreement_active(
    engine: Engine,
) -> None:
    """The mirror image of the refusal tests above: once `activate` has
    committed, a LATER withdrawal records standing (it still succeeds — the
    row is no longer held) but never reverses the lifecycle transition
    already committed. Reversing an already-committed lifecycle transition is
    S4-B's job (recording standing), not this barrier's."""
    agreement_id, request_id = _seed(engine, offer_code="off-activate-then-withdraw")
    _approve_and_commit(engine, agreement_id, request_id)
    _activate_and_commit(engine, agreement_id, request_id)
    assert _status(engine, agreement_id) == "active"

    with Session(engine) as db_b:
        outcome = _withdraw(
            db_b, request_id=request_id, external_ref=f"withdraw-{uuid.uuid4()}"
        )
        db_b.commit()
    assert outcome.state is ApprovalState.WITHDRAWN

    assert _status(engine, agreement_id) == "active"
