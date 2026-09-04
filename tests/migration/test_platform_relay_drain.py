"""The drain, against a real database: activation -> outbox -> allocation.

This is the proof that `vendor_cp.relay` closes the chain, and it is HERE rather
than in `tests/unit` for a reason that decides the value of the whole file.
`claim_platform_outbox_batch` and `settle_platform_outbox_event` are PostgreSQL
`SECURITY DEFINER` functions created by kernel `0012_platform_outbox`. They do
not exist on the in-memory SQLite kit, so a unit-tier version of this test could
only run by faking the claim — and a faked claim proves that the consumer
transports an event it was handed, which is not the defect. The defect is that
nothing handed it one.

So everything below runs against a migrated scratch database, through the
kernel's real worker, with the real leasing SQL and the real settle. Exactly two
things are substituted, and neither is the subject:

* the two DSNs, because the composed defaults point at the process-wide runtime
  that `tests/conftest.py` builds from a deliberately unreachable dummy URL;
* the capability catalogue the consumer resolves per delivery, because it is
  built from configured release pins and held manifest evidence whose own
  verification lives in `tests/unit/test_product_catalogue_config.py` and
  `tests/unit/test_release_evidence_ingestion.py`. What is under test here is
  whether an activation reaches an allocation, not where the catalogue came
  from.

The privilege split is asserted rather than described. Kernel `0012`'s docstring
says the dispatcher role holds EXECUTE on two functions and no table privilege
of any kind; a comment cannot fail, so the refusal is driven.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic import command
from dotmac_commercial_agreements import AGREEMENT_ACTIVATED_V1
from dotmac_kernel.messaging import OutboxStatus, PlatformOutboxEvent
from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter as allocations
from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import adapter as agreements
from vendor_cp.migrations import make_alembic_config
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion
from vendor_cp.relay.health import RelayHealth, RelayVerdict, relay_health
from vendor_cp.relay.models import RelayHeartbeat
from vendor_cp.relay.runner import RelayComposition, drain_once

PRODUCT = "dotmac-sub"
CAPABILITIES = ("cap.a", "cap.b")
DISPATCHER_ROLE = "platform_outbox_dispatcher"
PLATFORM_ROLE = "platform_api"
WINDOW = timedelta(seconds=300)
HEARTBEAT_WINDOW = timedelta(seconds=120)
SETTLED_WINDOW = timedelta(seconds=600)


# ── the database under test ─────────────────────────────────────────────────


@pytest.fixture
def migrated(scratch_db: str, url_for: Callable[..., str]) -> Iterator[tuple[str, str]]:
    """A scratch database at composed heads, plus the two online role DSNs.

    `scratch_db` yields an `app_admin` URL; migrations run as that role so the
    table owner and the grants match production. The dispatcher needs CONNECT,
    which the database OWNER can grant — no superuser is involved, and the
    module migration remains the authority for every schema and table privilege
    below it.
    """
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


# ── the activation that writes the outbox row ───────────────────────────────


def _catalogue() -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({PRODUCT: CAPABILITIES})


def _activate_an_agreement(db: Session) -> agreements.ContractView:
    """Drive the real lifecycle: draft -> propose -> approve -> activate.

    Nothing is inserted by hand. The outbox row this produces is written by
    Commercial Agreements inside its own transaction, which is the only way to
    know the row under test is the row production would write.
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
            lines=(
                agreements.LineInput("off", 1, "cap.a", quantity=2),
                agreements.LineInput("off", 1, "cap.b", quantity=1),
            ),
        ),
        catalogues=catalogues,
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"policy-{uuid.uuid4()}",
            policy_code="commercial",
            version=1,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    proposed = agreements.propose(
        db,
        agreements.ProposeCommand(
            command_id=f"propose-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_policy_code="commercial",
            approval_policy_version=1,
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
    agreements.approve(
        db,
        agreements.ApprovalCommand(
            command_id=f"approve-{uuid.uuid4()}",
            agreement_id=proposed.id,
            approval_request_id=proposed.approval_request_id,
        ),
    )
    return agreements.activate(
        db,
        agreements.ActivateCommand(
            command_id=f"activate-{uuid.uuid4()}",
            agreement_id=proposed.id,
            approval_request_id=proposed.approval_request_id,
            activation_rule="countersigned",
            activation_reference="signature-42",
            activation_satisfied_at=datetime.now(UTC),
        ),
    )


class _FixedCatalogueConsumer(ContractEventConsumer):
    """The real consumer with the catalogue SOURCE pinned. See the module
    docstring: where the catalogue comes from is verified elsewhere, and
    resolving it here would drag configured release pins and a manifest mount
    into a test about whether a drain happens."""

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
        transport=_FixedCatalogueConsumer(),
    )


def _count(db: Session, **where: object) -> int:
    statement = select(func.count()).select_from(PlatformOutboxEvent)
    for column, value in where.items():
        statement = statement.where(getattr(PlatformOutboxEvent, column) == value)
    return int(db.execute(statement).scalar_one())


# ── the chain ───────────────────────────────────────────────────────────────


def test_an_activation_reaches_an_allocation_through_the_real_relay(
    migrated: tuple[str, str],
) -> None:
    """The defect, closed end to end.

    Before this composition existed the row below was written and then sat
    forever: `ContractEventConsumer` was constructed nowhere under `src/` and no
    process claimed a batch, so an activated agreement looked complete while
    producing no entitlement allocation.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            active = _activate_an_agreement(db)
        with platform.platform_session() as db:
            # Exactly one ACTIVATION fact. The queued TOTAL is deliberately
            # derived rather than written down: the lifecycle also emits
            # `proposed` and `approved`, and how many facts the upstream owners
            # publish is their business and will change. A literal here would
            # make this test fail on their next release while proving nothing
            # about the drain.
            assert _count(db, event_type=AGREEMENT_ACTIVATED_V1) == 1
            queued = _count(db, status=OutboxStatus.PENDING.value)
            assert queued >= 1
            assert allocations.list_for_contract(db, active.id) == []

        report = drain_once(
            worker_id="relay-test",
            composition=_composition(dispatcher_url, platform),
        )
        assert report.claimed == queued

        with platform.platform_session() as db:
            staged = allocations.list_for_contract(db, active.id)
            assert len(staged) == 1
            assert staged[0].content_hash == active.content_hash
            assert {(e.capability_code, e.quantity) for e in staged[0].entries} == {
                ("cap.a", 2),
                ("cap.b", 1),
            }
            # Every row is SETTLED, not merely delivered — including the two the
            # consumer ignores. A relay that staged the allocation and failed to
            # settle would redeliver forever, and a consumer that RAISED on a
            # fact it does not handle would dead-letter every other transition.
            assert _count(db, status=OutboxStatus.SENT.value) == queued
            assert _count(db, status=OutboxStatus.PENDING.value) == 0
            # ...and exactly one of them produced an allocation.
            assert _count(db, event_type=AGREEMENT_ACTIVATED_V1) == 1


def test_a_drain_with_nothing_queued_claims_nothing_and_stages_nothing(
    migrated: tuple[str, str],
) -> None:
    """NON-VACUITY for the test above. A `drain_once` that reported a claim
    unconditionally, or a consumer that staged on any delivery, would pass it.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        report = drain_once(
            worker_id="relay-test",
            composition=_composition(dispatcher_url, platform),
        )
        assert report.claimed == 0


def test_redelivering_one_event_stages_nothing_new(
    migrated: tuple[str, str],
) -> None:
    """At-least-once delivery is safe because staging is idempotent on the
    source event id — at both layers, since the module keys its own staging on
    it through `dotmac_kernel.idempotency` too.

    The second drain is driven by resetting the settled row to `pending`, which
    is what a crash between delivery and settle leaves behind. That is the real
    redelivery shape, not a second call with the same argument.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            active = _activate_an_agreement(db)
        composition = _composition(dispatcher_url, platform)
        with platform.platform_session() as db:
            queued = _count(db, status=OutboxStatus.PENDING.value)
        assert (
            drain_once(worker_id="relay-test", composition=composition).claimed
            == queued
        )

        with platform.platform_session() as db:
            first = allocations.list_for_contract(db, active.id)
            assert len(first) == 1
            db.execute(
                text(
                    "UPDATE platform_outbox_events SET status = 'pending', "
                    "sent_at = NULL, leased_by = NULL, leased_at = NULL, "
                    "available_at = now()"
                )
            )

        # The SAME rows are claimed and delivered a second time. That is the
        # shape a crash between delivery and settle leaves behind, and it is
        # what at-least-once means.
        assert (
            drain_once(worker_id="relay-test", composition=composition).claimed
            == queued
        )

        with platform.platform_session() as db:
            again = allocations.list_for_contract(db, active.id)
            assert len(again) == 1
            assert again[0].id == first[0].id


# ── the privilege split, driven rather than described ───────────────────────


def test_the_dispatcher_cannot_read_the_outbox_it_drains(
    migrated: tuple[str, str],
) -> None:
    """Kernel `0012` grants the dispatcher EXECUTE on two functions and NO table
    privilege of any kind. It can lease and settle; it can never read a business
    table, and that includes the outbox itself.

    A migration comment cannot fail. This drives the refusal.
    """
    _platform_url, dispatcher_url = migrated
    with _connect(dispatcher_url) as conn:
        with pytest.raises(ProgrammingError) as refused:
            conn.execute(text("SELECT id FROM platform_outbox_events"))
    assert "permission denied" in str(refused.value).lower()


def test_the_dispatcher_can_still_claim_a_batch(
    migrated: tuple[str, str],
) -> None:
    """NON-VACUITY for the refusal above: a role that could do nothing at all
    would pass it while making the relay impossible. The EXECUTE half must
    work."""
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _activate_an_agreement(db)
        with platform.platform_session() as db:
            queued = _count(db, status=OutboxStatus.PENDING.value)
    assert queued >= 1
    with _connect(dispatcher_url) as conn:
        claimed = conn.execute(
            text(
                "SELECT id FROM claim_platform_outbox_batch("
                "'privilege-canary', 50, 300)"
            )
        ).all()
        conn.commit()
    assert len(claimed) == queued


def test_the_platform_role_can_read_the_outbox(
    migrated: tuple[str, str],
) -> None:
    """The other side of the split, so the refusal above is shown to be about
    the DISPATCHER rather than about the table being unreadable by everyone --
    which is what the readiness probe depends on being true."""
    platform_url, _dispatcher_url = migrated
    with _connect(platform_url) as conn:
        rows = conn.execute(
            text("SELECT count(*) FROM platform_outbox_events")
        ).scalar_one()
    assert rows == 0


# ── health, against the same real table ─────────────────────────────────────


def _observe(
    db: Session,
    *,
    now: datetime,
    heartbeat_stale_after: timedelta = HEARTBEAT_WINDOW,
    settled_within: timedelta = SETTLED_WINDOW,
) -> RelayHealth:
    return relay_health(
        db,
        now=now,
        overdue_after=WINDOW,
        stale_lease_after=WINDOW,
        heartbeat_stale_after=heartbeat_stale_after,
        settled_within=settled_within,
    )


def test_health_reports_a_stopped_relay_and_then_a_draining_one(
    migrated: tuple[str, str],
) -> None:
    """Both directions over rows a real activation wrote and a real drain
    settled, because either alone is satisfied by a function returning a
    constant.

    Before any drain, no worker has ever stamped: the relay has never run, and
    that is what health says — not "backlog overdue", which would describe the
    symptom rather than the cause.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _activate_an_agreement(db)

        with platform.platform_session() as db:
            stopped = _observe(db, now=datetime.now(UTC))
        assert stopped.verdict is RelayVerdict.RELAY_NOT_RUNNING
        assert stopped.relay_ever_reported is False
        assert stopped.heartbeat_age_seconds is None
        assert stopped.activation_overdue == 0  # not yet overdue; it is UNDRAINED

        drain_once(
            worker_id="relay-test",
            composition=_composition(dispatcher_url, platform),
        )

        with platform.platform_session() as db:
            drained = _observe(db, now=datetime.now(UTC))
        assert drained.verdict is RelayVerdict.DRAINING
        assert drained.activation_overdue == 0
        assert drained.observed is True
        assert drained.relay_ever_reported is True
        assert drained.heartbeat_age_seconds is not None


def test_a_real_drain_writes_a_durable_heartbeat(
    migrated: tuple[str, str],
) -> None:
    """The heartbeat is a ROW, written on the delivery connection.

    Asserted against the table rather than against the health verdict, because
    the verdict would also be produced by a reader that invented a timestamp.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _activate_an_agreement(db)
        drain_once(
            worker_id="relay-test",
            composition=_composition(dispatcher_url, platform),
        )
        with platform.platform_session() as db:
            row = db.get(RelayHeartbeat, "relay-test")
            assert row is not None
            assert row.last_polled_at is not None
            # This poll CLAIMED, so both advance.
            assert row.last_claimed_at is not None


def test_an_idle_drain_still_stamps_and_does_not_erase_the_last_claim(
    migrated: tuple[str, str],
) -> None:
    """THE WHOLE REASON THE HEARTBEAT EXISTS.

    A poll that claims nothing must still prove the relay is alive — otherwise
    an idle relay and a dead one produce identical evidence, which is the state
    this table was added to end.

    And `last_claimed_at` must SURVIVE that idle poll. Writing the excluded NULL
    would make every idle cycle look like a worker that has never claimed since
    it started, which is a different and much more alarming fact.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _activate_an_agreement(db)
        composition = _composition(dispatcher_url, platform)
        drain_once(worker_id="relay-test", composition=composition)
        with platform.platform_session() as db:
            first = db.get(RelayHeartbeat, "relay-test")
            assert first is not None
            claimed_at = first.last_claimed_at
            polled_at = first.last_polled_at
        assert claimed_at is not None

        # Nothing left to claim.
        idle = drain_once(worker_id="relay-test", composition=composition)
        assert idle.claimed == 0

        with platform.platform_session() as db:
            second = db.get(RelayHeartbeat, "relay-test")
            assert second is not None
            assert second.last_polled_at > polled_at, "an idle poll must still stamp"
            assert (
                second.last_claimed_at == claimed_at
            ), "an idle poll must not erase the last real claim"


class _RefusingConsumer(_FixedCatalogueConsumer):
    """A transport whose every delivery fails. The wedge, made real.

    Not a stub of the verdict: the kernel worker really does claim the batch,
    really does take the exception, and really does back the row off — so what
    the health surface reads afterwards is the state a wedged production relay
    actually leaves behind.
    """

    def deliver(self, event: object, platform_db: Session) -> None:
        raise RuntimeError("delivery refused by the wedge canary")


def test_a_relay_that_claims_and_settles_nothing_is_wedged_not_healthy(
    migrated: tuple[str, str],
) -> None:
    """THE STATE THAT HIDES, end to end.

    The process is alive and heartbeating — every liveness probe reports it
    healthy — it claims its batch, and nothing is ever settled. That must be RED
    and it must be its own word, because the operator's first action is to read
    the delivery failures rather than to restart anything.

    The windows are chosen so the heartbeat is comfortably INSIDE its staleness
    window while the outbox row is comfortably past its overdue window: the two
    are independent facts, and the point is that liveness alone says healthy.
    """
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _activate_an_agreement(db)
        dispatcher = DatabaseRuntime.from_urls(
            database_url=dispatcher_url, platform_database_url=dispatcher_url
        )
        wedged_composition = RelayComposition(
            dispatcher_sessions=dispatcher.platform_session_factory,
            delivery_sessions=platform.platform_session_factory,
            transport=_RefusingConsumer(),
        )
        report = drain_once(worker_id="relay-test", composition=wedged_composition)
        assert report.claimed >= 1, "the wedge must CLAIM; that is what hides it"

        with platform.platform_session() as db:
            # Nothing settled and nothing staged: the work was picked up and
            # put straight back.
            assert _count(db, status=OutboxStatus.SENT.value) == 0
            assert _count(db, status=OutboxStatus.PENDING.value) >= 1
            observed_at = datetime.now(UTC) + timedelta(seconds=400)
            wedged = _observe(
                db,
                now=observed_at,
                heartbeat_stale_after=timedelta(seconds=900),
                settled_within=timedelta(seconds=60),
            )
        assert wedged.verdict is RelayVerdict.RELAY_WEDGED
        assert wedged.last_settled_age_seconds is None
        # Alive. This is the half a liveness probe would report as healthy.
        assert wedged.heartbeat_age_seconds is not None
        assert wedged.heartbeat_age_seconds < 900


def test_the_same_shape_with_a_working_transport_is_not_wedged(
    migrated: tuple[str, str],
) -> None:
    """NON-VACUITY for the wedge. Identical windows and an identical elapsed
    observation time — only the transport differs — must NOT report a wedge, or
    the verdict is measuring the clock rather than the delivery."""
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _activate_an_agreement(db)
        drain_once(
            worker_id="relay-test",
            composition=_composition(dispatcher_url, platform),
        )
        with platform.platform_session() as db:
            healthy = _observe(
                db,
                now=datetime.now(UTC) + timedelta(seconds=400),
                heartbeat_stale_after=timedelta(seconds=900),
                settled_within=timedelta(seconds=60),
            )
        assert healthy.verdict is not RelayVerdict.RELAY_WEDGED
        assert healthy.verdict is RelayVerdict.DRAINING


def test_health_refuses_to_answer_as_the_dispatcher(
    migrated: tuple[str, str],
) -> None:
    """A GREEN ZERO MUST NEVER MEAN "COULD NOT QUERY".

    The dispatcher cannot read the table, so every count here is unobtainable.
    The observation must come back UNKNOWN with `None` counts — not a tidy row
    of zeros that a dashboard would render exactly like a healthy idle relay.
    This is the failure mode the field types exist for, driven against a real
    privilege refusal rather than a raising stub.
    """
    _platform_url, dispatcher_url = migrated
    with _sessions(dispatcher_url) as dispatcher:
        session = dispatcher.platform_session_factory()
        try:
            health = relay_health(
                session,
                now=datetime.now(UTC),
                overdue_after=WINDOW,
                stale_lease_after=WINDOW,
                heartbeat_stale_after=HEARTBEAT_WINDOW,
                settled_within=SETTLED_WINDOW,
            )
        finally:
            session.rollback()
            session.close()
    assert health.verdict is RelayVerdict.RELAY_STATE_UNKNOWN
    assert health.observed is False
    assert health.pending_total is None
    assert health.dead_total is None
    assert health.activation_overdue is None
