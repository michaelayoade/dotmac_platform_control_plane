"""Two-session proof that REAL replay claims are disjoint (Postgres).

This drives the production query — `transport.pending_deliveries(claim=True)` —
against the migrated licensing tables. An earlier version of this test ran
hand-written `SKIP LOCKED` SQL over a scratch table, which proved only that
Postgres implements SKIP LOCKED: deleting the lock from the service would have
left it green. A concurrency test that cannot fail when the concurrency control
is removed is worse than no test, because it converts an unproven claim into a
believed one.

Lives under `tests/migration` because it needs a real Postgres; SKIP LOCKED is
a no-op on SQLite, so the unit suite structurally cannot prove this.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from vendor_cp.licensing.transport import pending_deliveries


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    # `postgres_url` (conftest) skips locally and FAILS under
    # REQUIRE_POSTGRES_TESTS=1, so this suite can never pass by skipping.
    eng = create_engine(postgres_url, future=True)
    yield eng
    eng.dispose()


@pytest.fixture
def sessions(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture
def two_deliveries(engine: Engine) -> Iterator[tuple[str, str]]:
    """Two eligible deliveries in the REAL tables, with the target, licence and
    issuance rows their FKs require. Inserted with SQL rather than the service
    chain to keep the test about locking; the rows are shaped exactly as the
    service writes them."""
    suffix = uuid.uuid4().hex[:8]
    ids: dict[str, str] = {
        key: str(uuid.uuid4())
        for key in ("target", "licence", "issuance", "d1", "d2", "s1", "s2")
    }
    envelope = json.dumps({"schema": "dotmac-licence-envelope/1"})
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO licence_delivery_targets "
                "(id, target_ref, customer_ref, status) "
                "VALUES (:id, :ref, :cust, 'active')"
            ),
            {"id": ids["target"], "ref": f"target-{suffix}", "cust": f"cust-{suffix}"},
        )
        conn.execute(
            text(
                "INSERT INTO licences (id, customer_ref, product, generation) "
                "VALUES (:id, :cust, 'dotmac-sub', 1)"
            ),
            {"id": ids["licence"], "cust": f"cust-{suffix}"},
        )
        # An allocation is required by the issuance FK; the licensing chain that
        # normally produces one is irrelevant here, so a minimal contract +
        # allocation pair is created to satisfy referential integrity.
        contract_id = str(uuid.uuid4())
        allocation_id = str(uuid.uuid4())
        conn.execute(
            text(
                "INSERT INTO contracts (id, customer_ref, legal_entity, "
                "currency_code, term_start, term_end, status, content_hash, "
                "product_code) VALUES (:id, :cust, 'Dotmac Ltd', 'USD', "
                "'2026-01-01', '2026-12-31', 'active', :hash, 'dotmac-sub')"
            ),
            {"id": contract_id, "cust": f"cust-{suffix}", "hash": f"h-{suffix}"},
        )
        conn.execute(
            text(
                "INSERT INTO allocations (id, contract_id, customer_ref, "
                "content_hash, status, source_event_id) "
                "VALUES (:id, :contract, :cust, :hash, 'staged', :evt)"
            ),
            {
                "id": allocation_id,
                "contract": contract_id,
                "cust": f"cust-{suffix}",
                "hash": f"h-{suffix}",
                "evt": f"evt-{suffix}",
            },
        )
        conn.execute(
            text(
                "INSERT INTO licence_issuances (id, licence_id, allocation_id, "
                "version, digest, key_id, envelope, status) "
                "VALUES (:id, :licence, :alloc, 1, :digest, 'k', "
                "CAST(:envelope AS jsonb), 'issued')"
            ),
            {
                "id": ids["issuance"],
                "licence": ids["licence"],
                "alloc": allocation_id,
                "digest": f"sha256:{suffix}",
                "envelope": envelope,
            },
        )
        for delivery_key, state_key, n in (("d1", "s1", 1), ("d2", "s2", 2)):
            conn.execute(
                text(
                    "INSERT INTO licence_deliveries "
                    "(id, issuance_id, target_ref, target_id) "
                    "VALUES (:id, :issuance, :ref, :target)"
                ),
                {
                    "id": ids[delivery_key],
                    "issuance": ids["issuance"],
                    "ref": f"target-{suffix}-{n}",
                    "target": ids["target"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO licence_delivery_states "
                    "(id, delivery_id, state, replay_generation) "
                    "VALUES (:id, :delivery, 'delivered', 1)"
                ),
                {"id": ids[state_key], "delivery": ids[delivery_key]},
            )
    try:
        yield ids["d1"], ids["d2"]
    finally:
        with engine.begin() as conn:
            for table, key in (
                ("licence_delivery_states", "delivery_id"),
                ("licence_deliveries", "id"),
            ):
                conn.execute(
                    text(f"DELETE FROM {table} WHERE {key} = ANY(:ids)"),  # noqa: S608
                    {"ids": [ids["d1"], ids["d2"]]},
                )
            conn.execute(
                text("DELETE FROM licence_issuances WHERE id = :id"),
                {"id": ids["issuance"]},
            )
            conn.execute(
                text("DELETE FROM allocations WHERE contract_id = :id"),
                {"id": contract_id},
            )
            conn.execute(
                text("DELETE FROM contracts WHERE id = :id"), {"id": contract_id}
            )
            conn.execute(
                text("DELETE FROM licences WHERE id = :id"), {"id": ids["licence"]}
            )
            conn.execute(
                text("DELETE FROM licence_delivery_targets WHERE id = :id"),
                {"id": ids["target"]},
            )


def test_two_workers_claim_disjoint_deliveries(
    sessions: sessionmaker[Session], two_deliveries: tuple[str, str]
) -> None:
    """The property the replay driver depends on, through the REAL query: two
    workers never receive the same delivery, so they cannot compute the same
    next attempt number and race on the unique constraint.

    Remove `with_for_update(skip_locked=True)` from `pending_deliveries` and
    this test fails — which is the whole point of calling the service rather
    than re-implementing its SQL.
    """
    first = sessions()
    second = sessions()
    try:
        claimed_a = pending_deliveries(first, limit=1, claim=True)
        claimed_b = pending_deliveries(second, limit=1, claim=True)

        assert len(claimed_a) == 1
        # SENSITIVITY: B must get the OTHER delivery, not nothing. A query that
        # starved B would otherwise pass this test vacuously.
        assert len(claimed_b) == 1
        assert {d.id for d in claimed_a}.isdisjoint({d.id for d in claimed_b})
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()


def test_a_claimed_delivery_is_skipped_not_waited_on(
    sessions: sessionmaker[Session], two_deliveries: tuple[str, str]
) -> None:
    """A worker must SKIP a peer's in-flight claim rather than block on it —
    blocking would serialise the whole replay fleet behind one slow delivery.
    """
    first = sessions()
    second = sessions()
    try:
        claimed_a = pending_deliveries(first, limit=5, claim=True)
        assert len(claimed_a) == 2  # both eligible and now locked by A

        second.execute(text("SET LOCAL lock_timeout = '2s'"))
        # Returns immediately and empty; a blocking claim would raise a
        # lock-timeout error instead, which this assertion also catches.
        assert pending_deliveries(second, limit=5, claim=True) == []
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()
