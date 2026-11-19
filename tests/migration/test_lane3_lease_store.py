"""CP-5: Starter's pinned lease conformance suite, and the CP-only cases, on real PG16.

Every `CASES` entry of the vendored S1 suite (`tests/vendored/starter_lane3`, pinned
by sha256) runs against `CpLeaseStore` over the REAL stack: the `v023_lane3_store`
migration as the production migrator, real SECURITY DEFINER functions, a real
per-run lease role (rendered by `lease_role_spec`) and `run_bindings` row for every
handle, real Foundation `HostLease` and `HostLeaseReleaseV1` values, Control a17's
own attestation registry behind the receipts, and one new database connection per
handle (eight for the concurrency case).

The only thing replaced is the clock, and only in the per-case database
(`cp_lane3.store_now()` over a one-row clock the `advance` hook moves), so the
suite's `covers(...) == database_time()` and `released_at == database_time()`
assertions are ones no live clock could satisfy. The production `store_now` is
proven separately (`test_lane3_store_catalogue`).

REQUIRES Foundation (importable in the dedicated required CI step through an exact
checkout); the ordinary migration step skips this file and the dedicated step sets
`LANE3_REQUIRE_FOUNDATION=1`, which turns a missing import into a failure. A skipped
security test is not a passing one.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

try:
    import dotmac_deployment_foundation.lease_release  # noqa: F401
except ImportError:
    if os.environ.get("LANE3_REQUIRE_FOUNDATION") == "1":
        raise
    pytest.skip(
        "Foundation is not importable; the dedicated Lane 3 CI step runs this file",
        allow_module_level=True,
    )


def _support() -> Any:
    name = "lane3_cp_support"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "unit" / "lane3_cp_support.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = _support()
VENDORED = SUPPORT.load_vendored()
LS = VENDORED.lease_store

#: The suite's cases as pinned. A re-vendored suite that adds, removes or renames
#: one fails here, so a changed contract is reviewed rather than inherited.
EXPECTED_CASES = (
    "a_lease_needs_a_typed_e10_receipt",
    "a_lost_connection_fails_closed_and_writes_nothing",
    "a_marker_must_cite_a_different_incarnation_than_the_leases",
    "a_marker_must_cite_a_newer_receipt_than_the_leases",
    "a_marker_must_cite_a_strictly_later_receipt_order",
    "a_marker_must_cite_the_receipt_the_new_lease_is_taken_under",
    "a_release_commit_lost_is_unknown_and_never_retried",
    "a_release_must_match_the_held_lease",
    "an_acquire_commit_lost_is_unknown_and_never_retried",
    "an_untouched_release_may_be_reacquired",
    "covers_is_judged_on_store_time",
    "exclusive_under_concurrent_acquires",
    "expiry_is_a_mutated_host_never_a_clean_release",
    "no_reacquire_after_a_mutated_release",
    "no_reacquire_after_expiry",
    "only_an_explicit_reprovision_marker_reopens_a_mutated_host",
    "only_one_release",
    "released_at_is_store_time_not_the_runners",
    "the_lease_document_expiry_is_the_rows",
    "the_ttl_is_capped",
)


@pytest.fixture
def case(lane3_cases: Any) -> Any:
    return lane3_cases.new()


def _create_lease_role(db: Any, *, host: str = "host-a", run: str = "run-1") -> str:
    """A lease role from the exact `lease_role_spec` statements, bound to one run."""
    from datetime import UTC, datetime

    role = "l3_one_" + os.urandom(6).hex()
    now = datetime.now(UTC)
    verifier = SUPPORT.lease_role_spec.scram_verifier(
        "l" * 24, salt=bytes(range(16)), iterations=4096
    )
    with db.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for statement in SUPPORT.lease_role_spec.executable_creation_sql(
            role,
            host_id=host,
            authorization_run=run,
            scram_verifier_value=verifier,
            valid_until=now + timedelta(hours=3),
            now=now,
        ):
            if statement not in ("BEGIN", "COMMIT"):
                conn.exec_driver_sql(statement)
    db.roles.append(role)
    return role


def test_the_pinned_suite_has_exactly_the_cases_this_pr_runs() -> None:
    assert tuple(sorted(VENDORED.support.CASES)) == EXPECTED_CASES


@pytest.mark.parametrize("case", EXPECTED_CASES)
def test_every_pinned_conformance_case_passes_against_the_cp_store(
    lane3_cases: Any, case: str
) -> None:
    db = lane3_cases.new()
    VENDORED.support.CASES[case](db.make_store, db.advance, db.fixtures())


# ── CP-only cases ───────────────────────────────────────────────────────────


def _acquire(db: Any, store: Any, fx: Any, **extra: Any) -> Any:
    return VENDORED.support._acquire(store, fx, **extra)


def _refused(code: str, call: Any) -> None:
    VENDORED.support._raises(code, call)


def test_the_store_declares_database_time_and_answers_tz_aware(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store = db.make_store()
    assert store.time_authority == "database"
    assert VENDORED.lease_store.require_database_time(store) is store
    instant = store.database_time()
    assert instant.tzinfo is not None
    assert instant == db.now()


def test_released_at_is_none_before_a_release(lane3_cases: Any) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    held = _acquire(db, store, fx)
    assert store.released_at("host-a") is None
    store.release(held, release=fx.make_release(store, held), host_mutated=False)
    assert store.released_at("host-a") == db.now()


@pytest.mark.parametrize("not_a_bool", [1, 0, "true", None, 1.0])
def test_host_mutated_must_be_a_bool(lane3_cases: Any, not_a_bool: object) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    held = _acquire(db, store, fx)
    _refused(
        "host-mutated-required",
        lambda: store.release(
            held, release=fx.make_release(store, held), host_mutated=not_a_bool
        ),
    )
    assert store.standing("host-a") is LS.LeaseStanding.HELD


def _expired_host(db: Any, fx: Any, store: Any) -> Any:
    """host-a leased under receipt 2, then expired unreleased (a mutated host)."""
    held = _acquire(db, store, fx, generation=2)
    db.advance(store, 61)
    assert store.standing("host-a") is LS.LeaseStanding.EXPIRED_MUTATED
    return held


def _marker(db: Any, fx: Any, generation: int) -> Any:
    return LS.ReprovisionMarker("host-a", fx.receipt("host-a", generation))


def test_a_marker_citing_a_receipt_the_store_never_saw_is_refused_unknown(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    _expired_host(db, fx, store)
    real = fx.receipt("host-a", 3)
    ghost = dataclasses.replace(
        real, receipt_ref="e10-" + "0" * 8 + "-0000-0000-0000-" + "0" * 12
    )
    _refused(
        "reprovision-receipt-unknown",
        lambda: _acquire(
            db,
            store,
            fx,
            run="run-2",
            receipt=ghost,
            reprovision=LS.ReprovisionMarker("host-a", ghost),
        ),
    )
    assert store.standing("host-a") is LS.LeaseStanding.EXPIRED_MUTATED


@pytest.mark.parametrize(
    "field", ["machine_id", "vm_alias", "ssh_host_key_fingerprint", "vm_slot"]
)
def test_a_marker_whose_receipt_differs_from_the_stored_row_is_refused_mismatch(
    lane3_cases: Any, field: str
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    _expired_host(db, fx, store)
    real = fx.receipt("host-a", 3)
    altered = {
        "machine_id": "f" * 32,
        "vm_alias": "vm-other",
        "ssh_host_key_fingerprint": "SHA256:" + "C" * 43,
        "vm_slot": "node/9",
    }[field]
    forged = dataclasses.replace(real, **{field: altered})
    _refused(
        "reprovision-receipt-mismatch",
        lambda: _acquire(
            db,
            store,
            fx,
            run="run-2",
            receipt=forged,
            reprovision=LS.ReprovisionMarker("host-a", forged),
        ),
    )


def test_a_marker_whose_destruction_was_never_stamped_is_refused_not_destroyed(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    _expired_host(db, fx, store)
    unsealed = db.unsealed_receipt("host-a", 3)
    _refused(
        "reprovision-receipt-not-destroyed",
        lambda: _acquire(
            db,
            store,
            fx,
            run="run-2",
            receipt=unsealed,
            reprovision=LS.ReprovisionMarker("host-a", unsealed),
        ),
    )
    assert store.standing("host-a") is LS.LeaseStanding.EXPIRED_MUTATED


def test_a_marker_whose_enrolment_is_no_longer_the_current_root_is_refused(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    _expired_host(db, fx, store)
    newer = fx.receipt("host-a", 3)
    with SUPPORT.Session(db.admin) as session:  # revoke the newer incarnation's root
        db.registry.revoke(
            session,
            fingerprint=newer.incarnation_fingerprint,
            reason="test",
            revoked_at=db.now(),
        )
        session.commit()
    _refused(
        "reprovision-receipt-not-current-root",
        lambda: _acquire(
            db,
            store,
            fx,
            run="run-2",
            receipt=newer,
            reprovision=LS.ReprovisionMarker("host-a", newer),
        ),
    )
    assert store.standing("host-a") is LS.LeaseStanding.EXPIRED_MUTATED


def test_a_plain_acquire_under_a_superseded_or_unsealed_receipt_is_refused(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    first = fx.receipt("host-a", 1)
    fx.receipt("host-a", 2)  # rotates host-a's root away from receipt 1
    _refused(
        "e10-receipt-not-current-root",
        lambda: _acquire(db, store, fx, receipt=first),
    )
    unsealed = db.unsealed_receipt("host-b", 1)
    _refused(
        "e10-receipt-not-destroyed",
        lambda: _acquire(db, store, fx, host="host-b", receipt=unsealed),
    )


def test_a_receipt_is_spent_once_a_marker_has_cited_it(lane3_cases: Any) -> None:
    """`-spent` is defence in depth: the strict newer-than-the-lease's-receipt rule
    refuses a re-cite first in every normal sequence. So the state it guards is
    constructed by the OWNER (re-pointing the host at an older lease), and the UNIQUE
    constraint behind it is proven as a constraint too."""
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    first = _acquire(db, store, fx, generation=1)
    db.advance(store, 61)
    second = _acquire(
        db, store, fx, run="run-2", generation=2, reprovision=_marker(db, fx, 2)
    )
    db.advance(store, 61)
    # The owner rewinds the row-lock pointer to the FIRST lease (receipt 1).
    with db.admin.begin() as conn:
        conn.execute(
            text(
                "UPDATE cp_lane3.host_current_lease SET lease_id = CAST(:id AS uuid) "
                "WHERE host_id = 'host-a'"
            ),
            {"id": first.handle},
        )
    _refused(
        "reprovision-receipt-spent",
        lambda: _acquire(
            db, store, fx, run="run-3", generation=2, reprovision=_marker(db, fx, 2)
        ),
    )
    # And the constraint itself: a second lease citing the same receipt is a
    # unique violation, whatever path reached the insert.
    with pytest.raises(Exception, match="host_leases_reprovision_receipt_ref_key"):  # noqa: B017
        with db.admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO cp_lane3.host_leases (lease_id, host_id, "
                    "authorization_run, controller_identity, workload_principal, "
                    "e10_receipt_ref, reprovision_receipt_ref, acquired_at, "
                    "expires_at, ttl_seconds) SELECT gen_random_uuid(), host_id, "
                    "authorization_run, controller_identity, workload_principal, "
                    "e10_receipt_ref, reprovision_receipt_ref, acquired_at + "
                    "interval '1 day', acquired_at + interval '1 day 1 minute', 60 "
                    "FROM cp_lane3.host_leases WHERE lease_id = CAST(:id AS uuid)"
                ),
                {"id": second.handle},
            )


# ── Q1-B: a killed connection ───────────────────────────────────────────────


def _kill_before_the_commit_reaches_the_server(db: Any, store: Any) -> None:
    conn = store._connection()
    pid = conn.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
    conn.rollback()
    real = conn.commit

    def terminate_then_commit() -> None:
        with db.admin.begin() as admin:
            admin.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        time.sleep(0.2)
        real()  # the COMMIT never reaches a live backend

    conn.commit = terminate_then_commit  # type: ignore[method-assign]


def test_a_connection_killed_between_acquire_and_commit_leaves_no_lease(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, survivor, fx = db.make_store(), db.make_store(), db.fixtures()
    _kill_before_the_commit_reaches_the_server(db, store)
    with pytest.raises(LS.StoreRefused) as refused:
        _acquire(db, store, fx)
    # The client cannot tell whether the COMMIT arrived: it says so, and never retries.
    assert refused.value.code in {LS.STORE_COMMIT_UNKNOWN, LS.STORE_UNREACHABLE}
    with db.admin.begin() as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM cp_lane3.host_leases")).scalar_one()
            == 0
        )
    _refused("lease-host-unknown", lambda: survivor.standing("host-a"))
    held = _acquire(db, survivor, fx, run="run-2")
    assert survivor.standing("host-a") is LS.LeaseStanding.HELD
    assert held is not None
    _refused(LS.STORE_UNREACHABLE, lambda: _acquire(db, store, fx, run="run-3"))


def test_a_connection_killed_during_the_release_commit_is_unknown_and_consistent(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, survivor, fx = db.make_store(), db.make_store(), db.fixtures()
    held = _acquire(db, store, fx)
    release = fx.make_release(store, held)
    _kill_before_the_commit_reaches_the_server(db, store)
    with pytest.raises(LS.StoreRefused) as refused:
        store.release(held, release=release, host_mutated=True)
    assert refused.value.code == LS.STORE_COMMIT_UNKNOWN
    # The commit never landed: the lease is still HELD and nothing is recorded...
    assert survivor.standing("host-a") is LS.LeaseStanding.HELD
    with db.admin.begin() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM cp_lane3.host_lease_releases")
        ).scalar_one()
    assert count == 0
    # ...so the release can be written exactly once, by a NEW handle.
    survivor.release(held, release=fx.make_release(survivor, held), host_mutated=True)
    assert survivor.standing("host-a") is LS.LeaseStanding.RELEASED


# ── isolation between hosts, and the lease role's own reach ─────────────────


def test_a_held_row_lock_on_host_a_does_not_block_host_b(lane3_cases: Any) -> None:
    db = lane3_cases.new()
    store_a, store_b, fx = db.make_store(), db.make_store(), db.fixtures()
    _acquire(db, store_a, fx, host="host-a")  # creates host-a's lock row
    db.advance(store_a, 61)
    locked = threading.Event()
    done = threading.Event()

    def hold() -> None:
        with db.admin.connect() as conn:
            conn.execute(
                text(
                    "SELECT 1 FROM cp_lane3.host_current_lease "
                    "WHERE host_id='host-a' FOR UPDATE"
                )
            )
            locked.set()
            done.wait(timeout=30)
            conn.rollback()

    holder = threading.Thread(target=hold)
    holder.start()
    try:
        assert locked.wait(timeout=10)
        started = time.monotonic()
        held = _acquire(db, store_b, fx, host="host-b")
        assert time.monotonic() - started < 3
        assert held.lease.target == "host-b"
    finally:
        done.set()
        holder.join(timeout=30)


def test_a_lease_role_without_a_binding_is_refused_by_every_function(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    fx = db.fixtures()
    bound = db.make_store()
    receipt = fx.receipt("host-a", 1)
    role = "l3_unbound_" + os.urandom(4).hex()
    functions = ", ".join(
        f"cp_lane3.{sig}" for sig in SUPPORT.lease_role_spec.LEASE_FUNCTIONS
    )
    with db.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'CREATE ROLE "{role}" LOGIN NOINHERIT CONNECTION LIMIT 2')
        conn.exec_driver_sql(f'GRANT USAGE ON SCHEMA cp_lane3 TO "{role}"')
        conn.exec_driver_sql(f'GRANT EXECUTE ON FUNCTION {functions} TO "{role}"')
    db.roles.append(role)
    store = SUPPORT.CpLeaseStore(
        lambda: SUPPORT.create_engine(db._url_for_role(role)).connect(),
        workload_principal=VENDORED.support.PRINCIPAL,
        refused=LS.StoreRefused,
        held_lease=LS.HeldLease,
        standing_enum=LS.LeaseStanding,
    )
    _refused("lease-role-unbound", store.database_time)
    _refused("lease-role-unbound", lambda: store.standing("host-a"))
    _refused("lease-role-unbound", lambda: store.released_at("host-a"))
    _refused("lease-role-unbound", lambda: _acquire(db, store, fx))
    held = _acquire(db, bound, fx)
    _refused(
        "lease-role-unbound", lambda: store.covers(held, authorization_run="run-1")
    )
    _refused(
        "lease-role-unbound",
        lambda: store.e10_receipt(
            host_id="host-a", authorization_run="run-1", receipt_ref=receipt.receipt_ref
        ),
    )
    store.close()


def test_a_binding_is_for_one_host_and_one_run(lane3_cases: Any) -> None:
    db = lane3_cases.new()
    fx = db.fixtures()
    store = db.make_store()
    # The table is append-only: the owner steps over the guard (test setup only) to
    # leave this one role with exactly one binding.
    with db.admin.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(text("DELETE FROM cp_lane3.run_bindings"))
        role = db.roles[-1]
        conn.execute(
            text(
                "INSERT INTO cp_lane3.run_bindings (role_name, host_id, "
                "authorization_run, valid_until, created_at, recorded_by) VALUES "
                "(:r, 'host-a', 'run-1', :until, :now, 'test')"
            ),
            {"r": role, "until": db.now() + timedelta(hours=2), "now": db.now()},
        )
    assert _acquire(db, store, fx, host="host-a", run="run-1") is not None
    _refused(
        "lease-role-unbound",
        lambda: _acquire(db, store, fx, host="host-a", run="run-2"),
    )
    _refused(
        "lease-role-unbound",
        lambda: _acquire(db, store, fx, host="host-b", run="run-1"),
    )


def test_an_expired_binding_is_refused_on_store_time(lane3_cases: Any) -> None:
    db = lane3_cases.new()
    fx = db.fixtures()
    store = db.make_store()
    fx.receipt("host-a", 1)
    db.advance(store, 3 * 3600 + 5)
    _refused("lease-role-unbound", store.database_time)


def test_the_lease_role_gets_42501_on_direct_table_and_internal_function_access(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store = db.make_store()
    conn = store._connection()
    for statement in (
        "SELECT * FROM cp_lane3.host_leases",
        "SELECT * FROM cp_lane3.e10_receipts",
        "SELECT * FROM cp_lane3.run_bindings",
        "INSERT INTO cp_lane3.host_leases (lease_id) VALUES (gen_random_uuid())",
        "UPDATE cp_lane3.host_current_lease SET lease_id = NULL",
        "SELECT cp_lane3.store_now()",
        "SELECT cp_lane3.require_binding('host-a', 'run-1')",
        "SELECT nextval('cp_lane3.e10_receipts_seq_seq')",
    ):
        with pytest.raises(ProgrammingError) as caught:
            conn.exec_driver_sql(statement)
        assert getattr(caught.value.orig, "sqlstate", None) == "42501", statement
        conn.rollback()


def test_the_lease_document_is_the_row(lane3_cases: Any) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    held = _acquire(db, store, fx, ttl=90)
    with db.admin.begin() as conn:
        row = conn.execute(
            text(
                "SELECT lease_bytes, lease_digest, acquired_at, expires_at, "
                "encode(sha256(lease_bytes), 'hex') AS h FROM cp_lane3.host_leases "
                "WHERE lease_id = CAST(:id AS uuid)"
            ),
            {"id": held.handle},
        ).one()
    from dotmac_deployment_foundation.lease_release import lease_digest

    assert row.lease_digest == lease_digest(held.lease) == "sha256:" + row.h
    document = held.lease.as_document()
    assert (
        bytes(row.lease_bytes)
        == __import__("json")
        .dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        .encode()
    )
    assert held.acquired_at == row.acquired_at and held.expires_at == row.expires_at
    assert (row.expires_at - row.acquired_at) == timedelta(seconds=90)


def test_a_second_document_bind_and_a_wrong_digest_are_refused(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    held = _acquire(db, store, fx)
    conn = store._connection()
    for digest in ("sha256:" + "0" * 64,):
        with pytest.raises(DBAPIError) as caught:
            conn.execute(
                text("SELECT cp_lane3.bind_document(CAST(:i AS uuid), :b, :d)"),
                {"i": held.handle, "b": b"{}", "d": digest},
            )
        conn.rollback()
        assert caught.value.orig.diag.message_primary in {  # type: ignore[union-attr]
            "lease-document-already-bound",
            "lease-document-digest-mismatch",
        }
    with pytest.raises(DBAPIError) as caught:
        conn.execute(
            text("SELECT cp_lane3.bind_document(CAST(:i AS uuid), :b, :d)"),
            {
                "i": held.handle,
                "b": b"{}",
                "d": "sha256:" + __import__("hashlib").sha256(b"{}").hexdigest(),
            },
        )
    conn.rollback()
    assert caught.value.orig.diag.message_primary == "lease-document-already-bound"  # type: ignore[union-attr]


def test_the_store_serves_the_receipt_it_verifies(lane3_cases: Any) -> None:
    """The launcher reads its E10ReceiptRef from the STORE, never a workflow input."""
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    receipt = fx.receipt("host-a", 1)
    served = store.e10_receipt(
        host_id="host-a", authorization_run="run-1", receipt_ref=receipt.receipt_ref
    )
    assert served["receipt_ref"] == receipt.receipt_ref
    rebuilt = VENDORED.e10_receipt.E10ReceiptRef(
        **{
            **served,
            "incarnation_key_destroyed_at": __import__(
                "datetime"
            ).datetime.fromisoformat(served["incarnation_key_destroyed_at"]),
        }
    )
    assert rebuilt == receipt
    _refused(
        "e10-receipt-unknown",
        lambda: store.e10_receipt(
            host_id="host-a",
            authorization_run="run-1",
            receipt_ref="e10-00000000-0000-0000-0000-000000000000",
        ),
    )
    _refused(
        "e10-receipt-for-another-host",
        lambda: store.e10_receipt(
            host_id="host-b", authorization_run="run-1", receipt_ref=receipt.receipt_ref
        ),
    )
    unsealed = db.unsealed_receipt("host-b", 1)
    _refused(
        "e10-receipt-not-destroyed",
        lambda: store.e10_receipt(
            host_id="host-b",
            authorization_run="run-1",
            receipt_ref=unsealed.receipt_ref,
        ),
    )


# ── moved from the catalogue file: they need the vendored suite's store ──────


def test_the_row_lock_row_is_never_removed_and_its_key_never_changes(case: Any) -> None:
    store, fx = case.make_store(), case.fixtures()
    VENDORED.support._acquire(store, fx)
    for statement in (
        "DELETE FROM cp_lane3.host_current_lease",
        "TRUNCATE cp_lane3.host_current_lease",
        "UPDATE cp_lane3.host_current_lease SET host_id = 'host-z'",
    ):
        with pytest.raises(DBAPIError):
            with case.admin.begin() as conn:
                conn.execute(text(statement))


def test_a_lease_row_can_only_ever_gain_its_document_once(case: Any) -> None:
    store, fx = case.make_store(), case.fixtures()
    held = VENDORED.support._acquire(store, fx)
    for statement in (
        "UPDATE cp_lane3.host_leases SET ttl_seconds = 5",
        "UPDATE cp_lane3.host_leases SET expires_at = expires_at + interval '1 day'",
        "UPDATE cp_lane3.host_leases SET lease_bytes = '\\x00'::bytea",
        "UPDATE cp_lane3.host_leases SET lease_bytes = NULL, lease_digest = NULL",
    ):
        with pytest.raises(DBAPIError):
            with case.admin.begin() as conn:
                conn.execute(text(statement))
    assert held is not None


@pytest.mark.parametrize("ttl", [0, -1, 3601, 10**6])
def test_a_lease_ttl_outside_one_to_3600_is_refused_by_the_table(
    case: Any, ttl: int
) -> None:
    with pytest.raises(DBAPIError):
        with case.admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO cp_lane3.host_current_lease (host_id) VALUES ('host-q')"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO cp_lane3.host_leases (lease_id, host_id, "
                    "authorization_run, controller_identity, workload_principal, "
                    "e10_receipt_ref, acquired_at, expires_at, ttl_seconds) VALUES "
                    "(gen_random_uuid(), 'host-q', 'run', :c, 'principal', 'x', now(), "
                    "now() + interval '1 hour', :t)"
                ),
                {"c": "SHA256:" + "A" * 43, "t": ttl},
            )


# ── privileges (design 3.5) ─────────────────────────────────────────────────


def test_the_same_role_cannot_take_a_lease_outside_its_binding(case: Any) -> None:
    """The binding, enforced by the function and not only read by the proof."""
    support = _support().load_vendored().support
    role = _create_lease_role(case, host="host-a", run="run-1")
    store = _support().CpLeaseStore(
        lambda: create_engine(case._url_for_role(role)).connect(),
        workload_principal=support.PRINCIPAL,
        refused=_support().load_vendored().lease_store.StoreRefused,
        held_lease=_support().load_vendored().lease_store.HeldLease,
        standing_enum=_support().load_vendored().lease_store.LeaseStanding,
    )
    fx = case.fixtures()
    for host, run in (("host-a", "run-2"), ("host-b", "run-1")):
        with pytest.raises(
            _support().load_vendored().lease_store.StoreRefused
        ) as caught:
            support._acquire(store, fx, host=host, run=run)
        assert caught.value.code == "lease-role-unbound"
    assert support._acquire(store, fx, host="host-a", run="run-1") is not None
    store.close()


# ── architect review findings M1-M3 ─────────────────────────────────────────


def _close_fingerprint_keeping_the_view(db: Any, fingerprint: str) -> None:
    """A closure names the fingerprint while `attestation_current_roots` STILL does:
    the shape the first cut's "current root" test could not see."""
    with db.admin.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO mod_deploy.attestation_fingerprint_closures "
                "(fingerprint, closure_kind, closed_at, closure_authority) "
                "VALUES (:f, 'revoked', now(), 'test')"
            ),
            {"f": fingerprint},
        )
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM mod_deploy.attestation_current_roots "
                    "WHERE current_fingerprint = :f"
                ),
                {"f": fingerprint},
            ).scalar_one()
            == 1
        )


def test_m2_a_receipt_whose_fingerprint_is_named_by_any_closure_is_not_current(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    receipt = fx.receipt("host-a", 1)
    store.e10_receipt(
        host_id="host-a", authorization_run="run-1", receipt_ref=receipt.receipt_ref
    )  # current: served
    _close_fingerprint_keeping_the_view(db, receipt.incarnation_fingerprint)
    _refused(
        "e10-receipt-not-current-root",
        lambda: store.e10_receipt(
            host_id="host-a",
            authorization_run="run-1",
            receipt_ref=receipt.receipt_ref,
        ),
    )
    _refused(
        "e10-receipt-not-current-root",
        lambda: _acquire(db, store, fx, receipt=receipt),
    )


def test_m3_acquire_judges_the_destruction_against_the_stored_whole_second(
    lane3_cases: Any,
) -> None:
    """E9 requires destroyed <= acquired, and `acquired_at` is stored truncated to
    the second. A destruction inside the same second must be refused (fail closed:
    retry next second), and an accepted run always satisfies E9's check."""
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    db.advance(store, 0.5)
    receipt = fx.receipt("host-a", 1)  # destroyed at start + 0.5 s
    db.advance(store, 0.25)  # start + 0.75 s: same second as the destruction
    _refused(
        "e10-receipt-not-destroyed", lambda: _acquire(db, store, fx, receipt=receipt)
    )
    db.advance(store, 0.25)  # start + 1.0 s: the next whole second
    held = _acquire(db, store, fx, receipt=receipt)
    with db.admin.begin() as conn:
        destroyed = conn.execute(
            text(
                "SELECT destroyed_at FROM cp_lane3.e10_destructions "
                "WHERE receipt_ref = :r"
            ),
            {"r": receipt.receipt_ref},
        ).scalar_one()
    assert destroyed <= held.acquired_at
    assert held.acquired_at.microsecond == 0


def _raw_release(
    db: Any,
    store: Any,
    fx: Any,
    held: Any,
    *,
    mutate: Any = None,
    raw: bytes | None = None,
    host_mutated: bool = False,
    record_released_at: Any = None,
) -> str:
    import hashlib
    import json
    from datetime import datetime

    release = fx.make_release(store, held)
    document = release.as_document()
    if mutate is not None:
        mutate(document)
    data = (
        raw
        if raw is not None
        else json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )
    conn = store._connection()
    try:
        return str(
            conn.execute(
                text(
                    "SELECT cp_lane3.release(CAST(:id AS uuid), :b, :d, :ld, :by, "
                    ":ctl, :at, :m)"
                ),
                {
                    "id": held.handle,
                    "b": data,
                    "d": "sha256:" + hashlib.sha256(data).hexdigest(),
                    "ld": release.lease_digest,
                    "by": release.released_by.subject,
                    "ctl": str(release.controller_identity_fingerprint),
                    "at": record_released_at
                    or datetime.fromisoformat(release.released_at),
                    "m": host_mutated,
                },
            ).scalar_one()
        )
    except DBAPIError as exc:
        conn.rollback()
        raise LS.StoreRefused(str(exc.orig.diag.message_primary)) from None  # type: ignore[union-attr]


def _raw_refused(code: str, call: Any) -> None:
    try:
        call()
    except LS.StoreRefused as exc:
        assert exc.code == code, f"expected {code}, got {exc.code}"
        return
    raise AssertionError(f"expected {code}, but nothing was refused")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(lease_digest="sha256:" + "0" * 64),
        lambda d: d.update(controller_identity_fingerprint="SHA256:" + "C" * 43),
        lambda d: d["released_by"].update(subject="repo:someone/else:ref:x"),
        lambda d: d.update(authorization_run_id="run-other"),
        lambda d: d.update(released_at="2001-01-01T00:00:00+00:00"),
        lambda d: d.pop("released_by"),
    ],
    ids=[
        "lease_digest",
        "controller",
        "released_by",
        "authorization_run",
        "released_at",
        "released_by_absent",
    ],
)
def test_m1_a_release_document_that_disagrees_with_the_parameters_is_refused(
    lane3_cases: Any, mutate: Any
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    held = _acquire(db, store, fx)
    _raw_refused(
        "release-not-this-lease",
        lambda: _raw_release(db, store, fx, held, mutate=mutate),
    )
    with db.admin.begin() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM cp_lane3.host_lease_releases")
            ).scalar_one()
            == 0
        )
    assert store.standing("host-a") is LS.LeaseStanding.HELD


@pytest.mark.parametrize("raw", [b"not json", b"\xff\xfe", b"[]", b"null"])
def test_m1_unparseable_release_bytes_are_refused_with_the_typed_code(
    lane3_cases: Any, raw: bytes
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    held = _acquire(db, store, fx)
    _raw_refused(
        "release-not-this-lease",
        lambda: _raw_release(db, store, fx, held, raw=raw),
    )


def test_m1_host_mutated_false_needs_a_reusable_closure_and_a_faithful_document_passes(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    store, fx = db.make_store(), db.fixtures()
    held = _acquire(db, store, fx)
    for closure in ("inspection_required", "destroy_only", "", None):
        _raw_refused(
            "release-not-this-lease",
            lambda closure=closure: _raw_release(
                db,
                store,
                fx,
                held,
                mutate=lambda d: d.update(closure=closure),
                host_mutated=False,
            ),
        )
    assert store.standing("host-a") is LS.LeaseStanding.HELD
    # a mutated host may carry a restricted closure
    assert _raw_release(
        db,
        store,
        fx,
        held,
        mutate=lambda d: d.update(closure="inspection_required"),
        host_mutated=True,
    )
    assert store.standing("host-a") is LS.LeaseStanding.RELEASED
