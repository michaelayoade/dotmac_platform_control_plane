"""WP5c: the production (deploy) lease class on a real PG16 (`v024_deploy_lease`).

Every case runs the REAL migration chain as the production migrator and calls the
four `cp_deploy_lease` functions as the real CP runtime role `platform_api` over
its own connection, through `DeployLeaseStore`. The clock is the one thing
replaced, and only in the per-case database (`cp_lane3.store_now()` over a one-row
clock the `advance` hook moves), exactly as the rehearsal class's suite does, so
expiry and store-time assertions are exact. The production `store_now` is proven
by `test_lane3_store_catalogue`; the deploy class calls THAT function.

## The vendored lease CASES, re-run for the deploy class

The pinned Starter suite (`tests/vendored/starter_lane3`) is written against
Foundation's rehearsal `HostLease` (whose holder is fixed to the rehearsal token),
the typed E10 receipt and the rehearsal mutation rule. The deploy class has none of
the three, so the suite cannot run verbatim. `DEPLOY_CASE_MAP` states, for EVERY
pinned case, which test below re-runs its contract for the deploy class, or that
the case does not apply and why. `test_deploy_case_map_names_exactly_the_pinned_cases`
keeps the map equal to the pinned set (the Foundation step compares it with the
live vendored suite in `test_deploy_lease_cross_class`).

Cross-class exclusion (one writer per host across both classes) needs a real
rehearsal acquire, which needs Foundation: it is proven in
`test_deploy_lease_cross_class.py`.
"""

# ruff: noqa: E501 - case-map names and SQL strings are one token each
from __future__ import annotations

import ast
import importlib.util
import re
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from vendor_cp.deployment import lease_store
from vendor_cp.deployment.deploy_lease import DeployLeaseRefused, DeployLeaseStore

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = ROOT / "alembic" / "versions" / "v024_deploy_lease.py"

HOST = "host-a"
TARGET = "dotmac_erp/production/erp-prod-1"
RUN = "dispatch-run-1"
PRINCIPAL = "target-credential-1"
MARKER_1 = "sha256:" + "1" * 64
MARKER_2 = "sha256:" + "2" * 64

RUNTIME_FUNCTIONS = (
    "deploy_acquire(text, text, text, integer, text, text)",
    "deploy_covers(uuid, text)",
    "deploy_release(uuid, text, text, boolean)",
    "deploy_standing(text)",
)

#: The pinned Starter case names (S1 #1094 at the pinned commit), one entry each.
#: value = the test that re-runs the contract for the deploy class, or
#: ("n/a", reason). A deploy lease takes no E10 receipt, no Foundation HostLease
#: and no per-handle connection, and the persistent-host rule INVERTS the
#: rehearsal's "a mutated release is never reacquired".
DEPLOY_CASE_MAP: dict[str, str | tuple[str, str]] = {
    "a_lease_needs_a_typed_e10_receipt": (
        "n/a",
        "the deploy class takes no E10 receipt; identity is the asserted principal "
        "(test_deploy_lease_malformed_identity_refused)",
    ),
    "a_lost_connection_fails_closed_and_writes_nothing": (
        "n/a",
        "NOT COVERED for the deploy class: the CP application's own session, not a "
        "per-handle connection; DeployLeaseStore maps it to store-unreachable "
        "without a test here",
    ),
    "a_marker_must_cite_a_different_incarnation_than_the_leases": (
        "n/a",
        "no incarnation or receipt in the deploy class; the reconcile marker is "
        "judged by Control (test_reconcile_marker_requires_match)",
    ),
    "a_marker_must_cite_a_newer_receipt_than_the_leases": (
        "n/a",
        "as above: no receipt order in the deploy class",
    ),
    "a_marker_must_cite_a_strictly_later_receipt_order": (
        "n/a",
        "as above: no receipt order in the deploy class",
    ),
    "a_marker_must_cite_the_receipt_the_new_lease_is_taken_under": (
        "n/a",
        "as above: the marker is a digest the application asserts, spent once "
        "(test_deploy_lease_marker_is_spent_once)",
    ),
    "a_release_commit_lost_is_unknown_and_never_retried": (
        "n/a",
        "NOT COVERED for the deploy class: the caller owns the transaction; "
        "DeployLeaseStore never retries and never commits",
    ),
    "a_release_must_match_the_held_lease": "test_deploy_lease_release_must_name_the_holder",
    "an_acquire_commit_lost_is_unknown_and_never_retried": (
        "n/a",
        "NOT COVERED for the deploy class: as for the release commit",
    ),
    "an_untouched_release_may_be_reacquired": "test_deploy_lease_released_is_clean_whatever_host_mutated",
    "covers_is_judged_on_store_time": "test_deploy_lease_covers_is_judged_on_store_time",
    "exclusive_under_concurrent_acquires": "test_deploy_lease_exclusive_under_concurrent_acquires",
    "expiry_is_a_mutated_host_never_a_clean_release": "test_deploy_lease_expired_unreleased_is_never_a_clean_release",
    "no_reacquire_after_a_mutated_release": "test_deploy_lease_released_is_clean_whatever_host_mutated",
    "no_reacquire_after_expiry": "test_deploy_acquire_requires_marker",
    "only_an_explicit_reprovision_marker_reopens_a_mutated_host": "test_deploy_acquire_requires_marker",
    "only_one_release": "test_deploy_lease_double_release_refused",
    "released_at_is_store_time_not_the_runners": "test_deploy_lease_time_is_store_time",
    "the_lease_document_expiry_is_the_rows": "test_deploy_lease_time_is_store_time",
    "the_ttl_is_capped": "test_deploy_lease_ttl_is_capped",
}


def test_deploy_case_map_names_exactly_the_pinned_cases() -> None:
    pinned = ROOT / "tests" / "vendored" / "starter_lane3" / "lane3_store_support.py"
    names = {
        node.name.removeprefix("case_")
        for node in ast.parse(pinned.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("case_")
    }
    assert len(names) >= 20, "the pinned case functions were not found"
    assert set(DEPLOY_CASE_MAP) == names


def test_deploy_case_map_points_at_tests_that_exist() -> None:
    module = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    tests = {n.name for n in module.body if isinstance(n, ast.FunctionDef)}
    for case, target in DEPLOY_CASE_MAP.items():
        if isinstance(target, str):
            assert target in tests, (case, target)
        else:
            assert target[0] == "n/a" and target[1].strip(), case


def _migration() -> Any:
    spec = importlib.util.spec_from_file_location("v024_for_test", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_sql_refusal_code_is_in_the_closed_set() -> None:
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    codes = set(re.findall(r'_refuse\("([a-z0-9-]+)"\)', source))
    assert len(codes) >= 9
    assert codes - lease_store.REFUSAL_CODES == set()


# ── harness ─────────────────────────────────────────────────────────────────


class Runtime:
    """One CP runtime connection source over one case database."""

    def __init__(self, db: Any, url_for: Any, postgres_url: str, role: str) -> None:
        self.db = db
        self.engine: Engine = create_engine(
            url_for(postgres_url, db.admin.url.database, user=role)
        )

    def call(self, fn: Callable[[DeployLeaseStore], Any]) -> Any:
        """One call on its own connection and transaction: a refusal rolls back."""
        with self.engine.connect() as conn:
            try:
                result = fn(DeployLeaseStore(conn))
            except BaseException:
                conn.rollback()
                raise
            conn.commit()
            return result

    def acquire(self, **kw: Any) -> Any:
        args: dict[str, Any] = {
            "target_ref": TARGET,
            "host_id": HOST,
            "dispatch_run": RUN,
            "ttl_seconds": 60,
            "principal_ref": PRINCIPAL,
        }
        args.update(kw)
        return self.call(lambda s: s.acquire(**args))

    def covers(self, lease: Any, run: str = RUN) -> Any:
        return self.call(lambda s: s.covers(lease_id=lease.lease_id, dispatch_run=run))

    def release(self, lease: Any, **kw: Any) -> Any:
        args: dict[str, Any] = {
            "lease_id": lease.lease_id,
            "dispatch_run": RUN,
            "principal_ref": PRINCIPAL,
            "host_mutated": True,
        }
        args.update(kw)
        return self.call(lambda s: s.release(**args))

    def standing(self, host: str = HOST) -> Any:
        return self.call(lambda s: s.standing(host))

    def dispose(self) -> None:
        self.engine.dispose()


@pytest.fixture
def env(lane3_cases: Any, postgres_url: str, url_for: Any) -> Any:
    db = lane3_cases.new()
    runtime = Runtime(db, url_for, postgres_url, "platform_api")
    try:
        yield db, runtime
    finally:
        runtime.dispose()


def _refused(code: str, call: Callable[[], Any]) -> None:
    with pytest.raises(DeployLeaseRefused) as raised:
        call()
    assert raised.value.code == code


def _scalar(db: Any, sql: str, **params: Any) -> Any:
    with db.admin.begin() as conn:
        return conn.execute(text(sql), params).scalar_one()


# ── the lease contract, re-run for the deploy class ─────────────────────────


def test_deploy_lease_acquire_covers_release_roundtrip(env: Any) -> None:
    db, rt = env
    lease = rt.acquire()
    assert lease.expires_at - lease.acquired_at == timedelta(seconds=60)
    assert rt.standing().standing == "held"
    assert rt.covers(lease) == db.now()
    released_at = rt.release(lease, host_mutated=True)
    assert released_at == db.now()
    assert rt.standing().standing == "released"


def test_deploy_lease_exclusive_under_concurrent_acquires(env: Any) -> None:
    _db, rt = env
    count = 8
    barrier = threading.Barrier(count)
    outcomes: list[Any] = []
    guard = threading.Lock()

    def worker(i: int) -> None:
        barrier.wait()
        try:
            result: Any = rt.acquire(dispatch_run=f"dispatch-run-{i}")
        except DeployLeaseRefused as refusal:
            result = refusal.code
        with guard:
            outcomes.append(result)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [o for o in outcomes if not isinstance(o, str)]
    losers = [o for o in outcomes if isinstance(o, str)]
    assert len(winners) == 1
    assert losers == ["lease-held-by-another-run"] * (count - 1)


def test_deploy_lease_held_by_another_run_refused(env: Any) -> None:
    _db, rt = env
    rt.acquire()
    _refused("lease-held-by-another-run", lambda: rt.acquire(dispatch_run="other"))


@pytest.mark.parametrize("ttl", [0, -1, 3601, 86400, None])
def test_deploy_lease_ttl_is_capped(env: Any, ttl: Any) -> None:
    _db, rt = env
    _refused("lease-ttl-invalid", lambda: rt.acquire(ttl_seconds=ttl))
    with pytest.raises(DeployLeaseRefused):
        rt.standing()  # nothing was written: the host is unknown


def test_deploy_lease_ttl_cap_is_inclusive(env: Any) -> None:
    _db, rt = env
    lease = rt.acquire(ttl_seconds=3600)
    assert lease.expires_at - lease.acquired_at == timedelta(seconds=3600)


def test_deploy_lease_foreign_run_refused(env: Any) -> None:
    _db, rt = env
    lease = rt.acquire()
    _refused("lease-foreign-run", lambda: rt.covers(lease, run="other-run"))
    _refused("lease-foreign-run", lambda: rt.release(lease, dispatch_run="other-run"))
    assert rt.standing().standing == "held"


def test_deploy_lease_unknown_lease_refused(env: Any) -> None:
    _db, rt = env
    ghost = type("L", (), {"lease_id": "00000000-0000-4000-8000-000000000000"})()
    _refused("lease-role-unbound", lambda: rt.covers(ghost))
    _refused("lease-role-unbound", lambda: rt.release(ghost))


def test_deploy_lease_double_release_refused(env: Any) -> None:
    """ONE release row per lease. The same holder repeating the same statement is a
    replay (the wire contract) and gets the stored instant back; any other second
    release is refused."""
    db, rt = env
    lease = rt.acquire()
    first = rt.release(lease, host_mutated=False)
    db.advance(None, 5)
    assert rt.release(lease, host_mutated=False) == first  # replay, not a new release
    _refused("lease-already-released", lambda: rt.release(lease, host_mutated=True))
    _refused(
        "lease-already-released",
        lambda: rt.release(lease, dispatch_run="other-run", host_mutated=False),
    )
    _refused(
        "lease-already-released",
        lambda: rt.release(lease, principal_ref="x", host_mutated=False),
    )
    assert (
        _scalar(
            db,
            "SELECT count(*) FROM cp_deploy_lease.deploy_host_lease_releases "
            "WHERE lease_id = :l",
            l=str(lease.lease_id),
        )
        == 1
    )


def test_deploy_lease_reacquire_by_the_same_run_returns_its_lease(env: Any) -> None:
    """A lost response must not strand the agent: the retry gets the SAME lease, and
    a different run, principal or target still does not."""
    _db, rt = env
    first = rt.acquire()
    again = rt.acquire(ttl_seconds=600)  # the retry's ttl does not extend or replace
    assert again.lease_id == first.lease_id
    assert again.expires_at == first.expires_at
    _refused("lease-held-by-another-run", lambda: rt.acquire(principal_ref="other"))
    _refused("lease-held-by-another-run", lambda: rt.acquire(target_ref="p/e/other"))
    _refused("lease-held-by-another-run", lambda: rt.acquire(dispatch_run="other"))


def test_deploy_lease_release_must_name_the_holder(env: Any) -> None:
    _db, rt = env
    lease = rt.acquire()
    _refused("release-not-this-lease", lambda: rt.release(lease, principal_ref="x"))
    assert rt.standing().standing == "held"


@pytest.mark.parametrize("not_a_bool", [None])
def test_deploy_lease_host_mutated_required(env: Any, not_a_bool: Any) -> None:
    _db, rt = env
    lease = rt.acquire()
    _refused("host-mutated-required", lambda: rt.release(lease, host_mutated=None))
    assert rt.standing().standing == "held"


def test_deploy_lease_covers_is_judged_on_store_time(env: Any) -> None:
    db, rt = env
    lease = rt.acquire(ttl_seconds=60)
    db.advance(None, 59)
    assert rt.covers(lease) == db.now()
    db.advance(None, 1)  # store time == expires_at: no longer covered
    _refused("lease-expired", lambda: rt.covers(lease))


def test_deploy_lease_covers_refuses_a_released_lease(env: Any) -> None:
    _db, rt = env
    lease = rt.acquire()
    rt.release(lease)
    _refused("lease-expired", lambda: rt.covers(lease))


def test_deploy_lease_release_after_expiry_refused(env: Any) -> None:
    db, rt = env
    lease = rt.acquire(ttl_seconds=60)
    db.advance(None, 61)
    _refused("lease-expired", lambda: rt.release(lease))
    assert rt.standing().standing == "expired_unreleased"


def test_deploy_lease_released_is_clean_whatever_host_mutated(env: Any) -> None:
    """The persistent-host rule: a clean deploy releases a MUTATED host, and the
    next deploy is not refused (the rehearsal rule would refuse every second one)."""
    _db, rt = env
    first = rt.acquire()
    rt.release(first, host_mutated=True)
    second = rt.acquire(dispatch_run="dispatch-run-2")
    assert second.lease_id != first.lease_id
    rt.release(second, dispatch_run="dispatch-run-2", host_mutated=False)
    rt.acquire(dispatch_run="dispatch-run-3")


def test_deploy_lease_expired_unreleased_is_never_a_clean_release(env: Any) -> None:
    db, rt = env
    rt.acquire(ttl_seconds=60)
    db.advance(None, 61)
    standing = rt.standing()
    assert standing.standing == "expired_unreleased"
    _refused("lease-host-mutated", lambda: rt.acquire(dispatch_run="dispatch-run-2"))
    assert rt.standing().standing == "expired_unreleased"


def test_deploy_acquire_requires_marker(env: Any) -> None:
    """Expired unreleased: the next acquire needs the reconcile marker, and a
    marker reopens exactly that state."""
    db, rt = env
    rt.acquire(ttl_seconds=60)
    db.advance(None, 61)
    _refused("lease-host-mutated", lambda: rt.acquire(dispatch_run="dispatch-run-2"))
    reopened = rt.acquire(dispatch_run="dispatch-run-2", reconcile_marker=MARKER_1)
    assert rt.covers(reopened, run="dispatch-run-2") == db.now()
    assert (
        _scalar(
            db,
            "SELECT reconcile_marker_ref FROM cp_deploy_lease.deploy_host_leases "
            "WHERE lease_id = :l",
            l=str(reopened.lease_id),
        )
        == MARKER_1
    )


def test_deploy_lease_marker_is_spent_once(env: Any) -> None:
    db, rt = env
    rt.acquire(ttl_seconds=60)
    db.advance(None, 61)
    rt.acquire(dispatch_run="dispatch-run-2", ttl_seconds=60, reconcile_marker=MARKER_1)
    db.advance(None, 61)
    _refused(
        "reprovision-receipt-spent",
        lambda: rt.acquire(dispatch_run="dispatch-run-3", reconcile_marker=MARKER_1),
    )
    rt.acquire(dispatch_run="dispatch-run-3", reconcile_marker=MARKER_2)


def test_deploy_lease_marker_is_not_needed_nor_recorded_on_a_clean_host(
    env: Any,
) -> None:
    db, rt = env
    lease = rt.acquire(reconcile_marker=MARKER_1)
    assert (
        _scalar(
            db,
            "SELECT reconcile_marker_ref FROM cp_deploy_lease.deploy_host_leases "
            "WHERE lease_id = :l",
            l=str(lease.lease_id),
        )
        is None
    )


@pytest.mark.parametrize(
    "marker", ["", "sha256:abc", "SHA256:" + "1" * 64, "sha256:" + "G" * 64, "x"]
)
def test_deploy_lease_malformed_marker_refused(env: Any, marker: str) -> None:
    _db, rt = env
    _refused(
        "reprovision-receipt-mismatch", lambda: rt.acquire(reconcile_marker=marker)
    )


@pytest.mark.parametrize(
    "override",
    [
        {"host_id": "Host A"},
        {"host_id": ""},
        {"target_ref": ""},
        {"target_ref": "has space"},
        {"dispatch_run": ""},
        {"dispatch_run": "x" * 256},
        {"principal_ref": ""},
        {"principal_ref": "a b"},
        {"principal_ref": None},
    ],
)
def test_deploy_lease_malformed_identity_refused(env: Any, override: Any) -> None:
    _db, rt = env
    _refused("lease-role-unbound", lambda: rt.acquire(**override))


def test_deploy_lease_time_is_store_time(env: Any) -> None:
    db, rt = env
    start = db.now()
    lease = rt.acquire(ttl_seconds=90)
    assert lease.acquired_at == start
    assert lease.expires_at == start + timedelta(seconds=90)
    assert lease.store_now == start
    row = _scalar(
        db,
        "SELECT expires_at FROM cp_deploy_lease.deploy_host_leases WHERE lease_id = :l",
        l=str(lease.lease_id),
    )
    assert row == lease.expires_at  # one expiry: the answer is the row's
    db.advance(None, 30)
    assert rt.release(lease) == db.now()
    stored = _scalar(
        db,
        "SELECT released_at FROM cp_deploy_lease.deploy_host_lease_releases "
        "WHERE lease_id = :l",
        l=str(lease.lease_id),
    )
    assert stored == db.now()


def test_no_deploy_function_takes_a_time_from_the_caller(env: Any) -> None:
    db, _rt = env
    with db.admin.begin() as conn:
        args = conn.execute(
            text(
                "SELECT p.proname, pg_get_function_arguments(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'cp_deploy_lease'"
            )
        ).all()
    assert args
    assert not [a for a in args if "timestamp" in a[1] or "interval" in a[1]]


def test_deploy_lease_standing_answers(env: Any) -> None:
    db, rt = env
    _refused("lease-host-unknown", lambda: rt.standing("host-never"))
    lease = rt.acquire(ttl_seconds=60)
    held = rt.standing()
    assert (held.standing, held.lease_id, held.store_now) == (
        "held",
        lease.lease_id,
        db.now(),
    )
    rt.release(lease)
    assert rt.standing().standing == "released"
    rt.acquire(dispatch_run="dispatch-run-2", ttl_seconds=60)
    db.advance(None, 60)
    assert rt.standing().standing == "expired_unreleased"


def test_deploy_leases_on_two_hosts_do_not_exclude_each_other(env: Any) -> None:
    _db, rt = env
    rt.acquire(host_id="host-a")
    rt.acquire(host_id="host-b", dispatch_run="dispatch-run-2")


def test_deploy_evidence_is_append_only_even_for_the_owner(env: Any) -> None:
    db, rt = env
    lease = rt.acquire()
    rt.release(lease)
    for statement in (
        "UPDATE cp_deploy_lease.deploy_host_leases SET ttl_seconds = 1",
        "DELETE FROM cp_deploy_lease.deploy_host_leases",
        "TRUNCATE cp_deploy_lease.deploy_host_leases",
        "UPDATE cp_deploy_lease.deploy_host_lease_releases SET host_mutated = false",
        "DELETE FROM cp_deploy_lease.deploy_host_lease_releases",
        "TRUNCATE cp_deploy_lease.deploy_host_lease_releases",
    ):
        with pytest.raises(DBAPIError), db.admin.begin() as conn:
            conn.execute(text(statement))


# ── the runtime role's privilege proof ──────────────────────────────────────


def _held_in(db: Any, role: str, schema: str) -> list[str]:
    """Every privilege `role` holds in `schema`: must be exactly the intended set."""
    held: list[str] = []
    with db.admin.begin() as conn:
        for kind in ("USAGE", "CREATE"):
            if conn.execute(
                text("SELECT has_schema_privilege(:r, :s, :k)"),
                {"r": role, "s": schema, "k": kind},
            ).scalar_one():
                held.append(f"schema:{kind}")
        for relation, relkind in conn.execute(
            text(
                "SELECT c.oid::regclass::text, c.relkind FROM pg_class c JOIN "
                "pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = :s "
                "AND c.relkind IN ('r','S')"
            ),
            {"s": schema},
        ).all():
            if relkind == "r":
                for kind in (
                    "SELECT",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "TRUNCATE",
                    "REFERENCES",
                    "TRIGGER",
                ):
                    if conn.execute(
                        text(
                            "SELECT has_table_privilege(:r, CAST(:t AS regclass), :k)"
                        ),
                        {"r": role, "t": relation, "k": kind},
                    ).scalar_one():
                        held.append(f"{relation}:{kind}")
                if conn.execute(
                    text(
                        "SELECT has_any_column_privilege(:r, CAST(:t AS regclass), "
                        "'SELECT, INSERT, UPDATE, REFERENCES')"
                    ),
                    {"r": role, "t": relation},
                ).scalar_one():
                    held.append(f"{relation}:column")
            else:
                for kind in ("USAGE", "SELECT", "UPDATE"):
                    if conn.execute(
                        text(
                            "SELECT has_sequence_privilege(:r, CAST(:t AS regclass), :k)"
                        ),
                        {"r": role, "t": relation, "k": kind},
                    ).scalar_one():
                        held.append(f"{relation}:{kind}")
        for signature in conn.execute(
            text(
                "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n "
                "ON n.oid = p.pronamespace WHERE n.nspname = :s"
            ),
            {"s": schema},
        ).scalars():
            if conn.execute(
                text(
                    "SELECT has_function_privilege(:r, CAST(:f AS regprocedure), 'EXECUTE')"
                ),
                {"r": role, "f": signature},
            ).scalar_one():
                held.append(f"function:{signature}")
    return held


def test_runtime_role_cp_lane3_privilege_proof(env: Any) -> None:
    """The CP runtime role holds USAGE on `cp_deploy_lease` and EXECUTE on its four
    functions, and NOTHING else: no table, sequence or column privilege there, no
    rehearsal function, no `store_now`, nothing at all in `cp_lane3`."""
    db, rt = env
    assert _held_in(db, "platform_api", "cp_lane3") == []
    held = _held_in(db, "platform_api", "cp_deploy_lease")
    qualified = sorted(
        "function:cp_deploy_lease." + signature.replace(", ", ",")
        for signature in RUNTIME_FUNCTIONS
    )
    assert sorted(["schema:USAGE", *qualified]) == sorted(held)
    # and in fact, over a real connection as that role:
    with rt.engine.connect() as conn:
        for statement in (
            "SELECT cp_lane3.store_now()",
            "SELECT * FROM cp_lane3.host_leases",
            "SELECT * FROM cp_lane3.host_current_lease",
            "SELECT cp_lane3.database_time()",
            "SELECT * FROM cp_deploy_lease.deploy_host_leases",
            "INSERT INTO cp_deploy_lease.deploy_host_lease_releases "
            "(lease_id, released_at, host_mutated, released_by) "
            "VALUES (gen_random_uuid(), now(), true, 'x')",
            "SELECT cp_deploy_lease.stamp_deploy_release_time()",
        ):
            with pytest.raises(DBAPIError) as raised:
                conn.execute(text(statement))
            conn.rollback()
            assert getattr(raised.value.orig, "sqlstate", None) == "42501", statement


@pytest.mark.parametrize("role", ["public", "app_user"])
def test_no_other_runtime_role_holds_anything_in_the_deploy_schema(
    env: Any, role: str
) -> None:
    db, _rt = env
    assert _held_in(db, role, "cp_deploy_lease") == []


def test_the_migrations_privilege_read_back_passes_and_sees_a_leak(env: Any) -> None:
    db, _rt = env
    migration = _migration()
    clean = (
        migration.RELATION_ACL_SQL,
        migration.COLUMN_ACL_SQL,
        migration.FUNCTION_ACL_SQL,
        migration.SCHEMA_ACL_SQL,
        migration.DEFAULT_ACL_SQL,
        migration.OWNER_NOT_MIGRATOR_SQL,
    )
    with db.admin.begin() as conn:
        assert [conn.execute(text(q)).scalar_one() for q in clean] == [0] * len(clean)
        assert conn.execute(text(migration.SCHEMA_GRANT_PRESENT_SQL)).scalar_one() == 1
        assert conn.execute(text(migration.FUNCTION_GRANT_COUNT_SQL)).scalar_one() == 4
        assert conn.execute(text(migration.LANE3_REACH_SQL)).scalar_one() is False
    for leak, query in (
        (
            "GRANT SELECT ON cp_deploy_lease.deploy_host_leases TO platform_api",
            migration.RELATION_ACL_SQL,
        ),
        (
            "GRANT SELECT (host_id) ON cp_deploy_lease.deploy_host_leases TO app_user",
            migration.COLUMN_ACL_SQL,
        ),
        (
            "GRANT EXECUTE ON FUNCTION cp_deploy_lease.stamp_deploy_release_time() "
            "TO platform_api",
            migration.FUNCTION_ACL_SQL,
        ),
        (
            "GRANT USAGE ON SCHEMA cp_deploy_lease TO app_user",
            migration.SCHEMA_ACL_SQL,
        ),
        (
            "GRANT EXECUTE ON FUNCTION cp_deploy_lease.deploy_standing(text) "
            "TO app_user",
            migration.FUNCTION_ACL_SQL,
        ),
    ):
        with db.admin.connect() as conn:
            conn.execute(text(leak))
            assert conn.execute(text(query)).scalar_one() >= 1, leak
            conn.rollback()


def test_every_deploy_function_is_definer_pinned_and_none_is_public(env: Any) -> None:
    db, _rt = env
    with db.admin.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT p.oid::regprocedure::text, p.prosecdef, p.proconfig, "
                "has_function_privilege('public', p.oid, 'EXECUTE') "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'cp_deploy_lease'"
            )
        ).all()
    assert len(rows) == 5  # four callable + the release-time trigger function
    for signature, definer, config, public in rows:
        assert public is False, signature
        if signature.startswith("cp_deploy_lease.deploy_"):
            assert definer is True, signature
        assert config == ["search_path=pg_catalog, pg_temp"], signature


def test_the_schema_holds_exactly_two_tables_and_no_rehearsal_object_moved(
    env: Any,
) -> None:
    db, _rt = env
    with db.admin.begin() as conn:
        tables = set(
            conn.execute(
                text(
                    "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON "
                    "n.oid = c.relnamespace WHERE n.nspname = 'cp_deploy_lease' "
                    "AND c.relkind = 'r'"
                )
            ).scalars()
        )
        rehearsal = conn.execute(
            text(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON "
                "n.oid = c.relnamespace WHERE n.nspname = 'cp_lane3' "
                "AND c.relkind = 'r'"
            )
        ).scalar_one()
    assert tables == {"deploy_host_leases", "deploy_host_lease_releases"}
    assert rehearsal == 6  # the six v023 tables: nothing added to `cp_lane3`


# ── the names-only F-G read-back (plan for prod) ────────────────────────────


def _readback(db: Any, phase: str) -> Any:
    from vendor_cp.deployment import deploy_lease_readback as rb
    from vendor_cp.deployment.lane3_store_integrity import (
        begin_read_only,
        session_execute,
    )

    source = rb.migration()
    with db.admin.connect() as conn:
        execute = session_execute(conn)
        begin_read_only(execute)
        if phase == "after":
            return rb.run_after(execute, source=source)
        return rb.run_before(execute, source=source)


def test_the_after_read_back_holds_on_the_migrated_database(env: Any) -> None:
    db, _rt = env
    results = _readback(db, "after")
    assert [name for name, held in results if not held] == []
    assert len(results) == 9


def test_the_after_read_back_names_a_leak(env: Any) -> None:
    db, _rt = env
    with db.admin.begin() as conn:
        conn.execute(
            text("GRANT SELECT ON cp_deploy_lease.deploy_host_leases TO platform_api")
        )
    failed = [name for name, held in _readback(db, "after") if not held]
    assert failed == ["no-table-or-sequence-acl"]


def test_the_before_read_back_reports_the_runtime_roles_attributes_by_name(
    env: Any,
) -> None:
    db, _rt = env
    checks, info = _readback(db, "before")
    held = dict(checks)
    assert held["runtime-role-exists"] and held["runtime-role-nosuperuser"]
    # the schema exists in the case database, so the pre-migration check says so
    assert held["schema-cp_deploy_lease-absent"] is False
    assert "info runtime_role=platform_api" in info
    assert "info role_superuser=false" in info
    assert not [line for line in info if "=" in line and not line.startswith("info ")]
