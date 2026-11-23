"""WP5c: the production (deploy) lease class on a real PG16 (`v024_deploy_lease`).

Every case runs the REAL migration chain as the production migrator and calls the
five `cp_deploy_lease` functions as the dedicated lease role `platform_target_lease` over
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
import contextlib
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
from vendor_cp.deployment.deploy_lease import (
    DeployLeaseRefused,
    DeployLeaseStore,
    MarkerRequired,
    dispatch_run,
)
from vendor_cp.deployment.deploy_lease_consume import LeaseCoveringBackend

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = ROOT / "alembic" / "versions" / "v024_deploy_lease.py"

HOST = "host-a"
TARGET = "dotmac_erp/production/erp-prod-1"
RUN = "dispatch-run-1"
PRINCIPAL = "target-credential-1"
MARKER_1 = "sha256:" + "1" * 64
MARKER_2 = "sha256:" + "2" * 64

RUNTIME_FUNCTIONS = (
    "deploy_acquire(text, text, text, integer, integer, text, text, text)",
    "deploy_covers(uuid, text)",
    "deploy_release(uuid, text, text, boolean)",
    "deploy_renew(uuid, text)",
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
        "test_connection_lost_before_commit_writes_nothing_and_a_fresh_acquire_works"
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
        "test_release_commit_lost_the_repeat_is_a_replay"
    ),
    "a_release_must_match_the_held_lease": "test_deploy_lease_release_must_name_the_holder",
    "an_acquire_commit_lost_is_unknown_and_never_retried": (
        "test_acquire_commit_lost_the_retry_returns_the_same_lease_with_remaining_ttl"
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
            "max_seconds": 600,
            "lease_class": "serving",
            "principal_ref": PRINCIPAL,
        }
        args.update(kw)
        return self.call(lambda s: s.acquire(**args))

    def covers(self, lease: Any, run: str = RUN) -> Any:
        return self.call(lambda s: s.covers(lease_id=lease.lease_id, dispatch_run=run))

    def release(self, lease: Any, **kw: Any) -> Any:
        args: dict[str, Any] = {
            "lease_id": lease.lease_id,
            "target_ref": TARGET,
            "principal_ref": PRINCIPAL,
            "host_mutated": True,
        }
        args.update(kw)
        return self.call(lambda s: s.release(**args))

    def renew(self, lease: Any, run: str = RUN) -> Any:
        return self.call(lambda s: s.renew(lease_id=lease.lease_id, dispatch_run=run))

    def standing(self, host: str = HOST) -> Any:
        return self.call(lambda s: s.standing(host))

    def dispose(self) -> None:
        self.engine.dispose()


LEASE_ROLE = "platform_target_lease"


def make_lease_role(postgres_url: str) -> None:
    """The governed role op's part, done by the test cluster: a plain LOGIN role.
    The migration never creates it."""
    server = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        if (
            conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": LEASE_ROLE}
            ).first()
            is None
        ):
            conn.execute(text(f"CREATE ROLE {LEASE_ROLE} LOGIN"))
    server.dispose()


def drop_lease_role(postgres_url: str) -> None:
    server = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f"DROP ROLE IF EXISTS {LEASE_ROLE}"))
    server.dispose()


def grant_lease_role(db: Any) -> None:
    """Connect on this case database and run the migration's own grant statements
    (the F-G step that follows the role op when the role did not exist at migrate)."""
    migration = _migration()
    with db.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            text(f'GRANT CONNECT ON DATABASE "{db.admin.url.database}" TO {LEASE_ROLE}')
        )
        for statement in migration.role_grant_statements():
            conn.execute(text(statement))


@pytest.fixture(scope="module")
def lease_role(postgres_url: str) -> Any:
    make_lease_role(postgres_url)
    yield LEASE_ROLE
    # module-scoped, so it runs after every case database has been dropped
    drop_lease_role(postgres_url)


@pytest.fixture
def env(lane3_cases: Any, postgres_url: str, url_for: Any, lease_role: str) -> Any:
    db = lane3_cases.new()
    grant_lease_role(db)
    runtime = Runtime(db, url_for, postgres_url, lease_role)
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
    released = rt.release(lease, host_mutated=True)
    assert released.released_at == db.now() and released.replay is False
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


@pytest.mark.parametrize("ttl", [0, -1, 901, 86400, None])
def test_deploy_lease_ttl_is_capped(env: Any, ttl: Any) -> None:
    _db, rt = env
    _refused("lease-ttl-invalid", lambda: rt.acquire(ttl_seconds=ttl))
    with pytest.raises(DeployLeaseRefused):
        rt.standing()  # nothing was written: the host is unknown


@pytest.mark.parametrize("total", [None, 59, 10801])
def test_deploy_lease_total_is_bounded_by_the_ttl_and_10800(
    env: Any, total: Any
) -> None:
    _db, rt = env
    _refused("lease-ttl-invalid", lambda: rt.acquire(ttl_seconds=60, max_seconds=total))


def test_deploy_lease_ttl_and_total_caps_are_inclusive(env: Any) -> None:
    _db, rt = env
    lease = rt.acquire(ttl_seconds=900, max_seconds=10800)
    assert lease.ttl_seconds == 900
    assert lease.expires_at - lease.acquired_at == timedelta(seconds=900)


def test_deploy_lease_foreign_run_refused(env: Any) -> None:
    _db, rt = env
    lease = rt.acquire()
    _refused("lease-foreign-run", lambda: rt.covers(lease, run="other-run"))
    _refused("lease-foreign-run", lambda: rt.renew(lease, run="other-run"))
    # a release names the holder (target and principal), not the run
    _refused(
        "release-not-this-lease",
        lambda: rt.release(lease, target_ref="other/env/host-a"),
    )
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
    assert first.replay is False
    db.advance(None, 5)
    again = rt.release(lease, host_mutated=False)
    assert (again.released_at, again.replay) == (first.released_at, True)
    _refused("lease-already-released", lambda: rt.release(lease, host_mutated=True))
    _refused("release-not-this-lease", lambda: rt.release(lease, principal_ref="x"))
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
    db, rt = env
    first = rt.acquire()
    db.advance(None, 10)
    again = rt.acquire(ttl_seconds=600)  # the retry's ttl does not extend or replace
    assert again.lease_id == first.lease_id
    assert again.expires_at == first.expires_at
    assert again.ttl_seconds == first.ttl_seconds - 10  # the REMAINING ttl
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
    rt.release(second, host_mutated=False)
    rt.acquire(dispatch_run="dispatch-run-3")


def test_deploy_lease_expired_unreleased_is_never_a_clean_release(env: Any) -> None:
    db, rt = env
    rt.acquire(ttl_seconds=60)
    db.advance(None, 61)
    standing = rt.standing()
    assert standing.standing == "expired_unreleased"
    _refused(
        "reconcile-marker-required",
        lambda: rt.acquire(dispatch_run="dispatch-run-2"),
    )
    assert rt.standing().standing == "expired_unreleased"


def test_deploy_acquire_requires_marker(env: Any) -> None:
    """Expired unreleased: the next acquire needs the reconcile marker, and a
    marker reopens exactly that state."""
    db, rt = env
    rt.acquire(ttl_seconds=60)
    db.advance(None, 61)
    _refused(
        "reconcile-marker-required",
        lambda: rt.acquire(dispatch_run="dispatch-run-2"),
    )
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
        {"dispatch_run": "x" * 513},
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
    assert rt.release(lease).released_at == db.now()
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
    rt.renew(lease)  # a renewal row, so the row triggers have something to refuse
    rt.release(lease)
    for statement in (
        "UPDATE cp_deploy_lease.deploy_host_leases SET ttl_seconds = 1",
        "DELETE FROM cp_deploy_lease.deploy_host_leases",
        "TRUNCATE cp_deploy_lease.deploy_host_leases",
        "UPDATE cp_deploy_lease.deploy_host_lease_releases SET host_mutated = false",
        "DELETE FROM cp_deploy_lease.deploy_host_lease_releases",
        "TRUNCATE cp_deploy_lease.deploy_host_lease_releases",
        "UPDATE cp_deploy_lease.deploy_host_lease_renewals SET granted_seconds = 1",
        "DELETE FROM cp_deploy_lease.deploy_host_lease_renewals",
        "TRUNCATE cp_deploy_lease.deploy_host_lease_renewals",
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


def test_runtime_role_cp_lane3_privilege_proof(
    env: Any, url_for: Any, postgres_url: str
) -> None:
    """The dedicated lease role holds USAGE on `cp_deploy_lease` and EXECUTE on its
    five functions, and NOTHING else: no table, sequence or column privilege there,
    no rehearsal function, no `store_now`, nothing at all in `cp_lane3`. The CP
    application role `platform_api` (the app, relay and ops containers) holds
    NOTHING in either schema, and cannot call a lease function."""
    db, rt = env
    assert _held_in(db, LEASE_ROLE, "cp_lane3") == []
    held = _held_in(db, LEASE_ROLE, "cp_deploy_lease")
    qualified = sorted(
        "function:cp_deploy_lease." + signature.replace(", ", ",")
        for signature in RUNTIME_FUNCTIONS
    )
    assert sorted(["schema:USAGE", *qualified]) == sorted(held)
    for role in ("platform_api", "app_user", "public"):
        assert _held_in(db, role, "cp_lane3") == [], role
        assert _held_in(db, role, "cp_deploy_lease") == [], role
    app = create_engine(
        url_for(postgres_url, db.admin.url.database, user="platform_api")
    )
    try:
        with app.connect() as conn:
            for statement in (
                "SELECT * FROM cp_deploy_lease.deploy_standing('host-a')",
                "SELECT cp_deploy_lease.deploy_covers(gen_random_uuid(), 'r')",
            ):
                with pytest.raises(DBAPIError) as raised:
                    conn.execute(text(statement))
                conn.rollback()
                assert getattr(raised.value.orig, "sqlstate", None) == "42501"
    finally:
        app.dispose()
    # and in fact, over a real connection as that role:
    with rt.engine.connect() as conn:
        for statement in (
            "SELECT cp_lane3.store_now()",
            "SELECT * FROM cp_lane3.host_leases",
            "SELECT * FROM cp_lane3.host_current_lease",
            "SELECT cp_lane3.database_time()",
            "SELECT * FROM cp_deploy_lease.deploy_host_leases",
            "SELECT * FROM cp_deploy_lease.deploy_host_lease_renewals",
            "SELECT cp_deploy_lease.effective_expiry(gen_random_uuid())",
            "INSERT INTO cp_deploy_lease.deploy_host_lease_releases "
            "(lease_id, released_at, host_mutated, released_by) "
            "VALUES (gen_random_uuid(), now(), true, 'x')",
            "SELECT cp_deploy_lease.stamp_deploy_release_time()",
        ):
            with pytest.raises(DBAPIError) as raised:
                conn.execute(text(statement))
            conn.rollback()
            assert getattr(raised.value.orig, "sqlstate", None) == "42501", statement


def test_the_migrations_privilege_read_back_passes_and_sees_a_leak(env: Any) -> None:
    db, _rt = env
    migration = _migration()
    clean = (
        migration.RELATION_ACL_SQL,
        migration.COLUMN_ACL_SQL,
        migration.FUNCTION_ACL_SQL,
        migration.SCHEMA_ACL_SQL,
        migration.DEFAULT_ACL_SQL,
        # the case database was migrated by `app_admin`; this session is the admin
        migration.OWNER_NOT_MIGRATOR_SQL.replace("current_user", "'app_admin'"),
    )
    with db.admin.begin() as conn:
        assert [conn.execute(text(q)).scalar_one() for q in clean] == [0] * len(clean)
        assert conn.execute(text(migration.SCHEMA_GRANT_PRESENT_SQL)).scalar_one() == 1
        assert conn.execute(text(migration.FUNCTION_GRANT_COUNT_SQL)).scalar_one() == 5
        assert conn.execute(text(migration.LANE3_REACH_SQL)).scalar_one() is False
        assert conn.execute(text(migration.APP_ROLE_REACH_SQL)).scalar_one() is False
        assert conn.execute(text(migration.LEASE_ROLE_LANE3_SQL)).scalar_one() is False
    for leak, query in (
        (
            "GRANT USAGE ON SCHEMA cp_deploy_lease TO platform_api",
            migration.APP_ROLE_REACH_SQL,
        ),
        (
            "GRANT EXECUTE ON FUNCTION cp_deploy_lease.deploy_standing(text) "
            "TO platform_api",
            migration.APP_ROLE_REACH_SQL,
        ),
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
    assert len(rows) == 7  # five callable + the release stamp + effective_expiry
    for signature, definer, config, public in rows:
        assert public is False, signature
        if signature.startswith("cp_deploy_lease.deploy_"):
            assert definer is True, signature
        assert config == ["search_path=pg_catalog, pg_temp"], signature


def test_the_schema_holds_exactly_three_tables_and_no_rehearsal_object_moved(
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
    assert tables == {
        "deploy_host_leases",
        "deploy_host_lease_renewals",
        "deploy_host_lease_releases",
    }
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
    assert len(results) == 12


def test_the_after_read_back_fails_until_the_role_op_and_its_grants(
    lane3_cases: Any, lease_role: str
) -> None:
    db = lane3_cases.new()  # migrated; the lease role is NOT yet granted here
    failed = [name for name, held in _readback(db, "after") if not held]
    assert set(failed) == {
        "schema-usage-granted-to-lease-role",
        "five-functions-granted-to-lease-role",
    }


def test_the_after_read_back_names_a_leak_to_the_application_role(env: Any) -> None:
    db, _rt = env
    with db.admin.begin() as conn:
        conn.execute(
            text(
                "GRANT EXECUTE ON FUNCTION cp_deploy_lease.deploy_standing(text) "
                "TO platform_api"
            )
        )
    failed = {name for name, held in _readback(db, "after") if not held}
    assert "app-role-has-nothing-in-the-lease-schema" in failed
    assert "no-function-acl-beyond-the-five" in failed


def test_the_before_read_back_reports_the_roles_by_name(env: Any) -> None:
    db, _rt = env
    checks, info = _readback(db, "before")
    held = dict(checks)
    assert held["app-role-exists"] and held["app-role-nosuperuser"]
    assert held["lease-role-absent-or-a-plain-login-role"]
    # the schema exists in the case database, so the pre-migration check says so
    assert held["schema-cp_deploy_lease-absent"] is False
    assert "info lease_role=platform_target_lease" in info
    assert "info lease_role_present=true" in info
    assert "info app_role_superuser=false" in info
    assert not [line for line in info if "=" in line and not line.startswith("info ")]


# ── the run is qualified by the target; covers-in-consume on a real session ──


def test_the_longest_qualified_run_is_accepted(env: Any) -> None:
    _db, rt = env
    longest = "/".join(("p" * 64, "e" * 64, "h" * 63))
    run = dispatch_run(longest, "d" * 128)
    lease = rt.acquire(target_ref=longest, dispatch_run=run)
    assert rt.covers(lease, run=run)


def test_another_target_cannot_cover_or_release_this_targets_lease(env: Any) -> None:
    _db, rt = env
    mine = dispatch_run(TARGET, "d-1")
    lease = rt.acquire(dispatch_run=mine)
    theirs = dispatch_run("other/env/host-a", "d-1")  # same dispatch id, other target
    _refused("lease-foreign-run", lambda: rt.covers(lease, run=theirs))
    _refused(
        "release-not-this-lease",
        lambda: rt.release(lease, target_ref="other/env/host-a"),
    )
    assert rt.covers(lease, run=mine)


def test_consume_requires_covering_lease_on_a_real_session(env: Any) -> None:
    """The adapter 5b's consume calls (`ConsumptionBackend.covers_lease`), against the
    real functions: a live lease held by this run covers; a released, expired,
    foreign or unknown one does not, and the session stays usable (a savepoint)."""
    from sqlalchemy.orm import Session

    db, rt = env

    @contextlib.contextmanager
    def stores(_db: Any) -> Any:
        with Session(rt.engine) as lease_session:
            yield DeployLeaseStore(lease_session)

    backend = LeaseCoveringBackend(inner=None, stores=stores)  # type: ignore[arg-type]
    run = dispatch_run(TARGET, "d-1")
    lease = rt.acquire(dispatch_run=run, ttl_seconds=60)

    def covers(session: Session, lease_id: Any, dispatch: str = "d-1") -> bool:
        return backend.covers_lease(
            session,
            target_ref=TARGET,
            dispatch_id=dispatch,
            lease_id=str(lease_id),
            store_now=db.now(),
        )

    with Session(rt.engine) as session:
        assert covers(session, lease.lease_id) is True
        assert covers(session, lease.lease_id, dispatch="d-2") is False  # foreign run
        assert covers(session, "00000000-0000-4000-8000-000000000000") is False
        assert covers(session, "not-a-uuid") is False
        assert session.execute(text("SELECT 1")).scalar_one() == 1  # still healthy
        assert covers(session, lease.lease_id) is True
        session.rollback()
    rt.release(lease)
    with Session(rt.engine) as session:
        assert covers(session, lease.lease_id) is False  # released
        session.rollback()
    expiring = rt.acquire(dispatch_run=dispatch_run(TARGET, "d-3"), ttl_seconds=60)
    with Session(rt.engine) as session:
        assert covers(session, expiring.lease_id, dispatch="d-3") is True
        db.advance(None, 60)
        assert covers(session, expiring.lease_id, dispatch="d-3") is False  # expired
        session.rollback()


# ── renewal (architect ruling Q-c/4) ────────────────────────────────────────


def test_deploy_lease_renew_grants_min_ttl_and_the_time_left_in_the_total(
    env: Any,
) -> None:
    db, rt = env
    lease = rt.acquire(ttl_seconds=120, max_seconds=300)
    db.advance(None, 100)  # held 100 s; expires at 120
    first = rt.renew(lease)
    assert first.granted_seconds == 120  # min(120, 300 - 100) = 120
    assert first.expires_at == lease.acquired_at + timedelta(seconds=220)
    assert rt.covers(lease) == db.now()
    db.advance(None, 100)  # held 200; effective expiry 220
    second = rt.renew(lease)
    assert second.granted_seconds == 100  # min(120, 300 - 200)
    assert second.expires_at == lease.acquired_at + timedelta(seconds=300)
    assert rt.standing().expires_at == second.expires_at


def test_deploy_lease_renew_is_capped_at_the_total_then_the_lease_expires(
    env: Any,
) -> None:
    """The contract's reference ledger: the last grant is capped to what remains of
    the maximum, an early repeat still answers the remainder, and at the cap the
    lease is simply expired (not renewable)."""
    db, rt = env
    lease = rt.acquire(ttl_seconds=120, max_seconds=240)
    db.advance(None, 100)
    assert rt.renew(lease).granted_seconds == 120  # to 220
    db.advance(None, 100)  # held 200
    last = rt.renew(lease)
    assert last.granted_seconds == 40 and last.expires_at == (
        lease.acquired_at + timedelta(seconds=240)
    )
    db.advance(None, 10)  # held 210, still inside the capped lease
    assert rt.renew(lease).granted_seconds == 30
    assert rt.covers(lease) == db.now()
    db.advance(None, 30)  # held 240: the cap
    _refused("lease-expired", lambda: rt.renew(lease))
    assert rt.standing().standing == "expired_unreleased"


def test_deploy_lease_renew_never_resurrects_an_expired_or_released_lease(
    env: Any,
) -> None:
    db, rt = env
    expired = rt.acquire(ttl_seconds=120, max_seconds=600)
    db.advance(None, 120)  # store time == expires_at
    _refused("lease-expired", lambda: rt.renew(expired))
    assert rt.standing().standing == "expired_unreleased"
    released = rt.acquire(
        dispatch_run="dispatch-run-2", reconcile_marker=MARKER_1, ttl_seconds=120
    )
    rt.release(released, target_ref=TARGET)
    _refused("lease-already-released", lambda: rt.renew(released, run="dispatch-run-2"))
    ghost = type("L", (), {"lease_id": "00000000-0000-4000-8000-000000000000"})()
    _refused("lease-role-unbound", lambda: rt.renew(ghost))


def test_deploy_lease_renew_is_one_writer_with_acquire(env: Any) -> None:
    """A renewed lease still excludes another run, and an unrenewed one that expired
    needs the reconcile marker, not a silent takeover."""
    db, rt = env
    lease = rt.acquire(ttl_seconds=120, max_seconds=600)
    db.advance(None, 100)
    rt.renew(lease)
    db.advance(None, 100)  # past the ORIGINAL expiry, inside the renewed one
    _refused("lease-held-by-another-run", lambda: rt.acquire(dispatch_run="other"))
    db.advance(None, 200)  # past the renewed expiry too
    _refused("reconcile-marker-required", lambda: rt.acquire(dispatch_run="other"))


def test_deploy_acquire_without_a_marker_after_expiry_is_reconcile_marker_required(
    env: Any,
) -> None:
    db, rt = env
    rt.acquire(ttl_seconds=120)
    db.advance(None, 121)
    _refused("reconcile-marker-required", lambda: rt.acquire(dispatch_run="x"))
    with pytest.raises(MarkerRequired) as raised:
        rt.acquire(dispatch_run="x")
    assert raised.value.expired_dispatch_run == RUN


def test_standing_names_the_expired_dispatch_and_a_deletion_cannot_free_the_host(
    env: Any,
) -> None:
    db, rt = env
    rt.acquire(ttl_seconds=120, dispatch_run=dispatch_run(TARGET, "d-1"))
    db.advance(None, 121)
    standing = rt.standing()
    assert standing.standing == "expired_unreleased"
    assert standing.dispatch_run == dispatch_run(TARGET, "d-1")
    # append-only: deleting the row (even as the owner) is refused, so an expired
    # host cannot be made to look free; a never-leased host acquires without a marker
    with pytest.raises(DBAPIError), db.admin.begin() as conn:
        conn.execute(text("DELETE FROM cp_deploy_lease.deploy_host_leases"))
    assert rt.standing().standing == "expired_unreleased"
    rt.acquire(host_id="host-b", dispatch_run="dispatch-run-2")  # no marker needed


# ── lease class (serving or run_job) ────────────────────────────────────────


def test_a_run_job_lease_is_granted_once_ttl_equals_total_and_is_never_renewed(
    env: Any,
) -> None:
    db, rt = env
    job = rt.acquire(lease_class="run_job", ttl_seconds=2520, max_seconds=2520)
    assert job.ttl_seconds == 2520  # not held to the 900 s per-grant cap
    db.advance(None, 100)
    _refused("lease-not-renewable", lambda: rt.renew(job))
    assert rt.covers(job) == db.now()  # and the refusal changed nothing
    assert rt.standing().expires_at == job.expires_at


@pytest.mark.parametrize(
    ("lease_class", "ttl", "total"),
    [
        ("run_job", 600, 700),  # ttl must equal the total
        ("run_job", 3601, 3601),  # at most 3600
        ("serving", 901, 901),  # per grant at most 900
        ("serving", 600, 10801),  # total at most 10800
        ("serving", 600, 599),  # total at least the ttl
        ("batch", 600, 600),  # an unknown class
        (None, 600, 600),
    ],
)
def test_the_class_bounds_are_enforced_by_the_function(
    env: Any, lease_class: Any, ttl: int, total: int
) -> None:
    _db, rt = env
    _refused(
        "lease-ttl-invalid",
        lambda: rt.acquire(lease_class=lease_class, ttl_seconds=ttl, max_seconds=total),
    )


def test_the_class_bounds_are_also_table_constraints(env: Any) -> None:
    """Even the owner cannot write a lease row outside its class's bounds."""
    db, _rt = env
    base = (
        "INSERT INTO cp_deploy_lease.deploy_host_leases (lease_id, host_id, "
        "target_ref, dispatch_run, principal_ref, acquired_at, expires_at, "
        "lease_class, ttl_seconds, max_seconds) VALUES (gen_random_uuid(), 'h', "
        "'t', 'r', 'p', now(), now() + interval '{ttl} seconds', '{cls}', {ttl}, {mx})"
    )
    for cls, ttl, mx in (("run_job", 600, 700), ("serving", 901, 901), ("x", 60, 60)):
        with pytest.raises(DBAPIError), db.admin.begin() as conn:
            conn.execute(text(base.format(cls=cls, ttl=ttl, mx=mx)))
    with db.admin.begin() as conn:  # the same shape inside its class is accepted
        conn.execute(text(base.format(cls="run_job", ttl=2520, mx=2520)))


# ── commit lost / connection lost (the four named cases, architect ruling 5) ─


def _kill_after(db: Any, rt: Any, work: Callable[[Any], Any], *, commit: bool) -> Any:
    """Run `work` on a lease-role connection, optionally commit it, then terminate
    the backend (the connection is lost). Returns what `work` answered."""
    conn = rt.engine.connect()
    try:
        pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
        answered = work(DeployLeaseStore(conn))
        if commit:
            conn.commit()
        with db.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as adm:
            adm.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        if not commit:
            with pytest.raises(DBAPIError):
                conn.commit()  # the connection is gone: nothing can commit
        return answered
    finally:
        with contextlib.suppress(Exception):
            conn.invalidate()  # never return a dead connection to the pool
        with contextlib.suppress(Exception):
            conn.close()


def test_acquire_commit_lost_the_retry_returns_the_same_lease_with_remaining_ttl(
    env: Any,
) -> None:
    db, rt = env
    first = _kill_after(db, rt, lambda s: s.acquire(**_acquire_args()), commit=True)
    db.advance(None, 10)
    retry = rt.acquire(ttl_seconds=60)  # the agent never saw the answer
    assert retry.lease_id == first.lease_id
    assert retry.ttl_seconds == 50  # the REMAINING ttl
    assert rt.standing().standing == "held"


def test_release_commit_lost_the_repeat_is_a_replay(env: Any) -> None:
    db, rt = env
    lease = rt.acquire()
    done = _kill_after(
        db,
        rt,
        lambda s: s.release(
            lease_id=lease.lease_id,
            target_ref=TARGET,
            principal_ref=PRINCIPAL,
            host_mutated=True,
        ),
        commit=True,
    )
    db.advance(None, 5)
    again = rt.release(lease, host_mutated=True)
    assert (again.released_at, again.replay) == (done.released_at, True)


def test_connection_lost_before_commit_writes_nothing_and_a_fresh_acquire_works(
    env: Any,
) -> None:
    db, rt = env
    _kill_after(db, rt, lambda s: s.acquire(**_acquire_args()), commit=False)
    _refused("lease-host-unknown", lambda: rt.standing())  # no row, no pointer
    assert _scalar(db, "SELECT count(*) FROM cp_deploy_lease.deploy_host_leases") == 0
    assert rt.acquire().ttl_seconds == 60  # a fresh acquire is a fresh lease


def test_connection_lost_after_commit_is_the_same_as_commit_lost(env: Any) -> None:
    db, rt = env
    first = _kill_after(db, rt, lambda s: s.acquire(**_acquire_args()), commit=True)
    assert _scalar(db, "SELECT count(*) FROM cp_deploy_lease.deploy_host_leases") == 1
    assert rt.acquire().lease_id == first.lease_id


def _acquire_args() -> dict[str, Any]:
    return {
        "target_ref": TARGET,
        "host_id": HOST,
        "dispatch_run": RUN,
        "ttl_seconds": 60,
        "max_seconds": 600,
        "lease_class": "serving",
        "principal_ref": PRINCIPAL,
    }


# ── a moved pointer fails closed (architect ruling 4) ───────────────────────


def _move_pointer(db: Any) -> None:
    """What a rehearsal reprovision acquire does: point the host elsewhere."""
    with db.admin.begin() as conn:
        conn.execute(
            text(
                "UPDATE cp_lane3.host_current_lease SET lease_id = gen_random_uuid() "
                "WHERE host_id = :h"
            ),
            {"h": HOST},
        )


def test_covers_renew_and_release_refuse_a_superseded_lease(env: Any) -> None:
    db, rt = env
    lease = rt.acquire(ttl_seconds=120, max_seconds=600)
    _move_pointer(db)
    _refused("lease-superseded", lambda: rt.covers(lease))
    _refused("lease-superseded", lambda: rt.renew(lease))
    _refused("lease-superseded", lambda: rt.release(lease))


def test_consume_fails_closed_when_the_host_pointer_moved(env: Any) -> None:
    from sqlalchemy.orm import Session

    db, rt = env
    lease = rt.acquire(dispatch_run=dispatch_run(TARGET, "d-1"))

    @contextlib.contextmanager
    def stores(_db: Any) -> Any:
        with Session(rt.engine) as session:
            yield DeployLeaseStore(session)

    backend = LeaseCoveringBackend(inner=None, stores=stores)  # type: ignore[arg-type]

    def covers() -> bool:
        return backend.covers_lease(
            None,  # type: ignore[arg-type]
            target_ref=TARGET,
            dispatch_id="d-1",
            lease_id=str(lease.lease_id),
            store_now=db.now(),
        )

    assert covers() is True
    _move_pointer(db)
    assert covers() is False  # no covering lease: consume refuses


def test_a_released_leases_replay_survives_the_pointer_moving_on(env: Any) -> None:
    db, rt = env
    lease = rt.acquire()
    first = rt.release(lease)
    rt.acquire(dispatch_run="dispatch-run-2")  # the next deploy moves the pointer
    assert rt.release(lease).replay is True
    assert rt.release(lease).released_at == first.released_at


# ── release after expiry (architect ruling 3) ───────────────────────────────


def test_a_late_release_is_lease_expired_and_the_host_stays_expired_unreleased(
    env: Any,
) -> None:
    db, rt = env
    lease = rt.acquire(ttl_seconds=120)
    db.advance(None, 120)
    _refused("lease-expired", lambda: rt.release(lease))
    standing = rt.standing()
    assert (standing.standing, standing.dispatch_run) == ("expired_unreleased", RUN)


def test_a_release_replay_from_before_the_expiry_is_still_a_200_replay(
    env: Any,
) -> None:
    db, rt = env
    lease = rt.acquire(ttl_seconds=120)
    rt.release(lease)
    db.advance(None, 500)
    assert rt.release(lease).replay is True


# ── the marker is read under the host row lock, in the acquire's transaction ─


def test_the_marker_is_decided_inside_the_acquires_own_transaction(env: Any) -> None:
    """`deploy_acquire` ANSWERS "marker required" (it does not raise), so the host row
    lock it took is still held while the caller reads Control's marker; a competing
    acquire blocks until this transaction ends."""
    db, rt = env
    rt.acquire(ttl_seconds=120)
    db.advance(None, 121)
    holder = rt.engine.connect()
    try:
        with pytest.raises(MarkerRequired) as needed:
            DeployLeaseStore(holder).acquire(
                **{**_acquire_args(), "dispatch_run": "dispatch-run-2"}
            )
        assert needed.value.expired_dispatch_run == RUN
        # the lock is held by `holder`: another session cannot take the row
        with db.admin.connect() as other:
            other.execute(text("SET lock_timeout = '300ms'"))
            with pytest.raises(DBAPIError):
                other.execute(
                    text(
                        "SELECT 1 FROM cp_lane3.host_current_lease "
                        "WHERE host_id = :h FOR UPDATE"
                    ),
                    {"h": HOST},
                )
        # ...and the same transaction completes with the marker Control decided
        lease = DeployLeaseStore(holder).acquire(
            **{
                **_acquire_args(),
                "dispatch_run": "dispatch-run-2",
                "reconcile_marker": MARKER_1,
            }
        )
        holder.commit()
    finally:
        holder.close()
    assert (
        _scalar(
            db,
            "SELECT reopened_from_run FROM cp_deploy_lease.deploy_host_leases "
            "WHERE lease_id = :l",
            l=str(lease.lease_id),
        )
        == RUN
    )


# ── the lane3 integrity checker accepts a pointer into a deploy lease (R1) ───


def test_the_lane3_integrity_checker_accepts_a_pointer_into_a_deploy_lease(
    env: Any,
) -> None:
    from vendor_cp.deployment import lane3_store_integrity as integrity

    db, rt = env
    migration = ROOT / "alembic" / "versions" / "v023_lane3_store.py"

    def violations() -> tuple[str, ...]:
        with db.admin.connect() as conn:
            return integrity.check_store_integrity(
                integrity.session_execute(conn), migration_path=migration
            )

    before = violations()  # the case clock replaces `store_now`: a known baseline
    lease = rt.acquire()
    assert _scalar(
        db,
        "SELECT lease_id::text FROM cp_lane3.host_current_lease WHERE host_id = :h",
        h=HOST,
    ) == str(lease.lease_id)  # the shared pointer now names a cp_deploy_lease row
    assert violations() == before
    rt.release(lease)
    assert violations() == before
