"""WP5c: ONE writer per host across the rehearsal and the deploy lease class.

Both classes take the same row lock (`cp_lane3.host_current_lease`, `FOR UPDATE`).
Proving it needs a real REHEARSAL acquire, which needs Foundation's `HostLease` and
the typed E10 receipt, so this file runs in the dedicated Lane 3 CI step (like
`test_lane3_lease_store.py`): `LANE3_REQUIRE_FOUNDATION=1` turns a missing import
into a failure, and `scripts/check_lane3_junit.py` refuses a skip.

It also keeps `DEPLOY_CASE_MAP` (in `test_deploy_lease.py`) equal to the LIVE pinned
Starter suite: a re-vendored suite that adds, removes or renames a case fails here.

Known limit, stated rather than hidden: a rehearsal acquire that carries a valid
reprovision marker for a NEWER destroyed E10 receipt of the same host (an attended
ceremony: owner-DSN receipt, bound lease role) is not refused by the rehearsal
function when the pointer names a deploy lease, because the rehearsal functions are
byte-unchanged and read an unknown lease as no previous receipt. Closing that needs
a trigger on `cp_lane3.host_current_lease`, i.e. a new pin in the rehearsal
integrity set (WP6 decision); no test here asserts it either way.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

try:
    import dotmac_deployment_foundation.lease_release  # noqa: F401
except ImportError:
    if os.environ.get("LANE3_REQUIRE_FOUNDATION") == "1":
        raise
    pytest.skip(
        "Foundation is not importable; the dedicated Lane 3 CI step runs this file",
        allow_module_level=True,
    )

from vendor_cp.deployment.deploy_lease import DeployLeaseRefused

HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = _load("lane3_cp_support", HERE.parent / "unit" / "lane3_cp_support.py")
DEPLOY = _load("test_deploy_lease_for_cross_class", HERE / "test_deploy_lease.py")
VENDORED = SUPPORT.load_vendored()


@pytest.fixture(scope="module")
def lease_role(postgres_url: str) -> Any:
    DEPLOY.make_lease_role(postgres_url)
    yield DEPLOY.LEASE_ROLE
    DEPLOY.drop_lease_role(postgres_url)


@pytest.fixture
def env(lane3_cases: Any, postgres_url: str, url_for: Any, lease_role: str) -> Any:
    db = lane3_cases.new()
    DEPLOY.grant_lease_role(db)
    runtime = DEPLOY.Runtime(db, url_for, postgres_url, lease_role)
    try:
        yield db, runtime
    finally:
        runtime.dispose()


def _rehearsal_acquire(db: Any, run: str = "run-1") -> Any:
    store, fx = db.make_store(), db.fixtures()
    return store, fx, VENDORED.support._acquire(store, fx, run=run)


def test_deploy_case_map_equals_the_live_pinned_suite() -> None:
    assert set(DEPLOY.DEPLOY_CASE_MAP) == set(VENDORED.support.CASES)


def test_shared_row_lock_across_classes(env: Any) -> None:
    """A host held by the rehearsal class refuses a deploy acquire, and a host held
    by a deploy lease refuses a plain rehearsal acquire."""
    db, rt = env
    # rehearsal holds host-a: deploy refused
    store, fx, held = _rehearsal_acquire(db)
    DEPLOY._refused("lease-held-by-another-run", lambda: rt.acquire(host_id="host-a"))
    # released as untouched: still not a deploy host (the pointer names a
    # rehearsal lease), so a deploy acquire is refused rather than guessed at
    store.release(held, release=fx.make_release(store, held), host_mutated=False)
    DEPLOY._refused("lease-host-mutated", lambda: rt.acquire(host_id="host-a"))
    # deploy holds host-b: a plain rehearsal acquire is refused
    lease = rt.acquire(host_id="host-b")
    VENDORED.support._raises(
        "lease-host-mutated",
        lambda: VENDORED.support._acquire(
            db.make_store(), db.fixtures(), host="host-b", run="run-2"
        ),
    )
    assert rt.covers(lease) == db.now()


def test_deploy_lease_released_host_is_refused_by_a_plain_rehearsal_acquire(
    env: Any,
) -> None:
    """A released deploy lease is clean for the NEXT DEPLOY, not for a rehearsal:
    the rehearsal rule still reads a pointer it does not know as a mutated host."""
    db, rt = env
    lease = rt.acquire(host_id="host-b")
    rt.release(lease, host_mutated=False)
    VENDORED.support._raises(
        "lease-host-mutated",
        lambda: VENDORED.support._acquire(
            db.make_store(), db.fixtures(), host="host-b", run="run-2"
        ),
    )
    rt.acquire(host_id="host-b", dispatch_run="dispatch-run-2")


@pytest.mark.parametrize("round_", range(3))
def test_deploy_and_rehearsal_acquires_race_for_one_host(env: Any, round_: int) -> None:
    db, rt = env
    host = ("host-a", "host-b", "host-other")[round_]
    fx = db.fixtures()
    fx.receipt(host, 1)  # built BEFORE the race: the race is the acquire only
    barrier = threading.Barrier(2)
    outcome: dict[str, Any] = {}

    def rehearsal() -> None:
        barrier.wait()
        try:
            outcome["rehearsal"] = VENDORED.support._acquire(
                db.make_store(), fx, host=host, run="run-1"
            )
        except Exception as refusal:  # noqa: BLE001
            outcome["rehearsal"] = getattr(refusal, "code", repr(refusal))

    def deploy() -> None:
        barrier.wait()
        try:
            outcome["deploy"] = rt.acquire(host_id=host)
        except DeployLeaseRefused as refusal:
            outcome["deploy"] = refusal.code

    threads = [threading.Thread(target=rehearsal), threading.Thread(target=deploy)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    won = [k for k, v in outcome.items() if not isinstance(v, str)]
    assert len(won) == 1, outcome
    loser = "deploy" if won == ["rehearsal"] else "rehearsal"
    assert outcome[loser] == (
        "lease-held-by-another-run" if loser == "deploy" else "lease-host-mutated"
    ), outcome
