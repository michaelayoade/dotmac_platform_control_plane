"""An in-memory lease store, and the conformance cases a real one must pass.

E7 / U5. The CP production-database store does not exist yet (separate
image-budget ruling); this fake models the contract in
`scripts/lane3_lease_store.py` with an injected database clock, and
:data:`CASES` is the behaviour any implementation must show, one case per rule,
so the CP-side work can run each against its own store.

The lease and release are STAND-INS with the attribute names Foundation's real
types carry (`HostLease.target`, `workload_principal`, `expires_at`,
`controller_identity_fingerprint`; `HostLeaseReleaseV1.lease_digest`,
`released_by.subject`, `released_at`). The fake's lease also has a `digest`
attribute that a real `HostLease` LACKS, so no case reads it: every case goes
through :class:`Fixtures`, the hooks a store supplies for the parts that differ
between implementations (a valid controller identity, the principal, the lease
digest, a release factory, the receipts, and a way to drop a connection). The
fake's `FAKE_FIXTURES` are one implementation; the CP PR supplies the real ones.
"""

from __future__ import annotations

import dataclasses
import sys
import threading
import types
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from dotmac_deployment_foundation.controller_identity import (  # noqa: E402
    ControllerSshFingerprintV1,
)
from lane3_e10_receipt import E10ReceiptRef  # noqa: E402
from lane3_lease_store import (  # noqa: E402
    MAX_RELEASE_SKEW_SECONDS,
    MAX_TTL_SECONDS,
    STORE_COMMIT_UNKNOWN,
    STORE_UNREACHABLE,
    HeldLease,
    LeaseStanding,
    ReprovisionMarker,
    StoreRefused,
)

from tests.unit.lane3_e10_support import make_generation_receipt  # noqa: E402

EPOCH = datetime(2026, 11, 17, 5, 0, 0, tzinfo=UTC)
PRINCIPAL = "repo:dotmac-tech/lane3-exposure-execution:ref:refs/heads/main"


class Backing:
    """The shared state behind a store: the rows, the clock and the row lock.

    Several `FakeStore` HANDLES may be opened onto one `Backing`, as several
    connections open onto one database. Exclusivity lives here, in the shared
    lock, never in any one handle.
    """

    def __init__(self, now: datetime) -> None:
        self.now = now
        self.rows: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        #: Writes SENT to the store, whether or not they were accepted.
        self.write_attempts = 0
        #: Receipt refs a marker has already cited (design rule 5).
        self.spent: set[str] = set()


class FakeStore:
    """One handle onto a `Backing`: exclusive by the backing's lock, on its clock."""

    def __init__(
        self,
        *,
        authority: str = "database",
        now: datetime = EPOCH,
        backing: Backing | None = None,
    ) -> None:
        self.time_authority = authority
        self.backing = backing if backing is not None else Backing(now)
        self.covers_calls: list[tuple[str, datetime]] = []
        self.releases: list[tuple[Any, bool]] = []
        #: None, or when this handle's connection is dropped (see `sever`).
        self._severed: str | None = None
        self._pending_drop: str | None = None

    def sever(self, when: str) -> None:
        """Drop this handle's connection. `before_write`: it is gone before the
        next write is sent. `after_commit`: the next write commits, then the
        connection dies before the answer arrives."""
        if when not in ("before_write", "after_commit"):
            raise ValueError(when)
        if when == "before_write":
            self._severed = "dead"
        else:
            self._pending_drop = "after_commit"

    def _connected(self) -> None:
        if self._severed is not None:
            raise StoreRefused(STORE_UNREACHABLE)

    def _after_commit(self) -> None:
        if self._pending_drop is not None:
            self._pending_drop = None
            self._severed = "dead"
            raise StoreRefused(STORE_COMMIT_UNKNOWN)

    @property
    def _now(self) -> datetime:
        return self.backing.now

    @property
    def _rows(self) -> dict[str, dict[str, Any]]:
        return self.backing.rows

    @property
    def _lock(self) -> threading.Lock:
        return self.backing.lock

    def database_time(self) -> datetime:
        self._connected()
        return self.backing.now

    def advance(self, seconds: float) -> None:
        self.backing.now += timedelta(seconds=seconds)

    def acquire_exclusive(
        self,
        *,
        host_id: str,
        authorization_run: str,
        controller_identity: Any,
        ttl_seconds: int,
        e10_receipt: E10ReceiptRef,
        reprovision: ReprovisionMarker | None = None,
    ) -> HeldLease:
        self._connected()
        if not isinstance(e10_receipt, E10ReceiptRef):
            raise StoreRefused("e10-receipt-required")
        if e10_receipt.host_id != host_id:
            raise StoreRefused("e10-receipt-for-another-host")
        if (
            type(ttl_seconds) is not int
            or ttl_seconds < 1
            or ttl_seconds > MAX_TTL_SECONDS
        ):
            raise StoreRefused("lease-ttl-invalid")
        with self._lock:
            self.backing.write_attempts += 1
            row = self._rows.get(host_id)
            if row is not None:
                live = not row["released"] and self._now < row["expires_at"]
                if live:
                    raise StoreRefused("lease-held-by-another-run")
            if reprovision is not None:
                # Design rules 1 and 2: the marker names this host and cites the
                # receipt the new lease is taken under.
                if reprovision.host_id != host_id or reprovision.e10_receipt != (
                    e10_receipt
                ):
                    raise StoreRefused("reprovision-receipt-mismatch")
            if row is not None:
                mutated = (
                    row["mutated"] if row["released"] else True  # expired unreleased
                )
                if mutated and reprovision is None:
                    raise StoreRefused("lease-host-mutated")
                if reprovision is not None:
                    _require_newer_incarnation(row["receipt"], reprovision.e10_receipt)
            if reprovision is not None:
                if reprovision.e10_receipt.receipt_ref in self.backing.spent:
                    raise StoreRefused("reprovision-receipt-spent")
            expires = self._now + timedelta(seconds=ttl_seconds)
            lease = types.SimpleNamespace(
                controller_identity_fingerprint=controller_identity,
                authorization_run_id=authorization_run,
                target=host_id,
                workload_principal=PRINCIPAL,
                expires_at=expires.isoformat(),
                digest=f"sha256:{host_id}:{authorization_run}:{self._now.isoformat()}",
            )
            self._rows[host_id] = {
                "run": authorization_run,
                "expires_at": expires,
                "released": False,
                "mutated": None,
                "released_at": None,
                "lease": lease,
                "receipt": e10_receipt,
            }
            if reprovision is not None:
                self.backing.spent.add(reprovision.e10_receipt.receipt_ref)
            self._after_commit()
            return HeldLease(
                lease=lease,  # type: ignore[arg-type]
                handle=host_id,
                e10_receipt=e10_receipt,
                acquired_at=self._now,
                expires_at=expires,
            )

    def covers(self, held: HeldLease, *, authorization_run: str) -> datetime:
        self._connected()
        row = self._rows[held.handle]
        self.covers_calls.append((authorization_run, self._now))
        if row["released"] or self._now >= row["expires_at"]:
            raise StoreRefused("lease-expired")
        if row["run"] != authorization_run:
            raise StoreRefused("lease-foreign-run")
        return self._now

    def release(self, held: HeldLease, *, release: Any, host_mutated: bool) -> str:
        self._connected()
        with self._lock:
            self.backing.write_attempts += 1
            row = self._rows[held.handle]
            if row["released"]:
                raise StoreRefused("lease-already-released")
            if self._now >= row["expires_at"]:
                raise StoreRefused("lease-expired")
            lease = row["lease"]
            if (
                release.lease_digest != lease.digest
                or release.released_by.subject != lease.workload_principal
                or release.controller_identity_fingerprint
                != lease.controller_identity_fingerprint
            ):
                raise StoreRefused("release-not-this-lease")
            stamped = datetime.fromisoformat(release.released_at)
            if abs((stamped - self._now).total_seconds()) > MAX_RELEASE_SKEW_SECONDS:
                raise StoreRefused("release-clock-skew")
            row["released"] = True
            row["mutated"] = host_mutated
            row["released_at"] = self._now  # STORE time, whatever the record says
            self.releases.append((release, host_mutated))
            self._after_commit()
            return "release-digest"

    def standing(self, host_id: str) -> LeaseStanding:
        self._connected()
        row = self._rows[host_id]
        if row["released"]:
            return LeaseStanding.RELEASED
        if self._now >= row["expires_at"]:
            return LeaseStanding.EXPIRED_MUTATED
        return LeaseStanding.HELD

    def released_at(self, host_id: str) -> datetime | None:
        self._connected()
        return self._rows[host_id]["released_at"]


def release_for(store: Any, held: HeldLease, **overrides: Any) -> types.SimpleNamespace:
    """A release stand-in that matches `held` unless told otherwise."""
    fields: dict[str, Any] = {
        "lease_digest": held.lease.digest,
        "released_by": types.SimpleNamespace(subject=held.lease.workload_principal),
        "controller_identity_fingerprint": held.lease.controller_identity_fingerprint,
        "released_at": store.database_time().isoformat(),
    }
    fields.update(overrides)
    record = types.SimpleNamespace(**fields)
    record.as_document = lambda: {"release": "stand-in"}
    return record


def factory(cls: Callable[..., Any] = FakeStore) -> Callable[..., Any]:
    """`make(handle=None)`: a store, or a NEW handle onto `handle`'s backing."""

    def make(handle: Any = None) -> Any:
        if handle is None:
            return cls()
        return cls(backing=handle.backing)

    return make


def _require_newer_incarnation(
    leased_under: E10ReceiptRef, cited: E10ReceiptRef
) -> None:
    """A marker must cite a DIFFERENT, NEWER receipt than the lease's own.

    "Newer" is the store's receipt order: for the CP store its `seq`, for this
    fake the receipt's `incarnation_key_destroyed_at`. It must be STRICTLY
    greater, so an equal position is refused.

    The same receipt, key or enrolment is the same incarnation, whatever else
    differs; a different incarnation destroyed no later than the lease's is a
    receipt for a machine that came BEFORE the one the lease was taken under.
    """
    if (
        cited.receipt_ref == leased_under.receipt_ref
        or cited.incarnation_fingerprint == leased_under.incarnation_fingerprint
        or cited.enrolment_uuid == leased_under.enrolment_uuid
    ):
        raise StoreRefused("reprovision-receipt-same-incarnation")
    if cited.incarnation_key_destroyed_at <= leased_under.incarnation_key_destroyed_at:
        raise StoreRefused("reprovision-receipt-not-newer")


@dataclasses.dataclass(frozen=True)
class Fixtures:
    """What a store supplies for the parts of the suite that differ per store.

    Every case takes one, so no case reaches into a stand-in. The CP PR supplies
    a real one (a real `HostLease` digest, a real `HostLeaseReleaseV1`, receipts
    that exist in the receipt table, a killed connection); `FAKE_FIXTURES` is the
    reference fake's.
    """

    #: A valid `ControllerSshFingerprintV1` (a real lease refuses any other type),
    #: and a second, different one.
    controller_identity: Any
    other_controller_identity: Any
    #: The lease's `workload_principal`.
    principal: str
    #: The digest of the held lease, as the store computes it. A real `HostLease`
    #: has no `digest` attribute: this is Foundation's `lease_digest(lease)`.
    lease_digest: Callable[[HeldLease], str]
    #: `(store, held, *, digest=None, principal=None, controller=None,
    #: released_at=None)`: a release matching `held`, with any named field replaced.
    make_release: Callable[..., Any]
    #: `(host_id, generation, *, ordered_as=None, incarnation_of=None)`: the
    #: generation-th E10 receipt for the host. Each generation is a different
    #: incarnation (key, enrolment, ref), later in the store's receipt order than
    #: the one before; generation 1 is the first. `ordered_as=n` gives it
    #: generation n's position in that order; `incarnation_of=n` gives it
    #: generation n's incarnation key while its ref and order stay its own.
    receipt: Callable[..., E10ReceiptRef]
    #: `(store, when)`: drop that handle's connection, `when` being
    #: "before_write" or "after_commit" (the commit was sent, the answer lost).
    sever: Callable[[Any, str], None]
    #: How many writes have reached the store, accepted or not, on any handle.
    write_attempts: Callable[[Any], int]


def _fake_make_release(
    store: Any,
    held: HeldLease,
    *,
    digest: str | None = None,
    principal: str | None = None,
    controller: Any = None,
    released_at: str | None = None,
) -> types.SimpleNamespace:
    overrides: dict[str, Any] = {}
    if digest is not None:
        overrides["lease_digest"] = digest
    if principal is not None:
        overrides["released_by"] = types.SimpleNamespace(subject=principal)
    if controller is not None:
        overrides["controller_identity_fingerprint"] = controller
    if released_at is not None:
        overrides["released_at"] = released_at
    return release_for(store, held, **overrides)


FAKE_FIXTURES = Fixtures(
    controller_identity=ControllerSshFingerprintV1(digest=bytes(range(32))),
    other_controller_identity=ControllerSshFingerprintV1(digest=bytes(range(1, 33))),
    principal=PRINCIPAL,
    lease_digest=lambda held: held.lease.digest,
    make_release=_fake_make_release,
    receipt=make_generation_receipt,
    sever=lambda store, when: store.sever(when),
    write_attempts=lambda store: store.backing.write_attempts,
)


def _acquire(
    store: Any,
    fx: Fixtures,
    host: str = "host-a",
    run: str = "run-1",
    ttl: int = 60,
    *,
    generation: int = 1,
    receipt: Any = None,
    **extra: Any,
):
    return store.acquire_exclusive(
        host_id=host,
        authorization_run=run,
        controller_identity=fx.controller_identity,
        ttl_seconds=ttl,
        e10_receipt=receipt if receipt is not None else fx.receipt(host, generation),
        **extra,
    )


Case = Callable[[Callable[[], Any], Callable[[Any, float], None], Fixtures], None]


def _raises(code: str, call: Callable[[], Any]) -> None:
    try:
        call()
    except StoreRefused as exc:
        assert exc.code == code, f"expected {code}, got {exc.code}"
        return
    raise AssertionError(f"expected {code}, but nothing was refused")


def case_exclusive_under_concurrent_acquires(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    """One handle PER THREAD onto one shared store.

    A store that only serialises the calls of one handle (a Python lock inside the
    object) admits one holder per handle and fails here; only exclusivity held in
    the shared store, as a row lock is, admits exactly one.
    """
    base = make_store()
    handles = [make_store(base) for _ in range(8)]
    outcomes: list[str] = []
    barrier = threading.Barrier(len(handles))

    def attempt(index: int) -> None:
        barrier.wait()
        try:
            _acquire(handles[index], fx, run=f"run-{index}")
            outcomes.append("held")
        except StoreRefused:
            outcomes.append("refused")

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert outcomes.count("held") == 1
    assert outcomes.count("refused") == 7


def case_covers_is_judged_on_store_time(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    held = _acquire(store, fx)
    assert store.covers(held, authorization_run="run-1") == store.database_time()
    _raises("lease-foreign-run", lambda: store.covers(held, authorization_run="x"))
    advance(store, 61)
    _raises("lease-expired", lambda: store.covers(held, authorization_run="run-1"))


def case_expiry_is_a_mutated_host_never_a_clean_release(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    held = _acquire(store, fx)
    advance(store, 61)
    assert store.standing("host-a") is LeaseStanding.EXPIRED_MUTATED
    _raises(
        "lease-expired",
        lambda: store.release(
            held, release=fx.make_release(store, held), host_mutated=False
        ),
    )
    assert store.standing("host-a") is LeaseStanding.EXPIRED_MUTATED


def case_no_reacquire_after_expiry(make_store: Any, advance: Any, fx: Fixtures) -> None:
    store = make_store()
    _acquire(store, fx)
    advance(store, 61)
    _raises("lease-host-mutated", lambda: _acquire(store, fx, run="run-2"))
    assert store.standing("host-a") is LeaseStanding.EXPIRED_MUTATED


def case_no_reacquire_after_a_mutated_release(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    held = _acquire(store, fx)
    store.release(held, release=fx.make_release(store, held), host_mutated=True)
    _raises("lease-host-mutated", lambda: _acquire(store, fx, run="run-2"))
    assert store.standing("host-a") is LeaseStanding.RELEASED


def case_an_untouched_release_may_be_reacquired(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    held = _acquire(store, fx)
    store.release(held, release=fx.make_release(store, held), host_mutated=False)
    assert _acquire(store, fx, run="run-2") is not None


def case_only_an_explicit_reprovision_marker_reopens_a_mutated_host(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    _acquire(store, fx)
    advance(store, 61)
    other = ReprovisionMarker("host-other", fx.receipt("host-other", 2))
    _raises(
        "reprovision-receipt-mismatch",
        lambda: _acquire(store, fx, run="run-2", generation=2, reprovision=other),
    )
    _raises("lease-host-mutated", lambda: _acquire(store, fx, run="run-2"))
    marker = ReprovisionMarker("host-a", fx.receipt("host-a", 2))
    held = _acquire(store, fx, run="run-2", generation=2, reprovision=marker)
    assert store.standing("host-a") is LeaseStanding.HELD
    assert held.lease.authorization_run_id == "run-2"
    assert held.e10_receipt == fx.receipt("host-a", 2)


def case_a_marker_must_cite_a_different_incarnation_than_the_leases(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    _acquire(store, fx, generation=2)
    advance(store, 61)
    # The lease's own receipt, re-cited: the same incarnation, however it is dressed.
    same = ReprovisionMarker("host-a", fx.receipt("host-a", 2))
    _raises(
        "reprovision-receipt-same-incarnation",
        lambda: _acquire(store, fx, run="run-2", generation=2, reprovision=same),
    )
    assert store.standing("host-a") is LeaseStanding.EXPIRED_MUTATED


def case_a_marker_must_cite_a_newer_receipt_than_the_leases(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    _acquire(store, fx, generation=2)
    advance(store, 61)
    # A different incarnation, but one destroyed BEFORE the lease's: not newer.
    older = ReprovisionMarker("host-a", fx.receipt("host-a", 1))
    _raises(
        "reprovision-receipt-not-newer",
        lambda: _acquire(store, fx, run="run-2", generation=1, reprovision=older),
    )
    assert store.standing("host-a") is LeaseStanding.EXPIRED_MUTATED
    newer = ReprovisionMarker("host-a", fx.receipt("host-a", 3))
    assert _acquire(store, fx, run="run-2", generation=3, reprovision=newer)


def case_a_marker_must_cite_a_strictly_later_receipt_order(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    """Newer is the store's receipt order (CP: `seq`), strictly greater."""
    store = make_store()
    _acquire(store, fx, generation=2)
    advance(store, 61)
    # A different incarnation (ref, key, enrolment) at the SAME position: not newer.
    tied = fx.receipt("host-a", 3, ordered_as=2)
    _raises(
        "reprovision-receipt-not-newer",
        lambda: _acquire(
            store,
            fx,
            run="run-2",
            receipt=tied,
            reprovision=ReprovisionMarker("host-a", tied),
        ),
    )
    # A LATER position but the lease's own incarnation key: still the same one.
    reused = fx.receipt("host-a", 3, incarnation_of=2)
    _raises(
        "reprovision-receipt-same-incarnation",
        lambda: _acquire(
            store,
            fx,
            run="run-2",
            receipt=reused,
            reprovision=ReprovisionMarker("host-a", reused),
        ),
    )
    assert store.standing("host-a") is LeaseStanding.EXPIRED_MUTATED


def case_a_marker_must_cite_the_receipt_the_new_lease_is_taken_under(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    _acquire(store, fx)
    advance(store, 61)
    marker = ReprovisionMarker("host-a", fx.receipt("host-a", 2))
    # The new lease names a different receipt than the marker cites.
    _raises(
        "reprovision-receipt-mismatch",
        lambda: _acquire(store, fx, run="run-2", generation=3, reprovision=marker),
    )
    # A marker for another host, whatever it cites.
    foreign = ReprovisionMarker("host-other", fx.receipt("host-other", 2))
    _raises(
        "reprovision-receipt-mismatch",
        lambda: _acquire(store, fx, run="run-2", generation=2, reprovision=foreign),
    )
    assert store.standing("host-a") is LeaseStanding.EXPIRED_MUTATED


def case_a_lease_needs_a_typed_e10_receipt(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    for citation in ("e10-receipt-1", None, {"receipt_ref": "x"}):
        _raises(
            "e10-receipt-required",
            lambda c=citation: store.acquire_exclusive(
                host_id="host-a",
                authorization_run="run-1",
                controller_identity=fx.controller_identity,
                ttl_seconds=60,
                e10_receipt=c,
            ),
        )
    # A well-formed receipt for ANOTHER host is not this host's receipt.
    _raises(
        "e10-receipt-for-another-host",
        lambda: _acquire(store, fx, receipt=fx.receipt("host-b", 1)),
    )
    assert _acquire(store, fx) is not None


def case_only_one_release(make_store: Any, advance: Any, fx: Fixtures) -> None:
    store = make_store()
    held = _acquire(store, fx)
    store.release(held, release=fx.make_release(store, held), host_mutated=True)
    _raises(
        "lease-already-released",
        lambda: store.release(
            held, release=fx.make_release(store, held), host_mutated=False
        ),
    )
    assert len(getattr(store, "releases", [1])) == 1


def case_a_release_must_match_the_held_lease(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    held = _acquire(store, fx)
    wrong = {
        "digest": {"digest": "sha256:" + "0" * 64},
        "principal": {"principal": "someone-else"},
        "controller": {"controller": fx.other_controller_identity},
    }
    assert fx.lease_digest(held) != "sha256:" + "0" * 64
    assert held.lease.workload_principal == fx.principal
    for overrides in wrong.values():
        _raises(
            "release-not-this-lease",
            lambda o=overrides: store.release(
                held,
                release=fx.make_release(store, held, **o),
                host_mutated=True,
            ),
        )
    assert store.standing("host-a") is LeaseStanding.HELD
    # The release naming the digest the store computes for THIS lease is accepted.
    store.release(
        held,
        release=fx.make_release(store, held, digest=fx.lease_digest(held)),
        host_mutated=True,
    )
    assert store.standing("host-a") is LeaseStanding.RELEASED


def case_the_lease_document_expiry_is_the_rows(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    held = _acquire(store, fx, ttl=120)
    assert datetime.fromisoformat(held.lease.expires_at) == held.expires_at
    assert held.expires_at - held.acquired_at == timedelta(seconds=120)


def case_the_ttl_is_capped(make_store: Any, advance: Any, fx: Fixtures) -> None:
    store = make_store()
    for ttl in (0, -5, MAX_TTL_SECONDS + 1, 10**9, True, 1.5):
        _raises("lease-ttl-invalid", lambda t=ttl: _acquire(store, fx, ttl=t))
    assert _acquire(store, fx, ttl=MAX_TTL_SECONDS) is not None


def case_released_at_is_store_time_not_the_runners(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    held = _acquire(store, fx)
    advance(store, 10)
    # A runner whose clock is hours off cannot get its stamp accepted...
    runner_clock = (store.database_time() + timedelta(hours=5)).isoformat()
    _raises(
        "release-clock-skew",
        lambda: store.release(
            held,
            release=fx.make_release(store, held, released_at=runner_clock),
            host_mutated=True,
        ),
    )
    # ...and an accepted release is stamped on STORE time even if the record's own
    # stamp is slightly off.
    slightly_off = (store.database_time() - timedelta(seconds=5)).isoformat()
    store.release(
        held,
        release=fx.make_release(store, held, released_at=slightly_off),
        host_mutated=True,
    )
    assert store.released_at("host-a") == store.database_time()


def case_a_lost_connection_fails_closed_and_writes_nothing(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    """Q1-B: a dropped connection is `store-unreachable`, with no write sent."""
    store = make_store()
    survivor = make_store(store)
    fx.sever(store, "before_write")
    sent = fx.write_attempts(survivor)
    _raises(STORE_UNREACHABLE, lambda: _acquire(store, fx))
    assert fx.write_attempts(survivor) == sent
    # Nothing was taken: another handle acquires the host.
    held = _acquire(survivor, fx, run="run-2")
    sent = fx.write_attempts(survivor)
    # A release over a lost connection writes nothing and the lease stays held.
    lost = make_store(store)
    # Built on the live handle: the release call itself must be what fails.
    release = fx.make_release(survivor, held)
    fx.sever(lost, "before_write")
    _raises(
        STORE_UNREACHABLE,
        lambda: lost.release(held, release=release, host_mutated=True),
    )
    _raises(
        STORE_UNREACHABLE,
        lambda: lost.covers(held, authorization_run="run-2"),
    )
    assert fx.write_attempts(survivor) == sent
    assert survivor.standing("host-a") is LeaseStanding.HELD


def case_an_acquire_commit_lost_is_unknown_and_never_retried(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    """Q1-B: the answer to a sent commit is lost. `store-commit-unknown`, ONE write
    sent (never a second), and the standing read afterwards shows what happened."""
    store = make_store()
    survivor = make_store(store)
    sent = fx.write_attempts(survivor)
    fx.sever(store, "after_commit")
    _raises(STORE_COMMIT_UNKNOWN, lambda: _acquire(store, fx))
    assert fx.write_attempts(survivor) == sent + 1
    assert survivor.standing("host-a") is LeaseStanding.HELD
    # The dead connection stays dead: a further call is unreachable, not retried.
    _raises(STORE_UNREACHABLE, lambda: _acquire(store, fx, run="run-2"))
    assert fx.write_attempts(survivor) == sent + 1
    _raises("lease-held-by-another-run", lambda: _acquire(survivor, fx, run="run-2"))


def case_a_release_commit_lost_is_unknown_and_never_retried(
    make_store: Any, advance: Any, fx: Fixtures
) -> None:
    store = make_store()
    survivor = make_store(store)
    held = _acquire(store, fx)
    sent = fx.write_attempts(survivor)
    fx.sever(store, "after_commit")
    _raises(
        STORE_COMMIT_UNKNOWN,
        lambda: store.release(
            held, release=fx.make_release(store, held), host_mutated=True
        ),
    )
    assert fx.write_attempts(survivor) == sent + 1
    # Standing is consistent: released exactly once, as mutated.
    assert survivor.standing("host-a") is LeaseStanding.RELEASED
    _raises(
        "lease-already-released",
        lambda: survivor.release(
            held, release=fx.make_release(survivor, held), host_mutated=False
        ),
    )


CASES: dict[str, Case] = {
    name.removeprefix("case_"): fn
    for name, fn in sorted(globals().items())
    if name.startswith("case_")
}
