"""The lease-store interface the Lane 3 launcher requires (E7 / U5).

Michael's ruling (U5): the lease store is the CP production database, under the
per-run scoped role. This module defines ONLY the contract the launcher depends
on. It writes no table, no migration and no implementation: the CP side needs a
separate image-budget ruling, and nothing here touches the CP repository.

## The contract

1. **Exclusive acquisition.** `acquire_exclusive` takes the host's lease row under
   a row lock. Concurrent acquisitions of one host admit exactly one; a second
   acquisition of a live lease refuses.
2. **Store time is the only clock.** `database_time` is the store's own wall
   clock. Expiry, `covers` and `released_at` are judged and stamped on it and on
   nothing else: never the target's clock and never the runner's. A store that
   cannot supply database time is refused by :func:`require_database_time`; the
   file-backed store of the controller-side runner is exactly such a store.
3. **Custody and release are one store.** The release record is written through
   `release`, into the same store that holds the lease. There is no second
   ledger, so the destroy gate reads one answer.
4. **A release says whether the host was mutated.** `release` takes
   `host_mutated` explicitly and records it. It cannot be defaulted.
5. **A dead runner never releases a host as untouched.** If a holder never
   releases, the lease EXPIRES on store time and `standing` answers
   `EXPIRED_MUTATED`. `release` of an expired lease refuses.
6. **Mutation history is never wiped.** A host whose standing is
   `EXPIRED_MUTATED`, or that was released with `host_mutated=True`, is NEVER
   re-acquired. The only exception is an explicit :class:`ReprovisionMarker`
   naming the host and citing the typed E10 receipt for the new incarnation. The
   marker is defined here; nothing but the reference fake implements it, and CP
   verifies the citation against a real receipt.
7. **One release.** A lease is released at most once; a second `release` refuses.
8. **A release must be this lease's.** `release` refuses unless the record's
   `lease_digest` is the digest of the held lease, its `released_by.subject` is
   the lease's `workload_principal`, and its `controller_identity_fingerprint` is
   the lease's.
9. **The lease document is the row.** The `HostLease` the store returns carries
   an `expires_at` equal to the row's `expires_at`; there is not one expiry in the
   document and another in the table.
10. **A capped TTL.** `ttl_seconds` must be positive and no more than
    :data:`MAX_TTL_SECONDS`; anything else refuses.
11. **`released_at` is store time.** The store stamps the release on its own clock
    (`released_at(host_id)`) and refuses a record whose own `released_at` is more
    than :data:`MAX_RELEASE_SKEW_SECONDS` from store time. The runner's clock
    never decides when a host was released.

12. **A dropped connection fails closed and a write is never retried.** A store
    reached over a connection that can die (the CP store, over the attended
    tunnel) maps a connection that is gone BEFORE a write was sent to
    `store-unreachable`, and one lost after the commit was sent, so the outcome is
    unknown, to `store-commit-unknown`. Neither is retried: the store sends each
    write at most once, and the launcher reads standing afterwards instead of
    repeating a call.
13. **A lease carries the receipt it was taken under.** `acquire_exclusive`
    requires the typed E10 receipt for the host's current incarnation
    (`e10-receipt-required` otherwise) and the returned :class:`HeldLease`
    carries it. A :class:`ReprovisionMarker` must name this host and cite the
    receipt the new lease is taken under (`reprovision-receipt-mismatch`), and
    reopens a mutated host only when that receipt is a DIFFERENT incarnation
    (`reprovision-receipt-same-incarnation`: the same ref, incarnation key or
    enrolment) and NEWER than the receipt the previous lease was taken under
    (`reprovision-receipt-not-newer`). "Newer" is the store's own receipt order:
    for the CP store its `seq`, for the reference fake
    `incarnation_key_destroyed_at`. It is strictly greater, so an equal position
    is refused. A receipt a marker has cited once is spent
    (`reprovision-receipt-spent`).

## The target's role has no privileges on the lease tables

The target runs under a per-run SCOPED consumption role to consume the Control
dispatch. That role must hold NO privilege (not SELECT, not UPDATE, not a column
grant, not a lock) on any lease table. A compromised target must not be able to
read, extend or clear a lease; only the launcher's role writes this store.

The launcher enforces what it can from outside: it refuses a store that lacks
database time, judges `covers` on the store before it lets the target proceed,
passes the target the store's time (never its own), and forces
`host_mutated=True` once the target has reported `ready`.
"""

from __future__ import annotations

import dataclasses
import enum
import pathlib
import sys
from datetime import datetime
from typing import Final, Protocol, runtime_checkable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from dotmac_deployment_foundation.controller_identity import (
    ControllerSshFingerprintV1,
)
from dotmac_deployment_foundation.lease import HostLease
from dotmac_deployment_foundation.lease_release import HostLeaseReleaseV1
from lane3_e10_receipt import E10ReceiptRef

__all__ = [
    "DATABASE_TIME",
    "MAX_RELEASE_SKEW_SECONDS",
    "MAX_TTL_SECONDS",
    "STORE_COMMIT_UNKNOWN",
    "STORE_UNREACHABLE",
    "HeldLease",
    "LeaseStanding",
    "LeaseStore",
    "ReprovisionMarker",
    "StoreRefused",
    "require_database_time",
]

#: The only value `LeaseStore.time_authority` may carry.
DATABASE_TIME: Final = "database"
#: Refusal codes for a lost connection (rule 12). Never retried.
STORE_UNREACHABLE: Final = "store-unreachable"
STORE_COMMIT_UNKNOWN: Final = "store-commit-unknown"
#: The longest lease a store grants. A lease that outlives a run by hours is a
#: host nobody can take back.
MAX_TTL_SECONDS: Final = 3600
#: How far a release record's own `released_at` may sit from store time.
MAX_RELEASE_SKEW_SECONDS: Final = 60


@dataclasses.dataclass(frozen=True, slots=True)
class ReprovisionMarker:
    """The one explicit exception to "mutation history is never wiped".

    Names the host and cites the per-VM E10 receipt (a typed
    :class:`~lane3_e10_receipt.E10ReceiptRef`, never a free string) for the NEW
    incarnation of the machine. Without it a mutated or expired host is never
    re-acquired. This module only requires the citation to be well-formed and for
    the receipt to name this host; CP verifies the reference against a real
    receipt, and nothing here does.
    """

    host_id: str
    e10_receipt: E10ReceiptRef

    def __post_init__(self) -> None:
        if not isinstance(self.e10_receipt, E10ReceiptRef):
            raise StoreRefused("reprovision-receipt-required")
        if self.e10_receipt.host_id != self.host_id:
            raise StoreRefused("reprovision-receipt-for-another-host")


class StoreRefused(Exception):
    """The store, or the lease it holds, is unacceptable. A CODE, never a value."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LeaseStanding(enum.Enum):
    """What the store says about a host, on store time."""

    #: A live lease is held and no release exists.
    HELD = "held"
    #: A release record exists, written through `release`.
    RELEASED = "released"
    #: The lease expired without a release. The host is treated as MUTATED and is
    #: never read as released or reusable.
    EXPIRED_MUTATED = "expired_mutated"


@dataclasses.dataclass(frozen=True, slots=True)
class HeldLease:
    """A lease this launcher holds, with the store times it was judged on."""

    lease: HostLease
    #: Opaque to the launcher; names the row lock / row the store holds.
    handle: str
    #: The E10 receipt the lease was taken under (rule 13). A real `HostLease`
    #: does not carry it, so the held lease does.
    e10_receipt: E10ReceiptRef
    #: Both are STORE time.
    acquired_at: datetime
    expires_at: datetime


@runtime_checkable
class LeaseStore(Protocol):
    """What the launcher needs from a lease store. See the module docstring."""

    #: Must equal :data:`DATABASE_TIME`.
    time_authority: str

    def database_time(self) -> datetime:
        """The store's own wall clock, timezone-aware."""
        ...

    def acquire_exclusive(
        self,
        *,
        host_id: str,
        authorization_run: str,
        controller_identity: ControllerSshFingerprintV1,
        ttl_seconds: int,
        e10_receipt: E10ReceiptRef,
        reprovision: ReprovisionMarker | None = None,
    ) -> HeldLease:
        """Take the host's lease under a row lock, or raise `StoreRefused`.

        Refuses a non-positive or over-cap TTL, a live lease, and (without a
        `reprovision` marker for this host) a host that is expired-mutated or was
        released as mutated. A marker whose receipt is the lease's own
        incarnation refuses `reprovision-receipt-same-incarnation`; one that is
        not newer refuses `reprovision-receipt-not-newer`. A lost connection
        refuses `store-unreachable` or `store-commit-unknown` and is not retried.
        """
        ...

    def covers(self, held: HeldLease, *, authorization_run: str) -> datetime:
        """Judge `held` on STORE time; return the instant judged, or refuse."""
        ...

    def release(
        self,
        held: HeldLease,
        *,
        release: HostLeaseReleaseV1,
        host_mutated: bool,
    ) -> str:
        """Record the release in this same store; return its digest.

        Refuses when `held` has expired on store time.
        """
        ...

    def standing(self, host_id: str) -> LeaseStanding:
        """The host's standing on store time."""
        ...

    def released_at(self, host_id: str) -> datetime | None:
        """When the store stamped the release, on store time; None if unreleased."""
        ...


def require_database_time(store: object) -> LeaseStore:
    """Return `store` only if it provably supplies database time, else refuse.

    Checked: it has the interface; it declares `time_authority == "database"`;
    and `database_time()` answers with a timezone-aware instant. A store that
    cannot supply database time cannot judge expiry, so it is not a lease store
    for this lane, however it persists records.
    """
    if not isinstance(store, LeaseStore):
        raise StoreRefused("store-lacks-interface")
    if getattr(store, "time_authority", None) != DATABASE_TIME:
        raise StoreRefused("store-lacks-database-time")
    try:
        instant = store.database_time()
    except Exception:
        raise StoreRefused("store-lacks-database-time") from None
    if not isinstance(instant, datetime) or instant.tzinfo is None:
        raise StoreRefused("store-lacks-database-time")
    return store
