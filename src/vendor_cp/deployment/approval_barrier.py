"""The one place an approval hold meets a Control transition, in one transaction.

`vendor_cp.approvals.adapter.hold_approval` (over Approvals'
`hold_platform_approval`) locks the platform approval request row FOR SHARE
and validates it under that lock; it never commits, and the lock it takes
lives only until the CALLER's transaction ends. The evidence it
returns (`HeldPlatformApproval`) is not the lock — carrying it past a commit,
or into another session, carries no protection at all.

`held_transition` is the synchronous barrier: it takes the hold, then runs the
caller's Control transition against the SAME `db`, in the SAME transaction,
while the row is still locked. No commit, flush-commit, or new transaction
happens inside this module or the `transition` it calls — the caller owns the
single commit, and that commit is what releases the lock. A withdrawal
attempting the row's FOR UPDATE lock during that window either committed
first (and the hold above refused with `WITHDRAWN`) or blocks until the
caller's transaction ends.

Approvals and Control are imported lazily, inside the function, so this leaf
stays import-light, matching `protected_rehearsal_issuer.py`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar
from uuid import UUID

from sqlalchemy import text

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.orm import Session

    from vendor_cp.approvals.adapter import HeldPlatformApproval

T = TypeVar("T")


def held_transition(
    db: Session,
    *,
    request_id: UUID,
    subject_type: str,
    subject_id: str,
    content_digest: str,
    transition: Callable[[HeldPlatformApproval], T],
) -> T:
    """Hold the approval, then run `transition` while still holding it.

    Does not commit, flush-commit, or open a new transaction. The caller must
    perform its own single commit after this returns, in the same
    transaction — that commit is what releases the FOR SHARE lock this holds.

    Raises `ApprovalNotHeld` (re-exported by the approvals adapter), never
    calling `transition`, if the request does not stand approved for exactly
    this subject and digest.
    Raises `ApprovalBarrierUnavailable` (never calling `transition`) if `db`
    is on an AUTOCOMMIT connection, where the FOR SHARE lock would end with
    its own statement and the barrier would silently hold nothing.

    Two lock-order invariants a caller must keep (a global order of Approvals
    request row -> Control target -> plan -> rollout):

    - never enter `held_transition` while this transaction already holds a
      Control target or plan lock, which would invert the order;
    - never upgrade the held request row to FOR UPDATE inside the same
      transaction, because two concurrent upgraders deadlock.
    """
    # The approvals adapter is the only CP module that reaches Approvals'
    # service surface (tests/architecture/test_approvals_authority.py).
    # Resolved at call time so a conformance test can patch this exact name.
    from vendor_cp.approvals.adapter import hold_approval

    _require_transactional(db)
    held = hold_approval(
        db,
        request_id=request_id,
        subject_type=subject_type,
        subject_id=subject_id,
        content_digest=content_digest,
    )
    _require_the_hold_is_still_open(db)
    return transition(held)


class ApprovalBarrierUnavailable(RuntimeError):
    """The session cannot keep a lock past one statement, so there is no barrier."""


def _require_transactional(db: Session) -> None:
    """Refuse an AUTOCOMMIT connection before holding anything.

    SQLAlchemy's `Connection.get_isolation_level()` never reports AUTOCOMMIT
    (it asks the server for the real isolation level), so the DBAPI
    connection's own `autocommit` flag is what is read here. Both psycopg 2
    and 3 expose it.
    """
    dbapi_connection = db.connection().connection.dbapi_connection
    if getattr(dbapi_connection, "autocommit", False):
        raise ApprovalBarrierUnavailable(
            "held_transition needs a transactional session; on an AUTOCOMMIT "
            "connection the FOR SHARE hold would end with its own statement"
        )


def _require_the_hold_is_still_open(db: Session) -> None:
    """The database's own answer, independent of any driver flag: a row lock
    assigns a transaction id, so after the FOR SHARE hold this transaction
    MUST have one. If it does not, the hold's transaction already ended, for
    example on an autocommit connection a flag check missed. The barrier then
    holds nothing, and no transition may run."""
    assigned = db.execute(text("SELECT txid_current_if_assigned()")).scalar()
    if assigned is None:
        raise ApprovalBarrierUnavailable(
            "the approval hold's transaction is no longer open; the FOR SHARE "
            "lock is not held, so the transition must not run"
        )


__all__ = ["ApprovalBarrierUnavailable", "held_transition"]
