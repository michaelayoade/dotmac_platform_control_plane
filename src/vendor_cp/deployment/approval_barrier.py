"""The one place an approval hold meets a Control transition, in one transaction.

`dotmac_approvals.service.hold_platform_approval` locks the platform approval request
row FOR SHARE and validates it under that lock; it never commits, and the lock
it takes lives only until the CALLER's transaction ends. The evidence it
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

if TYPE_CHECKING:
    from collections.abc import Callable

    from dotmac_approvals import HeldPlatformApproval
    from sqlalchemy.orm import Session

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

    Raises `dotmac_approvals.ApprovalNotHeld` (never calling `transition`) if
    the request does not stand approved for exactly this subject and digest.
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
    # Approvals 0.1.0a8 exports the contracts (`HeldPlatformApproval`,
    # `ApprovalNotHeld`) from its package root but the function only from
    # `dotmac_approvals.service` -- the same module CP's approvals adapter
    # already imports from. Resolved at call time so a test can patch it.
    from dotmac_approvals.service import hold_platform_approval

    _require_transactional(db)
    held = hold_platform_approval(
        db,
        request_id=request_id,
        subject_type=subject_type,
        subject_id=subject_id,
        content_digest=content_digest,
    )
    return transition(held)


class ApprovalBarrierUnavailable(RuntimeError):
    """The session cannot keep a lock past one statement, so there is no barrier."""


def _require_transactional(db: Session) -> None:
    """Refuse an AUTOCOMMIT connection: there a FOR SHARE lock ends with its
    own statement, and the barrier would pass while holding nothing."""
    if db.connection().get_isolation_level() == "AUTOCOMMIT":
        raise ApprovalBarrierUnavailable(
            "held_transition needs a transactional session; on an AUTOCOMMIT "
            "connection the FOR SHARE hold would end with its own statement"
        )


__all__ = ["ApprovalBarrierUnavailable", "held_transition"]
