"""The one place an approval hold meets a Control transition, in one transaction.

`dotmac_approvals.hold_platform_approval` locks the platform approval request
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
    """
    from dotmac_approvals import hold_platform_approval

    held = hold_platform_approval(
        db,
        request_id=request_id,
        subject_type=subject_type,
        subject_id=subject_id,
        content_digest=content_digest,
    )
    return transition(held)


__all__ = ["held_transition"]
