"""The product descriptor as something checkable against a real database.

`deploy/product.toml` declares what this deployment's database is. Until
2026-08-31 nothing compared that declaration to a database, in either direction,
and a create-only bootstrap advanced the database to new migration heads —
creating a schema and revoking a privilege — while the descriptor went on
describing the state it started from. It surfaced because a relayed claim was
checked by hand, which is not a mechanism.

`drift` is the mechanism. It is a pure comparison over two documents and
connects to nothing: the target-side read is the catalogue capture that
`vendor_cp.recovery.capture` already emits, run by an operator, a deployment run
or a recovery run against the target. Deny case D1 keeps the connecting-entrypoint
allowlist empty, and a checker that could read the database it validates could
also arrange for its own check to pass.
"""

from __future__ import annotations

from vendor_cp.descriptor.drift import (
    CAPTURE_KEYS,
    Direction,
    DriftReport,
    Finding,
    IncompleteCapture,
    Subject,
    compare,
)

__all__ = [
    "CAPTURE_KEYS",
    "Direction",
    "DriftReport",
    "Finding",
    "IncompleteCapture",
    "Subject",
    "compare",
]
