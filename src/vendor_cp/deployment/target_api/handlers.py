"""The seam between the router and the target API's domain.

The router authenticates and signs; a `TargetHandlers` decides. A handler gets
the authenticated call, the request's own database session (the nonce has
already been spent in it, so everything the handler does commits or rolls back
WITH the nonce) and the parsed JSON payload (`None` for a GET; a POST body that
is not UTF-8 JSON, or repeats a key, is refused by the router before any handler
runs), and returns a status and a JSON-able mapping.

A handler that must undo partial work and still answer returns a refusal result
from inside a `conflict_savepoint`; one that raises rolls the whole request back
(the nonce too) and the caller sees an unsigned, retryable 5xx.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api.auth import AuthenticatedCall

__all__ = ["HandlerResult", "NotImplementedHandlers", "TargetHandlers"]


@dataclass(frozen=True, slots=True)
class HandlerResult:
    status: int
    body: Mapping[str, object]


class TargetHandlers(Protocol):
    def handle(
        self, call: AuthenticatedCall, db: Session, payload: object
    ) -> HandlerResult: ...


class NotImplementedHandlers:
    """Every authenticated route answers 501 until its handler exists."""

    def handle(
        self, call: AuthenticatedCall, db: Session, payload: object
    ) -> HandlerResult:
        return HandlerResult(501, {"error": "not_implemented"})
