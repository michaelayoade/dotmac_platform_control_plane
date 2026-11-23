"""Request authentication, credential binding and replay (DESIGN-rev3 section 2.6).

Every request is judged here, before any handler runs:

1. the ONE coordinate check (`contract.check_request`): path, verb, query string,
   five single-valued headers, nonce, timestamp skew against CP DATABASE time,
   and that the header target, the path target and the credential's target are
   the same target;
2. the credential must exist, carry the target-request purpose, be ACTIVE at
   store time and hold an admissible key (a published test key authenticates
   nobody);
3. the Ed25519 signature over `signed_message`;
4. the per-credential rate limit (applied only to AUTHENTICATED callers, so an
   attacker cannot spend a victim's budget by naming its credential id);
5. the nonce goes into the Kernel ledger under `deployment.target_request_nonce.v1`
   with permanent retention, in the same transaction as the request's effect.

No session cookie and no bearer token is accepted: a request that carries either
is refused rather than ignored, so a route can never answer to two owners.

The authenticator never builds a session: it receives one (hard rule 7).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dotmac_kernel.idempotency import execute_once_platform
from sqlalchemy import text
from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api import contract as c

__all__ = [
    "AMBIENT_CREDENTIAL_HEADERS",
    "AuthenticatedCall",
    "CredentialDirectory",
    "CredentialRecord",
    "KernelNonceLedger",
    "NonceLedger",
    "RateLimiter",
    "SlidingWindowRateLimiter",
    "StoreClock",
    "TargetApiRefusal",
    "TargetPrincipal",
    "TargetRequestAuthenticator",
    "database_store_now",
    "refusal_status",
]

#: Credentials that belong to OTHER authentication owners. A target request that
#: carries one is refused, never silently ignored.
AMBIENT_CREDENTIAL_HEADERS: Final = ("authorization", "cookie")

#: The kernel ledger's operation name for a spent nonce (operators read this).
_NONCE_OPERATION: Final = "vendor.deploy_target_api.nonce"

#: `check_request` refusals that are not a plain 401. Everything else the
#: contract defines is an authentication failure.
_CONTRACT_STATUS: Final = {
    "bad_path": 404,
    "wrong_verb": 405,
    "target_mismatch_credential": 403,
    "target_mismatch_header_path": 403,
}


def refusal_status(code: str) -> int:
    """The HTTP status of a contract refusal code (401 unless listed)."""
    return _CONTRACT_STATUS.get(code, 401)


class TargetApiRefusal(Exception):
    """A request refused. `code` is closed and never carries a value.

    `signed` is False for the transport faults the contract defines as
    unsigned and retryable (413, 429): a client maps those to `cp_unreachable`.
    """

    def __init__(
        self,
        code: str,
        status: int,
        *,
        signed: bool = True,
        store_now: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.signed = signed
        self.store_now = store_now


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    """What the directory knows about one credential, read at store time."""

    credential_id: str
    #: The target the credential is bound to, `<product>/<environment>/<host>`.
    target_ref: str
    #: Control's `TargetCredential.public_key_b64`: unpadded base64url.
    public_key_b64u: str
    #: ACTIVE at the store time asked about (half-open window, not revoked).
    eligible: bool
    #: Enrolled for the target-request purpose with the Ed25519 algorithm.
    purpose_ok: bool


class CredentialDirectory(Protocol):
    def lookup(
        self, db: Session, credential_id: str, *, at: datetime
    ) -> CredentialRecord | None: ...


class NonceLedger(Protocol):
    def spend(self, db: Session, ledger_key: str) -> bool:
        """True when the nonce was fresh and is now spent; False on a replay."""


class KernelNonceLedger:
    """The Kernel insert-only ledger, scope `deployment.target_request_nonce.v1`.

    Retention is PERMANENT per credential (`expires_at` is NULL, which
    `purge_expired` never deletes): the skew window bounds how old a request may
    be, and a bounded ledger would let a captured request replay once its entry
    aged out. The insert joins the caller's transaction, so a nonce is spent if
    and only if the request's effect committed.
    """

    def spend(self, db: Session, ledger_key: str) -> bool:
        outcome = execute_once_platform(
            db,
            scope=c.NONCE_LEDGER_SCOPE,
            key=ledger_key,
            operation=lambda _session: {},
            operation_name=_NONCE_OPERATION,
        )
        return not outcome.replayed


StoreClock = Callable[[Session], datetime]


def database_store_now(db: Session) -> datetime:
    """CP database time. Never the local clock.

    `clock_timestamp()`, not `now()`: `now()` is the START of the transaction,
    which would make a long request look fresh.
    """
    value = db.execute(text("SELECT clock_timestamp()")).scalar()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeError("database time was not a timezone-aware instant")
    return value.astimezone(UTC)


class RateLimiter(Protocol):
    def allow(self, key: str) -> bool: ...


class SlidingWindowRateLimiter:
    """Per-process sliding window, keyed by an AUTHENTICATED credential id.

    Process-local by design: a worker's budget is its own, which bounds each
    worker without a shared store. A multi-worker host multiplies the limit by
    the worker count.
    """

    def __init__(
        self,
        *,
        limit: int = 120,
        window_seconds: float = 60.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1 or window_seconds <= 0:
            raise ValueError("a rate limit needs a positive limit and window")
        self._limit = limit
        self._window = window_seconds
        self._monotonic = monotonic
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True


@dataclass(frozen=True, slots=True)
class TargetPrincipal:
    """The authenticated caller. Handlers authorise on THIS and nothing else.

    P-CP1 enrols target principals only. A later launcher principal is a Control
    enrolment act and adds no endpoint.
    """

    kind: str
    #: Stable reference for audit and for the lease class's `principal_ref`.
    principal_ref: str
    target_ref: str
    credential_id: str


@dataclass(frozen=True, slots=True)
class AuthenticatedCall:
    principal: TargetPrincipal
    coordinates: c.RequestCoordinates
    store_now: datetime
    store_now_stamp: str
    #: The raw bytes the signature covered, for a handler that must hand them on
    #: unparsed (an observation envelope is verified over its exact bytes).
    body: bytes = b""


class TargetRequestAuthenticator:
    def __init__(
        self,
        *,
        directory: CredentialDirectory,
        nonces: NonceLedger,
        clock: StoreClock,
        limiter: RateLimiter,
        denied_public_keys: frozenset[str] = c.DENIED_PUBLIC_KEYS_B64U,
    ) -> None:
        self._directory = directory
        self._nonces = nonces
        self._clock = clock
        self._limiter = limiter
        self._denied_raw = frozenset(c.b64u_decode(k) for k in denied_public_keys)

    def authenticate(
        self,
        db: Session,
        *,
        method: str,
        raw_path: str,
        query_string: str,
        headers: Sequence[tuple[str, str]],
        body: bytes,
    ) -> AuthenticatedCall:
        store_now = self._clock(db)
        stamp = c.format_stamp(store_now)

        def refuse(code: str, status: int | None = None) -> TargetApiRefusal:
            return TargetApiRefusal(
                code,
                refusal_status(code) if status is None else status,
                store_now=stamp,
            )

        if any(str(name).lower() in AMBIENT_CREDENTIAL_HEADERS for name, _ in headers):
            raise refuse("ambient_credential", 401)
        try:
            credential_id = c.request_credential_id(headers)
        except c.TargetApiError as exc:
            raise refuse(exc.code) from None
        record = self._directory.lookup(db, credential_id, at=store_now)
        # One external answer for every reason a credential cannot speak: an
        # unauthenticated caller learns nothing about which one it was.
        if (
            record is None
            or record.credential_id != credential_id
            or not record.eligible
            or not record.purpose_ok
            or self._key_is_denied(record.public_key_b64u)
        ):
            raise refuse("credential_refused", 401)
        try:
            coordinates = c.check_request(
                method=method,
                raw_path=raw_path,
                query_string=query_string,
                headers=headers,
                body=body,
                store_now=stamp,
                credential_target_ref=record.target_ref,
                looked_up_credential_id=credential_id,
            )
        except c.TargetApiError as exc:
            raise refuse(exc.code) from None
        if not _signature_verifies(
            record.public_key_b64u,
            coordinates.signed_message,
            coordinates.signature_b64u,
        ):
            raise refuse("credential_refused", 401)
        if not self._limiter.allow(credential_id):
            # Unsigned, retryable: the contract maps an unsigned 429 to
            # `cp_unreachable`.
            raise TargetApiRefusal("rate_limited", 429, signed=False, store_now=stamp)
        if not self._nonces.spend(db, coordinates.nonce_ledger_key):
            raise refuse("nonce_replay", 401)
        return AuthenticatedCall(
            principal=TargetPrincipal(
                kind="target",
                principal_ref=f"target-credential:{credential_id}",
                target_ref=coordinates.target_ref,
                credential_id=credential_id,
            ),
            coordinates=coordinates,
            store_now=store_now,
            store_now_stamp=stamp,
            body=body,
        )

    def _key_is_denied(self, public_key_b64u: str) -> bool:
        """A published test key, or any key that is not canonical base64url."""
        try:
            raw = c.b64u_decode(public_key_b64u)
        except c.TargetApiError:
            return True
        return raw in self._denied_raw


def _signature_verifies(
    public_key_b64u: str, message: bytes, signature_b64u: str
) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(c.b64u_decode(public_key_b64u))
        key.verify(c.b64u_decode(signature_b64u), message)
    except (c.TargetApiError, ValueError, InvalidSignature):
        return False
    return True
