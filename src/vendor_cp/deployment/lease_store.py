"""The Lane 3 lease store over the CP production database (CP-2, U5, Q1-B).

Pre-E11 design section 3.3. A thin typed client of the `cp_lane3` functions
`v023_lane3_store` creates. It owns no policy: every decision (exclusivity, the
store clock, mutation history, the reprovision marker, the release rules) is a
`SECURITY DEFINER` function in the database, so a second implementation of the
launcher, or a hand-run `psql`, gets the same answers.

## A leaf module

Standard library and SQLAlchemy only, plus Foundation imported INSIDE the
functions that need its lease types (this assembly deliberately does not depend
on Foundation, and the store is only ever used where it is installed). It never
imports Starter. The launcher's own types are INJECTED:

    CpLeaseStore(connect, workload_principal=..., refused=StoreRefused,
                 held_lease=HeldLease, standing_enum=LeaseStanding)

so the launcher still catches its own `StoreRefused`, receives its own
`HeldLease`, and CP names none of them. The receipt and the reprovision marker
are read by attribute (duck-typed).

## One connection per handle; a lost connection fails closed (Q1-B)

A handle owns exactly one connection, opened lazily from `connect()`. Each store
call is one short transaction, so an `idle_in_transaction_session_timeout` on the
lease role cannot fire between calls.

* A connection that is gone BEFORE a write was sent is `store-unreachable`.
* A connection lost while the `COMMIT` was in flight is `store-commit-unknown`:
  the write may or may not have committed.
* A write is sent at most once and never retried. Once either has happened the
  handle is dead: every later call is `store-unreachable`, and the caller reads
  `standing` through a new handle (the ceremony's owner session) instead of
  repeating the call.

## The lease DSN

`lease_dsn` accepts only a TCP DSN that verifies the server certificate and
requires channel binding, and refuses every libpq `PG*` variable and a
`passfile`: the path runs over an SSH-forwarded loopback listener whose far end
is the CP host (design 3.6), and TLS is end to end to the PostgreSQL server.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.exc import DBAPIError

__all__ = [
    "LEASE_DSN_ENV",
    "LEASE_HOLDER",
    "MAX_TTL_SECONDS",
    "REFUSAL_CODES",
    "CpLeaseStore",
    "LeaseDsnRefused",
    "format_instant",
    "lease_dsn",
    "receipt_parameters",
]

#: The one environment name the lease DSN is supplied under. A value, never echoed.
LEASE_DSN_ENV: Final = "LANE3_LEASE_DATABASE_URL"
#: The fixed holder token Foundation's `HostLease` demands.
LEASE_HOLDER: Final = "deployment-foundation-rehearsal"
MAX_TTL_SECONDS: Final = 3600
_DEFAULT_PREFIX: Final = "lane3_"

#: SQLSTATE the schema raises every typed refusal with.
_REFUSAL_SQLSTATE: Final = "L3001"
STORE_UNREACHABLE: Final = "store-unreachable"
STORE_COMMIT_UNKNOWN: Final = "store-commit-unknown"
STORE_ERROR: Final = "store-error"

#: The CLOSED set of codes the schema raises, mapped one to one. Anything else
#: the database says becomes `store-error`; no database text is ever surfaced.
REFUSAL_CODES: Final = frozenset(
    {
        "lease-role-unbound",
        "lease-ttl-invalid",
        "lease-controller-identity-invalid",
        "lease-held-by-another-run",
        "lease-host-mutated",
        "lease-host-unknown",
        "lease-expired",
        "lease-foreign-run",
        "lease-already-released",
        "lease-max-reached",
        "lease-not-renewable",
        "reconcile-marker-required",
        "lease-document-already-bound",
        "lease-document-digest-mismatch",
        "lease-document-mismatch",
        "release-not-this-lease",
        "release-clock-skew",
        "host-mutated-required",
        "e10-receipt-required",
        "e10-receipt-for-another-host",
        "e10-receipt-unknown",
        "e10-receipt-mismatch",
        "e10-receipt-not-destroyed",
        "e10-receipt-not-current-root",
        "reprovision-receipt-required",
        "reprovision-receipt-for-another-host",
        "reprovision-receipt-mismatch",
        "reprovision-receipt-unknown",
        "reprovision-receipt-not-destroyed",
        "reprovision-receipt-not-current-root",
        "reprovision-receipt-same-incarnation",
        "reprovision-receipt-not-newer",
        "reprovision-receipt-spent",
    }
)

_RECEIPT_FIELDS: Final = (
    "vm_alias",
    "host_id",
    "machine_id",
    "ssh_host_key_fingerprint",
    "incarnation_public_key_b64url",
    "incarnation_fingerprint",
    "enrolment_uuid",
    "incarnation_key_destroyed_at",
    "receipt_ref",
    "vm_slot",
)
_UNIQUE_SPENT: Final = "host_leases_reprovision_receipt_ref_key"
_STANDING: Final = {
    "held": "HELD",
    "released": "RELEASED",
    "expired_mutated": "EXPIRED_MUTATED",
}
_PG_ENV_PREFIX: Final = "PG"
_FORBIDDEN_URL_OPTIONS: Final = ("options", "role", "service", "passfile")


class LeaseDsnRefused(ValueError):
    """The lease DSN is not acceptable. Names a thing, never a value."""


def lease_dsn(env: Mapping[str, str]) -> str:
    """The lease DSN from `env`, or a refusal. No connection is opened.

    TCP only (a unix socket carries no TLS), `sslmode=verify-full` with a pinned
    absolute `sslrootcert`, `channel_binding=require`, a bounded
    `connect_timeout`, no `options`/`role`/`service`/`passfile`, and no libpq
    `PG*` environment variable that could redirect or re-credential it.
    """
    libpq = sorted(name for name in env if name.startswith(_PG_ENV_PREFIX))
    if libpq:
        raise LeaseDsnRefused(
            "libpq PG* environment variables are present: " + ", ".join(libpq)
        )
    raw = env.get(LEASE_DSN_ENV, "").strip()
    if not raw:
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} is not supplied")
    try:
        url = make_url(raw)
    except Exception:
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} is not a database URL") from None
    if not url.drivername.startswith("postgresql"):
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} is not a PostgreSQL URL")
    if not url.username or not url.database or not url.host:
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} lacks a role, host or database")
    if url.host.startswith("/"):
        raise LeaseDsnRefused(
            f"{LEASE_DSN_ENV} must be TCP (no unix socket carries TLS)"
        )
    query = dict(url.query)
    if any(key in query for key in _FORBIDDEN_URL_OPTIONS):
        raise LeaseDsnRefused(
            f"{LEASE_DSN_ENV} carries an option that can change the role or load "
            "further credentials"
        )
    if query.get("sslmode") != "verify-full":
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} must use sslmode=verify-full")
    root = query.get("sslrootcert")
    if not isinstance(root, str) or not root.startswith("/"):
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} must pin an absolute sslrootcert")
    if query.get("channel_binding") != "require":
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} must require channel_binding")
    timeout = query.get("connect_timeout")
    if (
        not isinstance(timeout, str)
        or not timeout.isdigit()
        or not 1 <= int(timeout) <= 5
    ):
        raise LeaseDsnRefused(
            f"{LEASE_DSN_ENV} needs connect_timeout of 1 to 5 seconds"
        )
    return raw


def format_instant(value: datetime) -> str:
    """A fixed spelling (UTC, always microseconds) so a receipt compares by equality."""
    if value.tzinfo is None:
        raise ValueError("an instant must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"


def receipt_parameters(receipt: Any) -> dict[str, Any]:
    """The ten fields of an E10 receipt reference, in the store's fixed spelling.

    Read by attribute, so it takes Starter's `E10ReceiptRef` without importing it.
    Raises `AttributeError`/`ValueError` for anything that is not one.
    """
    values: dict[str, Any] = {name: getattr(receipt, name) for name in _RECEIPT_FIELDS}
    destroyed = values["incarnation_key_destroyed_at"]
    if not isinstance(destroyed, datetime):
        raise ValueError("the destruction time must be a datetime")
    values["incarnation_key_destroyed_at"] = format_instant(destroyed)
    for name, value in values.items():
        if name == "vm_slot" and value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(f"{name} must be text")
    return values


class CpLeaseStore:
    """One handle: one connection to the CP database, as the per-run lease role."""

    #: The only value the launcher accepts (`require_database_time`).
    time_authority = "database"

    def __init__(
        self,
        connect: Callable[[], Connection],
        *,
        workload_principal: str,
        refused: type[Exception],
        held_lease: Callable[..., Any],
        standing_enum: type[Enum],
        compose_project_prefix: str = _DEFAULT_PREFIX,
    ) -> None:
        if not workload_principal or not workload_principal.strip():
            raise ValueError("a workload principal is required")
        self._connect = connect
        self._principal = workload_principal
        self._refused = refused
        self._held_lease = held_lease
        self._standing_enum = standing_enum
        self._prefix = compose_project_prefix
        self._conn: Connection | None = None
        self._dead = False
        #: Writes whose first statement reached the server (an answer, accepted
        #: or refused, came back). A write that never left is not counted.
        self.writes_reached = 0

    # ── plumbing ────────────────────────────────────────────────────────────

    def _refuse(self, code: str) -> Exception:
        return self._refused(code)

    def _connection(self) -> Connection:
        if self._dead:
            raise self._refuse(STORE_UNREACHABLE)
        if self._conn is None:
            try:
                self._conn = self._connect()
            except Exception:
                self._dead = True
                raise self._refuse(STORE_UNREACHABLE) from None
        return self._conn

    def _kill(self) -> None:
        self._dead = True
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110 - the connection is already gone
                pass

    @staticmethod
    def _state(exc: BaseException) -> str | None:
        orig = getattr(exc, "orig", exc)
        state = getattr(orig, "sqlstate", None)
        if state is None:
            state = getattr(getattr(orig, "diag", None), "sqlstate", None)
        return state if isinstance(state, str) else None

    def _lost(self, exc: DBAPIError) -> bool:
        state = self._state(exc)
        if getattr(exc, "connection_invalidated", False):
            return True
        if state is None:
            return True
        return state.startswith("08") or state in {"57P01", "57P02", "57P03"}

    def _map(self, exc: DBAPIError) -> Exception:
        """A database error as a refusal. Never retried; never any database text."""
        state = self._state(exc)
        if state == _REFUSAL_SQLSTATE:
            orig = getattr(exc, "orig", exc)
            message = getattr(getattr(orig, "diag", None), "message_primary", None)
            if message in REFUSAL_CODES:
                return self._refuse(str(message))
            return self._refuse(STORE_ERROR)
        if state == "23505" and _UNIQUE_SPENT in str(exc):
            return self._refuse("reprovision-receipt-spent")
        if self._lost(exc):
            self._kill()
            return self._refuse(STORE_UNREACHABLE)
        return self._refuse(STORE_ERROR)

    def _read(self, statement: str, params: Mapping[str, Any]) -> Any:
        """One read in its own transaction: ends it, so nothing idles open."""
        conn = self._connection()
        try:
            row = conn.execute(text(statement), dict(params)).one()
            conn.rollback()
            return row[0]
        except DBAPIError as exc:
            mapped = self._map(exc)
            self._rollback_quietly()
            raise mapped from None

    def _rollback_quietly(self) -> None:
        if self._conn is not None and not self._dead:
            try:
                self._conn.rollback()
            except Exception:  # noqa: BLE001
                self._kill()

    def _commit(self) -> None:
        conn = self._connection()
        try:
            conn.commit()
        except DBAPIError as exc:
            if self._lost(exc):
                # The COMMIT was sent; the answer was lost. Unknown, not retried.
                self._kill()
                raise self._refuse(STORE_COMMIT_UNKNOWN) from None
            self._rollback_quietly()
            raise self._refuse(STORE_ERROR) from None

    # ── the contract ────────────────────────────────────────────────────────

    def database_time(self) -> datetime:
        value = self._read("SELECT cp_lane3.database_time()", {})
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise self._refuse(STORE_ERROR)
        return value

    def acquire_exclusive(
        self,
        *,
        host_id: str,
        authorization_run: str,
        controller_identity: Any,
        ttl_seconds: int,
        e10_receipt: Any,
        reprovision: Any = None,
    ) -> Any:
        from dotmac_deployment_foundation.canonical_plan import canonical_plan_bytes
        from dotmac_deployment_foundation.controller_identity import (
            ControllerSshFingerprintV1,
        )
        from dotmac_deployment_foundation.errors import SpecError
        from dotmac_deployment_foundation.lease import HOST_LEASE_SCHEMA, HostLease
        from dotmac_deployment_foundation.lease_release import lease_digest

        try:
            receipt = receipt_parameters(e10_receipt)
        except (AttributeError, ValueError, TypeError):
            raise self._refuse("e10-receipt-required") from None
        if receipt["host_id"] != host_id:
            raise self._refuse("e10-receipt-for-another-host")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise self._refuse("lease-ttl-invalid")
        if not isinstance(controller_identity, ControllerSshFingerprintV1):
            raise self._refuse("lease-controller-identity-invalid")
        marker_host: str | None = None
        marker_receipt: str | None = None
        if reprovision is not None:
            try:
                marker_host = getattr(reprovision, "host_id", None)
                cited = receipt_parameters(getattr(reprovision, "e10_receipt", None))
            except (AttributeError, ValueError, TypeError):
                raise self._refuse("reprovision-receipt-required") from None
            if not isinstance(marker_host, str) or cited["host_id"] != marker_host:
                raise self._refuse("reprovision-receipt-for-another-host")
            marker_receipt = json.dumps(cited, sort_keys=True)

        conn = self._connection()
        try:
            row = conn.execute(
                text(
                    "SELECT o_lease_id, o_acquired_at, o_expires_at FROM "
                    "cp_lane3.acquire(:host, :run, :controller, :principal, :ttl, "
                    "CAST(:receipt AS jsonb), :marker_host, "
                    "CAST(:marker_receipt AS jsonb))"
                ),
                {
                    "host": host_id,
                    "run": authorization_run,
                    "controller": str(controller_identity),
                    "principal": self._principal,
                    "ttl": ttl_seconds,
                    "receipt": json.dumps(receipt, sort_keys=True),
                    "marker_host": marker_host,
                    "marker_receipt": marker_receipt,
                },
            ).one()
        except DBAPIError as exc:
            mapped = self._map(exc)
            self._count_if_answered(exc)
            self._rollback_quietly()
            raise mapped from None
        self.writes_reached += 1
        lease_id, acquired, expires = str(row[0]), row[1], row[2]
        try:
            lease = HostLease(
                target=host_id,
                holder=LEASE_HOLDER,
                authorization_run_id=authorization_run,
                starts_at=acquired.isoformat(),
                expires_at=expires.isoformat(),
                compose_project_prefix=self._prefix,
                controller_identity_fingerprint=controller_identity,
                workload_principal=self._principal,
            )
            document = canonical_plan_bytes(
                lease.as_document(), schema=HOST_LEASE_SCHEMA, path="host_lease"
            )
            digest = lease_digest(lease)
        except SpecError:
            self._rollback_quietly()
            raise self._refuse("lease-document-mismatch") from None
        if digest != "sha256:" + hashlib.sha256(document).hexdigest():
            self._rollback_quietly()
            raise self._refuse("lease-document-digest-mismatch")
        try:
            conn.execute(
                text(
                    "SELECT cp_lane3.bind_document(CAST(:id AS uuid), :bytes, :digest)"
                ),
                {"id": lease_id, "bytes": document, "digest": digest},
            )
        except DBAPIError as exc:
            mapped = self._map(exc)
            self._rollback_quietly()
            raise mapped from None
        self._commit()
        return self._held_lease(
            lease=lease,
            handle=lease_id,
            e10_receipt=e10_receipt,
            acquired_at=acquired,
            expires_at=expires,
        )

    def _count_if_answered(self, exc: DBAPIError) -> None:
        """A refusal or error the SERVER sent means the write reached it."""
        if self._state(exc) is not None and not self._lost(exc):
            self.writes_reached += 1

    def covers(self, held: Any, *, authorization_run: str) -> datetime:
        value = self._read(
            "SELECT cp_lane3.covers(CAST(:id AS uuid), :run)",
            {"id": held.handle, "run": authorization_run},
        )
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise self._refuse(STORE_ERROR)
        return value

    def release(self, held: Any, *, release: Any, host_mutated: bool) -> str:
        from dotmac_deployment_foundation.canonical_plan import canonical_plan_bytes
        from dotmac_deployment_foundation.lease_release import LEASE_RELEASE_SCHEMA

        if type(host_mutated) is not bool:
            raise self._refuse("host-mutated-required")
        try:
            document = canonical_plan_bytes(
                release.as_document(), schema=LEASE_RELEASE_SCHEMA, path="lease_release"
            )
            digest = release.digest()
            released_by = release.released_by.subject
            controller = str(release.controller_identity_fingerprint)
            stamped = datetime.fromisoformat(
                str(release.released_at).replace("Z", "+00:00")
            )
            lease_digest_value = release.lease_digest
        except Exception:  # noqa: BLE001 - any malformed record is not this lease's
            raise self._refuse("release-not-this-lease") from None
        if stamped.tzinfo is None:
            stamped = stamped.replace(tzinfo=UTC)
        conn = self._connection()
        result: Any
        try:
            result = conn.execute(
                text(
                    "SELECT cp_lane3.release(CAST(:id AS uuid), :bytes, :digest, "
                    ":lease_digest, :released_by, :controller, :stamped, :mutated)"
                ),
                {
                    "id": held.handle,
                    "bytes": document,
                    "digest": digest,
                    "lease_digest": lease_digest_value,
                    "released_by": released_by,
                    "controller": controller,
                    "stamped": stamped,
                    "mutated": host_mutated,
                },
            ).scalar_one()
        except DBAPIError as exc:
            mapped = self._map(exc)
            self._count_if_answered(exc)
            self._rollback_quietly()
            raise mapped from None
        self.writes_reached += 1
        self._commit()
        return str(result)

    def standing(self, host_id: str) -> Any:
        value = self._read("SELECT cp_lane3.standing(:host)", {"host": host_id})
        if value not in _STANDING:
            raise self._refuse(STORE_ERROR)
        return self._standing_enum[_STANDING[value]]

    def released_at(self, host_id: str) -> datetime | None:
        value = self._read("SELECT cp_lane3.released_at(:host)", {"host": host_id})
        if value is None:
            return None
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise self._refuse(STORE_ERROR)
        return value

    def e10_receipt(
        self, *, host_id: str, authorization_run: str, receipt_ref: str
    ) -> dict[str, Any]:
        """The receipt as the STORE verifies it (the launcher reads its
        `E10ReceiptRef` from here, never from a workflow input)."""
        value = self._read(
            "SELECT cp_lane3.e10_receipt(:host, :run, :ref)",
            {"host": host_id, "run": authorization_run, "ref": receipt_ref},
        )
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, dict) or set(value) != set(_RECEIPT_FIELDS):
            raise self._refuse(STORE_ERROR)
        return value

    def close(self) -> None:
        self._kill()
