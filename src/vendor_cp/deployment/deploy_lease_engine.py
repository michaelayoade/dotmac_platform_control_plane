"""The lease store's OWN database runtime, for the dedicated lease role (ruling 6).

The app, relay and ops containers all connect as `platform_api`. Under W-i the
lease functions trust the caller's asserted principal and marker, so `platform_api`
holds nothing in `cp_deploy_lease`: only the LOGIN role `platform_target_lease`
(created by the governed role op, never by the migration) may execute them, and only
this store connects with it. The DSN is a setting NAMED here and delivered by CP
secret delivery; its value is never read from a file in the repository, never logged
and never echoed.

The Kernel owns the engine (D1): this builds a Kernel `DatabaseRuntime` over the
lease DSN, exactly as the read-only preflights do, and never constructs a
connection itself.

Each lease call runs in its OWN transaction on this engine (commit on success, roll
back on a refusal or a fault). It is therefore not in the request's transaction:
the lease functions are idempotent under retry for exactly that reason (a replayed
acquire returns the remaining ttl, a repeated identical release is a replay).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from typing import Any, Final

from sqlalchemy.engine import make_url

from vendor_cp.deployment.deploy_lease import DeployLeaseStore

__all__ = [
    "LEASE_DSN_ENV",
    "LEASE_ROLE",
    "LeaseDsnRefused",
    "lease_runtime",
    "lease_store_scope",
]

#: The setting's name. Its value is a database URL for `LEASE_ROLE`.
LEASE_DSN_ENV: Final = "VENDOR_TARGET_LEASE_DATABASE_URL"
LEASE_ROLE: Final = "platform_target_lease"
_PG_ENV_PREFIX: Final = "PG"


class LeaseDsnRefused(ValueError):
    """The lease DSN is not acceptable. Names a thing, never a value."""


def lease_runtime(env: Mapping[str, str] | None = None) -> Any:
    """The lease store's Kernel runtime, or a refusal. Opens no connection."""
    values = os.environ if env is None else env
    libpq = sorted(name for name in values if name.startswith(_PG_ENV_PREFIX))
    if libpq:
        raise LeaseDsnRefused("libpq PG* environment variables are present")
    raw = values.get(LEASE_DSN_ENV, "").strip()
    if not raw:
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} is not supplied")
    try:
        url = make_url(raw)
    except Exception:
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} is not a database URL") from None
    if not url.drivername.startswith("postgresql"):
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} is not a PostgreSQL URL")
    if url.username != LEASE_ROLE:
        # An application DSN (`platform_api`) must never be accepted here.
        raise LeaseDsnRefused(f"{LEASE_DSN_ENV} must name the {LEASE_ROLE} role")
    if any(key in url.query for key in ("options", "role", "service", "passfile")):
        raise LeaseDsnRefused(
            f"{LEASE_DSN_ENV} carries an option that changes the role"
        )
    from dotmac_kernel.session_runtime import DatabaseRuntime

    return DatabaseRuntime.from_urls(database_url=raw, platform_database_url=raw)


def lease_store_scope(
    runtime: Any,
) -> Callable[[Any], AbstractContextManager[DeployLeaseStore]]:
    """`scope(request_db)` -> a store on a fresh session of the lease runtime.

    The request's own session is ignored on purpose (it belongs to `platform_api`).
    """

    @contextmanager
    def scope(_request_db: Any) -> Iterator[DeployLeaseStore]:
        session = runtime.platform_session_factory()
        try:
            yield DeployLeaseStore(session)
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    return scope
