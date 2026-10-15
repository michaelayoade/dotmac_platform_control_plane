"""Measured read-only authority identity; native connection bounds remain launch-owned.

No JSON boolean can manufacture this result. Importing this module does not
import the configured kernel runtime, and qualification never creates one.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import text

from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.image_heads import (
    IMAGE_HEADS_SCHEMA,
    HeadsVerdict,
    compare_heads,
)

if TYPE_CHECKING:
    from dotmac_kernel.session_runtime import DatabaseRuntime

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
_HEAD = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SEAL = object()


@dataclass(frozen=True, slots=True)
class DatabaseExpectation:
    """Reviewed public installation coordinates, never credentials or a DSN.

    Schemas are the exact non-system namespace set. Endpoint measurement binds
    a server IP/port and TLS state; route isolation and TLS peer authentication
    must also be qualified by the protected launch owner.
    """

    database: str
    role: str
    server_address: str
    server_port: int
    tls: bool
    schemas: tuple[str, ...]
    image_heads: tuple[str, ...]
    descriptor_heads: tuple[str, ...]
    source_revision: str
    expected_source_revision: str
    statement_timeout_ms: int
    lock_timeout_ms: int

    def validate(self) -> None:
        try:
            if (
                type(self.database) is not str
                or _NAME.fullmatch(self.database) is None
                or type(self.role) is not str
                or _NAME.fullmatch(self.role) is None
                or type(self.server_address) is not str
                or str(ipaddress.ip_address(self.server_address)) != self.server_address
                or type(self.server_port) is not int
                or not 1 <= self.server_port <= 65535
                or type(self.tls) is not bool
                or type(self.statement_timeout_ms) is not int
                or not 1 <= self.statement_timeout_ms <= 2000
                or type(self.lock_timeout_ms) is not int
                or not 1 <= self.lock_timeout_ms <= self.statement_timeout_ms
                or type(self.source_revision) is not str
                or _SOURCE.fullmatch(self.source_revision) is None
                or type(self.expected_source_revision) is not str
                or _SOURCE.fullmatch(self.expected_source_revision) is None
            ):
                raise ProviderRefused()
            for values, pattern, maximum in (
                (self.schemas, _NAME, 64),
                (self.image_heads, _HEAD, 64),
                (self.descriptor_heads, _HEAD, 64),
            ):
                if (
                    type(values) is not tuple
                    or not 1 <= len(values) <= maximum
                    or any(
                        type(v) is not str or pattern.fullmatch(v) is None
                        for v in values
                    )
                    or len(set(values)) != len(values)
                ):
                    raise ProviderRefused()
            if (
                "public" not in self.schemas
                or any(
                    v.startswith("pg_") or v == "information_schema"
                    for v in self.schemas
                )
                or compare_heads(
                    image_document=self.image_document(),
                    descriptor_heads=self.descriptor_heads,
                    expected_source_revision=self.expected_source_revision,
                )
                is not HeadsVerdict.MATCHED
            ):
                raise ProviderRefused()
        except (TypeError, ValueError):
            raise ProviderRefused() from None

    def image_document(self) -> dict[str, object]:
        return {
            "schema": IMAGE_HEADS_SCHEMA,
            "source_revision": self.source_revision,
            "heads": list(self.image_heads),
        }


@dataclass(frozen=True, slots=True, init=False)
class DatabaseQualification:
    """In-process SQL measurement tied to the exact configured runtime.

    This does not qualify native connect/pool checkout bounds, the supervisor,
    network route or TLS peer provenance. Those are separate launch obligations.
    """

    runtime: DatabaseRuntime
    expectation: DatabaseExpectation

    def __init__(
        self,
        runtime: DatabaseRuntime,
        expectation: DatabaseExpectation,
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _SEAL:
            raise ProviderRefused()
        object.__setattr__(self, "runtime", runtime)
        object.__setattr__(self, "expectation", expectation)

    def require_runtime(self, runtime: DatabaseRuntime) -> None:
        if runtime is not self.runtime:
            raise ProviderRefused()


def qualify_authority_database(
    expectation: DatabaseExpectation,
) -> DatabaseQualification:
    """Measure fixed SQL coordinates, always rollback and close the session.

    Invoke only after launch has proved native connection/checkout bounds.
    SQL timeouts cannot interrupt an unbounded driver connect or pool checkout.
    """
    if type(expectation) is not DatabaseExpectation:
        raise ProviderRefused()
    expectation.validate()

    try:
        # The configured-runtime importer remains the existing relay owner.
        from vendor_cp.relay.runner import authority_database_runtime

        runtime = authority_database_runtime()
        session = runtime.platform_session_factory()
    except Exception:
        raise ProviderRefused() from None
    try:
        session.execute(
            text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        )
        session.execute(
            text(
                "SELECT set_config('statement_timeout', :statement, true), "
                "set_config('lock_timeout', :lock, true)"
            ),
            {
                "statement": str(expectation.statement_timeout_ms),
                "lock": str(expectation.lock_timeout_ms),
            },
        )
        identity = session.execute(
            text(
                "SELECT current_database(), current_user, inet_server_addr()::text, "
                "inet_server_port(), COALESCE((SELECT ssl FROM pg_catalog.pg_stat_ssl "
                "WHERE pid = pg_backend_pid()), false)"
            )
        ).one()
        if tuple(identity) != (
            expectation.database,
            expectation.role,
            expectation.server_address,
            expectation.server_port,
            expectation.tls,
        ):
            raise ProviderRefused()
        role = session.execute(
            text(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
                "rolbypassrls, rolcanlogin FROM pg_catalog.pg_roles "
                "WHERE rolname = current_user"
            )
        ).one()
        if tuple(role) != (False, False, False, False, False, True):
            raise ProviderRefused()
        schemas = tuple(
            session.execute(
                text(
                    "SELECT nspname FROM pg_catalog.pg_namespace "
                    "WHERE left(nspname, 3) <> 'pg_' "
                    "AND nspname <> 'information_schema' "
                    "ORDER BY nspname LIMIT 65"
                )
            ).scalars()
        )
        if len(schemas) > 64 or set(schemas) != set(expectation.schemas):
            raise ProviderRefused()
        heads = tuple(
            session.execute(
                text(
                    "SELECT version_num FROM public.alembic_version "
                    "ORDER BY version_num LIMIT 65"
                )
            ).scalars()
        )
        if (
            len(heads) > 64
            or compare_heads(
                image_document=expectation.image_document(),
                descriptor_heads=expectation.descriptor_heads,
                database_heads=heads,
                expected_source_revision=expectation.expected_source_revision,
            )
            is not HeadsVerdict.MATCHED
        ):
            raise ProviderRefused()
        return DatabaseQualification(runtime, expectation, _seal=_SEAL)
    except Exception:
        # No exception/connection detail crosses the service boundary.
        raise ProviderRefused() from None
    finally:
        try:
            try:
                session.rollback()
            finally:
                session.close()
        except Exception:
            raise ProviderRefused() from None
