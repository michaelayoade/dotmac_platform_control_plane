"""Postgres-suite gate.

`pytest -rs` only PRINTS skips; it does not fail on them. Under required CI a
suite that can pass by skipping is not a gate at all — which is precisely how
these tests stayed silently unrun while the pipeline reported green.

Exposed as a FIXTURE rather than an importable helper: `tests.migration` is a
package, so cross-module imports here are import-path-fragile, and a gate that
breaks collection is no better than one that skips.

`REQUIRE_POSTGRES_TESTS=1` (set by the CI job) turns a missing
`TEST_DATABASE_URL` into a FAILURE. Locally the variable is unset, so the suite
still skips politely for anyone without a database.

`scratch_db` lives here for the same reason: it was defined inside the
rehearsals module, so a second Postgres suite could not use it without a
cross-module import into a package — the fragility this file's own docstring
warns about. It is one isolated database per test, migrated as the production
role, and both the rehearsals and the composed live-catalogue audit consume it.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Protocol

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.engine import make_url

from vendor_cp.deployment import transition_fence as fence_module


class UrlRewriter(Protocol):
    def __call__(
        self, base_url: str, dbname: str, *, user: str | None = None
    ) -> str: ...


@pytest.fixture(scope="session")
def postgres_url() -> str:
    """The single place that decides skip-vs-fail for the Postgres suites."""
    url = os.getenv("TEST_MIGRATION_DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if url:
        return url
    message = (
        "TEST_DATABASE_URL is not set — the Postgres migration and replay "
        "concurrency suites cannot run."
    )
    if os.getenv("REQUIRE_POSTGRES_TESTS") == "1":
        pytest.fail(
            f"{message} REQUIRE_POSTGRES_TESTS=1, so this is a FAILURE: under "
            "required CI these tests must never pass by skipping.",
            pytrace=False,
        )
    pytest.skip(message)


def _url_for(base_url: str, dbname: str, *, user: str | None = None) -> str:
    """Rewrite a DSN's database (and optionally its role) — the access canary
    must connect as the real online roles, not as the migrator."""
    scheme_userhost, _, _ = base_url.rpartition("/")
    if user is not None:
        scheme, _, userhost = scheme_userhost.partition("://")
        host = userhost.rpartition("@")[2]
        scheme_userhost = f"{scheme}://{user}@{host}"
    return f"{scheme_userhost}/{dbname}"


@pytest.fixture(scope="session")
def url_for() -> UrlRewriter:
    """`_url_for` as a FIXTURE, following this file's own rule: `tests` is not
    an importable package (there is no `tests/__init__.py`), so a suite that
    imported this helper by module path would break collection rather than
    skip."""
    return _url_for


@pytest.fixture
def scratch_db(postgres_url: str) -> Iterator[str]:
    """Create an isolated scratch DB and yield an APP_ADMIN url for it.

    Migrations run as `app_admin` (the production migrator, BYPASSRLS) so the
    table owner + grants match production. The cluster superuser only creates the
    DB and hands its public schema to app_admin (which exists globally once
    `make test-db-up` has run the kernel's initial migration)."""
    name = f"vcp_rehearsal_{uuid.uuid4().hex[:12]}"
    server = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    setup = create_engine(_url_for(postgres_url, name), isolation_level="AUTOCOMMIT")
    with setup.connect() as conn:
        conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
        # A stateful MODULE owns and creates its own schema. PostgreSQL checks
        # CREATE on the database for CREATE SCHEMA; owning `public` only covered
        # the pre-module kernel + assembly rehearsal.
        conn.execute(text(f'GRANT CREATE ON DATABASE "{name}" TO app_admin'))
        # The access canary must connect as the real online roles. Granting a
        # database connection does not grant schema/table access; the module
        # migration remains the authority for those privileges and denials.
        conn.execute(
            text(
                f'GRANT CONNECT ON DATABASE "{name}" TO platform_api, app_user, '
                "app_admin"
            )
        )
    setup.dispose()
    try:
        yield _url_for(postgres_url, name, user="app_admin")
    finally:
        with server.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :n AND pid <> pg_backend_pid()"
                ),
                {"n": name},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        server.dispose()


@contextmanager
def _connect(url: str) -> Iterator[Connection]:
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


@pytest.fixture
def target_only_connect(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
) -> Iterator[tuple[str, ...]]:
    """Temporarily close other DBs only on the disposable PG16 test service.

    The CI coordinate is the checked-in docker-compose.test.yml service.
    A different isolated loopback test container needs an explicit opt-in.
    Never run this fixture against a shared or remote database cluster.
    """
    parsed = make_url(postgres_url)
    ci_disposable = (
        parsed.host in {"localhost", "127.0.0.1"}
        and parsed.port == 5439
        and parsed.database == "vendor_cp_test"
        and parsed.username == "postgres"
    )
    explicit_disposable = (
        os.getenv("D16_DISPOSABLE_PG16") == "1"
        and parsed.host in {"localhost", "127.0.0.1"}
        and parsed.username == "postgres"
    )
    if not (ci_disposable or explicit_disposable):
        pytest.fail("candidate ACL fixture requires a disposable loopback PG16")
    target = scratch_db.rpartition("/")[2]
    with _connect(url_for(postgres_url, target)) as owner:
        databases = owner.execute(
            text(
                "SELECT datname, pg_get_userbyid(datdba) FROM pg_database "
                "WHERE datallowconn AND datname <> :target ORDER BY datname"
            ),
            {"target": target},
        ).all()
        snapshots: dict[str, frozenset[tuple[str, str, bool, str]]] = {}
        removed: dict[str, set[tuple[str, str, bool, str]]] = {}
        for name, database_owner in databases:
            grants = fence_module._current_grants(owner, str(name))
            selected = {
                grant
                for grant in grants
                if grant[1] == "CONNECT"
                and grant[0] in {"", "app_user", "platform_api"}
            }
            if any(
                grantor != database_owner or grantable
                for _, _, grantable, grantor in selected
            ):
                pytest.fail("disposable cluster has an unsupported other-DB ACL")
            snapshots[str(name)] = grants
            removed[str(name)] = selected
        try:
            for name in snapshots:
                quoted = owner.dialect.identifier_preparer.quote(name)
                owner.execute(
                    text(
                        f"REVOKE CONNECT ON DATABASE {quoted} "
                        "FROM PUBLIC, app_user, platform_api"
                    )
                )
                expected = snapshots[name] - removed[name]
                assert fence_module._current_grants(owner, name) == expected
            yield tuple(snapshots)
        finally:
            for name, selected in removed.items():
                quoted = owner.dialect.identifier_preparer.quote(name)
                for grantee, _priv, _grantable, _grantor in sorted(selected):
                    recipient = (
                        "PUBLIC"
                        if grantee == ""
                        else owner.dialect.identifier_preparer.quote(grantee)
                    )
                    owner.execute(
                        text(f"GRANT CONNECT ON DATABASE {quoted} TO {recipient}")
                    )
                assert fence_module._current_grants(owner, name) == snapshots[name]
