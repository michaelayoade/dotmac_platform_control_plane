"""Explicit Postgres and exact-artifact preconditions for this excluded suite."""

# ruff: noqa: S101

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL, Connection, Engine, make_url

from rehearsal_issuer_harness.artifacts import verify_installed, verify_wheels

# `deploy/postgres/init-roles.sh` -- the real production role initializer,
# run once by `docker-compose.test.yml` before this suite ever executes --
# is the sole creator of these five roles and the sole authority for their
# attributes. This harness reads `pg_roles`; it never creates, alters, or
# grants a role itself.
_ROLE_CONTRACTS: dict[str, str] = {
    "app_admin": "false|false|true|true",
    "app_user": "false|false|false|true",
    "platform_api": "false|false|false|true",
    "outbox_dispatcher": "false|false|false|true",
    "platform_outbox_dispatcher": "false|false|false|true",
}


def _verify_role_contracts(conn: Connection) -> None:
    """Verify the disposable server already matches production's role contract.

    Mirrors the query shape `scripts/deploy_production.sh`'s own
    ``ROLE_CONTRACT`` check uses (``rolsuper|rolcreaterole|rolbypassrls|
    rolcanlogin``), generalized across all five production roles instead of
    just ``current_user``. A read of ``pg_roles`` only -- this function never
    creates, alters, or grants anything, and `app_admin` is asserted to be
    ``NOCREATEROLE`` here, matching `docs/ARCHITECTURE.md`'s production
    contract, not the elevated `CREATEROLE` the old harness wrongly demanded.
    """
    rows = conn.execute(
        text(
            "SELECT rolname, "
            "rolsuper::text || '|' || rolcreaterole::text || '|' || "
            "rolbypassrls::text || '|' || rolcanlogin::text "
            "FROM pg_roles WHERE rolname = ANY(:names)"
        ),
        {"names": list(_ROLE_CONTRACTS)},
    ).all()
    observed: dict[str, str] = {str(row[0]): str(row[1]) for row in rows}
    missing = set(_ROLE_CONTRACTS) - observed.keys()
    if missing:
        raise RuntimeError(f"rehearsal test server lacks roles: {sorted(missing)}")
    mismatched = {
        role: {"observed": observed[role], "expected": expected}
        for role, expected in _ROLE_CONTRACTS.items()
        if observed[role] != expected
    }
    if mismatched:
        raise RuntimeError(
            "rehearsal test server role contract differs from production "
            f"(rolsuper|rolcreaterole|rolbypassrls|rolcanlogin): {mismatched}"
        )


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--control-wheel", type=Path)
    parser.addoption("--kernel-wheel", type=Path)
    parser.addoption("--public-wheelhouse", type=Path)


def pytest_configure(config: pytest.Config) -> None:
    if not os.environ.get("REHEARSAL_ISSUER_DATABASE_URL"):
        raise pytest.UsageError(
            "REHEARSAL_ISSUER_DATABASE_URL is required; this real-Postgres "
            "rehearsal suite never skips an unconfigured database"
        )
    control_wheel = config.getoption("--control-wheel")
    kernel_wheel = config.getoption("--kernel-wheel")
    public_wheelhouse = config.getoption("--public-wheelhouse")
    if control_wheel is None or kernel_wheel is None or public_wheelhouse is None:
        raise pytest.UsageError(
            "exact --control-wheel, --kernel-wheel, and --public-wheelhouse "
            "are required"
        )
    try:
        verify_wheels(control_wheel, kernel_wheel)
        verify_installed(control_wheel, kernel_wheel, public_wheelhouse)
    except (ValueError, RuntimeError, OSError, metadata.PackageNotFoundError) as error:
        raise pytest.UsageError(f"artifact precondition failed: {error}") from error


@pytest.fixture(scope="session")
def security() -> Iterator[tuple[object, object]]:
    from dotmac_deployment_control import module
    from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions

    from rehearsal_issuer_harness.runtime import install_disposable_security

    install_audit_actions(AuditActionRegistry.from_manifests([module]))
    yield install_disposable_security()


@dataclass(frozen=True, slots=True)
class _ScratchDatabase:
    """The one thing this harness owns: a scratch database and its teardown.

    No role, grant, or ownership is created or altered here -- both URLs
    below connect to a database whose roles and grants come entirely from
    `deploy/postgres/init-roles.sh` and the Kernel/Control migrations run
    below.
    """

    admin_url: URL
    platform_url: URL


@pytest.fixture(scope="session")
def _scratch_database(security: tuple[object, object]) -> Iterator[_ScratchDatabase]:
    del security
    supplied = os.environ["REHEARSAL_ISSUER_DATABASE_URL"]
    parsed = make_url(supplied)
    if not parsed.drivername.startswith("postgresql"):
        raise RuntimeError("rehearsal issuer tests require PostgreSQL")
    scratch_name = "rehearsal_issuer_" + uuid.uuid4().hex[:16]
    # The supplied URL is the disposable `postgres` bootstrap identity --
    # the same one `init-roles.sh` itself runs as -- reached over local trust
    # auth (`docker-compose.test.yml`'s `POSTGRES_HOST_AUTH_METHOD: trust`).
    bootstrap = create_engine(supplied, isolation_level="AUTOCOMMIT")
    try:
        with bootstrap.connect() as conn:
            _verify_role_contracts(conn)
            # `OWNER app_admin` is the only privilege statement this harness
            # ever issues: PostgreSQL 15+'s `public` schema is owned by the
            # dynamic `pg_database_owner` pseudo-role, so `app_admin` gets
            # full rights on its own scratch database with no further GRANT
            # or ALTER SCHEMA needed.
            conn.execute(text(f'CREATE DATABASE "{scratch_name}" OWNER app_admin'))
    except Exception:
        bootstrap.dispose()
        raise
    # Close the bootstrap connection now. It is reopened, briefly, only for
    # the final DROP DATABASE below -- never held for the session's length.
    bootstrap.dispose()
    try:
        yield _ScratchDatabase(
            admin_url=parsed.set(
                database=scratch_name, username="app_admin", password=None
            ),
            platform_url=parsed.set(
                database=scratch_name, username="platform_api", password=None
            ),
        )
    finally:
        server = create_engine(supplied, isolation_level="AUTOCOMMIT")
        try:
            with server.connect() as conn:
                conn.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = :name AND pid <> pg_backend_pid()"
                    ),
                    {"name": scratch_name},
                )
                conn.execute(text(f'DROP DATABASE "{scratch_name}"'))
        finally:
            server.dispose()


@pytest.fixture(scope="session")
def admin_engine(_scratch_database: _ScratchDatabase) -> Iterator[Engine]:
    """The migrator/table-owner connection.

    Raw-SQL structural assertions (schema/table/trigger/column existence,
    the sensitivity-proof grant manipulations) run here. This engine must
    NEVER reach an issuer/standing/revocation/consumption/target/plan call
    in `test_issuer.py` -- those use the `engine` fixture below, which is
    `platform_api`, the real online runtime role.
    """
    from dotmac_deployment_control import versions_dir as control_versions_dir
    from dotmac_kernel.migrations import versions_dir as kernel_versions_dir

    precheck = create_engine(_scratch_database.admin_url)
    try:
        with precheck.connect() as conn:
            # THE proof this fix exists for: the migration lineage below
            # runs, and succeeds, with app_admin genuinely NOCREATEROLE.
            rolcreaterole = conn.execute(
                text("SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user")
            ).scalar_one()
            assert (
                rolcreaterole is False
            ), "app_admin must run this migration lineage without CREATEROLE"
    finally:
        precheck.dispose()

    os.environ["REHEARSAL_ISSUER_MIGRATION_DATABASE_URL"] = (
        _scratch_database.admin_url.render_as_string(hide_password=False)
    )
    try:
        root = Path(__file__).resolve().parent
        cfg = Config(str(root / "alembic.ini"))
        installed_versions = (kernel_versions_dir(), control_versions_dir())
        cfg.set_main_option(
            "version_locations", os.pathsep.join(map(str, installed_versions))
        )
        parsed_locations = cfg.get_version_locations_list()
        if (
            parsed_locations is None
            or tuple(map(Path, parsed_locations)) != installed_versions
        ):
            raise RuntimeError("Alembic did not parse both installed version locations")
        expected_heads = {
            "0028_machine_attribution",
            "dc_0015_plan_purpose",
        }
        discovered_heads = set(ScriptDirectory.from_config(cfg).get_heads())
        if discovered_heads != expected_heads:
            raise RuntimeError(
                f"installed migration graph heads {sorted(discovered_heads)} "
                f"differ from locked heads {sorted(expected_heads)}"
            )
        command.upgrade(cfg, "heads")
    finally:
        os.environ.pop("REHEARSAL_ISSUER_MIGRATION_DATABASE_URL", None)

    online = create_engine(_scratch_database.admin_url)
    try:
        with online.connect() as conn:
            heads = set(
                conn.execute(text("SELECT version_num FROM alembic_version")).scalars()
            )
            assert heads == expected_heads
            assert (
                conn.execute(
                    text(
                        "SELECT to_regclass("
                        "'mod_deploy.rehearsal_issuer_authorizations')"
                    )
                ).scalar_one()
                is not None
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_trigger WHERE tgname = "
                        "'rehearsal_issuer_authorizations_terminal_state_guard' "
                        "AND NOT tgisinternal"
                    )
                ).scalar_one()
                == 1
            )
            columns = {
                column["name"]
                for column in inspect(conn).get_columns(
                    "rehearsal_issuer_authorizations", schema="mod_deploy"
                )
            }
            assert columns == {
                "id",
                "authorization_id",
                "single_use_reference",
                "lease_id",
                "plan_id",
                "target_id",
                "controller_fingerprint",
                "harness_evidence_digest",
                "authorization_envelope",
                "not_before",
                "issued_at",
                "expires_at",
                "state",
                "revoked_at",
                "revocation_ref",
                "spent_at",
                "created_at",
                "updated_at",
            }
        yield online
    finally:
        online.dispose()


@pytest.fixture(scope="session")
def engine(
    _scratch_database: _ScratchDatabase, admin_engine: Engine
) -> Iterator[Engine]:
    """The ONLY engine `test_issuer.py`'s issuer/standing/revocation/
    consumption/target/plan calls (including its `_seed` helper) may use.

    Depending on `admin_engine` guarantees the schema is migrated and its
    structural assertions have already run before this ever yields --
    `platform_api` is the real online CP runtime role `dc_0014` grants the
    ledger to, and this proof is worthless if it silently ran as the table
    owner instead.
    """
    del admin_engine
    platform_engine = create_engine(_scratch_database.platform_url)
    try:
        yield platform_engine
    finally:
        platform_engine.dispose()
