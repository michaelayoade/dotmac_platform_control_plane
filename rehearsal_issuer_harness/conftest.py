"""Explicit Postgres and exact-artifact preconditions for this excluded suite."""

# ruff: noqa: S101

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from importlib import metadata
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection, Engine, make_url

from rehearsal_issuer_harness.artifacts import verify_installed, verify_wheels


def _require_migration_roles(conn: Connection) -> None:
    """Check the disposable server can run the installed Kernel lineage."""
    rows = conn.execute(
        text(
            "SELECT rolname, rolcreaterole FROM pg_roles "
            "WHERE rolname IN ('app_admin', 'platform_api', 'app_user')"
        )
    ).all()
    roles: dict[str, bool] = {str(row[0]): bool(row[1]) for row in rows}
    missing = {"app_admin", "platform_api", "app_user"} - roles.keys()
    if missing:
        raise RuntimeError(f"rehearsal test server lacks roles: {sorted(missing)}")
    if not roles["app_admin"]:
        raise RuntimeError(
            "rehearsal test server app_admin requires CREATEROLE for "
            "the installed Kernel migration lineage"
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


@pytest.fixture(scope="session")
def engine(security: tuple[object, object]) -> Iterator[Engine]:
    from dotmac_deployment_control import versions_dir as control_versions_dir
    from dotmac_kernel.migrations import versions_dir as kernel_versions_dir

    del security
    supplied = os.environ["REHEARSAL_ISSUER_DATABASE_URL"]
    parsed = make_url(supplied)
    if not parsed.drivername.startswith("postgresql"):
        raise RuntimeError("rehearsal issuer tests require PostgreSQL")
    scratch_name = "rehearsal_issuer_" + uuid.uuid4().hex[:16]
    server = create_engine(supplied, isolation_level="AUTOCOMMIT")
    try:
        with server.connect() as conn:
            _require_migration_roles(conn)
            conn.execute(text(f'CREATE DATABASE "{scratch_name}"'))
    except Exception:
        server.dispose()
        raise
    scratch_url = parsed.set(database=scratch_name)
    setup = create_engine(scratch_url, isolation_level="AUTOCOMMIT")
    try:
        with setup.connect() as conn:
            conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
            conn.execute(
                text(f'GRANT CREATE ON DATABASE "{scratch_name}" TO app_admin')
            )
            for role in ("app_user", "platform_api"):
                conn.execute(
                    text(f'GRANT CONNECT ON DATABASE "{scratch_name}" TO {role}')
                )
                conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        admin_url = scratch_url.set(username="app_admin", password=None)
        os.environ["REHEARSAL_ISSUER_MIGRATION_DATABASE_URL"] = (
            admin_url.render_as_string(hide_password=False)
        )
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
            "dc_0014_rehearsal_issuer_ledger",
        }
        discovered_heads = set(ScriptDirectory.from_config(cfg).get_heads())
        if discovered_heads != expected_heads:
            raise RuntimeError(
                f"installed migration graph heads {sorted(discovered_heads)} "
                f"differ from locked heads {sorted(expected_heads)}"
            )
        command.upgrade(cfg, "heads")
        online = create_engine(admin_url)
        try:
            with online.connect() as conn:
                heads = set(
                    conn.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalars()
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
    finally:
        os.environ.pop("REHEARSAL_ISSUER_MIGRATION_DATABASE_URL", None)
        setup.dispose()
        with server.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": scratch_name},
            )
            conn.execute(text(f'DROP DATABASE "{scratch_name}"'))
        server.dispose()
