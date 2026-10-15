"""Hosted PostgreSQL measurement vectors; synthetic scratch installation only."""

from __future__ import annotations

from dataclasses import replace

import pytest
from alembic import command
from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import event, text

from vendor_cp.deployment.gate0_database import (
    DatabaseExpectation,
    qualify_authority_database,
)
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.migrations import make_alembic_config


def test_real_postgres_read_only_identity_heads_and_mismatch_refusal(
    scratch_db,
    url_for,
    monkeypatch,
):
    from vendor_cp.relay import runner

    command.upgrade(make_alembic_config(scratch_db), "heads")
    owner = DatabaseRuntime.from_urls(
        database_url=scratch_db,
        platform_database_url=scratch_db,
    )
    runtime = None
    try:
        with owner.platform_session() as session:
            database, address, port, tls = session.execute(
                text(
                    "SELECT current_database(), inet_server_addr()::text, "
                    "inet_server_port(), "
                    "COALESCE((SELECT ssl FROM pg_catalog.pg_stat_ssl "
                    "WHERE pid = pg_backend_pid()), false)"
                )
            ).one()
            schemas = tuple(
                session.execute(
                    text(
                        "SELECT nspname FROM pg_catalog.pg_namespace "
                        "WHERE left(nspname, 3) <> 'pg_' "
                        "AND nspname <> 'information_schema' "
                        "ORDER BY nspname"
                    )
                ).scalars()
            )
            heads = tuple(
                session.execute(
                    text(
                        "SELECT version_num FROM public.alembic_version "
                        "ORDER BY version_num"
                    )
                ).scalars()
            )
            # Synthetic installation explicitly supplies only migration metadata
            # read access; the production grant remains installation-owned.
            session.execute(
                text("GRANT SELECT ON public.alembic_version TO platform_api")
            )
        online = url_for(scratch_db, database, user="platform_api")
        runtime = DatabaseRuntime.from_urls(
            database_url=online, platform_database_url=online
        )
        monkeypatch.setattr(runner, "authority_database_runtime", lambda: runtime)
        expected = DatabaseExpectation(
            database=database,
            role="platform_api",
            server_address=address,
            server_port=port,
            tls=tls,
            schemas=schemas,
            image_heads=heads,
            descriptor_heads=heads,
            source_revision="a" * 40,
            expected_source_revision="a" * 40,
            statement_timeout_ms=1000,
            lock_timeout_ms=500,
        )
        statements = []
        read_only = []

        def before_execute(connection, cursor, statement, parameters, context, many):
            statements.append(statement)
            if "current_database()" in statement:
                cursor.execute("SHOW transaction_read_only")
                read_only.append(cursor.fetchone()[0])

        event.listen(runtime.platform_engine, "before_cursor_execute", before_execute)
        qualified = qualify_authority_database(expected)
        assert qualified.runtime is runtime
        qualified.require_runtime(runtime)
        assert read_only == ["on"]
        assert (
            statements[0]
            == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        )
        assert all(s.startswith("SELECT") for s in statements[1:])
        assert runtime.platform_engine.pool.checkedout() == 0
        for changes in (
            {"database": "wrong"},
            {"role": "wrong"},
            {"server_port": 1 if port != 1 else 2},
            {"tls": not tls},
            {"schemas": ("public", "missing_schema")},
            {"image_heads": ("wrong",), "descriptor_heads": ("wrong",)},
        ):
            with pytest.raises(ProviderRefused):
                qualify_authority_database(replace(expected, **changes))
            assert runtime.platform_engine.pool.checkedout() == 0
        with pytest.raises(ProviderRefused):
            qualified.require_runtime(owner)
        # A privileged migrator is refused even when every other coordinate
        # matches; qualification is specifically the safe online authority role.
        monkeypatch.setattr(runner, "authority_database_runtime", lambda: owner)
        with pytest.raises(ProviderRefused):
            qualify_authority_database(replace(expected, role="app_admin"))
    finally:
        if runtime is not None:
            runtime.platform_engine.dispose()
            runtime.engine.dispose()
        owner.platform_engine.dispose()
        owner.engine.dispose()
