"""Hosted actual PostgreSQL refusal before any role-secret acquisition.

Only the launch-loader boundary is synthetic in this vector. Actual read-only
qualification executes against a migrated scratch database and rolls back.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from alembic import command
from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import event, text

from vendor_cp.deployment.gate0_bootstrap import (
    ActualIssuerInstallation,
    CustodyInstallation,
    InstallationIdentity,
    PublicKeyPin,
    prepare_installed_issuer,
)
from vendor_cp.deployment.gate0_database import DatabaseExpectation
from vendor_cp.deployment.gate0_management_delivery import (
    CaptureSelection,
    ManagementDeliveryInstallation,
)
from vendor_cp.deployment.gate0_role_custody import (
    ProviderRefused,
    WireGuardBaoEndpoint,
)
from vendor_cp.migrations import make_alembic_config


def test_bootstrap_real_database_identity_refusal_precedes_secret(
    scratch_db, monkeypatch
):
    import vendor_cp.deployment.gate0_bootstrap as bootstrap
    from vendor_cp.deployment.gate0_launch import InstalledLaunchContext
    from vendor_cp.relay import runner

    command.upgrade(make_alembic_config(scratch_db), "heads")
    runtime = DatabaseRuntime.from_urls(
        database_url=scratch_db, platform_database_url=scratch_db
    )
    try:
        with runtime.platform_session() as session:
            database, address, port, tls = session.execute(
                text(
                    "SELECT current_database(), host(inet_server_addr()), "
                    "inet_server_port(), COALESCE((SELECT ssl "
                    "FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()), false)"
                )
            ).one()
            schemas = tuple(
                session.execute(
                    text(
                        "SELECT nspname FROM pg_catalog.pg_namespace "
                        "WHERE left(nspname,3)<>'pg_' "
                        "AND nspname<>'information_schema' ORDER BY nspname"
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
        monkeypatch.setattr(runner, "authority_database_runtime", lambda: runtime)
        # Explicit synthetic launch loader only. No fake DB qualifier or fake
        # approval owner: the actual privileged migrator must be refused.
        monkeypatch.setattr(bootstrap, "_installation", lambda *args: None)
        context = object.__new__(InstalledLaunchContext)
        monkeypatch.setattr(
            InstalledLaunchContext,
            "require_run_role_terms",
            lambda *args, **kwargs: None,
        )
        secrets = []
        monkeypatch.setattr(bootstrap, "_custody", lambda *args: secrets.append(True))
        statements = []
        event.listen(
            runtime.platform_engine,
            "before_cursor_execute",
            lambda conn, cursor, statement, params, context, many: statements.append(
                statement
            ),
        )
        now = datetime.now(UTC)
        end = now + timedelta(seconds=90)
        digest = "sha256:" + "1" * 64
        identity = InstallationIdentity(
            digest, "a" * 40, digest, digest, now - timedelta(seconds=1), end
        )
        endpoint = WireGuardBaoEndpoint(
            "issuer",
            "10.1.0.1",
            8200,
            "10.1.0.2",
            "wg0",
            1,
            1,
            1,
            digest,
            "10.1.0.1/32",
            digest,
            digest,
            digest,
        )
        custody = CustodyInstallation(
            "synthetic-role",
            PublicKeyPin("synthetic-issuer", bytes(range(32))),
            1,
            1,
            endpoint,
        )
        expected = DatabaseExpectation(
            database,
            "platform_api",
            address,
            port,
            tls,
            schemas,
            heads,
            heads,
            "a" * 40,
            "a" * 40,
            1000,
            500,
        )
        selections = tuple(
            CaptureSelection(digest, UUID(int=i), digest, UUID(int=3), UUID(int=i + 3))
            for i in (1, 2)
        )
        management = ManagementDeliveryInstallation(
            digest,
            identity.not_before,
            end,
            "10.1.0.2",
            "10.1.0.3",
            22,
            1002,
            "synthetic",
            "SHA256:" + "A" * 43,
            "ssh-ed25519",
            "SHA256:" + "B" * 43,
            digest,
            digest,
            digest,
            selections,
        )
        installation = ActualIssuerInstallation(
            identity,
            custody,
            expected,
            UUID(int=3),
            (UUID(int=1), UUID(int=2)),
            PublicKeyPin("synthetic-attester", bytes(range(32))),
            60,
            "synthetic-admin",
            management,
        )
        with (
            pytest.raises(ProviderRefused),
            prepare_installed_issuer(context, installation),
        ):
            raise AssertionError("privileged runtime yielded")
        assert any("current_database()" in statement for statement in statements)
        assert runtime.platform_engine.pool.checkedout() == 0
        assert secrets == []
    finally:
        runtime.platform_engine.dispose()
        runtime.engine.dispose()
