"""Real PG16 bundle/global restore into a fresh isolated cluster.

Image labels alone are synthetic. This exercises installed migrations, not a
historical migration path or a full host transition. TEST_RESTORE_DATABASE_URL
must name a disposable PG16 control DB with a unique bootstrap superuser (not
postgres); the source roles must be absent. Native PG16 tools must reach both
clusters and the shared bundle paths. The external driver owns cluster disposal.
"""

from __future__ import annotations

import os
import shlex
import shutil
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from vendor_cp.deployment.effects import (
    REQUIRED_ROLES,
    PlatformCpRecoveryBundle,
    ProcessResult,
    SubprocessExecutor,
)

_IMAGE = "registry.invalid/cp@sha256:"
_REVISION = "c" * 40
_HEADS = "SELECT version_num FROM alembic_version ORDER BY version_num"
_CLUSTER = text("SELECT system_identifier FROM pg_control_system()")
_ROLES = text(
    "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, "
    "rolreplication, rolbypassrls, rolconnlimit, rolvaliduntil FROM pg_roles "
    "WHERE rolname = ANY(:roles) ORDER BY rolname"
).bindparams(roles=list(REQUIRED_ROLES))
_OWNERS = (
    "SELECT 'schema', nspname, pg_get_userbyid(nspowner) FROM pg_namespace "
    "WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' UNION ALL "
    "SELECT schemaname, tablename, tableowner FROM pg_tables "
    "WHERE schemaname !~ '^pg_' AND schemaname <> 'information_schema' ORDER BY 1, 2"
)


def _descriptor(image: str) -> bytes:
    return (
        'product="dotmac_vendor_control_plane"\nenvironment="production"\n'
        f'[image]\nreference="{image}"\nsource_revision="{_REVISION}"\n'
    ).encode()


class _PostgresProcess(SubprocessExecutor):
    """Translate compose transport to native tools; execute the producer's SQL."""

    def __init__(self, source: str, server: str) -> None:
        self.tools: dict[str, str] = {}
        for tool in ("pg_dumpall", "pg_dump", "pg_restore", "psql"):
            executable = shutil.which(tool)
            if executable is None:
                raise RuntimeError(f"dedicated test tool missing: {tool}")
            self.tools[tool] = executable
        self.source = source.replace("postgresql+psycopg://", "postgresql://", 1)
        self.server = server.replace("postgresql+psycopg://", "postgresql://", 1)

    def capture_stdout(
        self,
        argv: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
    ) -> ProcessResult:
        globals_only = "pg_dumpall" in argv
        flags = ("--globals-only", "--no-role-passwords")
        if not globals_only:
            flags = ("--format", "custom")
        return super().capture_stdout(
            (
                self.tools["pg_dumpall" if globals_only else "pg_dump"],
                "--dbname",
                self.server if globals_only else self.source,
                *flags,
            ),
            destination,
            timeout_seconds=timeout_seconds,
            env=env,
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
        stdin_path: Path | None = None,
    ) -> ProcessResult:
        if "inspect" in argv:
            return ProcessResult(0, _REVISION)
        if "pg_restore" in argv:
            native = (self.tools["pg_restore"], "--list")
        else:
            query = argv[-1] if "psql" in argv else shlex.split(argv[-1])[-1]
            if "printf" in argv[-1]:
                query = "SELECT current_database()"
            native = (
                self.tools["psql"],
                "--dbname",
                self.server if "pg_control_system" in query else self.source,
                "-tAc",
                query,
            )
        return super().run(
            native, timeout_seconds=timeout_seconds, env=env, stdin_path=stdin_path
        )


def test_native_bundle_restores_real_dump_with_original_ownership(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    tmp_path: Path,
) -> None:
    restore_url = os.getenv("TEST_RESTORE_DATABASE_URL")
    if not restore_url:
        message = "TEST_RESTORE_DATABASE_URL must name a fresh isolated PG16 cluster"
        if os.getenv("REQUIRE_POSTGRES_TESTS") == "1":
            pytest.fail(message, pytrace=False)
        pytest.skip(message)
    for tool in ("dotmac-platform", "pg_dump", "pg_dumpall", "pg_restore", "psql"):
        assert shutil.which(tool), f"{tool} required on dedicated test server"
    dbname = scratch_db.rpartition("/")[2]
    source = create_engine(scratch_db)
    server = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    control = create_engine(restore_url, isolation_level="AUTOCOMMIT")
    restored = create_engine(url_for(restore_url, dbname))
    runner = SubprocessExecutor()
    env = dict(os.environ)
    env.update(
        {
            "DATABASE_URL": url_for(postgres_url, dbname, user="app_user"),
            "PLATFORM_DATABASE_URL": url_for(postgres_url, dbname, user="platform_api"),
            "MIGRATION_DATABASE_URL": scratch_db,
        }
    )
    restore_attempted = False
    try:
        with server.connect() as connection:
            connection.execute(text(f'ALTER DATABASE "{dbname}" OWNER TO app_admin'))
            cluster_id = connection.execute(_CLUSTER).scalar_one()
        with control.connect() as connection:
            version = connection.exec_driver_sql("SHOW server_version_num").scalar_one()
            assert int(version) // 10000 == 16
            assert connection.execute(_CLUSTER).scalar_one() != cluster_id
            assert connection.execute(_ROLES).all() == []
            assert not connection.execute(
                text("SELECT 1 FROM pg_database WHERE datname=:name"), {"name": dbname}
            ).all()
        assert runner.run(
            ("dotmac-platform", "admin", "migrate"), timeout_seconds=120, env=env
        ).ok
        with source.connect() as connection:
            heads = tuple(connection.execute(text(_HEADS)).scalars())
            roles = connection.execute(_ROLES).all()
            owners = connection.execute(text(_OWNERS)).all()
        assert {row[0] for row in roles} == set(REQUIRED_ROLES)
        assert {row[2] for row in owners} == {"app_admin"}
        host = tmp_path / "host"
        host.write_text("cp-native-test")
        owner = PlatformCpRecoveryBundle.for_transition(
            tmp_path,
            source_descriptor=_descriptor(_IMAGE + "a" * 64),
            target_descriptor=_descriptor(_IMAGE + "b" * 64),
            source_image=_IMAGE + "a" * 64,
            source_revision=_REVISION,
            target_image=_IMAGE + "b" * 64,
            target_source_revision=_REVISION,
            expected_source_heads=heads,
            target="cp-native-test",
            incumbent_roles=(("app", "sha256:" + "a" * 64),),
            host_id_file=host,
            backup_dir=tmp_path / "backups",
            process=_PostgresProcess(scratch_db, postgres_url),
        )
        result = owner.capture_transition(timeout_seconds=120)
        assert owner.verify(result)
        bundle = Path(result.path)
        restore_command = (
            "pg_restore",
            "--create",
            "--exit-on-error",
            "--dbname",
            restore_url.replace("postgresql+psycopg://", "postgresql://", 1),
            str(bundle / "database.dump"),
        )
        restore_attempted = True
        missing_roles = runner.run(restore_command, timeout_seconds=120, env=env)
        assert not missing_roles.ok
        assert 'role "app_admin" does not exist' in missing_roles.stderr
        with control.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)'))
        assert runner.run(
            (
                "psql",
                "-v",
                "ON_ERROR_STOP=1",
                "--dbname",
                restore_command[4],
                "--file",
                str(bundle / "globals.sql"),
            ),
            timeout_seconds=120,
            env=env,
        ).ok
        assert runner.run(restore_command, timeout_seconds=120, env=env).ok
        with control.connect() as connection:
            assert connection.execute(_ROLES).all() == roles
            assert (
                connection.execute(
                    text(
                        "SELECT pg_get_userbyid(datdba) FROM pg_database "
                        "WHERE datname=:name"
                    ),
                    {"name": dbname},
                ).scalar_one()
                == "app_admin"
            )
        with restored.connect() as connection:
            assert tuple(connection.execute(text(_HEADS)).scalars()) == heads
            assert connection.execute(text(_OWNERS)).all() == owners
    finally:
        restored.dispose()
        source.dispose()
        if restore_attempted:
            with control.connect() as connection:
                connection.execute(
                    text(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
                )
        control.dispose()
        server.dispose()
