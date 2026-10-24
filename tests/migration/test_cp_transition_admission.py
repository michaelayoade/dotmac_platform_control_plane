"""Public native_upgrade admission against a real historical PostgreSQL source.

The gh result and recovery payload are explicit synthetic boundary fixtures.
They exercise the actual authorization, immutable store and V2 recovery owners,
not real attestation or restore acceptance. Actual pg_dump/fresh restore is
proved separately by test_cp_transition_host; no host acceptance is claimed.
No private migration capability is issued or guard validation replaced here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from sqlalchemy import create_engine, event, text

from vendor_cp import migrations
from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment.cp_transition_host import measure_catalogue
from vendor_cp.deployment.image_heads import composed_effective_heads
from vendor_cp.deployment.transition_fence import fence_writers


def _reviewed_tree(tmp_path):
    git_binary = Path(os.getenv("CP_TRANSITION_TEST_GIT_BINARY", "/usr/bin/git"))
    if not git_binary.is_file():
        message = "public native admission requires configured protected Git binary"
        if os.getenv("REQUIRE_POSTGRES_TESTS") == "1":
            pytest.fail(message)
        pytest.skip(message)
    root = tmp_path / "reviewed-code"
    root.mkdir()
    source = migrations.migration_root()
    shutil.copy2(source / "alembic.ini", root / "alembic.ini")
    shutil.copytree(
        source / "alembic",
        root / "alembic",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "0",
    }

    def git(*arguments):
        return subprocess.run(  # noqa: S603 - test-controlled absolute executable and argv
            [str(git_binary), "-C", str(root), *arguments],
            env=environment,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout

    git("init")
    git("add", "alembic.ini", "alembic")
    git(
        "-c",
        "user.name=Boundary Fixture",
        "-c",
        "user.email=boundary@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "-m",
        "Reviewed migration fixture",
    )
    revision = git("rev-parse", "HEAD").decode().strip()
    return root, git_binary, revision


def _descriptor(image, revision):
    return (
        'product = "dotmac_vendor_control_plane"\nenvironment = "production"\n'
        f'[image]\nreference = "registry.invalid/cp@{image}"\n'
        f'source_revision = "{revision}"\n'
    ).encode()


def _synthetic_authorization(request, root, monkeypatch, now):
    """Only the subprocess result is synthetic; owner verification remains real."""
    proof = canonical_json(
        {
            "schema": "dotmac.cp_transition_environment_protection/2",
            "repository_id": "100",
            "repository_owner_id": "200",
            "workflow_revision": "c" * 40,
            "environment": "production",
            "protected_main": True,
            "approval_model": "single-user-manual",
            "prevent_self_review": False,
            "can_admins_bypass": False,
            "required_reviewer_ids": [200],
            "expires_at": request["expires_at"],
        }
    )
    policy = cp.CpTransitionTrustPolicy(
        cp.CpTransitionIdentity(
            request["host"],
            request["database"],
            request["cluster_system_identifier"],
            request["database_oid"],
        ),
        root / "gh",
        cp.raw_digest(b"synthetic published gh"),
        root,
        "example/cp",
        "100",
        "200",
        ".github/workflows/authorize.yml",
        "c" * 40,
        "https://example.test/cp-transition/1",
        root / "protection.json",
        cp.raw_digest(proof),
    )
    request_path = root / "request.json"
    for path, raw in (
        (request_path, canonical_json(request)),
        (policy.gh_binary, b"synthetic published gh"),
        (policy.environment_protection_proof, proof),
    ):
        path.write_bytes(raw)
        path.chmod(0o700 if path == policy.gh_binary else 0o600)
    repository = "https://github.com/example/cp"
    signer = repository + "/.github/workflows/authorize.yml@refs/heads/main"
    certificate = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": {"type": "URI", "value": signer},
        "buildSignerURI": signer,
        "buildSignerDigest": "c" * 40,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": repository,
        "sourceRepositoryDigest": "c" * 40,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryIdentifier": "100",
        "sourceRepositoryOwnerIdentifier": "200",
        "buildConfigURI": signer,
        "buildConfigDigest": "c" * 40,
        "runInvocationURI": repository + "/actions/runs/123/attempts/2",
    }
    result = {
        "signature": {"certificate": certificate},
        "verifiedTimestamps": [
            {
                "type": "Tlog",
                "timestamp": now.isoformat(),
                "uri": "https://rekor.sigstore.dev",
            }
        ],
        "statement": {
            "predicateType": policy.predicate_type,
            "subject": [
                {
                    "name": request_path.name,
                    "digest": {"sha256": cp.raw_digest(canonical_json(request))[7:]},
                }
            ],
            "predicate": {
                "request_digest": cp.request_digest(request),
                "trusted_actor": request["trusted_actor"],
                "environment": "production",
            },
        },
    }
    with monkeypatch.context() as boundary:
        boundary.setattr(
            subprocess,
            "run",
            lambda *_a, **_k: SimpleNamespace(
                returncode=0,
                stdout=json.dumps([{"verificationResult": result}]).encode(),
            ),
        )
        return cp.GhAttestationVerifier(policy).verify(
            request, request_path=request_path, bundle_path=None, now=now
        )


def _retained_prefix(request, authorization, nonce, store, connection):
    """Real owner validation over explicitly synthetic recovery bytes."""
    source, target = request["source"], request["target"]

    def retain(raw):
        checksum = cp.raw_digest(raw)
        try:
            store.put(raw)
        except FileExistsError:
            assert store.read(checksum) == raw
        return checksum

    source_descriptor = _descriptor(source["image_digest"], source["revision"])
    target_descriptor = _descriptor(target["image_digest"], target["revision"])
    retain(source_descriptor)
    retain(target_descriptor)
    genesis = {
        "side": source,
        "descriptor_declarations": cp.source_descriptor_declarations(source_descriptor),
        "database_owner": "app_admin",
        "roles": sorted(
            connection.execute(text("SELECT rolname FROM pg_roles")).scalars()
        ),
        "catalogue_digest": retain(measure_catalogue(connection)),
    }
    # This helper supplies explicitly synthetic recovery/parser boundaries.
    catalogue_proof = retain(
        canonical_json(
            {
                "schema": "dotmac.cp_catalogue_restore_comparison/1",
                "request_digest": cp.request_digest(request),
                "host_nonce": nonce,
                "source_cluster_system_identifier": request[
                    "cluster_system_identifier"
                ],
                "source_database": request["database"],
                "source_catalogue_digest": genesis["catalogue_digest"],
                "restored_catalogue_digest": genesis["catalogue_digest"],
                "method": "postgres16-temp-view-parse/1",
                "parser": {
                    "server_version_num": 160004,
                    "cluster_system_identifier": str(
                        int(request["cluster_system_identifier"]) + 1
                    ),
                    "database": request["database"],
                    "search_path": "pg_catalog",
                    "standard_conforming_strings": "on",
                },
                "checks": [],
                "restored_catalogue_after_digest": genesis["catalogue_digest"],
            }
        )
    )
    dump, globals_bytes = (
        b"synthetic boundary dump",
        b"CREATE ROLE postgres;\nsynthetic boundary globals\n",
    )
    replay_raw = globals_bytes.replace(cp.GLOBALS_BOOTSTRAP_STATEMENT.encode(), b"", 1)
    replay_proof = retain(
        canonical_json(
            {
                "schema": "dotmac.cp_globals_replay/1",
                "request_digest": cp.request_digest(request),
                "host_nonce": nonce,
                "original_digest": cp.raw_digest(globals_bytes),
                "original_size": len(globals_bytes),
                "replay_digest": cp.raw_digest(replay_raw),
                "replay_size": len(replay_raw),
                "omitted_statement": cp.GLOBALS_BOOTSTRAP_STATEMENT,
                "source_bootstrap": {"role": "postgres", "oid": 10, "superuser": True},
                "fresh_bootstrap": {"role": "postgres", "oid": 10, "superuser": True},
            }
        )
    )
    manifest = canonical_json(
        {
            "schema": "PlatformCpRecoveryBundle.v2",
            "target": request["host"],
            "postgres_major": 16,
            "source_image": "registry.invalid/cp@" + source["image_digest"],
            "incumbent_roles": [
                {"role": "app", "image_digest": source["image_digest"]}
            ],
            "first_deployment": False,
            "product": request["product"],
            "environment": request["environment"],
            "database_name": request["database"],
            "cluster_system_identifier": request["cluster_system_identifier"],
            "source_revision": source["revision"],
            "source_descriptor_raw_sha256": source["raw_descriptor_digest"],
            "target_descriptor_raw_sha256": target["raw_descriptor_digest"],
            "taken_for_image_digest": target["image_digest"],
            "taken_for_source_revision": target["revision"],
            "migration_heads": source["heads"],
            "files": {
                "database.dump": cp.raw_digest(dump),
                "globals.sql": cp.raw_digest(globals_bytes),
            },
            "file_sizes": {
                "database.dump": len(dump),
                "globals.sql": len(globals_bytes),
            },
            "restore_order": ["globals.sql", "database.dump"],
        }
    )
    root = store.root / "backups" / "boundary"
    root.mkdir(parents=True)
    for name, raw in (
        ("database.dump", dump),
        ("globals.sql", globals_bytes),
        ("manifest.json", manifest),
    ):
        (root / name).write_bytes(raw)
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{cp.raw_digest(raw)[7:]}  {name}\n"
            for name, raw in (("database.dump", dump), ("globals.sql", globals_bytes))
        )
    )
    owner = cp.PlatformCpRecoveryBundle.for_transition(
        store.root,
        source_descriptor=source_descriptor,
        target_descriptor=target_descriptor,
        source_image="registry.invalid/cp@" + source["image_digest"],
        source_revision=source["revision"],
        target_image="registry.invalid/cp@" + target["image_digest"],
        target_source_revision=target["revision"],
        expected_source_heads=tuple(source["heads"]),
        target=request["host"],
        incumbent_roles=(("app", source["image_digest"]),),
        backup_dir=store.root / "backups",
    )
    backup = cp.PlatformBackupResult(
        "primary",
        str(root),
        sum(p.stat().st_size for p in root.iterdir()),
        cp.raw_digest(manifest)[7:],
        "sha256",
        len(manifest),
        cp.raw_digest(dump),
        len(dump),
        cp.raw_digest(globals_bytes),
        len(globals_bytes),
    )
    recovery = {cp.request_digest(request): (owner, backup)}
    results = {
        "inspection": {"source": source, "target": target},
        "authorization": {
            "verification_digest": retain(authorization.verification_bytes),
            "run_id": request["authorization_run_id"],
            "run_attempt": request["authorization_run_attempt"],
            "trusted_actor": request["trusted_actor"],
        },
        "maintenance": {
            "external_status": 503,
            "active_http": 0,
            "active_websockets": 0,
        },
        "strict-fence-reconnect": {
            "database": request["database"],
            "writer_sessions": 0,
            "reconnect_denial": "database_acl",
        },
        "writers-stopped": {"running_writers": [], "restart_enabled": []},
        "source-genesis": genesis,
        "recovery-restored": {
            "source": genesis,
            "restored_source": genesis,
            "restore_evidence_digest": retain(canonical_json(genesis)),
            "manifest_digest": retain(manifest),
            "manifest_size": len(manifest),
            "dump_digest": retain(dump),
            "globals_digest": retain(globals_bytes),
            "dump_size": len(dump),
            "globals_size": len(globals_bytes),
            "restored_dump_digest": cp.raw_digest(dump),
            "restored_globals_digest": cp.raw_digest(replay_raw),
            "globals_replay_digest": replay_proof,
            "catalogue_comparison_digest": catalogue_proof,
        },
        "fence-source-rechecked": {
            "source": source,
            "writer_sessions": 0,
            "reconnect_denial": "database_acl",
        },
    }
    evidence = {
        kind: retain(
            canonical_json(
                {
                    "schema": "dotmac.cp_transition_evidence/2",
                    "request_digest": cp.request_digest(request),
                    "host_nonce": nonce,
                    "kind": kind,
                    "result": result,
                }
            )
        )
        for kind, result in results.items()
    }
    cp.verify_transition_prefix(
        request,
        authorization=authorization,
        store=store,
        host_nonce=nonce,
        evidence=evidence,
        recovery=recovery,
    )
    return evidence, recovery


@pytest.fixture
def admission(scratch_db, postgres_url, url_for, tmp_path, monkeypatch, request):
    case = getattr(request.node, "callspec", SimpleNamespace(params={})).params.get(
        "case"
    )
    command.upgrade(
        migrations.make_alembic_config(scratch_db), "v016_licensing_authority"
    )
    # Test directory ancestry is writable on the dedicated runner; keep real
    # leaf ownership/mode/digest/symlink checks and all exclusive writes.
    monkeypatch.setattr(
        cp,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    protected = cp._protected

    def root_owned(info, *, directory):
        entries = list(info)
        entries[4] = 0
        protected(os.stat_result(entries), directory=directory)

    monkeypatch.setattr(cp, "_protected", root_owned)
    repository_root, git_binary, revision = _reviewed_tree(tmp_path)
    monkeypatch.delenv(migrations.MIGRATION_ROOT_ENV_VAR, raising=False)
    database = scratch_db.rpartition("/")[2]
    with ExitStack() as stack:
        engines = []

        def connect(url, *, autocommit=False):
            engine = create_engine(
                url, isolation_level="AUTOCOMMIT" if autocommit else None
            )
            engines.append(engine)
            return stack.enter_context(engine.connect())

        observer = connect(url_for(postgres_url, database), autocommit=True)
        observer.exec_driver_sql(f'ALTER DATABASE "{database}" OWNER TO app_admin')
        connection = connect(scratch_db)
        now = datetime.now(UTC).replace(microsecond=0)
        source = {
            "image_digest": "sha256:" + "a" * 64,
            "revision": "a" * 40,
            "heads": sorted(migrations._source_heads(connection)),
        }
        previous_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            target_heads = composed_effective_heads(
                migrations.deploy_config(None, root=repository_root)
            )
        finally:
            sys.dont_write_bytecode = previous_bytecode
        target = {
            "image_digest": "sha256:" + "b" * 64,
            "revision": revision,
            "heads": list(target_heads),
        }
        connection.rollback()
        for side in (source, target):
            side["raw_descriptor_digest"] = cp.raw_digest(
                _descriptor(side["image_digest"], side["revision"])
            )
        cluster, oid = observer.execute(
            text(
                "SELECT system_identifier::text, (SELECT oid FROM pg_database "
                "WHERE datname=current_database()) FROM pg_control_system()"
            )
        ).one()
        request = {
            "schema": "dotmac.cp_transition_request/1",
            "product": "dotmac_vendor_control_plane",
            "environment": "production",
            "host": "cp-boundary",
            "database": database,
            "cluster_system_identifier": "1" if case == "wrong-cluster" else cluster,
            "database_oid": oid,
            "source": source,
            "target": target,
            "plan_digest": "",
            "authorization_run_id": 123,
            "authorization_run_attempt": 2,
            "trusted_actor": "example",
            "expires_at": (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
            "previous_receipt_digest": None,
        }
        request["plan_digest"] = cp.transition_plan_digest(request)
        authorization = _synthetic_authorization(request, tmp_path, monkeypatch, now)
        store = cp.ArtifactStore(tmp_path)
        nonce = store.reserve(request, authorization)
        proof = fence_writers(
            observer, database=database, fence_id=nonce, session_wait_seconds=3
        )
        evidence, recovery = _retained_prefix(
            request, authorization, nonce, store, observer
        )
        kwargs = dict(
            repository_root=repository_root,
            git_binary=git_binary,
            git_binary_digest=cp._protected_executable_digest(git_binary),
            fence_connection=observer,
            request=request,
            authorization=authorization,
            store=store,
            host_nonce=nonce,
            reservation_digest=cp.request_digest(request),
            genesis_digest=evidence["source-genesis"],
            restore_digest=evidence["recovery-restored"],
            fence_digest=evidence["fence-source-rechecked"],
            recovery=recovery,
            fence_proof=proof,
            evidence=evidence,
        )
        try:
            yield SimpleNamespace(
                connection=connection,
                observer=observer,
                kwargs=kwargs,
                connect=connect,
                admin_url=url_for(postgres_url, database),
                app_url=scratch_db,
            )
        finally:
            stack.close()
            for engine in engines:
                engine.dispose()


def _snapshot(connection):
    return (
        tuple(sorted(migrations._source_heads(connection))),
        measure_catalogue(connection),
    )


def test_public_native_upgrade_historical_source_and_durable_replay(admission):
    connection, kwargs = admission.connection, admission.kwargs
    assert (
        kwargs["fence_connection"].get_execution_options().get("isolation_level")
        is None
    )
    assert kwargs["fence_connection"].connection.dbapi_connection.autocommit is True
    with connection.begin() as transaction:
        migrations.native_upgrade(connection, **kwargs)
        assert connection.get_transaction() is transaction
        assert tuple(sorted(migrations._source_heads(connection))) == tuple(
            kwargs["request"]["target"]["heads"]
        )
    # The retained request is permanently consumed. Even restoring the source
    # version rows cannot license another execution with the old reservation.
    with connection.begin():
        connection.execute(text("DELETE FROM public.alembic_version"))
        for head in kwargs["request"]["source"]["heads"]:
            connection.execute(
                text("INSERT INTO public.alembic_version VALUES (:head)"),
                {"head": head},
            )
    with connection.begin():
        before = _snapshot(connection)
        statements = []
        event.listen(
            connection,
            "before_cursor_execute",
            lambda _c, _cu, sql, *_: statements.append(sql),
        )
        with pytest.raises(FileExistsError):
            migrations.native_upgrade(connection, **kwargs)
        assert _snapshot(connection) == before
        assert not _mutations(statements)


def _mutations(statements):
    return [
        sql
        for sql in statements
        if sql.lstrip().split()[0].upper()
        in {"CREATE", "ALTER", "DROP", "INSERT", "UPDATE", "DELETE", "GRANT", "REVOKE"}
    ]


@pytest.mark.parametrize(
    "case",
    [
        "same-observer",
        "transactional-observer",
        "wrong-role",
        "autocommit",
        "public-regrant",
        "wrong-nonce",
        "wrong-fence-id",
        "source-drift",
        "missing-genesis",
        "wrong-restore",
        "wrong-authorization",
        "wrong-cluster",
        "ambient-migration-root",
        "modified-migration",
        "extra-migration",
        "symlink-migration",
        "bytecode-migration",
    ],
)
def test_public_native_upgrade_refuses_before_ddl(admission, case, monkeypatch):
    connection = admission.connection
    kwargs = dict(admission.kwargs)
    if case == "same-observer":
        kwargs["fence_connection"] = connection
    elif case == "transactional-observer":
        # A regular transaction cannot stand in for the required independent
        # autocommit observer, even when it sees the same cluster.
        kwargs["fence_connection"] = admission.connect(admission.admin_url)
        assert (
            kwargs["fence_connection"].get_execution_options().get("isolation_level")
            is None
        )
        assert (
            kwargs["fence_connection"].connection.dbapi_connection.autocommit is False
        )
    elif case == "wrong-role":
        connection = admission.connect(admission.admin_url)
    elif case == "autocommit":
        connection = admission.connect(admission.app_url, autocommit=True)
    elif case == "public-regrant":
        admission.observer.exec_driver_sql(
            f'GRANT CONNECT ON DATABASE "{kwargs["request"]["database"]}" TO PUBLIC'
        )
    elif case == "wrong-nonce":
        kwargs["host_nonce"] = "f" * 64
    elif case == "wrong-fence-id":
        from dataclasses import replace

        kwargs["fence_proof"] = replace(
            kwargs["fence_proof"], fence_id="different-fence"
        )
    elif case == "source-drift":
        admission.observer.execute(
            text(
                "UPDATE public.alembic_version SET version_num='unknown_drift' "
                "WHERE version_num=:head"
            ),
            {"head": kwargs["request"]["source"]["heads"][0]},
        )
    elif case == "missing-genesis":
        kwargs["evidence"] = dict(kwargs["evidence"])
        del kwargs["evidence"]["source-genesis"]
    elif case == "wrong-restore":
        kwargs["restore_digest"] = kwargs["genesis_digest"]
    elif case == "wrong-authorization":
        from dataclasses import replace

        kwargs["authorization"] = replace(kwargs["authorization"], _witness=None)
    elif case == "wrong-cluster":
        # The fixture authorized and retained a consistent request naming a
        # different cluster. Only the live observer can detect this mismatch.
        assert kwargs["request"]["cluster_system_identifier"] == "1"
    if case == "ambient-migration-root":
        monkeypatch.setenv(
            migrations.MIGRATION_ROOT_ENV_VAR, str(kwargs["repository_root"].parent)
        )
    elif case == "modified-migration":
        path = kwargs["repository_root"] / "alembic" / "env.py"
        path.write_bytes(path.read_bytes() + b"\n# same revision names, changed code\n")
    elif case == "extra-migration":
        (
            kwargs["repository_root"] / "alembic" / "versions" / "unreviewed.py"
        ).write_text("raise RuntimeError('must not execute')\n")
    elif case == "bytecode-migration":
        directory = kwargs["repository_root"] / "alembic" / "versions" / "__pycache__"
        directory.mkdir()
        (directory / "unreviewed.pyc").write_bytes(b"unreviewed bytecode")
    elif case == "symlink-migration":
        path = kwargs["repository_root"] / "alembic" / "env.py"
        original = kwargs["repository_root"] / "env-reviewed.py"
        path.rename(original)
        path.symlink_to(original.name)
    statements = []
    with connection.begin():
        before = _snapshot(connection)
        event.listen(
            connection,
            "before_cursor_execute",
            lambda _c, _cu, sql, *_: statements.append(sql),
        )
        with pytest.raises(
            (ContractError, OSError) if case == "symlink-migration" else ContractError
        ):
            migrations.native_upgrade(connection, **kwargs)
        assert _snapshot(connection) == before
        assert not _mutations(statements)
