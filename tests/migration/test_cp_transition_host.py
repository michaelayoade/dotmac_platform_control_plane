"""Real PostgreSQL measurements used by the concrete host.

The optional fresh-cluster lane additionally needs the installed Linux/root
operator prerequisites. It runs only on the named dedicated Docker test host;
it must never be pointed at a local Docker daemon.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import cast

import pytest
from sqlalchemy import create_engine, text

from vendor_cp.deploy_agent.contracts import ContractError, read_json
from vendor_cp.deployment import cp_transition
from vendor_cp.deployment.cp_transition import (
    ArtifactStore,
    CpTransitionRequestV1,
    raw_digest,
)
from vendor_cp.deployment.cp_transition_host import (
    CpTransitionHostConfig,
    ExistingCpTransitionHost,
    measure_candidate_quiescence,
    measure_catalogue,
    verify_restore_comparison,
)
from vendor_cp.deployment.effects import SubprocessExecutor
from vendor_cp.deployment.transition_fence import fence_writers


def test_catalogue_measures_real_table_constraint_index_policy_and_role(
    postgres_url, scratch_db, url_for
):
    database = scratch_db.rpartition("/")[2]
    engine = create_engine(url_for(postgres_url, database))
    schema = f"cp_host_{uuid.uuid4().hex[:10]}"
    try:
        with engine.connect() as connection:
            before = measure_catalogue(connection)
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(
                f'CREATE TABLE "{schema}".proof '
                "(id integer PRIMARY KEY, value text NOT NULL)"
            )
            connection.exec_driver_sql(
                f'ALTER TABLE "{schema}".proof ENABLE ROW LEVEL SECURITY'
            )
            connection.exec_driver_sql(
                f'CREATE POLICY proof_policy ON "{schema}".proof USING (id > 0)'
            )
            measured = read_json(measure_catalogue(connection))
            assert any(
                row[0] == schema and row[1] == "proof" for row in measured["relations"]
            )
            assert any(
                row[0] == schema and row[1] == "proof"
                for row in measured["constraints"]
            )
            assert any(
                row[0] == schema and row[1] == "proof" for row in measured["indexes"]
            )
            assert any(
                row[0] == schema and row[2] == "proof_policy"
                for row in measured["policies"]
            )
            assert {row[0] for row in measured["roles"]} >= {
                "app_admin",
                "app_user",
                "platform_api",
            }
            connection.rollback()
            assert measure_catalogue(connection) == before
    finally:
        engine.dispose()


def test_live_connection_identity_refuses_wrong_cluster_or_database_oid(
    postgres_url, scratch_db, url_for
):
    database = scratch_db.rpartition("/")[2]
    engine = create_engine(url_for(postgres_url, database))
    try:
        with engine.connect() as connection:
            oid, cluster = connection.execute(
                text(
                    "SELECT oid,(SELECT system_identifier::text "
                    "FROM pg_control_system()) "
                    "FROM pg_database WHERE datname=current_database()"
                )
            ).one()
            request = cast(
                CpTransitionRequestV1,
                {
                    "database": database,
                    "database_oid": oid,
                    "cluster_system_identifier": cluster,
                },
            )
            ExistingCpTransitionHost._identity(connection, request)
            request["cluster_system_identifier"] = "1"
            with pytest.raises(ContractError, match="database_identity_mismatch"):
                ExistingCpTransitionHost._identity(connection, request)
            request["cluster_system_identifier"] = cluster
            request["database_oid"] = oid + 1
            with pytest.raises(ContractError, match="database_identity_mismatch"):
                ExistingCpTransitionHost._identity(connection, request)
    finally:
        engine.dispose()


def test_real_negative_reconnect_denial_is_measured_not_an_empty_session_claim(
    postgres_url, scratch_db, url_for, tmp_path, monkeypatch
):
    from contextlib import contextmanager

    database = scratch_db.rpartition("/")[2]
    role = f"cp_host_writer_{uuid.uuid4().hex[:10]}"
    engine = create_engine(
        url_for(postgres_url, database), isolation_level="AUTOCOMMIT"
    )
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE ROLE "{role}" LOGIN')
            connection.exec_driver_sql(
                f'ALTER DATABASE "{database}" OWNER TO app_admin'
            )
            proof = fence_writers(
                connection,
                database=database,
                fence_id="host-test",
                writer_roles=(role,),
                session_wait_seconds=3,
            )
        host = ExistingCpTransitionHost(
            _config(tmp_path), store=ArtifactStore(tmp_path), recovery={}
        )
        host.proof = proof

        @contextmanager
        def connect(database, role="postgres", **kwargs):
            writer = create_engine(url_for(postgres_url, database, user=role))
            try:
                with writer.connect() as connection:
                    yield connection
            finally:
                writer.dispose()

        monkeypatch.setattr(host, "_connect", connect)
        host._negative_reconnect(cast(CpTransitionRequestV1, {"database": database}))
        with engine.connect() as connection:
            connection.exec_driver_sql(
                f'GRANT CONNECT ON DATABASE "{database}" TO "{role}"'
            )
        with pytest.raises(ContractError, match="writer_reconnected"):
            host._negative_reconnect(
                cast(CpTransitionRequestV1, {"database": database})
            )
    finally:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'DROP OWNED BY "{role}"')
            connection.exec_driver_sql(f'DROP ROLE IF EXISTS "{role}"')
        engine.dispose()


def _config(tmp_path: Path, *, postgres_image: str = "") -> CpTransitionHostConfig:
    return CpTransitionHostConfig(
        repository_root=tmp_path,
        deploy_directory=tmp_path,
        target_descriptor=tmp_path / "target.toml",
        source_image=(
            "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "1" * 64
        ),
        target_image=(
            "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "2" * 64
        ),
        postgres_image=postgres_image,
        maintenance_helper=tmp_path / "maintenance",
        maintenance_helper_digest=f"sha256:{'3' * 64}",
        external_ready_url="https://platform.dotmac.io/health/ready",
        candidate_port=18100,
        backup_directory=tmp_path,
        # These public installed-tool digests are independently measured in the
        # root operator test runtime; real execution still verifies protected FD.
        docker_binary_digest=(
            cp_transition._protected_executable_digest(Path("/usr/bin/docker"))
            if postgres_image
            else "sha256:" + "5" * 64
        ),
        git_binary=Path("/usr/bin/git"),
        git_binary_digest=(
            cp_transition._protected_executable_digest(Path("/usr/bin/git"))
            if postgres_image
            else "sha256:" + "6" * 64
        ),
    )


def test_actual_fresh_globals_dump_restore_matches_independent_source(
    postgres_url, scratch_db, url_for, tmp_path, monkeypatch
):
    """Exercise the host's real scratch implementation; never an app acceptance."""
    container = os.getenv("CP_TRANSITION_TEST_POSTGRES_CONTAINER")
    image = os.getenv("CP_TRANSITION_TEST_POSTGRES_IMAGE")
    if not container or not image:
        message = (
            "fresh restore requires named dedicated-host PostgreSQL container/image"
        )
        if os.getenv("REQUIRE_CP_TRANSITION_HOST_TESTS") == "1":
            pytest.fail(message)
        pytest.skip(message)
    assert os.geteuid() == 0
    database = scratch_db.rpartition("/")[2]
    process = SubprocessExecutor()
    source_descriptor = (
        Path(__file__).parents[1]
        / "fixtures"
        / "cp-transition"
        / "source-3ef3cef4.toml"
    ).read_bytes()
    assert raw_digest(source_descriptor) == (
        "sha256:42d1b0b6bbb8b1b0cc9990cd5630a4be66ea778aaa206ef69a22c3cc72f1c5aa"
    )
    engine = create_engine(
        url_for(postgres_url, database), isolation_level="AUTOCOMMIT"
    )
    # Only ArtifactStore's test directory traversal is adapted. All PostgreSQL
    # commands, restore, measurements and kernel runtime connections are real.
    monkeypatch.setattr(
        cp_transition,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(
                f'ALTER DATABASE "{database}" OWNER TO app_admin'
            )
            connection.exec_driver_sql(
                "CREATE TABLE public.alembic_version "
                "(version_num varchar(64) PRIMARY KEY)"
            )
            connection.exec_driver_sql(
                "INSERT INTO public.alembic_version VALUES ('host_source')"
            )
            connection.exec_driver_sql(
                "ALTER TABLE public.alembic_version OWNER TO app_admin"
            )
            connection.exec_driver_sql(
                "CREATE TABLE public.restore_probe"
                "(id integer PRIMARY KEY, value text NOT NULL)"
            )
            connection.exec_driver_sql(
                "ALTER TABLE public.restore_probe OWNER TO app_admin"
            )
            connection.exec_driver_sql(
                "INSERT INTO public.restore_probe VALUES (1,'retained')"
            )
            cluster = connection.execute(
                text("SELECT system_identifier::text FROM pg_control_system()")
            )
            cluster_id = cluster.scalar_one()
            major = (
                int(connection.execute(text("SHOW server_version_num")).scalar_one())
                // 10000
            )
            request = cast(
                CpTransitionRequestV1,
                {
                    "database": database,
                    "cluster_system_identifier": cluster_id,
                    "source": {
                        "image_digest": f"sha256:{'1' * 64}",
                        "revision": "3ef3cef4eed6703cb60e2f1787ed7af41e9f502f",
                        "raw_descriptor_digest": raw_digest(source_descriptor),
                        "heads": ["host_source"],
                    },
                },
            )
            host = ExistingCpTransitionHost(
                _config(tmp_path, postgres_image=image),
                store=ArtifactStore(tmp_path),
                recovery={},
            )
            host._retain(source_descriptor)
            source = host._observe(connection, request["source"])
            host.genesis = source
            assert (
                source["descriptor_declarations"]["source_revision"]
                != request["source"]["revision"]
            )
        env = {"PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix:///var/run/docker.sock"}
        for component, command in (
            (
                "globals.sql",
                (
                    "pg_dumpall",
                    "--username",
                    "postgres",
                    "--globals-only",
                    "--no-role-passwords",
                ),
            ),
            (
                "database.dump",
                (
                    "pg_dump",
                    "--username",
                    "postgres",
                    "--format=custom",
                    "--dbname",
                    database,
                ),
            ),
        ):
            result = process.capture_stdout(
                ("/usr/bin/docker", "exec", "--user", "postgres", container, *command),
                tmp_path / component,
                timeout_seconds=60,
                env=env,
            )
            assert result.ok
        nonce = uuid.uuid4().hex * 2
        restored = host._restore_fresh(request, nonce, tmp_path, major)
        assert {
            key: value for key, value in restored.items() if key != "catalogue_digest"
        } == {key: value for key, value in source.items() if key != "catalogue_digest"}
        assert host._catalogue_comparison_digest is not None
        comparison_raw = host.store.read(host._catalogue_comparison_digest)
        verify_restore_comparison(
            comparison_raw,
            source_catalogue=host.store.read(source["catalogue_digest"]),
            restored_catalogue=host.store.read(restored["catalogue_digest"]),
            request_digest=cp_transition.request_digest(request),
            host_nonce=nonce,
            expected_source_cluster=cluster_id,
            expected_source_database=database,
        )
        comparison = read_json(comparison_raw)
        assert comparison["source_catalogue_digest"] == source["catalogue_digest"]
        assert comparison["restored_catalogue_digest"] == restored["catalogue_digest"]
        assert host._globals_replay_digest is not None
        proof = read_json(host.store.read(host._globals_replay_digest))
        assert proof["original_digest"] == raw_digest(
            (tmp_path / "globals.sql").read_bytes()
        )
        assert proof["replay_digest"] == host._globals_replay_sha
        assert (
            proof["source_bootstrap"]
            == proof["fresh_bootstrap"]
            == {"role": "postgres", "oid": 10, "superuser": True}
        )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "mutation",
    [
        "unchanged",
        "insert-commit",
        "insert-rollback",
        "update-commit",
        "delete-rollback",
        "sequence",
        "ddl",
        "replace-relation",
        "truncate",
    ],
)
def test_real_candidate_quiescence_observes_mutations_after_backend_exit(
    postgres_url, scratch_db, url_for, mutation
):
    database = scratch_db.rpartition("/")[2]
    url = url_for(postgres_url, database)
    schema = f"cp_quiescence_{uuid.uuid4().hex[:10]}"
    setup = create_engine(url)
    try:
        with setup.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(
                f'CREATE TABLE "{schema}".proof (id integer PRIMARY KEY,value text)'
            )
            connection.exec_driver_sql(
                f"INSERT INTO \"{schema}\".proof VALUES (1,'baseline')"  # noqa: S608
            )
            connection.exec_driver_sql(f'CREATE SEQUENCE "{schema}".counter')
    finally:
        # A real backend exit flushes setup's pending tuple counters before the
        # independent observer captures its baseline.
        setup.dispose()
    observer = create_engine(url, isolation_level="AUTOCOMMIT")
    writer = create_engine(url)
    try:
        with observer.connect() as connection:
            before = measure_candidate_quiescence(connection)
            with writer.connect() as candidate:
                transaction = candidate.begin()
                backend = candidate.execute(
                    text(
                        "SELECT pg_backend_pid(),backend_start::text "
                        "FROM pg_stat_activity "
                        "WHERE pid=pg_backend_pid()"
                    )
                ).one()
                if mutation.startswith("insert"):
                    candidate.exec_driver_sql(
                        f"INSERT INTO \"{schema}\".proof VALUES (2,'candidate')"  # noqa: S608
                    )
                elif mutation.startswith("update"):
                    candidate.exec_driver_sql(
                        f"UPDATE \"{schema}\".proof SET value='candidate' WHERE id=1"  # noqa: S608
                    )
                elif mutation.startswith("delete"):
                    candidate.exec_driver_sql(
                        f'DELETE FROM "{schema}".proof WHERE id=1'  # noqa: S608
                    )
                elif mutation == "sequence":
                    candidate.execute(text(f"SELECT nextval('{schema}.counter')"))
                elif mutation == "ddl":
                    candidate.exec_driver_sql(
                        f'ALTER TABLE "{schema}".proof ADD COLUMN drift integer'
                    )
                elif mutation == "replace-relation":
                    candidate.exec_driver_sql(f'DROP TABLE "{schema}".proof')
                    candidate.exec_driver_sql(
                        f'CREATE TABLE "{schema}".proof '
                        "(id integer PRIMARY KEY,value text)"
                    )
                elif mutation == "truncate":
                    candidate.exec_driver_sql(f'TRUNCATE "{schema}".proof')
                if mutation.endswith("rollback"):
                    transaction.rollback()
                else:
                    transaction.commit()
            writer.dispose()
            deadline = time.monotonic() + 3
            while connection.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE pid=:pid AND backend_start::text=:started"
                ),
                {"pid": backend[0], "started": backend[1]},
            ).scalar_one():
                assert time.monotonic() < deadline, "candidate backend did not exit"
                time.sleep(0.01)
            after = measure_candidate_quiescence(connection)
            if mutation == "unchanged":
                assert after == before
            else:
                assert after != before, f"mutation {mutation} was not observed"
            if mutation.endswith("rollback"):
                assert connection.execute(
                    text(f'SELECT id,value FROM "{schema}".proof ORDER BY id')  # noqa: S608
                ).all() == [(1, "baseline")]
    finally:
        writer.dispose()
        observer.dispose()


def test_real_candidate_quiescence_refuses_disabled_statistics(
    postgres_url, scratch_db, url_for
):
    database = scratch_db.rpartition("/")[2]
    engine = create_engine(
        url_for(postgres_url, database), isolation_level="AUTOCOMMIT"
    )
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SET track_counts=off")
            with pytest.raises(ContractError, match="quiescence_statistics_disabled"):
                measure_candidate_quiescence(connection)
    finally:
        engine.dispose()


def test_real_catalogue_preserves_custom_membership_grantor_drift(
    postgres_url, scratch_db, url_for
):
    """Custom grantors remain part of the exact restore comparison."""
    database = scratch_db.rpartition("/")[2]
    engine = create_engine(
        url_for(postgres_url, database), isolation_level="AUTOCOMMIT"
    )
    suffix = uuid.uuid4().hex[:10]
    parent, member, grantor = (
        f"cp_parent_{suffix}",
        f"cp_member_{suffix}",
        f"cp_grantor_{suffix}",
    )
    try:
        with engine.connect() as connection:
            for name in (parent, member, grantor):
                connection.exec_driver_sql(f'CREATE ROLE "{name}" NOLOGIN')
            connection.exec_driver_sql(
                f'GRANT "{parent}" TO "{grantor}" '
                "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
            )
            connection.exec_driver_sql(
                f'GRANT "{parent}" TO "{member}" '
                "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE"
            )
            before = measure_catalogue(connection)
            connection.exec_driver_sql(
                f'REVOKE "{parent}" FROM "{member}" GRANTED BY postgres'
            )
            connection.exec_driver_sql(
                f'GRANT "{parent}" TO "{member}" '
                "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE "
                f'GRANTED BY "{grantor}"'
            )
            after = measure_catalogue(connection)
            assert before != after
            assert raw_digest(before) != raw_digest(after)
            original = [
                row
                for row in read_json(before)["memberships"]
                if row[0] == parent and row[1] == member
            ]
            changed = [
                row
                for row in read_json(after)["memberships"]
                if row[0] == parent and row[1] == member
            ]
            assert original == [[parent, member, "postgres", False, True, True]]
            assert changed == [[parent, member, grantor, False, True, True]]
    finally:
        with engine.connect() as connection:
            for name in (member, grantor, parent):
                connection.exec_driver_sql(f'DROP ROLE IF EXISTS "{name}"')
        engine.dispose()


@pytest.mark.parametrize("change", ["missing", "renamed", "oid", "superuser"])
def test_real_pg_rejects_unsupported_retained_source_bootstrap(
    postgres_url, scratch_db, url_for, tmp_path, monkeypatch, change
):
    database = scratch_db.rpartition("/")[2]
    engine = create_engine(
        url_for(postgres_url, database), isolation_level="AUTOCOMMIT"
    )
    monkeypatch.setattr(
        cp_transition,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    # Hosted CI creates fixtures as its unprivileged runner. Simulate only
    # root ownership; retain real modes, file types, link counts and all I/O.
    protected = cp_transition._protected

    def root_owned(info, *, directory):
        values = list(info)
        values[4] = 0
        protected(os.stat_result(values), directory=directory)

    monkeypatch.setattr(cp_transition, "_protected", root_owned)
    host = ExistingCpTransitionHost(
        _config(tmp_path), store=ArtifactStore(tmp_path), recovery={}
    )
    try:
        with engine.connect() as connection:
            original = measure_catalogue(connection)
            catalogue = read_json(original)
            assert catalogue["bootstrap"] == [["postgres", 10, True]]
            if change == "missing":
                catalogue.pop("bootstrap")
            elif change == "renamed":
                catalogue["bootstrap"][0][0] = "renamed"
            elif change == "oid":
                catalogue["bootstrap"][0][1] = 11
            else:
                catalogue["bootstrap"][0][2] = False
            checksum = host._retain(cp_transition.canonical_json(catalogue))
            host.genesis = cast(
                cp_transition.SourceObservation, {"catalogue_digest": checksum}
            )
            with pytest.raises(ContractError, match="source_bootstrap_unsupported"):
                host._source_bootstrap()
            assert measure_catalogue(connection) == original
    finally:
        engine.dispose()


def test_held_fence_new_host_preserves_original_acl_through_failure_and_restore(
    postgres_url, scratch_db, url_for, tmp_path, monkeypatch
):
    """Dedicated-host PostgreSQL proof; never touches shared writer-role ACLs."""
    from contextlib import contextmanager
    from copy import deepcopy

    from vendor_cp.deployment import cp_transition_host as host_module
    from vendor_cp.deployment import transition_fence as fence

    database = scratch_db.rpartition("/")[2]
    role = f"cp_held_writer_{uuid.uuid4().hex[:10]}"
    admin = create_engine(url_for(postgres_url, database), isolation_level="AUTOCOMMIT")
    grants_query = text(
        "SELECT COALESCE(g.rolname,''), a.privilege_type, a.is_grantable, "
        "grantor.rolname FROM pg_database d, "
        "aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a "
        "LEFT JOIN pg_roles g ON g.oid=a.grantee "
        "JOIN pg_roles grantor ON grantor.oid=a.grantor "
        "WHERE d.datname=current_database()"
    )

    @contextmanager
    def connect(database, role="postgres", **kwargs):
        engine = create_engine(
            url_for(postgres_url, database, user=role), isolation_level="AUTOCOMMIT"
        )
        try:
            with engine.connect() as connection:
                yield connection
        finally:
            engine.dispose()

    public_fencer = fence.fence_writers

    def bounded_fencer(connection, **kwargs):
        return public_fencer(connection, writer_roles=(role,), **kwargs)

    # Use a disposable role through the public owner argument. Production
    # continues to use the public owner's normal complete writer-role set.
    monkeypatch.setattr(fence, "fence_writers", bounded_fencer)
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(f'CREATE ROLE "{role}" LOGIN')
            connection.exec_driver_sql(
                f'ALTER DATABASE "{database}" OWNER TO app_admin'
            )
            # Non-default direct CONNECT with grant option is the baseline.
            connection.exec_driver_sql(
                f'GRANT CONNECT ON DATABASE "{database}" TO "{role}" WITH GRANT OPTION'
            )
            baseline = frozenset(tuple(row) for row in connection.execute(grants_query))
            oid, cluster = connection.execute(
                text(
                    "SELECT oid,(SELECT system_identifier::text "
                    "FROM pg_control_system()) "
                    "FROM pg_database WHERE datname=current_database()"
                )
            ).one()
            proof = bounded_fencer(
                connection, database=database, fence_id="a" * 64, session_wait_seconds=3
            )
        source = {
            "image_digest": "sha256:" + "1" * 64,
            "revision": "a" * 40,
            "raw_descriptor_digest": "sha256:" + "3" * 64,
            "heads": ["source"],
        }
        prior = cast(
            CpTransitionRequestV1,
            {
                "schema": "dotmac.cp_transition_request/1",
                "product": "dotmac_vendor_control_plane",
                "environment": "production",
                "host": "dedicated-test",
                "database": database,
                "database_oid": oid,
                "cluster_system_identifier": cluster,
                "source": source,
                "previous_receipt_digest": None,
                "authorization_run_id": 1,
                "authorization_run_attempt": 1,
            },
        )
        # This test exercises real fence/restore and connection denial, while
        # maintenance and protected artifact storage remain separate owners.
        store = type("MemoryEvidence", (), {"put": lambda self, raw: raw_digest(raw)})()
        failed = ExistingCpTransitionHost(_config(tmp_path), store=store, recovery={})
        failed.proof = proof
        failed._request, failed._nonce = prior, proof.fence_id
        monkeypatch.setattr(failed, "_connect", connect)
        monkeypatch.setattr(failed, "_maintenance", lambda: None)
        failed.fail_closed(prior, proof.fence_id, acl_may_be_restored=False)
        retained = failed.proof.canonical_bytes()
        assert failed.proof.prior_grants == baseline

        # A new process/owner receives only the public document plus host pins.
        reloaded = fence.FenceProof.from_document(
            read_json(retained),
            expected_digest=raw_digest(retained),
            allowed_writer_roles=(role,),
        )
        current = deepcopy(prior)
        current["authorization_run_id"] = 2
        new_nonce = "b" * 64
        replacement = ExistingCpTransitionHost(
            _config(tmp_path),
            store=store,
            recovery={},
            held_fence=host_module.HeldFenceContinuation(prior, reloaded),
        )
        replacement._request, replacement._nonce = current, new_nonce
        monkeypatch.setattr(replacement, "_connect", connect)
        replacement.fence_and_negative_reconnect(current, new_nonce)
        assert replacement.proof.fence_id == new_nonce
        assert replacement.proof.prior_grants == baseline
        with admin.connect() as connection:
            assert fence.fence_is_holding(connection, replacement.proof)
            fence.restore_writers(
                connection,
                replacement.proof,
                database=database,
                expected_fence_id=new_nonce,
                session_wait_seconds=3,
            )
            assert (
                frozenset(tuple(row) for row in connection.execute(grants_query))
                == baseline
            )
    finally:
        with admin.connect() as connection:
            connection.exec_driver_sql(f'DROP OWNED BY "{role}"')
            connection.exec_driver_sql(f'DROP ROLE IF EXISTS "{role}"')
        admin.dispose()


@pytest.fixture
def committed_pg_host(postgres_url, url_for, tmp_path, monkeypatch, request):
    """Real PG admission with only installation/container boundaries replaced.

    Dynamic fixture acquisition makes the explicit disposable guard precede
    scratch creation and all maintenance-database ACL work.
    """
    from contextlib import contextmanager
    from copy import deepcopy
    from dataclasses import replace
    from types import SimpleNamespace

    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    from vendor_cp.deploy_agent.contracts import canonical_json
    from vendor_cp.deployment import cp_transition_host as host_module
    from vendor_cp.deployment import transition_fence as fence

    parsed = make_url(postgres_url)
    if not (
        os.getenv("D16_DISPOSABLE_PG16") == "1"
        and parsed.host in {"localhost", "127.0.0.1"}
        and parsed.username == "postgres"
    ):
        pytest.fail("committed host tests require explicit disposable loopback PG16")
    scratch = request.getfixturevalue("scratch_db")
    database = scratch.rpartition("/")[2]
    if getattr(request, "param", True):
        request.getfixturevalue("target_only_connect")

    @contextmanager
    def connect(database, role="postgres", **kwargs):
        engine = create_engine(
            url_for(postgres_url, database, user=role),
            isolation_level="AUTOCOMMIT",
            poolclass=NullPool,
        )
        try:
            with engine.connect() as connection:
                yield connection
        finally:
            engine.dispose()

    class Evidence:
        def __init__(self):
            self.values = {}
            self.writes = []

        def put(self, raw):
            checksum = raw_digest(raw)
            self.values[checksum] = raw
            self.writes.append(checksum)
            return checksum

        def read(self, checksum, **kwargs):
            if checksum not in self.values:
                raise FileNotFoundError
            return self.values[checksum]

    heads = [f"committed_target_{i}" for i in range(7)]
    with connect(database) as connection:
        assert (
            int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
            // 10000
            == 16
        )
        connection.exec_driver_sql(f'ALTER DATABASE "{database}" OWNER TO app_admin')
        connection.exec_driver_sql(
            "CREATE TABLE public.alembic_version (version_num varchar(64) PRIMARY KEY)"
        )
        connection.execute(
            text("INSERT INTO public.alembic_version VALUES (:head)"),
            [{"head": head} for head in heads],
        )
        connection.exec_driver_sql(
            "CREATE TABLE public.committed_probe (value integer)"
        )
        connection.exec_driver_sql("CREATE SEQUENCE public.committed_sequence")
        oid, cluster = connection.execute(
            text(
                "SELECT oid,(SELECT system_identifier::text FROM pg_control_system()) "
                "FROM pg_database WHERE datname=current_database()"
            )
        ).one()
        baseline = fence._current_grants(connection, database)
        proof = fence.fence_writers(
            connection, database=database, fence_id="a" * 64, session_wait_seconds=3
        )
    # NullPool closes the setup backend so pending tuple statistics are flushed
    # before the historical quiescence measurement is established.
    raw_descriptor = b"already independently verified target descriptor"
    prior = {
        "schema": "dotmac.cp_transition_request/1",
        "host": "dedicated-test",
        "database": database,
        "database_oid": oid,
        "cluster_system_identifier": cluster,
        "source": {"heads": [f"historical_source_{i}" for i in range(6)]},
        "target": {"heads": heads, "raw_descriptor_digest": raw_digest(raw_descriptor)},
    }
    with connect(database) as connection:
        measurement = measure_candidate_quiescence(connection)
    catalogue = measurement.pop("catalogue_bytes")
    measurement["catalogue_digest"] = raw_digest(catalogue)
    context = SimpleNamespace(
        request=prior,
        proof=proof,
        original_proof=proof,
        context_digest="test-verified-historical-context",
        measurement=measurement,
    )
    fresh = {
        **deepcopy(prior),
        "schema": "dotmac.cp_committed_migration_request/1",
        "operator_revision": "f" * 40,
        "basis": {
            "context_digest": context.context_digest,
            "current_fence_digest": proof.digest(),
            "current_fence_id": proof.fence_id,
            "original_fence_digest": proof.digest(),
            "frontier_measurement_digest": raw_digest(canonical_json(measurement)),
        },
    }
    evidence = Evidence()
    host = ExistingCpTransitionHost(
        replace(_config(tmp_path), operator_revision="f" * 40),
        store=evidence,
        recovery={},
        committed_context=context,
    )
    monkeypatch.setattr(host, "_connect", connect)
    monkeypatch.setattr(host, "_inspect_installation", lambda *a: None)
    monkeypatch.setattr(host, "_source_image_identity", lambda *a: "stopped-incumbent")
    monkeypatch.setattr(
        host,
        "_writers",
        lambda: [
            {
                "Image": "stopped-incumbent",
                "State": {"Running": False},
                "HostConfig": {"RestartPolicy": {"Name": "no"}},
            }
        ],
    )
    monkeypatch.setattr(host, "_docker", lambda *a: "")
    monkeypatch.setattr(host, "_http", lambda *a, **k: None)
    monkeypatch.setattr(host, "_maintenance", lambda: None)
    monkeypatch.setattr(host, "_run", lambda *a, **k: pytest.fail("container mutation"))
    monkeypatch.setattr(
        host, "_source_matches", lambda *a: pytest.fail("source observed")
    )
    monkeypatch.setattr(host_module, "_read_protected", lambda *a: raw_descriptor)
    try:
        yield SimpleNamespace(
            host=host,
            request=fresh,
            context=context,
            connect=connect,
            database=database,
            baseline=baseline,
            evidence=evidence,
        )
    finally:
        with connect(database) as connection:
            if host.roles is not None:
                for role, _ in host.roles.bindings():
                    if (
                        connection.execute(
                            text("SELECT 1 FROM pg_roles WHERE rolname=:role"),
                            {"role": role},
                        ).scalar_one_or_none()
                        is not None
                    ):
                        connection.exec_driver_sql(f'DROP OWNED BY "{role}"')
                        connection.exec_driver_sql(f'DROP ROLE "{role}"')
            fence.restore_writers(
                connection,
                host.proof,
                database=database,
                expected_fence_id=host.proof.fence_id,
                session_wait_seconds=3,
            )
            assert fence._current_grants(connection, database) == baseline


def test_committed_pg_admission_rebind_and_candidate_failure_preserve_lineage(
    committed_pg_host,
):
    """Actual queries/ACLs/roles; no candidate container or application startup."""
    from types import SimpleNamespace

    from vendor_cp.deployment import candidate_roles
    from vendor_cp.deployment import transition_fence as fence
    from vendor_cp.deployment.transition_evidence import read_current_migration_heads

    state = committed_pg_host
    host, request, context = state.host, state.request, state.context
    host.inspect_committed(request, context)
    assert state.evidence.writes == []  # Admission does not reserve or rebind.
    nonce = "b" * 64
    host._nonce = nonce  # Fresh executor reservation boundary is core-tested.
    rebound = read_json(host.rebind_committed(request, nonce, context))
    assert rebound["kind"] == "committed-rebound"
    assert host.proof.fence_id == nonce
    assert host.proof.prior_grants == state.baseline == context.proof.prior_grants
    host._candidate_quiescence_before = host._quiescence_snapshot(request, nonce)
    host.roles = candidate_roles.CandidateRoles.for_run(
        database=state.database, run_id=nonce[:32]
    )
    host.launch = SimpleNamespace(run_id=nonce[:32])
    host._candidate_created = True
    with state.connect(state.database) as connection:
        candidate_roles.create_roles(
            connection, host.roles, host.proof, **host._candidate_arguments()
        )
    # The candidate fails after role creation and before container startup.
    failure = read_json(host.fail_closed(request, nonce, acl_may_be_restored=False))
    assert failure["kind"] == "failure"
    assert not host._candidate_created and not host._candidate_started
    assert host.proof.prior_grants == state.baseline
    with state.connect(state.database) as connection:
        assert (
            list(read_current_migration_heads(connection)) == request["target"]["heads"]
        )
        assert fence.fence_is_holding(connection, host.proof)
        assert not connection.execute(
            text("SELECT rolname FROM pg_roles WHERE left(rolname,8)='vcp_d16_'")
        ).all()


@pytest.mark.parametrize(
    "drift", ["catalogue", "data", "sequence", "reset", "storage", "heads"]
)
def test_committed_pg_live_drift_refuses_before_rebind(committed_pg_host, drift):
    state = committed_pg_host
    statements = {
        "catalogue": (
            "CREATE INDEX committed_probe_index ON public.committed_probe(value)"
        ),
        "data": "INSERT INTO public.committed_probe VALUES (1)",
        "sequence": "SELECT nextval('public.committed_sequence')",
        "reset": "SELECT pg_stat_reset()",
        "storage": "TRUNCATE public.committed_probe",
        "heads": "UPDATE public.alembic_version SET version_num='wrong' "
        "WHERE version_num='committed_target_0'",
    }
    with state.connect(state.database) as connection:
        connection.exec_driver_sql(statements[drift])
        connection.exec_driver_sql("SELECT pg_stat_force_next_flush()")
    expected = (
        "committed_target_heads_mismatch"
        if drift == "heads"
        else "committed_measurement_drift"
    )
    with pytest.raises(ContractError, match=expected):
        state.host.inspect_committed(state.request, state.context)
    assert state.evidence.writes == []
    assert state.host.proof is state.context.proof
    assert state.host._request is None and state.host._nonce is None


@pytest.mark.parametrize("committed_pg_host", [False], indirect=True)
def test_committed_pg_public_other_database_connect_refuses_before_reservation(
    committed_pg_host,
):
    from vendor_cp.deployment.candidate_roles import CandidateRoleRefused

    state = committed_pg_host
    with state.connect(state.database) as connection:
        assert (
            connection.execute(
                text("SELECT has_database_privilege('app_user','postgres','CONNECT')")
            ).scalar_one()
            is True
        )
    with pytest.raises(CandidateRoleRefused, match="another database"):
        state.host.inspect_committed(state.request, state.context)
    assert state.evidence.writes == []
    assert state.host.proof is state.context.proof
    assert state.host._request is None and state.host._nonce is None
