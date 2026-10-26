"""Concrete host refusal, compensation and owner-composition tests (no Docker)."""

from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.exc import OperationalError

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition_host as module
from vendor_cp.deployment.cp_transition import (
    ArtifactStore,
    CpTransitionRequestV1,
    TransitionSideV1,
    raw_digest,
)
from vendor_cp.deployment.effects import PlatformBackupResult, ProcessResult
from vendor_cp.deployment.image_heads import render_image_document


def config(tmp_path: Path) -> module.CpTransitionHostConfig:
    return module.CpTransitionHostConfig(
        repository_root=tmp_path,
        deploy_directory=tmp_path,
        target_descriptor=tmp_path / "target.toml",
        source_image=f"{module.IMAGE_REPOSITORY}@sha256:{'1' * 64}",
        target_image=f"{module.IMAGE_REPOSITORY}@sha256:{'2' * 64}",
        postgres_image=f"postgres@sha256:{'3' * 64}",
        maintenance_helper=tmp_path / "maintenance",
        maintenance_helper_digest=f"sha256:{'4' * 64}",
        external_ready_url="https://platform.dotmac.io/health/ready",
        candidate_port=18100,
        docker_binary_digest="sha256:" + "5" * 64,
        git_binary=Path("/usr/bin/git"),
        git_binary_digest="sha256:" + "6" * 64,
    )


def descriptor(image: str, revision: str, heads: list[str]) -> bytes:
    return (
        'product="dotmac_vendor_control_plane"\nenvironment="production"\n'
        f'[image]\nreference="{image}"\nsource_revision="{revision}"\n'
        f"[migration]\nexpected_heads={json.dumps(heads)}\n"
    ).encode()


def side(image: str) -> tuple[TransitionSideV1, bytes]:
    revision = "a" * 40
    raw = descriptor(image, revision, ["source_head"])
    return {
        "image_digest": image.rsplit("@", 1)[1],
        "revision": revision,
        "raw_descriptor_digest": raw_digest(raw),
        "heads": ["source_head"],
    }, raw


@pytest.fixture
def host(tmp_path: Path, monkeypatch) -> module.ExistingCpTransitionHost:
    # Composition unit tests replace process/metadata boundaries. Real tool
    # protection and digest I/O are tested by the core owner and hosted lane.
    monkeypatch.setattr(
        module,
        "_protected_executable_digest",
        lambda path: "sha256:"
        + ("5" * 64 if path == Path("/usr/bin/docker") else "6" * 64),
    )
    return module.ExistingCpTransitionHost(
        config(tmp_path), store=ArtifactStore(tmp_path), recovery={}
    )


class ImageProcess:
    def __init__(
        self,
        image: str,
        *,
        heads: tuple[str, ...] = ("source_head",),
        revision: str = "a" * 40,
    ):
        self.image = image
        self.heads = heads
        self.revision = revision
        self.commands: list[tuple[str, ...]] = []

    def run(self, argv, **kwargs):
        self.commands.append(tuple(argv))
        if argv[1:3] == ("image", "inspect"):
            return ProcessResult(
                0,
                json.dumps(
                    [
                        {
                            "Id": "sha256:" + "c" * 64,
                            "RepoDigests": [self.image],
                            "Config": {
                                "Labels": {
                                    "org.opencontainers.image.revision": self.revision
                                }
                            },
                        }
                    ]
                ),
            )
        if argv[1] == "create":
            return ProcessResult(0, "b" * 64)
        if argv[1] == "cp":
            Path(argv[-1]).write_text(
                render_image_document(source_revision=self.revision, heads=self.heads)
            )
        return ProcessResult(0)

    def capture_stdout(self, *args, **kwargs):
        raise AssertionError("image inspection must not capture a database dump")


def test_target_image_proof_extracts_without_starting_runtime(host):
    observed, raw = side(host.config.target_image)
    process = ImageProcess(host.config.target_image)
    host.process = process
    host._image(host.config.target_image, observed, raw)
    assert [argv[1] for argv in process.commands] == ["image", "create", "cp", "rm"]
    assert "--network" in process.commands[1]
    assert not any("start" in argv or "run" in argv for argv in process.commands)


def test_bad_target_image_heads_still_removes_unstarted_container(host):
    observed, raw = side(host.config.target_image)
    process = ImageProcess(host.config.target_image, heads=("other_head",))
    host.process = process
    with pytest.raises(ContractError, match="image_heads_mismatch"):
        host._image(host.config.target_image, observed, raw)
    assert process.commands[-1][1] == "rm"


def test_target_descriptor_drift_refuses_before_docker(host):
    observed, raw = side(host.config.target_image)
    process = ImageProcess(host.config.target_image)
    host.process = process
    wrong = raw.replace(b"a" * 40, b"c" * 40)
    observed["raw_descriptor_digest"] = raw_digest(wrong)
    with pytest.raises(ContractError, match="descriptor_identity_mismatch"):
        host._image(host.config.target_image, observed, wrong)
    assert process.commands == []


@pytest.mark.parametrize("other_database", [None, "postgres", "template1"])
def test_candidate_connect_forecast_precedes_processes_and_transition_mutations(
    host, monkeypatch, tmp_path, other_database
):
    actions = []
    queries = []
    docker = tmp_path / "docker"
    docker.write_text("unit boundary")
    docker.chmod(0o700)
    host.config = replace(host.config, docker_binary=docker)
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        module, "_open_directory", lambda path: os.open(tmp_path, os.O_RDONLY)
    )
    monkeypatch.setattr(
        module,
        "_read_protected",
        lambda path: b"host" if path == host.config.host_id_file else b"maintenance",
    )
    host.config = replace(
        host.config, maintenance_helper_digest=raw_digest(b"maintenance")
    )

    def execute(sql, parameters):
        queries.append((str(sql), parameters))
        if "FROM pg_roles" in str(sql):
            return SimpleNamespace(scalars=lambda: ["app_user", "platform_api"])
        actions.append("candidate-connect-forecast")
        return SimpleNamespace(scalar_one_or_none=lambda: other_database)

    connection = SimpleNamespace(execute=execute)
    monkeypatch.setattr(host, "_connect", lambda *a: nullcontext(connection))
    monkeypatch.setattr(host, "_identity", lambda *a: actions.append("identity"))
    monkeypatch.setattr(
        host, "_check_fence_baseline", lambda *a: actions.append("baseline")
    )
    monkeypatch.setattr(host, "_docker", lambda *a: actions.append("docker"))
    monkeypatch.setattr(host, "_image", lambda *a: actions.append("image"))
    monkeypatch.setattr(host, "_source_matches", lambda *a: actions.append("source"))
    monkeypatch.setattr(host, "_run", lambda *a, **k: pytest.fail("process ran"))
    monkeypatch.setattr(host, "_maintenance", lambda: pytest.fail("maintenance ran"))
    request = cast(
        CpTransitionRequestV1,
        {"host": "host", "database": "cp", "source": {}, "target": {}},
    )
    if other_database is not None:
        with pytest.raises(
            module.candidate_roles.CandidateRoleRefused, match="another database"
        ):
            host.inspect(request)
        assert host._request is None
    else:
        host.inspect(request)
    assert actions[:3] == ["identity", "baseline", "candidate-connect-forecast"]
    assert actions[3:] == ([] if other_database else ["docker", "image", "source"])
    assert all(sql.startswith("SELECT ") for sql, _ in queries)
    assert queries[-1][1] == {
        "target": "cp",
        "app": "app_user",
        "platform": "platform_api",
    }


@pytest.fixture
def historic_source_descriptor():
    raw = (
        Path(__file__).parents[1]
        / "fixtures"
        / "cp-transition"
        / "source-3ef3cef4.toml"
    ).read_bytes()
    assert raw_digest(raw) == (
        "sha256:42d1b0b6bbb8b1b0cc9990cd5630a4be66ea778aaa206ef69a22c3cc72f1c5aa"
    )
    return raw


def _historic_source_host(host, monkeypatch, raw):
    """Actual immutable Git blob; OCI and SQL are explicit unit boundaries."""
    revision = "3ef3cef4eed6703cb60e2f1787ed7af41e9f502f"
    observed: TransitionSideV1 = {
        "image_digest": host.config.source_image.rsplit("@", 1)[1],
        "revision": revision,
        "raw_descriptor_digest": raw_digest(raw),
        "heads": ["observed_source_head"],
    }
    request = cast(CpTransitionRequestV1, {"database": "cp", "source": observed})
    process = ImageProcess(host.config.source_image, revision=revision)
    host.process = process
    monkeypatch.setattr(
        module, "read_descriptor_at_revision", lambda repo, source, **kw: raw
    )
    monkeypatch.setattr(
        module, "read_current_migration_heads", lambda conn: ("observed_source_head",)
    )
    monkeypatch.setattr(host, "_identity", lambda *a: None)
    connection = SimpleNamespace(
        execute=lambda sql, **k: [["postgres", 10, True]]
        if "WHERE oid=10" in str(sql)
        else SimpleNamespace(scalar_one=lambda: 1024)
    )
    monkeypatch.setattr(host, "_connect", lambda *a, **k: nullcontext(connection))
    monkeypatch.setattr(host, "_writers", lambda: [{"Image": "sha256:" + "c" * 64}])
    return request, process


def test_historic_source_admits_independent_image_descriptor_and_database_facts(
    host, monkeypatch, historic_source_descriptor
):
    request, process = _historic_source_host(
        host, monkeypatch, historic_source_descriptor
    )
    declarations = module.source_descriptor_declarations(historic_source_descriptor)
    assert declarations["source_revision"] == "af9fcf6d3fbd259fbef6b589d37b39d548f7ba8e"
    assert declarations["image_reference"].endswith(
        "sha256:45715e425dc248d85fe374fa5d347087328a445cf7ead1f8abc29f05f0117b0d"
    )
    assert declarations["migration_heads"] != request["source"]["heads"]
    host._source_matches(request)
    assert host._source_descriptor == historic_source_descriptor
    # No legacy migration_heads.json is read, and no source container starts.
    assert [command[1:3] for command in process.commands] == [("image", "inspect")]


@pytest.mark.parametrize(
    ("mismatch", "code"),
    [
        ("oci-revision", "image_identity_mismatch"),
        ("oci-digest", "image_identity_mismatch"),
        ("source-reference", "image_identity_mismatch"),
        ("git-blob", "source_descriptor_digest_mismatch"),
        ("raw-digest", "source_descriptor_digest_mismatch"),
        ("database-heads", "source_heads_mismatch"),
        ("incumbent-image", "incumbent_image_mismatch"),
    ],
)
def test_historic_source_still_refuses_unbound_actual_observations(
    host, monkeypatch, historic_source_descriptor, mismatch, code
):
    request, process = _historic_source_host(
        host, monkeypatch, historic_source_descriptor
    )
    if mismatch == "oci-revision":
        process.revision = "b" * 40
    elif mismatch == "oci-digest":
        process.image = host.config.target_image
    elif mismatch == "source-reference":
        host.config = replace(host.config, source_image=host.config.target_image)
    elif mismatch == "git-blob":
        monkeypatch.setattr(
            module,
            "read_descriptor_at_revision",
            lambda *a, **kw: historic_source_descriptor + b"\n#changed\n",
        )
    elif mismatch == "raw-digest":
        request["source"]["raw_descriptor_digest"] = "sha256:" + "d" * 64
    elif mismatch == "database-heads":
        monkeypatch.setattr(
            module, "read_current_migration_heads", lambda *a: ("changed",)
        )
    elif mismatch == "incumbent-image":
        monkeypatch.setattr(
            host,
            "_writers",
            lambda: [
                {"Image": "sha256:" + "c" * 64},
                {"Image": "sha256:" + "d" * 64},
            ],
        )
    with pytest.raises(ContractError, match=code):
        host._source_matches(request)


@pytest.mark.parametrize("sqlstate", ["28P01", "08006", "42501", None])
def test_reconnect_requires_database_acl_denial(host, monkeypatch, sqlstate):
    host.proof = SimpleNamespace(fenced_roles=("writer",), member_roles=())

    @contextmanager
    def denied(*args, **kwargs):
        error = RuntimeError("unrelated connection failure")
        error.sqlstate = sqlstate
        raise OperationalError(None, None, error)
        yield

    monkeypatch.setattr(host, "_connect", denied)
    with pytest.raises(ContractError, match="negative_reconnect_unproved"):
        host._negative_reconnect(cast(CpTransitionRequestV1, {"database": "source"}))


@pytest.mark.parametrize("sqlstate", [None, "42501"])
def test_reconnect_accepts_only_exact_bound_server_connect_denial(
    host, monkeypatch, sqlstate
):
    host.proof = SimpleNamespace(fenced_roles=("writer",), member_roles=())
    error = RuntimeError(
        'connection failed: connection to server at "postgres", port 5432 failed: '
        'FATAL:  permission denied for database "source"\n'
        "DETAIL:  User does not have CONNECT privilege."
    )
    error.sqlstate = sqlstate
    wrapped = OperationalError(None, None, error)

    @contextmanager
    def denied(*args, **kwargs):
        raise wrapped
        yield

    monkeypatch.setattr(host, "_connect", denied)
    assert module.classify_reconnect_denial(wrapped, database="source") is (
        module.ReconnectDenial.DATABASE_ACL_DENIAL
    )
    host._negative_reconnect(cast(CpTransitionRequestV1, {"database": "source"}))


@pytest.mark.parametrize(
    ("sqlstate", "message"),
    [
        (
            "28P01",
            'FATAL:  permission denied for database "source"\n'
            "DETAIL:  User does not have CONNECT privilege.",
        ),
        (
            None,
            'FATAL:  permission denied for database "other"\n'
            "DETAIL:  User does not have CONNECT privilege.",
        ),
        (
            "42501",
            'FATAL:  permission denied for database "source"\n'
            "DETAIL:  A different permission failed.",
        ),
        (None, 'FATAL:  permission denied for database "source"'),
        (None, 'FATAL:  password authentication failed for user "writer"'),
        (
            None,
            'connection to server at "postgres", port 5432 failed: Connection refused',
        ),
        (None, 'could not translate host name "postgres" to address'),
        (
            None,
            'FATAL:  permission denied for database "source"\n'
            "DETAIL:  User does not have CONNECT privilege.\n"
            "connection to another host failed",
        ),
    ],
)
def test_reconnect_classification_refuses_unrelated_errors(sqlstate, message):
    error = RuntimeError(message)
    error.sqlstate = sqlstate
    assert (
        module.classify_reconnect_denial(
            OperationalError(None, None, error), database="source"
        )
        is None
    )


def test_successful_writer_reconnect_is_refused(host, monkeypatch):
    host.proof = SimpleNamespace(fenced_roles=("writer",), member_roles=())
    monkeypatch.setattr(host, "_connect", lambda *a, **k: nullcontext(object()))
    with pytest.raises(ContractError, match="writer_reconnected"):
        host._negative_reconnect(cast(CpTransitionRequestV1, {"database": "source"}))


@pytest.mark.parametrize("acl_may_be_restored", [False, True])
def test_maintenance_failure_still_attempts_refence(
    host, monkeypatch, acl_may_be_restored
):
    actions = []
    request = cast(CpTransitionRequestV1, {"database": "source"})
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    monkeypatch.setattr(host, "_identity", lambda *a: None)
    monkeypatch.setattr(host, "_check_fence_baseline", lambda *a: None)
    monkeypatch.setattr(host, "_connect", lambda *a, **k: nullcontext(object()))

    def maintenance():
        actions.append("maintenance")
        raise RuntimeError("maintenance failed")

    def fence(*a, **k):
        actions.append("refence")
        return SimpleNamespace(fence_id="nonce")

    monkeypatch.setattr(host, "_maintenance", maintenance)
    monkeypatch.setattr(module.transition_fence, "fence_writers", fence)
    monkeypatch.setattr(
        host, "_strict", lambda *a: actions.append("negative-reconnect")
    )
    with pytest.raises(RuntimeError, match="containment"):
        host.fail_closed(request, "nonce", acl_may_be_restored=acl_may_be_restored)
    assert actions == ["maintenance", "refence", "negative-reconnect"]


def test_routing_requires_retained_receipt_before_helper(host, monkeypatch):
    calls = []
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    monkeypatch.setattr(host, "_run", lambda *a, **k: calls.append(a))
    with pytest.raises(ContractError, match="routing_gate_missing"):
        host.restore_routing(cast(CpTransitionRequestV1, {}), "nonce")
    assert calls == []


def test_shell_diagnostics_are_not_exposed(host):
    class Failed:
        def run(self, *a, **k):
            return ProcessResult(1, "secret-stdout", "secret-stderr")

    host.process = Failed()
    with pytest.raises(ContractError) as captured:
        host._run(("/missing",))
    assert "secret" not in str(captured.value)


@pytest.mark.parametrize("invocation", ["wrapper", "direct"])
def test_docker_bytes_are_checked_before_each_subprocess(host, monkeypatch, invocation):
    actions = []

    def verify(path):
        actions.append(("verified", path))
        return host.config.docker_binary_digest

    class Process:
        def run(self, argv, **kwargs):
            actions.append(("executed", argv[0]))
            return ProcessResult(0)

    host.process = Process()
    monkeypatch.setattr(module, "_protected_executable_digest", verify)
    if invocation == "wrapper":
        host._docker("version")
    else:
        host._run((str(host.config.docker_binary), "version"))
    assert actions == [
        ("verified", host.config.docker_binary),
        ("executed", str(host.config.docker_binary)),
    ]


@pytest.mark.parametrize("failure", ["wrong-digest", "unprotected-path"])
def test_docker_tool_refusal_precedes_any_execution(host, monkeypatch, failure):
    class Process:
        def run(self, *args, **kwargs):
            pytest.fail("an unverified root tool must not run")

    def verify(path):
        if failure == "unprotected-path":
            raise ContractError("unsafe_artifact_path")
        return "sha256:" + "9" * 64

    host.process = Process()
    monkeypatch.setattr(module, "_protected_executable_digest", verify)
    with pytest.raises(ContractError):
        host._docker("version")


def test_missing_local_socket_has_no_password_or_network_fallback(tmp_path):
    with pytest.raises(ContractError, match="local_postgres_unavailable"):
        with module.local_postgres_connection(
            tmp_path / "missing", "cp", "postgres", autocommit=True
        ):
            raise AssertionError("must refuse before connection")


def test_socket_uses_measured_container_canonical_run_path(host, monkeypatch):
    commands = []
    root = Path("/proc/987654321/root/run/postgresql")
    read_text = Path.read_text
    is_dir = Path.is_dir
    stat_path = Path.stat
    monkeypatch.setattr(
        host, "_container", lambda *a: {"State": {"Running": True, "Pid": 987654321}}
    )
    monkeypatch.setattr(
        host, "_docker", lambda *a, **k: commands.append(a) or "/run/postgresql"
    )
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **k: "postgres\n"
        if str(path) == "/proc/987654321/comm"
        else read_text(path, *a, **k),
    )
    monkeypatch.setattr(
        Path, "is_dir", lambda path: True if path == root else is_dir(path)
    )
    monkeypatch.setattr(
        Path,
        "stat",
        lambda path, *a, **k: SimpleNamespace(st_mode=stat.S_IFSOCK)
        if path == root / ".s.PGSQL.5432"
        else stat_path(path, *a, **k),
    )
    assert host._socket("owned-postgres") == root
    assert commands == [
        (
            "exec",
            "--user",
            "postgres",
            "owned-postgres",
            "readlink",
            "-f",
            "/var/run/postgresql",
        )
    ]


@pytest.mark.parametrize(
    "directory",
    [
        "/tmp",  # noqa: S108 - explicitly rejected socket-directory fixture
        "/var/run/postgresql",
        "/run/postgresql/../other",
        "/run/postgresql\n/tmp",
        "relative/path",
    ],
)
def test_socket_refuses_an_unmeasured_directory(host, monkeypatch, directory):
    read_text = Path.read_text
    monkeypatch.setattr(
        host, "_container", lambda *a: {"State": {"Running": True, "Pid": 987654321}}
    )
    monkeypatch.setattr(host, "_docker", lambda *a, **k: directory)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **k: "postgres\n"
        if str(path) == "/proc/987654321/comm"
        else read_text(path, *a, **k),
    )
    with pytest.raises(ContractError, match="postgres_socket_directory_mismatch"):
        host._socket("owned-postgres")


def test_base_candidate_environment_cannot_copy_original_writer_credentials(
    host, monkeypatch, tmp_path
):
    source = tmp_path / "runtime.env"
    source.write_bytes(b"DATABASE_URL=do-not-copy\n")
    host.config = replace(host.config, candidate_runtime_environment=source)
    monkeypatch.setattr(module, "_read_protected", lambda path: path.read_bytes())
    with pytest.raises(ContractError, match="exclude_database_credentials"):
        host._materialize_candidate_environment(
            cast(CpTransitionRequestV1, {"database": "cp"}), "a" * 32
        )


def test_evidence_is_bound_to_original_nonce(host, monkeypatch):
    request = cast(CpTransitionRequestV1, {"database": "cp"})
    host._request = request
    host._nonce = "original"
    with pytest.raises(ContractError, match="host_nonce_mismatch"):
        host._evidence(request, "other", "maintenance", {})


@pytest.mark.parametrize(
    ("status", "body", "accepted"),
    [
        (404, {"detail": "desired_state_absent"}, True),
        (404, {"detail": "Not Found"}, False),
        (503, {"detail": "feature_disabled"}, False),
        (200, {"ready": True}, False),
    ],
)
def test_ledger_probe_requires_actual_signed_fetch_owner(
    host, monkeypatch, status, body, accepted
):
    url = host._ledger_probe_url()

    class Response:
        def __init__(self):
            self.status = status
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return canonical_json(body)

    monkeypatch.setattr(
        module.urllib.request,
        "build_opener",
        lambda *a: SimpleNamespace(open=lambda *a, **k: Response()),
    )
    if accepted:
        host._http(url, expected=(200, 404), ledger=True)
    else:
        with pytest.raises(ContractError):
            host._http(url, expected=(200, 404), ledger=True)


def test_keyless_full_runtime_refuses_disabled_agent(host, monkeypatch, tmp_path):
    source = tmp_path / "compose.yml"
    source.write_bytes(b"protected compose inputs")
    host._runtime_inputs = {source: raw_digest(source.read_bytes())}
    monkeypatch.setattr(module, "_read_protected", lambda path: path.read_bytes())
    monkeypatch.setattr(
        host,
        "_run",
        lambda *a, **k: json.dumps(
            {
                "services": {
                    "app": {
                        "environment": {
                            "VENDOR_DEPLOYMENT_PROFILE": "production-keyless-v1",
                            "VENDOR_DEPLOY_AGENT_ENABLED": "false",
                        }
                    }
                }
            }
        ),
    )
    with pytest.raises(ContractError, match="keyless_runtime_overlay_required"):
        host._runtime_specification()


@pytest.mark.parametrize("with_registry", [False, True])
def test_migrate_passes_same_active_transaction_and_independent_observer(
    host, monkeypatch, with_registry
):
    from vendor_cp import migrations

    registry = {"historical-context": object()} if with_registry else {}
    host._committed_contexts = registry
    events = []
    observer = object()

    class MigrationConnection:
        active = False

        @contextmanager
        def begin(self):
            self.active = True
            events.append("begin")
            yield
            events.append("commit")
            self.active = False

    connection = MigrationConnection()

    def native(actual_connection, **kwargs):
        assert actual_connection is connection and connection.active
        assert kwargs["fence_connection"] is observer
        assert kwargs["evidence"] == {"source-genesis": "retained"}
        assert kwargs["host_nonce"] == "nonce"
        if with_registry:
            assert kwargs["committed_contexts"] is registry
        else:
            assert "committed_contexts" not in kwargs
        assert kwargs["repository_root"] == host.config.repository_root
        assert kwargs["git_binary"] == host.config.git_binary
        assert kwargs["git_binary_digest"] == host.config.git_binary_digest
        events.append("native-owner")

    monkeypatch.setattr(migrations, "native_upgrade", native)
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    monkeypatch.setattr(host, "_identity", lambda *a: None)
    monkeypatch.setattr(host, "_strict", lambda *a: object())
    monkeypatch.setattr(
        host, "_source_matches", lambda *a: events.append("source-recheck")
    )
    monkeypatch.setattr(host, "_evidence", lambda *a: b"result")
    monkeypatch.setattr(
        host,
        "_connect",
        lambda db, role="postgres", **k: nullcontext(
            connection if role == "app_admin" else observer
        ),
    )
    result = host.migrate(
        cast(
            CpTransitionRequestV1, {"database": "cp", "target": {"heads": ["target"]}}
        ),
        "nonce",
        authorization=object(),
        reservation_digest="reserved",
        genesis_digest="genesis",
        restore_digest="restore",
        fence_digest="fence",
        evidence={"source-genesis": "retained"},
    )
    assert result == b"result"
    assert events == ["source-recheck", "begin", "native-owner", "commit"]


def test_lost_scratch_creation_ack_cleans_only_our_labelled_container(
    host, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        host,
        "_source_bootstrap",
        lambda: {"role": "postgres", "oid": 10, "superuser": True},
    )
    nonce = "a" * 64
    request = cast(CpTransitionRequestV1, {"database": "source"})
    checksum = module.request_digest(request)
    name = f"vcp-d16-restore-{nonce[:32]}"

    class LostAck:
        def __init__(self):
            self.commands = []
            self.created = False

        def run(self, argv, **kwargs):
            self.commands.append(tuple(argv))
            if argv[1] == "ps":
                return ProcessResult(0, "b" * 64 if self.created else "")
            if argv[1] == "run":
                self.created = True
                return ProcessResult(124)
            if argv[1] == "inspect":
                return ProcessResult(
                    0,
                    json.dumps(
                        [
                            {
                                "Id": "b" * 64,
                                "Name": f"/{name}",
                                "Config": {
                                    "Labels": {
                                        module._SCRATCH_OWNER_LABEL: "1",
                                        module._SCRATCH_NONCE_LABEL: nonce,
                                        module._SCRATCH_REQUEST_LABEL: checksum,
                                    }
                                },
                            }
                        ]
                    ),
                )
            return ProcessResult(0)

    process = LostAck()
    host.process = process
    with pytest.raises(ContractError, match="transition_host_command_failed"):
        host._restore_fresh(request, nonce, tmp_path, 16)
    assert process.commands[-1][1:] == ("rm", "-f", "-v", "b" * 64)
    created = next(argv for argv in process.commands if argv[1] == "run")
    assert created[created.index("--memory") + 1] == "1g"
    assert created[created.index("--pids-limit") + 1] == "128"
    assert "/var/lib/postgresql/data:rw,nosuid,size=512m" in created


def test_scratch_cleanup_refuses_unknown_resource_identity(host, monkeypatch):
    commands = []
    monkeypatch.setattr(host, "_docker", lambda *a, **k: commands.append(a) or "b" * 64)
    monkeypatch.setattr(
        host,
        "_container",
        lambda *a: {"Id": "b" * 64, "Name": "/expected", "Config": {"Labels": {}}},
    )
    with pytest.raises(ContractError, match="scratch_cleanup_identity_mismatch"):
        host._cleanup_scratch("expected", "nonce", "digest")
    assert not any(argv[0] == "rm" for argv in commands)


@pytest.mark.parametrize(
    "url",
    [
        "http://platform.dotmac.io/health/ready",
        "https://vendor.dotmac.io/health/ready",
        "https://platform.dotmac.io:8443/health/ready",
        "https://platform.dotmac.io:443/health/ready",
        "https://user:password@platform.dotmac.io/health/ready",
        "https://platform.dotmac.io/health/ready?next=http://127.0.0.1/",
        "https://platform.dotmac.io/health/ready#fragment",
        "https://platform.dotmac.io.evil.example/health/ready",
    ],
)
def test_external_readiness_url_is_fixed_policy(host, url):
    with pytest.raises(ContractError, match="external_readiness_url_refused"):
        replace(host.config, external_ready_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:5432/health/ready",
        "http://127.0.0.1:8100/arbitrary",
        "http://127.0.0.1:8100/health/ready?query=1",
        "https://127.0.0.1:8100/health/ready",
    ],
)
def test_loopback_probe_path_port_and_scheme_are_fixed(host, monkeypatch, url):
    monkeypatch.setattr(
        module.urllib.request,
        "build_opener",
        lambda *a: pytest.fail("invalid probe must not open a transport"),
    )
    with pytest.raises(ContractError, match="unsafe_readiness_url"):
        host._http(url, expected=200)


def test_fixed_probe_cannot_follow_redirect_to_an_arbitrary_destination():
    handler = module._NoProbeRedirect()
    request = module.urllib.request.Request(module.EXTERNAL_READY_URL)
    assert (
        handler.redirect_request(
            request, None, 302, "redirect", {}, "http://127.0.0.1:5432/secret"
        )
        is None
    )


def test_candidate_quiescence_requires_backend_exit_before_read(host, monkeypatch):
    host._candidate_quiescence_before = b"baseline"
    monkeypatch.setattr(
        host,
        "_quiescence_snapshot",
        lambda *a: pytest.fail("post-stat read must follow backend exit"),
    )
    with pytest.raises(ContractError, match="candidate_backend_exit_unproved"):
        host._finish_candidate_quiescence(cast(CpTransitionRequestV1, {}), "nonce")


@pytest.mark.parametrize("after", [b"unchanged", b"mutation"])
def test_candidate_quiescence_retains_both_measurements_and_refuses_drift(
    host, monkeypatch, after
):
    retained = {}
    host._candidate_quiescence_before = b"unchanged"
    host._candidate_backends_exited = True
    monkeypatch.setattr(host, "_quiescence_snapshot", lambda *a: after)

    def retain(raw):
        checksum = raw_digest(raw)
        retained[checksum] = raw
        return checksum

    monkeypatch.setattr(host, "_retain", retain)
    request = cast(CpTransitionRequestV1, {"database": "cp"})
    if after == b"mutation":
        with pytest.raises(ContractError, match="candidate_mutation_observed"):
            host._finish_candidate_quiescence(request, "nonce")
        assert host._candidate_quiescence_digest is None
    else:
        checksum = host._finish_candidate_quiescence(request, "nonce")
        proof = module.read_json(retained[checksum])
        assert proof == {
            "schema": "dotmac.cp_candidate_quiescence/1",
            "request_digest": module.request_digest(request),
            "host_nonce": "nonce",
            "before_digest": raw_digest(b"unchanged"),
            "after_digest": raw_digest(after),
        }
    assert raw_digest(b"unchanged") in retained
    assert raw_digest(after) in retained


@pytest.mark.parametrize("operation", ["run", "capture"])
def test_v2_process_pins_docker_and_discards_poisoned_ambient_environment(
    host, monkeypatch, tmp_path, operation
):
    directory = tmp_path / "docker-config"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(
        module,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    for key, value in {
        "DOCKER_HOST": "tcp://untrusted:2375",
        "DOCKER_CONTEXT": "untrusted",
        "DOCKER_CONFIG": "/untrusted",
        "LD_PRELOAD": "/untrusted/loader",
        "PYTHONPATH": "/untrusted",
    }.items():
        monkeypatch.setenv(key, value)
    events = []
    monkeypatch.setattr(
        module,
        "_protected_executable_digest",
        lambda path: events.append(("pinned", path))
        or host.config.docker_binary_digest,
    )
    expected = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "DOCKER_CONFIG": str(directory),
        "VENDOR_APP_IMAGE": host.config.target_image,
        "VENDOR_DB_BOOTSTRAP_PASSWORD": "owner-ephemeral",
    }
    destination = tmp_path / "database.dump"

    class Delegate:
        def run(self, argv, **kwargs):
            assert kwargs["env"] == expected
            assert kwargs["stdin_path"] is destination
            events.append(("run",))
            return ProcessResult(0, "metadata")

        def capture_stdout(self, argv, target, **kwargs):
            assert kwargs["env"] == expected
            assert target is destination
            events.append(("capture",))
            target.write_bytes(b"streamed-PGDMP")
            return ProcessResult(0)

    process = module._PinnedRecoveryProcess(host.config, Delegate(), directory)
    owner_environment = {
        **os.environ,
        "VENDOR_APP_IMAGE": host.config.target_image,
        "VENDOR_DB_BOOTSTRAP_PASSWORD": "owner-ephemeral",
    }
    argv = (str(host.config.docker_binary), "compose", "exec", "db", "pg_dump")
    if operation == "run":
        process.run(
            argv, timeout_seconds=10, env=owner_environment, stdin_path=destination
        )
    else:
        process.capture_stdout(
            argv, destination, timeout_seconds=10, env=owner_environment
        )
    assert events == [("pinned", host.config.docker_binary), (operation,)]


@pytest.mark.parametrize("failure", ["binary", "argv", "config"])
def test_v2_process_refuses_unpinned_or_nonempty_context_before_execution(
    host, monkeypatch, tmp_path, failure
):
    directory = tmp_path / "docker-config"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(
        module,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    if failure == "config":
        (directory / "config.json").write_bytes(b"unexpected context")
    if failure == "binary":
        monkeypatch.setattr(
            module, "_protected_executable_digest", lambda path: "sha256:" + "9" * 64
        )

    class Delegate:
        def run(self, *args, **kwargs):
            pytest.fail("V2 capture must refuse before process execution")

    process = module._PinnedRecoveryProcess(host.config, Delegate(), directory)
    argv = (
        ("/untrusted/docker",)
        if failure == "argv"
        else (str(host.config.docker_binary),)
    )
    with pytest.raises(ContractError):
        process.run(
            argv,
            timeout_seconds=10,
            env={
                "VENDOR_APP_IMAGE": host.config.target_image,
                "VENDOR_DB_BOOTSTRAP_PASSWORD": "owner-ephemeral",
            },
        )


@pytest.mark.parametrize("fail", [False, True])
def test_recovery_context_is_fresh_private_and_removed_after_capture(
    host, monkeypatch, tmp_path, fail
):
    backup = tmp_path / "backups"
    backup.mkdir(mode=0o700)
    host.config = replace(host.config, backup_directory=backup)
    monkeypatch.setattr(
        module,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    context = None
    try:
        with host._recovery_process("a" * 64) as process:
            context = process.docker_config
            assert context.parent == backup
            assert list(context.iterdir()) == []
            assert stat.S_IMODE(context.stat().st_mode) == 0o700
            if fail:
                raise RuntimeError("capture failed")
    except RuntimeError:
        assert fail
    assert context is not None and not context.exists()


def test_actual_v2_owner_remains_verifiable_after_private_context_is_removed(
    host, monkeypatch, tmp_path
):
    backup_directory = tmp_path / "backups"
    backup_directory.mkdir(mode=0o700)
    host_file = tmp_path / "host-id"
    host_file.write_text("cp-test")
    host.config = replace(host.config, backup_directory=backup_directory)
    monkeypatch.setattr(
        module,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )

    class CaptureTransport:
        """Synthetic PG/OCI payloads; the V2 producer/readback owner is real."""

        def capture_stdout(self, argv, destination, **kwargs):
            destination.write_bytes(
                "".join(
                    f"CREATE ROLE {role};\n" for role in module.REQUIRED_ROLES
                ).encode()
                if "pg_dumpall" in argv
                else b"PGDMP-unit-payload"
            )
            return ProcessResult(0)

        def run(self, argv, **kwargs):
            command = " ".join(argv)
            for query, value in (
                ("server_version_num", "160010"),
                ("pg_control_system", "123456789"),
                ("printf", "cp"),
                ("alembic_version", "source_head"),
            ):
                if query in command:
                    return ProcessResult(0, value)
            if "inspect" in argv:
                return ProcessResult(0, "a" * 40)
            assert "pg_restore" in argv
            return ProcessResult(0)

    host.process = CaptureTransport()
    with host._recovery_process("a" * 64) as process:
        private_directory = process.docker_config
        owner = module.PlatformCpRecoveryBundle.for_transition(
            tmp_path,
            source_descriptor=descriptor(
                host.config.source_image, "a" * 40, ["source_head"]
            ),
            target_descriptor=descriptor(
                host.config.target_image, "a" * 40, ["target_head"]
            ),
            source_image=host.config.source_image,
            source_revision="a" * 40,
            target_image=host.config.target_image,
            target_source_revision="a" * 40,
            expected_source_heads=("source_head",),
            target="cp-test",
            incumbent_roles=(("app", host.config.source_image.rsplit("@", 1)[1]),),
            host_id_file=host_file,
            backup_dir=backup_directory,
            docker_bin=str(host.config.docker_binary),
            process=process,
        )
        backup = owner.capture_transition(timeout_seconds=10)
    assert not private_directory.exists()
    monkeypatch.setattr(
        module,
        "_protected_executable_digest",
        lambda path: pytest.fail("historical verification must execute no process"),
    )
    assert owner.verify(backup)


def _app_publication(port=8100):
    published = {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}
    info = {
        "HostConfig": {"PortBindings": published},
        "NetworkSettings": {"Ports": published},
    }
    declared = {
        "ports": [
            {
                "host_ip": "127.0.0.1",
                "target": 8000,
                "published": str(port),
                "protocol": "tcp",
            }
        ]
    }
    return info, declared


def test_full_app_publication_is_exact_loopback_configured_port(host):
    info, declared = _app_publication(host.config.app_port)
    host._runtime_app_publication(info, declared)


@pytest.mark.parametrize(
    "change",
    [
        "wildcard",
        "wrong-port",
        "duplicate",
        "wrong-container-port",
        "wrong-host-config",
        "declared-wildcard",
        "declared-other-port",
    ],
)
def test_full_app_publication_refuses_other_ready_endpoints(host, change):
    info, declared = _app_publication(host.config.app_port)
    if change == "wildcard":
        info["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostIp"] = "0.0.0.0"  # noqa: S104
    elif change == "wrong-port":
        info["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostPort"] = "8101"
    elif change == "duplicate":
        info["NetworkSettings"]["Ports"]["8000/tcp"].append(
            {"HostIp": "127.0.0.1", "HostPort": "8102"}
        )
    elif change == "wrong-container-port":
        info["NetworkSettings"]["Ports"] = {
            "9000/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host.config.app_port)}]
        }
    elif change == "wrong-host-config":
        info["HostConfig"]["PortBindings"] = {}
    elif change == "declared-wildcard":
        declared["ports"][0]["host_ip"] = "0.0.0.0"  # noqa: S104 - rejected fixture
    elif change == "declared-other-port":
        declared["ports"][0]["published"] = "8101"
    with pytest.raises(ContractError, match="runtime_port_binding_mismatch"):
        host._runtime_app_publication(info, declared)


def test_full_runtime_rejects_wrong_publication_before_any_http_probe(
    host, monkeypatch
):
    info, declared = _app_publication(host.config.app_port)
    info["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostPort"] = "8101"
    info.update(
        {
            "Image": "sha256:" + "1" * 64,
            "Config": {"Labels": {"com.docker.compose.service": "app"}},
            "State": {"Running": True, "Health": {"Status": "healthy"}},
        }
    )
    host._acl_restored = True
    monkeypatch.setattr(
        host,
        "_runtime_specification",
        lambda: {"services": {"app": declared, "relay": {}}},
    )
    monkeypatch.setattr(host, "_docker", lambda *a: json.dumps([{"Id": info["Image"]}]))
    monkeypatch.setattr(host, "_writers", lambda: [info])
    monkeypatch.setattr(host, "_runtime_container_inputs", lambda *a: None)
    monkeypatch.setattr(
        host,
        "_http",
        lambda *a, **k: pytest.fail("an unrelated ready endpoint must not be probed"),
    )
    with pytest.raises(ContractError, match="runtime_port_binding_mismatch"):
        host._full_runtime(cast(CpTransitionRequestV1, {}))


@pytest.fixture
def protected_replay_files(monkeypatch):
    """Emulate root identity only; file modes and no-follow/exclusive I/O stay real."""
    protected = module._protected

    def root_owned(info, *, directory):
        values = list(info)
        values[4] = 0
        protected(os.stat_result(values), directory=directory)

    monkeypatch.setattr(module, "_protected", root_owned)
    monkeypatch.setattr(
        module,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )


def test_globals_replay_preserves_every_other_byte_and_original_artifact(
    tmp_path, protected_replay_files
):
    original = tmp_path / "globals.sql"
    replay = tmp_path / "replay.sql"
    prefix = b"-- roles\nCREATE ROLE app_admin;\n"
    suffix = (
        b"ALTER ROLE postgres WITH SUPERUSER LOGIN;\n"
        b"GRANT custom_parent TO custom_member GRANTED BY custom_grantor;\n"
    )
    raw = prefix + module._POSTGRES_CREATE + suffix
    original.write_bytes(raw)
    measured = module._write_globals_replay(original, replay)
    assert original.read_bytes() == raw
    assert replay.read_bytes() == prefix + suffix
    assert measured == (
        raw_digest(raw),
        len(raw),
        raw_digest(prefix + suffix),
        len(prefix + suffix),
    )
    assert stat.S_IMODE(replay.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "raw",
    [
        b"CREATE ROLE app_admin;\n",
        b"CREATE ROLE postgres;\nCREATE ROLE postgres;\n",
        b"CREATE ROLE postgres;\n/* collision\nCREATE ROLE postgres;\n*/\n",
        b"CREATE ROLE postgres;\nCOMMENT ON ROLE app_admin IS 'collision\n"
        b"CREATE ROLE postgres;\n';\n",
        b'CREATE ROLE "postgres";\n',
        b"CREATE ROLE postgres;\r\n",
    ],
)
def test_globals_replay_ambiguity_or_noncanonical_statement_refuses(
    tmp_path, protected_replay_files, raw
):
    original = tmp_path / "globals.sql"
    original.write_bytes(raw)
    with pytest.raises(ContractError, match="globals_replay_statement_ambiguous"):
        module._write_globals_replay(original, tmp_path / "replay.sql")
    assert original.read_bytes() == raw


def test_globals_replay_does_not_omit_a_chunk_ending_inside_a_long_line(
    tmp_path, protected_replay_files
):
    original = tmp_path / "globals.sql"
    long_line = b"--" + b"x" * (1024 * 1024 - 2) + module._POSTGRES_CREATE
    original.write_bytes(long_line + module._POSTGRES_CREATE)
    result = module._write_globals_replay(original, tmp_path / "replay.sql")
    assert (tmp_path / "replay.sql").read_bytes() == long_line
    assert result[2:] == (raw_digest(long_line), len(long_line))


@pytest.mark.parametrize(
    "bootstrap",
    [
        None,
        [],
        [["renamed", 10, True]],
        [["postgres", 11, True]],
        [["postgres", 10, False]],
        [["postgres", 10, 1]],
        [["postgres", "10", True]],
    ],
)
def test_source_bootstrap_refuses_missing_renamed_non_superuser_or_wrong_oid(
    host, bootstrap
):
    raw = canonical_json({"bootstrap": bootstrap})
    host.genesis = {"catalogue_digest": raw_digest(raw)}
    host.store = SimpleNamespace(read=lambda checksum: raw)
    with pytest.raises(ContractError, match="source_bootstrap_unsupported"):
        host._source_bootstrap()


def test_globals_replay_proof_is_small_bound_and_file_removed_after_use(
    host, tmp_path, monkeypatch, protected_replay_files
):
    host.config = replace(host.config, backup_directory=tmp_path)
    retained = {}
    monkeypatch.setattr(
        host,
        "_retain",
        lambda raw: retained.setdefault(raw_digest(raw), raw) and raw_digest(raw),
    )
    original = tmp_path / "globals.sql"
    raw = module._POSTGRES_CREATE + b"ALTER ROLE postgres WITH SUPERUSER;\n"
    original.write_bytes(raw)
    bootstrap = {"role": "postgres", "oid": 10, "superuser": True}
    request = cast(CpTransitionRequestV1, {"database": "cp"})
    with host._globals_replay(
        request, "a" * 64, original, bootstrap, bootstrap
    ) as replay:
        expected = b"ALTER ROLE postgres WITH SUPERUSER;\n"
        assert replay.read_bytes() == expected
        assert host._globals_replay_sha == raw_digest(expected)
        proof = module.read_json(retained[host._globals_replay_digest])
        assert proof["source_bootstrap"] == proof["fresh_bootstrap"] == bootstrap
        assert proof["original_digest"] == raw_digest(raw)
        assert proof["replay_digest"] == raw_digest(expected)
        assert proof["omitted_statement"] == "CREATE ROLE postgres;\n"
        assert proof["request_digest"] == module.request_digest(request)
        assert proof["host_nonce"] == "a" * 64
    assert not replay.exists()
    assert original.read_bytes() == raw
    assert len(retained) == 1  # Metadata only; no bulk globals ArtifactStore copies.


@pytest.mark.parametrize("extra", ["none", "role", "database", "bootstrap"])
def test_fresh_scratch_profile_requires_pristine_postgres_identity(extra):
    roles = ["postgres"] + (["unexpected"] if extra == "role" else [])
    databases = [
        ["postgres", False, True],
        ["template0", True, False],
        ["template1", True, True],
    ]
    if extra == "database":
        databases.append(["unexpected", False, True])
    bootstrap = [["renamed" if extra == "bootstrap" else "postgres", 10, True]]

    def execute(sql):
        statement = str(sql)
        if "SELECT rolname FROM" in statement:
            return SimpleNamespace(scalars=lambda: iter(roles))
        return databases if "datname,datistemplate" in statement else bootstrap

    connection = SimpleNamespace(execute=execute)
    if extra == "none":
        assert module.ExistingCpTransitionHost._fresh_bootstrap(connection) == {
            "role": "postgres",
            "oid": 10,
            "superuser": True,
        }
    else:
        with pytest.raises(ContractError):
            module.ExistingCpTransitionHost._fresh_bootstrap(connection)


def test_scratch_probe_refuses_changed_binary_and_still_cleans_owned_resource(
    host, tmp_path, monkeypatch
):
    nonce = "a" * 64
    commands, cleanup, probes = [], [], []
    monkeypatch.setattr(
        host,
        "_source_bootstrap",
        lambda: {"role": "postgres", "oid": 10, "superuser": True},
    )

    def docker(*argv, **kwargs):
        commands.append(argv)
        return "b" * 64 if argv[0] == "run" else ""

    monkeypatch.setattr(host, "_docker", docker)
    monkeypatch.setattr(
        module, "_protected_executable_digest", lambda path: "sha256:" + "9" * 64
    )
    monkeypatch.setattr(host, "_cleanup_scratch", lambda *args: cleanup.append(args))
    host.process = SimpleNamespace(
        run=lambda *args, **kwargs: probes.append(args) or ProcessResult(0)
    )
    request = cast(CpTransitionRequestV1, {"database": "source"})
    with pytest.raises(ContractError, match="docker_binary_mismatch"):
        host._restore_fresh(request, nonce, tmp_path, 16)
    assert commands[1][0] == "run" and not probes
    assert cleanup == [
        (f"vcp-d16-restore-{nonce[:32]}", nonce, module.request_digest(request))
    ]


@pytest.mark.parametrize("case", ["measured", "field-drift", "missing", "invalid"])
def test_restore_retains_raw_catalogues_and_requires_bound_comparison(
    host, tmp_path, monkeypatch, case
):
    source_side, _ = side(host.config.source_image)
    request = cast(
        CpTransitionRequestV1,
        {
            "host": "cp",
            "database": "cp",
            "cluster_system_identifier": "123",
            "source": source_side,
            "target": source_side,
        },
    )
    nonce = "a" * 64
    retained = {}

    def retain(raw):
        checksum = raw_digest(raw)
        retained[checksum] = raw
        return checksum

    source_catalogue = b"independent source catalogue"
    restored_catalogue = b"independent restored catalogue"
    comparison = b"measured scratch comparison"
    host.genesis = {
        "side": source_side,
        "descriptor_declarations": {},
        "database_owner": "app_admin",
        "roles": ["app_admin"],
        "catalogue_digest": retain(source_catalogue),
    }
    restored = {**host.genesis, "catalogue_digest": retain(restored_catalogue)}
    if case == "field-drift":
        restored["database_owner"] = "unexpected"
    host._globals_replay_digest = retain(b"globals proof")
    host._globals_replay_sha = raw_digest(b"replayed globals")
    # A previous attempt's proof must never satisfy the current restore.
    host._catalogue_comparison_digest = retain(b"stale comparison")
    backup = PlatformBackupResult("cp", str(tmp_path), 1, "checksum", "sha256")
    owner = SimpleNamespace(
        capture_transition=lambda **kwargs: backup, verify=lambda _: True
    )
    (tmp_path / "manifest.json").write_bytes(
        canonical_json(
            {
                "database_name": "cp",
                "cluster_system_identifier": "123",
                "postgres_major": 16,
            }
        )
    )
    monkeypatch.setattr(host, "_retain", retain)
    monkeypatch.setattr(host.store, "read", retained.__getitem__)
    monkeypatch.setattr(host, "_bound", lambda *args: None)
    monkeypatch.setattr(host, "_strict", lambda *args: None)
    monkeypatch.setattr(host, "_recovery_process", lambda _: nullcontext(object()))
    monkeypatch.setattr(
        module.PlatformCpRecoveryBundle, "for_transition", lambda *args, **kwargs: owner
    )
    monkeypatch.setattr(host, "_evidence", lambda request, nonce, stage, result: result)

    def restore(*args):
        if case != "missing":
            host._catalogue_comparison_digest = retain(comparison)
        return restored

    verified = []

    def verify(raw, **bindings):
        assert raw == comparison
        assert bindings == {
            "source_catalogue": source_catalogue,
            "restored_catalogue": restored_catalogue,
            "request_digest": module.request_digest(request),
            "host_nonce": nonce,
            "expected_source_cluster": "123",
            "expected_source_database": "cp",
        }
        verified.append(raw)
        if case == "invalid":
            raise ContractError("catalogue_comparison_refused")

    monkeypatch.setattr(host, "_restore_fresh", restore)
    monkeypatch.setattr(module, "verify_restore_comparison", verify)
    if case == "measured":
        result = host.capture_and_restore(request, nonce)
        assert result["restored_source"] == restored
        assert result["source"]["catalogue_digest"] != restored["catalogue_digest"]
        assert retained[result["restore_evidence_digest"]] == canonical_json(restored)
        assert retained[result["catalogue_comparison_digest"]] == comparison
        assert verified == [comparison]
    else:
        code = {
            "field-drift": "restore_source_mismatch",
            "missing": "catalogue_comparison_proof_missing",
            "invalid": "catalogue_comparison_refused",
        }[case]
        with pytest.raises(ContractError, match=code):
            host.capture_and_restore(request, nonce)
