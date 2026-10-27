"""The finite CP transition's Linux/root operator composition.

This is a one-shot operator, never an application server dependency. The
operator installation must supply CP's pinned Python dependencies, Docker CLI,
the reviewed maintenance helper and protected inputs. PostgreSQL tools execute
in the pinned PostgreSQL image, not in the CP application image. No standing
superuser password is created: the existing local Unix socket is required.
Installation, credential materialisation and protected-environment approval
remain the installation owners' responsibilities.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import TypedDict, cast

from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import Connection, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError

from vendor_cp.deploy_agent.contracts import (
    Envelope,
    _shape,
    canonical_json,
    read_json,
    require,
)
from vendor_cp.deploy_agent.service import DeployAgentService
from vendor_cp.deployment import candidate_roles, transition_fence
from vendor_cp.deployment.candidate_compose_inputs import (
    ALLOWED_APP_ENV_KEYS,
    DEFAULT_COMPOSE_FILE,
    DEFAULT_RUN_ROOT,
    IMAGE_REPOSITORY,
    LICENCE_KEY_HOST_FILE,
    CandidateComposeLaunch,
    build_candidate_compose_launch,
)
from vendor_cp.deployment.cp_catalogue import (
    CATALOGUE_QUERIES as _CATALOGUE_QUERIES,
)
from vendor_cp.deployment.cp_catalogue import (
    capture_restore_comparison,
    measure_catalogue,
    verify_restore_comparison,
)
from vendor_cp.deployment.cp_transition import (
    ArtifactStore,
    CommittedMigrationContext,
    CpCommittedMigrationRequestV1,
    CpFailedCandidateRequestV1,
    CpTransitionRequestV1,
    FailedCandidateContext,
    RecoveryContexts,
    SourceObservation,
    TransitionRequest,
    TransitionSideV1,
    VerifiedAuthorization,
    _open_directory,
    _protected,
    _protected_executable_digest,
    _read_protected,
    raw_digest,
    request_digest,
    verify_any_receipt,
)
from vendor_cp.deployment.descriptor_binding import source_descriptor_declarations
from vendor_cp.deployment.effects import (
    REQUIRED_ROLES,
    PlatformCpRecoveryBundle,
    ProcessExecutor,
    ProcessResult,
    SubprocessExecutor,
)
from vendor_cp.deployment.image_heads import (
    HeadsVerdict,
    compare_heads,
    read_image_document,
)
from vendor_cp.deployment.transition_evidence import (
    capture_genesis_baseline,
    read_current_migration_heads,
    read_descriptor_at_revision,
)
from vendor_cp.deployment.transition_operator import CandidateReadinessPhase
from vendor_cp.production_secrets import production_deployment_lock

SCRATCH_MAX_SOURCE_BYTES = 384 * 1024 * 1024
_SCRATCH_OWNER_LABEL = "io.dotmac.cp-transition.restore"
_SCRATCH_NONCE_LABEL = "io.dotmac.cp-transition.nonce"
_SCRATCH_REQUEST_LABEL = "io.dotmac.cp-transition.request"
EXTERNAL_READY_URL = "https://platform.dotmac.io/health/ready"
_POSTGRES_CREATE = b"CREATE ROLE postgres;\n"


def _bootstrap_identity(rows: object, *, code: str) -> dict[str, object]:
    require(
        isinstance(rows, list)
        and len(rows) == 1
        and isinstance(rows[0], list)
        and len(rows[0]) == 3,
        code,
    )
    assert isinstance(rows, list)  # noqa: S101
    row = cast(list[object], rows[0])
    require(
        type(row[0]) is str
        and row[0] == "postgres"
        and type(row[1]) is int
        and row[1] == 10
        and type(row[2]) is bool
        and row[2] is True,
        code,
    )
    return {"role": "postgres", "oid": 10, "superuser": True}


def _write_globals_replay(
    original: Path, destination: Path
) -> tuple[str, int, str, int]:
    """Stream the pinned PG16 recipe; never modify the retained original.

    Its measured postgres bootstrap necessarily emits one canonical CREATE.
    An identical line inside a comment/string makes the count ambiguous and
    refuses before any SQL execution. No whitespace, quoting or case rewriting.
    """
    with ExitStack() as opened:
        source_directory = _open_directory(original.parent)
        opened.callback(os.close, source_directory)
        target_directory = _open_directory(destination.parent)
        opened.callback(os.close, target_directory)
        source_fd = os.open(
            original.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_directory
        )
        opened.callback(os.close, source_fd)
        _protected(os.fstat(source_fd), directory=False)
        target_fd = os.open(
            destination.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=target_directory,
        )
        target = opened.enter_context(os.fdopen(target_fd, "wb"))
        _protected(os.fstat(target.fileno()), directory=False)
        before, after = hashlib.sha256(), hashlib.sha256()
        before_size = after_size = omitted = 0
        beginning = True
        with os.fdopen(source_fd, "rb", closefd=False) as source:
            while piece := source.readline(1024 * 1024):
                before.update(piece)
                before_size += len(piece)
                if beginning and piece == _POSTGRES_CREATE:
                    omitted += 1
                else:
                    target.write(piece)
                    after.update(piece)
                    after_size += len(piece)
                beginning = piece.endswith(b"\n")
        require(omitted == 1, "globals_replay_statement_ambiguous")
        target.flush()
        os.fsync(target.fileno())
        os.fsync(target_directory)
    return (
        "sha256:" + before.hexdigest(),
        before_size,
        "sha256:" + after.hexdigest(),
        after_size,
    )


class ReconnectDenial(StrEnum):
    DATABASE_ACL_DENIAL = "database_acl"


def classify_reconnect_denial(
    error: DBAPIError, *, database: str
) -> ReconnectDenial | None:
    """Classify a real kernel-connect failure without inventing a SQLSTATE.

    libpq startup failures can lose structured SQLSTATE/diagnostic fields.
    Only the exact server database/CONNECT denial is admitted in that case.
    Authentication, routing and other operational failures prove no ACL gate.
    Error text is inspected locally and never retained or returned.
    """
    original = error.orig
    if getattr(original, "sqlstate", None) not in {None, "42501"}:
        return None
    primary = f'permission denied for database "{database}"'
    detail = "User does not have CONNECT privilege."
    diagnostic = getattr(original, "diag", None)
    if diagnostic is not None and (
        getattr(diagnostic, "message_primary", None)
        or getattr(diagnostic, "message_detail", None)
    ):
        if (
            getattr(diagnostic, "message_primary", None) == primary
            and getattr(diagnostic, "message_detail", None) == detail
        ):
            return ReconnectDenial.DATABASE_ACL_DENIAL
        return None
    lines = str(original).strip().splitlines()
    if len(lines) != 2:
        return None
    # The first line may carry libpq's single-line transport context before
    # the FATAL marker. Multi-attempt/multi-error reports are not admitted.
    if re.fullmatch(
        r"(?:[^\r\n]*\bFATAL:[ \t]+)?" + re.escape(primary), lines[0]
    ) and re.fullmatch(r"DETAIL:[ \t]+" + re.escape(detail), lines[1]):
        return ReconnectDenial.DATABASE_ACL_DENIAL
    return None


class _NoProbeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        # A trusted fixed probe URL must not become an arbitrary second URL.
        return None


@contextmanager
def local_postgres_connection(
    socket: Path, database: str, role: str, *, autocommit: bool
) -> Iterator[Connection]:
    """Use the kernel's engine and existing local authentication, or refuse.

    ``socket`` is derived from a freshly inspected PostgreSQL container PID.
    There is deliberately no network/password fallback. A host whose existing
    pg_hba/namespace does not support this topology needs explicit installation
    work before it can use this operator.
    """
    require(socket.is_absolute() and socket.is_dir(), "local_postgres_unavailable")
    require(
        not any(
            os.environ.get(name)
            for name in (
                "PGPASSWORD",
                "PGPASSFILE",
                "PGSERVICE",
                "PGSERVICEFILE",
                "PGOPTIONS",
            )
        ),
        "ambient_postgres_authority_refused",
    )
    url = URL.create(
        "postgresql+psycopg",
        username=role,
        password="",
        database=database,
        query={
            "host": str(socket),
            "port": "5432",
            "connect_timeout": "5",
            "passfile": "/dev/null",
        },
    ).render_as_string(hide_password=False)
    runtime = DatabaseRuntime.from_urls(
        database_url=url,
        platform_database_url=url,
        pool_size=1,
        max_overflow=0,
        platform_pool_size=1,
        platform_max_overflow=0,
    )
    try:
        engine = runtime.platform_engine
        if autocommit:
            engine = engine.execution_options(isolation_level="AUTOCOMMIT")
        with engine.connect() as connection:
            yield connection
    finally:
        runtime.platform_engine.dispose()
        runtime.engine.dispose()


ConnectionFactory = Callable[..., AbstractContextManager[Connection]]


class _CommittedContextArguments(TypedDict, total=False):
    committed_contexts: Mapping[str, CommittedMigrationContext]
    failed_candidate_contexts: Mapping[str, FailedCandidateContext]


class _FailedReceiptArguments(TypedDict, total=False):
    failed_candidate_context: FailedCandidateContext
    failed_candidate_contexts: Mapping[str, FailedCandidateContext]


class _CandidateArguments(TypedDict):
    expected_digest: str
    expected_fence_id: str


@dataclass(frozen=True, slots=True)
class CpTransitionHostConfig:
    """Reviewed root installation policy, never fields taken from a request.

    ``connection`` may be replaced by a test's independently verified real
    connections. Production uses the kernel runtime over the existing socket.
    The operator does not materialise or read the licensing private key.
    """

    repository_root: Path
    deploy_directory: Path
    target_descriptor: Path
    source_image: str
    target_image: str
    postgres_image: str
    maintenance_helper: Path
    maintenance_helper_digest: str
    external_ready_url: str
    candidate_port: int
    docker_binary_digest: str
    git_binary: Path
    git_binary_digest: str
    host_id_file: Path = Path("/etc/dotmac-host-id")
    docker_binary: Path = Path("/usr/bin/docker")
    backup_directory: Path = Path("/opt/backups/dotmac-vendor-control-plane")
    compose_file: Path | None = None
    compose_env_file: Path | None = None
    runtime_compose_overlay: Path | None = None
    candidate_env_file: Path | None = None
    candidate_runtime_environment: Path | None = None
    licence_key_host_file: Path = LICENCE_KEY_HOST_FILE
    ready_host: str = "platform.dotmac.io"
    app_port: int = 8100
    timeout_seconds: int = 180
    session_wait_seconds: float = 30
    connection: ConnectionFactory = local_postgres_connection
    operator_revision: str | None = None

    def __post_init__(self) -> None:
        require(
            all(
                re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
                for value in (self.docker_binary_digest, self.git_binary_digest)
            ),
            "operator_tool_digest_required",
        )
        require(
            self.external_ready_url == EXTERNAL_READY_URL,
            "external_readiness_url_refused",
        )
        require(self.ready_host == "platform.dotmac.io", "readiness_host_refused")


class _PinnedRecoveryProcess:
    """Only V2 capture's pinned local Docker commands and explicit owner fields."""

    def __init__(
        self,
        config: CpTransitionHostConfig,
        delegate: ProcessExecutor,
        docker_config: Path,
    ) -> None:
        self.config = config
        self.delegate = delegate
        self.docker_config = docker_config

    def _environment(
        self, argv: Sequence[str], owner: Mapping[str, str]
    ) -> dict[str, str]:
        require(
            bool(argv) and argv[0] == str(self.config.docker_binary),
            "recovery_process_command_refused",
        )
        require(
            _protected_executable_digest(self.config.docker_binary)
            == self.config.docker_binary_digest,
            "docker_binary_mismatch",
        )
        directory = _open_directory(self.docker_config)
        try:
            require(
                stat.S_IMODE(os.fstat(directory).st_mode) == 0o700
                and not os.listdir(directory),
                "recovery_docker_config_not_empty",
            )
        finally:
            os.close(directory)
        require(
            owner.get("VENDOR_APP_IMAGE") == self.config.target_image,
            "recovery_image_binding_mismatch",
        )
        bootstrap = owner.get("VENDOR_DB_BOOTSTRAP_PASSWORD")
        require(
            isinstance(bootstrap, str)
            and bool(bootstrap)
            and not any(value in bootstrap for value in ("\n", "\r", "\x00")),
            "recovery_owner_environment_invalid",
        )
        assert isinstance(bootstrap, str)  # noqa: S101 - runtime guard above
        return {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "DOCKER_CONFIG": str(self.docker_config),
            "VENDOR_APP_IMAGE": self.config.target_image,
            "VENDOR_DB_BOOTSTRAP_PASSWORD": bootstrap,
        }

    @staticmethod
    def _result(result: ProcessResult) -> ProcessResult:
        return (
            result
            if result.ok
            else ProcessResult(
                result.exit_code, stderr="pinned Docker recovery command failed"
            )
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
        stdin_path: Path | None = None,
    ) -> ProcessResult:
        return self._result(
            self.delegate.run(
                argv,
                timeout_seconds=timeout_seconds,
                env=self._environment(argv, env),
                stdin_path=stdin_path,
            )
        )

    def capture_stdout(
        self,
        argv: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
    ) -> ProcessResult:
        return self._result(
            self.delegate.capture_stdout(
                argv,
                destination,
                timeout_seconds=timeout_seconds,
                env=self._environment(argv, env),
            )
        )


def measure_candidate_quiescence(connection: Connection) -> dict[str, object]:
    """Bounded mutation witness over one fenced database, never a sandbox.

    The caller must prove candidate backend exit before the final reading:
    PostgreSQL flushes a backend's pending tuple statistics at normal exit.
    Identity/restart/reset, relation storage, sequences and the independent
    catalogue complement those counters; counters alone are insufficient.
    """
    require(
        getattr(connection.connection.dbapi_connection, "autocommit", False) is True,
        "quiescence_autocommit_required",
    )
    require(
        connection.execute(
            text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")
        ).scalar_one()
        is True,
        "quiescence_superuser_required",
    )
    require(
        connection.execute(
            text("SELECT current_setting('track_counts')::boolean")
        ).scalar_one()
        is True,
        "quiescence_statistics_disabled",
    )
    connection.execute(text("SELECT pg_stat_clear_snapshot()"))
    reset, started = connection.execute(
        text(
            "SELECT stats_reset::text,pg_postmaster_start_time()::text "
            "FROM pg_stat_database WHERE datname=current_database()"
        )
    ).one()
    relations = [
        list(row)
        for row in connection.execute(
            text("""
        SELECT n.nspname,c.relname,c.oid::bigint,c.relfilenode::bigint,
               COALESCE(s.n_tup_ins,0),COALESCE(s.n_tup_upd,0),COALESCE(s.n_tup_del,0)
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_stat_all_tables s ON s.relid=c.oid
        WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
        ORDER BY n.nspname,c.relname
    """)
        )
    ]
    sequences = [
        list(row)
        for row in connection.execute(
            text("""
        SELECT schemaname,sequencename,last_value FROM pg_sequences
        WHERE schemaname !~ '^pg_' AND schemaname <> 'information_schema'
        ORDER BY schemaname,sequencename
    """)
        )
    ]
    return {
        "track_counts": True,
        "stats_reset": reset,
        "server_start": started,
        "relations": relations,
        "sequences": sequences,
        "catalogue_bytes": measure_catalogue(connection),
    }


@dataclass(frozen=True, slots=True)
class HeldFenceContinuation:
    """Root-loaded prior state, never an authorization for the next attempt."""

    request: CpTransitionRequestV1
    proof: transition_fence.FenceProof

    def bind(self, request: CpTransitionRequestV1, nonce: str | None = None) -> None:
        require(
            all(
                cast(dict[str, object], request)[key]
                == cast(dict[str, object], self.request)[key]
                for key in (
                    "product",
                    "environment",
                    "host",
                    "database",
                    "cluster_system_identifier",
                    "database_oid",
                    "source",
                    "previous_receipt_digest",
                )
            ),
            "held_fence_source_mismatch",
        )
        require(
            request_digest(request) != request_digest(self.request),
            "held_fence_request_reused",
        )
        require(
            (request["authorization_run_id"], request["authorization_run_attempt"])
            != (
                self.request["authorization_run_id"],
                self.request["authorization_run_attempt"],
            ),
            "held_fence_authorization_reused",
        )
        require(nonce != self.proof.fence_id, "held_fence_nonce_reused")


class ExistingCpTransitionHost:
    """Concrete measured host used by ``execute_transition``.

    Stage methods do real owner operations and return bound evidence; they do
    not accept caller-provided stage verdicts. The executor retains each stage
    and permanently consumes the request before the first host mutation.
    """

    def __init__(
        self,
        config: CpTransitionHostConfig,
        *,
        store: ArtifactStore,
        recovery: RecoveryContexts,
        process: ProcessExecutor | None = None,
        held_fence: HeldFenceContinuation | None = None,
        committed_context: CommittedMigrationContext | None = None,
        committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
        failed_candidate_context: FailedCandidateContext | None = None,
        failed_candidate_contexts: Mapping[str, FailedCandidateContext] | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.recovery = recovery
        self.process = process or SubprocessExecutor()
        require(
            sum(
                context is not None
                for context in (held_fence, committed_context, failed_candidate_context)
            )
            <= 1,
            "continuation_contexts_mutually_exclusive",
        )
        self._held_fence = held_fence
        self._committed_context = committed_context
        self._failed_candidate_context = failed_candidate_context
        self._failed_candidate_contexts = dict(failed_candidate_contexts or {})
        if failed_candidate_context is not None:
            key = failed_candidate_context.context_digest
            require(
                key not in self._failed_candidate_contexts
                or self._failed_candidate_contexts[key] is failed_candidate_context,
                "failed_candidate_context_registry_conflict",
            )
            self._failed_candidate_contexts[key] = failed_candidate_context
        self._committed_contexts = dict(committed_contexts or {})
        if committed_context is not None:
            key = committed_context.context_digest
            require(
                key not in self._committed_contexts
                or self._committed_contexts[key] is committed_context,
                "committed_context_registry_conflict",
            )
            self._committed_contexts[key] = committed_context
        self.proof = (
            failed_candidate_context.proof
            if failed_candidate_context is not None
            else committed_context.proof
            if committed_context is not None
            else held_fence.proof
            if held_fence
            else None
        )
        self.genesis: SourceObservation | None = None
        self.roles: candidate_roles.CandidateRoles | None = None
        self.launch: CandidateComposeLaunch | None = None
        self._source_descriptor = b""
        self._target_descriptor = b""
        self._request: TransitionRequest | None = None
        self._nonce: str | None = None
        self._routing_receipt: str | None = None
        self._candidate_created = False
        self._candidate_started = False
        self.candidate_phase: CandidateReadinessPhase | None = None
        self._acl_restored = False
        self._runtime_inputs: dict[Path, str] = {}
        self._candidate_profile: str | None = None
        self._candidate_quiescence_before: bytes | None = None
        self._candidate_quiescence_digest: str | None = None
        self._candidate_backends_exited = False
        self._catalogue_comparison_digest: str | None = None
        self._globals_replay_digest: str | None = None
        self._globals_replay_sha: str | None = None

    def lock(self) -> AbstractContextManager[None]:
        return production_deployment_lock()

    def _run(
        self,
        argv: Sequence[str],
        *,
        stdin: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> str:
        if argv and argv[0] == str(self.config.docker_binary):
            require(
                _protected_executable_digest(self.config.docker_binary)
                == self.config.docker_binary_digest,
                "docker_binary_mismatch",
            )
        result = self.process.run(
            argv,
            timeout_seconds=self.config.timeout_seconds,
            env=env
            or {"PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix:///var/run/docker.sock"},
            stdin_path=stdin,
        )
        # Child diagnostics can contain DSNs/environment material. Never copy
        # them into a receipt, an exception or operator output.
        require(result.ok, "transition_host_command_failed")
        return result.stdout.strip()

    def _docker(self, *argv: str, stdin: Path | None = None) -> str:
        return self._run((str(self.config.docker_binary), *argv), stdin=stdin)

    def _compose(self, *argv: str) -> str:
        config = self.config
        return self._docker(
            "compose",
            "--project-name",
            "dotmac_vendor_control_plane",
            "-f",
            str(
                config.compose_file
                or config.deploy_directory / "docker-compose.production.yml"
            ),
            "--env-file",
            str(config.compose_env_file or config.deploy_directory / ".env"),
            *argv,
        )

    def _container(self, identifier: str) -> dict[str, object]:
        documents = json.loads(self._docker("inspect", identifier))
        require(
            isinstance(documents, list) and len(documents) == 1,
            "container_identity_mismatch",
        )
        return cast(dict[str, object], documents[0])

    def _db_container(self) -> str:
        ids = self._compose("ps", "-q", "db").splitlines()
        require(len(ids) == 1 and re.fullmatch(r"[0-9a-f]{12,64}", ids[0]) is not None)
        return ids[0]

    def _socket(self, container: str) -> Path:
        info = self._container(container)
        state = cast(dict[str, object], info["State"])
        pid = state.get("Pid")
        require(
            state.get("Running") is True and type(pid) is int and pid > 1,
            "local_postgres_unavailable",
        )
        require(
            Path(f"/proc/{pid}/comm").read_text().strip() == "postgres",
            "local_postgres_unavailable",
        )
        # Resolve inside the validated container: its absolute /var/run -> /run
        # link would otherwise escape into the operator runner's /run after
        # crossing the /proc/PID/root magic link. The pinned PG image must
        # supply readlink and this one measured canonical socket directory.
        directory = self._docker(
            "exec",
            "--user",
            "postgres",
            container,
            "readlink",
            "-f",
            "/var/run/postgresql",
        )
        require(directory == "/run/postgresql", "postgres_socket_directory_mismatch")
        socket = Path(f"/proc/{pid}/root{directory}")
        require(
            socket.is_dir()
            and stat.S_ISSOCK((socket / ".s.PGSQL.5432").stat().st_mode),
            "local_postgres_unavailable",
        )
        return socket

    def _connect(
        self,
        database: str,
        role: str = "postgres",
        *,
        autocommit: bool = True,
        container: str | None = None,
    ) -> AbstractContextManager[Connection]:
        return self.config.connection(
            self._socket(container or self._db_container()),
            database,
            role,
            autocommit=autocommit,
        )

    @staticmethod
    def _identity(connection: Connection, request: TransitionRequest) -> None:
        row = connection.execute(
            text("""SELECT current_database(),d.oid,
            (SELECT system_identifier::text FROM pg_control_system())
            FROM pg_database d WHERE datname=current_database()""")
        ).one()
        require(
            tuple(row)
            == (
                request["database"],
                request["database_oid"],
                request["cluster_system_identifier"],
            ),
            "database_identity_mismatch",
        )

    def _bound(self, request: TransitionRequest, nonce: str) -> None:
        if self._held_fence is not None:
            require(request["schema"] == "dotmac.cp_transition_request/1")
            self._held_fence.bind(cast(CpTransitionRequestV1, request), nonce)
        if request.get("schema") == "dotmac.cp_committed_migration_request/1":
            require(self._committed_context is not None, "committed_context_required")
            assert self._committed_context is not None  # noqa: S101
            self._committed_binding(
                cast(CpCommittedMigrationRequestV1, request), self._committed_context
            )
        elif request.get("schema") == "dotmac.cp_failed_candidate_request/1":
            require(
                self._failed_candidate_context is not None,
                "failed_candidate_context_required",
            )
            assert self._failed_candidate_context is not None  # noqa: S101
            self._failed_candidate_binding(
                cast(CpFailedCandidateRequestV1, request),
                self._failed_candidate_context,
            )
        require(self._request == request, "host_request_mismatch")
        if self._nonce is None:
            reservation = read_json(
                self.store.read(request_digest(request), kind="reservation")
            )
            require(reservation.get("host_nonce") == nonce, "reservation_mismatch")
            self._nonce = nonce
        require(self._nonce == nonce, "host_nonce_mismatch")

    def _evidence(
        self, request: TransitionRequest, nonce: str, kind: str, result: object
    ) -> bytes:
        self._bound(request, nonce)
        return canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "request_digest": request_digest(request),
                "host_nonce": nonce,
                "kind": kind,
                "result": result,
            }
        )

    def _image(self, image: str, side: TransitionSideV1, descriptor: bytes) -> None:
        require(
            image == f"{IMAGE_REPOSITORY}@{side['image_digest']}",
            "image_identity_mismatch",
        )
        document = tomllib.loads(descriptor.decode("utf-8"))
        require(
            document.get("product") == "dotmac_vendor_control_plane"
            and document.get("environment") == "production"
            and document.get("image", {}).get("reference") == image
            and document.get("image", {}).get("source_revision") == side["revision"]
            and document.get("migration", {}).get("expected_heads") == side["heads"]
            and raw_digest(descriptor) == side["raw_descriptor_digest"],
            "descriptor_identity_mismatch",
        )
        image_info = json.loads(self._docker("image", "inspect", image))[0]
        require(
            image in image_info.get("RepoDigests", [])
            and image_info.get("Config", {})
            .get("Labels", {})
            .get("org.opencontainers.image.revision")
            == side["revision"],
            "image_identity_mismatch",
        )
        # docker create never starts an entrypoint/runtime role.
        container = self._docker(
            "create", "--network", "none", "--entrypoint", "/bin/false", image
        )
        require(re.fullmatch(r"[0-9a-f]{64}", container) is not None)
        try:
            with tempfile.TemporaryDirectory(
                prefix="cp-transition-image-"
            ) as directory:
                destination = Path(directory) / "migration_heads.json"
                self._docker(
                    "cp", f"{container}:/app/migration_heads.json", str(destination)
                )
                verdict = compare_heads(
                    image_document=read_image_document(destination),
                    descriptor_heads=side["heads"],
                    expected_source_revision=side["revision"],
                )
                require(verdict == HeadsVerdict.MATCHED, "image_heads_mismatch")
        finally:
            self._docker("rm", "-v", container)

    def _writers(self) -> list[dict[str, object]]:
        ids = self._docker(
            "ps",
            "-aq",
            "--filter",
            "label=com.docker.compose.project=dotmac_vendor_control_plane",
        ).splitlines()
        writers = []
        for identifier in ids:
            info = self._container(identifier)
            config = cast(dict[str, object], info["Config"])
            labels = cast(dict[str, str], config.get("Labels", {}))
            service = labels.get("com.docker.compose.service")
            if service in {"db", "redis", "manifest-init"}:
                continue
            require(service in {"app", "relay", "ops"}, "unknown_cp_writer")
            writers.append(info)
        return writers

    def _source_image_identity(self, image: str, side: TransitionSideV1) -> str:
        """Measure the incumbent OCI identity without requiring newer metadata.

        Historical descriptors record separate deployment events and can lag
        the running image or database. Legacy images predate the embedded head
        document. Neither fact permits substituting an unverified OCI image.
        """
        require(
            image == f"{IMAGE_REPOSITORY}@{side['image_digest']}",
            "image_identity_mismatch",
        )
        documents = json.loads(self._docker("image", "inspect", image))
        require(
            isinstance(documents, list) and len(documents) == 1,
            "image_identity_mismatch",
        )
        info = documents[0]
        require(
            image in info.get("RepoDigests", [])
            and info.get("Config", {})
            .get("Labels", {})
            .get("org.opencontainers.image.revision")
            == side["revision"]
            and re.fullmatch(r"sha256:[0-9a-f]{64}", str(info.get("Id"))) is not None,
            "image_identity_mismatch",
        )
        return cast(str, info["Id"])

    def _source_matches(self, request: CpTransitionRequestV1) -> None:
        source_id = self._source_image_identity(
            self.config.source_image, request["source"]
        )
        # The Git revision has just been independently bound to the exact
        # incumbent OCI label. Preserve its actual descriptor declarations.
        descriptor = read_descriptor_at_revision(
            self.config.repository_root,
            request["source"]["revision"],
            git_binary=self.config.git_binary,
            git_binary_digest=self.config.git_binary_digest,
        )
        require(
            raw_digest(descriptor) == request["source"]["raw_descriptor_digest"],
            "source_descriptor_digest_mismatch",
        )
        source_descriptor_declarations(descriptor)
        require(
            not self._source_descriptor or descriptor == self._source_descriptor,
            "source_descriptor_changed",
        )
        self._source_descriptor = descriptor
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            _bootstrap_identity(
                [
                    list(row)
                    for row in connection.execute(text(_CATALOGUE_QUERIES["bootstrap"]))
                ],
                code="source_bootstrap_unsupported",
            )
            require(
                int(
                    connection.execute(
                        text("SELECT pg_database_size(current_database())")
                    ).scalar_one()
                )
                <= SCRATCH_MAX_SOURCE_BYTES,
                "source_exceeds_reviewed_scratch_capacity",
            )
            require(
                list(read_current_migration_heads(connection))
                == request["source"]["heads"],
                "source_heads_mismatch",
            )
        writers = self._writers()
        require(bool(writers), "incumbent_missing")
        for info in writers:
            # An already stopped incumbent is a valid measured baseline. Its
            # exact immutable image still has to be the admitted source.
            require(info.get("Image") == source_id, "incumbent_image_mismatch")

    def _inspect_installation(self, request: TransitionRequest) -> None:
        require(
            sys.platform == "linux" and os.geteuid() == 0,
            "root_linux_operator_required",
        )
        config = self.config
        require(
            config.docker_binary.is_absolute()
            and config.docker_binary.is_file()
            and os.access(config.docker_binary, os.X_OK),
            "docker_cli_required",
        )
        require(
            raw_digest(_read_protected(config.maintenance_helper))
            == config.maintenance_helper_digest,
            "maintenance_helper_mismatch",
        )
        require(
            _read_protected(config.host_id_file).decode().strip() == request["host"],
            "host_identity_mismatch",
        )
        for directory_path in (
            config.deploy_directory,
            config.backup_directory,
            self.store.root,
        ):
            descriptor = _open_directory(directory_path)
            os.close(descriptor)
        for path in (
            config.compose_file
            or config.deploy_directory / "docker-compose.production.yml",
            config.compose_env_file or config.deploy_directory / ".env",
            config.runtime_compose_overlay,
        ):
            if path is not None:
                self._runtime_inputs[path] = raw_digest(_read_protected(path))
        require(
            re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", config.postgres_image) is not None,
            "postgres_image_not_pinned",
        )

    def inspect(self, request: CpTransitionRequestV1) -> bytes:
        if self._held_fence is not None:
            self._held_fence.bind(request)
        self._inspect_installation(request)
        config = self.config
        # Admission precedes even disposable image-inspection containers and
        # the executor's new reservation, as well as all transition mutations.
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            self._check_fence_baseline(connection, request)
            candidate_roles.require_planned_target_only_connect(
                connection, database=request["database"]
            )
        self._docker("image", "inspect", config.postgres_image)
        self._target_descriptor = _read_protected(config.target_descriptor)
        self._image(config.target_image, request["target"], self._target_descriptor)
        self._source_matches(request)
        self._request = request
        return canonical_json(
            {"source": request["source"], "target": request["target"]}
        )

    def _committed_binding(
        self,
        request: CpCommittedMigrationRequestV1,
        context: CommittedMigrationContext,
    ) -> None:
        require(
            self._held_fence is None and self._committed_context is context,
            "committed_context_mismatch",
        )
        require(
            self.config.operator_revision is not None
            and self.config.operator_revision == request["operator_revision"],
            "operator_revision_mismatch",
        )
        require(
            request["basis"]["context_digest"] == context.context_digest
            and request["basis"]["current_fence_digest"] == context.proof.digest()
            and request["basis"]["current_fence_id"] == context.proof.fence_id
            and request["basis"]["original_fence_digest"]
            == context.original_proof.digest(),
            "committed_fence_basis_mismatch",
        )
        require(
            request["source"] == context.request["source"]
            and request["target"] == context.request["target"]
            and all(
                cast(Mapping[str, object], request)[key]
                == cast(Mapping[str, object], context.request)[key]
                for key in (
                    "host",
                    "database",
                    "database_oid",
                    "cluster_system_identifier",
                )
            ),
            "committed_identity_mismatch",
        )
        require(
            context.proof.prior_grants == context.original_proof.prior_grants,
            "committed_original_grants_mismatch",
        )

    def _failed_candidate_binding(
        self,
        request: CpFailedCandidateRequestV1,
        context: FailedCandidateContext,
    ) -> None:
        require(
            self._held_fence is None
            and self._committed_context is None
            and self._failed_candidate_context is context,
            "failed_candidate_context_mismatch",
        )
        require(
            self.config.operator_revision is not None
            and self.config.operator_revision == request["operator_revision"],
            "operator_revision_mismatch",
        )
        require(
            request["basis"]["context_digest"] == context.context_digest
            and request["basis"]["current_fence_digest"] == context.proof.digest()
            and request["basis"]["current_fence_id"] == context.proof.fence_id
            and request["basis"]["original_fence_digest"]
            == context.original_proof.digest(),
            "failed_candidate_fence_basis_mismatch",
        )
        historical = context.original.request
        require(
            request["source"] == historical["source"]
            and request["target"] == historical["target"]
            and all(
                cast(Mapping[str, object], request)[key]
                == cast(Mapping[str, object], historical)[key]
                for key in (
                    "host",
                    "database",
                    "database_oid",
                    "cluster_system_identifier",
                )
            ),
            "failed_candidate_identity_mismatch",
        )
        require(
            context.proof.prior_grants == context.original_proof.prior_grants
            and context.proof.prior_acl == context.original_proof.prior_acl,
            "failed_candidate_original_grants_mismatch",
        )

    def _failed_candidate_admission(
        self,
        request: CpFailedCandidateRequestV1,
        context: FailedCandidateContext,
    ) -> None:
        self._failed_candidate_binding(request, context)
        self._continuation_admission(
            request, context, historical=context.original.request
        )

    @staticmethod
    def _check_committed_measurement(
        request: CpCommittedMigrationRequestV1 | CpFailedCandidateRequestV1,
        context: CommittedMigrationContext | FailedCandidateContext,
        measurement: dict[str, object],
    ) -> None:
        measurement = dict(measurement)
        catalogue = cast(bytes, measurement.pop("catalogue_bytes"))
        measurement["catalogue_digest"] = raw_digest(catalogue)
        require(
            canonical_json(measurement) == canonical_json(context.measurement)
            and raw_digest(canonical_json(measurement))
            == request["basis"]["frontier_measurement_digest"],
            "committed_measurement_drift",
        )

    def _committed_admission(
        self,
        request: CpCommittedMigrationRequestV1,
        context: CommittedMigrationContext,
    ) -> None:
        """Only current-state reads; historical source six is never reobserved."""
        self._committed_binding(request, context)
        self._continuation_admission(request, context, historical=context.request)

    def _continuation_admission(
        self,
        request: CpCommittedMigrationRequestV1 | CpFailedCandidateRequestV1,
        context: CommittedMigrationContext | FailedCandidateContext,
        *,
        historical: CpTransitionRequestV1,
    ) -> None:
        require(self.proof == context.proof, "committed_current_fence_mismatch")
        self._http(self.config.external_ready_url, expected=503)
        # The early forecast must precede every image/candidate/fence mutation.
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            self._check_fence_baseline(connection, request)
            candidate_roles.require_planned_target_only_connect(
                connection, database=request["database"]
            )
            require(
                list(read_current_migration_heads(connection))
                == historical["target"]["heads"],
                "committed_target_heads_mismatch",
            )
            require(
                not connection.execute(
                    text(
                        "SELECT rolname FROM pg_roles WHERE "
                        "left(rolname,8)='vcp_d16_'"
                    )
                ).all(),
                "committed_candidate_roles_present",
            )
            require(
                not connection.execute(
                    text(
                        "SELECT pid FROM pg_stat_activity WHERE "
                        "left(usename,8)='vcp_d16_'"
                    )
                ).all(),
                "committed_candidate_sessions_present",
            )
            measurement = measure_candidate_quiescence(connection)
        self._check_committed_measurement(request, context, measurement)
        descriptor = _read_protected(self.config.target_descriptor)
        require(
            raw_digest(descriptor) == request["target"]["raw_descriptor_digest"],
            "committed_target_descriptor_mismatch",
        )
        self._target_descriptor = descriptor
        self._source_image_identity(self.config.target_image, request["target"])
        incumbent = self._source_image_identity(
            self.config.source_image, historical["source"]
        )
        writers = self._writers()
        require(bool(writers), "incumbent_missing")
        for info in writers:
            require(info.get("Image") == incumbent, "incumbent_image_mismatch")
            require(
                cast(dict[str, object], info["State"])["Running"] is False
                and cast(
                    dict[str, object],
                    cast(dict[str, object], info["HostConfig"])["RestartPolicy"],
                )["Name"]
                == "no",
                "writer_stop_unproved",
            )
        # Include stopped resources: no prior candidate may be reused silently.
        require(
            not self._docker("ps", "-aq", "--filter", "name=vcp-d16-"),
            "committed_candidate_containers_present",
        )
        # Compose labels survive a privileged container rename.
        for identifier in self._docker(
            "ps", "-aq", "--filter", "label=com.docker.compose.project"
        ).splitlines():
            info = self._container(identifier)
            labels = cast(
                dict[str, str],
                cast(dict[str, object], info["Config"]).get("Labels", {}),
            )
            require(
                not labels.get("com.docker.compose.project", "").startswith("vcp-d16-"),
                "committed_candidate_containers_present",
            )
        self._strict(request)

    def inspect_committed(
        self,
        request: CpCommittedMigrationRequestV1,
        context: CommittedMigrationContext,
    ) -> bytes:
        self._inspect_installation(request)
        self._committed_admission(request, context)
        self._request = request
        return canonical_json(
            {"source": request["source"], "target": request["target"]}
        )

    def rebind_committed(
        self,
        request: CpCommittedMigrationRequestV1,
        nonce: str,
        context: CommittedMigrationContext,
    ) -> bytes:
        self._bound(request, nonce)
        require(nonce != context.proof.fence_id, "committed_nonce_reused")
        # Core owns the durable single-use prior-frontier claim under lock.
        # A FenceProof ID is not a server-stored compare-and-swap token.
        self._committed_admission(request, context)
        return self._rebind_continuation(
            request, nonce, context, kind="committed-rebound"
        )

    def inspect_failed_candidate(
        self,
        request: CpFailedCandidateRequestV1,
        context: FailedCandidateContext,
    ) -> bytes:
        self._inspect_installation(request)
        self._failed_candidate_admission(request, context)
        self._request = request
        return canonical_json(
            {"source": request["source"], "target": request["target"]}
        )

    def rebind_failed_candidate(
        self,
        request: CpFailedCandidateRequestV1,
        nonce: str,
        context: FailedCandidateContext,
    ) -> bytes:
        self._bound(request, nonce)
        require(nonce != context.proof.fence_id, "failed_candidate_nonce_reused")
        self._failed_candidate_admission(request, context)
        return self._rebind_continuation(
            request, nonce, context, kind="failed-candidate-rebound"
        )

    def _rebind_continuation(
        self,
        request: CpCommittedMigrationRequestV1 | CpFailedCandidateRequestV1,
        nonce: str,
        context: CommittedMigrationContext | FailedCandidateContext,
        *,
        kind: str,
    ) -> bytes:
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            self._check_fence_baseline(connection, request)
            candidate_roles.require_planned_target_only_connect(
                connection, database=request["database"]
            )
            require(
                list(read_current_migration_heads(connection))
                == request["target"]["heads"],
                "committed_target_heads_mismatch",
            )
            self._check_committed_measurement(
                request, context, measure_candidate_quiescence(connection)
            )
            self.proof = transition_fence.fence_writers(
                connection,
                database=request["database"],
                fence_id=nonce,
                session_wait_seconds=self.config.session_wait_seconds,
                prior=context.proof,
                expected_prior_fence_id=context.proof.fence_id,
            )
        self.store.put(canonical_json(self.proof.to_document()))
        self._strict(request)
        return self._evidence(
            request,
            nonce,
            kind,
            {
                "prior_fence_id": context.proof.fence_id,
                "fence_id": nonce,
                "original_fence_digest": request["basis"]["original_fence_digest"],
                "current_fence_digest": request["basis"]["current_fence_digest"],
            },
        )

    def _maintenance(self) -> None:
        require(
            raw_digest(_read_protected(self.config.maintenance_helper))
            == self.config.maintenance_helper_digest,
            "maintenance_helper_mismatch",
        )
        # The existing helper proves nginx reload, public 503 and drained old
        # HTTP/WebSocket workers before its successful return.
        self._run((str(self.config.maintenance_helper), "maintenance-on"))
        self._http(self.config.external_ready_url, expected=503)

    def _http(
        self,
        url: str,
        *,
        expected: int | tuple[int, ...],
        ready: bool = False,
        ledger: bool = False,
    ) -> None:
        require(
            url
            in {
                EXTERNAL_READY_URL,
                f"http://127.0.0.1:{self.config.app_port}/health/ready",
                f"http://127.0.0.1:{self.config.candidate_port}/health/ready",
                self._ledger_probe_url(),
            },
            "unsafe_readiness_url",
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoProbeRedirect()
        )
        headers = (
            {"Host": self.config.ready_host}
            if url.startswith("http://127.0.0.1:")
            else {}
        )
        request = urllib.request.Request(url, headers=headers)  # noqa: S310 - http(s)
        try:
            response = opener.open(request, timeout=5)  # noqa: S310 - validated http(s)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            require(
                response.status
                in (expected if isinstance(expected, tuple) else (expected,))
                and response.url == url,
                "readiness_failed",
            )
            body = response.read(65537)
            require(len(body) <= 65536, "readiness_response_too_large")
            if ready:
                require(read_json(body).get("ready") is True, "readiness_failed")
            if ledger:
                value = read_json(body)
                if response.status == 404:
                    require(
                        value == {"detail": "desired_state_absent"},
                        "ledger_runtime_not_ready",
                    )
                else:
                    _shape(value, Envelope)

    def maintenance(self, request: CpTransitionRequestV1, nonce: str) -> bytes:
        self._bound(request, nonce)
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            self._check_fence_baseline(connection, request)
        self._maintenance()
        return self._evidence(
            request,
            nonce,
            "maintenance",
            {"external_status": 503, "active_http": 0, "active_websockets": 0},
        )

    def _strict(self, request: TransitionRequest) -> transition_fence.FenceProof:
        require(self.proof is not None, "fence_missing")
        assert self.proof is not None  # noqa: S101 - require above is runtime guard
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            require(
                transition_fence.fence_is_holding(connection, self.proof),
                "fence_not_holding",
            )
        self._negative_reconnect(request)
        return self.proof

    def _negative_reconnect(self, request: TransitionRequest) -> None:
        require(self.proof is not None, "fence_missing")
        assert self.proof is not None  # noqa: S101 - require above is runtime guard
        for role in (*self.proof.fenced_roles, *self.proof.member_roles):
            try:
                with self._connect(request["database"], role):
                    require(False, "writer_reconnected")
            except DBAPIError as error:
                require(
                    classify_reconnect_denial(error, database=request["database"])
                    is ReconnectDenial.DATABASE_ACL_DENIAL,
                    "negative_reconnect_unproved",
                )

    def fence_and_negative_reconnect(
        self, request: CpTransitionRequestV1, nonce: str
    ) -> bytes:
        self._bound(request, nonce)
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            self._check_fence_baseline(connection, request)
            self.proof = transition_fence.fence_writers(
                connection,
                database=request["database"],
                fence_id=nonce,
                session_wait_seconds=self.config.session_wait_seconds,
                prior=self.proof,
                expected_prior_fence_id=self.proof.fence_id if self.proof else None,
            )
        self.store.put(canonical_json(self.proof.to_document()))
        self._strict(request)
        return self._evidence(
            request,
            nonce,
            "strict-fence-reconnect",
            {
                "database": request["database"],
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
        )

    def _check_fence_baseline(
        self, connection: Connection, request: TransitionRequest
    ) -> None:
        """Read-only admission; never capture a held ACL as a fresh baseline."""
        if self.proof is None:
            blocked = connection.execute(
                text(
                    "SELECT rolname FROM pg_roles WHERE rolname = ANY(:writers) "
                    "AND NOT has_database_privilege(rolname, :database, 'CONNECT')"
                ),
                {
                    "writers": list(transition_fence.WRITER_ROLES),
                    "database": request["database"],
                },
            ).all()
            require(not blocked, "held_fence_context_required")
            return
        proof = self.proof
        require(proof.database == request["database"], "held_fence_database_mismatch")
        require(
            transition_fence.fence_is_holding(connection, proof),
            "held_fence_not_holding",
        )
        # Compare the server-decomposed ACL, including grantors/options. The
        # public fence owner alone performs revocation, rebind and restoration.
        live = frozenset(
            tuple(row)
            for row in connection.execute(
                text(
                    "SELECT COALESCE(g.rolname, ''), a.privilege_type, "
                    "a.is_grantable, grantor.rolname FROM pg_database d, "
                    "aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a "
                    "LEFT JOIN pg_roles g ON g.oid=a.grantee "
                    "JOIN pg_roles grantor ON grantor.oid=a.grantor "
                    "WHERE d.datname=:database"
                ),
                {"database": request["database"]},
            )
        )
        revoked = {"", *proof.fenced_roles, *proof.member_roles}
        expected = frozenset(
            grant
            for grant in proof.prior_grants
            if not (grant[0] in revoked and grant[1] == "CONNECT")
        )
        require(live == expected, "held_fence_acl_drift")

    def stop_and_drain_writers(
        self, request: CpTransitionRequestV1, nonce: str
    ) -> bytes:
        self._bound(request, nonce)
        self._strict(request)
        for info in self._writers():
            identifier = str(info["Id"])
            self._docker("update", "--restart=no", identifier)
            self._docker("stop", "--time", "30", identifier)
        for info in self._writers():
            require(
                cast(dict[str, object], info["State"])["Running"] is False
                and cast(
                    dict[str, object],
                    cast(dict[str, object], info["HostConfig"])["RestartPolicy"],
                )["Name"]
                == "no",
                "writer_stop_unproved",
            )
        self._strict(request)
        return self._evidence(
            request,
            nonce,
            "writers-stopped",
            {"running_writers": [], "restart_enabled": []},
        )

    def _observe(
        self,
        connection: Connection,
        side: TransitionSideV1,
    ) -> SourceObservation:
        require(
            list(read_current_migration_heads(connection)) == side["heads"],
            "observed_heads_mismatch",
        )
        owner = connection.execute(
            text(
                "SELECT pg_get_userbyid(datdba) FROM pg_database "
                "WHERE datname=current_database()"
            )
        ).scalar_one()
        roles = list(
            connection.execute(
                text(
                    "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' "
                    "ORDER BY rolname"
                ),
            ).scalars()
        )
        require(
            owner == "app_admin" and set(REQUIRED_ROLES) <= set(roles),
            "source_role_owner_mismatch",
        )
        descriptor = self._source_descriptor or self.store.read(
            side["raw_descriptor_digest"]
        )
        require(
            raw_digest(descriptor) == side["raw_descriptor_digest"],
            "source_descriptor_digest_mismatch",
        )
        return {
            "side": side,
            "descriptor_declarations": source_descriptor_declarations(descriptor),
            "database_owner": owner,
            "roles": roles,
            "catalogue_digest": self._retain(measure_catalogue(connection)),
        }

    def _retain(self, raw: bytes) -> str:
        checksum = raw_digest(raw)
        # Content-addressed evidence may be identical on independent reads.
        try:
            require(self.store.read(checksum) == raw, "artifact_digest_mismatch")
        except FileNotFoundError:
            return self.store.put(raw)
        return checksum

    def source_genesis(self, request: CpTransitionRequestV1, nonce: str) -> bytes:
        self._bound(request, nonce)
        self._strict(request)
        self._source_matches(request)
        with self._connect(request["database"]) as connection:
            baseline = capture_genesis_baseline(
                connection,
                repo_root=self.config.repository_root,
                source_revision=request["source"]["revision"],
                git_binary=self.config.git_binary,
                git_binary_digest=self.config.git_binary_digest,
            )
            require(
                baseline.descriptor_bytes == self._source_descriptor
                and list(baseline.migration_heads) == request["source"]["heads"],
                "genesis_source_mismatch",
            )
            self._retain(baseline.descriptor_bytes)
            self._retain(self._target_descriptor)
            self.genesis = self._observe(connection, request["source"])
        return self._evidence(request, nonce, "source-genesis", self.genesis)

    def capture_and_restore(self, request: CpTransitionRequestV1, nonce: str) -> bytes:
        self._catalogue_comparison_digest = None
        self._bound(request, nonce)
        self._strict(request)
        require(self.genesis is not None, "genesis_missing")
        assert self.genesis is not None  # noqa: S101
        config = self.config
        with self._recovery_process(nonce) as process:
            owner = PlatformCpRecoveryBundle.for_transition(
                config.deploy_directory,
                source_descriptor=self._source_descriptor,
                target_descriptor=self._target_descriptor,
                source_image=config.source_image,
                source_revision=request["source"]["revision"],
                target_image=config.target_image,
                target_source_revision=request["target"]["revision"],
                expected_source_heads=tuple(request["source"]["heads"]),
                target=request["host"],
                incumbent_roles=[
                    ("app", request["source"]["image_digest"]),
                    ("relay", request["source"]["image_digest"]),
                ],
                host_id_file=config.host_id_file,
                compose_file=config.compose_file,
                env_file=config.compose_env_file,
                backup_dir=config.backup_directory,
                docker_bin=str(config.docker_binary),
                process=process,
            )
            backup = owner.capture_transition(timeout_seconds=config.timeout_seconds)
            require(owner.verify(backup), "recovery_owner_refused")
        # RecoveryContexts is shared with the core verifier, never reconstructed
        # from a receipt's claimed digests. Installation supplies a mutable dict.
        if not isinstance(self.recovery, dict):
            raise RuntimeError("mutable recovery context required")
        self.recovery[request_digest(request)] = (owner, backup)
        self._retain(
            canonical_json(
                {
                    "schema": "dotmac.cp_transition_recovery_capture/1",
                    "request_digest": request_digest(request),
                    "backup": asdict(backup),
                }
            )
        )
        root = Path(backup.path)
        manifest_raw = (root / "manifest.json").read_bytes()
        manifest = read_json(manifest_raw)
        require(
            manifest.get("database_name") == request["database"]
            and manifest.get("cluster_system_identifier")
            == request["cluster_system_identifier"],
            "recovery_database_mismatch",
        )
        restored = self._restore_fresh(
            request, nonce, root, cast(int, manifest["postgres_major"])
        )
        require(
            {key: value for key, value in restored.items() if key != "catalogue_digest"}
            == {
                key: value
                for key, value in self.genesis.items()
                if key != "catalogue_digest"
            },
            "restore_source_mismatch",
        )
        require(
            self._catalogue_comparison_digest is not None,
            "catalogue_comparison_proof_missing",
        )
        assert self._catalogue_comparison_digest is not None  # noqa: S101
        verify_restore_comparison(
            self.store.read(self._catalogue_comparison_digest),
            source_catalogue=self.store.read(self.genesis["catalogue_digest"]),
            restored_catalogue=self.store.read(restored["catalogue_digest"]),
            request_digest=request_digest(request),
            host_nonce=nonce,
            expected_source_cluster=request["cluster_system_identifier"],
            expected_source_database=request["database"],
        )
        require(owner.verify(backup), "recovery_changed_during_restore")
        require(
            self._globals_replay_digest is not None
            and self._globals_replay_sha is not None,
            "globals_replay_proof_missing",
        )
        return self._evidence(
            request,
            nonce,
            "recovery-restored",
            {
                "source": self.genesis,
                "restored_source": restored,
                "restore_evidence_digest": self._retain(canonical_json(restored)),
                "manifest_digest": self._retain(manifest_raw),
                "manifest_size": len(manifest_raw),
                "dump_digest": backup.database_dump_sha256,
                "globals_digest": backup.globals_sha256,
                "dump_size": backup.database_dump_size_bytes,
                "globals_size": backup.globals_size_bytes,
                "globals_replay_digest": self._globals_replay_digest,
                "catalogue_comparison_digest": self._catalogue_comparison_digest,
                "restored_dump_digest": backup.database_dump_sha256,
                "restored_globals_digest": self._globals_replay_sha,
            },
        )

    @contextmanager
    def _recovery_process(self, nonce: str) -> Iterator[_PinnedRecoveryProcess]:
        require(re.fullmatch(r"[0-9a-f]{64}", nonce) is not None, "host_nonce_mismatch")
        directory = _open_directory(self.config.backup_directory)
        os.close(directory)
        with tempfile.TemporaryDirectory(
            prefix=f".cp-docker-{nonce[:16]}-", dir=self.config.backup_directory
        ) as root:
            yield _PinnedRecoveryProcess(self.config, self.process, Path(root))

    def _restore_fresh(
        self,
        request: CpTransitionRequestV1,
        nonce: str,
        root: Path,
        postgres_major: int,
    ) -> SourceObservation:
        self._catalogue_comparison_digest = None
        name = f"vcp-d16-restore-{nonce[:32]}"
        bootstrap = "postgres"
        source_bootstrap = self._source_bootstrap()
        self._globals_replay_digest = self._globals_replay_sha = None
        require(postgres_major == 16, "scratch_postgres_profile_unsupported")
        checksum = request_digest(request)
        # Refuse an existing name before entering cleanup ownership. After a
        # lost Docker acknowledgement, find only our exact labelled resource.
        require(
            not self._docker("ps", "-aq", "--filter", f"name=^/{name}$"),
            "scratch_name_already_exists",
        )
        try:
            container = self._docker(
                "run",
                "-d",
                "--name",
                name,
                "--label",
                f"{_SCRATCH_OWNER_LABEL}=1",
                "--label",
                f"{_SCRATCH_NONCE_LABEL}={nonce}",
                "--label",
                f"{_SCRATCH_REQUEST_LABEL}={checksum}",
                "--network",
                "none",
                "--pull",
                "never",
                "--memory",
                "1g",
                "--memory-swap",
                "1g",
                "--cpus",
                "1",
                "--pids-limit",
                "128",
                "--tmpfs",
                "/var/lib/postgresql/data:rw,nosuid,size=512m",
                "--tmpfs",
                "/var/run/postgresql:rw,nosuid,size=8m",
                "-e",
                f"POSTGRES_USER={bootstrap}",
                "-e",
                "POSTGRES_DB=postgres",
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                self.config.postgres_image,
            )
            require(
                re.fullmatch(r"[0-9a-f]{64}", container) is not None,
                "scratch_container_identity_mismatch",
            )
            deadline = time.monotonic() + 60
            while True:
                require(
                    _protected_executable_digest(self.config.docker_binary)
                    == self.config.docker_binary_digest,
                    "docker_binary_mismatch",
                )
                result = self.process.run(
                    (
                        str(self.config.docker_binary),
                        "exec",
                        container,
                        "pg_isready",
                        "-h",
                        "127.0.0.1",
                        "-U",
                        bootstrap,
                    ),
                    timeout_seconds=5,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "DOCKER_HOST": "unix:///var/run/docker.sock",
                    },
                )
                if result.ok:
                    break
                require(time.monotonic() < deadline, "scratch_postgres_not_ready")
                time.sleep(0.25)
            with self._connect(
                "postgres", bootstrap, container=container
            ) as connection:
                require(
                    int(
                        connection.execute(text("SHOW server_version_num")).scalar_one()
                    )
                    // 10000
                    == postgres_major,
                    "scratch_postgres_major_mismatch",
                )
                require(
                    connection.execute(
                        text("SELECT system_identifier::text FROM pg_control_system()")
                    ).scalar_one()
                    != request["cluster_system_identifier"],
                    "scratch_is_source_cluster",
                )
                fresh_bootstrap = self._fresh_bootstrap(connection)
            base = ("exec", "-i", "--user", "postgres", container)
            with self._globals_replay(
                request, nonce, root / "globals.sql", source_bootstrap, fresh_bootstrap
            ) as replay:
                self._docker(
                    *base,
                    "psql",
                    "-X",
                    "--set",
                    "ON_ERROR_STOP=1",
                    "--username",
                    bootstrap,
                    "--dbname",
                    "postgres",
                    stdin=replay,
                )
            # Quoting is performed by PostgreSQL's public dialect, not string
            # interpolation of arbitrary request text into shell commands.
            with self._connect(
                "postgres", bootstrap, container=container
            ) as connection:
                database = connection.dialect.identifier_preparer.quote(
                    request["database"]
                )
                connection.exec_driver_sql(
                    f"CREATE DATABASE {database} OWNER app_admin TEMPLATE template0"
                )
            self._docker(
                *base,
                "pg_restore",
                "--exit-on-error",
                "--username",
                bootstrap,
                "--dbname",
                request["database"],
                stdin=root / "database.dump",
            )
            with self._connect(
                request["database"], bootstrap, container=container, autocommit=False
            ) as connection:
                with connection.begin():
                    observation = self._observe(connection, request["source"])
                    require(self.genesis is not None, "genesis_missing")
                    assert self.genesis is not None  # noqa: S101
                    comparison = capture_restore_comparison(
                        connection,
                        source_catalogue=self.store.read(
                            self.genesis["catalogue_digest"]
                        ),
                        restored_catalogue=self.store.read(
                            observation["catalogue_digest"]
                        ),
                        request_digest=checksum,
                        host_nonce=nonce,
                        expected_source_cluster=request["cluster_system_identifier"],
                        expected_source_database=request["database"],
                    )
                    self._catalogue_comparison_digest = self._retain(comparison)
                return observation
        finally:
            self._cleanup_scratch(name, nonce, checksum)

    def _source_bootstrap(self) -> dict[str, object]:
        require(self.genesis is not None, "genesis_missing")
        assert self.genesis is not None  # noqa: S101
        catalogue = read_json(self.store.read(self.genesis["catalogue_digest"]))
        return _bootstrap_identity(
            catalogue.get("bootstrap"), code="source_bootstrap_unsupported"
        )

    @staticmethod
    def _fresh_bootstrap(connection: Connection) -> dict[str, object]:
        roles = list(
            connection.execute(
                text(
                    "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' "
                    "ORDER BY rolname"
                )
            ).scalars()
        )
        databases = [
            list(row)
            for row in connection.execute(
                text(
                    "SELECT datname,datistemplate,datallowconn FROM pg_database "
                    "ORDER BY datname"
                )
            )
        ]
        require(
            roles == ["postgres"]
            and databases
            == [
                ["postgres", False, True],
                ["template0", True, False],
                ["template1", True, True],
            ],
            "scratch_not_fresh",
        )
        bootstrap = [
            list(row)
            for row in connection.execute(
                text("SELECT rolname,oid::bigint,rolsuper FROM pg_roles WHERE oid=10")
            )
        ]
        return _bootstrap_identity(bootstrap, code="scratch_bootstrap_mismatch")

    @contextmanager
    def _globals_replay(
        self,
        request: CpTransitionRequestV1,
        nonce: str,
        original: Path,
        source_bootstrap: dict[str, object],
        fresh_bootstrap: dict[str, object],
    ) -> Iterator[Path]:
        directory = _open_directory(self.config.backup_directory)
        os.close(directory)
        with tempfile.TemporaryDirectory(
            prefix=f".cp-globals-{nonce[:16]}-", dir=self.config.backup_directory
        ) as root:
            replay = Path(root) / "globals.replay.sql"
            original_sha, original_size, replay_sha, replay_size = (
                _write_globals_replay(original, replay)
            )
            # Verify the actual protected file that will be passed as stdin.
            descriptor = os.open(replay, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                _protected(os.fstat(descriptor), directory=False)
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    measured = hashlib.sha256()
                    size = 0
                    while piece := stream.read(1024 * 1024):
                        measured.update(piece)
                        size += len(piece)
                require(
                    "sha256:" + measured.hexdigest() == replay_sha
                    and size == replay_size,
                    "globals_replay_file_changed",
                )
            finally:
                os.close(descriptor)
            proof = canonical_json(
                {
                    "schema": "dotmac.cp_globals_replay/1",
                    "request_digest": request_digest(request),
                    "host_nonce": nonce,
                    "original_digest": original_sha,
                    "original_size": original_size,
                    "replay_digest": replay_sha,
                    "replay_size": replay_size,
                    "omitted_statement": _POSTGRES_CREATE.decode("ascii"),
                    "source_bootstrap": source_bootstrap,
                    "fresh_bootstrap": fresh_bootstrap,
                }
            )
            self._globals_replay_digest = self._retain(proof)
            self._globals_replay_sha = replay_sha
            yield replay

    def _cleanup_scratch(self, name: str, nonce: str, checksum: str) -> None:
        identifiers = self._docker(
            "ps", "-aq", "--filter", f"name=^/{name}$"
        ).splitlines()
        if not identifiers:
            return
        require(len(identifiers) == 1, "scratch_cleanup_identity_mismatch")
        info = self._container(identifiers[0])
        labels = cast(dict[str, str], cast(dict[str, object], info["Config"])["Labels"])
        require(
            info.get("Name") == f"/{name}"
            and labels.get(_SCRATCH_OWNER_LABEL) == "1"
            and labels.get(_SCRATCH_NONCE_LABEL) == nonce
            and labels.get(_SCRATCH_REQUEST_LABEL) == checksum,
            "scratch_cleanup_identity_mismatch",
        )
        self._docker("rm", "-f", "-v", str(info["Id"]))

    def recheck_fence_source(self, request: CpTransitionRequestV1, nonce: str) -> bytes:
        self._bound(request, nonce)
        self._strict(request)
        self._source_matches(request)
        return self._evidence(
            request,
            nonce,
            "fence-source-rechecked",
            {
                "source": request["source"],
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
        )

    def migrate(
        self,
        request: CpTransitionRequestV1,
        nonce: str,
        *,
        authorization: VerifiedAuthorization,
        reservation_digest: str,
        genesis_digest: str,
        restore_digest: str,
        fence_digest: str,
        evidence: Mapping[str, str],
    ) -> bytes:
        from vendor_cp.migrations import native_upgrade

        historical_contexts: _CommittedContextArguments = {}
        if self._committed_contexts:
            historical_contexts["committed_contexts"] = self._committed_contexts
        if self._failed_candidate_contexts:
            historical_contexts["failed_candidate_contexts"] = (
                self._failed_candidate_contexts
            )
        self._bound(request, nonce)
        proof = self._strict(request)
        self._source_matches(request)
        with self._connect(request["database"]) as observer:
            self._identity(observer, request)
            with self._connect(
                request["database"], "app_admin", autocommit=False
            ) as connection:
                with connection.begin():
                    native_upgrade(
                        connection,
                        fence_connection=observer,
                        request=request,
                        authorization=authorization,
                        store=self.store,
                        host_nonce=nonce,
                        reservation_digest=reservation_digest,
                        genesis_digest=genesis_digest,
                        restore_digest=restore_digest,
                        fence_digest=fence_digest,
                        recovery=self.recovery,
                        fence_proof=proof,
                        evidence=evidence,
                        repository_root=self.config.repository_root,
                        git_binary=self.config.git_binary,
                        git_binary_digest=self.config.git_binary_digest,
                        **historical_contexts,
                    )
        self._strict(request)
        return self._evidence(
            request,
            nonce,
            "migrate",
            {
                "heads": request["target"]["heads"],
                "restore_digest": restore_digest,
                "fence_digest": fence_digest,
            },
        )

    def target_heads(self, request: TransitionRequest, nonce: str) -> bytes:
        self._bound(request, nonce)
        self._strict(request)
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            require(
                list(read_current_migration_heads(connection))
                == request["target"]["heads"],
                "target_heads_mismatch",
            )
        self._image(
            self.config.target_image, request["target"], self._target_descriptor
        )
        return self._evidence(
            request, nonce, "migrated-target-heads", request["target"]
        )

    def _candidate_arguments(self) -> _CandidateArguments:
        require(self.proof is not None)
        assert self.proof is not None  # noqa: S101 - require above is runtime guard
        return {
            "expected_digest": self.proof.digest(),
            "expected_fence_id": self.proof.fence_id,
        }

    def candidate_ready(self, request: TransitionRequest, nonce: str) -> bytes:
        self.candidate_phase = None
        self._bound(request, nonce)
        proof = self._strict(request)
        if request["schema"] == "dotmac.cp_failed_candidate_request/1":
            require(
                self._failed_candidate_context is not None,
                "failed_candidate_context_required",
            )
            assert self._failed_candidate_context is not None  # noqa: S101
            historical = self._failed_candidate_context.recovery_context()
            require(
                request_digest(self._failed_candidate_context.original.request)
                in historical,
                "recovery_missing",
            )
        elif request["schema"] == "dotmac.cp_committed_migration_request/1":
            require(self._committed_context is not None, "committed_context_required")
            assert self._committed_context is not None  # noqa: S101
            historical = self._committed_context.recovery_context()
            require(
                request_digest(self._committed_context.request) in historical,
                "recovery_missing",
            )
        else:
            require(
                request["schema"] == "dotmac.cp_transition_request/1",
                "unsupported_candidate_request",
            )
            require(request_digest(request) in self.recovery, "recovery_missing")
        self.target_heads(request, nonce)
        self._candidate_backends_exited = False
        self._candidate_quiescence_before = self._quiescence_snapshot(request, nonce)
        self._retain(self._candidate_quiescence_before)
        run_id = nonce[:32]
        config = self.config
        self._materialize_candidate_environment(request, run_id)
        self.launch = build_candidate_compose_launch(
            run_id=run_id,
            selected_image=config.target_image,
            expected_digest=request["target"]["image_digest"],
            candidate_port=config.candidate_port,
            database=request["database"],
            env_file=config.candidate_env_file or DEFAULT_RUN_ROOT / run_id / "app.env",
            licence_key_host_file=config.licence_key_host_file,
        )
        self._candidate_mounts()
        self.roles = candidate_roles.CandidateRoles.for_run(
            database=request["database"], run_id=run_id
        )
        self._candidate_created = True  # creation may fail after its atomic DDL
        self.candidate_phase = CandidateReadinessPhase.ROLES_CREATE
        with self._connect(request["database"]) as connection:
            candidate_roles.create_roles(
                connection, self.roles, proof, **self._candidate_arguments()
            )
            self.candidate_phase = CandidateReadinessPhase.PASSWORD_INSTALL
            self._install_candidate_passwords(connection)
            self.candidate_phase = CandidateReadinessPhase.ROLES_ACTIVATE
            candidate_roles.activate(
                connection, self.roles, proof, **self._candidate_arguments()
            )
        self._candidate_started = True  # also compensate a partially successful launch
        self.candidate_phase = CandidateReadinessPhase.COMPOSE_LAUNCH
        self._run(
            (str(config.docker_binary), *self.launch.argv[1:]),
            env=self.launch.subprocess_env({}),
        )
        self.candidate_phase = CandidateReadinessPhase.CANDIDATE_VERIFY
        self._verify_candidate(request)
        self.candidate_phase = None
        return self._evidence(
            request,
            nonce,
            "candidate-ready",
            {"side": request["target"], "status": 200, "writer_sessions": 0},
        )

    def _materialize_candidate_environment(
        self, request: TransitionRequest, run_id: str
    ) -> None:
        source = self.config.candidate_runtime_environment
        if source is None:
            require(
                self.config.candidate_env_file is not None,
                "candidate_runtime_environment_required",
            )
            return
        require(
            self.config.candidate_env_file is None, "ambiguous_candidate_environment"
        )
        values: dict[str, str] = {}
        for line in _read_protected(source).decode().splitlines():
            if not line:
                continue
            require("=" in line, "invalid_candidate_runtime_environment")
            key, value = line.split("=", 1)
            require(
                key in ALLOWED_APP_ENV_KEYS and key not in values,
                "invalid_candidate_runtime_environment",
            )
            values[key] = value
        require(
            "DATABASE_URL" not in values and "PLATFORM_DATABASE_URL" not in values,
            "candidate_base_must_exclude_database_credentials",
        )
        roles = candidate_roles.CandidateRoles.for_run(
            database=request["database"], run_id=run_id
        )
        for key, role in (
            ("DATABASE_URL", roles.app),
            ("PLATFORM_DATABASE_URL", roles.platform),
        ):
            values[key] = URL.create(
                "postgresql+psycopg",
                username=role,
                password=secrets.token_hex(32),
                host="db",
                port=5432,
                database=request["database"],
            ).render_as_string(hide_password=False)
        values["VENDOR_RELAY_EXPECTED"] = "false"
        # Exclusive creation under an installed protected parent. A consumed
        # request never reuses or repairs an earlier candidate directory.
        parent = _open_directory(DEFAULT_RUN_ROOT)
        try:
            os.mkdir(run_id, mode=0o700, dir_fd=parent)
            directory = os.open(
                run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            try:
                os.mkdir("docker-config", mode=0o700, dir_fd=directory)
                descriptor = os.open(
                    "app.env",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(
                        "".join(
                            f"{key}={value}\n" for key, value in sorted(values.items())
                        ).encode()
                    )
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
            finally:
                os.close(directory)
            os.fsync(parent)
        finally:
            os.close(parent)

    def _candidate_mounts(self) -> None:
        # Inspect metadata only; key material stays with its existing owner.
        key = self.config.licence_key_host_file
        parent = _open_directory(key.parent.parent)
        os.close(parent)
        require(
            key == LICENCE_KEY_HOST_FILE and not key.is_symlink(),
            "candidate_key_mount_mismatch",
        )
        info = key.stat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 10001
            and stat.S_IMODE(info.st_mode) == 0o400
            and info.st_nlink == 1,
            "candidate_key_custody_mismatch",
        )
        require(
            not key.parent.is_symlink()
            and key.parent.stat().st_uid == 10001
            and stat.S_IMODE(key.parent.stat().st_mode) == 0o700,
            "candidate_key_custody_mismatch",
        )
        volume = json.loads(
            self._docker(
                "volume",
                "inspect",
                "dotmac_vendor_control_plane_vendor_product_manifests",
            )
        )[0]
        require(
            volume.get("Driver") == "local" and not volume.get("Options"),
            "candidate_volume_mismatch",
        )
        network = json.loads(
            self._docker(
                "network", "inspect", "dotmac_vendor_control_plane_vendor_backend"
            )
        )[0]
        require(network.get("Driver") == "bridge", "candidate_network_mismatch")

    def _install_candidate_passwords(self, connection: Connection) -> None:
        require(self.launch is not None and self.roles is not None)
        assert self.launch is not None and self.roles is not None  # noqa: S101
        # The launch owner already validates the complete literal env allowlist,
        # role URLs, ownership and mode. Reopen through protected descriptors.
        values: dict[str, str] = dict(
            cast(tuple[str, str], tuple(line.split("=", 1)))
            for line in _read_protected(self.launch.env_file).decode().splitlines()
            if line
        )
        self._candidate_profile = values["VENDOR_DEPLOYMENT_PROFILE"]
        try:
            for role, key in (
                (self.roles.app, "DATABASE_URL"),
                (self.roles.platform, "PLATFORM_DATABASE_URL"),
            ):
                password = make_url(values[key]).password
                require(password is not None)
                # Parameterised transfer and fixed DO body. Neither parameters
                # nor driver diagnostics may escape this credential installer.
                connection.execute(
                    text(
                        "SELECT set_config('dotmac.candidate_password', "
                        ":password, false)"
                    ),
                    {"password": password},
                )
                quoted = connection.dialect.identifier_preparer.quote(role)
                try:
                    connection.exec_driver_sql(
                        "DO $password$ BEGIN EXECUTE "
                        f"format('ALTER ROLE {quoted} PASSWORD %L', "
                        "current_setting('dotmac.candidate_password')); "
                        "END $password$",
                        # %L belongs to PostgreSQL format(), not psycopg's
                        # parameter parser. Keep the DO body byte-for-byte.
                        execution_options={"no_parameters": True},
                    )
                finally:
                    connection.exec_driver_sql("RESET dotmac.candidate_password")
        except DBAPIError:
            raise RuntimeError("candidate credential installation failed") from None

    def _verify_candidate(self, request: TransitionRequest) -> None:
        require(
            self.roles is not None
            and self.proof is not None
            and self.launch is not None
        )
        assert self.roles is not None and self.proof is not None  # noqa: S101
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            require(
                candidate_roles.verify_staged_database(
                    connection, self.roles, self.proof, **self._candidate_arguments()
                ),
                "candidate_database_not_ready",
            )
            require(
                list(read_current_migration_heads(connection))
                == request["target"]["heads"],
                "target_heads_mismatch",
            )
        self._negative_reconnect(request)
        self._http(
            f"http://127.0.0.1:{self.config.candidate_port}/health/ready",
            expected=200,
            ready=True,
        )

    def close_candidate_and_refence(
        self, request: TransitionRequest, nonce: str
    ) -> bytes:
        self._bound(request, nonce)
        require(
            self.roles is not None
            and self.proof is not None
            and self.launch is not None
        )
        assert self.roles is not None and self.proof is not None  # noqa: S101
        assert self.launch is not None  # noqa: S101
        # Stop the app, then close LOGIN/CONNECT and terminate/drain any leftover
        # candidate backends before candidate_roles' strict cleanup verifier.
        if self._candidate_started:
            argv = (
                str(self.config.docker_binary),
                "compose",
                "-p",
                f"vcp-d16-{self.launch.run_id}",
                "-f",
                str(DEFAULT_COMPOSE_FILE),
                "down",
                "--remove-orphans",
            )
            self._run(argv, env=self.launch.subprocess_env({}))
        with self._connect(request["database"]) as connection:
            present = set(
                connection.execute(
                    text(
                        "SELECT rolname FROM pg_roles "
                        "WHERE rolname=ANY(CAST(:names AS text[]))"
                    ),
                    {"names": [name for name, _ in self.roles.bindings()]},
                ).scalars()
            )
            for role, _ in self.roles.bindings():
                if role not in present:
                    continue
                quoted = connection.dialect.identifier_preparer.quote(role)
                database = connection.dialect.identifier_preparer.quote(
                    request["database"]
                )
                connection.exec_driver_sql(f"ALTER ROLE {quoted} NOLOGIN")
                connection.exec_driver_sql(
                    f"REVOKE CONNECT ON DATABASE {database} FROM {quoted}"
                )
            self._drain_candidates(connection, request)
            if len(present) == 2:
                candidate_roles.deactivate(
                    connection, self.roles, self.proof, **self._candidate_arguments()
                )
            candidate_roles.cleanup_before_restore(
                connection, self.roles, self.proof, **self._candidate_arguments()
            )
        self._candidate_created = False
        self._candidate_started = False
        self._strict(request)
        quiescence_digest = self._finish_candidate_quiescence(request, nonce)
        return self._evidence(
            request,
            nonce,
            "candidate-removed-fenced",
            {
                "candidate_sessions": 0,
                "candidate_roles": [],
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
                "quiescence_digest": quiescence_digest,
            },
        )

    def _quiescence_snapshot(self, request: TransitionRequest, nonce: str) -> bytes:
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            measurement = measure_candidate_quiescence(connection)
        catalogue = cast(bytes, measurement.pop("catalogue_bytes"))
        measurement["catalogue_digest"] = self._retain(catalogue)
        return canonical_json(
            {
                "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
                "request_digest": request_digest(request),
                "host_nonce": nonce,
                "measurement": measurement,
            }
        )

    def _finish_candidate_quiescence(
        self, request: TransitionRequest, nonce: str
    ) -> str:
        require(
            self._candidate_quiescence_before is not None, "candidate_baseline_missing"
        )
        require(
            self._candidate_backends_exited
            and not self._candidate_created
            and not self._candidate_started,
            "candidate_backend_exit_unproved",
        )
        assert self._candidate_quiescence_before is not None  # noqa: S101
        # The caller has stopped candidate processes, observed zero remaining
        # candidate backends, dropped the temporary roles and re-proved fence.
        after = self._quiescence_snapshot(request, nonce)
        before_digest = self._retain(self._candidate_quiescence_before)
        after_digest = self._retain(after)
        require(
            after == self._candidate_quiescence_before, "candidate_mutation_observed"
        )
        proof = canonical_json(
            {
                "schema": "dotmac.cp_candidate_quiescence/1",
                "request_digest": request_digest(request),
                "host_nonce": nonce,
                "before_digest": before_digest,
                "after_digest": after_digest,
            }
        )
        self._candidate_quiescence_digest = self._retain(proof)
        return self._candidate_quiescence_digest

    def _drain_candidates(
        self, connection: Connection, request: TransitionRequest
    ) -> None:
        require(self.roles is not None)
        assert self.roles is not None  # noqa: S101
        names = [role for role, _ in self.roles.bindings()]
        deadline = time.monotonic() + self.config.session_wait_seconds
        while True:
            pids = list(
                connection.execute(
                    text(
                        "SELECT pid FROM pg_stat_activity WHERE datname=:db "
                        "AND usename=ANY(CAST(:roles AS text[]))"
                    ),
                    {"db": request["database"], "roles": names},
                ).scalars()
            )
            if not pids:
                self._candidate_backends_exited = True
                return
            for pid in pids:
                connection.execute(
                    text("SELECT pg_terminate_backend(:pid)"), {"pid": pid}
                )
            require(time.monotonic() < deadline, "candidate_drain_failed")
            time.sleep(0.05)

    def restore_acl(self, request: TransitionRequest, nonce: str) -> bytes:
        self._bound(request, nonce)
        proof = self._strict(request)
        require(
            self.roles is not None
            and not self._candidate_created
            and not self._candidate_started,
            "candidate_cleanup_missing",
        )
        require(
            self._candidate_quiescence_digest is not None,
            "candidate_quiescence_missing",
        )
        assert self.roles is not None  # noqa: S101
        with self._connect(request["database"]) as connection:
            candidate_roles.restore_after_candidate(
                connection,
                self.roles,
                proof,
                **self._candidate_arguments(),
                session_wait_seconds=self.config.session_wait_seconds,
            )
        self._acl_restored = True
        return self._evidence(
            request,
            nonce,
            "acl-restored",
            {"database": request["database"], "acl_difference": []},
        )

    def _full_runtime(self, request: TransitionRequest) -> None:
        require(self._acl_restored, "acl_not_restored")
        specification = self._runtime_specification()
        target_id = json.loads(
            self._docker("image", "inspect", self.config.target_image)
        )[0]["Id"]
        writers = self._writers()
        services: set[str] = set()
        for info in writers:
            labels = cast(
                dict[str, str], cast(dict[str, object], info["Config"])["Labels"]
            )
            if labels["com.docker.compose.service"] == "ops":
                require(
                    cast(dict[str, object], info["State"])["Running"] is False,
                    "ops_running",
                )
                continue
            services.add(labels["com.docker.compose.service"])
            service = labels["com.docker.compose.service"]
            declared = specification["services"][service]
            self._runtime_container_inputs(info, declared)
            if service == "app":
                self._runtime_app_publication(info, declared)
            require(
                info["Image"] == target_id
                and cast(dict[str, object], info["State"])["Running"] is True,
                "full_runtime_image_mismatch",
            )
            health = cast(
                dict[str, object],
                cast(dict[str, object], info["State"]).get("Health", {}),
            )
            require(health.get("Status") == "healthy", "full_runtime_unhealthy")
        require(services == {"app", "relay"}, "full_runtime_roles_missing")
        with self._connect(request["database"]) as connection:
            self._identity(connection, request)
            require(
                list(read_current_migration_heads(connection))
                == request["target"]["heads"],
                "target_heads_mismatch",
            )
        self._http(
            f"http://127.0.0.1:{self.config.app_port}/health/ready",
            expected=200,
            ready=True,
        )
        app_environment = cast(
            dict[str, str], specification["services"]["app"]["environment"]
        )
        if app_environment.get("VENDOR_DEPLOYMENT_PROFILE") == "production-keyless-v1":
            # The existing signed-fetch route is public/read-only. A disabled
            # runtime returns 503; an empty, available ledger returns the exact
            # owner-specific 404. A generic router 404 is never admitted.
            self._http(
                self._ledger_probe_url(),
                expected=(200, 404),
                ledger=True,
            )

    def _runtime_app_publication(
        self, info: dict[str, object], declared: dict[str, object]
    ) -> None:
        ports = declared.get("ports")
        require(
            isinstance(ports, list) and len(ports) == 1 and isinstance(ports[0], dict),
            "runtime_port_binding_mismatch",
        )
        assert isinstance(ports, list)  # noqa: S101
        port = cast(dict[str, object], ports[0])
        require(
            port.get("host_ip") == "127.0.0.1"
            and port.get("target") == 8000
            and str(port.get("published")) == str(self.config.app_port)
            and port.get("protocol", "tcp") == "tcp",
            "runtime_port_binding_mismatch",
        )
        expected = {
            "8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(self.config.app_port)}]
        }
        host = cast(dict[str, object], info.get("HostConfig", {}))
        network = cast(dict[str, object], info.get("NetworkSettings", {}))
        require(
            host.get("PortBindings") == expected and network.get("Ports") == expected,
            "runtime_port_binding_mismatch",
        )

    def _ledger_probe_url(self) -> str:
        reference = (
            inspect.signature(DeployAgentService).parameters["deployment_ref"].default
        )
        require(
            isinstance(reference, str) and len(reference.split("/")) == 3,
            "ledger_probe_identity_unavailable",
        )
        path = urllib.parse.quote(str(reference), safe="/")
        return (
            f"http://127.0.0.1:{self.config.app_port}"
            f"/platform/deploy/desired-state/{path}"
        )

    def full_ready(self, request: TransitionRequest, nonce: str) -> bytes:
        self._bound(request, nonce)
        # Compose reads the root-materialised runtime inputs. The selected image
        # is a fixed explicit env binding, never an environment inheritance.
        argv = self._runtime_argv() + (
            "up",
            "-d",
            "--wait",
            "--pull",
            "never",
            "--no-deps",
            "app",
            "relay",
        )
        self._runtime_specification()
        self._run(argv, env=self._runtime_environment())
        self._full_runtime(request)
        return self._evidence(
            request, nonce, "full-ready", {"side": request["target"], "status": 200}
        )

    def _runtime_argv(self) -> tuple[str, ...]:
        config = self.config
        argv: tuple[str, ...] = (
            str(config.docker_binary),
            "compose",
            "--project-name",
            "dotmac_vendor_control_plane",
            "-f",
            str(
                config.compose_file
                or config.deploy_directory / "docker-compose.production.yml"
            ),
            "--env-file",
            str(config.compose_env_file or config.deploy_directory / ".env"),
        )
        if config.runtime_compose_overlay is not None:
            argv += ("-f", str(config.runtime_compose_overlay))
        return argv

    def _runtime_environment(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "VENDOR_APP_IMAGE": self.config.target_image,
        }

    def _runtime_specification(self) -> dict[str, dict[str, dict[str, object]]]:
        require(bool(self._runtime_inputs), "runtime_inputs_not_inspected")
        for path, checksum in self._runtime_inputs.items():
            require(
                raw_digest(_read_protected(path)) == checksum, "runtime_inputs_changed"
            )
        document = json.loads(
            self._run(
                (*self._runtime_argv(), "config", "--format", "json"),
                env=self._runtime_environment(),
            )
        )
        app = document["services"]["app"]
        profile = app["environment"].get("VENDOR_DEPLOYMENT_PROFILE")
        if self._candidate_profile is not None:
            require(profile == self._candidate_profile, "runtime_profile_mismatch")
        if (
            profile == "production-keyless-v1"
            or self.config.runtime_compose_overlay is not None
        ):
            require(
                profile == "production-keyless-v1"
                and self.config.runtime_compose_overlay is not None
                and app["environment"].get("VENDOR_DEPLOY_AGENT_ENABLED") == "true",
                "keyless_runtime_overlay_required",
            )
        for service in ("app", "relay"):
            for mount in document["services"][service].get("volumes", []):
                if mount["type"] == "volume":
                    mount["source"] = document["volumes"][mount["source"]]["name"]
        return cast(dict[str, dict[str, dict[str, object]]], document)

    @staticmethod
    def _runtime_container_inputs(
        info: dict[str, object], declared: dict[str, object]
    ) -> None:
        config = cast(dict[str, object], info["Config"])
        actual_environment = {
            value.partition("=")[0]: value.partition("=")[2]
            for value in cast(list[str], config.get("Env", []))
        }
        expected_environment = cast(dict[str, str], declared["environment"])
        require(
            all(
                actual_environment.get(key) == str(value)
                for key, value in expected_environment.items()
            ),
            "runtime_environment_mismatch",
        )
        expected_mounts = {
            str(mount["target"]): mount
            for mount in cast(list[dict[str, object]], declared.get("volumes", []))
        }
        actual_mounts = {
            str(mount["Destination"]): mount
            for mount in cast(list[dict[str, object]], info.get("Mounts", []))
        }
        require(set(actual_mounts) == set(expected_mounts), "runtime_mount_mismatch")
        for destination, expected in expected_mounts.items():
            actual = actual_mounts[destination]
            require(
                actual.get("Type") == expected.get("type")
                and actual.get("RW") is (not expected.get("read_only", False)),
                "runtime_mount_mismatch",
            )
            if expected["type"] == "bind":
                path = Path(str(expected["source"]))
                require(actual.get("Source") == str(path), "runtime_mount_mismatch")
                parent_shape = path.parent.lstat()
                if parent_shape.st_uid == 10001:
                    # The existing signing custodian owns its 0700 leaf
                    # directory. Everything above it remains root-protected.
                    require(
                        stat.S_ISDIR(parent_shape.st_mode)
                        and stat.S_IMODE(parent_shape.st_mode) == 0o700,
                        "runtime_mount_unprotected",
                    )
                    parent = _open_directory(path.parent.parent)
                else:
                    parent = _open_directory(path.parent)
                os.close(parent)
                shape = path.lstat()
                require(
                    not stat.S_ISLNK(shape.st_mode)
                    and shape.st_uid in {0, 10001}
                    and shape.st_mode & 0o022 == 0,
                    "runtime_mount_unprotected",
                )
            elif expected["type"] == "volume":
                require(
                    actual.get("Name") == expected.get("source"),
                    "runtime_mount_mismatch",
                )

    def verify_pre_routing(self, receipt_bytes: bytes) -> bytes:
        require(self._request is not None and self._nonce is not None)
        assert self._request is not None and self._nonce is not None  # noqa: S101
        failed_contexts: _FailedReceiptArguments = {}
        if self._failed_candidate_context is not None:
            failed_contexts["failed_candidate_context"] = self._failed_candidate_context
        if self._failed_candidate_contexts:
            failed_contexts["failed_candidate_contexts"] = (
                self._failed_candidate_contexts
            )
        verify_any_receipt(
            receipt_bytes,
            store=self.store,
            request=self._request,
            host_nonce=self._nonce,
            recovery=self.recovery,
            routing_gate=True,
            context=self._committed_context,
            committed_contexts=self._committed_contexts,
            **failed_contexts,
        )
        checksum = raw_digest(receipt_bytes)
        require(
            self.store.read(checksum, kind="receipt") == receipt_bytes,
            "routing_receipt_not_retained",
        )
        self._full_runtime(self._request)
        self._routing_receipt = checksum
        return self._evidence(
            self._request,
            self._nonce,
            "pre-routing-verified",
            {"receipt_digest": checksum},
        )

    def restore_routing(self, request: TransitionRequest, nonce: str) -> bytes:
        self._bound(request, nonce)
        require(self._routing_receipt is not None, "routing_gate_missing")
        assert self._routing_receipt is not None  # noqa: S101
        self.verify_pre_routing(self.store.read(self._routing_receipt, kind="receipt"))
        self._run((str(self.config.maintenance_helper), "routing-restore"))
        self._http(self.config.external_ready_url, expected=200)
        return self._evidence(
            request,
            nonce,
            "routing-restored",
            {"side": request["target"], "external_status": 200},
        )

    def fail_closed(
        self, request: TransitionRequest, nonce: str, *, acl_may_be_restored: bool
    ) -> bytes:
        self._bound(request, nonce)
        if self.proof is None:
            # A failure before the initial fence is not permission to overwrite
            # an existing held ACL baseline through the containment path.
            with self._connect(request["database"]) as connection:
                self._identity(connection, request)
                self._check_fence_baseline(connection, request)
        errors: list[BaseException] = []
        # Each independent containment action is attempted even if another
        # fails. In particular maintenance failure must not skip DB re-fencing.
        try:
            self._maintenance()
        except BaseException as error:
            errors.append(error)
        if self._candidate_created:
            try:
                self.close_candidate_and_refence(request, nonce)
            except BaseException as error:
                errors.append(error)
        try:
            with self._connect(request["database"]) as connection:
                self._identity(connection, request)
                if self.proof is None:
                    self._check_fence_baseline(connection, request)
                self.proof = transition_fence.fence_writers(
                    connection,
                    database=request["database"],
                    fence_id=nonce,
                    session_wait_seconds=self.config.session_wait_seconds,
                    prior=self.proof,
                    expected_prior_fence_id=self.proof.fence_id if self.proof else None,
                )
            self._strict(request)
        except BaseException as error:
            errors.append(error)
        if errors:
            raise RuntimeError(
                "transition containment could not be fully proved"
            ) from None
        return self._evidence(
            request,
            nonce,
            "failure",
            {
                "external_status": 503,
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
        )
