"""Finite CI rehearsal of installed native migration, not live-host acceptance.

Run only as root with python -I in the exact candidate. The only synthetic
external boundary is the explicitly named GitHub verifier executable. Historical
SQL is constructed by a distinct pinned historical rebuilt test fixture.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import importlib
import json
import os
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from vendor_cp import migrations
from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, require
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment.cp_transition_host import (
    CpTransitionHostConfig,
    ExistingCpTransitionHost,
    measure_catalogue,
)
from vendor_cp.deployment.effects import PlatformCpRecoveryBundle, SubprocessExecutor
from vendor_cp.deployment.image_heads import composed_effective_heads
from vendor_cp.deployment.transition_fence import fence_writers, restore_writers
from vendor_cp.production_secrets import PRODUCTION_DEPLOYMENT_LOCK

DOCKER = Path("/usr/bin/docker")
GIT = Path("/usr/bin/git")
ENV = {"PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix:///var/run/docker.sock"}
ROOT = Path("/opt/candidate-native")


def cli(*argv):
    return subprocess.check_output(argv, env=ENV, timeout=180)  # noqa: S603 -- fixed argv, CI fixture


def descriptor(reference, revision, heads):
    return (
        'product = "dotmac_vendor_control_plane"\nenvironment = "production"\n'
        f'[image]\nreference = "{reference}"\nsource_revision = "{revision}"\n'
        "[migration]\nexpected_heads = " + json.dumps(heads) + "\n"
    ).encode()


def synthetic_authorization(request, root, now):
    """Execute the real verifier owner across one explicit synthetic boundary."""
    request_path = root / "request.json"
    request_path.write_bytes(canonical_json(request))
    proof = canonical_json(
        {
            "schema": "dotmac.cp_transition_environment_protection/1",
            "repository_id": "100",
            "repository_owner_id": "200",
            "workflow_revision": "c" * 40,
            "environment": "production",
            "protected_main": True,
            "prevent_self_review": True,
            "required_reviewer_ids": [300],
            "expires_at": request["expires_at"],
        }
    )
    protection = root / "synthetic-protection.json"
    protection.write_bytes(proof)
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
    verified = [
        {
            "verificationResult": {
                "signature": {"certificate": certificate},
                "verifiedTimestamps": [
                    {
                        "type": "Tlog",
                        "timestamp": now.isoformat(),
                        "uri": "https://rekor.sigstore.dev",
                    }
                ],
                "statement": {
                    "predicateType": "https://example.test/cp-transition/1",
                    "subject": [
                        {
                            "name": request_path.name,
                            "digest": {"sha256": cp.request_digest(request)[7:]},
                        }
                    ],
                    "predicate": {
                        "request_digest": cp.request_digest(request),
                        "trusted_actor": request["trusted_actor"],
                        "environment": "production",
                    },
                },
            }
        }
    ]
    executable = root / "SYNTHETIC-github-verifier"
    executable.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.write({json.dumps(verified)!r})\n"
    )
    executable.chmod(0o700)
    for path in (request_path, protection):
        path.chmod(0o600)
    policy = cp.CpTransitionTrustPolicy(
        cp.CpTransitionIdentity(
            request["host"],
            request["database"],
            request["cluster_system_identifier"],
            request["database_oid"],
        ),
        executable,
        cp._protected_executable_digest(executable),
        root,
        "example/cp",
        "100",
        "200",
        ".github/workflows/authorize.yml",
        "c" * 40,
        "https://example.test/cp-transition/1",
        protection,
        cp.raw_digest(proof),
    )
    return cp.GhAttestationVerifier(policy).verify(
        request, request_path=request_path, bundle_path=None, now=now
    )


class FixtureRecoveryProcess:
    """Translate only reviewed capture commands; all subprocess outputs are real."""

    def __init__(self, container, images):
        self.container, self.images = container, images
        self.delegate = SubprocessExecutor()

    def translate(self, argv):
        argv = list(argv)
        require(argv[0] == str(DOCKER), "fixture_command_refused")
        if argv[1:3] == ["image", "inspect"] and len(argv) == 6:
            require(
                argv[3] == "--format"
                and argv[4]
                == '{{index .Config.Labels "org.opencontainers.image.revision"}}'
                and argv[5] in self.images,
                "fixture_image_command_refused",
            )
            return [*argv[:5], self.images[argv[5]]]
        # Strip only compose addressing; retain the owner's exact SQL/tool argv.
        require(argv[1:3] == ["compose", "--project-name"], "fixture_command_refused")
        prefix = [
            str(DOCKER),
            "compose",
            "--project-name",
            "dotmac_vendor_control_plane",
            "--project-directory",
            str(ROOT),
            "--env-file",
            str(ROOT / ".env"),
            "-f",
            str(ROOT / "docker-compose.production.yml"),
            "exec",
        ]
        require(argv[: len(prefix)] == prefix, "fixture_command_refused")
        suffix = argv[len(prefix) :]
        require(suffix[:1] == ["-T"], "fixture_command_refused")
        suffix = suffix[1:]
        user = []
        if suffix[:2] == ["--user", "postgres"]:
            user, suffix = suffix[:2], suffix[2:]
        require(suffix[:1] == ["db"], "fixture_command_refused")
        command = suffix[1:]
        allowed = (
            [
                "pg_dumpall",
                "--username",
                "postgres",
                "--globals-only",
                "--no-role-passwords",
            ],
            [
                "sh",
                "-c",
                "exec pg_dump --username app_admin "
                '--dbname "$POSTGRES_DB" --format custom',
            ],
            ["pg_restore", "--list"],
            [
                "sh",
                "-c",
                'psql --username app_admin --dbname "$POSTGRES_DB" '
                '-tAc "SHOW server_version_num"',
            ],
            [
                "psql",
                "--username",
                "postgres",
                "-tAc",
                "SELECT system_identifier FROM pg_control_system()",
            ],
            ["sh", "-c", 'printf %s "$POSTGRES_DB"'],
            [
                "sh",
                "-c",
                'psql --username app_admin --dbname "$POSTGRES_DB" '
                '-tAc "SELECT version_num FROM alembic_version ORDER BY version_num"',
            ],
        )
        require(command in allowed, "fixture_command_refused")
        return [
            str(DOCKER),
            "exec",
            "-i",
            "-e",
            "POSTGRES_DB=restored_ok",
            *user,
            self.container,
            *command,
        ]

    def run(self, argv, **kwargs):
        return self.delegate.run(self.translate(argv), **kwargs)

    def capture_stdout(self, argv, destination, **kwargs):
        return self.delegate.capture_stdout(self.translate(argv), destination, **kwargs)


class FixtureHost(ExistingCpTransitionHost):
    """Only map the CI service name to its exact inspected container identity."""

    def __init__(self, *args, container, **kwargs):
        super().__init__(*args, **kwargs)
        self.fixture_container = container

    def _db_container(self):
        return self.fixture_container


def snapshot(connection):
    return tuple(sorted(migrations._source_heads(connection))), measure_catalogue(
        connection
    )


def refusal(action, expected, connection):
    before = snapshot(connection)
    try:
        action()
    except ContractError as error:
        require(expected in str(error), "unexpected_native_refusal")
    else:
        raise AssertionError("native sensitivity did not refuse")
    require(snapshot(connection) == before, "refusal_changed_source")


@contextmanager
def writer_fixtures(source_image, image_id, nonce):
    """Own only CIDs returned by our creates, then verify identity before cleanup."""
    created, observations = [], []
    try:
        for role in ("app", "relay"):
            name = "candidate-native-" + nonce[:32] + "-" + role
            identifier = (
                cli(
                    str(DOCKER),
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--network",
                    "none",
                    "--restart=no",
                    "--label",
                    "io.dotmac.candidate.run=" + nonce,
                    "--label",
                    "io.dotmac.candidate.fixture=" + role,
                    "--entrypoint",
                    "sleep",
                    source_image,
                    "600",
                )
                .decode()
                .strip()
            )
            require(
                len(identifier) == 64
                and all(c in "0123456789abcdef" for c in identifier),
                "fixture_writer_cid_invalid",
            )
            created.append((identifier, role, name))
            cli(str(DOCKER), "stop", "--time", "5", identifier)
            (writer,) = json.loads(cli(str(DOCKER), "container", "inspect", identifier))
            require(
                writer["Image"] == image_id
                and writer["State"]["Running"] is False
                and writer["HostConfig"]["RestartPolicy"]["Name"] == "no",
                "fixture_writer_identity_mismatch",
            )
            observations.append(
                {
                    "role": role,
                    "container_id": identifier,
                    "image_id": writer["Image"],
                    "running": writer["State"]["Running"],
                    "restart": writer["HostConfig"]["RestartPolicy"]["Name"],
                }
            )
        yield observations
    finally:
        for identifier, role, name in reversed(created):
            (writer,) = json.loads(cli(str(DOCKER), "container", "inspect", identifier))
            require(
                writer["Id"] == identifier
                and writer["Name"] == "/" + name
                and writer["Image"] == image_id
                and writer["Config"]["Labels"].get("io.dotmac.candidate.run") == nonce
                and writer["Config"]["Labels"].get("io.dotmac.candidate.fixture")
                == role,
                "fixture_cleanup_identity_mismatch",
            )
            cli(str(DOCKER), "rm", "-f", "-v", identifier)


@contextmanager
def maintenance_fixture():
    """Measure an actual disposable HTTP gate and drain; never address production."""
    condition = threading.Condition()
    release, entered = threading.Event(), threading.Event()
    websocket_entered = threading.Event()
    counters = {"active_http": 0, "active_websockets": 0}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_GET(self):
            with condition:
                counters["active_http"] += 1
                condition.notify_all()
            try:
                if self.path == "/hold":
                    entered.set()
                    require(release.wait(10), "fixture_http_drain_timeout")
                if self.path == "/hold-websocket":
                    key = self.headers["Sec-WebSocket-Key"]
                    accept = base64.b64encode(
                        hashlib.sha1(  # noqa: S324 -- RFC6455 handshake, not security hashing
                            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                        ).digest()
                    ).decode()
                    self.send_response(101)
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    self.send_header("Sec-WebSocket-Accept", accept)
                    self.end_headers()
                    self.wfile.flush()
                    with condition:
                        counters["active_websockets"] += 1
                    websocket_entered.set()
                    try:
                        require(release.wait(10), "fixture_websocket_drain_timeout")
                    finally:
                        with condition:
                            counters["active_websockets"] -= 1
                            condition.notify_all()
                    self.close_connection = True
                    return
                # Maintenance never accepts new WebSocket upgrades.
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
            finally:
                with condition:
                    counters["active_http"] -= 1
                    condition.notify_all()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    endpoint = "http://127.0.0.1:" + str(server.server_port)
    statuses, errors = [], []

    def probe(path, upgrade=False):
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=10
        )
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                }
                if upgrade
                else {},
            )
            response = connection.getresponse()
            status = response.status
            if status == 101:
                require(
                    response.getheader("Sec-WebSocket-Accept")
                    == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                    "fixture_websocket_handshake_invalid",
                )
                require(release.wait(10), "fixture_websocket_client_timeout")
            response.read()
            return status
        finally:
            connection.close()

    def held_request(path):
        try:
            statuses.append(probe(path, upgrade=path == "/hold-websocket"))
        except Exception as error:
            errors.append(type(error).__name__)

    held = threading.Thread(target=held_request, args=("/hold",), daemon=True)
    websocket = threading.Thread(
        target=held_request, args=("/hold-websocket",), daemon=True
    )
    held.start()
    websocket.start()
    try:
        require(
            entered.wait(5) and websocket_entered.wait(5),
            "fixture_requests_not_observed",
        )
        with condition:
            before = dict(counters)
        require(
            before == {"active_http": 2, "active_websockets": 1},
            "fixture_drain_counters_inert",
        )
        release.set()
        held.join(timeout=10)
        websocket.join(timeout=10)
        require(
            not held.is_alive()
            and not websocket.is_alive()
            and not errors
            and sorted(statuses) == [101, 503],
            "fixture_http_drain_unproved",
        )
        status = probe("/maintenance")
        upgrade_status = probe("/maintenance", upgrade=True)
        with condition:
            require(
                condition.wait_for(lambda: counters["active_http"] == 0, timeout=5),
                "fixture_http_not_drained",
            )
            measured = dict(counters)
        require(
            status == upgrade_status == 503 and measured["active_websockets"] == 0,
            "fixture_maintenance_unproved",
        )
        yield {
            "endpoint": endpoint,
            "scope": "disposable CI loopback gate; not platform production",
            "before_drain": before,
            "held_request_statuses": sorted(statuses),
            "websocket_upgrade_status": upgrade_status,
            "measured": {"external_status": status, **measured},
        }
    finally:
        release.set()
        held.join(timeout=10)
        websocket.join(timeout=10)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def postgres_fixture_identity(container, requested_image):
    """Join running database image ID to an independently inspected digest ref."""
    (database,) = json.loads(cli(str(DOCKER), "container", "inspect", container))
    (image,) = json.loads(cli(str(DOCKER), "image", "inspect", requested_image))
    require(
        database["Id"] == container
        and database["Image"] == image["Id"]
        and database["State"]["Running"] is True,
        "postgres_fixture_image_mismatch",
    )
    references = sorted(image.get("RepoDigests", []))
    require(bool(references), "postgres_fixture_immutable_reference_absent")
    reference = references[0]
    require(
        "@sha256:" in reference
        and len(reference.rsplit("@sha256:", 1)[-1]) == 64
        and all(c in "0123456789abcdef" for c in reference.rsplit("@sha256:", 1)[-1]),
        "postgres_fixture_digest_invalid",
    )
    (pinned,) = json.loads(cli(str(DOCKER), "image", "inspect", reference))
    require(pinned["Id"] == image["Id"], "postgres_fixture_digest_join_mismatch")
    return {
        "requested_image": requested_image,
        "immutable_reference": reference,
        "image_id": image["Id"],
        "container_id": container,
    }


def _cancel(_signum, _frame):
    raise SystemExit("candidate fixture cancelled")


def main():
    require(os.geteuid() == 0 and sys.flags.isolated == 1, "isolated_root_required")
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    os.umask(0o077)
    sys.dont_write_bytecode = True
    ROOT.mkdir(mode=0o700)
    origins = {}
    libraries = {
        Path(sysconfig.get_path(key)).resolve() for key in ("purelib", "platlib")
    }
    for name in (
        "vendor_cp",
        "vendor_cp.migrations",
        "vendor_cp.deployment.cp_transition",
        "dotmac_kernel",
        "sqlalchemy",
        "alembic",
    ):
        origin = Path(importlib.import_module(name).__file__).resolve()
        require(
            any(origin.is_relative_to(lib) for lib in libraries),
            "candidate_import_overlay",
        )
        origins[name] = str(origin)
    image, source_image, container, postgres_image = sys.argv[1:]
    (inspected,) = json.loads(cli(str(DOCKER), "image", "inspect", image))
    (source_info,) = json.loads(cli(str(DOCKER), "image", "inspect", source_image))
    require(source_image != image, "distinct_fixture_images_required")
    revision = inspected["Config"]["Labels"]["org.opencontainers.image.revision"]
    source_revision = source_info["Config"]["Labels"][
        "org.opencontainers.image.revision"
    ]
    require(
        source_revision == "348c31315efaaca9ea23ea7c025d137a3afaad74",
        "historical_fixture_revision_mismatch",
    )
    coordinates = json.loads(Path("/inputs/native-coordinate.json").read_text())
    coordinate = coordinates["target"]
    source_coordinate = coordinates["source"]
    require(
        source_coordinate["source_revision"] == source_revision
        and source_coordinate["layers"] == source_info["RootFS"]["Layers"],
        "source_coordinate_mismatch",
    )
    source_reference = (
        "acceptance.invalid/source@" + source_coordinate["manifest_digest"]
    )
    require(
        coordinate["source_revision"] == revision
        and coordinate["layers"] == inspected["RootFS"]["Layers"],
        "candidate_coordinate_mismatch",
    )
    target_reference = "acceptance.invalid/cp@" + coordinate["manifest_digest"]
    require(
        source_coordinate["manifest_digest"] != coordinate["manifest_digest"],
        "distinct_artifacts_required",
    )
    code = ROOT / "reviewed"
    code.mkdir()
    shutil.copy2("/app/alembic.ini", code / "alembic.ini")
    # Preserve every actual image file, including unexpected bytecode, for the guard.
    shutil.copytree("/app/alembic", code / "alembic")
    for path in [code, *code.rglob("*")]:
        require(not path.is_symlink(), "image_migration_symlink")
        path.chmod(0o700 if path.is_dir() else 0o600)
    cli(str(GIT), "-C", str(code), "init")
    cli(
        str(GIT), "-C", str(code), "fetch", "--no-tags", "/inputs/source.bundle", "HEAD"
    )
    cli(
        str(GIT),
        "-C",
        str(code),
        "fetch",
        "--no-tags",
        "/inputs/native-source.bundle",
        "source-fixture",
    )
    os.environ[migrations.MIGRATION_ROOT_ENV_VAR] = str(code)
    git_sha = cp._protected_executable_digest(GIT)
    tree_digest, _tree = migrations._verified_migration_tree(
        code, revision, git_binary=GIT, git_binary_digest=git_sha
    )
    backups = ROOT / "backups"
    backups.mkdir()
    store = cp.ArtifactStore(ROOT)
    postgres_identity = postgres_fixture_identity(container, postgres_image)
    config = CpTransitionHostConfig(
        repository_root=code,
        deploy_directory=ROOT,
        target_descriptor=ROOT / "target.toml",
        source_image=source_reference,
        target_image=target_reference,
        postgres_image=postgres_identity["immutable_reference"],
        maintenance_helper=ROOT / "unused",
        maintenance_helper_digest="sha256:" + "0" * 64,
        external_ready_url="https://platform.dotmac.io/health/ready",
        candidate_port=18100,
        docker_binary_digest=cp._protected_executable_digest(DOCKER),
        git_binary=GIT,
        git_binary_digest=git_sha,
        backup_directory=backups,
    )
    recovery = {}
    host = FixtureHost(config, store=store, recovery=recovery, container=container)
    # Use the installed lock owner in this disposable image's own filesystem.
    # The host's production lock directory is never mounted into this fixture.
    PRODUCTION_DEPLOYMENT_LOCK.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with host.lock(), host._connect("restored_ok") as observer:
        source_heads = list(sorted(migrations._source_heads(observer)))
        target_heads = list(
            composed_effective_heads(migrations.deploy_config(None, root=code))
        )
        require(source_heads != target_heads, "historical_fixture_is_already_target")
        cluster, oid = observer.execute(
            text(
                "SELECT system_identifier::text,(SELECT oid FROM pg_database "
                "WHERE datname=current_database()) FROM pg_control_system()"
            )
        ).one()
        source_descriptor = Path("/inputs/native-source-descriptor.toml").read_bytes()
        require(
            source_descriptor
            == cli(
                str(GIT),
                "-C",
                str(code),
                "show",
                source_revision + ":deploy/product.toml",
            ),
            "source_descriptor_not_actual_git_blob",
        )
        target_descriptor = descriptor(target_reference, revision, target_heads)
        host._retain(source_descriptor)
        host._retain(target_descriptor)
        config.target_descriptor.write_bytes(target_descriptor)
        request = {
            "schema": "dotmac.cp_transition_request/1",
            "product": "dotmac_vendor_control_plane",
            "environment": "production",
            "host": "candidate-native-fixture",
            "database": "restored_ok",
            "cluster_system_identifier": cluster,
            "database_oid": oid,
            "source": {
                "image_digest": source_coordinate["manifest_digest"],
                "revision": source_revision,
                "heads": source_heads,
                "raw_descriptor_digest": cp.raw_digest(source_descriptor),
            },
            "target": {
                "image_digest": coordinate["manifest_digest"],
                "revision": revision,
                "heads": target_heads,
                "raw_descriptor_digest": cp.raw_digest(target_descriptor),
            },
            "plan_digest": "",
            "authorization_run_id": 123,
            "authorization_run_attempt": 2,
            "trusted_actor": "SYNTHETIC-ci-reviewer",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            "previous_receipt_digest": None,
        }
        request["plan_digest"] = cp.transition_plan_digest(request)
        auth = synthetic_authorization(request, ROOT, datetime.now(UTC))
        nonce = store.reserve(request, auth)
        host._request, host._nonce = request, nonce
        host.proof = fence_writers(
            observer, database="restored_ok", fence_id=nonce, session_wait_seconds=3
        )
        host._negative_reconnect(request)
        host.genesis = host._observe(observer, request["source"])
        with host._connect("restored_wrong_owner") as wrong:
            require(
                snapshot(wrong) == snapshot(observer),
                "restore_lanes_catalogue_or_heads_differ",
            )
            refusal(
                lambda: host._observe(wrong, request["source"]),
                "source_role_owner_mismatch",
                wrong,
            )
        # Rollback-only database privilege probe independently demonstrates the cause.
        for database in ("restored_ok", "restored_wrong_owner"):
            with host._connect(database, "app_admin", autocommit=False) as connection:
                transaction = connection.begin()
                try:
                    connection.exec_driver_sql(
                        "CREATE SCHEMA candidate_ownership_probe"
                    )
                    require(database == "restored_ok", "wrong_owner_created_schema")
                except DBAPIError as error:
                    require(
                        database == "restored_wrong_owner"
                        and error.orig.sqlstate == "42501"
                        and "permission denied for database" in str(error.orig)
                        and database in str(error.orig),
                        "ownership_probe_wrong_failure",
                    )
                finally:
                    transaction.rollback()
        host_id = ROOT / "host-id"
        host_id.write_text(request["host"])
        owner = PlatformCpRecoveryBundle.for_transition(
            ROOT,
            source_descriptor=source_descriptor,
            target_descriptor=target_descriptor,
            source_image=source_reference,
            source_revision=source_revision,
            target_image=target_reference,
            target_source_revision=revision,
            expected_source_heads=tuple(source_heads),
            target=request["host"],
            incumbent_roles=tuple(
                (role, request["source"]["image_digest"]) for role in ("app", "relay")
            ),
            host_id_file=host_id,
            backup_dir=backups,
            process=FixtureRecoveryProcess(
                container, {source_reference: source_image, target_reference: image}
            ),
        )
        with (
            writer_fixtures(source_image, source_info["Id"], nonce) as fixture_writers,
            maintenance_fixture() as maintenance,
        ):
            backup = owner.capture_transition(timeout_seconds=180)
            require(owner.verify(backup), "real_recovery_owner_refused")
            recovery[cp.request_digest(request)] = owner, backup
            bundle = Path(backup.path)
            manifest = json.loads((bundle / "manifest.json").read_bytes())
            restored = host._restore_fresh(
                request, nonce, bundle, manifest["postgres_major"]
            )
            require(restored == host.genesis, "actual_restore_source_mismatch")
            results = {
                "inspection": {
                    "source": request["source"],
                    "target": request["target"],
                },
                "authorization": {
                    "verification_digest": host._retain(auth.verification_bytes),
                    "run_id": 123,
                    "run_attempt": 2,
                    "trusted_actor": request["trusted_actor"],
                },
                "maintenance": maintenance["measured"],
                "strict-fence-reconnect": {
                    "database": "restored_ok",
                    "writer_sessions": 0,
                    "reconnect_denial": "database_acl",
                },
                "writers-stopped": {
                    "running_writers": [
                        item["container_id"]
                        for item in fixture_writers
                        if item["running"]
                    ],
                    "restart_enabled": [
                        item["container_id"]
                        for item in fixture_writers
                        if item["restart"] != "no"
                    ],
                },
                "source-genesis": host.genesis,
                "recovery-restored": {
                    "source": host.genesis,
                    "restored_source": restored,
                    "restore_evidence_digest": host._retain(canonical_json(restored)),
                    "manifest_digest": host._retain(
                        (bundle / "manifest.json").read_bytes()
                    ),
                    "manifest_size": backup.manifest_size_bytes,
                    "dump_digest": backup.database_dump_sha256,
                    "globals_digest": backup.globals_sha256,
                    "dump_size": backup.database_dump_size_bytes,
                    "globals_size": backup.globals_size_bytes,
                    "restored_dump_digest": backup.database_dump_sha256,
                    "restored_globals_digest": host._globals_replay_sha,
                    "globals_replay_digest": host._globals_replay_digest,
                },
                "fence-source-rechecked": {
                    "source": request["source"],
                    "writer_sessions": 0,
                    "reconnect_denial": "database_acl",
                },
            }
            evidence = {
                kind: host._retain(host._evidence(request, nonce, kind, result))
                for kind, result in results.items()
            }
            kwargs = dict(
                fence_connection=observer,
                request=request,
                authorization=auth,
                store=store,
                host_nonce=nonce,
                reservation_digest=cp.request_digest(request),
                genesis_digest=evidence["source-genesis"],
                restore_digest=evidence["recovery-restored"],
                fence_digest=evidence["fence-source-rechecked"],
                recovery=recovery,
                fence_proof=host.proof,
                evidence=evidence,
                repository_root=code,
                git_binary=GIT,
                git_binary_digest=git_sha,
            )
            with host._connect(
                "restored_ok", "app_admin", autocommit=False
            ) as connection:
                with connection.begin():
                    refusal(
                        lambda: migrations.native_upgrade(
                            connection,
                            **{**kwargs, "authorization": replace(auth, _witness=None)},
                        ),
                        "unverified_authorization",
                        connection,
                    )
                    refusal(
                        lambda: migrations.native_upgrade(
                            connection, **{**kwargs, "evidence": {}}
                        ),
                        "transition_prefix_mismatch",
                        connection,
                    )
                env_path = code / "alembic" / "env.py"
                original = env_path.read_bytes()
                env_path.write_bytes(original + b"\n# altered artifact tree\n")
                with connection.begin():
                    refusal(
                        lambda: migrations.native_upgrade(connection, **kwargs),
                        "migration_tree_bytes_mismatch",
                        connection,
                    )
                env_path.write_bytes(original)
                wrong_request = {
                    **request,
                    "target": {**request["target"], "revision": "0" * 40},
                }
                with connection.begin():
                    refusal(
                        lambda: migrations.native_upgrade(
                            connection, **{**kwargs, "request": wrong_request}
                        ),
                        "migration_git_read_failed",
                        connection,
                    )
                with connection.begin() as transaction:
                    migrations.native_upgrade(connection, **kwargs)
                    require(
                        connection.get_transaction() is transaction,
                        "native_changed_transaction",
                    )
                    require(
                        list(sorted(migrations._source_heads(connection)))
                        == target_heads,
                        "native_target_heads_mismatch",
                    )
                # Reach the durable claim after restoring the source version rows.
                with connection.begin():
                    connection.exec_driver_sql("DELETE FROM public.alembic_version")
                    for head in source_heads:
                        connection.execute(
                            text("INSERT INTO public.alembic_version VALUES (:head)"),
                            {"head": head},
                        )
                with connection.begin():
                    before = snapshot(connection)
                    try:
                        migrations.native_upgrade(connection, **kwargs)
                    except FileExistsError:
                        pass
                    else:
                        raise AssertionError("native durable replay accepted")
                    require(snapshot(connection) == before, "replay_changed_database")
                with connection.begin():
                    connection.exec_driver_sql("DELETE FROM public.alembic_version")
                    for head in target_heads:
                        connection.execute(
                            text("INSERT INTO public.alembic_version VALUES (:head)"),
                            {"head": head},
                        )
            restore_writers(
                observer,
                host.proof,
                database="restored_ok",
                expected_fence_id=nonce,
                session_wait_seconds=3,
            )
    report = {
        "schema": "dotmac.candidate_native_acceptance/1",
        "candidate": coordinate,
        "postgres_fixture": postgres_identity,
        "source_fixture": {
            "image": source_image,
            "revision": source_revision,
            "coordinate": source_coordinate,
            "construction": (
                "rebuilt immutable historical Git348 fixture; installed source "
                "image to v016; neither byte-identical accepted image "
                "nor production dump"
            ),
        },
        "fixture_writers": fixture_writers,
        "maintenance_fixture": maintenance,
        "target_descriptor_origin": (
            "CI prospective fixture; not accepted descriptor promotion"
        ),
        "import_origins": origins,
        "migration_tree_digest": tree_digest,
        "request_digest": cp.request_digest(request),
        "source_heads": source_heads,
        "target_heads": target_heads,
        "recovery_manifest_digest": "sha256:" + backup.checksum,
        "globals_replay_digest": host._globals_replay_digest,
        "negative": [
            "host source preflight _observe wrong-owner typed refusal before DDL",
            "rollback-only CREATE SCHEMA SQLSTATE 42501 database denial",
            "invalid authorization",
            "missing native evidence",
            "changed migration bytes",
            "wrong target revision",
            "durable replay",
        ],
        "trust_boundary": (
            "SYNTHETIC GitHub authorization executable and protection fixture; "
            "maintenance/writers facts describe disposable CI fixture; no full host, "
            "production routing, or real protected-environment issuance acceptance"
        ),
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
