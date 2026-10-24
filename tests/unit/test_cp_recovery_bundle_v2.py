"""Native CP backup uses exact descriptor and file bytes, preserving V1."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vendor_cp.deployment.effects import (
    REQUIRED_ROLES,
    PlatformBackupResult,
    PlatformCpRecoveryBundle,
    PlatformRecoveryError,
    ProcessResult,
)

SOURCE = "registry.invalid/cp@sha256:" + "a" * 64
TARGET = "registry.invalid/cp@sha256:" + "b" * 64
REVISION = "c" * 40
TARGET_REVISION = "d" * 40
HEADS = ("dc_0014", "v022_deploy_agent")


def descriptor(image: str, revision: str) -> bytes:
    return (
        'product = "dotmac_vendor_control_plane"\nenvironment = "production"\n'
        f'[image]\nreference = "{image}"\nsource_revision = "{revision}"\n'
    ).encode()


class Process:
    def __init__(self) -> None:
        self.heads = HEADS
        self.source_revision = REVISION
        self.omit_role = ""

    def capture_stdout(
        self,
        argv: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
    ) -> ProcessResult:
        destination.write_bytes(
            "".join(
                f"CREATE ROLE {role};\n"
                for role in REQUIRED_ROLES
                if role != self.omit_role
            ).encode()
            if "pg_dumpall" in argv
            else b"PGDMP-native-fixture"
        )
        return ProcessResult(0)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
        stdin_path: Path | None = None,
    ) -> ProcessResult:
        command = " ".join(argv)
        if "pg_restore" in argv:
            assert stdin_path is not None
            assert stdin_path.read_bytes().startswith(b"PGDMP")
            return ProcessResult(0)
        for query, output in (
            ("server_version_num", "160010"),
            ("pg_control_system", "123456789"),
            ("printf", "vendor_control_plane"),
            ("alembic_version", "\n".join(self.heads)),
        ):
            if query in command:
                return ProcessResult(0, output)
        if "inspect" in argv:
            return ProcessResult(
                0, self.source_revision if argv[-1] == SOURCE else TARGET_REVISION
            )
        raise AssertionError(argv)


def bundle(
    tmp_path: Path, process: Process, *, source_descriptor: bytes | None = None
) -> PlatformCpRecoveryBundle:
    host = tmp_path / "host"
    host.write_text("cp-test")
    return PlatformCpRecoveryBundle.for_transition(
        tmp_path,
        source_descriptor=(
            source_descriptor
            if source_descriptor is not None
            else descriptor(SOURCE, REVISION)
        ),
        target_descriptor=descriptor(TARGET, TARGET_REVISION),
        source_image=SOURCE,
        source_revision=REVISION,
        target_image=TARGET,
        target_source_revision=TARGET_REVISION,
        expected_source_heads=HEADS,
        target="cp-test",
        incumbent_roles=(("app", SOURCE.rsplit("@", 1)[1]),),
        host_id_file=host,
        backup_dir=tmp_path / "backups",
        process=process,
        clock=lambda: datetime(2026, 10, 24, tzinfo=UTC),
    )


def test_native_bundle_binds_exact_bytes_and_distinct_artifacts(tmp_path: Path) -> None:
    owner = bundle(tmp_path, Process())
    result = owner.capture_transition(timeout_seconds=30)
    assert isinstance(result, PlatformBackupResult)
    root = Path(result.path)
    raw = (root / "manifest.json").read_bytes()
    manifest = json.loads(raw)
    assert manifest["schema"] == "PlatformCpRecoveryBundle.v2"
    assert "descriptor_sha256" not in manifest
    for side, image, revision in (
        ("source", SOURCE, REVISION),
        ("target", TARGET, TARGET_REVISION),
    ):
        assert manifest[f"{side}_descriptor_raw_sha256"] == (
            "sha256:" + hashlib.sha256(descriptor(image, revision)).hexdigest()
        )
    assert result.checksum == hashlib.sha256(raw).hexdigest()
    assert result.checksum != manifest["files"]["database.dump"].removeprefix("sha256:")
    for name in ("database.dump", "globals.sql"):
        assert manifest["file_sizes"][name] == (root / name).stat().st_size
        assert (
            manifest["files"][name]
            == "sha256:" + hashlib.sha256((root / name).read_bytes()).hexdigest()
        )
    assert owner.verify(result)
    assert not list(root.parent.glob(".bundle-*"))
    assert not owner.verify(
        replace(
            result, checksum=manifest["files"]["database.dump"].removeprefix("sha256:")
        )
    )
    with pytest.raises(PlatformRecoveryError, match="already exists"):
        owner.capture("primary", timeout_seconds=30)
    (root / "database.dump").write_bytes(b"tampered")
    assert not owner.verify(result)


@pytest.mark.parametrize("failure", ["heads", "revision", "role", "host"])
def test_native_failure_never_publishes(tmp_path: Path, failure: str) -> None:
    process = Process()
    owner = bundle(tmp_path, process)
    if failure == "heads":
        process.heads = ("wrong",)
    elif failure == "revision":
        process.source_revision = "e" * 40
    elif failure == "role":
        process.omit_role = "platform_api"
    else:
        (tmp_path / "host").write_text("wrong-host")
    with pytest.raises(PlatformRecoveryError):
        owner.capture("primary", timeout_seconds=30)
    assert not list((tmp_path / "backups").glob("*"))


def test_wrong_target_image_refused_before_capture(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="descriptor"):
        PlatformCpRecoveryBundle.for_transition(
            tmp_path,
            source_descriptor=descriptor(SOURCE, REVISION),
            target_descriptor=descriptor(TARGET, TARGET_REVISION),
            source_image=SOURCE,
            source_revision=REVISION,
            target_image=SOURCE,
            target_source_revision=TARGET_REVISION,
            expected_source_heads=HEADS,
            target="cp-test",
            incumbent_roles=(("app", SOURCE.rsplit("@", 1)[1]),),
        )


@pytest.mark.parametrize(
    "field",
    [
        "schema",
        "source_descriptor_raw_sha256",
        "target_descriptor_raw_sha256",
        "migration_heads",
        "incumbent_roles",
        "target",
        "source_image",
        "first_deployment",
        "descriptor_sha256",
    ],
)
def test_native_manifest_refuses_rehashed_identity_changes(
    tmp_path: Path,
    field: str,
) -> None:
    owner = bundle(tmp_path, Process())
    result = owner.capture_transition(timeout_seconds=30)
    path = Path(result.path) / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest[field] = [] if field in ("migration_heads", "incumbent_roles") else "wrong"
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    path.write_bytes(raw)
    modified = replace(
        result,
        checksum=hashlib.sha256(raw).hexdigest(),
        manifest_size_bytes=len(raw),
        size_bytes=result.size_bytes - result.manifest_size_bytes + len(raw),
    )
    assert not owner.verify(modified)


def test_native_verification_streams_large_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class LargeProcess(Process):
        def capture_stdout(self, argv, destination, **kwargs):
            result = super().capture_stdout(argv, destination, **kwargs)
            if "pg_dumpall" not in argv:
                with destination.open("ab") as output:
                    output.truncate(17 * 1024 * 1024)
            return result

    owner = bundle(tmp_path, LargeProcess())
    result = owner.capture_transition(timeout_seconds=30)
    assert result.database_dump_size_bytes > 16 * 1024 * 1024
    original = Path.read_bytes

    def bounded_read(path: Path) -> bytes:
        assert path.name != "database.dump", "dump must be verified as a stream"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", bounded_read)
    assert owner.verify(result)


def test_historical_descriptor_declarations_remain_independent(tmp_path: Path) -> None:
    raw = (
        Path(__file__).parents[1] / "fixtures/cp-transition/source-3ef3cef4.toml"
    ).read_bytes()
    assert (
        hashlib.sha256(raw).hexdigest()
        == "42d1b0b6bbb8b1b0cc9990cd5630a4be66ea778aaa206ef69a22c3cc72f1c5aa"
    )
    owner = bundle(tmp_path, Process(), source_descriptor=raw)
    result = owner.capture_transition(timeout_seconds=30)
    manifest = json.loads((Path(result.path) / "manifest.json").read_bytes())
    assert (
        manifest["source_descriptor_raw_sha256"]
        == "sha256:" + hashlib.sha256(raw).hexdigest()
    )
    assert manifest["source_image"] == SOURCE
    assert manifest["migration_heads"] == list(HEADS)
    assert owner.verify(result)


def test_native_capture_does_not_inherit_docker_or_loader_environment(
    tmp_path, monkeypatch
):
    poisoned = {
        "DOCKER_HOST": "tcp://untrusted.invalid:2375",
        "DOCKER_CONTEXT": "untrusted",
        "DOCKER_CONFIG": "/untrusted/config",
        "LD_PRELOAD": "/untrusted/preload.so",
        "LD_LIBRARY_PATH": "/untrusted/lib",
        "PYTHONPATH": "/untrusted/python",
        "HOME": "/untrusted/home",
    }
    for key, value in poisoned.items():
        monkeypatch.setenv(key, value)
    environments = []

    class ObservedProcess(Process):
        def run(self, argv, **kwargs):
            environments.append(dict(kwargs["env"]))
            return super().run(argv, **kwargs)

        def capture_stdout(self, argv, destination, **kwargs):
            environments.append(dict(kwargs["env"]))
            return super().capture_stdout(argv, destination, **kwargs)

    result = bundle(tmp_path, ObservedProcess()).capture_transition(timeout_seconds=30)
    assert result.path and environments
    for environment in environments:
        assert environment["DOCKER_HOST"] == "unix:///var/run/docker.sock"
        assert environment["HOME"] == "/nonexistent"
        assert environment["PATH"] == "/usr/bin:/bin"
        assert environment["VENDOR_APP_IMAGE"] == TARGET
        assert not set(environment) & {
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "PYTHONPATH",
        }
