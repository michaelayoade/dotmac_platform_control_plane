from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest

import vendor_cp.production_secrets as production_secrets
from vendor_cp.production_secrets import (
    DATABASE_PATH,
    DEPLOY_SSH_PATH,
    LEGACY_RUNTIME_PROBE_IMAGE,
    LEGACY_RUNTIME_PROBE_REVISION,
    LICENCE_SIGNING_PATH,
    ROLLBACK_CONFIRMATION,
    ROTATION_DATABASE_AUTH_ORACLE_PAYLOAD,
    ROTATION_DEPLOY_DIR,
    ROTATION_HOST_ID,
    ROTATION_PREFLIGHT_REFUSALS,
    ROTATION_RUNTIME_MATERIAL_ORACLE_PAYLOAD,
    ROTATION_RUNTIME_ORACLE_PAYLOAD,
    ROTATION_TARGET,
    RUNTIME_PATH,
    HistoricalHostRotationProof,
    HostRotationProof,
    HttpReadinessOracle,
    LegacyRuntimeProbeOracle,
    OpenBaoClient,
    ProductionSecretError,
    RotationPhase,
    RotationRuntimeOracleProof,
    RotationTargetPreflightProof,
    SecretRotationReceipt,
    VersionedSecretRecord,
    _adapter_ssh_prefix,
    _refusal_message,
    _remote_command,
    apply_secret_rotation_on_target,
    build_rotation_payload,
    commit_openbao_rotation,
    complete_secret_rotation,
    execute_secret_rotation,
    install_rotation_adapter,
    preflight_rotation_target,
    prepare_secret_rotation,
    probe_rotation_runtime,
    read_rotation_custody,
    read_rotation_receipt,
    retire_rotation_adapter,
    rollback_openbao_rotation,
    rotation_adapter_bytes,
    rotation_adapter_digest,
    rotation_adapter_installer_program,
    rotation_adapter_verifier_program,
    rotation_database_auth_oracle_program,
    rotation_runtime_material_oracle_program,
    rotation_runtime_oracle_program,
    rotation_target_preflight_program,
    sanitize_diagnostic_text,
    select_readiness_oracle,
    transfer_rotation_payload,
    verify_rotation_adapter,
)

EXPECTED_IMAGE = "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "c" * 64
EXPECTED_REVISION = "b" * 40


def _proof(operation_id: str) -> HostRotationProof:
    return HostRotationProof(
        operation_id=operation_id,
        target_host_id=ROTATION_HOST_ID,
        image_reference=EXPECTED_IMAGE,
        source_revision=EXPECTED_REVISION,
        adapter_digest=rotation_adapter_digest(),
    )


def _preflight() -> RotationTargetPreflightProof:
    return RotationTargetPreflightProof(
        target_host_id=ROTATION_HOST_ID,
        image_reference=EXPECTED_IMAGE,
        source_revision=EXPECTED_REVISION,
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _records() -> dict[str, dict[str, str]]:
    return {
        LICENCE_SIGNING_PATH: {
            "key_id": "vendor-prod-test",
            "private_key_b64url": _b64url(b"k" * 32),
        },
        DATABASE_PATH: {
            "admin_password": "old_admin_" + "a" * 48,
            "app_user_password": "old_app_" + "b" * 48,
            "platform_api_password": "old_platform_" + "c" * 48,
        },
        RUNTIME_PATH: {
            "jwt_secret": "old_jwt_" + "d" * 64,
            "session_hash_secret": "old_session_" + "e" * 64,
            "csrf_secret": "preserved_csrf_" + "f" * 48,
        },
        DEPLOY_SSH_PATH: {
            "private_key_openssh": (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "fixture\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            ),
            "public_key_openssh": "ssh-ed25519 AAAA vendor-cp-prod-deploy",
            "username": "root",
        },
    }


class FakeVersionedStore:
    def __init__(self) -> None:
        self.history: dict[str, list[dict[str, str]]] = {
            path: [dict(fields)] for path, fields in _records().items()
        }
        self.fail_next: str | None = None
        self.updates: list[tuple[str, int]] = []
        self.reads: list[str] = []

    def read_versioned(
        self, path: str, *, version: int | None = None
    ) -> VersionedSecretRecord:
        self.reads.append(path)
        records = self.history[path]
        selected = len(records) if version is None else version
        return VersionedSecretRecord(
            path=path,
            version=selected,
            fields=dict(records[selected - 1]),
        )

    def cas_update(
        self, path: str, fields: Mapping[str, str], *, expected_version: int
    ) -> int:
        if self.fail_next == path:
            self.fail_next = None
            raise ProductionSecretError("injected CAS failure")
        if len(self.history[path]) != expected_version:
            raise ProductionSecretError("CAS conflict")
        self.history[path].append(dict(fields))
        self.updates.append((path, expected_version))
        return len(self.history[path])


class _Response:
    def __init__(self, body: object) -> None:
        self.body = json.dumps(body).encode()

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def _token_factory() -> tuple[Callable[[int], str], list[str]]:
    generated: list[str] = []

    def token(length: int) -> str:
        value = f"candidate_{len(generated)}_" + chr(97 + len(generated)) * length
        generated.append(value)
        return value

    return token, generated


def _prepare(
    tmp_path: Path,
    store: FakeVersionedStore,
) -> tuple[Path, Path, object, SecretRotationReceipt, list[str]]:
    custody_file = tmp_path / "private" / "rotation.custody.json"
    receipt_file = tmp_path / "private" / "rotation.receipt.json"
    token_factory, generated = _token_factory()
    custody, receipt = prepare_secret_rotation(
        store,
        custody_file=custody_file,
        receipt_file=receipt_file,
        expected_image_reference=EXPECTED_IMAGE,
        expected_source_revision=EXPECTED_REVISION,
        token_factory=token_factory,
    )
    return custody_file, receipt_file, custody, receipt, generated


def test_prepare_writes_one_protected_candidate_and_a_names_only_receipt(
    tmp_path: Path,
) -> None:
    store = FakeVersionedStore()
    custody_file, receipt_file, custody, receipt, generated = _prepare(tmp_path, store)

    assert len(generated) == 5
    assert custody.candidate.csrf_secret == custody.prior.csrf_secret
    assert stat.S_IMODE(custody_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(receipt_file.stat().st_mode) == 0o600
    receipt_bytes = receipt_file.read_text(encoding="utf-8")
    for value in generated:
        assert value not in receipt_bytes
        assert hashlib.sha256(value.encode()).hexdigest() not in receipt_bytes
    assert custody.prior.csrf_secret not in receipt_bytes
    assert receipt.phase is RotationPhase.PREPARED
    assert "admin_password" in receipt_bytes
    assert "csrf_secret" in receipt_bytes
    representation = repr(custody) + repr(custody.prior) + repr(custody.candidate)
    for value in generated:
        assert value not in representation


def test_prepare_resumes_without_generating_a_second_candidate(tmp_path: Path) -> None:
    store = FakeVersionedStore()
    custody_file, receipt_file, first, _receipt, generated = _prepare(tmp_path, store)
    token_factory, second_generation = _token_factory()

    resumed, _ = prepare_secret_rotation(
        store,
        custody_file=custody_file,
        receipt_file=receipt_file,
        expected_image_reference=EXPECTED_IMAGE,
        expected_source_revision=EXPECTED_REVISION,
        token_factory=token_factory,
    )

    assert resumed.to_json() == first.to_json()
    assert second_generation == []
    assert len(generated) == 5


def test_prepare_reconstructs_missing_names_only_receipt_from_same_custody(
    tmp_path: Path,
) -> None:
    store = FakeVersionedStore()
    custody_file, receipt_file, custody, _receipt, _generated = _prepare(
        tmp_path, store
    )
    receipt_file.unlink()

    resumed, receipt = prepare_secret_rotation(
        store,
        custody_file=custody_file,
        receipt_file=receipt_file,
        expected_image_reference=EXPECTED_IMAGE,
        expected_source_revision=EXPECTED_REVISION,
        token_factory=lambda _length: pytest.fail("must not generate on resume"),
    )

    assert resumed.to_json() == custody.to_json()
    assert receipt.image_reference == EXPECTED_IMAGE
    assert receipt.source_revision == EXPECTED_REVISION
    assert receipt.phase is RotationPhase.PREPARED


def test_partial_openbao_commit_records_boundary_and_resumes_same_candidate(
    tmp_path: Path,
) -> None:
    store = FakeVersionedStore()
    custody_file, receipt_file, custody, receipt, generated = _prepare(tmp_path, store)
    store.fail_next = RUNTIME_PATH

    with pytest.raises(ProductionSecretError, match="injected CAS failure"):
        commit_openbao_rotation(
            store,
            custody,
            receipt,
            receipt_file=receipt_file,
        )

    partial = read_rotation_receipt(receipt_file)
    assert partial.phase is RotationPhase.OPENBAO_DATABASE_WRITTEN
    assert partial.database_candidate_version == 2
    assert store.read_versioned(DATABASE_PATH).fields == (
        custody.candidate.database_record()
    )
    assert store.read_versioned(RUNTIME_PATH).fields == custody.prior.runtime_record()

    completed = commit_openbao_rotation(
        store,
        custody,
        partial,
        receipt_file=receipt_file,
    )

    assert completed.phase is RotationPhase.OPENBAO_COMMITTED
    assert store.updates == [(DATABASE_PATH, 1), (RUNTIME_PATH, 1)]
    assert read_rotation_custody(custody_file).candidate.to_object() == (
        custody.candidate.to_object()
    )
    assert len(generated) == 5


def test_partial_openbao_records_never_reach_the_host_consumer(tmp_path: Path) -> None:
    store = FakeVersionedStore()
    custody_file = tmp_path / "private" / "rotation.custody.json"
    receipt_file = tmp_path / "private" / "rotation.receipt.json"
    token_factory, generated = _token_factory()
    store.fail_next = RUNTIME_PATH
    host_calls: list[object] = []

    with pytest.raises(ProductionSecretError, match="injected CAS failure"):
        execute_secret_rotation(
            store_factory=lambda: store,
            preflight=_preflight,
            custody_file=custody_file,
            receipt_file=receipt_file,
            expected_image_reference=EXPECTED_IMAGE,
            expected_source_revision=EXPECTED_REVISION,
            token_factory=token_factory,
            host_apply=lambda payload: host_calls.append(payload),  # type: ignore[arg-type,return-value]
        )

    assert host_calls == []
    assert read_rotation_receipt(receipt_file).phase is (
        RotationPhase.OPENBAO_DATABASE_WRITTEN
    )
    assert len(generated) == 5

    proof = _proof(read_rotation_custody(custody_file).operation_id)
    completed = execute_secret_rotation(
        store_factory=lambda: store,
        preflight=_preflight,
        custody_file=custody_file,
        receipt_file=receipt_file,
        expected_image_reference=EXPECTED_IMAGE,
        expected_source_revision=EXPECTED_REVISION,
        token_factory=lambda _length: pytest.fail("must not generate on retry"),
        host_apply=lambda payload: (host_calls.append(payload), proof)[1],
    )

    assert completed.phase is RotationPhase.PROVED
    assert len(host_calls) == 1
    assert store.updates == [(DATABASE_PATH, 1), (RUNTIME_PATH, 1)]


def test_failed_preflight_precedes_openbao_and_every_local_mutation(
    tmp_path: Path,
) -> None:
    store = FakeVersionedStore()
    custody_file = tmp_path / "private" / "rotation.custody.json"
    receipt_file = tmp_path / "private" / "rotation.receipt.json"
    store_factory_calls = 0

    def store_factory() -> FakeVersionedStore:
        nonlocal store_factory_calls
        store_factory_calls += 1
        return store

    def refuse_preflight() -> RotationTargetPreflightProof:
        raise ProductionSecretError("readiness preflight refused")

    with pytest.raises(ProductionSecretError, match="readiness preflight"):
        execute_secret_rotation(
            store_factory=store_factory,
            preflight=refuse_preflight,
            custody_file=custody_file,
            receipt_file=receipt_file,
            expected_image_reference=EXPECTED_IMAGE,
            expected_source_revision=EXPECTED_REVISION,
            host_apply=lambda _payload: pytest.fail("host must not be called"),
        )

    assert store_factory_calls == 0
    assert store.reads == []
    assert store.updates == []
    assert not custody_file.exists()
    assert not receipt_file.exists()


def test_advanced_openbao_without_matching_custody_is_refused(tmp_path: Path) -> None:
    store = FakeVersionedStore()
    receipt_file = tmp_path / "private" / "rotation.receipt.json"
    receipt_file.parent.mkdir(parents=True)
    receipt_file.write_text(
        SecretRotationReceipt(
            operation_id="a" * 32,
            target_host_id=ROTATION_HOST_ID,
            phase=RotationPhase.PREPARED,
            database_prior_version=1,
            runtime_prior_version=1,
        ).to_json(),
        encoding="utf-8",
    )
    receipt_file.chmod(0o600)
    store.history[DATABASE_PATH].append(
        {
            **store.history[DATABASE_PATH][-1],
            "admin_password": "advanced_" + "z" * 48,
        }
    )

    with pytest.raises(ProductionSecretError, match="without custody"):
        execute_secret_rotation(
            store_factory=lambda: store,
            preflight=_preflight,
            custody_file=tmp_path / "private" / "missing.custody.json",
            receipt_file=receipt_file,
            expected_image_reference=EXPECTED_IMAGE,
            expected_source_revision=EXPECTED_REVISION,
            host_apply=lambda _payload: pytest.fail("host must not be called"),
        )


def test_cas_conflict_refuses_without_overwriting_an_external_change(
    tmp_path: Path,
) -> None:
    store = FakeVersionedStore()
    _custody_file, receipt_file, custody, receipt, _generated = _prepare(
        tmp_path, store
    )
    external = dict(store.read_versioned(DATABASE_PATH).fields)
    external["admin_password"] = "external_" + "z" * 48
    store.history[DATABASE_PATH].append(external)

    with pytest.raises(ProductionSecretError, match="diverged"):
        commit_openbao_rotation(
            store,
            custody,
            receipt,
            receipt_file=receipt_file,
        )

    assert store.read_versioned(DATABASE_PATH).fields == external
    assert store.updates == []


def test_openbao_update_sends_expected_version_and_never_exposes_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[urllib.request.Request] = []

    def urlopen(request: urllib.request.Request, *, timeout: float) -> _Response:
        seen.append(request)
        return _Response({"data": {"version": 8}})

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    fields = _records()[DATABASE_PATH]
    version = OpenBaoClient(address="https://bao.example", token="held").cas_update(
        DATABASE_PATH,
        fields,
        expected_version=7,
    )

    assert version == 8
    body = json.loads(seen[0].data or b"{}")
    assert body["options"] == {"cas": 7}

    sentinel = "response-must-not-escape"

    def conflict(_request: urllib.request.Request, *, timeout: float) -> _Response:
        raise urllib.error.HTTPError(
            "https://bao.example",
            400,
            "conflict",
            {},
            __import__("io").BytesIO(sentinel.encode()),
        )

    monkeypatch.setattr(urllib.request, "urlopen", conflict)
    with pytest.raises(ProductionSecretError) as caught:
        OpenBaoClient(address="https://bao.example", token="held").cas_update(
            DATABASE_PATH,
            fields,
            expected_version=7,
        )
    assert sentinel not in str(caught.value)
    assert "CAS conflict" in str(caught.value)


def _committed(
    tmp_path: Path,
) -> tuple[FakeVersionedStore, Path, Path, object, SecretRotationReceipt]:
    store = FakeVersionedStore()
    custody_file, receipt_file, custody, receipt, _generated = _prepare(tmp_path, store)
    receipt = commit_openbao_rotation(
        store,
        custody,
        receipt,
        receipt_file=receipt_file,
    )
    return store, custody_file, receipt_file, custody, receipt


def test_transfer_is_fixed_to_the_named_target_and_keeps_material_off_argv(
    tmp_path: Path,
) -> None:
    store, _custody_file, _receipt_file, custody, _receipt = _committed(tmp_path)
    payload = build_rotation_payload(store, custody, _receipt)
    calls: list[tuple[Sequence[str], str]] = []
    proof = _proof(custody.operation_id)

    def runner(
        command: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        stdin = str(kwargs.get("input") or "")
        calls.append((command, stdin))
        output = proof.to_json() if command[-1].endswith(".pyz") else ""
        return subprocess.CompletedProcess(command, 0, output, "")

    observed = transfer_rotation_payload(
        payload,
        known_hosts_file=tmp_path / "known_hosts",
        runner=runner,
    )

    assert len(calls) == 2
    command, stdin = calls[1]
    assert ROTATION_TARGET in command
    assert "/usr/local/libexec/dotmac/platform-cp-secret-rotation-adapter.pyz" in (
        " ".join(command)
    )
    assert str(ROTATION_DEPLOY_DIR) not in " ".join(command)
    assert observed == proof
    for value in list(custody.prior.to_object().values()) + list(
        custody.candidate.to_object().values()
    ):
        assert value not in " ".join(command)
    assert custody.candidate.admin_password in stdin


def test_read_only_preflight_program_uses_exact_labels_and_both_health_axes() -> None:
    program = rotation_target_preflight_program()

    compile(program, "<rotation-target-preflight>", "exec")
    assert "docker','ps" in program
    assert "com.docker.compose.project=" in program
    assert "com.docker.compose.service=" in program
    assert "com.docker.compose.container-number=1" in program
    assert "com.docker.compose.oneoff=False" in program
    assert ".Config.Image" in program
    assert ".Config.Env" not in program
    assert "docker compose" not in program
    assert "'/health'" in program
    assert "'/health/ready'" in program


class _ProbeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> _ProbeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _execute_target_preflight_program(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    containers: tuple[str, ...] = ("a" * 64,),
    liveness: int = 200,
    readiness: int = 200,
) -> str:
    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        joined = " ".join(command)
        if command[:2] == ["docker", "ps"]:
            output = "".join(f"{container}\n" for container in containers)
        elif command[:2] == ["docker", "inspect"]:
            output = EXPECTED_IMAGE + "\n"
        elif command[:3] == ["docker", "image", "inspect"]:
            output = EXPECTED_REVISION + "\n"
        else:  # pragma: no cover - a new command is a security-significant change
            raise AssertionError(joined)
        return subprocess.CompletedProcess(command, 0, output, "")

    def urlopen(
        request: urllib.request.Request,
        **_kwargs: object,
    ) -> _ProbeResponse:
        status = readiness if request.full_url.endswith("/health/ready") else liveness
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, "probe", None, None)
        return _ProbeResponse(status)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: ROTATION_HOST_ID)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(
        sys,
        "argv",
        ["rotation-preflight", EXPECTED_IMAGE, EXPECTED_REVISION],
    )
    exec(
        compile(
            rotation_target_preflight_program(),
            "<rotation-target-preflight>",
            "exec",
        ),
        {"__name__": "__main__"},
    )
    return capsys.readouterr().out


def test_read_only_preflight_program_emits_bound_names_only_proof(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    proof = RotationTargetPreflightProof.from_json(
        _execute_target_preflight_program(monkeypatch, capsys)
    )
    assert proof == _preflight()


@pytest.mark.parametrize("containers", ((), ("a" * 64, "b" * 64)))
def test_read_only_preflight_program_refuses_zero_or_multiple_exact_matches(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    containers: tuple[str, ...],
) -> None:
    with pytest.raises(SystemExit) as refusal:
        _execute_target_preflight_program(
            monkeypatch,
            capsys,
            containers=containers,
        )
    assert refusal.value.code == 22


def test_read_only_preflight_program_refuses_missing_readiness_support(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as refusal:
        _execute_target_preflight_program(
            monkeypatch,
            capsys,
            liveness=200,
            readiness=404,
        )
    assert refusal.value.code == 26


def test_read_only_preflight_program_refuses_db_unready_despite_liveness(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as refusal:
        _execute_target_preflight_program(
            monkeypatch,
            capsys,
            liveness=200,
            readiness=503,
        )
    assert refusal.value.code == 27


def test_remote_preflight_binds_expected_identity_without_secret_access(
    tmp_path: Path,
) -> None:
    calls: list[tuple[tuple[str, ...], str | None]] = []

    def runner(
        command: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        stdin = kwargs.get("input")
        assert stdin is None or isinstance(stdin, str)
        calls.append((tuple(command), stdin))
        return subprocess.CompletedProcess(command, 0, _preflight().to_json(), "")

    proof = preflight_rotation_target(
        known_hosts_file=tmp_path / "known_hosts",
        expected_image_reference=EXPECTED_IMAGE,
        expected_source_revision=EXPECTED_REVISION,
        runner=runner,
    )

    assert proof == _preflight()
    assert len(calls) == 1
    command, stdin = calls[0]
    assert ROTATION_TARGET in command
    assert EXPECTED_IMAGE in command[-1]
    assert EXPECTED_REVISION in command[-1]
    assert stdin == rotation_target_preflight_program()
    assert "secret" not in command[-1].lower()


def test_adapter_install_stops_before_writing_when_preflight_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_calls = 0

    def refuse(**_kwargs: object) -> RotationTargetPreflightProof:
        raise ProductionSecretError("preflight refused")

    def runner(
        _command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal runner_calls
        runner_calls += 1
        return subprocess.CompletedProcess((), 0, "", "")

    monkeypatch.setattr(production_secrets, "preflight_rotation_target", refuse)
    with pytest.raises(ProductionSecretError, match="preflight refused"):
        production_secrets.install_rotation_adapter(
            known_hosts_file=tmp_path / "known_hosts",
            expected_image_reference=EXPECTED_IMAGE,
            expected_source_revision=EXPECTED_REVISION,
            runner=runner,
        )

    assert runner_calls == 0


def test_rotation_payload_never_reads_or_transmits_signing_or_deploy_material(
    tmp_path: Path,
) -> None:
    store, _custody_file, _receipt_file, custody, receipt = _committed(tmp_path)
    store.reads.clear()

    payload = build_rotation_payload(store, custody, receipt)
    encoded = payload.to_json()

    assert store.reads == []
    assert "licence" not in encoded
    assert "deploy" not in encoded
    assert _records()[LICENCE_SIGNING_PATH]["private_key_b64url"] not in encoded
    assert _records()[DEPLOY_SSH_PATH]["public_key_openssh"] not in encoded


def test_adapter_verifier_refuses_missing_writable_and_wrong_bytes(
    tmp_path: Path,
) -> None:
    adapter = tmp_path / "adapter.pyz"
    expected = rotation_adapter_digest()
    verifier = rotation_adapter_verifier_program()

    def verify() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- fixed interpreter and verifier
            (
                sys.executable,
                "-c",
                verifier,
                str(adapter),
                expected,
                str(os.getuid()),
                str(os.getgid()),
                str(tmp_path),
            ),
            text=True,
            capture_output=True,
            check=False,
        )

    assert verify().returncode != 0
    adapter.write_bytes(rotation_adapter_bytes())
    adapter.chmod(0o555)
    assert verify().returncode == 0
    tmp_path.chmod(0o777)
    assert verify().returncode != 0
    tmp_path.chmod(0o700)
    adapter.chmod(0o755)
    assert verify().returncode != 0
    adapter.write_bytes(rotation_adapter_bytes() + b"foreign")
    adapter.chmod(0o555)
    assert verify().returncode != 0

    real_parent = tmp_path / "real"
    real_parent.mkdir(mode=0o700)
    (real_parent / "adapter.pyz").write_bytes(rotation_adapter_bytes())
    (real_parent / "adapter.pyz").chmod(0o555)
    symlink_parent = tmp_path / "linked"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    adapter = symlink_parent / "adapter.pyz"
    assert verify().returncode != 0


def test_adapter_installer_refuses_writable_and_symlinked_ancestry(
    tmp_path: Path,
) -> None:
    archive = rotation_adapter_bytes()
    encoded = base64.b64encode(archive).decode("ascii")
    installer = rotation_adapter_installer_program()

    def install(path: Path, anchor: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- fixed interpreter and installer
            (
                sys.executable,
                "-c",
                installer,
                str(path),
                rotation_adapter_digest(),
                str(anchor),
                str(os.getuid()),
                str(os.getgid()),
            ),
            input=encoded,
            text=True,
            capture_output=True,
            check=False,
        )

    safe_root = tmp_path / "safe-root"
    safe_root.mkdir(mode=0o700)
    installed = safe_root / "libexec" / "dotmac" / "adapter.pyz"
    assert install(installed, safe_root).returncode == 0
    assert installed.read_bytes() == archive
    assert stat.S_IMODE(installed.stat().st_mode) == 0o555

    writable = safe_root / "writable"
    writable.mkdir(mode=0o777)
    writable.chmod(0o777)
    refused = writable / "adapter.pyz"
    assert install(refused, safe_root).returncode != 0
    assert not refused.exists()

    real = safe_root / "real"
    real.mkdir(mode=0o700)
    linked = safe_root / "linked"
    linked.symlink_to(real, target_is_directory=True)
    refused = linked / "adapter.pyz"
    assert install(refused, safe_root).returncode != 0
    assert not refused.exists()


def test_adapter_archive_runs_in_isolated_mode_without_checkout_imports(
    tmp_path: Path,
) -> None:
    adapter = tmp_path / "adapter.pyz"
    adapter.write_bytes(rotation_adapter_bytes())
    adapter.chmod(0o555)

    result = subprocess.run(  # noqa: S603 -- fixed interpreter and archive
        (sys.executable, "-I", str(adapter)),
        input="{}",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "ModuleNotFoundError" not in result.stderr
    assert "rotation adapter" in result.stderr


def test_adapter_archive_carries_the_runtime_oracle_and_bridge_probe(
    tmp_path: Path,
) -> None:
    """The target adapter runs outside the checkout. A source-only payload
    would let coordinator preflight pass and then fail after OpenBao advanced."""
    with zipfile.ZipFile(io.BytesIO(rotation_adapter_bytes())) as archive:
        member = f"vendor_cp/{ROTATION_RUNTIME_ORACLE_PAYLOAD}"
        assert member in archive.namelist()
        assert archive.read(member) == rotation_runtime_oracle_program().encode()
        auth_member = f"vendor_cp/{ROTATION_DATABASE_AUTH_ORACLE_PAYLOAD}"
        assert auth_member in archive.namelist()
        assert archive.read(auth_member) == (
            rotation_database_auth_oracle_program().encode()
        )
        material_member = f"vendor_cp/{ROTATION_RUNTIME_MATERIAL_ORACLE_PAYLOAD}"
        assert material_member in archive.namelist()
        assert archive.read(material_member) == (
            rotation_runtime_material_oracle_program().encode()
        )

    adapter = tmp_path / "adapter.pyz"
    adapter.write_bytes(rotation_adapter_bytes())
    imported = subprocess.run(  # noqa: S603 -- fixed interpreter and archive
        (
            sys.executable,
            "-I",
            "-c",
            "import sys;sys.path.insert(0,sys.argv[1]);"
            "from vendor_cp.production_secrets import "
            "rotation_runtime_oracle_program;"
            "print('PlatformSessionLocal' in rotation_runtime_oracle_program())",
            str(adapter),
        ),
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert imported.returncode == 0, imported.stderr
    assert imported.stdout.strip() == "True"


def test_runtime_material_oracle_matches_the_deployed_kernel_surface(
    tmp_path: Path,
) -> None:
    """The legacy artifact exposes decode only from its security module.

    CSRF is deliberately absent here too: it is preserved by the custody and
    environment byte-equality gates, not treated as runtime material this
    legacy artifact consumes.
    """
    package = tmp_path / "dotmac_kernel"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "security.py").write_text(
        "import os\n"
        "def decode_access_token(token):\n"
        "    return {'ok': True} if token == os.environ['ACCEPTED_JWT'] else None\n"
        "def hash_token(value):\n"
        "    return os.environ['ACCEPTED_SESSION_HASH']\n"
    )
    accepted_hash = "accepted-session-hash"
    payload = {
        "refused_jwt": "refused",
        "accepted_jwt": "accepted",
        "canary": "canary",
        "refused_session_hash": "refused-session-hash",
        "accepted_session_hash": accepted_hash,
    }
    environment = {
        **os.environ,
        "PYTHONPATH": str(tmp_path),
        "ACCEPTED_JWT": "accepted",
        "ACCEPTED_SESSION_HASH": accepted_hash,
    }

    result = subprocess.run(  # noqa: S603 -- fixed interpreter and program
        (sys.executable, "-c", rotation_runtime_material_oracle_program()),
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=environment,
        cwd=tmp_path,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "decode_access_token" not in (package / "__init__.py").read_text()
    assert "csrf_secret" not in rotation_runtime_material_oracle_program()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("operation_id", "wrong"),
        ("target_host_id", "another-host"),
        ("image_reference", "mutable:latest"),
        ("source_revision", "short"),
        ("adapter_digest", "sha256:" + "0" * 64),
        ("database_roles_rotated", ()),
        ("runtime_material_rotated", ()),
        ("preserved_material", ()),
        ("readiness", "unknown"),
        ("prior_authentication", "passed"),
        ("plan_rollout_state", "not-checked"),
    ),
)
def test_host_proof_refuses_every_mutated_coordinate(field: str, value: object) -> None:
    proof = _proof("a" * 32)

    with pytest.raises(ProductionSecretError):
        replace(proof, **{field: value})


class HostRunner:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls: list[tuple[tuple[str, ...], str | None]] = []
        self.pg_dump_calls = 0
        self.identity_calls = 0
        self.fail_kind: str | None = None
        self.old_auth_succeeds = False
        self.role_auth_states: dict[str, str] = {}
        self.db_rotated = False
        self.runtime_rotated = False
        self.compose_bootstrap_values: list[str | None] = []
        self.compose_image_values: list[str | None] = []
        self.app_container_ids: tuple[str, ...] = ("a" * 64,)
        self.db_container_ids: tuple[str, ...] = ("f" * 64,)
        self.liveness_status = 200
        self.readiness_status = 200

    def __call__(
        self, command: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(command)
        stdin = kwargs.get("input")
        assert stdin is None or isinstance(stdin, str)
        self.calls.append((command, stdin))
        joined = " ".join(command)
        if "compose" in command:
            environment = kwargs.get("env")
            assert environment is None or isinstance(environment, dict)
            bootstrap_value = (
                None
                if environment is None
                else environment.get("VENDOR_DB_BOOTSTRAP_PASSWORD")
            )
            assert bootstrap_value is None or isinstance(bootstrap_value, str)
            self.compose_bootstrap_values.append(bootstrap_value)
            image_value = (
                None if environment is None else environment.get("VENDOR_APP_IMAGE")
            )
            assert image_value is None or isinstance(image_value, str)
            self.compose_image_values.append(image_value)
            if (
                bootstrap_value
                != (production_secrets._ROTATION_COMPOSE_BOOTSTRAP_PLACEHOLDER)
                or image_value != self.payload.expected_image_reference
            ):
                return subprocess.CompletedProcess(
                    command,
                    1,
                    "",
                    "VENDOR_DB_BOOTSTRAP_PASSWORD is required for interpolation",
                )
        if command[:2] == ("docker", "ps"):
            joined_command = " ".join(command)
            selected = (
                self.app_container_ids
                if "com.docker.compose.service=app" in joined_command
                else self.db_container_ids
            )
            stdout = "".join(container + "\n" for container in selected)
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if command[:3] == ("docker", "inspect", "--format"):
            self.identity_calls += 1
            reference = (
                "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:"
                + (
                    "d"
                    if self.fail_kind == "image-drift" and self.identity_calls > 1
                    else "c"
                )
                * 64
            )
            return subprocess.CompletedProcess(command, 0, reference + "\n", "")
        if command[:3] == ("docker", "image", "inspect"):
            return subprocess.CompletedProcess(command, 0, "b" * 40 + "\n", "")
        if "pg_dump" in command:
            self.pg_dump_calls += 1
            state = (
                "changed"
                if self.fail_kind == "plan-drift" and self.pg_dump_calls > 1
                else "same"
            )
            return subprocess.CompletedProcess(command, 0, state, "")
        if "psql" in command and "--quiet" in command:
            if self.fail_kind == "database":
                return subprocess.CompletedProcess(command, 1, "", "refused")
            self.db_rotated = True
            return subprocess.CompletedProcess(command, 0, "", "")
        if "pg_isready" in command and "--host" in command:
            return subprocess.CompletedProcess(command, 0, "accepting\n", "")
        if (
            "psql" in command
            and "--command" in command
            and "current_database()" in command[-1]
        ):
            return subprocess.CompletedProcess(command, 0, "ready\n", "")
        if "rotation-auth" in command:
            role = command[-1]
            password = (stdin or "").strip()
            prior_by_role = {
                "app_admin": self.payload.replaced.admin_password,
                "app_user": self.payload.replaced.app_user_password,
                "platform_api": self.payload.replaced.platform_api_password,
            }
            is_prior = password == prior_by_role[role]
            state = self.role_auth_states.get(role)
            if state is None:
                accepted = (is_prior and not self.db_rotated) or (
                    not is_prior and self.db_rotated
                )
                if is_prior and self.db_rotated and self.old_auth_succeeds:
                    accepted = True
            else:
                accepted = state == "both" or state == (
                    "prior" if is_prior else "candidate"
                )
            code = 0 if accepted else 1
            return subprocess.CompletedProcess(command, code, "", "")
        if "--force-recreate" in command:
            code = 1 if self.fail_kind == "recreate" else 0
            if code == 0:
                self.runtime_rotated = True
            return subprocess.CompletedProcess(command, code, "", "")
        if command and command[0] == "curl":
            path = command[-1].removeprefix("http://127.0.0.1:8100")
            status = (
                self.liveness_status if path == "/health" else self.readiness_status
            )
            if self.fail_kind == "readiness" and path == "/health/ready":
                status = 503
            return subprocess.CompletedProcess(command, 0, str(status), "")
        if (
            command[:2] == ("docker", "exec")
            and stdin is not None
            and "PlatformSessionLocal" in stdin
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                _oracle_payload(app_refused=True, platform_refused=True),
                "",
            )
        if "decode_access_token" in joined:
            proof = json.loads(stdin or "{}")
            canary = proof["canary"]
            accepted = (
                self.payload.desired if self.runtime_rotated else self.payload.replaced
            )
            expected = hmac.new(
                accepted.session_hash_secret.encode(),
                canary.encode(),
                hashlib.sha256,
            ).hexdigest()
            code = 0 if proof["accepted_session_hash"] == expected else 1
            return subprocess.CompletedProcess(command, code, "", "")
        raise AssertionError(command)


def _host_fixture(
    tmp_path: Path,
) -> tuple[object, Path, Path, HostRunner]:
    store, _custody_file, _receipt_file, custody, _receipt = _committed(tmp_path)
    payload = build_rotation_payload(store, custody, _receipt)
    deploy_dir = tmp_path / "opt" / "dotmac" / "vendor-control-plane"
    deploy_dir.mkdir(parents=True)
    (deploy_dir / "docker-compose.production.yml").write_text("services: {}\n")
    current = (
        f"VENDOR_DB_ADMIN_PASSWORD={payload.replaced.admin_password}\n"
        f"VENDOR_DB_APP_USER_PASSWORD={payload.replaced.app_user_password}\n"
        "UNTOUCHED_CURRENT_DECLARATION=production-value\n"
        f"VENDOR_DB_PLATFORM_API_PASSWORD={payload.replaced.platform_api_password}\n"
        f"JWT_SECRET={payload.replaced.jwt_secret}\n"
        f"SESSION_HASH_SECRET={payload.replaced.session_hash_secret}\n"
        f"CSRF_SECRET={payload.replaced.csrf_secret}\n"
        "VENDOR_LICENCE_SIGNING_KEY_ID=host-declared-id\n"
    )
    (deploy_dir / ".env").write_text(current)
    (deploy_dir / ".env").chmod(0o600)
    host_id = tmp_path / "dotmac-host-id"
    host_id.write_text(ROTATION_HOST_ID + "\n")
    runner = HostRunner(payload)
    return payload, deploy_dir, host_id, runner


def test_host_rotation_proves_atomic_db_env_recreate_and_unchanged_state(
    tmp_path: Path,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    before = (deploy_dir / ".env").read_bytes()

    proof = apply_secret_rotation_on_target(
        payload,
        deploy_dir=deploy_dir,
        host_id_file=host_id,
        runner=runner,
    )

    assert proof.readiness == "passed"
    assert proof.plan_rollout_state == "unchanged"
    env = (deploy_dir / ".env").read_text()
    assert f"CSRF_SECRET={payload.replaced.csrf_secret}" in env
    assert "UNTOUCHED_CURRENT_DECLARATION=production-value\n" in env
    assert "VENDOR_LICENCE_SIGNING_KEY_ID=host-declared-id\n" in env
    expected = before
    for prior, candidate in (
        (payload.replaced.admin_password, payload.desired.admin_password),
        (payload.replaced.app_user_password, payload.desired.app_user_password),
        (
            payload.replaced.platform_api_password,
            payload.desired.platform_api_password,
        ),
        (payload.replaced.jwt_secret, payload.desired.jwt_secret),
        (payload.replaced.session_hash_secret, payload.desired.session_hash_secret),
    ):
        expected = expected.replace(prior.encode(), candidate.encode())
    assert (deploy_dir / ".env").read_bytes() == expected
    transaction = next(
        stdin
        for command, stdin in runner.calls
        if "--quiet" in command and stdin is not None
    )
    assert transaction.count("ALTER ROLE") == 3
    assert "BEGIN;" in transaction and "COMMIT;" in transaction
    for command, _stdin in runner.calls:
        rendered = " ".join(command)
        for value in list(payload.replaced.to_object().values()) + list(
            payload.desired.to_object().values()
        ):
            assert value not in rendered
        assert "docker inspect" not in rendered or ".Config.Env" not in rendered
    assert any("--force-recreate" in command for command, _ in runner.calls)
    auth_calls = [
        (command, stdin)
        for command, stdin in runner.calls
        if "rotation-auth" in command
    ]
    assert auth_calls
    assert {command[3] for command, _request in auth_calls} == {
        runner.db_container_ids[0]
    }
    assert all(command[4:6] == ("sh", "-ceu") for command, _ in auth_calls)
    assert all(
        command[6] == rotation_database_auth_oracle_program()
        for command, _ in auth_calls
    )
    assert {command[-1] for command, _request in auth_calls} == {
        "app_admin",
        "app_user",
        "platform_api",
    }


def _assert_no_target_mutation(
    deploy_dir: Path,
    runner: HostRunner,
    before: bytes,
) -> None:
    assert (deploy_dir / ".env").read_bytes() == before
    assert runner.db_rotated is False
    assert runner.runtime_rotated is False
    assert not any("ALTER ROLE" in (stdin or "") for _command, stdin in runner.calls)
    assert not any("--force-recreate" in command for command, _stdin in runner.calls)
    assert not (deploy_dir / ".rotation-state").exists()


@pytest.mark.parametrize("container_count", (0, 2))
def test_host_rotation_refuses_zero_or_multiple_exact_app_label_matches(
    tmp_path: Path,
    container_count: int,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    before = (deploy_dir / ".env").read_bytes()
    runner.app_container_ids = tuple(
        f"{number + 1:064x}" for number in range(container_count)
    )

    with pytest.raises(ProductionSecretError, match="selection is not exactly one"):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )

    _assert_no_target_mutation(deploy_dir, runner, before)


def test_missing_readiness_support_refuses_before_every_target_mutation(
    tmp_path: Path,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    before = (deploy_dir / ".env").read_bytes()
    runner.readiness_status = 404

    with pytest.raises(ProductionSecretError, match="deploy a capable image first"):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )

    assert runner.liveness_status == 200
    _assert_no_target_mutation(deploy_dir, runner, before)


def test_database_unready_refuses_while_liveness_passes_before_every_mutation(
    tmp_path: Path,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    before = (deploy_dir / ".env").read_bytes()
    runner.readiness_status = 503

    with pytest.raises(ProductionSecretError, match="database readiness"):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )

    assert runner.liveness_status == 200
    _assert_no_target_mutation(deploy_dir, runner, before)


def test_host_rotation_uses_only_an_inert_process_interpolation_for_compose(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    inherited_bootstrap = "caller_bootstrap_material_that_must_not_propagate"
    monkeypatch.setenv("VENDOR_DB_BOOTSTRAP_PASSWORD", inherited_bootstrap)

    proof = apply_secret_rotation_on_target(
        payload,
        deploy_dir=deploy_dir,
        host_id_file=host_id,
        runner=runner,
    )

    assert proof.operation_id == payload.operation_id
    assert runner.compose_bootstrap_values
    assert set(runner.compose_bootstrap_values) == {
        production_secrets._ROTATION_COMPOSE_BOOTSTRAP_PLACEHOLDER
    }
    assert set(runner.compose_image_values) == {payload.expected_image_reference}
    recreate_commands = [
        command for command, _stdin in runner.calls if "--force-recreate" in command
    ]
    assert len(recreate_commands) == 1
    assert recreate_commands[0][-1] == "app"
    assert "--no-deps" in recreate_commands[0]
    service_mutations = [
        command
        for command, _stdin in runner.calls
        if "compose" in command
        and any(verb in command for verb in ("up", "create", "restart", "start", "run"))
    ]
    assert service_mutations == recreate_commands
    rendered_argv = "\n".join(" ".join(command) for command, _stdin in runner.calls)
    persisted = "\n".join(
        path.read_text(encoding="utf-8")
        for path in deploy_dir.rglob("*")
        if path.is_file()
    )
    for forbidden in (
        inherited_bootstrap,
        production_secrets._ROTATION_COMPOSE_BOOTSTRAP_PLACEHOLDER,
    ):
        assert forbidden not in rendered_argv
        assert forbidden not in persisted
    assert "VENDOR_DB_BOOTSTRAP_PASSWORD=" not in (deploy_dir / ".env").read_text(
        encoding="utf-8"
    )
    assert "VENDOR_APP_IMAGE=" not in (deploy_dir / ".env").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        (
            "expected_image_reference",
            "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "d" * 64,
        ),
        ("expected_source_revision", "e" * 40),
    ),
)
def test_host_rotation_refuses_wrong_expected_identity_before_mutation(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    wrong = replace(payload, **{field: value})

    with pytest.raises(ProductionSecretError, match="expected identity"):
        apply_secret_rotation_on_target(
            wrong,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )

    assert not any("ALTER ROLE" in (stdin or "") for _, stdin in runner.calls)
    assert not any("--force-recreate" in command for command, _ in runner.calls)


@pytest.mark.parametrize(
    "failed_phase",
    (
        production_secrets.TargetRotationPhase.DATABASE_COMMITTED,
        production_secrets.TargetRotationPhase.ENVIRONMENT_WRITTEN,
        production_secrets.TargetRotationPhase.APP_RECREATED,
    ),
)
def test_host_retry_converges_after_process_death_at_each_mutation_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_phase: production_secrets.TargetRotationPhase,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    original = production_secrets._write_target_receipt
    injected = False

    def write_then_fail(
        path: Path, receipt: production_secrets.TargetRotationReceipt
    ) -> None:
        nonlocal injected
        if receipt.phase is failed_phase and not injected:
            injected = True
            raise RuntimeError("injected process death")
        original(path, receipt)

    monkeypatch.setattr(production_secrets, "_write_target_receipt", write_then_fail)
    with pytest.raises(RuntimeError, match="injected process death"):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )

    proof = apply_secret_rotation_on_target(
        payload,
        deploy_dir=deploy_dir,
        host_id_file=host_id,
        runner=runner,
    )
    assert proof.operation_id == payload.operation_id
    assert runner.db_rotated is True
    assert runner.runtime_rotated is True


def test_proved_target_replay_is_explicitly_historical_and_same_identity_only(
    tmp_path: Path,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    fresh = apply_secret_rotation_on_target(
        payload,
        deploy_dir=deploy_dir,
        host_id_file=host_id,
        runner=runner,
    )
    replay = apply_secret_rotation_on_target(
        payload,
        deploy_dir=deploy_dir,
        host_id_file=host_id,
        runner=runner,
    )

    assert type(fresh) is HostRotationProof
    assert type(replay) is HistoricalHostRotationProof
    assert json.loads(replay.to_json())["schema"] == (
        "platform-secret-host-historical-proof.v1"
    )

    store, custody_file, receipt_file, _custody, receipt = _committed(
        tmp_path / "coordinator"
    )
    receipt = replace(receipt, operation_id=replay.operation_id)
    completed = complete_secret_rotation(
        receipt,
        replay,
        receipt_file=receipt_file,
        custody_file=custody_file,
    )
    assert completed.phase is RotationPhase.PROVED
    assert store.history
    with pytest.raises(ProductionSecretError, match="identity"):
        complete_secret_rotation(
            receipt,
            replace(replay, source_revision="e" * 40),
            receipt_file=receipt_file,
            custody_file=custody_file,
        )


@pytest.mark.parametrize(
    "failure", ("database", "recreate", "readiness", "plan-drift", "image-drift")
)
def test_host_rotation_fails_closed_at_every_post_openbao_boundary(
    tmp_path: Path,
    failure: str,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    runner.fail_kind = failure

    with pytest.raises(ProductionSecretError):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )


def test_host_rotation_refuses_when_an_old_tcp_credential_still_works(
    tmp_path: Path,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    runner.old_auth_succeeds = True

    with pytest.raises(
        ProductionSecretError,
        match=("app_admin=both, app_user=both, platform_api=both"),
    ):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )


@pytest.mark.parametrize("state", ("neither", "both"))
def test_host_rotation_names_each_nonconvergent_role_state_before_mutation(
    tmp_path: Path, state: str
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    before = (deploy_dir / ".env").read_bytes()
    runner.role_auth_states["app_user"] = state

    with pytest.raises(
        ProductionSecretError,
        match=f"app_admin=prior, app_user={state}, platform_api=prior",
    ):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )

    _assert_no_target_mutation(deploy_dir, runner, before)


def test_host_rotation_refuses_a_csrf_change_before_any_command(tmp_path: Path) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    desired = payload.desired.to_object()
    desired["csrf_secret"] = "changed_csrf_" + "x" * 48
    raw = json.loads(payload.to_json())
    raw["desired"] = desired

    with pytest.raises(ProductionSecretError, match="preserve csrf_secret"):
        type(payload).from_json(json.dumps(raw))

    assert runner.calls == []


def test_materialization_failure_leaves_database_commit_visible_for_retry(
    tmp_path: Path,
) -> None:
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    (deploy_dir / ".env").write_text("JWT_SECRET=\n")

    with pytest.raises(ProductionSecretError, match="exactly once"):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )

    assert not any("ALTER ROLE" in (stdin or "") for _, stdin in runner.calls)
    assert not any("--force-recreate" in command for command, _ in runner.calls)


def test_completion_deletes_custody_only_after_host_proof(tmp_path: Path) -> None:
    store, custody_file, receipt_file, custody, receipt = _committed(tmp_path)
    proof = _proof(custody.operation_id)

    completed = complete_secret_rotation(
        receipt,
        proof,
        receipt_file=receipt_file,
        custody_file=custody_file,
    )

    assert completed.phase is RotationPhase.PROVED
    assert not custody_file.exists()
    assert read_rotation_receipt(receipt_file).phase is RotationPhase.PROVED
    for record in store.history.values():
        assert record


def test_rollback_is_incident_only_and_uses_historical_versions(tmp_path: Path) -> None:
    store, _custody_file, receipt_file, _custody, receipt = _committed(tmp_path)

    with pytest.raises(ProductionSecretError, match="incident-only"):
        rollback_openbao_rotation(
            store,
            receipt,
            receipt_file=receipt_file,
            incident_confirmation="yes",
        )

    custody, rollback_receipt = rollback_openbao_rotation(
        store,
        receipt,
        receipt_file=receipt_file,
        incident_confirmation=ROLLBACK_CONFIRMATION,
    )

    assert rollback_receipt.phase is RotationPhase.ROLLBACK_OPENBAO_COMMITTED
    assert store.read_versioned(DATABASE_PATH).fields == custody.prior.database_record()
    assert store.read_versioned(RUNTIME_PATH).fields == custody.prior.runtime_record()


def test_rollback_records_partial_cas_and_resumes_exact_historical_values(
    tmp_path: Path,
) -> None:
    store, _custody_file, receipt_file, custody, receipt = _committed(tmp_path)
    store.fail_next = RUNTIME_PATH

    with pytest.raises(ProductionSecretError, match="injected CAS failure"):
        rollback_openbao_rotation(
            store,
            receipt,
            receipt_file=receipt_file,
            incident_confirmation=ROLLBACK_CONFIRMATION,
        )

    partial = read_rotation_receipt(receipt_file)
    assert partial.phase is RotationPhase.ROLLBACK_OPENBAO_DATABASE_WRITTEN
    assert partial.database_rollback_version == 3
    assert store.read_versioned(DATABASE_PATH).fields == custody.prior.database_record()
    assert store.read_versioned(RUNTIME_PATH).fields == (
        custody.candidate.runtime_record()
    )

    _loaded, completed = rollback_openbao_rotation(
        store,
        partial,
        receipt_file=receipt_file,
        incident_confirmation=ROLLBACK_CONFIRMATION,
    )
    assert completed.phase is RotationPhase.ROLLBACK_OPENBAO_COMMITTED
    assert completed.runtime_rollback_version == 3
    assert store.updates == [
        (DATABASE_PATH, 1),
        (RUNTIME_PATH, 1),
        (DATABASE_PATH, 2),
        (RUNTIME_PATH, 2),
    ]


# ── the operator can diagnose the refusal, and learns nothing else ───────────


@pytest.mark.parametrize(
    ("code", "fragment"),
    sorted((code, text) for code, text in ROTATION_PREFLIGHT_REFUSALS.items()),
)
def test_every_preflight_refusal_names_itself(code: int, fragment: str) -> None:
    """All nine, planted individually - not a representative sample.

    The remote program already refuses for nine distinct reasons and says which
    in its exit status. `_run_quiet` used to discard that and surface
    "production rotation command failed" for every one, so an operator inside a
    thirty-minute window could not tell a wrong host from a duplicate container
    from a missing readiness route without re-running the program by hand.
    """
    message = _refusal_message(code, ROTATION_PREFLIGHT_REFUSALS)
    assert f"exit {code}" in message
    assert fragment in message


def test_each_refusal_is_distinguishable_from_every_other() -> None:
    """SENSITIVITY. Nine messages that all named the code but shared one text
    would satisfy the test above while telling an operator nothing."""
    rendered = {
        code: _refusal_message(code, ROTATION_PREFLIGHT_REFUSALS)
        for code in ROTATION_PREFLIGHT_REFUSALS
    }
    assert len(set(rendered.values())) == len(rendered)


def test_an_unrecognised_exit_is_still_reported_with_its_code() -> None:
    """A code outside the vocabulary must not collapse to the old message."""
    message = _refusal_message(99, ROTATION_PREFLIGHT_REFUSALS)
    assert "exit 99" in message


#: Material shaped like the things that actually leak. Planted in stderr, which
#: is free-form text from a command this module does not own.
_PLANTED_SECRETS = (
    "postgresql+psycopg://app_user:sup3rSecretPassw0rdValue@db:5432/vendor",
    "PGPASSWORD=sup3rSecretPassw0rdValue",
    "jwt_secret: aVeryLongHighEntropyTokenValue0123456789",
    "sup3rSecretPassw0rdValueThatIsLong",
)


@pytest.mark.parametrize("planted", _PLANTED_SECRETS)
def test_a_refusal_never_carries_secret_material(planted: str) -> None:
    """The fix must not trade a diagnosis problem for a disclosure one."""
    message = _refusal_message(21, ROTATION_PREFLIGHT_REFUSALS, planted)
    assert "sup3rSecretPassw0rdValue" not in message
    assert "aVeryLongHighEntropyTokenValue0123456789" not in message
    assert "<redacted>" in message
    # The diagnosis still survives the redaction.
    assert "exit 21" in message


def test_the_sanitizer_keeps_a_diagnosis_that_carries_no_material() -> None:
    """SENSITIVITY the other way. A sanitizer that erased everything would pass
    every assertion above and leave the operator exactly where they started."""
    kept = sanitize_diagnostic_text("docker: no such container")
    assert "no such container" in kept


# ── the transitional oracle is bound to one image, structurally ──────────────


def test_the_exact_pair_is_the_only_thing_that_selects_the_legacy_probe() -> None:
    """Two outcomes, never three, and no widening."""
    admitted = select_readiness_oracle(
        image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
        source_revision=LEGACY_RUNTIME_PROBE_REVISION,
    )
    assert isinstance(admitted, LegacyRuntimeProbeOracle)

    # A different revision at the SAME digest is a different artifact.
    assert isinstance(
        select_readiness_oracle(
            image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
            source_revision="b" * 40,
        ),
        HttpReadinessOracle,
    )
    # And a different digest at the same revision.
    assert isinstance(
        select_readiness_oracle(
            image_reference="ghcr.io/michaelayoade/x@sha256:" + "c" * 64,
            source_revision=LEGACY_RUNTIME_PROBE_REVISION,
        ),
        HttpReadinessOracle,
    )


def test_the_legacy_probe_cannot_be_constructed_for_another_image() -> None:
    """`permitted only for the old image` has to be inexpressible otherwise, or
    it becomes a general fallback the first time somebody is in a hurry."""
    with pytest.raises(ProductionSecretError, match="selected, never constructed"):
        LegacyRuntimeProbeOracle(
            object(),  # type: ignore[arg-type]
            LEGACY_RUNTIME_PROBE_IMAGE,
            LEGACY_RUNTIME_PROBE_REVISION,
        )


def test_the_legacy_program_refuses_an_image_that_serves_readiness() -> None:
    """The premise of the exception is that this image has no readiness route.
    If one appears, the exception no longer applies and the program says so."""
    legacy = select_readiness_oracle(
        image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
        source_revision=LEGACY_RUNTIME_PROBE_REVISION,
    )
    assert "raise SystemExit(28)" in rotation_target_preflight_program(legacy)
    http = select_readiness_oracle(
        image_reference=LEGACY_RUNTIME_PROBE_IMAGE, source_revision="d" * 40
    )
    assert "raise SystemExit(26)" in rotation_target_preflight_program(http)


# ── the runtime oracle proof cannot exist without its negative half ──────────


def _oracle_payload(*, app_refused: bool, platform_refused: bool) -> str:
    return json.dumps(
        {
            "schema": "platform-rotation-runtime-oracle.v1",
            "planes": {
                "application": {
                    "reached": True,
                    "role": "app_user",
                    "database": "vendor_control_plane",
                },
                "platform": {
                    "reached": True,
                    "role": "platform_api",
                    "database": "vendor_control_plane",
                },
            },
            "invalid_material": {
                "application": {"refused": app_refused},
                "platform": {"refused": platform_refused},
            },
        }
    )


def test_the_runtime_oracle_proof_reports_both_plane_identities() -> None:
    proof = RotationRuntimeOracleProof.from_json(
        _oracle_payload(app_refused=True, platform_refused=True)
    )
    assert proof.application_role == "app_user"
    assert proof.platform_role == "platform_api"
    assert proof.database == "vendor_control_plane"


@pytest.mark.parametrize(
    ("app_refused", "platform_refused"),
    ((False, True), (True, False), (False, False)),
)
def test_a_probe_that_accepted_invalid_material_proves_nothing(
    app_refused: bool, platform_refused: bool
) -> None:
    """A probe seen only succeeding cannot tell "the runtime reached the
    database" from "the check does not check". So the proof type refuses to
    exist without the negative half, on BOTH planes."""
    with pytest.raises(ProductionSecretError, match="proves nothing"):
        RotationRuntimeOracleProof.from_json(
            _oracle_payload(app_refused=app_refused, platform_refused=platform_refused)
        )


def test_the_runtime_oracle_payload_ships_and_keeps_both_halves() -> None:
    """The payload is package DATA, so nothing imports it and a typo would only
    surface on the target. It is read here instead.

    Both halves are asserted. A payload that lost its negative half would still
    run, still print a proof-shaped document, and prove nothing — which is the
    failure mode the whole oracle exists to avoid.
    """
    program = rotation_runtime_oracle_program()
    assert "SessionLocal" in program and "PlatformSessionLocal" in program
    assert "current_user" in program
    assert "deliberately-invalid-" in program
    assert '"refused":True' in program.replace(" ", "")


def test_the_database_authentication_oracle_is_bridge_bound_and_names_no_material() -> (
    None
):
    program = rotation_database_auth_oracle_program()

    parsed = subprocess.run(  # noqa: S603 -- fixed shell syntax check
        ("sh", "-n"),
        input=program,
        text=True,
        capture_output=True,
        check=False,
    )
    assert parsed.returncode == 0, parsed.stderr
    assert "PGPASSFILE" in program
    assert "--host db --port 5432" in program
    assert "--dbname vendor_control_plane" in program
    assert "inet_client_addr() IS NOT NULL" in program
    assert "inet_server_addr() IS NOT NULL" in program
    assert "inet '127.0.0.0/8'" in program
    assert "inet '::1'" in program
    assert "2>/dev/null" in program
    assert "echo" not in program


def test_the_oracle_payload_is_not_part_of_the_python_surface() -> None:
    """D1's guard reads every `.py` under `src` for connection constructors and
    is right to: one in this assembly's runtime IS the violation.

    The payload opens a connection in another interpreter, in another image, to
    prove invalid credentials are refused. Respelling the constructor to slip
    past the regex would be evasion; keeping the payload out of the code surface
    is what makes the guard's answer true rather than fooled. This holds it
    there.
    """
    assert ROTATION_RUNTIME_ORACLE_PAYLOAD.endswith(".pyprogram")
    source = Path(production_secrets.__file__).read_text(encoding="utf-8")
    for constructor in ("create_engine", "psycopg.connect", "sessionmaker"):
        assert constructor not in source, (
            f"{constructor} is back in the assembly's Python surface; D1 says "
            "the kernel owns the one engine"
        )


# ── the seam: the preflight must USE the oracle, not merely have one ─────────


def _wiring_runner(
    sent: list[str], *, oracle_name: str, source_revision: str
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """A runner that answers whichever program it is handed, and records both."""

    def run(
        command: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        program = str(kwargs.get("input") or "")
        sent.append(program)
        if "PlatformSessionLocal" in program:
            payload = _oracle_payload(app_refused=True, platform_refused=True)
        else:
            payload = RotationTargetPreflightProof(
                target_host_id=ROTATION_HOST_ID,
                image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
                source_revision=source_revision,
                readiness=oracle_name,
            ).to_json()
        return subprocess.CompletedProcess(list(command), 0, payload, "")

    return run


def test_the_preflight_runs_the_runtime_probe_for_the_legacy_image() -> None:
    """The wiring, not the parts.

    `select_readiness_oracle`, `probe_rotation_runtime` and the two variants all
    shipped with ZERO call sites: the preflight still generated the HTTP variant
    and would still have refused with exit 26 on the one image the exception was
    written for. Every unit test passed, because each tested a part. Nothing
    asserted the seam.
    """
    sent: list[str] = []
    proof = preflight_rotation_target(
        known_hosts_file=Path("/dev/null"),
        expected_image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
        expected_source_revision=LEGACY_RUNTIME_PROBE_REVISION,
        runner=_wiring_runner(
            sent,
            oracle_name=LegacyRuntimeProbeOracle.name,
            source_revision=LEGACY_RUNTIME_PROBE_REVISION,
        ),
    )

    assert proof.readiness == LegacyRuntimeProbeOracle.name
    # The legacy variant was generated ...
    assert "raise SystemExit(28)" in sent[0]
    assert "raise SystemExit(26)" not in sent[0]
    # ... and the database-reaching half actually ran.
    assert any("PlatformSessionLocal" in program for program in sent), (
        "the legacy oracle proves only that an HTTP process is alive unless the "
        "runtime probe runs; skipping it restores the false positive"
    )


def test_the_preflight_does_not_run_the_runtime_probe_for_any_other_image() -> None:
    """SENSITIVITY. A preflight that always ran the runtime probe would satisfy
    the test above while granting every image the exception."""
    sent: list[str] = []
    proof = preflight_rotation_target(
        known_hosts_file=Path("/dev/null"),
        expected_image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
        expected_source_revision="e" * 40,
        runner=_wiring_runner(
            sent,
            oracle_name=HttpReadinessOracle.name,
            source_revision="e" * 40,
        ),
    )
    assert proof.readiness == HttpReadinessOracle.name
    assert "raise SystemExit(26)" in sent[0]
    assert not any("PlatformSessionLocal" in program for program in sent)


def test_a_target_answering_with_the_wrong_oracle_is_refused() -> None:
    """The image is permitted one oracle. A target claiming the other one
    answered is not a target this rotation understands."""
    sent: list[str] = []
    with pytest.raises(ProductionSecretError, match="is permitted"):
        preflight_rotation_target(
            known_hosts_file=Path("/dev/null"),
            expected_image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
            expected_source_revision="f" * 40,
            runner=_wiring_runner(
                sent,
                oracle_name=LegacyRuntimeProbeOracle.name,
                source_revision="f" * 40,
            ),
        )


def test_the_preflight_proof_names_the_same_two_oracles() -> None:
    """The proof validates against literals because the oracle types are defined
    later in the module. This ties them, so a rename cannot split one vocabulary
    into two that agree only by coincidence."""
    for name in (HttpReadinessOracle.name, LegacyRuntimeProbeOracle.name):
        assert (
            RotationTargetPreflightProof(
                target_host_id=ROTATION_HOST_ID,
                image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
                source_revision=LEGACY_RUNTIME_PROBE_REVISION,
                readiness=name,
            ).readiness
            == name
        )
    with pytest.raises(ProductionSecretError, match="names no known oracle"):
        RotationTargetPreflightProof(
            target_host_id=ROTATION_HOST_ID,
            image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
            source_revision=LEGACY_RUNTIME_PROBE_REVISION,
            readiness="passed",
        )


# ── every remote command must survive the remote shell ──────────────────────


class _StopAfterFirstCall(Exception):
    """Raised by the recording runner so only the argv shape is examined."""


def _record_first_command(recorded: list[Sequence[str]]) -> Callable[..., object]:
    def run(command: Sequence[str], **_kwargs: object) -> object:
        recorded.append(list(command))
        raise _StopAfterFirstCall

    return run


@pytest.mark.parametrize(
    "invoke",
    (
        pytest.param(
            lambda runner: preflight_rotation_target(
                known_hosts_file=Path("/dev/null"),
                expected_image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
                expected_source_revision=LEGACY_RUNTIME_PROBE_REVISION,
                runner=runner,
            ),
            id="preflight",
        ),
        pytest.param(
            lambda runner: probe_rotation_runtime(
                known_hosts_file=Path("/dev/null"), runner=runner
            ),
            id="runtime-oracle",
        ),
        pytest.param(
            lambda runner: install_rotation_adapter(
                known_hosts_file=Path("/dev/null"),
                expected_image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
                expected_source_revision=LEGACY_RUNTIME_PROBE_REVISION,
                runner=runner,
            ),
            id="install-adapter",
        ),
        pytest.param(
            lambda runner: verify_rotation_adapter(
                known_hosts_file=Path("/dev/null"), runner=runner
            ),
            id="verify-adapter",
        ),
        pytest.param(
            lambda runner: retire_rotation_adapter(
                known_hosts_file=Path("/dev/null"), runner=runner
            ),
            id="retire-adapter",
        ),
    ),
)
def test_every_remote_command_survives_the_remote_shell(
    invoke: Callable[[Callable[..., object]], object],
) -> None:
    """`ssh` has no argv vector - it joins and hands the result to a SHELL.

    Three call sites passed the remote program as its own argv element. Locally
    that list looks right, and the unit tests passed because a fake runner
    receives the list and never performs the join `ssh` performs. On a real host
    the program was word-split and bash died on the first parenthesis, so the
    adapter install, verify and retire paths had never worked at all.

    The property, asserted rather than the spelling: everything after the ssh
    destination is ONE argument, and splitting it the way a shell would recovers
    the tokens intact.
    """
    recorded: list[Sequence[str]] = []
    with pytest.raises(_StopAfterFirstCall):
        invoke(_record_first_command(recorded))

    assert recorded, "no remote command was issued"
    command = list(recorded[0])
    prefix = list(_adapter_ssh_prefix(Path("/dev/null")))
    assert command[: len(prefix)] == prefix

    remainder = command[len(prefix) :]
    assert len(remainder) == 1, (
        "everything after the ssh destination is joined with spaces and reparsed "
        f"by the remote shell, so it must be one already-quoted argument: {remainder}"
    )

    tokens = shlex.split(remainder[0])
    assert tokens, "the remote command is empty after shell splitting"
    assert tokens[0] in ("python3", "docker"), tokens[0]


def test_the_quoting_helper_round_trips_a_program_full_of_shell_metacharacters() -> (
    None
):
    """SENSITIVITY. A helper that simply joined with spaces would satisfy the
    one-argument assertion above and be exactly the bug."""
    program = "import sys;print(('a b','c;d'))\nprint(\"$HOME\")"
    parts = ("python3", "-c", program, "/path with space", "sha256:" + "a" * 64)
    assert shlex.split(_remote_command(*parts)) == list(parts)
    assert _remote_command(*parts) != " ".join(parts)


def test_the_target_adapter_uses_the_legacy_oracle_before_and_after_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The coordinator seam is not enough. The installed target adapter must
    use the selected oracle on both sides of its mutation boundary."""
    payload, deploy_dir, host_id, runner = _host_fixture(tmp_path)
    payload = replace(
        payload,
        expected_image_reference=LEGACY_RUNTIME_PROBE_IMAGE,
        expected_source_revision=LEGACY_RUNTIME_PROBE_REVISION,
    )
    runner.payload = payload
    runner.readiness_status = 404
    monkeypatch.setattr(
        production_secrets,
        "_running_identity",
        lambda _deploy_dir, _runner: (
            LEGACY_RUNTIME_PROBE_IMAGE,
            LEGACY_RUNTIME_PROBE_REVISION,
        ),
    )

    proof = apply_secret_rotation_on_target(
        payload,
        deploy_dir=deploy_dir,
        host_id_file=host_id,
        runner=runner,
    )

    assert proof.readiness == "passed"
    runtime_programs = [
        stdin
        for _command, stdin in runner.calls
        if stdin is not None and "PlatformSessionLocal" in stdin
    ]
    assert len(runtime_programs) >= 2
