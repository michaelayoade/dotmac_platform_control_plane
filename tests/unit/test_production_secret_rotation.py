from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest

import vendor_cp.production_secrets as production_secrets
from vendor_cp.production_secrets import (
    DATABASE_PATH,
    DEPLOY_SSH_PATH,
    LICENCE_SIGNING_PATH,
    ROLLBACK_CONFIRMATION,
    ROTATION_DEPLOY_DIR,
    ROTATION_HOST_ID,
    ROTATION_TARGET,
    RUNTIME_PATH,
    HistoricalHostRotationProof,
    HostRotationProof,
    OpenBaoClient,
    ProductionSecretError,
    RotationPhase,
    SecretRotationReceipt,
    VersionedSecretRecord,
    apply_secret_rotation_on_target,
    build_rotation_payload,
    commit_openbao_rotation,
    complete_secret_rotation,
    execute_secret_rotation,
    prepare_secret_rotation,
    read_rotation_custody,
    read_rotation_receipt,
    rollback_openbao_rotation,
    rotation_adapter_bytes,
    rotation_adapter_digest,
    rotation_adapter_installer_program,
    rotation_adapter_verifier_program,
    transfer_rotation_payload,
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
            store,
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
        store,
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
            store,
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
        self.db_rotated = False
        self.runtime_rotated = False

    def __call__(
        self, command: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(command)
        stdin = kwargs.get("input")
        assert stdin is None or isinstance(stdin, str)
        self.calls.append((command, stdin))
        joined = " ".join(command)
        if "compose" in command and command[-3:] == ("ps", "-q", "app"):
            return subprocess.CompletedProcess(command, 0, "a" * 64 + "\n", "")
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
        if "rotation-auth" in command:
            password = (stdin or "").strip()
            is_old = password in self.payload.replaced.to_object().values()
            is_active = (is_old and not self.db_rotated) or (
                not is_old and self.db_rotated
            )
            if is_old and self.db_rotated and self.old_auth_succeeds:
                is_active = True
            code = 0 if is_active else 1
            return subprocess.CompletedProcess(command, code, "", "")
        if "--force-recreate" in command:
            code = 1 if self.fail_kind == "recreate" else 0
            if code == 0:
                self.runtime_rotated = True
            return subprocess.CompletedProcess(command, code, "", "")
        if command and command[0] == "curl":
            code = 1 if self.fail_kind == "readiness" else 0
            return subprocess.CompletedProcess(command, code, "", "")
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

    with pytest.raises(ProductionSecretError, match="mixed rotation state"):
        apply_secret_rotation_on_target(
            payload,
            deploy_dir=deploy_dir,
            host_id_file=host_id,
            runner=runner,
        )


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
