from __future__ import annotations

import base64
import io
import json
import stat
import subprocess
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from vendor_cp.production_secrets import (
    DATABASE_PATH,
    DEPLOY_SSH_PATH,
    LICENCE_SIGNING_PATH,
    RUNTIME_PATH,
    SECRET_FIELDS,
    HostSecretBundle,
    OpenBaoClient,
    ProductionSecretError,
    build_host_bundle,
    materialize_host_bundle,
    seed_missing_records,
    sync_github_deploy_key,
    transfer_host_bundle,
    validate_record,
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
            "admin_password": "admin_test_123",
            "app_user_password": "app_test_123",
            "platform_api_password": "platform_test_123",
        },
        RUNTIME_PATH: {
            "jwt_secret": "jwt_test_123",
            "session_hash_secret": "session_test_123",
        },
        DEPLOY_SSH_PATH: {
            "private_key_openssh": (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "test-fixture\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            ),
            "public_key_openssh": "ssh-ed25519 AAAA vendor-cp-prod-deploy",
            "username": "root",
        },
    }


class FakeSecrets:
    def __init__(self, records: Mapping[str, Mapping[str, str]] | None = None) -> None:
        self.records = {path: dict(fields) for path, fields in (records or {}).items()}
        self.created: list[str] = []

    def read_optional(self, path: str) -> dict[str, str] | None:
        fields = self.records.get(path)
        return dict(fields) if fields is not None else None

    def create(self, path: str, fields: Mapping[str, str]) -> None:
        assert path not in self.records
        self.records[path] = dict(fields)
        self.created.append(path)


def _keypair() -> tuple[str, str]:
    fields = _records()[DEPLOY_SSH_PATH]
    return fields["private_key_openssh"], fields["public_key_openssh"]


def _bundle() -> HostSecretBundle:
    return build_host_bundle(FakeSecrets(_records()))


def _template() -> str:
    return """\
APP_ENV=production
VENDOR_DB_ADMIN_PASSWORD=
VENDOR_DB_APP_USER_PASSWORD=
VENDOR_DB_PLATFORM_API_PASSWORD=
JWT_SECRET=
SESSION_HASH_SECRET=
VENDOR_LICENCE_SIGNING_KEY_ID=vendor-prod-1
"""


def test_seed_creates_exact_four_records_and_no_registry_credential() -> None:
    client = FakeSecrets()

    created = seed_missing_records(client, keypair_factory=_keypair)

    assert set(created) == set(SECRET_FIELDS)
    assert set(client.records) == {
        LICENCE_SIGNING_PATH,
        DATABASE_PATH,
        RUNTIME_PATH,
        DEPLOY_SSH_PATH,
    }
    assert all(
        set(client.records[path]) == fields for path, fields in SECRET_FIELDS.items()
    )
    assert all("ghcr" not in path.lower() for path in client.records)


def test_seed_preserves_existing_records() -> None:
    records = _records()
    original = dict(records[DATABASE_PATH])
    client = FakeSecrets({DATABASE_PATH: original})

    created = seed_missing_records(client, keypair_factory=_keypair)

    assert DATABASE_PATH not in created
    assert client.records[DATABASE_PATH] == original
    assert len(created) == 3


def test_signing_material_refuses_non_urlsafe_base64() -> None:
    fields = dict(_records()[LICENCE_SIGNING_PATH])
    fields["private_key_b64url"] = "+" * 43

    with pytest.raises(ProductionSecretError, match="base64url"):
        validate_record(LICENCE_SIGNING_PATH, fields)


def test_host_bundle_excludes_the_deployment_private_key() -> None:
    records = _records()

    bundle = build_host_bundle(FakeSecrets(records))

    assert "private_key_openssh" not in bundle.__dataclass_fields__
    assert records[DEPLOY_SSH_PATH]["private_key_openssh"] not in bundle.to_json()


def test_materialization_writes_expected_files_and_modes(tmp_path: Path) -> None:
    env_template = tmp_path / ".env.production.example"
    env_file = tmp_path / ".env"
    signing_key_file = tmp_path / "run" / "primary.key"
    authorized_keys_file = tmp_path / "root" / ".ssh" / "authorized_keys"
    env_template.write_text(_template(), encoding="utf-8")
    authorized_keys_file.parent.mkdir(parents=True)
    authorized_keys_file.write_text("ssh-ed25519 OLD operator\n", encoding="utf-8")

    for _ in range(2):
        materialize_host_bundle(
            _bundle(),
            env_template=env_template,
            env_file=env_file,
            signing_key_file=signing_key_file,
            authorized_keys_file=authorized_keys_file,
            app_owner=None,
        )

    env = env_file.read_text(encoding="utf-8")
    assert "VENDOR_DB_ADMIN_PASSWORD=admin_test_123" in env
    assert "VENDOR_LICENCE_SIGNING_KEY_ID=vendor-prod-test" in env
    assert signing_key_file.read_text(encoding="utf-8") == _b64url(b"k" * 32) + "\n"
    authorized_keys = authorized_keys_file.read_text(encoding="utf-8")
    assert "ssh-ed25519 OLD operator" in authorized_keys
    assert authorized_keys.count("ssh-ed25519 AAAA vendor-cp-prod-deploy") == 1
    for path in (env_file, signing_key_file, authorized_keys_file):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(signing_key_file.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(authorized_keys_file.parent.stat().st_mode) == 0o700


def test_invalid_bundle_refuses_before_writing_any_file(tmp_path: Path) -> None:
    env_template = tmp_path / ".env.production.example"
    env_file = tmp_path / ".env"
    signing_key_file = tmp_path / "run" / "primary.key"
    authorized_keys_file = tmp_path / "root" / ".ssh" / "authorized_keys"
    env_template.write_text(_template(), encoding="utf-8")
    bundle = _bundle()
    invalid = replace(bundle, admin_password="unsafe=value")

    with pytest.raises(ProductionSecretError, match="URL-safe"):
        materialize_host_bundle(
            invalid,
            env_template=env_template,
            env_file=env_file,
            signing_key_file=signing_key_file,
            authorized_keys_file=authorized_keys_file,
            app_owner=None,
        )

    assert not env_file.exists()
    assert not signing_key_file.exists()
    assert not authorized_keys_file.exists()


def test_transfer_places_the_bundle_only_on_ssh_stdin(tmp_path: Path) -> None:
    calls: list[tuple[Sequence[str], str]] = []

    def runner(
        command: Sequence[str], *, input: str, text: bool, check: bool
    ) -> subprocess.CompletedProcess[str]:
        assert text is True
        assert check is True
        calls.append((command, input))
        return subprocess.CompletedProcess(command, 0)

    bundle = _bundle()
    transfer_host_bundle(
        bundle,
        target="root@149.102.158.144",
        target_dir="/opt/dotmac/vendor-control-plane",
        known_hosts_file=tmp_path / "known_hosts",
        runner=runner,
    )

    command, stdin = calls[0]
    assert bundle.admin_password not in " ".join(command)
    assert bundle.licence_private_key_b64url not in " ".join(command)
    assert json.loads(stdin)["admin_password"] == bundle.admin_password


def test_transfer_refuses_a_shell_metacharacter_in_the_target_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(ProductionSecretError, match="absolute safe path"):
        transfer_host_bundle(
            _bundle(),
            target="root@149.102.158.144",
            target_dir="/opt/vendor;touch-bad",
            known_hosts_file=tmp_path / "known_hosts",
        )


def test_github_deploy_key_is_passed_only_on_stdin() -> None:
    calls: list[tuple[Sequence[str], str]] = []

    def runner(
        command: Sequence[str], *, input: str, text: bool, check: bool
    ) -> subprocess.CompletedProcess[str]:
        assert text is True
        assert check is True
        calls.append((command, input))
        return subprocess.CompletedProcess(command, 0)

    records = _records()
    sync_github_deploy_key(
        FakeSecrets(records),
        repository="michaelayoade/dotmac_vendor_control_plane",
        environment="production",
        runner=runner,
    )

    command, stdin = calls[0]
    private_key = records[DEPLOY_SSH_PATH]["private_key_openssh"]
    assert private_key not in " ".join(command)
    assert stdin == private_key


class _Response:
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return b"{}"


def test_openbao_create_is_create_only(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[urllib.request.Request] = []

    def urlopen(request: urllib.request.Request, *, timeout: float) -> _Response:
        assert timeout == 15.0
        seen.append(request)
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    fields = _records()[DATABASE_PATH]

    OpenBaoClient(address="https://bao.example", token="fixture").create(
        DATABASE_PATH, fields
    )

    request = seen[0]
    assert request.method == "POST"
    assert json.loads(request.data or b"{}")["options"] == {"cas": 0}


def test_openbao_error_does_not_disclose_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "must-not-escape"

    def urlopen(_request: urllib.request.Request, *, timeout: float) -> _Response:
        raise urllib.error.HTTPError(
            "https://bao.example",
            500,
            "failed",
            {},
            io.BytesIO(sentinel.encode()),
        )

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    client = OpenBaoClient(address="https://bao.example", token="fixture")

    with pytest.raises(ProductionSecretError) as caught:
        client.read_optional(DATABASE_PATH)

    assert sentinel not in str(caught.value)
