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
    ENV_SECRET_KEYS,
    LICENCE_SIGNING_PATH,
    RELAY_DISPATCHER_PATH,
    RUNTIME_PATH,
    SECRET_FIELDS,
    HostSecretBundle,
    OpenBaoClient,
    ProductionSecretError,
    _render_env,
    build_host_bundle,
    materialize_host_bundle,
    pin_product_release,
    reconcile_host_environment_declarations,
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
            # At least 32 bytes and distinct from the other two, because the
            # contract now refuses anything less — the same three ways the
            # kernel refuses a production CSRF_SECRET.
            "csrf_secret": "csrf_test_" + "c" * 40,
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
        RELAY_DISPATCHER_PATH: {"dispatcher_password": "dispatcher_test_123"},
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
CSRF_SECRET=
VENDOR_LICENCE_SIGNING_KEY_ID=vendor-prod-1
"""


def test_seed_creates_exact_five_records_and_no_registry_credential() -> None:
    client = FakeSecrets()

    created = seed_missing_records(client, keypair_factory=_keypair)

    assert set(created) == set(SECRET_FIELDS)
    assert set(client.records) == {
        LICENCE_SIGNING_PATH,
        DATABASE_PATH,
        RUNTIME_PATH,
        DEPLOY_SSH_PATH,
        # The relay dispatcher joined as its OWN record rather than as a fourth
        # field on the database one, because that record is the rotation
        # ceremony's subject and its candidate set is exact.
        RELAY_DISPATCHER_PATH,
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
    assert len(created) == 4


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


def test_reconcile_updates_only_the_owned_profile_and_preserves_secrets(
    tmp_path: Path,
) -> None:
    template = tmp_path / ".env.production.example"
    env_file = tmp_path / ".env"
    template.write_text(
        "APP_ENV=production\n"
        "VENDOR_DEPLOYMENT_PROFILE=production-bootstrap\n"
        "VENDOR_DB_ADMIN_PASSWORD=\n",
        encoding="utf-8",
    )
    env_file.write_text(
        "APP_ENV=production\n"
        "VENDOR_DEPLOYMENT_PROFILE=full\n"
        "VENDOR_DB_ADMIN_PASSWORD=must-stay-held\n"
        "OPERATOR_OWNED=must-stay-unchanged\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    changed = reconcile_host_environment_declarations(
        env_template=template,
        env_file=env_file,
    )

    rendered = env_file.read_text(encoding="utf-8")
    assert changed == ("VENDOR_DEPLOYMENT_PROFILE",)
    assert rendered.count("VENDOR_DEPLOYMENT_PROFILE=production-bootstrap") == 1
    assert "VENDOR_DB_ADMIN_PASSWORD=must-stay-held" in rendered
    assert "OPERATOR_OWNED=must-stay-unchanged" in rendered
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_reconcile_adds_a_missing_owned_profile_without_rendering_secrets(
    tmp_path: Path,
) -> None:
    template = tmp_path / ".env.production.example"
    env_file = tmp_path / ".env"
    template.write_text(
        "VENDOR_DEPLOYMENT_PROFILE=production-bootstrap\n", encoding="utf-8"
    )
    env_file.write_text("VENDOR_DB_ADMIN_PASSWORD=must-stay-held\n", encoding="utf-8")

    reconcile_host_environment_declarations(
        env_template=template,
        env_file=env_file,
    )

    assert env_file.read_text(encoding="utf-8") == (
        "VENDOR_DB_ADMIN_PASSWORD=must-stay-held\n"
        "VENDOR_DEPLOYMENT_PROFILE=production-bootstrap\n"
    )


def test_reconcile_refuses_duplicate_owned_declarations(tmp_path: Path) -> None:
    template = tmp_path / ".env.production.example"
    env_file = tmp_path / ".env"
    template.write_text(
        "VENDOR_DEPLOYMENT_PROFILE=production-bootstrap\n", encoding="utf-8"
    )
    original = (
        "VENDOR_DEPLOYMENT_PROFILE=full\n"
        "VENDOR_DEPLOYMENT_PROFILE=production-bootstrap\n"
    )
    env_file.write_text(original, encoding="utf-8")

    with pytest.raises(ProductionSecretError, match="repeats"):
        reconcile_host_environment_declarations(
            env_template=template,
            env_file=env_file,
        )

    assert env_file.read_text(encoding="utf-8") == original


def test_product_release_pin_updates_only_its_declaration_atomically(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    secret_line = "JWT_SECRET=held-value-with-spaces  "
    env_file.write_text(
        "APP_ENV=production\n"
        + secret_line
        + "\n"
        + 'VENDOR_PRODUCT_RELEASE_PINS_JSON={"dotmac-erp":'
        + '{"artifact_digest":"sha256:'
        + "c" * 64
        + '","product_manifest_digest":"sha256:'
        + "d" * 64
        + '"}}\n'
        + "OPERATOR_OWNED=unchanged\n",
        encoding="utf-8",
    )
    env_file.chmod(0o640)
    before = env_file.stat()

    changed = pin_product_release(
        env_file=env_file,
        product_code="dotmac-sub",
        artifact_digest=f"sha256:{'a' * 64}",
        product_manifest_digest=f"sha256:{'b' * 64}",
    )

    rendered = env_file.read_text(encoding="utf-8")
    declaration = next(
        line
        for line in rendered.splitlines()
        if line.startswith("VENDOR_PRODUCT_RELEASE_PINS_JSON=")
    )
    pins = json.loads(declaration.partition("=")[2])
    assert changed is True
    assert list(pins) == ["dotmac-erp", "dotmac-sub"]
    assert pins["dotmac-sub"] == {
        "artifact_digest": f"sha256:{'a' * 64}",
        "product_manifest_digest": f"sha256:{'b' * 64}",
    }
    assert secret_line in rendered
    assert "OPERATOR_OWNED=unchanged\n" in rendered
    after = env_file.stat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)


def test_product_release_pin_is_an_idempotent_noop(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        'VENDOR_PRODUCT_RELEASE_PINS_JSON={"dotmac-sub":'
        + '{"artifact_digest":"sha256:'
        + "a" * 64
        + '","product_manifest_digest":"sha256:'
        + "b" * 64
        + '"}}\n',
        encoding="utf-8",
    )
    before = env_file.stat()

    changed = pin_product_release(
        env_file=env_file,
        product_code="dotmac-sub",
        artifact_digest=f"sha256:{'a' * 64}",
        product_manifest_digest=f"sha256:{'b' * 64}",
    )

    after = env_file.stat()
    assert changed is False
    assert after.st_ino == before.st_ino
    assert after.st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize(
    "declaration, error",
    (
        ("VENDOR_PRODUCT_RELEASE_PINS_JSON=not-json\n", "valid JSON"),
        (
            "VENDOR_PRODUCT_RELEASE_PINS_JSON={}\n"
            "VENDOR_PRODUCT_RELEASE_PINS_JSON={}\n",
            "exactly once",
        ),
    ),
)
def test_product_release_pin_refuses_an_ambiguous_or_invalid_current_value(
    tmp_path: Path,
    declaration: str,
    error: str,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "JWT_SECRET=must-not-change\n" + declaration,
        encoding="utf-8",
    )
    original = env_file.read_bytes()

    with pytest.raises((ProductionSecretError, ValueError), match=error):
        pin_product_release(
            env_file=env_file,
            product_code="dotmac-sub",
            artifact_digest=f"sha256:{'a' * 64}",
            product_manifest_digest=f"sha256:{'b' * 64}",
        )

    assert env_file.read_bytes() == original


@pytest.mark.parametrize(
    "product_code, artifact_digest, manifest_digest",
    (
        (" dotmac-sub", f"sha256:{'a' * 64}", f"sha256:{'b' * 64}"),
        ("dotmac-sub", f"sha256:{'A' * 64}", f"sha256:{'b' * 64}"),
        ("dotmac-sub", f"sha256:{'a' * 63}", f"sha256:{'b' * 64}"),
        ("dotmac-sub", f"sha256:{'a' * 64}", f"sha256:{'B' * 64}"),
    ),
)
def test_product_release_pin_refuses_invalid_identity_before_writing(
    tmp_path: Path,
    product_code: str,
    artifact_digest: str,
    manifest_digest: str,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "JWT_SECRET=must-not-change\nVENDOR_PRODUCT_RELEASE_PINS_JSON={}\n",
        encoding="utf-8",
    )
    original = env_file.read_bytes()

    with pytest.raises(ProductionSecretError):
        pin_product_release(
            env_file=env_file,
            product_code=product_code,
            artifact_digest=artifact_digest,
            product_manifest_digest=manifest_digest,
        )

    assert env_file.read_bytes() == original


def test_product_release_pin_refuses_a_symlinked_environment_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "held.env"
    env_file = tmp_path / ".env"
    target.write_text("VENDOR_PRODUCT_RELEASE_PINS_JSON={}\n", encoding="utf-8")
    env_file.symlink_to(target)

    with pytest.raises(ProductionSecretError, match="regular file"):
        pin_product_release(
            env_file=env_file,
            product_code="dotmac-sub",
            artifact_digest=f"sha256:{'a' * 64}",
            product_manifest_digest=f"sha256:{'b' * 64}",
        )

    assert target.read_text(encoding="utf-8") == (
        "VENDOR_PRODUCT_RELEASE_PINS_JSON={}\n"
    )


# ── CSRF_SECRET is part of the contract, and its refusals are actionable ──────
#
# Kernel a98 `validate_settings` makes a production `CSRF_SECRET` fatal three
# ways. Until 2026-09-01 the secret contract declared no such field at all, so
# a host `.env` materialized from the template could not boot the artifact —
# and the failure arrived in the application's lifespan, after the migrations.


def test_the_runtime_record_carries_a_csrf_secret() -> None:
    assert "csrf_secret" in SECRET_FIELDS[RUNTIME_PATH]
    assert "CSRF_SECRET" in ENV_SECRET_KEYS
    assert build_host_bundle(FakeSecrets(_records())).csrf_secret


def test_a_runtime_record_without_csrf_secret_names_its_remediation() -> None:
    """A refusal that does not say what to do sends the reader to `seed`, which
    only creates ABSENT records and therefore cannot repair this one."""
    records = _records()
    del records[RUNTIME_PATH]["csrf_secret"]

    with pytest.raises(ProductionSecretError) as refusal:
        build_host_bundle(FakeSecrets(records))

    message = str(refusal.value)
    assert "missing csrf_secret" in message
    assert RUNTIME_PATH in message
    assert "will not repair one that exists" in message
    assert "at least 32 bytes" in message
    assert "distinct from `jwt_secret` and `session_hash_secret`" in message


def test_no_secret_value_reaches_a_schema_refusal() -> None:
    """The one refusal that names what is wrong is the one that risks naming
    what is in it. Field NAMES only."""
    records = _records()
    secret_values = set(records[RUNTIME_PATH].values())
    del records[RUNTIME_PATH]["csrf_secret"]

    with pytest.raises(ProductionSecretError) as refusal:
        build_host_bundle(FakeSecrets(records))

    for value in secret_values:
        assert value not in str(refusal.value)


def test_a_short_csrf_secret_is_refused() -> None:
    records = _records()
    records[RUNTIME_PATH]["csrf_secret"] = "c" * 31

    with pytest.raises(ProductionSecretError, match="at least 32 bytes"):
        build_host_bundle(FakeSecrets(records))


@pytest.mark.parametrize("twin", ["jwt_secret", "session_hash_secret"])
def test_a_csrf_secret_equal_to_another_runtime_secret_is_refused(twin: str) -> None:
    records = _records()
    records[RUNTIME_PATH][twin] = "x" * 40
    records[RUNTIME_PATH]["csrf_secret"] = "x" * 40

    with pytest.raises(ProductionSecretError, match="must differ from"):
        build_host_bundle(FakeSecrets(records))


def test_the_bundle_revalidates_csrf_over_the_ssh_pipe() -> None:
    """`from_json` is a second entry point and never calls `validate_record`."""
    bundle = _bundle()
    smuggled = json.loads(bundle.to_json())
    smuggled["csrf_secret"] = "too-short"

    with pytest.raises(ProductionSecretError, match="shorter than 32 bytes"):
        HostSecretBundle.from_json(json.dumps(smuggled))


def test_the_rendered_env_carries_the_csrf_secret() -> None:
    rendered = _render_env(_template(), _bundle())

    assert f"CSRF_SECRET={_bundle().csrf_secret}" in rendered


def test_seed_generates_a_conforming_csrf_secret_for_an_absent_record() -> None:
    """Only for an ABSENT record. `seed_missing_records` never touches one that
    exists, which is exactly why the production record needs a manual patch."""
    client = FakeSecrets()

    seed_missing_records(client, keypair_factory=_keypair)
    validate_record(RUNTIME_PATH, client.records[RUNTIME_PATH])

    existing = FakeSecrets(_records())
    before = dict(existing.records[RUNTIME_PATH])
    seed_missing_records(existing, keypair_factory=_keypair)
    assert existing.records[RUNTIME_PATH] == before
