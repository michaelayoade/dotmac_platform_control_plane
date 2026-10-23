"""Synthetic custody and filesystem proofs; no real credentials or services."""

import importlib.util
import io
import json
import os
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from vendor_cp.deploy_agent.contracts import b64
from vendor_cp.deploy_agent.keys import ConfiguredDesiredSigner
from vendor_cp.production_secrets import (
    DESIRED_SIGNING_PATH,
    LICENCE_SIGNING_PATH,
    SECRET_FIELDS,
    DesiredSignerBundle,
    OpenBaoClient,
    ProductionSecretError,
    VersionedSecretRecord,
    materialize_desired_signer,
    seed_desired_signer,
    transfer_desired_signer,
)


def bundle() -> DesiredSignerBundle:
    return DesiredSignerBundle("desired-test", b64(b"d" * 32), 1)


def install(value: DesiredSignerBundle, directory: Path) -> dict[str, object]:
    return materialize_desired_signer(
        value, directory=directory, app_owner=(os.geteuid(), os.getegid())
    )


def test_only_desired_material_is_installed_and_idempotence_keeps_inodes(tmp_path):
    directory = tmp_path.resolve() / "desired"
    sentinel = tmp_path / ".env"
    sentinel.write_bytes(b"untouched synthetic environment\n")
    before = sentinel.stat()
    value = bundle()
    result = install(value, directory)
    key = directory / "primary.key"
    identity = directory / "identity.json"
    assert result == {**value.public_identity(), "installed": True}
    assert value.private_key_b64url not in repr(value)
    assert value.private_key_b64url not in json.dumps(result)
    assert (
        ConfiguredDesiredSigner(value.key_id, str(key)).public_key_b64
        == result["public_key_b64"]
    )
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in (key, identity))
    inodes = (key.stat().st_ino, identity.stat().st_ino)
    assert install(value, directory)["installed"] is False
    assert inodes == (key.stat().st_ino, identity.stat().st_ino)
    assert sentinel.read_bytes() == b"untouched synthetic environment\n"
    after = sentinel.stat()
    assert (
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_mtime_ns,
    ) == (
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_mtime_ns,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"pointer": LICENCE_SIGNING_PATH},
        {"pointer": "secret/dotmac/platform-cp/authorization/signing-key"},
        {"private_key_b64url": "not-material"},
        {"private_key_b64url": b64(b"x" * 31)},
        {"private_key_b64url": b64(b"x" * 32) + "="},
        {"custody_version": True},
        {"custody_version": 0},
        {"key_id": "invalid key id"},
    ],
)
def test_invalid_purpose_or_material_refuses_before_filesystem_write(tmp_path, change):
    directory = tmp_path.resolve() / "not-created"
    value = replace(bundle(), **change)
    with pytest.raises(ProductionSecretError) as error:
        install(value, directory)
    assert bundle().private_key_b64url not in str(error.value)
    assert not directory.exists()


@pytest.mark.parametrize(
    "change",
    [
        {"key_id": "another-id"},
        {"private_key_b64url": b64(b"e" * 32)},
        {"custody_version": 2},
    ],
)
def test_existing_identity_cannot_be_replaced_or_silently_advanced(tmp_path, change):
    directory = tmp_path.resolve() / "desired"
    install(bundle(), directory)
    before = {p.name: (p.read_bytes(), p.stat().st_ino) for p in directory.iterdir()}
    with pytest.raises(ProductionSecretError, match="replacement refused"):
        install(replace(bundle(), **change), directory)
    assert before == {
        p.name: (p.read_bytes(), p.stat().st_ino) for p in directory.iterdir()
    }


@pytest.mark.parametrize("damage", ["mode", "missing", "extra", "symlink", "hardlink"])
def test_untrusted_or_partial_existing_installation_refuses(tmp_path, damage):
    directory = tmp_path.resolve() / "desired"
    install(bundle(), directory)
    key = directory / "primary.key"
    if damage == "mode":
        key.chmod(0o644)
    elif damage == "missing":
        (directory / "identity.json").unlink()
    elif damage == "extra":
        (directory / "unknown").write_text("retained")
    elif damage == "symlink":
        key.unlink()
        key.symlink_to(tmp_path / "elsewhere")
    else:
        os.link(key, tmp_path / "another-key-name")
    before = sorted(p.name for p in directory.iterdir())
    with pytest.raises(ProductionSecretError):
        install(bundle(), directory)
    assert sorted(p.name for p in directory.iterdir()) == before


def test_atomic_install_failure_does_not_leave_a_partial_identity(
    tmp_path, monkeypatch
):
    directory = tmp_path.resolve() / "desired"
    monkeypatch.setattr(
        os, "rename", lambda *_: (_ for _ in ()).throw(OSError("fixture"))
    )
    with pytest.raises(OSError):
        install(bundle(), directory)
    assert not directory.exists()
    assert not list(directory.parent.glob(".desired-state-*"))


@pytest.mark.parametrize("failure_at", [1, 2])
def test_member_write_failure_leaves_no_partial_install(
    tmp_path, monkeypatch, failure_at
):
    from vendor_cp import production_secrets as owner

    original = owner._atomic_write
    calls = []

    def write(*args, **kwargs):
        calls.append(args[0])
        if len(calls) == failure_at:
            raise OSError("synthetic write failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, "_atomic_write", write)
    directory = tmp_path.resolve() / "desired"
    with pytest.raises(OSError):
        install(bundle(), directory)
    assert not directory.exists()
    assert not list(directory.parent.glob(".desired-state-*"))


@pytest.mark.parametrize(
    "damage",
    [
        "writable-parent",
        "symlink-parent",
        "directory-mode",
        "metadata-mode",
        "metadata-link",
    ],
)
def test_ancestry_and_metadata_refusals(tmp_path, damage):
    parent = tmp_path.resolve() / "protected"
    parent.mkdir(mode=0o700)
    directory = parent / "desired"
    if damage == "writable-parent":
        parent.chmod(0o777)
    elif damage == "symlink-parent":
        link = tmp_path.resolve() / "redirect"
        link.symlink_to(parent, target_is_directory=True)
        directory = link / "desired"
    else:
        install(bundle(), directory)
        if damage == "directory-mode":
            directory.chmod(0o750)
        elif damage == "metadata-mode":
            (directory / "identity.json").chmod(0o644)
        else:
            os.link(directory / "identity.json", parent / "metadata-copy")
    with pytest.raises(ProductionSecretError):
        install(bundle(), directory)


def test_setgid_parent_does_not_create_non_idempotent_identity(tmp_path):
    parent = tmp_path.resolve() / "setgid"
    parent.mkdir(mode=0o2700)
    parent.chmod(0o2700)
    directory = parent / "desired"
    assert install(bundle(), directory)["installed"] is True
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert install(bundle(), directory)["installed"] is False


@pytest.mark.parametrize("mutation", ["extra", "missing", "invalid-json"])
def test_closed_transfer_schema_does_not_echo_input(mutation):
    body = json.loads(bundle().to_json())
    if mutation == "extra":
        body["unexpected"] = "fixture-only"
    elif mutation == "missing":
        del body["pointer"]
    raw = "{" if mutation == "invalid-json" else json.dumps(body)
    with pytest.raises(ProductionSecretError) as error:
        DesiredSignerBundle.from_json(raw)
    assert bundle().private_key_b64url not in str(error.value)


class Custody(OpenBaoClient):
    def __init__(self, existing=False):
        self.fields = (
            {
                "key_id": bundle().key_id,
                "private_key_b64url": bundle().private_key_b64url,
            }
            if existing
            else None
        )
        self.created = []

    def read_optional(self, path):
        assert path == DESIRED_SIGNING_PATH
        return self.fields

    def create(self, path, fields):
        assert path == DESIRED_SIGNING_PATH and self.fields is None
        self.created.append(path)
        self.fields = dict(fields)

    def read_versioned(self, path, *, version=None):
        assert path == DESIRED_SIGNING_PATH
        return VersionedSecretRecord(path=path, version=1, fields=dict(self.fields))


@pytest.mark.parametrize("existing", [False, True])
def test_explicit_seed_preserves_existing_key_and_ordinary_seed_scope(existing):
    client = Custody(existing)
    before = dict(client.fields) if existing else None
    result = seed_desired_signer(client, bundle().key_id)
    assert result["created"] is not existing
    assert client.created == ([] if existing else [DESIRED_SIGNING_PATH])
    if before:
        assert client.fields == before
    assert DESIRED_SIGNING_PATH not in SECRET_FIELDS
    assert client.fields["private_key_b64url"] not in json.dumps(result)


def test_explicit_seed_does_not_rotate_an_existing_identity():
    client = Custody(True)
    before = dict(client.fields)
    with pytest.raises(ProductionSecretError, match="another identity"):
        seed_desired_signer(client, "replacement-id")
    assert client.fields == before and not client.created


def test_actual_openbao_client_uses_exact_path_and_cas_zero(monkeypatch):
    client = OpenBaoClient(address="http://127.0.0.1:8200", token="fixture-token")
    calls = []
    monkeypatch.setattr(client, "_request", lambda *a: calls.append(a))
    fields = {
        "key_id": bundle().key_id,
        "private_key_b64url": bundle().private_key_b64url,
    }
    client.create(DESIRED_SIGNING_PATH, fields)
    assert calls == [
        ("POST", DESIRED_SIGNING_PATH, {"options": {"cas": 0}, "data": fields})
    ]
    assert client._url(DESIRED_SIGNING_PATH) == (
        "http://127.0.0.1:8200/v1/secret/data/dotmac/platform-cp/desired-state/signing-key"
    )
    with pytest.raises(ProductionSecretError):
        client._url(DESIRED_SIGNING_PATH + "/other")


def test_existing_transfer_owner_holds_material_only_on_stdin(tmp_path):
    captured = []

    def run(command, **kwargs):
        captured.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    transfer_desired_signer(
        bundle(),
        target="root@cp.example",
        target_dir="/root/pinned-owner",
        known_hosts_file=tmp_path / "known_hosts",
        runner=run,
    )
    command, kwargs = captured[0]
    assert bundle().private_key_b64url not in " ".join(command)
    assert command[-1] == "receive-desired-signer"
    assert "StrictHostKeyChecking=yes" in command
    assert DesiredSignerBundle.from_json(kwargs["input"]) == bundle()


@pytest.fixture
def cli(monkeypatch):
    import sys

    path = (
        Path(__file__).resolve().parents[2]
        / "scripts/materialize_production_secrets.py"
    )
    spec = importlib.util.spec_from_file_location("desired_materializer_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", [str(path), "receive-desired-signer"])
    return module


def test_receiver_holds_lock_and_emits_only_public_identity(cli, monkeypatch, capsys):
    events = []

    @contextmanager
    def lock():
        events.append("locked")
        yield
        events.append("released")

    def materialize(value):
        assert events == ["locked"] and value == bundle()
        return {**value.public_identity(), "installed": True}

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(bundle().to_json()))
    monkeypatch.setattr(cli, "production_deployment_lock", lock)
    monkeypatch.setattr(cli, "materialize_desired_signer", materialize)
    assert cli.main() == 0 and events == ["locked", "released"]
    output = capsys.readouterr()
    assert (
        json.loads(output.out)["public_key_b64"]
        == bundle().public_identity()["public_key_b64"]
    )
    assert bundle().private_key_b64url not in output.out + output.err


@pytest.mark.parametrize("case", ["not-root", "oversized", "malformed"])
def test_receiver_refuses_before_materialization_without_echo(
    cli, monkeypatch, capsys, case
):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 10001 if case == "not-root" else 0)
    raw = "x" * 8193 if case == "oversized" else bundle().private_key_b64url
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(raw))
    monkeypatch.setattr(
        cli, "materialize_desired_signer", lambda *_: pytest.fail("must refuse")
    )
    assert cli.main() != 0
    output = capsys.readouterr()
    assert raw not in output.out + output.err
