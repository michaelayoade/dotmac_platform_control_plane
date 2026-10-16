"""Authored filesystem tests; UID metadata alone is a non-native unit seam."""

from __future__ import annotations

import os
import stat
import time
from asyncio import CancelledError
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_e_transfer as transfer
from vendor_cp.deployment.gate0_framing import canonical


class NativeMetadata:
    """Real descriptors, bytes, modes, inode/link identity; simulated UID/GID."""

    def __init__(self, root):
        self.root = root
        self.owners = {}
        self.uid = 0

    def __getattr__(self, name):
        return getattr(os, name)

    def getuid(self):
        return self.uid

    geteuid = getuid

    def open(self, path, flags, *args, **kwargs):
        if str(path).startswith("/"):
            path = self.root / str(path).lstrip("/")
        return os.open(path, flags, *args, **kwargs)

    def fchown(self, fd, uid, gid):
        info = os.fstat(fd)
        self.owners[(info.st_dev, info.st_ino)] = (uid, gid)

    def metadata(self, info):
        uid, gid = self.owners.get((info.st_dev, info.st_ino), (0, 0))
        return SimpleNamespace(
            **{
                name: (
                    uid
                    if name == "st_uid"
                    else gid
                    if name == "st_gid"
                    else getattr(info, name)
                )
                for name in dir(info)
                if name.startswith("st_")
            }
        )

    def fstat(self, fd):
        return self.metadata(os.fstat(fd))

    def stat(self, path, *args, **kwargs):
        if str(path).startswith("/"):
            path = self.root / str(path).lstrip("/")
        return self.metadata(os.stat(path, *args, **kwargs))


@pytest.fixture
def installed(tmp_path, monkeypatch):
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    for name in ("run", "source", "run/dotmac-gate0-e", "run/dotmac-gate0-e/staging"):
        (root / name).mkdir(mode=0o700)
    (root / "source/module.py").write_bytes(b"qualified transfer source fixture")
    (root / "source/module.py").chmod(0o644)
    native = NativeMetadata(root)
    monkeypatch.setattr(transfer, "os", native)
    monkeypatch.setattr(transfer, "__file__", "/source/module.py")
    boot = "12345678-1234-1234-1234-123456789abc"
    monkeypatch.setattr(transfer, "_boot", lambda: boot)
    selection = dict(
        deadline=time.monotonic() + 30,
        boot_id=boot,
        campaign_digest="sha256:" + "a" * 64,
        lifecycle_binding_digest="sha256:" + "b" * 64,
        profile_digest="sha256:" + "c" * 64,
        source_bundle_digest="sha256:" + "d" * 64,
        courier_uid=1234,
        courier_gid=1235,
    )

    def courier():
        assert native.uid == selection["courier_uid"]
        return (
            selection,
            {},
            SimpleNamespace(boot_id=boot, finalization_end=selection["deadline"]),
        )

    monkeypatch.setattr(transfer, "_installed_public_selection", courier)
    ciphertext = b"opaque encrypted archive fixture; no plaintext collection"
    projection = dict(
        schema="Gate0EncryptedEvidenceProjection.v1",
        result="encrypted_evidence",
        ciphertext_digest=transfer._sha(ciphertext),
        ciphertext_bytes=len(ciphertext),
        campaign_digest=selection["campaign_digest"],
        source_bundle_digest=selection["source_bundle_digest"],
        policy_digest="sha256:" + "e" * 64,
        collection_digest="sha256:" + "f" * 64,
        plaintext_archive_digest="sha256:" + "1" * 64,
        inner_manifest_digest="sha256:" + "2" * 64,
        producer=dict(
            repository_id=1,
            owner_id=2,
            workflow_id=3,
            run_id=4,
            attempt=1,
            job_id=5,
            source_revision="a" * 40,
        ),
    )
    for name, raw in zip(
        transfer._NAMES, (ciphertext, canonical(projection)), strict=True
    ):
        path = root / "run/dotmac-gate0-e/staging" / name
        path.write_bytes(raw)
        path.chmod(0o600)
    return root, native, selection, projection


def publish(installed):
    root, native, selection, _ = installed
    transfer._initialize_original_transfer(**selection)
    transfer._publish_original_encrypted_pair(**selection)
    native.uid = selection["courier_uid"]
    return root / "run/dotmac-gate0-e-transfer"


def test_actual_publication_and_nonroot_verify_same_exact_pair(installed, capsys):
    pair = publish(installed)
    assert transfer.run_installed_await_e_transfer() == 0
    assert capsys.readouterr().out == "E_TRANSFER_READY\n"
    assert {p.name for p in pair.iterdir()} == set(transfer._NAMES)
    assert stat.S_IMODE(pair.stat().st_mode) == 0o750
    for name in transfer._NAMES:
        assert stat.S_IMODE((pair / name).stat().st_mode) == 0o640
        assert (pair / name).read_bytes() == (
            installed[0] / "run/dotmac-gate0-e/staging" / name
        ).read_bytes()
    state = installed[0] / "run/dotmac-gate0-e-transfer-state"
    assert stat.S_IMODE((state / "manifest.json").stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "change",
    [
        "partial",
        "extra",
        "symlink",
        "hardlink",
        "inode",
        "mode",
        "uid",
        "digest",
        "source",
        "ticket",
        "boot",
        "deadline",
        "late",
    ],
)
def test_modified_complete_pair_never_ready(installed, change, monkeypatch, capsys):
    pair = publish(installed)
    root, native, selection, _ = installed
    target = pair / transfer._NAMES[0]
    if change == "partial":
        target.unlink()
    elif change == "extra":
        (pair / "collection.json").write_bytes(b"forbidden")
    elif change == "symlink":
        target.unlink()
        target.symlink_to(root / "run/dotmac-gate0-e/staging" / transfer._NAMES[0])
    elif change == "hardlink":
        os.link(target, root / "extra-link")
    elif change == "inode":
        raw = target.read_bytes()
        target.rename(root / "old")
        target.write_bytes(raw)
        target.chmod(0o640)
    elif change == "mode":
        target.chmod(0o660)
    elif change == "uid":
        info = target.stat()
        native.owners[(info.st_dev, info.st_ino)] = (
            selection["courier_uid"],
            selection["courier_gid"],
        )
    elif change == "digest":
        target.write_bytes(b"swapped ciphertext")
    elif change == "source":
        (root / "source/module.py").write_bytes(b"changed selected source")
    elif change == "ticket":
        path = root / "run/dotmac-gate0-e-transfer-state/ticket.json"
        path.write_bytes(path.read_bytes() + b" ")
    elif change == "boot":
        monkeypatch.setattr(
            transfer, "_boot", lambda: "87654321-1234-1234-1234-123456789abc"
        )
    elif change == "deadline":
        selection["deadline"] += 1
    elif change == "late":
        monkeypatch.setattr(
            transfer.time, "monotonic", lambda: selection["deadline"] + 1
        )
    assert transfer.run_installed_await_e_transfer() == 3
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf")])
def test_invalid_original_deadline_cannot_initialize(installed, bad):
    root, _, selection, _ = installed
    selection["deadline"] = bad
    with pytest.raises(ValueError):
        transfer._initialize_original_transfer(**selection)
    assert not (root / "run/dotmac-gate0-e-transfer-state").exists()


def test_missing_ticket_never_waits_or_prints(installed, monkeypatch, capsys):
    _, native, selection, _ = installed
    native.uid = selection["courier_uid"]
    monkeypatch.setattr(
        transfer.time, "sleep", lambda _: pytest.fail("no ticket must not wait")
    )
    assert transfer.run_installed_await_e_transfer() == 3
    assert capsys.readouterr().out == ""


def test_original_ticket_wait_is_bounded_without_rearm(installed, monkeypatch):
    root, native, selection, _ = installed
    transfer._initialize_original_transfer(**selection)
    native.uid = selection["courier_uid"]
    now = [time.monotonic()]
    monkeypatch.setattr(transfer.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        transfer.time,
        "sleep",
        lambda seconds: now.__setitem__(0, selection["deadline"] + seconds),
    )
    assert transfer.run_installed_await_e_transfer() == 3
    assert not (root / "run/dotmac-gate0-e-transfer").exists()


def test_create_once_no_overwrite_and_preserve_failed_attempt(installed):
    root, _, selection, _ = installed
    transfer._initialize_original_transfer(**selection)
    ticket = root / "run/dotmac-gate0-e-transfer-state/ticket.json"
    retained = ticket.read_bytes()
    with pytest.raises(ValueError):
        transfer._initialize_original_transfer(**selection)
    assert ticket.read_bytes() == retained
    transfer._publish_original_encrypted_pair(**selection)
    with pytest.raises(ValueError):
        transfer._publish_original_encrypted_pair(**selection)
    assert ticket.read_bytes() == retained


def test_wrong_projection_source_never_exposed(installed):
    root, _, selection, projection = installed
    transfer._initialize_original_transfer(**selection)
    projection["source_bundle_digest"] = "sha256:" + "9" * 64
    (root / "run/dotmac-gate0-e/staging/gate0-evidence-public.json").write_bytes(
        canonical(projection)
    )
    with pytest.raises(ValueError):
        transfer._publish_original_encrypted_pair(**selection)
    assert not (root / "run/dotmac-gate0-e-transfer").exists()


def test_nonroot_cannot_initialize_or_publish(installed):
    _, native, selection, _ = installed
    native.uid = selection["courier_uid"]
    for operation in (
        transfer._initialize_original_transfer,
        transfer._publish_original_encrypted_pair,
    ):
        with pytest.raises(ValueError):
            operation(**selection)


@pytest.mark.parametrize("category", [KeyboardInterrupt, SystemExit, CancelledError])
def test_control_exception_category_survives_without_raw_context(
    installed, monkeypatch, category
):
    def failed():
        raise category("private raw failure")

    monkeypatch.setattr(transfer, "_await_work", failed)
    with pytest.raises(category) as caught:
        transfer.run_installed_await_e_transfer()
    assert caught.value.__context__ is None
    assert "private raw failure" not in str(caught.value)


def test_partial_failed_publication_stays_private_and_is_not_rearmed(
    installed, monkeypatch
):
    root, _, selection, _ = installed
    transfer._initialize_original_transfer(**selection)
    original = transfer._create

    def fail_second(parent, name, raw, **kwargs):
        if name == transfer._NAMES[1]:
            raise OSError("private write failure")
        return original(parent, name, raw, **kwargs)

    monkeypatch.setattr(transfer, "_create", fail_second)
    with pytest.raises(ValueError) as caught:
        transfer._publish_original_encrypted_pair(**selection)
    pair = root / "run/dotmac-gate0-e-transfer"
    assert stat.S_IMODE(pair.stat().st_mode) == 0o700
    assert {p.name for p in pair.iterdir()} == {transfer._NAMES[0]}
    assert caught.value.__context__ is None
    assert "private write failure" not in str(caught.value)
    monkeypatch.setattr(transfer, "_create", original)
    with pytest.raises(ValueError):
        transfer._publish_original_encrypted_pair(**selection)
    assert {p.name for p in pair.iterdir()} == {transfer._NAMES[0]}


def test_ticket_written_by_courier_cannot_be_positive_provenance(installed, capsys):
    publish(installed)
    root, native, selection, _ = installed
    info = (root / "run/dotmac-gate0-e-transfer-state/ticket.json").stat()
    native.owners[(info.st_dev, info.st_ino)] = (
        selection["courier_uid"],
        selection["courier_gid"],
    )
    assert transfer.run_installed_await_e_transfer() == 3
    assert capsys.readouterr().out == ""


def test_staging_plaintext_or_extra_file_refused(installed):
    root, _, selection, _ = installed
    transfer._initialize_original_transfer(**selection)
    (root / "run/dotmac-gate0-e/staging/collection.json").write_bytes(
        b"private collection"
    )
    with pytest.raises(ValueError):
        transfer._publish_original_encrypted_pair(**selection)
    assert not (root / "run/dotmac-gate0-e-transfer").exists()
