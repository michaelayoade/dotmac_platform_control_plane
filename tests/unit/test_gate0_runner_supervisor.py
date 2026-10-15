"""Root supervisor candidate orchestration; mocked native facts grant no acceptance."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_runner_supervisor as owner
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_runner_lifecycle import LifecycleRefused


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(owner.time, "monotonic", lambda: 10.0)
    return owner.SupervisorInstallation(
        {
            "cli": {"path": "/opt/pinned/cli"},
            "systemctl": {"path": "/usr/bin/systemctl"},
        },
        {
            "lifecycle_binding_digest": "sha256:" + "1" * 64,
            "campaign_digest": "sha256:" + "2" * 64,
            "collector_uid": 1001,
            "courier_gid": 1003,
        },
        SimpleNamespace(provisioning_end=20.0, finalization_end=100.0),
        {},
    )


def test_missing_supervisor_native_installation_refuses(monkeypatch):
    monkeypatch.setattr(
        owner, "_protected", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    with pytest.raises((FileNotFoundError, LifecycleRefused)):
        owner.SupervisorInstallation.load()
    assert owner.run_installed_lifecycle() == 3
    assert owner.run_installed_lifecycle_retirement() == 3


def test_manager_vocabulary_refuses_arbitrary_unit_before_spawn(installed, monkeypatch):
    calls = []
    monkeypatch.setattr(owner.subprocess, "Popen", lambda *a, **k: calls.append(a))
    manager = owner.SupervisorManager(installed)
    with pytest.raises(LifecycleRefused):
        manager._call(("start", "--no-block", "other.service"), 20.0)
    with pytest.raises(LifecycleRefused):
        manager._call(("daemon-reload",), 20.0)
    assert calls == []


def test_original_outer_timer_is_read_back_not_reanchored(installed, monkeypatch):
    manager = owner.SupervisorManager(installed)
    calls = []
    monkeypatch.setattr(
        manager, "_call", lambda args, deadline: calls.append((args, deadline))
    )

    def show(unit, deadline):
        assert deadline == 20.0
        if unit == owner._TIMER:
            return dict(
                ActiveState="active",
                SubState="waiting",
                NextElapseUSecMonotonic="100000000",
                AccuracyUSec="1us",
                RandomizedDelayUSec="0",
                WakeSystem="no",
                Unit=owner._EXPIRED,
                FragmentPath="/run/systemd/system/" + unit,
                DropInPaths="",
            )
        return dict(
            FragmentPath="/run/systemd/system/" + unit,
            DropInPaths="",
            Conflicts=" ".join((owner._LIFECYCLE, owner._BOOTSTRAP, owner._JIT)),
        )

    monkeypatch.setattr(manager, "show", show)
    manager.arm()
    assert calls == [(("start", "--no-block", owner._TIMER), 20.0)]
    original = show

    def wrong(unit, deadline):
        values = original(unit, deadline)
        if unit == owner._TIMER:
            values["NextElapseUSecMonotonic"] = "102000000"
        return values

    monkeypatch.setattr(manager, "show", wrong)
    with pytest.raises(LifecycleRefused):
        manager.arm()


@pytest.mark.parametrize("failure", [False, True])
def test_same_manager_file_retirement_precedes_close_and_manifest(
    installed, monkeypatch, failure
):
    events = []
    fact = SimpleNamespace(observation=canonical({"normal": True}), normal=True)

    class Manager:
        installation = SimpleNamespace(
            campaign=installed.lifecycle["campaign_digest"], uid=1001
        )

        def owns_retirement(self, value):
            events.append("owns")
            return value is fact

    manager = Manager()

    class Lock:
        def __init__(self, deadline):
            assert deadline == 19.0
            events.append("lock")

        def close(self):
            events.append("unlock")

    class Recovered:
        def retire_owned_files(self, actual, actual_fact):
            assert actual is manager and actual_fact is fact
            events.append("retire")
            return canonical(
                {
                    "schema": "Gate0A9OwnedFilesRetirementFailure.v1"
                    if failure
                    else "Gate0A9OwnedFilesRetirement.v1",
                    "result": "owned_files_retirement_failed"
                    if failure
                    else "owned_files_retired",
                }
            )

        def close(self):
            events.append("lifecycle-close")

    monkeypatch.setattr(owner, "NativeSystemManager", Manager)
    monkeypatch.setattr(
        owner.SupervisorInstallation, "load", classmethod(lambda cls: installed)
    )
    monkeypatch.setattr(owner, "JournalLock", Lock)
    monkeypatch.setattr(
        owner.InstalledA9Lifecycle,
        "from_installed",
        classmethod(lambda cls: Recovered()),
    )
    published = []
    monkeypatch.setattr(owner, "_export_directory", lambda gid, deadline: None)
    monkeypatch.setattr(
        owner,
        "_publish",
        lambda path, raw, gid, deadline, **kw: published.append(
            (path.name, raw, deadline)
        ),
    )
    monkeypatch.setattr(
        owner, "_collection_bytes", lambda uid, deadline: b'{"readiness":false}'
    )
    monkeypatch.setattr(
        owner.SupervisorManager,
        "show",
        lambda *args: dict(
            MainPID=str(os.getpid()), ActiveState="active", InvocationID="a" * 32
        ),
    )
    if failure:
        with pytest.raises(LifecycleRefused):
            owner.retire_and_export_collector(manager, fact, 19.0, complete=True)
        assert "manifest.json" not in [name for name, _, _ in published]
        assert published[-1][0] == "failure.json"
    else:
        owner.retire_and_export_collector(manager, fact, 19.0, complete=True)
        assert [name for name, _, _ in published] == [
            "collector-retirement.json",
            "owned-files-retirement.json",
            "collection.json",
            "manifest.json",
        ]
        manifest = strict_object(published[-1][1])
        assert manifest["result"] == "retained_bytes_exported"
        assert manifest["files"]["collection.json"] == {
            "bytes": 19,
            "digest": owner._hash(b'{"readiness":false}'),
        }
        assert published[2][1] == b'{"readiness":false}'
    assert (
        events.index("retire")
        < events.index("lifecycle-close")
        < events.index("unlock")
    )
    assert {deadline for _, _, deadline in published} == {19.0}


def test_export_create_only_and_actual_fifo_refusal(monkeypatch, tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    monkeypatch.setattr(owner, "_EXPORT", export)
    monkeypatch.setattr(
        owner,
        "_publication_parent",
        lambda path, deadline: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(owner.os, "fchown", lambda *args: None)
    path = export / "collection.json"
    owner._publish(path, b"actual-byte-fixture", 0, owner.time.monotonic() + 5)
    before = path.stat()
    with pytest.raises(FileExistsError):
        owner._publish(path, b"other", 0, owner.time.monotonic() + 5)
    assert path.read_bytes() == b"actual-byte-fixture"
    assert path.stat().st_ino == before.st_ino
    other = export / "failure.json"
    os.mkfifo(other, 0o600)
    with pytest.raises(FileExistsError):
        owner._publish(other, b"never-overwrites-fifo", 0, owner.time.monotonic() + 5)
    assert other.stat().st_mode & 0o170000 == 0o010000


def test_expired_export_never_creates_or_deletes(monkeypatch, tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    monkeypatch.setattr(owner, "_EXPORT", export)
    path = export / "manifest.json"
    path.write_bytes(b"foreign")
    with pytest.raises(LifecycleRefused):
        owner._publish(path, b"new", 0, owner.time.monotonic() - 1)
    assert path.read_bytes() == b"foreign"
    assert [p.name for p in export.iterdir()] == ["manifest.json"]


def test_fixed_unit_topology_and_capability_boundary():
    root = Path(__file__).resolve().parents[2] / "deploy/gate0-a9"
    lifecycle = (root / (owner._LIFECYCLE + ".in")).read_text()
    jit = (root / (owner._JIT + ".in")).read_text()
    bootstrap = (root / (owner._BOOTSTRAP + ".in")).read_text()
    assert "ExecStopPost=@BINARY@ gate0 lifecycle-retire-jit" in lifecycle
    assert "CAP_KILL" in lifecycle and "CAP_SYS_ADMIN" not in lifecycle
    for unit in (jit, bootstrap):
        assert "BindsTo=" + owner._LIFECYCLE in unit
        assert "After=" + owner._LIFECYCLE in unit
    assert "BindsTo=" + owner._BOOTSTRAP not in jit
    assert "ExecStop=" not in jit and "ExecStopPost=" not in jit
    timer = (root / (owner._TIMER + ".in")).read_text()
    assert "OnBootSec=@FINALIZATION_US@us" in timer
    assert "RuntimeMaxSec" not in lifecycle + timer


def test_actual_journal_lock_excludes_second_writer_without_pid_takeover(
    monkeypatch, tmp_path
):
    import time

    monkeypatch.setattr(owner, "_ROOT", tmp_path)
    monkeypatch.setattr(
        owner,
        "_directory",
        lambda path, **kw: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    original_stat = owner.os.fstat

    def root_metadata(fd):
        info = original_stat(fd)
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_uid=0,
            st_nlink=info.st_nlink,
        )

    monkeypatch.setattr(owner.os, "fstat", root_metadata)
    first = owner.JournalLock(time.monotonic() + 1)
    try:
        inode = (tmp_path / "lifecycle-owner.lock").stat().st_ino
        with pytest.raises(LifecycleRefused):
            owner.JournalLock(time.monotonic() + 0.03)
        assert first.fd >= 0
        assert (tmp_path / "lifecycle-owner.lock").stat().st_ino == inode
        assert (tmp_path / "lifecycle-owner.lock").read_bytes() == b""
    finally:
        first.close()
    second = owner.JournalLock(time.monotonic() + 1)
    second.close()
    assert (tmp_path / "lifecycle-owner.lock").stat().st_ino == inode


@pytest.fixture
def outer_credential_mount(monkeypatch, tmp_path):
    """Actual FDs/files; root identity/device/read-only metadata are explicit mocks."""
    import stat

    base = tmp_path / "credentials"
    service = base / "dotmac-gate0-a9-lifecycle.service"
    service.mkdir(parents=True, mode=0o700)
    credential = service / "jit-config-delivery"
    credential.write_bytes(b"ZXhhY3QtZW5jb2RlZC1jb25maWc=")
    credential.chmod(0o400)
    service.chmod(0o500)
    identities = {
        base.stat().st_ino: "base",
        service.stat().st_ino: "directory",
        credential.stat().st_ino: "file",
    }
    settings = {"owner": 0, "readonly": True, "device": 55}
    original_stat = os.fstat
    opened = []
    original_open = os.open

    def directory(path, **kwargs):
        assert path == Path("/run/credentials")
        return original_open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def metadata(fd):
        info = original_stat(fd)
        values = {
            name: getattr(info, name)
            for name in (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_uid",
                "st_gid",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        values["st_uid"] = 0
        if identities.get(info.st_ino) == "directory":
            values["st_dev"] = settings["device"]
        if stat.S_ISREG(info.st_mode) or stat.S_ISFIFO(info.st_mode):
            values["st_uid"] = settings["owner"]
        return SimpleNamespace(**values)

    def open_file(path, flags, *args, **kwargs):
        opened.append((str(path), flags))
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(owner, "_directory", directory)
    monkeypatch.setattr(owner.os, "fstat", metadata)
    monkeypatch.setattr(
        owner.os,
        "fstatvfs",
        lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if settings["readonly"] else 0),
    )
    monkeypatch.setattr(owner.os, "open", open_file)
    return credential, service, settings, opened


def test_outer_credential_accepts_separate_readonly_mount(outer_credential_mount):
    credential, _, _, opened = outer_credential_mount
    expected = credential.read_bytes()
    assert owner._read_outer_credential(owner.time.monotonic() + 5) == expected
    assert [path for path, _ in opened] == [
        "dotmac-gate0-a9-lifecycle.service",
        "jit-config-delivery",
    ]
    assert all("jit.service" not in path for path, _ in opened)
    assert all(flags & os.O_NOFOLLOW for _, flags in opened)
    assert opened[-1][1] & os.O_NONBLOCK


@pytest.mark.parametrize(
    "mutation",
    [
        "writable",
        "owner",
        "mode",
        "directory-mode",
        "symlink",
        "directory-symlink",
        "fifo",
        "oversized",
        "changed",
        "late",
    ],
)
def test_outer_credential_rejects_unqualified_or_changed_delivery(
    outer_credential_mount, monkeypatch, mutation
):
    credential, service, settings, _ = outer_credential_mount
    now = [10.0]
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    if mutation == "writable":
        settings["readonly"] = False
    elif mutation == "owner":
        settings["owner"] = 500
    elif mutation == "mode":
        credential.chmod(0o640)
    elif mutation == "directory-mode":
        service.chmod(0o750)
    elif mutation in ("symlink", "directory-symlink"):
        selected = credential if mutation == "symlink" else service
        retained = selected.with_name(selected.name + "-original")
        if mutation == "symlink":
            service.chmod(0o700)
        selected.rename(retained)
        selected.symlink_to(
            retained, target_is_directory=mutation == "directory-symlink"
        )
        if mutation == "symlink":
            service.chmod(0o500)
    elif mutation == "fifo":
        service.chmod(0o700)
        credential.unlink()
        os.mkfifo(credential, 0o400)
        service.chmod(0o500)
    elif mutation == "oversized":
        credential.chmod(0o600)
        credential.write_bytes(b"x" * 65537)
        credential.chmod(0o400)
    elif mutation in ("changed", "late"):
        original_read = os.pread
        fired = []

        def read(fd, count, offset):
            result = original_read(fd, count, offset)
            if not fired:
                fired.append(True)
                if mutation == "late":
                    now[0] = 20.0
                else:
                    credential.chmod(0o600)
            return result

        monkeypatch.setattr(owner.os, "pread", read)
    with pytest.raises((LifecycleRefused, OSError)):
        owner._read_outer_credential(20.0)


@pytest.mark.parametrize("late", [False, True])
def test_orchestration_failed_or_late_outer_delivery_never_starts_jit(
    installed, monkeypatch, late
):
    events = []
    now = [10.0]
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        owner.SupervisorInstallation, "load", classmethod(lambda cls: installed)
    )
    monkeypatch.setattr(owner.SupervisorManager, "qualify", lambda *a, **k: {})
    monkeypatch.setattr(
        owner.SupervisorManager, "arm", lambda *a: events.append("timer")
    )

    class Lock:
        def __init__(self, deadline):
            events.append("lock")

        def close(self):
            events.append("unlock")

    class Lifecycle:
        def create_controller_keys(self):
            events.append("keys")
            return (
                SimpleNamespace(
                    case_kind="consume_replay",
                    public_key=b"ssh-ed25519 A",
                    controller_fingerprint="A",
                ),
                SimpleNamespace(
                    case_kind="withdrawal_later_use",
                    public_key=b"ssh-ed25519 B",
                    controller_fingerprint="B",
                ),
            )

        def install_controller_certificates(self):
            events.append("certificates")

        def _install_original_jit_config(self, raw):
            events.append("jit-config")

        def receive_original_job_credential(self):
            events.append("jit-start")

        def close(self):
            events.append("close")

    monkeypatch.setattr(owner, "JournalLock", Lock)
    monkeypatch.setattr(
        owner.InstalledA9Lifecycle,
        "from_installed",
        classmethod(lambda cls: Lifecycle()),
    )
    monkeypatch.setattr(owner, "_publish", lambda *a, **k: None)
    monkeypatch.setattr(owner, "_delivery", lambda *a: None)
    monkeypatch.setattr(owner, "_failure", lambda *a: None)

    def refuse(deadline):
        assert deadline == installed.bounds.provisioning_end
        if late:
            now[0] = deadline
            owner._before(deadline)
        raise LifecycleRefused()

    monkeypatch.setattr(owner, "_read_outer_credential", refuse)
    assert owner.run_installed_lifecycle() == 3
    assert events == ["timer", "lock", "keys", "certificates", "close", "unlock"]


@pytest.mark.parametrize("trigger", ["link", "fsync", "close"])
def test_publication_expiry_never_starts_rollback_work(monkeypatch, tmp_path, trigger):
    import stat

    export = tmp_path / "export"
    export.mkdir()
    monkeypatch.setattr(owner, "_EXPORT", export)
    now = [10.0]
    end = 20.0
    operations = []
    real_open, real_link, real_stat, real_unlink, real_sync, real_close = (
        os.open,
        os.link,
        os.stat,
        os.unlink,
        os.fsync,
        os.close,
    )

    def parent(path, deadline):
        operations.append(("directory", now[0], deadline))
        assert now[0] < deadline
        return real_open(path, os.O_RDONLY | os.O_DIRECTORY)

    def link(*args, **kwargs):
        operations.append(("link", now[0], end))
        real_link(*args, **kwargs)
        if trigger == "link":
            now[0] = end

    def sync(fd):
        operations.append(("fsync", now[0], end))
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        real_sync(fd)
        if trigger == "fsync" and directory:
            now[0] = end

    def close(fd):
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        real_close(fd)
        if trigger == "close" and directory:
            now[0] = end

    def inspect(*args, **kwargs):
        operations.append(("stat", now[0], end))
        return real_stat(*args, **kwargs)

    def unlink(*args, **kwargs):
        operations.append(("unlink", now[0], end))
        return real_unlink(*args, **kwargs)

    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(owner, "_publication_parent", parent)
    monkeypatch.setattr(owner.os, "fchown", lambda *a: None)
    monkeypatch.setattr(owner.os, "link", link)
    monkeypatch.setattr(owner.os, "fsync", sync)
    monkeypatch.setattr(owner.os, "close", close)
    monkeypatch.setattr(owner.os, "stat", inspect)
    monkeypatch.setattr(owner.os, "unlink", unlink)
    with pytest.raises(LifecycleRefused):
        owner._publish(export / "manifest.json", b"uncertain-documentary-bytes", 0, end)
    assert all(start < deadline for _, start, deadline in operations)
    assert sum(name == "directory" for name, _, _ in operations) == 1
    assert (export / "manifest.json").read_bytes() == b"uncertain-documentary-bytes"


@pytest.mark.parametrize("replacement", [False, True])
def test_in_bound_rollback_removes_only_exact_owned_final(
    monkeypatch, tmp_path, replacement
):
    import stat

    export = tmp_path / "export"
    export.mkdir()
    path = export / "manifest.json"
    monkeypatch.setattr(owner, "_EXPORT", export)
    monkeypatch.setattr(
        owner,
        "_publication_parent",
        lambda path, deadline: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(owner.os, "fchown", lambda *a: None)
    real_sync = os.fsync
    failures = []

    def sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failures:
            failures.append(True)
            if replacement:
                path.rename(export / "retained-owned")
                path.write_bytes(b"foreign-replacement")
            raise OSError("synthetic in-bound directory sync failure")
        return real_sync(fd)

    monkeypatch.setattr(owner.os, "fsync", sync)
    with pytest.raises(OSError):
        owner._publish(path, b"owned", 0, owner.time.monotonic() + 5)
    if replacement:
        assert path.read_bytes() == b"foreign-replacement"
        assert (export / "retained-owned").read_bytes() == b"owned"
    else:
        assert not path.exists()


def test_publication_parent_stops_walk_when_open_crosses_original_end(monkeypatch):
    now = [10.0]
    operations = []
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])

    def opening(*args, **kwargs):
        operations.append("open")
        now[0] = 20.0
        return 123

    monkeypatch.setattr(owner.os, "open", opening)
    monkeypatch.setattr(owner.os, "close", lambda fd: operations.append("close"))
    monkeypatch.setattr(
        owner.os, "fstat", lambda fd: operations.append("unexpected-stat")
    )
    with pytest.raises(LifecycleRefused):
        owner._publication_parent(owner._EXPORT, 20.0)
    assert operations == ["open", "close"]


def test_uncertain_parent_close_preserves_documentary_inode(monkeypatch, tmp_path):
    import stat

    export = tmp_path / "export"
    export.mkdir()
    monkeypatch.setattr(owner, "_EXPORT", export)
    opens = []
    real_close = os.close

    def parent(path, deadline):
        opens.append(path)
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY)

    def close(fd):
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        real_close(fd)
        if directory:
            raise OSError("uncertain close state")

    monkeypatch.setattr(owner, "_publication_parent", parent)
    monkeypatch.setattr(owner.os, "fchown", lambda *a: None)
    monkeypatch.setattr(owner.os, "close", close)
    with pytest.raises(OSError):
        owner._publish(
            export / "manifest.json",
            b"retained-uncertain",
            0,
            owner.time.monotonic() + 5,
        )
    assert len(opens) == 1
    assert (export / "manifest.json").read_bytes() == b"retained-uncertain"
