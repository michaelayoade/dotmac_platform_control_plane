"""Focused ownership mechanics only; no installed/native qualification claim.

Process/manager fixtures are explicit test seams; production accepts no callback
or caller-created success facts. These tests were not locally executed.
"""

from __future__ import annotations

import os
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from test_gate0_attester import proof_setup  # noqa: F401
from test_gate0_runner_installation import installed_model  # noqa: F401
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_runner_lifecycle as life
from vendor_cp.deployment.gate0_attester import AttesterRefused

_ACTUAL_STAGE_RECOVERY = life.InstalledA9Lifecycle._capture_partial_stage_files


def bounds():
    now = datetime.now(UTC)
    return life._OriginalBounds(
        "0" * 36,
        now,
        time.monotonic(),
        now + timedelta(seconds=60),
        now + timedelta(seconds=120),
    )


def test_original_bounds_never_gain_a_now_plus_reset():
    value = bounds()
    original = value.finalization_end
    assert value.finalization_end == original
    assert value.provisioning_end <= original
    with pytest.raises(life.LifecycleRefused):
        life._before(time.monotonic() - 1)


def test_constructor_rejects_caller_owned_dtos():
    with pytest.raises(life.LifecycleRefused):
        life.InstalledA9Lifecycle(object(), {}, bounds())
    with pytest.raises(life.LifecycleRefused):
        life.NativeJitInvocation(object(), object())
    with pytest.raises(life.LifecycleRefused):
        life.InstalledJitBinding(object(), object(), object(), object())


def test_journal_is_create_only_bounded_and_contains_no_token_hash(tmp_path):
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        journal = life._Journal(
            directory, "sha256:" + "a" * 64, "sha256:" + "b" * 64, bounds()
        )
        journal.event(
            "intent",
            {"slot": life.FileSlot.OIDC_SOURCE},
            journal.bounds.finalization_end,
        )
        first = (tmp_path / "event-000.json").read_bytes()
        value = life.strict_object(first)
        assert value["previous_digest"] is None
        assert value["facts"] == {"slot": "oidc_source"}
        assert b"token_hash" not in first and b"integrity" not in first
        another = life._Journal(
            directory, journal.binding, journal.campaign, journal.bounds
        )
        with pytest.raises(FileExistsError):
            another.event("intent", {}, another.bounds.finalization_end)
        journal.event("phase", {"name": "keys"}, journal.bounds.finalization_end)
        assert life.strict_object((tmp_path / "event-001.json").read_bytes())[
            "previous_digest"
        ] == life._hash(first)
    finally:
        os.close(directory)


@pytest.fixture
def owned_file(tmp_path, monkeypatch):
    path = tmp_path / "a.key"
    path.write_bytes(b"private unchanged key bytes")
    path.chmod(0o600)
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    parent_info, info = os.fstat(parent), os.fstat(descriptor)
    owned = life.OwnedLifecycleFile(
        life.FileSlot.A_KEY,
        parent,
        descriptor,
        parent_info.st_dev,
        parent_info.st_ino,
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        0o600,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        life._hash(path.read_bytes()),
    )
    owner = life.InstalledA9Lifecycle(life._SEAL, {}, bounds())
    owner._owned = {life.FileSlot.A_KEY: owned}
    monkeypatch.setitem(life._ROSTER, life.FileSlot.A_KEY, (tmp_path, "a.key"))
    # The fixture supplies only protected-parent metadata. Real inode/read/unlink
    # syscalls remain real; no fixture is an installed root provenance proof.
    actual_fstat = os.fstat

    def fstat(fd):
        value = actual_fstat(fd)
        if fd == parent:
            fields = {
                name: getattr(value, name)
                for name in dir(value)
                if name.startswith("st_")
            }
            fields["st_uid"] = 0
            return SimpleNamespace(**fields)
        return value

    monkeypatch.setattr(life.os, "fstat", fstat)
    monkeypatch.setattr(life.InstalledA9Lifecycle, "_event", lambda *args: None)
    try:
        yield owner, path, owned
    finally:
        for fd in (parent, descriptor) if owner._owned else ():
            try:
                os.close(fd)
            except OSError:
                pass


def test_positive_retirement_matches_real_inode_read_unlink_and_absence(owned_file):
    owner, path, owned = owned_file
    record = owner._unlink_owned(life.FileSlot.A_KEY, owner._bounds.finalization_end)
    assert record == {
        "slot": life.FileSlot.A_KEY,
        "device": owned.dev,
        "inode": owned.ino,
        "read_before_unlink": True,
        "unlinked": True,
        "absent_after_unlink": True,
    }
    assert not path.exists() and not owner._owned and not owner._failed


def test_replaced_inode_is_never_unlinked(owned_file):
    owner, path, _ = owned_file
    path.rename(path.with_name("original-held"))
    path.write_bytes(b"replacement must survive")
    with pytest.raises(life.LifecycleRefused):
        owner._unlink_owned(life.FileSlot.A_KEY, owner._bounds.finalization_end)
    assert path.read_bytes() == b"replacement must survive"


def test_unexpected_hardlink_remains_failure_without_claiming_no_copies(owned_file):
    owner, path, _ = owned_file
    other = path.with_name("unexpected-copy")
    os.link(path, other)
    record = owner._unlink_owned(life.FileSlot.A_KEY, owner._bounds.finalization_end)
    assert record["unlinked"] and record["absent_after_unlink"]
    assert not record["read_before_unlink"] and owner._failed
    assert other.read_bytes() == b"private unchanged key bytes"


def test_changed_original_can_be_removed_but_never_success(owned_file):
    owner, path, _ = owned_file
    path.write_bytes(b"changed original")
    record = owner._unlink_owned(life.FileSlot.A_KEY, owner._bounds.finalization_end)
    assert record["unlinked"] and not record["read_before_unlink"] and owner._failed


def test_read_fd_ignores_access_time_but_not_content_metadata(tmp_path):
    path = tmp_path / "public"
    path.write_bytes(b"bounded")
    fd = os.open(path, os.O_RDONLY)
    try:
        assert life._read_fd(fd, 7) == b"bounded"
        with pytest.raises(life.LifecycleRefused):
            life._read_fd(fd, 6)
        with pytest.raises(life.LifecycleRefused):
            life._read_fd(fd, 7, uid=os.getuid() + 1)
    finally:
        os.close(fd)


def test_actual_certificate_matches_key_ca_original_interval(proof_setup):  # noqa: F811
    p = proof_setup
    cert = life._checked_certificate(
        p["cert"],
        p["controller"].public_key(),
        p["operation"],
        p["now"],
        p["now"] + timedelta(seconds=119),
        p["ca"]
        .public_key()
        .public_bytes(life.Encoding.OpenSSH, life.PublicFormat.OpenSSH),
    )
    assert cert.public_bytes() == p["cert"]


@pytest.mark.parametrize(
    "change", ["key", "ca", "duration", "canonical", "digest", "principal"]
)
def test_certificate_source_or_coverage_splice_refuses(proof_setup, change):  # noqa: F811
    p = proof_setup
    raw, public, operation = p["cert"], p["controller"].public_key(), p["operation"]
    end = p["now"] + timedelta(seconds=119)
    ca = (
        p["ca"]
        .public_key()
        .public_bytes(life.Encoding.OpenSSH, life.PublicFormat.OpenSSH)
    )
    if change == "key":
        public = life.Ed25519PrivateKey.generate().public_key()
    elif change == "ca":
        ca = (
            life.Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(life.Encoding.OpenSSH, life.PublicFormat.OpenSSH)
        )
    elif change == "duration":
        end = p["now"] + timedelta(seconds=121)
    elif change == "canonical":
        raw += b"\n"
    elif change == "digest":
        operation = replace(operation, certificate_digest="sha256:" + "f" * 64)
    else:
        raw = p["certificate"](principals=[b"wrong"])
        operation = replace(operation, certificate_digest=life._hash(raw))
    with pytest.raises((life.LifecycleRefused, AttesterRefused)):
        life._checked_certificate(raw, public, operation, p["now"], end, ca)


@pytest.mark.parametrize("mode", ["nonzero", "oversized", "wait_failure"])
def test_fixed_manager_request_refuses_failure_and_reaps(tmp_path, monkeypatch, mode):
    path = tmp_path / "private-output"
    path.write_bytes(b"x" * (262145 if mode == "oversized" else 1))
    calls = []

    class Process:
        pid = 123

        def __init__(self, arguments, **kwargs):
            calls.append((arguments, kwargs))
            self.stdout = path.open("rb")
            self.waited = 0

        def wait(self, timeout):
            self.waited += 1
            if mode == "wait_failure":
                raise TimeoutError("private exception never reflected")
            return 1 if mode == "nonzero" else 0

        def poll(self):
            return 0

    monkeypatch.setattr(life.subprocess, "Popen", Process)
    native = object.__new__(life.NativeJitInvocation)
    native.selection = {"systemctl": {"path": "/usr/bin/systemctl"}}
    with pytest.raises(life.LifecycleRefused, match="^gate0_a9_lifecycle_refused$"):
        native._call(("stop", "--no-block", life._JIT_UNIT), time.monotonic() + 1)
    assert calls[0][0] == (
        "/usr/bin/systemctl",
        "--system",
        "--no-pager",
        "stop",
        "--no-block",
        life._JIT_UNIT,
    )
    assert calls[0][1]["start_new_session"] and calls[0][1]["close_fds"]
    assert calls[0][1]["stderr"] is life.subprocess.DEVNULL


def test_native_manager_has_no_generic_unit_or_command_escape():
    native = object.__new__(life.NativeJitInvocation)
    with pytest.raises(life.LifecycleRefused):
        native._call(("stop", "unrelated.service"), time.monotonic() + 1)


def test_installed_launcher_rejects_pid_or_unsigned_success_fields():
    with pytest.raises(life.LifecycleRefused):
        life.NativeJitInvocation._selection(
            {"schema": "Gate0A9JitLauncherSelection.v1", "pid": 1, "accepted": True}
        )


def test_retirement_requires_exact_manager_owned_fact():
    owner = life.InstalledA9Lifecycle(
        life._SEAL,
        {
            "lifecycle_binding_digest": "sha256:" + "a" * 64,
            "campaign_digest": "sha256:" + "b" * 64,
        },
        bounds(),
    )
    owner._phase = lambda *args: None
    result = life.strict_object(
        owner.retire_owned_files(object(), {"observed_empty": True})
    )
    assert result["result"] == "owned_files_retirement_failed"
    assert b"observed_empty" not in life.canonical(result)


@pytest.fixture
def recovery_owner(tmp_path, monkeypatch):
    """Real bounded journal/inode syscalls, no installed provenance assertion."""
    doc = {
        "lifecycle_binding_digest": "sha256:" + "a" * 64,
        "campaign_digest": "sha256:" + "b" * 64,
        "collector_uid": os.getuid(),
    }
    clock = bounds()
    monkeypatch.setattr(life, "_LIFECYCLE", tmp_path)
    monkeypatch.setattr(
        life,
        "_directory",
        lambda path, **kw: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    actual_fstat = os.fstat

    def root_metadata(fd):
        actual = actual_fstat(fd)
        return SimpleNamespace(
            **{
                name: (0 if name == "st_uid" else getattr(actual, name))
                for name in dir(actual)
                if name.startswith("st_")
            }
        )

    # Keep the real protected reader and append predicates; adapt root metadata only.
    monkeypatch.setattr(life.os, "fstat", root_metadata)
    actual_stat = os.stat

    def root_stat(*args, **kwargs):
        actual = actual_stat(*args, **kwargs)
        return SimpleNamespace(
            **{
                name: (0 if name == "st_uid" else getattr(actual, name))
                for name in dir(actual)
                if name.startswith("st_")
            }
        )

    monkeypatch.setattr(life.os, "stat", root_stat)
    monkeypatch.setattr(life, "_uid_processes", lambda *a: set())
    monkeypatch.setattr(
        life.InstalledA9Lifecycle, "_ensure_directories", lambda self: None
    )
    monkeypatch.setattr(
        life.InstalledA9Lifecycle, "_capture_partial_stage_files", lambda self: None
    )
    owner = life.InstalledA9Lifecycle(life._SEAL, doc, clock)
    owner._open_journal(fresh=True)
    for slot, name in ((life.FileSlot.A_KEY, "a.key"), (life.FileSlot.B_KEY, "b.key")):
        monkeypatch.setitem(life._ROSTER, slot, (tmp_path, name))
        path = tmp_path / name
        path.write_bytes(name.encode())
        path.chmod(0o600)
        owner._capture(slot)

    def reopen():
        owner.close()
        recovered = life.InstalledA9Lifecycle(life._SEAL, doc, clock)
        recovered._open_journal(fresh=False)
        return recovered

    yield owner, reopen, tmp_path
    owner.close()


def test_cleanup_phase_resume_never_rearms_operational_phase(recovery_owner):
    owner, reopen, _ = recovery_owner
    owner._phase("retire", owner._bounds.finalization_end)
    recovered = reopen()
    try:
        recovered._phase("retire", recovered._bounds.finalization_end)
        recovered._phase("jit", recovered._bounds.finalization_end)
        with pytest.raises(FileExistsError):
            recovered._phase("jit", recovered._bounds.finalization_end)
    finally:
        recovered.close()


@pytest.mark.parametrize("damage", ["replacement", "missing"])
def test_bad_first_recovery_slot_does_not_block_intact_secret(
    recovery_owner, monkeypatch, damage
):
    owner, reopen, path = recovery_owner
    first = path / "a.key"
    if damage == "replacement":
        first.rename(path / "held-original")
        first.write_bytes(b"replacement survives")
    else:
        first.unlink()
    recovered = reopen()

    class Manager:
        installation = SimpleNamespace(
            campaign=owner._doc["campaign_digest"], uid=os.getuid()
        )

        def owns_retirement(self, fact):
            return fact is receipt

    receipt = SimpleNamespace(observation_digest="sha256:" + "c" * 64)
    monkeypatch.setattr(life, "NativeSystemManager", Manager)
    # Test-only parent metadata; original inode syscalls remain real.
    original = life.os.fstat
    parents = {owned.parent_fd for owned in recovered._owned.values()}

    def fstat(fd):
        actual = original(fd)
        if fd in parents:
            return SimpleNamespace(
                **{
                    name: (0 if name == "st_uid" else getattr(actual, name))
                    for name in dir(actual)
                    if name.startswith("st_")
                }
            )
        return actual

    monkeypatch.setattr(life.os, "fstat", fstat)
    try:
        raw = life.strict_object(recovered.retire_owned_files(Manager(), receipt))
        assert raw["result"] == "owned_files_retirement_failed"
        assert not (path / "b.key").exists()
        if damage == "replacement":
            assert first.read_bytes() == b"replacement survives"
    finally:
        recovered.close()


@pytest.mark.parametrize(
    "predicate", ["read_before_unlink", "unlinked", "absent_after_unlink"]
)
def test_false_retired_predicate_is_sticky_after_reopen(recovery_owner, predicate):
    owner, reopen, _ = recovery_owner
    owned = owner._owned[life.FileSlot.A_KEY]
    record = {
        "slot": life.FileSlot.A_KEY,
        "device": owned.dev,
        "inode": owned.ino,
        "read_before_unlink": True,
        "unlinked": True,
        "absent_after_unlink": True,
    }
    record[predicate] = False
    owner._event("retired", record, owner._bounds.finalization_end)
    recovered = reopen()
    try:
        assert recovered._failed
        assert life.FileSlot.B_KEY in recovered._owned
    finally:
        recovered.close()


def test_explicit_failure_marker_survives_recovery(recovery_owner):
    owner, reopen, _ = recovery_owner
    owner._fail()
    recovered = reopen()
    try:
        assert recovered._failed
    finally:
        recovered.close()


def test_unconfirmed_delete_stays_failed_but_other_slot_recovers(recovery_owner):
    owner, reopen, path = recovery_owner
    owned = owner._owned[life.FileSlot.A_KEY]
    owner._event(
        "deletion-intent",
        {
            "slot": life.FileSlot.A_KEY,
            "device": owned.dev,
            "inode": owned.ino,
            "read_before_unlink": True,
        },
        owner._bounds.finalization_end,
    )
    (path / "a.key").unlink()  # crash before fsync/outcome journal
    recovered = reopen()
    try:
        assert recovered._failed and "delete:a_key" in recovered._unknown_intents
        assert life.FileSlot.B_KEY in recovered._owned
    finally:
        recovered.close()


def peer_native(monkeypatch, change=None):
    native = object.__new__(life.NativeJitInvocation)
    native.lifecycle = SimpleNamespace(_doc={"courier_uid": 4001, "courier_gid": 4002})
    cli = b"#!/usr/bin/python3\n"
    native.selection = {
        "interpreter": {"path": "/usr/bin/python3"},
        "cli": {"path": "/installed/dotmac-platform", "digest": life._hash(cli)},
        "groups": [4002],
    }
    native.owns_binding = lambda binding: True
    native._require_current = lambda: None
    measurements = iter(
        [
            (11, 4001, "77"),
            (
                12 if change == "parent" else 11,
                4003 if change == "uid" else 4001,
                "78" if change == "start" else "77",
            ),
        ]
    )
    monkeypatch.setattr(life, "measure_handoff_process", lambda pid: next(measurements))
    monkeypatch.setattr(life, "_protected", lambda *a: cli)
    monkeypatch.setattr(
        life.os,
        "readlink",
        lambda path: "/wrong" if change == "exe" else "/usr/bin/python3",
    )

    def proc(path, *args):
        if path.name == "cmdline":
            return (
                b"/usr/bin/python3\0/installed/dotmac-platform\0gate0\0"
                + (b"wrong" if change == "argv" else b"courier-original-oidc")
                + b"\0"
            )
        if path.name == "status":
            return b"Groups: " + (b"99" if change == "groups" else b"4002") + b"\n"
        if path.name == "cgroup":
            return (
                "0::" + ("/wrong" if change == "cgroup" else life._JIT_GROUP) + "\n"
            ).encode()
        return b"123\n"

    monkeypatch.setattr(life, "_proc", proc)
    peer = SimpleNamespace(
        family=life.socket.AF_UNIX,
        type=life.socket.SOCK_SEQPACKET,
        getsockopt=lambda *a: life.struct.pack("3i", 123, 4001, 4002),
    )
    return native, peer


def test_actual_peer_body_joins_ppid_separately_from_peer_pid(monkeypatch):
    native, peer = peer_native(monkeypatch)
    assert native.require_courier_peer(peer, object()) == (123, "77")


@pytest.mark.parametrize(
    "change", ["parent", "uid", "start", "exe", "argv", "groups", "cgroup"]
)
def test_actual_peer_body_rejects_repeated_measurement_splice(monkeypatch, change):
    native, peer = peer_native(monkeypatch, change)
    with pytest.raises(life.LifecycleRefused):
        native.require_courier_peer(peer, object())


def test_captured_failed_start_stops_only_matching_invocation(monkeypatch):
    native = object.__new__(life.NativeJitInvocation)
    native.bounds = bounds()
    native.lifecycle = SimpleNamespace(_fail=lambda: None)
    native.invocation = "a" * 32
    native._unit_predicates = lambda values: None
    native._show = lambda deadline: {
        "InvocationID": "b" * 32,
        "MainPID": "123",
        "ActiveState": "active",
    }
    calls = []
    native._call = lambda *args: calls.append(args)
    with pytest.raises(life.LifecycleRefused):
        native._stop_failed_start()
    assert calls == []
    native._show = lambda deadline: {
        "InvocationID": "a" * 32,
        "MainPID": "0",
        "ActiveState": "failed",
    }
    native._stop_failed_start()
    assert calls[0][0] == ("stop", "--no-block", life._JIT_UNIT)


def test_intent_only_crash_reconciles_without_adopting_or_stopping(monkeypatch):
    native = object.__new__(life.NativeJitInvocation)
    native.bounds = bounds()
    failed = []
    native.lifecycle = SimpleNamespace(
        _jit_record=None,
        _jit_start_intent=True,
        _jit_invocation=None,
        _fail=lambda: failed.append(True),
    )
    native.selection = {
        name: {"path": "/pinned/" + name, "digest": life._hash(b"pinned")}
        for name in ("systemctl", "manager")
    }
    monkeypatch.setattr(life, "_protected", lambda *a: b"pinned")
    monkeypatch.setattr(life.os, "readlink", lambda *a: "/pinned/manager")
    native._unit_predicates = lambda values: None
    native._show = lambda deadline: {"InvocationID": "b" * 32}
    calls = []
    native._call = lambda *args: calls.append(args)
    with pytest.raises(life.LifecycleRefused):
        native._restore_owned_invocation()
    assert failed and not calls and native.invocation is None


def test_authoritative_collection_installation_serves_both_readers(
    installed_model,  # noqa: F811
    monkeypatch,
):
    from vendor_cp.deployment import gate0_runner_installation as loader

    model = installed_model
    descriptor = model.descriptor
    owner = life.InstalledA9Lifecycle(
        life._SEAL,
        {
            "campaign_digest": descriptor["campaign_digest"],
            "collector_uid": descriptor["collector_uid"],
            "repository_id": int(descriptor["job"]["repository_id"]),
            "run_id": int(descriptor["job"]["run_id"]),
        },
        bounds(),
    )
    monkeypatch.setattr(
        life, "_protected", lambda path, *a, **kw: model.files[str(path)]
    )
    assert len(owner._collection_cases()) == 2
    assert len(loader.InstalledRunnerCollection.from_installed().cases) == 2
    pin = descriptor["cases"][0]["shared_packet"]
    original = dict(pin)
    for wrong in (
        {**original, "digest": "sha256:" + "f" * 64},
        {**original, "sha256": "a" * 64},
    ):
        descriptor["cases"][0]["shared_packet"] = wrong
        model.seal()
        with pytest.raises(life.LifecycleRefused):
            owner._collection_cases()
        with pytest.raises(loader.ProviderRefused):
            loader.InstalledRunnerCollection.from_installed()
    descriptor["cases"][0]["shared_packet"] = original


@pytest.mark.parametrize("fault", ["wrapper", "events", "journal"])
def test_first_native_id_precedes_readiness_and_failure_stops_owned_start(
    monkeypatch, fault
):
    owner = life.InstalledA9Lifecycle(life._SEAL, {"courier_uid": 4001}, bounds())
    native = object.__new__(life.NativeJitInvocation)
    native.lifecycle, native.bounds = owner, owner._bounds
    native._started = native._closed = False
    native.invocation = None
    native.selection = {"interpreter": {"path": "/usr/bin/python3"}}
    native._qualify_installed = lambda: None
    native._unit_predicates = lambda values: None
    owner._phase = lambda *a: None
    events = []

    def event(kind, facts, deadline):
        events.append(kind)
        if fault == "journal" and kind == "jit-invocation":
            raise OSError()

    owner._event = event
    snapshots = iter(
        [
            {
                "ActiveState": "inactive",
                "SubState": "dead",
                "MainPID": "0",
                "InvocationID": "",
            },
            {"ActiveState": "active", "MainPID": "123", "InvocationID": "a" * 32},
        ]
    )
    native._show = lambda deadline: next(snapshots)
    calls = []
    native._call = lambda args, deadline: calls.append(args)
    monkeypatch.setattr(life, "_uid_processes", lambda *a: set())
    monkeypatch.setattr(
        life.os,
        "readlink",
        lambda path: "/usr/bin/python3" if fault == "wrapper" else str(life._RUNNER),
    )
    native._measure_main = lambda *a: (123, "77", "a" * 32)
    if fault == "events":
        monkeypatch.setattr(
            life.os, "open", lambda *a, **kw: (_ for _ in ()).throw(OSError())
        )
    cleaned = []
    native._stop_failed_start = lambda: cleaned.append(native.invocation)
    with pytest.raises(life.LifecycleRefused):
        native.start_once()
    assert events[:2] == ["jit-start-intent", "jit-invocation"]
    assert cleaned == ["a" * 32]
    assert owner._failed
    assert calls == [("start", "--no-block", life._JIT_UNIT)]


@pytest.mark.skipif(
    not hasattr(os, "waitid") or not hasattr(os, "pidfd_open"),
    reason="Linux owned-child primitives",
)
@pytest.mark.parametrize("escape", [False, True])
def test_keygen_leader_exit_pipe_holder_keeps_anchor_until_group_cleanup(
    tmp_path, monkeypatch, escape
):
    """Hosted subprocess fault: production still receives only fixed keygen args."""
    import signal
    import subprocess
    import sys

    owner = life.InstalledA9Lifecycle(
        life._SEAL,
        {
            "collector_uid": os.getuid(),
            "collector_gid": os.getgid(),
            "cleanup_reserve_microseconds": 300000,
        },
        replace(bounds(), provisioning=datetime.now(UTC) + timedelta(seconds=0.8)),
    )
    monkeypatch.setattr(life, "_KEYS", tmp_path)
    monkeypatch.setattr(
        life,
        "_directory",
        lambda path, **kw: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(life.os, "fchown", lambda *a: None)
    monkeypatch.setattr(owner, "_event", lambda *a: None)
    monkeypatch.setattr(owner, "_phase", lambda *a: None)
    # Dedicated census represents this explicit planted process tree only.
    children = []

    def census(*a):
        child_file = tmp_path / "child"
        if escape and child_file.exists():
            return {int(child_file.read_text())}
        return set()

    monkeypatch.setattr(life, "_uid_processes", census)
    real_popen = subprocess.Popen
    leader = []
    reaped = []
    kill_calls = []
    real_killpg = os.killpg
    script = (
        "import os,time; p=os.fork(); "
        + ("os.setsid() if p==0 else None; " if escape else "")
        + "open('child','w').write(str(os.getpid())) if p==0 else None; "
        + "time.sleep(2) if p==0 else None; os._exit(0)"
    )

    def popen(args, **kwargs):
        # Test transport only; production invocation remains fixed and asserted.
        assert args[0] == str(life._KEYGEN) and kwargs["start_new_session"]
        process = real_popen(
            (sys.executable, "-c", script),
            cwd=tmp_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        original_wait = process.wait

        def wait(*a, **kw):
            reaped.append(process.pid)
            return original_wait(*a, **kw)

        process.wait = wait
        process.poll = lambda: pytest.fail("poll would reap the retained leader")
        leader.append(process)
        return process

    def killpg(pid, sig):
        assert not reaped and pid == leader[0].pid
        kill_calls.append((pid, sig))
        real_killpg(pid, sig)

    monkeypatch.setattr(life.subprocess, "Popen", popen)
    monkeypatch.setattr(life.os, "killpg", killpg)
    try:
        with pytest.raises(life.LifecycleRefused):
            owner.create_controller_keys()
        assert owner._failed and kill_calls and reaped
        assert not (tmp_path / "a.key").exists()
    finally:
        child_file = tmp_path / "child"
        if child_file.exists():
            children.append(int(child_file.read_text()))
        # Explicit test-owned escaped child only; no production UID-wide kill.
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_retirement_rechecks_final_native_state_after_event_observation(monkeypatch):
    native = object.__new__(life.NativeJitInvocation)
    native.bounds = bounds()
    native.lifecycle = SimpleNamespace(_jit_record={})
    native._started, native._closed, native._retirement = True, False, None
    native.invocation, native._events, native._pidfd = "a" * 32, 9, -1
    native._unit_predicates = lambda values: None
    native._call = lambda *a: None
    state = {
        "InvocationID": "a" * 32,
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ControlGroup": life._JIT_GROUP,
    }
    states = iter([dict(state), dict(state), {**state, "InvocationID": "b" * 32}])
    native._show = lambda deadline: next(states)
    monkeypatch.setattr(life.os, "pread", lambda *a: b"populated 0\n")
    with pytest.raises(life.LifecycleRefused):
        native.stop_and_observe()
    assert native._retirement is None


def test_corrupt_stage_does_not_prevent_separate_known_slot_attempt(
    recovery_owner, monkeypatch
):
    owner, _, path = recovery_owner
    # Exercise actual stage recovery body despite fixture's inert default.
    # Isolate stage ancestry only; this is not root qualification.
    monkeypatch.setattr(life, "_KEYS", path)
    monkeypatch.setattr(
        life, "_directory", lambda p, **kw: os.open(p, os.O_RDONLY | os.O_DIRECTORY)
    )
    monkeypatch.setattr(life, "_uid_processes", lambda *a: set())
    owner._stages["a"] = (99, 99)  # missing stage is a sticky anomaly
    _ACTUAL_STAGE_RECOVERY(owner)
    assert owner._failed and life.FileSlot.B_KEY in owner._owned
    # The unrelated known file remains positively identified and independently
    # eligible for retirement; failed stage recovery did not discard its FD.
    owned = owner._owned[life.FileSlot.B_KEY]
    assert os.pread(owned.file_fd, 99, 0) == b"b.key"


def retire_with_owned_test_manager(owner, monkeypatch):
    """Explicit test manager seam; real marker/journal/inode operations retained."""
    receipt = SimpleNamespace(observation_digest="sha256:" + "c" * 64)

    class Manager:
        installation = SimpleNamespace(
            campaign=owner._doc["campaign_digest"], uid=os.getuid()
        )

        def owns_retirement(self, fact):
            return fact is receipt

    monkeypatch.setattr(life, "NativeSystemManager", Manager)
    return life.strict_object(owner.retire_owned_files(Manager(), receipt))


@pytest.mark.parametrize("name", ["failed", "phase-retire"])
def test_fixed_markers_use_actual_protected_reader_and_resume_cleanup(
    recovery_owner, monkeypatch, name
):
    owner, reopen, path = recovery_owner
    if name == "failed":
        owner._fail()
    else:
        owner._phase("retire", owner._bounds.finalization_end)
    assert (path / name).read_bytes() == life._MARKER
    life._marker(path / name)  # real protected open/fstat/pread/stability predicate
    recovered = reopen()
    try:
        result = retire_with_owned_test_manager(recovered, monkeypatch)
        assert not (path / "a.key").exists() and not (path / "b.key").exists()
        assert result["result"] == (
            "owned_files_retirement_failed"
            if name == "failed"
            else "owned_files_retired"
        )
    finally:
        recovered.close()


@pytest.mark.parametrize(
    "damage", ["empty", "content", "mode", "hardlink", "symlink", "directory", "uid"]
)
def test_actual_marker_reader_rejects_wrong_metadata_and_bytes(
    recovery_owner, monkeypatch, damage
):
    _, _, path = recovery_owner
    marker = path / "marker-test"
    marker.write_bytes(life._MARKER)
    marker.chmod(0o600)
    if damage == "empty":
        marker.write_bytes(b"")
    elif damage == "content":
        marker.write_bytes(b"x" * len(life._MARKER))
    elif damage == "mode":
        marker.chmod(0o640)
    elif damage == "hardlink":
        os.link(marker, path / "extra-link")
    elif damage == "symlink":
        marker.rename(path / "original-marker")
        marker.symlink_to(path / "original-marker")
    elif damage == "directory":
        marker.unlink()
        marker.mkdir()
    elif damage == "uid":
        original = life.os.fstat

        def wrong_uid(fd):
            actual = original(fd)
            return SimpleNamespace(
                **{
                    name: (1234 if name == "st_uid" else getattr(actual, name))
                    for name in dir(actual)
                    if name.startswith("st_")
                }
            )

        monkeypatch.setattr(life.os, "fstat", wrong_uid)
    with pytest.raises((life.LifecycleRefused, OSError)):
        life._marker(marker)


@pytest.mark.parametrize("fault", ["created", "partial", "pre_fsync", "bad_commit"])
def test_torn_tail_preserved_while_verified_prefix_originals_are_cleaned(
    recovery_owner, monkeypatch, fault
):
    owner, reopen, path = recovery_owner
    journal = owner._journal
    number = journal.number
    event = path / f"event-{number:03d}.json"
    commit = path / f"committed-{number:03d}"
    original_bound = owner._bounds.finalization_end
    # Keep a replacement and an independently known original in the same prefix.
    (path / "a.key").rename(path / "held-original")
    (path / "a.key").write_bytes(b"replacement survives")
    if fault in ("created", "partial"):
        with event.open("xb") as stream:
            stream.write(b"" if fault == "created" else b'{"schema":')
        event.chmod(0o600)
    elif fault == "pre_fsync":
        actual_fsync = life.os.fsync

        def fail_event_fsync(fd):
            if event.exists() and os.fstat(fd).st_ino == event.stat().st_ino:
                raise OSError("injected before event fsync")
            actual_fsync(fd)

        with monkeypatch.context() as injection:
            injection.setattr(life.os, "fsync", fail_event_fsync)
            with pytest.raises(OSError):
                owner._event("phase", {"name": "credential"}, original_bound)
        assert event.read_bytes()  # full event bytes, no commit authority
        assert not commit.exists()
    else:
        owner._event("phase", {"name": "credential"}, original_bound)
        commit.write_bytes(b"incomplete")
    tail_bytes = event.read_bytes()
    commit_bytes = commit.read_bytes() if commit.exists() else None
    recovered = reopen()
    try:
        assert recovered._failed and recovered._journal_unavailable
        result = retire_with_owned_test_manager(recovered, monkeypatch)
        assert result["result"] == "owned_files_retirement_failed"
        assert (path / "a.key").read_bytes() == b"replacement survives"
        assert not (path / "b.key").exists()
        assert event.read_bytes() == tail_bytes
        assert (commit.read_bytes() if commit.exists() else None) == commit_bytes
        assert recovered._bounds.finalization_end == original_bound
        with pytest.raises(life.LifecycleRefused):
            recovered._phase("keys", original_bound)
        with pytest.raises(life.LifecycleRefused):
            recovered._phase("jit", original_bound)
    finally:
        recovered.close()


def test_actual_cleanup_append_failure_does_not_block_positive_unlink(
    recovery_owner, monkeypatch
):
    owner, _, path = recovery_owner
    event = path / f"event-{owner._journal.number:03d}.json"
    actual_write = life.os.write

    def fail_event_write(fd, raw):
        if event.exists() and os.fstat(fd).st_ino == event.stat().st_ino:
            raise OSError("injected append failure")
        return actual_write(fd, raw)

    with monkeypatch.context() as injection:
        injection.setattr(life.os, "write", fail_event_write)
        result = retire_with_owned_test_manager(owner, injection)
    assert result["result"] == "owned_files_retirement_failed"
    assert not (path / "a.key").exists() and not (path / "b.key").exists()
    assert event.exists() and event.read_bytes() == b""
    assert (path / "failed").read_bytes() == life._MARKER


def test_actual_journal_expiry_cannot_start_unlink(recovery_owner, monkeypatch):
    owner, _, path = recovery_owner
    original_end = owner._bounds.finalization_end
    now = [life.time.monotonic()]
    actual_event = life._Journal.event
    actual_unlink = life.os.unlink
    unlink_calls = []

    def event_then_expire(journal, kind, facts, deadline):
        actual_event(journal, kind, facts, deadline)
        if kind == "deletion-intent":
            now[0] = original_end
            life._before(deadline)

    def record_unlink(*args, **kwargs):
        unlink_calls.append(args)
        return actual_unlink(*args, **kwargs)

    monkeypatch.setattr(life.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(life._Journal, "event", event_then_expire)
    monkeypatch.setattr(life.os, "unlink", record_unlink)
    with pytest.raises(life.LifecycleRefused):
        owner._unlink_owned(life.FileSlot.A_KEY, original_end)
    assert unlink_calls == []
    assert (path / "a.key").exists() and (path / "b.key").exists()
    assert owner._failed and owner._bounds.finalization_end == original_end


def test_listener_close_failure_is_sticky_but_each_owned_file_is_attempted(
    recovery_owner, monkeypatch
):
    owner, _, path = recovery_owner

    class Listener:
        def close(self):
            raise OSError("private close failure")

    owner._listener = Listener()
    original_bound = owner._bounds.finalization_end
    result = retire_with_owned_test_manager(owner, monkeypatch)
    assert result["result"] == "owned_files_retirement_failed"
    assert "listener_close_failed" in result["reasons"]
    assert not (path / "a.key").exists() and not (path / "b.key").exists()
    assert owner._failed and owner._bounds.finalization_end == original_bound


def test_recovery_descriptor_close_error_does_not_abort_other_slot(
    recovery_owner, monkeypatch
):
    _, reopen, path = recovery_owner
    first = path / "a.key"
    first.rename(path / "held-original")
    first.write_bytes(b"replacement survives")
    replacement_inode = first.stat().st_ino
    actual_close, actual_fstat = life.os.close, life.os.fstat
    failed = []

    def close_failure(fd):
        inode = actual_fstat(fd).st_ino
        actual_close(fd)
        if inode == replacement_inode and not failed:
            failed.append(True)
            raise OSError("injected close uncertainty")

    with monkeypatch.context() as injection:
        injection.setattr(life.os, "close", close_failure)
        recovered = reopen()
    try:
        assert failed and recovered._failed
        assert life.FileSlot.B_KEY in recovered._owned
        result = retire_with_owned_test_manager(recovered, monkeypatch)
        assert result["result"] == "owned_files_retirement_failed"
        assert first.read_bytes() == b"replacement survives"
        assert not (path / "b.key").exists()
    finally:
        recovered.close()
