"""Focused handoff adapter tests; these confer no installed/root acceptance."""

import base64
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time
import types
from datetime import UTC, datetime, timedelta

import pytest

from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_handoff import (
    FixedLaunchHolder,
    InstalledHandoffReceiver,
    RootFrameSequence,
    RootHostBinding,
    decode_case_a_complete,
    decode_root_event,
    decode_terminal,
    encode_case_a_complete,
    encode_root_event,
    parse_holder_auth_info,
)

CAMPAIGN = "sha256:" + "a" * 64


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def test_raw_root_bytes_preserved_and_campaign_bound():
    root = b'{"schema":"RootFixture.v1"}'
    event = encode_root_event(CAMPAIGN, "NS3", root)
    assert decode_root_event(event, CAMPAIGN) == ("NS3", root)
    with pytest.raises(ProviderRefused):
        decode_root_event(event, "sha256:" + "b" * 64)


def test_envelope_duplicate_unknown_field_noncanonical_and_bad_base64_refused():
    root = canonical({"schema": "RootFixture.v1"})
    doc = {
        "schema": "Gate0RootHandoff.v1",
        "campaign_digest": CAMPAIGN,
        "host": "NS3",
        "root_b64": base64.b64encode(root).decode(),
    }
    for raw in (
        canonical(dict(doc, extra=True)),
        b" " + canonical(doc),
        canonical(dict(doc, root_b64="%%%")),
        canonical(doc)[:-1] + b',"host":"NS3"}',
    ):
        with pytest.raises(ValueError):
            decode_root_event(raw, CAMPAIGN)


def test_ack_matches_both_own_a_finals_in_fixed_host_order():
    finals = (canonical({"host": "IDP3"}), canonical({"host": "NS3"}))
    join = canonical({"schema": "JoinFixture.v1"})
    ack = encode_case_a_complete(CAMPAIGN, join, finals)
    assert decode_case_a_complete(ack, CAMPAIGN, finals) == digest(join)
    with pytest.raises(ProviderRefused):
        decode_case_a_complete(ack, CAMPAIGN, finals[::-1])
    with pytest.raises(ProviderRefused):
        decode_case_a_complete(ack, "sha256:" + "b" * 64, finals)


def test_terminal_never_accepts_boolean_as_actual_wait_result():
    final = canonical({"schema": "RootFixture.v1"})
    doc = {
        "schema": "Gate0RootHandoffTerminal.v1",
        "campaign_digest": CAMPAIGN,
        "host": "IDP3",
        "root_final_digest": digest(final),
        "stdout_eof": True,
        "management_returncode": 0,
    }
    assert decode_terminal(canonical(doc), CAMPAIGN, "IDP3", final) == 0
    for replacement in (
        {"management_returncode": False},
        {"stdout_eof": 1},
        {"root_final_digest": CAMPAIGN},
        {"host": "NS3"},
    ):
        with pytest.raises(ProviderRefused):
            decode_terminal(
                canonical(dict(doc, **replacement)), CAMPAIGN, "IDP3", final
            )


def test_expose_authinfo_single_plain_ed25519_key_only():
    wire = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"x" * 32
    key = b"ssh-ed25519 " + base64.b64encode(wire)
    raw = b"publickey " + key + b"\n"
    assert parse_holder_auth_info(raw) == key
    for bad in (
        raw + raw,
        raw[:-1],
        raw.replace(b"publickey", b"password"),
        raw.replace(b"ssh-ed25519 ", b"ssh-ed25519-cert-v01@openssh.com "),
        raw[:-1] + b" comment\n",
        b"publickey ssh-ed25519 AAAA\n",
    ):
        with pytest.raises(ProviderRefused):
            parse_holder_auth_info(bad)


def test_public_installed_owners_cannot_be_minted_from_caller_boolean():
    with pytest.raises(ProviderRefused):
        FixedLaunchHolder(True, {}, "/caller/ssh", None, 0)
    with pytest.raises(ProviderRefused):
        InstalledHandoffReceiver(True, {}, (10, 20, "30"), None, 0)


def test_final_before_startup_phase_is_refused():
    terms = {
        "host_role": "attester",
        "case_kind": "consume_replay",
        "launch_packet_digest": CAMPAIGN,
        "local_packet_digest": "sha256:" + "b" * 64,
        "window_digest": "sha256:" + "c" * 64,
        "machine_id_digest": "sha256:" + "d" * 64,
        "network_measurement_digest": "sha256:" + "e" * 64,
        "not_before": "2026-10-15T00:00:00+00:00",
        "expires_at": "2026-10-15T00:05:00+00:00",
    }
    sequence = RootFrameSequence(RootHostBinding(canonical(terms)))
    with pytest.raises(ValueError):
        sequence.accept(canonical(dict(terms, schema="Gate0LaunchCleanup.v1")))
    assert sequence.records == []
    assert sequence.final is None


# The following exercise actual owned children and OS channels. Root records
# remain explicit source fixtures and confer no installed acceptance.


def _binding(role="attester", kind="consume_replay", local="b"):
    start = datetime.now(UTC) - timedelta(seconds=2)
    return {
        "host_role": role,
        "case_kind": kind,
        "launch_packet_digest": CAMPAIGN,
        "local_packet_digest": "sha256:" + local * 64,
        "window_digest": "sha256:" + "c" * 64,
        "machine_id_digest": "sha256:" + "d" * 64,
        "network_measurement_digest": "sha256:" + "e" * 64,
        "not_before": start.isoformat(),
        "expires_at": (start + timedelta(seconds=300)).isoformat(),
    }


def _phase(terms, name):
    doc = dict(
        terms,
        schema="Gate0RootLaunchPhase.v1",
        supervisor_pid=42,
        supervisor_start="123",
        started_at=terms["not_before"],
        monotonic_origin=10.0,
        deadline=310.0,
        emitted_at=(
            datetime.fromisoformat(terms["not_before"]) + timedelta(seconds=1)
        ).isoformat(),
        emitted_elapsed_seconds=1.0,
        phase=name,
        listener={
            "role": "issuer"
            if name == "issuer_listening"
            else "management"
            if name == "management_listening"
            else "attester",
            "interface": "wg0",
            "local_address": "10.1.0.1",
            "local_port": 2222,
            "remote_address": "10.1.0.2",
        },
        management_capture=None,
    )
    if name == "attester_listening_after_capture":
        readback = {
            "schema": "Gate0CaptureInstalled.v1",
            "launch_packet_digest": CAMPAIGN,
            "capture": {
                "capture_digest": CAMPAIGN,
                "window_digest": terms["window_digest"],
                "plan_digest": CAMPAIGN,
                "plan_id": "00000000-0000-0000-0000-000000000001",
                "target_id": "00000000-0000-0000-0000-000000000002",
                "approval_request_id": "00000000-0000-0000-0000-000000000003",
            },
            "effective_end": terms["expires_at"],
        }
        doc["management_capture"] = {
            "readback": readback,
            "readback_digest": digest(canonical(readback)),
        }
    return canonical(doc)


def _final(terms):
    doc = dict(terms)
    del doc["not_before"]
    doc.update(
        schema="Gate0LaunchCleanup.v1",
        supervisor_pid=42,
        supervisor_start="123",
        started_at=terms["not_before"],
        phase_completed_at={},
        terminals={},
        daemon_observations={},
        boundaries=[],
        removed=[],
        expected_removed=[],
        cleanup_completed_at=terms["expires_at"],
        outcome="complete",
        reason="completed_mechanics",
        delivery_status="unconfirmed",
    )
    doc[
        "capture_delivery" if terms["host_role"] == "issuer" else "management_capture"
    ] = None
    return canonical(doc)


def _child_frames(records, *, status=0, pause=0):
    raw = b"".join(struct.pack("!I", len(record)) + record for record in records)
    script = (
        "import os,time;os.write(1,"
        + repr(raw)
        + ");time.sleep("
        + repr(pause)
        + ");raise SystemExit("
        + repr(status)
        + ")"
    )
    return subprocess.Popen(  # noqa: S603 -- fixed Python child/source fixture only
        [sys.executable, "-c", script],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def test_complete_five_root_frame_roster_and_duplicates():
    ns_terms, idp_terms = _binding(), _binding("issuer", local="f")
    ns = RootFrameSequence(RootHostBinding(canonical(ns_terms)))
    idp = RootFrameSequence(RootHostBinding(canonical(idp_terms)))
    frames = [
        (ns, _phase(ns_terms, "management_listening")),
        (idp, _phase(idp_terms, "issuer_listening")),
        (ns, _phase(ns_terms, "attester_listening_after_capture")),
        (idp, _final(idp_terms)),
        (ns, _final(ns_terms)),
    ]
    for sequence, raw in frames:
        sequence.accept(raw)
    ns.require_complete()
    idp.require_complete()
    assert len(ns.records) + len(idp.records) == 5
    with pytest.raises(ProviderRefused):
        ns.accept(frames[0][1])


def test_actual_owned_popen_eof_and_wait_are_both_required():
    from vendor_cp.deployment.gate0_runner_handoff import _OwnedLaunch

    terms = _binding("issuer")
    process = _child_frames(
        [_phase(terms, "issuer_listening"), _final(terms)], status=3
    )
    owner = _OwnedLaunch(
        process,
        RootFrameSequence(RootHostBinding(canonical(terms))),
        time.monotonic() + 2,
    )
    try:
        assert owner.next_root()[0] == "issuer_listening"
        assert owner.next_root()[0] == "final"
        assert owner.next_root() is None
        assert owner.eof and owner.returncode == 3
        with pytest.raises(ProviderRefused):
            owner.require_complete()
    finally:
        owner.close()
    assert process.stdout.closed


def test_blocked_actual_pipe_write_stops_at_a_deadline_and_reaps_pending_child():
    from vendor_cp.deployment.gate0_runner_handoff import _OwnedIO, _teardown

    process = subprocess.Popen(  # noqa: S603 -- fixed Python child/source fixture only
        [sys.executable, "-c", "import time;time.sleep(20)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    end = time.monotonic() + 0.1
    io = _OwnedIO(process.stdout.fileno(), process.stdin.fileno(), end)
    start = time.monotonic()
    try:
        with pytest.raises(ProviderRefused):
            io.send(canonical({"large": "x" * 200000}))
        assert time.monotonic() - start < 1.0
    finally:
        _teardown([process], time.monotonic() + 2)
    assert process.poll() is not None
    assert process.stdin.closed and process.stdout.closed


@pytest.mark.parametrize(
    "raw", [b"\0\0", struct.pack("!I", 270337), struct.pack("!I", 10) + b"{}"]
)
def test_actual_pipe_partial_or_oversized_input_refuses(raw):
    from vendor_cp.deployment.gate0_runner_handoff import _OwnedIO, _teardown

    process = subprocess.Popen(  # noqa: S603 -- fixed Python child/source fixture only
        [sys.executable, "-c", "import os;os.write(1," + repr(raw) + ")"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        io = _OwnedIO(
            process.stdout.fileno(), process.stdout.fileno(), time.monotonic() + 1
        )
        with pytest.raises(ValueError):
            io.receive()
    finally:
        _teardown([process], time.monotonic() + 2)


def test_actual_unix_peer_uid_pid_and_start_mismatch():
    from vendor_cp.deployment.gate0_runner_handoff import _process, _require_peer

    if not hasattr(socket, "SO_PEERCRED") or os.geteuid() == 0:
        pytest.skip("Linux dedicated unprivileged UID peer fixture")
    left, right = socket.socketpair()
    try:
        _, uid, start = _process(os.getpid())
        _require_peer(left, uid, os.getpid(), start)
        for wanted in (
            (uid + 1, os.getpid(), start),
            (uid, os.getpid() + 1, start),
            (uid, os.getpid(), str(int(start) + 1)),
        ):
            with pytest.raises(ProviderRefused):
                _require_peer(left, *wanted)
    finally:
        left.close()
        right.close()


def test_teardown_first_wait_failure_still_reaps_and_closes_all_under_one_end(
    monkeypatch,
):
    from vendor_cp.deployment.gate0_runner_handoff import _teardown

    children = [
        subprocess.Popen(  # noqa: S603 -- fixed Python child/source fixture only
            [sys.executable, "-c", "import time;time.sleep(20)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    original = children[0].wait
    timeouts = []

    def fail_first(timeout=None):
        timeouts.append(timeout)
        raise subprocess.TimeoutExpired("fixture", timeout)

    monkeypatch.setattr(children[0], "wait", fail_first)
    end = time.monotonic() + 0.2
    try:
        with pytest.raises(ProviderRefused) as caught:
            _teardown(children, end)
        assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)
        assert timeouts[0] <= 0.2
        assert children[1].poll() is not None
        assert all(child.stdin.closed and child.stdout.closed for child in children)
        assert time.monotonic() < end + 0.2
    finally:
        monkeypatch.setattr(children[0], "wait", original)
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)


def test_fixed_loader_path_and_no_root_holder(monkeypatch):
    import pwd

    from vendor_cp.deployment import gate0_runner_handoff as handoff

    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(os, "getuid", lambda: 501)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_dir="/"))
    seen = []

    def absent(path, uid, maximum=65536, *, private=False):
        seen.append((str(path), uid, private))
        raise FileNotFoundError("fixture")

    monkeypatch.setattr(handoff, "_protected_bytes", absent)
    with pytest.raises(FileNotFoundError):
        FixedLaunchHolder.from_installed()
    assert seen == [("/.config/dotmac-gate0/handoff.json", 501, True)]
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ProviderRefused):
        FixedLaunchHolder.from_installed()


def test_prospective_fifo_pin_is_opened_nonblocking_before_fstat(tmp_path, monkeypatch):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    fifo = tmp_path / "pin"
    os.mkfifo(fifo)
    real_open, real_fstat = os.open, os.fstat
    captured = []

    def opening(path, flags, *args, **kwargs):
        if path == "pin":
            captured.append(flags)
            assert flags & os.O_NONBLOCK
        return real_open(path, flags, *args, **kwargs)

    def metadata(fd):
        info = real_fstat(fd)
        return types.SimpleNamespace(st_uid=os.geteuid(), st_mode=info.st_mode & ~0o022)

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "fstat", metadata)
    with pytest.raises(ProviderRefused):
        handoff._protected_bytes(fifo, os.geteuid())
    assert len(captured) == 1


def test_four_derived_activation_commands_have_no_caller_command_slot():
    from vendor_cp.deployment.gate0_runner_handoff import activation_command

    commands = {
        activation_command(CAMPAIGN, case, role)
        for case in ("consume_replay", "withdrawal_later_use")
        for role in ("issuer", "attester")
    }
    assert len(commands) == 4
    assert all(
        command.startswith("/usr/local/libexec/dotmac-gate0/" + "a" * 64 + "/")
        for command in commands
    )
    for bad in ("../other", "consume-replay", "consume_replay;id"):
        with pytest.raises(ProviderRefused):
            activation_command(CAMPAIGN, bad, "issuer")


@pytest.mark.parametrize("upstream_status", [0, 3])
def test_owned_a_eof_wait_and_ack_gate_prevent_any_b_launch(
    monkeypatch, upstream_status
):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    a_ns, a_idp = _binding(), _binding("issuer", local="f")
    b_ns, b_idp = (
        _binding(kind="withdrawal_later_use"),
        _binding("issuer", "withdrawal_later_use", "f"),
    )
    cases = [
        {"kind": kind, "NS3": {"binding": ns}, "IDP3": {"binding": idp}}
        for kind, ns, idp in (
            ("consume_replay", a_ns, a_idp),
            ("withdrawal_later_use", b_ns, b_idp),
        )
    ]
    holder = handoff.FixedLaunchHolder(
        handoff._SEAL,
        {"campaign_digest": CAMPAIGN, "cases": cases, "downstream": {}},
        "/fixture/ssh",
        datetime.now(UTC),
        time.monotonic(),
    )
    calls = []
    events = []
    real_send = handoff._OwnedIO.send

    def retained_send(channel, raw):
        result = real_send(channel, raw)
        event = handoff.strict_object(raw)
        if event.get("schema") == "Gate0RootHandoff.v1":
            _, root = decode_root_event(raw, CAMPAIGN)
            events.append(handoff.strict_object(root).get("phase"))
        return result

    monkeypatch.setattr(handoff._OwnedIO, "send", retained_send)
    wrong_ack = encode_case_a_complete(
        CAMPAIGN,
        canonical({"join": "fixture"}),
        (canonical({"wrong": 1}), canonical({"wrong": 2})),
    )
    wire = struct.pack("!I", len(wrong_ack)) + wrong_ack

    def downstream(endpoint, *, downstream):
        assert downstream
        process = subprocess.Popen(  # noqa: S603 -- actual owned local fixture
            [
                sys.executable,
                "-c",
                "import os,sys;os.write(1," + repr(wire) + ");sys.stdin.buffer.read()",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        holder._processes.append(process)
        return process

    def launch(endpoint):
        terms = endpoint["binding"]
        if terms["host_role"] == "issuer":
            assert events == ["management_listening"]
        calls.append((terms["case_kind"], terms["host_role"]))
        records = [
            _phase(terms, name)
            for name in (
                ("management_listening", "attester_listening_after_capture")
                if terms["host_role"] == "attester"
                else ("issuer_listening",)
            )
        ]
        process = _child_frames([*records, _final(terms)], status=upstream_status)
        holder._processes.append(process)
        owner = handoff._OwnedLaunch(
            process,
            RootFrameSequence(RootHostBinding(canonical(terms))),
            time.monotonic() + 2,
        )
        holder._launches.append(owner)
        return owner

    monkeypatch.setattr(holder, "_spawn", downstream)
    monkeypatch.setattr(holder, "_launch", launch)
    with pytest.raises(ProviderRefused):
        holder.run()
    assert calls == [("consume_replay", "attester"), ("consume_replay", "issuer")]
    assert all(process.poll() is not None for process in holder._processes)
    assert all(process.stdout.closed for process in holder._processes)
    if upstream_status == 0:
        assert all(owner.eof and owner.returncode == 0 for owner in holder._launches)
    with pytest.raises(ProviderRefused):
        holder.run()


def test_exact_agent_socket_metadata_swap_refuses(tmp_path, monkeypatch):
    from vendor_cp.deployment.gate0_runner_handoff import _agent_socket

    # Exercise actual sockets while isolating metadata policy from pytest's
    # intentionally shared temporary ancestors.
    path = tmp_path.resolve() / "agent"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o600)

    real_stat = type(path).stat

    def qualified_parent_stat(target, *, follow_symlinks=True):
        info = real_stat(target, follow_symlinks=follow_symlinks)
        if target == path:
            return info
        return types.SimpleNamespace(
            st_uid=os.geteuid(), st_mode=0o40700, st_dev=info.st_dev, st_ino=info.st_ino
        )

    monkeypatch.setattr(type(path), "stat", qualified_parent_stat)

    def metadata(target):
        info = target.stat(follow_symlinks=False)
        return {
            "path": str(target),
            "uid": info.st_uid,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": info.st_mode & 0o7777,
        }

    pin = dict(
        metadata(path), parents=[metadata(parent) for parent in reversed(path.parents)]
    )
    try:
        _agent_socket(pin, os.geteuid())
        pin["inode"] += 1
        with pytest.raises(ProviderRefused):
            _agent_socket(pin, os.geteuid())
    finally:
        listener.close()


@pytest.mark.parametrize("sign_status,delay", [(0, 0), (1, 0), (0, 20)])
def test_live_agent_identity_and_sign_check_uses_actual_bounded_children(
    monkeypatch, sign_status, delay
):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    public = (
        b"ssh-ed25519 "
        + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + b"k" * 32)
        + b"\n"
    )
    holder = handoff.FixedLaunchHolder(
        handoff._SEAL,
        {
            "holder_uid": 501,
            "agent": {"path": "/fixed/agent"},
            "public_identity": {"path": "/fixed/public", "digest": digest(public)},
            "ssh_add_binary": {"path": "/fixed/ssh-add"},
        },
        "/fixed/ssh",
        datetime.now(UTC),
        time.monotonic(),
    )
    real_popen = subprocess.Popen
    calls = []
    checks = []
    monkeypatch.setattr(
        handoff, "_agent_socket", lambda agent, uid: checks.append((agent["path"], uid))
    )
    monkeypatch.setattr(handoff, "_protected_bytes", lambda *args, **kwargs: public)

    def agent_process(command, **kwargs):
        calls.append((command, kwargs["env"]))
        assert command[0] == "/fixed/ssh-add"
        if command[1] == "-L":
            script = "import os;os.write(1," + repr(public) + ")"
        else:
            assert command[1:] == ["-T", "/fixed/public"]
            script = (
                "import time;time.sleep("
                + repr(delay)
                + ");raise SystemExit("
                + repr(sign_status)
                + ")"
            )
        return real_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(handoff.subprocess, "Popen", agent_process)
    try:
        if sign_status or delay:
            with pytest.raises((ProviderRefused, subprocess.TimeoutExpired)):
                holder._check_agent(time.monotonic() + 1)
        else:
            holder._check_agent(time.monotonic() + 1)
        assert [command[1] for command, _ in calls] == ["-L", "-T"]
        assert all(env["SSH_AUTH_SOCK"] == "/fixed/agent" for _, env in calls)
        assert len(checks) >= 2
    finally:
        holder.close()
    assert all(process.poll() is not None for process in holder._processes)
    assert all(process.stdout.closed for process in holder._processes)


def test_holder_a_blocked_relay_never_inherits_b_end_with_live_ns_child(monkeypatch):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    now = datetime.now(UTC)

    def bounded(terms, seconds):
        end = now + timedelta(seconds=seconds)
        terms["expires_at"] = end.isoformat()
        terms["not_before"] = (end - timedelta(seconds=300)).isoformat()
        return terms

    a_ns = bounded(_binding(), 0.25)
    a_idp = bounded(_binding("issuer", local="f"), 0.25)
    b_ns = bounded(_binding(kind="withdrawal_later_use"), 2)
    b_idp = bounded(_binding("issuer", "withdrawal_later_use", "f"), 2)
    cases = [
        {"kind": kind, "NS3": {"binding": ns}, "IDP3": {"binding": idp}}
        for kind, ns, idp in (
            ("consume_replay", a_ns, a_idp),
            ("withdrawal_later_use", b_ns, b_idp),
        )
    ]
    holder = handoff.FixedLaunchHolder(
        handoff._SEAL,
        {"campaign_digest": CAMPAIGN, "cases": cases, "downstream": {}},
        "/fixture/ssh",
        now,
        time.monotonic(),
    )
    calls = []

    def downstream(endpoint, *, downstream):
        process = subprocess.Popen(  # noqa: S603 -- actual blocked local pipe fixture
            [sys.executable, "-c", "import time;time.sleep(20)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        holder._processes.append(process)
        os.set_blocking(process.stdin.fileno(), False)
        while True:
            try:
                os.write(process.stdin.fileno(), b"x" * 4096)
            except BlockingIOError:
                break
        return process

    def launch(endpoint):
        terms = endpoint["binding"]
        calls.append(terms["host_role"])
        process = _child_frames([_phase(terms, "management_listening")], pause=20)
        holder._processes.append(process)
        owner = handoff._OwnedLaunch(
            process,
            RootFrameSequence(RootHostBinding(canonical(terms))),
            time.monotonic() + 0.25,
        )
        holder._launches.append(owner)
        return owner

    monkeypatch.setattr(holder, "_spawn", downstream)
    monkeypatch.setattr(holder, "_launch", launch)
    start = time.monotonic()
    with pytest.raises(ProviderRefused):
        holder.run()
    assert time.monotonic() - start < 1.2
    assert calls == ["attester"]
    assert all(process.poll() is not None for process in holder._processes)
    assert all(process.stdout.closed for process in holder._processes)


def test_receiver_loader_uses_only_fixed_protected_descriptor(monkeypatch):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    seen = []

    def absent(path, uid, maximum=65536, *, private=False):
        seen.append((str(path), uid))
        raise FileNotFoundError("fixture")

    monkeypatch.setattr(handoff, "_protected_bytes", absent)
    with pytest.raises(FileNotFoundError):
        InstalledHandoffReceiver.from_installed()
    assert seen == [("/run/dotmac-gate0-handoff/installation.json", 0)]


@pytest.mark.parametrize(
    "field,value",
    [
        ("local_packet_digest", "sha256:" + "f" * 64),
        ("launch_packet_digest", "sha256:" + "f" * 64),
        ("window_digest", "sha256:" + "f" * 64),
        ("case_kind", "withdrawal_later_use"),
    ],
)
def test_actual_root_frame_case_and_packet_swaps_refuse(field, value):
    terms = _binding()
    sequence = RootFrameSequence(RootHostBinding(canonical(terms)))
    wrong = dict(terms, **{field: value})
    with pytest.raises(ProviderRefused):
        sequence.accept(_phase(wrong, "management_listening"))
    assert sequence.records == []


def test_downstream_actual_eof_before_late_zero_exit_still_refuses(monkeypatch):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    process = subprocess.Popen(  # noqa: S603 -- actual EOF-before-exit fixture
        [sys.executable, "-c", "import os,time;os.close(1);time.sleep(0.15)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    original_wait = process.wait
    waits = []
    try:
        assert os.read(process.stdout.fileno(), 1) == b""
        assert process.poll() is None
        deadline = time.monotonic() + 0.05

        # Model a wait implementation/scheduler returning success after its
        # requested budget. Actual child EOF and its later actual exit remain
        # owned measurements; status zero cannot replace the post-wait clock.
        def late_wait(timeout=None):
            waits.append(timeout)
            return original_wait(timeout=1)

        monkeypatch.setattr(process, "wait", late_wait)
        with pytest.raises(ProviderRefused):
            handoff._finish_downstream(process, deadline)
        assert len(waits) == 1 and 0 < waits[0] <= 0.05
        assert process.returncode == 0
        assert time.monotonic() >= deadline
    finally:
        monkeypatch.setattr(process, "wait", original_wait)
        handoff._teardown([process], time.monotonic() + 2)


@pytest.mark.parametrize("after_wait", [100.0, 100.001])
def test_downstream_wait_exact_deadline_equality_and_late_success_refuse(
    monkeypatch, after_wait
):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    process = _child_frames([])
    try:
        assert os.read(process.stdout.fileno(), 1) == b""
        assert process.wait(timeout=1) == 0
        readings = iter((99.5, after_wait))
        with monkeypatch.context() as patch:
            patch.setattr(handoff.time, "monotonic", lambda: next(readings))
            with pytest.raises(ProviderRefused):
                handoff._finish_downstream(process, 100.0)
    finally:
        handoff._teardown([process], time.monotonic() + 2)


def test_downstream_exhausted_deadline_never_gets_fresh_wait_budget(monkeypatch):
    from vendor_cp.deployment import gate0_runner_handoff as handoff

    process = _child_frames([])
    try:
        assert process.wait(timeout=1) == 0

        def forbidden_wait(timeout=None):
            pytest.fail("expired downstream deadline granted another wait")

        with monkeypatch.context() as patch:
            patch.setattr(process, "wait", forbidden_wait)
            patch.setattr(handoff.time, "monotonic", lambda: 100.0)
            with pytest.raises(ProviderRefused):
                handoff._finish_downstream(process, 100.0)
    finally:
        handoff._teardown([process], time.monotonic() + 2)
