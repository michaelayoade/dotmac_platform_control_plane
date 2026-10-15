"""Native role-image capability/sshd/spawn/socket proof, hosted only.

Run as an isolated one-shot image PID1 in a private network/PID namespace with
initial P0 capabilities, read-only image and bounded tmpfs; never on a workstation.
This proves native mechanisms with synthetic certificates and loopback addresses.
It does NOT qualify full WG peers/routes/firewall, protected launch installation,
real custody, business approval, host cgroup mounts or Gate0/E readiness.
"""

# Fixed disposable native fixture commands; no production input selects them.
# ruff: noqa: S603
from __future__ import annotations

import ctypes
import hashlib
import json
import multiprocessing
import os
import pwd
import select
import socket
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)

from vendor_cp.deployment import gate0_launch as launch
from vendor_cp.deployment import gate0_role_custody as custody

K = 0x400E3


_STAGES = frozenset(
    {
        "worker_entered",
        "worker_marker_created",
        "worker_identity_checked",
        "worker_authinfo_checked",
        "worker_privileges_checked",
        "worker_spawn_started",
        "worker_failed",
        "transport_entered",
        "transport_privileges_checked",
        "transport_socket_created",
        "transport_device_bound",
        "transport_initial_device_readback_checked",
        "transport_source_bound",
        "transport_connected",
        "transport_socket_readback_checked",
        "transport_device_mismatch_refused",
        "transport_readback_received",
        "transport_failed",
        "positive_authentication_started",
        "positive_exchange_failed",
        "negative_socket_received",
        "positive_socket_received",
        "diagnostics_truncated",
        "child_cleanup_deadline",
    }
)


def _stage(value):
    assert value in _STAGES
    print("GATE0_NATIVE_STAGE=" + value, file=sys.stderr, flush=True)


_FAILURE_CLASSES = frozenset(
    {
        "AssertionError",
        "PermissionError",
        "ProviderRefused",
        "FileNotFoundError",
        "TimeoutError",
        "EOFError",
        "KeyError",
        "OSError",
        "ConnectionRefusedError",
        "other",
    }
)


def _failure(stage, error):
    _stage(stage)
    kind = type(error).__name__
    if kind not in _FAILURE_CLASSES:
        kind = "other"
    print("GATE0_NATIVE_FAILURE_CLASS=" + kind, file=sys.stderr, flush=True)
    number = error.errno if isinstance(error, OSError) else 0
    if type(number) is not int or not 0 <= number <= 4095:
        number = 0
    print(f"GATE0_NATIVE_ERRNO={number}", file=sys.stderr, flush=True)
    ffi_number = ctypes.get_errno()
    if type(ffi_number) is not int or not 0 <= ffi_number <= 4095:
        ffi_number = 0
    print(f"GATE0_NATIVE_FFI_ERRNO={ffi_number}", file=sys.stderr, flush=True)


def _native_readbacks(stage):
    assert stage in {"supervisor", "worker", "spawn"}
    status = Path("/proc/self/status").read_text()
    filesystem_uid = next(
        line.split()[4] for line in status.splitlines() if line.startswith("Uid:")
    )
    document = {
        "stage": stage,
        "uids": list(os.getresuid()),
        "filesystem_uid": int(filesystem_uid),
        "gids": list(os.getresgid()),
        "groups": sorted(os.getgroups()),
        "capget": list(launch._capget()),
        "proc_capabilities": [
            int(
                next(
                    line.split()[1]
                    for line in status.splitlines()
                    if line.startswith(field + ":")
                ),
                base,
            )
            for field, base in (
                ("CapEff", 16),
                ("CapPrm", 16),
                ("CapInh", 16),
                ("CapAmb", 16),
                ("CapBnd", 16),
                ("NoNewPrivs", 10),
            )
        ],
        "securebits": launch._prctl(27),
        "nnp": launch._prctl(39),
    }
    assert _checked_readbacks(document)
    print(
        "GATE0_NATIVE_READBACK=" + json.dumps(document, sort_keys=True),
        file=sys.stderr,
        flush=True,
    )


def _checked_readbacks(document):
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "stage",
            "uids",
            "filesystem_uid",
            "gids",
            "groups",
            "capget",
            "proc_capabilities",
            "securebits",
            "nnp",
        }
        or type(document["stage"]) is not str
        or document["stage"] not in {"supervisor", "worker", "spawn"}
    ):
        return False
    for field, length, maximum in (
        ("uids", 3, 2**32 - 1),
        ("gids", 3, 2**32 - 1),
        ("capget", 3, 2**64 - 1),
        ("proc_capabilities", 6, 2**64 - 1),
    ):
        values = document[field]
        if (
            not isinstance(values, list)
            or len(values) != length
            or not all(type(value) is int and 0 <= value <= maximum for value in values)
        ):
            return False
    groups = document["groups"]
    return (
        isinstance(groups, list)
        and len(groups) <= 64
        and all(type(value) is int and 0 <= value < 2**32 for value in groups)
        and type(document["filesystem_uid"]) is int
        and 0 <= document["filesystem_uid"] < 2**32
        and type(document["securebits"]) is int
        and 0 <= document["securebits"] <= 255
        and type(document["nnp"]) is int
        and document["nnp"] in (0, 1)
    )


def _exit_code(name, code):
    assert name in {"client", "daemon", "spawn"}
    assert code is None or type(code) is int and -255 <= code <= 255
    print(f"GATE0_NATIVE_EXIT_{name}={code}", file=sys.stderr, flush=True)


def _safe_child_diagnostics(
    client, daemon, buffers, captured_client_error=b"", *, emit=False
):
    # Fixed public stages only. Never copy raw SSH/worker stderr, tracebacks,
    # credentials, private keys, request data or exception text into the log.
    for name, process in (("client", client), ("daemon", daemon)):
        if process is None:
            if emit:
                _exit_code(name, None)
            continue
        if emit:
            _exit_code(name, process.poll())
        stream = process.stderr
        output = buffers.setdefault(name, bytearray())
        if name == "client" and captured_client_error:
            output.extend(captured_client_error[: max(0, 16384 - len(output))])
        if stream is not None and not stream.closed:
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            while len(output) < 16384 and select.select([descriptor], [], [], 0)[0]:
                try:
                    part = os.read(descriptor, min(4096, 16384 - len(output)))
                except BlockingIOError:
                    break
                if not part:
                    break
                output.extend(part)
        if not emit:
            continue
        if len(output) == 16384:
            _stage("diagnostics_truncated")
        print(f"GATE0_NATIVE_STDERR_BYTES_{name}={len(output)}", file=sys.stderr)
        # Session-child failures travel over the SSH channel to client stderr;
        # only monitor/daemon failures necessarily remain in daemon stderr.
        # These fixed hints are diagnostic, never a refusal/pass criterion.
        lowered = bytes(output).lower()
        emitted = set()
        for needle, branch in (
            (b"prepare_auth_info_file", "auth_info_file"),
            (b"mkstemp", "temporary_file"),
            (b"write:", "file_write"),
            (b"close:", "file_close"),
            (b"do_exec_no_pty", "session_execution"),
            (b"socketpair", "socketpair"),
            (b"pipe", "pipe"),
            (b"fork", "fork"),
            (b"setsid failed:", "session_setsid"),
            (b"dup2 stdin", "session_stdio"),
            (b"dup2 stdout", "session_stdio"),
            (b"dup2 stderr", "session_stdio"),
            (b"setlogin failed:", "setlogin"),
            (b"unable to set user context", "user_context"),
            (b"setgroups", "setgroups"),
            (b"initgroups", "initgroups"),
            (b"setgid", "setgid"),
            (b"setreuid", "setreuid"),
            (b"setresuid", "setresuid"),
            (b"setresgid", "setresgid"),
            (b"failed to set uids to", "set_uids"),
            (b"chroot", "chroot"),
            (b"authentication", "authentication"),
            (b"certificate", "certificate"),
            (b"signature", "signature"),
            (b"publickey", "publickey"),
            (b"monitor", "monitor"),
            (b"mm_", "monitor_function"),
            (b"keystate", "key_state"),
            (b"ssh_msg", "monitor_message"),
            (b"reexec", "reexec"),
            (b"prctl", "prctl"),
            (b"permanently_set_uid", "permanent_uid"),
            (b"restore old", "restore_identity"),
            (b"no such file", "missing_path"),
            (b"read-only file system", "read_only"),
            (b"operation not permitted", "permission_refusal"),
            (b"permission denied", "permission_refusal"),
            (b"bad ownership", "ownership_refusal"),
            (b"could not chdir", "cwd_refusal"),
            (b"refusing non-sftp session", "session_policy"),
            (b"fatal", "fatal"),
            (b"disconnect", "disconnect"),
            (b"connection closed", "connection_closed"),
        ):
            if needle in lowered and branch not in emitted:
                emitted.add(branch)
                print(
                    f"GATE0_NATIVE_CLASS_{name}=" + branch,
                    file=sys.stderr,
                    flush=True,
                )
        if output and not emitted:
            print(
                f"GATE0_NATIVE_CLASS_{name}=unclassified_nonempty",
                file=sys.stderr,
                flush=True,
            )
        for line in bytes(output).decode("ascii", errors="ignore").splitlines():
            prefix, separator, value = line.partition("=")
            if separator and prefix == "GATE0_NATIVE_STAGE" and value in _STAGES:
                _stage(value)
            elif (
                separator
                and prefix == "GATE0_NATIVE_FAILURE_CLASS"
                and value in _FAILURE_CLASSES
            ):
                print(line, file=sys.stderr, flush=True)
            elif (
                separator
                and prefix in {"GATE0_NATIVE_ERRNO", "GATE0_NATIVE_FFI_ERRNO"}
                and value.isdecimal()
                and 0 <= int(value) <= 4095
            ):
                print(f"{prefix}={int(value)}", file=sys.stderr, flush=True)
            elif separator and prefix == "GATE0_NATIVE_EXIT_spawn":
                if value == "None":
                    _exit_code("spawn", None)
                elif value.lstrip("-").isdecimal() and -255 <= int(value) <= 255:
                    _exit_code("spawn", int(value))
            elif separator and prefix == "GATE0_NATIVE_READBACK":
                try:
                    document = json.loads(value)
                except (ValueError, TypeError, RecursionError):
                    continue
                if _checked_readbacks(document):
                    print(
                        prefix + "=" + json.dumps(document, sort_keys=True),
                        file=sys.stderr,
                        flush=True,
                    )


def _accept_echo_or_exit(listener, client, daemon, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or client.poll() is not None or daemon.poll() is not None:
            raise AssertionError(
                "native positive worker exited or exchange deadline elapsed"
            )
        if select.select([listener], [], [], min(0.05, remaining))[0]:
            listener.settimeout(max(0.001, deadline - time.monotonic()))
            return listener.accept()


def _run(arguments, *, accepted=True):
    result = subprocess.run(arguments, capture_output=True, timeout=3, check=False)
    if accepted:
        assert result.returncode == 0, result.stderr.decode(errors="replace")
    else:
        assert result.returncode != 0
        assert (
            b"permitted" in result.stderr.lower()
            or b"permission" in result.stderr.lower()
        )
    return result


def _socket_child_body(writer, supervisor_pid, port):
    uid = 10032
    _native_readbacks("spawn")
    launch._require_worker_privileges(uid, supervisor_pid)
    _stage("transport_privileges_checked")
    namespace = Path("/proc/self/ns/net").stat()
    endpoint = custody.WireGuardBaoEndpoint(
        role="attester",
        address="10.251.0.2",
        port=port,
        local_address="10.251.0.1",
        interface="lo",
        interface_index=socket.if_nametoindex("lo"),
        namespace_device=namespace.st_dev,
        namespace_inode=namespace.st_ino,
        peer_fingerprint="sha256:" + "a" * 64,
        peer_allowed_ip="10.251.0.2/32",
        wg_binary_digest="sha256:" + "b" * 64,
        network_config_digest="sha256:" + "c" * 64,
        launch_packet_digest="sha256:" + "d" * 64,
    )
    # Actual connected-device mismatch refuses before a synthetic payload.
    for negative in (True, False):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            _stage("transport_socket_created")
            connection.settimeout(3)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
            _stage("transport_device_bound")
            assert (
                connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16
                ).rstrip(b"\0")
                == b"lo"
            )
            _stage("transport_initial_device_readback_checked")
            connection.bind((endpoint.local_address, 0))
            _stage("transport_source_bound")
            connection.connect((endpoint.address, endpoint.port))
            _stage("transport_connected")
            if negative:
                wrong = replace(
                    endpoint,
                    interface="g0proof",
                    interface_index=socket.if_nametoindex("g0proof"),
                )
                try:
                    custody._socket_readback(connection, wrong)
                except custody.ProviderRefused:
                    _stage("transport_device_mismatch_refused")
                else:
                    raise AssertionError("wrong native bound device was accepted")
            else:
                custody._socket_readback(connection, endpoint)
                _stage("transport_socket_readback_checked")
                connection.sendall(b"gate0-native-synthetic")
                assert connection.recv(64) == b"native-readback"
                _stage("transport_readback_received")
    assert launch._capget() == (0, 0, 0)
    writer.send_bytes(
        json.dumps(
            {
                "uid": uid,
                "capabilities": launch._proc_capabilities(os.getpid()),
                "device_mismatch_refused": True,
                "fresh_socket_exchange": True,
            }
        ).encode()
    )
    writer.close()


def _socket_child(writer, supervisor_pid, port):
    _stage("transport_entered")
    try:
        _socket_child_body(writer, supervisor_pid, port)
    except Exception as error:
        _failure("transport_failed", error)
        raise


def _worker(supervisor_pid, port, entry_marker):
    # Fixed entry checkpoint and marker precede worker validation; an auth
    # refusal must reach neither, even if marker creation itself would fail.
    _stage("worker_entered")
    _native_readbacks("worker")
    descriptor = os.open(
        entry_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    os.close(descriptor)
    _stage("worker_marker_created")
    assert os.geteuid() == 10032
    _stage("worker_identity_checked")
    assert not os.environ.get("SSH_ORIGINAL_COMMAND")
    assert "-cert-v01@openssh.com" in Path(os.environ["SSH_USER_AUTH"]).read_text()
    _stage("worker_authinfo_checked")
    launch._require_worker_privileges(10032, supervisor_pid)
    _stage("worker_privileges_checked")
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_socket_child, args=(writer, supervisor_pid, port))
    process.start()
    _stage("worker_spawn_started")
    writer.close()
    try:
        spawn_deadline = time.monotonic() + 8
        while not reader.poll(0.05):
            if process.exitcode is not None or time.monotonic() >= spawn_deadline:
                _exit_code("spawn", process.exitcode)
                raise AssertionError(
                    "native transport child exited or deadline elapsed"
                )
        report = json.loads(reader.recv_bytes(65536))
        process.join(2)
        _exit_code("spawn", process.exitcode)
        assert process.exitcode == 0
        assert report["capabilities"] == [0, 0, 0, 0, K, 1]
        print(
            json.dumps(
                {"worker": launch._proc_capabilities(os.getpid()), "spawn": report},
                sort_keys=True,
            )
        )
    finally:
        if process.is_alive():
            process.kill()
        process.join(2)
        _exit_code("spawn", process.exitcode)
        assert not process.is_alive()
        reader.close()


def _native_role_image():
    assert os.environ.get("GITHUB_ACTIONS") == "true", "hosted-only native proof"
    assert os.getpid() == 1 and os.geteuid() == 0, "isolated image PID1 required"
    assert (
        Path(launch.__file__)
        .resolve()
        .is_relative_to(Path(sysconfig.get_path("purelib")).resolve())
    )
    assert not (launch.ROOT / "packet.json").exists(), "no operational installation"
    inventory = json.loads(Path("/app/gate0_native_tools.json").read_bytes())
    assert inventory["schema"] == "Gate0NativeTools.v1"
    for name in (
        "/usr/bin/ssh",
        "/usr/sbin/sshd",
        "/usr/bin/wg",
        "/usr/sbin/ip",
        "/usr/sbin/nft",
    ):
        assert not Path(name).is_symlink()
        assert (
            hashlib.sha256(Path(name).read_bytes()).hexdigest()
            == inventory["binaries"][name]["sha256"]
        )
    # Fixture setup only, inside this one-shot private namespace before P0.
    _run(["/usr/sbin/ip", "link", "set", "lo", "up"])
    _run(["/usr/sbin/ip", "address", "add", "10.251.0.1/32", "dev", "lo"])
    _run(["/usr/sbin/ip", "address", "add", "10.251.0.2/32", "dev", "lo"])
    _run(["/usr/sbin/ip", "link", "add", "g0proof", "type", "wireguard"])
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
    # StrictModes traverses every principals-file ancestor. /tmp is deliberately
    # world-writable and is not a valid fixture parent, even with a private leaf.
    for ancestor in (Path("/"), Path("/run")):
        status = ancestor.stat()
        assert stat.S_ISDIR(status.st_mode) and status.st_uid == 0
        assert stat.S_IMODE(status.st_mode) & 0o022 == 0
    with tempfile.TemporaryDirectory(prefix="g0-native-", dir="/run") as directory_name:
        directory = Path(directory_name)
        directory.chmod(0o755)
        host, client, ca, wrong_client = (
            Ed25519PrivateKey.generate() for _ in range(4)
        )
        for name, key in (
            ("host", host),
            ("client", client),
            ("wrong-client", wrong_client),
        ):
            (directory / name).write_bytes(
                key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
            )
            (directory / name).chmod(0o600)
        (directory / "ca.pub").write_bytes(
            ca.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        )
        (directory / "principals").write_text("gate0-native\n")
        certificate = (
            SSHCertificateBuilder()
            .public_key(client.public_key())
            .type(SSHCertificateType.USER)
            .key_id(b"synthetic-native-only")
            .valid_principals([b"gate0-native"])
            .valid_after(int(time.time()) - 1)
            .valid_before(int(time.time()) + 60)
            .sign(ca)
            .public_bytes()
        )
        (directory / "client-cert.pub").write_bytes(certificate)
        wrong_certificate = (
            SSHCertificateBuilder()
            .public_key(wrong_client.public_key())
            .type(SSHCertificateType.USER)
            .key_id(b"synthetic-wrong-principal")
            .valid_principals([b"not-gate0-native"])
            .valid_after(int(time.time()) - 1)
            .valid_before(int(time.time()) + 60)
            .sign(ca)
            .public_bytes()
        )
        (directory / "wrong-client-cert.pub").write_bytes(wrong_certificate)
        (directory / "wrong-client-cert.pub").chmod(0o444)
        worker_status = directory / "worker-status"
        worker_status.mkdir(mode=0o700)
        os.chown(worker_status, 10032, pwd.getpwuid(10032).pw_gid)
        entry_marker = worker_status / "entered"
        assert directory.stat().st_uid == 0
        assert stat.S_IMODE(directory.stat().st_mode) == 0o755
        assert worker_status.stat().st_uid == 10032
        assert worker_status.stat().st_gid == pwd.getpwuid(10032).pw_gid
        assert stat.S_IMODE(worker_status.stat().st_mode) == 0o700
        assert not entry_marker.exists()
        for name in ("ca.pub", "principals", "client-cert.pub"):
            (directory / name).chmod(0o444)
        launch._prepare_network_privileges()
        # Actual public queries; all synchronous helpers are reaped before seal.
        assert _run(["/usr/bin/wg", "show", "g0proof", "peers"]).stdout == b""
        assert _run(["/usr/bin/wg", "show", "g0proof", "allowed-ips"]).stdout == b""
        _run(["/usr/sbin/ip", "-j", "route", "show"])
        _run(["/usr/sbin/nft", "-j", "list", "ruleset"])
        assert not Path("/proc/1/task/1/children").read_text().strip()
        launch._seal_network_privileges()
        assert launch._proc_capabilities(1) == (K, K, 0, 0, K, 1)
        _native_readbacks("supervisor")
        for mutation in (
            ["/usr/bin/wg", "set", "g0proof", "fwmark", "1"],
            ["/usr/sbin/ip", "route", "add", "blackhole", "10.251.0.99/32"],
            ["/usr/sbin/nft", "add", "table", "inet", "g0_escape"],
        ):
            _run(mutation, accepted=False)
        try:
            launch._capset(0x411E3, 0x411E3, 0)
        except custody.ProviderRefused:
            pass
        else:
            raise AssertionError("NET_ADMIN was regained")
        regained = _run(
            [
                sys.executable,
                "-I",
                "-c",
                "import json; from vendor_cp.deployment.gate0_launch import _capget; "
                "print(json.dumps(_capget()))",
            ]
        )
        assert json.loads(regained.stdout) == [K, K, 0]
        with socket.socket() as ssh_listener, socket.socket() as echo_listener:
            for listener, address in (
                (ssh_listener, "127.0.0.1"),
                (echo_listener, "10.251.0.2"),
            ):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
                listener.bind((address, 0))
                listener.listen(1)
                listener.settimeout(8)
            ssh_port, echo_port = (
                ssh_listener.getsockname()[1],
                echo_listener.getsockname()[1],
            )
            assert ssh_port >= 1024 and echo_port >= 1024
            worker_path = Path(__file__).resolve()
            assert " " not in str(worker_path) and " " not in sys.executable
            worker_command = (
                f"{sys.executable} -I -B {worker_path} "
                f"--native-worker 1 {echo_port} {entry_marker}"
            )
            config = directory / "sshd_config"
            config.write_text(f"""HostKey {directory}/host
StrictModes yes
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com
TrustedUserCAKeys {directory}/ca.pub
AuthorizedKeysFile none
AuthorizedPrincipalsFile {directory}/principals
AllowUsers gate0-attester
ExposeAuthInfo yes
DisableForwarding yes
PermitTTY no
PermitUserRC no
PermitUserEnvironment no
PermitTunnel no
MaxSessions 1
ForceCommand {worker_command}
LogLevel ERROR
""")
            config.chmod(0o444)
            host_public = (
                host.public_key()
                .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                .decode()
            )
            (directory / "known_hosts").write_text(
                f"[127.0.0.1]:{ssh_port} {host_public}\n"
            )
            ssh_arguments = [
                "/usr/bin/ssh",
                "-F",
                "/dev/null",
                "-T",
                "-oBatchMode=yes",
                "-oIdentitiesOnly=yes",
                "-oStrictHostKeyChecking=yes",
                f"-oUserKnownHostsFile={directory}/known_hosts",
                "-oGlobalKnownHostsFile=/dev/null",
                "-oConnectTimeout=3",
                "-i",
                str(directory / "client"),
                "-p",
                str(ssh_port),
                "gate0-attester@127.0.0.1",
            ]
            # Same already-sealed K and pinned daemon, but a genuine certificate
            # signed by the accepted CA for an unaccepted principal. A distinct
            # private key avoids the client's automatic valid-cert fallback.
            refused_arguments = [
                str(directory / "wrong-client")
                if value == str(directory / "client")
                else value
                for value in ssh_arguments
            ]
            assert not entry_marker.exists()
            refused_client = subprocess.Popen(
                refused_arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            refused_daemon = None
            try:
                accepted, _ = ssh_listener.accept()
                with accepted:
                    refused_daemon = subprocess.Popen(
                        ["/usr/sbin/sshd", "-i", "-e", "-f", str(config)],
                        stdin=accepted,
                        stdout=accepted,
                        stderr=subprocess.PIPE,
                    )
                refused_output, refused_error = refused_client.communicate(timeout=8)
                _, daemon_error = refused_daemon.communicate(timeout=3)
                assert refused_client.returncode == 255
                assert refused_daemon.returncode is not None
                assert (
                    refused_daemon.returncode >= 0
                ), "authentication monitor was killed"
                assert refused_output == b""
                assert b"GATE0_NATIVE_STAGE=worker_entered" not in refused_error
                assert b"Permission denied (publickey)" in refused_error
                assert b"principal" in daemon_error.lower()
                assert not entry_marker.exists(), "refused principal entered worker"
                assert launch._proc_capabilities(1) == (K, K, 0, 0, K, 1)
            finally:
                for process in (refused_client, refused_daemon):
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=3)
                        if process.stdout is not None:
                            process.stdout.close()
                        if process.stderr is not None:
                            process.stderr.close()
            # Reap the actual authentication monitor/privsep descendants before
            # admitting the positive session. A timeout is not a refusal proof.
            refusal_cleanup_end = time.monotonic() + 3
            while Path("/proc/1/task/1/children").read_text().strip():
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                assert (
                    time.monotonic() < refusal_cleanup_end
                ), "refused authentication descendant remained"
                if pid == 0:
                    time.sleep(0.02)
            assert not Path("/proc/1/task/1/children").read_text().strip()
            assert not entry_marker.exists()
            _stage("positive_authentication_started")
            ssh_client = subprocess.Popen(
                ssh_arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            daemon = None
            client_error = b""
            diagnostic_buffers = {}
            try:
                accepted, _ = ssh_listener.accept()
                with accepted:
                    assert (
                        accepted.getsockopt(
                            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16
                        ).rstrip(b"\0")
                        == b"lo"
                    )
                    daemon = subprocess.Popen(
                        ["/usr/sbin/sshd", "-i", "-e", "-f", str(config)],
                        stdin=accepted,
                        stdout=accepted,
                        stderr=subprocess.PIPE,
                    )
                for negative in (True, False):
                    connection, _ = _accept_echo_or_exit(
                        echo_listener, ssh_client, daemon, time.monotonic() + 8
                    )
                    _stage(
                        "negative_socket_received"
                        if negative
                        else "positive_socket_received"
                    )
                    with connection:
                        connection.settimeout(3)
                        received = connection.recv(64)
                        if negative:
                            assert (
                                received == b""
                            ), "payload preceded native device refusal"
                        else:
                            assert received == b"gate0-native-synthetic"
                            connection.sendall(b"native-readback")
                output, client_error = ssh_client.communicate(timeout=8)
                daemon.wait(timeout=3)
                if ssh_client.returncode != 0 or daemon.returncode != 0:
                    raise AssertionError("native positive SSH exchange failed")
                assert daemon.returncode == 0
                report = json.loads(output)
                assert entry_marker.is_file(), "positive did not enter fixed worker"
                assert report["worker"] == [0, 0, 0, 0, K, 1]
                assert report["spawn"]["fresh_socket_exchange"] is True
                assert report["spawn"]["device_mismatch_refused"] is True
            except Exception as failure:
                _failure("positive_exchange_failed", failure)
                if isinstance(failure, subprocess.TimeoutExpired) and isinstance(
                    failure.stderr, bytes
                ):
                    client_error = failure.stderr
                _safe_child_diagnostics(
                    ssh_client, daemon, diagnostic_buffers, client_error
                )
                raise
            finally:
                # Close the server first, allowing the client to forward its
                # final fixed worker diagnostics before its own bounded close.
                for process in (daemon, ssh_client):
                    if process is not None:
                        close_deadline = time.monotonic() + 3
                        while (
                            process is ssh_client
                            and process.poll() is None
                            and time.monotonic() < close_deadline - 0.1
                        ):
                            _safe_child_diagnostics(
                                ssh_client, daemon, diagnostic_buffers
                            )
                            time.sleep(
                                min(
                                    0.02,
                                    max(0, close_deadline - 0.1 - time.monotonic()),
                                )
                            )
                        if process.poll() is None:
                            if process is ssh_client:
                                _stage("child_cleanup_deadline")
                            process.kill()
                        process.wait(
                            timeout=max(0.001, close_deadline - time.monotonic())
                        )
                        _safe_child_diagnostics(ssh_client, daemon, diagnostic_buffers)
                _safe_child_diagnostics(
                    ssh_client, daemon, diagnostic_buffers, emit=True
                )
                for process in (daemon, ssh_client):
                    if process is not None:
                        if process.stdout is not None:
                            process.stdout.close()
                        if process.stderr is not None:
                            process.stderr.close()
        # PID1 must reap any exited privsep/spawn grandchildren as well.
        cleanup_end = time.monotonic() + 3
        while Path("/proc/1/task/1/children").read_text().strip():
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            assert time.monotonic() < cleanup_end, "native descendant remained"
            if pid == 0:
                time.sleep(0.02)
        assert not Path("/proc/1/task/1/children").read_text().strip()
        print(
            json.dumps(
                {
                    "schema": "Gate0NativeNetworkPrivilegeProof.v1",
                    "passed": True,
                    "supervisor_capabilities": launch._proc_capabilities(1),
                    "worker": report,
                    "wrong_principal_refused_under_k": True,
                    "refused_authentication_boundary_empty": True,
                    "full_wireguard_installation_qualified": False,
                    "live_readiness": False,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--native-worker":
        try:
            _worker(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
        except Exception as error:
            _failure("worker_failed", error)
            raise
    else:
        assert len(sys.argv) == 1
        _native_role_image()
