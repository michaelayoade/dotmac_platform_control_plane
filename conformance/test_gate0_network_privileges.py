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

import hashlib
import json
import multiprocessing
import os
import pwd
import socket
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


def _socket_child(writer, supervisor_pid, port):
    uid = 10032
    launch._require_worker_privileges(uid, supervisor_pid)
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
            connection.settimeout(3)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
            connection.bind((endpoint.local_address, 0))
            connection.connect((endpoint.address, endpoint.port))
            if negative:
                wrong = replace(
                    endpoint,
                    interface="g0proof",
                    interface_index=socket.if_nametoindex("g0proof"),
                )
                try:
                    custody._socket_readback(connection, wrong)
                except custody.ProviderRefused:
                    pass
                else:
                    raise AssertionError("wrong native bound device was accepted")
            else:
                custody._socket_readback(connection, endpoint)
                connection.sendall(b"gate0-native-synthetic")
                assert connection.recv(64) == b"native-readback"
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


def _worker(supervisor_pid, port, entry_marker):
    # First instruction of the fixed forced worker, before its own checks:
    # authentication refusal must never reach even this marker.
    descriptor = os.open(
        entry_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    os.close(descriptor)
    assert os.geteuid() == 10032
    assert not os.environ.get("SSH_ORIGINAL_COMMAND")
    assert "-cert-v01@openssh.com" in Path(os.environ["SSH_USER_AUTH"]).read_text()
    launch._require_worker_privileges(10032, supervisor_pid)
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_socket_child, args=(writer, supervisor_pid, port))
    process.start()
    writer.close()
    try:
        assert reader.poll(8), "native transport child did not respond"
        report = json.loads(reader.recv_bytes(65536))
        process.join(2)
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
    with tempfile.TemporaryDirectory(prefix="g0-native-") as directory_name:
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
            ssh_client = subprocess.Popen(
                ssh_arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            daemon = None
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
                    connection, _ = echo_listener.accept()
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
                output, error = ssh_client.communicate(timeout=8)
                daemon.wait(timeout=3)
                assert ssh_client.returncode == 0, error.decode(errors="replace")
                assert daemon.returncode == 0
                report = json.loads(output)
                assert entry_marker.is_file(), "positive did not enter fixed worker"
                assert report["worker"] == [0, 0, 0, 0, K, 1]
                assert report["spawn"]["fresh_socket_exchange"] is True
                assert report["spawn"]["device_mismatch_refused"] is True
            finally:
                for process in (ssh_client, daemon):
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=3)
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
        _worker(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    else:
        assert len(sys.argv) == 1
        _native_role_image()
