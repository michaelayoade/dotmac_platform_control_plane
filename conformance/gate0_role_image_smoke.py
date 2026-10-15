"""Hosted image-byte acceptance, with no operational inputs or network.

This checks native ABI/installed command closure and missing-input refusal. It
does not qualify a launch, WireGuard peer, custody grant or readiness receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import pwd
import socket
import ssl
import subprocess
import sysconfig
import tempfile
import time

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vendor_cp.deployment import gate0_launch


def check_daemon_initialization() -> None:
    account = pwd.getpwnam("sshd")
    assert account.pw_uid != 0 and account.pw_shell == "/usr/sbin/nologin"
    with tempfile.TemporaryDirectory(prefix="gate0-image-smoke-") as directory:
        root = pathlib.Path(directory)
        key = root / "host-key"
        key.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )
        )
        key.chmod(0o600)
        config = root / "sshd.conf"
        config.write_text(
            "Port 37841\nListenAddress 127.0.0.1\n"
            f"HostKey {key}\nPidFile none\nUsePAM no\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "PermitRootLogin no\nAllowUsers nonexistent-gate0-smoke-user\n"
        )
        daemon = subprocess.Popen(  # noqa: S603 -- pinned daemon, local synthetic key
            ["/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 3
            banner = b""
            while time.monotonic() < deadline:
                assert daemon.poll() is None, "native daemon failed initialization"
                try:
                    with socket.create_connection(
                        ("127.0.0.1", 37841), timeout=0.2
                    ) as connection:
                        banner = connection.recv(256)
                    break
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(0.02)
            assert banner.startswith(b"SSH-2.0-OpenSSH_9.6"), "no pinned daemon banner"
        finally:
            daemon.terminate()
            daemon.wait(timeout=3)


def main() -> None:
    assert os.geteuid() == 0
    installed = pathlib.Path(sysconfig.get_path("purelib")).resolve()
    assert pathlib.Path(gate0_launch.__file__).resolve().is_relative_to(installed)
    assert not (gate0_launch.ROOT / "packet.json").exists()
    inventory = json.loads(pathlib.Path("/app/gate0_native_tools.json").read_bytes())
    assert inventory["schema"] == "Gate0NativeTools.v1"
    assert set(inventory["binaries"]) == {
        "/usr/bin/ssh",
        "/usr/sbin/sshd",
        "/usr/bin/wg",
        "/usr/sbin/ip",
        "/usr/sbin/nft",
    }
    for name, record in inventory["binaries"].items():
        assert not pathlib.Path(name).is_symlink()
        assert (
            hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
            == record["sha256"]
        )
    for role, uid in (
        ("issuer", 10031),
        ("attester", 10032),
        ("management", 10033),
        ("capture-sender", 10034),
    ):
        account = pwd.getpwnam("gate0-" + role)
        assert account.pw_uid == uid
        home = pathlib.Path(account.pw_dir).stat()
        assert home.st_uid == 0 and home.st_mode & 0o222 == 0
    versions: dict[str, str] = {}
    for command in (
        ["/usr/bin/ssh", "-V"],
        ["/usr/sbin/sshd", "-V"],
        ["/usr/bin/wg", "--version"],
        ["/usr/sbin/ip", "-Version"],
        ["/usr/sbin/nft", "--version"],
    ):
        result = subprocess.run(  # noqa: S603 -- closed image-native smoke commands
            command, capture_output=True, check=True, timeout=5
        )
        versions[command[0]] = (result.stdout + result.stderr).decode("ascii").strip()
    check_daemon_initialization()
    executable = "/opt/venv/bin/dotmac-platform"
    for command in (
        "issuer-run",
        "attester-session",
        "capture-install",
        "capture-send",
        "supervise",
    ):
        help_result = subprocess.run(  # noqa: S603 -- fixed installed command census
            [executable, "gate0", command, "--help"],
            capture_output=True,
            check=False,
            timeout=5,
        )
        assert help_result.returncode == 0
        result = subprocess.run(  # noqa: S603 -- fixed missing-input negative
            [executable, "gate0", command],
            capture_output=True,
            check=False,
            timeout=5,
        )
        assert result.returncode != 0
        assert b"Traceback" not in result.stderr
    print(
        json.dumps(
            {
                "schema": "Gate0RoleImageSmoke.v1",
                "passed": True,
                "native_versions": versions,
                "ssl": ssl.OPENSSL_VERSION,
                "psycopg": psycopg.__version__,
                "live_readiness": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
