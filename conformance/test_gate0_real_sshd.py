"""Real sshd conformance, hosted-only, installed wheel and exact binaries required.

This suite is outside default pytest testpaths and is explicitly invoked by
the coordinator-owned installed-sshd workflow and artifact pins. Missing
bindings fail; source pins are not hosted qualification or live acceptance.
"""
# Fixed hosted test fixture vectors only; no production request selects commands.
# ruff: noqa: S603

import hashlib
import json
import os
import pwd
import shutil
import socket
import struct
import subprocess
import sys
import sysconfig
import tempfile
import time
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://x:x@127.0.0.1/gate0_synthetic"
)
os.environ.setdefault(
    "PLATFORM_DATABASE_URL", "postgresql+psycopg://x:x@127.0.0.1/gate0_synthetic"
)

from vendor_cp.deployment.gate0_attester import ssh_public_fingerprint  # noqa: E402
from vendor_cp.deployment.gate0_framing import FramedChannel, canonical  # noqa: E402
from vendor_cp.deployment.gate0_observation import (
    decode,
    digest,
    encode,
    parse_bundle,
    verify_observation,
)  # noqa: E402
from vendor_cp.deployment.gate0_runtime import AdmittedOperation  # noqa: E402
from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,  # noqa: E402
)


def run(argv, **kwargs):
    return subprocess.run(
        argv,
        check=True,
        timeout=10,
        capture_output=True,
        **kwargs,
    )  # noqa: S603 -- fixed hosted synthetic fixture vectors


def qualified_binary(document, name):
    entry = document[name]
    path = Path(entry["path"])
    assert path.is_absolute() and path.is_file()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["binary_sha256"]
    assert len(entry["archive_sha256"]) == 64
    assert entry["package_version"] == "1:9.6p1-3ubuntu13.19"
    return str(path)


@pytest.fixture
def daemon(record_property):
    assert os.environ.get("GITHUB_ACTIONS") == "true", "hosted-only qualification"
    assert (
        os.geteuid() == 0
    ), "disposable task daemon requires root; worker must not be root"
    from vendor_cp.deployment import gate0_services

    assert (
        Path(gate0_services.__file__)
        .resolve()
        .is_relative_to(Path(sysconfig.get_path("purelib")).resolve())
    ), "qualification must use the installed wheel, not an editable checkout"
    qualification = json.loads(
        Path(os.environ["GATE0_SSHD_QUALIFICATION_JSON"]).read_bytes()
    )
    sshd = qualified_binary(qualification, "server")
    ssh = qualified_binary(qualification, "client")
    record_property("sshd_qualification", json.dumps(qualification, sort_keys=True))
    # The supervisor must separately authenticate these archive coordinates.
    # A self-asserted descriptor alone is not artifact provenance.
    directory = Path(tempfile.mkdtemp(prefix="gate0-sshd-"))
    directory.chmod(0o755)
    username = "g0" + directory.name.rsplit("-", 1)[1][:12]
    created = False
    process = None
    log = None
    try:
        run(
            [
                "/usr/sbin/useradd",
                "-M",
                "-d",
                str(directory),
                "-s",
                "/bin/sh",
                "-p",
                "x",
                username,
            ]
        )
        created = True
        account = pwd.getpwnam(username)
        uid, gid = account.pw_uid, account.pw_gid
        assert uid > 0
        now = datetime.now(UTC)
        controller, ca, attester, host = (
            Ed25519PrivateKey.generate() for _ in range(4)
        )

        def write_private(name, key):
            path = directory / name
            path.write_bytes(
                key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
            )
            path.chmod(0o600)
            return path

        controller_path = write_private("controller", controller)
        host_path = write_private("host", host)
        cert = (
            SSHCertificateBuilder()
            .public_key(controller.public_key())
            .type(SSHCertificateType.USER)
            .key_id(b"gate0:1:2:1")
            .valid_principals([b"dotmac-gate0-controller"])
            .valid_after(int(now.timestamp()) - 1)
            .valid_before(int(now.timestamp()) + 120)
            .sign(ca)
            .public_bytes()
        )
        (directory / "controller-cert.pub").write_bytes(cert)
        ca_public = ca.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        (directory / "ca.pub").write_bytes(ca_public)
        (directory / "principals").write_text("dotmac-gate0-controller\n")
        public = attester.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        trust = {
            "version": 1,
            "trusted_key_ids": {"synthetic-attester": digest(public)},
            "revoked_key_ids": [],
        }
        operation = AdmittedOperation(
            "1",
            "2",
            "1",
            "synthetic-window",
            "issue",
            None,
            None,
            "synthetic-lease",
            ssh_public_fingerprint(controller.public_key()),
            "synthetic-target",
            "00000000-0000-0000-0000-000000000001",
            digest(b"plan"),
            "rehearsal_issuer_operation",
            "deploy",
            digest(b"execution"),
            digest(cert),
            ssh_public_fingerprint(ca.public_key()),
        )
        config = directory / "synthetic.json"
        config.write_text(
            json.dumps(
                {
                    "operation": asdict(operation),
                    "attester_seed": encode(
                        attester.private_bytes(
                            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                        )
                    ),
                    "attester_public": encode(public),
                    "ca_public": encode(ca_public),
                    "trust": trust,
                    "record_digest": digest(b"independent-window"),
                    "expires_at": (now + timedelta(seconds=120)).isoformat(),
                }
            )
        )
        config.chmod(0o440)
        os.chown(config, 0, gid)
        lock = config.with_suffix(".lock")
        lock.touch(mode=0o444)
        lock.chmod(0o444)
        # This disposable fixture refuses unreviewed system startup hooks.
        assert not Path("/etc/ssh/sshrc").exists()
        scratch = directory / "scratch"
        scratch.mkdir(mode=0o700)
        os.chown(scratch, uid, gid)
        ssh_home = directory / ".ssh"
        ssh_home.mkdir(mode=0o755)
        for startup in (ssh_home / "rc", directory / ".profile"):
            startup.write_text(f"touch {scratch}/startup-executed\n")
            startup.chmod(0o444)
        worker = directory / "worker.py"
        shutil.copyfile(
            Path(__file__).with_name("gate0_synthetic_sshd_worker.py"), worker
        )
        worker.chmod(0o444)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        # Only root-generated safe paths occur in the fixed command. No client
        # text is interpolated or evaluated by the server's login shell.
        assert all(
            " " not in str(path) for path in (worker, config, Path(sys.executable))
        )
        daemon_config = directory / "sshd_config"
        daemon_config.write_text(f"""Port {port}
ListenAddress 127.0.0.1
HostKey {host_path}
PidFile {directory}/pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com
TrustedUserCAKeys {directory}/ca.pub
AuthorizedKeysFile none
AuthorizedPrincipalsFile {directory}/principals
AllowUsers {username}
ExposeAuthInfo yes
DisableForwarding yes
PermitTTY no
PermitUserRC no
PermitUserEnvironment no
PermitTunnel no
MaxSessions 1
ForceCommand {sys.executable} -I {worker} {config}
LogLevel ERROR
""")
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
        run([sshd, "-t", "-f", str(daemon_config)])
        effective = run([sshd, "-T", "-f", str(daemon_config)]).stdout.decode()
        for required in (
            "disableforwarding yes",
            "permittty no",
            "permituserrc no",
            "permituserenvironment no",
            "exposeauthinfo yes",
            "authorizedkeysfile none",
        ):
            assert required in effective.splitlines()
        log = (directory / "daemon.log").open("wb")
        process = subprocess.Popen(
            [sshd, "-D", "-e", "-f", str(daemon_config)],
            stdout=subprocess.DEVNULL,
            stderr=log,
        )  # noqa: S603 -- isolated loopback test daemon
        for _ in range(100):
            assert process.poll() is None
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            pytest.fail("synthetic sshd did not become ready")
        yield dict(
            ssh=ssh,
            port=port,
            user=username,
            key=controller_path,
            operation=operation,
            public=public,
            trust=trust,
            directory=directory,
            record_digest=digest(b"independent-window"),
            ca=ca,
        )
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=5)
        if log is not None:
            log.close()
        if created:
            run(["/usr/sbin/userdel", username])
        shutil.rmtree(directory)


def client(daemon, options=(), command=()):
    return [
        daemon["ssh"],
        "-F",
        "/dev/null",
        "-p",
        str(daemon["port"]),
        "-i",
        str(daemon["key"]),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=2",
        *options,
        f"{daemon['user']}@127.0.0.1",
        *command,
    ]


@pytest.mark.parametrize(
    "attempt_environment_override",
    [
        None,
        "SSH_USER_AUTH",
        "SSH_ORIGINAL_COMMAND",
        "ENV",
        "BASH_ENV",
        "PYTHONPATH",
        "PATH",
        "LD_PRELOAD",
    ],
)
def test_real_certificate_authentication_installed_dispatch_and_same_key_proof(
    daemon, attempt_environment_override
):
    environment = os.environ.copy()
    options = ()
    if attempt_environment_override:
        environment[attempt_environment_override] = str(
            daemon["directory"] / ".profile"
        )
        options = ("-o", "SendEnv=" + attempt_environment_override)
    process = subprocess.Popen(
        client(daemon, options),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )  # noqa: S603 -- fixed synthetic SSH client
    try:
        channel = FramedChannel(
            process.stdout.fileno(),
            process.stdin.fileno(),
            deadline=time.monotonic() + 5,
        )
        channel.send(
            {
                "schema": "Gate0SessionBegin.v1",
                "phase": "issue",
                "plan_id": daemon["operation"].plan_id,
                "workload_token": "synthetic-job",
                "authorization": None,
            }
        )
        challenge = channel.receive()
        signature = run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(daemon["key"]),
                "-n",
                "dotmac-gate0-possession-v1",
            ],
            input=decode(challenge["challenge"], 8192),
        ).stdout
        channel.send(
            {
                "schema": "Gate0SessionResponse.v1",
                "challenge_id": challenge["challenge_id"],
                "sshsig": encode(signature),
            }
        )
        process.stdin.close()
        proof, observation = parse_bundle(channel.receive())
        verify_observation(
            proof=proof,
            observation=observation,
            operation=daemon["operation"],
            window_record_digest=daemon["record_digest"],
            key_id="synthetic-attester",
            public_key=daemon["public"],
            trust_state=RehearsalIssuerTrustState.start(
                minimum_version=1, read_record=lambda: daemon["trust"]
            ),
            now=datetime.now(UTC),
        )
        assert process.wait(timeout=5) == 0
        assert not (daemon["directory"] / "scratch" / "startup-executed").exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize(
    "options,command",
    [
        ((), ("touch /tmp/gate0-shell-bypass",)),
        (("-s",), ("sftp",)),
        (("-tt",), ()),
    ],
)
def test_no_arbitrary_command_subsystem_or_pty_proof(daemon, options, command):
    result = subprocess.run(
        client(daemon, options, command),
        input=b"",
        capture_output=True,
        timeout=5,
        check=False,
    )  # noqa: S603 -- fixed negative fixture vectors
    assert result.returncode != 0
    assert b"Gate0SessionProofBundle" not in result.stdout


def test_forwarding_rejected_by_actual_daemon(daemon):
    result = subprocess.run(
        client(
            daemon,
            ("-N", "-R", "127.0.0.1:0:127.0.0.1:1", "-o", "ExitOnForwardFailure=yes"),
        ),
        input=b"",
        capture_output=True,
        timeout=5,
        check=False,
    )  # noqa: S603 -- isolated forwarding-negative probe
    assert result.returncode != 0


def test_different_authenticated_controller_never_receives_challenge(daemon):
    other = Ed25519PrivateKey.generate()
    key = daemon["directory"] / "other"
    key.write_bytes(
        other.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    )
    key.chmod(0o600)
    now = datetime.now(UTC)
    certificate = (
        SSHCertificateBuilder()
        .public_key(other.public_key())
        .type(SSHCertificateType.USER)
        .key_id(b"gate0:1:2:1")
        .valid_principals([b"dotmac-gate0-controller"])
        .valid_after(int(now.timestamp()) - 1)
        .valid_before(int(now.timestamp()) + 120)
        .sign(daemon["ca"])
        .public_bytes()
    )
    key.with_name("other-cert.pub").write_bytes(certificate)
    selected = dict(daemon, key=key)
    request = canonical(
        {
            "schema": "Gate0SessionBegin.v1",
            "phase": "issue",
            "plan_id": daemon["operation"].plan_id,
            "workload_token": "synthetic-job",
            "authorization": None,
        }
    )
    result = subprocess.run(
        client(selected),
        input=struct.pack("!I", len(request)) + request,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 3
    assert result.stdout == b""
    assert b"Traceback" not in result.stderr


def begin_document(daemon):
    return {
        "schema": "Gate0SessionBegin.v1",
        "phase": "issue",
        "plan_id": daemon["operation"].plan_id,
        "workload_token": "synthetic-job",
        "authorization": None,
    }


def finish_exchange(daemon, process, channel, challenge):
    signature = run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(daemon["key"]),
            "-n",
            "dotmac-gate0-possession-v1",
        ],
        input=decode(challenge["challenge"], 8192),
    ).stdout
    channel.send(
        {
            "schema": "Gate0SessionResponse.v1",
            "challenge_id": challenge["challenge_id"],
            "sshsig": encode(signature),
        }
    )
    process.stdin.close()
    return channel.receive()


def test_valid_exchange_attempt_under_requested_pty_produces_no_proof(daemon):
    process = subprocess.Popen(
        client(daemon, ("-tt",)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        channel = FramedChannel(
            process.stdout.fileno(),
            process.stdin.fileno(),
            deadline=time.monotonic() + 5,
        )
        bundle = None
        try:
            channel.send(begin_document(daemon))
            challenge = channel.receive()
            bundle = finish_exchange(daemon, process, channel, challenge)
        except (ValueError, OSError):
            pass
        assert bundle is None, "a valid protocol must not produce proof under PTY"
        assert process.wait(timeout=5) != 0
        assert b"PTY allocation request failed" in process.stderr.read()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_fixture_serializes_distinct_authenticated_connections(daemon):
    first = subprocess.Popen(
        client(daemon),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        channel = FramedChannel(
            first.stdout.fileno(), first.stdin.fileno(), deadline=time.monotonic() + 5
        )
        channel.send(begin_document(daemon))
        challenge = channel.receive()  # First invocation holds fixture admission.
        request = canonical(begin_document(daemon))
        second = subprocess.run(
            client(daemon),
            input=struct.pack("!I", len(request)) + request,
            capture_output=True,
            timeout=5,
            check=False,
        )
        assert second.returncode == 3 and second.stdout == b""
        proof, _ = parse_bundle(finish_exchange(daemon, first, channel, challenge))
        assert proof.context.phase == "issue" and first.wait(timeout=5) == 0
    finally:
        if first.poll() is None:
            first.kill()
            first.wait(timeout=5)


def test_worker_cannot_write_immutable_startup_and_remote_command_cannot_execute(
    daemon,
):
    config = daemon["directory"] / "synthetic.json"
    worker = daemon["directory"] / "worker.py"
    before = (config.read_bytes(), worker.read_bytes())
    user = pwd.getpwnam(daemon["user"])
    # Exact dedicated worker UID gets only read access to its root-owned startup.
    for path in (config, worker):
        attempted = subprocess.run(
            [
                "/usr/bin/setpriv",
                "--reuid",
                str(user.pw_uid),
                "--regid",
                str(user.pw_gid),
                "--clear-groups",
                sys.executable,
                "-I",
                "-c",
                "import os,sys; os.open(sys.argv[1],os.O_WRONLY)",
                str(path),
            ],
            capture_output=True,
            timeout=5,
            check=False,
        )
        assert attempted.returncode != 0
    request = canonical(begin_document(daemon))
    result = subprocess.run(
        client(daemon, command=(f"touch {daemon['directory']}/remote-executed",)),
        input=struct.pack("!I", len(request)) + request,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 3 and result.stdout == b""
    assert not (daemon["directory"] / "remote-executed").exists()
    assert (config.read_bytes(), worker.read_bytes()) == before
    assert not (daemon["directory"] / "scratch" / "startup-executed").exists()


@pytest.mark.parametrize("change", ["worker-writable", "worker-owned"])
def test_unprotected_fixture_startup_refuses_before_challenge(daemon, change):
    config = daemon["directory"] / "synthetic.json"
    if change == "worker-writable":
        config.chmod(0o660)
    else:
        account = pwd.getpwnam(daemon["user"])
        os.chown(config, account.pw_uid, account.pw_gid)
    request = canonical(begin_document(daemon))
    result = subprocess.run(
        client(daemon),
        input=struct.pack("!I", len(request)) + request,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 3 and result.stdout == b""
    assert b"Traceback" not in result.stderr
