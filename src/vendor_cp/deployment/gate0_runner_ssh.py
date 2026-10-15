"""Finite A9 controller clients. Protected installation is a separate authority.

These owners spawn their own children and never accept a caller pipe/process,
command, signer or completion observation. Pins constrain local inputs; a caller
constructing this DTO has not authenticated a protected installation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import select
import signal
import stat
import struct
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    load_ssh_private_key,
    load_ssh_public_identity,
)

from vendor_cp.deployment.gate0_attester import ssh_public_fingerprint
from vendor_cp.deployment.gate0_collection import (
    FramedCaseCollector,
    IssuerOutcome,
    OutcomeKind,
)
from vendor_cp.deployment.gate0_framing import (
    FramedChannel,
    ServiceRefused,
    canonical,
    strict_object,
)
from vendor_cp.deployment.gate0_observation import decode, digest, encode, parse_bundle
from vendor_cp.deployment.gate0_runtime import AdmittedOperation

_NAMESPACE = "dotmac-gate0-possession-v1"
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class RunnerFilePin:
    path: str
    sha256: str

    def read(self, uid: int, *, private: bool = False, maximum: int = 65536) -> bytes:
        path = Path(self.path)
        if (
            not path.is_absolute()
            or str(path) != self.path
            or ".." in path.parts
            or _HEX.fullmatch(self.sha256) is None
        ):
            raise ServiceRefused()
        for parent in (path.parent, *path.parents):
            metadata = parent.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in (0, uid)
                or metadata.st_mode & 0o022
            ):
                raise ServiceRefused()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in (0, uid)
                or metadata.st_mode & (0o077 if private else 0o022)
                or not 0 < metadata.st_size <= maximum
            ):
                raise ServiceRefused()
            raw = os.read(fd, maximum + 1)
            if (
                len(raw) != metadata.st_size
                or hashlib.sha256(raw).hexdigest() != self.sha256
            ):
                raise ServiceRefused()
            return raw
        finally:
            os.close(fd)


@dataclass(frozen=True, slots=True)
class RunnerSshEndpoint:
    host: str
    port: int
    source: str
    user: str
    host_key_alias: str

    def __post_init__(self) -> None:
        if (
            str(ipaddress.ip_address(self.host)) != self.host
            or str(ipaddress.ip_address(self.source)) != self.source
            or ipaddress.ip_address(self.host).version
            != ipaddress.ip_address(self.source).version
            or self.user == "root"
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.user) is None
            or re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", self.host_key_alias) is None
        ):
            raise ServiceRefused()


@dataclass(frozen=True, slots=True)
class RunnerSshInstallation:
    """One case's already approved fresh controller identity and fixed endpoints.

    The installer must qualify protected ownership, original clock mapping,
    per-case key freshness/distinctness, executable pins and host-key contents.
    This object alone supplies no installed/root provenance.
    """

    issuer: RunnerSshEndpoint
    attester: RunnerSshEndpoint
    ssh: RunnerFilePin
    keygen: RunnerFilePin
    private_key: RunnerFilePin = field(repr=False)
    certificate: RunnerFilePin
    known_hosts: RunnerFilePin
    owner_uid: int
    expires_at: datetime
    deadline: float

    def __post_init__(self) -> None:
        if (
            self.ssh.path != "/usr/bin/ssh"
            or self.keygen.path != "/usr/bin/ssh-keygen"
            or type(self.owner_uid) is not int
            or self.owner_uid != os.getuid()
            or type(self.expires_at) is not datetime
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() != timedelta(0)
            or not 0 < (self.expires_at - datetime.now(UTC)).total_seconds() <= 300
            or not math.isfinite(self.deadline)
            or not 0 < self.deadline - monotonic() <= 300
            or self.issuer == self.attester
        ):
            raise ServiceRefused()
        # Restrict the supplied original elapsed mapping; never extend it.
        object.__setattr__(
            self,
            "deadline",
            min(
                self.deadline,
                monotonic() + (self.expires_at - datetime.now(UTC)).total_seconds(),
            ),
        )

    def require_open(self) -> None:
        if monotonic() >= self.deadline or datetime.now(UTC) >= self.expires_at:
            raise ServiceRefused()

    def qualify_files(self) -> SSHCertificate:
        self.require_open()
        self.ssh.read(self.owner_uid, maximum=32 * 1024 * 1024)
        self.keygen.read(self.owner_uid, maximum=32 * 1024 * 1024)
        known = self.known_hosts.read(self.owner_uid)
        rows = known.splitlines()
        aliases = {self.issuer.host_key_alias, self.attester.host_key_alias}
        if len(aliases) != 2 or len(rows) != 2:
            raise ServiceRefused()
        found: set[str] = set()
        for row in rows:
            fields = row.split(b" ")
            if len(fields) != 3 or fields[1] != b"ssh-ed25519":
                raise ServiceRefused()
            alias = fields[0].decode("ascii")
            identity = load_ssh_public_identity(b" ".join(fields[1:]))
            if (
                alias not in aliases
                or alias in found
                or not isinstance(identity, Ed25519PublicKey)
            ):
                raise ServiceRefused()
            found.add(alias)
        raw = self.certificate.read(self.owner_uid).rstrip(b"\n")
        certificate = load_ssh_public_identity(raw)
        key_bytes = self.private_key.read(self.owner_uid, private=True)
        try:
            key = load_ssh_private_key(key_bytes, password=None)
        finally:
            del key_bytes
        if (
            not isinstance(certificate, SSHCertificate)
            or certificate.public_bytes() != raw
            or not isinstance(certificate.public_key(), Ed25519PublicKey)
            or not isinstance(certificate.signature_key(), Ed25519PublicKey)
            or not hasattr(key, "public_key")
            or not isinstance(key.public_key(), Ed25519PublicKey)
            or ssh_public_fingerprint(key.public_key())
            != ssh_public_fingerprint(certificate.public_key())
            or not certificate.valid_after
            <= datetime.now(UTC).timestamp()
            < certificate.valid_before
            or certificate.valid_before < self.expires_at.timestamp()
        ):
            raise ServiceRefused()
        self.require_open()
        return certificate


def _command(installation: RunnerSshInstallation, *, attester: bool) -> list[str]:
    endpoint = installation.attester if attester else installation.issuer
    return [
        installation.ssh.path,
        "-F",
        "/dev/null",
        "-T",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oIdentitiesOnly=yes",
        "-oIdentityAgent=none",
        "-oAddKeysToAgent=no",
        "-oPubkeyAuthentication=yes",
        "-oPreferredAuthentications=publickey",
        "-oPasswordAuthentication=no",
        "-oKbdInteractiveAuthentication=no",
        "-oHostbasedAuthentication=no",
        "-oGSSAPIAuthentication=no",
        "-oProxyCommand=none",
        "-oProxyJump=none",
        "-oControlMaster=no",
        "-oControlPath=none",
        "-oControlPersist=no",
        "-oClearAllForwardings=yes",
        "-oForwardAgent=no",
        "-oForwardX11=no",
        "-oPermitLocalCommand=no",
        "-oRequestTTY=no",
        "-oTunnel=no",
        "-oConnectionAttempts=1",
        "-oConnectTimeout=5",
        "-oServerAliveInterval=0",
        "-oEscapeChar=none",
        "-oEnableEscapeCommandline=no",
        "-oHostKeyAlgorithms=ssh-ed25519",
        "-oUpdateHostKeys=no",
        "-oVerifyHostKeyDNS=no",
        "-oGlobalKnownHostsFile=/dev/null",
        "-oUserKnownHostsFile=" + installation.known_hosts.path,
        "-oHostKeyAlias=" + endpoint.host_key_alias,
        "-oCertificateFile=" + installation.certificate.path,
        "-i",
        installation.private_key.path,
        "-b",
        endpoint.source,
        "-p",
        str(endpoint.port),
        endpoint.user + "@" + endpoint.host,
    ]


def _cleanup(processes: list[subprocess.Popen[bytes]], deadline: float) -> None:
    """One shared <=2s cleanup tail, including every signing child."""
    end = min(deadline, monotonic() + 2) if monotonic() < deadline else monotonic() + 2
    for process in processes:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    # Kill every remaining group before waiting, so N children cannot multiply
    # the bounded tail. wait() is always against that same absolute end.
    for process in processes:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    failed = False
    for process in processes:
        try:
            process.wait(timeout=max(0, end - monotonic()))
        except subprocess.TimeoutExpired:
            # A still-unreaped child is a failure, never completion evidence.
            failed = True
        finally:
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
    if failed:
        raise ServiceRefused()


@dataclass(frozen=True, slots=True)
class RunnerClientCompletion:
    """Read-only retained measurement; no public acceptance constructor seam."""

    pid: int
    returncode: int
    stdout_eof: bool
    completed_at: float


class _OwnedClient:
    def __init__(self, installation: RunnerSshInstallation, *, attester: bool) -> None:
        self.installation = installation
        self._processes: list[subprocess.Popen[bytes]] = []
        self._completion: RunnerClientCompletion | None = None
        self._closed = False
        try:
            self.certificate = installation.qualify_files()
            self._process = self._spawn(_command(installation, attester=attester))
            if self._process.stdin is None or self._process.stdout is None:
                raise ServiceRefused()
            self.channel = FramedChannel(
                self._process.stdout.fileno(),
                self._process.stdin.fileno(),
                deadline=installation.deadline,
            )
        except BaseException:
            self.close()
            raise

    def _spawn(self, command: list[str]) -> subprocess.Popen[bytes]:
        self.installation.require_open()
        process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603 -- closed pinned command construction
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_ENV,
            close_fds=True,
            start_new_session=True,
            bufsize=0,
        )
        self._processes.append(process)
        return process

    def _half_close(self) -> None:
        if self._process.stdin is None or self._process.stdin.closed:
            raise ServiceRefused()
        self._process.stdin.close()

    def _finish(self, status: int) -> RunnerClientCompletion:
        if self._completion is not None or self._closed:
            raise ServiceRefused()
        if self.channel.receive(allow_eof=True) is not None:
            raise ServiceRefused()
        self.installation.require_open()
        try:
            actual = self._process.wait(
                timeout=max(0, self.channel.deadline - monotonic())
            )
        except subprocess.TimeoutExpired:
            raise ServiceRefused() from None
        self.channel.require_open()
        self.installation.require_open()
        completed_at = monotonic()
        if actual != status or completed_at >= self.channel.deadline:
            raise ServiceRefused()
        self._completion = RunnerClientCompletion(
            self._process.pid, actual, True, completed_at
        )
        return self._completion

    @property
    def completion(self) -> RunnerClientCompletion | None:
        return self._completion

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _cleanup(self._processes, self.installation.deadline)

    def __enter__(self) -> _OwnedClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class OwnedIssuerSession(_OwnedClient):
    def __init__(self, installation: RunnerSshInstallation) -> None:
        super().__init__(installation, attester=False)
        self.collector = FramedCaseCollector(self.channel)

    def finish(self) -> tuple[IssuerOutcome, ...]:
        try:
            outcomes = self.collector.outcomes
            if (
                not outcomes
                or outcomes[-1].operation != "consume"
                or outcomes[-1].kind is not OutcomeKind.OWNER_REFUSED
                or any(
                    item.kind in (OutcomeKind.OWNER_REFUSED, OutcomeKind.INCOMPLETE)
                    for item in outcomes[:-1]
                )
            ):
                raise ServiceRefused()
            self._half_close()
            self._finish(3)
            return outcomes
        except BaseException:
            self.close()
            raise


def validate_challenge(
    frame: object,
    operation: AdmittedOperation,
    *,
    expires_at: datetime,
    wall: datetime,
) -> tuple[bytes, str, datetime]:
    if (
        type(operation) is not AdmittedOperation
        or type(frame) is not dict
        or set(frame) != {"schema", "challenge_id", "challenge"}
        or frame["schema"] != "Gate0SessionChallenge.v1"
    ):
        raise ServiceRefused()
    raw = decode(frame["challenge"], 8192)
    document = strict_object(raw, 8192)
    if (
        canonical(document) != raw
        or set(document)
        != {"schema", "instance_id", "challenge_id", "nonce", "context", "expires_at"}
        or document["schema"] != "Gate0PossessionChallenge.v1"
        or document["context"] != asdict(operation)
        or document["challenge_id"] != frame["challenge_id"]
        or any(
            type(document[key]) is not str or _HEX.fullmatch(document[key]) is None
            for key in ("instance_id", "challenge_id", "nonce")
        )
        or type(document["expires_at"]) is not str
    ):
        raise ServiceRefused()
    try:
        expiry = datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
    except ValueError:
        raise ServiceRefused() from None
    if (
        document["expires_at"]
        != expiry.astimezone(UTC).isoformat().replace("+00:00", "Z")
        or expiry.tzinfo is None
        or expiry.utcoffset() != timedelta(0)
        or not wall < expiry <= min(expires_at, wall + timedelta(seconds=30))
    ):
        raise ServiceRefused()
    return raw, document["challenge_id"], expiry


class OwnedAttesterSession(_OwnedClient):
    def __init__(self, installation: RunnerSshInstallation) -> None:
        super().__init__(installation, attester=True)
        self._bundle: bytes | None = None
        self._invocation_id: str | None = None
        self._used = False

    @property
    def bundle(self) -> bytes | None:
        return self._bundle

    @property
    def invocation_id(self) -> str | None:
        return self._invocation_id

    def _exact_bundle(self) -> bytes:
        # FramedChannel owns the same dedicated pipe. Its parser discards raw
        # JSON representation; retain the exact final frame for root digest joins.
        def read(size: int) -> bytes:
            result = bytearray()
            while len(result) < size:
                self.channel.require_open()
                timeout = self.channel.deadline - monotonic()
                if (
                    timeout <= 0
                    or not select.select([self.channel.input_fd], [], [], timeout)[0]
                ):
                    raise ServiceRefused()
                try:
                    chunk = os.read(
                        self.channel.input_fd, min(65536, size - len(result))
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    raise ServiceRefused()
                result.extend(chunk)
            self.channel.require_open()
            return bytes(result)

        size = struct.unpack("!I", read(4))[0]
        if not 0 < size <= 128 * 1024:
            raise ServiceRefused()
        raw = read(size)
        if canonical(strict_object(raw, 128 * 1024)) != raw:
            raise ServiceRefused()
        return raw

    def _sign(self, message: bytes, deadline: float) -> bytes:
        self.installation.keygen.read(
            self.installation.owner_uid, maximum=32 * 1024 * 1024
        )
        self.installation.private_key.read(self.installation.owner_uid, private=True)
        process = self._spawn(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                self.installation.private_key.path,
                "-n",
                _NAMESPACE,
            ]
        )
        if process.stdin is None or process.stdout is None:
            raise ServiceRefused()
        # The message is <=8192. Use the same nonblocking finite pipe writer;
        # unlike frames ssh-keygen consumes the exact raw challenge bytes.
        fd = process.stdin.fileno()
        os.set_blocking(fd, False)
        remaining = memoryview(message)
        while remaining:
            timeout = deadline - monotonic()
            if timeout <= 0 or not select.select([], [fd], [], timeout)[1]:
                raise ServiceRefused()
            try:
                count = os.write(fd, remaining[:512])
            except BlockingIOError:
                continue
            if count <= 0:
                raise ServiceRefused()
            remaining = remaining[count:]
        process.stdin.close()
        fd = process.stdout.fileno()
        os.set_blocking(fd, False)
        output = bytearray()
        while True:
            timeout = deadline - monotonic()
            if timeout <= 0 or not select.select([fd], [], [], timeout)[0]:
                raise ServiceRefused()
            try:
                chunk = os.read(fd, 16385 - len(output))
            except BlockingIOError:
                continue
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 16384:
                raise ServiceRefused()
        try:
            code = process.wait(timeout=max(0, deadline - monotonic()))
        except subprocess.TimeoutExpired:
            raise ServiceRefused() from None
        if code != 0 or monotonic() >= deadline or not output:
            raise ServiceRefused()
        return bytes(output)

    def collect(
        self,
        operation: AdmittedOperation,
        *,
        workload_token: str,
        authorization: bytes | None = None,
    ) -> bytes:
        try:
            if (
                self._used
                or type(operation) is not AdmittedOperation
                or type(workload_token) is not str
                or not 0 < len(workload_token) <= 16384
                or (operation.phase == "issue") != (authorization is None)
                or (
                    authorization is not None
                    and (
                        type(authorization) is not bytes
                        or not 0 < len(authorization) <= 128 * 1024
                        or digest(authorization) != operation.authorization_digest
                    )
                )
                or digest(self.certificate.public_bytes())
                != operation.certificate_digest
                or ssh_public_fingerprint(self.certificate.public_key())
                != operation.controller_fingerprint
                or ssh_public_fingerprint(self.certificate.signature_key())
                != operation.ca_fingerprint
            ):
                raise ServiceRefused()
            self._used = True
            self.channel.send(
                {
                    "schema": "Gate0SessionBegin.v1",
                    "phase": operation.phase,
                    "plan_id": operation.plan_id,
                    "workload_token": workload_token,
                    "authorization": None
                    if authorization is None
                    else encode(authorization),
                }
            )
            del workload_token
            challenge, challenge_id, expiry = validate_challenge(
                self.channel.receive(),
                operation,
                expires_at=self.installation.expires_at,
                wall=datetime.now(UTC),
            )
            end = min(
                self.installation.deadline,
                monotonic() + (expiry - datetime.now(UTC)).total_seconds(),
            )
            self.channel.deadline = min(self.channel.deadline, end)
            signature = self._sign(challenge, end)
            self.installation.require_open()
            if datetime.now(UTC) >= expiry or monotonic() >= end:
                raise ServiceRefused()
            self.channel.send(
                {
                    "schema": "Gate0SessionResponse.v1",
                    "challenge_id": challenge_id,
                    "sshsig": encode(signature),
                }
            )
            self._half_close()
            raw = self._exact_bundle()
            document = strict_object(raw, 128 * 1024)
            proof, observation = parse_bundle(document)
            context = asdict(proof.context)
            if (
                {
                    key: value
                    for key, value in context.items()
                    if key not in {"challenge_digest", "proof_transcript_digest"}
                }
                != asdict(operation)
                or proof.context.challenge_digest != digest(challenge)
                or proof.context.proof_transcript_digest
                != digest(proof.public_proof_transcript)
                or strict_object(proof.public_proof_transcript)
                != {
                    "schema": "Gate0PublicProofTranscript.v1",
                    "certificate": encode(self.certificate.public_bytes()),
                    "challenge": encode(challenge),
                    "sshsig": encode(signature),
                }
            ):
                raise ServiceRefused()
            from vendor_cp.deployment.gate0_observation import DOMAIN

            if not observation.canonical_bytes.startswith(DOMAIN):
                raise ServiceRefused()
            observed = strict_object(observation.canonical_bytes[len(DOMAIN) :], 8192)
            invocation = observed.get("invocation_id")
            if type(invocation) is not str or _HEX.fullmatch(invocation) is None:
                raise ServiceRefused()
            self._finish(0)
            self._bundle = raw
            self._invocation_id = invocation
            return raw
        except BaseException:
            self.close()
            raise
