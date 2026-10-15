"""Closed public capture delivery; root supervisor alone owns publication.

A parsed selection is an equality value, never authority. The receiver obtains
its concrete launch context from the protected installation, not request JSON.
"""

from __future__ import annotations

import base64
import binascii
import re
import socket
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from time import monotonic
from uuid import UUID

from vendor_cp.deployment.gate0_capture import (
    CaptureCoordinates,
    PublicCapture,
    decode_capture,
)
from vendor_cp.deployment.gate0_framing import FramedChannel, canonical
from vendor_cp.deployment.gate0_launch import (
    CaptureInstallReadback,
    InstalledLaunchContext,
)
from vendor_cp.deployment.gate0_role_custody import (
    ProviderRefused,
    json_record,
    json_string,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_INSTALL_BYTES = 196608


def _hash(value: object) -> str:
    value = json_string(value)
    if _DIGEST.fullmatch(value) is None:
        raise ProviderRefused()
    return value


def _uuid(value: object) -> UUID:
    text = json_string(value)
    result = UUID(text)
    if str(result) != text:
        raise ProviderRefused()
    return result


@dataclass(frozen=True, slots=True)
class CaptureSelection:
    window_digest: str
    plan_id: UUID
    plan_digest: str
    target_id: UUID
    approval_request_id: UUID

    def __post_init__(self) -> None:
        _hash(self.window_digest)
        _hash(self.plan_digest)
        if any(
            type(value) is not UUID
            for value in (self.plan_id, self.target_id, self.approval_request_id)
        ):
            raise ProviderRefused()

    def require_coordinates(self, coordinates: CaptureCoordinates) -> None:
        if type(coordinates) is not CaptureCoordinates or any(
            getattr(self, field) != getattr(coordinates, field)
            for field in self.__dataclass_fields__
        ):
            raise ProviderRefused()


def selection_document(value: CaptureSelection) -> dict[str, object]:
    return {key: str(item) for key, item in asdict(value).items()}


def parse_selection(value: object) -> CaptureSelection:
    record = json_record(value)
    if set(record) != set(CaptureSelection.__dataclass_fields__):
        raise ProviderRefused()
    return CaptureSelection(
        _hash(record["window_digest"]),
        _uuid(record["plan_id"]),
        _hash(record["plan_digest"]),
        _uuid(record["target_id"]),
        _uuid(record["approval_request_id"]),
    )


def _coordinates(value: object) -> CaptureCoordinates:
    record = json_record(value)
    if set(record) != set(CaptureCoordinates.__dataclass_fields__):
        raise ProviderRefused()
    selection = parse_selection(
        {key: item for key, item in record.items() if key != "capture_digest"}
    )
    return CaptureCoordinates(
        _hash(record["capture_digest"]),
        selection.window_digest,
        selection.plan_id,
        selection.plan_digest,
        selection.target_id,
        selection.approval_request_id,
    )


def install_document(
    packet_digest: str,
    captures: tuple[PublicCapture, PublicCapture],
    selections: tuple[CaptureSelection, CaptureSelection],
) -> dict[str, object]:
    _hash(packet_digest)
    if (
        type(captures) is not tuple
        or len(captures) != 2
        or type(selections) is not tuple
        or len(selections) != 2
        or selections[0].plan_id == selections[1].plan_id
    ):
        raise ProviderRefused()
    entries: list[dict[str, object]] = []
    for slot, capture, selection in zip(("a", "b"), captures, selections, strict=True):
        if (
            type(capture) is not PublicCapture
            or type(selection) is not CaptureSelection
        ):
            raise ProviderRefused()
        selection.require_coordinates(capture.coordinates)
        decode_capture(capture.encoded, expected=capture.coordinates)
        entries.append(
            {
                "slot": slot,
                "coordinates": {
                    key: str(value)
                    for key, value in asdict(capture.coordinates).items()
                },
                "capture_b64": base64.b64encode(capture.encoded).decode("ascii"),
            }
        )
    result: dict[str, object] = {
        "schema": "Gate0CaptureInstall.v1",
        "launch_packet_digest": packet_digest,
        "captures": entries,
    }
    if len(canonical(result)) > MAX_INSTALL_BYTES:
        raise ProviderRefused()
    return result


def validate_install(
    document: dict[str, object],
    packet_digest: str,
    selections: tuple[CaptureSelection, CaptureSelection],
) -> tuple[CaptureCoordinates, CaptureCoordinates]:
    if (
        set(document) != {"schema", "launch_packet_digest", "captures"}
        or document["schema"] != "Gate0CaptureInstall.v1"
        or document["launch_packet_digest"] != packet_digest
        or len(canonical(document)) > MAX_INSTALL_BYTES
    ):
        raise ProviderRefused()
    entries = document["captures"]
    if not isinstance(entries, list) or len(entries) != 2 or len(selections) != 2:
        raise ProviderRefused()
    coordinates: list[CaptureCoordinates] = []
    for slot, entry, selection in zip(("a", "b"), entries, selections, strict=True):
        record = json_record(entry)
        if (
            set(record) != {"slot", "coordinates", "capture_b64"}
            or record["slot"] != slot
        ):
            raise ProviderRefused()
        coordinate = _coordinates(record["coordinates"])
        selection.require_coordinates(coordinate)
        text = json_string(record["capture_b64"])
        if not 0 < len(text) <= 87384:
            raise ProviderRefused()
        try:
            encoded = base64.b64decode(text, validate=True)
        except (ValueError, binascii.Error):
            raise ProviderRefused() from None
        if base64.b64encode(encoded).decode("ascii") != text:
            raise ProviderRefused()
        decode_capture(encoded, expected=coordinate)
        coordinates.append(coordinate)
    return coordinates[0], coordinates[1]


def verify_readback(
    document: dict[str, object], expected: CaptureInstallReadback
) -> None:
    if document != expected.document():
        raise ProviderRefused()


def receive_capture_install(
    *,
    context: InstalledLaunchContext,
    channel: FramedChannel,
    selections: tuple[CaptureSelection, CaptureSelection],
    absolute_end: datetime,
) -> None:
    """Stage one SSH-authenticated request; parent commits and owns readback.

    This worker never creates active files or changes their metadata. The root
    context pins its UID/cgroup and the parent verifies native peer credentials.
    """
    import os

    if (
        type(context) is not InstalledLaunchContext
        or context.role != "management"
        or os.environ.get("SSH_ORIGINAL_COMMAND")
        or os.environ.get("SSH_TTY")
        or absolute_end.tzinfo is None
        or absolute_end != context.expires_at
    ):
        raise ProviderRefused()
    context.require_installation("management", context.packet_digest, absolute_end)
    if channel.deadline > min(context.deadline, monotonic() + 10):
        raise ProviderRefused()
    document = channel.receive()
    if document is None:
        raise ProviderRefused()
    coordinates = validate_install(document, context.packet_digest, selections)
    if channel.receive(allow_eof=True) is not None:
        raise ProviderRefused()
    context.require_open()
    expected = CaptureInstallReadback(context.packet_digest, coordinates, absolute_end)
    with context.open_management_channel() as connection:
        parent = FramedChannel(
            connection.fileno(),
            connection.fileno(),
            deadline=channel.deadline,
            maximum_frames=2,
        )
        parent.send(document)
        connection.shutdown(socket.SHUT_WR)
        readback = parent.receive()
        if readback is None:
            raise ProviderRefused()
        verify_readback(readback, expected)
        if parent.receive(allow_eof=True) is not None:
            raise ProviderRefused()
    if datetime.now(UTC) >= absolute_end:
        raise ProviderRefused()
    context.require_open()
    channel.send(expected.document())


@dataclass(frozen=True, slots=True)
class ManagementDeliveryInstallation:
    launch_packet_digest: str
    not_before: datetime
    expires_at: datetime
    source_address: str
    destination_address: str
    destination_port: int
    recipient_uid: int
    recipient_name: str
    management_key_fingerprint: str
    host_key_algorithm: str
    host_key_fingerprint: str
    ssh_client_digest: str
    ssh_server_digest: str
    ssh_config_digest: str
    captures: tuple[CaptureSelection, CaptureSelection]

    def validate(self) -> None:
        import ipaddress

        for digest in (
            self.launch_packet_digest,
            self.ssh_client_digest,
            self.ssh_server_digest,
            self.ssh_config_digest,
        ):
            _hash(digest)
        if (
            any(
                type(value) is not datetime
                or value.tzinfo is None
                or value.utcoffset() != datetime.now(UTC).utcoffset()
                for value in (self.not_before, self.expires_at)
            )
            or not self.not_before <= datetime.now(UTC) < self.expires_at
            or not 0 < (self.expires_at - self.not_before).total_seconds() <= 300
        ):
            raise ProviderRefused()
        for address in (self.source_address, self.destination_address):
            if type(address) is not str:
                raise ProviderRefused()
            try:
                parsed = ipaddress.IPv4Address(address)
            except ValueError:
                raise ProviderRefused() from None
            if str(parsed) != address or not any(
                parsed in ipaddress.IPv4Network(network)
                for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            ):
                raise ProviderRefused()
        if (
            self.source_address == self.destination_address
            or type(self.destination_port) is not int
            or not 1 <= self.destination_port <= 65535
            or type(self.recipient_uid) is not int
            or self.recipient_uid <= 0
            or type(self.recipient_name) is not str
            or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.recipient_name) is None
            or type(self.host_key_algorithm) is not str
            or self.host_key_algorithm != "ssh-ed25519"
            or any(
                type(value) is not str
                or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value) is None
                for value in (
                    self.management_key_fingerprint,
                    self.host_key_fingerprint,
                )
            )
            or type(self.captures) is not tuple
            or len(self.captures) != 2
            or any(type(value) is not CaptureSelection for value in self.captures)
            or self.captures[0].plan_id == self.captures[1].plan_id
        ):
            raise ProviderRefused()
        for selection in self.captures:
            selection.__post_init__()

    def document(self) -> dict[str, object]:
        self.validate()
        return {
            "schema": "Gate0ManagementCaptureDelivery.v1",
            **{
                key: value
                for key, value in asdict(self).items()
                if key not in ("captures", "not_before", "expires_at")
            },
            "not_before": self.not_before.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
            "captures": [selection_document(item) for item in self.captures],
        }


def _protected_bytes(path: str, maximum: int, *, secret: bool = False) -> bytes:
    """Fixed package ABI files; no caller-supplied path reaches this helper."""
    import os
    import stat
    from pathlib import Path

    selected = Path(path)
    for parent in reversed(selected.parents):
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise ProviderRefused()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or before.st_mode & (0o077 if secret else 0o022)
            or not 0 < before.st_size <= maximum
        ):
            raise ProviderRefused()
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        immutable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            any(getattr(before, field) != getattr(after, field) for field in immutable)
            or len(raw) != before.st_size
        ):
            raise ProviderRefused()
        return raw
    finally:
        os.close(fd)


def ssh_public_key_fingerprint(line: bytes, algorithm: str) -> str:
    import hashlib

    if (
        type(line) is not bytes
        or not 0 < len(line) <= 4096
        or algorithm != "ssh-ed25519"
    ):
        raise ProviderRefused()
    fields = line.strip().split()
    if len(fields) != 2 or fields[0] != algorithm.encode("ascii"):
        raise ProviderRefused()
    try:
        raw = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error):
        raise ProviderRefused() from None
    # A canonical OpenSSH blob starts with the exact algorithm string.
    prefix = len(algorithm).to_bytes(4, "big") + algorithm.encode("ascii")
    if (
        len(raw) != len(prefix) + 4 + 32
        or not raw.startswith(prefix + (32).to_bytes(4, "big"))
        or base64.b64encode(raw) != fields[1]
    ):
        raise ProviderRefused()
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode(
        "ascii"
    ).rstrip("=")


def push_capture_install(
    *,
    context: InstalledLaunchContext,
    installation: ManagementDeliveryInstallation,
) -> CaptureInstallReadback:
    """One pinned SSH invocation, fixed mounts, half-close and bounded readback.

    The protected key stays mounted under its existing management owner. Root
    supervision bounds every descendant by the same original cgroup deadline.
    A lost response never retries an already committed publication.
    """
    import hashlib
    import os

    installation.validate()
    if type(context) is not InstalledLaunchContext or context.role != "capture_sender":
        raise ProviderRefused()
    context.require_installation(
        "capture_sender", installation.launch_packet_digest, installation.expires_at
    )
    if installation.expires_at != context.expires_at:
        raise ProviderRefused()
    deadline = min(context.deadline, monotonic() + 10)
    # Public delivery input is pinned in the separate protected sender installation.
    fd = context.open_installation()
    try:
        installed = bytearray()
        while len(installed) <= 65536:
            part = os.read(fd, min(4096, 65537 - len(installed)))
            if not part:
                break
            installed.extend(part)
    finally:
        os.close(fd)
    from vendor_cp.deployment.gate0_framing import strict_object

    protected = strict_object(bytes(installed), 65536)
    if protected != installation.document():
        raise ProviderRefused()
    executable = "/usr/bin/ssh"
    root = "/run/dotmac-gate0/management/"
    binary = _protected_bytes(executable, 16 * 1024 * 1024)
    config = _protected_bytes(root + "ssh_config", 65536)
    if (
        "sha256:" + hashlib.sha256(binary).hexdigest() != installation.ssh_client_digest
        or "sha256:" + hashlib.sha256(config).hexdigest()
        != installation.ssh_config_digest
    ):
        raise ProviderRefused()
    if config != b"Host *\n    IdentityFile none\n":
        raise ProviderRefused()
    known = _protected_bytes(root + "known_hosts", 4096)
    host = (
        f"[{installation.destination_address}]:{installation.destination_port}".encode(
            "ascii"
        )
    )
    fields = known.strip().split(maxsplit=1)
    if (
        len(fields) != 2
        or fields[0] != host
        or ssh_public_key_fingerprint(fields[1], installation.host_key_algorithm)
        != installation.host_key_fingerprint
    ):
        raise ProviderRefused()
    # The dedicated parent's channel, not a caller argument or arbitrary
    # file, is the sole source of the owner export and its actual digest.
    with socket.socket(fileno=context.open_capture_export()) as export_connection:
        export = FramedChannel(
            export_connection.fileno(),
            export_connection.fileno(),
            deadline=deadline,
            maximum_frames=2,
        )
        document = export.receive()
        if document is None:
            raise ProviderRefused()
        coordinates = validate_install(
            document, installation.launch_packet_digest, installation.captures
        )
        if export.receive(allow_eof=True) is not None:
            raise ProviderRefused()
        result = _ssh_exchange(context, installation, document, coordinates, deadline)
        export.send(result.document())
        export_connection.shutdown(socket.SHUT_WR)
        return result


def _ssh_exchange(
    context: InstalledLaunchContext,
    installation: ManagementDeliveryInstallation,
    document: dict[str, object],
    coordinates: tuple[CaptureCoordinates, CaptureCoordinates],
    deadline: float,
) -> CaptureInstallReadback:
    import os
    import subprocess

    executable = "/usr/bin/ssh"
    root = "/run/dotmac-gate0/management/"
    expected = CaptureInstallReadback(
        installation.launch_packet_digest, coordinates, installation.expires_at
    )
    options = {
        "BatchMode": "yes",
        "IdentitiesOnly": "yes",
        "IdentityAgent": "none",
        "ForwardAgent": "no",
        "ClearAllForwardings": "yes",
        "RequestTTY": "no",
        "ProxyCommand": "none",
        "ProxyJump": "none",
        "ControlMaster": "no",
        "ControlPath": "none",
        "ControlPersist": "no",
        "StrictHostKeyChecking": "yes",
        "UserKnownHostsFile": root + "known_hosts",
        "GlobalKnownHostsFile": "/dev/null",
        "CanonicalizeHostname": "no",
        "PermitLocalCommand": "no",
        "LocalCommand": "none",
        "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no",
        "NumberOfPasswordPrompts": "0",
        "ConnectionAttempts": "1",
        "ConnectTimeout": "5",
        "UpdateHostKeys": "no",
        "EscapeChar": "none",
        "RemoteCommand": "none",
        "KnownHostsCommand": "none",
        "CertificateFile": "none",
        "HostKeyAlgorithms": "ssh-ed25519",
        "PubkeyAcceptedAlgorithms": "ssh-ed25519",
        "PreferredAuthentications": "publickey",
        "ForwardX11": "no",
        "Tunnel": "no",
        "ForkAfterAuthentication": "no",
        "AddKeysToAgent": "no",
    }
    argv = [
        executable,
        "-F",
        root + "ssh_config",
        "-T",
        "-b",
        installation.source_address,
        "-p",
        str(installation.destination_port),
    ]
    for key, value in options.items():
        argv.extend(("-o", key + "=" + value))
    argv.extend(("-l", installation.recipient_name, installation.destination_address))
    context.require_open()
    identity_fd = context.open_management_identity(
        expected_fingerprint=installation.management_key_fingerprint
    )
    argv[1:1] = ["-i", root + "identity"]
    if monotonic() >= deadline:
        os.close(identity_fd)
        raise ProviderRefused()
    try:
        process = subprocess.Popen(  # noqa: S603 -- fixed binary, closed installed arguments
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            close_fds=True,
        )
    except BaseException:
        os.close(identity_fd)
        raise
    try:
        if process.stdin is None or process.stdout is None:
            raise ProviderRefused()
        channel = FramedChannel(
            process.stdout.fileno(),
            process.stdin.fileno(),
            deadline=deadline,
            maximum_frames=2,
        )
        channel.send(document)
        process.stdin.close()
        response = channel.receive()
        if response is None:
            raise ProviderRefused()
        verify_readback(response, expected)
        if (
            channel.receive(allow_eof=True) is not None
            or process.wait(timeout=max(0.001, deadline - monotonic())) != 0
        ):
            raise ProviderRefused()
        context.require_open()
        return expected
    finally:
        if process.poll() is None:
            process.kill()
        try:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # Root's finite cgroup supervisor owns native-code cleanup.
                raise ProviderRefused() from None
        finally:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
            os.close(identity_fd)


def require_management_server_pin(expected_digest: str) -> None:
    """Destination-only measurement of the same fixed supervised sshd binary."""
    import hashlib

    _hash(expected_digest)
    raw = _protected_bytes("/usr/sbin/sshd", 16 * 1024 * 1024)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ProviderRefused()
