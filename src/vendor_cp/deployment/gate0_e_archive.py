"""Private E packing mechanism; never an acceptance or custody authority."""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import traceback
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn

MAX_PRIVATE_BYTES = 16 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = MAX_PRIVATE_BYTES + 1024 * 1024
MAX_KEY_BYTES = 128 * 1024
ARCHIVE_NAMES = (
    "collection.json",
    "producer.json",
    "prerequisites.json",
    "receipt.json",
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")


class ArchiveRefused(Exception):
    """Fixed, nonreflecting refusal; private process diagnostics never escape."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class GpgArchiveProfile:
    """Externally qualified pins, not an assertion of qualification/acceptance."""

    executable: Path
    executable_sha256: str
    version_line: str
    public_key: bytes
    public_key_sha256: str
    primary_fingerprint: str
    encryption_fingerprint: str


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedArchive:
    ciphertext: bytes
    ciphertext_sha256: str
    plaintext_sha256: str
    inner_manifest_sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class PrivateArchive:
    inner_manifest: bytes
    proof_files: Mapping[str, bytes]


def unpack_private_archive(plaintext: bytes) -> PrivateArchive:
    """Closed byte-only inverse for actual B custody; never extract to a path.

    Validating archive shape and member hashes does not validate E semantics.
    """
    if type(plaintext) is not bytes or not 0 < len(plaintext) <= MAX_PRIVATE_BYTES:
        raise ArchiveRefused("archive_input_bound")
    files = {}
    offset = 0
    aggregate = 0
    try:
        for name in sorted(("manifest.json", *ARCHIVE_NAMES)):
            header = plaintext[offset : offset + 512]
            if len(header) != 512 or header[156:157] != b"0":
                raise ArchiveRefused("archive_members")
            size_field = header[124:136]
            if not re.fullmatch(rb"[0-7]{11}\x00", size_field):
                raise ArchiveRefused("archive_members")
            size = int(size_field[:-1], 8)
            aggregate += size
            if (
                not 0 < size <= MAX_PRIVATE_BYTES
                or aggregate > MAX_PRIVATE_BYTES - 65536
            ):
                raise ArchiveRefused("archive_input_bound")
            if name == "manifest.json" and size > 65536:
                raise ArchiveRefused("archive_manifest")
            expected = _tar_member(name, size).tobuf(format=tarfile.USTAR_FORMAT)
            if header != expected:
                raise ArchiveRefused("archive_members")
            offset += 512
            end = offset + size
            padded_end = end + (-size % 512)
            if padded_end > len(plaintext) or any(plaintext[end:padded_end]):
                raise ArchiveRefused("archive_members")
            files[name] = plaintext[offset:end]
            offset = padded_end
        # Match the writer's exact record padding, including at least two zero blocks.
        archive_end = ((offset + 1024 + 10239) // 10240) * 10240
        if len(plaintext) != archive_end or any(plaintext[offset:]):
            raise ArchiveRefused("archive_members")
        manifest = files.pop("manifest.json")
        if _pack(manifest, files) != plaintext:
            raise ArchiveRefused("archive_members")
        return PrivateArchive(manifest, MappingProxyType(files))
    except ArchiveRefused:
        raise
    except (ValueError, KeyError, UnicodeError):
        raise ArchiveRefused("archive_members") from None


def _tar_member(name: str, size: int) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = size
    member.mode = 0o600
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ""
    return member


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _deadline(deadline: float) -> None:
    if not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise ArchiveRefused("archive_deadline")


@dataclass(frozen=True, slots=True)
class GnuPgToolPins:
    executable: Path
    executable_sha256: str
    version_line: str


def qualify_gnupg_tools(
    gpg: GnuPgToolPins,
    gpgconf: GnuPgToolPins,
    *,
    deadline: float,
) -> None:
    """Qualify both fixed tools before any synthetic key operation or cleanup.

    No generic command callback or profile acceptance flag is introduced.
    """
    try:
        _deadline(deadline)
        # Complete both disk/install checks before even a --version invocation.
        for tool, pins in (("gpg", gpg), ("gpgconf", gpgconf)):
            if not re.fullmatch(
                rf"{tool} \(GnuPG\) 2\.[0-9]+\.[0-9]+", pins.version_line
            ):
                raise ArchiveRefused("archive_profile")
            _protected_binary(pins)
        with tempfile.TemporaryDirectory(prefix="gate0-e-tools-") as directory:
            os.chmod(directory, 0o700)
            env = {
                "HOME": directory,
                "GNUPGHOME": directory,
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            }
            for tool, pins in (("gpg", gpg), ("gpgconf", gpgconf)):
                options = (
                    [
                        "--no-options",
                        "--homedir",
                        directory,
                        "--batch",
                        "--no-tty",
                        "--no-autostart",
                    ]
                    if tool == "gpg"
                    else []
                )
                result = _run(
                    [str(pins.executable), *options, "--version"],
                    b"",
                    env,
                    deadline,
                    16384,
                )
                if (
                    not result.splitlines()
                    or result.splitlines()[0].decode("ascii") != pins.version_line
                ):
                    raise ArchiveRefused("archive_installation")
        _deadline(deadline)
    except ArchiveRefused:
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ArchiveRefused("archive_unavailable") from None


def _protected_binary(profile: GnuPgToolPins) -> None:
    path = profile.executable
    if not isinstance(path, Path) or not path.is_absolute():
        raise ArchiveRefused("archive_profile")
    for component in (path, *path.parents):
        info = component.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ArchiveRefused("archive_installation")
    if (
        not stat.S_ISREG(path.stat().st_mode)
        or path.stat().st_size > 64 * 1024 * 1024
        or not os.access(path, os.X_OK)
    ):
        raise ArchiveRefused("archive_installation")
    if not _DIGEST.fullmatch(profile.executable_sha256):
        raise ArchiveRefused("archive_profile")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != profile.executable_sha256:
        raise ArchiveRefused("archive_installation")


def _public_packets(raw: bytes) -> None:
    """Require binary public certificate packets; no secret, partial or opaque data."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_KEY_BYTES:
        raise ArchiveRefused("archive_recipient")
    offset = 0
    primaries = 0
    while offset < len(raw):
        header = raw[offset]
        offset += 1
        if not header & 128:
            raise ArchiveRefused("archive_recipient")
        if header & 64:
            tag = header & 63
            if offset >= len(raw):
                raise ArchiveRefused("archive_recipient")
            first = raw[offset]
            offset += 1
            if first < 192:
                length = first
            elif first < 224:
                if offset >= len(raw):
                    raise ArchiveRefused("archive_recipient")
                length = (first - 192) * 256 + raw[offset] + 192
                offset += 1
            elif first == 255:
                if offset + 4 > len(raw):
                    raise ArchiveRefused("archive_recipient")
                length = int.from_bytes(raw[offset : offset + 4], "big")
                offset += 4
            else:
                raise ArchiveRefused("archive_recipient")
        else:
            tag = (header >> 2) & 15
            size = (1, 2, 4, 0)[header & 3]
            if not size or offset + size > len(raw):
                raise ArchiveRefused("archive_recipient")
            length = int.from_bytes(raw[offset : offset + size], "big")
            offset += size
        if tag not in {2, 6, 13, 14, 17} or not length or offset + length > len(raw):
            raise ArchiveRefused("archive_recipient")
        primaries += tag == 6
        offset += length
    if primaries != 1:
        raise ArchiveRefused("archive_recipient")


def _run(
    argv: list[str],
    data: bytes,
    env: dict[str, str],
    deadline: float,
    limit: int,
) -> bytes:
    """Preserve the original encryption/version/listing API and stdout semantics."""
    output, _ = _run_channels(argv, data, env, deadline, limit)
    return output


def _run_channels(
    argv: list[str],
    data: bytes,
    env: dict[str, str],
    deadline: float,
    limit: int,
    *,
    status_channel: bool = False,
) -> tuple[bytes, bytes]:
    """Own the real child, bounded duplex pipes, group cancellation and reaping."""
    work_deadline = deadline - 1.0
    _deadline(work_deadline)
    status_read, status_write = (-1, -1)
    if status_channel:
        try:
            status_read, status_write = os.pipe()
        except OSError:
            raise ArchiveRefused("archive_process") from None
    try:
        process = subprocess.Popen(  # noqa: S603 -- internal fixed argv
            argv + (["--status-fd", str(status_write)] if status_channel else []),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            close_fds=True,
            pass_fds=(status_write,) if status_channel else (),
        )
    except BaseException:
        for descriptor in (status_read, status_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise ArchiveRefused("archive_process") from None
    status_output = bytearray()
    output = bytearray()
    sent = 0
    successful = False
    try:
        if status_write >= 0:
            os.close(status_write)
            status_write = -1
        if process.stdin is None or process.stdout is None:
            raise ArchiveRefused("archive_process")
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdin, process.stdout):
                os.set_blocking(stream.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            if status_read >= 0:
                os.set_blocking(status_read, False)
                selector.register(status_read, selectors.EVENT_READ)
            if data:
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selector.get_map():
                _deadline(work_deadline)
                for key, _ in selector.select(
                    max(0.0, min(0.05, work_deadline - time.monotonic()))
                ):
                    if key.fileobj is process.stdin:
                        try:
                            count = os.write(
                                process.stdin.fileno(), data[sent : sent + 65536]
                            )
                        except BrokenPipeError:
                            raise ArchiveRefused("archive_process") from None
                        sent += count
                        if sent == len(data):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    elif key.fileobj == status_read:
                        chunk = os.read(status_read, 65536)
                        if not chunk:
                            selector.unregister(status_read)
                            os.close(status_read)
                            status_read = -1
                        else:
                            status_output.extend(chunk)
                            if len(status_output) > 65536:
                                raise ArchiveRefused("archive_status_bound")
                    else:
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(process.stdout)
                            process.stdout.close()
                        else:
                            output.extend(chunk)
                            if len(output) > limit:
                                raise ArchiveRefused("archive_output_bound")
            _deadline(work_deadline)
            try:
                code = process.wait(
                    timeout=max(0.001, work_deadline - time.monotonic())
                )
            except subprocess.TimeoutExpired:
                raise ArchiveRefused("archive_deadline") from None
            if code or sent != len(data):
                raise ArchiveRefused("archive_process")
            successful = True
            return bytes(output), bytes(status_output)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ArchiveRefused("archive_process") from None
    finally:
        cleanup_failed = False
        for descriptor in (status_read, status_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    cleanup_failed = True
        # returncode is set by wait: never signal a numeric PID/PGID after reap.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                cleanup_failed = True
                # Still own the unreaped leader; make a separate bounded kill attempt.
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException:
                    cleanup_failed = True
        for cleanup_stream in (process.stdin, process.stdout):
            if cleanup_stream is not None:
                try:
                    cleanup_stream.close()
                except BaseException:
                    cleanup_failed = True
        if process.returncode is None:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ArchiveRefused("archive_cleanup")
                process.wait(timeout=remaining)
            except BaseException:
                cleanup_failed = True
                # One best-effort reap retry stays inside the same absolute end.
                if process.returncode is None:
                    try:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ArchiveRefused("archive_cleanup")
                        process.wait(timeout=remaining)
                    except BaseException:
                        cleanup_failed = True
        if not successful or cleanup_failed:
            output.clear()
            status_output.clear()
        if cleanup_failed:
            raise ArchiveRefused("archive_cleanup") from None


def _key_listing(raw: bytes, profile: GpgArchiveProfile) -> None:
    try:
        lines = [line.split(":") for line in raw.decode("ascii").splitlines()]
        keys = []
        pending = None
        for fields in lines:
            if fields[0] in {"pub", "sub"}:
                if pending is not None or len(fields) < 12:
                    raise ValueError
                pending = fields
            elif fields[0] == "fpr":
                if pending is None or len(fields) < 10:
                    raise ValueError
                keys.append((pending, fields[9]))
                pending = None
            elif fields[0] in {"sec", "ssb"}:
                raise ValueError
        if pending is not None:
            raise ValueError
        primary = [pair for pair in keys if pair[0][0] == "pub"]
        selected = [pair for pair in keys if pair[1] == profile.encryption_fingerprint]
        if len(primary) != 1 or primary[0][1] != profile.primary_fingerprint:
            raise ValueError
        if len(selected) != 1 or "e" not in selected[0][0][11]:
            raise ValueError
        now = time.time()
        for fields, _ in (primary[0], selected[0]):
            if fields[1] in {"r", "e", "d", "i"} or "D" in fields[11]:
                raise ValueError
            if not 0 < int(fields[5]) <= now:
                raise ValueError
            if fields[6] and int(fields[6]) != 0 and int(fields[6]) <= now:
                raise ValueError
    except (ValueError, UnicodeError, IndexError):
        raise ArchiveRefused("archive_recipient") from None


def _pack(inner_manifest: bytes, proof_files: Mapping[str, bytes]) -> bytes:
    if type(inner_manifest) is not bytes or not 0 < len(inner_manifest) <= 65536:
        raise ArchiveRefused("archive_manifest")
    if set(proof_files) != set(ARCHIVE_NAMES):
        raise ArchiveRefused("archive_members")
    files = {"manifest.json": inner_manifest, **proof_files}
    if any(type(raw) is not bytes or not raw for raw in files.values()):
        raise ArchiveRefused("archive_members")
    if sum(map(len, files.values())) > MAX_PRIVATE_BYTES - 65536:
        raise ArchiveRefused("archive_input_bound")
    # Canonical inner manifest syntax is checked without reserializing its bytes.
    try:
        document = json.loads(inner_manifest)
        canonical = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if canonical != inner_manifest or type(document) is not dict:
            raise ValueError
        expected = {
            "schema": "Gate0EArchiveManifest.v1",
            "files": {
                name: {
                    "length": len(proof_files[name]),
                    "sha256": _sha(proof_files[name]),
                }
                for name in ARCHIVE_NAMES
            },
        }
        if canonical != json.dumps(
            expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii"):
            raise ValueError
    except (ValueError, UnicodeError, RecursionError):
        raise ArchiveRefused("archive_manifest") from None
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(files):
            raw = files[name]
            member = _tar_member(name, len(raw))
            archive.addfile(member, io.BytesIO(raw))
    packed = output.getvalue()
    if len(packed) > MAX_PRIVATE_BYTES:
        raise ArchiveRefused("archive_input_bound")
    return packed


def _ciphertext_packets(raw: bytes, fingerprint: str) -> None:
    """Only one pinned v3 PKESK followed by integrity-protected encrypted data."""
    offset = 0
    packets = []
    while offset < len(raw):
        header = raw[offset]
        offset += 1
        if not header & 128:
            raise ArchiveRefused("archive_ciphertext")
        tag = header & 63 if header & 64 else (header >> 2) & 15
        body_start = None
        body_size = 0
        while True:
            if header & 64:
                if offset >= len(raw):
                    raise ArchiveRefused("archive_ciphertext")
                first = raw[offset]
                offset += 1
                partial = 224 <= first < 255
                if first < 192:
                    length = first
                elif first < 224:
                    if offset >= len(raw):
                        raise ArchiveRefused("archive_ciphertext")
                    length = (first - 192) * 256 + raw[offset] + 192
                    offset += 1
                elif first == 255:
                    if offset + 4 > len(raw):
                        raise ArchiveRefused("archive_ciphertext")
                    length = int.from_bytes(raw[offset : offset + 4], "big")
                    offset += 4
                else:
                    length = 1 << (first & 31)
            else:
                size = (1, 2, 4, 0)[header & 3]
                if not size or offset + size > len(raw):
                    raise ArchiveRefused("archive_ciphertext")
                length = int.from_bytes(raw[offset : offset + size], "big")
                offset += size
                partial = False
            if offset + length > len(raw) or (partial and tag != 18):
                raise ArchiveRefused("archive_ciphertext")
            if body_start is None:
                body_start = offset
            body_size += length
            offset += length
            if not partial:
                break
        packets.append(tag)
        if tag == 1:
            if body_size < 10 or raw[body_start] != 3:
                raise ArchiveRefused("archive_ciphertext")
            if raw[body_start + 1 : body_start + 9].hex().upper() != fingerprint[-16:]:
                raise ArchiveRefused("archive_ciphertext")
        elif tag != 18 or body_size < 40 or raw[body_start] != 1:
            raise ArchiveRefused("archive_ciphertext")
    if packets != [1, 18]:
        raise ArchiveRefused("archive_ciphertext")


def package_private_collection(
    inner_manifest: bytes,
    proof_files: Mapping[str, bytes],
    profile: GpgArchiveProfile,
    *,
    deadline: float,
) -> EncryptedArchive:
    """Encrypt once under one original monotonic deadline; return bytes, no readiness.

    The caller must obtain complete bytes/canonical manifest from the actual
    finalization owner. This module cannot authenticate their origin or coverage.
    """
    try:
        _deadline(deadline)
        if not re.fullmatch(r"gpg \(GnuPG\) 2\.[0-9]+\.[0-9]+", profile.version_line):
            raise ArchiveRefused("archive_profile")
        _protected_binary(
            GnuPgToolPins(
                profile.executable, profile.executable_sha256, profile.version_line
            )
        )
        _public_packets(profile.public_key)
        if (
            _sha(profile.public_key) != profile.public_key_sha256
            or not _DIGEST.fullmatch(profile.public_key_sha256)
            or not _FINGERPRINT.fullmatch(profile.primary_fingerprint)
            or not _FINGERPRINT.fullmatch(profile.encryption_fingerprint)
        ):
            raise ArchiveRefused("archive_recipient")
        packed = _pack(inner_manifest, proof_files)
        with tempfile.TemporaryDirectory(prefix="gate0-e-") as directory:
            os.chmod(directory, 0o700)
            env = {
                "GNUPGHOME": directory,
                "HOME": directory,
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            }
            base = [
                str(profile.executable),
                "--no-options",
                "--homedir",
                directory,
                "--batch",
                "--no-tty",
                "--no-autostart",
                "--no-default-keyring",
                "--keyring",
                str(Path(directory) / "public.gpg"),
                "--no-encrypt-to",
                "--no-auto-key-locate",
                "--no-auto-key-retrieve",
                "--no-auto-key-import",
                "--no-auto-check-trustdb",
            ]
            version = _run(base + ["--version"], b"", env, deadline, 16384)
            if version.splitlines()[0].decode("ascii") != profile.version_line:
                raise ArchiveRefused("archive_installation")
            _run(base + ["--import"], profile.public_key, env, deadline, 16384)
            listing = _run(
                base
                + [
                    "--with-colons",
                    "--with-fingerprint",
                    "--with-subkey-fingerprint",
                    "--list-keys",
                ],
                b"",
                env,
                deadline,
                MAX_KEY_BYTES,
            )
            _key_listing(listing, profile)
            secrets = _run(
                base + ["--with-colons", "--list-secret-keys"],
                b"",
                env,
                deadline,
                16384,
            )
            if any(
                line.startswith((b"sec:", b"ssb:")) for line in secrets.splitlines()
            ):
                raise ArchiveRefused("archive_recipient")
            ciphertext = _run(
                base
                + [
                    "--trust-model",
                    "always",
                    "--set-filename",
                    "",
                    "--cipher-algo",
                    "AES256",
                    "--compress-algo",
                    "none",
                    "--recipient",
                    profile.encryption_fingerprint + "!",
                    "--output",
                    "-",
                    "--encrypt",
                ],
                packed,
                env,
                deadline,
                MAX_CIPHERTEXT_BYTES,
            )
            _ciphertext_packets(ciphertext, profile.encryption_fingerprint)
            result = EncryptedArchive(
                ciphertext, _sha(ciphertext), _sha(packed), _sha(inner_manifest)
            )
        _deadline(deadline)
        return result
    except ArchiveRefused:
        raise
    except (OSError, ValueError, TypeError, IndexError, UnicodeError):
        raise ArchiveRefused("archive_unavailable") from None


@dataclass(frozen=True, slots=True, repr=False)
class GpgHolderProfile:
    """Inert installed custody pins; no key material is copied or imported."""

    public: GpgArchiveProfile
    homedir: Path
    runtime_home: Path
    gpgconf: GnuPgToolPins
    agent_socket: Path
    keyring: Path


@dataclass(frozen=True, slots=True, repr=False)
class DecryptedArchive:
    plaintext: bytes
    plaintext_sha256: str
    status_sha256: str


@dataclass(frozen=True, slots=True)
class _PrivateFailure:
    category: str
    exit_code: int = 1


def _private_failure(error: BaseException) -> _PrivateFailure:
    category = (
        "interrupt"
        if isinstance(error, KeyboardInterrupt)
        else "exit"
        if isinstance(error, SystemExit)
        else "refused"
    )
    exit_code = (
        error.code
        if isinstance(error, SystemExit)
        and type(error.code) is int
        and 0 <= error.code <= 255
        else 1
    )
    _discard_private_failure(error)
    return _PrivateFailure(category, exit_code)


def _raise_private_failure(failure: _PrivateFailure, code: str) -> NoReturn:
    if failure.category == "interrupt":
        raise KeyboardInterrupt
    if failure.category == "exit":
        raise SystemExit(failure.exit_code)
    raise ArchiveRefused(code)


def _discard_private_failure(error: BaseException) -> None:
    """Discard nested failure frames and chains; never preserve the exception."""
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for nested in (current.__cause__, current.__context__):
            if nested is not None:
                pending.append(nested)
        traceback.clear_frames(current.__traceback__)
        current.__traceback__ = None
        current.__cause__ = None
        current.__context__ = None


def _decrypt_status_checked(
    raw: bytes, profile: GpgArchiveProfile, plaintext_size: int
) -> bool | _PrivateFailure:
    """Closed GPG2 status grammar for the existing AES256/MDC archive format."""
    try:
        if (
            not raw
            or len(raw) > 65536
            or not raw.endswith(b"\n")
            or any(value != 10 and not 32 <= value <= 126 for value in raw)
        ):
            raise ValueError
        records: dict[str, list[list[str]]] = {}
        order = []
        allowed = {
            "ENC_TO",
            "KEY_CONSIDERED",
            "DECRYPTION_KEY",
            "BEGIN_DECRYPTION",
            "DECRYPTION_INFO",
            "PLAINTEXT",
            "PLAINTEXT_LENGTH",
            "DECRYPTION_OKAY",
            "GOODMDC",
            "END_DECRYPTION",
        }
        for line in raw.decode("ascii").splitlines():
            if not line.startswith("[GNUPG:] ") or len(line) > 2048:
                raise ValueError
            fields = line[9:].split(" ")
            code, args = fields[0], fields[1:]
            if code not in allowed:
                raise ValueError
            records.setdefault(code, []).append(args)
            order.append(code)
        for code in allowed - {"KEY_CONSIDERED", "PLAINTEXT_LENGTH"}:
            if len(records.get(code, [])) != 1:
                raise ValueError
        for code in (
            "BEGIN_DECRYPTION",
            "DECRYPTION_OKAY",
            "GOODMDC",
            "END_DECRYPTION",
        ):
            if records[code] != [[]]:
                raise ValueError
        key = records["DECRYPTION_KEY"][0]
        if len(key) != 3 or key[:2] != [
            profile.encryption_fingerprint,
            profile.primary_fingerprint,
        ]:
            raise ValueError
        if key[2] not in {"-", "q", "n", "m", "f", "u", "w", "s"}:
            raise ValueError
        recipient = records["ENC_TO"][0]
        if len(recipient) != 3 or recipient[0] != profile.encryption_fingerprint[-16:]:
            raise ValueError
        if any(not value.isdigit() for value in recipient[1:]):
            raise ValueError
        for args in records.get("KEY_CONSIDERED", []):
            if len(args) != 2 or args != [profile.primary_fingerprint, "0"]:
                raise ValueError
        if len(records.get("KEY_CONSIDERED", [])) > 8:
            raise ValueError
        if records["DECRYPTION_INFO"][0] not in (["2", "9"], ["2", "9", "0"]):
            raise ValueError
        literal = records["PLAINTEXT"][0]
        if len(literal) not in (2, 3) or literal[0] != "62" or not literal[1].isdigit():
            raise ValueError
        if len(literal) == 3 and literal[2] != "":
            raise ValueError
        lengths = records.get("PLAINTEXT_LENGTH", [])
        if len(lengths) > 1 or (lengths and lengths != [[str(plaintext_size)]]):
            raise ValueError
        indices = [
            order.index(code)
            for code in (
                "BEGIN_DECRYPTION",
                "DECRYPTION_INFO",
                "PLAINTEXT",
                "DECRYPTION_OKAY",
                "GOODMDC",
                "END_DECRYPTION",
            )
        ]
        if indices != sorted(indices) or order[-1] != "END_DECRYPTION":
            raise ValueError
        return True
    except BaseException as error:
        return _private_failure(error)
    finally:
        raw = b""
        records = {}
        fields = args = key = recipient = literal = []
        line = ""


def _decrypt_status(
    raw: bytes, profile: GpgArchiveProfile, plaintext_size: int
) -> None:
    valid = _decrypt_status_checked(raw, profile, plaintext_size)
    del raw, profile
    if type(valid) is _PrivateFailure:
        _raise_private_failure(valid, "archive_decrypt_status")


def _decrypt_private_collection_checked(
    ciphertext: bytes,
    profile: GpgHolderProfile,
    *,
    deadline: float,
) -> DecryptedArchive | _PrivateFailure:
    """Use only the existing holder context; plaintext never touches a temp file.

    Current custody/key validity/agent identity is independently qualified by the
    installed B owner. Human unlock happens there before this fixed operation.
    No key import/export, key discovery, passphrase transport or agent autostart.
    """
    try:
        _deadline(deadline)
        if (
            type(profile) is not GpgHolderProfile
            or type(profile.public) is not GpgArchiveProfile
        ):
            raise ArchiveRefused("archive_profile")
        public = profile.public
        if not re.fullmatch(r"gpg \(GnuPG\) 2\.[0-9]+\.[0-9]+", public.version_line):
            raise ArchiveRefused("archive_profile")
        _protected_binary(profile.gpgconf)
        if not re.fullmatch(
            r"gpgconf \(GnuPG\) 2\.[0-9]+\.[0-9]+", profile.gpgconf.version_line
        ):
            raise ArchiveRefused("archive_profile")
        _protected_binary(
            GnuPgToolPins(
                public.executable, public.executable_sha256, public.version_line
            )
        )
        if not all(
            isinstance(path, Path) and path.is_absolute()
            for path in (
                profile.homedir,
                profile.runtime_home,
                profile.agent_socket,
                profile.keyring,
            )
        ):
            raise ArchiveRefused("archive_profile")
        _public_packets(public.public_key)
        if _sha(public.public_key) != public.public_key_sha256:
            raise ArchiveRefused("archive_recipient")
        if not _FINGERPRINT.fullmatch(
            public.primary_fingerprint
        ) or not _FINGERPRINT.fullmatch(public.encryption_fingerprint):
            raise ArchiveRefused("archive_recipient")
        if (
            type(ciphertext) is not bytes
            or not 0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES
        ):
            raise ArchiveRefused("archive_input_bound")
        _ciphertext_packets(ciphertext, public.encryption_fingerprint)
        env = {
            "GNUPGHOME": str(profile.homedir),
            "HOME": str(profile.runtime_home),
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        conf_base = [str(profile.gpgconf.executable), "--homedir", str(profile.homedir)]
        conf_version = _run(conf_base + ["--version"], b"", env, deadline, 16384)
        if (
            not conf_version.splitlines()
            or conf_version.splitlines()[0].decode("ascii")
            != profile.gpgconf.version_line
        ):
            raise ArchiveRefused("archive_installation")
        observed_socket = _run(
            conf_base + ["--list-dirs", "agent-socket"], b"", env, deadline, 4096
        )
        if observed_socket != os.fsencode(profile.agent_socket) + b"\n":
            raise ArchiveRefused("archive_agent_binding")
        base = [
            str(public.executable),
            "--no-options",
            "--homedir",
            str(profile.homedir),
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-default-keyring",
            "--keyring",
            str(profile.keyring),
            "--pinentry-mode",
            "error",
            "--no-auto-key-locate",
            "--no-auto-key-retrieve",
            "--no-auto-key-import",
            "--no-auto-check-trustdb",
        ]
        version = _run(base + ["--version"], b"", env, deadline, 16384)
        if (
            not version.splitlines()
            or version.splitlines()[0].decode("ascii") != public.version_line
        ):
            raise ArchiveRefused("archive_installation")
        listing = _run(
            base
            + [
                "--with-colons",
                "--with-fingerprint",
                "--with-subkey-fingerprint",
                "--list-keys",
                public.primary_fingerprint,
            ],
            b"",
            env,
            deadline,
            MAX_KEY_BYTES,
        )
        _key_listing(listing, public)
        plaintext, status = _run_channels(
            base + ["--output", "-", "--decrypt"],
            ciphertext,
            env,
            deadline,
            MAX_PRIVATE_BYTES,
            status_channel=True,
        )
        _decrypt_status(status, public, len(plaintext))
        _deadline(deadline)
        return DecryptedArchive(plaintext, _sha(plaintext), _sha(status))
    except BaseException as error:
        return _private_failure(error)
    finally:
        plaintext = status = listing = version = conf_version = observed_socket = b""


def decrypt_private_collection(
    ciphertext: bytes,
    profile: GpgHolderProfile,
    *,
    deadline: float,
) -> DecryptedArchive:
    """Clean public refusal boundary; private helpers never return exceptions."""
    result = _decrypt_private_collection_checked(ciphertext, profile, deadline=deadline)
    del ciphertext, profile
    if isinstance(result, _PrivateFailure):
        _raise_private_failure(result, "archive_decrypt_unavailable")
    return result
