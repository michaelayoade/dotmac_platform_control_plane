"""Fixed output-only handoff under the already qualified original root owner.

Filesystem provenance is the trust boundary. No argument grants root authority;
private helpers are called only by the qualified supervisor, never a job CLI.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, cast

from vendor_cp.deployment.gate0_e_archive import MAX_CIPHERTEXT_BYTES
from vendor_cp.deployment.gate0_e_preparation import validate_encrypted_e_projection
from vendor_cp.deployment.gate0_e_writer import _private_failure, _raise_private_failure
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_runner_lifecycle_courier import (
    _installed_public_selection,
)

_TRANSFER = Path("/run/dotmac-gate0-e-transfer")
_STATE = Path("/run/dotmac-gate0-e-transfer-state")
_STAGING = Path("/run/dotmac-gate0-e/staging")
_NAMES = ("gate0-evidence.pgp", "gate0-evidence-public.json")
_LIMITS = (MAX_CIPHERTEXT_BYTES, 65536)


class ETransferRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_e_transfer_refused")


def _require(condition: bool) -> None:
    if not condition:
        raise ETransferRefused()


def _before(deadline: float) -> None:
    _require(type(deadline) in (int, float) and math.isfinite(deadline))
    _require(0 < time.monotonic() < deadline)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value: object) -> None:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory(path: Path, *, mode: int | None = None, gid: int | None = None) -> int:
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            parent = fd
            fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            os.close(parent)
            info = os.fstat(fd)
            _require(info.st_uid == 0 and not info.st_mode & 0o022)
        info = os.fstat(fd)
        _require(mode is None or stat.S_IMODE(info.st_mode) == mode)
        _require(gid is None or info.st_gid == gid)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(
    parent: int, name: str, maximum: int, *, mode: int, gid: int, deadline: float
) -> tuple[bytes, tuple[int, ...]]:
    _before(deadline)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        _require(info.st_uid == 0 and info.st_gid == gid)
        _require(stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= maximum)
        raw = bytearray()
        while len(raw) <= info.st_size:
            _before(deadline)
            chunk = os.read(fd, min(65536, info.st_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        _require(len(raw) == info.st_size)
        identity = _identity(info)
        _require(identity == _identity(os.fstat(fd)))
        _require(
            identity == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        )
        _before(deadline)
        return bytes(raw), identity
    finally:
        os.close(fd)


def _create(
    parent: int, name: str, raw: bytes, *, mode: int, gid: int, deadline: float
) -> None:
    _before(deadline)
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
    )
    try:
        os.fchown(fd, 0, gid)
        view = memoryview(raw)
        while view:
            _before(deadline)
            count = os.write(fd, view)
            _require(count > 0)
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        _before(deadline)
    finally:
        os.close(fd)


def _new_directory(path: Path, gid: int) -> int:
    parent = _directory(path.parent)
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        fd = os.open(
            path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        try:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, 0o700)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def _source_digest(deadline: float) -> str:
    parent = _directory(Path(__file__).parent)
    try:
        # Installed source may be 0644 or 0600, never group/other writable.
        info = os.stat(Path(__file__).name, dir_fd=parent, follow_symlinks=False)
        _require(not info.st_mode & 0o022)
        raw, _ = _read(
            parent,
            Path(__file__).name,
            1024 * 1024,
            mode=stat.S_IMODE(info.st_mode),
            gid=info.st_gid,
            deadline=deadline,
        )
        return _sha(raw)
    finally:
        os.close(parent)


def _boot() -> str:
    fd = os.open("/proc/sys/kernel/random/boot_id", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 65)
        _require(len(raw) <= 64)
        return raw.decode("ascii").strip()
    finally:
        os.close(fd)


def _ticket(
    *,
    deadline: float,
    boot_id: str,
    campaign_digest: object,
    lifecycle_binding_digest: str,
    courier_uid: int,
    courier_gid: int,
    profile_digest: object,
    source_bundle_digest: object,
) -> dict[str, Any]:
    _before(deadline)
    _require(boot_id == _boot() and re.fullmatch(r"[0-9a-f-]{36}", boot_id) is not None)
    for value in (
        campaign_digest,
        lifecycle_binding_digest,
        profile_digest,
        source_bundle_digest,
    ):
        _digest(value)
    _require(type(courier_uid) is int and courier_uid > 0)
    _require(type(courier_gid) is int and courier_gid > 0)
    return dict(
        schema="Gate0EOriginalTransferTicket.v1",
        deadline=deadline,
        boot_id=boot_id,
        campaign_digest=campaign_digest,
        lifecycle_binding_digest=lifecycle_binding_digest,
        courier_uid=courier_uid,
        courier_gid=courier_gid,
        profile_digest=profile_digest,
        source_bundle_digest=source_bundle_digest,
        transfer_source_digest=_source_digest(deadline),
        names=list(_NAMES),
    )


def _initialize_work(**selection: Any) -> None:
    _require(os.getuid() == os.geteuid() == 0)
    ticket = _ticket(**selection)
    fd = _new_directory(_STATE, ticket["courier_gid"])
    try:
        _create(
            fd,
            "ticket.json",
            canonical(ticket),
            mode=0o640,
            gid=ticket["courier_gid"],
            deadline=ticket["deadline"],
        )
        os.fsync(fd)
        _before(ticket["deadline"])
        os.fchmod(fd, 0o750)
    finally:
        os.close(fd)


def _validate_pair(raw: dict[str, bytes], ticket: dict[str, Any]) -> None:
    projection = validate_encrypted_e_projection(raw[_NAMES[1]])
    _require(projection["ciphertext_digest"] == _sha(raw[_NAMES[0]]))
    _require(projection["ciphertext_bytes"] == len(raw[_NAMES[0]]))
    for name in ("campaign_digest", "source_bundle_digest"):
        _require(projection[name] == ticket[name])


def _publish_work(**selection: Any) -> None:
    _require(os.getuid() == os.geteuid() == 0)
    ticket = _ticket(**selection)
    deadline, gid = ticket["deadline"], ticket["courier_gid"]
    state = _directory(_STATE, mode=0o750, gid=gid)
    try:
        ticket_raw, _ = _read(
            state, "ticket.json", 65536, mode=0o640, gid=gid, deadline=deadline
        )
        _require(ticket_raw == canonical(ticket))
        _require(set(os.listdir(state)) == {"ticket.json"})
        staging = _directory(_STAGING, mode=0o700)
        try:
            _require(set(os.listdir(staging)) == set(_NAMES))
            raw = {
                name: _read(staging, name, limit, mode=0o600, gid=0, deadline=deadline)[
                    0
                ]
                for name, limit in zip(_NAMES, _LIMITS, strict=True)
            }
        finally:
            os.close(staging)
        _validate_pair(raw, ticket)
        transfer = _new_directory(_TRANSFER, gid)
        try:
            for name in _NAMES:
                _create(
                    transfer, name, raw[name], mode=0o640, gid=gid, deadline=deadline
                )
            files = {}
            for name, limit in zip(_NAMES, _LIMITS, strict=True):
                retained, identity = _read(
                    transfer, name, limit, mode=0o640, gid=gid, deadline=deadline
                )
                _require(retained == raw[name])
                files[name] = dict(
                    digest=_sha(retained), size=len(retained), identity=list(identity)
                )
            ready = canonical(
                dict(
                    schema="Gate0ETransferReady.v1",
                    ticket_digest=_sha(ticket_raw),
                    files=files,
                    published_monotonic=time.monotonic(),
                )
            )
            _create(state, "manifest.json", ready, mode=0o600, gid=0, deadline=deadline)
            _create(state, "ready.json", ready, mode=0o640, gid=gid, deadline=deadline)
            os.fsync(state)
            os.fsync(transfer)
            _require(set(os.listdir(transfer)) == set(_NAMES))
            _before(deadline)
            os.fchmod(transfer, 0o750)
            _before(deadline)
        finally:
            os.close(transfer)
    finally:
        os.close(state)


def _checked(operation: Any, selection: dict[str, Any]) -> Any:
    try:
        return operation(**selection)
    except BaseException as error:
        return _private_failure(error)
    finally:
        del operation, selection


def _initialize_original_transfer(
    *,
    deadline: float,
    boot_id: str,
    campaign_digest: str,
    lifecycle_binding_digest: str,
    courier_uid: int,
    courier_gid: int,
    profile_digest: str,
    source_bundle_digest: str,
) -> None:
    outcome = _checked(_initialize_work, dict(locals()))
    del (
        deadline,
        boot_id,
        campaign_digest,
        lifecycle_binding_digest,
        courier_uid,
        courier_gid,
    )
    del profile_digest, source_bundle_digest
    if outcome is not None:
        _raise_private_failure(outcome)


def _publish_original_encrypted_pair(
    *,
    deadline: float,
    boot_id: str,
    campaign_digest: str,
    lifecycle_binding_digest: str,
    courier_uid: int,
    courier_gid: int,
    profile_digest: str,
    source_bundle_digest: str,
) -> None:
    outcome = _checked(_publish_work, dict(locals()))
    del (
        deadline,
        boot_id,
        campaign_digest,
        lifecycle_binding_digest,
        courier_uid,
        courier_gid,
    )
    del profile_digest, source_bundle_digest
    if outcome is not None:
        _raise_private_failure(outcome)


def _await_work() -> None:
    public, _, bounds = _installed_public_selection()
    deadline = bounds.finalization_end
    _before(deadline)
    gid = public["courier_gid"]
    state = _directory(_STATE, mode=0o750, gid=gid)
    state_identity = (os.fstat(state).st_dev, os.fstat(state).st_ino)
    try:
        ticket_raw, ticket_identity = _read(
            state, "ticket.json", 65536, mode=0o640, gid=gid, deadline=deadline
        )
        ticket = strict_object(ticket_raw, 65536)
        expected = _ticket(
            deadline=deadline,
            boot_id=bounds.boot_id,
            campaign_digest=ticket.get("campaign_digest"),
            lifecycle_binding_digest=public["lifecycle_binding_digest"],
            courier_uid=public["courier_uid"],
            courier_gid=gid,
            profile_digest=ticket.get("profile_digest"),
            source_bundle_digest=ticket.get("source_bundle_digest"),
        )
        _require(ticket_raw == canonical(expected))
        while True:
            _before(deadline)
            try:
                parent = _directory(_TRANSFER.parent)
                try:
                    info = os.stat(_TRANSFER.name, dir_fd=parent, follow_symlinks=False)
                    _require(
                        stat.S_ISDIR(info.st_mode)
                        and info.st_uid == 0
                        and info.st_gid == gid
                    )
                    mode = stat.S_IMODE(info.st_mode)
                    _require(mode in (0o700, 0o750))
                finally:
                    os.close(parent)
                if mode == 0o750:
                    break
            except FileNotFoundError:
                pass
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        ready_raw, ready_identity = _read(
            state, "ready.json", 65536, mode=0o640, gid=gid, deadline=deadline
        )
        ready = strict_object(ready_raw, 65536)
        _require(
            set(ready) == {"schema", "ticket_digest", "files", "published_monotonic"}
        )
        _require(
            ready["schema"] == "Gate0ETransferReady.v1"
            and canonical(ready) == ready_raw
        )
        _require(ready["ticket_digest"] == _sha(ticket_raw))
        published = ready["published_monotonic"]
        if type(published) is not float and type(published) is not int:
            raise ETransferRefused()
        _require(math.isfinite(published))
        _require(0 < published <= time.monotonic() < deadline)
        _require(type(ready["files"]) is dict and set(ready["files"]) == set(_NAMES))
        files = cast(dict[str, object], ready["files"])
        transfer = _directory(_TRANSFER, mode=0o750, gid=gid)
        try:
            directory_identity = (os.fstat(transfer).st_dev, os.fstat(transfer).st_ino)
            _require(directory_identity == (info.st_dev, info.st_ino))
            _require(set(os.listdir(transfer)) == set(_NAMES))
            raw = {}
            for name, limit in zip(_NAMES, _LIMITS, strict=True):
                retained, identity = _read(
                    transfer, name, limit, mode=0o640, gid=gid, deadline=deadline
                )
                _require(
                    files[name]
                    == dict(
                        digest=_sha(retained),
                        size=len(retained),
                        identity=list(identity),
                    )
                )
                raw[name] = retained
            verified_files = cast(dict[str, dict[str, object]], files)
            _validate_pair(raw, ticket)
            _require(set(os.listdir(transfer)) == set(_NAMES))
            for name in _NAMES:
                _require(
                    list(
                        _identity(os.stat(name, dir_fd=transfer, follow_symlinks=False))
                    )
                    == verified_files[name]["identity"]
                )
            current = os.stat(_TRANSFER, follow_symlinks=False)
            _require(directory_identity == (current.st_dev, current.st_ino))
            _require(
                current.st_uid == 0
                and current.st_gid == gid
                and stat.S_IMODE(current.st_mode) == 0o750
            )
        finally:
            os.close(transfer)
        _require(
            _read(state, "ticket.json", 65536, mode=0o640, gid=gid, deadline=deadline)
            == (ticket_raw, ticket_identity)
        )
        _require(
            _read(state, "ready.json", 65536, mode=0o640, gid=gid, deadline=deadline)
            == (ready_raw, ready_identity)
        )
        current_state = os.stat(_STATE, follow_symlinks=False)
        _require(state_identity == (current_state.st_dev, current_state.st_ino))
        _require(
            current_state.st_uid == 0
            and current_state.st_gid == gid
            and stat.S_IMODE(current_state.st_mode) == 0o750
        )
        _before(deadline)
    finally:
        os.close(state)


def run_installed_await_e_transfer() -> int:
    """No parameters, credentials, root delegation or new deadline allocation."""
    outcome = _checked(_await_work, {})
    if outcome is None:
        print("E_TRANSFER_READY")
        return 0
    if outcome.category != "refused":
        _raise_private_failure(outcome)
    return 3
