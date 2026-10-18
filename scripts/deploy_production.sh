#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_HOST_ID="vendor-cp-prod"
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.production.yml}"
readonly ENV_FILE="${ENV_FILE:-.env}"
readonly HOST_ID_FILE="${HOST_ID_FILE:-/etc/dotmac-host-id}"
readonly BACKUP_DIR="${BACKUP_DIR:-/opt/backups/dotmac-vendor-control-plane}"
readonly DESCRIPTOR_FILE="${DESCRIPTOR_FILE:-deploy/product.toml}"

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 || $# -eq 3 ]] || die "usage: scripts/deploy_production.sh sha256:<digest> <authorization-ref> [--gate0-collection-activate|--gate0-collection-retire]"
readonly DIGEST="$1"
readonly AUTHORIZATION_REF="$2"
readonly GATE0_COLLECTION_OPERATION="${3:-}"
case "$GATE0_COLLECTION_OPERATION" in
    ""|--gate0-collection-activate|--gate0-collection-retire) ;;
    *) die "unknown finite collection operation" ;;
esac
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "image digest is not sha256"
# Validated ON ARRIVAL, not trusted from the caller, and the allowlist is the
# injection defence: no quote, no space, no dollar, no backtick can pass, so a
# reference can cross an ssh remote-command boundary without becoming shell.
# The workflow and the wrapper validate the same shape before sending; each
# layer checks for itself because each layer is separately invokable.
[[ "$AUTHORIZATION_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
    || die "authorization reference must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\$"

# A finite request must refuse every path override before even opening a lock.
# This check is also before the cleanup trap: caller-owned paths are not ours.
if [[ -n "$GATE0_COLLECTION_OPERATION" ]]; then
    [[ "$COMPOSE_FILE" == "docker-compose.production.yml" \
        && "$ENV_FILE" == ".env" \
        && "$HOST_ID_FILE" == "/etc/dotmac-host-id" \
        && "${LOCK_FILE:-/var/lock/dotmac_dotmac_vendor_control_plane_deploy.lock}" \
            == "/var/lock/dotmac_dotmac_vendor_control_plane_deploy.lock" ]] \
        || die "finite collection requires the canonical executor paths"
fi

# Only this invocation's later mktemp result belongs to its cleanup trap.
# Never consume an inherited BUNDLE_TMP, including on finite refusal or success.
BUNDLE_TMP=""

# This script's own cleanup. The wrapper that hands it a registry token traps;
# this process is the one holding the compose operation and the bundle
# temporary when an SSH connection drops, and it had no trap of its own.
cleanup_effector() {
    local status=$?
    [[ -n "${BUNDLE_TMP:-}" && -d "${BUNDLE_TMP:-/nonexistent}" ]] \
        && rm -rf -- "$BUNDLE_TMP"
    return "$status"
}
trap cleanup_effector EXIT HUP INT TERM

# ── One deployment at a time, on the SAME inode the Foundation locks ─────────
#
# The lock file name is the Foundation's own convention —
# `engine/lock.py: lock_path()` returns `dotmac_{product}_deploy.lock` under
# /var/lock, and the product is `dotmac_vendor_control_plane` from the accepted
# descriptor. Foundation takes it with fcntl.flock(), which is flock(2);
# `flock(1)` here is the same primitive, so the two contend on the same inode
# rather than each holding "the lock" while the other proceeds. A different
# name, or fcntl-style lockf here, would serialise nothing while appearing to.
#
# Weaker than the Python owner in one respect, stated rather than hidden:
# flock(1) follows symlinks and cannot fstat the descriptor it locked, so the
# best a shell caller can do is refuse a symlink or a non-regular file before
# opening. The successor executes through the Foundation and inherits the
# hardened lock; this shell path is frozen below anyway.
readonly LOCK_FILE="${LOCK_FILE:-/var/lock/dotmac_dotmac_vendor_control_plane_deploy.lock}"
[[ -L "$LOCK_FILE" ]] && die "deployment lock $LOCK_FILE is a symlink; refusing"
[[ ! -e "$LOCK_FILE" || -f "$LOCK_FILE" ]] \
    || die "deployment lock $LOCK_FILE is not a regular file; refusing"
exec {LOCK_FD}>>"$LOCK_FILE" || die "cannot open deployment lock $LOCK_FILE"
if [[ -n "$GATE0_COLLECTION_OPERATION" ]]; then
    # Standard-library only: this is not the unresolved installed CP binding.
    # Validate the actual open description before flock or a holder-marker write.
    /usr/bin/python3 -I - "$LOCK_FD" <<'FINITE_LOCK' \
        || die "finite collection lock metadata refused"
import os
import stat
import sys

fd = int(sys.argv[1])
metadata = os.fstat(fd)
named = os.stat(
    "/var/lock/dotmac_dotmac_vendor_control_plane_deploy.lock",
    follow_symlinks=False,
)
if (
    metadata.st_uid != 0
    or not stat.S_ISREG(metadata.st_mode)
    or metadata.st_nlink != 1
    or stat.S_IMODE(metadata.st_mode) & 0o022
    or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
):
    sys.exit(1)
FINITE_LOCK
fi
flock --nonblock "$LOCK_FD" || die "another deployment holds $LOCK_FILE \
($(head -c 200 "$LOCK_FILE" 2>/dev/null || echo 'holder unreadable')). Two \
concurrent runs each start a backup and each migrate; that is the load-52 \
incident this lock exists to prevent."
if [[ -n "$GATE0_COLLECTION_OPERATION" ]]; then
    # Never reopen/truncate a pathname after checking a different description.
    printf '%s %s\n' "$$" "finite-collection ${DIGEST}" >&"$LOCK_FD"
else
    printf '%s %s\n' "$$" "legacy-freeze ${DIGEST}" >"$LOCK_FILE"
fi

# ── Where the successor's ADMIT check lands ─────────────────────────────────
#
# The authorization reference is validated and carried, and NOT yet consulted:
# resolving approved-plan standing and `authorized_images` arrives with the
# authorized executor (Foundation a5 + Control a10), which replaces this
# script's role wholesale. Nothing here pretends to be that check — a gate
# shaped like the successor but unable to admit is how a path stays wedged, and
# a gate that quietly admits is how a bypass survives a rewrite. Until the
# successor demonstrates a real admit path, this hardened legacy path remains
# production's emergency executor: canonical lock held, identifiers validated,
# no service replacement or schema advancement above this line.

[[ -f "$ENV_FILE" ]] || die "$ENV_FILE is missing"
grep -Fqx 'APP_ENV=production' "$ENV_FILE" || die "APP_ENV marker mismatch"
grep -Fqx 'SERVER_NAME=vendor-cp-prod' "$ENV_FILE" || die "server marker mismatch"
grep -Fqx 'ENVIRONMENT=production' "$ENV_FILE" || die "runtime is not production"
grep -Fqx 'PLATFORM_ROOT_DOMAIN=vendor.dotmac.io' "$ENV_FILE" \
    || die "platform domain mismatch"
# The deployment profile is REQUIRED here rather than defaulted in the image.
# `load_deployment_profile` falls back to `full` OUTSIDE production only, so a
# developer sees the whole assembly; since ADR-0015 an absent profile in a
# production environment fails the boot instead. This grep is therefore no
# longer the only thing standing between the host and the `full` composition —
# it is the cheap check that runs before the image starts, and the loader is
# the one that runs on every restart this script does not perform.
grep -Fqx 'VENDOR_DEPLOYMENT_PROFILE=production-bootstrap' "$ENV_FILE" \
    || die "deployment profile is not production-bootstrap"
# ── Fast environment floor, before candidate containers or database work ─────
#
# Look at the order of this script. `compose up -d --no-deps app --wait` is the
# final service mutation. The existing database is REQUIRED healthy;
# this script never starts or recreates it. The image is pulled, the role and
# ownership contracts are read, a recovery bundle is published and verified, the
# manifest volume is initialised, and THE MIGRATIONS ARE APPLIED before the
# application is ever started. A
# configuration error left to the application's lifespan therefore arrives with
# the schema already advanced and the service down — the most expensive possible
# moment to learn it, and entirely avoidable, because every input it depends on
# is readable here.
#
# `CSRF_SECRET` is the live instance. Kernel a98 `validate_settings` refuses it
# three ways: still the dev default, fewer than 32 bytes, or equal to
# `JWT_SECRET`/`SESSION_HASH_SECRET`. The host that runs this script was
# materialized from a template that never declared it at all.
#
# Nothing below prints a value. Lengths and equality only.
readonly CSRF_REMEDY="Remediation: patch the OpenBao record \
secret/dotmac/vendor-control-plane/production/runtime to add a csrf_secret \
field of at least 32 bytes, distinct from jwt_secret and session_hash_secret, \
then re-run 'materialize_production_secrets.py push'. Note that 'seed' only \
CREATES absent records and will not repair one that already exists."

env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | head -1; }

grep -Fqx 'CSRF_ENABLED=true' "$ENV_FILE" || die "CSRF_ENABLED is not true"
csrf_secret="$(env_value CSRF_SECRET)"
[[ -n "$csrf_secret" ]] \
    || die "CSRF_SECRET is absent or empty in $ENV_FILE. $CSRF_REMEDY"
(( ${#csrf_secret} >= 32 )) \
    || die "CSRF_SECRET is shorter than 32 bytes. $CSRF_REMEDY"
[[ "$csrf_secret" != "$(env_value JWT_SECRET)" \
    && "$csrf_secret" != "$(env_value SESSION_HASH_SECRET)" ]] \
    || die "CSRF_SECRET must differ from JWT_SECRET and SESSION_HASH_SECRET. $CSRF_REMEDY"
unset csrf_secret

[[ -f "$HOST_ID_FILE" ]] || die "$HOST_ID_FILE is missing"
[[ "$(tr -d '\r\n' < "$HOST_ID_FILE")" == "$EXPECTED_HOST_ID" ]] \
    || die "host identity mismatch"

# Explicit same-image collection leaf. The ordinary two-argument deployment
# continues below unchanged. No reference here certifies operational approval.
# The inherited descriptor is the SAME canonical lock's open description.
if [[ -n "$GATE0_COLLECTION_OPERATION" ]]; then
    /usr/bin/python3 -I - "$LOCK_FD" "$DIGEST" "$GATE0_COLLECTION_OPERATION" <<'FINITE_COLLECTION'
from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

_SOURCE = Path("/etc/dotmac-gate0-collection/installation.json")
_STATE = Path("/var/lib/dotmac-gate0-collection")
_RUNTIME = Path("/run/dotmac-gate0-collection")
_LOCK = Path("/var/lock/dotmac_dotmac_vendor_control_plane_deploy.lock")
_REPOSITORY = "ghcr.io/michaelayoade/dotmac_vendor_control_plane"
_PROJECT = "dotmac_vendor_control_plane"
_USER = "10001:10001"
_BOOTSTRAP = "production-bootstrap"
_BASE = "docker-compose.production.yml"
_OVERLAY = "docker-compose.gate0-collection.yml"
_MAXIMUM = 524288


class ProviderRefused(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProviderRefused()
        result[key] = value
    return result


def strict_object(raw, maximum=_MAXIMUM):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
        raise ProviderRefused()
    value = json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ProviderRefused()),
    )
    if type(value) is not dict:
        raise ProviderRefused()
    return value


def _fields(value, names):
    if type(value) is not dict or set(value) != names:
        raise ProviderRefused()
    return value


def _selected(raw):
    value = _fields(
        strict_object(raw),
        {
            "schema",
            "source_revision",
            "image_digest",
            "profile_digest",
            "profile_code",
            "profile_version",
            "database",
            "clock_anchor",
            "cases",
        },
    )
    _require(
        canonical(value) == raw
        and value["schema"] == "Gate0CollectionApiInstallation.v1"
    )
    _require(
        type(value["source_revision"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["source_revision"])
    )
    _require(
        type(value["image_digest"]) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_digest"])
        and value["image_digest"] == sys.argv[2]
    )
    for name in ("profile_code", "profile_version", "profile_digest"):
        _require(type(value[name]) is str and 0 < len(value[name]) <= 128)
    return value


def _call(arguments, *, environment=None, input_bytes=None, maximum=_MAXIMUM):
    """Collect with a byte ceiling, a tool timeout and exact child ownership."""
    process = subprocess.Popen(  # noqa: S603 -- fixed Docker verbs and protected identity data
        ("docker", *arguments),
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        env=environment or {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    output = bytearray()
    deadline = time.monotonic() + 30
    pending = memoryview(input_bytes or b"")
    try:
        os.set_blocking(process.stdout.fileno(), False)
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
        while True:
            remaining = deadline - time.monotonic()
            _require(remaining > 0)
            reads, writes, _ = select.select(
                [process.stdout],
                [process.stdin] if process.stdin is not None else [],
                [],
                min(remaining, 0.1),
            )
            if process.stdin is not None and process.stdin in writes:
                if pending:
                    count = os.write(process.stdin.fileno(), pending[:65536])
                    pending = pending[count:]
                else:
                    process.stdin.close()
                    process.stdin = None
            if process.stdout in reads:
                chunk = os.read(
                    process.stdout.fileno(), min(65536, maximum + 1 - len(output))
                )
                if not chunk:
                    break
                output.extend(chunk)
                _require(len(output) <= maximum)
        _require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0)
        return bytes(output).decode("utf-8").strip()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if process.stdin is not None:
            process.stdin.close()
        process.stdout.close()


def _docker(*arguments, environment=None):
    return _call(arguments, environment=environment)


def _helpers_resolved(state, raw):
    for operation in ("activation", "retirement"):
        owned = operation + "-helper-owned.json"
        complete = operation + "-helper-complete.json"
        names = os.listdir(state)
        if any(name.startswith(operation + "-helper") for name in names):
            _require(owned in names)
        if owned in names:
            record, _ = _read(state, owned)
            ownership = strict_object(record)
            _require(ownership["installation_digest"] == _hash(raw))
            _require(complete in os.listdir(state))
            finished, _ = _read(state, complete)
            terminal = strict_object(finished)
            _require(operation + "-helper" not in names)
            _require(terminal["installation_digest"] == _hash(raw))
            _require(
                all(
                    terminal[key] == ownership[key]
                    for key in ("operation", "name", "reference")
                )
            )
            _require(
                type(terminal["container_id"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", terminal["container_id"])
            )


def _original_open(result, document):
    """Re-observe the image-derived ORIGINAL wall/monotonic intersection."""
    clock = _fields(
        result["original_clock"],
        {
            "boot_id",
            "wall_origin",
            "monotonic_origin",
            "a_expires_at",
            "a_monotonic_end",
        },
    )
    anchor = _fields(
        document["clock_anchor"], {"boot_id", "wall_origin", "monotonic_origin"}
    )
    _require(all(clock[key] == anchor[key] for key in anchor))
    for key in ("monotonic_origin", "a_monotonic_end"):
        _require(type(clock[key]) in (int, float) and math.isfinite(clock[key]))
    wall = datetime.fromisoformat(clock["wall_origin"].replace("Z", "+00:00"))
    expiry = datetime.fromisoformat(clock["a_expires_at"].replace("Z", "+00:00"))
    _require(
        wall.utcoffset().total_seconds() == 0
        and expiry.utcoffset().total_seconds() == 0
    )
    _require(
        clock["a_monotonic_end"]
        == clock["monotonic_origin"] + (expiry - wall).total_seconds()
    )
    _require(
        Path("/proc/sys/kernel/random/boot_id").read_text().strip() == clock["boot_id"]
    )
    now, elapsed = datetime.now(UTC), time.monotonic()
    _require(
        wall <= now < expiry
        and 0 <= clock["monotonic_origin"] <= elapsed < clock["a_monotonic_end"]
    )
    _require(
        abs((now - wall).total_seconds() - (elapsed - clock["monotonic_origin"])) <= 2
    )


def _validate_image_input(state, raw, document, reference, *, activation):
    """Persist exact helper ownership before launching; never retry an orphan."""
    _helpers_resolved(state, raw)
    operation = "activation" if activation else "retirement"
    temporary = _STATE / (operation + "-helper")
    with _directory(temporary, create=True) as directory:
        _require(not os.listdir(directory))
        metadata = os.fstat(directory)
    name = "dotmac-gate0-collection-check-" + uuid.uuid4().hex
    cidfile = temporary / "cid"
    _record(
        state,
        operation + "-helper-owned.json",
        raw,
        operation=operation,
        name=name,
        reference=reference,
        directory=str(temporary),
        directory_device=metadata.st_dev,
        directory_inode=metadata.st_ino,
    )
    result = None
    cleanup_complete = False
    try:
        try:
            result = strict_object(
                _call(
                    (
                        "run",
                        "--name",
                        name,
                        "--cidfile",
                        str(cidfile),
                        "--label",
                        "io.dotmac.gate0.collection.input=" + _hash(raw),
                        "--pull",
                        "never",
                        "--user",
                        _USER,
                        "--network",
                        "none",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges",
                        "--memory",
                        "128m",
                        "--pids-limit",
                        "64",
                        "--cpus",
                        "1",
                        "--interactive",
                        "--entrypoint",
                        "/opt/venv/bin/dotmac-platform",
                        reference,
                        "gate0",
                        "collection-check-" + operation,
                    ),
                    input_bytes=raw,
                    maximum=4096,
                ).encode(),
                4096,
            )
        finally:
            # A killed Docker CLI is not evidence that its container retired.
            # The private cidfile and exact labels/image/name identify only this run.
            with _directory(temporary) as directory:
                actual = os.fstat(directory)
                _require(_identity(actual) == _identity(metadata))
                cid_raw, _ = _read(directory, "cid")
                cid = cid_raw.decode("ascii").strip()
                _require(re.fullmatch(r"[0-9a-f]{64}", cid))
                observed = strict_object(
                    _call(
                        (
                            "inspect",
                            "--format",
                            '{"id":{{json .Id}},"name":{{json .Name}},'
                            '"image":{{json .Config.Image}},"input":{{json '
                            "(index .Config.Labels "
                            '"io.dotmac.gate0.collection.input")}}}',
                            cid,
                        ),
                        maximum=4096,
                    ).encode(),
                    4096,
                )
                _require(
                    observed
                    == {
                        "id": cid,
                        "name": "/" + name,
                        "image": reference,
                        "input": _hash(raw),
                    }
                )
                _require(_call(("rm", "--force", cid), maximum=4096) == cid)
                os.unlink("cid", dir_fd=directory)
                os.fsync(directory)
                cleanup_complete = True
            if cleanup_complete:
                os.rmdir(temporary)
                _record(
                    state,
                    operation + "-helper-complete.json",
                    raw,
                    operation=operation,
                    name=name,
                    reference=reference,
                    container_id=cid,
                )
    except BaseException:
        _record(
            state,
            operation + "-helper-incomplete.json",
            raw,
            operation=operation,
            name=name,
        )
        raise
    expected = {
        "schema": "Gate0CollectionInputCheck.v1",
        "operation": operation,
        "input_digest": _hash(raw),
    }
    expected.update(
        {
            key: document[key]
            for key in (
                "source_revision",
                "image_digest",
                "profile_code",
                "profile_version",
                "profile_digest",
            )
        }
    )
    _require(type(result) is dict and set(result) == set(expected) | {"original_clock"})
    _require({key: result[key] for key in expected} == expected and cleanup_complete)
    if activation:
        _original_open(result, document)
    else:
        _require(result["original_clock"] is None)
    return result


def _require(condition: object) -> None:
    if not condition:
        raise ProviderRefused()


def _hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _metadata(fd: int, *, directory: bool = False) -> os.stat_result:
    metadata = os.fstat(fd)
    _require(
        metadata.st_uid == 0
        and not stat.S_IMODE(metadata.st_mode) & 0o022
        and (
            stat.S_ISDIR(metadata.st_mode)
            if directory
            else stat.S_ISREG(metadata.st_mode)
        )
        and (directory or metadata.st_nlink == 1)
    )
    return metadata


@contextmanager
def _directory(path: Path, *, create: bool = False) -> Iterator[int]:
    """Hold and check every root-owned directory, without symlink traversal."""
    _require(path.is_absolute() and ".." not in path.parts)
    descriptors: list[int] = []
    bindings: list[tuple[int, str, int]] = []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(fd)
        _metadata(fd, directory=True)
        for index, name in enumerate(path.parts[1:]):
            if create and index == len(path.parts) - 2:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            descriptors.append(child)
            _metadata(child, directory=True)
            bindings.append((fd, name, child))
            fd = child
        _require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700 if create else True)
        yield fd
        for parent, name, child in bindings:
            _require(
                _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                == _identity(os.fstat(child))
            )
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _read(fd: int, name: str) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        dir_fd=fd,
    )
    try:
        metadata = _metadata(descriptor)
        _require(0 < metadata.st_size <= _MAXIMUM)
        raw = bytearray()
        while len(raw) <= _MAXIMUM:
            part = os.read(descriptor, min(65536, _MAXIMUM + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        _require(0 < len(raw) <= _MAXIMUM)
        _require(
            _identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
            == _identity(metadata)
        )
        return bytes(raw), metadata
    finally:
        os.close(descriptor)


def _exclusive(
    fd: int, name: str, raw: bytes, *, runtime: bool = False
) -> os.stat_result:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=fd,
    )
    try:
        if runtime:
            os.fchown(descriptor, 0, 10001)
            os.fchmod(descriptor, 0o640)
        remaining = memoryview(raw)
        while remaining:
            count = os.write(descriptor, remaining)
            _require(count > 0)
            remaining = remaining[count:]
        os.fsync(descriptor)
        metadata = _metadata(descriptor)
        _require(
            _identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
            == _identity(metadata)
        )
        os.fsync(fd)
        return metadata
    finally:
        os.close(descriptor)


def _record(fd: int, record_filename: str, raw: bytes, **facts: object) -> None:
    _exclusive(
        fd, record_filename, canonical({"installation_digest": _hash(raw), **facts})
    )


@contextmanager
def _executor_lock() -> Iterator[None]:
    """Use the executor's inherited open description of the canonical inode."""
    _require(os.geteuid() == 0)
    value = sys.argv[1]
    _require(re.fullmatch(r"[0-9]{1,8}", value))
    fd = int(value)
    metadata = _metadata(fd)
    with _lock_directory() as parent:
        descriptor = os.open(
            _LOCK.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent,
        )
        try:
            named = _metadata(descriptor)
            _require(_identity(metadata) == _identity(named))
        finally:
            os.close(descriptor)
        # Same inherited open description: this neither unlocks the parent nor
        # opens a competing description. Direct CLI calls without it refuse.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


@contextmanager
def _lock_directory() -> Iterator[int]:
    """Only the standard root/sticky lock layout permits a writable directory."""
    with _directory(Path("/var")) as parent:
        named = os.stat("lock", dir_fd=parent, follow_symlinks=False)
        _require(named.st_uid == 0)
        if stat.S_ISLNK(named.st_mode):
            _require(os.readlink("lock", dir_fd=parent) in ("/run/lock", "../run/lock"))
            path = Path("/run")
        else:
            _require(stat.S_ISDIR(named.st_mode))
            path = Path("/var")
        with _directory(path) as ancestor:
            fd = os.open(
                "lock",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=ancestor,
            )
            try:
                metadata = os.fstat(fd)
                _require(metadata.st_uid == 0 and stat.S_ISDIR(metadata.st_mode))
                _require(
                    not stat.S_IMODE(metadata.st_mode) & 0o022
                    or metadata.st_mode & stat.S_ISVTX
                )
                yield fd
                _require(
                    _identity(os.stat("lock", dir_fd=ancestor, follow_symlinks=False))
                    == _identity(metadata)
                )
            finally:
                os.close(fd)


def _image(document: dict[str, object]) -> tuple[str, str]:
    reference = _REPOSITORY + "@" + str(document["image_digest"])
    image = strict_object(
        _docker(
            "image",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"digests":{{json .RepoDigests}},'
            '"source":{{json (index .Config.Labels '
            '"org.opencontainers.image.revision")}},"user":{{json .Config.User}}}',
            reference,
        ).encode()
    )
    _require(set(image) == {"id", "digests", "source", "user"})
    _require(
        type(image["id"]) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", cast(str, image["id"]))
    )
    _require(
        type(image["digests"]) is list
        and reference in cast(list[object], image["digests"])
    )
    _require(image["source"] == document["source_revision"] and image["user"] == _USER)
    return reference, cast(str, image["id"])


def _app(reference: str, image_id: str) -> dict[str, object]:
    containers = _docker(
        "ps",
        "-aq",
        "--filter",
        f"label=com.docker.compose.project={_PROJECT}",
        "--filter",
        "label=com.docker.compose.service=app",
        "--filter",
        "label=com.docker.compose.container-number=1",
        "--filter",
        "label=com.docker.compose.oneoff=False",
    ).splitlines()
    _require(len(containers) == 1 and re.fullmatch(r"[0-9a-f]{12,64}", containers[0]))
    # Project only the profile, never dump Config.Env or database credentials.
    value = strict_object(
        _docker(
            "inspect",
            "--format",
            '{"id":{{json .Id}},"image":{{json .Image}},'
            '"reference":{{json .Config.Image}},"user":{{json .Config.User}},'
            '"running":{{json .State.Running}},"profiles":[{{range .Config.Env}}'
            '{{if eq (index (split . "=") 0) "VENDOR_DEPLOYMENT_PROFILE"}}'
            '{{json .}},{{end}}{{end}}null],"mounts":{{json .Mounts}}}',
            containers[0],
        ).encode()
    )
    _require(
        value["image"] == image_id
        and value["reference"] == reference
        and value["user"] == _USER
    )
    _require(type(value["mounts"]) is list and type(value["profiles"]) is list)
    return value


def _profile(app: dict[str, object], code: object) -> None:
    _require(app["profiles"] == ["VENDOR_DEPLOYMENT_PROFILE=" + str(code), None])


def _mount(app: dict[str, object], *, present: bool) -> None:
    matching = [
        m
        for m in cast(list[dict[str, object]], app["mounts"])
        if type(m) is dict and str(m.get("Destination", "")).startswith(str(_RUNTIME))
    ]
    if present:
        _require(len(matching) == 1)
        _require(
            matching[0].get("Type") == "bind"
            and matching[0].get("Source") == str(_RUNTIME / "installation.json")
            and matching[0].get("Destination") == str(_RUNTIME / "installation.json")
            and matching[0].get("RW") is False
        )
    else:
        _require(not matching)


def _recreate(reference: str, profile: object, *, activation: bool) -> None:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "VENDOR_APP_IMAGE": reference,
        "VENDOR_DB_BOOTSTRAP_PASSWORD": "gate0-compose-parse-only",
    }
    command = ["compose", "--env-file", ".env", "-f", _BASE]
    if activation:
        environment["VENDOR_GATE0_COLLECTION_PROFILE"] = str(profile)
        command.extend(("-f", _OVERLAY))
    command.extend(
        (
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "--force-recreate",
            "--wait",
            "app",
        )
    )
    _docker(*command, environment=environment)


def _assets() -> None:
    # The caller is the existing executor in its protected deployment directory.
    with _directory(Path.cwd()) as directory:
        for name in (_BASE, _OVERLAY):
            _read(directory, name)
        descriptor = os.open(
            ".env",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory,
        )
        try:
            _metadata(descriptor)
        finally:
            os.close(descriptor)
    with _directory(Path("/etc")) as directory:
        host, _ = _read(directory, "dotmac-host-id")
        _require(host.strip() == b"vendor-cp-prod")


def _runtime_binding(state: int, raw: bytes, *, remove: bool = False) -> None:
    """Missing volatile bytes permit cleanup, never activation or replacement."""
    binding = None
    if "runtime-binding.json" in os.listdir(state):
        binding_raw, _ = _read(state, "runtime-binding.json")
        binding = _fields(
            strict_object(binding_raw),
            {
                "installation_digest",
                "device",
                "inode",
                "directory_device",
                "directory_inode",
            },
        )
        _require(binding["installation_digest"] == _hash(raw))
    try:
        with _directory(_RUNTIME) as runtime:
            if binding is None:
                _require(not os.listdir(runtime))
                return
            _require(
                [os.fstat(runtime).st_dev, os.fstat(runtime).st_ino]
                == [binding["directory_device"], binding["directory_inode"]]
            )
            try:
                current, metadata = _read(runtime, "installation.json")
            except FileNotFoundError:
                return
            _require(
                current == raw
                and [metadata.st_dev, metadata.st_ino]
                == [binding["device"], binding["inode"]]
            )
            if remove:
                os.unlink("installation.json", dir_fd=runtime)
                os.fsync(runtime)
    except FileNotFoundError:
        # An absent directory cannot supply replacement bytes or rearm clocks.
        return


def _activate() -> None:
    with _executor_lock():
        _assets()
        with _directory(_SOURCE.parent) as source:
            raw, _ = _read(source, _SOURCE.name)
        document = _selected(raw)
        reference, image_id = _image(document)
        before = _app(reference, image_id)
        _require(before["running"] is True)
        _profile(before, _BOOTSTRAP)
        _mount(before, present=False)
        with _directory(_STATE, create=True) as state:
            _require(not os.listdir(state))
            # Persist exact selection before creating anything in volatile /run.
            _exclusive(state, "installation.json", raw)
            _record(state, "activation-attempt.json", raw, app_id=before["id"])
            try:
                result = _validate_image_input(
                    state, raw, document, reference, activation=True
                )
                _original_open(result, document)
                with _directory(_RUNTIME, create=True) as runtime:
                    _require(not os.listdir(runtime))
                    metadata = _exclusive(
                        runtime, "installation.json", raw, runtime=True
                    )
                    _record(
                        state,
                        "runtime-binding.json",
                        raw,
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                        directory_device=os.fstat(runtime).st_dev,
                        directory_inode=os.fstat(runtime).st_ino,
                    )
                    # Recheck the original clock immediately before recreation.
                    _original_open(result, document)
                    _recreate(reference, document["profile_code"], activation=True)
                    after = _app(reference, image_id)
                    _require(after["running"] is True and after["id"] != before["id"])
                    _profile(after, document["profile_code"])
                    _mount(after, present=True)
                    current, actual = _read(runtime, "installation.json")
                    _require(
                        current == raw and _identity(actual) == _identity(metadata)
                    )
                    _original_open(result, document)
                    _record(state, "activation-complete.json", raw, app_id=after["id"])
            except BaseException:
                _record(state, "activation-incomplete.json", raw)
                raise


def _retire() -> None:
    with _executor_lock():
        _assets()
        with _directory(_STATE) as state:
            raw, _ = _read(state, "installation.json")
            # Retirement does not consult live case clocks, DB qualification or
            # current source profile acceptance. It restores these SAME bytes'
            # selected image to bootstrap even after the read interval expires.
            document = _selected(raw)
            _require(
                not any(name.startswith("retirement-") for name in os.listdir(state))
            )
            _helpers_resolved(state, raw)
            reference, image_id = _image(document)
            before = _app(reference, image_id)
            _require(
                before["profiles"]
                in (
                    [
                        "VENDOR_DEPLOYMENT_PROFILE=" + str(document["profile_code"]),
                        None,
                    ],
                    ["VENDOR_DEPLOYMENT_PROFILE=" + _BOOTSTRAP, None],
                )
            )
            _runtime_binding(state, raw)
            _record(state, "retirement-attempt.json", raw, app_id=before["id"])
            try:
                _validate_image_input(state, raw, document, reference, activation=False)
                _recreate(reference, _BOOTSTRAP, activation=False)
                after = _app(reference, image_id)
                _require(after["running"] is True and after["id"] != before["id"])
                _profile(after, _BOOTSTRAP)
                _mount(after, present=False)
                _runtime_binding(state, raw, remove=True)
                _record(state, "retirement-complete.json", raw, app_id=after["id"])
            except BaseException:
                _record(state, "retirement-incomplete.json", raw)
                raise


try:
    if sys.argv[3] == "--gate0-collection-activate":
        _activate()
    elif sys.argv[3] == "--gate0-collection-retire":
        _retire()
    else:
        raise ProviderRefused()
except BaseException:
    print("GATE0_COLLECTION_INCOMPLETE", file=sys.stderr)
    sys.exit(3)
FINITE_COLLECTION
    exit "$?"
fi

# The official image requires a bootstrap password even though that role is
# not the application migrator. Generate it per deploy, pass it only to the DB
# service, and let first-cluster initialization remove the stored verifier.
readonly VENDOR_DB_BOOTSTRAP_PASSWORD="$(
    python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
)"
[[ "$VENDOR_DB_BOOTSTRAP_PASSWORD" =~ ^[A-Za-z0-9_-]{64}$ ]] \
    || die "could not generate the database bootstrap credential"
export VENDOR_DB_BOOTSTRAP_PASSWORD

readonly VENDOR_APP_IMAGE="ghcr.io/michaelayoade/dotmac_vendor_control_plane@${DIGEST}"
export VENDOR_APP_IMAGE

compose() {
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

docker pull "$VENDOR_APP_IMAGE"

# Ask the installed product owner through each actual runtime service. Compose
# supplies the service's database environment and read-only primary signing-key
# mount; no placeholder material or second validator lives in this adapter.
# Override the entrypoint/command so neither API startup nor the relay loop runs.
# These one-offs create containers and may ensure networks/volumes exist. They
# precede database inspection/exec, recovery-bundle work and all migrations.
# The CLI owns the typed verdict and exit status. Discard both output streams:
# an unavailable CLI, Compose failure or refusal produces only our fixed message.
for role in app relay; do
    if ! compose run --rm --no-deps -T --entrypoint dotmac-platform "$role" \
        deployment candidate-material-probe --role "$role" >/dev/null 2>&1; then
        die "candidate material probe failed for ${role}; deployment stopped before database checks, backup or migration"
    fi
done

# The production database volume predates the relay. Docker's init directory
# runs only for a NEW data directory, so bringing `db` up here cannot repair an
# absent relay credential and risks recreating the one database this deploy must
# preserve. Refuse unless the existing, named container is already healthy;
# everything below is an exec/run operation against that unchanged database.
mapfile -t DB_CONTAINER_IDS < <(compose ps --status running -q db)
[[ "${#DB_CONTAINER_IDS[@]}" -eq 1 ]] \
    || die "expected exactly one running existing db container; refusing to create one"
readonly DB_CONTAINER_ID="${DB_CONTAINER_IDS[0]}"
readonly DB_HEALTH="$(docker inspect --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
    "$DB_CONTAINER_ID")"
[[ "$DB_HEALTH" == "healthy" ]] \
    || die "existing db container is not healthy; refusing to recreate it"

readonly ROLE_CONTRACT="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" --tuples-only --no-align --command "SELECT rolsuper::text || '\''|'\'' || rolcreaterole::text || '\''|'\'' || rolbypassrls::text || '\''|'\'' || rolcanlogin::text FROM pg_roles WHERE rolname = current_user"')"
[[ "$ROLE_CONTRACT" == "false|false|true|true" ]] \
    || die "module database role contract is not satisfied"
readonly OWNER_CONTRACT="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" --tuples-only --no-align --command "SELECT pg_get_userbyid(datdba) || '\''|'\'' || (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='\''public'\'') FROM pg_database WHERE datname = current_database()"')"
[[ "$OWNER_CONTRACT" == "app_admin|app_admin" ]] \
    || die "module database ownership contract is not satisfied"

# ── The recovery bundle: one atomic artifact, or no deployment ───────────────
#
# Rehearsed 2026-08-30 against this host's own newest backup: a plain
# `pg_restore` of a custom dump exited 1 with 114 missing-role errors across
# five roles, and left a database that LOOKED recovered — 45 tables, 23 of 26
# policies, 16 RLS-enabled tables — with no roles, no grants, and every object
# owned by whoever ran the restore. `pg_dump` of one database carries object
# ACLs and RLS policies but never role definitions, memberships or tablespaces:
# those are CLUSTER objects and only `pg_dumpall --globals-only` emits them.
#
# That is worse than a backup that fails outright. This assembly's plane
# separation IS the grant/revoke matrix rather than the policies alone
# (`dotmac_starter_mt` ADR-0023), so a restore that silently drops the role
# layer produces a control-plane database with no plane separation, and an
# operator reading `pg_policies` afterwards concludes the isolation model came
# back. It did not.
#
# So a backup is no longer a file. It is a BUNDLE — dump, globals, manifest and
# checksums — assembled in a hidden temporary directory, validated in full, and
# moved into place with a single `mv`, which is `rename(2)` within one
# filesystem and therefore atomic. A reader either sees a complete bundle or
# sees nothing. And the deploy REFUSES to migrate unless one exists: a rollback
# that is discovered to be absent after the schema has advanced is not a
# rollback.
#
# This runs before the migration and before the application is replaced, under
# the workflow's `vendor-control-plane-production` concurrency group, which is
# the only deployment lock this path has.
mkdir -p "$BACKUP_DIR"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly BUNDLE_PATH="${BACKUP_DIR}/bundle-${TIMESTAMP}"
[[ ! -e "$BUNDLE_PATH" ]] || die "recovery bundle $BUNDLE_PATH already exists"
BUNDLE_TMP="$(mktemp -d "${BACKUP_DIR}/.bundle-${TIMESTAMP}.XXXXXX")"
readonly BUNDLE_TMP
chmod 700 "$BUNDLE_TMP"

# 1. Cluster globals, through the container-local PostgreSQL superuser over the
#    unix socket. `app_admin` is NOSUPERUSER by contract (checked above) and is
#    not the right authority for a CLUSTER dump — it owns one database. The
#    socket is why no password is needed and none is retained: this cluster
#    deliberately has none for `postgres` (`deploy/postgres/init-roles.sh` ends
#    with `ALTER ROLE postgres PASSWORD NULL`).
#
#    `--no-role-passwords` is the configuration that was PROVED, not a
#    precaution: the same artefact restored with globals captured this way
#    exited 0 with zero errors and `verify_recovery` reported zero findings
#    across roles, memberships, ownership, effective privileges and RLS force
#    (`docs/operations/recovery-proved-2026-08-30.md`). It reads `pg_roles`
#    rather than `pg_authid`, so no SCRAM verifier is written to a file at rest.
#    A restored cluster therefore has the five roles with NULL passwords, and
#    the operator resupplies them from OpenBao before the application connects.
compose exec -T --user postgres db \
    pg_dumpall --username postgres --globals-only --no-role-passwords \
    > "${BUNDLE_TMP}/globals.sql"

# 2. The database, with ownership and privileges INTACT. No `--no-owner` and no
#    `--no-privileges`: stripping either would reproduce, by flag, exactly the
#    state the rehearsal found by accident.
compose exec -T db sh -c \
    'exec pg_dump --username app_admin --dbname "$POSTGRES_DB" --format custom' \
    > "${BUNDLE_TMP}/database.dump"

# 3. Validate BEFORE accepting. Every check below is a way the pair can be
#    present and useless.
[[ -s "${BUNDLE_TMP}/globals.sql" ]] || die "cluster globals capture is empty"
[[ -s "${BUNDLE_TMP}/database.dump" ]] || die "database dump is empty"

#    The dump's own table of contents must parse. A truncated custom-format
#    dump is a well-formed FILE and `pg_restore --list` is what distinguishes
#    it from an archive. Piped back into the container because the host holds
#    no PostgreSQL client tools.
compose exec -T db pg_restore --list < "${BUNDLE_TMP}/database.dump" > /dev/null \
    || die "the database dump is not a readable pg_restore archive"

#    Checked by NAME, against the five roles `deploy/postgres/init-roles.sh`
#    creates and `deploy/product.toml` declares as `[[database.roles]]`. A
#    non-empty check would pass on a globals file carrying only tablespaces —
#    which is exactly the shape that produces 114 errors while looking like a
#    capture.
for role in app_admin app_user platform_api outbox_dispatcher \
            platform_outbox_dispatcher; do
    grep -Eq "^CREATE ROLE \"?${role}\"?;\$" "${BUNDLE_TMP}/globals.sql" || die \
"cluster globals capture does not create role ${role}. The pair would restore \
without the grant/revoke matrix that IS this database's plane separation, and \
the restore would look successful. No migration or service replacement has run."
done

#    And the other direction, because `--no-role-passwords` is a flag and a flag
#    can be dropped. A verifier in this file would be a production credential at
#    rest in a backup directory. Matched on the SHAPE of a verifier, never
#    printed.
! grep -Eq "SCRAM-SHA-256\\\$|PASSWORD '(md5|SCRAM)" "${BUNDLE_TMP}/globals.sql" \
    || die "the cluster globals capture contains a password verifier; \
--no-role-passwords did not hold and this bundle must not be kept"

# 4. The facts a restore has to be checked against, measured from the cluster
#    being captured rather than assumed from a declaration.
PG_VERSION_NUM="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" -tAc "SHOW server_version_num"' \
    | tr -d '\r\n')"
readonly PG_VERSION_NUM
[[ "$PG_VERSION_NUM" =~ ^[0-9]+$ ]] || die "could not read server_version_num"
readonly PG_MAJOR="$(( PG_VERSION_NUM / 10000 ))"

CLUSTER_SYSTEM_IDENTIFIER="$(compose exec -T --user postgres db \
    psql --username postgres -tAc \
    'SELECT system_identifier FROM pg_control_system()' | tr -d '\r\n')"
readonly CLUSTER_SYSTEM_IDENTIFIER
[[ "$CLUSTER_SYSTEM_IDENTIFIER" =~ ^[0-9]+$ ]] \
    || die "could not read the cluster system identifier"

DATABASE_NAME="$(compose exec -T db sh -c 'printf %s "$POSTGRES_DB"' | tr -d '\r\n')"
readonly DATABASE_NAME
[[ -n "$DATABASE_NAME" ]] || die "could not read the database name"

# READ OFF THE ARTIFACT, not accepted as an argument. The revision this image
# was built from is inside its own config as an OCI label, so the manifest
# records what the bytes say rather than what the caller asserted.
SOURCE_REVISION="$(docker inspect \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
    "$VENDOR_APP_IMAGE" | tr -d '\r\n')"
readonly SOURCE_REVISION
[[ "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]] \
    || die "the image carries no 40-character OCI revision label"

# The ACCEPTED descriptor, as the deployment adapter delivered it. A bundle that
# cannot say which contract it is meant to satisfy cannot be checked against one.
[[ -f "$DESCRIPTOR_FILE" ]] || die "$DESCRIPTOR_FILE is missing; the deployment \
adapter did not deliver the accepted descriptor, so this bundle could not name \
the contract a recovery must satisfy"
DESCRIPTOR_SHA256="sha256:$(sha256sum "$DESCRIPTOR_FILE" | cut -d' ' -f1)"
readonly DESCRIPTOR_SHA256

MIGRATION_HEADS="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" -tAc \
        "SELECT version_num FROM alembic_version ORDER BY version_num"' \
    | tr -d '\r')"
readonly MIGRATION_HEADS
[[ -n "$MIGRATION_HEADS" ]] || die "the database reports no migration heads"

# 5. Hash both components, in the format `sha256sum -c` reads back.
( cd "$BUNDLE_TMP" && sha256sum database.dump globals.sql > SHA256SUMS )

# 6. The manifest. Canonical JSON, so the bundle digest over it is re-derivable
#    by anyone holding the bundle.
env \
    BUNDLE_TMP="$BUNDLE_TMP" \
    TARGET_HOST_ID="$EXPECTED_HOST_ID" \
    PG_MAJOR="$PG_MAJOR" \
    CLUSTER_SYSTEM_IDENTIFIER="$CLUSTER_SYSTEM_IDENTIFIER" \
    DATABASE_NAME="$DATABASE_NAME" \
    IMAGE_DIGEST="$DIGEST" \
    SOURCE_REVISION="$SOURCE_REVISION" \
    DESCRIPTOR_SHA256="$DESCRIPTOR_SHA256" \
    MIGRATION_HEADS="$MIGRATION_HEADS" \
    CREATED_AT="$TIMESTAMP" \
    python3 - <<'MANIFEST'
import hashlib, json, os
from pathlib import Path

bundle = Path(os.environ["BUNDLE_TMP"])
digests = {}
for name in ("database.dump", "globals.sql"):
    digests[name] = "sha256:" + hashlib.sha256((bundle / name).read_bytes()).hexdigest()

manifest = {
    "schema": "PlatformCpRecoveryBundle.v1",
    "product": "dotmac_vendor_control_plane",
    "environment": "production",
    "target": os.environ["TARGET_HOST_ID"],
    "postgres_major": int(os.environ["PG_MAJOR"]),
    "cluster_system_identifier": os.environ["CLUSTER_SYSTEM_IDENTIFIER"],
    "database_name": os.environ["DATABASE_NAME"],
    "image_digest": os.environ["IMAGE_DIGEST"],
    "image_source_revision": os.environ["SOURCE_REVISION"],
    "descriptor_sha256": os.environ["DESCRIPTOR_SHA256"],
    "migration_heads": sorted(
        line for line in os.environ["MIGRATION_HEADS"].splitlines() if line.strip()
    ),
    "files": digests,
    "created_at": os.environ["CREATED_AT"],
    "restore_order": ["globals.sql", "database.dump"],
}
payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
# Written, not printed. The bundle digest has ONE producer, immediately below;
# a second `print` here would be a second answer to the same question.
(bundle / "manifest.json").write_text(payload + "\n", encoding="utf-8")
MANIFEST

# 7. The bundle digest is over the canonical manifest, which names both file
#    digests — so one value identifies the whole artifact.
BUNDLE_DIGEST="$(env BUNDLE_TMP="$BUNDLE_TMP" python3 - <<'DIGEST'
import hashlib, json, os
from pathlib import Path
payload = json.loads(
    (Path(os.environ["BUNDLE_TMP"]) / "manifest.json").read_text(encoding="utf-8")
)
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
print("sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest())
DIGEST
)"
readonly BUNDLE_DIGEST
[[ "$BUNDLE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "could not digest the bundle"

# 8. Publish atomically. Until this line there is no bundle, only a dot-prefixed
#    temporary directory that no reader will mistake for one.
mv "$BUNDLE_TMP" "$BUNDLE_PATH"

# 9. REFUSE to go further without it — re-read from its published location
#    rather than trusting the variables that built it. `sha256sum -c` is the
#    check that the bytes on disk are the bytes that were hashed.
for component in database.dump globals.sql manifest.json SHA256SUMS; do
    [[ -f "${BUNDLE_PATH}/${component}" ]] \
        || die "recovery bundle is incomplete: ${component} is missing"
done
( cd "$BUNDLE_PATH" && sha256sum --quiet --check SHA256SUMS ) \
    || die "recovery bundle checksums do not verify; refusing to migrate"

printf 'recovery bundle %s\n  digest %s\n  restore order: globals.sql then database.dump\n' \
    "$BUNDLE_PATH" "$BUNDLE_DIGEST"

# Initialize the manifest volume only after the published recovery bundle has
# been verified on disk, and before the composed migration consumes it.
compose --profile ops run --rm --no-deps manifest-init

# This is the one composed migration owner: kernel, Vendor, Release Catalog,
# Entitlement Allocation, and Approvals advance before the app is replaced.
#
# The INSTALLED console script, not a path into the image. `scripts/` is no
# longer copied into the runtime stage at all, so this cannot silently become a
# stale file somebody rsynced; and the command's exit status is the CLI's own —
# 3 if the migration owner refused the target, 4 if the evidence it needed was
# absent — which `set -e` propagates to the deploy as a whole.
compose --profile ops run --rm --no-deps ops dotmac-platform admin migrate

# The relay is an independently restartable worker, not an application
# dependency Compose should create opportunistically. The database is already
# healthy and the migration above created its heartbeat storage, so start the
# relay explicitly before the app's readiness probe can judge its durable
# heartbeat. `--no-deps` is intentional: recreating `db` here would be unsafe
# on an already-initialized production volume.
compose up -d --no-deps relay
compose up -d --no-deps app --wait
# Both probes, and they answer different questions. `/health` is the kernel's
# liveness route and does not touch the database; `/health/ready` asks the one
# dependency this assembly has. Checking only the first is how a deploy could
# report success while the application could not serve — so the readiness check
# is the one that gates the printed result, and liveness is kept as the
# positive control that distinguishes "not ready" from "not answering at all".
curl --fail --silent --show-error --max-time 10 \
    --header "Host: vendor.dotmac.io" \
    "http://127.0.0.1:${VENDOR_APP_PORT:-8100}/health" >/dev/null
curl --fail --silent --show-error --max-time 10 \
    --header "Host: vendor.dotmac.io" \
    "http://127.0.0.1:${VENDOR_APP_PORT:-8100}/health/ready" >/dev/null

printf 'Deployed %s\nrecovery bundle: %s\nrecovery bundle digest: %s\n' \
    "$VENDOR_APP_IMAGE" "$BUNDLE_PATH" "$BUNDLE_DIGEST"
