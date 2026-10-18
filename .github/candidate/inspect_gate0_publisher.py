"""Private hosted shape measurement; never extract untrusted rootfs members.

No rootfs or dependency byte upload. Success is runtime_NOT_RETAINED and cannot
qualify Runner.Listener, gh, host systemd, credentials, or an installed host.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

PREFIX = "opt/venv/"
CP_DIST = "dotmac_vendor_control_plane-"
MAX_TAR_BYTES = 8 * 1024**3
MAX_ENTRIES = 250_000
MAX_FILE_BYTES = 512 * 1024**2
MAX_PATH_BYTES = 4096
MAX_FILES_BYTES = 128 * 1024**2
SOURCE_OWNERS = (
    "vendor_cp/cli/__init__.py",
    "vendor_cp/cli/owners.py",
    "vendor_cp/deployment/gate0_framing.py",
    "vendor_cp/deployment/gate0_runner_lifecycle.py",
    "vendor_cp/deployment/gate0_runner_lifecycle_courier.py",
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def private_input(path: Path, maximum: int) -> BinaryIO:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077
            and 0 < info.st_size <= maximum
        ):
            raise ValueError("private input shape")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def stream_digest(stream: BinaryIO, maximum: int = MAX_TAR_BYTES) -> str:
    position = stream.tell()
    stream.seek(0)
    value = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        if size > maximum:
            raise ValueError("rootfs archive budget")
        value.update(block)
    stream.seek(position)
    return value.hexdigest()


def private_output(path: Path) -> BinaryIO:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    return os.fdopen(descriptor, "wb")


def bounded_pax_records(raw: bytes) -> None:
    """Reject sparse extensions before tarfile can interpret sparse maps."""
    if len(raw) > 16 * 1024:
        raise ValueError("rootfs extension budget")
    offset = 0
    while offset < len(raw):
        space = raw.find(b" ", offset, min(offset + 7, len(raw)))
        if space == -1:
            raise ValueError("rootfs extension framing")
        encoded_length = raw[offset:space]
        if not encoded_length.isdigit() or encoded_length.startswith(b"0"):
            raise ValueError("rootfs extension framing")
        length = int(encoded_length)
        end = offset + length
        if end > len(raw) or end <= space + 3 or raw[end - 1 : end] != b"\n":
            raise ValueError("rootfs extension framing")
        key, separator, _ = raw[space + 1 : end - 1].partition(b"=")
        if not key or not separator or b"\x00" in key or b"\n" in key:
            raise ValueError("rootfs extension framing")
        if key.startswith(b"GNU.sparse."):
            raise ValueError("sparse rootfs member")
        offset = end


def bounded_tar_headers(stream: BinaryIO) -> None:
    """Bound extension-header reads before tarfile can allocate their bodies."""
    stream.seek(0, os.SEEK_END)
    total = stream.tell()
    if total > MAX_TAR_BYTES or total % 512:
        raise ValueError("rootfs archive framing")
    stream.seek(0)
    headers = 0
    while stream.tell() < total:
        header = stream.read(512)
        if header == bytes(512):
            if stream.read(512) != bytes(512):
                raise ValueError("rootfs archive framing")
            while block := stream.read(1024 * 1024):
                if any(block):
                    raise ValueError("rootfs trailing data")
            stream.seek(0)
            return
        headers += 1
        if headers > MAX_ENTRIES * 2:
            raise ValueError("rootfs header budget")
        kind = header[156:157]
        if kind == b"S":
            raise ValueError("sparse rootfs member")
        encoded = header[124:136]
        if encoded[0] & 0x80:
            size = int.from_bytes(encoded, "big", signed=True)
            if encoded[0] == 0x80:
                size += 1 << 95
        else:
            try:
                size = int(encoded.strip(b"\x00 ") or b"0", 8)
            except ValueError as error:
                raise ValueError("rootfs archive framing") from error
        maximum = (
            16 * 1024 if kind in {b"x", b"g", b"X", b"L", b"K"} else MAX_FILE_BYTES
        )
        padded = ((size + 511) // 512) * 512
        if not 0 <= size <= maximum or stream.tell() + padded > total:
            raise ValueError("rootfs header budget")
        if kind in {b"x", b"g", b"X"}:
            raw = stream.read(size)
            if len(raw) != size:
                raise ValueError("rootfs extension framing")
            bounded_pax_records(raw)
            stream.seek(padded - size, os.SEEK_CUR)
        else:
            stream.seek(padded, os.SEEK_CUR)
    raise ValueError("rootfs archive terminator")


def member_name(name: str) -> str:
    # Docker export writes relative canonical POSIX paths (directories may end /).
    result = name.removesuffix("/")
    if (
        not result
        or len(result.encode("utf-8")) > MAX_PATH_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in result)
        or result.startswith("/")
        or "\\" in result
        or any(p in {"", ".", ".."} for p in result.split("/"))
    ):
        raise ValueError("noncanonical rootfs member")
    return result


def protected(name: str) -> bool:
    return (
        name == "opt"
        or name.startswith("opt/venv")
        or name == "app"
        or name.startswith("app/")
    )


def forbidden(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return (
        any(
            p
            in {
                ".git",
                ".cache",
                ".aws",
                ".ssh",
                ".gnupg",
                ".netrc",
                ".pypirc",
                "__pypackages__",
                "poetry.lock",
                "pyproject.toml",
            }
            for p in parts
        )
        or name in {"app/src", "app/scripts", "opt/poetry"}
        or name.startswith(("app/src/", "app/scripts/", "opt/poetry/", "run/secrets/"))
    )


def inventory(
    archive: tarfile.TarFile, *, publisher: bool
) -> dict[str, tarfile.TarInfo]:
    result: dict[str, tarfile.TarInfo] = {}
    for item in archive:
        if len(result) >= MAX_ENTRIES or not 0 <= item.size <= MAX_FILE_BYTES:
            raise ValueError("rootfs budget")
        name = member_name(item.name)
        if len(item.linkname.encode("utf-8")) > MAX_PATH_BYTES:
            raise ValueError("rootfs link budget")
        if name in result:
            raise ValueError("duplicate rootfs member")
        if not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
            raise ValueError("special rootfs member")
        if publisher and forbidden(name):
            raise ValueError("checkout, cache, or credential material")
        if publisher and protected(name):
            if item.uid != 0 and publisher:
                raise ValueError("non-root protected owner")
            if not item.issym() and item.mode & 0o022 and publisher:
                raise ValueError("writable protected path")
            if item.islnk():
                raise ValueError("protected hardlink")
            if item.issym():
                # Permit only dependency sibling links; protected python/CLI
                # paths and every protected ancestor must be real entries.
                if name == "opt/venv/lib64" and item.linkname == "lib":
                    result[name] = item
                    continue
                if (
                    not name.startswith("opt/venv/bin/")
                    or PurePosixPath(name).name
                    in {"python", "python3", "python3.12", "dotmac-platform"}
                    or PurePosixPath(item.linkname).name != item.linkname
                ):
                    raise ValueError("protected link")
        result[name] = item
    if publisher:
        for name, item in result.items():
            if not protected(name):
                continue
            for parent in PurePosixPath(name).parents:
                if str(parent) == ".":
                    continue
                entry = result.get(str(parent))
                if (
                    entry is None
                    or not entry.isdir()
                    or entry.uid != 0
                    or entry.mode & 0o022
                ):
                    raise ValueError("unsafe protected ancestry")
            if item.issym():
                target = str(PurePosixPath(name).parent / item.linkname)
                if target not in result or not (
                    result[target].isfile()
                    or (name == "opt/venv/lib64" and result[target].isdir())
                ):
                    raise ValueError("unsafe protected link target")
    return result


# Role inventory is a separate refusal policy, never inventory(publisher=False).
# This primitive alone does not accept an image or enable runtime retention.
ROLE_ENVIRONMENTS = ("opt/venv", "opt/poetry")
ROLE_PROJECT_FILES = frozenset({"app/pyproject.toml", "app/poetry.lock"})
ROLE_PYTHON_LINKS = {
    f"{prefix}/bin/{name}": target
    for prefix in ROLE_ENVIRONMENTS
    for name, target in (
        ("python", "python3"),
        ("python3", "/usr/bin/python3"),
        ("python3.12", "python3"),
    )
}


def role_protected(name: str) -> bool:
    return (
        name in {"opt", "app", "usr", "usr/bin"}
        or name.startswith("app/")
        or name == "usr/bin/python3"
        or name == "usr/bin/python3.12"
        or any(
            name == prefix or name.startswith(prefix + "/")
            for prefix in ROLE_ENVIRONMENTS
        )
    )


def role_forbidden(name: str) -> bool:
    # Only the exact role project inputs and Poetry runtime are admitted.
    # Credentials and caches remain forbidden everywhere, including Poetry.
    parts = PurePosixPath(name).parts
    if any(
        part
        in {
            ".git",
            ".cache",
            ".aws",
            ".ssh",
            ".gnupg",
            ".netrc",
            ".pypirc",
            "__pypackages__",
            "auth.toml",
        }
        for part in parts
    ):
        return True
    if any(part in {"pyproject.toml", "poetry.lock"} for part in parts):
        return name not in ROLE_PROJECT_FILES
    return name in {"app/src", "app/scripts", "run/secrets"} or name.startswith(
        ("app/src/", "app/scripts/", "run/secrets/")
    )


def role_inventory(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    """Inventory role-native shapes with the publisher's bounded refusal rules.

    Callers must also bind actual installed wheel/profile/native subjects and
    synthetic results before acceptance. No upload consumes this
    policy primitive until all role subject joins also succeed.
    """
    result: dict[str, tarfile.TarInfo] = {}
    for item in archive:
        if len(result) >= MAX_ENTRIES or not 0 <= item.size <= MAX_FILE_BYTES:
            raise ValueError("rootfs budget")
        name = member_name(item.name)
        if len(item.linkname.encode("utf-8")) > MAX_PATH_BYTES:
            raise ValueError("rootfs link budget")
        if name in result:
            raise ValueError("duplicate rootfs member")
        if not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
            raise ValueError("special rootfs member")
        if role_forbidden(name):
            raise ValueError("checkout, cache, or credential material")
        if role_protected(name):
            if item.uid != 0 or item.gid != 0:
                raise ValueError("non-root protected owner")
            if not item.issym() and item.mode & 0o022:
                raise ValueError("writable protected path")
            if item.islnk():
                raise ValueError("protected hardlink")
            if item.issym():
                expected = ROLE_PYTHON_LINKS.get(name)
                if name == "usr/bin/python3":
                    expected = "python3.12"
                if name in {prefix + "/lib64" for prefix in ROLE_ENVIRONMENTS}:
                    expected = "lib"
                if expected is not None:
                    if item.linkname != expected:
                        raise ValueError("protected native link")
                elif (
                    not any(
                        name.startswith(prefix + "/bin/")
                        for prefix in ROLE_ENVIRONMENTS
                    )
                    or PurePosixPath(name).name == "dotmac-platform"
                    or PurePosixPath(item.linkname).name != item.linkname
                    or item.linkname in {"", ".", ".."}
                ):
                    raise ValueError("protected link")
        result[name] = item
    for name, item in result.items():
        if not role_protected(name):
            continue
        for parent in PurePosixPath(name).parents:
            if str(parent) == ".":
                continue
            entry = result.get(str(parent))
            if (
                entry is None
                or not entry.isdir()
                or entry.uid != 0
                or entry.gid != 0
                or entry.mode & 0o022
            ):
                raise ValueError("unsafe protected ancestry")
        if not item.issym():
            continue
        target = (
            item.linkname.removeprefix("/")
            if item.linkname.startswith("/")
            else str(PurePosixPath(name).parent / item.linkname)
        )
        target = member_name(target)
        seen = {name}
        while True:
            entry = result.get(target)
            if entry is None or target in seen:
                raise ValueError("unsafe protected link target")
            if (
                entry.uid != 0
                or entry.gid != 0
                or (not entry.issym() and entry.mode & 0o022)
            ):
                raise ValueError("unsafe protected link target")
            if not entry.issym():
                is_lib = name in {prefix + "/lib64" for prefix in ROLE_ENVIRONMENTS}
                if not (entry.isdir() if is_lib else entry.isfile()):
                    raise ValueError("unsafe protected link target")
                break
            # Only the finite native interpreter chain may traverse a symlink.
            if target not in ROLE_PYTHON_LINKS and target != "usr/bin/python3":
                raise ValueError("unsafe protected link target")
            seen.add(target)
            target = member_name(
                entry.linkname.removeprefix("/")
                if entry.linkname.startswith("/")
                else str(PurePosixPath(target).parent / entry.linkname)
            )
    return result


def member_digest(archive: tarfile.TarFile, item: tarfile.TarInfo) -> str:
    """Hash a bounded regular member without materialising or extracting it."""
    if not item.isfile() or not 0 <= item.size <= MAX_FILE_BYTES:
        raise ValueError("rootfs file budget")
    stream = archive.extractfile(item)
    if stream is None:
        raise ValueError("unreadable rootfs member")
    value = hashlib.sha256()
    remaining = item.size
    with stream:
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                raise ValueError("truncated rootfs member")
            value.update(block)
            remaining -= len(block)
        if stream.read(1):
            raise ValueError("rootfs member size")
    return value.hexdigest()


def _complete_files(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], *, role: bool
) -> bytes:
    """Canonical private roster covers every entry, including non-venv paths."""
    rows = []
    encoded_bytes = 0
    for name, item in sorted(members.items()):
        kind = (
            "file"
            if item.isfile()
            else "directory"
            if item.isdir()
            else "symlink"
            if item.issym()
            else "hardlink"
        )
        row = {
            "path": name,
            "type": kind,
            "mode": item.mode,
            "uid": item.uid,
            "gid": item.gid,
            "size": item.size,
            "sha256": member_digest(archive, item) if item.isfile() else None,
            "link_target": item.linkname if item.issym() or item.islnk() else None,
        }
        encoded_bytes += (
            len(
                json.dumps(
                    row, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode()
            )
            + 1
        )
        if encoded_bytes > MAX_FILES_BYTES - 1024:
            raise ValueError("files manifest budget")
        rows.append(row)
    raw = (
        json.dumps(
            {
                "schema": "Gate0RoleQualificationFiles.v1"
                if role
                else "Gate0PublisherFiles.v1",
                "files": rows,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        + b"\n"
    )
    if len(raw) > MAX_FILES_BYTES:
        raise ValueError("files manifest budget")
    return raw


def complete_files(archive, members):
    return _complete_files(archive, members, role=False)


def complete_role_files(archive, members):
    return _complete_files(archive, members, role=True)


def read(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
    maximum: int = 128 * 1024 * 1024,
) -> bytes:
    item = members[name]
    if not item.isfile() or not 0 <= item.size <= maximum:
        raise ValueError("not a bounded ordinary rootfs file")
    stream = archive.extractfile(item)
    if stream is None:
        raise ValueError("unreadable rootfs member")
    raw = stream.read(maximum + 1)
    if len(raw) != item.size:
        raise ValueError("rootfs member size")
    return raw


def excluded(name: str) -> bool:
    # Only interpreter identity, CP installer-generated metadata/entry point,
    # fresh venv configuration, and generated bytecode are outside comparison.
    relative = name.removeprefix(PREFIX)
    return (
        relative
        in {
            "pyvenv.cfg",
            "bin/python",
            "bin/python3",
            "bin/python3.12",
            "bin/dotmac-platform",
        }
        or "__pycache__" in PurePosixPath(name).parts
        or name.endswith(".pyc")
        or any(
            p.startswith(CP_DIST) and p.endswith(".dist-info")
            for p in PurePosixPath(name).parts
        )
    )


def closure(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo]
) -> dict[str, tuple]:
    result = {}
    for name, item in members.items():
        if not name.startswith(PREFIX) or excluded(name):
            continue
        if item.isfile():
            result[name] = (
                "file",
                item.mode & 0o777,
                member_digest(archive, item),
            )
        elif item.isdir():
            result[name] = ("directory", item.mode & 0o777)
        elif item.issym():
            result[name] = ("symlink", item.linkname)
        else:
            raise ValueError("unsupported closure member")
    return result


def bounded_structural_closure_difference_counts(
    expected: dict[str, tuple], actual: dict[str, tuple]
) -> dict[str, int]:
    counts = {
        "missing": len(expected.keys() - actual.keys()),
        "extra": len(actual.keys() - expected.keys()),
        "kind": 0,
        "mode": 0,
        "content": 0,
        "link_target": 0,
    }
    for name in expected.keys() & actual.keys():
        left, right = expected[name], actual[name]
        if left[0] != right[0]:
            counts["kind"] += 1
            continue
        if left[0] == "directory":
            if left[1] != right[1]:
                counts["mode"] += 1
        elif left[0] == "file":
            if left[1] != right[1]:
                counts["mode"] += 1
            if left[2] != right[2]:
                counts["content"] += 1
        elif left[0] == "symlink" and left[1] != right[1]:
            counts["link_target"] += 1
    return counts


def inspect(
    production: Path,
    publisher: Path,
    shape: Path,
    output: Path,
    files_output: Path | None = None,
) -> None:
    with (
        private_input(production, MAX_TAR_BYTES) as production_stream,
        private_input(publisher, MAX_TAR_BYTES) as publisher_stream,
        private_input(shape, 1024**2) as shape_stream,
    ):
        bounded_tar_headers(production_stream)
        bounded_tar_headers(publisher_stream)
        _inspect_open_streams(
            production_stream, publisher_stream, shape_stream, output, files_output
        )


def _inspect_open_streams(
    production_stream: BinaryIO,
    publisher_stream: BinaryIO,
    shape_stream: BinaryIO,
    output: Path,
    files_output: Path | None,
) -> None:
    with (
        tarfile.open(fileobj=production_stream, mode="r:") as prod,
        tarfile.open(fileobj=publisher_stream, mode="r:") as pub,
    ):
        left = inventory(prod, publisher=False)
        right = inventory(pub, publisher=True)
        manifest = read(pub, right, "app/distributions.json", 1024 * 1024)
        if manifest != read(prod, left, "app/distributions.json", 1024 * 1024):
            raise ValueError("actual distribution manifests differ")
        document = json.loads(manifest)
        if document["contract"] != "dotmac-distribution-digests/1":
            raise ValueError("distribution contract")
        entries = document["files"]
        names = [entry["filename"] for entry in entries]
        if len(names) != len(set(names)) or any(
            PurePosixPath(n).name != n for n in names
        ):
            raise ValueError("distribution names")
        wheels = [entry for entry in entries if entry["filename"].endswith(".whl")]
        if len(wheels) != 1 or not wheels[0]["filename"].startswith(CP_DIST):
            raise ValueError("exactly one CP wheel")
        actual_dist = {
            name.removeprefix("app/dist/")
            for name, item in right.items()
            if name.startswith("app/dist/") and not item.isdir()
        }
        if actual_dist != set(names):
            raise ValueError("unexpected publisher distribution entries")
        expected_metadata = (
            "-".join(wheels[0]["filename"].split("-")[:2]) + ".dist-info"
        )
        for members in (left, right):
            metadata = {
                part
                for name in members
                for part in PurePosixPath(name).parts
                if part.startswith(CP_DIST) and part.endswith(".dist-info")
            }
            if metadata != {expected_metadata}:
                raise ValueError("unexpected CP installer metadata")
        for entry in entries:
            raw = read(pub, right, "app/dist/" + entry["filename"])
            if (
                len(raw) != entry["size_bytes"]
                or "sha256:" + digest(raw) != entry["sha256"]
            ):
                raise ValueError("publisher distribution hash")
        wheel = read(pub, right, "app/dist/" + wheels[0]["filename"])
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            zip_names = archive.namelist()
            if len(zip_names) != len(set(zip_names)):
                raise ValueError("duplicate wheel member")
            for owner in SOURCE_OWNERS:
                installed = PREFIX + "lib/python3.12/site-packages/" + owner
                if archive.getinfo(owner).file_size > 1024**2:
                    raise ValueError("source-owner budget")
                expected = archive.read(owner)
                if (
                    read(pub, right, installed) != expected
                    or read(prod, left, installed) != expected
                ):
                    raise ValueError("installed source-owner bytes differ from wheel")
        expected_closure = closure(prod, left)
        actual_closure = closure(pub, right)
        if expected_closure != actual_closure:
            print(
                json.dumps(
                    bounded_structural_closure_difference_counts(
                        expected_closure, actual_closure
                    ),
                    sort_keys=True,
                )
            )
            raise ValueError(
                "dependency closure differs outside explicit generated exceptions"
            )
        measured = json.loads(shape_stream.read(1024**2 + 1))
        if (
            measured.get("schema") != "Gate0PublisherShape.v1"
            or measured.get("status") != "shape_only"
        ):
            raise ValueError("shape measurement missing")
        files = complete_files(pub, right)
        if files_output is not None:
            with private_output(files_output) as stream:
                stream.write(files)
        with private_output(output) as output_stream:
            output_stream.write(
                (
                    json.dumps(
                        {
                            "schema": "Gate0PublisherBuild.v1",
                            "status": "runtime_NOT_RETAINED",
                            "artifact_acceptance": False,
                            "native_qualification": False,
                            "production_wheel_retained": False,
                            "production_comparison": (
                                "actual_manifest_and_installed_source_owners"
                            ),
                            "distribution_manifest_sha256": digest(manifest),
                            "publisher_wheel_sha256": digest(wheel),
                            "production_rootfs_sha256": stream_digest(
                                production_stream
                            ),
                            "publisher_rootfs_sha256": stream_digest(publisher_stream),
                            "dependency_closure_entries": len(closure(pub, right)),
                            "files_manifest_sha256": digest(files),
                            "footprint": {
                                "entries": len(right),
                                "regular_files": sum(
                                    item.isfile() for item in right.values()
                                ),
                                "regular_bytes": sum(
                                    item.size
                                    for item in right.values()
                                    if item.isfile()
                                ),
                                "largest_member_bytes": max(
                                    (item.size for item in right.values()), default=0
                                ),
                                "publisher_tar_bytes": os.fstat(
                                    publisher_stream.fileno()
                                ).st_size,
                                "inspection_scratch_bytes": os.fstat(
                                    production_stream.fileno()
                                ).st_size
                                + os.fstat(publisher_stream.fileno()).st_size
                                + len(files)
                                + os.fstat(shape_stream.fileno()).st_size,
                            },
                        },
                        sort_keys=True,
                    )
                    + "\n"
                ).encode()
            )


def _role_retention_owner():
    # Fixed sibling source owner; no caller-selected import path.
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "role_inspector_retention",
        Path(__file__).with_name("retain_gate0_publisher.py"),
    )
    if spec is None or spec.loader is None:
        raise ValueError("missing retention owner")
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    return owner


def role_subjects(
    archive, members, source, *, native_pins_raw=None, validation_owner=None
):
    """Join data in the actual export to selected source; execute no member."""
    owner = _role_retention_owner() if validation_owner is None else validation_owner
    closed, parse_json, sha256 = owner.closed, owner.parse_json, owner.sha256

    manifest = read(archive, members, "app/distributions.json", 1024**2)
    document = closed(parse_json(manifest, 1024**2), ("contract", "files"))
    if document["contract"] != "dotmac-distribution-digests/1":
        raise ValueError("distribution contract")
    entries = document["files"]
    if not isinstance(entries, list) or not 2 <= len(entries) <= 16:
        raise ValueError("distribution roster")
    names = []
    for entry in entries:
        closed(entry, ("filename", "size_bytes", "sha256"))
        name = member_name(entry["filename"])
        if "/" in name or name in names or not name.endswith((".whl", ".tar.gz")):
            raise ValueError("distribution names")
        names.append(name)
        raw = read(archive, members, "app/dist/" + name)
        if (
            type(entry["size_bytes"]) is not int
            or len(raw) != entry["size_bytes"]
            or "sha256:" + digest(raw) != entry["sha256"]
        ):
            raise ValueError("distribution digest")
    actual = {
        name.removeprefix("app/dist/")
        for name, item in members.items()
        if name.startswith("app/dist/") and not item.isdir()
    }
    if actual != set(names):
        raise ValueError("distribution closure")
    wheels = [name for name in names if name.endswith(".whl")]
    if (
        len(wheels) != 1
        or not wheels[0].startswith(CP_DIST)
        or not any(name.endswith(".tar.gz") for name in names)
    ):
        raise ValueError("CP wheel subject")
    expected_metadata = "-".join(wheels[0].split("-")[:2]) + ".dist-info"
    actual_metadata = {
        part
        for name in members
        for part in PurePosixPath(name).parts
        if part.startswith(CP_DIST) and part.endswith(".dist-info")
    }
    if actual_metadata != {expected_metadata}:
        raise ValueError("installed CP metadata closure")
    wheel = read(archive, members, "app/dist/" + wheels[0])
    prefix = "opt/venv/lib/python3.12/site-packages/"
    with zipfile.ZipFile(io.BytesIO(wheel)) as zipped:
        infos = zipped.infolist()
        if len(infos) > MAX_ENTRIES or len({info.filename for info in infos}) != len(
            infos
        ):
            raise ValueError("wheel roster")
        wheel_owners = set()
        total = 0
        for info in infos:
            name = member_name(info.filename)
            if info.is_dir():
                continue
            total += info.file_size
            if (
                not (
                    name.startswith("vendor_cp/")
                    or (
                        name.split("/")[0].startswith(CP_DIST)
                        and name.split("/")[0].endswith(".dist-info")
                    )
                )
                or info.file_size > MAX_FILE_BYTES
                or total > MAX_FILE_BYTES
            ):
                raise ValueError("wheel owner budget")
            if name.endswith(".dist-info/RECORD"):
                continue
            wheel_owners.add(name)
            if read(archive, members, prefix + name, info.file_size) != zipped.read(
                info
            ):
                raise ValueError("installed wheel owner bytes")
        if not set(SOURCE_OWNERS) <= wheel_owners:
            raise ValueError("wheel source owners")
        installed_owners = {
            name.removeprefix(prefix)
            for name, item in members.items()
            if name.startswith(prefix + "vendor_cp/")
            and item.isfile()
            and "__pycache__" not in PurePosixPath(name).parts
            and not name.endswith(".pyc")
        }
        if installed_owners != {
            name for name in wheel_owners if name.startswith("vendor_cp/")
        }:
            raise ValueError("installed wheel owner closure")
    hashes = {
        "distribution_manifest_sha256": digest(manifest),
        "role_wheel_sha256": digest(wheel),
    }
    for name, field, marker, value in (
        (
            "application_foundation_profile.json",
            "foundation_profile_sha256",
            "contract",
            "dotmac-application-foundation-profile/1",
        ),
        (
            "deployment_profile_declarations.json",
            "deployment_declarations_sha256",
            "schema",
            "DotmacDeploymentProfileDeclarations.v1",
        ),
        (
            "migration_heads.json",
            "migration_heads_sha256",
            "schema",
            "ImageMigrationHeads.v1",
        ),
    ):
        raw = read(archive, members, "app/" + name, 1024**2)
        document = parse_json(raw, 1024**2)
        if (
            document.get(marker) != value
            or document.get("source_revision") != source["revision"]
        ):
            raise ValueError("embedded role metadata")
        hashes[field] = digest(raw)
    profile = parse_json(
        read(archive, members, "app/application_foundation_profile.json", 1024**2),
        1024**2,
    )
    if profile.get("wheel_sha256") != "sha256:" + hashes["role_wheel_sha256"]:
        raise ValueError("foundation wheel join")
    declarations = parse_json(
        read(archive, members, "app/deployment_profile_declarations.json", 1024**2),
        1024**2,
    )
    if (
        declarations.get("foundation_profile_digest")
        != "sha256:" + hashes["foundation_profile_sha256"]
    ):
        raise ValueError("declaration profile join")
    for name, key in (
        ("app/pyproject.toml", "pyproject_sha256"),
        ("app/poetry.lock", "poetry_lock_sha256"),
    ):
        if member_digest(archive, members[name]) != source["files"][key]:
            raise ValueError("embedded source input")
    native_raw = read(archive, members, "app/gate0_native_tools.json", 1024**2)
    native = closed(parse_json(native_raw, 1024**2), ("schema", "binaries", "packages"))
    if (
        native["schema"] != "Gate0NativeTools.v1"
        or not isinstance(native["packages"], str)
        or not native["packages"]
    ):
        raise ValueError("native tools inventory")
    paths = (
        "/usr/bin/ssh",
        "/usr/sbin/sshd",
        "/usr/bin/wg",
        "/usr/sbin/ip",
        "/usr/sbin/nft",
    )
    closed(native["binaries"], paths)
    pins_raw = native_pins_raw
    if pins_raw is None:
        pins_raw = owner.read_owned_regular(
            Path(__file__).resolve().parents[2]
            / owner.ROLE_SOURCE_FILES["native_artifacts_sha256"],
            1024**2,
            private=False,
        )
    if not isinstance(pins_raw, bytes) or len(pins_raw) > 1024**2:
        raise ValueError("native source pin budget")
    if digest(pins_raw) != source["files"]["native_artifacts_sha256"]:
        raise ValueError("native source pin")
    pins = parse_json(pins_raw, 1024**2)
    if (
        pins.get("schema") != "Gate0HostedSshArtifacts.v1"
        or len(pins["artifacts"]) != 2
    ):
        raise ValueError("native source roster")
    ssh_pins = {"/" + item["binary_path"]: item for item in pins["artifacts"]}
    closed(ssh_pins, paths[:2])
    for name, record in native["binaries"].items():
        closed(
            record,
            ("sha256", "archive_sha256", "package_version")
            if name in paths[:2]
            else ("sha256",),
        )
        if name in paths[:2] and (
            record["archive_sha256"] != ssh_pins[name]["sha256"]
            or record["package_version"] != ssh_pins[name]["version"]
        ):
            raise ValueError("native artifact source join")
        entry = members[name.removeprefix("/")]
        if (
            not entry.isfile()
            or entry.uid != 0
            or entry.gid != 0
            or entry.mode & 0o022
            or member_digest(archive, entry) != sha256(record["sha256"])
        ):
            raise ValueError("native tool subject")
        for parent in PurePosixPath(name.removeprefix("/")).parents:
            if str(parent) != ".":
                ancestor = members[str(parent)]
                if (
                    not ancestor.isdir()
                    or ancestor.uid != 0
                    or ancestor.gid != 0
                    or ancestor.mode & 0o022
                ):
                    raise ValueError("native tool ancestry")
    accounts = (
        read(archive, members, "etc/passwd", 1024**2).decode("utf-8").splitlines()
    )
    for role, uid in (
        ("issuer", 10031),
        ("attester", 10032),
        ("management", 10033),
        ("capture-sender", 10034),
    ):
        rows = [
            line.split(":")
            for line in accounts
            if line.split(":")[0] == "gate0-" + role
        ]
        home = "var/empty/dotmac-gate0/" + role
        if (
            len(rows) != 1
            or len(rows[0]) != 7
            or rows[0][2] != str(uid)
            or rows[0][5:] != ["/" + home, "/bin/sh"]
        ):
            raise ValueError("role UID subject")
        entry = members[home]
        if not entry.isdir() or entry.uid != 0 or entry.gid != 0 or entry.mode & 0o222:
            raise ValueError("role home custody")
        for parent in PurePosixPath(home).parents:
            if str(parent) != ".":
                ancestor = members[str(parent)]
                if (
                    not ancestor.isdir()
                    or ancestor.uid != 0
                    or ancestor.gid != 0
                    or ancestor.mode & 0o022
                ):
                    raise ValueError("role home ancestry")
    hashes["native_tools_sha256"] = digest(native_raw)
    return hashes


def role_synthetic_qualification(
    smoke_raw, network_raw, revision, image_id, *, validation_owner=None
):
    owner = _role_retention_owner() if validation_owner is None else validation_owner
    ROLE_PURPOSE, canonical_json, closed, parse_json = (
        owner.ROLE_PURPOSE,
        owner.canonical_json,
        owner.closed,
        owner.parse_json,
    )

    smoke = closed(
        parse_json(smoke_raw, 1024**2),
        (
            "schema",
            "passed",
            "native_versions",
            "python",
            "ssl",
            "psycopg",
            "live_readiness",
        ),
    )
    network = parse_json(network_raw, 1024**2)
    if (
        smoke["schema"] != "Gate0RoleImageSmoke.v1"
        or smoke["passed"] is not True
        or smoke["live_readiness"] is not False
    ):
        raise ValueError("role smoke predicate")
    closed(
        smoke["native_versions"],
        (
            "/usr/bin/ssh",
            "/usr/sbin/sshd",
            "/usr/bin/wg",
            "/usr/sbin/ip",
            "/usr/sbin/nft",
        ),
    )
    if any(
        not isinstance(value, str) or not 0 < len(value) < 4096
        for value in (
            *smoke["native_versions"].values(),
            smoke["python"],
            smoke["ssl"],
            smoke["psycopg"],
        )
    ):
        raise ValueError("role smoke measurements")
    if (
        network.get("schema") != "Gate0NativeNetworkPrivilegeProof.v1"
        or any(
            network.get(key) is not True
            for key in (
                "passed",
                "wrong_principal_refused_under_k",
                "refused_authentication_boundary_empty",
            )
        )
        or any(
            network.get(key) is not False
            for key in ("full_wireguard_installation_qualified", "live_readiness")
        )
    ):
        raise ValueError("role network predicate")
    return canonical_json(
        {
            "schema": "Gate0RoleSyntheticQualification.v1",
            "purpose": ROLE_PURPOSE,
            "source_revision": revision,
            "image_id": image_id,
            "smoke_sha256": digest(smoke_raw),
            "network_sha256": digest(network_raw),
            "smoke": smoke,
            "network": network,
            "live_readiness": False,
            "installed_native_qualified": False,
            "operationally_accepted": False,
            "gate0_accepted": False,
        },
        1024**2,
    )


# Data-only retained inspection. These fixed names are deliberately separate
# from the producer's live export/retention entrypoints.
RETAINED_INPUTS = (
    "runtime-payload.tar",
    "original-packet.json",
    "producer-receipt.json",
    "authenticated-retention-readback.json",
    "historical-native-artifacts.json",
    "terminal-run.json",
    "terminal-jobs.json",
)
RETAINED_OUTER_BYTES = 2 * 1024**3 + MAX_FILES_BYTES + 3 * 1024**2


def retained_outer(stream, rootfs, limits):
    """Read exactly four ordinary USTAR members, without tarfile extensions."""
    metadata = {}
    names = ("role-rootfs.tar.gz", "files.json", "build.json", "qualification.json")
    caps = (
        limits["rootfs_compressed_bytes"],
        limits["files_manifest_bytes"],
        1024**2,
        1024**2,
    )
    stream.seek(0)
    for name, maximum in zip(names, caps, strict=True):
        header = stream.read(512)
        if len(header) != 512:
            raise ValueError("retained outer header")
        try:
            item = tarfile.TarInfo.frombuf(header, "ascii", "strict")
        except (tarfile.TarError, UnicodeError) as error:
            raise ValueError("retained outer header") from error
        # Equality to the ordinary USTAR encoding refuses prefix/path aliases,
        # extensions, base256 numbers, links, sparse maps and hidden header data.
        expected = tarfile.TarInfo(name)
        expected.mode, expected.size = 0o600, item.size
        if not 0 < item.size <= maximum or header != expected.tobuf(
            format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict"
        ):
            raise ValueError("retained outer member")
        remaining = item.size
        chunks = []
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("retained outer truncation")
            remaining -= len(block)
            if name == names[0]:
                rootfs.write(block)
            else:
                chunks.append(block)
        padding = (-item.size) % 512
        if stream.read(padding) != bytes(padding):
            raise ValueError("retained outer padding")
        if name != names[0]:
            metadata[name] = b"".join(chunks)
    if stream.read(1024) != bytes(1024):
        raise ValueError("retained outer terminator")
    while block := stream.read(1024 * 1024):
        if any(block):
            raise ValueError("retained outer trailing data")
    if stream.tell() % 512:
        raise ValueError("retained outer framing")
    rootfs.flush()
    rootfs.seek(0)
    return metadata


def retained_gzip(compressed, uncompressed, maximum):
    """Bound output allocation and reject extra gzip members and trailing bytes."""
    import zlib

    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    compressed.seek(0)
    try:
        while block := compressed.read(1024 * 1024):
            if decoder.eof:
                raise ValueError("retained gzip trailing data")
            while block:
                raw = decoder.decompress(block, min(1024 * 1024, maximum - total + 1))
                total += len(raw)
                if total > maximum:
                    raise ValueError("retained gzip budget")
                uncompressed.write(raw)
                if decoder.unused_data:
                    raise ValueError("retained gzip trailing data")
                block = decoder.unconsumed_tail
        if not decoder.eof or total == 0:
            raise ValueError("retained gzip truncation")
    except zlib.error as error:
        raise ValueError("retained gzip framing") from error
    uncompressed.flush()
    uncompressed.seek(0)
    return total


def retained_join(
    packet_raw, receipt_raw, readback_raw, run_raw, jobs_raw, expected, owner
):
    """Only owner-selected hashes authenticate these public evidence records."""
    receipt = owner.closed(
        owner.parse_json(receipt_raw, 16384),
        (
            "schema",
            "purpose",
            "image_target",
            "source_revision",
            "workflow_blob_sha256",
            "run_id",
            "attempt",
            "job_id",
            "recipient_certificate_sha256",
            "recipient_encryption_fingerprint",
            "encrypted_bundle_sha256",
            "encrypted_bundle_bytes",
            "private_manifest_sha256",
        ),
    )
    readback = owner.closed(
        owner.parse_json(readback_raw, 16384),
        (
            "schema",
            "archive_bytes",
            "archive_sha256",
            "artifact_id",
            "attempt",
            "ciphertext_retained",
            "encrypted_bundle_bytes",
            "encrypted_bundle_sha256",
            "exact_pair",
            "gate0_accepted",
            "job_id",
            "plaintext_decrypted",
            "private_manifest_independently_verified",
            "producer_receipt_joins",
            "producer_receipt_sha256",
            "role_runtime_accepted",
            "run_id",
            "verified_at",
        ),
    )
    # Historical packet validation uses a time inside its ORIGINAL interval.
    # This is not a grant for present custody or an extension of that interval.
    preliminary = owner.parse_json(packet_raw, 16384)
    packet = owner.load_role_packet(
        packet_raw, expected[1], owner.utc(preliminary["validity"]["not_before"])
    )
    if (
        receipt["schema"] != "Gate0RoleQualificationProducerReceipt.v1"
        or receipt["purpose"] != owner.ROLE_PURPOSE
        or receipt["image_target"] != "gate0-role"
        or receipt["source_revision"] != packet["source"]["revision"]
        or receipt["workflow_blob_sha256"] != packet["source"]["workflow_blob_sha256"]
        or receipt["recipient_certificate_sha256"]
        != packet["recipient"]["certificate_sha256"]
        or receipt["recipient_encryption_fingerprint"]
        != packet["recipient"]["encryption_fingerprint"]
        or readback["schema"] != "DotmacAuthenticatedRoleRetentionReadback.v1"
        or readback["producer_receipt_sha256"] != expected[2]
    ):
        raise ValueError("retained evidence join")
    for key in ("run_id", "job_id", "encrypted_bundle_bytes"):
        owner.positive(receipt[key])
    if receipt["encrypted_bundle_bytes"] > owner.MAX_CIPHERTEXT_BYTES:
        raise ValueError("retained ciphertext budget")
    for key in ("encrypted_bundle_sha256", "private_manifest_sha256"):
        owner.sha256(receipt[key])
    owner.sha256(readback["archive_sha256"])
    for key in ("artifact_id", "archive_bytes"):
        owner.positive(readback[key])
    if type(receipt["attempt"]) is not int or receipt["attempt"] != 1:
        raise ValueError("retained attempt")
    for key in (
        "run_id",
        "attempt",
        "job_id",
        "encrypted_bundle_sha256",
        "encrypted_bundle_bytes",
    ):
        if (
            type(readback[key]) is not type(receipt[key])
            or readback[key] != receipt[key]
        ):
            raise ValueError("retained readback join")
    for key in ("ciphertext_retained", "exact_pair", "producer_receipt_joins"):
        if readback[key] is not True:
            raise ValueError("retained evidence predicate")
    for key in (
        "gate0_accepted",
        "plaintext_decrypted",
        "private_manifest_independently_verified",
        "role_runtime_accepted",
    ):
        if readback[key] is not False:
            raise ValueError("retained evidence predicate")
    run = owner.parse_json(run_raw, 1024**2)
    jobs = owner.parse_json(jobs_raw, 1024**2)
    source, github = packet["source"], packet["github"]
    for value in (
        run["id"],
        run["run_attempt"],
        run["repository"]["id"],
        run["repository"]["owner"]["id"],
        run["workflow_id"],
        run["actor"]["id"],
        run["triggering_actor"]["id"],
    ):
        owner.positive(value)
    if (
        run["id"] != receipt["run_id"]
        or run["run_attempt"] != 1
        or run["event"] != "workflow_dispatch"
        or run["head_sha"] != source["revision"]
        or run["head_branch"] != source["ref"].removeprefix("refs/heads/")
        or run["path"] != source["workflow_path"]
        or run["repository"]["full_name"] != github["repository"]
        or run["head_repository"]["full_name"] != github["repository"]
        or run["repository"]["id"] != github["repository_id"]
        or run["repository"]["owner"]["id"] != github["owner_id"]
        or run["workflow_id"] != github["workflow_id"]
        or run["actor"]["id"] != github["actor_id"]
        or run["triggering_actor"]["id"] != github["actor_id"]
        or run["status"] != "completed"
        or run["conclusion"] != "success"
    ):
        raise ValueError("retained run join")
    roster = jobs["jobs"]
    if (
        not isinstance(roster, list)
        or not 0 < len(roster) <= 100
        or type(jobs["total_count"]) is not int
        or jobs["total_count"] != len(roster)
    ):
        raise ValueError("retained job roster")
    selected = [job for job in roster if job["name"] == github["job_key"]]
    if len(selected) != 1:
        raise ValueError("retained selected job")
    job = selected[0]
    for key in ("id", "run_id", "run_attempt"):
        owner.positive(job[key])
    if (
        job["id"] != receipt["job_id"]
        or job["run_id"] != receipt["run_id"]
        or job["run_attempt"] != 1
        or job["head_sha"] != source["revision"]
        or job["status"] != "completed"
        or job["conclusion"] != "success"
    ):
        raise ValueError("retained job join")
    # Validate ORIGINAL producer times, not the current inspection clock.
    times = [
        owner.utc(value)
        for value in (
            run["created_at"],
            run["run_started_at"],
            job["started_at"],
            job["completed_at"],
            run["updated_at"],
        )
    ]
    if (
        times != sorted(times)
        or not owner.utc(packet["validity"]["not_before"]) <= times[0]
        or not times[-1] < owner.utc(packet["validity"]["expires_at"])
    ):
        raise ValueError("retained historical producer times")
    return packet, receipt


def retained_equal(actual, expected):
    """Compare closed JSON joins without Python's bool/int/float aliases."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(
            retained_equal(actual[key], value) for key, value in expected.items()
        )
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            retained_equal(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return type(expected) in {str, int, float, bool, type(None)} and actual == expected


def retained_measure(rootfs, compressed, metadata, packet, receipt, native_raw, owner):
    """Authenticate private manifests before recomputing the role data subjects."""
    build_raw = metadata["build.json"]
    if digest(build_raw) != receipt["private_manifest_sha256"]:
        raise ValueError("retained private manifest digest")
    build = owner.closed(
        owner.parse_json(build_raw, 1024**2),
        (
            "schema",
            "source",
            "producer",
            "images",
            "runtime",
            "limits",
            "footprint",
            "tool_qualification_sha256",
        ),
    )
    if build_raw != owner.canonical_json(build, 1024**2):
        raise ValueError("retained private manifest encoding")
    source = packet["source"]
    expected_source = {
        "revision": source["revision"],
        "workflow_blob_sha256": source["workflow_blob_sha256"],
        **source["files"],
    }
    if (
        build["schema"] != "Gate0RoleQualificationPrivateBuild.v1"
        or not retained_equal(
            owner.closed(build["source"], expected_source), expected_source
        )
        or not retained_equal(build["limits"], packet["limits"])
        or build["tool_qualification_sha256"] != packet["tool_qualification_sha256"]
    ):
        raise ValueError("retained build source join")
    producer = owner.closed(
        build["producer"],
        (
            "repository_id",
            "owner_id",
            "workflow_id",
            "actor_id",
            "run_id",
            "attempt",
            "job_id",
        ),
    )
    for key, value in producer.items():
        owner.positive(value)
        if value != (
            packet["github"][key] if key in packet["github"] else receipt[key]
        ):
            raise ValueError("retained producer join")
    images = owner.closed(build["images"], ("base", "role"))
    base = owner.closed(images["base"], ("reference", "image_id", "rootfs_diff_ids"))
    image = owner.closed(
        images["role"],
        (
            "target",
            "image_id",
            "source_revision_label",
            "rootfs_diff_ids",
            "inspect_sha256",
            "config_sha256",
            "config_bytes",
        ),
    )
    for summary in (base, image):
        if not isinstance(summary["image_id"], str) or not summary[
            "image_id"
        ].startswith("sha256:"):
            raise ValueError("retained image identity")
        owner.sha256(summary["image_id"][7:])
        layers = summary["rootfs_diff_ids"]
        if not isinstance(layers, list) or not 0 < len(layers) <= 256:
            raise ValueError("retained image layers")
        for layer in layers:
            if not isinstance(layer, str) or not layer.startswith("sha256:"):
                raise ValueError("retained image layers")
            owner.sha256(layer[7:])
    if (
        base["reference"] != owner.ROLE_BASE_IMAGE
        or image["target"] != "gate0-role"
        or image["source_revision_label"] != source["revision"]
        or image["config_sha256"] != image["image_id"][7:]
        or image["rootfs_diff_ids"][: len(base["rootfs_diff_ids"])]
        != base["rootfs_diff_ids"]
        or len(image["rootfs_diff_ids"]) <= len(base["rootfs_diff_ids"])
    ):
        raise ValueError("retained image summary join")
    owner.sha256(image["inspect_sha256"])
    if owner.positive(image["config_bytes"]) > 1024**2:
        raise ValueError("retained image config size")
    qualification_raw = metadata["qualification.json"]
    qualification = owner.closed(
        owner.parse_json(qualification_raw, 1024**2),
        (
            "schema",
            "purpose",
            "source_revision",
            "image_id",
            "smoke_sha256",
            "network_sha256",
            "smoke",
            "network",
            "live_readiness",
            "installed_native_qualified",
            "operationally_accepted",
            "gate0_accepted",
        ),
    )
    # Reuse the parsed semantic validator, but do NOT claim the reserialized
    # smoke/network bytes have the original diagnostic digests.
    checked = owner.parse_json(
        role_synthetic_qualification(
            owner.canonical_json(qualification["smoke"], 1024**2),
            owner.canonical_json(qualification["network"], 1024**2),
            source["revision"],
            image["image_id"],
            validation_owner=owner,
        ),
        1024**2,
    )
    for key in ("smoke_sha256", "network_sha256"):
        owner.sha256(qualification[key])
        checked[key] = qualification[key]
    if any(
        qualification[key] is not False
        for key in (
            "live_readiness",
            "installed_native_qualified",
            "operationally_accepted",
            "gate0_accepted",
        )
    ) or not retained_equal(qualification, checked):
        raise ValueError("retained qualification join")
    bounded_tar_headers(rootfs)
    with tarfile.open(fileobj=rootfs, mode="r:") as archive:
        members = role_inventory(archive)
        subjects = role_subjects(
            archive, members, source, native_pins_raw=native_raw, validation_owner=owner
        )
        files = complete_role_files(archive, members)
        footprint = {
            "entries": len(members),
            "regular_files": sum(item.isfile() for item in members.values()),
            "regular_bytes": sum(
                item.size for item in members.values() if item.isfile()
            ),
            "largest_member_bytes": max(
                (item.size for item in members.values()), default=0
            ),
            "role_tar_bytes": os.fstat(rootfs.fileno()).st_size,
        }
    limits = packet["limits"]
    if (
        files != metadata["files.json"]
        or len(files) > limits["files_manifest_bytes"]
        or footprint["entries"] > limits["rootfs_members"]
        or footprint["largest_member_bytes"] > limits["regular_member_bytes"]
        or footprint["role_tar_bytes"] > limits["rootfs_uncompressed_bytes"]
        or not retained_equal(owner.closed(build["footprint"], footprint), footprint)
    ):
        raise ValueError("retained inventory join")
    runtime = {
        "uncompressed_tar_sha256": stream_digest(rootfs),
        "uncompressed_tar_bytes": footprint["role_tar_bytes"],
        "compressed_archive_sha256": stream_digest(compressed),
        "compressed_archive_bytes": os.fstat(compressed.fileno()).st_size,
        "files_manifest_sha256": digest(files),
        "files_manifest_bytes": len(files),
        "qualification_manifest_sha256": digest(qualification_raw),
        "qualification_manifest_bytes": len(qualification_raw),
        **subjects,
    }
    if not retained_equal(owner.closed(build["runtime"], runtime), runtime):
        raise ValueError("retained runtime join")
    return footprint


def retained_owner(stream, expected):
    """Load ONLY the captured, pinned current inspector-owned helper source.

    The ordinary sibling loader could reopen a replaced path before final
    refusal. This fixed loader consumes the already held helper bytes and never
    accepts a module/path/code callback from retained data. No retained producer
    source is loaded. Pure validators receive this one current owner explicitly.
    """
    import importlib.machinery
    import importlib.util

    stream.seek(0)
    raw = stream.read(1024**2 + 1)
    stream.seek(0)
    if len(raw) > 1024**2 or digest(raw) != expected:
        raise ValueError("retained inspector helper pin")
    path = str(Path(__file__).absolute().with_name("retain_gate0_publisher.py"))

    class CapturedInspectorLoader(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            if fullname != "retained_current_inspector_owner":
                raise ValueError("retained inspector helper module")
            return self.source_to_code(raw, path)

    loader = CapturedInspectorLoader("retained_current_inspector_owner", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise ValueError("retained inspector helper module")
    owner = importlib.util.module_from_spec(spec)
    loader.exec_module(owner)
    return owner


def retained_stat(info):
    # Reads may update atime; byte/ownership/replacement coordinates may not move.
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def retained_directory(path, held):
    """Hold every ancestry component and forbid symlink traversal."""
    directories = []
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    held.callback(os.close, descriptor)
    for component in path.parts[1:]:
        child = os.open(
            component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
        )
        held.callback(os.close, child)
        info = os.fstat(child)
        if info.st_uid not in {0, os.getuid()} or (
            info.st_mode & 0o022
            and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        ):
            raise ValueError("retained private ancestry")
        directories.append((descriptor, component, child, info))
        descriptor = child
    return descriptor, directories


def role_retained_inspect(private: Path, expected) -> None:
    """Fixed data inspection only; operational custody authority is external."""
    import contextlib
    import tempfile

    if len(expected) != 9 or any(
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in expected
    ):
        raise ValueError("retained expected hashes")
    if not private.is_absolute() or any(part in {".", ".."} for part in private.parts):
        raise ValueError("retained private path")
    with contextlib.ExitStack() as held:
        descriptor, directories = retained_directory(private, held)
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("retained private directory")
        streams, identities = [], []
        source_paths = (
            Path(__file__).absolute(),
            Path(__file__).absolute().with_name("retain_gate0_publisher.py"),
        )
        for index, path in enumerate((*RETAINED_INPUTS, *source_paths)):
            # Source code is fixed trusted inspector code, never an archive path.
            if index < len(RETAINED_INPUTS):
                fd = os.open(
                    path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptor
                )
                parent_fd, name = descriptor, path
            else:
                parent_fd, source_directories = retained_directory(path.parent, held)
                directories.extend(source_directories)
                name = path.name
                fd = os.open(
                    name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd
                )
            stream = held.enter_context(os.fdopen(fd, "rb"))
            info = os.fstat(fd)
            cap = RETAINED_OUTER_BYTES if index == 0 else 1024**2
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or not 0 < info.st_size <= cap
                or info.st_mode & (0o077 if index < len(RETAINED_INPUTS) else 0o022)
                or (info.st_dev, info.st_ino)
                in {(old.st_dev, old.st_ino) for *_, old in identities}
                or stream_digest(stream, cap) != expected[index]
            ):
                raise ValueError("retained held input")
            streams.append(stream)
            identities.append((parent_fd, name, info))
        # The fixed sibling is pinned BEFORE importing its pure validators.
        owner = retained_owner(streams[-1], expected[-1])
        packet, receipt = retained_join(
            *(streams[index].read() for index in (1, 2, 3, 5, 6)), expected, owner
        )
        native_raw = streams[4].read()
        if digest(native_raw) != packet["source"]["files"]["native_artifacts_sha256"]:
            raise ValueError("retained historical native pin")
        # Anonymous files are unlinked at creation, mode0600, and bounded by the
        # streaming loops. No member pathname is ever extracted or executed.
        with (
            tempfile.TemporaryFile(mode="w+b", dir=private) as compressed,
            tempfile.TemporaryFile(mode="w+b", dir=private) as rootfs,
        ):
            metadata = retained_outer(streams[0], compressed, packet["limits"])
            retained_gzip(
                compressed, rootfs, packet["limits"]["rootfs_uncompressed_bytes"]
            )
            footprint = retained_measure(
                rootfs, compressed, metadata, packet, receipt, native_raw, owner
            )
        for parent, component, child, initial in directories:
            current = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if current != os.fstat(child) or (
                current.st_dev,
                current.st_ino,
                current.st_mode,
                current.st_uid,
            ) != (initial.st_dev, initial.st_ino, initial.st_mode, initial.st_uid):
                raise ValueError("retained directory changed")
        for index, (parent, name, initial) in enumerate(identities):
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                retained_stat(current)
                != retained_stat(os.fstat(streams[index].fileno()))
                or retained_stat(current) != retained_stat(initial)
                or stream_digest(
                    streams[index], RETAINED_OUTER_BYTES if index == 0 else 1024**2
                )
                != expected[index]
            ):
                raise ValueError("retained input changed")
        result = owner.canonical_json(
            {
                "schema": "DotmacRoleRetainedInspection.v1",
                "verdict": "authenticated-data-only",
                "input_sha256": dict(
                    zip(
                        (*RETAINED_INPUTS, "inspector", "retention_helper"),
                        expected,
                        strict=True,
                    )
                ),
                "source_revision": packet["source"]["revision"],
                "run_id": receipt["run_id"],
                "job_id": receipt["job_id"],
                "footprint": footprint,
                "live_readiness": False,
                "installed_native_qualified": False,
                "operationally_accepted": False,
                "gate0_accepted": False,
            },
            16384,
        )
        fd = os.open(
            "retained-inspection.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        with os.fdopen(fd, "wb") as output:
            output.write(result)


def role_inspect(private: Path) -> None:
    owner = _role_retention_owner()
    owner.role_private_directory(str(private))
    # The retention owner authenticates source, tools and current job before
    # importing this owner, then rechecks this same held export before compression.
    owner.role_inspection(private)


def shape() -> None:
    interpreter = Path("/opt/venv/bin/python3.12")
    cli = Path("/opt/venv/bin/dotmac-platform")
    for path in (interpreter, cli):
        info = path.lstat()
        # Source-aware constraints from lifecycle._read_fd/_protected, used by
        # courier._installed_public_selection; no invented host qualification.
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == 0
            and not info.st_mode & 0o022
            and 0 < info.st_size <= 32 * 1024 * 1024
        ):
            raise ValueError("courier protected file shape")
        for parent in path.parents:
            info = parent.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
            ):
                raise ValueError("courier protected ancestry")
    if os.readlink("/proc/self/exe") != str(interpreter):
        raise ValueError("actual proc interpreter path")
    if cli.read_bytes().splitlines()[0] != b"#!/opt/venv/bin/python3.12":
        raise ValueError("generated CLI shebang")
    modules = {}
    for module in (
        "vendor_cp.cli",
        "vendor_cp.cli.owners",
        "vendor_cp.deployment.gate0_framing",
        "vendor_cp.deployment.gate0_runner_lifecycle",
        "vendor_cp.deployment.gate0_runner_lifecycle_courier",
    ):
        path = Path(importlib.import_module(module).__file__)
        if not str(path).startswith("/opt/venv/lib/python3.12/site-packages/"):
            raise ValueError("module is not installed")
        info = path.lstat()
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == 0
            and not info.st_mode & 0o022
            and 0 < info.st_size <= 1024 * 1024
        ):
            raise ValueError("courier source protected file shape")
        modules[module] = str(path)
    commands = [
        ["--version"],
        ["--format", "json", "diagnose", "self", "--strict"],
        ["--format", "json", "diagnose", "version"],
        ["--format", "json", "diagnose", "composition"],
    ]
    owners = subprocess.check_output(  # noqa: S603 -- fixed installed diagnostic
        [str(cli), "--format", "json", "diagnose", "owners"], timeout=120
    )
    for owner in json.loads(owners)["data"]["owners"]:
        commands.append([*owner["command"].split(), "--help"])
    for arguments in commands:
        subprocess.run(  # noqa: S603 -- installed owner-derived help only
            [str(cli), *arguments],
            check=True,
            stdout=subprocess.DEVNULL,  # noqa: S603 -- installed owner-derived help only
            timeout=120,
        )
    print(
        json.dumps(
            {
                "schema": "Gate0PublisherShape.v1",
                "status": "shape_only",
                "proc_self_exe": os.readlink("/proc/self/exe"),
                "modules": modules,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["shape"]:
        shape()
    elif len(sys.argv) == 12 and sys.argv[1] == "role-retained-inspect":
        try:
            role_retained_inspect(Path(sys.argv[2]), sys.argv[3:])
        except Exception:
            raise SystemExit("retained inspection refused") from None
    elif len(sys.argv) == 3 and sys.argv[1] == "role-inspect":
        role_inspect(Path(sys.argv[2]))
    elif len(sys.argv) in {6, 7} and sys.argv[1] == "inspect":
        inspect(*(Path(argument) for argument in sys.argv[2:]))
    else:
        raise SystemExit("expected shape or inspect PRODUCTION PUBLISHER SHAPE OUTPUT")
