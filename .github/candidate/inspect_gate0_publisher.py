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


def complete_files(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo]
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
            {"schema": "Gate0PublisherFiles.v1", "files": rows},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        + b"\n"
    )
    if len(raw) > MAX_FILES_BYTES:
        raise ValueError("files manifest budget")
    return raw


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
    elif len(sys.argv) in {6, 7} and sys.argv[1] == "inspect":
        inspect(*(Path(argument) for argument in sys.argv[2:]))
    else:
        raise SystemExit("expected shape or inspect PRODUCTION PUBLISHER SHAPE OUTPUT")
