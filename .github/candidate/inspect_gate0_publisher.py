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

PREFIX = "opt/venv/"
CP_DIST = "dotmac_vendor_control_plane-"
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


def member_name(name: str) -> str:
    # Docker export writes relative canonical POSIX paths (directories may end /).
    result = name.removesuffix("/")
    if (
        not result
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
        name = member_name(item.name)
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
                digest(read(archive, members, name)),
            )
        elif item.isdir():
            result[name] = ("directory", item.mode & 0o777)
        elif item.issym():
            result[name] = ("symlink", item.linkname)
        else:
            raise ValueError("unsupported closure member")
    return result


def inspect(production: Path, publisher: Path, shape: Path, output: Path) -> None:
    with tarfile.open(production, "r:") as prod, tarfile.open(publisher, "r:") as pub:
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
                expected = archive.read(owner)
                if (
                    read(pub, right, installed) != expected
                    or read(prod, left, installed) != expected
                ):
                    raise ValueError("installed source-owner bytes differ from wheel")
        if closure(prod, left) != closure(pub, right):
            raise ValueError(
                "dependency closure differs outside explicit generated exceptions"
            )
        measured = json.loads(shape.read_bytes())
        if (
            measured.get("schema") != "Gate0PublisherShape.v1"
            or measured.get("status") != "shape_only"
        ):
            raise ValueError("shape measurement missing")
        output.write_text(
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
                    "production_rootfs_sha256": file_digest(production),
                    "publisher_rootfs_sha256": file_digest(publisher),
                    "dependency_closure_entries": len(closure(pub, right)),
                },
                sort_keys=True,
            )
            + "\n"
        )
        output.chmod(0o600)


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
    elif len(sys.argv) == 6 and sys.argv[1] == "inspect":
        inspect(*(Path(argument) for argument in sys.argv[2:]))
    else:
        raise SystemExit("expected shape or inspect PRODUCTION PUBLISHER SHAPE OUTPUT")
