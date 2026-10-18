"""Build-only same-prefix Python closure copy and offline CP wheel installation.

This prepares candidate bytes only. It grants no installed-host qualification.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

INTERPRETERS = frozenset({"python", "python3", "python3.12"})
PRESERVED_PREFIX_ENTRIES = frozenset({"pyvenv.cfg"})


def wheel_from_manifest(root: Path) -> Path:
    document = json.loads((root / "distributions.json").read_bytes())
    if document.get("contract") != "dotmac-distribution-digests/1":
        raise ValueError("distribution manifest contract")
    entries = document["files"]
    names = [entry["filename"] for entry in entries]
    if len(names) != len(set(names)) or any(Path(n).name != n for n in names):
        raise ValueError("distribution filename")
    wheels = [n for n in names if n.endswith(".whl")]
    if len(wheels) != 1 or not wheels[0].startswith("dotmac_vendor_control_plane-"):
        raise ValueError("exactly one CP wheel required")
    if set(p.name for p in (root / "dist").iterdir()) != set(names):
        raise ValueError("distribution inventory")
    for entry in entries:
        path = root / "dist" / entry["filename"]
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("distribution must be ordinary file")
        if (
            info.st_size != entry["size_bytes"]
            or ("sha256:" + hashlib.sha256(path.read_bytes()).hexdigest())
            != entry["sha256"]
        ):
            raise ValueError("distribution digest")
    return root / "dist" / wheels[0]


def _validate_entry(path: Path, expected_uid: int, *, allow_link: bool = False) -> None:
    info = path.lstat()
    if info.st_uid != expected_uid:
        raise ValueError("environment entry owner")
    if stat.S_ISDIR(info.st_mode):
        if info.st_mode & 0o022:
            raise ValueError("writable environment directory")
    elif stat.S_ISREG(info.st_mode):
        if info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError("unsafe environment file")
    elif stat.S_ISLNK(info.st_mode) and allow_link:
        return
    else:
        raise ValueError("unsupported environment entry")


def _validate_environment(source: Path, expected_uid: int) -> None:
    for entry in source.iterdir():
        if entry.name == "pyvenv.cfg":
            continue
        if entry.name == "bin":
            _validate_entry(entry, expected_uid)
            for child in entry.iterdir():
                if child.name in INTERPRETERS:
                    continue
                _validate_entry(child, expected_uid, allow_link=True)
                if child.is_symlink():
                    _validate_bin_link(entry, child, expected_uid)
                elif child.is_dir():
                    raise ValueError("dependency bin directory")
            continue
        _validate_entry(entry, expected_uid, allow_link=True)
        if entry.is_symlink():
            if entry.name != "lib64" or os.readlink(entry) != "lib":
                raise ValueError("unsafe environment link")
            target = source / "lib"
            if not stat.S_ISDIR(target.lstat().st_mode):
                raise ValueError("unsafe environment link target")
            _validate_entry(target, expected_uid)
            for nested in target.rglob("*"):
                _validate_entry(nested, expected_uid)
        elif entry.is_dir():
            for nested in entry.rglob("*"):
                _validate_entry(nested, expected_uid)


def _validate_bin_link(source: Path, entry: Path, expected_uid: int) -> None:
    link = os.readlink(entry)
    if Path(link).name != link or link in INTERPRETERS:
        raise ValueError("unsafe dependency bin link")
    target = source / link
    _validate_entry(target, expected_uid)


def copy_bin(source: Path, destination: Path, expected_uid: int = 0) -> None:
    for entry in source.iterdir():
        if entry.name in INTERPRETERS:
            continue
        _validate_entry(entry, expected_uid, allow_link=True)
        if entry.is_symlink():
            _validate_bin_link(source, entry, expected_uid)
        elif not stat.S_ISREG(entry.lstat().st_mode):
            raise ValueError("unsupported dependency bin entry")
    for entry in source.iterdir():
        if entry.name in INTERPRETERS:
            continue
        target = destination / entry.name
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            link = os.readlink(entry)
            target.unlink(missing_ok=True)
            target.symlink_to(link)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            target.unlink(missing_ok=True)
            _validate_entry(entry, expected_uid)
            shutil.copy2(entry, target)
        else:
            raise ValueError("unsupported dependency bin entry")


def copy_environment(source: Path, destination: Path, expected_uid: int) -> None:
    """Mirror a validated environment while retaining the fresh interpreter."""
    _validate_environment(source, expected_uid)
    preserved = set(PRESERVED_PREFIX_ENTRIES)
    preserved.update(f"bin/{name}" for name in INTERPRETERS)
    for entry in destination.iterdir():
        relative = entry.relative_to(destination).as_posix()
        if relative in preserved:
            continue
        if relative == "bin" and entry.is_dir() and not entry.is_symlink():
            for child in entry.iterdir():
                if child.name not in INTERPRETERS:
                    if child.is_symlink() or child.is_file():
                        child.unlink()
                    elif child.is_dir():
                        shutil.rmtree(child)
                    else:
                        raise ValueError("unsupported destination entry")
            continue
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
        elif entry.is_dir():
            shutil.rmtree(entry)
        else:
            raise ValueError("unsupported destination entry")
    for entry in source.iterdir():
        if entry.name == "pyvenv.cfg":
            continue
        target = destination / entry.name
        if entry.name == "bin":
            target.mkdir(exist_ok=True)
            copy_bin(entry, target, expected_uid)
            target.chmod(stat.S_IMODE(entry.lstat().st_mode))
        elif entry.is_symlink():
            target.symlink_to(os.readlink(entry))
        elif entry.is_dir():
            shutil.copytree(entry, target, symlinks=True)
        else:
            shutil.copy2(entry, target)


def main() -> None:
    source = Path("/mnt/builder-venv")
    destination = Path("/opt/venv")
    wheel = wheel_from_manifest(Path("/app"))
    # Both stages use the identical pinned base and CPython ABI and prefix.
    copy_environment(source, destination, expected_uid=0)
    for directory in (destination / "lib").rglob("__pycache__"):
        shutil.rmtree(directory)
    subprocess.run(  # noqa: S603 -- fixed offline installer and verified wheel
        [
            str(destination / "bin/python3.12"),
            "-I",
            "-B",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--force-reinstall",
            str(wheel),
        ],
        check=True,
    )
    _validate_environment(destination, expected_uid=0)
    interpreter = destination / "bin/python3.12"
    info = interpreter.lstat()
    if not (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == 0
        and not info.st_mode & 0o022
    ):
        raise ValueError("interpreter violates courier _read_fd constraints")
    if (destination / "bin/dotmac-platform").read_bytes().splitlines()[0] != (
        b"#!/opt/venv/bin/python3.12"
    ):
        raise ValueError("installer did not generate exact interpreter shebang")


if __name__ == "__main__":
    main()
