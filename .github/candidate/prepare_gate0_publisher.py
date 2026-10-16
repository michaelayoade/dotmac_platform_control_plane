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


def copy_bin(source: Path, destination: Path) -> None:
    for entry in source.iterdir():
        if entry.name in INTERPRETERS:
            continue
        target = destination / entry.name
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            link = os.readlink(entry)
            # Dependency scripts may link to sibling scripts, never escape bin.
            if Path(link).name != link or link in INTERPRETERS:
                raise ValueError("unsafe dependency bin link")
            resolved = entry.resolve(strict=True)
            if resolved.parent != source or not resolved.is_file():
                raise ValueError("dependency bin link target")
            target.unlink(missing_ok=True)
            target.symlink_to(link)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            target.unlink(missing_ok=True)
            shutil.copyfile(entry, target)
            target.chmod(stat.S_IMODE(info.st_mode) & ~0o022)
        else:
            raise ValueError("unsupported dependency bin entry")


def main() -> None:
    source = Path("/mnt/builder-venv")
    destination = Path("/opt/venv")
    wheel = wheel_from_manifest(Path("/app"))
    # Both stages use the identical pinned base and CPython ABI and prefix.
    shutil.copytree(
        source / "lib", destination / "lib", dirs_exist_ok=True, symlinks=True
    )
    copy_bin(source / "bin", destination / "bin")
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
    for directory, directories, files in os.walk(destination, followlinks=False):
        for name in [*directories, *files]:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o022)
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
