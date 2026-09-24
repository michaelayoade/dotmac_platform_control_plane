"""Verify exact local wheel bytes and installed runtime provenance."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from dataclasses import dataclass
from email.parser import BytesParser
from importlib import metadata
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)
from packaging.version import Version

LOCK = Path(__file__).with_name("artifacts.json")
PUBLIC_LOCK = Path(__file__).with_name("public-requirements.lock")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_REQUIREMENT = re.compile(r"([a-z0-9-]+)==([0-9][A-Za-z0-9.!+_-]*)\s+\\\Z")
_HASH = re.compile(r"\s+--hash=sha256:([0-9a-f]{64})(?:\s+\\)?\Z")


@dataclass(frozen=True, slots=True)
class PublicWheelPin:
    version: str
    hashes: frozenset[str]


def read_lock() -> dict[str, Any]:
    lock: dict[str, Any] = json.loads(LOCK.read_text())
    if set(lock) != {"artifacts", "harness_dependencies"}:
        raise ValueError("artifact lock shape changed")
    return lock


def read_public_lock(path: Path = PUBLIC_LOCK) -> dict[str, PublicWheelPin]:
    """Refuse an unhashed, mutable, duplicate, or incomplete public package."""
    pins: dict[str, PublicWheelPin] = {}
    current: str | None = None
    current_version: str | None = None
    hashes: set[str] = set()
    lines = path.read_text().splitlines()
    if "--only-binary=:all:" not in lines:
        raise ValueError("public dependency lock must install wheels only")
    for line in lines:
        if not line or line.startswith("#") or line == "--only-binary=:all:":
            continue
        requirement = _REQUIREMENT.fullmatch(line)
        if requirement is not None:
            if current is not None:
                if not hashes or current_version is None:
                    raise ValueError(f"{current} has no wheel SHA-256")
                pins[current] = PublicWheelPin(current_version, frozenset(hashes))
            name, version = requirement.groups()
            if name in pins or name == current:
                raise ValueError(f"duplicate public dependency {name}")
            current, current_version, hashes = name, version, set()
            continue
        digest = _HASH.fullmatch(line)
        if digest is None or current is None:
            raise ValueError("public dependency lock has an unrecognized line")
        if digest.group(1) in hashes:
            raise ValueError(f"duplicate public wheel hash for {current}")
        hashes.add(digest.group(1))
    if current is None or current_version is None or not hashes:
        raise ValueError("public dependency lock ends without a wheel SHA-256")
    pins[current] = PublicWheelPin(current_version, frozenset(hashes))
    if pins.get("greenlet") is None or pins["greenlet"].version != "3.5.4":
        raise ValueError(
            "SQLAlchemy's Linux greenlet dependency is missing or unpinned"
        )
    if len(pins) != 31:
        raise ValueError("public dependency closure differs from the 31-package lock")
    return pins


def verify_wheels(control_wheel: Path, kernel_wheel: Path) -> None:
    """Only wheel paths are accepted; no branch, checkout or mutable locator."""
    lock = read_lock()["artifacts"]
    for name, path in (
        ("dotmac-deployment-control", control_wheel),
        ("dotmac-kernel", kernel_wheel),
    ):
        spec = lock[name]
        if not isinstance(path, Path) or not path.is_file() or path.suffix != ".whl":
            raise ValueError(f"{name} requires an existing wheel path")
        if path.name != spec["filename"]:
            raise ValueError(f"{name} wheel filename differs from lock")
        if not _HEX40.fullmatch(spec["source_commit"]) or not _HEX64.fullmatch(
            spec["sha256"]
        ):
            raise ValueError(f"{name} lock lacks immutable coordinates")
        if "tag_object" in spec and not _HEX40.fullmatch(spec["tag_object"]):
            raise ValueError(f"{name} tag object is not immutable")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != spec["sha256"]:
            raise ValueError(f"{name} wheel bytes differ from lock")
        with ZipFile(path) as wheel:
            entries = [n for n in wheel.namelist() if n.endswith(".dist-info/METADATA")]
            if len(entries) != 1:
                raise ValueError(f"{name} wheel has no unique METADATA")
            info = BytesParser().parsebytes(wheel.read(entries[0]))
        if info["Name"] != name or info["Version"] != spec["version"]:
            raise ValueError(f"{name} wheel METADATA differs from lock")
        if name == "dotmac-deployment-control" and (
            "dotmac-kernel (>=0.1.0a100)" not in info.get_all("Requires-Dist", [])
        ):
            raise ValueError("Control a14 kernel floor differs from lock")


def _public_wheel_identity(path: Path) -> tuple[str, str]:
    try:
        filename_name, filename_version, _, _ = parse_wheel_filename(path.name)
        with ZipFile(path) as wheel:
            entries = [n for n in wheel.namelist() if n.endswith(".dist-info/METADATA")]
            if len(entries) != 1:
                raise ValueError(f"{path.name} has no unique METADATA")
            info = BytesParser().parsebytes(wheel.read(entries[0]))
    except (BadZipFile, InvalidWheelFilename) as error:
        raise ValueError(f"invalid public wheel {path.name}") from error
    metadata_name = canonicalize_name(str(info["Name"]))
    metadata_version = str(info["Version"])
    if filename_name != metadata_name or filename_version != Version(metadata_version):
        raise ValueError(f"{path.name} filename and METADATA disagree")
    return metadata_name, metadata_version


def verify_public_wheelhouse(wheelhouse: Path) -> dict[str, Path]:
    """Bind every public runtime distribution to one hash-approved wheel."""
    if not wheelhouse.is_dir():
        raise ValueError("public wheelhouse must be an existing directory")
    pins = read_public_lock()
    selected: dict[str, Path] = {}
    for path in sorted(wheelhouse.glob("*.whl")):
        name, version = _public_wheel_identity(path)
        if name not in pins:
            raise ValueError(f"unknown public wheel {name}")
        if name in selected:
            raise ValueError(f"duplicate public wheel {name}")
        if version != pins[name].version:
            raise ValueError(f"{name} wheel version differs from public lock")
        selected[name] = path
    for name, path in selected.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest not in pins[name].hashes:
            raise ValueError(f"{name} wheel bytes differ from public lock")
    missing = set(pins) - set(selected)
    if missing:
        raise ValueError(f"public wheelhouse lacks: {sorted(missing)}")
    return selected


def verify_installed(
    control_wheel: Path, kernel_wheel: Path, public_wheelhouse: Path
) -> None:
    """Runtime imports must resolve to the named installed distributions."""
    lock = read_lock()
    for name, wheel_path in (
        ("dotmac-deployment-control", control_wheel),
        ("dotmac-kernel", kernel_wheel),
    ):
        spec = lock["artifacts"][name]
        dist = metadata.distribution(name)
        if dist.version != spec["version"]:
            raise RuntimeError(f"installed {name} version differs from artifact lock")
        root = Path(str(dist.locate_file(""))).resolve()
        package = name.replace("-", "_")
        import_path = Path(str(dist.locate_file(f"{package}/__init__.py"))).resolve()
        if not import_path.is_file() or not import_path.is_relative_to(root):
            raise RuntimeError(f"{name} is not imported from its installation")
        origin = importlib.util.find_spec(package)
        if (
            origin is None
            or origin.origin is None
            or Path(origin.origin).resolve() != import_path
        ):
            raise RuntimeError(f"{name} import resolves outside its installation")
        with ZipFile(wheel_path) as wheel:
            for entry in wheel.namelist():
                if not entry.startswith(package + "/") or entry.endswith("/"):
                    continue
                installed = Path(str(dist.locate_file(entry)))
                if not installed.is_file() or installed.read_bytes() != wheel.read(
                    entry
                ):
                    raise RuntimeError(f"installed {name} bytes differ at {entry}")
    public_pins = read_public_lock()
    public_wheels = verify_public_wheelhouse(public_wheelhouse)
    for name, version in lock["harness_dependencies"].items():
        if name not in public_pins or public_pins[name].version != version:
            raise RuntimeError(f"{name} direct version differs from public hash lock")
    for name, pin in public_pins.items():
        dist = metadata.distribution(name)
        if dist.version != pin.version:
            raise RuntimeError(f"installed {name} version differs from artifact lock")
        with ZipFile(public_wheels[name]) as wheel:
            for entry in wheel.namelist():
                if (
                    entry.endswith("/")
                    or entry.endswith(".dist-info/RECORD")
                    or ".data/headers/" in entry
                ):
                    continue
                # RECORD is installer-owned. Wheel ``.data/headers`` members are
                # build headers that pip relocates outside site-packages; they are
                # not imported at runtime. Every code, native extension, package
                # data and other metadata byte must equal the selected wheel.
                installed = Path(str(dist.locate_file(entry)))
                if not installed.is_file() or installed.read_bytes() != wheel.read(
                    entry
                ):
                    raise RuntimeError(
                        f"installed {name} bytes differ from selected wheel at {entry}"
                    )
