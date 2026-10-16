"""Synthetic stdlib checks for build-only publisher refusal boundaries."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / ".github/candidate" / (name + ".py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSPECT = load("inspect_gate0_publisher")
PREPARE = load("prepare_gate0_publisher")


def archive(items):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as output:
        for name, kind, mode, link in items:
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.linkname = kind, mode, link
            output.addfile(item)
    stream.seek(0)
    return tarfile.open(fileobj=stream, mode="r:")


class PublisherTarRefusalTests(unittest.TestCase):
    def test_traversal_and_noncanonical_names(self):
        for name in ("../x", "/x", "a/../b", "a//b", "./a", "a\\b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                INSPECT.member_name(name)

    def test_duplicate_and_special_members(self):
        for items in (
            [("a", tarfile.REGTYPE, 0o644, "")] * 2,
            [("device", tarfile.CHRTYPE, 0o644, "")],
        ):
            with archive(items) as subject, self.assertRaises(ValueError):
                INSPECT.inventory(subject, publisher=True)

    def test_protected_link_and_writable_ancestor(self):
        roots = [
            ("opt", tarfile.DIRTYPE, 0o755, ""),
            ("opt/venv", tarfile.DIRTYPE, 0o755, ""),
            ("opt/venv/bin", tarfile.DIRTYPE, 0o755, ""),
        ]
        for bad in (
            ("opt/venv/bin/python3.12", tarfile.SYMTYPE, 0o777, "python"),
            ("opt/venv/bin/python3.12", tarfile.LNKTYPE, 0o755, "x"),
            ("opt/venv/bin/unsafe", tarfile.SYMTYPE, 0o777, "../../etc/passwd"),
        ):
            with archive([*roots, bad]) as subject, self.assertRaises(ValueError):
                INSPECT.inventory(subject, publisher=True)
        roots[0] = ("opt", tarfile.DIRTYPE, 0o777, "")
        with archive(roots) as subject, self.assertRaises(ValueError):
            INSPECT.inventory(subject, publisher=True)

    def test_no_checkout_cache_or_credential_material(self):
        for name in (
            "app/src/a.py",
            "root/.cache/pip/a",
            "run/secrets/token",
            "root/.ssh/id_rsa",
            "app/poetry.lock",
        ):
            with archive([(name, tarfile.REGTYPE, 0o600, "")]) as subject:
                with self.assertRaises(ValueError):
                    INSPECT.inventory(subject, publisher=True)

    def test_only_explicit_generated_closure_exceptions(self):
        self.assertTrue(INSPECT.excluded("opt/venv/bin/python3.12"))
        self.assertTrue(
            INSPECT.excluded(
                "opt/venv/lib/python3.12/site-packages/dotmac_vendor_control_plane-1.dist-info/RECORD"
            )
        )
        self.assertFalse(
            INSPECT.excluded(
                "opt/venv/lib/python3.12/site-packages/dependency-1.dist-info/RECORD"
            )
        )
        self.assertFalse(
            INSPECT.excluded(
                "opt/venv/lib/python3.12/site-packages/vendor_cp/cli/owners.py"
            )
        )


class PublisherPreparationTests(unittest.TestCase):
    def test_manifest_binds_single_wheel_hash_and_refuses_extra_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()
            name = "dotmac_vendor_control_plane-1-py3-none-any.whl"
            wheel = root / "dist" / name
            wheel.write_bytes(b"synthetic wheel bytes")
            entry = {
                "filename": name,
                "size_bytes": wheel.stat().st_size,
                "sha256": "sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest(),
            }
            (root / "distributions.json").write_text(
                json.dumps(
                    {"contract": "dotmac-distribution-digests/1", "files": [entry]}
                )
            )
            self.assertEqual(PREPARE.wheel_from_manifest(root), wheel)
            wheel.write_bytes(b"different bytes")
            with self.assertRaises(ValueError):
                PREPARE.wheel_from_manifest(root)

    def test_copy_preserves_fresh_interpreters_and_refuses_escaping_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "destination"
            source.mkdir()
            destination.mkdir()
            for name in PREPARE.INTERPRETERS:
                (source / name).write_bytes(b"builder")
                (destination / name).write_bytes(b"fresh")
            (source / "dependency").write_bytes(b"dependency")
            PREPARE.copy_bin(source, destination)
            for name in PREPARE.INTERPRETERS:
                self.assertEqual((destination / name).read_bytes(), b"fresh")
            (source / "escape").symlink_to("../outside")
            with self.assertRaises(ValueError):
                PREPARE.copy_bin(source, destination)
