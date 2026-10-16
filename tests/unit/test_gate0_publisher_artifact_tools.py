"""Synthetic stdlib checks for build-only publisher refusal boundaries."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
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

    def test_structural_difference_counts_are_bounded(self):
        counts = INSPECT.bounded_structural_closure_difference_counts(
            {
                "planted/private/path": ("file", 0o644, "secret-content-digest"),
                "mode": ("directory", 0o755),
                "link": ("symlink", "private-target"),
                "kind": ("file", 0o644, "a"),
                "missing": ("directory", 0o755),
            },
            {
                "planted/private/path": ("file", 0o600, "other-secret-digest"),
                "mode": ("directory", 0o700),
                "link": ("symlink", "other-private-target"),
                "kind": ("directory", 0o755),
                "extra/private": ("file", 0o600, "extra-secret"),
            },
        )
        self.assertEqual(
            counts,
            {
                "missing": 1,
                "extra": 1,
                "kind": 1,
                "mode": 2,
                "content": 1,
                "link_target": 1,
            },
        )
        encoded = json.dumps(counts, sort_keys=True)
        for secret in ("planted", "private", "secret-content", "other-secret"):
            self.assertNotIn(secret, encoded)
        self.assertTrue(all(type(value) is int for value in counts.values()))


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
            PREPARE.copy_bin(source, destination, os.getuid())
            for name in PREPARE.INTERPRETERS:
                self.assertEqual((destination / name).read_bytes(), b"fresh")
            (source / "escape").symlink_to("../outside")
            with self.assertRaises(ValueError):
                PREPARE.copy_bin(source, destination, os.getuid())

    def test_copy_environment_mirrors_prefix_and_preserves_fresh_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "destination"
            (source / "bin").mkdir(parents=True)
            (source / "bin").chmod(0o750)
            destination.mkdir()
            (source / "pyvenv.cfg").write_text("builder config")
            for name in PREPARE.INTERPRETERS:
                (source / "bin" / name).write_text("builder")
                (destination / "bin").mkdir(exist_ok=True)
                (destination / "bin" / name).write_text("fresh interpreter")
            for name in ("lib", "include", "share"):
                (source / name).mkdir()
                payload = source / name / "payload.dat"
                payload.write_bytes(name.encode())
                payload.chmod(0o640)
            (destination / "pyvenv.cfg").write_text("fresh config")
            (destination / "stale").write_text("remove me")
            (destination / "include").mkdir()
            (destination / "include" / "leftover").write_text("remove me")

            PREPARE.copy_environment(source, destination, os.getuid())

            self.assertEqual(stat.S_IMODE((destination / "bin").stat().st_mode), 0o750)
            self.assertEqual((destination / "pyvenv.cfg").read_text(), "fresh config")
            self.assertFalse((destination / "stale").exists())
            self.assertFalse((destination / "include" / "leftover").exists())
            for name in PREPARE.INTERPRETERS:
                self.assertEqual(
                    (destination / "bin" / name).read_text(), "fresh interpreter"
                )
            for name in ("lib", "include", "share"):
                self.assertEqual(
                    (destination / name / "payload.dat").read_bytes(), name.encode()
                )
                self.assertEqual(
                    stat.S_IMODE((destination / name / "payload.dat").stat().st_mode),
                    0o640,
                )

    def test_copy_environment_refuses_unsafe_source_before_destination_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "destination"
            (source / "bin").mkdir(parents=True)
            destination.mkdir()
            (source / "share").mkdir()
            unsafe = source / "share" / "unsafe"
            unsafe.write_text("unsafe")
            unsafe.chmod(0o666)
            sentinel = destination / "sentinel"
            sentinel.write_text("untouched")
            with self.assertRaises(ValueError):
                PREPARE.copy_environment(source, destination, os.getuid())
            self.assertEqual(sentinel.read_text(), "untouched")

    def test_copy_environment_refuses_special_and_escaping_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "destination"
            (source / "bin").mkdir(parents=True)
            destination.mkdir()
            (source / "share").mkdir()
            (source / "share" / "escape").symlink_to("../../outside")
            with self.assertRaises(ValueError):
                PREPARE.copy_environment(source, destination, os.getuid())
            self.assertEqual(list(destination.iterdir()), [])

            (source / "share" / "escape").unlink()
            os.mkfifo(source / "share" / "special")
            with self.assertRaises(ValueError):
                PREPARE.copy_environment(source, destination, os.getuid())
            self.assertEqual(list(destination.iterdir()), [])

    def test_copy_environment_allows_only_direct_bin_and_lib64_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "destination"
            (source / "bin").mkdir(parents=True)
            (source / "lib").mkdir()
            (source / "bin" / "target").write_text("direct target")
            (source / "bin" / "direct").symlink_to("target")
            (source / "lib64").symlink_to("lib")
            destination.mkdir()

            PREPARE.copy_environment(source, destination, os.getuid())

            self.assertEqual(os.readlink(destination / "bin" / "direct"), "target")
            self.assertTrue((destination / "lib64").is_symlink())
            self.assertEqual(os.readlink(destination / "lib64"), "lib")

            (source / "bin" / "chain").symlink_to("direct")
            sentinel = destination / "sentinel"
            sentinel.write_text("untouched")
            with self.assertRaises(ValueError):
                PREPARE.copy_environment(source, destination, os.getuid())
            self.assertEqual(sentinel.read_text(), "untouched")
