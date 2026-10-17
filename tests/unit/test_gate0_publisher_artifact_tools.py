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


class RoleTarPolicyTests(unittest.TestCase):
    @staticmethod
    def roots():
        roots = [
            (name, tarfile.DIRTYPE, 0o755, "")
            for name in (
                "opt",
                "opt/venv",
                "opt/venv/bin",
                "opt/venv/lib",
                "opt/poetry",
                "opt/poetry/bin",
                "opt/poetry/lib",
                "usr",
                "usr/bin",
                "app",
            )
        ]
        roots.append(("usr/bin/python3.12", tarfile.REGTYPE, 0o755, ""))
        roots.append(("usr/bin/python3", tarfile.SYMTYPE, 0o777, "python3.12"))
        for prefix in ("opt/venv", "opt/poetry"):
            roots.extend(
                (name, tarfile.SYMTYPE, 0o777, target)
                for name, target in INSPECT.ROLE_PYTHON_LINKS.items()
                if name.startswith(prefix + "/")
            )
            roots.append((prefix + "/lib64", tarfile.SYMTYPE, 0o777, "lib"))
        roots.extend(
            (name, tarfile.REGTYPE, 0o644, "") for name in INSPECT.ROLE_PROJECT_FILES
        )
        return roots

    def test_finite_native_python_links_and_role_inputs(self):
        with archive(self.roots()) as subject:
            members = INSPECT.role_inventory(subject)
            self.assertIn("opt/poetry/bin/python", members)
            self.assertIn("app/poetry.lock", members)
            roster = json.loads(INSPECT.complete_role_files(subject, members))
            self.assertEqual(roster["schema"], "Gate0RoleQualificationFiles.v1")
            self.assertEqual([row["path"] for row in roster["files"]], sorted(members))
        with archive(self.roots()) as subject, self.assertRaises(ValueError):
            INSPECT.inventory(subject, publisher=True)

    def test_role_never_admits_cache_credentials_or_arbitrary_project_inputs(self):
        for name in (
            "root/.cache/pip/a",
            "root/.cache/pypoetry/a",
            "opt/poetry/.cache/a",
            "root/.ssh/id_rsa",
            "root/.config/pypoetry/auth.toml",
            "run/secrets/token",
            "app/src/a.py",
            "opt/poetry/pyproject.toml",
            "app/other/poetry.lock",
            "../outside",
        ):
            with (
                self.subTest(name=name),
                archive([*self.roots(), (name, tarfile.REGTYPE, 0o600, "")]) as subject,
                self.assertRaises(ValueError),
            ):
                INSPECT.role_inventory(subject)

    def test_wrong_python_target_protected_hardlink_and_ancestor_refuse(self):
        for change in (
            ("opt/venv/bin/python3", tarfile.SYMTYPE, 0o777, "/untrusted/python"),
            ("opt/venv/bin/python", tarfile.SYMTYPE, 0o777, "../bin/python"),
            ("opt/venv/bin/python", tarfile.LNKTYPE, 0o755, "usr/bin/python3.12"),
            ("opt", tarfile.DIRTYPE, 0o777, ""),
            ("usr/bin/python3.12", tarfile.SYMTYPE, 0o777, "python3"),
            ("opt/venv/bin/dotmac-platform", tarfile.SYMTYPE, 0o777, "python"),
        ):
            items = [item for item in self.roots() if item[0] != change[0]] + [change]
            with (
                self.subTest(change=change),
                archive(items) as subject,
                self.assertRaises(ValueError),
            ):
                INSPECT.role_inventory(subject)
        for items in (
            [*self.roots(), ("app/poetry.lock", tarfile.REGTYPE, 0o644, "")],
            [*self.roots(), ("device", tarfile.CHRTYPE, 0o644, "")],
        ):
            with archive(items) as subject, self.assertRaises(ValueError):
                INSPECT.role_inventory(subject)

    def test_actual_synthetic_outputs_are_preserved_and_false_acceptance_fixed(self):
        smoke = {
            "schema": "Gate0RoleImageSmoke.v1",
            "passed": True,
            "native_versions": dict.fromkeys(
                (
                    "/usr/bin/ssh",
                    "/usr/sbin/sshd",
                    "/usr/bin/wg",
                    "/usr/sbin/ip",
                    "/usr/sbin/nft",
                ),
                "synthetic-version",
            ),
            "python": "3.12",
            "ssl": "synthetic",
            "psycopg": "synthetic",
            "live_readiness": False,
        }
        network = {
            "schema": "Gate0NativeNetworkPrivilegeProof.v1",
            "passed": True,
            "wrong_principal_refused_under_k": True,
            "refused_authentication_boundary_empty": True,
            "full_wireguard_installation_qualified": False,
            "live_readiness": False,
        }
        smoke_raw, network_raw = (
            json.dumps(smoke).encode(),
            json.dumps(network).encode(),
        )
        qualified = json.loads(
            INSPECT.role_synthetic_qualification(
                smoke_raw, network_raw, "a" * 40, "sha256:" + "b" * 64
            )
        )
        self.assertEqual(qualified["smoke"], smoke)
        self.assertEqual(qualified["network"], network)
        self.assertEqual(
            qualified["smoke_sha256"], hashlib.sha256(smoke_raw).hexdigest()
        )
        self.assertEqual(
            qualified["network_sha256"], hashlib.sha256(network_raw).hexdigest()
        )
        for key in (
            "live_readiness",
            "installed_native_qualified",
            "operationally_accepted",
            "gate0_accepted",
        ):
            self.assertIs(qualified[key], False)
        for bad_smoke, bad_network in (
            (network_raw, smoke_raw),
            (json.dumps({**smoke, "passed": False}).encode(), network_raw),
            (
                smoke_raw,
                json.dumps(
                    {**network, "full_wireguard_installation_qualified": True}
                ).encode(),
            ),
            (
                smoke_raw,
                json.dumps({**network, "wrong_principal_refused_under_k": 1}).encode(),
            ),
        ):
            with self.assertRaises(ValueError):
                INSPECT.role_synthetic_qualification(
                    bad_smoke, bad_network, "a" * 40, "sha256:" + "b" * 64
                )


def synthetic_role_subject():
    """Actual public byte fixtures, never a real runtime or native acceptance."""
    import zipfile

    source = {"revision": "a" * 40, "files": {}}
    wheel_stream = io.BytesIO()
    with zipfile.ZipFile(wheel_stream, "w") as wheel:
        for name in INSPECT.SOURCE_OWNERS:
            wheel.writestr(name, b"synthetic installed owner\n")
        wheel.writestr(
            "dotmac_vendor_control_plane-1.dist-info/METADATA", b"synthetic metadata"
        )
        wheel.writestr(
            "dotmac_vendor_control_plane-1.dist-info/RECORD", b"synthetic record"
        )
    wheel_bytes = wheel_stream.getvalue()
    wheel_name = "dotmac_vendor_control_plane-1-py3-none-any.whl"
    raw_files = {
        "app/dist/" + wheel_name: wheel_bytes,
        "app/dist/source.tar.gz": b"synthetic sdist",
    }
    for name in INSPECT.SOURCE_OWNERS:
        raw_files["opt/venv/lib/python3.12/site-packages/" + name] = (
            b"synthetic installed owner\n"
        )
    raw_files[
        "opt/venv/lib/python3.12/site-packages/dotmac_vendor_control_plane-1.dist-info/METADATA"
    ] = b"synthetic metadata"
    raw_files[
        "opt/venv/lib/python3.12/site-packages/dotmac_vendor_control_plane-1.dist-info/RECORD"
    ] = b"installer-generated"
    manifest = {
        "contract": "dotmac-distribution-digests/1",
        "files": [
            {
                "filename": name.removeprefix("app/dist/"),
                "size_bytes": len(raw),
                "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
            for name, raw in raw_files.items()
            if name.startswith("app/dist/")
        ],
    }
    raw_files["app/distributions.json"] = json.dumps(manifest).encode()
    profile = {
        "contract": "dotmac-application-foundation-profile/1",
        "source_revision": source["revision"],
        "wheel_sha256": "sha256:" + hashlib.sha256(wheel_bytes).hexdigest(),
    }
    raw_files["app/application_foundation_profile.json"] = json.dumps(profile).encode()
    raw_files["app/deployment_profile_declarations.json"] = json.dumps(
        {
            "schema": "DotmacDeploymentProfileDeclarations.v1",
            "source_revision": source["revision"],
            "foundation_profile_digest": "sha256:"
            + hashlib.sha256(
                raw_files["app/application_foundation_profile.json"]
            ).hexdigest(),
        }
    ).encode()
    raw_files["app/migration_heads.json"] = json.dumps(
        {
            "schema": "ImageMigrationHeads.v1",
            "source_revision": source["revision"],
            "heads": ["synthetic"],
        }
    ).encode()
    for name, key in (
        ("app/pyproject.toml", "pyproject_sha256"),
        ("app/poetry.lock", "poetry_lock_sha256"),
    ):
        raw_files[name] = b"synthetic source input"
        source["files"][key] = hashlib.sha256(raw_files[name]).hexdigest()
    pins_raw = (ROOT / "conformance/openssh-ubuntu-artifacts.json").read_bytes()
    source["files"]["native_artifacts_sha256"] = hashlib.sha256(pins_raw).hexdigest()
    binaries = {}
    for name in (
        "/usr/bin/ssh",
        "/usr/sbin/sshd",
        "/usr/bin/wg",
        "/usr/sbin/ip",
        "/usr/sbin/nft",
    ):
        raw_files[name.removeprefix("/")] = b"synthetic native binary"
        binaries[name] = {
            "sha256": hashlib.sha256(b"synthetic native binary").hexdigest()
        }
    for item in json.loads(pins_raw)["artifacts"]:
        binaries["/" + item["binary_path"]].update(
            archive_sha256=item["sha256"], package_version=item["version"]
        )
    raw_files["app/gate0_native_tools.json"] = json.dumps(
        {
            "schema": "Gate0NativeTools.v1",
            "binaries": binaries,
            "packages": "synthetic\t1\n",
        }
    ).encode()
    raw_files["etc/passwd"] = b"".join(
        f"gate0-{name}:x:{uid}:{uid}::/var/empty/dotmac-gate0/{name}:/bin/sh\n".encode()
        for name, uid in (
            ("issuer", 10031),
            ("attester", 10032),
            ("management", 10033),
            ("capture-sender", 10034),
        )
    )
    return source, raw_files


def subject_archive(raw_files):
    from pathlib import PurePosixPath

    stream = io.BytesIO()
    directories = {
        str(parent)
        for name in raw_files
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    directories.update(
        "var/empty/dotmac-gate0/" + role
        for role in ("issuer", "attester", "management", "capture-sender")
    )
    with tarfile.open(fileobj=stream, mode="w") as output:
        for name in sorted(directories):
            item = tarfile.TarInfo(name)
            item.type, item.mode = (
                tarfile.DIRTYPE,
                0o555 if name.startswith("var/empty/dotmac-gate0/") else 0o755,
            )
            output.addfile(item)
        for name, raw in sorted(raw_files.items()):
            item = tarfile.TarInfo(name)
            item.mode, item.size = 0o644, len(raw)
            output.addfile(item, io.BytesIO(raw))
    stream.seek(0)
    return tarfile.open(fileobj=stream, mode="r:")


class RoleSubjectJoinTests(unittest.TestCase):
    def test_actual_role_shaped_tar_joins_and_missing_or_changed_subject_refusals(self):
        source, files = synthetic_role_subject()
        with subject_archive(files) as archive:
            members = INSPECT.role_inventory(archive)
            subjects = INSPECT.role_subjects(archive, members, source)
            self.assertEqual(
                subjects["native_tools_sha256"],
                hashlib.sha256(files["app/gate0_native_tools.json"]).hexdigest(),
            )
        for name in (
            "app/distributions.json",
            "app/dist/dotmac_vendor_control_plane-1-py3-none-any.whl",
            "app/application_foundation_profile.json",
            "app/deployment_profile_declarations.json",
            "app/migration_heads.json",
            "app/gate0_native_tools.json",
            "usr/sbin/sshd",
        ):
            changed = {key: value for key, value in files.items() if key != name}
            with self.subTest(missing=name), subject_archive(changed) as archive:
                members = INSPECT.role_inventory(archive)
                with self.assertRaises((ValueError, KeyError)):
                    INSPECT.role_subjects(archive, members, source)
        for name, raw in (
            ("app/poetry.lock", b"changed lock"),
            ("usr/bin/ssh", b"changed native binary"),
            ("etc/passwd", files["etc/passwd"].replace(b":10031:", b":10099:", 1)),
            (
                "opt/venv/lib/python3.12/site-packages/vendor_cp/cli/owners.py",
                b"changed installed owner",
            ),
        ):
            with (
                self.subTest(changed=name),
                subject_archive({**files, name: raw}) as archive,
            ):
                members = INSPECT.role_inventory(archive)
                with self.assertRaises(ValueError):
                    INSPECT.role_subjects(archive, members, source)
