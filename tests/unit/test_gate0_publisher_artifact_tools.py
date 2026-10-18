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


def synthetic_role_subject(native_pins_raw=None):
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
    pins_raw = native_pins_raw
    if pins_raw is None:
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
    homes = {
        "var/empty/dotmac-gate0/" + role
        for role in ("issuer", "attester", "management", "capture-sender")
    }
    directories.update(homes)
    directories.update(
        str(parent)
        for name in homes
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
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
    def test_synthetic_role_homes_include_real_root_owned_ancestors(self):
        _, files = synthetic_role_subject()
        with subject_archive(files) as archive:
            members = INSPECT.role_inventory(archive)
            for name in ("var", "var/empty", "var/empty/dotmac-gate0"):
                entry = members[name]
                self.assertTrue(entry.isdir())
                self.assertEqual((entry.uid, entry.gid), (0, 0))
                self.assertFalse(entry.mode & 0o022)

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


def retained_fixture():
    """Entirely synthetic retained data; no retained production plaintext needed."""
    import gzip

    owner = load("retain_gate0_publisher")

    def canonical(value):
        return owner.canonical_json(value, 1024**2)

    pins = canonical(
        {
            "schema": "Gate0HostedSshArtifacts.v1",
            "artifacts": [
                {"binary_path": name, "sha256": "e" * 64, "version": "synthetic"}
                for name in ("usr/bin/ssh", "usr/sbin/sshd")
            ],
        }
    )
    source, raw_files = synthetic_role_subject(pins)
    source.update(
        ref="refs/heads/synthetic",
        workflow_path=owner.ROLE_WORKFLOW,
        workflow_blob_sha256="b" * 64,
    )
    source["files"] = {
        **dict.fromkeys(owner.ROLE_SOURCE_FILES, "c" * 64),
        **source["files"],
    }
    packet = {
        "schema": owner.ROLE_SCHEMA,
        "purpose": owner.ROLE_PURPOSE,
        "operation": "build-inspect-encrypt-retain",
        "source": source,
        "github": {
            "repository": owner.REPOSITORY,
            "repository_id": 1,
            "owner_id": 2,
            "workflow_id": 3,
            "actor_id": 4,
            "job_key": "role-image",
        },
        "validity": {
            "not_before": "2026-10-16T00:00:00Z",
            "expires_at": "2026-10-17T00:00:00Z",
        },
        "recipient": {
            "certificate_sha256": owner.CERTIFICATE_SHA256,
            "primary_fingerprint": owner.PRIMARY_FINGERPRINT,
            "encryption_fingerprint": owner.ENCRYPTION_FINGERPRINT,
        },
        "tool_qualification_sha256": "d" * 64,
        "build": {
            "mode": "build-once-in-selected-job",
            "platform": "linux/amd64",
            "base_image": owner.ROLE_BASE_IMAGE,
            "target": "gate0-role",
        },
        "limits": dict(owner.LIMITS),
        "artifact": {
            "name": "gate0-role-qualification-runtime",
            "retention_days": 30,
            "files": ["encrypted-runtime-bundle.pgp", "producer-receipt.json"],
        },
    }
    with subject_archive(raw_files) as archive:
        rootfs = archive.fileobj.getvalue()
        members = INSPECT.role_inventory(archive)
        subjects = INSPECT.role_subjects(archive, members, source, native_pins_raw=pins)
        files = INSPECT.complete_role_files(archive, members)
        footprint = {
            "entries": len(members),
            "regular_files": sum(item.isfile() for item in members.values()),
            "regular_bytes": sum(
                item.size for item in members.values() if item.isfile()
            ),
            "largest_member_bytes": max(item.size for item in members.values()),
            "role_tar_bytes": len(rootfs),
        }
    compressed = gzip.compress(rootfs, mtime=0)
    image_id = "sha256:" + "f" * 64
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
            "synthetic",
        ),
        "python": "synthetic",
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
    # Noncanonical original diagnostics prove inspection checks parsed semantics,
    # not an invented reserialized-byte equality.
    qualification = INSPECT.role_synthetic_qualification(
        json.dumps(smoke, indent=2).encode(),
        json.dumps(network, indent=2).encode(),
        source["revision"],
        image_id,
    )
    producer = {
        "repository_id": 1,
        "owner_id": 2,
        "workflow_id": 3,
        "actor_id": 4,
        "run_id": 5,
        "attempt": 1,
        "job_id": 6,
    }
    base_layers = ["sha256:" + "1" * 64]
    build = {
        "schema": "Gate0RoleQualificationPrivateBuild.v1",
        "source": {
            "revision": source["revision"],
            "workflow_blob_sha256": "b" * 64,
            **source["files"],
        },
        "producer": producer,
        "images": {
            "base": {
                "reference": owner.ROLE_BASE_IMAGE,
                "image_id": "sha256:" + "2" * 64,
                "rootfs_diff_ids": base_layers,
            },
            "role": {
                "target": "gate0-role",
                "image_id": image_id,
                "source_revision_label": source["revision"],
                "rootfs_diff_ids": [*base_layers, "sha256:" + "3" * 64],
                "inspect_sha256": "4" * 64,
                "config_sha256": "f" * 64,
                "config_bytes": 64,
            },
        },
        "runtime": {
            "uncompressed_tar_sha256": INSPECT.digest(rootfs),
            "uncompressed_tar_bytes": len(rootfs),
            "compressed_archive_sha256": INSPECT.digest(compressed),
            "compressed_archive_bytes": len(compressed),
            "files_manifest_sha256": INSPECT.digest(files),
            "files_manifest_bytes": len(files),
            "qualification_manifest_sha256": INSPECT.digest(qualification),
            "qualification_manifest_bytes": len(qualification),
            **subjects,
        },
        "limits": packet["limits"],
        "footprint": footprint,
        "tool_qualification_sha256": packet["tool_qualification_sha256"],
    }
    receipt = {
        "schema": "Gate0RoleQualificationProducerReceipt.v1",
        "purpose": owner.ROLE_PURPOSE,
        "image_target": "gate0-role",
        "source_revision": source["revision"],
        "workflow_blob_sha256": "b" * 64,
        "run_id": 5,
        "attempt": 1,
        "job_id": 6,
        "recipient_certificate_sha256": owner.CERTIFICATE_SHA256,
        "recipient_encryption_fingerprint": owner.ENCRYPTION_FINGERPRINT,
        "encrypted_bundle_sha256": "5" * 64,
        "encrypted_bundle_bytes": 100,
        "private_manifest_sha256": INSPECT.digest(canonical(build)),
    }
    readback = {
        "schema": "DotmacAuthenticatedRoleRetentionReadback.v1",
        "archive_bytes": 200,
        "archive_sha256": "6" * 64,
        "artifact_id": 7,
        "attempt": 1,
        "ciphertext_retained": True,
        "encrypted_bundle_bytes": 100,
        "encrypted_bundle_sha256": "5" * 64,
        "exact_pair": True,
        "gate0_accepted": False,
        "job_id": 6,
        "plaintext_decrypted": False,
        "private_manifest_independently_verified": False,
        "producer_receipt_joins": True,
        "producer_receipt_sha256": INSPECT.digest(canonical(receipt)),
        "role_runtime_accepted": False,
        "run_id": 5,
        "verified_at": "2026-10-17T00:01:00Z",
    }
    run = {
        "id": 5,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_sha": source["revision"],
        "head_branch": "synthetic",
        "path": owner.ROLE_WORKFLOW,
        "repository": {"full_name": owner.REPOSITORY, "id": 1, "owner": {"id": 2}},
        "head_repository": {"full_name": owner.REPOSITORY},
        "workflow_id": 3,
        "actor": {"id": 4},
        "triggering_actor": {"id": 4},
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-16T01:00:00Z",
        "run_started_at": "2026-10-16T01:00:01Z",
        "updated_at": "2026-10-16T02:00:00Z",
    }
    jobs = {
        "total_count": 1,
        "jobs": [
            {
                "id": 6,
                "run_id": 5,
                "run_attempt": 1,
                "head_sha": source["revision"],
                "name": "role-image",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-10-16T01:00:02Z",
                "completed_at": "2026-10-16T01:59:59Z",
            }
        ],
    }
    return (
        owner,
        packet,
        receipt,
        readback,
        run,
        jobs,
        pins,
        compressed,
        files,
        build,
        qualification,
    )


def retained_payload(compressed, files, build_raw, qualification):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in zip(
            ("role-rootfs.tar.gz", "files.json", "build.json", "qualification.json"),
            (compressed, files, build_raw, qualification),
            strict=True,
        ):
            item = tarfile.TarInfo(name)
            item.mode, item.size = 0o600, len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return stream.getvalue()


class RetainedRoleDataInspectionTests(unittest.TestCase):
    def stage(self, root, fixture=None):
        fixture = retained_fixture() if fixture is None else fixture
        (
            owner,
            packet,
            receipt,
            readback,
            run,
            jobs,
            pins,
            compressed,
            files,
            build,
            qualification,
        ) = fixture

        def canonical(value):
            return owner.canonical_json(value, 1024**2)

        data = (
            retained_payload(compressed, files, canonical(build), qualification),
            canonical(packet),
            canonical(receipt),
            canonical(readback),
            pins,
            canonical(run),
            canonical(jobs),
        )
        root.chmod(0o700)
        for name, raw in zip(INSPECT.RETAINED_INPUTS, data, strict=True):
            path = root / name
            path.write_bytes(raw)
            path.chmod(0o600)
        return [INSPECT.digest(raw) for raw in data] + [
            INSPECT.digest((ROOT / ".github/candidate" / name).read_bytes())
            for name in ("inspect_gate0_publisher.py", "retain_gate0_publisher.py")
        ]

    def test_actual_data_mode_valid_archive_with_no_external_execution(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            expected = self.stage(root)
            with (
                patch.object(
                    INSPECT.subprocess,
                    "run",
                    side_effect=AssertionError("no execution"),
                ),
                patch.object(
                    INSPECT.subprocess,
                    "check_output",
                    side_effect=AssertionError("no execution"),
                ),
            ):
                INSPECT.role_retained_inspect(root, expected)
            output = root / "retained-inspection.json"
            result = json.loads(output.read_bytes())
            self.assertEqual(result["verdict"], "authenticated-data-only")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            for key in (
                "live_readiness",
                "installed_native_qualified",
                "operationally_accepted",
                "gate0_accepted",
            ):
                self.assertIs(result[key], False)
            with self.assertRaises(FileExistsError):
                INSPECT.role_retained_inspect(root, expected)

    def test_owner_hashes_and_held_input_shape_refuse(self):
        for change in ("hash", "symlink", "hardlink", "public", "ancestor"):
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary).resolve()
                expected = self.stage(root)
                path = root / INSPECT.RETAINED_INPUTS[1]
                if change == "hash":
                    expected[1] = "0" * 64
                elif change == "symlink":
                    path.rename(root / "target")
                    path.symlink_to(root / "target")
                elif change == "hardlink":
                    os.link(path, root / "alias")
                elif change == "public":
                    path.chmod(0o644)
                else:
                    alias = root / "alias"
                    alias.symlink_to(root, target_is_directory=True)
                    root = alias
                with self.assertRaises((ValueError, OSError)):
                    INSPECT.role_retained_inspect(root, expected)
                self.assertFalse((root / "retained-inspection.json").exists())

    def test_authenticated_but_wrong_source_producer_and_acceptance_refuse(self):
        for change in (
            "source",
            "producer",
            "recipient",
            "run",
            "job",
            "clock",
            "flag",
            "digest",
            "size",
            "native",
        ):
            fixture = list(retained_fixture())
            (
                owner,
                packet,
                receipt,
                readback,
                run,
                jobs,
                pins,
                compressed,
                files,
                build,
                qualification,
            ) = fixture
            if change == "source":
                build["source"]["dockerfile_sha256"] = "0" * 64
            elif change == "producer":
                build["producer"]["actor_id"] = 99
            elif change == "recipient":
                receipt["recipient_encryption_fingerprint"] = "0" * 40
            elif change == "run":
                run["actor"]["id"] = 99
            elif change == "job":
                jobs["jobs"][0]["id"] = 99
            elif change == "clock":
                jobs["jobs"][0]["completed_at"] = "2026-10-17T00:00:00Z"
            elif change == "flag":
                q = json.loads(qualification)
                q["gate0_accepted"] = True
                fixture[-1] = owner.canonical_json(q, 1024**2)
                build["runtime"]["qualification_manifest_sha256"] = INSPECT.digest(
                    fixture[-1]
                )
                build["runtime"]["qualification_manifest_bytes"] = len(fixture[-1])
            elif change == "digest":
                build["runtime"]["uncompressed_tar_sha256"] = "0" * 64
            elif change == "size":
                build["runtime"]["compressed_archive_bytes"] += 1
            else:
                fixture[6] = pins + b" "
            receipt["private_manifest_sha256"] = INSPECT.digest(
                owner.canonical_json(build, 1024**2)
            )
            readback["producer_receipt_sha256"] = INSPECT.digest(
                owner.canonical_json(receipt, 1024**2)
            )
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary).resolve()
                expected = self.stage(root, fixture)
                with self.assertRaises(ValueError):
                    INSPECT.role_retained_inspect(root, expected)
                self.assertFalse((root / "retained-inspection.json").exists())

    def test_input_replacement_during_data_scan_refuses(self):
        from unittest.mock import patch

        original = INSPECT.retained_measure
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            expected = self.stage(root)

            def changed(*arguments):
                result = original(*arguments)
                path = root / INSPECT.RETAINED_INPUTS[1]
                raw = path.read_bytes()
                path.unlink()
                path.write_bytes(raw)
                path.chmod(0o600)
                return result

            with (
                patch.object(INSPECT, "retained_measure", side_effect=changed),
                self.assertRaises(ValueError),
            ):
                INSPECT.role_retained_inspect(root, expected)
            self.assertFalse((root / "retained-inspection.json").exists())


class RetainedCapturedHelperDriftTests(unittest.TestCase):
    stage = RetainedRoleDataInspectionTests.stage

    def test_changed_helper_after_capture_never_executes_changed_code(self):
        import importlib.machinery
        from unittest.mock import patch

        for mutation in ("replace", "same-inode"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                base = Path(temporary).resolve()
                tool_dir = base / "tools"
                tool_dir.mkdir(mode=0o700)
                for name in ("inspect_gate0_publisher.py", "retain_gate0_publisher.py"):
                    (tool_dir / name).write_bytes(
                        (ROOT / ".github/candidate" / name).read_bytes()
                    )
                spec = importlib.util.spec_from_file_location(
                    "isolated_retained_inspector",
                    tool_dir / "inspect_gate0_publisher.py",
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                private = base / "private"
                private.mkdir(mode=0o700)
                expected = self.stage(private)
                helper = tool_dir / "retain_gate0_publisher.py"
                source_to_code = importlib.machinery.SourceFileLoader.source_to_code
                changed = False

                def mutate_after_capture(
                    loader,
                    data,
                    path,
                    *,
                    helper=helper,
                    mutation=mutation,
                    source_to_code=source_to_code,
                    **kwargs,
                ):
                    nonlocal changed
                    if (
                        loader.name == "retained_current_inspector_owner"
                        and not changed
                    ):
                        changed = True
                        raw = (
                            helper.read_bytes()
                            + b"\nraise AssertionError('changed helper executed')\n"
                        )
                        if mutation == "replace":
                            helper.unlink()
                        helper.write_bytes(raw)
                    return source_to_code(loader, data, path, **kwargs)

                with (
                    patch.object(
                        importlib.machinery.SourceFileLoader,
                        "source_to_code",
                        mutate_after_capture,
                    ),
                    patch.object(
                        module,
                        "_role_retention_owner",
                        side_effect=AssertionError("legacy path loader forbidden"),
                    ),
                ):
                    with self.assertRaisesRegex(ValueError, "retained input changed"):
                        module.role_retained_inspect(private, expected)
                self.assertTrue(changed)
                self.assertFalse((private / "retained-inspection.json").exists())


def reauthenticate_retained_fixture(fixture, *, qualification_changed=True):
    """Update synthetic authentication after a deliberate malformed data change."""
    owner, _, receipt, readback, _, _, _, _, _, build, qualification = fixture
    if qualification_changed:
        build["runtime"].update(
            qualification_manifest_sha256=INSPECT.digest(qualification),
            qualification_manifest_bytes=len(qualification),
        )
    receipt["private_manifest_sha256"] = INSPECT.digest(
        owner.canonical_json(build, 1024**2)
    )
    readback["producer_receipt_sha256"] = INSPECT.digest(
        owner.canonical_json(receipt, 1024**2)
    )
    return fixture


class RetainedExactJsonTypesTests(unittest.TestCase):
    stage = RetainedRoleDataInspectionTests.stage

    def test_each_false_qualification_flag_refuses_numeric_aliases(self):
        for flag in (
            "live_readiness",
            "installed_native_qualified",
            "operationally_accepted",
            "gate0_accepted",
        ):
            for value in (0, 0.0):
                fixture = list(retained_fixture())
                qualification = json.loads(fixture[-1])
                qualification[flag] = value
                fixture[-1] = fixture[0].canonical_json(qualification, 1024**2)
                reauthenticate_retained_fixture(fixture)
                with (
                    self.subTest(flag=flag, value=repr(value)),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary).resolve()
                    expected = self.stage(root, fixture)
                    with self.assertRaisesRegex(
                        ValueError, "retained qualification join"
                    ):
                        INSPECT.role_retained_inspect(root, expected)
                    self.assertFalse((root / "retained-inspection.json").exists())

    def test_each_limits_footprint_runtime_counter_refuses_coercion(self):
        for section in ("limits", "footprint", "runtime"):
            original = retained_fixture()[-2][section]
            for field, value in original.items():
                if type(value) is not int:
                    continue
                for altered in (float(value), True, str(value)):
                    fixture = list(retained_fixture())
                    fixture[-2][section] = dict(fixture[-2][section])
                    fixture[-2][section][field] = altered
                    reauthenticate_retained_fixture(
                        fixture, qualification_changed=False
                    )
                    with (
                        self.subTest(
                            section=section, field=field, kind=type(altered).__name__
                        ),
                        tempfile.TemporaryDirectory() as temporary,
                    ):
                        root = Path(temporary).resolve()
                        expected = self.stage(root, fixture)
                        with self.assertRaises(ValueError):
                            INSPECT.role_retained_inspect(root, expected)
                        self.assertFalse((root / "retained-inspection.json").exists())

    def test_nested_closed_json_join_preserves_scalar_types(self):
        for actual, expected in (
            (False, 0),
            (0, False),
            (0.0, False),
            (True, 1),
            (1.0, 1),
            ("1", 1),
        ):
            with self.subTest(actual=repr(actual), expected=repr(expected)):
                self.assertFalse(
                    INSPECT.retained_equal({"rows": [actual]}, {"rows": [expected]})
                )
        self.assertTrue(
            INSPECT.retained_equal(
                {"rows": [False, 1, None]}, {"rows": [False, 1, None]}
            )
        )


def malformed_retained_wheel_fixture(encrypted, *, corrupt_deflate=False):
    import gzip
    import struct
    import zipfile

    fixture = list(retained_fixture())
    raw_files = {}
    with tarfile.open(
        fileobj=io.BytesIO(gzip.decompress(fixture[7])), mode="r:"
    ) as archive:
        for item in archive:
            if item.isfile():
                raw_files[item.name] = archive.extractfile(item).read()
    wheel_path = next(
        name
        for name in raw_files
        if name.startswith("app/dist/") and name.endswith(".whl")
    )
    if corrupt_deflate:
        marker = "vendor_cp/SYNTHETIC_PRIVATE_VALUE.py"
        wheel_stream = io.BytesIO()
        with (
            zipfile.ZipFile(io.BytesIO(raw_files[wheel_path])) as original,
            zipfile.ZipFile(
                wheel_stream, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as wheel,
        ):
            for item in original.infolist():
                wheel.writestr(item.filename, original.read(item))
            wheel.writestr(marker, b"synthetic inert bytes")
        raw = bytearray(wheel_stream.getvalue())
        with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
            offset = wheel.getinfo(marker).header_offset
        name_bytes, extra_bytes = struct.unpack_from("<HH", raw, offset + 26)
        # Preserve ZIP headers/central directory but set the first DEFLATE
        # block to the reserved BTYPE=3 value, reaching zlib.error on read.
        raw[offset + 30 + name_bytes + extra_bytes] = 0x07
        raw_files[wheel_path] = bytes(raw)
        raw_files["opt/venv/lib/python3.12/site-packages/" + marker] = (
            b"synthetic inert bytes"
        )
    elif encrypted:
        wheel_stream = io.BytesIO(raw_files[wheel_path])
        marker = "vendor_cp/SYNTHETIC_PRIVATE_VALUE.py"
        with zipfile.ZipFile(wheel_stream, mode="a") as wheel:
            wheel.writestr(marker, b"synthetic inert bytes")
        raw = bytearray(wheel_stream.getvalue())
        with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
            offset = wheel.getinfo(marker).header_offset
        struct.pack_into(
            "<H", raw, offset + 6, struct.unpack_from("<H", raw, offset + 6)[0] | 1
        )
        offset = 0
        while (offset := raw.find(b"PK\x01\x02", offset)) != -1:
            length = struct.unpack_from("<H", raw, offset + 28)[0]
            if raw[offset + 46 : offset + 46 + length] == marker.encode():
                struct.pack_into(
                    "<H",
                    raw,
                    offset + 8,
                    struct.unpack_from("<H", raw, offset + 8)[0] | 1,
                )
            offset += 4
        raw_files[wheel_path] = bytes(raw)
        raw_files["opt/venv/lib/python3.12/site-packages/" + marker] = (
            b"synthetic inert bytes"
        )
    else:
        raw_files[wheel_path] = b"SYNTHETIC_PRIVATE_VALUE is not ZIP framing"
    distributions = json.loads(raw_files["app/distributions.json"])
    for row in distributions["files"]:
        if "app/dist/" + row["filename"] == wheel_path:
            row.update(
                size_bytes=len(raw_files[wheel_path]),
                sha256="sha256:" + INSPECT.digest(raw_files[wheel_path]),
            )
    raw_files["app/distributions.json"] = json.dumps(distributions).encode()
    with subject_archive(raw_files) as archive:
        rootfs = archive.fileobj.getvalue()
        members = INSPECT.role_inventory(archive)
        fixture[8] = INSPECT.complete_role_files(archive, members)
        footprint = {
            "entries": len(members),
            "regular_files": sum(item.isfile() for item in members.values()),
            "regular_bytes": sum(
                item.size for item in members.values() if item.isfile()
            ),
            "largest_member_bytes": max(item.size for item in members.values()),
            "role_tar_bytes": len(rootfs),
        }
    fixture[7] = gzip.compress(rootfs, mtime=0)
    fixture[-2]["footprint"] = footprint
    fixture[-2]["runtime"].update(
        uncompressed_tar_sha256=INSPECT.digest(rootfs),
        uncompressed_tar_bytes=len(rootfs),
        compressed_archive_sha256=INSPECT.digest(fixture[7]),
        compressed_archive_bytes=len(fixture[7]),
        files_manifest_sha256=INSPECT.digest(fixture[8]),
        files_manifest_bytes=len(fixture[8]),
    )
    return reauthenticate_retained_fixture(fixture)


class RetainedCliRedactionTests(unittest.TestCase):
    stage = RetainedRoleDataInspectionTests.stage

    def test_actual_cli_sanitizes_zip_encryption_and_deep_json_failures(self):
        import subprocess
        import sys
        import zipfile
        import zlib

        for kind, error in (
            ("malformed-wheel", zipfile.BadZipFile),
            ("encrypted-wheel", RuntimeError),
            ("corrupt-deflate-wheel", zlib.error),
            ("deep-json", (RecursionError, TypeError)),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture = (
                    malformed_retained_wheel_fixture(
                        kind == "encrypted-wheel",
                        corrupt_deflate=kind == "corrupt-deflate-wheel",
                    )
                    if kind != "deep-json"
                    else retained_fixture()
                )
                expected = self.stage(root, fixture)
                if kind == "deep-json":
                    raw = b"[" * 2000 + b'"SYNTHETIC_PRIVATE_VALUE"' + b"]" * 2000
                    (root / "original-packet.json").write_bytes(raw)
                    expected[1] = INSPECT.digest(raw)
                # Confirm the fixture reaches a parser or structural refusal.
                with self.assertRaises(error):
                    INSPECT.role_retained_inspect(root, expected)
                completed = subprocess.run(  # noqa: S603 -- fixed trusted CLI, synthetic hosted-only data
                    [
                        sys.executable,
                        str(ROOT / ".github/candidate/inspect_gate0_publisher.py"),
                        "role-retained-inspect",
                        str(root),
                        *expected,
                    ],
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, b"")
                self.assertEqual(completed.stderr, b"retained inspection refused\n")
                self.assertNotIn(b"SYNTHETIC_PRIVATE_VALUE", completed.stderr)
                self.assertEqual(
                    {path.name for path in root.iterdir()}, set(INSPECT.RETAINED_INPUTS)
                )
