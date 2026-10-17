"""Synthetic public measurement tests; no local/native qualification execution."""

import hashlib
import json
import os
import runpy
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / ".github/candidate/measure_gate0_gpg_tools.py"
M = runpy.run_path(str(SOURCE), run_name="synthetic_gpg_measurements")
G = M["measure"].__globals__
PRIMITIVE_BYTES = G["PRIMITIVES"].read_bytes()


class GpgToolMeasurementTests(unittest.TestCase):
    def setUp(self):
        M["load_primitives"](PRIMITIVE_BYTES)

    def record(self):
        snapshots = M["source_snapshots"](time.monotonic() + 5)
        return dict(
            schema="DotmacPublisherGpgToolMeasurements.v1",
            public="synthetic",
            source={
                key: hashlib.sha256(raw).hexdigest() for key, raw in snapshots.items()
            },
        )

    def context(self):
        return dict(
            GITHUB_ACTIONS="true",
            GITHUB_SHA="a" * 40,
            GITHUB_REPOSITORY="michaelayoade/dotmac_platform_control_plane",
            GITHUB_REPOSITORY_ID="12",
            GITHUB_RUN_ID="34",
            GITHUB_RUN_ATTEMPT="2",
            GITHUB_JOB="check",
            GITHUB_REF="refs/pull/244/merge",
            GITHUB_WORKFLOW_REF="michaelayoade/dotmac_platform_control_plane/.github/workflows/ci.yml@refs/pull/244/merge",
            GITHUB_WORKFLOW_SHA="b" * 40,
        )

    def test_actual_measurement_composition_keeps_existing_identity_bytes(self):
        tool_bytes = {"gpg": b"synthetic-gpg", "gpgconf": b"synthetic-gpgconf"}
        tools = {
            name: dict(
                path="/usr/bin/" + name,
                sha256=hashlib.sha256(raw).hexdigest(),
                version_line=name + " (GnuPG) 2.4.4",
            )
            for name, raw in tool_bytes.items()
        }
        legacy = {}
        for name, pin in tools.items():
            prefix = "GATE0_TEST_QUALIFIED_" + name.upper()
            legacy.update(
                {
                    prefix: pin["path"],
                    prefix + "_SHA256": pin["sha256"],
                    prefix + "_VERSION": pin["version_line"],
                }
            )
        legacy_raw = (json.dumps(legacy, sort_keys=True) + "\n").encode()
        reads = []

        def read(path, *_, **__):
            path = Path(path)
            reads.append(str(path))
            if path == G["PRIMITIVES"]:
                return PRIMITIVE_BYTES
            if path.name == "cp-gpg-tool-identities.json":
                return legacy_raw
            if path.name in tool_bytes:
                return tool_bytes[path.name]
            return b"synthetic-public-source"

        calls = []

        def command(name, _):
            calls.append(name)
            if name == "architecture":
                return b"amd64\n"
            if name == "packages":
                return (
                    b"gpgconf\t2.4.4-2ubuntu17.6\tamd64\n"
                    b"gpg\t2.4.4-2ubuntu17.6\tamd64\n"
                )
            if name.startswith("verify_"):
                return b""
            return (
                tools[name.removesuffix("_version")]["version_line"]
                + "\npublic version details\n"
            ).encode()

        with (
            patch.dict(
                G,
                {
                    "read_regular": read,
                    "command": command,
                    "operating_system": lambda _: dict(id="ubuntu", version_id="24.04"),
                    "context": lambda: self.context(),
                    "TEMP": Path("/synthetic"),
                },
            ),
            patch.object(G["platform"], "system", return_value="Linux"),
            patch.object(G["platform"], "machine", return_value="x86_64"),
            patch.object(G["time"], "monotonic", return_value=10),
        ):
            record = M["measure"](100)
        self.assertEqual(
            record["operating_system"],
            dict(id="ubuntu", version_id="24.04", architecture="amd64"),
        )
        self.assertEqual(record["tools"], tools)
        self.assertEqual([p["name"] for p in record["packages"]], ["gpg", "gpgconf"])
        self.assertEqual(record["github"]["run_id"], 34)
        self.assertEqual(record["github"]["attempt"], 2)
        self.assertEqual(record["github"]["job_key"], "check")
        self.assertEqual(record["source"]["revision"], "a" * 40)
        self.assertEqual(record["github"]["workflow_revision"], "b" * 40)
        self.assertEqual(
            record["legacy_tool_identities_sha256"],
            hashlib.sha256(legacy_raw).hexdigest(),
        )
        self.assertEqual(set(calls), set(M["COMMANDS"]))
        self.assertNotIn("qualified", json.dumps(record))
        self.assertNotIn("reviewer_record_sha256", record)
        self.assertEqual(
            legacy_raw, (json.dumps(legacy, sort_keys=True) + "\n").encode()
        )

    def test_fixed_command_owner_uses_sanitized_environment_and_shared_deadline(self):
        captured = []

        def run(argv, deadline, **kwargs):
            captured.append((argv, deadline, kwargs))
            return b"public"

        with (
            patch.dict(G, {"RUN": run}),
            patch.object(G["time"], "monotonic", return_value=10),
        ):
            self.assertEqual(M["command"]("architecture", 60), b"public")
            with self.assertRaises(M["Incomplete"]):
                M["command"]("caller-command", 60)
            with self.assertRaises(M["Incomplete"]):
                M["command"]("architecture", 10)
        argv, deadline, kwargs = captured[0]
        self.assertEqual(tuple(argv), M["COMMANDS"]["architecture"])
        self.assertEqual(deadline, 20)
        self.assertEqual(
            kwargs["environment"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
        )
        self.assertEqual(kwargs["maximum"], 16384)

    def test_package_parser_refuses_missing_duplicate_foreign_and_unbounded_rows(self):
        good = b"gpg\t2.4.4-1\tamd64\ngpgconf\t2.4.4-1\tamd64\n"
        self.assertEqual(len(M["packages"](good)), 2)
        for raw in (
            good + good,
            good.replace(b"gpgconf", b"foreign"),
            good.splitlines()[0],
            good.replace(b"amd64", b"arm64"),
            good.replace(b"2.4.4-1", b"bad version"),
            good + b"\n",
        ):
            with self.subTest(raw=raw), self.assertRaises(M["Incomplete"]):
                M["packages"](raw)

    def test_context_only_reads_explicit_public_whitelist(self):
        class PublicEnvironment(dict):
            def __getitem__(self, key):
                if key not in G["CONTEXT_KEYS"]:
                    raise AssertionError("non-public environment read")
                return super().__getitem__(key)

        with patch.object(G["os"], "environ", PublicEnvironment(self.context())):
            self.assertEqual(M["context"](), self.context())
        for key, value in (
            ("GITHUB_JOB", "image"),
            ("GITHUB_SHA", "not-a-sha"),
            ("GITHUB_RUN_ID", "01"),
            ("GITHUB_WORKFLOW_REF", "other/workflow"),
        ):
            environment = self.context()
            environment[key] = value
            with (
                self.subTest(key=key),
                patch.object(G["os"], "environ", environment),
                self.assertRaises(M["Incomplete"]),
            ):
                M["context"]()

    def test_source_workflow_keeps_legacy_writer_and_adds_separate_artifacts(self):
        workflow = (SOURCE.parents[2] / ".github/workflows/ci.yml").read_text()
        self.assertIn(
            'record.write_text(json.dumps(identities, sort_keys=True) + "\\n")',
            workflow,
        )
        self.assertIn("python .github/candidate/measure_gate0_gpg_tools.py", workflow)
        self.assertIn("cp-gpg-native-measurements.json", workflow)
        self.assertIn("cp-gpg-native-measurements.sha256", workflow)

    def test_os_release_exact_aliases_and_closed_public_fields(self):
        for path, raw, expected in (
            (
                "/usr/lib/os-release",
                b'ID=ubuntu\nVERSION_ID="24.04"\nSECRET=not-retained\n',
                {"id": "ubuntu", "version_id": "24.04"},
            ),
            (
                "/etc/os-release",
                b'ID=ubuntu\nVERSION_ID="24.04"\n',
                {"id": "ubuntu", "version_id": "24.04"},
            ),
            ("/unapproved/os-release", b'ID=ubuntu\nVERSION_ID="24.04"\n', None),
            ("/etc/os-release", b'ID=ubuntu\nID=other\nVERSION_ID="24.04"\n', None),
            ("/etc/os-release", b"ID=ubuntu\n", None),
        ):
            reads = []

            def read(path, maximum, deadline, _reads=reads, _raw=raw, **options):
                _reads.append((path, maximum, deadline, options))
                return _raw

            with (
                self.subTest(path=path, raw=raw),
                patch.object(Path, "resolve", return_value=Path(path)),
                patch.dict(G, {"read_regular": read}),
            ):
                if expected is None:
                    with self.assertRaises(M["Incomplete"]):
                        M["operating_system"](100)
                else:
                    self.assertEqual(M["operating_system"](100), expected)
                    self.assertEqual(reads[0][1:], (16384, 100, {"root_owned": True}))
            if path == "/unapproved/os-release":
                self.assertEqual(reads, [])

    def test_canonical_manifest_digest_sidecar_create_once_preserves_legacy(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(G, {"TEMP": Path(directory)}),
        ):
            root = Path(directory)
            legacy = root / "cp-gpg-tool-identities.json"
            legacy.write_bytes(b"existing identity bytes\n")
            record = self.record()
            M["publish"](record, time.monotonic() + 5)
            raw = (root / "cp-gpg-native-measurements.json").read_bytes()
            self.assertEqual(raw, G["P"]["canonical_json"](record, G["LIMIT"]))
            self.assertEqual(
                (root / "cp-gpg-native-measurements.sha256").read_bytes(),
                hashlib.sha256(raw).hexdigest().encode() + b"\n",
            )
            self.assertEqual(legacy.read_bytes(), b"existing identity bytes\n")
            self.assertEqual(
                (root / "cp-gpg-native-measurements.json").stat().st_mode & 0o777, 0o600
            )
            with self.assertRaises(FileExistsError):
                M["publish"]({**record, "changed": True}, time.monotonic() + 5)
            self.assertEqual(
                (root / "cp-gpg-native-measurements.json").read_bytes(), raw
            )
            with self.assertRaises(ValueError):
                M["publish"]({"large": "x" * G["LIMIT"]}, time.monotonic() + 5)

    def test_measurement_failure_never_publishes_or_promotes_qualification(self):
        names = ("gpg", "gpgconf")
        tool_bytes = b"synthetic-public-tool"
        legacy = {}
        for name in names:
            prefix = "GATE0_TEST_QUALIFIED_" + name.upper()
            legacy.update(
                {
                    prefix: "/usr/bin/" + name,
                    prefix + "_SHA256": hashlib.sha256(tool_bytes).hexdigest(),
                    prefix + "_VERSION": name + " (GnuPG) 2.4.4",
                }
            )
        for mutation in ("legacy-mismatch", "verification-output", "tool-changed"):
            count = {}

            def read(path, *_, _mutation=mutation, _count=count, **__):
                path = Path(path)
                if path == G["PRIMITIVES"]:
                    return PRIMITIVE_BYTES
                if path in G["SOURCE_PATHS"].values():
                    return b"synthetic-public-source"
                name = path.name
                if name == "cp-gpg-tool-identities.json":
                    return json.dumps(
                        {} if _mutation == "legacy-mismatch" else legacy
                    ).encode()
                _count[name] = _count.get(name, 0) + 1
                return (
                    b"changed"
                    if _mutation == "tool-changed" and _count[name] > 1
                    else tool_bytes
                )

            def command(name, _):
                if name == "architecture":
                    return b"amd64\n"
                if name == "packages":
                    return b"gpg\t2.4.4-1\tamd64\ngpgconf\t2.4.4-1\tamd64\n"
                if name.startswith("verify_"):
                    return b"changed package file"
                return (name.removesuffix("_version") + " (GnuPG) 2.4.4\n").encode()

            with (
                self.subTest(mutation=mutation),
                patch.dict(
                    G,
                    {
                        "TEMP": Path("/synthetic"),
                        "read_regular": read,
                        "command": command,
                        "context": lambda: self.context(),
                        "operating_system": lambda _: {
                            "id": "ubuntu",
                            "version_id": "24.04",
                        },
                    },
                ),
                patch.object(G["platform"], "system", return_value="Linux"),
                patch.object(G["platform"], "machine", return_value="x86_64"),
                patch.object(G["time"], "monotonic", return_value=10),
            ):
                with self.assertRaises(M["Incomplete"]):
                    M["measure"](100)

    def test_primitive_executes_measured_bytes_in_non_main_module_context(self):
        raw = (
            b"WORKFLOW = '.github/workflows/ci.yml'\n"
            b"ORIGIN = (__name__, __file__, __package__)\n"
            b"def run_bounded():\n    return b'measured-snapshot'\n"
        )
        with patch.object(
            Path, "read_bytes", side_effect=AssertionError("primitive path reopened")
        ):
            M["load_primitives"](raw)
        self.assertEqual(G["RUN"](), b"measured-snapshot")
        self.assertEqual(
            G["P"]["ORIGIN"],
            ("public_gpg_measurement_primitives", str(G["PRIMITIVES"]), ""),
        )

    def test_initial_source_snapshots_are_rechecked_after_measurement(self):
        tool = b"synthetic-public-tool"
        legacy = {}
        for name in ("gpg", "gpgconf"):
            prefix = "GATE0_TEST_QUALIFIED_" + name.upper()
            legacy.update(
                {
                    prefix: "/usr/bin/" + name,
                    prefix + "_SHA256": hashlib.sha256(tool).hexdigest(),
                    prefix + "_VERSION": name + " (GnuPG) 2.4.4",
                }
            )

        def read(path, *_, **__):
            return (
                json.dumps(legacy).encode()
                if Path(path).name == "cp-gpg-tool-identities.json"
                else tool
            )

        def command(name, _):
            if name == "architecture":
                return b"amd64\n"
            if name == "packages":
                return b"gpg\t2.4.4-1\tamd64\ngpgconf\t2.4.4-1\tamd64\n"
            if name.startswith("verify_"):
                return b""
            return (name.removesuffix("_version") + " (GnuPG) 2.4.4\n").encode()

        for changed in G["SOURCE_PATHS"]:
            count = []

            def snapshots(_, _changed=changed, _count=count):
                _count.append(1)
                result = {
                    "workflow_sha256": b"workflow",
                    "helper_sha256": b"helper",
                    "primitives_sha256": PRIMITIVE_BYTES,
                }
                if len(_count) > 1:
                    result[_changed] += b"changed"
                return result

            with (
                self.subTest(changed=changed),
                patch.dict(
                    G,
                    {
                        "TEMP": Path("/synthetic"),
                        "source_snapshots": snapshots,
                        "read_regular": read,
                        "command": command,
                        "context": lambda: self.context(),
                        "operating_system": lambda _: {
                            "id": "ubuntu",
                            "version_id": "24.04",
                        },
                    },
                ),
                patch.object(G["platform"], "system", return_value="Linux"),
                patch.object(G["platform"], "machine", return_value="x86_64"),
                patch.object(G["time"], "monotonic", return_value=10),
            ):
                with self.assertRaises(M["Incomplete"]):
                    M["measure"](100)
            self.assertEqual(len(count), 2)

    def test_each_owned_write_fsync_and_ambiguous_commit_failure_rolls_back_pair(self):
        for operation, point in (
            ("write", 1),
            ("write", 2),
            ("fsync", 1),
            ("fsync", 2),
            ("fsync", 3),
            ("fsync", 4),
            ("fsync", 5),
            ("link", 1),
            ("link", 2),
        ):
            with (
                self.subTest(operation=operation, point=point),
                tempfile.TemporaryDirectory() as directory,
                patch.dict(G, {"TEMP": Path(directory)}),
            ):
                record = self.record()
                original = getattr(os, operation)
                count = []

                def failure(
                    *args,
                    _original=original,
                    _operation=operation,
                    _point=point,
                    _count=count,
                    **kwargs,
                ):
                    _count.append(1)
                    if _operation == "link":
                        result = _original(*args, **kwargs)
                        if len(_count) == _point:
                            raise OSError("synthetic ambiguous link")
                        return result
                    if len(_count) == _point:
                        raise OSError("synthetic owned IO failure")
                    return _original(*args, **kwargs)

                with patch.object(os, operation, failure), self.assertRaises(OSError):
                    M["publish"](record, time.monotonic() + 5)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_each_commit_deadline_refuses_and_cleans_owned_pair(self):
        for point in (1, 2):
            with (
                self.subTest(point=point),
                tempfile.TemporaryDirectory() as directory,
                patch.dict(G, {"TEMP": Path(directory)}),
            ):
                record = self.record()
                original_clock = time.monotonic
                deadline = original_clock() + 5
                original_link = os.link
                count = []
                expired = []

                def link(
                    *args,
                    _point=point,
                    _count=count,
                    _expired=expired,
                    _original_link=original_link,
                    **kwargs,
                ):
                    result = _original_link(*args, **kwargs)
                    _count.append(1)
                    if len(_count) == _point:
                        _expired.append(True)
                    return result

                with (
                    patch.object(os, "link", link),
                    patch.object(
                        time,
                        "monotonic",
                        lambda _deadline=deadline,
                        _expired=expired,
                        _original_clock=original_clock: _deadline + 1
                        if _expired
                        else _original_clock(),
                    ),
                    self.assertRaises(M["Incomplete"]),
                ):
                    M["publish"](record, deadline)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_source_changed_between_staging_and_commit_rolls_back(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(G, {"TEMP": Path(directory)}),
        ):
            record = self.record()
            original = M["source_snapshots"]
            count = []

            def snapshots(deadline):
                result = original(deadline)
                count.append(1)
                if len(count) > 1:
                    result["workflow_sha256"] += b"changed"
                return result

            with (
                patch.dict(G, {"source_snapshots": snapshots}),
                self.assertRaises(M["Incomplete"]),
            ):
                M["publish"](record, time.monotonic() + 5)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_preexisting_and_late_sidecar_collisions_preserve_foreign_bytes(self):
        for late in (False, True):
            with (
                self.subTest(late=late),
                tempfile.TemporaryDirectory() as directory,
                patch.dict(G, {"TEMP": Path(directory)}),
            ):
                root = Path(directory)
                record = self.record()
                sidecar = root / "cp-gpg-native-measurements.sha256"
                original_link = os.link

                def link(
                    source,
                    target,
                    *args,
                    _original_link=original_link,
                    _sidecar=sidecar,
                    **kwargs,
                ):
                    result = _original_link(source, target, *args, **kwargs)
                    if target == "cp-gpg-native-measurements.json":
                        _sidecar.write_bytes(b"foreign-existing-sidecar")
                    return result

                if not late:
                    sidecar.write_bytes(b"foreign-existing-sidecar")
                with patch.object(os, "link", link), self.assertRaises(FileExistsError):
                    M["publish"](record, time.monotonic() + 5)
                self.assertEqual(sidecar.read_bytes(), b"foreign-existing-sidecar")
                self.assertEqual(sorted(p.name for p in root.iterdir()), [sidecar.name])

    def test_foreign_replacement_is_never_unlinked_on_owned_rollback(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(G, {"TEMP": Path(directory)}),
        ):
            root = Path(directory)
            record = self.record()
            original_link = os.link

            def link(source, target, *args, **kwargs):
                original_link(source, target, *args, **kwargs)
                if target == "cp-gpg-native-measurements.json":
                    (root / target).unlink()
                    (root / target).write_bytes(b"foreign-replacement")
                    raise OSError("synthetic post-link failure")

            with patch.object(os, "link", link), self.assertRaises(OSError):
                M["publish"](record, time.monotonic() + 5)
            self.assertEqual(
                (root / "cp-gpg-native-measurements.json").read_bytes(),
                b"foreign-replacement",
            )
            self.assertEqual(len(list(root.iterdir())), 1)

    def test_cleanup_uncertainty_refuses_and_workflow_upload_requires_success(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(G, {"TEMP": Path(directory)}),
        ):
            root = Path(directory)
            record = self.record()
            original_link, original_unlink = os.link, os.unlink

            def link(*args, **kwargs):
                original_link(*args, **kwargs)
                raise OSError("synthetic post-link failure")

            def unlink(name, *args, **kwargs):
                if name == "cp-gpg-native-measurements.json":
                    raise OSError("synthetic rollback failure")
                return original_unlink(name, *args, **kwargs)

            with (
                patch.object(os, "link", link),
                patch.object(os, "unlink", unlink),
                self.assertRaisesRegex(M["Incomplete"], "cleanup-incomplete"),
            ):
                M["publish"](record, time.monotonic() + 5)
            self.assertTrue((root / "cp-gpg-native-measurements.json").exists())
            self.assertFalse((root / "cp-gpg-native-measurements.sha256").exists())
        workflow = (SOURCE.parents[2] / ".github/workflows/ci.yml").read_text()
        self.assertIn("id: public-gpg-measurements", workflow)
        pair = workflow.split(
            "      - name: Retain complete public GnuPG measurement pair\n", 1
        )[1].split(
            "      - name: Retain source-test results and synthetic tool identities\n",
            1,
        )[0]
        self.assertIn(
            "if: ${{ always() && steps.public-gpg-measurements.outcome == 'success' }}",
            pair,
        )
        legacy = workflow.split(
            "      - name: Retain source-test results and synthetic tool identities\n",
            1,
        )[1].split("      # Gate the temporary", 1)[0]
        self.assertIn("if: always()", legacy)
        self.assertIn("cp-gpg-tool-identities.json", legacy)
        self.assertNotIn("cp-gpg-native-measurements", legacy)


if __name__ == "__main__":
    unittest.main()
