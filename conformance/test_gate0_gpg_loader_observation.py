"""Mocked loader resolution and real synthetic byte/owned-write canaries.

Hosted source conformance only: no native loader or encryption execution here.
"""

import ast
import hashlib
import json
import os
import runpy
import stat
import struct
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / ".github/candidate/observe_gate0_gpg_loader.py"
N = runpy.run_path(str(SOURCE), run_name="synthetic_loader_observer")
G = N["observe"].__globals__
OWNER = ROOT / ".github/candidate/measure_gate0_gpg_tools.py"
N["load_measurement"](OWNER.read_bytes())
M = G["M"]
M.load_primitives((ROOT / ".github/candidate/retain_gate0_publisher.py").read_bytes())


def elf(interpreter="/lib64/ld-linux-x86-64.so.2", machine=62):
    value = interpreter.encode() + b"\0"
    raw = bytearray(120 + len(value))
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<HHIQQQIHHHHHH", raw, 16, 3, machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0
    )
    struct.pack_into("<IIQQQQQQ", raw, 64, 3, 0, 120, 0, 0, len(value), 0, 0)
    raw[120:] = value
    return bytes(raw)


LOADER = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
LISTED = "/lib/x86_64-linux-gnu/libc.so.6"
CANONICAL = "/usr/lib/x86_64-linux-gnu/libc.so.6"
OUTPUT = (
    "\tlinux-vdso.so.1 (0xabcdef)\n"
    f"\tlibc.so.6 => {LISTED} (0x123)\n"
    "\t/lib64/ld-linux-x86-64.so.2 (0x456)\n"
).encode()


@contextmanager
def root_metadata():
    """Mock only system ownership; keep actual inodes, clocks and file bytes."""
    actual_fstat, actual_lstat = os.fstat, Path.lstat

    def root(info):
        values = {key: getattr(info, key) for key in G["STABLE"]}
        values["st_uid"] = 0
        return SimpleNamespace(**values)

    with (
        patch.object(os, "fstat", side_effect=lambda fd: root(actual_fstat(fd))),
        patch.object(
            Path, "lstat", lambda path, **kwargs: root(actual_lstat(path, **kwargs))
        ),
    ):
        yield


class LoaderParsingTests(unittest.TestCase):
    def test_bounded_actual_elf_and_closed_output(self):
        self.assertEqual(N["elf_interpreter"](elf()), G["INTERPRETER"])
        bindings = N["parse_loader"](OUTPUT, LOADER)
        self.assertEqual(
            [b["kind"] for b in bindings], ["kernel-vdso", "library", "interpreter"]
        )
        self.assertIsNone(bindings[0]["listed_path"])
        self.assertNotIn("0x", json.dumps(bindings))

    def test_elf_faults(self):
        wrong_count = bytearray(elf())
        struct.pack_into("<H", wrong_count, 56, 129)
        duplicate = bytearray(elf())
        struct.pack_into("<H", duplicate, 56, 2)
        for raw in (
            b"",
            elf(machine=183),
            elf("/unsupported/loader"),
            bytes(wrong_count),
            bytes(duplicate),
            elf()[:-1],
        ):
            with self.subTest(raw_hash=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises((G["Incomplete"], UnicodeError)):
                    N["elf_interpreter"](raw)

    def test_loader_faults(self):
        bad = [
            b"",
            OUTPUT[:-1],
            OUTPUT + OUTPUT,
            OUTPUT.replace(b" => /lib/", b" => lib/"),
            OUTPUT.replace(b"(0x123)", b"not found"),
            OUTPUT.replace(LISTED.encode(), b"/tmp/libc.so.6"),
            OUTPUT.replace(b"libc.so.6 =>", b"linux-vdso.so.1 =>"),
            OUTPUT.replace(b"/lib64/ld-linux-x86-64.so.2", b"/usr/bin/gpg"),
            b"x" * 16385,
            OUTPUT.split(b"\n", 1)[1],
        ]
        for raw in bad:
            with self.subTest(raw_hash=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(G["Incomplete"]):
                    N["parse_loader"](raw, LOADER)

    def test_protected_alias_resolution_and_faults(self):
        def info(mode):
            return SimpleNamespace(
                st_dev=1,
                st_ino=1,
                st_mode=mode,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_size=1,
                st_mtime_ns=1,
                st_ctime_ns=1,
            )

        aliases = {
            "/lib": "usr/lib",
            "/lib64": "usr/lib64",
            "/usr/lib64/ld-linux-x86-64.so.2": (
                "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
            ),
        }

        def lstat(path):
            path = str(path)
            if path in aliases:
                return info(stat.S_IFLNK | 0o777)
            return info(
                (stat.S_IFREG | 0o755) if path == LOADER else stat.S_IFDIR | 0o755
            )

        with (
            patch.object(Path, "lstat", lstat),
            patch.object(os, "readlink", lambda path: aliases[str(path)]),
        ):
            canonical, edges = N["resolve_library"](G["INTERPRETER"], loader=True)
            self.assertEqual(canonical, LOADER)
            self.assertEqual(len(edges), 2)
            for target in ("/unsupported/escape", "/lib64", "/usr/lib/wrong-loader"):
                with (
                    self.subTest(target=target),
                    patch.dict(aliases, {"/lib64": target}),
                ):
                    with self.assertRaises(G["Incomplete"]):
                        N["resolve_library"](G["INTERPRETER"], loader=True)
        with patch.object(Path, "lstat", return_value=info(stat.S_IFDIR | 0o777)):
            with self.assertRaises(G["Incomplete"]):
                N["resolve_library"](LISTED)

    def test_preload_is_not_read(self):
        with patch.object(Path, "lstat", return_value=object()):
            with self.assertRaises(G["Incomplete"]):
                N["no_preload"]()


class HeldFilesTests(unittest.TestCase):
    def test_held_actual_bytes_drift_refuses(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            root_metadata(),
            patch.object(
                M, "read_regular", side_effect=lambda p, *a, **k: p.read_bytes()
            ),
        ):
            path = Path(directory) / "synthetic-public-file"
            path.write_bytes(b"public-library")
            files = N["Files"](time.monotonic() + 10)
            try:
                # Only replace the root-owned system reader boundary; holding,
                # hashing, inode comparison and reread use real synthetic bytes.
                row, _ = files.capture(str(path))
                files.verify()
                self.assertTrue(row["stable_before_after"])
                path.write_bytes(b"changed-library")
                with self.assertRaises(G["Incomplete"]):
                    files.verify()
            finally:
                files.close()

    def test_replacement_and_limits_refuse(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            root_metadata(),
            patch.object(
                M, "read_regular", side_effect=lambda p, *a, **k: p.read_bytes()
            ),
        ):
            path = Path(directory) / "library"
            path.write_bytes(b"public")
            files = N["Files"](time.monotonic() + 10)
            try:
                files.capture(str(path))
                path.unlink()
                path.write_bytes(b"public")
                with self.assertRaises(G["Incomplete"]):
                    files.verify()
                files.total = 134217728
                fd = next(iter(files.held.values()))[0]
                with self.assertRaises(G["Incomplete"]):
                    files.read(fd, 33554432)
            finally:
                files.close()
        with self.assertRaises(G["Incomplete"]):
            N["before"](time.monotonic() - 1)


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.deadline = time.monotonic() + 30
        self.sources = {
            key: b"synthetic-source-" + key.encode() for key in G["SOURCES"]
        }
        self.context = dict(
            GITHUB_SHA="a" * 40,
            GITHUB_REPOSITORY="synthetic/repo",
            GITHUB_REPOSITORY_ID="1",
            GITHUB_RUN_ID="2",
            GITHUB_RUN_ATTEMPT="1",
            GITHUB_JOB="check",
            GITHUB_REF="refs/pull/1/merge",
            GITHUB_WORKFLOW_REF="synthetic/repo/.github/workflows/ci.yml@refs/pull/1/merge",
            GITHUB_WORKFLOW_SHA="b" * 40,
        )
        self.prior = dict(
            schema="DotmacPublisherGpgToolMeasurements.v1",
            measurement_scope="hosted-ci-public-os-and-tool-metadata.v1",
            github=N["github_record"](self.context),
            source=dict(
                revision="a" * 40,
                workflow_sha256=N["digest"](self.sources["workflow_sha256"]),
                helper_sha256=N["digest"](self.sources["measurement_sha256"]),
                primitives_sha256=N["digest"](self.sources["primitives_sha256"]),
            ),
            operating_system=dict(
                id="ubuntu", version_id="24.04", architecture="amd64"
            ),
            tools={
                name: dict(
                    path=path,
                    sha256=N["digest"](elf()),
                    version_line=name + " (GnuPG) 2.4.4",
                )
                for name, path in G["TARGETS"].items()
            },
            packages=[
                dict(name=name, version="1", architecture="amd64")
                for name in G["TARGETS"]
            ],
        )
        self.calls = []
        self.rows = {}

    def capture(self, path, **kwargs):
        canonical = (
            LOADER
            if kwargs.get("loader")
            else path.replace("/lib/", "/usr/lib/", 1)
            if path.startswith("/lib/")
            else path
        )
        if canonical not in self.rows:
            self.rows[canonical] = dict(
                id=str(len(self.rows)),
                canonical_path=canonical,
                listed_paths=[],
                symlink_edges=[],
                sha256=N["digest"](elf()),
                package_names=[],
                stable_before_after=True,
            )
        row = self.rows[canonical]
        if path not in row["listed_paths"]:
            row["listed_paths"].append(path)
        return row, elf()

    def provider(self, argv, _deadline):
        self.calls.append(argv)
        if argv[-2:-1] == ["--list"]:
            return OUTPUT
        if argv == ["/usr/bin/dpkg", "--print-architecture"]:
            return b"amd64\n"
        if argv[1] == "--search":
            pattern = argv[2]
            if "gpgconf" in pattern:
                return b"gpgconf: /usr/bin/gpgconf\n"
            if "gpg" in pattern:
                return b"gpg: /usr/bin/gpg\n"
            path = pattern.removeprefix("*")
            return ("libc6:amd64: " + path + "\n").encode()
        if argv[1] == "--show":
            return (argv[-1].split(":")[0] + "\t1\tamd64\n").encode()
        if argv[1] == "--verify":
            return b""
        raise AssertionError(argv)

    def run_observe(
        self, *, mutate=None, provider=None, preload=None, cache=False, fault=None
    ):
        if mutate:
            mutate(self.prior)
        raw = json.dumps(self.prior).encode()
        sidecar = (N["digest"](raw) + "\n").encode()
        files = SimpleNamespace(capture=self.capture, verify=lambda: None)

        class Held:
            def values(inner):
                return [(None, None, row) for row in self.rows.values()]

        files.held = Held()

        reads, source_reads, cache_reads = 0, 0, 0

        def read(path, *_args, **_kwargs):
            nonlocal reads
            reads += 1
            if fault == "prior-drift" and reads > 2:
                return b"changed"
            if fault == "sidecar" and path.name.endswith(".sha256"):
                return b"0" * 64 + b"\n"
            return sidecar if path.name.endswith(".sha256") else raw

        def snapshots(_):
            nonlocal source_reads
            source_reads += 1
            result = dict(self.sources)
            if fault == "source-drift" and source_reads > 1:
                result["observer_sha256"] = b"changed-source"
            return result

        def cache_stat(path):
            nonlocal cache_reads
            if str(path) == "/etc/ld.so.cache":
                cache_reads += 1
                if cache or (fault == "cache-appeared" and cache_reads > 1):
                    return object()
            raise FileNotFoundError()

        with (
            patch.dict(
                G,
                {
                    "TEMP": Path("/synthetic"),
                    "MEASUREMENT_BYTES": self.sources["measurement_sha256"],
                },
            ),
            patch.object(M, "load_primitives"),
            patch.object(M, "context", return_value=self.context),
            patch.object(
                M,
                "operating_system",
                return_value=dict(id="ubuntu", version_id="24.04"),
            ),
            patch.object(M, "read_regular", side_effect=read),
            patch.object(
                M,
                "command",
                side_effect=lambda name, _: (
                    name.removesuffix("_version") + " (GnuPG) 2.4.4\n"
                ).encode(),
            ),
            patch.dict(
                G,
                {
                    "snapshots": snapshots,
                    "command": provider or self.provider,
                    "no_preload": preload or (lambda: None),
                },
            ),
            patch.object(Path, "lstat", cache_stat),
            patch.object(G["platform"], "system", return_value="Linux"),
            patch.object(G["platform"], "machine", return_value="x86_64"),
        ):
            record, verify = N["observe"](self.deadline, files)
            verify()
            return record

    def test_actual_composition_and_package_joins(self):
        record = self.run_observe(cache=True)
        self.assertEqual(set(record["targets"]), {"gpg", "gpgconf"})
        self.assertEqual(len([a for a in self.calls if "--list" in a]), 2)
        self.assertEqual(
            record["loader"]["trust_basis"], "existing-hosted-Ubuntu-bootstrap"
        )
        cache = record["loader_cache"]["file"]
        self.assertEqual(cache["package_names"], [])
        self.assertTrue(
            all(r["package_names"] for r in record["files"] if r is not cache)
        )
        self.assertIsNone(record["targets"]["gpg"]["dependencies"][0]["file_id"])

    def test_bootstrap_owner_swap_refuses_before_primitives_or_commands(self):
        # Bootstrap executed A, while the initial roster and potential prior
        # pair name B. The actual orchestration must refuse before using A.
        with (
            patch.dict(
                G,
                {
                    "MEASUREMENT_BYTES": b"executed-owner-A",
                    "snapshots": lambda _: self.sources,
                },
            ),
            patch.object(G["platform"], "system", return_value="Linux"),
            patch.object(G["platform"], "machine", return_value="x86_64"),
            patch.object(M, "load_primitives") as primitives,
            patch.object(M, "command") as commands,
            patch.object(M, "RUN") as run,
        ):
            with self.assertRaises(G["Incomplete"]):
                N["observe"](self.deadline, SimpleNamespace())
            primitives.assert_not_called()
            commands.assert_not_called()
            run.assert_not_called()

    def test_prior_context_and_tool_faults(self):
        for mutate in (
            lambda p: p["github"].update(run_id=9),
            lambda p: p["source"].update(revision="c" * 40),
            lambda p: p["source"].update(workflow_sha256="d" * 64),
            lambda p: p["tools"]["gpg"].update(sha256="e" * 64),
        ):
            self.setUp()
            with self.assertRaises(G["Incomplete"]):
                self.run_observe(mutate=mutate)

    def test_prior_pair_source_and_cache_drift(self):
        for fault in ("sidecar", "source-drift", "prior-drift", "cache-appeared"):
            self.setUp()
            with self.subTest(fault=fault), self.assertRaises(G["Incomplete"]):
                self.run_observe(fault=fault)

    def test_provider_missing_ambiguous_modified_and_metadata_faults(self):
        for fault in ("unowned", "ambiguous", "metadata", "modified", "changed-verify"):
            self.setUp()
            counts = {}

            def provider(argv, deadline, fault=fault, counts=counts):
                raw = self.provider(argv, deadline)
                if argv[1] == "--search" and fault == "unowned":
                    return b""
                if argv[1] == "--search" and fault == "ambiguous":
                    return raw + raw.replace(raw.split(b":", 1)[0], b"another", 1)
                if argv[1] == "--show" and fault == "metadata":
                    return b"wrong\t1\tamd64\n"
                if argv[1] == "--verify":
                    counts[argv[-1]] = counts.get(argv[-1], 0) + 1
                    if fault == "modified" or (
                        fault == "changed-verify" and counts[argv[-1]] > 1
                    ):
                        return b"changed\n"
                return raw

            with self.subTest(fault=fault), self.assertRaises(G["Incomplete"]):
                self.run_observe(provider=provider)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.deadline = time.monotonic() + 10
        self.record = {"schema": "synthetic-loader-observation", "public": True}

    def test_complete_pair_and_preexisting_foreign_preserved(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(G, {"TEMP": Path(directory)}),
        ):
            N["publish"](self.record, lambda: None, self.deadline)
            raw = (Path(directory) / G["OUTPUT_NAMES"][0]).read_bytes()
            self.assertEqual(
                (Path(directory) / G["OUTPUT_NAMES"][1]).read_bytes(),
                (N["digest"](raw) + "\n").encode(),
            )
            with self.assertRaises(G["Incomplete"]):
                N["publish"](self.record, lambda: None, self.deadline)
            self.assertEqual((Path(directory) / G["OUTPUT_NAMES"][0]).read_bytes(), raw)

    def test_interrupted_links_and_source_drift_remove_only_owned_outputs(self):
        for failure in ("second-link", "verify"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
                patch.dict(G, {"TEMP": Path(directory)}),
            ):
                foreign = Path(directory) / "foreign"
                foreign.write_bytes(b"preserved")
                real_link = os.link
                count = 0

                def link(*args, _real_link=real_link, **kwargs):
                    nonlocal count
                    count += 1
                    if count == 2:
                        raise OSError("synthetic interruption")
                    return _real_link(*args, **kwargs)

                checks = 0

                def verify(failure=failure):
                    nonlocal checks
                    checks += 1
                    if failure == "verify" and checks == 2:
                        raise G["Incomplete"]()

                with patch.object(
                    os,
                    "link",
                    side_effect=link if failure == "second-link" else real_link,
                ):
                    with self.assertRaises((OSError, G["Incomplete"])):
                        N["publish"](self.record, verify, self.deadline)
                self.assertEqual(list(Path(directory).iterdir()), [foreign])
                self.assertEqual(foreign.read_bytes(), b"preserved")

    def test_expired_budget_refuses(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(G, {"TEMP": Path(directory)}),
        ):
            with self.assertRaises(G["Incomplete"]):
                N["publish"](self.record, lambda: None, time.monotonic() - 1)
            self.assertEqual(list(Path(directory).iterdir()), [])


class FailureDiagnosticTests(unittest.TestCase):
    def decode(self, error):
        prefix = "GATE0_PUBLIC_GPG_LOADER_OBSERVATION_INCOMPLETE "
        text = N["failure_diagnostic"](error)
        self.assertTrue(text.startswith(prefix))
        self.assertLess(len(text), 8192)
        record = json.loads(text.removeprefix(prefix))
        self.assertIn(record["phase"], G["PHASES"])
        for item in record["exception_chain"]:
            self.assertIn(item["kind"], G["EXCEPTION_KINDS"] | {"other"})
            self.assertIn(item["relation"], {"raised", "cause", "context"})
            self.assertLessEqual(len(item["frames"]), 8)
            for frame in item["frames"]:
                self.assertEqual(set(frame), {"owner", "line"})
                self.assertIn(
                    frame["owner"], {"observer", "measurement-owner", "retention-owner"}
                )
                self.assertIs(type(frame["line"]), int)
                self.assertGreater(frame["line"], 0)
        return text, record

    def test_redaction_closed_grammar_and_no_post_failure_io(self):
        class PoisonedError(ValueError):
            def __str__(self):
                raise AssertionError("exception string accessed")

            def __repr__(self):
                raise AssertionError("exception repr accessed")

        private_marker = "NEVER_REPORT_PRIVATE_VALUE_OR_PATH"
        error = PoisonedError(private_marker)
        with (
            patch.dict(
                G, {"DIAGNOSTIC": {"phase": private_marker, "work_failure": None}}
            ),
            patch.object(os, "open", side_effect=AssertionError("IO after failure")),
            patch.object(os, "read", side_effect=AssertionError("IO after failure")),
            patch.object(
                Path, "read_bytes", side_effect=AssertionError("IO after failure")
            ),
            patch.object(M, "RUN", side_effect=AssertionError("command after failure")),
            patch.object(
                time, "monotonic", side_effect=AssertionError("clock after failure")
            ),
        ):
            text, record = self.decode(error)
        self.assertNotIn(private_marker, text)
        self.assertEqual(record["phase"], "unknown")
        self.assertEqual(record["exception_chain"][0]["kind"], "other")

    def test_fixed_owner_lines_and_original_failure_survive_cleanup_override(self):
        with patch.dict(G, {"DIAGNOSTIC": {"phase": "target", "work_failure": None}}):
            try:
                N["require"](False)
            except G["Incomplete"] as error:
                original = error
                N["remember_failure"](error)
            G["DIAGNOSTIC"]["phase"] = "descriptor-cleanup"
            try:
                try:
                    raise original
                except G["Incomplete"]:
                    raise OSError("NEVER_REPORT_CLEANUP_ERROR_VALUE") from None
            except OSError as error:
                text, record = self.decode(error)
        self.assertNotIn("NEVER_REPORT_CLEANUP_ERROR_VALUE", text)
        self.assertEqual(record["work_failure"]["phase"], "target")
        self.assertTrue(
            any(
                frame["owner"] == "observer"
                for frame in record["work_failure"]["frames"]
            )
        )
        self.assertEqual(
            {item["kind"] for item in record["exception_chain"]},
            {"OSError", "Incomplete"},
        )

    def test_bounded_cycle_detected_cause_and_context(self):
        errors = [ValueError("NEVER_REPORT_CHAIN_VALUE") for _ in range(10)]
        for index in range(9):
            errors[index].__cause__ = errors[index + 1]
            errors[index].__context__ = errors[index + 1]
        errors[-1].__context__ = errors[0]
        with patch.dict(G, {"DIAGNOSTIC": {"phase": "package", "work_failure": None}}):
            text, record = self.decode(errors[0])
        self.assertEqual(len(record["exception_chain"]), 4)
        self.assertTrue(record["chain_truncated"])
        self.assertNotIn("NEVER_REPORT_CHAIN_VALUE", text)
        error = ValueError()
        error.__cause__ = error
        with patch.dict(
            G, {"DIAGNOSTIC": {"phase": "bootstrap", "work_failure": None}}
        ):
            _, record = self.decode(error)
        self.assertEqual(len(record["exception_chain"]), 1)
        self.assertFalse(record["chain_truncated"])

    def test_actual_publication_remembers_primary_before_cleanup_refusal(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                G,
                {
                    "TEMP": Path(directory),
                    "DIAGNOSTIC": {"phase": "publication", "work_failure": None},
                },
            ),
        ):
            with (
                patch.object(
                    os, "link", side_effect=ValueError("NEVER_REPORT_WORK_VALUE")
                ),
                patch.object(
                    os, "unlink", side_effect=OSError("NEVER_REPORT_CLEANUP_VALUE")
                ),
            ):
                try:
                    N["publish"](
                        {"synthetic": True}, lambda: None, time.monotonic() + 10
                    )
                except G["Incomplete"] as error:
                    text, record = self.decode(error)
                else:
                    self.fail("publication unexpectedly succeeded")
            self.assertEqual(record["phase"], "publication-cleanup")
            self.assertEqual(record["work_failure"]["kind"], "ValueError")
            self.assertEqual(record["work_failure"]["phase"], "publication")
            self.assertNotIn("NEVER_REPORT", text)
            self.assertTrue(
                all(not (Path(directory) / name).exists() for name in G["OUTPUT_NAMES"])
            )


class SourceBoundaryTests(unittest.TestCase):
    def test_existing_crypto_measurement_and_acceptors_unchanged(self):
        pins = {
            ".github/candidate/measure_gate0_gpg_tools.py": (
                "110e312e4a30068659268e43919cd407e18bd231f879da79f7041b446b84723b"
            ),
            ".github/candidate/retain_gate0_publisher.py": (
                "efd52b0459e11d57637c110bd3542d001c02861ddc4cd07b977be8a4778bbec5"
            ),
            "conformance/test_gate0_publisher_retention_gpg.py": (
                "67603c1450fe72822bdef1e0d1db411357228a2ca5ad8ea60845d06ed72d8da0"
            ),
        }
        for path, pin in pins.items():
            self.assertEqual(N["digest"]((ROOT / path).read_bytes()), pin)

    def test_finite_source_scope_and_separate_upload(self):
        tree = ast.parse(SOURCE.read_text())
        imports = {node.name for node in ast.walk(tree) if isinstance(node, ast.alias)}
        self.assertFalse(
            imports & {"subprocess", "threading", "signal", "socket", "urllib"}
        )
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(
            calls
            & {
                "Popen",
                "production_main",
                "role_main",
                "qualify_tools",
                "qualify_role_tools",
            }
        )
        text = SOURCE.read_text()
        for forbidden in (
            "/proc/",
            "LD_PRELOAD",
            "LD_DEBUG",
            "LD_TRACE_LOADED_OBJECTS",
            '"ldd"',
        ):
            self.assertNotIn(forbidden, text)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn(
            "steps.public-gpg-loader-observation.outcome == 'success'", workflow
        )
        self.assertIn("python .github/candidate/observe_gate0_gpg_loader.py", workflow)
        self.assertEqual(
            workflow.count(
                "python -m unittest discover -s conformance -p "
                "test_gate0_publisher_retention_gpg.py -v"
            ),
            1,
        )
        self.assertEqual(
            set(G["TARGETS"].values()), {"/usr/bin/gpg", "/usr/bin/gpgconf"}
        )


if __name__ == "__main__":
    unittest.main()
