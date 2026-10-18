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
ALIAS_OUTPUT = OUTPUT.replace(
    b"/lib64/ld-linux-x86-64.so.2 (0x456)",
    (G["INTERPRETER"] + " => " + LOADER + " (0x456)").encode(),
)


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
    def test_exact_validated_interpreter_alias_and_faults(self):
        self.assertEqual(
            N["parse_loader"](ALIAS_OUTPUT, LOADER),
            N["parse_loader"](OUTPUT, LOADER),
        )
        for raw in (
            ALIAS_OUTPUT.replace(G["INTERPRETER"].encode(), b"/lib64/wrong-loader"),
            ALIAS_OUTPUT.replace(LOADER.encode(), b"/usr/lib/wrong-loader"),
            ALIAS_OUTPUT.replace(
                LOADER.encode(), b"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
            ),
            ALIAS_OUTPUT.replace(
                (G["INTERPRETER"] + " => ").encode(),
                (G["INTERPRETER"] + "  => ").encode(),
            ),
            ALIAS_OUTPUT.replace(
                (G["INTERPRETER"] + " => ").encode(),
                (G["INTERPRETER"] + "\t=>\t").encode(),
            ),
            ALIAS_OUTPUT.replace(b"(0x456)", b"(0xABC)"),
            ALIAS_OUTPUT + ALIAS_OUTPUT.splitlines(keepends=True)[-1],
            ALIAS_OUTPUT + OUTPUT.splitlines(keepends=True)[-1],
        ):
            with (
                self.subTest(raw_hash=hashlib.sha256(raw).hexdigest()),
                self.assertRaises(G["Incomplete"]),
            ):
                N["parse_loader"](raw, LOADER)

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
                dev=1,
                inode=len(self.rows) + 1,
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

    def test_alias_row_composition_joins_same_held_loader_identity(self):
        def provider(argv, deadline):
            return ALIAS_OUTPUT if "--list" in argv else self.provider(argv, deadline)

        record = self.run_observe(provider=provider)
        for target in record["targets"].values():
            interpreter = [
                b for b in target["dependencies"] if b["kind"] == "interpreter"
            ]
            self.assertEqual(len(interpreter), 1)
            self.assertEqual(interpreter[0]["listed_path"], G["INTERPRETER"])
            self.assertEqual(interpreter[0]["file_id"], record["loader"]["file_id"])

    def test_diversion_composition_rechecks_response_and_refuses_drift(self):
        for drift in (False, True):
            self.setUp()
            reads = 0

            def provider(argv, deadline, drift=drift):
                nonlocal reads
                raw = self.provider(argv, deadline)
                if "--list" in argv:
                    # Loader listed only the canonical library coordinate;
                    # the later finite /lib alias must be genuinely captured.
                    raw = raw.replace(LISTED.encode(), CANONICAL.encode())
                if argv[1] == "--search" and argv[-1] == "*" + LISTED:
                    reads += 1
                    raw = ("\n".join(PairedDiversionTests().lines()) + "\n").encode()
                    if drift and reads > 1:
                        raw += b"\n"
                return raw

            if drift:
                with self.assertRaises(G["Incomplete"]):
                    self.run_observe(provider=provider)
            else:
                record = self.run_observe(provider=provider)
                declarations = [
                    d
                    for p in record["packages"]
                    for d in p.get("declared_diversions", [])
                ]
                self.assertEqual(len(declarations), 1)
                self.assertFalse(declarations[0]["destination_bytes_measured"])
                self.assertIn(LISTED, self.rows[CANONICAL]["listed_paths"])
                self.assertGreaterEqual(reads, 3)

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


class PairedDiversionTests(unittest.TestCase):
    def test_missing_finite_alias_capture_proves_same_held_identity(self):
        for owned in (CANONICAL, LISTED):
            row = dict(
                id="held",
                canonical_path=CANONICAL,
                listed_paths=[CANONICAL],
                sha256="a" * 64,
                dev=1,
                inode=2,
            )
            calls = []

            def capture(path, original, calls=calls, row=row):
                calls.append(path)
                self.assertIs(original, row)
                self.assertEqual(path, LISTED)
                original["listed_paths"].append(path)
                return original

            owner, declaration = N["parse_declared_diversion"](
                self.lines(owned=owned), row, {LISTED, CANONICAL}, capture
            )
            self.assertEqual(owner, "libc6:amd64")
            self.assertEqual(calls, [LISTED])
            self.assertEqual(declaration["file_id"], "held")
            self.assertEqual(declaration["ownership_path"], owned)
            self.assertFalse(declaration["destination_bytes_measured"])

    def test_pair_faults_precede_capture_and_different_files_or_capture_failure_refuse(
        self,
    ):
        row = dict(
            id="held",
            canonical_path=CANONICAL,
            listed_paths=[CANONICAL],
            sha256="a" * 64,
            dev=1,
            inode=2,
        )
        lines = self.lines()
        variants = [
            lines[:2],
            lines + [lines[0]],
            [lines[0], lines[1].replace(".usr-is-merged", ".wrong-suffix"), lines[2]],
            [
                line.replace("diversion by libc6", "diversion by wrong-package")
                for line in lines
            ],
            self.lines(source="/UNKNOWN_PRIVATE_ESCAPE"),
            self.lines(owned="/UNKNOWN_PRIVATE_ESCAPE"),
        ]
        for candidate in variants:
            calls = []
            with (
                self.subTest(candidate_hash=N["digest"]("\n".join(candidate).encode())),
                self.assertRaises(G["Incomplete"]),
            ):
                N["parse_declared_diversion"](
                    candidate,
                    row,
                    {LISTED, CANONICAL},
                    lambda path, original, calls=calls: calls.append(path),
                )
            self.assertEqual(calls, [])
        for key in ("id", "canonical_path", "sha256", "dev", "inode"):

            def changed(path, original, key=key):
                return dict(original, **{key: "different", "listed_paths": [path]})

            with self.subTest(key=key), self.assertRaises(G["Incomplete"]):
                N["parse_declared_diversion"](lines, row, {LISTED, CANONICAL}, changed)

        def failed(*_):
            raise G["Incomplete"]("synthetic capture failure")

        with self.assertRaises(G["Incomplete"]):
            N["parse_declared_diversion"](lines, row, {LISTED, CANONICAL}, failed)

    def row(self):
        return dict(
            id="synthetic-held",
            canonical_path=CANONICAL,
            listed_paths=[LISTED, CANONICAL],
        )

    def lines(self, owned=CANONICAL, source=LISTED):
        return [
            "diversion by libc6 from: " + source,
            "diversion by libc6 to: " + source + ".usr-is-merged",
            "libc6:amd64: " + owned,
        ]

    def test_complete_pair_accepts_same_held_coordinates_and_orders(self):
        for owned in (LISTED, CANONICAL):
            lines = self.lines(owned=owned)
            for ordered in (lines, lines[::-1], [lines[2], lines[0], lines[1]]):
                owner, declaration = N["parse_declared_diversion"](
                    ordered, self.row(), {LISTED, CANONICAL}, None
                )
                self.assertEqual(owner, "libc6:amd64")
                self.assertEqual(declaration["ownership_path"], owned)
                self.assertEqual(declaration["from_path"], LISTED)
                self.assertEqual(declaration["to_path"], LISTED + ".usr-is-merged")
                self.assertEqual(declaration["file_id"], "synthetic-held")
                self.assertTrue(declaration["declared_metadata_only"])
                self.assertFalse(declaration["destination_bytes_measured"])

    def test_incomplete_local_unknown_wrong_identity_or_suffix_refuses(self):
        lines = self.lines()
        variants = [
            lines[:2],
            lines + [lines[0]],
            [lines[0], lines[0], lines[2]],
            [lines[0], lines[1], "UNKNOWN_PRIVATE_ROW"],
            [line.replace("diversion by libc6", "local diversion") for line in lines],
            [lines[0], lines[1].replace("libc6 to", "other-package to"), lines[2]],
            [
                line.replace("diversion by libc6", "diversion by other-package")
                for line in lines
            ],
            [line.replace("libc6", "libc6:arm64") for line in lines],
            [
                lines[0],
                lines[1].replace(".usr-is-merged", ".arbitrary-suffix"),
                lines[2],
            ],
            [
                lines[0],
                lines[1].replace(".usr-is-merged", ".usr-is-merged/escape"),
                lines[2],
            ],
            self.lines(source="/lib/uncaptured"),
            self.lines(owned="/lib/uncaptured"),
        ]
        for candidate in variants:
            with (
                self.subTest(candidate_hash=N["digest"]("\n".join(candidate).encode())),
                self.assertRaises(G["Incomplete"]),
            ):
                N["parse_declared_diversion"](
                    candidate, self.row(), {LISTED, CANONICAL}, None
                )
        # A synthesized merged-/usr alias alone is not a captured identity.
        row = dict(id="synthetic-held", canonical_path=CANONICAL, listed_paths=[])
        with self.assertRaises(G["Incomplete"]):
            N["parse_declared_diversion"](self.lines(), row, {LISTED, CANONICAL}, None)

    def test_architecture_metadata_and_query_recheck_are_required(self):
        query = ("\n".join(self.lines()) + "\n").encode()
        calls = []

        def provider(argv, deadline, architecture="amd64"):
            calls.append((argv, deadline))
            if argv[1] == "--search":
                return query
            if argv[1] == "--show":
                return ("libc6\t1\t" + architecture + "\n").encode()
            if argv[1] == "--verify":
                return b""
            raise AssertionError(argv)

        deadline = time.monotonic() + 10
        checks = []
        with patch.dict(G, {"command": provider}):
            packages = N["package_owners"]([self.row()], deadline, checks, None)
            N["verify_ownership_queries"](checks, deadline)
        declaration = packages[0]["declared_diversions"][0]
        self.assertEqual(declaration["query_stdout_sha256"], N["digest"](query))
        self.assertEqual(declaration["query_stdout_bytes"], len(query))
        self.assertEqual(checks, [("*" + LISTED, query)])
        self.assertTrue(all(end == deadline for _, end in calls))
        with patch.dict(G, {"command": lambda argv, end: provider(argv, end, "all")}):
            with self.assertRaises(G["Incomplete"]):
                N["package_owners"]([self.row()], deadline, [], None)
        with patch.dict(G, {"command": lambda *_: query + b"\n"}):
            with self.assertRaises(G["Incomplete"]):
                N["verify_ownership_queries"](checks, deadline)
        with self.assertRaises(G["Incomplete"]):
            N["verify_ownership_queries"](checks, time.monotonic() - 1)


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
        if record["loader_row"] is not None:
            row = record["loader_row"]
            self.assertEqual(
                set(row),
                {
                    "shape",
                    "validated_interpreter_alias_mapping",
                    "known_row_spacing_variant",
                },
            )
            self.assertIn(row["shape"], G["LOADER_ROW_SHAPES"])
            self.assertIs(type(row["validated_interpreter_alias_mapping"]), bool)
            self.assertIs(type(row["known_row_spacing_variant"]), bool)
        if record["package_row"] is not None:
            row = record["package_row"]
            self.assertEqual(
                set(row),
                {"shape", "file_category", "grammar_matched", "exact_alias_matched"},
            )
            self.assertIn(row["shape"], G["PACKAGE_ROW_SHAPES"])
            self.assertIn(row["file_category"], G["FILE_CATEGORIES"] | {None})
            self.assertIs(type(row["grammar_matched"]), bool)
            self.assertIs(type(row["exact_alias_matched"]), bool)
        if record["package_query"] is not None:
            query = record["package_query"]
            self.assertEqual(
                set(query), set(G["QUERY_COUNT_KEYS"]) | set(G["QUERY_BOOL_KEYS"])
            )
            for key in G["QUERY_COUNT_KEYS"]:
                self.assertIs(type(query[key]), int)
                self.assertTrue(0 <= query[key] <= 128)
            for key in G["QUERY_BOOL_KEYS"]:
                self.assertIs(type(query[key]), bool)
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

    def test_complete_query_summary_precedes_first_refusal_without_more_commands(self):
        lines = [
            "diversion by private-owner from: " + LISTED,
            "diversion by private-owner to: " + LISTED + ".UNKNOWN_PRIVATE_SUFFIX",
            "private-owner:amd64: " + CANONICAL,
        ]
        row = dict(id="synthetic", canonical_path=CANONICAL, listed_paths=[LISTED])
        calls = []

        def command(*args):
            calls.append(args)
            return ("\n".join(lines) + "\n").encode()

        # Mock only the existing command boundary; actual ownership parsing
        # still refuses the first row and summarizes later rows.
        with patch.dict(
            G,
            {
                "DIAGNOSTIC": {"phase": "package", "work_failure": None},
                "command": command,
            },
        ):
            try:
                N["package_owners"]([row], time.monotonic() + 5, [], None)
            except G["Incomplete"] as error:
                text, record = self.decode(error)
            else:
                self.fail("diversion record unexpectedly accepted")
        self.assertEqual(len(calls), 1)
        query = record["package_query"]
        self.assertEqual(query["rows"], 3)
        self.assertEqual(query["package_owner_rows"], 1)
        self.assertEqual(query["diversion_from_rows"], 1)
        self.assertEqual(query["diversion_to_rows"], 1)
        self.assertEqual(query["from_alias_matches"], 1)
        self.assertEqual(query["ownership_alias_matches"], 1)
        self.assertEqual(query["to_same_directory_basename_suffix"], 1)
        self.assertFalse(query["diversion_owner_exact_matches_ownership"])
        self.assertTrue(query["diversion_owner_base_matches_ownership"])
        self.assertTrue(query["from_to_count_balance_not_pair_proof"])
        for forbidden in ("private-owner", "UNKNOWN_PRIVATE_SUFFIX", LISTED, CANONICAL):
            self.assertNotIn(forbidden, text)

    def test_query_summary_limits_unknown_local_and_owner_ambiguity(self):
        aliases = {LISTED, CANONICAL}
        lines = [
            "local diversion from: " + LISTED,
            "local diversion to: /UNKNOWN_PRIVATE_PATH",
            "private-owner: " + CANONICAL,
            "other-owner: " + CANONICAL,
            "UNKNOWN_PRIVATE_ROW",
        ]
        query = N["package_query_summary"](lines, aliases)
        self.assertEqual(query["local_diversion_rows"], 2)
        self.assertEqual(query["ownership_owners"], 2)
        self.assertEqual(query["other_rows"], 1)
        self.assertEqual(query["to_outside_library_roots"], 1)
        self.assertFalse(query["unique_ownership_owner"])
        self.assertFalse(query["diversion_owner_base_matches_ownership"])
        bounded = N["package_query_summary"](lines * 40, aliases)
        self.assertEqual(bounded["rows"], 128)
        self.assertTrue(bounded["overflow"])
        self.assertFalse(bounded["from_to_count_balance_not_pair_proof"])
        self.assertFalse(bounded["unique_diversion_owner"])
        injected = dict.fromkeys(G["QUERY_COUNT_KEYS"], "UNKNOWN_PRIVATE_COUNT")
        injected.update(dict.fromkeys(G["QUERY_BOOL_KEYS"], 1))
        injected["rows"] = True
        with patch.dict(
            G,
            {
                "DIAGNOSTIC": {
                    "phase": "package",
                    "work_failure": None,
                    "package_query": injected,
                }
            },
        ):
            text, record = self.decode(ValueError("UNKNOWN_PRIVATE_ERROR"))
        self.assertTrue(
            all(record["package_query"][key] == 0 for key in G["QUERY_COUNT_KEYS"])
        )
        self.assertTrue(
            all(record["package_query"][key] is False for key in G["QUERY_BOOL_KEYS"])
        )
        self.assertNotIn("UNKNOWN_PRIVATE", text)

    def test_package_query_failure_shapes_refuse_and_redact_held_categories(self):
        cases = [
            ("private-owner: /UNKNOWN_PRIVATE_PATH", "package-owner", True),
            (
                "diversion by private-owner from: /UNKNOWN_PRIVATE_PATH",
                "diversion-from",
                False,
            ),
            ("local diversion from: /UNKNOWN_PRIVATE_PATH", "diversion-from", False),
            (
                "diversion by private-owner:amd64 to: /UNKNOWN_PRIVATE_PATH",
                "diversion-to",
                False,
            ),
            ("local diversion to: /UNKNOWN_PRIVATE_PATH", "diversion-to", False),
            ("private-owner:arm64: /UNKNOWN_PRIVATE_PATH", "other", False),
            ("UNKNOWN_PRIVATE_ROW", "other", False),
        ]
        for category, canonical in (
            ("target", G["TARGETS"]["gpg"]),
            ("loader", LOADER),
            ("library", CANONICAL),
        ):
            for line, shape, matched in cases:
                row = dict(
                    id="synthetic", canonical_path=canonical, listed_paths=[canonical]
                )
                with (
                    self.subTest(category=category, shape=shape),
                    patch.dict(
                        G,
                        {
                            "DIAGNOSTIC": {
                                "phase": "package",
                                "work_failure": None,
                                "package_row": None,
                            },
                            "command": lambda *args, line=line: (line + "\n").encode(),
                        },
                    ),
                ):
                    try:
                        N["package_owners"]([row], time.monotonic() + 5, [], None)
                    except G["Incomplete"] as error:
                        text, record = self.decode(error)
                    else:
                        self.fail(
                            "diagnostic classification accepted a refused package row"
                        )
                    if shape.startswith("diversion-"):
                        self.assertIsNone(record["package_row"])
                        self.assertEqual(record["package_query"]["rows"], 1)
                    else:
                        self.assertEqual(
                            record["package_row"],
                            dict(
                                shape=shape,
                                file_category=category,
                                grammar_matched=matched,
                                exact_alias_matched=False,
                            ),
                        )
                    for forbidden in ("private-owner", "UNKNOWN_PRIVATE", canonical):
                        self.assertNotIn(forbidden, text)
        with patch.dict(
            G,
            {
                "DIAGNOSTIC": {
                    "phase": "package",
                    "work_failure": None,
                    "package_row": {
                        "shape": "UNKNOWN_PRIVATE_SHAPE",
                        "file_category": "UNKNOWN_PRIVATE_CATEGORY",
                        "grammar_matched": 1,
                        "exact_alias_matched": "UNKNOWN_PRIVATE_BOOL",
                    },
                }
            },
        ):
            text, record = self.decode(ValueError("UNKNOWN_PRIVATE_ERROR"))
        self.assertEqual(
            record["package_row"],
            dict(
                shape="other",
                file_category=None,
                grammar_matched=False,
                exact_alias_matched=False,
            ),
        )
        self.assertNotIn("UNKNOWN_PRIVATE", text)

    def test_rejected_loader_row_shapes_redact_values_without_accepting(self):
        alias = G["INTERPRETER"] + " => " + LOADER + " (0xabcdef)"
        cases = [
            (alias.replace(" => ", "  => "), "absolute-mapping", True, True),
            (
                "/UNKNOWN_PRIVATE_LEFT => /UNKNOWN_PRIVATE_RIGHT (0x123)",
                "absolute-mapping",
                False,
                False,
            ),
            ("libc.so.6\t=>\t" + LISTED + "\t(0x123)", "soname-mapping", False, True),
            (G["INTERPRETER"] + "\t(0x123)", "direct-absolute", False, True),
            ("linux-vdso.so.1\t(0x123)", "vdso", False, True),
            ("UNKNOWN_PRIVATE_SONAME => not found", "not-found", False, False),
            ("", "blank", False, False),
            ("UNKNOWN_PRIVATE_ROW", "other", False, False),
        ]
        for line, shape, alias_matches, spacing in cases:
            with (
                self.subTest(shape=shape, spacing=spacing),
                patch.dict(
                    G,
                    {
                        "DIAGNOSTIC": {
                            "phase": "dependency",
                            "work_failure": None,
                            "loader_row": None,
                        },
                    },
                ),
            ):
                raw = OUTPUT + (line + "\n").encode()
                try:
                    N["parse_loader"](raw, LOADER)
                except G["Incomplete"] as error:
                    text, record = self.decode(error)
                else:
                    self.fail("diagnostic classification accepted a rejected row")
                self.assertEqual(
                    record["loader_row"],
                    dict(
                        shape=shape,
                        validated_interpreter_alias_mapping=alias_matches,
                        known_row_spacing_variant=spacing,
                    ),
                )
                for forbidden in (
                    "UNKNOWN_PRIVATE",
                    "0x",
                    LOADER,
                    LISTED,
                    G["INTERPRETER"],
                ):
                    self.assertNotIn(forbidden, text)
        # Diagnostic input itself cannot introduce arbitrary shape/value output.
        with patch.dict(
            G,
            {
                "DIAGNOSTIC": {
                    "phase": "dependency",
                    "work_failure": None,
                    "loader_row": {
                        "shape": "UNKNOWN_PRIVATE_SHAPE",
                        "validated_interpreter_alias_mapping": "UNKNOWN_PRIVATE_BOOL",
                        "known_row_spacing_variant": 1,
                    },
                }
            },
        ):
            text, record = self.decode(ValueError("UNKNOWN_PRIVATE_ERROR"))
        self.assertEqual(
            record["loader_row"],
            dict(
                shape="other",
                validated_interpreter_alias_mapping=False,
                known_row_spacing_variant=False,
            ),
        )
        self.assertNotIn("UNKNOWN_PRIVATE", text)

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
