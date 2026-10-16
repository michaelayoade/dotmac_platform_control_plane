"""AUTHORED ONLY: bounded source tests; native boundaries remain mocked."""

import base64
import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import adapter
import installer as i
import outer


def selection():
    tools = {
        key: dict(
            sha256=hashlib.sha256(key.encode()).hexdigest(),
            size=20,
            mode=0o755,
            package="source-test",
            version="1.0",
            origin="Ubuntu-signed-archive",
            package_artifact_sha256="1" * 64,
            provenance_sha256="2" * 64,
        )
        for key in i.TOOLS
    }
    return dict(
        schema="DotmacNativeComponentSelection.v1",
        repository="example/project",
        source_commit="a" * 40,
        workflow_sha256="b" * 64,
        installer_sha256="c" * 64,
        actions=dict(checkout=i.CHECKOUT, upload=i.UPLOAD),
        tools=tools,
        runc_artifact=dict(
            kind="upstream-detached-openpgp-elf",
            url="https://github.com/opencontainers/runc/releases/download/v1.2.3/runc.amd64",
            sha256=tools["runc"]["sha256"],
            size=20,
            version="v1.2.3",
            signature_sha256="d" * 64,
            signature_size=488,
            keyring_url="https://raw.githubusercontent.com/opencontainers/runc/"
            + "a" * 40
            + "/runc.keyring",
            keyring_sha256="e" * 64,
            keyring_size=100,
            signer_fingerprint="A" * 40,
            provenance_sha256="f" * 64,
        ),
    )


def rendered():
    record = dict(case="pre-guard-stop", instance="a" * 64)
    p = adapter.paths(record)
    host = dict(
        manager_version="255.4",
        kernel_release="source-test",
        yama_scope=1,
        libc_abi="linux-x86_64-glibc-ptrace-long",
        boot_id="11111111-1111-1111-1111-111111111111",
    )
    root_hash = hashlib.sha256(b"real-source-test-manifest\n").hexdigest()
    image = dict(image_config_digest="sha256:" + "a" * 64, rootfs_tree_digest=root_hash)

    def measured(path):
        return dict(
            sha256=root_hash
            if path.endswith("rootfs-manifest.json")
            else hashlib.sha256(path.encode()).hexdigest(),
            size=10,
            mode=0o555 if path.startswith(i.PREFIX) else 0o600,
        )

    tools = {
        key: dict(
            pin=dict(
                sha256=hashlib.sha256(key.encode()).hexdigest(), size=10, mode=0o755
            )
        )
        for key in i.TOOLS
    }
    # Installation pin must equal canonical installation bytes, not fixture hash.
    original = measured

    def pins(path):
        if path.endswith("installation-evidence.json"):
            raw = i.canonical({"scope": "source-test"})
            return dict(sha256=i.sha(raw), size=len(raw), mode=0o600)
        return original(path)

    with (
        patch.object(i, "exclusive"),
        patch.object(i, "pin", side_effect=pins),
        patch.object(i.time, "time_ns", return_value=1_000_000_000_000),
        patch.object(i.time, "monotonic_ns", return_value=100_000_000_000),
    ):
        result = i.render_config_and_intent(
            adapter, outer, record, p, host, image, {"scope": "source-test"}, tools
        )
    return result, p


class SelectionTests(unittest.TestCase):
    def test_closed_genuine_selection_shape(self):
        i.validate_selection(selection())

    def test_every_required_top_level_field_and_extra_refused(self):
        good = selection()
        for key in good:
            broken = copy.deepcopy(good)
            del broken[key]
            with self.subTest(key=key), self.assertRaises(i.Refusal):
                i.validate_selection(broken)
        good["approval"] = True
        with self.assertRaises(i.Refusal):
            i.validate_selection(good)

    def test_each_tool_digest_and_provenance_refuses_mutation(self):
        for key in i.TOOLS:
            for field in ("sha256", "package_artifact_sha256", "provenance_sha256"):
                bad = selection()
                bad["tools"][key][field] = "0" * 64
                with self.subTest(tool=key, field=field), self.assertRaises(i.Refusal):
                    i.validate_selection(bad)

    def test_signature_and_url_authority_are_closed(self):
        for field, value in (
            ("kind", "qualified"),
            ("url", "file:///tmp/runc"),
            ("keyring_url", "https://example.org/key"),
            ("signer_fingerprint", "B" * 39),
            ("sha256", "0" * 64),
            ("size", 0),
        ):
            bad = selection()
            bad["runc_artifact"][field] = value
            with self.subTest(field=field), self.assertRaises(i.Refusal):
                i.validate_selection(bad)

    def test_duplicate_or_noncanonical_json_refused(self):
        for raw in (b'{"a":1,"a":2}\n', b'{"a": 1}\n', b"{}"):
            with self.assertRaises(i.Refusal):
                i.decode(raw, 64)

    def test_missing_selector_before_mutation(self):
        with (
            patch.object(i.os, "geteuid", return_value=0),
            patch.object(i, "read_fixed", side_effect=FileNotFoundError),
            patch.object(i, "mkdir") as mutation,
        ):
            with self.assertRaises(FileNotFoundError):
                i.load_selection("pre-guard-stop")
            mutation.assert_not_called()

    def test_bootstrap_empty_selector_never_privileges(self):
        with (
            patch.dict(
                i.os.environ,
                {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1"},
                clear=True,
            ),
            patch.object(i.subprocess, "run") as launch,
        ):
            with self.assertRaises(i.Refusal):
                i.bootstrap("pre-guard-stop")
            launch.assert_not_called()

    def test_no_arbitrary_case(self):
        with self.assertRaises(i.Refusal):
            i.load_selection("recovery")


class RuncKeyringTests(unittest.TestCase):
    @staticmethod
    def fixture(sizes=(1915, 1243, 2272)):
        # Synthetic encoding only: no operational key or selector is supplied.
        parts = [bytes([value]) * size for value, size in enumerate(sizes, start=1)]
        blocks = []
        for part in parts:
            encoded = base64.b64encode(part)
            lines = [
                encoded[start : start + 64] for start in range(0, len(encoded), 64)
            ]
            blocks.append(
                b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: github=test\n\n"
                + b"\n".join(lines)
                + b"\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
            )
        raw = b"".join(blocks)
        raw += b" " * (8507 - len(raw))
        return raw, b"".join(parts)

    def install(
        self,
        raw,
        expected_binary,
        artifact_change=None,
        derived_hash=None,
        outer_hash=None,
    ):
        chosen = selection()
        chosen["runc_artifact"].update(
            keyring_size=8507,
            keyring_sha256=i.sha(raw),
        )
        if artifact_change:
            chosen["runc_artifact"].update(artifact_change)
        binary = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\0"
        status = b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" source-test\n"
        with (
            patch.object(i, "RUNC_KEYRING_SHA", outer_hash or i.sha(raw)),
            patch.object(
                i, "RUNC_BINARY_KEYRING_SHA", derived_hash or i.sha(expected_binary)
            ),
            patch.object(
                i,
                "pin",
                return_value={
                    key: chosen["tools"]["gpgv"][key]
                    for key in ("sha256", "size", "mode")
                },
            ),
            patch.object(i, "download_public", side_effect=[binary, b"signature", raw]),
            patch.object(i, "mkdir") as mkdir,
            patch.object(i, "exclusive") as exclusive,
            patch.object(i, "run", return_value=status) as run,
        ):
            try:
                i.install_selected_runc(chosen)
            except i.Refusal:
                mkdir.assert_not_called()
                exclusive.assert_not_called()
                run.assert_not_called()
                return False, exclusive, run
        return True, exclusive, run

    def test_actual_installer_gpgv_uses_exclusive_derived_binary_keyring(self):
        raw, binary = self.fixture()
        success, writes, run = self.install(raw, binary)
        self.assertTrue(success)
        path = i.STATE + "/public-tool-preparation/runc-keyring.gpg"
        writes.assert_any_call(path, binary)
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index("--keyring") + 1], path)
        self.assertNotIn(i.STATE + "/public-tool-preparation/runc.keyring", argv)
        self.assertEqual(writes.call_args.args[0], i.TOOLS["runc"])
        self.assertEqual(writes.call_args.args[2], 0o755)

    def test_selected_original_digest_and_size_mismatch_refuse_before_writes(self):
        raw, binary = self.fixture()
        for change in ({"keyring_size": 8506}, {"keyring_sha256": "0" * 64}):
            with self.subTest(change=change):
                self.assertFalse(self.install(raw, binary, change)[0])

    def test_corrupted_original_bytes_refuse_fixed_outer_hash(self):
        raw, binary = self.fixture()
        chosen = dict(keyring_size=8507, keyring_sha256=i.sha(raw))
        with patch.object(i, "RUNC_KEYRING_SHA", i.sha(raw)):
            with self.assertRaises(i.Refusal):
                i.normalize_selected_keyring(raw[:-1] + b"!", chosen)
        self.assertFalse(
            self.install(
                raw[:-1] + b"!",
                binary,
                {"keyring_sha256": i.sha(raw)},
                outer_hash=i.sha(raw),
            )[0]
        )
        self.assertFalse(self.install(raw, binary, derived_hash="0" * 64)[0])

    def test_missing_duplicate_and_unknown_armor_refuse_before_writes(self):
        raw, binary = self.fixture()
        for damaged in (
            raw.replace(b"BEGIN PGP PUBLIC", b"BEGIN PGP SECRET", 1),
            raw.replace(b"END PGP PUBLIC", b"END PGP SECRET", 1),
            raw.replace(b"Comment: github=test", b"Comment: github=te!t", 1),
            raw.replace(b"=AAAA", b"=AA!A", 1),
            raw.replace(b"-----BEGIN", b"-----BEGIN-----BEGIN", 1),
        ):
            with self.subTest(damaged=i.sha(damaged)):
                self.assertFalse(self.install(damaged, binary)[0])

    def test_oversize_truncated_and_empty_keyring_refuse_before_writes(self):
        raw, binary = self.fixture()
        for damaged in (raw + b"x", raw[:-1], b""):
            with self.subTest(size=len(damaged)):
                self.assertFalse(self.install(damaged, binary)[0])

    def test_malformed_base64_and_wrong_decoded_sizes_refuse_before_writes(self):
        raw, binary = self.fixture()
        for damaged in (
            raw.replace(b"AQEB", b"A===", 1),
            raw.replace(b"AQEB", b"AQ==", 1),
        ):
            with self.subTest(damaged=i.sha(damaged)):
                self.assertFalse(self.install(damaged, binary)[0])

    def test_decoded_member_size_contract_refuses_even_matching_derived_hash(self):
        for sizes in ((1914, 1243, 2272), (1915, 1244, 2271)):
            with self.subTest(sizes=sizes):
                raw, binary = self.fixture(sizes)
                self.assertFalse(self.install(raw, binary)[0])


class ArchiveTests(unittest.TestCase):
    def archive(self, specs):
        file = tempfile.TemporaryFile()
        self.addCleanup(file.close)
        with tarfile.open(fileobj=file, mode="w") as archive:
            for name, kind, target in specs:
                item = tarfile.TarInfo(name)
                item.mode = 0o755 if kind == "dir" else 0o644
                if kind == "dir":
                    item.type = tarfile.DIRTYPE
                elif kind in ("sym", "hard"):
                    item.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                    item.linkname = target
                elif kind == "fifo":
                    item.type = tarfile.FIFOTYPE
                else:
                    item.size = len(target)
                archive.addfile(item, io.BytesIO(target) if kind == "file" else None)
        file.seek(0)
        archive = tarfile.open(fileobj=file, mode="r:")
        self.addCleanup(archive.close)
        return archive

    def test_full_plan_before_extraction(self):
        archive = self.archive([("good", "file", b"safe"), ("../bad", "file", b"bad")])
        with patch.object(i.os, "mkdir") as mutation, self.assertRaises(i.Refusal):
            i.archive_plan(archive)
        mutation.assert_not_called()

    def test_unsafe_entries_refused(self):
        cases = [
            [("a", "file", b"x"), ("a", "file", b"x")],
            [("/abs", "file", b"x")],
            [("a//b", "file", b"x")],
            [("fifo", "fifo", "")],
            [("a", "sym", "../../escape")],
            [("a", "hard", "../escape")],
            [("a", "hard", "missing")],
            [("a", "sym", "b"), ("a/file", "file", b"x"), ("b", "dir", "")],
            [("a", "sym", "b"), ("b", "sym", "a")],
        ]
        for specs in cases:
            with self.subTest(specs=specs), self.assertRaises(i.Refusal):
                i.archive_plan(self.archive(specs))

    def test_caps_refuse_before_extraction(self):
        for cap, value in (("entries", 0), ("content", 1), ("file", 1), ("path", 1)):
            with (
                patch.dict(i.CAPS, {cap: value}),
                self.subTest(cap=cap),
                self.assertRaises(i.Refusal),
            ):
                i.archive_plan(self.archive([("file", "file", b"xx")]))

    def test_internal_hardlinks_and_symlinks_after_regulars(self):
        archive = self.archive(
            [
                ("d", "dir", ""),
                ("d/file", "file", b"data"),
                ("hard", "hard", "d/file"),
                ("sym", "sym", "d/file"),
            ]
        )
        entries = i.archive_plan(archive)
        with tempfile.TemporaryDirectory() as root:
            i.extract_validated(archive, entries, root)
            self.assertEqual(
                os.stat(root + "/hard").st_ino, os.stat(root + "/d/file").st_ino
            )
            self.assertEqual(os.readlink(root + "/sym"), "d/file")
            self.assertEqual(Path(root + "/d/file").read_bytes(), b"data")
            manifest = json.loads(i.tree_manifest(root))
            self.assertEqual(
                {item["path"] for item in manifest}, {"d", "d/file", "hard", "sym"}
            )


class FixtureTests(unittest.TestCase):
    def test_real_rendered_templates_and_digest_binding(self):
        record, p = rendered()
        adapter.validate_record(record)
        self.assertEqual(set(outer.fragments(record, p)), set(outer.TEMPLATES))
        self.assertEqual(
            record["rootfs_tree_digest"], record["pins"]["rootfs_manifest"]["sha256"]
        )
        self.assertEqual(
            record["installation_evidence_digest"],
            record["pins"]["installation_evidence"]["sha256"],
        )
        self.assertEqual(record["s_us"], record["e_mono_us"] + 30_000_000)
        self.assertEqual(record["c_us"], record["e_mono_us"] + 60_000_000)
        self.assertEqual(record["e_wall_us"] - record["not_before_wall_us"], 60_000_000)
        self.assertEqual(record["accuracy_us"], 1000)

    def test_exact_oci_shape_and_missing_payload_is_preserved(self):
        record, p = rendered()
        config = i.config_for(record, p)
        self.assertEqual(
            set(config), {"ociVersion", "root", "process", "mounts", "linux"}
        )
        self.assertEqual(config["mounts"], [])
        self.assertEqual(
            config["root"], dict(path=p["base"] + "/rootfs", readonly=True)
        )
        self.assertEqual(
            config["process"]["args"],
            ["/opt/venv/bin/dotmac-platform", "gate0", "supervise"],
        )
        self.assertEqual(
            config["linux"]["resources"],
            dict(devices=[dict(allow=False, access="rwm")]),
        )
        self.assertEqual(config["linux"]["devices"], [])
        self.assertEqual(len(config["linux"]["namespaces"]), 6)
        self.assertEqual(config["linux"]["cgroupsPath"], p["group"] + "/payload")

    def test_fixture_clock_and_exclusive_freeze(self):
        record, _ = rendered()
        a = Mock(wraps=adapter)
        a.clock = Mock(side_effect=adapter.Incomplete)
        with (
            patch.object(i, "exclusive") as write,
            self.assertRaises(adapter.Incomplete),
        ):
            i.freeze_fixture(a, record)
        write.assert_not_called()
        a.clock = Mock()
        raw = i.canonical(record)
        with (
            patch.object(i, "exclusive", side_effect=FileExistsError) as write,
            self.assertRaises(FileExistsError),
        ):
            i.freeze_fixture(a, record)
        write.assert_called_once_with(i.STATE + "/fixture.json", raw)

    def test_stale_boot_refuses_without_any_write(self):
        record, _ = rendered()
        with (
            patch(
                "builtins.open",
                unittest.mock.mock_open(
                    read_data="22222222-2222-2222-2222-222222222222\n"
                ),
            ),
            self.assertRaises(adapter.Incomplete),
        ):
            adapter.clock(record, True)

    def test_no_replacement_uses_exclusive_nofollow(self):
        with (
            patch.object(i, "protected", return_value=7),
            patch.object(i.os, "open", side_effect=FileExistsError) as opened,
            patch.object(i.os, "close"),
        ):
            with self.assertRaises(FileExistsError):
                i.exclusive(i.STATE + "/fixture.json", b"bounded")
            self.assertTrue(opened.call_args.args[1] & os.O_EXCL)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)

    def test_template_mutation_refuses(self):
        record, p = rendered()
        record["pins"]["timer"]["sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            outer.fragments(record, p)

    def test_frozen_seven_templates_unchanged(self):
        root = Path(__file__).parent
        expected = {
            "expired.in": (
                "5a7dfc50a3cdaa9cc2eeb29f60ce188b941846dc9d77da002bbdb940cf828e2a"
            ),
            "observer-expired.in": (
                "ba321f01c52e6342511dc552d627d2d1c11b0927ab04aedfb2692ceb6838f98f"
            ),
            "observer-ready.in": (
                "d3c9d2e18f427f59b0eadf3cb7a7dc5ff48d4aba0a545869f10c082cd8706813"
            ),
            "observer-timer.in": (
                "c175e8f5cdec88f93f695c9fe37fc46bb63be3251a2bc1a68bdc0e8c0b3cd106"
            ),
            "observer.in": (
                "b0ab689f3be0daaaeaba7b34bd9ce1be046d86ab5d89d3420692d874fa5ffd38"
            ),
            "ready.in": (
                "722aacf6008f062049556eaa8df3798dd240cc3d5d22d9e0e22a81694125897c"
            ),
            "timer.in": (
                "6ba764f438cc733425172aeac495cff35ecadf458aa6a5c8eb792a542330691e"
            ),
        }
        self.assertEqual(len(expected), 7)
        for name, digest in expected.items():
            self.assertEqual(
                hashlib.sha256((root / name).read_bytes()).hexdigest(), digest
            )

    def test_frozen_r4_hashes_unchanged(self):
        root = Path(__file__).parent
        for name, expected in i.R4.items():
            filename = "scratch_helper.py" if name == "scratch-helper" else name + ".py"
            self.assertEqual(
                hashlib.sha256((root / filename).read_bytes()).hexdigest(), expected
            )


class ReceiptTests(unittest.TestCase):
    def test_unknown_retirement_is_incomplete_and_blocks_continuation(self):
        record, _ = rendered()
        context = dict(
            repository="example/project", source_commit="a" * 40, run_id=123, job_id=456
        )
        writes = {}
        with (
            patch.object(i, "mkdir"),
            patch.object(
                i, "exclusive", side_effect=lambda path, raw: writes.update({path: raw})
            ),
        ):
            self.assertFalse(
                i.retain_public_receipt(
                    selection(), context, record, "e" * 64, None, None
                )
            )
        self.assertEqual(
            set(writes),
            {
                i.PUBLIC + "/producer-receipt.json",
                i.PUBLIC + "/component-observation.json",
            },
        )
        receipt = json.loads(writes[i.PUBLIC + "/producer-receipt.json"])
        self.assertFalse(receipt["overall_native_pass"])
        self.assertFalse(receipt["normal_observer_retirement"])
        self.assertEqual(receipt["failure_class"], "owner-retirement-unproven")
        self.assertLessEqual(sum(map(len, writes.values())), i.CAPS["public"])

    def test_arbitrary_or_exit_only_observation_cannot_be_success(self):
        record, _ = rendered()
        for document in ({}, {"exit": 0}, {"overall_native_pass": True}):
            with self.assertRaises(i.Refusal):
                i.validate_observation(document, record)

    def test_receipt_limit_refuses_before_writes(self):
        record, _ = rendered()
        context = dict(
            repository="example/project", source_commit="a" * 40, run_id=123, job_id=456
        )
        with patch.dict(i.CAPS, {"public": 1}), patch.object(i, "mkdir") as mutation:
            with self.assertRaises(i.Refusal):
                i.retain_public_receipt(
                    selection(), context, record, "e" * 64, None, None
                )
            mutation.assert_not_called()


def physical_archive(kind, payload=b"", declared=None, terminator=True):
    header = bytearray(512)
    header[:4] = b"meta"
    header[124:136] = (
        f"{len(payload) if declared is None else declared:011o}\0".encode()
    )
    header[148:156] = b"        "
    header[156:157] = kind
    header[257:263] = b"ustar\0"
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    return (
        bytes(header)
        + payload
        + bytes((-len(payload)) % 512)
        + (bytes(1024) if terminator else b"")
    )


def pax_record(key, value=b"1"):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while len(str(length)) + 1 + len(body) != length:
        length = len(str(length)) + 1 + len(body)
    return str(length).encode() + b" " + body


class RawPreflightTests(unittest.TestCase):
    def refused_before_tarfile(self, raw):
        with patch.object(i.tarfile, "open") as parser, self.assertRaises(i.Refusal):
            i.extract_export_stream(io.BytesIO(raw), "/unused-source-test")
        parser.assert_not_called()

    def test_old_sparse_never_reaches_tarfile(self):
        self.refused_before_tarfile(physical_archive(b"S"))

    def test_all_sparse_pax_variants_and_unknown_keys_never_reach_tarfile(self):
        for kind in (b"x", b"g", b"X"):
            for key in (
                b"GNU.sparse.map",
                b"GNU.sparse.size",
                b"GNU.sparse.numblocks",
                b"GNU.sparse.major",
                b"GNU.sparse.minor",
                b"GNU.sparse.unknown",
            ):
                with self.subTest(kind=kind, key=key):
                    self.refused_before_tarfile(physical_archive(kind, pax_record(key)))

    def test_malformed_and_oversized_pax_never_reaches_tarfile(self):
        for payload in (
            b"12 path=a",
            b"0 path=a\n",
            b"09 path=a\n",
            b"9 noequals\n",
            b"8 =bad\n",
            b"9 a\0b=c\n",
            b"1" * 16385,
        ):
            for kind in (b"x", b"g", b"X"):
                with self.subTest(payload=payload[:16], kind=kind):
                    self.refused_before_tarfile(physical_archive(kind, payload))

    def test_longname_and_longlink_payload_and_terminator_caps(self):
        for kind in (b"L", b"K"):
            for payload in (
                b"x" * 4097 + b"\0",
                b"x" * 4097,
                b"x\0hidden\0",
                b"unterminated",
                b"\0",
            ):
                with self.subTest(kind=kind, size=len(payload)):
                    self.refused_before_tarfile(physical_archive(kind, payload))

    def test_raw_header_and_aggregate_extension_budgets(self):
        for raw in (
            physical_archive(b"0", terminator=False),
            bytes(513),
            physical_archive(b"0") + b"x" * 512,
            physical_archive(b"0", declared=i.CAPS["file"] + 1),
        ):
            self.refused_before_tarfile(raw)
        with patch.dict(i.CAPS, {"entries": 0}):
            self.refused_before_tarfile(physical_archive(b"0"))
        # Many minimal records exhaust the per-PAX record bound before parsing.
        self.refused_before_tarfile(physical_archive(b"x", pax_record(b"a") * 1025))

    def test_aggregate_extension_bytes_refuse_before_tarfile(self):
        payload = pax_record(b"comment", b"x" * 16000)
        header = physical_archive(b"g", payload, terminator=False)
        repetitions = (16 * 1024 * 1024) // len(payload) + 1
        self.refused_before_tarfile(header * repetitions + bytes(1024))

    def test_bounded_pax_and_gnu_long_extensions_reach_parser(self):
        for kind, payload in (
            (b"x", pax_record(b"path", b"ordinary")),
            (b"g", pax_record(b"mtime", b"1")),
            (b"X", pax_record(b"linkpath", b"ordinary")),
            (b"L", b"x" * 4096 + b"\0"),
            (b"K", b"x" * 4096 + b"\0"),
        ):
            with (
                self.subTest(kind=kind),
                patch.object(i.tarfile, "open") as parser,
                patch.object(i, "archive_plan", return_value={}),
                patch.object(i, "extract_validated"),
            ):
                i.extract_export_stream(
                    io.BytesIO(physical_archive(kind, payload)), "/unused-source-test"
                )
                parser.assert_called_once()


class LayerJoinTests(unittest.TestCase):
    def prepared_until_create(self, measured):
        chain = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]
        config = dict(
            architecture="amd64", os="linux", rootfs=dict(type="layers", diff_ids=chain)
        )
        config_raw = i.canonical(config)
        config_digest = "sha256:" + i.sha(config_raw)
        manifest = dict(
            config=dict(digest=config_digest),
            layers=[
                dict(digest="sha256:" + "3" * 64, size=20),
                dict(digest="sha256:" + "4" * 64, size=30),
            ],
        )
        manifest_raw = i.canonical(manifest)
        platform_digest = "sha256:" + i.sha(manifest_raw)
        index = dict(
            manifests=[
                dict(
                    platform=dict(architecture="amd64", os="linux"),
                    digest=platform_digest,
                )
            ]
        )
        index_raw = i.canonical(index)
        image = dict(
            Id=config_digest, Os="linux", Architecture="amd64", RootFS=measured
        )
        commands = []

        class CreateBoundary(Exception):
            pass

        def command(argv, **kwargs):
            commands.append(argv)
            if argv[1:3] == ["image", "inspect"]:
                return i.canonical([image])
            if argv[1] == "create":
                raise CreateBoundary()
            return b""

        p = dict(base="/source-test", instance="source-test")
        with (
            patch.object(i, "IMAGE", i.sha(index_raw)),
            patch.object(
                i,
                "registry_json",
                side_effect=[
                    (b"", dict(token="anonymous-test")),  # noqa: S106
                    (index_raw, index),
                    (manifest_raw, manifest),
                    (config_raw, config),
                ],
            ),
            patch.object(i, "verify_registry_layer"),
            patch.object(i, "mkdir"),
            patch.object(i, "run", side_effect=command),
            patch.object(i.subprocess, "run") as export,
        ):
            try:
                i.prepare_public_rootfs(p)
            except CreateBoundary:
                result = "create-boundary"
            except i.Refusal:
                result = "refused"
            export.assert_not_called()
        return result, commands

    def test_positive_exact_ordered_chain_reaches_container_create(self):
        result, commands = self.prepared_until_create(
            dict(Type="layers", Layers=["sha256:" + "1" * 64, "sha256:" + "2" * 64])
        )
        self.assertEqual(result, "create-boundary")
        self.assertEqual(commands[-1][1], "create")

    def test_same_config_id_missing_malformed_changed_swapped_truncated_chain_refuses(
        self,
    ):
        a, b = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        for rootfs in (
            None,
            {},
            dict(Type="wrong", Layers=[a, b]),
            dict(Type="layers"),
            dict(Type="layers", Layers=a),
            dict(Type="layers", Layers=[a, None]),
            dict(Type="layers", Layers=[a, "sha256:" + "5" * 64]),
            dict(Type="layers", Layers=[b, a]),
            dict(Type="layers", Layers=[a]),
        ):
            with self.subTest(rootfs=rootfs):
                result, commands = self.prepared_until_create(rootfs)
                self.assertEqual(result, "refused")
                self.assertFalse(any(command[1] == "create" for command in commands))

    def test_authenticated_diff_ids_type_digest_and_count_are_closed(self):
        a = "sha256:" + "1" * 64
        for rootfs in (
            None,
            {},
            dict(type="layers", diff_ids=a),
            dict(type="wrong", diff_ids=[a]),
            dict(type="layers", diff_ids=[]),
            dict(type="layers", diff_ids=[a, a]),
            dict(type="layers", diff_ids=[None]),
            dict(type="layers", diff_ids=["sha256:bad"]),
            dict(type="layers", diff_ids=[a], extra=True),
        ):
            with self.subTest(rootfs=rootfs), self.assertRaises(i.Refusal):
                i.authenticated_diff_ids(dict(rootfs=rootfs), [dict(size=1)])


def matching_public_pair():
    record, _ = rendered()
    context = dict(
        repository="example/project",
        source_commit="a" * 40,
        run_id=123,
        run_attempt=1,
        job_id=456,
        image_version="20261001.1.0",
    )
    coords = {
        key: context[key]
        for key in ("repository", "source_commit", "run_id", "run_attempt", "job_id")
    }
    coords.update(case=record["case"], boot_id=record["boot_id"])
    record["instance"] = i.sha(i.canonical(coords))
    target = dict(
        schema="DotmacNativeEnvelopeTargetObservation.v1",
        status="target-cutoff-observed-observer-retirement-pending",
        case=record["case"],
        instance=record["instance"],
        boot_id=record["boot_id"],
        original_s_us=record["s_us"],
        original_c_us=record["c_us"],
        held_boundary="source-test",
        target={},
        retirement={},
        observer={},
        observer_cgroup={},
        systemd_run_exit=1,
        actual_stdout_empty_eof=True,
        overall_native_pass=False,
    )
    observation = dict(
        schema="DotmacNativeEnvelopeOwnerComponentObservation.v1",
        status="observer-normal-retirement-observed-unqualified",
        case=record["case"],
        instance=record["instance"],
        boot_id=record["boot_id"],
        original_s_us=record["s_us"],
        original_c_us=record["c_us"],
        observer={},
        observer_terminal={},
        retained_observer_cgroup={},
        original_observer_disappeared=True,
        observer_pidfd_ready=True,
        observer_recursive_populated_zero=True,
        target_observation=target,
        overall_native_pass=False,
    )
    writes = {}
    with (
        patch.object(i, "mkdir"),
        patch.object(
            i, "exclusive", side_effect=lambda path, raw: writes.update({path: raw})
        ),
    ):
        i.retain_public_receipt(selection(), context, record, "e" * 64, 0, observation)
    producer = json.loads(writes[i.PUBLIC + "/producer-receipt.json"])
    workspace = Path(__file__).parents[3]
    producer["installer_sha256"] = i.sha(
        (
            workspace / "conformance/gate0_envelope_source/native/installer.py"
        ).read_bytes()
    )
    producer["workflow_sha256"] = i.sha((workspace / i.WORKFLOW).read_bytes())
    return producer, observation, workspace


class WorkflowStageTests(unittest.TestCase):
    def staged(self, producer, component, workspace):
        with tempfile.TemporaryDirectory() as temporary:
            env = dict(
                GITHUB_REPOSITORY="example/project",
                GITHUB_SHA="a" * 40,
                GITHUB_RUN_ID="123",
                GITHUB_RUN_ATTEMPT="1",
                GITHUB_WORKSPACE=str(workspace),
                RUNNER_TEMP=temporary,
            )
            results = [
                Mock(returncode=0, stdout=i.canonical(producer)),
                Mock(
                    returncode=1 if component is None else 0,
                    stdout=b"" if component is None else component,
                ),
            ]
            with (
                patch.dict(i.os.environ, env, clear=True),
                patch.object(i.os, "geteuid", return_value=1000),
                patch.object(i.subprocess, "run", side_effect=results),
                patch.object(i, "staged_install") as install,
                patch.object(i, "main") as main,
            ):
                try:
                    success = i.stage_public_receipts("pre-guard-stop")
                except (i.Refusal, KeyError, ValueError, TypeError):
                    success = False
                install.assert_not_called()
                main.assert_not_called()
            files = {
                name: (Path(temporary) / "gate0-native-public" / name).read_bytes()
                for name in ("producer-receipt.json", "component-observation.json")
            }
            self.assertLessEqual(sum(map(len, files.values())), i.CAPS["public"])
            return success, files

    def test_actual_stage_valid_matching_pair_succeeds(self):
        producer, observation, workspace = matching_public_pair()
        success, files = self.staged(producer, i.canonical(observation), workspace)
        self.assertTrue(success)
        self.assertEqual(json.loads(files["component-observation.json"]), observation)

    def test_retired_producer_missing_fallback_or_malformed_component_blocks_stage(
        self,
    ):
        producer, _, workspace = matching_public_pair()
        for component in (
            None,
            b"malformed raw diagnostic",
            i.canonical(
                dict(
                    schema="DotmacNativeComponentPreparationRefusal.v1",
                    overall_native_pass=False,
                )
            ),
        ):
            with self.subTest(component=component):
                success, files = self.staged(producer, component, workspace)
                self.assertFalse(success)
                self.assertEqual(
                    json.loads(files["component-observation.json"])["failure_class"],
                    "preparation-refused",
                )
                self.assertNotIn(
                    b"malformed raw diagnostic", files["component-observation.json"]
                )

    def test_missing_producer_schema_preserves_fallback_and_blocks_stage(self):
        _, observation, workspace = matching_public_pair()
        success, files = self.staged({}, i.canonical(observation), workspace)
        self.assertFalse(success)
        self.assertEqual(
            json.loads(files["producer-receipt.json"])["failure_class"],
            "preparation-refused",
        )

    def test_foreign_or_mismatched_component_and_producer_coordinates_block_stage(self):
        producer, observation, workspace = matching_public_pair()
        for key, value in (
            ("case", "runc-exec-stop"),
            ("instance", "f" * 64),
            ("boot_id", "22222222-2222-2222-2222-222222222222"),
            ("original_s_us", observation["original_s_us"] + 1),
            ("original_c_us", observation["original_c_us"] + 1),
        ):
            bad = copy.deepcopy(observation)
            bad[key] = value
            with self.subTest(component=key):
                self.assertFalse(self.staged(producer, i.canonical(bad), workspace)[0])
        for key, value in (
            ("source_commit", "f" * 40),
            ("run_id", 124),
            ("job_id", 457),
            ("run_attempt", 2),
        ):
            bad = copy.deepcopy(producer)
            bad[key] = value
            with self.subTest(producer=key):
                self.assertFalse(
                    self.staged(bad, i.canonical(observation), workspace)[0]
                )

    def test_workflow_calls_actual_unprivileged_stage_helper_for_both_cases(self):
        workflow = (Path(__file__).parents[3] / i.WORKFLOW).read_text()
        for case in i.CASES:
            self.assertIn("source['stage_public_receipts']('" + case + "')", workflow)
        self.assertEqual(workflow.count("run_name='gate0_receipt_validation_only'"), 2)
        self.assertNotIn("receipt['normal_observer_retirement']", workflow)


if __name__ == "__main__":
    unittest.main()
