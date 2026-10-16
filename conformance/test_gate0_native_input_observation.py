"""Mocked standard-library tests only; no native/signature qualification."""

import base64
import hashlib
import io
import json
import os
import runpy
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SOURCE = Path(__file__).parents[1] / ".github/candidate/observe_gate0_native_inputs.py"
M = runpy.run_path(str(SOURCE), run_name="mocked_public_input_source")


def valid_status(primary=True):
    line = "[GNUPG:] VALIDSIG " + M["SIGNER"] + " 2026-09-25 123 0 4 0 1 10 00"
    return line + (" " + "A" * 40 if primary else "") + "\n"


class PublicInputTests(unittest.TestCase):
    def test_expected_direct_signer_and_separate_optional_primary(self):
        for primary in (True, False):
            observation = M["signature_status"](valid_status(primary))
            self.assertTrue(observation["cryptographic_signature_verified"])
            self.assertEqual(observation["direct_signer_fingerprint"], M["SIGNER"])
            self.assertEqual(
                observation["reported_primary_fingerprint"],
                "A" * 40 if primary else None,
            )

    def test_bad_expired_revoked_unknown_duplicate_and_foreign_status_refuses(self):
        for raw in (
            valid_status().replace(M["SIGNER"], "B" * 40),
            valid_status() * 2,
            valid_status() + "[GNUPG:] BADSIG x\n",
            valid_status() + "[GNUPG:] ERRSIG x\n",
            valid_status() + "[GNUPG:] EXPKEYSIG x\n",
            valid_status() + "[GNUPG:] EXPSIG x\n",
            valid_status() + "[GNUPG:] REVKEYSIG x\n",
            valid_status() + "[GNUPG:] FAILURE x\n",
            valid_status() + "raw diagnostic\n",
        ):
            with self.subTest(raw=raw[-30:]), self.assertRaises(M["Incomplete"]):
                M["signature_status"](raw)

    def test_only_exact_https_redirect_hosts_without_userinfo_fragments_or_other_ports(
        self,
    ):
        allowed = (
            "https://release-assets.githubusercontent.com/path?signed=not-retained"
        )
        self.assertEqual(M["checked_url"](allowed), allowed)
        for url in (
            "http://github.com/a",
            "https://example.com/a",
            "https://github.com.evil/a",
            "https://user@github.com/a",
            "https://github.com/a#fragment",
            "https://github.com:80/a",
            "https://github.com:bad/a",
            "file:///etc/passwd",
        ):
            with self.subTest(url=url), self.assertRaises(M["Incomplete"]):
                M["checked_url"](url)

    def test_download_exact_bytes_digest_exclusivity_and_overflow(self):
        data = b"public-test-data"
        artifact = (
            "runc.amd64",
            M["BASE"],
            len(data),
            hashlib.sha256(data).hexdigest(),
        )
        for payload in (data, data + b"extra", data[:-1], b"x" * len(data)):
            response = Mock()
            response.geturl.return_value = M["BASE"]
            response.read1.side_effect = [payload, b""]
            opener = Mock()
            opener.open.return_value.__enter__ = Mock(return_value=response)
            opener.open.return_value.__exit__ = Mock(return_value=False)
            with (
                tempfile.TemporaryDirectory() as work,
                patch.dict(
                    M["download"].__globals__, {"time": Mock(monotonic=lambda: 100)}
                ),
            ):
                if payload == data:
                    M["download"](opener, work, artifact, 160)
                    self.assertEqual((Path(work) / artifact[0]).read_bytes(), data)
                    with self.assertRaises(FileExistsError):
                        M["download"](opener, work, artifact, 160)
                else:
                    with self.assertRaises(M["Incomplete"]):
                        M["download"](opener, work, artifact, 160)

    def test_signature_observation_uses_one_deadline_and_never_executes_runc(self):
        glob = M["observe_signature"].__globals__
        with (
            patch.dict(
                glob,
                {
                    "download": Mock(),
                    "derive_keyring": Mock(return_value="/mock/runc-keyring.gpg"),
                    "command": Mock(return_value=valid_status()),
                },
            ),
            patch.object(glob["signal"], "signal"),
            patch.object(glob["signal"], "setitimer") as timer,
        ):
            result = M["observe_signature"]()
            self.assertTrue(result["cryptographic_signature_verified"])
            argv = glob["command"].call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/gpgv")
            self.assertTrue(argv[-1].endswith("/runc.amd64"))
            self.assertEqual(
                argv[argv.index("--keyring") + 1], "/mock/runc-keyring.gpg"
            )
            self.assertTrue(result["keyring_encoding"]["binary_derivation_observed"])
            self.assertEqual([call.args[1] for call in timer.call_args_list], [60, 0])

    def test_expected_download_failure_is_bounded_and_unexpected_bug_surfaces(self):
        glob = M["observe_signature"].__globals__
        with (
            patch.dict(
                glob,
                {
                    "download": Mock(
                        side_effect=M["Incomplete"]("public-input-deadline")
                    )
                },
            ),
            patch.object(glob["signal"], "signal"),
            patch.object(glob["signal"], "setitimer"),
        ):
            result = M["observe_signature"]()
            self.assertFalse(result["cryptographic_signature_verified"])
            self.assertEqual(result["failure_class"], "public-input-deadline")
        with patch.dict(
            M["package_facts"].__globals__,
            {"query_fact": Mock(side_effect=NameError("never retained"))},
        ):
            with self.assertRaises(NameError):
                M["package_facts"](("/usr/bin/gpgv",), 130)

    def test_missing_fixed_file_explicit_and_ambient_environment_filtered(self):
        glob = M["observe_file"].__globals__
        with patch.object(glob["os"], "lstat", side_effect=FileNotFoundError):
            self.assertEqual(
                M["observe_file"]("/usr/bin/gpgv")["failure_class"], "file-missing"
            )
        with patch.dict(
            os.environ,
            {"GITHUB_SHA": "a" * 40, "UNRELATED_PRIVATE_VALUE": "excluded"},
            clear=True,
        ):
            metadata = M["metadata"]()
        self.assertEqual(metadata["GITHUB_SHA"], "a" * 40)
        self.assertNotIn("UNRELATED_PRIVATE_VALUE", metadata)
        self.assertEqual(M["ENV"], {"PATH": "/usr/bin:/bin", "LANG": "C"})

    def test_main_only_one_bounded_json_with_false_qualification_flags(self):
        glob = M["main"].__globals__
        file = dict(
            lexical_path="/usr/bin/gpgv",
            status="observed-not-authenticated",
            sha256="a" * 64,
            packages=[dict(package="gpgv")],
        )
        with (
            tempfile.TemporaryDirectory() as work,
            patch.dict(os.environ, {"RUNNER_TEMP": work}, clear=True),
            patch.object(glob["os"], "geteuid", return_value=1000),
            patch.object(glob["sys"], "argv", ["observe_gate0_native_inputs.py"]),
            patch.dict(
                glob,
                {
                    "metadata": Mock(return_value={"GITHUB_SHA": "a" * 40}),
                    "observe_metadata": Mock(
                        return_value=(
                            [file] * len(M["FILES"]),
                            dict(presence="absent", type=None),
                        )
                    ),
                    "observe_signature": Mock(
                        return_value=dict(cryptographic_signature_verified=False)
                    ),
                },
            ),
            patch(
                "builtins.open",
                return_value=io.BytesIO(
                    b'ID=ubuntu\nVERSION_ID="24.04"\nUBUNTU_CODENAME=noble\n'
                ),
            ),
        ):
            M["main"]()
            path = Path(work) / "native-input-observation.json"
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), 65536)
            record = json.loads(raw)
            for key in (
                "overall_native_pass",
                "production_qualified",
                "operational_selector_configured",
            ):
                self.assertIs(record[key], False)
            self.assertEqual(record["status"], "incomplete")
            self.assertEqual(
                [item.name for item in Path(work).iterdir()],
                ["native-input-observation.json"],
            )


class InputCorrectionTests(unittest.TestCase):
    def armor_fixture(self):
        chunks = [b"A" * 1915, b"B" * 1243, b"C" * 2272]
        blocks = []
        for chunk in chunks:
            encoded = base64.b64encode(chunk)
            lines = [
                encoded[index : index + 64] for index in range(0, len(encoded), 64)
            ]
            blocks.append(
                b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: github=test\n\n"
                + b"\n".join(lines)
                + b"\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
            )
        raw = b"      " + M["SIGNER"].encode() + b"\n" + b"\n".join(blocks)
        return raw + b" " * (8507 - len(raw)), b"".join(chunks)

    def test_pinned_listing_derives_exact_binary_keyring_exclusively(self):
        raw, binary = self.armor_fixture()
        pins = dict(
            KEYRING_SHA=hashlib.sha256(raw).hexdigest(),
            KEYRING_BINARY_SHA=hashlib.sha256(binary).hexdigest(),
        )
        with (
            tempfile.TemporaryDirectory() as work,
            patch.dict(M["derive_keyring"].__globals__, pins),
        ):
            (Path(work) / "runc.keyring").write_bytes(raw)
            derived = M["derive_keyring"](work)
            self.assertEqual(Path(derived).read_bytes(), binary)
            self.assertEqual(Path(derived).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                M["derive_keyring"](work)

    def test_corrupted_outer_missing_or_malformed_blocks_and_derived_hash_refuse(self):
        raw, binary = self.armor_fixture()
        for content, outer, derived in (
            (
                raw + b"x",
                hashlib.sha256(raw).hexdigest(),
                hashlib.sha256(binary).hexdigest(),
            ),
            (
                raw.replace(b"BEGIN PGP PUBLIC KEY", b"BEGIN PGP PRIVAT KEY", 1),
                None,
                None,
            ),
            (raw.replace(b"=AAAA", b"=bad!", 1), None, None),
            (raw, hashlib.sha256(raw).hexdigest(), "0" * 64),
        ):
            with self.subTest(size=len(content)), tempfile.TemporaryDirectory() as work:
                (Path(work) / "runc.keyring").write_bytes(content)
                pins = dict(
                    KEYRING_SHA=outer or hashlib.sha256(content).hexdigest(),
                    KEYRING_BINARY_SHA=derived or hashlib.sha256(binary).hexdigest(),
                )
                with (
                    patch.dict(M["derive_keyring"].__globals__, pins),
                    self.assertRaises(M["Incomplete"]),
                ):
                    M["derive_keyring"](work)
                self.assertFalse((Path(work) / "runc-keyring.gpg").exists())

    def test_multiple_exact_owners_and_diversions_are_distinct_metadata(self):
        alias = "/usr/bin/python3.12"
        rows = (
            "diversion by python3.12-minimal from: "
            + alias
            + "\n"
            + "diversion by python3.12-minimal to: "
            + alias
            + ".distrib\n"
            + "python3.12, python3.12-minimal: "
            + alias
            + "\n"
        )

        def query(argv, deadline):
            if "--search" in argv:
                return "zero", rows
            return "zero", argv[-1] + "\t3.12.3-1ubuntu0.13\tamd64\n"

        with patch.dict(
            M["package_facts"].__globals__, {"query_fact": Mock(side_effect=query)}
        ):
            records, _ = M["package_facts"]((alias,), 130)
        self.assertEqual(
            {item["package"] for item in records}, {"python3.12", "python3.12-minimal"}
        )
        self.assertTrue(all(item["diversion_observed"] for item in records))
        self.assertTrue(all(item["alias"] == alias for item in records))

    def test_diversion_only_unknown_or_overbudget_owner_rows_remain_incomplete(self):
        alias = "/usr/bin/gpgv"
        for rows in (
            "local diversion from: " + alias + "\n",
            "unknown owner syntax\n",
            ("pkg: " + alias + "\n") * 13,
            "a, b, c, d, e: " + alias + "\n",
        ):
            query = Mock(return_value=("zero", rows))
            with (
                self.subTest(rows=rows[:30]),
                patch.dict(M["package_facts"].__globals__, {"query_fact": query}),
            ):
                records, facts = M["package_facts"]((alias,), 130)
            query.assert_called_once_with(
                ["/usr/bin/dpkg-query", "--search", alias], 130
            )
            self.assertEqual(records, [])
            self.assertEqual(facts[0]["failure_stage"], "search-shape")

    def test_optional_image_release_stays_null_and_required_image_os_still_blocks(self):
        context = dict(
            ImageVersion="20261012.334.1",
            ImageOS="ubuntu24",
            ImageRelease=None,
            GITHUB_SHA="a" * 40,
            GITHUB_REPOSITORY="example/project",
            GITHUB_RUN_ID="123",
            GITHUB_RUN_ATTEMPT="1",
            GITHUB_JOB="installed-sshd",
        )
        glob = M["main"].__globals__
        observed = dict(
            lexical_path="/usr/bin/gpgv",
            status="observed-not-authenticated",
            sha256="a" * 64,
            packages=[dict(package="gpgv")],
        )
        for required_missing in (False, True):
            values = dict(context)
            if required_missing:
                values["ImageOS"] = None
            with (
                self.subTest(required_missing=required_missing),
                tempfile.TemporaryDirectory() as work,
                patch.dict(os.environ, {"RUNNER_TEMP": work}, clear=True),
                patch.object(glob["os"], "geteuid", return_value=1000),
                patch.object(glob["sys"], "argv", ["observe_gate0_native_inputs.py"]),
                patch.dict(
                    glob,
                    {
                        "metadata": Mock(return_value=values),
                        "observe_metadata": Mock(
                            return_value=(
                                [observed] * len(M["FILES"]),
                                dict(presence="absent", type=None),
                            )
                        ),
                        "observe_signature": Mock(
                            return_value=dict(cryptographic_signature_verified=True)
                        ),
                    },
                ),
                patch(
                    "builtins.open",
                    return_value=io.BytesIO(
                        b'ID=ubuntu\nVERSION_ID="24.04"\nUBUNTU_CODENAME=noble\n'
                    ),
                ),
            ):
                M["main"]()
                record = json.loads(
                    (Path(work) / "native-input-observation.json").read_bytes()
                )
                self.assertIsNone(record["context"]["ImageRelease"])
                self.assertEqual(
                    record["status"],
                    "incomplete" if required_missing else "candidate-observation-only",
                )
                self.assertFalse(record["overall_native_pass"])
                self.assertFalse(record["production_qualified"])
                self.assertFalse(record["operational_selector_configured"])


class NativePrerequisiteFactsTests(unittest.TestCase):
    def test_fixed_missing_tools_and_verifier_last(self):
        self.assertEqual(
            M["FILES"][-5:],
            (
                "/usr/bin/docker",
                "/usr/sbin/ip",
                "/usr/bin/mount",
                "/usr/bin/dpkg-query",
                "/usr/bin/gpgv",
            ),
        )
        self.assertEqual(len(set(M["FILES"])), 10)
        for path in M["FILES"]:
            self.assertIn(path, M["fixed_aliases"](path))
        self.assertIn("/usr/bin/ip", M["fixed_aliases"]("/usr/sbin/ip"))
        with self.assertRaises(M["Incomplete"]):
            M["fixed_aliases"]("/outside-approved-layout/unknown")

    @staticmethod
    def info(mode):
        return SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=mode,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=3,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )

    def test_file_mode_suid_ancestors_and_symlink_facts_are_observed_not_changed(self):
        glob = M["observe_file"].__globals__
        path, resolved = "/usr/sbin/ip", "/usr/bin/ip"
        regular = self.info(stat.S_IFREG | 0o4755)

        def lstat(value):
            return (
                self.info(stat.S_IFLNK | 0o777)
                if value == path
                else self.info(stat.S_IFDIR | 0o755)
            )

        with (
            patch.object(glob["time"], "monotonic", return_value=100),
            patch.object(glob["os"].path, "realpath", return_value=resolved),
            patch.object(glob["os"], "lstat", side_effect=lstat),
            patch.object(glob["os"], "open", return_value=42),
            patch.object(glob["os"], "fstat", return_value=regular),
            patch.object(glob["os"], "read", side_effect=[b"abc", b""]),
            patch.object(glob["os"], "close"),
            patch.object(glob["os"], "listxattr", return_value=["security.capability"]),
            patch.dict(glob, {"package_facts": Mock(return_value=([], []))}),
        ):
            result = M["observe_file"](path, 130)
        self.assertEqual(result["status"], "observed-not-authenticated")
        self.assertEqual(result["mode"], 0o4755)
        self.assertEqual((result["uid"], result["gid"], result["nlink"]), (0, 0, 1))
        self.assertTrue(result["lexical"]["symlink"])
        self.assertEqual(result["capability_presence"], "present")
        self.assertEqual(
            {item["path"] for item in result["ancestors"]},
            {"/", "/usr", "/usr/bin", "/usr/sbin"},
        )
        self.assertTrue(
            all(item["uid"] == item["gid"] == 0 for item in result["ancestors"])
        )

    def test_outside_alias_refuses_without_reading_or_retaining_unknown_path(self):
        glob = M["observe_file"].__globals__
        with (
            patch.object(glob["os"].path, "realpath", return_value="/private/unknown"),
            patch.object(glob["os"], "open") as opened,
            patch.object(glob["os"], "lstat") as measured,
        ):
            result = M["observe_file"]("/usr/bin/docker")
        opened.assert_not_called()
        measured.assert_not_called()
        self.assertEqual(result["failure_class"], "unexpected-alias")
        self.assertNotIn("private", json.dumps(result))

    def test_capabilities_absent_present_and_unknown_never_read_raw_values(self):
        glob = M["capabilities"].__globals__
        for value, expected in (
            ([], "absent"),
            (["security.capability"], "present"),
            (OSError("not retained"), "unknown"),
        ):
            with patch.object(
                glob["os"],
                "listxattr",
                **(
                    {"side_effect": value}
                    if isinstance(value, OSError)
                    else {"return_value": value}
                ),
            ):
                self.assertEqual(M["capabilities"](42), expected)

    def test_typed_multiarch_multiple_owner_diversion_and_unknown_rows_no_raw_text(
        self,
    ):
        alias = "/usr/bin/python3.12"
        raw = (
            "libc6:amd64, python3.12-minimal: " + alias + "\n"
            "diversion by python3.12-minimal from: " + alias + "\n"
            "local diversion to: /private/unknown\n"
            "invalid PRIVATE_ROW_TOKEN\n"
            "foreign: /private/foreign\n"
        )
        result, names = M["search_facts"](raw, alias)
        self.assertEqual(names, {"libc6:amd64", "python3.12-minimal"})
        self.assertEqual(result["unknown_rows"], 1)
        self.assertEqual(result["shape"], "unrecognized-or-unassociated")
        self.assertEqual(
            result["rows"][0],
            dict(
                type="owner",
                package="libc6",
                qualifier="amd64",
                matched_fixed_path=True,
            ),
        )
        self.assertEqual(result["rows"][-1]["matched_fixed_path"], False)
        self.assertNotIn("PRIVATE_ROW_TOKEN", json.dumps(result))
        self.assertNotIn("/private", json.dumps(result))
        for malformed in ("", "unknown\n" * 13, "x" * 1025):
            self.assertEqual(
                M["search_facts"](malformed, alias)[0]["shape"], "bounds-or-empty"
            )

    def test_query_exit_timeout_budget_encoding_and_bounds_are_typed(self):
        glob = M["query_fact"].__globals__
        argv = ["/usr/bin/dpkg-query", "--search", "/usr/bin/docker"]
        for code, payload, expected in (
            (0, b"pkg: /usr/bin/docker\n", "zero"),
            (1, b"", "nonzero"),
            (0, b"\xff", "encoding"),
            (0, b"x" * 65537, "bounds"),
        ):

            def run(command, payload=payload, code=code, **kwargs):
                kwargs["stdout"].write(payload)
                self.assertEqual(kwargs["timeout"], 2)
                self.assertEqual(kwargs["env"], M["ENV"])
                self.assertIs(kwargs["stderr"], M["subprocess"].DEVNULL)
                return Mock(returncode=code)

            with (
                patch.object(glob["time"], "monotonic", return_value=100),
                patch.object(glob["subprocess"], "run", side_effect=run),
            ):
                self.assertEqual(M["query_fact"](argv, 130)[0], expected)
        for error, expected in (
            (M["subprocess"].TimeoutExpired(argv, 2), "timeout"),
            (OSError("not retained"), "unavailable"),
        ):
            with (
                patch.object(glob["time"], "monotonic", return_value=100),
                patch.object(glob["subprocess"], "run", side_effect=error),
            ):
                self.assertEqual(M["query_fact"](argv, 130), (expected, None))
        with (
            patch.object(glob["time"], "monotonic", return_value=130),
            patch.object(glob["subprocess"], "run") as run,
        ):
            self.assertEqual(M["query_fact"](argv, 130), ("budget-exhausted", None))
            run.assert_not_called()

    def test_package_failure_stages_and_python_candidate_are_separate(self):
        glob = M["package_facts"].__globals__
        alias = "/usr/bin/python3.12"
        for exit_class, raw, stage in (
            ("nonzero", "", "search-exit"),
            ("zero", "unrecognized\n", "search-shape"),
            ("timeout", None, "search-exit"),
        ):
            query = Mock(
                side_effect=[
                    (exit_class, raw),
                    ("zero", "python3.12-minimal\t3.12.3-1ubuntu0.17\tamd64\n"),
                ]
            )
            with patch.dict(glob, {"query_fact": query}):
                associated, facts = M["package_facts"]((alias,), 130)
            self.assertEqual(associated, [])
            self.assertEqual(facts[0]["failure_stage"], stage)
            candidate = facts[-1]["candidate_query"]
            self.assertEqual(candidate["query_kind"], "candidate-only-not-association")
            self.assertTrue(candidate["architecture_matches_amd64"])
        for show_exit, show_raw, stage in (
            ("nonzero", "", "show-exit"),
            ("zero", "PRIVATE_BAD_ROW\n", "show-shape"),
            ("timeout", None, "show-exit"),
        ):
            with patch.dict(
                glob,
                {
                    "query_fact": Mock(
                        side_effect=[
                            ("zero", "docker: /usr/bin/docker\n"),
                            (show_exit, show_raw),
                        ]
                    )
                },
            ):
                associated, facts = M["package_facts"](("/usr/bin/docker",), 130)
            self.assertEqual(associated, [])
            self.assertEqual(facts[0]["failure_stage"], stage)
            self.assertNotIn("PRIVATE_BAD_ROW", json.dumps(facts))

    def test_show_arch_qualifier_and_requested_package_match_facts(self):
        glob = M["show_fact"].__globals__
        with patch.dict(
            glob,
            {
                "query_fact": Mock(
                    return_value=("zero", "libc6:amd64\t2.39-0ubuntu8.9\tamd64\n")
                )
            },
        ):
            result = M["show_fact"]("libc6:amd64", "owner-association", 130)
        self.assertEqual(result["qualifier"], "amd64")
        self.assertTrue(result["requested_package_matches"])
        with patch.dict(
            glob,
            {"query_fact": Mock(return_value=("zero", "foreign:arm64\t1.0\tarm64\n"))},
        ):
            result = M["show_fact"]("libc6:amd64", "owner-association", 130)
        self.assertFalse(result["requested_package_matches"])
        self.assertFalse(result["architecture_matches_amd64"])

    def test_runc_target_absent_regular_symlink_special_or_unknown_without_open(self):
        glob = M["runc_target"].__globals__
        for value, presence, kind in (
            (FileNotFoundError(), "absent", None),
            (self.info(stat.S_IFREG | 0o755), "present", "regular"),
            (self.info(stat.S_IFLNK | 0o777), "present", "symlink"),
            (self.info(stat.S_IFCHR | 0o600), "present", "special"),
            (PermissionError(), "unknown", None),
        ):
            with (
                patch.object(
                    glob["os"],
                    "lstat",
                    **(
                        {"side_effect": value}
                        if isinstance(value, OSError)
                        else {"return_value": value}
                    ),
                ),
                patch.object(glob["os"], "open") as opened,
            ):
                self.assertEqual(M["runc_target"](), dict(presence=presence, type=kind))
                opened.assert_not_called()

    def test_original_metadata_budget_never_reanchors_or_calls_remaining_files(self):
        glob = M["observe_metadata"].__globals__
        clock = iter([100, 100] + [131] * 10)
        with (
            patch.object(glob["time"], "monotonic", side_effect=lambda: next(clock)),
            patch.object(glob["signal"], "signal"),
            patch.object(glob["signal"], "setitimer") as timer,
            patch.dict(
                glob,
                {
                    "observe_file": Mock(return_value=dict(status="observed")),
                    "runc_target": Mock(),
                },
            ),
        ):
            files, target = M["observe_metadata"]()
            glob["observe_file"].assert_called_once_with(M["FILES"][0], 130)
            glob["runc_target"].assert_not_called()
        self.assertEqual(len(files), len(M["FILES"]))
        self.assertEqual([call.args[1] for call in timer.call_args_list], [30, 0])
        self.assertEqual(target["presence"], "unknown")
        self.assertTrue(
            all(item["failure_class"] == "metadata-budget" for item in files[1:])
        )

    def test_metadata_alarm_retains_partial_files_and_marks_rest_incomplete(self):
        glob = M["observe_metadata"].__globals__
        with (
            patch.object(glob["time"], "monotonic", return_value=100),
            patch.object(glob["signal"], "signal") as handler,
            patch.object(glob["signal"], "setitimer") as timer,
            patch.dict(
                glob,
                {
                    "observe_file": Mock(
                        side_effect=[
                            dict(status="observed"),
                            M["Incomplete"]("metadata-budget"),
                        ]
                    )
                },
            ),
        ):
            files, target = M["observe_metadata"]()
        self.assertEqual(files[0], dict(status="observed"))
        self.assertTrue(
            all(item["failure_class"] == "metadata-budget" for item in files[1:])
        )
        self.assertEqual(target["presence"], "unknown")
        self.assertEqual([call.args[1] for call in timer.call_args_list], [30, 0])
        with self.assertRaises(M["Incomplete"]):
            handler.call_args_list[0].args[1](None, None)


if __name__ == "__main__":
    unittest.main()
