"""Mocked standard-library tests only; no native/signature qualification."""

import base64
import hashlib
import io
import json
import os
import runpy
import tempfile
import unittest
from pathlib import Path
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
            M["packages"].__globals__,
            {"command": Mock(side_effect=NameError("never retained"))},
        ):
            with self.assertRaises(NameError):
                M["packages"](("/usr/bin/gpgv",))

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
                    "observe_file": Mock(return_value=file),
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

        def query(argv):
            if "--search" in argv:
                return rows
            return argv[-1] + "\t3.12.3-1ubuntu0.13\tamd64\n"

        with patch.dict(
            M["packages"].__globals__, {"command": Mock(side_effect=query)}
        ):
            records = M["packages"]((alias,))
        self.assertEqual(
            {item["package"] for item in records}, {"python3.12", "python3.12-minimal"}
        )
        self.assertTrue(all(item["diversion_observed"] for item in records))
        self.assertTrue(all(item["alias"] == alias for item in records))

    def test_diversion_only_unknown_or_overbudget_owner_rows_remain_incomplete(self):
        alias = "/usr/bin/python3.12"
        for rows in (
            "local diversion from: " + alias + "\n",
            "unknown owner syntax\n",
            ("pkg: " + alias + "\n") * 13,
            "a, b, c, d, e: " + alias + "\n",
        ):
            query = Mock(return_value=rows)
            with (
                self.subTest(rows=rows[:30]),
                patch.dict(M["packages"].__globals__, {"command": query}),
            ):
                records = M["packages"]((alias,))
            query.assert_called_once_with(["/usr/bin/dpkg-query", "--search", alias])
            self.assertFalse(any("package" in item for item in records))
            self.assertEqual(records[0]["failure_class"], "package-incomplete")

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
                        "observe_file": Mock(return_value=observed),
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


if __name__ == "__main__":
    unittest.main()
