"""Mocked standard-library tests only; no native/signature qualification."""

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
                glob, {"download": Mock(), "command": Mock(return_value=valid_status())}
            ),
            patch.object(glob["signal"], "signal"),
            patch.object(glob["signal"], "setitimer") as timer,
        ):
            result = M["observe_signature"]()
            self.assertTrue(result["cryptographic_signature_verified"])
            argv = glob["command"].call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/gpgv")
            self.assertTrue(argv[-1].endswith("/runc.amd64"))
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


if __name__ == "__main__":
    unittest.main()
