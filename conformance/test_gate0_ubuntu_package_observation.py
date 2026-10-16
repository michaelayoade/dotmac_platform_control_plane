"""Mocked public package-chain source checks; no native/package installation."""

import copy
import hashlib
import io
import json
import lzma
import os
import runpy
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import Mock, patch

SOURCE = (
    Path(__file__).parents[1] / ".github/candidate/observe_gate0_ubuntu_packages.py"
)
M = runpy.run_path(str(SOURCE), run_name="mocked_ubuntu_package_source")


def signed():
    return "[GNUPG:] VALIDSIG " + M["SIGNER"] + " 2026-10-12 123 0 4 0 1 10 00\n"


def index_bytes(packages):
    return lzma.compress(
        (
            "\n\n".join(
                "\n".join(key + ": " + value for key, value in item.items())
                for item in packages
            )
            + "\n\n"
        ).encode()
    )


class UbuntuPackageTests(unittest.TestCase):
    def test_readonly_utility_loading_preserves_argv_and_never_starts_operations(self):
        original = list(sys.argv)
        handler = signal.getsignal(signal.SIGALRM)
        with (
            patch.object(subprocess, "run") as child,
            patch.object(urllib.request.OpenerDirector, "open") as network,
        ):
            runpy.run_path(str(SOURCE), run_name="import_without_operations")
        self.assertEqual(sys.argv, original)
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)
        child.assert_not_called()
        network.assert_not_called()

    def test_exact_direct_signer_and_bad_revoked_expired_foreign_status_refuse(self):
        self.assertTrue(
            M["signed_status"](signed())["cryptographic_signature_verified"]
        )
        for raw in (
            signed().replace(M["SIGNER"], "A" * 40),
            signed() * 2,
            signed() + "[GNUPG:] BADSIG x\n",
            signed() + "[GNUPG:] REVKEYSIG x\n",
            signed() + "[GNUPG:] EXPKEYSIG x\n",
            signed() + "[GNUPG:] ERRSIG x\n",
        ):
            with self.subTest(raw=raw[-30:]), self.assertRaises(M["Incomplete"]):
                M["signed_status"](raw)

    def test_signed_release_index_hash_size_and_duplicates_are_joined(self):
        size, digest = M["INDEX_PIN"]
        row = " " + digest + " " + str(size) + " " + M["INDEX"] + "\n"

        def release(rows):
            return (
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
                "Origin: Ubuntu\nSHA256:\n" + rows + "-----BEGIN PGP SIGNATURE-----\n"
            ).encode()

        M["release_chain"](release(row))
        for rows in (
            row + row,
            row.replace(digest, "0" * 64),
            row.replace(str(size), str(size + 1)),
            row.replace(M["INDEX"], "foreign/Packages.xz"),
        ):
            with self.subTest(rows=rows[:20]), self.assertRaises(M["Incomplete"]):
                M["release_chain"](release(rows))

    def test_exact_package_stanzas_and_duplicate_foreign_or_tampered_fields(self):
        M["package_index"](index_bytes(M["PACKAGES"]))
        variants = [M["PACKAGES"][:-1], M["PACKAGES"] + [M["PACKAGES"][0]]]
        for field in ("Version", "Architecture", "Filename", "Size", "SHA256"):
            bad = copy.deepcopy(M["PACKAGES"])
            bad[0][field] = "foreign"
            variants.append(bad)
        for rows in variants:
            with self.subTest(count=len(rows)), self.assertRaises(M["Incomplete"]):
                M["package_index"](index_bytes(rows))
        duplicate = b"Package: gpgv\nPackage: gpgv\n\n"
        with self.assertRaises(M["Incomplete"]):
            M["package_index"](lzma.compress(duplicate))

    def test_xz_truncation_trailing_data_and_expansion_bound(self):
        compressed = index_bytes(M["PACKAGES"])
        for raw in (compressed[:-2], compressed + b"trailing"):
            with self.assertRaises(M["Incomplete"]):
                M["package_index"](raw)
        decoder = Mock(eof=True, unused_data=b"")
        decoder.decompress.return_value = b"x" * ((32 << 20) + 1)
        with (
            patch.object(
                M["package_index"].__globals__["lzma"],
                "LZMADecompressor",
                return_value=decoder,
            ),
            self.assertRaises(M["Incomplete"]),
        ):
            M["package_index"](b"mocked")
        decoder.decompress.assert_called_once_with(b"mocked", max_length=(32 << 20) + 1)

    def package_tar(self, kind="regular", duplicate=False, foreign=False):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as tar:
            for _ in range(2 if duplicate else 1):
                item = tarfile.TarInfo(
                    "./usr/bin/foreign" if foreign else "./usr/bin/python3.12"
                )
                item.mode = 0o755
                item.size = 4
                if kind == "symlink":
                    item.type = tarfile.SYMTYPE
                    item.linkname = "foreign"
                    item.size = 0
                tar.addfile(item, io.BytesIO(b"data") if item.size else None)
        return output.getvalue()

    def test_data_reader_regular_member_hash_and_no_execution_or_extraction(self):
        raw = self.package_tar()

        def read(argv, **kwargs):
            self.assertEqual(
                argv, ["/usr/bin/dpkg-deb", "--fsys-tarfile", "/mock/python.deb"]
            )
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C"})
            kwargs["stdout"].write(raw)
            return Mock(returncode=0)

        with (
            tempfile.TemporaryDirectory() as work,
            patch.object(
                M["package_members"].__globals__["subprocess"], "run", side_effect=read
            ),
        ):
            members = M["package_members"](
                "python3.12-minimal", "/mock/python.deb", work, 10**12
            )
            self.assertEqual(
                members,
                [
                    dict(
                        path="/usr/bin/python3.12",
                        size=4,
                        mode=0o755,
                        sha256=hashlib.sha256(b"data").hexdigest(),
                    )
                ],
            )
            self.assertEqual(list(Path(work).iterdir()), [])

    def test_duplicate_foreign_and_nonregular_selected_members_refuse(self):
        for raw in (
            self.package_tar(duplicate=True),
            self.package_tar(foreign=True),
            self.package_tar(kind="symlink"),
        ):

            def read(argv, stdout, raw=raw, **kwargs):
                stdout.write(raw)
                return Mock(returncode=0)

            with (
                tempfile.TemporaryDirectory() as work,
                patch.object(
                    M["package_members"].__globals__["subprocess"],
                    "run",
                    side_effect=read,
                ),
                self.assertRaises(M["Incomplete"]),
            ):
                M["package_members"](
                    "python3.12-minimal", "/mock/python.deb", work, 10**12
                )

    def test_sparse_preflight_before_tar_parser_and_reader_failure(self):
        raw = bytearray(self.package_tar())
        raw[156:157] = b"S"

        def read(argv, stdout, **kwargs):
            stdout.write(raw)
            return Mock(returncode=0)

        glob = M["package_members"].__globals__
        with (
            tempfile.TemporaryDirectory() as work,
            patch.object(glob["subprocess"], "run", side_effect=read),
            patch.object(glob["tarfile"], "open") as parser,
            self.assertRaises(ValueError),
        ):
            M["package_members"]("python3.12-minimal", "/mock/python.deb", work, 10**12)
        parser.assert_not_called()
        with (
            tempfile.TemporaryDirectory() as work,
            patch.object(glob["subprocess"], "run", return_value=Mock(returncode=1)),
            self.assertRaises(M["Incomplete"]),
        ):
            M["package_members"]("python3.12-minimal", "/mock/python.deb", work, 10**12)

    def test_mismatch_is_explicit_and_all_native_qualification_flags_false(self):
        context = dict(
            GITHUB_SHA="a" * 40,
            GITHUB_REPOSITORY="example/project",
            GITHUB_RUN_ID="123",
            GITHUB_RUN_ATTEMPT="1",
            GITHUB_JOB="installed-sshd",
        )
        glob = M["main"].__globals__

        def fetch(work, name, relative, pin, deadline):
            path = Path(work) / name
            path.write_bytes(b"mocked signed data")
            return path

        def members(package, archive, work, deadline):
            return [
                dict(path="/" + name, size=4, mode=0o755, sha256="a" * 64)
                for name in M["MEMBERS"][package]
            ]

        actual = {
            "/" + name: dict(size=4, mode=0o755, sha256="a" * 64)
            for paths in M["MEMBERS"].values()
            for name in paths
        }
        actual["/usr/bin/python3.12"]["sha256"] = "b" * 64
        utilities = dict(
            M["U"],
            metadata=Mock(return_value=context),
            command=Mock(return_value=signed()),
        )
        with (
            tempfile.TemporaryDirectory() as work,
            patch.dict(os.environ, {"RUNNER_TEMP": work}, clear=True),
            patch.object(glob["os"], "geteuid", return_value=1000),
            patch.object(glob["sys"], "argv", ["observe"]),
            patch.object(glob["signal"], "signal"),
            patch.object(glob["signal"], "setitimer") as timer,
            patch.dict(
                glob,
                {
                    "U": utilities,
                    "local_hash": Mock(return_value="a" * 64),
                    "fetch": fetch,
                    "release_chain": Mock(),
                    "package_index": Mock(),
                    "package_members": members,
                    "observed_files": Mock(return_value=actual),
                },
            ),
        ):
            M["main"]()
            raw = (Path(work) / "ubuntu-package-observation.json").read_bytes()
            self.assertLessEqual(len(raw), 65536)
            result = json.loads(raw)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["failure_stage"], "member-comparison")
            self.assertEqual(result["candidate_package"], "python3.12-minimal")
            python = next(
                item
                for item in result["packages"]
                if item["candidate"]["Package"] == "python3.12-minimal"
            )
            self.assertEqual(python["members"][0]["observed_match"], "mismatch")
            self.assertTrue(
                result["release_signature"]["cryptographic_signature_verified"]
            )
            for key in (
                "overall_native_pass",
                "production_qualified",
                "operational_selector_configured",
            ):
                self.assertIs(result[key], False)
            self.assertEqual([call.args[1] for call in timer.call_args_list], [120, 0])

    def test_legitimate_unrelated_long_index_field_and_16k_line_refusal(self):
        unrelated = dict(
            Package="unrelated-public-metadata",
            Metadata="x" * (11203 - len("Metadata: ")),
        )
        M["package_index"](index_bytes(M["PACKAGES"] + [unrelated]))
        for total in (16384, 16385):
            unrelated["Metadata"] = "x" * (total - len("Metadata: "))
            compressed = index_bytes(M["PACKAGES"] + [unrelated])
            if total == 16384:
                M["package_index"](compressed)
            else:
                with self.assertRaises(M["Incomplete"]):
                    M["package_index"](compressed)

    def test_closed_failure_stages_preserve_partial_signature_and_no_raw_error(self):
        glob = M["main"].__globals__
        context = dict(
            GITHUB_SHA="a" * 40,
            GITHUB_REPOSITORY="example/project",
            GITHUB_RUN_ID="123",
            GITHUB_RUN_ATTEMPT="1",
            GITHUB_JOB="installed-sshd",
        )
        for failing in (
            "bootstrap",
            "release-signature",
            "release-index",
            "package-index",
            "package-download",
            "package-data-reader",
            "member-comparison",
        ):

            def fail(*args, **kwargs):
                raise KeyError("never-retain-raw-exception-details")

            def fetch(work, name, relative, pin, deadline, failing=failing):
                if failing == "package-download" and name.endswith(".deb"):
                    return fail()
                path = Path(work) / name
                path.write_bytes(b"mocked public data")
                return path

            def members(package, archive, work, deadline):
                return [
                    dict(path="/" + name, size=4, mode=0o755, sha256="a" * 64)
                    for name in M["MEMBERS"][package]
                ]

            broken = Mock()
            broken.get.side_effect = KeyError("never-retain-raw-exception-details")
            utilities = dict(
                M["U"],
                metadata=Mock(return_value=context),
                command=Mock(return_value=signed()),
            )
            overrides = dict(
                U=utilities,
                local_hash=Mock(return_value="a" * 64),
                fetch=fetch,
                signed_status=Mock(
                    return_value=dict(cryptographic_signature_verified=True)
                ),
                release_chain=Mock(),
                package_index=Mock(),
                package_members=members,
                observed_files=Mock(return_value={"/usr/bin/gpgv": broken}),
            )
            name = {
                "bootstrap": "local_hash",
                "release-signature": "signed_status",
                "release-index": "release_chain",
                "package-index": "package_index",
                "package-data-reader": "package_members",
            }.get(failing)
            if name:
                overrides[name] = fail
            with (
                self.subTest(stage=failing),
                tempfile.TemporaryDirectory() as work,
                patch.dict(os.environ, {"RUNNER_TEMP": work}, clear=True),
                patch.object(glob["os"], "geteuid", return_value=1000),
                patch.object(glob["sys"], "argv", ["observe"]),
                patch.object(glob["signal"], "signal"),
                patch.object(glob["signal"], "setitimer"),
                patch.dict(glob, overrides),
            ):
                M["main"]()
                raw = (Path(work) / "ubuntu-package-observation.json").read_bytes()
                record = json.loads(raw)
                self.assertEqual(record["failure_stage"], failing)
                self.assertEqual(
                    record["candidate_package"],
                    "gpgv"
                    if failing
                    in ("package-download", "package-data-reader", "member-comparison")
                    else None,
                )
                self.assertEqual(
                    record["release_signature"]["cryptographic_signature_verified"],
                    failing not in ("bootstrap", "release-signature"),
                )
                self.assertFalse(record["overall_native_pass"])
                self.assertFalse(record["production_qualified"])
                self.assertFalse(record["operational_selector_configured"])
                self.assertNotIn(b"never-retain-raw-exception-details", raw)
                self.assertLessEqual(len(raw), 65536)


if __name__ == "__main__":
    unittest.main()
