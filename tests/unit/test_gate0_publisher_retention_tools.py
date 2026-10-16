"""Synthetic refusal checks; these never inspect a production certificate."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "publisher_retention_inspector",
    ROOT / ".github/candidate/inspect_gate0_publisher.py",
)
assert SPEC is not None and SPEC.loader is not None
INSPECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECT)


def synthetic_archive():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, kind, raw, target in (
            ("etc", tarfile.DIRTYPE, b"", ""),
            ("etc/data", tarfile.REGTYPE, b"synthetic bytes", ""),
            ("etc/sibling", tarfile.SYMTYPE, b"", "data"),
            ("etc/hard", tarfile.LNKTYPE, b"", "etc/data"),
        ):
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.uid, item.gid = kind, 0o755, 0, 42
            item.size, item.linkname = len(raw), target
            archive.addfile(item, io.BytesIO(raw))
    stream.seek(0)
    return tarfile.open(fileobj=stream, mode="r:")


def pax_record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while True:
        raw = str(size).encode() + b" " + body
        if len(raw) == size:
            return raw
        size = len(raw)


def raw_tar_member(name, kind, body=b""):
    item = tarfile.TarInfo(name)
    item.type, item.size = kind, len(body)
    return item.tobuf(format=tarfile.GNU_FORMAT) + body + bytes((-len(body)) % 512)


class CompleteInventoryTests(unittest.TestCase):
    def assert_sparse_refuses_before_tarfile(self, raw):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in (
                ("production.tar", raw),
                ("publisher.tar", raw),
                ("shape.json", b"{}"),
            ):
                path = root / name
                path.write_bytes(data)
                path.chmod(0o600)
            with patch.object(
                INSPECT.tarfile,
                "open",
                side_effect=AssertionError("tarfile must not process sparse input"),
            ) as parser:
                with self.assertRaises(ValueError):
                    INSPECT.inspect(
                        root / "production.tar",
                        root / "publisher.tar",
                        root / "shape.json",
                        root / "manifest.json",
                    )
                parser.assert_not_called()

    def test_old_gnu_sparse_refuses_before_tarfile_extension_processing(self):
        raw = raw_tar_member("sparse", tarfile.GNUTYPE_SPARSE) + bytes(1024)
        self.assert_sparse_refuses_before_tarfile(raw)

    def test_pax_sparse_1_0_and_0_x_refuse_before_tarfile_map_allocation(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, b"X"):
            for records, body in (
                (
                    (
                        (b"GNU.sparse.major", b"1"),
                        (b"GNU.sparse.minor", b"0"),
                        (b"GNU.sparse.realsize", b"1"),
                        (b"GNU.sparse.name", b"sparse"),
                    ),
                    b"1000000000\n",
                ),
                (((b"GNU.sparse.map", b"0,1"), (b"GNU.sparse.size", b"1")), b"x"),
                (
                    (
                        (b"GNU.sparse.numblocks", b"1"),
                        (b"GNU.sparse.offset", b"0"),
                        (b"GNU.sparse.numbytes", b"1"),
                    ),
                    b"x",
                ),
                (((b"GNU.sparse.future-unrecognised", b"1"),), b"x"),
            ):
                with self.subTest(kind=kind, keys=[key for key, _ in records]):
                    pax = b"".join(pax_record(key, value) for key, value in records)
                    raw = (
                        raw_tar_member("pax", kind, pax)
                        + raw_tar_member("sparse", tarfile.REGTYPE, body)
                        + bytes(1024)
                    )
                    self.assert_sparse_refuses_before_tarfile(raw)

    def test_malformed_pax_records_refuse_before_tarfile(self):
        for body in (
            b"9 a=b\n",
            b"0 a=b\n",
            b"6 a=b",
            b"6 a:b\n",
            b"6 =ab\n",
            b"6 a=b\ntrailing",
            b"6 a\x00=\n",
        ):
            raw = raw_tar_member("pax", tarfile.XHDTYPE, body) + bytes(1024)
            self.assert_sparse_refuses_before_tarfile(raw)

    def test_ordinary_bounded_pax_and_gnu_long_names_remain_supported(self):
        name = "ordinary/" + "x" * 150
        for format_ in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w", format=format_) as archive:
                item = tarfile.TarInfo(name)
                item.size = 1
                if format_ == tarfile.PAX_FORMAT:
                    item.pax_headers = {
                        "comment": "bounded ordinary metadata",
                        "mtime": "1.5",
                    }
                archive.addfile(item, io.BytesIO(b"x"))
            INSPECT.bounded_tar_headers(stream)
            self.assertEqual(stream.tell(), 0)
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                members = INSPECT.inventory(archive, publisher=True)
                self.assertEqual(set(members), {name})

    def test_raw_header_preflight_refuses_oversized_extensions_and_trailing_data(self):
        extension = tarfile.TarInfo("extension")
        extension.type = tarfile.XHDTYPE
        extension.size = 16 * 1024 + 1
        oversized = extension.tobuf() + bytes(17 * 1024) + bytes(1024)
        for raw in (oversized, bytes(1024) + b"x" + bytes(511), bytes(512)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                INSPECT.bounded_tar_headers(io.BytesIO(raw))

    def test_raw_header_preflight_accepts_regular_export_and_rewinds(self):
        with synthetic_archive() as archive:
            stream = archive.fileobj
            INSPECT.bounded_tar_headers(stream)
            self.assertEqual(stream.tell(), 0)

    def test_complete_canonical_roster_includes_non_venv_and_links(self):
        with synthetic_archive() as archive:
            members = INSPECT.inventory(archive, publisher=True)
            raw = INSPECT.complete_files(archive, members)
            rows = json.loads(raw)["files"]
            self.assertEqual([row["path"] for row in rows], sorted(members))
            self.assertEqual(raw, INSPECT.complete_files(archive, members))
            self.assertEqual(len(rows), 4)
            data = next(row for row in rows if row["path"] == "etc/data")
            self.assertEqual(
                data["sha256"], hashlib.sha256(b"synthetic bytes").hexdigest()
            )
            self.assertEqual((data["uid"], data["gid"], data["mode"]), (0, 42, 0o755))
            hard = next(row for row in rows if row["type"] == "hardlink")
            self.assertEqual(hard["link_target"], "etc/data")
            self.assertIsNone(hard["sha256"])

    def test_streaming_member_hash_does_not_use_materializing_reader(self):
        with synthetic_archive() as archive:
            members = INSPECT.inventory(archive, publisher=True)
            with patch.object(INSPECT, "read", side_effect=AssertionError):
                INSPECT.complete_files(archive, members)

    def test_fixed_entry_file_and_manifest_limits_refuse(self):
        for limit, value in (("MAX_ENTRIES", 2), ("MAX_FILE_BYTES", 2)):
            with synthetic_archive() as archive, patch.object(INSPECT, limit, value):
                with self.assertRaises(ValueError):
                    INSPECT.inventory(archive, publisher=True)
        with synthetic_archive() as archive:
            members = INSPECT.inventory(archive, publisher=True)
            with patch.object(INSPECT, "MAX_FILES_BYTES", 64):
                with self.assertRaises(ValueError):
                    INSPECT.complete_files(archive, members)

    def test_path_byte_limit_and_control_characters_refuse(self):
        for name in ("x" * 4097, "a\nb", "a\x00b", "a\x7fb"):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                INSPECT.member_name(name)


class PrivateInputTests(unittest.TestCase):
    def test_exclusive_private_outputs_and_stream_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            with INSPECT.private_output(output) as stream:
                stream.write(b"synthetic")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                INSPECT.private_output(output)
            self.assertEqual(output.read_bytes(), b"synthetic")
        with self.assertRaises(ValueError):
            INSPECT.stream_digest(io.BytesIO(b"12345"), maximum=4)

    def test_symlink_hardlink_and_public_mode_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input"
            source.write_bytes(b"synthetic")
            source.chmod(0o600)
            link = root / "symlink"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                INSPECT.private_input(link, 100)
            os.link(source, root / "hardlink")
            with self.assertRaises(ValueError):
                INSPECT.private_input(source, 100)
            (root / "hardlink").unlink()
            source.chmod(0o644)
            with self.assertRaises(ValueError):
                INSPECT.private_input(source, 100)

    def test_held_descriptor_survives_path_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input"
            source.write_bytes(b"original")
            source.chmod(0o600)
            with INSPECT.private_input(source, 100) as stream:
                source.rename(source.with_suffix(".held"))
                source.write_bytes(b"substituted")
                self.assertEqual(stream.read(), b"original")


RETENTION_SPEC = importlib.util.spec_from_file_location(
    "publisher_runtime_retention", ROOT / ".github/candidate/retain_gate0_publisher.py"
)
assert RETENTION_SPEC is not None and RETENTION_SPEC.loader is not None
RETAIN = importlib.util.module_from_spec(RETENTION_SPEC)
RETENTION_SPEC.loader.exec_module(RETAIN)


def synthetic_packet():
    # Digests below are synthetic inputs, never production qualification records.
    return {
        "schema": "DotmacPublisherRuntimeRetentionExecution.v1",
        "operation": "build-inspect-encrypt-retain",
        "source": {
            "revision": "a" * 40,
            "ref": "refs/heads/synthetic",
            "workflow_path": RETAIN.WORKFLOW,
            "workflow_blob_sha256": "b" * 64,
            "files": dict.fromkeys(RETAIN.SOURCE_FILES, "c" * 64),
        },
        "github": {
            "repository": RETAIN.REPOSITORY,
            "repository_id": 1,
            "owner_id": 2,
            "workflow_id": 3,
            "actor_id": 4,
            "job_key": "image",
        },
        "validity": {
            "not_before": "2026-10-16T00:00:00Z",
            "expires_at": "2026-10-17T00:00:00Z",
        },
        "recipient": {
            "certificate_sha256": RETAIN.CERTIFICATE_SHA256,
            "primary_fingerprint": RETAIN.PRIMARY_FINGERPRINT,
            "encryption_fingerprint": RETAIN.ENCRYPTION_FINGERPRINT,
        },
        "tool_qualification_sha256": "d" * 64,
        "build": {
            "mode": "build-once-in-selected-job",
            "platform": "linux/amd64",
            "base_image": RETAIN.BASE_IMAGE,
            "production_target": "runtime",
            "publisher_target": "gate0-publisher",
        },
        "limits": dict(RETAIN.LIMITS),
        "artifact": {
            "name": "gate0-publisher-runtime",
            "retention_days": 30,
            "files": ["encrypted-runtime-bundle.pgp", "producer-receipt.json"],
        },
    }


class RetentionPacketTests(unittest.TestCase):
    def test_authenticated_job_selection_and_origin_mismatches(self):
        import base64
        import copy

        packet = synthetic_packet()
        packet["source"]["workflow_blob_sha256"] = hashlib.sha256(
            (ROOT / RETAIN.WORKFLOW).read_bytes()
        ).hexdigest()
        packet["source"]["files"] = {
            key: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for key, path in RETAIN.SOURCE_FILES.items()
        }
        environment = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": RETAIN.REPOSITORY,
            "GITHUB_JOB": "image",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/synthetic",
            "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_WORKFLOW_REF": RETAIN.REPOSITORY
            + "/"
            + RETAIN.WORKFLOW
            + "@refs/heads/synthetic",
            "GITHUB_RUN_ID": "10",
            "GITHUB_TOKEN": "synthetic-placeholder",
        }
        run = {
            "id": 10,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "head_sha": "a" * 40,
            "head_branch": "synthetic",
            "repository": {"full_name": RETAIN.REPOSITORY, "id": 1, "owner": {"id": 2}},
            "head_repository": {"full_name": RETAIN.REPOSITORY},
            "workflow_id": 3,
            "actor": {"id": 4},
            "triggering_actor": {"id": 4},
        }
        job = {
            "name": "image",
            "id": 555,
            "run_id": 10,
            "run_attempt": 1,
            "head_sha": "a" * 40,
            "status": "in_progress",
        }
        responses = [
            run,
            {"id": 3, "path": RETAIN.WORKFLOW},
            {
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(
                    (ROOT / RETAIN.WORKFLOW).read_bytes()
                ).decode(),
            },
            {"total_count": 1, "jobs": [job]},
        ]
        with (
            patch.object(RETAIN, "api_json", side_effect=responses),
            patch.object(RETAIN, "run_bounded", return_value=b"a" * 40 + b"\n"),
        ):
            producer = RETAIN.authenticate_context(
                packet, environment, ROOT, float("inf")
            )
        self.assertEqual(producer["job_id"], 555)
        self.assertEqual(producer["attempt"], 1)
        variants = []
        actor_mismatch = copy.deepcopy(responses)
        actor_mismatch[0]["triggering_actor"]["id"] = 99
        variants.append(actor_mismatch)
        duplicate_job = copy.deepcopy(responses)
        duplicate_job[3] = {"total_count": 2, "jobs": [job, job]}
        variants.append(duplicate_job)
        wrong_attempt = copy.deepcopy(responses)
        wrong_attempt[3]["jobs"][0]["run_attempt"] = 2
        variants.append(wrong_attempt)
        for variant in variants:
            with (
                patch.object(RETAIN, "api_json", side_effect=variant),
                patch.object(RETAIN, "run_bounded", return_value=b"a" * 40 + b"\n"),
                self.assertRaises(RETAIN.RetentionRefused),
            ):
                RETAIN.authenticate_context(packet, environment, ROOT, float("inf"))

    def load(self, packet):
        raw = RETAIN.canonical_json(packet, 16384)
        return RETAIN.load_packet(
            raw, hashlib.sha256(raw).hexdigest(), RETAIN.utc("2026-10-16T12:00:00Z")
        )

    def test_closed_canonical_selection_and_fixed_limits(self):
        packet = synthetic_packet()
        self.assertEqual(self.load(packet), packet)
        for mutate in (
            lambda p: p.update(approved=True),
            lambda p: p["github"].update(actor_id=True),
            lambda p: p["github"].update(repository="unselected/repo"),
            lambda p: p["recipient"].update(encryption_fingerprint="0" * 40),
            lambda p: p["source"].update(ref="refs/pull/1/merge"),
            lambda p: p["source"]["files"].update(extra="c" * 64),
            lambda p: p["limits"].update(rootfs_compressed_bytes=2147483649),
            lambda p: p["limits"].update(rootfs_members=0),
            lambda p: p["artifact"].update(files=["*.pgp"]),
            lambda p: p["validity"].update(expires_at="2026-10-16T01:00:00Z"),
        ):
            with self.subTest(mutation=mutate):
                packet = synthetic_packet()
                mutate(packet)
                with self.assertRaises(RETAIN.RetentionRefused):
                    self.load(packet)

    def test_digest_noncanonical_duplicate_and_design_hash_refuse(self):
        raw = RETAIN.canonical_json(synthetic_packet(), 16384)
        now = RETAIN.utc("2026-10-16T12:00:00Z")
        for candidate, selected in (
            (raw, RETAIN.DESIGN_SHA256),
            (raw + b" ", hashlib.sha256(raw + b" ").hexdigest()),
            (b'{"x":1,"x":2}', hashlib.sha256(b'{"x":1,"x":2}').hexdigest()),
        ):
            with self.assertRaises(RETAIN.RetentionRefused):
                RETAIN.load_packet(candidate, selected, now)

    def test_workflow_guard_refuses_before_network_or_commands(self):
        packet = synthetic_packet()
        valid_environment = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": RETAIN.REPOSITORY,
            "GITHUB_JOB": "image",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/synthetic",
            "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_WORKFLOW_REF": RETAIN.REPOSITORY
            + "/"
            + RETAIN.WORKFLOW
            + "@refs/heads/synthetic",
            "GITHUB_RUN_ID": "10",
            "GITHUB_TOKEN": "synthetic-test-placeholder",
        }
        for key, value in (
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_REPOSITORY", "fork/repository"),
            ("GITHUB_SHA", "e" * 40),
            ("GITHUB_WORKFLOW_SHA", "e" * 40),
            ("GITHUB_REF", "refs/heads/other"),
            ("GITHUB_TOKEN", ""),
        ):
            environment = {**valid_environment, key: value}
            with (
                patch.object(RETAIN, "api_json", side_effect=AssertionError),
                patch.object(RETAIN, "run_bounded", side_effect=AssertionError),
            ):
                with self.subTest(key=key), self.assertRaises(RETAIN.RetentionRefused):
                    RETAIN.authenticate_context(packet, environment, ROOT, float("inf"))


class RetentionPackagingTests(unittest.TestCase):
    def test_compression_reproducible_and_inner_roster_exact(self):
        import gzip

        raw = b"synthetic rootfs tar fixture" * 1000
        first, second = io.BytesIO(), io.BytesIO()
        expected = hashlib.sha256(raw).hexdigest()
        meta = RETAIN.compress_inspected_rootfs(
            io.BytesIO(raw), first, expected, float("inf")
        )
        RETAIN.compress_inspected_rootfs(
            io.BytesIO(raw), second, expected, float("inf")
        )
        self.assertEqual(first.getvalue(), second.getvalue())
        self.assertEqual(gzip.decompress(first.getvalue()), raw)
        payload = io.BytesIO()
        RETAIN.write_inner_archive(
            payload,
            first,
            meta["compressed_bytes"],
            b"files",
            b"build",
            b"shape",
            float("inf"),
        )
        payload.seek(0)
        with tarfile.open(fileobj=payload, mode="r:") as archive:
            self.assertEqual(tuple(archive.getnames()), RETAIN.INNER_NAMES)
            self.assertEqual(
                archive.extractfile("publisher-rootfs.tar.gz").read(), first.getvalue()
            )
            self.assertTrue(
                all(
                    item.mode == 0o600 and item.uid == item.gid == item.mtime == 0
                    for item in archive
                )
            )

    def test_archive_identity_limit_and_original_deadline_refuse(self):
        for expected, deadline in (
            ("0" * 64, float("inf")),
            (hashlib.sha256(b"x").hexdigest(), 0),
        ):
            with self.assertRaises(RETAIN.RetentionRefused):
                RETAIN.compress_inspected_rootfs(
                    io.BytesIO(b"x"), io.BytesIO(), expected, deadline
                )
        with (
            patch.object(RETAIN, "MAX_COMPRESSED_BYTES", 2),
            self.assertRaises(RETAIN.RetentionRefused),
        ):
            RETAIN.compress_inspected_rootfs(
                io.BytesIO(b"x"),
                io.BytesIO(),
                hashlib.sha256(b"x").hexdigest(),
                float("inf"),
            )
        with (
            patch.object(RETAIN.time, "time", return_value=20),
            self.assertRaises(RETAIN.RetentionRefused),
        ):
            RETAIN.check_deadline(RETAIN.ProductionDeadline(float("inf"), 10))


def framed_fixture(key_id=None):
    # Synthetic RSA PKESK framing only, not a valid cryptographic ciphertext.
    if key_id is None:
        key_id = bytes.fromhex(RETAIN.ENCRYPTION_FINGERPRINT[-16:])
    body = b"\x03" + key_id + b"\x01\x00\x08\x80"
    encrypted = b"\x01" + bytes(48)
    return (
        b"\xc1"
        + bytes([len(body)])
        + body
        + b"\xd2"
        + bytes([len(encrypted)])
        + encrypted
    )


class RuntimeFramingTests(unittest.TestCase):
    def test_certificate_packet_roster_refuses_secret_subkeys_and_multiple_primaries(
        self,
    ):
        public = b"\xc6\x01\x04"
        RETAIN.certificate_packet_shape(public)
        for candidate in (
            b"\xc5\x01\x04",
            public + b"\xce\x01\x04",
            public + public,
            public[:-1],
        ):
            with self.assertRaises(RETAIN.RetentionRefused):
                RETAIN.certificate_packet_shape(candidate)

    def test_unselected_tool_record_refuses_before_native_commands(self):
        raw = b'{"synthetic":"unqualified"}'
        with (
            patch.object(RETAIN, "run_bounded", side_effect=AssertionError),
            self.assertRaises(RETAIN.RetentionRefused),
        ):
            RETAIN.qualify_tools(raw, "0" * 64, 0, float("inf"))

    def test_one_recipient_mdc_v1_exact_eof_and_partial_chunks(self):
        raw = framed_fixture()
        RETAIN.verify_ciphertext_framing(
            io.BytesIO(raw), RETAIN.ENCRYPTION_FINGERPRINT, float("inf")
        )
        partial = raw[:-51] + b"\xd2\xe5" + raw[-49:-17] + b"\x11" + raw[-17:]
        RETAIN.verify_ciphertext_framing(
            io.BytesIO(partial), RETAIN.ENCRYPTION_FINGERPRINT, float("inf")
        )

    def test_other_recipient_extra_packets_truncation_aead_and_unprotected_refuse(self):
        raw = framed_fixture()
        for candidate in (
            framed_fixture(bytes(8)),
            raw + raw,
            raw[:-1],
            raw[:-51] + b"\xd4" + raw[-50:],
            raw[:-51] + b"\xc9" + raw[-50:],
            raw[:-49] + b"\x02" + raw[-48:],
        ):
            with (
                self.subTest(size=len(candidate)),
                self.assertRaises(RETAIN.RetentionRefused),
            ):
                RETAIN.verify_ciphertext_framing(
                    io.BytesIO(candidate), RETAIN.ENCRYPTION_FINGERPRINT, float("inf")
                )


if __name__ == "__main__":
    unittest.main()
