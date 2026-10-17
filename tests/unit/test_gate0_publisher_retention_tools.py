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
            patch.object(RETAIN, "api_json", side_effect=responses) as api,
            patch.object(RETAIN, "run_bounded", return_value=b"a" * 40 + b"\n"),
        ):
            producer = RETAIN.authenticate_context(
                packet, environment, ROOT, float("inf")
            )
        self.assertEqual(producer["job_id"], 555)
        self.assertEqual(producer["attempt"], 1)
        self.assertEqual(
            api.call_args.args[0],
            "/repos/"
            + RETAIN.REPOSITORY
            + "/actions/runs/10/attempts/1/jobs?per_page=100",
        )
        corroborated = copy.deepcopy(responses)
        corroborated[3]["jobs"][0]["run_attempt"] = 1
        with (
            patch.object(RETAIN, "api_json", side_effect=corroborated),
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
        for attempt in (2, 0, -1, True, False, 1.0, "1", None):
            wrong_attempt = copy.deepcopy(responses)
            wrong_attempt[3]["jobs"][0]["run_attempt"] = attempt
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


class RoleRetentionPacketTests(unittest.TestCase):
    @staticmethod
    def packet():
        packet = synthetic_packet()
        packet.update(schema=RETAIN.ROLE_SCHEMA, purpose=RETAIN.ROLE_PURPOSE)
        packet["source"].update(
            workflow_path=RETAIN.ROLE_WORKFLOW,
            files=dict.fromkeys(RETAIN.ROLE_SOURCE_FILES, "c" * 64),
        )
        packet["github"]["job_key"] = "role-image"
        packet["build"] = {
            "mode": "build-once-in-selected-job",
            "platform": "linux/amd64",
            "base_image": RETAIN.ROLE_BASE_IMAGE,
            "target": "gate0-role",
        }
        packet["artifact"]["name"] = "gate0-role-qualification-runtime"
        return packet

    def load(self, packet):
        raw = RETAIN.canonical_json(packet, 16384)
        return RETAIN.load_role_packet(
            raw, hashlib.sha256(raw).hexdigest(), RETAIN.utc("2026-10-16T12:00:00Z")
        )

    def test_fixed_role_profile_and_bidirectional_publisher_refusal(self):
        role = self.packet()
        self.assertEqual(self.load(role), role)
        for loader, packet in (
            (RETAIN.load_packet, role),
            (RETAIN.load_role_packet, synthetic_packet()),
        ):
            raw = RETAIN.canonical_json(packet, 16384)
            with self.assertRaises(RETAIN.RetentionRefused):
                loader(
                    raw,
                    hashlib.sha256(raw).hexdigest(),
                    RETAIN.utc("2026-10-16T12:00:00Z"),
                )
        for mutate in (
            lambda p: p.update(purpose="production"),
            lambda p: p.update(approved=True),
            lambda p: p["source"].update(workflow_path=RETAIN.WORKFLOW),
            lambda p: p["source"]["files"].update(extra="e" * 64),
            lambda p: p["github"].update(job_key="image"),
            lambda p: p["github"].update(repository="fork/repo"),
            lambda p: p["github"].update(actor_id=True),
            lambda p: p["build"].update(base_image=RETAIN.BASE_IMAGE),
            lambda p: p["build"].update(target="gate0-publisher"),
            lambda p: p["artifact"].update(name="gate0-publisher-runtime"),
            lambda p: p["artifact"].update(files=["role.tar"]),
            lambda p: p["recipient"].update(encryption_fingerprint="0" * 40),
            lambda p: p["limits"].update(rootfs_members=250001),
            lambda p: p["validity"].update(expires_at="2026-10-15T00:00:00Z"),
        ):
            candidate = self.packet()
            mutate(candidate)
            with (
                self.subTest(mutation=mutate),
                self.assertRaises(RETAIN.RetentionRefused),
            ):
                self.load(candidate)

    def test_role_qualification_scope_swap_refuses_before_live_tool_reads(self):
        raw = RETAIN.canonical_json(
            {
                "schema": "DotmacPublisherRuntimeGpgQualification.v1",
                "method_scope": "publisher-runtime-public-key-encryption.v1",
                "qualified_at": "2026-10-16T00:00:00Z",
                "valid_until": "2026-10-17T00:00:00Z",
                "operating_system": {},
                "tools": {},
                "packages": [],
                "measurements_sha256": "a" * 64,
                "reviewer_record_sha256": "b" * 64,
            },
            65536,
        )
        with (
            patch.object(RETAIN, "run_bounded", side_effect=AssertionError),
            self.assertRaises(RETAIN.RetentionRefused),
        ):
            RETAIN.qualify_role_tools(
                raw,
                hashlib.sha256(raw).hexdigest(),
                RETAIN.utc("2026-10-16T12:00:00Z"),
                float("inf"),
            )

    def test_role_archive_names_and_original_deadline(self):
        payload = io.BytesIO()
        RETAIN.write_role_inner_archive(
            payload,
            io.BytesIO(b"compressed"),
            10,
            b"files",
            b"build",
            b"qualification",
            float("inf"),
        )
        payload.seek(0)
        with tarfile.open(fileobj=payload, mode="r:") as archive:
            self.assertEqual(tuple(archive.getnames()), RETAIN.ROLE_INNER_NAMES)
            self.assertNotEqual(tuple(archive.getnames()), RETAIN.INNER_NAMES)
            self.assertEqual(
                archive.extractfile("qualification.json").read(), b"qualification"
            )
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.write_role_inner_archive(
                io.BytesIO(), io.BytesIO(b"x"), 1, b"{}", b"{}", b"{}", 0
            )

    def test_role_authenticated_context_and_early_refusals(self):
        import base64
        import copy

        packet = self.packet()
        packet["source"]["workflow_blob_sha256"] = hashlib.sha256(
            (ROOT / RETAIN.ROLE_WORKFLOW).read_bytes()
        ).hexdigest()
        packet["source"]["files"] = {
            key: hashlib.sha256((ROOT / value).read_bytes()).hexdigest()
            for key, value in RETAIN.ROLE_SOURCE_FILES.items()
        }
        environment = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": RETAIN.REPOSITORY,
            "GITHUB_JOB": "role-image",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/synthetic",
            "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_WORKFLOW_REF": RETAIN.REPOSITORY
            + "/"
            + RETAIN.ROLE_WORKFLOW
            + "@refs/heads/synthetic",
            "GITHUB_RUN_ID": "10",
            "GITHUB_TOKEN": "synthetic-test-placeholder",
        }
        responses = [
            {
                "id": 10,
                "run_attempt": 1,
                "event": "workflow_dispatch",
                "head_sha": "a" * 40,
                "head_branch": "synthetic",
                "repository": {
                    "full_name": RETAIN.REPOSITORY,
                    "id": 1,
                    "owner": {"id": 2},
                },
                "head_repository": {"full_name": RETAIN.REPOSITORY},
                "workflow_id": 3,
                "actor": {"id": 4},
                "triggering_actor": {"id": 4},
            },
            {"id": 3, "path": RETAIN.ROLE_WORKFLOW},
            {
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(
                    (ROOT / RETAIN.ROLE_WORKFLOW).read_bytes()
                ).decode(),
            },
            {
                "total_count": 1,
                "jobs": [
                    {
                        "id": 555,
                        "name": "role-image",
                        "run_id": 10,
                        "run_attempt": 1,
                        "head_sha": "a" * 40,
                        "status": "in_progress",
                    }
                ],
            },
        ]
        with (
            patch.object(RETAIN, "api_json", side_effect=responses),
            patch.object(RETAIN, "run_bounded", return_value=b"a" * 40 + b"\n"),
        ):
            self.assertEqual(
                RETAIN.authenticate_role_context(
                    packet, environment, ROOT, float("inf")
                )["job_id"],
                555,
            )
        for key, value in (
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_JOB", "image"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_REPOSITORY", "fork/repo"),
            ("GITHUB_REF", "refs/heads/other"),
            ("GITHUB_SHA", "b" * 40),
            ("GITHUB_WORKFLOW_SHA", "b" * 40),
            ("GITHUB_TOKEN", ""),
        ):
            with (
                patch.object(RETAIN, "api_json", side_effect=AssertionError),
                patch.object(RETAIN, "run_bounded", side_effect=AssertionError),
                self.subTest(key=key),
                self.assertRaises(RETAIN.RetentionRefused),
            ):
                RETAIN.authenticate_role_context(
                    packet, {**environment, key: value}, ROOT, float("inf")
                )
        for index, key, value in (
            (0, "triggering_actor", {"id": 99}),
            (1, "path", RETAIN.WORKFLOW),
            (2, "content", base64.b64encode(b"wrong blob").decode()),
        ):
            changed = copy.deepcopy(responses)
            changed[index][key] = value
            with (
                patch.object(RETAIN, "api_json", side_effect=changed),
                patch.object(RETAIN, "run_bounded", return_value=b"a" * 40 + b"\n"),
                self.assertRaises(RETAIN.RetentionRefused),
            ):
                RETAIN.authenticate_role_context(
                    packet, environment, ROOT, float("inf")
                )


class RoleRetentionOrchestrationTests(unittest.TestCase):
    """Real synthetic tar/JSON/descriptor/compression/receipt paths, hosted only.

    Mock only authenticated provider/tool qualification, Docker observations and
    encryption. Actual GPG bytes have their separate hosted conformance owner.
    """

    @staticmethod
    def artifact_fixtures():
        spec = importlib.util.spec_from_file_location(
            "role_orchestration_public_fixtures",
            ROOT / "tests/unit/test_gate0_publisher_artifact_tools.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def setUp(self):
        import base64
        import datetime
        import time
        from contextlib import ExitStack

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.private = self.temporary / "gate0-role.ABCDEFGH"
        self.private.mkdir(mode=0o700)
        fixtures = self.artifact_fixtures()
        source, files = fixtures.synthetic_role_subject()
        with fixtures.subject_archive(files) as archive:
            self.rootfs_bytes = archive.fileobj.getvalue()
        self.write("role.tar", self.rootfs_bytes)
        self.packet = RoleRetentionPacketTests.packet()
        self.packet["source"]["files"].update(source["files"])
        now = datetime.datetime.now(datetime.UTC)
        self.packet["validity"] = {
            "not_before": (now - datetime.timedelta(seconds=60)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "expires_at": (now + datetime.timedelta(seconds=3600)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        self.certificate = b"\xc6\x01\x04"  # Public structural test packet only.
        certificate_digest = hashlib.sha256(self.certificate).hexdigest()
        self.stack.enter_context(
            patch.object(RETAIN, "CERTIFICATE_SHA256", certificate_digest)
        )
        self.packet["recipient"]["certificate_sha256"] = certificate_digest
        self.tool_raw = b"synthetic live qualification seam"
        self.packet["tool_qualification_sha256"] = hashlib.sha256(
            self.tool_raw
        ).hexdigest()
        packet_raw = RETAIN.canonical_json(self.packet, 16384)
        self.stack.enter_context(
            patch.dict(
                os.environ,
                {
                    "RUNNER_TEMP": str(self.temporary),
                    "RETENTION_PACKET_CONFIGURATION": packet_raw.decode(),
                    "RETENTION_PACKET_SHA256": hashlib.sha256(packet_raw).hexdigest(),
                    "RETENTION_GPG_QUALIFICATION_CONFIGURATION": self.tool_raw.decode(),
                    "RETENTION_CERTIFICATE_CONFIGURATION": base64.b64encode(
                        self.certificate
                    ).decode(),
                },
            )
        )
        self.write(
            "packaging-clock.json",
            json.dumps({"monotonic": time.monotonic(), "wall": time.time()}).encode(),
        )
        self.producer = {
            "repository_id": 1,
            "owner_id": 2,
            "workflow_id": 3,
            "actor_id": 4,
            "run_id": 10,
            "attempt": 1,
            "job_id": 555,
        }
        self.authentication = self.stack.enter_context(
            patch.object(
                RETAIN, "authenticate_role_context", return_value=self.producer
            )
        )
        self.tools = self.stack.enter_context(
            patch.object(
                RETAIN,
                "qualify_role_tools",
                return_value={"valid_until": self.packet["validity"]["expires_at"]},
            )
        )
        self.base_layer, self.role_layer = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        self.config = {
            "created": "2026-10-17T00:00:00Z",
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Labels": {
                    "org.opencontainers.image.revision": "a" * 40,
                    "io.dotmac.runtime": "gate0-finite-role",
                },
                "User": "0:0",
                "Entrypoint": ["/opt/venv/bin/dotmac-platform", "gate0", "supervise"],
                "Env": ["VIRTUAL_ENV=/opt/venv"],
                "WorkingDir": "/app",
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": [self.base_layer, self.role_layer],
            },
            "history": [
                {"created_by": "synthetic base"},
                {"created_by": "synthetic fixed role"},
            ],
        }
        self.config_raw = RETAIN.canonical_json(self.config, 1024**2)
        self.image_id = "sha256:" + hashlib.sha256(self.config_raw).hexdigest()
        self.image = {
            "Id": self.image_id,
            "Architecture": "amd64",
            "Os": "linux",
            "RootFS": {"Type": "layers", "Layers": [self.base_layer, self.role_layer]},
            "Config": self.config["config"],
        }
        self.base = {
            "Id": "sha256:" + "d" * 64,
            "Architecture": "amd64",
            "Os": "linux",
            "RootFS": {"Type": "layers", "Layers": [self.base_layer]},
            "RepoDigests": ["ubuntu@" + RETAIN.ROLE_BASE_IMAGE.split("@", 1)[1]],
        }
        self.container_id = "c" * 64
        self.container = {
            "Id": self.container_id,
            "Image": self.image_id,
            "State": {"Status": "created", "Running": False},
            "Mounts": [],
        }
        self.write("role-image-id", (self.image_id + "\n").encode())
        self.write("export-container-id", (self.container_id + "\n").encode())
        self.write("role-image.json", json.dumps([self.image]).encode())
        self.save_image(self.config_raw)
        self.smoke = {
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
        self.network = {
            "schema": "Gate0NativeNetworkPrivilegeProof.v1",
            "passed": True,
            "wrong_principal_refused_under_k": True,
            "refused_authentication_boundary_empty": True,
            "full_wireguard_installation_qualified": False,
            "live_readiness": False,
        }
        self.write("smoke.json", json.dumps(self.smoke).encode())
        self.write("network.json", json.dumps(self.network).encode())
        self.docker = self.stack.enter_context(
            patch.object(RETAIN, "run_bounded", side_effect=self.docker_observation)
        )
        self.cipher_bytes = b"synthetic encrypted bytes, not real OpenPGP"
        self.payload_bytes = None
        self.encryption = self.stack.enter_context(
            patch.object(RETAIN, "checked_encrypt", side_effect=self.encrypt)
        )

    def write(self, name, raw):
        path = self.private / name
        path.write_bytes(raw)
        path.chmod(0o600)

    def save_image(self, config_raw):
        config_name = self.image_id[7:] + ".json"
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for name, value in (
                (config_name, config_raw),
                (
                    "manifest.json",
                    json.dumps(
                        [
                            {
                                "Config": config_name,
                                "RepoTags": ["gate0-role-qualified-local:latest"],
                                "Layers": ["base/layer.tar", "role/layer.tar"],
                            }
                        ]
                    ).encode(),
                ),
            ):
                item = tarfile.TarInfo(name)
                item.mode, item.size = 0o600, len(value)
                archive.addfile(item, io.BytesIO(value))
        self.write("role-image-save.tar", raw.getvalue())

    def docker_observation(self, arguments, deadline):
        RETAIN.check_deadline(deadline)
        if arguments == ["/usr/bin/docker", "container", "inspect", self.container_id]:
            value = self.container
        elif arguments == ["/usr/bin/docker", "image", "inspect", self.image_id]:
            value = self.image
        elif arguments == [
            "/usr/bin/docker",
            "image",
            "inspect",
            RETAIN.ROLE_BASE_IMAGE,
        ]:
            value = self.base
        else:
            self.fail("unexpected Docker command")
        return json.dumps([value]).encode()

    def encrypt(
        self, certificate, primary, encryption, home, payload, cipher, deadline
    ):
        self.assertEqual(certificate, self.certificate)
        self.assertEqual(primary, RETAIN.PRIMARY_FINGERPRINT)
        self.assertEqual(encryption, RETAIN.ENCRYPTION_FINGERPRINT)
        RETAIN.check_deadline(deadline)
        payload.seek(0)
        self.payload_bytes = payload.read()
        cipher.write(self.cipher_bytes)
        cipher.flush()

    def assert_no_completed_pair(self):
        for name in ("encrypted-runtime-bundle.pgp", "producer-receipt.json"):
            self.assertFalse((self.private / name).exists(), name)

    def inspect_then_package(self):
        RETAIN.role_inspection(self.private)
        RETAIN.role_main(str(self.private))

    def test_real_context_preflight_inspection_packaging_and_receipt_binding(self):
        import gzip

        RETAIN.role_main(str(self.private), preflight=True)
        deadline = json.loads((self.private / "packaging-deadline.json").read_bytes())
        clock = json.loads((self.private / "packaging-clock.json").read_bytes())
        self.assertEqual(deadline["monotonic"], clock["monotonic"] + 1180)
        self.inspect_then_package()
        self.assertGreaterEqual(self.authentication.call_count, 3)
        self.assertGreaterEqual(self.tools.call_count, 3)
        self.assertEqual(
            (self.private / "encrypted-runtime-bundle.pgp").read_bytes(),
            self.cipher_bytes,
        )
        receipt = json.loads((self.private / "producer-receipt.json").read_bytes())
        self.assertEqual(receipt["schema"], "Gate0RoleQualificationProducerReceipt.v1")
        self.assertEqual(
            receipt["encrypted_bundle_sha256"],
            hashlib.sha256(self.cipher_bytes).hexdigest(),
        )
        self.assertEqual(receipt["encrypted_bundle_bytes"], len(self.cipher_bytes))
        build_raw = (self.private / "build.json").read_bytes()
        self.assertEqual(
            receipt["private_manifest_sha256"], hashlib.sha256(build_raw).hexdigest()
        )
        build = json.loads(build_raw)
        self.assertEqual(build["images"]["role"]["image_id"], self.image_id)
        self.assertEqual(build["images"]["role"]["config_sha256"], self.image_id[7:])
        self.assertEqual(build["images"]["base"]["image_id"], self.base["Id"])
        self.assertEqual(build["images"]["base"]["rootfs_diff_ids"], [self.base_layer])
        with tarfile.open(fileobj=io.BytesIO(self.payload_bytes), mode="r:") as archive:
            self.assertEqual(tuple(archive.getnames()), RETAIN.ROLE_INNER_NAMES)
            self.assertEqual(
                gzip.decompress(archive.extractfile("role-rootfs.tar.gz").read()),
                self.rootfs_bytes,
            )
            self.assertEqual(archive.extractfile("build.json").read(), build_raw)
            self.assertEqual(
                archive.extractfile("files.json").read(),
                (self.private / "files.json").read_bytes(),
            )
            qualification = json.loads(archive.extractfile("qualification.json").read())
            self.assertEqual(qualification["image_id"], self.image_id)
            self.assertEqual(qualification["smoke"], self.smoke)
            self.assertEqual(qualification["network"], self.network)
            self.assertIs(qualification["gate0_accepted"], False)

    def test_wrong_container_image_base_layer_and_config_refuse(self):
        import copy

        original_container, original_base, original_image = (
            copy.deepcopy(self.container),
            copy.deepcopy(self.base),
            copy.deepcopy(self.image),
        )
        mutations = (
            lambda: self.container.update(Image="sha256:" + "e" * 64),
            lambda: self.container["State"].update(Status="running", Running=True),
            lambda: self.container.update(Mounts=[{"Destination": "/app"}]),
            lambda: self.image.update(Id="sha256:" + "e" * 64),
            lambda: self.base.update(
                RepoDigests=["wrong@" + RETAIN.ROLE_BASE_IMAGE.split("@", 1)[1]]
            ),
            lambda: self.base.update(RepoDigests=["ubuntu@sha256:" + "f" * 64]),
            lambda: self.base["RootFS"].update(Layers=["sha256:" + "e" * 64]),
            lambda: self.base.update(Id="sha256:invalid"),
            lambda: self.image["RootFS"].update(
                Layers=[self.base_layer, "sha256:" + "e" * 64]
            ),
            lambda: self.image["Config"].update(User="10031:10031"),
        )
        for mutate in mutations:
            self.container, self.base, self.image = (
                copy.deepcopy(original_container),
                copy.deepcopy(original_base),
                copy.deepcopy(original_image),
            )
            mutate()
            with (
                self.subTest(mutation=mutate),
                self.assertRaises(RETAIN.RetentionRefused),
            ):
                RETAIN.role_image_subject(
                    self.private, self.packet, INSPECT, float("inf")
                )
            self.assert_no_completed_pair()
        self.container, self.base, self.image = (
            original_container,
            original_base,
            original_image,
        )
        self.save_image(self.config_raw + b" ")
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_image_subject(self.private, self.packet, INSPECT, float("inf"))
        self.assert_no_completed_pair()

    def test_saved_config_layer_join_refuses_consistent_inspection_swap(self):
        # Both stored/current Docker inspection agree on a changed role layer.
        # Only the actual config-bytes/ordered-diffID join can reject this plant.
        self.image["RootFS"]["Layers"] = [self.base_layer, "sha256:" + "e" * 64]
        self.write("role-image.json", json.dumps([self.image]).encode())
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_image_subject(self.private, self.packet, INSPECT, float("inf"))
        self.assert_no_completed_pair()

    def test_postinspection_export_byte_change_refuses_before_encryption(self):
        RETAIN.role_inspection(self.private)
        # A valid same-shaped tar with changed ordinary non-subject bytes defeats
        # subject-only comparisons; the complete roster/rootfs join must refuse.
        fixtures = self.artifact_fixtures()
        _, changed = fixtures.synthetic_role_subject()
        changed["etc/unselected-data"] = b"changed after actual inspection"
        with fixtures.subject_archive(changed) as archive:
            self.write("role.tar", archive.fileobj.getvalue())
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_main(str(self.private))
        self.encryption.assert_not_called()
        self.assert_no_completed_pair()

    def test_held_export_mutation_at_compression_boundary_refuses(self):
        RETAIN.role_inspection(self.private)
        original_open = os.open
        mutated = []

        def corrupt_held_export(path, flags, mode=0o777, **kwargs):
            if Path(path).name == "role-rootfs.tar.gz":
                # role_main has already inspected and hashed this held descriptor.
                # Change one byte in place: real compression must detect the hash
                # mismatch even though no path substitution or re-export occurs.
                with (self.private / "role.tar").open("r+b") as stream:
                    stream.seek(512)
                    original = stream.read(1)
                    stream.seek(512)
                    stream.write(bytes([original[0] ^ 1]))
                mutated.append(True)
            return original_open(path, flags, mode, **kwargs)

        with (
            patch.object(os, "open", side_effect=corrupt_held_export),
            self.assertRaises(RETAIN.RetentionRefused),
        ):
            RETAIN.role_main(str(self.private))
        self.assertEqual(mutated, [True])
        self.encryption.assert_not_called()
        self.assert_no_completed_pair()

    def test_context_failure_preserves_preexisting_noncompletion_files(self):
        self.write("unowned-existing-data", b"preserve this independent input")
        self.authentication.side_effect = RETAIN.RetentionRefused(
            "synthetic context refusal"
        )
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_main(str(self.private))
        self.assertEqual(
            (self.private / "unowned-existing-data").read_bytes(),
            b"preserve this independent input",
        )
        self.assert_no_completed_pair()

    def test_original_clock_expiry_refuses_without_reset_or_live_reads(self):
        import time

        RETAIN.role_inspection(self.private)
        self.write(
            "packaging-clock.json",
            json.dumps(
                {"monotonic": time.monotonic() - 1181, "wall": time.time() - 1181}
            ).encode(),
        )
        self.authentication.reset_mock()
        self.tools.reset_mock()
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_main(str(self.private))
        self.authentication.assert_not_called()
        self.tools.assert_not_called()
        self.encryption.assert_not_called()
        self.assert_no_completed_pair()

    def test_encryption_failure_leaves_neither_completion_name(self):
        RETAIN.role_inspection(self.private)
        self.encryption.side_effect = RETAIN.RetentionRefused(
            "synthetic encryption failure"
        )
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_main(str(self.private))
        self.assert_no_completed_pair()

    def test_failure_between_completion_links_removes_first_completion(self):
        RETAIN.role_inspection(self.private)
        original_link = os.link
        completed = []

        def fail_second(source, destination):
            if Path(destination).name == "producer-receipt.json":
                self.assertTrue(
                    (self.private / "encrypted-runtime-bundle.pgp").is_file()
                )
                raise OSError("synthetic filesystem completion failure")
            original_link(source, destination)
            completed.append(Path(destination).name)

        # Fault injection at the filesystem boundary, not a mocked cleanup owner.
        with (
            patch.object(os, "link", side_effect=fail_second),
            self.assertRaises(OSError),
        ):
            RETAIN.role_main(str(self.private))
        self.assertEqual(completed, ["encrypted-runtime-bundle.pgp"])
        self.assert_no_completed_pair()

    def test_cleanup_preserves_replacement_completion_inode(self):
        RETAIN.role_inspection(self.private)
        original_link = os.link

        def replace_first_then_fail(source, destination):
            if Path(destination).name == "producer-receipt.json":
                first = self.private / "encrypted-runtime-bundle.pgp"
                first.rename(self.private / "moved-owned-inode")
                self.write(
                    "encrypted-runtime-bundle.pgp", b"independent replacement inode"
                )
                raise OSError("synthetic replacement plus completion failure")
            return original_link(source, destination)

        with (
            patch.object(os, "link", side_effect=replace_first_then_fail),
            self.assertRaises(OSError),
        ):
            RETAIN.role_main(str(self.private))
        self.assertEqual(
            (self.private / "encrypted-runtime-bundle.pgp").read_bytes(),
            b"independent replacement inode",
        )
        self.assertFalse((self.private / "producer-receipt.json").exists())

    def test_packet_expiry_after_inspection_refuses_before_live_context(self):
        import copy

        RETAIN.role_inspection(self.private)
        expired = copy.deepcopy(self.packet)
        expired["validity"] = {
            "not_before": "2020-01-01T00:00:00Z",
            "expires_at": "2020-01-02T00:00:00Z",
        }
        raw = RETAIN.canonical_json(expired, 16384)
        self.authentication.reset_mock()
        with (
            patch.dict(
                os.environ,
                {
                    "RETENTION_PACKET_CONFIGURATION": raw.decode(),
                    "RETENTION_PACKET_SHA256": hashlib.sha256(raw).hexdigest(),
                },
            ),
            self.assertRaises(RETAIN.RetentionRefused),
        ):
            RETAIN.role_main(str(self.private))
        self.authentication.assert_not_called()
        self.encryption.assert_not_called()
        self.assert_no_completed_pair()

    def test_preexisting_partial_pair_is_preserved_on_refusal(self):
        self.write(
            "encrypted-runtime-bundle.pgp", b"ineligible partial from failed work"
        )
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_main(str(self.private))
        self.assertEqual(
            (self.private / "encrypted-runtime-bundle.pgp").read_bytes(),
            b"ineligible partial from failed work",
        )
        self.assertFalse((self.private / "producer-receipt.json").exists())
        self.authentication.assert_not_called()

    def test_precise_role_base_normalization_does_not_change_publisher_policy(self):
        result = RETAIN.role_base_identity(json.dumps([self.base]).encode())
        self.assertEqual(result["reference"], RETAIN.ROLE_BASE_IMAGE)
        self.assertEqual(result["image_id"], self.base["Id"])
        tagged = {**self.base, "RepoDigests": [RETAIN.ROLE_BASE_IMAGE]}
        self.assertEqual(
            RETAIN.role_base_identity(json.dumps([tagged]).encode()), result
        )
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.image_identity(
                json.dumps([self.base]).encode(), RETAIN.ROLE_BASE_IMAGE, None, None
            )
        for reference in (
            "notubuntu@" + RETAIN.ROLE_BASE_IMAGE.split("@", 1)[1],
            "ubuntu@sha256:" + "e" * 64,
            "ubuntu:other@" + RETAIN.ROLE_BASE_IMAGE.split("@", 1)[1],
        ):
            with (
                self.subTest(reference=reference),
                self.assertRaises(RETAIN.RetentionRefused),
            ):
                RETAIN.role_base_identity(
                    json.dumps([{**self.base, "RepoDigests": [reference]}]).encode()
                )


class RoleExportCleanupOwnershipTests(unittest.TestCase):
    """Actual owned record/FD/provider guards; no cleanup owner is mocked."""

    def setUp(self):
        import time
        from contextlib import ExitStack

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.private = self.temporary / "gate0-role.OWNED123"
        self.private.mkdir(mode=0o700)
        self.stack.enter_context(
            patch.dict(os.environ, {"RUNNER_TEMP": str(self.temporary)})
        )
        self.image_id, self.cid = "sha256:" + "a" * 64, "b" * 64
        path = self.private / "role-image-id"
        path.write_text(self.image_id + "\n")
        path.chmod(0o600)
        self.image = {
            "Id": self.image_id,
            "Config": {"Labels": {"io.dotmac.runtime": "gate0-finite-role"}},
        }
        image_path = self.private / "role-image.json"
        image_path.write_text(json.dumps([self.image]))
        image_path.chmod(0o600)
        self.name = "gate0-role-export-OWNED123"
        self.subject = {
            "Id": self.cid,
            "Name": "/" + self.name,
            "Image": self.image_id,
            "State": {"Status": "created", "Running": False},
            "Mounts": [],
        }
        self.created = False
        self.removals = []
        self.commands = []
        self.deadline = RETAIN.ProductionDeadline(
            time.monotonic() + 280, time.time() + 280
        )
        self.stack.enter_context(
            patch.object(RETAIN, "run_bounded", side_effect=self.provider)
        )

    def provider(self, arguments, deadline, **kwargs):
        RETAIN.check_deadline(deadline)
        self.commands.append(arguments)
        if arguments == ["/usr/bin/docker", "image", "inspect", self.image_id]:
            return json.dumps([self.image]).encode()
        if arguments[:4] == ["/usr/bin/docker", "container", "ls", "-aq"]:
            return (self.cid + "\n").encode() if self.created else b""
        if arguments[:2] == ["/usr/bin/docker", "create"]:
            self.assertIn(self.name, arguments)
            self.assertEqual(arguments[-1], self.image_id)
            path = self.private / "export-container-id"
            path.write_text(self.cid + "\n")
            path.chmod(0o600)
            self.created = True
            return (self.cid + "\n").encode()
        if arguments == ["/usr/bin/docker", "container", "inspect", self.cid]:
            return json.dumps([self.subject]).encode()
        if arguments == ["/usr/bin/docker", "container", "rm", "-f", self.cid]:
            self.removals.append(self.cid)
            self.created = False
            return (self.cid + "\n").encode()
        self.fail("unexpected provider command")

    def create(self):
        self.assertEqual(
            RETAIN.role_export_create(self.private, self.image_id, self.deadline),
            self.cid,
        )
        self.assertTrue((self.private / "export-created-owner.json").is_file())

    def assert_refusal_preserves_evidence(self):
        with self.assertRaises(RETAIN.RetentionRefused):
            RETAIN.role_export_cleanup(self.private)
        self.assertEqual(self.removals, [])
        self.assertTrue((self.private / "export-container-id").is_file())
        self.assertTrue((self.private / "export-created-owner.json").is_file())
        self.assertFalse((self.private / "export-cleanup-confirmed.json").exists())
        self.assertTrue(self.private.is_dir())

    def test_actual_creation_and_reverified_cleanup_success(self):
        self.create()
        RETAIN.role_export_cleanup(self.private)
        self.assertEqual(self.removals, [self.cid])
        self.assertTrue((self.private / "export-cleanup-confirmed.json").is_file())
        rm_index = self.commands.index(
            ["/usr/bin/docker", "container", "rm", "-f", self.cid]
        )
        self.assertEqual(
            self.commands[rm_index - 1],
            ["/usr/bin/docker", "container", "inspect", self.cid],
        )

    def test_changed_held_cid_refuses_unrelated_deletion(self):
        self.create()
        (self.private / "export-container-id").write_text("c" * 64 + "\n")
        self.assert_refusal_preserves_evidence()

    def test_wrong_actual_id_name_or_image_preserves_evidence(self):
        self.create()
        original = dict(self.subject)
        for key, value in (
            ("Id", "c" * 64),
            ("Name", "/unrelated-container"),
            ("Image", "sha256:" + "c" * 64),
        ):
            self.subject = {**original, key: value}
            with self.subTest(key=key):
                self.assert_refusal_preserves_evidence()

    def test_replaced_cid_inode_refuses_even_with_same_text(self):
        self.create()
        path = self.private / "export-container-id"
        path.rename(self.private / "original-held-cid")
        path.write_text(self.cid + "\n")
        path.chmod(0o600)
        self.assert_refusal_preserves_evidence()

    def test_missing_created_owner_after_ambiguous_create_preserves_cid(self):
        self.create()
        (self.private / "export-created-owner.json").unlink()
        with self.assertRaises(FileNotFoundError):
            RETAIN.role_export_cleanup(self.private)
        self.assertEqual(self.removals, [])
        self.assertTrue((self.private / "export-container-id").is_file())
        self.assertTrue(self.private.is_dir())


if __name__ == "__main__":
    unittest.main()
