"""Hosted-only actual synthetic runtime encryption; never production B custody."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import os
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "runtime_retention_synthetic", ROOT / ".github/candidate/retain_gate0_publisher.py"
)
assert SPEC is not None and SPEC.loader is not None
RETAIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETAIN)


class ActualSyntheticRuntimeGpgTests(unittest.TestCase):
    def test_actual_roundtrip_exact_roster_and_structural_refusals(self):
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true")
        self.assertNotEqual(os.getuid(), 0)
        for name in ("gpg", "gpgconf"):
            prefix = "GATE0_TEST_QUALIFIED_" + name.upper()
            self.assertEqual(os.environ[prefix], "/usr/bin/" + name)
            actual = hashlib.sha256(Path(os.environ[prefix]).read_bytes()).hexdigest()
            self.assertEqual(actual, os.environ[prefix + "_SHA256"])
        deadline = time.monotonic() + 180
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret_home, encrypt_home = root / "synthetic-secret", root / "public-only"
            secret_home.mkdir(mode=0o700)
            encrypt_home.mkdir(mode=0o700)
            common = [
                "/usr/bin/gpg",
                "--no-options",
                "--homedir",
                str(secret_home),
                "--batch",
                "--no-tty",
            ]
            try:
                RETAIN.run_bounded(
                    [
                        *common,
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                        "--default-preference-list",
                        "S9 S8 S7 S2 H10 H9 H8 H11 H2 Z2 Z3 Z1",
                        "--quick-generate-key",
                        "Runtime synthetic test <runtime.invalid@example.invalid>",
                        "rsa2048",
                        "encr",
                        "1d",
                    ],
                    deadline,
                )
                records = (
                    RETAIN.run_bounded(
                        [*common, "--with-colons", "--with-fingerprint", "--list-keys"],
                        deadline,
                    )
                    .decode("ascii")
                    .splitlines()
                )
                fingerprints = [
                    line.split(":")[9] for line in records if line.startswith("fpr:")
                ]
                self.assertEqual(len(fingerprints), 1)
                fingerprint = fingerprints[0]
                self.assertNotEqual(fingerprint, RETAIN.PRIMARY_FINGERPRINT)
                certificate = RETAIN.run_bounded(
                    [*common, "--export", fingerprint], deadline, maximum=65536
                )
                RETAIN.certificate_packet_shape(certificate)
                raw = b"Synthetic runtime byte fixture\n" * 10000
                with (
                    (root / "rootfs.tar.gz").open("w+b") as compressed,
                    (root / "payload.tar").open("w+b") as payload,
                    (root / "cipher.pgp").open("w+b") as cipher,
                ):
                    metadata = RETAIN.compress_inspected_rootfs(
                        io.BytesIO(raw),
                        compressed,
                        hashlib.sha256(raw).hexdigest(),
                        deadline,
                    )
                    RETAIN.write_inner_archive(
                        payload,
                        compressed,
                        metadata["compressed_bytes"],
                        b'{"synthetic":"files"}\n',
                        b'{"synthetic":"build"}\n',
                        b'{"synthetic":"shape"}\n',
                        deadline,
                    )
                    RETAIN.checked_encrypt(
                        certificate,
                        fingerprint,
                        fingerprint,
                        encrypt_home,
                        payload,
                        cipher,
                        deadline,
                    )
                    cipher.seek(0)
                    decrypted = RETAIN.run_bounded(
                        [
                            *common,
                            "--pinentry-mode",
                            "loopback",
                            "--passphrase",
                            "",
                            "--decrypt",
                        ],
                        deadline,
                        stdin=cipher,
                        maximum=2 * 1024**2,
                    )
                    payload.seek(0)
                    self.assertEqual(decrypted, payload.read())
                    with tarfile.open(
                        fileobj=io.BytesIO(decrypted), mode="r:"
                    ) as archive:
                        self.assertEqual(tuple(archive.getnames()), RETAIN.INNER_NAMES)
                        self.assertEqual(
                            gzip.decompress(
                                archive.extractfile(RETAIN.INNER_NAMES[0]).read()
                            ),
                            raw,
                        )
                    cipher.seek(0)
                    encrypted_bytes = cipher.read()
                # The same qualified primitives preserve the finite role roster;
                # this recipient is ephemeral synthetic test material only.
                role_home = root / "role-public-only"
                role_home.mkdir(mode=0o700)
                with (
                    (root / "role-payload.tar").open("w+b") as role_payload,
                    (root / "role.pgp").open("w+b") as role_cipher,
                ):
                    role_compressed = io.BytesIO(gzip.compress(raw, mtime=0))
                    RETAIN.write_role_inner_archive(
                        role_payload,
                        role_compressed,
                        len(role_compressed.getvalue()),
                        b'{"synthetic":"role-files"}\n',
                        b'{"synthetic":"role-build"}\n',
                        b'{"synthetic":"qualification"}\n',
                        deadline,
                    )
                    RETAIN.checked_encrypt(
                        certificate,
                        fingerprint,
                        fingerprint,
                        role_home,
                        role_payload,
                        role_cipher,
                        deadline,
                    )
                    role_cipher.seek(0)
                    role_decrypted = RETAIN.run_bounded(
                        [
                            *common,
                            "--pinentry-mode",
                            "loopback",
                            "--passphrase",
                            "",
                            "--decrypt",
                        ],
                        deadline,
                        stdin=role_cipher,
                        maximum=2 * 1024**2,
                    )
                    role_payload.seek(0)
                    self.assertEqual(role_decrypted, role_payload.read())
                    with tarfile.open(
                        fileobj=io.BytesIO(role_decrypted), mode="r:"
                    ) as role_archive:
                        self.assertEqual(
                            tuple(role_archive.getnames()), RETAIN.ROLE_INNER_NAMES
                        )
                        self.assertEqual(
                            gzip.decompress(
                                role_archive.extractfile("role-rootfs.tar.gz").read()
                            ),
                            raw,
                        )
                    role_cipher.seek(0)
                    role_bytes = role_cipher.read()
                    for invalid in (role_bytes[:-1], role_bytes + role_bytes):
                        with self.assertRaises(RETAIN.RetentionRefused):
                            RETAIN.verify_ciphertext_framing(
                                io.BytesIO(invalid), fingerprint, deadline
                            )
                    with self.assertRaises(RETAIN.RetentionRefused):
                        RETAIN.verify_ciphertext_framing(
                            io.BytesIO(role_bytes), "0" * 40, deadline
                        )
                for malformed in (
                    encrypted_bytes[:-1],
                    encrypted_bytes + encrypted_bytes,
                ):
                    with self.assertRaises(RETAIN.RetentionRefused):
                        RETAIN.verify_ciphertext_framing(
                            io.BytesIO(malformed), fingerprint, deadline
                        )
                with self.assertRaises(RETAIN.RetentionRefused):
                    RETAIN.verify_ciphertext_framing(
                        io.BytesIO(encrypted_bytes), "0" * 40, deadline
                    )
                secret = RETAIN.run_bounded(
                    [
                        *common,
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                        "--export-secret-keys",
                        fingerprint,
                    ],
                    deadline,
                    maximum=65536,
                )
                with self.assertRaises(RETAIN.RetentionRefused):
                    RETAIN.certificate_packet_shape(secret)
                # Hostile ambient GPG configuration never reaches the subprocess.
                with patch.dict(
                    os.environ,
                    {
                        "GNUPGHOME": str(secret_home),
                        "GPG_AGENT_INFO": "hostile",
                        "LD_PRELOAD": "/invalid/synthetic",
                    },
                ):
                    with (
                        (root / "second.pgp").open("w+b") as cipher,
                        (root / "payload.tar").open("rb") as payload,
                    ):
                        second_home = root / "second-public-only"
                        second_home.mkdir(mode=0o700)
                        RETAIN.checked_encrypt(
                            certificate,
                            fingerprint,
                            fingerprint,
                            second_home,
                            payload,
                            cipher,
                            deadline,
                        )
            finally:
                RETAIN.run_bounded(
                    [
                        "/usr/bin/gpgconf",
                        "--homedir",
                        str(secret_home),
                        "--kill",
                        "gpg-agent",
                    ],
                    time.monotonic() + 10,
                    maximum=16384,
                )


if __name__ == "__main__":
    unittest.main()
