"""Explicit hosted GPG mechanism lane; required tool pins, no skips or E acceptance."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

from vendor_cp.deployment import gate0_e_archive as archive_owner
from vendor_cp.deployment.gate0_e_archive import (
    ARCHIVE_NAMES,
    GnuPgToolPins,
    GpgArchiveProfile,
    _pack,
    _run,
    package_private_collection,
    qualify_gnupg_tools,
)


def _packet_structure(raw: bytes) -> dict[str, object]:
    """Bounded framing diagnostics only; never retain packet-body bytes."""
    position = 0
    packets = []
    summary: dict[str, object] = {"size": len(raw), "packets": packets}
    while position < len(raw) and len(packets) < 8:
        start = position
        header = raw[position]
        position += 1
        new_format = bool(header & 64)
        tag = header & 63 if new_format else (header >> 2) & 15
        chunks = []
        packets.append(
            {"offset": start, "tag": tag, "new_format": new_format, "chunks": chunks}
        )
        if not header & 128:
            summary["stop"] = "invalid_header"
            return summary
        for _ in range(64):
            if position >= len(raw):
                summary["stop"] = "missing_length"
                return summary
            first = raw[position]
            if new_format:
                position += 1
                partial = 224 <= first < 255
                if first < 192:
                    length = first
                elif first < 224:
                    if position >= len(raw):
                        summary["stop"] = "short_two_octet_length"
                        return summary
                    length = ((first - 192) << 8) + raw[position] + 192
                    position += 1
                elif first == 255:
                    if len(raw) - position < 4:
                        summary["stop"] = "short_five_octet_length"
                        return summary
                    length = int.from_bytes(raw[position : position + 4], "big")
                    position += 4
                else:
                    length = 1 << (first & 31)
            else:
                width = (1, 2, 4, 0)[header & 3]
                if not width or len(raw) - position < width:
                    summary["stop"] = "unsupported_or_short_old_length"
                    return summary
                length = int.from_bytes(raw[position : position + width], "big")
                position += width
                partial = False
            chunks.append({"offset": position, "length": length, "partial": partial})
            if length > len(raw) - position:
                summary["stop"] = "body_exceeds_available_bytes"
                return summary
            if partial and tag != 18:
                summary["stop"] = "partial_length_outside_tag18"
                return summary
            position += length
            if not partial:
                break
        else:
            summary["stop"] = "chunk_diagnostic_bound"
            return summary
    summary["stop"] = "complete" if position == len(raw) else "packet_diagnostic_bound"
    return summary


def _inputs():
    files = {name: b"private unchanged proof\x00\xff" for name in ARCHIVE_NAMES}
    manifest = json.dumps(
        {
            "schema": "Gate0EArchiveManifest.v1",
            "files": {
                name: {"length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in files.items()
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return manifest, files


def test_actual_synthetic_gpg_encrypt_decrypt_on_qualified_host(tmp_path, monkeypatch):
    """Host-qualified tool input is REQUIRED in this lane; absence fails, not skips.

    This test has no B key: its ephemeral synthetic secret stays in the isolated
    test home, never the packager. It cannot stand in for independent B custody.
    """
    original_packets = archive_owner._ciphertext_packets

    def checked_packets(raw, fingerprint):
        try:
            original_packets(raw, fingerprint)
        except archive_owner.ArchiveRefused:
            print(
                "SYNTHETIC_GPG_PACKET_STRUCTURE="
                + json.dumps(_packet_structure(raw), separators=(",", ":")),
                file=sys.stderr,
            )
            raise

    monkeypatch.setattr(archive_owner, "_ciphertext_packets", checked_packets)
    executable = Path(os.environ["GATE0_TEST_QUALIFIED_GPG"])
    digest = os.environ["GATE0_TEST_QUALIFIED_GPG_SHA256"]
    version = os.environ["GATE0_TEST_QUALIFIED_GPG_VERSION"]
    home = tmp_path / "synthetic-key-home"
    home.mkdir(mode=0o700)
    env = {
        "HOME": str(home),
        "GNUPGHOME": str(home),
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    base = [str(executable), "--no-options", "--homedir", str(home), "--batch"]
    deadline = time.monotonic() + 30
    gpgconf = Path(os.environ["GATE0_TEST_QUALIFIED_GPGCONF"])
    gpgconf_digest = os.environ["GATE0_TEST_QUALIFIED_GPGCONF_SHA256"]
    gpgconf_version = os.environ["GATE0_TEST_QUALIFIED_GPGCONF_VERSION"]
    qualify_gnupg_tools(
        GnuPgToolPins(executable, digest, version),
        GnuPgToolPins(gpgconf, gpgconf_digest, gpgconf_version),
        deadline=deadline,
    )
    try:
        _run(
            base
            + [
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Synthetic E test",
                "rsa2048",
                "encr",
                "1d",
            ],
            b"",
            env,
            deadline,
            16384,
        )
        listing = _run(
            base + ["--with-colons", "--list-keys"], b"", env, deadline, 65536
        )
        fingerprint = next(
            line.split(b":")[9].decode()
            for line in listing.splitlines()
            if line.startswith(b"fpr:")
        )
        public = _run(base + ["--export", fingerprint], b"", env, deadline, 131072)
        profile = GpgArchiveProfile(
            executable,
            digest,
            version,
            public,
            hashlib.sha256(public).hexdigest(),
            fingerprint,
            fingerprint,
        )
        hostile = tmp_path / "inherited-config"
        hostile.mkdir(mode=0o700)
        leaked = tmp_path / "must-not-exist"
        (hostile / "gpg.conf").write_text(
            f"encrypt-to DEADBEEFDEADBEEF\noutput {leaked}\narmor\n"
        )
        monkeypatch.setenv("GNUPGHOME", str(hostile))
        monkeypatch.setenv("HOME", str(hostile))
        monkeypatch.setenv("https_proxy", "http://must-not-be-used.invalid:9")
        manifest, files = _inputs()
        result = package_private_collection(manifest, files, profile, deadline=deadline)
        clear = _run(
            base + ["--pinentry-mode", "loopback", "--decrypt"],
            result.ciphertext,
            env,
            deadline,
            16777216,
        )
        assert not leaked.exists()
        assert clear == _pack(manifest, files)
        assert hashlib.sha256(clear).hexdigest() == result.plaintext_sha256
        # No claim about live protected producer, prerequisite owners or B custody.
        assert not hasattr(result, "readiness_accepted")
    finally:
        _run(
            [str(gpgconf), "--homedir", str(home), "--kill", "gpg-agent"],
            b"",
            env,
            time.monotonic() + 3,
            16384,
        )
