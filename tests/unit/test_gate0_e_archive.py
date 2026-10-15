"""Source mechanism tests only; neither synthetic encryption nor CI accepts E."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time
from dataclasses import replace
from pathlib import Path

import pytest

from vendor_cp.deployment.gate0_e_archive import (
    ARCHIVE_NAMES,
    ArchiveRefused,
    GnuPgToolPins,
    GpgArchiveProfile,
    _ciphertext_packets,
    _key_listing,
    _pack,
    _public_packets,
    _run,
    package_private_collection,
    qualify_gnupg_tools,
    unpack_private_archive,
)

FINGERPRINT = "A" * 40


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


def _profile():
    return GpgArchiveProfile(
        Path("/usr/bin/gpg"),
        "0" * 64,
        "gpg (GnuPG) 2.4.7",
        b"",
        "0" * 64,
        FINGERPRINT,
        FINGERPRINT,
    )


def test_archive_is_closed_flat_deterministic_and_byte_preserving():
    manifest, files = _inputs()
    packed = _pack(manifest, files)
    assert packed == _pack(manifest, dict(reversed(list(files.items()))))
    with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
        assert archive.getnames() == sorted(["manifest.json", *ARCHIVE_NAMES])
        for member in archive.getmembers():
            assert member.isfile() and member.mode == 0o600
            assert (member.uid, member.gid, member.mtime) == (0, 0, 0)
            assert member.uname == member.gname == ""
            assert archive.extractfile(member).read() == (
                manifest if member.name == "manifest.json" else files[member.name]
            )


@pytest.mark.parametrize("name", ["../escape", "/absolute", "link", "collection.json/"])
def test_member_injection_refused(name):
    manifest, files = _inputs()
    files[name] = b"secret"
    with pytest.raises(ArchiveRefused, match="archive_members"):
        _pack(manifest, files)


def test_manifest_cannot_lie_or_reserialize_private_proof():
    manifest, files = _inputs()
    files["collection.json"] += b"changed"
    with pytest.raises(ArchiveRefused, match="archive_manifest"):
        _pack(manifest, files)
    with pytest.raises(ArchiveRefused):
        _pack(manifest + b"\n", _inputs()[1])


@pytest.mark.parametrize(
    "key",
    [
        b"\xc5\x01X",
        b"\xc7\x01X",
        b"\xc6\xe0X",
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ],
)
def test_private_or_opaque_key_rejected_before_gpg(key):
    with pytest.raises(ArchiveRefused, match="archive_recipient"):
        _public_packets(key)


def _listing(validity="-", expiry="0", caps="e", fingerprint=FINGERPRINT):
    fields = [
        "pub",
        validity,
        "2048",
        "1",
        "A" * 16,
        "1",
        expiry,
        "",
        "",
        "",
        "",
        caps,
        "",
        "",
    ]
    return (":".join(fields) + "\nfpr:::::::::" + fingerprint + ":\n").encode()


@pytest.mark.parametrize(
    "raw",
    [
        _listing("r"),
        _listing("e"),
        _listing(expiry="1"),
        _listing(caps="s"),
        _listing(fingerprint="B" * 40),
        _listing() + _listing(),
        b"sec:::::::::::",
    ],
)
def test_actual_key_listing_rejects_revoked_expired_wrong_or_extra_recipient(raw):
    with pytest.raises(ArchiveRefused, match="archive_recipient"):
        _key_listing(raw, _profile())


def _child(script, data=b"", limit=65536, seconds=3):
    return _run(
        [sys.executable, "-I", "-c", script],
        data,
        {"PATH": "/usr/bin:/bin"},
        time.monotonic() + seconds,
        limit,
    )


def test_owned_process_duplex_does_not_deadlock():
    raw = b"private" * 100000
    assert (
        _child(
            "import sys; b=sys.stdin.buffer.read(); sys.stdout.buffer.write(b)",
            raw,
            len(raw),
        )
        == raw
    )


@pytest.mark.parametrize(
    "script",
    [
        "import sys; sys.stderr.write('PRIVATE JWT path'); sys.exit(9)",
        "import os; os.close(0); os.close(1)",
    ],
)
def test_owned_process_failure_and_early_eof_are_sanitized(script):
    with pytest.raises(ArchiveRefused) as caught:
        _child(script, b"private" * 100000)
    assert str(caught.value) == "archive_process"
    assert "PRIVATE" not in repr(caught.value)


def test_owned_process_output_bound():
    with pytest.raises(ArchiveRefused, match="archive_output_bound"):
        _child("import sys; sys.stdout.buffer.write(b'x'*100000)", limit=10)


def test_owned_timeout_kills_and_reaps_process_group(tmp_path):
    pid_path = tmp_path / "pid"
    script = (
        "import os,time; "
        f"open({str(pid_path)!r},'w').write(str(os.getpid())); "
        "os.fork(); time.sleep(60)"
    )
    start = time.monotonic()
    with pytest.raises(ArchiveRefused, match="archive_deadline"):
        _child(script, seconds=2)
    assert time.monotonic() - start < 2.5
    pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_ciphertext_rejects_plaintext_extra_recipients_and_wrong_key():
    pkesk = b"\xc1\x0a\x03" + bytes.fromhex(FINGERPRINT[-16:]) + b"\x01"
    encrypted = b"\xd2\x28\x01" + b"x" * 39
    _ciphertext_packets(pkesk + encrypted, FINGERPRINT)
    for raw in (
        b"private",
        pkesk * 2 + encrypted,
        pkesk + b"\xcb\x01X",
        pkesk + encrypted + b"\xcb\x01X",
    ):
        with pytest.raises(ArchiveRefused, match="archive_ciphertext"):
            _ciphertext_packets(raw, FINGERPRINT)
    with pytest.raises(ArchiveRefused):
        _ciphertext_packets(pkesk + encrypted, "B" * 40)


def test_no_profile_constructor_flag_can_authorize_or_export_private_bytes():
    profile = _profile()
    assert "public_key" not in repr(profile)
    manifest, files = _inputs()
    with pytest.raises(ArchiveRefused):
        package_private_collection(
            manifest,
            files,
            replace(profile, executable=Path("relative")),
            deadline=time.monotonic() + 5,
        )


def test_bounded_inverse_preserves_bytes_and_refuses_appended_or_changed_tar():
    manifest, files = _inputs()
    packed = _pack(manifest, files)
    parsed = unpack_private_archive(packed)
    assert parsed.inner_manifest == manifest
    assert parsed.proof_files == files
    with pytest.raises(TypeError):
        parsed.proof_files["collection.json"] = b"replacement"
    for invalid in (packed + b"hidden", packed[:-512], b"not a tar"):
        with pytest.raises(ArchiveRefused):
            unpack_private_archive(invalid)


def test_inverse_rejects_symlink_and_duplicate_members():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo("collection.json")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside"
        archive.addfile(member)
    with pytest.raises(ArchiveRefused, match="archive_members"):
        unpack_private_archive(output.getvalue())


def test_owned_cancellation_reaps_real_child(tmp_path, monkeypatch):
    pid_path = tmp_path / "cancel-pid"
    script = (
        "import os,time; "
        f"open({str(pid_path)!r},'w').write(str(os.getpid())); "
        "os.write(1,b'ready'); time.sleep(60)"
    )
    real_read = os.read

    def interrupted_read(fd, size):
        raw = real_read(fd, size)
        if raw == b"ready":
            raise KeyboardInterrupt
        return raw

    # Interrupt after real child output, without replacing the process owner.
    monkeypatch.setattr(os, "read", interrupted_read)
    with pytest.raises(KeyboardInterrupt):
        _child(script)
    pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_reaped_child_is_never_signaled(monkeypatch):
    kills = []
    real_killpg = os.killpg

    def observe_killpg(pid, sig):
        kills.append(pid)
        return real_killpg(pid, sig)

    monkeypatch.setattr(os, "killpg", observe_killpg)
    assert _child("import sys; sys.stdout.write('ok')") == b"ok"
    assert kills == []
    with pytest.raises(ArchiveRefused, match="archive_process"):
        _child("import sys; sys.exit(3)")
    assert kills == []


@pytest.mark.parametrize(
    "fault", ["signal", "first_close", "first_wait", "cleanup_wait"]
)
def test_cleanup_fault_does_not_bypass_later_owned_cleanup(
    tmp_path, monkeypatch, fault
):
    """Fault injection wraps a real Popen/pipe; no fabricated process success."""
    events = []
    owned = []
    real_popen = subprocess.Popen
    real_killpg = os.killpg
    real_wait = subprocess.Popen.wait

    class Pipe:
        def __init__(self, stream, name):
            self.stream, self.name = stream, name
            self.failed = False

        def fileno(self):
            return self.stream.fileno()

        def close(self):
            events.append(self.name)
            if (
                fault == "first_close"
                and self.name == "stdin"
                and "signal" in events
                and not self.failed
            ):
                self.failed = True
                raise OSError("PRIVATE close detail")
            return self.stream.close()

    def spawn(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        owned.append(child)
        child.stdin = Pipe(child.stdin, "stdin")
        child.stdout = Pipe(child.stdout, "stdout")
        return child

    def failing_signal(pid, sig):
        events.append("signal")
        if fault == "signal":
            raise PermissionError("PRIVATE signal detail")
        return real_killpg(pid, sig)

    wait_failed = False

    def failing_wait(child, timeout=None):
        nonlocal wait_failed
        events.append("wait")
        if (
            fault == "first_wait" or (fault == "cleanup_wait" and "signal" in events)
        ) and not wait_failed:
            wait_failed = True
            raise OSError("PRIVATE wait detail")
        return real_wait(child, timeout=timeout)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(os, "killpg", failing_signal)
    monkeypatch.setattr(real_popen, "wait", failing_wait)
    # For first_wait, close both output pipes, then sleep so the owner waits.
    script = (
        "import os,time; os.close(1); time.sleep(60)"
        if fault == "first_wait"
        else "import time; time.sleep(60)"
    )
    with pytest.raises(ArchiveRefused) as caught:
        _child(script, seconds=2)
    assert "stdout" in events and "wait" in events
    assert owned[0].returncode is not None
    assert owned[0].stdout.stream.closed
    assert "PRIVATE" not in str(caught.value)


def test_inverse_refuses_physical_extension_chains_sparse_and_bad_sizes(monkeypatch):
    manifest, files = _inputs()
    packed = _pack(manifest, files)

    def no_generic_processing(*args, **kwargs):
        pytest.fail("malformed physical input reached generic tar processing")

    monkeypatch.setattr(tarfile, "open", no_generic_processing)
    for tag in (b"L", b"K", b"x", b"g", b"S", b"1", b"2"):
        header = bytearray(packed[:512])
        header[156:157] = tag
        if tag == b"S":
            # GNU sparse original logical size: reject type before interpreting it.
            header[483:495] = b"00077777777\x00"
        # 1500 chained extension headers must be refused at the first physical one.
        bad = bytes(header) * 1500
        with pytest.raises(ArchiveRefused, match="archive_members"):
            unpack_private_archive(bad)
    for size in (
        b"77777777777\x00",
        b"00000000000\x00",
        b"0000000000x\x00",
        b"\x80" + b"\x00" * 11,
    ):
        header = bytearray(packed[:512])
        header[124:136] = size
        with pytest.raises(ArchiveRefused):
            unpack_private_archive(bytes(header) + packed[512:])
    # Duplicate first regular header in the second slot: exact order rejects it.
    size = int(packed[124:135], 8)
    second_offset = 512 + size + (-size % 512)
    duplicate = packed[:second_offset] + packed[:512] + packed[second_offset + 512 :]
    with pytest.raises(ArchiveRefused, match="archive_members"):
        unpack_private_archive(duplicate)
    # Nonzero member padding is rejected before any later member processing.
    bad = bytearray(packed)
    bad[512 + size] = 1
    with pytest.raises(ArchiveRefused, match="archive_members"):
        unpack_private_archive(bytes(bad))


def test_tool_pair_rejects_missing_or_unprotected_pins_without_executing(monkeypatch):
    def forbidden_spawn(*args, **kwargs):
        pytest.fail("unqualified tool was executed")

    monkeypatch.setattr(subprocess, "Popen", forbidden_spawn)
    # Real root-protected bytes pass the first disk check, but are never run:
    # the relative second tool must fail before any --version invocation.
    root_file = Path("/usr/bin/true")
    good_shape = GnuPgToolPins(
        root_file,
        hashlib.sha256(root_file.read_bytes()).hexdigest(),
        "gpg (GnuPG) 2.4.7",
    )
    bad_conf = GnuPgToolPins(
        Path("relative-gpgconf"), "0" * 64, "gpgconf (GnuPG) 2.4.7"
    )
    with pytest.raises(ArchiveRefused):
        qualify_gnupg_tools(good_shape, bad_conf, deadline=time.monotonic() + 5)
