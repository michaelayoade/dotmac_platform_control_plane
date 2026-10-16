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


def _decrypt_status_fixture(size=7):
    return (
        f"[GNUPG:] ENC_TO {FINGERPRINT[-16:]} 1 0\n"
        f"[GNUPG:] KEY_CONSIDERED {FINGERPRINT} 0\n"
        f"[GNUPG:] DECRYPTION_KEY {FINGERPRINT} {FINGERPRINT} u\n"
        "[GNUPG:] BEGIN_DECRYPTION\n[GNUPG:] DECRYPTION_INFO 2 9 0\n"
        "[GNUPG:] PLAINTEXT 62 0 \n"
        f"[GNUPG:] PLAINTEXT_LENGTH {size}\n"
        "[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n[GNUPG:] END_DECRYPTION\n"
    ).encode()


def test_decrypt_status_requires_selected_recipient_and_integrity_completion():
    from vendor_cp.deployment.gate0_e_archive import _decrypt_status

    _decrypt_status(_decrypt_status_fixture(), _profile(), 7)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: b"",
        lambda raw: raw.replace(b"GOODMDC", b"BADMDC"),
        lambda raw: raw.replace(b"[GNUPG:] DECRYPTION_OKAY\n", b""),
        lambda raw: raw.replace(b"[GNUPG:] END_DECRYPTION\n", b""),
        lambda raw: raw.replace(b"DECRYPTION_INFO 2 9 0", b"DECRYPTION_INFO 0 9 0"),
        lambda raw: raw.replace(b"PLAINTEXT_LENGTH 7", b"PLAINTEXT_LENGTH 8"),
        lambda raw: raw.replace(
            b"DECRYPTION_KEY " + b"A" * 40, b"DECRYPTION_KEY " + b"B" * 40
        ),
        lambda raw: raw + b"[GNUPG:] ERROR PRIVATE-DIAGNOSTIC\n",
        lambda raw: raw.replace(b"GOODMDC\n", b"GOODMDC\n[GNUPG:] GOODMDC\n"),
        lambda raw: raw.replace(b"\n", b"\r\n"),
    ],
)
def test_decrypt_status_zero_exit_cannot_replace_complete_status(mutation):
    from vendor_cp.deployment.gate0_e_archive import _decrypt_status

    with pytest.raises(ArchiveRefused, match="archive_decrypt_status") as error:
        _decrypt_status(mutation(_decrypt_status_fixture()), _profile(), 7)
    assert "PRIVATE" not in str(error.value)


def test_separate_status_pipe_and_plaintext_eof_with_actual_child():
    from vendor_cp.deployment.gate0_e_archive import _run_channels

    script = """
import os, sys
fd = int(sys.argv[sys.argv.index('--status-fd') + 1])
raw = sys.stdin.buffer.read()
os.write(fd, b'[GNUPG:] DECRYPTION_OKAY\\n')
sys.stdout.buffer.write(raw[::-1]); sys.stdout.buffer.flush()
os.close(fd)
"""
    plaintext, status = _run_channels(
        [sys.executable, "-I", "-c", script],
        b"private-input",
        {},
        time.monotonic() + 3,
        4096,
        status_channel=True,
    )
    assert plaintext == b"tupni-etavirp"
    assert status == b"[GNUPG:] DECRYPTION_OKAY\n"


@pytest.mark.parametrize(
    "fault", ["status_bound", "plaintext_bound", "nonzero", "status_eof_deadline"]
)
def test_actual_status_child_failure_is_closed_and_bounded(fault):
    from vendor_cp.deployment.gate0_e_archive import _run_channels

    scripts = {
        "status_bound": "os.write(fd, b'S' * 70000)",
        "plaintext_bound": (
            "sys.stdout.buffer.write(b'P' * 70000); sys.stdout.buffer.flush()"
        ),
        "nonzero": "os.write(fd, b'PRIVATE-STATUS'); sys.exit(7)",
        "status_eof_deadline": "sys.stdout.close(); time.sleep(20)",
    }
    script = (
        "import os,sys,time\nfd=int(sys.argv[sys.argv.index('--status-fd')+1])\n"
        + scripts[fault]
    )
    started = time.monotonic()
    with pytest.raises(ArchiveRefused) as error:
        _run_channels(
            [sys.executable, "-I", "-c", script],
            b"",
            {},
            started + 2,
            4096,
            status_channel=True,
        )
    assert time.monotonic() - started < 4
    assert "PRIVATE" not in str(error.value)


def test_status_parent_close_fault_still_cancels_and_reaps_actual_child(monkeypatch):
    from vendor_cp.deployment.gate0_e_archive import _run_channels

    real_pipe, real_close, real_popen = os.pipe, os.close, subprocess.Popen
    status_pair = []
    children = []
    failed = []

    def pipe():
        pair = real_pipe()
        if not status_pair:
            status_pair.extend(pair)
        return pair

    def close(fd):
        if status_pair and fd == status_pair[1] and children and not failed:
            failed.append(fd)
            raise OSError("PRIVATE close diagnostic")
        return real_close(fd)

    def spawn(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(os, "pipe", pipe)
    monkeypatch.setattr(os, "close", close)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    with pytest.raises(ArchiveRefused) as error:
        _run_channels(
            [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
            b"",
            {},
            time.monotonic() + 3,
            4096,
            status_channel=True,
        )
    assert failed and children and children[0].returncode is not None
    assert "PRIVATE" not in str(error.value)


def _decrypt_native_seams(monkeypatch, *, interrupt=False, valid=False):
    from vendor_cp.deployment import gate0_e_archive as owner

    public = replace(_profile(), public_key_sha256=hashlib.sha256(b"").hexdigest())
    profile = owner.GpgHolderProfile(
        public,
        Path("/fixture/home/.gnupg"),
        Path("/fixture/home"),
        owner.GnuPgToolPins(
            Path("/fixture/gpgconf"), "0" * 64, "gpgconf (GnuPG) 2.4.7"
        ),
        Path("/fixture/home/.gnupg/S.gpg-agent"),
        Path("/fixture/home/.gnupg/pubring.kbx"),
    )
    monkeypatch.setattr(owner, "_protected_binary", lambda pins: None)
    monkeypatch.setattr(owner, "_public_packets", lambda raw: None)
    monkeypatch.setattr(owner, "_ciphertext_packets", lambda raw, fingerprint: None)

    def run(argv, data, env, deadline, limit):
        if "--list-dirs" in argv:
            return os.fsencode(profile.agent_socket) + b"\n"
        if "--list-keys" in argv:
            return _listing()
        version = (
            profile.gpgconf.version_line
            if argv[0] == str(profile.gpgconf.executable)
            else public.version_line
        )
        return version.encode() + b"\n"

    monkeypatch.setattr(owner, "_run", run)

    def channels(*args, **kwargs):
        plaintext = b"ARCHIVE-PRIVATE-PLAINTEXT-MARKER"
        status = b"[GNUPG:] ERROR ARCHIVE-PRIVATE-STATUS-MARKER\n"
        if interrupt:
            raise KeyboardInterrupt(plaintext + status)
        return plaintext, _decrypt_status_fixture(len(plaintext)) if valid else status

    monkeypatch.setattr(owner, "_run_channels", channels)
    return profile


def _archive_private_trace(error):
    from vendor_cp.deployment import gate0_e_archive as owner

    assert error.__context__ is None and error.__cause__ is None
    values = []
    tb = error.__traceback__
    while tb:
        if tb.tb_frame.f_code.co_filename == owner.__file__:
            values.extend(repr(value) for value in tb.tb_frame.f_locals.values())
        tb = tb.tb_next
    return "\n".join(values)


def test_decrypt_checked_native_unit_boundary_has_success(monkeypatch):
    from vendor_cp.deployment.gate0_e_archive import decrypt_private_collection

    profile = _decrypt_native_seams(monkeypatch, valid=True)
    result = decrypt_private_collection(
        b"fixture-ciphertext", profile, deadline=time.monotonic() + 10
    )
    assert result.plaintext_sha256 == hashlib.sha256(result.plaintext).hexdigest()
    assert result.plaintext == b"ARCHIVE-PRIVATE-PLAINTEXT-MARKER"


@pytest.mark.parametrize("interrupt", [False, True])
def test_decrypt_failure_detaches_private_context_and_frames(monkeypatch, interrupt):
    from vendor_cp.deployment.gate0_e_archive import decrypt_private_collection

    profile = _decrypt_native_seams(monkeypatch, interrupt=interrupt)
    with pytest.raises(KeyboardInterrupt if interrupt else ArchiveRefused) as caught:
        decrypt_private_collection(
            b"fixture-ciphertext", profile, deadline=time.monotonic() + 10
        )
    assert "ARCHIVE-PRIVATE" not in _archive_private_trace(caught.value)
    assert "ARCHIVE-PRIVATE" not in str(caught.value)


def test_status_parser_refusal_retains_no_raw_status_context():
    from vendor_cp.deployment.gate0_e_archive import _decrypt_status

    with pytest.raises(ArchiveRefused) as caught:
        _decrypt_status(
            b"[GNUPG:] ERROR ARCHIVE-PRIVATE-STATUS-MARKER\n", _profile(), 7
        )
    assert "ARCHIVE-PRIVATE" not in _archive_private_trace(caught.value)
