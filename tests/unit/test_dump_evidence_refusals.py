"""`dump_evidence`'s refusals, isolated from whether Postgres or Foundation
are actually present.

No real Postgres and no real `dotmac-deployment-foundation` install is
needed for any test here: the missing-file/empty-file checks run before any
subprocess, the `pg_restore`-absent check is driven by monkeypatching
`shutil.which`, and the two Foundation-import tests drive
`sys.modules['dotmac_deployment_foundation.backup']` directly — set to
`None` to force the exact `ModuleNotFoundError` `to_backup_record` catches
(CPython's import machinery raises `ModuleNotFoundError` for a `None` cache
entry — see `importlib._bootstrap._find_and_load`), or to a hand-built fake
module carrying real `Enum` types when the test needs the import to
succeed. This keeps every test here true regardless of whether this
assembly's own venv happens to have Foundation installed (it does not,
`pyproject.toml`'s `dotmac_deployment_foundation.*` mypy override says
exactly that).
"""

from __future__ import annotations

import subprocess
import sys
import types
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import pytest

from vendor_cp.recovery.dump_evidence import (
    DumpEvidence,
    FoundationUnavailable,
    PgRestoreCheckFailed,
    PgRestoreUnavailable,
    capture_dump_evidence,
    to_backup_record,
)

_SAMPLE = DumpEvidence(
    path="sample.dump",
    size_bytes=1024,
    checksum="a" * 64,
    checksum_algorithm="sha256",
    captured_at_epoch=1_700_000_000,
    decompression_proved=True,
)


def _refuse_any_subprocess_call(
    *args: object, **kwargs: object
) -> subprocess.CompletedProcess[str]:
    raise AssertionError(
        "capture_dump_evidence called a subprocess before refusing the file"
    )


def test_a_missing_file_is_refused_before_any_subprocess_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)
    missing = tmp_path / "does-not-exist.dump"

    with pytest.raises(ValueError, match="does not exist"):
        capture_dump_evidence(missing)


def test_an_empty_file_is_refused_before_any_subprocess_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)
    empty = tmp_path / "empty.dump"
    empty.write_bytes(b"")

    with pytest.raises(ValueError, match="empty"):
        capture_dump_evidence(empty)


def test_pg_restore_unavailable_is_a_distinct_refusal_from_a_failed_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An absent tool must not be silently reported as `decompression_proved=False`
    — that would say "the check ran and the file is bad" about a file nobody
    examined."""
    present = tmp_path / "present.dump"
    present.write_bytes(b"not a real dump, but non-empty")
    monkeypatch.setattr(
        "vendor_cp.recovery.dump_evidence.shutil.which", lambda _name: None
    )
    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)

    with pytest.raises(PgRestoreUnavailable):
        capture_dump_evidence(present)


def test_capture_dump_evidence_invokes_a_full_decompression_not_a_toc_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sensitivity proof for the fix: `--list` only reads the archive header
    and table of contents, never the data blocks, so it cannot back
    `Assurance.VERIFIED`'s "reads every byte" claim. The real check must be
    `--file /dev/null` (a full decompression, discarded), with `--` guarding
    the path from being parsed as an option, and no `-d`/`--dbname` (no live
    database connection)."""
    present = tmp_path / "present.dump"
    present.write_bytes(b"not a real dump, but non-empty")
    monkeypatch.setattr(
        "vendor_cp.recovery.dump_evidence.shutil.which",
        lambda _name: "/usr/bin/pg_restore",
    )

    captured_argv: list[object] = []

    def _spy_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_argv.extend(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _spy_run)

    capture_dump_evidence(present)

    assert captured_argv[0] == "/usr/bin/pg_restore"
    assert (
        "--list" not in captured_argv
    ), "a TOC-only listing does not prove full decompression"
    assert "--file" in captured_argv
    assert captured_argv[captured_argv.index("--file") + 1] == "/dev/null"
    assert "--" in captured_argv, (
        "the dump path must be guarded by `--` so a path beginning with "
        "`-` cannot be parsed as an option"
    )
    assert captured_argv.index("--") < captured_argv.index(
        str(present)
    ), "`--` must come before the path it guards"
    assert (
        "-d" not in captured_argv and "--dbname" not in captured_argv
    ), "this check must never open a live database connection"


def test_a_pg_restore_timeout_is_a_check_failure_not_a_pass_or_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timeout answers neither "the archive is fine" nor "the archive is
    bad" — it must not be silently folded into either `decompression_proved`
    outcome, nor confused with `PgRestoreUnavailable` (the tool WAS found and
    started)."""
    present = tmp_path / "present.dump"
    present.write_bytes(b"not a real dump, but non-empty")
    monkeypatch.setattr(
        "vendor_cp.recovery.dump_evidence.shutil.which",
        lambda _name: "/usr/bin/pg_restore",
    )

    def _timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="pg_restore", timeout=30)

    monkeypatch.setattr(subprocess, "run", _timeout)

    with pytest.raises(PgRestoreCheckFailed):
        capture_dump_evidence(present)


def test_a_pg_restore_os_error_is_a_check_failure_not_a_pass_or_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    present = tmp_path / "present.dump"
    present.write_bytes(b"not a real dump, but non-empty")
    monkeypatch.setattr(
        "vendor_cp.recovery.dump_evidence.shutil.which",
        lambda _name: "/usr/bin/pg_restore",
    )

    def _os_error(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError("permission denied")

    monkeypatch.setattr(subprocess, "run", _os_error)

    with pytest.raises(PgRestoreCheckFailed):
        capture_dump_evidence(present)


def test_an_unrecognised_checksum_algorithm_raises_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)
    present = tmp_path / "present.dump"
    present.write_bytes(b"not a real dump, but non-empty")

    with pytest.raises(ValueError, match="not a hashlib algorithm"):
        capture_dump_evidence(present, checksum_algorithm="not-a-real-algorithm")


def test_a_variable_length_digest_algorithm_raises_value_error_before_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`shake_128` is a real `hashlib` algorithm whose `.hexdigest()` needs an
    explicit length argument — calling it bare fails cryptically, and only
    after a whole file has already been streamed through it if the probe
    were placed after the read loop instead of before."""
    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)
    present = tmp_path / "present.dump"
    present.write_bytes(b"not a real dump, but non-empty")

    with pytest.raises(ValueError, match="variable-length digest"):
        capture_dump_evidence(present, checksum_algorithm="shake_128")


def _force_foundation_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the exact `ModuleNotFoundError` `to_backup_record` catches.

    A `None` entry in `sys.modules` is CPython's own documented "this name
    was looked up and does not exist" cache marker; `_find_and_load` raises
    `ModuleNotFoundError` for it. This makes the test true whether or not
    Foundation happens to be installed in the venv actually running it.
    """
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", None)
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation.backup", None)


def test_to_backup_record_refuses_cleanly_when_foundation_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_foundation_absent(monkeypatch)

    with pytest.raises(FoundationUnavailable, match="not installed"):
        to_backup_record(
            _SAMPLE,
            dataset="primary",
            artefact_class="data_export",
            evidence_origin="local_artefact",
        )


def test_to_backup_record_refuses_cleanly_when_foundation_is_present_but_incompatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sensitivity proof for the broadened `except` clause: a Foundation
    checkout that IMPORTS but is missing a name this module needs (an older
    API surface with no `BackupEvidenceOrigin`, say) raises a plain
    `ImportError`, not the narrower `ModuleNotFoundError` — before the fix,
    `except ModuleNotFoundError` alone would have let this escape untyped."""

    class Assurance(str, Enum):
        COMPLETED = "completed"

    class ArtefactClass(str, Enum):
        DATA_EXPORT = "data_export"

    @dataclass(frozen=True, slots=True)
    class BackupRecord:
        dataset: str
        path: str
        size_bytes: int
        checksum: str
        checksum_algorithm: str
        completed_at_epoch: int

    # Deliberately no `BackupEvidenceOrigin` — an older Foundation surface.
    incomplete_backup = types.ModuleType("dotmac_deployment_foundation.backup")
    incomplete_backup.Assurance = Assurance  # type: ignore[attr-defined]
    incomplete_backup.ArtefactClass = ArtefactClass  # type: ignore[attr-defined]
    incomplete_backup.BackupRecord = BackupRecord  # type: ignore[attr-defined]

    fake_package = types.ModuleType("dotmac_deployment_foundation")
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", fake_package)
    monkeypatch.setitem(
        sys.modules, "dotmac_deployment_foundation.backup", incomplete_backup
    )

    with pytest.raises(FoundationUnavailable):
        to_backup_record(
            _SAMPLE,
            dataset="primary",
            artefact_class="data_export",
            evidence_origin="local_artefact",
        )


def _install_fake_foundation_backup(
    monkeypatch: pytest.MonkeyPatch,
) -> types.ModuleType:
    """A hand-built stand-in for `dotmac_deployment_foundation.backup`.

    Only what `to_backup_record` actually imports: real `Enum` types (so an
    invalid member genuinely raises `ValueError`, not something this fake
    merely claims) and a `BackupRecord` shape wide enough to construct.
    Injected into `sys.modules` rather than actually installed, so this test
    does not depend on Foundation being present in the venv running it.
    """

    class Assurance(str, Enum):
        COMPLETED = "completed"
        VERIFIED = "verified"
        RESTORABLE = "restorable"
        PROVED = "proved"

    class ArtefactClass(str, Enum):
        DATA_EXPORT = "data_export"
        RECOVERY_BUNDLE = "recovery_bundle"

    class BackupEvidenceOrigin(str, Enum):
        UNSPECIFIED = "unspecified"
        LOCAL_ARTEFACT = "local_artefact"
        EXTERNAL_RECEIPT = "external_receipt"

    @dataclass(frozen=True, slots=True)
    class BackupRecord:
        dataset: str
        path: str
        size_bytes: int
        checksum: str
        checksum_algorithm: str
        completed_at_epoch: int
        assurance: Assurance = Assurance.COMPLETED
        artefact_class: ArtefactClass = ArtefactClass.DATA_EXPORT
        evidence_origin: BackupEvidenceOrigin = BackupEvidenceOrigin.UNSPECIFIED

    fake_backup = types.ModuleType("dotmac_deployment_foundation.backup")
    fake_backup.Assurance = Assurance  # type: ignore[attr-defined]
    fake_backup.ArtefactClass = ArtefactClass  # type: ignore[attr-defined]
    fake_backup.BackupEvidenceOrigin = BackupEvidenceOrigin  # type: ignore[attr-defined]
    fake_backup.BackupRecord = BackupRecord  # type: ignore[attr-defined]

    fake_package = types.ModuleType("dotmac_deployment_foundation")
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation", fake_package)
    monkeypatch.setitem(sys.modules, "dotmac_deployment_foundation.backup", fake_backup)
    return fake_backup


def test_to_backup_record_with_an_invalid_artefact_class_raises_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_foundation_backup(monkeypatch)

    with pytest.raises(ValueError):
        to_backup_record(
            _SAMPLE,
            dataset="primary",
            artefact_class="not_a_real_class",
            evidence_origin="local_artefact",
        )


def test_to_backup_record_with_an_invalid_evidence_origin_raises_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_foundation_backup(monkeypatch)

    with pytest.raises(ValueError):
        to_backup_record(
            _SAMPLE,
            dataset="primary",
            artefact_class="data_export",
            evidence_origin="not_a_real_origin",
        )


def test_to_backup_record_assurance_tracks_decompression_proved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sensitivity check for the mapping itself: a proved dump is VERIFIED, an
    unproved one is COMPLETED — not the other way around, and not always one
    value regardless of the evidence."""
    fake_backup = _install_fake_foundation_backup(monkeypatch)

    proved = to_backup_record(
        _SAMPLE,
        dataset="primary",
        artefact_class="data_export",
        evidence_origin="local_artefact",
    )
    assert proved.assurance is fake_backup.Assurance.VERIFIED

    unproved_evidence = DumpEvidence(
        path=_SAMPLE.path,
        size_bytes=_SAMPLE.size_bytes,
        checksum=_SAMPLE.checksum,
        checksum_algorithm=_SAMPLE.checksum_algorithm,
        captured_at_epoch=_SAMPLE.captured_at_epoch,
        decompression_proved=False,
    )
    unproved = to_backup_record(
        unproved_evidence,
        dataset="primary",
        artefact_class="data_export",
        evidence_origin="local_artefact",
    )
    assert unproved.assurance is fake_backup.Assurance.COMPLETED
