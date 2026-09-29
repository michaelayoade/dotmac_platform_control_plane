"""Write-time proof about the bytes of one database dump on disk.

Two layers, kept apart on purpose. :class:`DumpEvidence` and
:func:`capture_dump_evidence` prove facts about a file — its size, its
checksum, whether it actually decompresses — with **no** dependency on
`dotmac-deployment-foundation` at all: a dump's bytes are true or false
regardless of whether the facility that would consume the evidence is even
installed. :func:`to_backup_record` is the second layer, mapping those local
facts into Foundation's ``BackupRecord`` vocabulary; it late-imports the
facility exactly the way `recovery/bundle.py` does, for the same reason —
`dotmac-deployment-foundation` is not a declared dependency of this assembly,
so its absence must be a runtime answer, not a collection error.

``scripts/deploy_production.sh`` already proves decompression today with
``pg_restore --list < database.dump`` after checking the file is non-empty
(``[[ -s "${BUNDLE_TMP}/database.dump" ]] || die "database dump is empty"``).
This module reproduces that exact check in typed, testable Python — it does
not invent a new one.

A missing `pg_restore` binary and a `pg_restore` that ran and rejected the
file are different findings and must not be collapsed into one boolean: the
first means "this host cannot answer the question", the second means "the
question was asked and the answer is no". :class:`PgRestoreUnavailable` is
raised for the first; the second is recorded as
``decompression_proved=False`` on a normally-returned :class:`DumpEvidence`,
with the tool's stderr logged rather than swallowed, because a corrupt-but-
present dump is exactly the kind of failed check a caller needs to see
without the call itself raising.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess  # noqa: S404 - argv list, shell=False throughout
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Streamed in 1 MiB reads, matching `deployment/effects.py`'s own `_sha256`
#: chunking — not imported from there, because this module must not depend
#: on `effects.py`.
_CHUNK_BYTES = 1024 * 1024

#: Bounded, never open-ended, matching this repo's own subprocess convention
#: (`test_fenced_migration.py`'s `SESSION_WAIT_SECONDS`, `effects.py`'s
#: `timeout_seconds` throughout).
_PG_RESTORE_TIMEOUT_SECONDS = 30


class PgRestoreUnavailable(RuntimeError):
    """`pg_restore` is not on this host's `PATH`.

    Distinct from a failed decompression check: this host cannot even ask
    the question, so returning `decompression_proved=False` here would say
    "the check ran and the file is bad" about a file nobody examined.
    """


class FoundationUnavailable(RuntimeError):
    """`dotmac-deployment-foundation` is not installed.

    Same tone as `recovery/bundle.py`'s `evidence.tool_absent` refusal
    (`cli/commands.py::recovery_bundle`): the facility that owns every
    backup-evidence decision cannot be reached, and this assembly does not
    pin it and must not re-implement it.
    """


@dataclass(frozen=True, slots=True)
class DumpEvidence:
    """What is known about one dump file's bytes, with no Foundation import.

    Deliberately narrower than Foundation's `BackupRecord`: this is CP-local
    evidence about a file, not yet a claim about what the file IS (a data
    export or a recovery bundle) — that classification is the caller's, made
    explicitly, in `to_backup_record`.
    """

    path: str
    size_bytes: int
    checksum: str
    checksum_algorithm: str
    captured_at_epoch: int
    decompression_proved: bool


def capture_dump_evidence(
    dump_path: Path,
    *,
    checksum_algorithm: str = "sha256",
    now_epoch: int | None = None,
) -> DumpEvidence:
    """Prove size, checksum, and full decompression for one dump file.

    Refuses a missing or empty file before any subprocess call — the same
    check `deploy_production.sh` makes with `[[ -s ... ]] || die`. Refuses
    with `PgRestoreUnavailable` if this host cannot even ask the
    decompression question. A present-but-corrupt dump is not a refusal: it
    comes back as ordinary evidence with `decompression_proved=False`, its
    `pg_restore` stderr logged rather than dropped.
    """
    if not dump_path.exists():
        raise ValueError(f"{dump_path} does not exist — there is no dump to evidence")
    size_bytes = dump_path.stat().st_size
    if size_bytes == 0:
        raise ValueError(f"{dump_path} is empty — a zero-byte dump is not evidence")

    digest = hashlib.new(checksum_algorithm)
    with dump_path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
    checksum = digest.hexdigest()

    pg_restore = shutil.which("pg_restore")
    if pg_restore is None:
        raise PgRestoreUnavailable(
            "pg_restore is not on PATH, so full decompression cannot be proved "
            "for this dump. This is an absent capability, not a failed check: "
            "the file itself was never examined"
        )

    result = subprocess.run(  # noqa: S603 - argv list, resolved executable, no shell
        [pg_restore, "--list", str(dump_path)],
        capture_output=True,
        text=True,
        timeout=_PG_RESTORE_TIMEOUT_SECONDS,
        check=False,
    )
    decompression_proved = result.returncode == 0
    if not decompression_proved:
        logger.warning(
            "pg_restore --list rejected %s (exit %s): %s",
            dump_path,
            result.returncode,
            result.stderr.strip(),
        )

    return DumpEvidence(
        path=str(dump_path),
        size_bytes=size_bytes,
        checksum=checksum,
        checksum_algorithm=checksum_algorithm,
        captured_at_epoch=now_epoch if now_epoch is not None else int(time.time()),
        decompression_proved=decompression_proved,
    )


def to_backup_record(
    evidence: DumpEvidence,
    *,
    dataset: str,
    artefact_class: str,
    evidence_origin: str,
) -> Any:
    """Map local dump evidence into Foundation's `BackupRecord`.

    `artefact_class` / `evidence_origin` are the CALLER's explicit claim, not
    a default this function guesses: a single dump file is not yet a
    recovery bundle until it is paired with a manifest (future work, not
    this slice), so nothing here defaults to `RECOVERY_BUNDLE`. `assurance`
    is the one thing this function does decide, from evidence it just
    measured: `VERIFIED` when decompression was proved, `COMPLETED`
    otherwise. `BackupRecord.__post_init__` is left to refuse an invalid
    combination (e.g. `DATA_EXPORT` claiming `RESTORABLE`) — pre-checking
    that here would duplicate a rule Foundation already owns.
    """
    try:
        from dotmac_deployment_foundation.backup import (  # noqa: PLC0415
            ArtefactClass,
            Assurance,
            BackupEvidenceOrigin,
            BackupRecord,
        )
    except ModuleNotFoundError as error:
        raise FoundationUnavailable(
            "dotmac-deployment-foundation is not installed, so the recovery "
            "facility that owns every bundle decision cannot be reached "
            f"({error}). This assembly does not pin it and must not "
            "re-implement it."
        ) from error

    assurance = (
        Assurance.VERIFIED if evidence.decompression_proved else Assurance.COMPLETED
    )
    return BackupRecord(
        dataset=dataset,
        path=evidence.path,
        size_bytes=evidence.size_bytes,
        checksum=evidence.checksum,
        checksum_algorithm=evidence.checksum_algorithm,
        completed_at_epoch=evidence.captured_at_epoch,
        assurance=assurance,
        artefact_class=ArtefactClass(artefact_class),
        evidence_origin=BackupEvidenceOrigin(evidence_origin),
    )


__all__ = [
    "DumpEvidence",
    "FoundationUnavailable",
    "PgRestoreUnavailable",
    "capture_dump_evidence",
    "to_backup_record",
]
