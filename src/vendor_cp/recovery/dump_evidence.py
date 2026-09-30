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

## What "decompression proved" actually checks, and why `--list` is not it

Foundation's own `Assurance.VERIFIED` requires a check that reads every byte
of the artefact (`backup.verification_plan`'s docstring: decompressing to
`/dev/null` "is the only check here that touches the whole artefact"). `
pg_restore --list <path>` reads only the archive header and table of
contents — it never touches the data blocks — so a dump with an intact
header but a truncated or corrupted data section would pass `--list` and
still fail a real restore. This module instead runs
`pg_restore --file /dev/null -- <path>` (no `-d`/`--dbname`, so no live
database connection is needed): that converts the whole archive to a SQL
script and discards it, which requires decompressing every data block to
produce. That is the actual check `decompression_proved=True` stands for.

``scripts/deploy_production.sh`` (read-only reference, DO NOT TOUCH) proves
decompression today with `pg_restore --list < database.dump` — the weaker,
TOC-only check. That divergence is intentional: this module closes a gap
the shell script does not, rather than reproducing the shell script's own
check verbatim.

A missing `pg_restore` binary, a `pg_restore` that ran and rejected the
file, and a `pg_restore` that could not complete the check at all (crashed
or timed out) are three different findings and must not be collapsed:
"this host cannot answer the question" (:class:`PgRestoreUnavailable`),
"the question was asked and the answer is no" (`decompression_proved=False`
on an ordinarily-returned :class:`DumpEvidence`, its `pg_restore` stderr
logged rather than dropped), and "the question could not be asked to
completion" (:class:`PgRestoreCheckFailed`, for a timeout or an OS-level
failure to execute the resolved binary).

Decompression is proved using whichever `pg_restore` is on this host's
PATH. A `pg_restore` OLDER than the `pg_dump` that wrote the archive can
reject a genuinely fine file as "unproved" — that is toolchain version
skew, not corruption, and pinning compatible versions is an ops concern
this module does not attempt to solve.
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
#: `timeout_seconds` throughout). `--file /dev/null` reads every data block
#: rather than only the header `--list` read, so this is more work than the
#: check it replaced; 30s stays generous for the scratch-database dump sizes
#: this module's own tests exercise, but a much larger production archive may
#: need a wider bound at the call site (there is no call site outside tests
#: yet — this module is reachable only from the CLI/tests, never the live
#: deploy path).
_PG_RESTORE_TIMEOUT_SECONDS = 30


class PgRestoreUnavailable(RuntimeError):
    """`pg_restore` is not on this host's `PATH`.

    Distinct from a failed decompression check: this host cannot even ask
    the question, so returning `decompression_proved=False` here would say
    "the check ran and the file is bad" about a file nobody examined.
    """


class PgRestoreCheckFailed(RuntimeError):
    """`pg_restore` was invoked but did not run to completion.

    Distinct from BOTH `PgRestoreUnavailable` (the tool was resolved and
    started) and `decompression_proved=False` (the tool ran to completion
    and reported the archive as bad). A timeout or an OS-level failure to
    execute the resolved binary answers neither "yes" nor "no" about the
    archive's own bytes, so it must not be silently folded into either.
    """


class FoundationUnavailable(RuntimeError):
    """`dotmac-deployment-foundation` is not installed, or is missing a name
    this module needs from it.

    Same tone as `recovery/bundle.py`'s `evidence.tool_absent` refusal
    (`cli/commands.py::recovery_bundle`): the facility that owns every
    backup-evidence decision cannot be reached, and this assembly does not
    pin it and must not re-implement it. Raised for both an absent package
    (`ModuleNotFoundError`) and a present-but-incompatible one missing a
    required name (a plain `ImportError`) — an older Foundation checkout
    without `BackupEvidenceOrigin`, say, is unusable here for the same
    reason an absent one is, and must not escape as an untyped exception.
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
    decompression question, or `PgRestoreCheckFailed` if it asked and the
    check itself did not complete (timeout, OS error). A present-but-corrupt
    dump is not a refusal: it comes back as ordinary evidence with
    `decompression_proved=False`, its `pg_restore` stderr logged rather than
    dropped. `size_bytes` is the count of bytes actually streamed through
    the checksum, not a separate `stat()` reading, so the two facts can
    never disagree about what was measured.
    """
    if not dump_path.exists():
        raise ValueError(f"{dump_path} does not exist — there is no dump to evidence")
    if dump_path.stat().st_size == 0:
        raise ValueError(f"{dump_path} is empty — a zero-byte dump is not evidence")

    try:
        digest = hashlib.new(checksum_algorithm)
    except ValueError as error:
        raise ValueError(
            f"{checksum_algorithm!r} is not a hashlib algorithm this host " "recognises"
        ) from error
    try:
        digest.hexdigest()
    except TypeError as error:
        # A variable-length digest (a SHAKE algorithm) needs an explicit
        # output length at `.hexdigest()` time. Probed here, on the empty
        # digest, before streaming a potentially large file — hashlib
        # objects tolerate `.hexdigest()` being called more than once, so
        # this costs nothing and fails loudly before any real work.
        raise ValueError(
            f"{checksum_algorithm!r} is a variable-length digest algorithm "
            "(e.g. a SHAKE variant) and needs an explicit output length; "
            "only a fixed-length digest algorithm is supported here"
        ) from error

    bytes_read = 0
    with dump_path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
            bytes_read += len(chunk)
    checksum = digest.hexdigest()

    pg_restore = shutil.which("pg_restore")
    if pg_restore is None:
        raise PgRestoreUnavailable(
            "pg_restore is not on PATH, so full decompression cannot be proved "
            "for this dump. This is an absent capability, not a failed check: "
            "the file itself was never examined"
        )

    try:
        result = subprocess.run(  # noqa: S603 - argv list, resolved executable
            [pg_restore, "--file", "/dev/null", "--", str(dump_path)],
            capture_output=True,
            text=True,
            timeout=_PG_RESTORE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise PgRestoreCheckFailed(
            f"pg_restore did not finish within {_PG_RESTORE_TIMEOUT_SECONDS}s "
            f"for {dump_path}: {error}"
        ) from error
    except OSError as error:
        raise PgRestoreCheckFailed(
            f"pg_restore could not be executed against {dump_path}: {error}"
        ) from error

    decompression_proved = result.returncode == 0
    if not decompression_proved:
        logger.warning(
            "pg_restore --file /dev/null rejected %s (exit %s): %s",
            dump_path,
            result.returncode,
            result.stderr.strip(),
        )

    return DumpEvidence(
        path=str(dump_path),
        size_bytes=bytes_read,
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
    except ImportError as error:
        # `ImportError`, not the narrower `ModuleNotFoundError`: a present
        # but older/incompatible Foundation checkout missing a name this
        # module needs (e.g. no `BackupEvidenceOrigin`) raises the former,
        # not the latter, and must refuse the same clean way an absent
        # package does rather than escape untyped.
        raise FoundationUnavailable(
            "dotmac-deployment-foundation is not installed, or is missing a "
            "name this module needs from it, so the recovery facility that "
            f"owns every bundle decision cannot be reached ({error}). This "
            "assembly does not pin it and must not re-implement it."
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
    "PgRestoreCheckFailed",
    "PgRestoreUnavailable",
    "capture_dump_evidence",
    "to_backup_record",
]
