"""Write-time dump evidence against a REAL `pg_dump` archive.

`deploy_production.sh` already proves decompression today with
``pg_restore --list < database.dump`` after an ``[[ -s ... ]]`` emptiness
check (see that script, around its step 2/3). `dump_evidence.py` deliberately
checks MORE than that: `--list` only reads the archive header and table of
contents, never the data blocks, so this file's REAL assertions exercise
`capture_dump_evidence`'s `pg_restore --file /dev/null -- <path>` check — a
full decompression of every data block, converted to a SQL script and
discarded — against a REAL custom-format dump of a nonempty scratch
database, not a hand-built fixture, because the property under test is "does
`pg_restore` actually accept and fully decompress the bytes `pg_dump`
wrote", which a synthetic file cannot answer and a header-only check cannot
prove. The positive scratch database contains a real table row, so the
archive includes table data rather than only a schema.

Requires the test Postgres cluster from `make test-db-up`; skips (or fails
under `REQUIRE_POSTGRES_TESTS=1`) when `TEST_DATABASE_URL` is unset — see
`tests/migration/conftest.py`.

The `capture_dump_evidence` assertions (checksum, size, decompression
proved/unproved) need only Postgres and run regardless of Foundation. The
required CI D16 conformance step supplies exact Foundation source and refuses
skipped or missing tests; a local run without it may still skip. Each
`to_backup_record` call is wrapped in `try/except FoundationUnavailable`,
converted to `pytest.skip` on catch: `to_backup_record` raises
`FoundationUnavailable` (a plain `RuntimeError`) when Foundation is absent
or incompatible, and an uncaught `RuntimeError` inside a test function is a
FAIL, not a SKIP — so without this guard, the Postgres-only evidence this
file proves would be reported as a failure alongside the genuinely
separate, currently-open question of whether Foundation is installed at
all.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from vendor_cp.recovery.dump_evidence import (
    FoundationUnavailable,
    capture_dump_evidence,
    to_backup_record,
)


def _libpq_url(sqlalchemy_url: str) -> str:
    """`postgresql+psycopg://...` -> `postgresql://...`.

    `scratch_db` yields a SQLAlchemy DSN (driver suffix included, for
    `create_engine`); `pg_dump`/`pg_restore` speak plain libpq connection
    strings and do not understand the `+psycopg` dialect suffix.
    """
    return sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://", 1)


def test_capture_dump_evidence_proves_a_real_custom_format_dump(
    scratch_db: str, tmp_path: Path
) -> None:
    pg_dump = shutil.which("pg_dump")
    assert pg_dump is not None, (
        "pg_dump is not on PATH; this suite must run inside an environment "
        "with the PostgreSQL client tools installed, the same as the "
        "`deploy_production.sh` host this test's flags mirror"
    )

    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(
                text("CREATE TABLE public.d16_archive_probe (value text NOT NULL)")
            )
            conn.execute(
                text(
                    "INSERT INTO public.d16_archive_probe (value) VALUES ('data-block')"
                )
            )
    finally:
        engine.dispose()

    dump_path = tmp_path / "database.dump"
    # Same two flags `deploy_production.sh` uses for the database dump
    # (`--dbname`, `--format custom`) — no `--no-owner`, no `--no-privileges`
    # — with only the connection target swapped for the scratch DB's own
    # libpq URI in place of the production host's local-socket `$POSTGRES_DB`.
    with dump_path.open("wb") as output:
        result = subprocess.run(  # noqa: S603 - argv list, fixed flags, no shell
            [pg_dump, "--dbname", _libpq_url(scratch_db), "--format", "custom"],
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    assert result.returncode == 0, (
        f"pg_dump failed (exit {result.returncode}): "
        f"{result.stderr.decode('utf-8', 'replace')}"
    )
    assert dump_path.stat().st_size > 0, "pg_dump wrote an empty archive"

    evidence = capture_dump_evidence(dump_path)

    assert evidence.decompression_proved is True
    assert evidence.size_bytes == dump_path.stat().st_size

    independent = hashlib.sha256(dump_path.read_bytes()).hexdigest()
    assert evidence.checksum == independent

    try:
        good_record = to_backup_record(
            evidence,
            dataset="primary",
            artefact_class="data_export",
            evidence_origin="local_artefact",
        )
    except FoundationUnavailable as error:
        pytest.skip(
            "dotmac-deployment-foundation is not yet a declared CP dependency "
            f"(an open decision) — the capture_dump_evidence proof above holds "
            f"regardless; only the to_backup_record mapping needs Foundation: "
            f"{error}"
        )
    assert good_record.assurance.value == "verified"


def test_capture_dump_evidence_reports_a_corrupt_dump_as_unproved_not_a_refusal(
    scratch_db: str, tmp_path: Path
) -> None:
    """A present-but-corrupt dump is a FAILED check, not a missing tool: it
    must surface as `decompression_proved=False` on an ordinarily-returned
    `DumpEvidence`, never `PgRestoreUnavailable`.

    A 100-byte prefix of a real archive fails `pg_restore --file /dev/null`
    at least as certainly as it failed the old `--list` check: `--file`
    reads everything `--list` reads (the header and TOC) and then goes on to
    read the data blocks, so a file too short to even carry a valid header
    is rejected before decompression would begin."""
    pg_dump = shutil.which("pg_dump")
    assert pg_dump is not None

    good_path = tmp_path / "good.dump"
    with good_path.open("wb") as output:
        result = subprocess.run(  # noqa: S603 - argv list, fixed flags, no shell
            [pg_dump, "--dbname", _libpq_url(scratch_db), "--format", "custom"],
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")

    # Truncate a COPY to the first 100 bytes — present, non-empty, and not a
    # valid custom-format archive.
    corrupt_path = tmp_path / "corrupt.dump"
    corrupt_path.write_bytes(good_path.read_bytes()[:100])

    evidence = capture_dump_evidence(corrupt_path)

    assert evidence.decompression_proved is False
    assert evidence.size_bytes == 100

    try:
        bad_record = to_backup_record(
            evidence,
            dataset="primary",
            artefact_class="data_export",
            evidence_origin="local_artefact",
        )
    except FoundationUnavailable as error:
        pytest.skip(
            "dotmac-deployment-foundation is not yet a declared CP dependency "
            f"(an open decision) — the capture_dump_evidence proof above holds "
            f"regardless; only the to_backup_record mapping needs Foundation: "
            f"{error}"
        )
    assert bad_record.assurance.value == "completed"
