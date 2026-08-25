"""The rehearsal shadow, and idempotent repair SQL that grants nothing.

A rehearsal needs somewhere to put per-row verdicts so a half-finished run can
be repaired rather than reasoned about. This module owns that place and the
statements that repair it. It is for **test and development databases only**,
and three separate properties keep it there.

## 1. It is not part of any lineage, and not a Vendor table

The shadow schema is created by the repair statements themselves, in a
disposable database, by the migrator role. No revision in the vendor lineage
creates it, no model declares it — there is no `__tablename__` anywhere in this
package — and it therefore never appears in a production database at all. The
declared vendor-owned table set in `vendor_cp.cutover_readiness` does not move,
because nothing here is a table this assembly owns.

## 2. Nothing here connects, and nothing here grants

This module returns SQL TEXT. It opens no connection, holds no DSN and reads no
environment variable — deny case D1 keeps the kernel the only owner of an
engine, and the connection allowlist in `tests/architecture/test_deny_cases.py`
is empty and stays empty. An operator applies the statements under the migrator
role; the migration-tier rehearsal applies them through the test harness's own
connection.

And there is no `GRANT` in any statement this module emits. The opposite: the
repair REVOKEs everything from the runtime role on the rehearsal schema, guarded
so it is a no-op where that role does not exist. Vendor's runtime role gains
nothing from this work, which is the invariant the final-DML-grant gate carries.

## 3. Replay-safety is designed, not hoped for

The table has **no timestamp column and no surrogate key**. That is the whole
trick: a row is its fingerprint plus a handful of category names, so two runs
over the same source rows produce byte-identical state and a byte-identical
report. A `recorded_at` column would make every replay a diff, and the first
person to compare two rehearsals would have to explain it away.

The statements are idempotent in both directions: rows whose fingerprint is no
longer in the cohort are DELETEd, and rows that are get an upsert. Applied twice
in a row, the second application changes nothing.

## Every value that reaches a statement comes from a closed set

There is no free text anywhere in the emitted SQL. A value is either a member
NAME from `vocabulary.py` — upper-case ASCII and underscores — or a 64-character
lowercase hex fingerprint, and `_literal` refuses anything else before it is
quoted. That is a stronger property than escaping: nothing that could need
escaping can reach the statement in the first place.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from vendor_cp.commercial_backfill.cohort import RowVerdict, SourceRow
from vendor_cp.commercial_backfill.vocabulary import DIMENSION_ORDER, Dimension

#: The rehearsal namespace. Deliberately not `public` and deliberately not a
#: `mod_*` name: `public` is the kernel's and the host assembly's, and `mod_*`
#: belongs to an independently released module with a registered lineage. This
#: is neither — it is scratch space that only ever exists in a disposable
#: database.
SHADOW_SCHEMA: Final[str] = "bf_rehearsal"

#: The one table in it.
SHADOW_TABLE: Final[str] = "shadow_verdicts"

#: Vendor's ONLINE role. Named here only so the repair can revoke from it. The
#: repair never grants it anything, and `tests/architecture
#: /test_commercial_backfill.py` fails the build if the word GRANT appears in
#: anything this module emits.
RUNTIME_ROLE: Final[str] = "platform_api"

#: Per-dimension outcome columns, in the declared dimension order so the column
#: list, the insert list and the conflict-update list cannot drift apart.
DIMENSION_COLUMNS: Final[dict[Dimension, str]] = {
    Dimension.PRODUCT_IDENTITY: "product_identity",
    Dimension.CURRENCY: "currency",
    Dimension.CADENCE: "cadence",
    Dimension.PRORATION: "proration",
    Dimension.FROZEN_CONTENT: "frozen_content",
}

COLUMNS: Final[tuple[str, ...]] = (
    "fingerprint",
    "source_kind",
    "bucket",
    "exclusion",
    "blocking_dimension",
    *(DIMENSION_COLUMNS[dimension] for dimension in DIMENSION_ORDER),
)

_MEMBER_NAME = re.compile(r"[A-Z][A-Z_]*")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


class UnsafeShadowValue(ValueError):
    """A value that is neither a declared member name nor a fingerprint."""


def _literal(value: str | None) -> str:
    """Quote a value that has already been proven to come from a closed set.

    FAIL CLOSED. Nothing that could need escaping can get this far, so this is
    not an escaping function — it is a refusal with quotes on the end.
    """
    if value is None:
        return "NULL"
    if not (_MEMBER_NAME.fullmatch(value) or _FINGERPRINT.fullmatch(value)):
        raise UnsafeShadowValue("only declared member names and fingerprints")
    return f"'{value}'"


#: `CREATE SCHEMA`/`CREATE TABLE` are `IF NOT EXISTS`, so a repair run against
#: an already-prepared rehearsal is a no-op rather than an error — which is what
#: lets the same statements both prepare and repair.
CREATE_SQL: Final[tuple[str, ...]] = (
    f"CREATE SCHEMA IF NOT EXISTS {SHADOW_SCHEMA}",
    f"""CREATE TABLE IF NOT EXISTS {SHADOW_SCHEMA}.{SHADOW_TABLE} (
    fingerprint        char(64) PRIMARY KEY,
    source_kind        text NOT NULL,
    bucket             text NOT NULL,
    exclusion          text,
    blocking_dimension text,
    product_identity   text,
    currency           text,
    cadence            text,
    proration          text,
    frozen_content     text
)""",
)

#: Guarded so it is a no-op in a database that has no runtime role — a
#: workstation-shaped disposable database often does not. An unguarded REVOKE
#: would fail there, and the natural "fix" is to delete the REVOKE.
REVOKE_SQL: Final[str] = f"""DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RUNTIME_ROLE}') THEN
        REVOKE ALL ON SCHEMA {SHADOW_SCHEMA} FROM {RUNTIME_ROLE};
        REVOKE ALL ON ALL TABLES IN SCHEMA {SHADOW_SCHEMA} FROM {RUNTIME_ROLE};
    END IF;
END
$$"""


def _row_values(row: SourceRow, verdict: RowVerdict) -> tuple[str, ...]:
    outcomes = dict(verdict.outcomes)
    return (
        _literal(row.fingerprint),
        _literal(row.kind.name),
        _literal(verdict.bucket.name),
        _literal(verdict.exclusion.name if verdict.exclusion else None),
        _literal(
            verdict.blocking_dimension.name if verdict.blocking_dimension else None
        ),
        *(
            _literal(outcomes[d].name if d in outcomes else None)
            for d in DIMENSION_ORDER
        ),
    )


def repair_statements(
    verdicts: Sequence[tuple[SourceRow, RowVerdict]],
) -> tuple[str, ...]:
    """Prepare-or-repair, idempotent, deterministic, and grant-free.

    Ordered by fingerprint so two runs emit identical text. Applied twice, the
    second application changes nothing: the delete removes what is already gone
    and the upsert writes what is already there.
    """
    table = f"{SHADOW_SCHEMA}.{SHADOW_TABLE}"
    statements = [*CREATE_SQL, REVOKE_SQL]

    ordered = sorted(verdicts, key=lambda pair: pair[0].fingerprint)
    keep = [_literal(row.fingerprint) for row, _ in ordered]
    if keep:
        statements.append(
            f"DELETE FROM {table} WHERE fingerprint NOT IN ({', '.join(keep)})"
        )
    else:
        # No cohort rows at all. An empty `NOT IN ()` is not valid SQL, and
        # skipping the delete would leave a previous run's rows behind — which
        # is the drift a repair exists to remove.
        statements.append(f"DELETE FROM {table}")

    columns = ", ".join(COLUMNS)
    updates = ", ".join(
        f"{column} = EXCLUDED.{column}" for column in COLUMNS if column != "fingerprint"
    )
    for row, verdict in ordered:
        values = ", ".join(_row_values(row, verdict))
        statements.append(
            f"INSERT INTO {table} ({columns}) VALUES ({values}) "
            f"ON CONFLICT (fingerprint) DO UPDATE SET {updates}"
        )
    return tuple(statements)


#: A read-only projection of the half of the cohort this assembly can actually
#: enumerate. `public.offer_versions` is a real table with a real model here.
#:
#: There is no counterpart for agreement lines, and that absence is the point:
#: the agreements module owns its own schema and this assembly holds no listing
#: surface over it, so inventing a SELECT against tables nobody here can name
#: would be guessing. It is reported as `AGREEMENT_LINE_NOT_ENUMERABLE` instead.
OFFER_VERSION_EXPORT_SQL: Final[str] = """SELECT
    encode(sha256(convert_to(
        coalesce(product_code, '') || '/' || offer_code || '/' || version::text,
        'UTF8')), 'hex') AS fingerprint,
    product_code,
    offer_code,
    version,
    amount,
    currency_code
FROM public.offer_versions
ORDER BY product_code, offer_code, version"""


__all__ = [
    "COLUMNS",
    "CREATE_SQL",
    "DIMENSION_COLUMNS",
    "OFFER_VERSION_EXPORT_SQL",
    "REVOKE_SQL",
    "RUNTIME_ROLE",
    "SHADOW_SCHEMA",
    "SHADOW_TABLE",
    "UnsafeShadowValue",
    "repair_statements",
]
