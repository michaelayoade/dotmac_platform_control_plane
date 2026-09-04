"""The production table inventory: how many rows, never which.

Designed now, executed at step 8 against `vendor-cp-prod` as the production
observation and bundle-source host. Nothing here contacts a host on its own —
it receives a connection and reads.

## Why it exists

`data_governance` needs a closed inventory over every platform AND tenant-plane
table, and the emptiness of the seventeen tenant-plane tables cannot be inferred
from source. This assembly uses `get_platform_db` in ten files and
`get_db`/`tenant_session`/`set_tenant` in none — but **unused is a fact about
code and empty is a fact about a database**, and only the second is evidence
about data. A table nothing reads today may hold rows written by an earlier
version, a migration backfill, or a path since removed.

A migrated scratch database is empty BY CONSTRUCTION, so measuring it proves
nothing about production. That is the whole reason this runs where it does.

## How many, never which

The inventory answers a cardinality and nothing else. A count is a fact about
governance; a row is the data being governed, and an inventory that carried one
would be exfiltrating the thing it exists to protect. The only per-table
statement this module issues is a `count(*)`, and
`tests/unit/test_table_inventory.py` reads the module's own SQL to hold it to
that rather than trusting this paragraph.

## UNKNOWN is a member of the type, not an absent value

A table that could not be read is not an empty table. Rendering a timeout as `0`
would justify retiring a table that is full — the same failure this fleet
removed from relay health, arriving somewhere new. `ReadOutcome.UNKNOWN` is a
member, `row_count` is `None` exactly when the outcome is UNKNOWN, and the
dataclass refuses any other combination at construction. There is no way to
express "zero rows, because I could not look".

## Bound, not signed

The five binding terms are PROVENANCE recorded with the observation: an
inventory that does not name the migration heads it was taken at cannot be
compared with a later one, and a count with no database identity could have come
from anywhere.

Binding is not signing. Nothing here produces a signed envelope and nothing here
reaches for a mint identity — in particular not the target-execution observation
signer, whose purpose is a different one. If this observation should also be
signed, that is a sixth signing purpose and a decision for Michael rather than
something to invent here.

## A clean result is an input, never a conclusion

A zero-row production result does NOT make `data_governance` inapplicable. It
informs retirement decisions about specific tables; the remaining platform data
still needs `PlatformDataGovernanceV1`, which is built on that assumption
regardless of what this reports.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final, Protocol

__all__ = [
    "INVENTORY_QUERY_VERSION",
    "ObservationBinding",
    "ReadOutcome",
    "TableInventoryObservation",
    "TableObservation",
    "observe_table_inventory",
]

#: Bumped whenever the statements below change. Two observations are comparable
#: only if the same query produced them: a count taken by a query that excluded
#: a schema is not a smaller inventory, it is a different question.
INVENTORY_QUERY_VERSION: Final = "table_inventory.v1"

#: Every table in every non-system schema, ordered so two runs are diffable
#: without sorting them afterwards. `pg_class`/`pg_namespace` rather than
#: `information_schema`, which shows only what the CURRENT ROLE can see and
#: would silently shrink the inventory for a less privileged observer.
TABLE_INVENTORY_SQL: Final = """
SELECT n.nspname AS schema, c.relname AS table
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
 WHERE c.relkind = 'r'
   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname NOT LIKE 'pg_toast%'
 ORDER BY n.nspname, c.relname
"""

#: The ONLY per-table statement. A cardinality, never a column.
ROW_COUNT_SQL: Final = 'SELECT count(*) FROM "{schema}"."{table}"'

#: Read-only, and enforced by the server rather than by intent. A transaction
#: the database refuses writes in cannot be talked into one by a later edit.
READ_ONLY_SQL: Final = "SET TRANSACTION READ ONLY"

#: A table too large to count inside this budget yields UNKNOWN rather than
#: hanging the observation or returning a partial answer.
STATEMENT_TIMEOUT_SQL: Final = "SET LOCAL statement_timeout = '{ms}ms'"


class ReadOutcome(StrEnum):
    """Whether a table's cardinality was established. UNKNOWN is a member."""

    COUNTED = "counted"
    #: Unreadable, timed out, or refused. NEVER rendered as a count.
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TableObservation:
    """One table's cardinality, or the explicit absence of one."""

    schema: str
    table: str
    outcome: ReadOutcome
    #: Set exactly when `outcome` is COUNTED. The constructor refuses every
    #: other combination, so "zero rows because I could not look" cannot be
    #: expressed at all.
    row_count: int | None = None

    def __post_init__(self) -> None:
        if self.outcome is ReadOutcome.COUNTED:
            if not isinstance(self.row_count, int) or self.row_count < 0:
                raise ValueError(
                    f"{self.schema}.{self.table}: a counted table must carry a "
                    "non-negative count"
                )
        elif self.row_count is not None:
            raise ValueError(
                f"{self.schema}.{self.table}: an UNKNOWN table may not carry a "
                "count. A number beside 'I could not read it' is the exact "
                "confusion this type exists to prevent"
            )

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.table}"


@dataclass(frozen=True, slots=True)
class ObservationBinding:
    """What this observation is OF. Five terms, none optional.

    An inventory that does not name the migration heads it was taken at cannot
    be compared with a later one, and a count with no database identity could
    have come from anywhere.
    """

    database_identity: str
    image_reference: str
    source_revision: str
    migration_heads: tuple[str, ...]
    observed_at: datetime
    query_version: str = INVENTORY_QUERY_VERSION

    def __post_init__(self) -> None:
        blank = [
            name
            for name in ("database_identity", "image_reference", "source_revision")
            if not str(getattr(self, name)).strip()
        ]
        if blank:
            raise ValueError(f"an observation binding omits {sorted(blank)}")
        if not self.migration_heads:
            raise ValueError(
                "an observation with no migration heads names no schema state, "
                "so no later inventory can be compared with it"
            )
        if self.observed_at.tzinfo is None:
            raise ValueError("an observation timestamp must carry its timezone")


@dataclass(frozen=True, slots=True)
class TableInventoryObservation:
    """The complete inventory, bound to what it is an observation of."""

    binding: ObservationBinding
    tables: tuple[TableObservation, ...]

    @property
    def unknown(self) -> tuple[TableObservation, ...]:
        return tuple(t for t in self.tables if t.outcome is ReadOutcome.UNKNOWN)

    @property
    def complete(self) -> bool:
        """Whether every table answered. A partial inventory is still an
        observation; it is just not one a retirement decision may rest on."""
        return not self.unknown


class _Result(Protocol):
    """What a driver hands back. Typed narrowly so the reader below cannot
    quietly start using a richer result than it declares."""

    def __iter__(self) -> Iterator[Sequence[object]]: ...

    def scalar_one(self) -> object: ...


class _Connection(Protocol):
    """The narrowest shape this needs. It reads; it cannot be handed a session
    whose transaction boundary it might commit."""

    def execute(self, statement: object) -> _Result: ...


def observe_table_inventory(
    connection: _Connection,
    *,
    binding: ObservationBinding,
    statement_timeout_ms: int = 30_000,
) -> TableInventoryObservation:
    """Derive the complete inventory in a READ ONLY transaction.

    RECEIVES a connection; it opens none, so it cannot reach a host that was not
    already named. The transaction is marked read-only on the server, which is a
    refusal rather than a promise: a later edit that tried to write would be
    stopped by PostgreSQL rather than by review.

    A table that cannot be counted — a privilege refusal, a lock wait, a
    statement timeout — is recorded UNKNOWN. It is never recorded as zero.
    """
    from sqlalchemy import text  # noqa: PLC0415 - kept off the import path

    connection.execute(text(READ_ONLY_SQL))
    listed = connection.execute(text(TABLE_INVENTORY_SQL))
    rows = [(str(row[0]), str(row[1])) for row in listed]

    observations: list[TableObservation] = []
    for schema, table in rows:
        try:
            connection.execute(
                text(STATEMENT_TIMEOUT_SQL.format(ms=int(statement_timeout_ms)))
            )
            counted = connection.execute(
                text(ROW_COUNT_SQL.format(schema=schema, table=table))
            )
            raw = counted.scalar_one()
            if not isinstance(raw, int):
                # A count that is not a number is not a count. Falls through to
                # UNKNOWN rather than being coerced into one.
                raise TypeError(f"{schema}.{table} returned a non-integer count")
            value = raw
        except Exception:  # noqa: BLE001 - every failure is the same answer
            observations.append(TableObservation(schema, table, ReadOutcome.UNKNOWN))
            continue
        observations.append(TableObservation(schema, table, ReadOutcome.COUNTED, value))

    return TableInventoryObservation(binding=binding, tables=tuple(observations))
