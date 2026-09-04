"""The inventory answers HOW MANY, never WHICH — and never zero for "unknown".

Two properties carry this design, and both are enforced by the type rather than
by the reader's care:

* a table that could not be read is `UNKNOWN`, and the combination "zero rows,
  because I could not look" cannot be constructed at all;
* the only per-table statement is a `count(*)`, read out of the module's own SQL
  rather than taken from its docstring.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vendor_cp.deployment.table_inventory import (
    INVENTORY_QUERY_VERSION,
    ROW_COUNT_SQL,
    TABLE_INVENTORY_SQL,
    ObservationBinding,
    ReadOutcome,
    TableInventoryObservation,
    TableObservation,
    observe_table_inventory,
)

MODULE = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "vendor_cp"
    / "deployment"
    / "table_inventory.py"
)

BINDING = ObservationBinding(
    database_identity="vendor_control_plane@6100000000000000000",
    image_reference="ghcr.io/example@sha256:" + "a" * 64,
    source_revision="b" * 40,
    migration_heads=("0028_machine_attribution", "v019_relay_heartbeat"),
    observed_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
)


# ── UNKNOWN is a member, and zero cannot impersonate it ─────────────────────


def test_an_unknown_table_may_not_carry_a_count() -> None:
    """A number beside "I could not read it" is the exact confusion this type
    exists to prevent. Rendering a timeout as `0` would justify retiring a table
    that is full."""
    with pytest.raises(ValueError, match="may not carry a count"):
        TableObservation("public", "t", ReadOutcome.UNKNOWN, 0)


def test_a_counted_table_must_carry_a_count() -> None:
    """The other direction: COUNTED with no number is an outcome that says
    nothing, and it would read as a successful observation."""
    with pytest.raises(ValueError, match="non-negative count"):
        TableObservation("public", "t", ReadOutcome.COUNTED)


def test_zero_is_a_legitimate_count() -> None:
    """NON-VACUITY for both refusals. An empty table is a real measurement and
    must remain expressible — the point is that it cannot be reached by
    accident."""
    empty = TableObservation("public", "t", ReadOutcome.COUNTED, 0)
    assert empty.row_count == 0
    assert empty.outcome is ReadOutcome.COUNTED


def test_an_unreadable_table_is_unknown_rather_than_absent_or_zero() -> None:
    """Driven through the reader with a table that raises on count."""

    class _Result:
        def __init__(self, rows: list[tuple[str, str]] | None = None) -> None:
            self._rows = rows or []

        def __iter__(self):  # noqa: ANN204
            return iter(self._rows)

        def scalar_one(self) -> object:
            raise RuntimeError("permission denied")

    class _Connection:
        def execute(self, statement: object) -> _Result:
            rendered = str(statement)
            if "pg_catalog.pg_class" in rendered:
                return _Result([("public", "unreadable")])
            return _Result()

    observation = observe_table_inventory(_Connection(), binding=BINDING)  # type: ignore[arg-type]
    assert len(observation.tables) == 1
    only = observation.tables[0]
    assert only.outcome is ReadOutcome.UNKNOWN
    assert only.row_count is None
    assert observation.complete is False
    assert observation.unknown == (only,)


def test_a_readable_table_is_counted() -> None:
    """NON-VACUITY for the test above: a reader that returned UNKNOWN for
    everything would pass it while measuring nothing."""

    class _Result:
        def __init__(self, rows: list[tuple[str, str]] | None = None) -> None:
            self._rows = rows or []

        def __iter__(self):  # noqa: ANN204
            return iter(self._rows)

        def scalar_one(self) -> object:
            return 7

    class _Connection:
        def execute(self, statement: object) -> _Result:
            if "pg_catalog.pg_class" in str(statement):
                return _Result([("public", "vendor_accounts")])
            return _Result()

    observation = observe_table_inventory(_Connection(), binding=BINDING)  # type: ignore[arg-type]
    assert observation.tables[0].row_count == 7
    assert observation.complete is True


# ── how many, never which ───────────────────────────────────────────────────


def test_the_only_per_table_statement_is_a_count() -> None:
    """Read out of the module's own SQL, because a docstring cannot be wrong in
    a way CI notices. A count is a fact about governance; a row is the data
    being governed."""
    assert "count(*)" in ROW_COUNT_SQL
    assert "SELECT count(*)" in ROW_COUNT_SQL
    # No column list, no star-select, no ORDER BY that could imply row access.
    assert "SELECT *" not in ROW_COUNT_SQL


def test_the_module_issues_no_statement_that_could_return_a_row() -> None:
    """A stronger form of the same check, over every SQL constant in the file.

    The inventory query reads the CATALOGUE, which is metadata; the per-table
    query is a cardinality. Nothing else may select from a governed table.
    """
    source = MODULE.read_text(encoding="utf-8")
    selects = re.findall(r"SELECT\s+(.+?)\s+FROM", source, re.S | re.I)
    assert selects, "no SELECT found, so this check reads nothing"
    for projection in selects:
        collapsed = " ".join(projection.split())
        assert collapsed in {
            "count(*)",
            "n.nspname AS schema, c.relname AS table",
        }, collapsed


def test_the_inventory_reads_the_catalogue_not_information_schema() -> None:
    """`information_schema` shows only what the current role can see, so a less
    privileged observer would get a SMALLER inventory that looked complete."""
    assert "pg_catalog.pg_class" in TABLE_INVENTORY_SQL
    assert "information_schema" not in TABLE_INVENTORY_SQL.replace(
        "NOT IN ('pg_catalog', 'information_schema')", ""
    )


# ── the binding is provenance, and none of it is optional ───────────────────


@pytest.mark.parametrize(
    "field",
    ["database_identity", "image_reference", "source_revision"],
)
def test_a_binding_with_a_blank_term_is_refused(field: str) -> None:
    import dataclasses

    with pytest.raises(ValueError, match="omits"):
        dataclasses.replace(BINDING, **{field: "  "})


def test_a_binding_with_no_migration_heads_is_refused() -> None:
    """An inventory that does not name the schema state it was taken at cannot
    be compared with a later one, which is the only thing an inventory is for."""
    import dataclasses

    with pytest.raises(ValueError, match="migration heads"):
        dataclasses.replace(BINDING, migration_heads=())


def test_a_naive_timestamp_is_refused() -> None:
    import dataclasses

    with pytest.raises(ValueError, match="timezone"):
        dataclasses.replace(BINDING, observed_at=datetime(2026, 9, 4, 12, 0))


def test_the_binding_carries_the_query_version() -> None:
    """Two observations are comparable only if the same query produced them: a
    count taken by a query that excluded a schema is not a smaller inventory, it
    is a different question."""
    assert BINDING.query_version == INVENTORY_QUERY_VERSION
    assert INVENTORY_QUERY_VERSION.startswith("table_inventory.")


def test_the_observation_is_bound_and_not_signed() -> None:
    """Binding is not signing. Nothing here produces an envelope and nothing
    reaches for a mint identity — in particular not the target-execution
    observation signer, whose purpose is a different one.

    Asserted on the field names so a signature field added later is a visible
    decision rather than an import nobody reviewed.
    """
    import dataclasses

    names = {f.name for f in dataclasses.fields(TableInventoryObservation)}
    assert names == {"binding", "tables"}
    source = MODULE.read_text(encoding="utf-8")
    assert "signers" not in source
    assert "sign(" not in source


def test_each_count_is_wrapped_in_its_own_savepoint() -> None:
    """One refusal must not abort the transaction and turn every later table
    into a false UNKNOWN. Asserted on the statement SEQUENCE, which is the only
    place the isolation is visible from here."""
    issued: list[str] = []

    class _Result:
        def __init__(self, rows: list[tuple[str, str]] | None = None) -> None:
            self._rows = rows or []

        def __iter__(self):  # noqa: ANN204
            return iter(self._rows)

        def scalar_one(self) -> object:
            raise RuntimeError("permission denied")

    class _Connection:
        def execute(self, statement: object) -> _Result:
            rendered = str(statement)
            issued.append(rendered)
            if "pg_catalog.pg_class" in rendered:
                return _Result([("public", "a"), ("public", "b")])
            return _Result()

    observe_table_inventory(_Connection(), binding=BINDING)  # type: ignore[arg-type]

    assert issued.count("SAVEPOINT table_count") == 2
    assert issued.count("ROLLBACK TO SAVEPOINT table_count") == 2
    # And the rollback follows the failed count rather than preceding it.
    first_savepoint = issued.index("SAVEPOINT table_count")
    first_rollback = issued.index("ROLLBACK TO SAVEPOINT table_count")
    assert first_savepoint < first_rollback
