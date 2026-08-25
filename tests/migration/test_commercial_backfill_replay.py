"""PostgreSQL canary for backfill rehearsal replay-safety.

The claim: applying the repair statements twice leaves identical state and
produces an identical report. It is a claim about a real database — `IF NOT
EXISTS`, `ON CONFLICT`, a guarded `DO` block and a `char(64)` primary key all
behave in PostgreSQL and nowhere else — so CI exercises them here rather than
the durable governance rule recording a run result. It runs under the same
`scratch_db` fixture and the same
`REQUIRE_POSTGRES_TESTS` gate as every other Postgres suite in this repository.

The design that makes it true is in `vendor_cp.commercial_backfill.shadow`: the
shadow table has no timestamp column and no surrogate key, so a row is its
fingerprint plus a handful of category names and two runs cannot differ.

The privilege half is checked here too, because it is the one condition the
final-DML-grant gate records as discharged: after a repair, Vendor's ONLINE role
holds nothing at all on the rehearsal schema. Verified as an EFFECTIVE outcome
against `information_schema`, not by reading the SQL back.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from vendor_cp.commercial_backfill import (
    CohortRules,
    SourceKind,
    SourceRow,
    plan,
    render,
    repair_statements,
)
from vendor_cp.commercial_backfill.shadow import (
    RUNTIME_ROLE,
    SHADOW_SCHEMA,
    SHADOW_TABLE,
)

RULES = CohortRules(declared_product_codes=frozenset({"acme"}))


def _rows() -> tuple[SourceRow, ...]:
    """A cohort with one row per bucket, so a replay has something to preserve
    in each. A rehearsal over three mapped rows proves the easy third."""
    return (
        SourceRow(
            kind=SourceKind.AGREEMENT_LINE,
            fingerprint="a" * 64,
            amount="10.00",
            currency_code="NGN",
            product_code="acme",
            agreement_status="ACTIVE",
            content_hash="c" * 64,
            term_start=date(2026, 1, 1),
            term_end_exclusive=date(2027, 1, 1),
        ),
        SourceRow(
            kind=SourceKind.AGREEMENT_LINE,
            fingerprint="b" * 64,
            amount="10.000",
            currency_code="NGN",
            product_code="acme",
            agreement_status="ACTIVE",
            content_hash="c" * 64,
            term_start=date(2026, 1, 1),
            term_end_exclusive=date(2027, 1, 1),
        ),
        SourceRow(
            kind=SourceKind.OFFER_VERSION,
            fingerprint="d" * 64,
            amount="10.00",
            currency_code="NGN",
            product_code="acme",
            referenced_by_cohort_line=False,
        ),
    )


@pytest.fixture
def engine(scratch_db: str) -> Iterator[Engine]:
    """The migrator role, which is how every privileged statement in this
    repository already runs. Nothing here connects as the online role, and the
    command that emits these statements connects at all."""
    made = create_engine(scratch_db, isolation_level="AUTOCOMMIT")
    try:
        yield made
    finally:
        made.dispose()


def _apply(engine: Engine, statements: tuple[str, ...]) -> None:
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _state(engine: Engine) -> list[tuple[str, ...]]:
    """The whole shadow, ordered, as comparable tuples."""
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                f"SELECT fingerprint, source_kind, bucket, exclusion, "
                f"blocking_dimension, product_identity, currency, cadence, "
                f"proration, frozen_content FROM {SHADOW_SCHEMA}.{SHADOW_TABLE} "
                "ORDER BY fingerprint"
            )
        ).all()
    return [tuple(str(value) for value in row) for row in rows]


def test_the_repair_replays_without_changing_anything(engine: Engine) -> None:
    """The property, stated as a test: apply, apply again, compare.

    A `recorded_at` column would fail this — every replay would be a diff, and
    the first person comparing two rehearsals would have to explain it away.
    """
    outcome = plan(_rows(), RULES, enumerated=frozenset(SourceKind))
    statements = repair_statements(outcome.verdicts)

    _apply(engine, statements)
    first = _state(engine)
    _apply(engine, statements)
    second = _state(engine)

    assert first == second
    assert len(first) == len(_rows())


def test_the_report_is_identical_across_replays(engine: Engine) -> None:
    """Row-count parity is not semantic parity, and this is the same distinction
    applied to a rehearsal: identical rows are not enough — the plan the rows
    came from must render identically too."""
    first = plan(_rows(), RULES, enumerated=frozenset(SourceKind))
    _apply(engine, repair_statements(first.verdicts))
    second = plan(_rows(), RULES, enumerated=frozenset(SourceKind))
    _apply(engine, repair_statements(second.verdicts))
    assert render(first.report) == render(second.report)


def test_a_row_leaving_the_cohort_leaves_the_shadow(engine: Engine) -> None:
    """A repair removes drift as well as adding rows. A reconciler that only
    inserted would let a stale verdict survive every future run, which is the
    condition the whole exercise exists to detect."""
    full = plan(_rows(), RULES, enumerated=frozenset(SourceKind))
    _apply(engine, repair_statements(full.verdicts))
    assert len(_state(engine)) == len(_rows())

    smaller = plan(_rows()[:1], RULES, enumerated=frozenset(SourceKind))
    _apply(engine, repair_statements(smaller.verdicts))
    remaining = _state(engine)
    assert len(remaining) == 1
    assert remaining[0][0] == "a" * 64


def test_an_empty_cohort_clears_the_shadow(engine: Engine) -> None:
    """`NOT IN ()` is not valid SQL and skipping the delete would leave the
    previous run behind, so the empty case takes its own branch — and its own
    test, because a branch nothing exercises is a branch nobody has run."""
    _apply(
        engine, repair_statements(plan(_rows(), RULES, enumerated=frozenset()).verdicts)
    )
    assert _state(engine)
    _apply(engine, repair_statements(()))
    assert _state(engine) == []


def test_the_repair_grants_the_online_role_nothing(engine: Engine) -> None:
    """The final-DML-grant gate's one discharged condition, verified as an
    EFFECTIVE outcome rather than by reading the emitted SQL back.

    `platform_api` is Vendor's online role. After a repair it holds no privilege
    on the rehearsal schema and none on its table — which is what "this work
    grants Vendor's runtime role nothing" has to mean to be worth stating.
    """
    outcome = plan(_rows(), RULES, enumerated=frozenset(SourceKind))
    _apply(engine, repair_statements(outcome.verdicts))
    with engine.connect() as connection:
        table_privileges = connection.execute(
            text(
                "SELECT privilege_type FROM information_schema.table_privileges "
                "WHERE grantee = :role AND table_schema = :schema"
            ),
            {"role": RUNTIME_ROLE, "schema": SHADOW_SCHEMA},
        ).scalars()
        schema_usage = connection.execute(
            text(
                "SELECT has_schema_privilege(:role, :schema, 'USAGE') "
                "OR has_schema_privilege(:role, :schema, 'CREATE')"
            ),
            {"role": RUNTIME_ROLE, "schema": SHADOW_SCHEMA},
        ).scalar_one()
    assert sorted(table_privileges) == []
    assert schema_usage is False


def test_the_privilege_check_can_see_a_granted_privilege(engine: Engine) -> None:
    """SENSITIVITY. "The role holds nothing" and "the query found nothing" are
    the same assertion until this separates them — the shape ADR-0006 § 3 used
    for `mod_ealloc`, verified in both directions."""
    outcome = plan(_rows(), RULES, enumerated=frozenset(SourceKind))
    _apply(engine, repair_statements(outcome.verdicts))
    with engine.begin() as connection:
        connection.execute(
            text(f"GRANT USAGE ON SCHEMA {SHADOW_SCHEMA} TO {RUNTIME_ROLE}")
        )
        connection.execute(
            text(f"GRANT SELECT ON {SHADOW_SCHEMA}.{SHADOW_TABLE} TO {RUNTIME_ROLE}")
        )
    with engine.connect() as connection:
        granted = connection.execute(
            text(
                "SELECT privilege_type FROM information_schema.table_privileges "
                "WHERE grantee = :role AND table_schema = :schema"
            ),
            {"role": RUNTIME_ROLE, "schema": SHADOW_SCHEMA},
        ).scalars()
    assert sorted(granted) == ["SELECT"]

    # And the repair takes it away again, which is the reconciler's own claim.
    _apply(engine, repair_statements(outcome.verdicts))
    with engine.connect() as connection:
        after = connection.execute(
            text(
                "SELECT privilege_type FROM information_schema.table_privileges "
                "WHERE grantee = :role AND table_schema = :schema"
            ),
            {"role": RUNTIME_ROLE, "schema": SHADOW_SCHEMA},
        ).scalars()
    assert sorted(after) == []
