"""The inventory against a real database — including one that is NOT empty.

An inventory run against an empty scratch database reports zeros, and that proves
almost nothing: a collector that always returned zero would look identical. Since
the whole programme now turns on whether the legacy tables are empty, the reading
"empty" has to be one this tool could have contradicted.

So the load-bearing test here is the seeded one. Rows go in, and every fact the
inventory claims to report has to move.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from vendor_cp.approvals_inventory import (
    collect_legacy_estate,
    collect_module_readiness,
    render_evidence,
)
from vendor_cp.migrations import make_alembic_config

POLICY_CODE = "contract.activate"
SUBJECT_TYPE = "contract"


def _upgrade(url: str) -> None:
    command.upgrade(make_alembic_config(url), "heads")


@contextmanager
def _read_only(url: str) -> Iterator[object]:
    """Exactly how the CLI connects: a READ ONLY transaction."""
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            yield connection
    finally:
        engine.dispose()


def _inventory(url: str) -> dict:
    with _read_only(url) as connection:
        estate = collect_legacy_estate(connection)
        readiness = collect_module_readiness(connection)
    return json.loads(render_evidence(estate, readiness))


def _evidence_text(url: str) -> str:
    with _read_only(url) as connection:
        estate = collect_legacy_estate(connection)
        readiness = collect_module_readiness(connection)
    return render_evidence(estate, readiness)


def _seed(url: str, *, approvers: int = 2, subjects: int = 1) -> None:
    """Write a small legacy estate, as the legacy service would have."""
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO approval_policies "
                    "(id, policy_code, version, quorum, allow_self_approval) "
                    "VALUES (:id, :code, 1, 2, false)"
                ),
                {"id": str(uuid.uuid4()), "code": POLICY_CODE},
            )
            for subject in range(subjects):
                for _approver in range(approvers):
                    connection.execute(
                        text(
                            "INSERT INTO approval_records "
                            "(id, policy_code, policy_version, subject_type, "
                            "subject_id, content_hash, approver_id) VALUES "
                            "(:id, :code, 1, :stype, :sid, :hash, :approver)"
                        ),
                        {
                            "id": str(uuid.uuid4()),
                            "code": POLICY_CODE,
                            "stype": SUBJECT_TYPE,
                            "sid": f"subject-{subject}",
                            "hash": "a" * 64,
                            "approver": str(uuid.uuid4()),
                        },
                    )
    finally:
        engine.dispose()


# ── The empty reading ───────────────────────────────────────────────────────


def test_an_empty_estate_reports_zero(scratch_db: str) -> None:
    """The reading the programme is waiting on — meaningful only because the
    seeded test below shows it could have come out otherwise."""
    _upgrade(scratch_db)
    document = _inventory(scratch_db)

    legacy = document["payload"]["legacy_estate"]
    assert legacy["policies"]["row_count"] == 0
    assert legacy["records"]["row_count"] == 0
    assert legacy["is_empty"] is True
    assert legacy["records"]["distinct_approval_groups"] == 0
    assert legacy["policies"]["earliest_created_at"] is None


# ── NON-VACUITY: the same tool against a populated estate ───────────────────


def test_a_populated_estate_is_reported(scratch_db: str) -> None:
    """THE test. Every fact the inventory claims to report must move when rows
    exist — otherwise "empty" is just what this code always says."""
    _upgrade(scratch_db)
    _seed(scratch_db, approvers=2, subjects=3)

    legacy = _inventory(scratch_db)["payload"]["legacy_estate"]

    assert legacy["is_empty"] is False
    assert legacy["policies"]["row_count"] == 1
    assert legacy["policies"]["policy_codes"] == [POLICY_CODE]
    assert legacy["policies"]["distinct_quorums"] == [2]
    assert legacy["policies"]["allow_self_approval_values"] == [False]

    records = legacy["records"]
    assert records["row_count"] == 6
    assert records["subject_types"] == [SUBJECT_TYPE]
    # Three subjects, one content hash each: the GROUP is the unit a cutover
    # disposes of, and it is not the row count.
    assert records["distinct_approval_groups"] == 3
    assert records["distinct_policy_references"] == 1
    assert records["distinct_approvers"] == 6

    # Stored extents are present and ordered, and are row facts rather than a
    # reading of the inventory's clock.
    assert records["earliest_created_at"] is not None
    assert records["latest_created_at"] is not None
    assert records["earliest_created_at"] <= records["latest_created_at"]
    assert records["earliest_created_at"].endswith("Z")


def test_the_empty_and_populated_readings_differ(scratch_db: str) -> None:
    """The two tests above could both pass against a tool that ignored the
    database. This pins that they disagree on the same scratch database."""
    _upgrade(scratch_db)
    before = _evidence_text(scratch_db)
    _seed(scratch_db)
    after = _evidence_text(scratch_db)
    assert before != after


# ── Determinism ─────────────────────────────────────────────────────────────


def test_two_runs_over_one_database_are_byte_identical(scratch_db: str) -> None:
    """Evidence you cannot diff is most of the way to no evidence. No run
    timestamp, sorted keys, sorted lists."""
    _upgrade(scratch_db)
    _seed(scratch_db, approvers=2, subjects=2)
    assert _evidence_text(scratch_db) == _evidence_text(scratch_db)


def test_the_digest_covers_the_payload(scratch_db: str) -> None:
    """The digest is a function of the payload, so tampering with a count
    without recomputing shows up."""
    import hashlib

    _upgrade(scratch_db)
    _seed(scratch_db)
    document = json.loads(_evidence_text(scratch_db))
    body = json.dumps(
        document["payload"],
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    expected = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert document["payload_digest"] == f"sha256:{expected}"


# ── Read-only, enforced by the database ─────────────────────────────────────


def test_the_read_only_transaction_refuses_a_write(scratch_db: str) -> None:
    """SENSITIVITY for the read-only premise the D1 exemption rests on: not that
    the code avoids writing, but that a write would be refused if it tried."""
    _upgrade(scratch_db)
    with _read_only(scratch_db) as connection, pytest.raises(DBAPIError) as failure:
        connection.execute(  # type: ignore[attr-defined]
            text(
                "INSERT INTO approval_policies "
                "(id, policy_code, version, quorum, allow_self_approval) "
                "VALUES (gen_random_uuid(), 'x', 1, 1, false)"
            )
        )
    assert "read-only" in str(failure.value).lower()


def test_the_inventory_leaves_the_estate_untouched(scratch_db: str) -> None:
    """Belt and braces: running it changes no count, in either system."""
    _upgrade(scratch_db)
    _seed(scratch_db, approvers=2, subjects=2)
    before = _inventory(scratch_db)["payload"]
    _inventory(scratch_db)
    after = _inventory(scratch_db)["payload"]
    assert before == after


# ── The module observation, kept separate ───────────────────────────────────


def test_module_readiness_holds_during_shadow(scratch_db: str) -> None:
    """Reported alongside the legacy estate, never compared with it."""
    _upgrade(scratch_db)
    readiness = _inventory(scratch_db)["payload"]["module_readiness"]

    assert readiness["ok"] is True
    for table in readiness["tables"]:
        assert table["exists"] is True
        assert table["row_count"] == 0
        assert table["online_role_can_select"] is True
        assert table["online_role_write_privileges"] == []
        assert table["tenant_role_privileges"] == []


def test_module_readiness_notices_a_granted_write(scratch_db: str) -> None:
    """SENSITIVITY: `ok` must be capable of being False, or it is decoration."""
    _upgrade(scratch_db)
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "GRANT INSERT ON mod_approvals.platform_approval_policies "
                    "TO platform_api"
                )
            )
        readiness = _inventory(scratch_db)["payload"]["module_readiness"]
        assert readiness["ok"] is False
        offending = [
            table
            for table in readiness["tables"]
            if table["online_role_write_privileges"]
        ]
        assert offending and offending[0]["online_role_write_privileges"] == ["INSERT"]
    finally:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "REVOKE INSERT ON mod_approvals.platform_approval_policies "
                    "FROM platform_api"
                )
            )
        engine.dispose()

    assert _inventory(scratch_db)["payload"]["module_readiness"]["ok"] is True
