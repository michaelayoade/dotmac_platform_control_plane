"""`request_fingerprint`, and the refusals `issuer_receipts.py` makes without
ever reaching Control or Approvals.

The live half — real Postgres, the append-only triggers, the six D18-C
scenarios and the privilege grants — is
`tests/migration/test_issuer_command_receipts.py`. What is provable without a
real database is provable here, following
`tests/unit/test_withdrawal_outcomes.py`'s own split.

`IssuerCommandReceipt` uses generic `Uuid()`/`String` column types (not
PostgreSQL-only ones), so it IS SQLite-compilable — confirmed by creating just
this one table (never the shared kernel `Base.metadata`, which also carries
unrelated PostgreSQL-only models) against an in-memory engine, which lets
`record_receipt`/`find_receipt`'s own concurrency-adjacent branches be
exercised here too.
"""

from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest
from dotmac_kernel import ConflictError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vendor_cp.deployment.issuer_receipts import (
    APPROVE_PLAN,
    ISSUE_AUTHORIZATION,
    IssuerCommandCommittedButWithdrawn,
    IssuerCommandReceipt,
    IssuerCommandReused,
    IssuerReceiptMismatch,
    _normalize,
    find_receipt,
    record_receipt,
    request_fingerprint,
)

# ── request_fingerprint ──────────────────────────────────────────────────────


def test_the_fingerprint_is_stable_and_key_order_insensitive() -> None:
    plan_id = uuid4()
    a = request_fingerprint(
        APPROVE_PLAN, {"command_id": "c-1", "plan_id": plan_id, "actor_ref": None}
    )
    b = request_fingerprint(
        APPROVE_PLAN, {"actor_ref": None, "plan_id": plan_id, "command_id": "c-1"}
    )
    assert a == b
    assert a.startswith("sha256:")
    assert len(a) == len("sha256:") + 64


def test_the_fingerprint_changes_when_any_field_changes() -> None:
    base = {"command_id": "c-1", "plan_id": uuid4(), "actor_ref": "operator"}
    baseline = request_fingerprint(APPROVE_PLAN, base)

    changed_command_id = request_fingerprint(
        APPROVE_PLAN, {**base, "command_id": "c-2"}
    )
    changed_plan_id = request_fingerprint(APPROVE_PLAN, {**base, "plan_id": uuid4()})
    changed_actor_ref = request_fingerprint(
        APPROVE_PLAN, {**base, "actor_ref": "other"}
    )

    assert baseline not in (changed_command_id, changed_plan_id, changed_actor_ref)
    assert len({baseline, changed_command_id, changed_plan_id, changed_actor_ref}) == 4


def test_the_fingerprint_is_sensitive_to_the_verb() -> None:
    """Non-vacuity for folding `verb` into the digest: identical request
    fields claimed under `approve_plan` and `issue_authorization` must not
    collide."""
    request = {"command_id": "c-1", "plan_id": uuid4()}
    a = request_fingerprint(APPROVE_PLAN, request)
    b = request_fingerprint(ISSUE_AUTHORIZATION, request)
    assert a != b


def test_the_fingerprint_normalizes_uuids_and_datetimes_to_plain_strings() -> None:
    from datetime import UTC, datetime

    identifier = uuid4()
    stamp = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    digest = request_fingerprint(
        APPROVE_PLAN, {"plan_id": identifier, "decided_at": stamp}
    )
    same = request_fingerprint(
        APPROVE_PLAN, {"plan_id": str(identifier), "decided_at": stamp.isoformat()}
    )
    assert digest == same


def test_normalize_raises_on_a_type_it_does_not_recognize() -> None:
    class Unrecognised:
        pass

    with pytest.raises(TypeError):
        _normalize(Unrecognised())


def test_the_fingerprint_raises_rather_than_silently_stringify_an_unknown_type() -> (
    None
):
    """SENSITIVITY (near-miss): a JSON-native value (str) must still work,
    proving the raise above is reached only for the type it targets."""

    class Unrecognised:
        pass

    with pytest.raises(TypeError):
        request_fingerprint(APPROVE_PLAN, {"weird": Unrecognised()})
    # A near-miss: an ordinary string is JSON-native and never reaches
    # `_normalize` at all.
    request_fingerprint(APPROVE_PLAN, {"fine": "a plain string"})


# ── exceptions carry no envelope field ───────────────────────────────────────


def test_committed_but_withdrawn_carries_only_command_verb_and_control_ref() -> None:
    exc = IssuerCommandCommittedButWithdrawn("cmd-1", APPROVE_PLAN, "control-ref-1")
    assert vars(exc) == {
        "command_id": "cmd-1",
        "verb": APPROVE_PLAN,
        "control_ref": "control-ref-1",
    }
    # The message is the only positional arg -- never a signed envelope or any
    # other result object.
    assert exc.args == (str(exc),)
    assert isinstance(exc.args[0], str)


def test_every_issuer_receipt_exception_is_a_kernel_conflict_error() -> None:
    assert issubclass(IssuerCommandReused, ConflictError)
    assert issubclass(IssuerReceiptMismatch, ConflictError)
    assert issubclass(IssuerCommandCommittedButWithdrawn, ConflictError)


# ── record_receipt / find_receipt, against an in-memory SQLite table ────────


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    IssuerCommandReceipt.__table__.create(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _receipt_kwargs(command_id: str, **overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "command_id": command_id,
        "verb": APPROVE_PLAN,
        "fingerprint": "sha256:" + "aa" * 32,
        "plan_id": uuid4(),
        "approval_request_id": uuid4(),
        "control_ref": "control-ref",
    }
    kwargs.update(overrides)
    return kwargs


def test_find_receipt_returns_none_when_no_row_exists(db: Session) -> None:
    assert find_receipt(db, "no-such-command") is None


def test_record_receipt_then_find_receipt_round_trips(db: Session) -> None:
    row = record_receipt(db, **_receipt_kwargs("cmd-1"))
    db.commit()
    found = find_receipt(db, "cmd-1")
    assert found is not None
    assert found.id == row.id
    assert found.control_ref == "control-ref"


def test_record_receipt_a_disagreeing_reinsert_raises_mismatch(db: Session) -> None:
    """The `IntegrityError` recovery path, serially: a second insert for the
    same command id, with a DIFFERENT `control_ref`, must fail closed rather
    than silently keep the first story or the second. The full concurrent
    (two-session) proof lives in
    `tests/migration/test_issuer_command_receipts.py`'s case (b); what is
    provable without a real database is this serial half of the same
    IntegrityError-recovery branch."""
    record_receipt(db, **_receipt_kwargs("cmd-3", control_ref="control-ref-a"))
    db.commit()

    with pytest.raises(IssuerReceiptMismatch):
        record_receipt(db, **_receipt_kwargs("cmd-3", control_ref="control-ref-b"))
