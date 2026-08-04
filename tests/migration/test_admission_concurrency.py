"""Two-session proof that concurrent first arrivals resolve to ONE report.

Acceptance cases 26–27. "No canonical row yet" cannot be decided by looking:
two simultaneous first arrivals both observe none, which at-least-once delivery
plus a retrying transport makes ordinary rather than exotic. The read-then-insert
race is resolved by the DATABASE, so proving it needs two real concurrent
transactions.

Lives under `tests/migration` because SQLite cannot reproduce a unique-constraint
collision between concurrent transactions — the unit suite structurally cannot
prove this, and a version of it that passed there would be an unproven claim
converted into a believed one.

These drive the production path (`admission.admit`) rather than hand-written
SQL: a test over a scratch table would prove only that Postgres implements
unique constraints, and deleting the algorithm from the service would leave it
green.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from dotmac_kernel.licensing import ReceiverAppliedState, seal_applied_state
from dotmac_kernel.testing import FakeDeploymentSigner
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from vendor_cp.licensing.admission import admit
from vendor_cp.licensing.admission_models import (
    AdmissionDisposition,
    AppliedStateReceiptAttempt,
    AppliedStateReport,
)

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "ab" * 32


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    # `postgres_url` (conftest) skips locally and FAILS under
    # REQUIRE_POSTGRES_TESTS=1, so this suite can never pass by skipping.
    eng = create_engine(postgres_url, future=True)
    yield eng
    eng.dispose()


@pytest.fixture
def sessions(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture
def credential(engine: Engine) -> Iterator[tuple[str, str, FakeDeploymentSigner]]:
    """An ACTIVE credential in the real tables, with a unique key so parallel
    runs of this module cannot collide."""
    suffix = uuid.uuid4().hex[:8]
    key_id, dep = f"key-{suffix}", f"dep-{suffix}"
    signer = FakeDeploymentSigner(key_id=key_id, deployment_ref=dep)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO deployment_credentials "
                "(id, key_id, deployment_ref, public_key_b64, public_key_fingerprint,"
                " status, activated_at, enrollment_authority, created_at, updated_at) "
                "VALUES (gen_random_uuid(), :k, :d, :pk, :fp, 'active',"
                " :activated, 'platform_admin_policy', now(), now())"
            ),
            {
                "k": key_id,
                "d": dep,
                "pk": signer.public_key_b64,
                "fp": f"sha256:{suffix}{'0' * (64 - len(suffix))}",
                "activated": NOW,
            },
        )
    yield key_id, dep, signer
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM applied_state_receipt_attempts WHERE key_id = :k"),
            {"k": key_id},
        )
        conn.execute(
            text(
                "DELETE FROM applied_state_reports "
                "WHERE authenticated_deployment_ref = :d"
            ),
            {"d": dep},
        )
        conn.execute(
            text("DELETE FROM deployment_credentials WHERE key_id = :k"), {"k": key_id}
        )


def _wire(dep: str, signer: FakeDeploymentSigner, **over) -> bytes:
    fields: dict[str, object] = {
        "report_id": "rep-concurrent",
        "deployment_ref": dep,
        "licence_id": "lic-1",
        "licence_version": 3,
        "digest": DIGEST,
        "keyring_generation": 2,
        "revocation_list_version": 5,
        "observed_at": NOW,
        "status": "applied",
    }
    fields.update(over)
    state = ReceiverAppliedState(**fields)  # type: ignore[arg-type]
    return json.dumps(seal_applied_state(state, signer=signer).to_wire()).encode()


def _run_interleaved(
    sessions: sessionmaker[Session], first: bytes, second: bytes
) -> tuple[str, str]:
    """Both sessions admit BEFORE either commits — the genuine race. Without
    that overlap each would simply see the other's committed row and this would
    degenerate into a sequential replay test."""
    s1, s2 = sessions(), sessions()
    try:
        out1 = admit(s1, first, received_at=NOW)
        out2 = admit(s2, second, received_at=NOW)
        s1.commit()
        s2.commit()
        return out1.disposition, out2.disposition
    finally:
        s1.close()
        s2.close()


def test_simultaneous_identical_first_arrivals_yield_one_report(
    sessions: sessionmaker[Session], engine: Engine, credential
) -> None:
    """One canonical row, one verdict, and both attempts retained. The loser
    resolves to the winner's verdict rather than re-running consequences, so
    two racing identical reports activate a delivery exactly once."""
    _, dep, signer = credential
    wire = _wire(dep, signer)
    d1, d2 = _run_interleaved(sessions, wire, wire)

    assert {d1, d2} == {
        AdmissionDisposition.ACCEPTED,
        AdmissionDisposition.IDEMPOTENT_REPLAY,
    }, f"expected one winner and one replay, got {d1} and {d2}"

    with sessions() as check:
        reports = list(
            check.execute(
                select(AppliedStateReport).where(
                    AppliedStateReport.authenticated_deployment_ref == dep
                )
            ).scalars()
        )
        attempts = list(
            check.execute(
                select(AppliedStateReceiptAttempt).where(
                    AppliedStateReceiptAttempt.authenticated_deployment_ref == dep
                )
            ).scalars()
        )
    assert len(reports) == 1, "the race created more than one canonical row"
    assert len(attempts) == 2, "a losing attempt was discarded"
    assert all(
        a.report_ref == reports[0].id for a in attempts
    ), "the losing attempt does not point at the winner"


def test_simultaneous_divergent_first_arrivals_yield_one_report_and_a_conflict(
    sessions: sessionmaker[Session], engine: Engine, credential
) -> None:
    """Same `report_id`, different bytes: one of the two is forged or a
    receiver bug, and never picking one is the point. BOTH byte sequences must
    survive — that is the whole reason the schema is split in two."""
    _, dep, signer = credential
    first = _wire(dep, signer)
    second = _wire(dep, signer, licence_version=4)
    assert first != second

    d1, d2 = _run_interleaved(sessions, first, second)
    assert {d1, d2} == {
        AdmissionDisposition.ACCEPTED,
        AdmissionDisposition.CONFLICT,
    }, f"expected one winner and one conflict, got {d1} and {d2}"

    with sessions() as check:
        reports = list(
            check.execute(
                select(AppliedStateReport).where(
                    AppliedStateReport.authenticated_deployment_ref == dep
                )
            ).scalars()
        )
        bodies = {
            a.raw_body
            for a in check.execute(
                select(AppliedStateReceiptAttempt).where(
                    AppliedStateReceiptAttempt.authenticated_deployment_ref == dep
                )
            ).scalars()
        }
    assert len(reports) == 1
    assert {first, second} <= bodies, "a conflicting byte sequence was lost"
