"""V6 slice 2 — applied-state admission (ADR-0007).

Acceptance cases 14, 16–17, 19–25 and 33. The concurrency cases (26–27) need a
real unique-constraint collision between CONCURRENT transactions and live in
the Postgres rehearsals — SQLite cannot reproduce one, so passing here would
prove nothing.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.licensing import (
    AppliedStateEnvelope,
    ReceiverAppliedState,
    answer_possession_challenge,
    seal_applied_state,
)
from dotmac_kernel.testing import (
    FakeDeploymentSigner,
    create_test_engine,
    isolated_session,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

# Imported for their metadata side effect only — create_all resolves every FK
# in the shared metadata, not just the tables a test touches.
from vendor_cp.allocations import models as _allocations_models  # noqa: F401
from vendor_cp.approvals import models as _approvals_models  # noqa: F401
from vendor_cp.contracts import models as _contracts_models  # noqa: F401
from vendor_cp.licensing import models as _licensing_models  # noqa: F401
from vendor_cp.licensing import projection
from vendor_cp.licensing.admission import (
    ABSOLUTE_INGRESS_CAP,
    EVIDENCE_STORAGE_CAP,
    admit,
    applied_state_to_acknowledgement,
    database_now,
    read_bounded_body,
    record_verdict,
)
from vendor_cp.licensing.admission_models import (
    AdmissionDisposition,
    AppliedStateReceiptAttempt,
    AppliedStateReport,
    EligibilityAtReceipt,
    SignatureStatus,
)
from vendor_cp.licensing.credential_models import CredentialStatus
from vendor_cp.licensing.credentials import (
    activate_credential,
    issue_challenge,
    register_credential,
)
from vendor_cp.licensing.delivery_models import LicenceDeliveryTarget, TargetStatus
from vendor_cp.offers import models as _offers_models  # noqa: F401

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
DEP = "edge-site-1"
KEY_ID = "dep-edge1-2026-08"
DIGEST = "sha256:" + "ab" * 32


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


@pytest.fixture
def signer() -> FakeDeploymentSigner:
    return FakeDeploymentSigner(key_id=KEY_ID, deployment_ref=DEP)


def _state(**over) -> ReceiverAppliedState:
    fields: dict[str, object] = {
        "report_id": "rep-1",
        "deployment_ref": DEP,
        "licence_id": "lic-1",
        "licence_version": 3,
        "digest": DIGEST,
        "keyring_generation": 2,
        "revocation_list_version": 5,
        "observed_at": NOW,
        "status": "applied",
    }
    fields.update(over)
    return ReceiverAppliedState(**fields)  # type: ignore[arg-type]


def _active_credential(db, signer):
    db.add(
        LicenceDeliveryTarget(
            target_ref=DEP, customer_ref="cust-1", status=TargetStatus.ACTIVE.value
        )
    )
    db.flush()
    credential = register_credential(
        db, key_id=KEY_ID, deployment_ref=DEP, public_key_b64=signer.public_key_b64
    )
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    activate_credential(
        db, answer_possession_challenge(issued.challenge, signer=signer), now=NOW
    )
    return credential


def _wire(state, signer) -> bytes:
    return json.dumps(seal_applied_state(state, signer=signer).to_wire()).encode()


def _attempts(db) -> list[AppliedStateReceiptAttempt]:
    return list(db.execute(select(AppliedStateReceiptAttempt)).scalars())


# ── The two adapters ────────────────────────────────────────────────────────


def test_admin_ingestion_cannot_accept_a_proven_identity() -> None:
    """STRUCTURAL, not behavioural. The parameter must be ABSENT, not defaulted
    to None — a default is one careless keyword away from an admin route
    activating a licence, and the type system should make the mistake
    unexpressible rather than the code merely avoid it."""
    params = inspect.signature(projection.ingest_admin_acknowledgement).parameters
    assert "authenticated_deployment_ref" not in params
    assert not any("deployment_ref" in name for name in params)


def test_authenticated_ingestion_requires_a_verified_result_not_a_string() -> None:
    """A `deployment_ref: str` would let any caller supply an identity.
    Requiring the kernel's verified RESULT means the only way to obtain one is
    to have verified a signature."""
    params = inspect.signature(projection.ingest_authenticated_applied_state).parameters
    annotation = params["verified"].annotation
    assert "VerifiedAppliedState" in str(annotation)


def test_both_adapters_converge_on_one_core() -> None:
    source = inspect.getsource(projection.ingest_admin_acknowledgement)
    assert "_apply_acknowledgement" in source
    source = inspect.getsource(projection.ingest_authenticated_applied_state)
    assert "_apply_acknowledgement" in source


# ── Signature validity vs eligibility ───────────────────────────────────────


def test_a_valid_report_from_an_eligible_credential_is_accepted(db, signer) -> None:
    _active_credential(db, signer)
    outcome = admit(db, _wire(_state(), signer), received_at=NOW)
    assert outcome.disposition == AdmissionDisposition.ACCEPTED
    assert outcome.verified is not None
    assert outcome.verified.deployment_ref == DEP


def test_a_late_report_from_a_revoked_key_is_valid_but_not_eligible(db, signer) -> None:
    """THE distinction. Garbage naming a revoked key and a genuinely signed
    late report from that key are completely different operational events — the
    first is an attacker or a bug, the second a deployment that was offline
    during a rotation. Collapsing them destroys the evidence that a compromised
    key is still in use."""
    credential = _active_credential(db, signer)
    credential.revoked_at = NOW + timedelta(hours=1)
    credential.status = CredentialStatus.REVOKED
    db.flush()

    outcome = admit(db, _wire(_state(), signer), received_at=NOW + timedelta(hours=2))
    assert outcome.disposition == AdmissionDisposition.NOT_ELIGIBLE

    attempt = _attempts(db)[-1]
    assert attempt.signature_status == SignatureStatus.VALID
    assert attempt.eligibility_at_receipt == EligibilityAtReceipt.NOT_ELIGIBLE
    assert attempt.authenticated_deployment_ref == DEP


def test_garbage_naming_the_same_key_is_distinguishable_from_a_late_report(
    db, signer
) -> None:
    credential = _active_credential(db, signer)
    credential.revoked_at = NOW + timedelta(hours=1)
    credential.status = CredentialStatus.REVOKED
    db.flush()

    envelope = AppliedStateEnvelope(
        key_id=KEY_ID, payload=b'{"schema":"x"}', signature=b"\x00" * 64
    )
    admit(db, json.dumps(envelope.to_wire()).encode(), received_at=NOW)
    attempt = _attempts(db)[-1]
    assert attempt.signature_status == SignatureStatus.INVALID
    assert attempt.eligibility_at_receipt == EligibilityAtReceipt.NOT_APPLICABLE
    assert attempt.authenticated_deployment_ref is None


def test_an_unknown_key_id_records_an_attempt_with_no_identity(db, signer) -> None:
    """A tripwire: a fail-closed system that discarded these would be blind to
    exactly the traffic it is refusing."""
    outcome = admit(db, _wire(_state(), signer), received_at=NOW)
    assert outcome.disposition == AdmissionDisposition.UNKNOWN_KEY
    attempt = _attempts(db)[-1]
    assert attempt.signature_status == SignatureStatus.UNRESOLVED
    assert attempt.authenticated_deployment_ref is None
    assert attempt.key_id == KEY_ID  # kept for triage


def test_a_malformed_envelope_records_an_attempt(db) -> None:
    outcome = admit(db, b"not an envelope", received_at=NOW)
    assert outcome.disposition == AdmissionDisposition.MALFORMED
    assert len(_attempts(db)) == 1


def test_a_claimed_deployment_that_contradicts_the_proof_is_quarantined(db) -> None:
    """A contradiction is quarantined, not resolved in the caller's favour.

    Sealed by a signer that BELIEVES it speaks for `elsewhere`, while the
    registry maps its key to `edge-site-1` — a misconfigured or hostile
    receiver. An honest one cannot build this at all (the kernel's signer
    refuses a foreign claim), but the vendor must still handle it: refusing to
    produce a thing is not the same as being safe when someone else produces
    it.
    """
    liar = FakeDeploymentSigner(key_id=KEY_ID, deployment_ref="elsewhere")
    db.add(
        LicenceDeliveryTarget(
            target_ref=DEP, customer_ref="cust-1", status=TargetStatus.ACTIVE.value
        )
    )
    db.flush()
    credential = register_credential(
        db, key_id=KEY_ID, deployment_ref=DEP, public_key_b64=liar.public_key_b64
    )
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    # The possession challenge is for DEP, so the liar cannot answer it — its
    # own signer guard refuses a foreign deployment. Activate the timeline
    # directly; possession is slice 1's concern, not this test's.
    del issued
    credential.status = CredentialStatus.ACTIVE
    credential.activated_at = NOW
    db.flush()

    outcome = admit(
        db, _wire(_state(deployment_ref="elsewhere"), liar), received_at=NOW
    )
    assert outcome.disposition == AdmissionDisposition.DEPLOYMENT_MISMATCH

    attempt = _attempts(db)[-1]
    assert attempt.authenticated_deployment_ref == DEP  # the PROVEN identity
    assert attempt.claimed_deployment_ref == "elsewhere"  # the claim, kept
    # Nothing was admitted, so no canonical row was established.
    assert not list(db.execute(select(AppliedStateReport)).scalars())


# ── Caps ────────────────────────────────────────────────────────────────────


def test_a_body_within_both_caps_is_stored_whole_with_a_digest() -> None:
    body, digest, truncated = read_bounded_body(b"small")
    assert body == b"small"
    assert digest is not None
    assert truncated is False


def test_a_body_over_the_evidence_cap_is_truncated_but_still_digested() -> None:
    """The digest is computed BEFORE truncation, so two truncated attempts stay
    distinguishable."""
    a = b"a" * (EVIDENCE_STORAGE_CAP + 10)
    b = a[:-1] + b"b"
    body_a, digest_a, truncated_a = read_bounded_body(a)
    _, digest_b, _ = read_bounded_body(b)
    assert truncated_a is True
    assert len(body_a) == EVIDENCE_STORAGE_CAP
    assert digest_a is not None and digest_a != digest_b


def test_a_body_over_the_absolute_cap_has_no_digest(db) -> None:
    """Past the absolute cap there is no complete body to hash, and claiming a
    digest would be a lie about evidence we never held."""
    huge = b"x" * (ABSOLUTE_INGRESS_CAP + 1)
    body, digest, truncated = read_bounded_body(huge)
    assert digest is None
    assert truncated is True
    assert len(body) == EVIDENCE_STORAGE_CAP

    outcome = admit(db, huge, received_at=NOW)
    assert outcome.disposition == AdmissionDisposition.BODY_TOO_LARGE
    attempt = _attempts(db)[-1]
    assert attempt.raw_body_digest is None
    assert attempt.raw_body_truncated is True


# ── Replay and conflict ─────────────────────────────────────────────────────


def test_an_identical_replay_returns_the_original_verdict(db, signer) -> None:
    """Recomputing could yield a different answer against changed licence state
    for bytes the deployment sent once, which would make an at-least-once
    transport look like a state change."""
    _active_credential(db, signer)
    wire = _wire(_state(), signer)

    first = admit(db, wire, received_at=NOW)
    record_verdict(db, first.report_id, "activated")

    second = admit(db, wire, received_at=NOW + timedelta(minutes=5))
    assert second.disposition == AdmissionDisposition.IDEMPOTENT_REPLAY
    assert second.verdict == "activated"
    assert second.report_id == first.report_id
    # Exactly one canonical row; both arrivals in the attempt log.
    assert len(list(db.execute(select(AppliedStateReport)).scalars())) == 1
    assert len(_attempts(db)) == 2


def test_the_same_report_id_with_different_bytes_is_a_conflict(db, signer) -> None:
    """One of the two is forged or a receiver bug; never pick one. BOTH byte
    sequences survive in the attempt log — that is the whole reason the schema
    is split in two."""
    _active_credential(db, signer)
    first_wire = _wire(_state(), signer)
    other_wire = _wire(_state(licence_version=4), signer)  # same report_id

    admit(db, first_wire, received_at=NOW)
    outcome = admit(db, other_wire, received_at=NOW + timedelta(minutes=1))

    assert outcome.disposition == AdmissionDisposition.CONFLICT
    assert outcome.verdict is None, "a conflict must not resolve to a verdict"
    assert len(list(db.execute(select(AppliedStateReport)).scalars())) == 1
    bodies = {a.raw_body for a in _attempts(db)}
    assert first_wire in bodies and other_wire in bodies


def test_report_ids_are_scoped_to_the_proven_identity(db, signer) -> None:
    """One deployment's report_id can never collide with another's."""
    _active_credential(db, signer)
    other = FakeDeploymentSigner(key_id="key-2", deployment_ref="edge-site-2")
    db.add(
        LicenceDeliveryTarget(
            target_ref="edge-site-2",
            customer_ref="cust-1",
            status=TargetStatus.ACTIVE.value,
        )
    )
    db.flush()
    cred2 = register_credential(
        db,
        key_id="key-2",
        deployment_ref="edge-site-2",
        public_key_b64=other.public_key_b64,
    )
    issued = issue_challenge(db, credential_id=cred2.id, now=NOW)
    activate_credential(
        db, answer_possession_challenge(issued.challenge, signer=other), now=NOW
    )

    admit(db, _wire(_state(), signer), received_at=NOW)
    outcome = admit(
        db,
        _wire(_state(deployment_ref="edge-site-2"), other),
        received_at=NOW,
    )
    # Same report_id, different proven identity — a separate canonical row.
    assert outcome.disposition == AdmissionDisposition.ACCEPTED
    assert len(list(db.execute(select(AppliedStateReport)).scalars())) == 2


# ── Mapping ─────────────────────────────────────────────────────────────────


def test_the_legacy_mapping_keeps_the_claim_a_claim(db, signer) -> None:
    _active_credential(db, signer)
    outcome = admit(db, _wire(_state(), signer), received_at=NOW)
    mapped = applied_state_to_acknowledgement(outcome.verified)
    assert mapped["deployment_id"] == DEP  # the CLAIM
    assert mapped["licence_id"] == "lic-1"
    assert mapped["digest"] == DIGEST
    # The four fields with no legacy home stay off the acknowledgement.
    assert "report_id" not in mapped
    assert "keyring_generation" not in mapped
    assert "revocation_list_version" not in mapped
    assert "observed_at" not in mapped


def test_the_database_clock_is_used_for_receipt_time(db) -> None:
    """Not the application clock: comparing an app-server timestamp against
    database-written lifecycle timestamps compares two independently drifting
    clocks, and a few hundred milliseconds at a revocation boundary decides
    whether a compromised key's report is admitted."""
    stamped = database_now(db)
    assert stamped.tzinfo is not None
