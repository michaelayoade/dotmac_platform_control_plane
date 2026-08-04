"""`AppliedStateAdmissionService` — receipt, verification, replay, admission.

The canonical writer for *what arrived, and have we seen it before?*
`DeploymentCredentialService` owns *may this key speak?*;
`EntitlementProjectionService` remains the sole consequence owner and its
activation rules are untouched by this slice.

Folding admission into either of the others would leave the receipt row, the
receipt clock and the replay verdict without a named writer — the exact shape
of gap this architecture exists to prevent.

Transaction-authority contract: receives a `Session` and only add/flush, except
for the one `conflict_savepoint` the concurrency algorithm requires.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from dotmac_kernel import BadRequestError
from dotmac_kernel.db import conflict_savepoint
from dotmac_kernel.licensing import (
    AppliedStateEnvelope,
    BadSignatureError,
    DeploymentVerificationKey,
    LicenceError,
    MalformedAppliedStateError,
    UnknownKeyError,
    VerifiedAppliedState,
    verify_applied_state,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.licensing.admission_models import (
    AdmissionDisposition,
    AppliedStateReceiptAttempt,
    AppliedStateReport,
    EligibilityAtReceipt,
    SignatureStatus,
)
from vendor_cp.licensing.credential_models import DeploymentCredential
from vendor_cp.licensing.credentials import resolve_eligible_credential

#: Above this, `raw_body` is truncated for storage and the flag is set. The row
#: still exists and is still useful; only the stored copy is shortened.
EVIDENCE_STORAGE_CAP = 64 * 1024

#: Above this the request is NOT READ past the limit. This is the cap that
#: matters for safety: without it, "read the whole body, hash it, then truncate
#: for storage" still reads and hashes unbounded attacker-supplied input, so
#: the amplifier merely moves from disk to memory and CPU.
ABSOLUTE_INGRESS_CAP = 1024 * 1024


class AdmissionInvariantError(RuntimeError):
    """An assumption this module documents did not hold.

    Deliberately NOT a `BadRequestError`: nothing the caller sent caused it, so
    reporting it as a client fault would send an operator looking in the wrong
    place.
    """


class BodyTooLargeError(BadRequestError):
    """The body exceeded the absolute ingress cap and was not fully read."""


@dataclass(frozen=True, slots=True)
class AdmissionOutcome:
    """What admission decided. `verified` is present only when the signature
    checked out AND the credential was eligible — the two questions that
    together gate consequences."""

    attempt_id: UUID
    disposition: str
    verified: VerifiedAppliedState | None = None
    report_id: UUID | None = None
    #: The verdict a consequence owner recorded, or the ORIGINAL verdict
    #: replayed back for an identical resend.
    verdict: str | None = None


def database_now(db: Session) -> datetime:
    """The trusted receipt instant, from the DATABASE clock.

    The same clock that writes `activated_at`, `retired_at` and `revoked_at`.
    Comparing an application-server timestamp against database-written lifecycle
    timestamps compares two clocks that drift independently, and a few hundred
    milliseconds of skew at a revocation boundary decides whether a compromised
    key's report is admitted.

    CALL THIS AFTER the complete bounded body has arrived and BEFORE parsing.
    Both halves matter. Stamping at request START lets a slow or chunked upload
    begin before a revocation and finish after it while keeping the earlier
    timestamp — a trivially exploitable way to be admitted by a key that was
    revoked mid-transfer. Stamping after PARSING makes the receipt time depend
    on how long parsing took, which is attacker-influenced through payload
    shape.
    """
    value = db.execute(select(func.now())).scalar_one()
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def read_bounded_body(raw: bytes) -> tuple[bytes | None, str | None, bool]:
    """Apply the two caps. Returns `(stored_bytes, digest, truncated)`.

    A body beyond the ABSOLUTE cap yields `(prefix, None, True)`: there is no
    complete body to hash, and claiming a digest would be a lie about evidence
    we never held.
    """
    if len(raw) > ABSOLUTE_INGRESS_CAP:
        return raw[:EVIDENCE_STORAGE_CAP], None, True
    # Digest over the FULL body, computed BEFORE truncation, so two truncated
    # attempts remain distinguishable.
    digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if len(raw) > EVIDENCE_STORAGE_CAP:
        return raw[:EVIDENCE_STORAGE_CAP], digest, True
    return raw, digest, False


def _record_attempt(
    db: Session,
    *,
    received_at: datetime,
    raw: bytes,
    disposition: str,
    signature_status: str = SignatureStatus.UNRESOLVED,
    eligibility: str = EligibilityAtReceipt.NOT_APPLICABLE,
    key_id: str | None = None,
    authenticated_deployment_ref: str | None = None,
    report_id: str | None = None,
    claimed_deployment_ref: str | None = None,
    signature: bytes | None = None,
    report_ref: UUID | None = None,
) -> AppliedStateReceiptAttempt:
    """Append the evidence. Called on EVERY path, including the ones that never
    resolved an identity — those are the tripwires."""
    body, digest, truncated = read_bounded_body(raw)
    attempt = AppliedStateReceiptAttempt(
        received_at=received_at,
        raw_body=body,
        raw_body_truncated=truncated,
        raw_body_digest=digest,
        signature_status=signature_status,
        eligibility_at_receipt=eligibility,
        key_id=key_id,
        authenticated_deployment_ref=authenticated_deployment_ref,
        report_id=report_id,
        claimed_deployment_ref=claimed_deployment_ref,
        signature=signature,
        disposition=disposition,
        report_ref=report_ref,
    )
    db.add(attempt)
    db.flush()
    return attempt


def _known_key(db: Session, key_id: str) -> DeploymentCredential | None:
    """Verification material for ANY registered key_id, regardless of
    lifecycle.

    Deliberately not the eligibility lookup. A revoked key's signature is still
    a fact worth establishing: a genuinely signed late report from that key and
    garbage naming it are completely different operational events — the first
    is a deployment that was offline during a rotation, the second is an
    attacker or a bug — and collapsing them destroys the evidence that a
    compromised key is still being used.
    """
    return db.execute(
        select(DeploymentCredential).where(DeploymentCredential.key_id == key_id)
    ).scalar_one_or_none()


def admit(
    db: Session,
    raw_body: bytes,
    *,
    received_at: datetime,
) -> AdmissionOutcome:
    """Verify, deduplicate and admit one inbound applied-state envelope.

    `received_at` must come from `database_now`, taken at the boundary this
    module documents. It is passed in rather than read here so the caller
    cannot accidentally stamp it after parsing.
    """
    if len(raw_body) > ABSOLUTE_INGRESS_CAP:
        attempt = _record_attempt(
            db,
            received_at=received_at,
            raw=raw_body,
            disposition=AdmissionDisposition.BODY_TOO_LARGE,
        )
        return AdmissionOutcome(attempt.id, AdmissionDisposition.BODY_TOO_LARGE)

    # 1. Structure. A malformed envelope never resolves an identity.
    try:
        envelope = AppliedStateEnvelope.from_wire(raw_body)
    except MalformedAppliedStateError:
        attempt = _record_attempt(
            db,
            received_at=received_at,
            raw=raw_body,
            disposition=AdmissionDisposition.MALFORMED,
        )
        return AdmissionOutcome(attempt.id, AdmissionDisposition.MALFORMED)

    # 2. Is the key_id one we know? Resolved independent of lifecycle.
    credential = _known_key(db, envelope.key_id)
    if credential is None:
        attempt = _record_attempt(
            db,
            received_at=received_at,
            raw=raw_body,
            disposition=AdmissionDisposition.UNKNOWN_KEY,
            key_id=envelope.key_id,
            signature=envelope.signature,
        )
        return AdmissionOutcome(attempt.id, AdmissionDisposition.UNKNOWN_KEY)

    # 3. Did this key sign these bytes? Still independent of lifecycle.
    key = DeploymentVerificationKey(
        key_id=credential.key_id,
        public_key_b64=credential.public_key_b64,
        deployment_ref=credential.deployment_ref,
    )
    try:
        verified = verify_applied_state(envelope, keys=[key])
    except (BadSignatureError, UnknownKeyError, LicenceError):
        attempt = _record_attempt(
            db,
            received_at=received_at,
            raw=raw_body,
            disposition=AdmissionDisposition.BAD_SIGNATURE,
            signature_status=SignatureStatus.INVALID,
            key_id=envelope.key_id,
            signature=envelope.signature,
        )
        return AdmissionOutcome(attempt.id, AdmissionDisposition.BAD_SIGNATURE)

    proven_ref = verified.deployment_ref
    state = verified.state

    # 4. Was that credential ADMITTED at the receipt instant? Only now does
    #    lifecycle enter, and only this gates consequences.
    eligible = resolve_eligible_credential(
        db, key_id=envelope.key_id, received_at=received_at
    )
    if eligible is None:
        attempt = _record_attempt(
            db,
            received_at=received_at,
            raw=raw_body,
            disposition=AdmissionDisposition.NOT_ELIGIBLE,
            signature_status=SignatureStatus.VALID,
            eligibility=EligibilityAtReceipt.NOT_ELIGIBLE,
            key_id=envelope.key_id,
            authenticated_deployment_ref=proven_ref,
            report_id=state.report_id,
            claimed_deployment_ref=state.deployment_ref,
            signature=envelope.signature,
        )
        return AdmissionOutcome(attempt.id, AdmissionDisposition.NOT_ELIGIBLE)

    # 5. The body's claim is EVIDENCE. A contradiction is quarantined — it is
    #    not a mistake to resolve in the caller's favour.
    if not verified.claim_matches_proof:
        attempt = _record_attempt(
            db,
            received_at=received_at,
            raw=raw_body,
            disposition=AdmissionDisposition.DEPLOYMENT_MISMATCH,
            signature_status=SignatureStatus.VALID,
            eligibility=EligibilityAtReceipt.ELIGIBLE,
            key_id=envelope.key_id,
            authenticated_deployment_ref=proven_ref,
            report_id=state.report_id,
            claimed_deployment_ref=state.deployment_ref,
            signature=envelope.signature,
        )
        return AdmissionOutcome(
            attempt.id, AdmissionDisposition.DEPLOYMENT_MISMATCH, verified=verified
        )

    return _claim_report(
        db,
        raw_body=raw_body,
        envelope=envelope,
        verified=verified,
        received_at=received_at,
    )


def _claim_report(
    db: Session,
    *,
    raw_body: bytes,
    envelope: AppliedStateEnvelope,
    verified: VerifiedAppliedState,
    received_at: datetime,
) -> AdmissionOutcome:
    """Establish or match the canonical row for this idempotency key.

    "No canonical row yet" CANNOT be decided by looking: two simultaneous first
    arrivals both observe none, which at-least-once delivery plus a retrying
    transport makes ordinary rather than exotic. The read-then-insert race is
    therefore resolved by the DATABASE:

    1. The attempt row is written in the OUTER transaction — evidence never
       depends on winning a race.
    2. The canonical insert is attempted inside `conflict_savepoint`, letting
       the unique constraint arbitrate.
    3. On collision, the committed winner is loaded and LOCKED and the digests
       compared.
    4. The losing attempt is preserved either way, pointing at the winner.

    The loser does NOT re-run consequences: it resolves to the winner's
    verdict, so two racing identical reports activate a delivery exactly once.
    """
    proven_ref = verified.deployment_ref
    state = verified.state
    digest = f"sha256:{hashlib.sha256(envelope.payload).hexdigest()}"

    candidate = AppliedStateReport(
        authenticated_deployment_ref=proven_ref,
        report_id=state.report_id,
        payload=envelope.payload,
        payload_digest=digest,
        key_id=envelope.key_id,
        first_received_at=received_at,
        # Provisional until a consequence owner records its verdict; overwritten
        # below by the caller's decision for a genuinely new report.
        original_verdict=AdmissionDisposition.ACCEPTED,
    )
    won = True
    try:
        with conflict_savepoint(db):
            db.add(candidate)
            db.flush()
    except IntegrityError:
        won = False

    if won:
        attempt = _record_attempt(
            db,
            received_at=received_at,
            raw=raw_body,
            disposition=AdmissionDisposition.ACCEPTED,
            signature_status=SignatureStatus.VALID,
            eligibility=EligibilityAtReceipt.ELIGIBLE,
            key_id=envelope.key_id,
            authenticated_deployment_ref=proven_ref,
            report_id=state.report_id,
            claimed_deployment_ref=state.deployment_ref,
            signature=envelope.signature,
            report_ref=candidate.id,
        )
        return AdmissionOutcome(
            attempt.id,
            AdmissionDisposition.ACCEPTED,
            verified=verified,
            report_id=candidate.id,
        )

    # Lost the race, or this is an ordinary later resend. Load and LOCK the
    # committed winner before comparing, so two losers cannot both read a row
    # mid-update.
    #
    # The winner is necessarily COMMITTED by the time we get here, and that is
    # not an assumption — it is what a unique violation means. Postgres BLOCKS a
    # conflicting inserter while the other transaction is still open; the
    # violation is only raised once that transaction commits, at which point
    # READ COMMITTED can see the row. (If it rolls back instead, our insert
    # succeeds and we never reach this branch.)
    #
    # `scalar_one_or_none` rather than `scalar_one` so that if the invariant is
    # ever violated — a different unique constraint firing, an isolation level
    # this reasoning does not hold under — it surfaces as a statement about
    # WHAT went wrong rather than an opaque NoResultFound from deep inside the
    # result API.
    winner = db.execute(
        select(AppliedStateReport)
        .where(
            AppliedStateReport.authenticated_deployment_ref == proven_ref,
            AppliedStateReport.report_id == state.report_id,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if winner is None:
        raise AdmissionInvariantError(
            "a unique violation on "
            f"({proven_ref!r}, {state.report_id!r}) implies a committed winner, "
            "but none is visible. Either a DIFFERENT unique constraint fired, or "
            "this transaction is running at an isolation level where the "
            "block-then-violate ordering does not hold."
        )

    identical = winner.payload_digest == digest
    disposition = (
        AdmissionDisposition.IDEMPOTENT_REPLAY
        if identical
        else AdmissionDisposition.CONFLICT
    )
    attempt = _record_attempt(
        db,
        received_at=received_at,
        raw=raw_body,
        disposition=disposition,
        signature_status=SignatureStatus.VALID,
        eligibility=EligibilityAtReceipt.ELIGIBLE,
        key_id=envelope.key_id,
        authenticated_deployment_ref=proven_ref,
        report_id=state.report_id,
        claimed_deployment_ref=state.deployment_ref,
        signature=envelope.signature,
        report_ref=winner.id,
    )
    return AdmissionOutcome(
        attempt.id,
        disposition,
        # An identical replay resolves to the winner's ORIGINAL verdict and
        # runs no consequences. A conflict runs none either: one of the two is
        # forged or a receiver bug, and picking one would be guessing.
        verdict=winner.original_verdict if identical else None,
        report_id=winner.id,
    )


def record_verdict(db: Session, report_id: UUID, verdict: str) -> None:
    """Freeze the consequence owner's verdict onto the canonical row.

    Recorded rather than recomputed on replay: recomputation against changed
    licence state could yield a different answer for bytes the deployment sent
    once, which would make an at-least-once transport look like a state change.
    """
    report = db.get(AppliedStateReport, report_id)
    if report is None:
        raise BadRequestError(f"no applied-state report {report_id}")
    report.original_verdict = verdict
    db.flush()


def applied_state_to_acknowledgement(
    verified: VerifiedAppliedState,
) -> dict[str, object]:
    """Map a verified report onto the LEGACY acknowledgement vocabulary.

    Explicit, field by field, so a future change to either vocabulary is a
    visible edit here rather than a silent mismatch. `deployment_ref` maps to
    `deployment_id` as a CLAIM on both sides; the proven identity travels
    separately and is never merged into it.

    `report_id`, `keyring_generation`, `revocation_list_version` and
    `observed_at` have no legacy home — which is why the receipt tables exist
    rather than columns bolted onto `LicenceAckRecord`.
    """
    state = verified.state
    return {
        "licence_id": state.licence_id,
        "licence_version": state.licence_version,
        "digest": state.digest,
        "status": state.status,
        "reason": state.reason,
        "deployment_id": state.deployment_ref,
    }


def payload_json(envelope: AppliedStateEnvelope) -> dict[str, object]:
    """The signed payload as a dict, for callers that need to inspect it after
    verification. Parsed from the EXACT signed bytes."""
    parsed = json.loads(envelope.payload)
    if not isinstance(parsed, dict):
        raise MalformedAppliedStateError("applied-state payload must be an object")
    return parsed


__all__ = [
    "ABSOLUTE_INGRESS_CAP",
    "AdmissionInvariantError",
    "EVIDENCE_STORAGE_CAP",
    "AdmissionOutcome",
    "BodyTooLargeError",
    "admit",
    "applied_state_to_acknowledgement",
    "database_now",
    "payload_json",
    "read_bounded_body",
    "record_verdict",
]
