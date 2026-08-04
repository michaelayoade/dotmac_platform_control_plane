"""Applied-state admission evidence — PLATFORM catalog tables (migration v012).

Two records, not one. A single append-only table keyed uniquely on
`(authenticated_deployment_ref, report_id)` cannot work: the SECOND arrival
under a given key is exactly the row worth keeping — the replay, or the
conflicting bytes — and the unique constraint forbids inserting it. Updating
the first row instead would break append-only semantics AND discard the
conflicting bytes, destroying the evidence the table exists to preserve. That
schema also had nowhere to put an attempt that never resolved to an identity at
all: unknown `key_id`, malformed envelope, bad signature. Those are the
tripwires.

So: an append-only log of ATTEMPTS, and one canonical REPORT per idempotency
key.

`LicenceAckRecord` remains the legacy acknowledgement log and is untouched. It
has no `report_id`, no signed bytes, no `key_id`, no server receipt time and no
replay digest — and extending it would blur an operator's CLAIM with a
cryptographically signed ATTESTATION.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column


class SignatureStatus:
    """*Did this key sign these bytes?* — independent of lifecycle.

    Resolved for any KNOWN `key_id` regardless of credential state, INCLUDING
    revoked. A revoked key's signature is still a fact, and refusing to
    evaluate it would discard the evidence that a compromised key is still in
    use — an operator's cue to go looking for the theft.
    """

    #: No such `key_id` is registered, so there was nothing to check against.
    UNRESOLVED = "unresolved"
    INVALID = "invalid"
    VALID = "valid"


class EligibilityAtReceipt:
    """*Was that credential admitted at `received_at`?* — the timeline
    predicate. `n/a` when the signature is not `valid`, because the eligibility
    of an unproven claim is not a meaningful question.

    ONLY `ELIGIBLE` gates consequences. A `valid` + `not_eligible` attempt is
    recorded, attributable, and activates nothing.
    """

    NOT_APPLICABLE = "n/a"
    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not_eligible"


class AdmissionDisposition:
    """What was done with this arrival."""

    ACCEPTED = "accepted"
    IDEMPOTENT_REPLAY = "idempotent_replay"
    CONFLICT = "conflict"
    UNKNOWN_KEY = "unknown_key"
    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    NOT_ELIGIBLE = "not_eligible"
    DEPLOYMENT_MISMATCH = "deployment_mismatch"
    BODY_TOO_LARGE = "body_too_large"


class AppliedStateReport(Base, TimestampMixin):
    """One canonical row per idempotency key — the FIRST eligible verified
    arrival.

    "First **eligible verified**", not "first accepted": a report can be validly
    signed, eligible, and still be quarantined by the projection (unknown
    digest, deployment mismatch, a version we never issued). Those establish the
    canonical row too, and their verdict must be just as stable as an
    activation's — otherwise a quarantined `report_id` could be re-sent with
    different bytes and re-decided, which is exactly the re-litigation the
    idempotency key exists to prevent.
    """

    __tablename__ = "applied_state_reports"
    __table_args__ = (
        # Scoped to the PROVEN identity, so one deployment's `report_id` can
        # never collide with another's.
        UniqueConstraint(
            "authenticated_deployment_ref",
            "report_id",
            name="uq_applied_state_reports_identity_report",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    authenticated_deployment_ref: Mapped[str] = mapped_column(
        String(200), nullable=False
    )
    report_id: Mapped[str] = mapped_column(String(200), nullable=False)
    #: The exact signed bytes — not a parsed projection of them. This is what
    #: keeps the report portable evidence a third party can verify, which is
    #: the property ADR-0007 §1 justifies Ed25519 with in the first place.
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Which credential verified it — attributable after rotation.
    key_id: Mapped[str] = mapped_column(String(200), nullable=False)
    #: The receipt time that DECIDED eligibility, retained so the decision
    #: stays reproducible rather than being re-derived from a moving clock.
    first_received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: Returned verbatim to every subsequent identical replay. Recomputing
    #: could yield a different answer against changed licence state for bytes
    #: the deployment sent once, which would make an at-least-once transport
    #: look like a state change.
    original_verdict: Mapped[str] = mapped_column(String(40), nullable=False)


class AppliedStateReceiptAttempt(Base, TimestampMixin):
    """Append-only: one row per ARRIVAL, whatever happens to it.

    Written on EVERY path, including the ones that fail before an identity
    exists, because an unknown `key_id` or a bad signature against a known one
    is precisely the evidence an operator needs — and the thing a fail-closed
    system would otherwise discard silently.
    """

    __tablename__ = "applied_state_receipt_attempts"
    # Declared here AND in v012. The unit lane builds its schema with
    # `create_all` from this metadata, so a constraint living only in the
    # migration would mean the fast tests run against a schema production does
    # not have — the defect slice 1 shipped and had to correct. Migrations stay
    # self-contained (frozen snapshots must not import app code), so the
    # predicates are deliberately duplicated and the rehearsal proves they
    # agree.
    __table_args__ = (
        # Claim/proof separation, made structural: a row may carry an
        # "authenticated" ref only when something actually authenticated it.
        CheckConstraint(
            "(signature_status = 'valid') OR (authenticated_deployment_ref IS NULL)",
            name="ck_receipt_attempt_identity_needs_valid_signature",
        ),
        CheckConstraint(
            "(signature_status = 'valid') OR (eligibility_at_receipt = 'n/a')",
            name="ck_receipt_attempt_eligibility_needs_valid_signature",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    #: The trusted receipt instant: the DATABASE clock, taken after the
    #: complete bounded body has arrived and BEFORE parsing. See
    #: `admission.py` for why both halves of that matter.
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: The exact inbound bytes, truncated at the EVIDENCE cap. Bounded because
    #: they are attacker-controlled and unauthenticated at the moment they are
    #: stored.
    raw_body: Mapped[bytes | None] = mapped_column(LargeBinary)
    raw_body_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    #: `sha256:` over the full body as received, computed BEFORE truncation so
    #: two truncated attempts remain distinguishable. NULL when the body
    #: exceeded the ABSOLUTE ingress cap — past that there is no complete body
    #: to hash, and claiming a digest would be a lie about evidence we never
    #: held.
    raw_body_digest: Mapped[str | None] = mapped_column(String(128))

    #: The two questions, kept separate on purpose — see the classes above.
    signature_status: Mapped[str] = mapped_column(String(20), nullable=False)
    eligibility_at_receipt: Mapped[str] = mapped_column(String(20), nullable=False)

    #: As presented; meaningless until resolved, kept for triage.
    key_id: Mapped[str | None] = mapped_column(String(200))
    #: The PROVEN identity. NULL unless `signature_status = valid`.
    authenticated_deployment_ref: Mapped[str | None] = mapped_column(String(200))
    #: Parsed from the payload. EVIDENCE ONLY — never authority.
    report_id: Mapped[str | None] = mapped_column(String(200))
    claimed_deployment_ref: Mapped[str | None] = mapped_column(String(200))
    signature: Mapped[bytes | None] = mapped_column(LargeBinary)

    disposition: Mapped[str] = mapped_column(String(40), nullable=False)
    #: The canonical row this arrival resolved to, when one was established.
    #: A LOSING concurrent arrival points at the winner.
    report_ref: Mapped[UUID | None] = mapped_column(
        Uuid(), ForeignKey("applied_state_reports.id")
    )


__all__ = [
    "AdmissionDisposition",
    "AppliedStateReceiptAttempt",
    "AppliedStateReport",
    "EligibilityAtReceipt",
    "SignatureStatus",
]
