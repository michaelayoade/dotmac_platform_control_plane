"""Deployment credential state — PLATFORM catalog tables (migration v011).

The vendor half of ADR-0007 (`docs/design/deployment-credentials.md`). These
tables answer ONE question — *may this key speak, and for whom?* — and decide
nothing about entitlements.

Two records:

- `DeploymentCredential` — a deployment's registered PUBLIC key and its
  lifecycle timeline. No private key material is ever stored here or anywhere
  in this repo.
- `DeploymentChallenge` — a stored possession challenge. The kernel's
  `DeploymentPossessionChallenge` is the signed value object on the wire; this
  is the issuer's authoritative RECORD of one, and it is the record — never the
  response — that supplies the nonce, deployment and expiry at verification
  time.

**The timestamps are the authority, not `status`.** Admission is decided for a
report received at some past instant, so a status column cannot answer it: it
only ever describes now. `status` is kept as a single-writer, rebuildable
projection with a CHECK constraint tying it to the timestamps, so the two
cannot disagree even under a direct SQL edit.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

#: `status` must equal what the timestamps say. Ordered most-terminal first,
#: because revocation outranks retirement: a credential that was retired and
#: then revoked is revoked. Kept byte-identical to the v011 predicate — see the
#: comment on the CheckConstraint below for why it is stated twice.
STATUS_MATCHES_TIMESTAMPS = """
    (status = 'revoked' AND revoked_at IS NOT NULL)
 OR (status = 'retired' AND retired_at IS NOT NULL AND revoked_at IS NULL)
 OR (status = 'active'  AND activated_at IS NOT NULL
        AND retired_at IS NULL AND revoked_at IS NULL)
 OR (status = 'pending' AND activated_at IS NULL
        AND retired_at IS NULL AND revoked_at IS NULL)
"""


class CredentialStatus:
    """Lifecycle states. Derived from the timestamps — see the module
    docstring and the v011 CHECK constraint."""

    PENDING = "pending"
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class DeploymentCredential(Base, TimestampMixin):
    """A deployment's registered public key and its eligibility timeline."""

    __tablename__ = "deployment_credentials"
    __table_args__ = (
        # `key_id` is what a signed report resolves to an identity through, so
        # it is unique across ALL states INCLUDING revoked. ADR-0007 §6 makes
        # revocation terminal: reinstating a revoked key_id would retroactively
        # re-trust everything it can sign, and a partial index excluding
        # revoked rows would permit exactly that reinstatement.
        UniqueConstraint("key_id", name="uq_deployment_credentials_key_id"),
        # Defence in depth against the §4 substitution attack. Signing `key_id`
        # into the envelope makes substitution unexploitable; this makes its
        # precondition — the same public key registered twice under different
        # ids — unreachable. Both, because either alone is one mistake away.
        UniqueConstraint(
            "public_key_fingerprint", name="uq_deployment_credentials_fingerprint"
        ),
        # `status` is a PROJECTION of the timestamps and may not disagree with
        # them. Declared HERE as well as in v011 on purpose: the unit lane
        # builds its schema with `create_all` from this metadata, so a
        # constraint living only in the migration would mean the fast tests run
        # against a schema production does not have — and the guard would be
        # exercised solely on Postgres. Migrations stay self-contained (they are
        # frozen snapshots and must not import app code), so the predicate is
        # deliberately duplicated; the v011 rehearsal proves the two agree.
        CheckConstraint(
            STATUS_MATCHES_TIMESTAMPS, name="ck_deployment_credentials_status_timeline"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    key_id: Mapped[str] = mapped_column(String(200), nullable=False)
    deployment_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Unpadded base64url, exactly as the kernel's verifier expects it.
    public_key_b64: Mapped[str] = mapped_column(String(200), nullable=False)
    #: `sha256:<hex>` over the DECODED 32 raw key bytes — never over the base64
    #: text, which is not canonical (padding, alphabet and whitespace variants
    #: would each hash differently and defeat the uniqueness constraint above).
    public_key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)

    #: Projection of the three timestamps below; see the v011 CHECK.
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=CredentialStatus.PENDING
    )
    #: The eligibility window: admits reports received from `activated_at`, up
    #: to but NOT including `retired_at` / `revoked_at`.
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(200))

    #: Who asserted the enrollment, and under which authority. Recorded because
    #: the interim authority is platform-admin POLICY, not proof a Deployment
    #: exists; when FleetDesiredStateService lands, historic registrations must
    #: still read as "authorised under the stopgap" rather than being silently
    #: reinterpreted. See `docs/design/deployment-credentials.md`.
    registered_by_admin_id: Mapped[UUID | None] = mapped_column(Uuid())
    enrollment_authority: Mapped[str] = mapped_column(String(60), nullable=False)


class DeploymentChallenge(Base, TimestampMixin):
    """A stored possession challenge — the issuer's authoritative record.

    Single-use, and consumed ONLY on successful verification. Consuming a
    failed attempt would hand an enrollment denial-of-service to anyone who
    learns the routing identifiers: `challenge_id` and `key_id` travel in the
    response and identify a record, they do not authenticate it. The nonce is
    the unpredictable part and the signature is the proof; the identifiers are
    an address.
    """

    __tablename__ = "deployment_challenges"
    __table_args__ = (
        UniqueConstraint("challenge_id", name="uq_deployment_challenges_challenge_id"),
    )

    id: Mapped[UUID] = uuid_pk()
    challenge_id: Mapped[str] = mapped_column(String(200), nullable=False)
    credential_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("deployment_credentials.id"), nullable=False
    )
    #: Denormalised from the credential so the SIGNED bindings are recorded as
    #: issued, not re-derived at verification time from a row that may since
    #: have changed.
    key_id: Mapped[str] = mapped_column(String(200), nullable=False)
    deployment_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    #: Set when this challenge is consumed by a successful activation, or
    #: invalidated as a sibling of one. Either way it can never be used again.
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: `activated` | `superseded` — why it was retired, so an operator can tell
    #: "this proved possession" from "a sibling did".
    consumed_reason: Mapped[str | None] = mapped_column(String(40))
    #: Failed verification attempts, counted rather than acted on: repeated
    #: failures are a signal to surface and throttle, not a reason to destroy
    #: the legitimate holder's ability to answer.
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


__all__ = [
    "STATUS_MATCHES_TIMESTAMPS",
    "CredentialStatus",
    "DeploymentChallenge",
    "DeploymentCredential",
]
