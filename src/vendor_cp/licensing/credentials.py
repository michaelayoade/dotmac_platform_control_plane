"""`DeploymentCredentialService` — registry, possession, eligibility.

The vendor half of ADR-0007 (`docs/design/deployment-credentials.md`). It owns
ONE question — *may this key speak, and for whom?* — and decides nothing about
entitlements. `EntitlementProjectionService` remains the sole consequence
owner; `AppliedStateAdmissionService` (slice 2) owns receipts and admission.

No private key material enters this repo. The vendor stores PUBLIC keys only.

Transaction-authority contract: receives a `Session` and only add/flush.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from dotmac_kernel import BadRequestError, NotFoundError, write_platform_audit_event
from dotmac_kernel.licensing import (
    DeploymentPossessionChallenge,
    DeploymentPossessionResponse,
    DeploymentVerificationKey,
    LicenceError,
    verify_possession,
)
from dotmac_kernel.messaging import enqueue_platform_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.licensing.credential_models import (
    CredentialStatus,
    DeploymentChallenge,
    DeploymentCredential,
)
from vendor_cp.licensing.delivery_models import LicenceDeliveryTarget, TargetStatus

_EVENT_REGISTERED = "vendor.deployment_credential.registered"
_EVENT_ACTIVATED = "vendor.deployment_credential.activated"

#: The interim enrollment authority, recorded on every registration. When
#: FleetDesiredStateService lands, historic rows must still read as
#: "authorised under the stopgap" rather than being silently reinterpreted.
ENROLLMENT_AUTHORITY_ADMIN_POLICY = "platform_admin_policy"

#: Ed25519 raw public keys are exactly this long. Validated before fingerprint
#: computation so a truncated or padded key cannot produce a "valid-looking"
#: fingerprint that collides with nothing.
_ED25519_PUBLIC_KEY_BYTES = 32

_DEFAULT_CHALLENGE_TTL = timedelta(minutes=15)
#: Matches the kernel's minimum. A shorter nonce is guessable enough that a
#: response could be precomputed before the challenge is even issued.
_NONCE_BYTES = 32


class EnrollmentNotAuthorisedError(BadRequestError):
    """No authorised enrollment subject for this `deployment_ref`."""


class CredentialConflictError(BadRequestError):
    """This `key_id` or public key is already registered."""


@dataclass(frozen=True, slots=True)
class IssuedChallenge:
    """What the vendor hands the deployment, plus the record it keeps."""

    challenge: DeploymentPossessionChallenge
    record_id: UUID


def public_key_fingerprint(public_key_b64: str) -> str:
    """`sha256:<hex>` over the DECODED raw key bytes.

    Over the decoded bytes, never the base64 text: base64 is not a canonical
    encoding — padding variants, the URL-safe versus standard alphabet, and
    incidental whitespace all render the same 32-byte key as different strings.
    A text fingerprint would therefore let the identical key register twice and
    silently defeat the uniqueness constraint that makes the ADR-0007 §4
    substitution attack's precondition unreachable.
    """
    padded = public_key_b64 + "=" * (-len(public_key_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise BadRequestError(f"public key is not valid base64url: {exc}") from exc
    if len(raw) != _ED25519_PUBLIC_KEY_BYTES:
        raise BadRequestError(
            f"an Ed25519 public key is {_ED25519_PUBLIC_KEY_BYTES} bytes, "
            f"got {len(raw)}"
        )
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _authorised_enrollment_target(db: Session, deployment_ref: str) -> None:
    """The ONLY place this service reads `LicenceDeliveryTarget`, and only
    during registration.

    The authority here is platform-admin POLICY; an active delivery target is
    an eligibility INPUT to it, not proof a Deployment exists. The same admin
    can create the target and then the credential, so requiring one before the
    other adds a step, not an independent authority — treating it as
    corroboration would be laundering one actor's assertion through two tables.

    It is still worth doing: it catches a mistyped `deployment_ref` and
    constrains registration to refs this customer's licences may legitimately
    reach. When `FleetDesiredStateService` lands, this check moves to the real
    authority and this reader is deleted along with its architecture canary.
    """
    target = db.execute(
        select(LicenceDeliveryTarget).where(
            LicenceDeliveryTarget.target_ref == deployment_ref,
            LicenceDeliveryTarget.status == TargetStatus.ACTIVE.value,
        )
    ).scalar_one_or_none()
    if target is None:
        raise EnrollmentNotAuthorisedError(
            f"no active delivery target for deployment {deployment_ref!r} — "
            "registration requires an authorised enrollment subject"
        )


def register_credential(
    db: Session,
    *,
    key_id: str,
    deployment_ref: str,
    public_key_b64: str,
    actor_admin_id: UUID | None = None,
) -> DeploymentCredential:
    """Register a public key as `pending`. It authenticates nothing yet.

    Registration proves only that someone submitted a key; it does not prove
    the deployment holds the matching private half. A key that authenticated
    from the moment it was pasted in would let a typo — or an operator with
    control-plane write access — bind an identity the real deployment never
    had. Possession is proven separately, and only then does it activate.
    """
    if not key_id or not deployment_ref:
        raise BadRequestError("key_id and deployment_ref are required")

    fingerprint = public_key_fingerprint(public_key_b64)
    _authorised_enrollment_target(db, deployment_ref)

    # Checked here for a clear error; the DATABASE constraints are what
    # actually enforce it, including against a concurrent registration.
    clash = db.execute(
        select(DeploymentCredential).where(
            (DeploymentCredential.key_id == key_id)
            | (DeploymentCredential.public_key_fingerprint == fingerprint)
        )
    ).scalar_one_or_none()
    if clash is not None:
        detail = (
            f"key_id {key_id!r} is already registered"
            if clash.key_id == key_id
            # Naming the other key_id matters: this is the exact shape of the
            # §4 substitution attempt, and an operator needs to see both ids.
            else f"this public key is already registered as {clash.key_id!r}"
        )
        raise CredentialConflictError(detail)

    credential = DeploymentCredential(
        key_id=key_id,
        deployment_ref=deployment_ref,
        public_key_b64=public_key_b64,
        public_key_fingerprint=fingerprint,
        status=CredentialStatus.PENDING,
        registered_by_admin_id=actor_admin_id,
        enrollment_authority=ENROLLMENT_AUTHORITY_ADMIN_POLICY,
    )
    db.add(credential)
    db.flush()

    write_platform_audit_event(
        db,
        action=_EVENT_REGISTERED,
        entity_type="deployment_credential",
        entity_id=str(credential.id),
        actor_admin_id=actor_admin_id,
        details={
            "key_id": key_id,
            "deployment_ref": deployment_ref,
            "public_key_fingerprint": fingerprint,
            # Provenance, not decoration: the authority under which this was
            # authorised must remain readable after the stopgap is retired.
            "enrollment_authority": ENROLLMENT_AUTHORITY_ADMIN_POLICY,
        },
    )
    enqueue_platform_event(
        db,
        event_type=_EVENT_REGISTERED,
        payload={"key_id": key_id, "deployment_ref": deployment_ref},
    )
    return credential


def issue_challenge(
    db: Session,
    *,
    credential_id: UUID,
    now: datetime,
    ttl: timedelta = _DEFAULT_CHALLENGE_TTL,
    nonce: bytes | None = None,
    challenge_id: str | None = None,
) -> IssuedChallenge:
    """Issue a one-time, expiry-bound possession challenge.

    Issuing a second challenge while a first is outstanding is NORMAL — a
    retry, or an operator re-issuing after a timeout — so this does not refuse.
    Activation invalidates the siblings instead, which is what keeps one
    possession proof to one activation.
    """
    credential = db.get(DeploymentCredential, credential_id)
    if credential is None:
        raise NotFoundError(f"no deployment credential {credential_id}")
    if credential.status != CredentialStatus.PENDING:
        raise BadRequestError(
            f"credential {credential.key_id!r} is {credential.status}, not pending — "
            "possession is proven once, at activation"
        )

    record = DeploymentChallenge(
        challenge_id=challenge_id or f"chal-{uuid4()}",
        credential_id=credential.id,
        # Denormalised as ISSUED, so verification compares against what was
        # signed rather than re-deriving from a row that may have changed.
        key_id=credential.key_id,
        deployment_ref=credential.deployment_ref,
        nonce=nonce if nonce is not None else _fresh_nonce(),
        expires_at=now + ttl,
    )
    db.add(record)
    db.flush()
    return IssuedChallenge(challenge=_to_kernel_challenge(record), record_id=record.id)


def _fresh_nonce() -> bytes:
    import secrets

    return secrets.token_bytes(_NONCE_BYTES)


def _to_kernel_challenge(record: DeploymentChallenge) -> DeploymentPossessionChallenge:
    return DeploymentPossessionChallenge(
        challenge_id=record.challenge_id,
        key_id=record.key_id,
        deployment_ref=record.deployment_ref,
        nonce=record.nonce,
        expires_at=_utc(record.expires_at),
    )


def activate_credential(
    db: Session,
    response: DeploymentPossessionResponse,
    *,
    now: datetime,
    actor_admin_id: UUID | None = None,
) -> DeploymentCredential:
    """Verify a possession response and activate the credential.

    ONE transaction, and the ordering is part of the contract:

    1. Lock the CREDENTIAL, then the challenge — consistent order, so
       concurrent activations cannot deadlock.
    2. Verify with the kernel against the STORED challenge. The response's
       identifiers are routing only; the record supplies the nonce, deployment
       and expiry.
    3. On success only: consume the challenge, activate the credential, and
       invalidate every sibling challenge.

    A FAILED verification consumes nothing — it increments a counter. See
    `DeploymentChallenge` for why consuming on failure would be a denial of
    service on enrollment.
    """
    record = db.execute(
        select(DeploymentChallenge)
        .where(DeploymentChallenge.challenge_id == response.challenge_id)
        .with_for_update()
    ).scalar_one_or_none()
    if record is None:
        raise NotFoundError(f"no challenge {response.challenge_id!r}")
    if record.consumed_at is not None:
        raise BadRequestError(
            f"challenge {record.challenge_id!r} was already consumed "
            f"({record.consumed_reason}) — a possession proof is single-use"
        )

    # Credential first, then challenge, in every path that takes both.
    credential = db.execute(
        select(DeploymentCredential)
        .where(DeploymentCredential.id == record.credential_id)
        .with_for_update()
    ).scalar_one()

    key = DeploymentVerificationKey(
        key_id=credential.key_id,
        public_key_b64=credential.public_key_b64,
        deployment_ref=credential.deployment_ref,
    )
    try:
        verify_possession(_to_kernel_challenge(record), response, key=key, now=now)
    except LicenceError:
        # Counted, not acted on. The kernel's error TYPE is the stable reason
        # (expired vs mismatch vs bad signature) and is re-raised unchanged so
        # the caller does not have to classify a message.
        record.failed_attempts += 1
        db.flush()
        raise

    record.consumed_at = now
    record.consumed_reason = "activated"

    credential.status = CredentialStatus.ACTIVE
    credential.activated_at = now

    # Sibling invalidation is not housekeeping. Leaving other outstanding
    # challenges valid would mean one proof of possession could be followed by
    # a second, independent activation path using a challenge whose response
    # may have been captured elsewhere. One proof activates one credential once.
    siblings = db.execute(
        select(DeploymentChallenge)
        .where(
            DeploymentChallenge.credential_id == credential.id,
            DeploymentChallenge.id != record.id,
            DeploymentChallenge.consumed_at.is_(None),
        )
        .with_for_update()
    ).scalars()
    for sibling in siblings:
        sibling.consumed_at = now
        sibling.consumed_reason = "superseded"

    db.flush()
    write_platform_audit_event(
        db,
        action=_EVENT_ACTIVATED,
        entity_type="deployment_credential",
        entity_id=str(credential.id),
        actor_admin_id=actor_admin_id,
        details={
            "key_id": credential.key_id,
            "deployment_ref": credential.deployment_ref,
            "challenge_id": record.challenge_id,
            "activated_at": now.isoformat(),
        },
    )
    enqueue_platform_event(
        db,
        event_type=_EVENT_ACTIVATED,
        payload={
            "key_id": credential.key_id,
            "deployment_ref": credential.deployment_ref,
        },
    )
    return credential


def resolve_eligible_credential(
    db: Session, *, key_id: str, received_at: datetime
) -> DeploymentCredential | None:
    """The credential that may admit a report received at `received_at`, or None.

    Eligibility is decided against the PERSISTED server receipt time, never the
    payload's `observed_at` (a claim inside data a compromised key's holder
    controls) and never "now" (which would give a different answer each time it
    is re-evaluated).

        activated_at <= received_at
        AND (retired_at IS NULL OR received_at <  retired_at)
        AND (revoked_at IS NULL OR received_at <  revoked_at)

    Read as a window: a credential admits exactly the reports received FROM its
    activation, UP TO BUT NOT INCLUDING its retirement or revocation. Both
    boundaries close against the credential — a report received at the exact
    instant is refused, because the alternative resolves a tie in favour of a
    key the operator has just stood down or declared compromised.

    Returning None is NOT "the signature was bad". Cryptographic attribution is
    a separate question (slice 2 records it separately): a genuinely signed but
    late report from a revoked key is not the same event as garbage naming that
    key, and collapsing them destroys the evidence that a compromised key is
    still in use.
    """
    credential = db.execute(
        select(DeploymentCredential).where(DeploymentCredential.key_id == key_id)
    ).scalar_one_or_none()
    if credential is None or credential.activated_at is None:
        return None
    received_at = _utc(received_at)
    if _utc(credential.activated_at) > received_at:
        return None
    if credential.retired_at is not None and received_at >= _utc(credential.retired_at):
        return None
    if credential.revoked_at is not None and received_at >= _utc(credential.revoked_at):
        return None
    return credential


def _utc(value: datetime) -> datetime:
    """Re-attach UTC to a timestamp a backend returned naive.

    Every timestamp this service writes is timezone-aware UTC, and the columns
    are `DateTime(timezone=True)` — but only Postgres `timestamptz` preserves
    that. SQLite (the unit lane) returns a naive value, which the kernel
    correctly refuses, and which would raise comparing against an aware
    `received_at`. The stored instant is UTC by construction, so re-attaching
    it restores the fact rather than assuming one.
    """
    return value if value.tzinfo else value.replace(tzinfo=UTC)


__all__ = [
    "ENROLLMENT_AUTHORITY_ADMIN_POLICY",
    "CredentialConflictError",
    "EnrollmentNotAuthorisedError",
    "IssuedChallenge",
    "activate_credential",
    "issue_challenge",
    "public_key_fingerprint",
    "register_credential",
    "resolve_eligible_credential",
]
