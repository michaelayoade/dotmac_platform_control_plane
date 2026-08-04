"""V6 slice 1 — credential registry, possession, eligibility (ADR-0007).

Acceptance cases 1–13 and 15–19 from `docs/design/deployment-credentials.md`.
The cases needing a real unique-constraint collision between CONCURRENT
transactions belong to the Postgres suite, not here.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from dotmac_kernel import BadRequestError
from dotmac_kernel.licensing import (
    BadSignatureError,
    DeploymentMismatchError,
    DeploymentPossessionResponse,
    LicenceExpiredError,
    answer_possession_challenge,
)
from dotmac_kernel.testing import (
    FakeDeploymentSigner,
    create_test_engine,
    isolated_session,
)
from sqlalchemy.orm import Session

# Imported for their side effect only. `licence_delivery_targets` sits in a
# metadata graph whose FKs reach issuances -> allocations -> contracts -> offers,
# and create_all resolves every FK in the shared metadata, not just the tables
# a test touches. Nothing here reads these models.
from vendor_cp.allocations import models as _allocations_models  # noqa: F401
from vendor_cp.approvals import models as _approvals_models  # noqa: F401
from vendor_cp.contracts import models as _contracts_models  # noqa: F401
from vendor_cp.licensing import models as _licensing_models  # noqa: F401
from vendor_cp.licensing.credential_models import (
    CredentialStatus,
    DeploymentChallenge,
    DeploymentCredential,
)
from vendor_cp.licensing.credentials import (
    ENROLLMENT_AUTHORITY_ADMIN_POLICY,
    CredentialConflictError,
    EnrollmentNotAuthorisedError,
    activate_credential,
    issue_challenge,
    public_key_fingerprint,
    register_credential,
    resolve_eligible_credential,
)
from vendor_cp.licensing.delivery_models import LicenceDeliveryTarget, TargetStatus
from vendor_cp.offers import models as _offers_models  # noqa: F401

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
DEP = "edge-site-1"
KEY_ID = "dep-edge1-2026-08"


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


def _utc(value):
    """SQLite does not persist offsets, so a timestamp written aware comes back
    naive. Postgres `timestamptz` does. Normalising here keeps these assertions
    about the stored INSTANT rather than about the backend's tz fidelity."""
    return value if value is None or value.tzinfo else value.replace(tzinfo=UTC)


def _target(db, ref: str = DEP, status: str = TargetStatus.ACTIVE.value):
    target = LicenceDeliveryTarget(target_ref=ref, customer_ref="cust-1", status=status)
    db.add(target)
    db.flush()
    return target


def _registered(db, signer, key_id: str = KEY_ID, ref: str = DEP):
    _target(db, ref)
    return register_credential(
        db,
        key_id=key_id,
        deployment_ref=ref,
        public_key_b64=signer.public_key_b64,
        actor_admin_id=uuid4(),
    )


# ── Enrollment ──────────────────────────────────────────────────────────────


def test_registration_without_an_active_target_is_refused(db, signer) -> None:
    with pytest.raises(EnrollmentNotAuthorisedError):
        register_credential(
            db,
            key_id=KEY_ID,
            deployment_ref="never-enrolled",
            public_key_b64=signer.public_key_b64,
        )


def test_an_inactive_target_does_not_authorise_registration(db, signer) -> None:
    _target(db, "paused-site", status=TargetStatus.SUSPENDED.value)
    with pytest.raises(EnrollmentNotAuthorisedError):
        register_credential(
            db,
            key_id=KEY_ID,
            deployment_ref="paused-site",
            public_key_b64=signer.public_key_b64,
        )


def test_registration_records_the_authority_it_was_granted_under(db, signer) -> None:
    """When FleetDesiredStateService lands, historic registrations must still
    read as 'authorised under the stopgap' rather than being reinterpreted."""
    credential = _registered(db, signer)
    assert credential.enrollment_authority == ENROLLMENT_AUTHORITY_ADMIN_POLICY
    assert credential.registered_by_admin_id is not None


def test_a_target_going_inactive_does_not_disturb_an_existing_credential(
    db, signer
) -> None:
    """The target gated ONE moment — registration — and has no standing over a
    credential whose possession has since been proven. Coupling them would let
    a delivery-routing edit revoke a proven identity."""
    credential = _registered(db, signer)
    challenge = issue_challenge(db, credential_id=credential.id, now=NOW).challenge
    activate_credential(
        db, answer_possession_challenge(challenge, signer=signer), now=NOW
    )

    target = db.query(LicenceDeliveryTarget).filter_by(target_ref=DEP).one()
    target.status = TargetStatus.SUSPENDED.value
    db.flush()

    assert credential.status == CredentialStatus.ACTIVE
    assert resolve_eligible_credential(db, key_id=KEY_ID, received_at=NOW) is not None


# ── Registry uniqueness ─────────────────────────────────────────────────────


def test_a_newly_registered_credential_is_pending_and_authenticates_nothing(
    db, signer
) -> None:
    credential = _registered(db, signer)
    assert credential.status == CredentialStatus.PENDING
    assert credential.activated_at is None
    assert resolve_eligible_credential(db, key_id=KEY_ID, received_at=NOW) is None


def test_the_same_public_key_cannot_be_registered_under_a_second_key_id(
    db, signer
) -> None:
    """THE §4 precondition. Signing key_id makes the substitution
    unexploitable; this makes registering the same material twice
    unreachable."""
    _registered(db, signer)
    _target(db, "other-site")
    with pytest.raises(CredentialConflictError, match="already registered as"):
        register_credential(
            db,
            key_id="key-b",
            deployment_ref="other-site",
            public_key_b64=signer.public_key_b64,
        )


def test_a_re_encoded_variant_of_the_same_key_is_still_refused(db, signer) -> None:
    """The fingerprint is over DECODED bytes. base64 is not canonical, so a
    padded or standard-alphabet variant of the same key must collide."""
    _registered(db, signer)
    raw = base64.urlsafe_b64decode(
        signer.public_key_b64 + "=" * (-len(signer.public_key_b64) % 4)
    )
    variant = base64.urlsafe_b64encode(raw).decode()  # WITH padding this time
    assert variant != signer.public_key_b64
    assert public_key_fingerprint(variant) == public_key_fingerprint(
        signer.public_key_b64
    )
    _target(db, "other-site")
    with pytest.raises(CredentialConflictError):
        register_credential(
            db,
            key_id="key-b",
            deployment_ref="other-site",
            public_key_b64=variant,
        )


def test_a_duplicate_key_id_is_refused(db, signer) -> None:
    _registered(db, signer)
    other = FakeDeploymentSigner(key_id=KEY_ID, deployment_ref=DEP)
    with pytest.raises(CredentialConflictError, match="already registered"):
        register_credential(
            db,
            key_id=KEY_ID,
            deployment_ref=DEP,
            public_key_b64=other.public_key_b64,
        )


@pytest.mark.parametrize("bad", ["not base64!!", "c2hvcnQ", ""])
def test_a_malformed_public_key_is_refused(db, signer, bad) -> None:
    _target(db)
    with pytest.raises(BadRequestError):
        register_credential(db, key_id=KEY_ID, deployment_ref=DEP, public_key_b64=bad)


# ── Possession ──────────────────────────────────────────────────────────────


def test_a_correct_response_activates_and_consumes_the_challenge(db, signer) -> None:
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    activate_credential(
        db, answer_possession_challenge(issued.challenge, signer=signer), now=NOW
    )
    record = db.get(DeploymentChallenge, issued.record_id)
    assert credential.status == CredentialStatus.ACTIVE
    assert _utc(credential.activated_at) == NOW
    assert _utc(record.consumed_at) == NOW
    assert record.consumed_reason == "activated"


def test_activation_invalidates_sibling_challenges(db, signer) -> None:
    """One possession proof activates one credential once. A live sibling would
    allow a second, independent activation path using a response that may have
    been captured elsewhere."""
    credential = _registered(db, signer)
    first = issue_challenge(db, credential_id=credential.id, now=NOW)
    second = issue_challenge(db, credential_id=credential.id, now=NOW)
    activate_credential(
        db, answer_possession_challenge(second.challenge, signer=signer), now=NOW
    )
    orphan = db.get(DeploymentChallenge, first.record_id)
    assert _utc(orphan.consumed_at) == NOW
    assert orphan.consumed_reason == "superseded"


def test_replaying_a_consumed_response_activates_nothing(db, signer) -> None:
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    response = answer_possession_challenge(issued.challenge, signer=signer)
    activate_credential(db, response, now=NOW)
    with pytest.raises(Exception, match="already consumed"):
        activate_credential(db, response, now=NOW)


def test_a_FAILED_attempt_does_not_consume_the_challenge(db, signer) -> None:
    """Consuming on failure hands an enrollment denial-of-service to anyone who
    learns the routing identifiers — they travel in the response and identify a
    record, they do not authenticate it. The correct response must still work
    afterwards."""
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    forged = DeploymentPossessionResponse(
        challenge_id=issued.challenge.challenge_id,
        key_id=KEY_ID,
        signature=b"\x00" * 64,
    )
    with pytest.raises(BadSignatureError):
        activate_credential(db, forged, now=NOW)

    record = db.get(DeploymentChallenge, issued.record_id)
    assert record.consumed_at is None, "a bad signature burned the challenge"
    assert record.failed_attempts == 1

    activate_credential(
        db, answer_possession_challenge(issued.challenge, signer=signer), now=NOW
    )
    assert credential.status == CredentialStatus.ACTIVE


def test_invalid_attempts_are_counted(db, signer) -> None:
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    forged = DeploymentPossessionResponse(
        challenge_id=issued.challenge.challenge_id,
        key_id=KEY_ID,
        signature=b"\x01" * 64,
    )
    for _ in range(3):
        with pytest.raises(BadSignatureError):
            activate_credential(db, forged, now=NOW)
    assert db.get(DeploymentChallenge, issued.record_id).failed_attempts == 3


def test_an_expired_challenge_is_refused_as_expired(db, signer) -> None:
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    with pytest.raises(LicenceExpiredError):
        activate_credential(
            db,
            answer_possession_challenge(issued.challenge, signer=signer),
            now=NOW + timedelta(hours=2),
        )


def test_a_response_naming_another_key_is_a_mismatch(db, signer) -> None:
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    forged = DeploymentPossessionResponse(
        challenge_id=issued.challenge.challenge_id,
        key_id="not-this-key",
        signature=answer_possession_challenge(
            issued.challenge, signer=signer
        ).signature,
    )
    with pytest.raises(DeploymentMismatchError):
        activate_credential(db, forged, now=NOW)


def test_a_challenge_cannot_be_issued_for_an_already_active_credential(
    db, signer
) -> None:
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    activate_credential(
        db, answer_possession_challenge(issued.challenge, signer=signer), now=NOW
    )
    with pytest.raises(Exception, match="not pending"):
        issue_challenge(db, credential_id=credential.id, now=NOW)


# ── Eligibility window ──────────────────────────────────────────────────────


def _active(db, signer):
    credential = _registered(db, signer)
    issued = issue_challenge(db, credential_id=credential.id, now=NOW)
    activate_credential(
        db, answer_possession_challenge(issued.challenge, signer=signer), now=NOW
    )
    return credential


def test_a_report_received_before_activation_is_not_admitted(db, signer) -> None:
    """Later activation must not retro-admit what arrived before possession was
    proven — otherwise activating a key silently blesses everything it already
    sent."""
    _active(db, signer)
    assert (
        resolve_eligible_credential(
            db, key_id=KEY_ID, received_at=NOW - timedelta(seconds=1)
        )
        is None
    )


def test_a_report_received_at_activation_is_admitted(db, signer) -> None:
    _active(db, signer)
    assert resolve_eligible_credential(db, key_id=KEY_ID, received_at=NOW) is not None


@pytest.mark.parametrize("field", ["retired_at", "revoked_at"])
def test_the_closing_boundary_is_closed_against_the_credential(
    db, signer, field
) -> None:
    """A report received at the EXACT retirement or revocation instant is
    refused: the alternative resolves a tie in favour of a key the operator has
    just stood down or declared compromised."""
    credential = _active(db, signer)
    cut = NOW + timedelta(hours=1)
    setattr(credential, field, cut)
    credential.status = (
        CredentialStatus.RETIRED if field == "retired_at" else CredentialStatus.REVOKED
    )
    db.flush()

    assert (
        resolve_eligible_credential(
            db, key_id=KEY_ID, received_at=cut - timedelta(seconds=1)
        )
        is not None
    )
    assert resolve_eligible_credential(db, key_id=KEY_ID, received_at=cut) is None
    assert (
        resolve_eligible_credential(
            db, key_id=KEY_ID, received_at=cut + timedelta(days=365)
        )
        is None
    )


def test_a_backdated_report_cannot_evade_revocation(db, signer) -> None:
    """Eligibility uses the PERSISTED server receipt time. The payload's
    observed_at is a claim inside data a compromised key's holder controls."""
    credential = _active(db, signer)
    revoked = NOW + timedelta(hours=1)
    credential.revoked_at = revoked
    credential.status = CredentialStatus.REVOKED
    db.flush()
    # Received after revocation — whatever the payload claims about itself.
    assert (
        resolve_eligible_credential(
            db, key_id=KEY_ID, received_at=revoked + timedelta(minutes=5)
        )
        is None
    )


def test_an_unknown_key_id_resolves_to_nothing(db) -> None:
    assert resolve_eligible_credential(db, key_id="never-seen", received_at=NOW) is None


def test_rotation_overlap_admits_both_windows(db) -> None:
    """Overlap is expressed as overlapping WINDOWS, not as a retired key
    admitting new work indefinitely."""
    old = FakeDeploymentSigner(key_id="key-old", deployment_ref=DEP)
    new = FakeDeploymentSigner(key_id="key-new", deployment_ref=DEP)
    _target(db)

    for signer_, key_id in ((old, "key-old"), (new, "key-new")):
        cred = register_credential(
            db,
            key_id=key_id,
            deployment_ref=DEP,
            public_key_b64=signer_.public_key_b64,
        )
        issued = issue_challenge(db, credential_id=cred.id, now=NOW)
        activate_credential(
            db, answer_possession_challenge(issued.challenge, signer=signer_), now=NOW
        )

    changeover = NOW + timedelta(hours=1)
    old_cred = db.query(DeploymentCredential).filter_by(key_id="key-old").one()
    old_cred.retired_at = changeover + timedelta(hours=1)
    old_cred.status = CredentialStatus.RETIRED
    db.flush()

    # Both windows cover the changeover; each report is attributed to the key
    # that signed it.
    assert (
        resolve_eligible_credential(db, key_id="key-old", received_at=changeover)
        is not None
    )
    assert (
        resolve_eligible_credential(db, key_id="key-new", received_at=changeover)
        is not None
    )
