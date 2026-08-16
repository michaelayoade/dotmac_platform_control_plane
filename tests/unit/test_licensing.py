"""Unit tests for `LicenceIssuanceService` (SQLite).

The vendor half of WS8, against the acceptance cases in
`docs/design/licence-service.md`: every issued envelope verifies through the
PINNED kernel verifier, lineage versions are monotonic, issuance is immutable
and idempotent per allocation, capabilities come from the staged allocation,
binding is contracted, key rotation behaves, and no private key material is
ever persisted.

The chain is driven end-to-end from a real ContractService activation →
AllocationService staging → issuance, so the boundaries are exercised as they
compose in production, not through hand-built fixtures.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta

import pytest
from dotmac_kernel.entitlements import TenantEntitlementGrant
from dotmac_kernel.licensing import (
    AppliedLicence,
    BadSignatureError,
    LicenceExpiredError,
    RevokedKeyError,
    StaleLicenceError,
    UnknownKeyError,
    verify_licence,
)
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter as allocations
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import service as contracts
from vendor_cp.contracts.models import Contract
from vendor_cp.licensing import service as licensing
from vendor_cp.licensing.models import (
    Licence,
    LicenceIssuance,
    LicenceSigningKey,
    SigningKeyStatus,
)
from vendor_cp.licensing.signer import (
    EphemeralLicenceSigner,
    SigningKeyUnavailableError,
    SigningModeNotPermittedError,
    build_licence_signer,
)
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion

NOW = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)
PRODUCT = "dotmac-sub"


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


@pytest.fixture
def signer() -> EphemeralLicenceSigner:
    return EphemeralLicenceSigner(key_id="vendor-key-1")


def _approve(db: Session, contract_id: uuid.UUID, content_hash: str | None) -> None:
    """Reach quorum on the contract's OWN approval request.

    `submit` opened that request and stored its id on the row, so the id is read
    back off the ORM row — the service returns a view, which does not carry it.
    """
    assert content_hash is not None
    row = db.get(Contract, contract_id)
    assert row is not None and row.approval_request_id is not None
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"dec-{uuid.uuid4()}",
            request_id=row.approval_request_id,
            approver_id=uuid.uuid4(),
            content_hash=content_hash,
        ),
    )


def _catalogue(*codes: str) -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({PRODUCT: tuple(codes)})


def _staged_allocation(
    db: Session, *, suffix: str = "a", customer_ref: str | None = None
) -> uuid.UUID:
    """Drive contract → activate → stage, returning the staged allocation id.

    `customer_ref` is separable from `suffix` so a RENEWAL — a second contract
    for the same customer — can be driven through the real path. The allocation
    is the module's now, and its rows are immutable by design; a test that
    reached in and rewrote `customer_ref` afterwards would be asserting against
    a state production can never produce.
    """
    customer_ref = customer_ref or f"cust-{suffix}"
    offer_code = f"off-{suffix}"
    db.add(
        OfferVersion(
            product_code=PRODUCT,
            offer_code=offer_code,
            version=1,
            amount="10.00",
            currency_code="USD",
            capability_codes=["cap.a", "cap.b"],
        )
    )
    db.flush()
    draft = contracts.create_draft(
        db,
        contracts.CreateDraftCommand(
            command_id=f"d-{uuid.uuid4()}",
            product_code=PRODUCT,
            customer_ref=customer_ref,
            legal_entity="Dotmac Ltd",
            currency_code="USD",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(
                contracts.LineInput(offer_code, 1, "cap.a", quantity=2),
                contracts.LineInput(offer_code, 1, "cap.b", quantity=1),
            ),
        ),
    )
    # The policy must exist BEFORE submit: submit opens the approval
    # request against that exact revision, so publishing after it would
    # be too late.
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"pol-{uuid.uuid4()}",
            policy_code=f"p-{suffix}",
            version=1,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    submitted = contracts.submit(
        db,
        contracts.SubmitCommand(
            command_id=f"s-{uuid.uuid4()}",
            contract_id=draft.id,
            approval_policy_code=f"p-{suffix}",
            approval_policy_version=1,
            submitter_id=uuid.uuid4(),
        ),
        catalogues=_catalogue("cap.a", "cap.b"),
    )
    _approve(db, draft.id, submitted.content_hash)
    contracts.approve(
        db,
        contracts.TransitionCommand(
            command_id=f"ap-{uuid.uuid4()}", contract_id=draft.id
        ),
    )
    contracts.activate(
        db,
        contracts.TransitionCommand(
            command_id=f"act-{uuid.uuid4()}",
            contract_id=draft.id,
            activation_evidence="countersigned",
        ),
    )
    view = allocations.stage_allocation(
        db,
        allocations.StageAllocationCommand(
            source_event_id=f"evt-{uuid.uuid4()}",
            contract_id=draft.id,
            content_hash=submitted.content_hash or "",
            customer_ref=customer_ref,
        ),
        catalogues=_catalogue("cap.a", "cap.b"),
    )
    return view.id


def _issue(db, allocation_id, signer, **over):
    return licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(
            allocation_id=allocation_id,
            product=over.pop("product", PRODUCT),
            **over,
        ),
        signer=signer,
        now=over.pop("now", NOW),
    )


# ── 1. Round-trip against the pinned kernel verifier ────────────────────────


def test_issued_envelope_verifies_with_the_kernel(db: Session, signer) -> None:
    alloc = _staged_allocation(db)
    issued = _issue(db, alloc, signer)

    verified = verify_licence(
        issued.envelope, keyring=licensing.build_keyring(db), now=NOW
    )
    assert verified.document.licence_id == str(issued.licence_id)
    assert verified.document.licence_version == 1
    assert verified.document.product == PRODUCT
    assert verified.digest == issued.digest
    assert verified.validity == "valid"


def test_capabilities_and_limits_come_from_the_allocation(db: Session, signer) -> None:
    alloc = _staged_allocation(db)
    issued = _issue(db, alloc, signer)
    verified = verify_licence(
        issued.envelope, keyring=licensing.build_keyring(db), now=NOW
    )
    granted = {c.code: dict(c.limits) for c in verified.document.capabilities}
    assert granted == {"cap.a": {"quantity": 2}, "cap.b": {"quantity": 1}}


def test_tampered_envelope_fails_verification(db: Session, signer) -> None:
    alloc = _staged_allocation(db)
    issued = _issue(db, alloc, signer)
    envelope = dict(issued.envelope)
    payload_b64 = envelope["payload_b64"]
    assert isinstance(payload_b64, str)
    doc = json.loads(
        base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    )
    doc["capabilities"] = [{"code": "everything.use", "limits": {}}]
    envelope["payload_b64"] = (
        base64.urlsafe_b64encode(json.dumps(doc).encode()).rstrip(b"=").decode()
    )
    with pytest.raises(BadSignatureError):
        verify_licence(envelope, keyring=licensing.build_keyring(db), now=NOW)


# ── 2. Lineage + version monotonicity ───────────────────────────────────────


def test_second_allocation_issues_next_version_in_same_lineage(
    db: Session, signer
) -> None:
    first = _issue(db, _staged_allocation(db, suffix="a"), signer)
    # A renewal for the SAME customer+product — a new contract and a new
    # allocation, but one customer, so one lineage.
    second_alloc = _staged_allocation(db, suffix="a2", customer_ref="cust-a")
    licence = db.get(Licence, first.licence_id)
    assert licence is not None and licence.customer_ref == "cust-a"

    second = _issue(db, second_alloc, signer)
    assert second.licence_id == first.licence_id
    assert (first.version, second.version) == (1, 2)


def test_a_lower_version_cannot_supersede_a_higher_one(db: Session, signer) -> None:
    """The vendor's monotonic versions are what make the receiver's rollback
    guard work — prove the pairing end to end."""
    first = _issue(db, _staged_allocation(db, suffix="a"), signer)
    second_alloc = _staged_allocation(db, suffix="a2", customer_ref="cust-a")
    second = _issue(db, second_alloc, signer)

    keyring = licensing.build_keyring(db)
    applied = AppliedLicence(
        licence_id=str(second.licence_id),
        licence_version=second.version,
        digest=second.digest,
    )
    with pytest.raises(StaleLicenceError):
        verify_licence(first.envelope, keyring=keyring, now=NOW, applied=applied)


def test_distinct_products_are_distinct_lineages(db: Session, signer) -> None:
    alloc_one = _staged_allocation(db, suffix="a")
    alloc_two = _staged_allocation(db, suffix="b")
    one = _issue(db, alloc_one, signer, product="dotmac-sub")
    two = _issue(db, alloc_two, signer, product="dotmac-erp")
    assert one.licence_id != two.licence_id
    assert one.version == two.version == 1


# ── 3. Immutability + idempotency ───────────────────────────────────────────


def test_reissuing_the_same_allocation_is_idempotent(db: Session, signer) -> None:
    alloc = _staged_allocation(db)
    first = _issue(db, alloc, signer)
    second = _issue(db, alloc, signer)
    assert (second.id, second.version, second.digest) == (
        first.id,
        first.version,
        first.digest,
    )
    assert (
        db.execute(select(func.count()).select_from(LicenceIssuance)).scalar_one() == 1
    )


def test_issuance_emits_a_platform_outbox_event_atomically(db: Session, signer) -> None:
    alloc = _staged_allocation(db)
    issued = _issue(db, alloc, signer)
    events = (
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "licence.issued"
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].payload["digest"] == issued.digest
    assert events[0].payload["licence_version"] == 1


def test_issuance_writes_no_product_entitlement_grants(db: Session, signer) -> None:
    """The C4 boundary: the vendor control plane never writes a product data
    plane's WS2 grants — it issues a document and stops."""
    _issue(db, _staged_allocation(db), signer)
    assert (
        db.execute(
            select(func.count()).select_from(TenantEntitlementGrant)
        ).scalar_one()
        == 0
    )


# ── 4. Validity + binding are contracted ────────────────────────────────────


def test_expiry_and_grace_are_carried_into_the_document(db: Session, signer) -> None:
    alloc = _staged_allocation(db)
    issued = _issue(
        db,
        alloc,
        signer,
        expires_at=NOW + timedelta(days=30),
        grace_days=14,
    )
    keyring = licensing.build_keyring(db)
    # Inside the term.
    assert verify_licence(issued.envelope, keyring=keyring, now=NOW).validity == "valid"
    # Past expiry but inside grace.
    in_grace = verify_licence(
        issued.envelope, keyring=keyring, now=NOW + timedelta(days=35)
    )
    assert in_grace.validity == "in_grace"
    # Past grace.
    with pytest.raises(LicenceExpiredError):
        verify_licence(issued.envelope, keyring=keyring, now=NOW + timedelta(days=60))


def test_deployment_binding_is_recorded_when_contracted(db: Session, signer) -> None:
    alloc = _staged_allocation(db)
    issued = _issue(db, alloc, signer, deployment_id="dep-a")
    verified = verify_licence(
        issued.envelope,
        keyring=licensing.build_keyring(db),
        now=NOW,
        expected_deployment_id="dep-a",
    )
    assert verified.document.subject.deployment_id == "dep-a"


def test_unbound_by_default(db: Session, signer) -> None:
    issued = _issue(db, _staged_allocation(db), signer)
    verified = verify_licence(
        issued.envelope, keyring=licensing.build_keyring(db), now=NOW
    )
    assert verified.document.subject.deployment_id is None


# ── 5. Key registry + rotation ──────────────────────────────────────────────


def test_signing_key_public_material_is_registered_on_issue(
    db: Session, signer
) -> None:
    _issue(db, _staged_allocation(db), signer)
    row = db.execute(
        select(LicenceSigningKey).where(LicenceSigningKey.key_id == "vendor-key-1")
    ).scalar_one()
    assert row.public_key_b64 == signer.public_key_b64
    assert row.status == SigningKeyStatus.ACTIVE.value


def test_no_private_key_material_is_persisted(db: Session, signer) -> None:
    """Structural: the key table has no private column, and nothing anywhere
    stores the private bytes."""
    assert "private" not in {c.name for c in LicenceSigningKey.__table__.columns}
    _issue(db, _staged_allocation(db), signer)
    private_bytes = signer._private_key.private_bytes_raw()  # noqa: SLF001 (test)
    leaked = base64.urlsafe_b64encode(private_bytes).rstrip(b"=").decode()
    row = db.execute(select(LicenceSigningKey)).scalar_one()
    assert leaked not in (row.public_key_b64, row.key_id)


def test_retired_key_still_verifies_but_revoked_does_not(db: Session, signer) -> None:
    issued = _issue(db, _staged_allocation(db), signer)

    licensing.set_key_status(db, key_id="vendor-key-1", status=SigningKeyStatus.RETIRED)
    verify_licence(issued.envelope, keyring=licensing.build_keyring(db), now=NOW)

    licensing.set_key_status(db, key_id="vendor-key-1", status=SigningKeyStatus.REVOKED)
    with pytest.raises(RevokedKeyError):
        verify_licence(issued.envelope, keyring=licensing.build_keyring(db), now=NOW)


def test_a_key_outside_the_registry_is_unknown_to_deployments(
    db: Session, signer
) -> None:
    """A document signed by a key the registry never published cannot verify —
    the keyring is a closed world."""
    alloc = _staged_allocation(db)
    issued = _issue(db, alloc, signer)
    stranger_ring = licensing.build_keyring(db)
    db.execute(select(LicenceSigningKey))  # registry currently holds vendor-key-1 only
    # Rebuild an envelope claiming an unregistered key id.
    envelope = dict(issued.envelope)
    signatures = [dict(s) for s in envelope["signatures"]]  # type: ignore[union-attr]
    signatures[0]["key_id"] = "not-registered"
    envelope["signatures"] = signatures
    with pytest.raises(UnknownKeyError):
        verify_licence(envelope, keyring=stranger_ring, now=NOW)


# ── 6. Signing-mode fail-closed ─────────────────────────────────────────────


def test_unknown_signing_mode_refuses_to_build(monkeypatch) -> None:
    from vendor_cp import config as vendor_config
    from vendor_cp.licensing import signer as signer_module

    monkeypatch.setattr(
        signer_module,
        "vendor_settings",
        vendor_config.VendorSettings(
            provider_mode="fake", licence_signing_mode="hsm-someday"
        ),
    )
    with pytest.raises(SigningModeNotPermittedError, match="hsm-someday"):
        build_licence_signer()


def test_configured_mode_without_a_key_fails_startup(monkeypatch) -> None:
    """`configured` is a real mode now, but selecting it without key material
    must fail loudly rather than fall back to a throwaway key."""
    from vendor_cp import config as vendor_config
    from vendor_cp.licensing import signer as signer_module

    monkeypatch.setattr(
        signer_module,
        "vendor_settings",
        vendor_config.VendorSettings(
            provider_mode="fake", licence_signing_mode="configured"
        ),
    )
    with pytest.raises(SigningKeyUnavailableError):
        build_licence_signer()


def test_ephemeral_is_the_default_mode() -> None:
    assert build_licence_signer("k").key_id == "k"


# ── 7. Guards ───────────────────────────────────────────────────────────────


def test_unknown_allocation_is_rejected(db: Session, signer) -> None:
    from dotmac_kernel import NotFoundError

    with pytest.raises(NotFoundError):
        _issue(db, uuid.uuid4(), signer)
