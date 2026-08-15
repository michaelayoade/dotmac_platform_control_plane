"""Key custody + the full rotation lifecycle (WS8 production-readiness).

Rotation is the operation most likely to take a fleet offline, because the
failure is silent: documents keep being issued, and only deployments that
haven't received the new keyring discover they can no longer verify. So the
overlap is exercised here as a SEQUENCE, not as isolated unit assertions —

    active → (publish new key, double-sign) → retire old → revoke old

— with, at each step, the two populations that matter checked separately: a
deployment still holding only the OLD keyring, and one holding only the NEW.

Also covers `configured` key custody: the key is read from a file whose
canonical source is OpenBao, and every failure path must name the path and the
shape problem while never revealing the bytes.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotmac_kernel.licensing import (
    BadSignatureError,
    LicenceKey,
    LicenceKeyRing,
    RevokedKeyError,
    UnknownKeyError,
    verify_licence,
)
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp import config as vendor_config
from vendor_cp.allocations import service as allocations
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import service as contracts
from vendor_cp.contracts.models import Contract
from vendor_cp.licensing import service as licensing
from vendor_cp.licensing import signer as signer_module
from vendor_cp.licensing.models import SigningKeyStatus
from vendor_cp.licensing.signer import (
    ConfiguredLicenceSigner,
    EphemeralLicenceSigner,
    SigningKeyUnavailableError,
    build_licence_signer,
    build_overlap_signer,
)
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion

NOW = datetime(2026, 8, 2, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


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
    return ProductCapabilityCatalogues.from_capabilities({"dotmac-sub": tuple(codes)})


def _staged(db: Session, *, suffix: str, customer_ref: str) -> uuid.UUID:
    offer_code = f"off-{suffix}"
    db.add(
        OfferVersion(
            product_code="dotmac-sub",
            offer_code=offer_code,
            version=1,
            amount="10.00",
            currency_code="USD",
            capability_codes=["cap.a"],
        )
    )
    db.flush()
    draft = contracts.create_draft(
        db,
        contracts.CreateDraftCommand(
            command_id=f"d-{uuid.uuid4()}",
            product_code="dotmac-sub",
            customer_ref=customer_ref,
            legal_entity="Dotmac Ltd",
            currency_code="USD",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(contracts.LineInput(offer_code, 1, "cap.a", quantity=1),),
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
        catalogues=_catalogue("cap.a"),
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
    return allocations.stage_allocation(
        db,
        allocations.StageAllocationCommand(
            source_event_id=f"evt-{uuid.uuid4()}",
            contract_id=draft.id,
            content_hash=submitted.content_hash or "",
            customer_ref=customer_ref,
        ),
    ).id


def _issue(db, *, suffix, customer_ref, signer, overlap_signers=()):
    return licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(
            allocation_id=_staged(db, suffix=suffix, customer_ref=customer_ref),
            product="dotmac-sub",
        ),
        signer=signer,
        overlap_signers=overlap_signers,
        now=NOW,
    )


def _ring_of(signer) -> LicenceKeyRing:
    """A deployment holding ONLY this key — the population that matters when
    reasoning about who can still verify mid-rotation."""
    return LicenceKeyRing(
        [LicenceKey(key_id=signer.key_id, public_key_b64=signer.public_key_b64)]
    )


# ── The rotation sequence ───────────────────────────────────────────────────


def test_rotation_overlap_keeps_both_fleet_populations_verifying(db) -> None:
    old = EphemeralLicenceSigner(key_id="vendor-2026-a")
    new = EphemeralLicenceSigner(key_id="vendor-2026-b")

    # 1. Before rotation: signed with the old key only.
    before = _issue(db, suffix="a", customer_ref="cust-a", signer=old)
    verify_licence(before.envelope, keyring=_ring_of(old), now=NOW)
    with pytest.raises(UnknownKeyError):
        verify_licence(before.envelope, keyring=_ring_of(new), now=NOW)

    # 2. Overlap: every document is double-signed, so BOTH populations verify
    #    the SAME envelope — this is what makes rotation non-breaking.
    during = _issue(
        db, suffix="b", customer_ref="cust-b", signer=old, overlap_signers=(new,)
    )
    assert len(during.envelope["signatures"]) == 2
    verify_licence(during.envelope, keyring=_ring_of(old), now=NOW)
    verify_licence(during.envelope, keyring=_ring_of(new), now=NOW)

    # 3. After the fleet has the new keyring: sign with the new key alone.
    after = _issue(db, suffix="c", customer_ref="cust-c", signer=new)
    verify_licence(after.envelope, keyring=_ring_of(new), now=NOW)
    with pytest.raises(UnknownKeyError):
        verify_licence(after.envelope, keyring=_ring_of(old), now=NOW)


def test_retiring_the_old_key_keeps_the_installed_base_working(db) -> None:
    """`retired` is the whole point of the state: documents already out in the
    field must keep verifying, or rotation would be a fleet-wide outage."""
    old = EphemeralLicenceSigner(key_id="vendor-2026-a")
    new = EphemeralLicenceSigner(key_id="vendor-2026-b")
    issued = _issue(db, suffix="a", customer_ref="cust-a", signer=old)

    licensing.register_signing_key(
        db, key_id=new.key_id, public_key_b64=new.public_key_b64
    )
    licensing.set_key_status(db, key_id=old.key_id, status=SigningKeyStatus.RETIRED)

    # The distributed keyring now holds retired-old + active-new; the older
    # document still verifies.
    verified = verify_licence(
        issued.envelope, keyring=licensing.build_keyring(db), now=NOW
    )
    assert verified.document.licence_version == 1


def test_revoking_a_compromised_key_kills_its_documents_but_not_the_overlap(
    db,
) -> None:
    """Compromise response: revoke, and everything signed ONLY by that key
    stops verifying immediately. A document that was double-signed during an
    overlap survives via the other signature — which is exactly why the
    overlap window is also a safety margin."""
    compromised = EphemeralLicenceSigner(key_id="vendor-2026-a")
    healthy = EphemeralLicenceSigner(key_id="vendor-2026-b")

    single = _issue(db, suffix="a", customer_ref="cust-a", signer=compromised)
    double = _issue(
        db,
        suffix="b",
        customer_ref="cust-b",
        signer=compromised,
        overlap_signers=(healthy,),
    )
    licensing.set_key_status(
        db, key_id=compromised.key_id, status=SigningKeyStatus.REVOKED
    )
    keyring = licensing.build_keyring(db)

    with pytest.raises(RevokedKeyError):
        verify_licence(single.envelope, keyring=keyring, now=NOW)
    verify_licence(double.envelope, keyring=keyring, now=NOW)


def test_overlap_registers_both_public_keys_for_distribution(db) -> None:
    """A signature nobody can verify is worse than no signature: both halves
    must reach the distributed keyring before the document does."""
    old = EphemeralLicenceSigner(key_id="vendor-2026-a")
    new = EphemeralLicenceSigner(key_id="vendor-2026-b")
    _issue(db, suffix="a", customer_ref="cust-a", signer=old, overlap_signers=(new,))

    assert licensing.build_keyring(db).key_ids == frozenset(
        {"vendor-2026-a", "vendor-2026-b"}
    )


def test_a_forged_overlap_signature_does_not_grant_verification(db) -> None:
    """Two signatures are not "more trusted" — each must independently verify
    under a key in the ring."""
    real = EphemeralLicenceSigner(key_id="vendor-2026-a")
    impostor = EphemeralLicenceSigner(key_id="vendor-2026-b")
    issued = _issue(
        db, suffix="a", customer_ref="cust-a", signer=real, overlap_signers=(impostor,)
    )
    # A ring that trusts ONLY the impostor's key id, but with the real key's
    # public bytes — i.e. the impostor's signature cannot check out.
    mismatched = LicenceKeyRing(
        [LicenceKey(key_id=impostor.key_id, public_key_b64=real.public_key_b64)]
    )
    with pytest.raises(BadSignatureError):
        verify_licence(issued.envelope, keyring=mismatched, now=NOW)


# ── Configured key custody ──────────────────────────────────────────────────


def _write_key(tmp_path, name: str = "signing.key") -> tuple[str, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes_raw()
    path = tmp_path / name
    path.write_text(base64.urlsafe_b64encode(raw).rstrip(b"=").decode())
    return str(path), key


def test_configured_signer_loads_the_key_and_signs(tmp_path) -> None:
    path, key = _write_key(tmp_path)
    signer = ConfiguredLicenceSigner(key_id="vendor-prod-1", key_file=path)

    assert signer.key_id == "vendor-prod-1"
    # Signs verifiably under the file's key.
    key.public_key().verify(signer.sign(b"payload"), b"payload")


def test_configured_mode_is_selected_by_settings(tmp_path, monkeypatch) -> None:
    path, _ = _write_key(tmp_path)
    monkeypatch.setattr(
        signer_module,
        "vendor_settings",
        vendor_config.VendorSettings(
            provider_mode="fake",
            licence_signing_mode="configured",
            licence_signing_key_file=path,
            licence_signing_key_id="vendor-prod-1",
        ),
    )
    assert build_licence_signer().key_id == "vendor-prod-1"
    # No overlap configured ⇒ no second signer.
    assert build_overlap_signer() is None


def test_overlap_signer_is_built_when_both_knobs_are_set(tmp_path, monkeypatch) -> None:
    primary, _ = _write_key(tmp_path, "primary.key")
    overlap, _ = _write_key(tmp_path, "overlap.key")
    monkeypatch.setattr(
        signer_module,
        "vendor_settings",
        vendor_config.VendorSettings(
            provider_mode="fake",
            licence_signing_mode="configured",
            licence_signing_key_file=primary,
            licence_signing_key_id="vendor-prod-1",
            licence_overlap_key_file=overlap,
            licence_overlap_key_id="vendor-prod-2",
        ),
    )
    built = build_overlap_signer()
    assert built is not None and built.key_id == "vendor-prod-2"


def test_half_configured_overlap_fails_loudly(tmp_path, monkeypatch) -> None:
    """Configuring the file without the id (or vice versa) would silently
    disable double-signing mid-rotation — the worst time for it."""
    primary, _ = _write_key(tmp_path, "primary.key")
    overlap, _ = _write_key(tmp_path, "overlap.key")
    monkeypatch.setattr(
        signer_module,
        "vendor_settings",
        vendor_config.VendorSettings(
            provider_mode="fake",
            licence_signing_mode="configured",
            licence_signing_key_file=primary,
            licence_signing_key_id="vendor-prod-1",
            licence_overlap_key_file=overlap,
        ),
    )
    with pytest.raises(SigningKeyUnavailableError, match="BOTH"):
        build_overlap_signer()


@pytest.mark.parametrize(
    ("contents", "expected"),
    [
        ("", "empty"),
        ("!!!not-base64!!!", "base64url"),
        (base64.urlsafe_b64encode(b"tooshort").rstrip(b"=").decode(), "bytes"),
    ],
)
def test_malformed_key_material_fails_closed_without_leaking(
    tmp_path, contents: str, expected: str
) -> None:
    path = tmp_path / "bad.key"
    path.write_text(contents)
    with pytest.raises(SigningKeyUnavailableError) as exc:
        ConfiguredLicenceSigner(key_id="k", key_file=str(path))

    message = str(exc.value)
    assert expected in message
    assert str(path) in message  # actionable: names the path…
    if contents:
        assert contents not in message  # …but never the material itself


def test_missing_key_file_names_the_path_and_the_source(tmp_path) -> None:
    missing = str(tmp_path / "absent.key")
    with pytest.raises(SigningKeyUnavailableError) as exc:
        ConfiguredLicenceSigner(key_id="k", key_file=missing)
    message = str(exc.value)
    assert missing in message
    assert "OpenBao" in message  # tells the operator where to get it


def test_configured_signer_requires_an_explicit_key_id(tmp_path) -> None:
    path, _ = _write_key(tmp_path)
    with pytest.raises(SigningKeyUnavailableError, match="key id"):
        ConfiguredLicenceSigner(key_id="", key_file=path)
