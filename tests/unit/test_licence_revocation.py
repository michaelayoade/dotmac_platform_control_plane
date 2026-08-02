"""Unit tests for revocation publication (vendor half of the WS8 slice).

The invariant under test is the ruled one: **revoked licence ids are
permanently cumulative.** Monotonic `list_version` alone does not prevent
un-revocation — a higher version that silently omits an earlier id would
restore access while looking perfectly ordered to a receiver, which can verify
ordering but cannot know what it was not told. So publication fails closed on
any omission, and every snapshot is round-tripped through the pinned kernel's
`verify_revocation_list` before it is recorded.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import pytest
from dotmac_kernel import CapabilityCatalogue, FeatureManifest
from dotmac_kernel.licensing import StaleRevocationListError, verify_revocation_list
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import service as allocations
from vendor_cp.approvals import service as approvals
from vendor_cp.contracts import service as contracts
from vendor_cp.licensing import revocation
from vendor_cp.licensing import service as licensing
from vendor_cp.licensing.revocation_models import (
    LicenceRevocationEntry,
    LicenceRevocationList,
)
from vendor_cp.licensing.signer import EphemeralLicenceSigner
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


@pytest.fixture
def signer() -> EphemeralLicenceSigner:
    return EphemeralLicenceSigner(key_id="vendor-key-1")


def _catalogue(*codes: str) -> CapabilityCatalogue:
    return CapabilityCatalogue.from_manifests(
        [FeatureManifest(name="t", capabilities=tuple(codes))]
    )


def _issue(db: Session, signer, *, suffix: str, customer_ref: str):
    """contract → activate → stage → issue, returning the issuance view."""
    offer_code = f"off-{suffix}"
    db.add(
        OfferVersion(
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
            customer_ref=customer_ref,
            legal_entity="Dotmac Ltd",
            currency_code="USD",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(contracts.LineInput(offer_code, 1, "cap.a", quantity=1),),
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
        catalogue=_catalogue("cap.a"),
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"pol-{uuid.uuid4()}",
            policy_code=f"p-{suffix}",
            version=1,
            quorum=1,
        ),
    )
    approvals.record_approval(
        db,
        approvals.RecordApprovalCommand(
            command_id=f"a-{uuid.uuid4()}",
            policy_code=f"p-{suffix}",
            policy_version=1,
            subject_type="contract",
            subject_id=str(draft.id),
            content_hash=submitted.content_hash or "",
            approver_id=uuid.uuid4(),
        ),
    )
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
    alloc = allocations.stage_allocation(
        db,
        allocations.StageAllocationCommand(
            source_event_id=f"evt-{uuid.uuid4()}",
            contract_id=draft.id,
            content_hash=submitted.content_hash or "",
            customer_ref=customer_ref,
        ),
    )
    return licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(allocation_id=alloc.id, product="dotmac-sub"),
        signer=signer,
        now=NOW,
    )


def _publish(db, signer):
    return revocation.publish_revocation_list(db, signer=signer, now=NOW)


# ── Entries are append-only and idempotent ──────────────────────────────────


def test_revoking_appends_an_entry_with_reason_and_event(db, signer) -> None:
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    revocation.revoke_licence(
        db,
        revocation.RevokeLicenceCommand(
            licence_id=issued.licence_id, reason="contract terminated"
        ),
    )
    entry = db.execute(select(LicenceRevocationEntry)).scalar_one()
    assert entry.licence_id == issued.licence_id
    assert entry.reason == "contract terminated"
    events = (
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "licence.revoked"
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


def test_revoking_twice_is_idempotent(db, signer) -> None:
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    cmd = revocation.RevokeLicenceCommand(licence_id=issued.licence_id, reason="fraud")
    first = revocation.revoke_licence(db, cmd)
    second = revocation.revoke_licence(db, cmd)
    assert first.id == second.id
    assert (
        db.execute(
            select(func.count()).select_from(LicenceRevocationEntry)
        ).scalar_one()
        == 1
    )


def test_revoking_requires_a_reason(db, signer) -> None:
    from dotmac_kernel import BadRequestError

    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    with pytest.raises(BadRequestError):
        revocation.revoke_licence(
            db,
            revocation.RevokeLicenceCommand(licence_id=issued.licence_id, reason="  "),
        )


def test_revoking_an_unknown_licence_is_rejected(db) -> None:
    from dotmac_kernel import NotFoundError

    with pytest.raises(NotFoundError):
        revocation.revoke_licence(
            db,
            revocation.RevokeLicenceCommand(licence_id=uuid.uuid4(), reason="x"),
        )


# ── Publication: signed, verified, monotonic ────────────────────────────────


def test_published_list_verifies_with_the_pinned_kernel(db, signer) -> None:
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    revocation.revoke_licence(
        db, revocation.RevokeLicenceCommand(licence_id=issued.licence_id, reason="r")
    )
    view = _publish(db, signer)

    verified = verify_revocation_list(
        view.envelope, keyring=licensing.build_keyring(db)
    )
    assert verified.list_version == 1
    assert verified.revoked_licence_ids == frozenset({str(issued.licence_id)})
    assert view.entry_count == 1
    events = (
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "licence.revocation_list_published"
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


def test_list_versions_strictly_increase(db, signer) -> None:
    first = _publish(db, signer)
    second = _publish(db, signer)
    assert (first.list_version, second.list_version) == (1, 2)
    # And a receiver holding v2 rejects the older artifact.
    with pytest.raises(StaleRevocationListError):
        verify_revocation_list(
            first.envelope,
            keyring=licensing.build_keyring(db),
            applied_list_version=second.list_version,
        )


def test_empty_list_is_publishable(db, signer) -> None:
    """A deployment must be able to import "nothing is revoked" — the absence
    of a list is not the same as a signed statement that the set is empty."""
    view = _publish(db, signer)
    assert view.entry_count == 0
    verified = verify_revocation_list(
        view.envelope, keyring=licensing.build_keyring(db)
    )
    assert verified.revoked_licence_ids == frozenset()


# ── THE cumulative canary ───────────────────────────────────────────────────


def test_each_published_set_is_a_superset_of_the_previous(db, signer) -> None:
    a = _issue(db, signer, suffix="a", customer_ref="cust-a")
    b = _issue(db, signer, suffix="b", customer_ref="cust-b")
    revocation.revoke_licence(
        db, revocation.RevokeLicenceCommand(licence_id=a.licence_id, reason="r1")
    )
    v1 = _publish(db, signer)
    revocation.revoke_licence(
        db, revocation.RevokeLicenceCommand(licence_id=b.licence_id, reason="r2")
    )
    v2 = _publish(db, signer)

    assert set(v1.revoked_licence_ids) == {str(a.licence_id)}
    assert set(v2.revoked_licence_ids) == {str(a.licence_id), str(b.licence_id)}
    assert set(v1.revoked_licence_ids) <= set(v2.revoked_licence_ids)


def test_publication_fails_closed_if_a_previously_revoked_id_is_omitted(
    db, signer
) -> None:
    """The canary for the ruled invariant: deleting an entry (the only way to
    shrink the set) must make the NEXT publication refuse, rather than quietly
    restoring the deployment's access."""
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    revocation.revoke_licence(
        db, revocation.RevokeLicenceCommand(licence_id=issued.licence_id, reason="r")
    )
    _publish(db, signer)

    # Simulate an operator/bug removing the entry — the omission path.
    entry = db.execute(select(LicenceRevocationEntry)).scalar_one()
    db.delete(entry)
    db.flush()

    with pytest.raises(revocation.RevocationListRegressionError, match="omits"):
        _publish(db, signer)

    # Nothing was recorded: the last published list is still v1, intact.
    assert (
        db.execute(select(func.count()).select_from(LicenceRevocationList)).scalar_one()
        == 1
    )
    assert revocation.latest_list(db).list_version == 1


def test_reissue_under_a_new_lineage_is_the_recovery_path(db, signer) -> None:
    """Recovery is NOT removing the id — the revoked lineage stays revoked
    forever. Re-issuing for the SAME customer and product mints a new lineage
    generation, which is simply absent from the list.

    Without generations this would be impossible: the resolver would return the
    revoked lineage and every "recovery" document would be dead on arrival.
    """
    revoked = _issue(db, signer, suffix="a", customer_ref="cust-a")
    revocation.revoke_licence(
        db,
        revocation.RevokeLicenceCommand(licence_id=revoked.licence_id, reason="r"),
    )
    _publish(db, signer)

    # SAME customer, SAME product — the realistic recovery.
    replacement = _issue(db, signer, suffix="a2", customer_ref="cust-a")
    assert replacement.licence_id != revoked.licence_id
    assert replacement.version == 1  # a fresh lineage restarts at v1

    from vendor_cp.licensing.models import Licence

    generations = sorted(
        g
        for g in db.execute(
            select(Licence.generation).where(Licence.customer_ref == "cust-a")
        ).scalars()
    )
    assert generations == [1, 2]

    latest = _publish(db, signer)
    assert str(revoked.licence_id) in latest.revoked_licence_ids
    assert str(replacement.licence_id) not in latest.revoked_licence_ids


def test_issuance_reuses_the_lineage_while_it_is_not_revoked(db, signer) -> None:
    """The generation must not drift upward on every issuance — only a
    revocation forces a new one."""
    first = _issue(db, signer, suffix="a", customer_ref="cust-a")
    second = _issue(db, signer, suffix="a2", customer_ref="cust-a")
    assert second.licence_id == first.licence_id
    assert (first.version, second.version) == (1, 2)
