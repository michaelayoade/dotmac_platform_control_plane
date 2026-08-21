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
from dotmac_kernel import BadRequestError
from dotmac_kernel.licensing import StaleRevocationListError, verify_revocation_list
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from dotmac_licensing import Licence, Revocation, RevocationList
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter as allocations
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import adapter as contracts
from vendor_cp.licensing import adapter as licensing
from vendor_cp.licensing.signing_adapter import EphemeralLicenceSigner
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


@pytest.fixture
def signer() -> EphemeralLicenceSigner:
    return EphemeralLicenceSigner(key_id="vendor-key-1")


def _approve(db: Session, proposed: contracts.ContractView) -> None:
    assert proposed.content_hash is not None
    assert proposed.approval_request_id is not None
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"dec-{uuid.uuid4()}",
            request_id=proposed.approval_request_id,
            approver_id=uuid.uuid4(),
            content_hash=proposed.content_hash,
        ),
    )


def _catalogue(*codes: str) -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({"dotmac-sub": tuple(codes)})


def _issue(db: Session, signer, *, suffix: str, customer_ref: str):
    """contract → activate → stage → issue, returning the issuance view."""
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
            reference=f"AGR-{uuid.uuid4()}",
            product_code="dotmac-sub",
            counterparty_ref=customer_ref,
            agreement_type="software_subscription",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(contracts.LineInput(offer_code, 1, "cap.a", quantity=1),),
        ),
        catalogues=_catalogue("cap.a"),
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
    proposed = contracts.propose(
        db,
        contracts.ProposeCommand(
            command_id=f"s-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_policy_code=f"p-{suffix}",
            approval_policy_version=1,
            requested_by=uuid.uuid4(),
        ),
        catalogues=_catalogue("cap.a"),
    )
    _approve(db, proposed)
    assert proposed.approval_request_id is not None
    contracts.approve(
        db,
        contracts.ApprovalCommand(
            command_id=f"ap-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_request_id=proposed.approval_request_id,
        ),
    )
    active = contracts.activate(
        db,
        contracts.ActivateCommand(
            command_id=f"act-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_request_id=proposed.approval_request_id,
            activation_rule="countersigned",
            activation_reference="signature-1",
            activation_satisfied_at=NOW,
        ),
    )
    alloc = allocations.stage_allocation(
        db,
        allocations.StageAllocationCommand(
            source_event_id=f"evt-{uuid.uuid4()}",
            contract_id=draft.id,
            content_hash=active.content_hash or "",
        ),
        catalogues=_catalogue("cap.a"),
    )
    return licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(allocation_id=alloc.id),
        signer=signer,
        now=NOW,
    )


def _publish(db, signer):
    return licensing.publish_revocation_list(db, signer=signer, now=NOW)


# ── Entries are append-only and idempotent ──────────────────────────────────


def test_revoking_appends_an_entry_with_reason_and_event(db, signer) -> None:
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    licensing.revoke_licence(
        db,
        licensing.RevokeLicenceCommand(
            licence_id=issued.licence_id, reason="contract terminated"
        ),
    )
    entry = db.execute(select(Revocation)).scalar_one()
    assert entry.licence_id == issued.licence_id
    assert entry.reason == "contract terminated"
    events = (
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "licence.revoked.v1"
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


def test_revoking_twice_is_idempotent(db, signer) -> None:
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    cmd = licensing.RevokeLicenceCommand(licence_id=issued.licence_id, reason="fraud")
    first = licensing.revoke_licence(db, cmd)
    second = licensing.revoke_licence(db, cmd)
    assert first.id == second.id
    assert db.execute(select(func.count()).select_from(Revocation)).scalar_one() == 1


def test_revoking_requires_a_reason(db, signer) -> None:
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    with pytest.raises(BadRequestError):
        licensing.revoke_licence(
            db,
            licensing.RevokeLicenceCommand(licence_id=issued.licence_id, reason="  "),
        )


def test_revoking_an_unknown_licence_is_rejected(db) -> None:
    from dotmac_kernel import NotFoundError

    with pytest.raises(NotFoundError):
        licensing.revoke_licence(
            db,
            licensing.RevokeLicenceCommand(licence_id=uuid.uuid4(), reason="x"),
        )


# ── Publication: signed, verified, monotonic ────────────────────────────────


def test_published_list_verifies_with_the_pinned_kernel(db, signer) -> None:
    issued = _issue(db, signer, suffix="a", customer_ref="cust-a")
    licensing.revoke_licence(
        db, licensing.RevokeLicenceCommand(licence_id=issued.licence_id, reason="r")
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
                PlatformOutboxEvent.event_type == "licence.revocation_list.published.v1"
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
    licensing.revoke_licence(
        db, licensing.RevokeLicenceCommand(licence_id=a.licence_id, reason="r1")
    )
    v1 = _publish(db, signer)
    licensing.revoke_licence(
        db, licensing.RevokeLicenceCommand(licence_id=b.licence_id, reason="r2")
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
    licensing.revoke_licence(
        db, licensing.RevokeLicenceCommand(licence_id=issued.licence_id, reason="r")
    )
    _publish(db, signer)

    # Simulate an operator/bug removing the entry — the omission path.
    entry = db.execute(select(Revocation)).scalar_one()
    db.delete(entry)
    db.flush()

    with pytest.raises(BadRequestError, match="omit"):
        _publish(db, signer)

    # Nothing was recorded: the last published list is still v1, intact.
    assert (
        db.execute(select(func.count()).select_from(RevocationList)).scalar_one() == 1
    )
    assert licensing.latest_list(db).list_version == 1


def test_reissue_under_a_new_lineage_is_the_recovery_path(db, signer) -> None:
    """Recovery is NOT removing the id — the revoked lineage stays revoked
    forever. Re-issuing for the SAME customer and product mints a new lineage
    generation, which is simply absent from the list.

    Without generations this would be impossible: the resolver would return the
    revoked lineage and every "recovery" document would be dead on arrival.
    """
    revoked = _issue(db, signer, suffix="a", customer_ref="cust-a")
    licensing.revoke_licence(
        db,
        licensing.RevokeLicenceCommand(licence_id=revoked.licence_id, reason="r"),
    )
    _publish(db, signer)

    # SAME customer, SAME product — the realistic recovery.
    replacement = _issue(db, signer, suffix="a2", customer_ref="cust-a")
    assert replacement.licence_id != revoked.licence_id
    assert replacement.version == 1  # a fresh lineage restarts at v1

    generations = sorted(
        g
        for g in db.execute(
            select(Licence.generation).where(Licence.subject_ref == "cust-a")
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
