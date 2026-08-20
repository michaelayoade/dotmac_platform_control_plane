"""ROUTE-level tests for the licensing operational adapters.

These drive the HTTP endpoints, not the services behind them. The previous
"replay endpoint" test called `dispatch_pending()` directly and never touched a
route, so it would have passed whether or not the endpoint existed or worked —
which is how a false-delivery endpoint survived review.

Auth is overridden rather than exercised: `require_platform_admin` is the
kernel's, proven there. What matters here is that the adapter is wired, thin,
and honest about what it did.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import pytest
from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.errors import register_error_handlers
from dotmac_kernel.platform_auth import require_platform_admin
from dotmac_kernel.testing import create_test_engine, isolated_session
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter as allocations
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import adapter as contracts
from vendor_cp.licensing import service as licensing
from vendor_cp.licensing.delivery_models import (
    AttemptOutcome,
    DeliveryState,
    LicenceDeliveryAttempt,
)
from vendor_cp.licensing.router import router
from vendor_cp.licensing.signer import EphemeralLicenceSigner
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion

NOW = datetime(2026, 8, 2, 12, 0, 0, tzinfo=UTC)
TARGET = "edge-site-1"
CUSTOMER = "cust-a"


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


@pytest.fixture
def client(db: Session) -> Iterator[TestClient]:
    app = FastAPI()
    # The kernel's handlers map DomainError subclasses to their HTTP status;
    # without them a BadRequestError would surface as a 500 and this suite
    # would assert the wrong contract.
    register_error_handlers(app)
    app.include_router(router)
    admin = PlatformAdmin(id=uuid.uuid4(), email="ops@dotmac.io", password_hash="x")
    app.dependency_overrides[get_platform_db] = lambda: db
    app.dependency_overrides[require_platform_admin] = lambda: admin
    with TestClient(app) as c:
        yield c


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


def _issue(db: Session) -> object:
    """contract → activate → stage allocation → issue."""
    db.add(
        OfferVersion(
            product_code="dotmac-sub",
            offer_code="off",
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
            counterparty_ref=CUSTOMER,
            agreement_type="software_subscription",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(contracts.LineInput("off", 1, "cap.a", quantity=1),),
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
            policy_code="p",
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
            approval_policy_code="p",
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
        signer=EphemeralLicenceSigner(key_id="k1"),
        now=NOW,
    )


# ── The adapters a clean deployment needs ───────────────────────────────────


def test_a_clean_deployment_can_register_a_target_and_stage(client, db) -> None:
    """Before these adapters existed, this whole flow was unreachable at
    runtime: staging demands a registered target and nothing could create one."""
    issued = _issue(db)

    registered = client.post(
        "/platform/vendor/licences/targets",
        json={"target_ref": TARGET, "customer_ref": CUSTOMER},
    )
    assert registered.status_code == 200
    assert registered.json()["target_ref"] == TARGET

    listed = client.get("/platform/vendor/licences/targets")
    assert [t["target_ref"] for t in listed.json()] == [TARGET]

    staged = client.post(
        "/platform/vendor/licences/deliveries",
        json={"issuance_id": str(issued.id), "target_ref": TARGET},
    )
    assert staged.status_code == 200
    assert staged.json()["state"] == DeliveryState.DELIVERED.value


def test_registering_an_unknown_status_is_rejected(client) -> None:
    response = client.post(
        "/platform/vendor/licences/targets",
        json={
            "target_ref": TARGET,
            "customer_ref": CUSTOMER,
            "status": "definitely-not-a-status",
        },
    )
    assert response.status_code == 400


# ── Export is the only delivery path, and it is honest ──────────────────────


def test_export_returns_the_bundle_and_records_a_real_handoff(client, db) -> None:
    issued = _issue(db)
    client.post(
        "/platform/vendor/licences/targets",
        json={"target_ref": TARGET, "customer_ref": CUSTOMER},
    )
    delivery = client.post(
        "/platform/vendor/licences/deliveries",
        json={"issuance_id": str(issued.id), "target_ref": TARGET},
    ).json()

    response = client.post(
        f"/platform/vendor/licences/deliveries/{delivery['id']}/export"
    )
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    bundle = json.loads(response.content)
    assert bundle["bundle"] == "dotmac-licence-envelope-bundle/1"
    assert bundle["digest"] == issued.digest

    # The bytes genuinely left the process, so this is `exported` — a real
    # handoff — and NOT `sent`, which would imply a transport delivered it.
    attempt = db.execute(select(LicenceDeliveryAttempt)).scalar_one()
    assert attempt.outcome == AttemptOutcome.EXPORTED.value


def test_there_is_no_generic_replay_endpoint(client) -> None:
    """Connected replay stays disabled until a transport performs a genuine
    external handoff. An endpoint that reported success while an in-process
    transport discarded the bytes would be worse than none: it manufactures
    delivery evidence."""
    assert client.post("/platform/vendor/licences/replay", json={}).status_code == 404


# ── Mapping and resume are reachable ────────────────────────────────────────


def test_map_and_resume_are_reachable_over_http(client, db) -> None:
    from vendor_cp.licensing.delivery_models import (
        LicenceDelivery,
        LicenceDeliveryState,
    )

    issued = _issue(db)
    client.post(
        "/platform/vendor/licences/targets",
        json={"target_ref": TARGET, "customer_ref": CUSTOMER},
    )
    delivery = client.post(
        "/platform/vendor/licences/deliveries",
        json={"issuance_id": str(issued.id), "target_ref": TARGET},
    ).json()

    # Force the pre-v010 shape: parked, with no resolved destination.
    row = db.get(LicenceDelivery, uuid.UUID(delivery["id"]))
    assert row is not None
    row.target_id = None
    state = db.execute(
        select(LicenceDeliveryState).where(LicenceDeliveryState.delivery_id == row.id)
    ).scalar_one()
    state.state = DeliveryState.PARKED.value
    db.flush()

    # Resume refuses while unmapped — it would otherwise vanish from replay.
    refused = client.post(
        f"/platform/vendor/licences/deliveries/{delivery['id']}/resume"
    )
    assert refused.status_code == 400

    mapped = client.post(
        f"/platform/vendor/licences/deliveries/{delivery['id']}/map",
        json={"target_ref": TARGET},
    )
    assert mapped.status_code == 200

    resumed = client.post(
        f"/platform/vendor/licences/deliveries/{delivery['id']}/resume"
    )
    assert resumed.status_code == 200
    assert resumed.json()["state"] == DeliveryState.DELIVERED.value


def test_health_endpoint_reports_the_separated_observations(client, db) -> None:
    _issue(db)
    body = client.get("/platform/vendor/licences/health").json()
    for field in (
        "never_attempted",
        "attempted_never_sent",
        "sent_unacknowledged",
        "parked_total",
        "unknown_digest_acks",
        "unverified_identity_acks",
        "critical_acks",
        "keyring_uptake_lag_measurable",
        "revocation_application_lag_measurable",
    ):
        assert field in body
    assert body["keyring_uptake_lag_measurable"] is False
    assert body["revocation_application_lag_measurable"] is False
