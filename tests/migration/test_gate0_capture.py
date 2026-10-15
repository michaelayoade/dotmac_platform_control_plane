"""Hosted PostgreSQL: actual owner export, frozen state and withdrawal refusal.

Synthetic plan/key/decision inputs; no live human approval or custody is claimed.
"""

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import uuid4

import dotmac_deployment_control as control
import pytest
from alembic import command
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotmac_kernel.session_runtime import DatabaseRuntime

from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.deployment.gate0_capture import (
    CaptureRefused,
    decode_capture,
    export_approved_start,
)
from vendor_cp.deployment.gate0_role_custody import PublicIssuerVerifier
from vendor_cp.deployment.gate0_window import OwnerWindowReader
from vendor_cp.deployment.gate0_workload_admission import _FIXED_CLAIMS
from vendor_cp.deployment.protected_rehearsal_issuer import (
    ProposeIssuerPlan,
    approve_issuer_plan,
    open_issuer_approval,
    propose_issuer_plan,
)
from vendor_cp.deployment.rehearsal_issuer_trust_state import RehearsalIssuerTrustState
from vendor_cp.migrations import make_alembic_config


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def test_real_owner_capture_frozen_plan_and_withdrawn_approval(scratch_db, url_for):
    command.upgrade(make_alembic_config(scratch_db), "heads")
    database = scratch_db.rpartition("/")[2]
    online = url_for(scratch_db, database, user="platform_api")
    runtime = DatabaseRuntime.from_urls(
        database_url=online, platform_database_url=online
    )
    now, origin = datetime.now(UTC), monotonic()
    expires = now + timedelta(seconds=120)
    public = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    identity = control.RehearsalIssuerAuthorizationSignerIdentity(
        "capture-synthetic", "ed25519", _digest(public)
    )
    trust = RehearsalIssuerTrustState.start(
        minimum_version=1,
        read_record=lambda: {
            "version": 1,
            "trusted_key_ids": {identity.key_id: identity.public_key_fingerprint},
            "revoked_key_ids": [],
        },
    )
    verifier = PublicIssuerVerifier(
        identity.key_id, public, trust, origin + 120, expires, now, origin
    )
    fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode().rstrip("=")
    descriptor, execution = (
        _digest(b"synthetic-descriptor"),
        _digest(b"synthetic-Foundation-inputs"),
    )
    try:
        with runtime.platform_session() as db:
            target = control.register_target(
                db,
                control.RegisterTargetCommand(
                    command_id=uuid4().hex,
                    target_ref="capture-" + uuid4().hex,
                    subject_ref="synthetic-subject",
                    product_code="dotmac_sub",
                    environment="rehearsal",
                ),
            )
            window = {
                "schema": "Gate0IssuerWindow.v1",
                "case_kind": "consume_replay",
                "window_id": "synthetic-capture-window",
                "not_before": (now - timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "expires_at": expires.isoformat().replace("+00:00", "Z"),
                "purpose": "rehearsal_issuer_operation",
                "allowed_phases": ["issue", "consume"],
                "authorization_binding": "control_parsed_full_envelope_v1",
                "github": dict(
                    _FIXED_CLAIMS,
                    run_id="2",
                    run_attempt="1",
                    sub="synthetic-subject",
                    workflow_sha="a" * 40,
                    environment_node_id="synthetic-node",
                ),
                "target": {
                    "id": str(target.id),
                    "ref": target.target_ref,
                    "environment": "rehearsal",
                    "operation": "deploy",
                },
                "approval_policy": {"code": "gate0.capture.synthetic", "version": 1},
                "plan_inputs": {
                    "source_ref": "synthetic-source",
                    "config_ref": "synthetic-config",
                    "descriptor_digest": descriptor,
                    "execution_plan_digest": execution,
                },
                "controller": {
                    "lease_id": "synthetic-capture-lease",
                    "fingerprint": fingerprint,
                    "certificate_digest": _digest(b"synthetic-cert"),
                    "ca_fingerprint": fingerprint,
                    "principal": "dotmac-gate0-controller",
                    "certificate_ttl_ceiling_seconds": 600,
                },
                "prerequisite_evidence_refs": [_digest(b"synthetic-prerequisite")],
            }
            desired = control.set_desired_state(
                db,
                control.SetDesiredStateCommand(
                    command_id=uuid4().hex,
                    target_id=target.id,
                    desired=control.DesiredDeployment(
                        release_ref="synthetic-capture",
                        spec={"gate0_window_v1": window},
                        images=[],
                    ),
                ),
            )
            plan = propose_issuer_plan(
                db,
                ProposeIssuerPlan(
                    uuid4().hex,
                    target.id,
                    descriptor,
                    execution,
                    "gate0.capture.synthetic",
                    1,
                    expected_desired_revision=desired.desired_revision,
                ),
            )
            approvals.publish_policy_version(
                db,
                approvals.PublishPolicyCommand(
                    uuid4().hex, "gate0.capture.synthetic", 1, 1, False
                ),
            )
            request = open_issuer_approval(
                db, command_id=uuid4().hex, plan_id=plan.id, requested_by=uuid4()
            )
            # A real Approvals decision through its canonical CP adapter, with
            # synthetic CI actor; not a live authenticated human-route witness.
            approvals.record_decision(
                db,
                approvals.RecordDecisionCommand(
                    uuid4().hex,
                    request.request_id,
                    uuid4(),
                    bare_content_hash(plan.plan_digest),
                ),
            )
        with runtime.platform_session() as db:
            approve_issuer_plan(
                db,
                command_id=uuid4().hex,
                plan_id=plan.id,
                approval_request_id=request.request_id,
            )
        reader = OwnerWindowReader(
            runtime=runtime,
            rehearsal_target_id=target.id,
            issuer_identity=identity,
            authorization_verifier=verifier,
            expires_at=expires,
            database_io_qualified=True,  # Explicit isolated hosted fixture only.
        )
        packet = export_approved_start(reader, (plan.id,))[0]
        decoded = decode_capture(packet.encoded, expected=packet.coordinates)
        assert decoded.binding.expectation.operation.plan_digest == plan.plan_digest
        assert decoded.binding.expectation.operation.execution_plan_digest == execution
        assert decoded.binding.expectation.approval_request_id == request.request_id
        assert decoded.binding.expectation.window_freshness is None
        with runtime.platform_session() as db:
            # Mutable desired state cannot replace the approved frozen capture.
            control.set_desired_state(
                db,
                control.SetDesiredStateCommand(
                    command_id=uuid4().hex,
                    target_id=target.id,
                    desired=control.DesiredDeployment(
                        release_ref="synthetic-changed",
                        spec={
                            "gate0_window_v1": dict(window, window_id="not-approved")
                        },
                        images=[],
                    ),
                ),
            )
        repeated = export_approved_start(reader, (plan.id,))[0]
        assert repeated.encoded == packet.encoded
        assert repeated.coordinates == packet.coordinates
        with runtime.platform_session() as db:
            approvals.withdraw_request(
                db,
                approvals.WithdrawRequestCommand(
                    request.request_id,
                    uuid4(),
                    "synthetic-human",
                    "capture-withdrawal",
                    uuid4().hex,
                ),
            )
        # No relay convergence or cached capture can replace the held read.
        with pytest.raises(CaptureRefused):
            export_approved_start(reader, (plan.id,))
        # Decoding old bytes still yields data, never current approval standing.
        assert decode_capture(packet.encoded, expected=packet.coordinates) == decoded
    finally:
        runtime.platform_engine.dispose()
        runtime.engine.dispose()
