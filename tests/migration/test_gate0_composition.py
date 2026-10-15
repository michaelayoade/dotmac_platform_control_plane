"""One isolated hosted-CI process: real owners/roles and synthetic custody.

No private Control reset hook. The child installs security once for both leases.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import text

from vendor_cp.migrations import make_alembic_config


def _digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def test_single_install_real_approvals_ssh_proof_issue_consume_withdrawal(
    scratch_db, url_for
):
    command.upgrade(make_alembic_config(scratch_db), "heads")
    owner = DatabaseRuntime.from_urls(
        database_url=scratch_db, platform_database_url=scratch_db
    )
    try:
        with owner.platform_session() as db:
            name = db.scalar(text("SELECT current_database()"))
            db.execute(
                text(
                    f'GRANT CONNECT ON DATABASE "{name}" TO platform_outbox_dispatcher'
                )
            )
        inputs = {
            "platform": url_for(scratch_db, name, user="platform_api"),
            "dispatcher": url_for(scratch_db, name, user="platform_outbox_dispatcher"),
        }
        result = subprocess.run(  # noqa: S603 -- isolated hosted fixture process, no private owner reset
            [sys.executable, str(Path(__file__).resolve())],
            input=json.dumps(inputs).encode(),
            capture_output=True,
            timeout=90,
            check=False,
            env={**os.environ, "GATE0_SYNTHETIC_COMPOSITION_WORKER": "1"},
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert result.stdout.strip() == b"synthetic-composition-lifecycle-complete"
    finally:
        owner.platform_engine.dispose()
        owner.engine.dispose()


def _worker(inputs):
    import dotmac_deployment_control as control
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        SSHCertificateBuilder,
        SSHCertificateType,
    )
    from dotmac_kernel import AuditActionRegistry, install_audit_actions
    from dotmac_kernel.messaging import OutboxStatus, PlatformOutboxEvent
    from sqlalchemy import select

    from vendor_cp.allocations.consumer import ContractEventConsumer
    from vendor_cp.approvals import adapter as approvals
    from vendor_cp.approvals_authority import bare_content_hash
    from vendor_cp.assembly import STATEFUL_MODULES, VENDOR_SURFACES
    from vendor_cp.deployment.gate0_attester import (
        AttesterProofProducer,
        ssh_public_fingerprint,
    )
    from vendor_cp.deployment.gate0_composition import (
        AdmissionExpectation,
        Gate0Composition,
        authorization_binding,
    )
    from vendor_cp.deployment.gate0_runtime import (
        AdmittedOperation,
        BoundedHarnessVerifier,
    )
    from vendor_cp.deployment.protected_rehearsal_issuer import (
        ProposeIssuerPlan,
        approve_issuer_plan,
        open_issuer_approval,
        propose_issuer_plan,
    )
    from vendor_cp.deployment.rehearsal_issuer_seam import RehearsalIssuerCommand
    from vendor_cp.deployment.rehearsal_issuer_trust_state import (
        RehearsalIssuerTrustState,
    )
    from vendor_cp.relay.approval_router import ApprovalEventRouter
    from vendor_cp.relay.runner import (
        PlatformEventConsumers,
        RelayComposition,
        drain_once,
    )
    from vendor_cp.relay.withdrawal_outcomes import (
        WithdrawalDisposition,
        outcomes_for_event,
    )

    install_audit_actions(
        AuditActionRegistry.from_manifests((*STATEFUL_MODULES, *VENDOR_SURFACES))
    )
    platform = DatabaseRuntime.from_urls(
        database_url=inputs["platform"], platform_database_url=inputs["platform"]
    )
    dispatcher = DatabaseRuntime.from_urls(
        database_url=inputs["dispatcher"], platform_database_url=inputs["dispatcher"]
    )
    issuer, attester, ca = (Ed25519PrivateKey.generate() for _ in range(3))
    issuer_raw = issuer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    attester_raw = attester.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    class FixtureIssuer:
        @property
        def rehearsal_issuer_identity(self):
            return control.RehearsalIssuerAuthorizationSignerIdentity(
                "fixture-issuer", "ed25519", _digest(issuer_raw)
            )

        def sign_rehearsal_issuer_authorization(self, message):
            return control.RehearsalIssuerAuthorizationSignature(
                "fixture-issuer",
                "ed25519",
                "deployment_rehearsal_issuer",
                _digest(issuer_raw),
                base64.b64encode(issuer.sign(message)).decode(),
            )

        def verify_rehearsal_issuer_authorization(
            self,
            *,
            key_id,
            algorithm,
            purpose,
            public_key_fingerprint,
            canonical_bytes,
            signature,
        ):
            if (key_id, algorithm, purpose, public_key_fingerprint) != (
                "fixture-issuer",
                "ed25519",
                "deployment_rehearsal_issuer",
                _digest(issuer_raw),
            ):
                return False
            try:
                issuer.public_key().verify(
                    base64.b64decode(signature, validate=True), canonical_bytes
                )
            except Exception:
                return False
            return True

    trust = RehearsalIssuerTrustState.start(
        minimum_version=2,
        read_record=lambda: {
            "version": 2,
            "trusted_key_ids": {"fixture-attester": _digest(attester_raw)},
            "revoked_key_ids": [],
        },
    )
    expiry = datetime.now(UTC) + timedelta(seconds=120)
    verifier = BoundedHarnessVerifier(
        key_id="fixture-attester",
        public_key=attester_raw,
        trust_state=trust,
        expires_at=expiry,
    )
    fixture_signer = FixtureIssuer()
    control.install_rehearsal_issuer_security(
        signer=fixture_signer,
        authorization_verifier=fixture_signer,
        harness_verifier=verifier,
        authorization_ttl=timedelta(seconds=120),
    )
    with pytest.raises(RuntimeError):
        control.install_rehearsal_issuer_security(
            signer=fixture_signer,
            authorization_verifier=fixture_signer,
            harness_verifier=verifier,
            authorization_ttl=timedelta(seconds=120),
        )
    expectations = {}
    controllers = {}
    certificates = {}
    selected = {}

    def seed(index):
        with platform.platform_session() as db:
            target = control.register_target(
                db,
                control.RegisterTargetCommand(
                    command_id=uuid4().hex,
                    target_ref=f"gate0-composition-{uuid4().hex}",
                    subject_ref="synthetic-subject",
                    product_code="dotmac_sub",
                    environment="rehearsal",
                ),
            )
            control.set_desired_state(
                db,
                control.SetDesiredStateCommand(
                    command_id=uuid4().hex,
                    target_id=target.id,
                    desired=control.DesiredDeployment(
                        release_ref="synthetic-issuer-operation",
                        spec={"replicas": 1},
                        images=[],
                    ),
                ),
            )
            plan = propose_issuer_plan(
                db,
                ProposeIssuerPlan(
                    uuid4().hex,
                    target.id,
                    _digest(b"descriptor"),
                    _digest(b"operation"),
                    "gate0.synthetic",
                    1,
                ),
            )
            approvals.publish_policy_version(
                db,
                approvals.PublishPolicyCommand(
                    "gate0-publish", "gate0.synthetic", 1, 1, False
                ),
            )
            request = open_issuer_approval(
                db, command_id=uuid4().hex, plan_id=plan.id, requested_by=uuid4()
            )
            approvals.record_decision(
                db,
                approvals.RecordDecisionCommand(
                    uuid4().hex,
                    request.request_id,
                    uuid4(),
                    bare_content_hash(plan.plan_digest),
                ),
            )
        with platform.platform_session() as db:
            approve_issuer_plan(
                db,
                command_id=uuid4().hex,
                plan_id=plan.id,
                approval_request_id=request.request_id,
            )
        key = Ed25519PrivateKey.generate()
        controllers[plan.id] = key
        now = int(datetime.now(UTC).timestamp())
        cert = (
            SSHCertificateBuilder()
            .public_key(key.public_key())
            .type(SSHCertificateType.USER)
            .key_id(b"gate0:1:2:1")
            .valid_principals([b"dotmac-gate0-controller"])
            .valid_after(now - 1)
            .valid_before(now + 120)
            .sign(ca)
            .public_bytes()
        )
        certificates[plan.id] = cert
        with platform.platform_session() as db:
            view = control.get_plan(db, plan.id)
        op = AdmittedOperation(
            "1",
            "2",
            "1",
            "fixture-window",
            "issue",
            None,
            None,
            f"lease-{index}",
            ssh_public_fingerprint(key.public_key()),
            target.target_ref,
            str(plan.id),
            view.plan_digest,
            "rehearsal_issuer_operation",
            "deploy",
            view.execution_plan_digest,
            _digest(cert),
            ssh_public_fingerprint(ca.public_key()),
        )
        expected = AdmissionExpectation(
            op, target.id, "rehearsal", request.request_id, "gate0.synthetic", 1
        )
        expectations[plan.id] = expected
        selected[("issue", plan.id)] = expected
        return plan.id, request.request_id

    def admission(phase, plan_id):
        return selected.get((phase, plan_id))

    def resolve(expected):
        op = expected.operation
        producer = AttesterProofProducer(
            admitted=op,
            ca_public_key=ca.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            ),
            key_id="fixture-attester",
            signer_purpose="deployment_rehearsal_harness_evidence",
            attester_public_key=attester_raw,
            trust_state=trust,
            sign=attester.sign,
            expires_at=expiry,
        )
        challenge = producer.begin_challenge(certificates[UUID(op.plan_id)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-controller"
            path.write_bytes(
                controllers[UUID(op.plan_id)].private_bytes(
                    Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
                )
            )
            path.chmod(0o600)
            signed = subprocess.run(  # noqa: S603 -- fixed SSHSIG fixture command
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(path),
                    "-n",
                    "dotmac-gate0-possession-v1",
                ],
                input=challenge.canonical_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=True,
            )  # noqa: S603
        return producer.complete_challenge(challenge.challenge_id, signed.stdout)

    driver = Gate0Composition(
        sessions=platform.platform_session_factory,
        admission=admission,
        proof_resolver=resolve,
        verifier=verifier,
    )
    try:
        first, first_request = seed("a")
        issued = driver.issue(RehearsalIssuerCommand(uuid4().hex, first))
        assert issued.readiness_accepted is False
        # A real pre-read starts a transaction; owner standing must refuse it.
        with platform.platform_session() as dirty:
            assert control.get_plan(dirty, first) is not None
            with pytest.raises(control.RehearsalIssuerIssuanceRefusedError) as caught:
                control.rehearsal_issuer_standing_for(
                    dirty,
                    authorization_document=json.loads(issued.authorization_document),
                    harness_evidence_document=json.loads(
                        verifier._evidence(issued.evidence_digest).owner_envelope
                    ),
                )
            refused_code = control.RehearsalIssuerIssuanceRefusalCode
            assert caught.value.code is refused_code.STANDING_REQUIRES_COMMITTED_SESSION
        # Driver closes preflight and opens a clean standing session below.
        assert (
            driver.standing(
                issued.authorization_document, issued.evidence_digest
            ).standing
            is control.RehearsalIssuerAuthorizationStanding.VALID
        )
        binding = authorization_binding(issued.authorization_document)
        consume = replace(
            expectations[first],
            operation=replace(
                expectations[first].operation,
                phase="consume",
                authorization_digest=binding.digest,
                authorization_issued_at=binding.issued_at,
            ),
        )
        selected[("consume", first)] = consume
        consumed = driver.consume(first, issued.authorization_document)
        assert consumed.authorization_id == issued.authorization_id
        # Replay reuses retained immutable proof; owner, not CP, rejects the spend.
        packet = verifier._evidence(consumed.evidence_digest)
        from vendor_cp.deployment.gate0_attester import ProducedAttestation

        replay = ProducedAttestation(
            packet.owner_envelope, packet.companion, packet.context, packet.transcript
        )
        replay_driver = Gate0Composition(
            sessions=platform.platform_session_factory,
            admission=admission,
            proof_resolver=lambda _: replay,
            verifier=verifier,
        )
        with pytest.raises(control.RehearsalIssuerIssuanceRefusedError):
            replay_driver.consume(first, issued.authorization_document)
        second, second_request = seed("b")
        second_issued = driver.issue(RehearsalIssuerCommand(uuid4().hex, second))
        second_binding = authorization_binding(second_issued.authorization_document)
        selected[("consume", second)] = replace(
            expectations[second],
            operation=replace(
                expectations[second].operation,
                phase="consume",
                authorization_digest=second_binding.digest,
                authorization_issued_at=second_binding.issued_at,
            ),
        )
        with platform.platform_session() as db:
            approvals.withdraw_request(
                db,
                approvals.WithdrawRequestCommand(
                    second_request,
                    uuid4(),
                    "synthetic-human",
                    "withdraw-test",
                    uuid4().hex,
                ),
            )
        composition = RelayComposition(
            dispatcher.platform_session_factory,
            platform.platform_session_factory,
            PlatformEventConsumers(
                contracts=ContractEventConsumer(), approvals=ApprovalEventRouter()
            ),
        )
        assert (
            drain_once(
                worker_id="gate0-composition-fixture", composition=composition
            ).claimed
            >= 1
        )
        with platform.platform_session() as db:
            rows = (
                db.execute(
                    select(PlatformOutboxEvent).where(
                        PlatformOutboxEvent.event_type == "approval.withdrawn"
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1 and rows[0].status == OutboxStatus.SENT.value
            outcomes = outcomes_for_event(db, rows[0].id)
            assert (
                len(outcomes) == 1
                and outcomes[0].disposition is WithdrawalDisposition.APPLIED
            )
            assert outcomes[0].evidence["authorizations_revoked"] == [
                second_issued.authorization_id
            ]
        assert (
            driver.standing(
                second_issued.authorization_document, second_issued.evidence_digest
            ).standing
            is not control.RehearsalIssuerAuthorizationStanding.VALID
        )
        with pytest.raises(approvals.ApprovalNotHeld):
            driver.consume(second, second_issued.authorization_document)
        assert verifier._retained_count == 4
        with platform.platform_session() as db:
            assert db.scalar(text("SELECT count(*) FROM mod_deploy.rollouts")) == 0
        print("synthetic-composition-lifecycle-complete")
    finally:
        platform.platform_engine.dispose()
        platform.engine.dispose()
        dispatcher.platform_engine.dispose()
        dispatcher.engine.dispose()


if __name__ == "__main__":
    if os.environ.get("GATE0_SYNTHETIC_COMPOSITION_WORKER") != "1":
        raise SystemExit(2)
    _worker(json.loads(sys.stdin.buffer.read()))
