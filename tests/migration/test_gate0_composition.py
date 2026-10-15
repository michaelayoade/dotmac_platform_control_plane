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
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
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
        Gate0Composition,
        authorization_binding,
    )
    from vendor_cp.deployment.gate0_role_custody import (
        BoundedJSONTransport,
        ProviderRefused,
    )
    from vendor_cp.deployment.gate0_runtime import BoundedHarnessVerifier
    from vendor_cp.deployment.gate0_window import (
        FrozenIssuerWindow,
        OwnerWindowReader,
        derive_consume_expectation,
    )
    from vendor_cp.deployment.gate0_workload_admission import (
        _FIXED_CLAIMS,
        GITHUB_ISSUER,
        OwnerWorkloadAdmission,
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
    expectations = {}
    controllers = {}
    certificates = {}
    readers, documents, owner_admissions = {}, {}, {}
    synthetic_oidc = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def url64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    numbers = synthetic_oidc.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kid": "synthetic-github",
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "n": url64(numbers.n.to_bytes(256, "big")),
                "e": url64(numbers.e.to_bytes(3, "big")),
            }
        ]
    }

    def fixture_jwks(transport, path, **kwargs):
        assert transport.origin == GITHUB_ISSUER and path == "/.well-known/jwks"
        assert kwargs["token"] is None
        return jwks

    # Explicit child fixture only: never installed in a wheel or CLI selector.
    BoundedJSONTransport.request = fixture_jwks

    def workload_token(plan_id):
        github = json.loads(expectations[plan_id].frozen_window_bytes)["github"]
        stamp = int(datetime.now(UTC).timestamp())
        claims = dict(
            github,
            iat=stamp,
            nbf=stamp,
            exp=min(stamp + 30, int(expiry.timestamp())),
            jti=uuid4().hex,
        )
        header = url64(
            json.dumps(
                {"alg": "RS256", "kid": "synthetic-github", "typ": "JWT"}
            ).encode()
        )
        body = (header + "." + url64(json.dumps(claims).encode())).encode()
        return (
            body.decode()
            + "."
            + url64(synthetic_oidc.sign(body, padding.PKCS1v15(), hashes.SHA256()))
        )

    def make_window(target, index, key, cert):
        return {
            "schema": "Gate0IssuerWindow.v1",
            "window_id": f"fixture-window-{index}",
            "case_kind": "withdrawal_later_use" if index == "b" else "consume_replay",
            "not_before": (datetime.now(UTC) - timedelta(seconds=1))
            .isoformat()
            .replace("+00:00", "Z"),
            "expires_at": expiry.isoformat().replace("+00:00", "Z"),
            "purpose": "rehearsal_issuer_operation",
            "allowed_phases": ["issue", "consume"],
            "github": dict(
                _FIXED_CLAIMS,
                run_id="2",
                run_attempt="1",
                sub="synthetic-subject",
                workflow_sha="a" * 40,
                environment_node_id="synthetic-environment-node",
            ),
            "target": {
                "id": str(target.id),
                "ref": target.target_ref,
                "environment": "rehearsal",
                "operation": "deploy",
            },
            "approval_policy": {"code": "gate0.synthetic", "version": 1},
            "plan_inputs": {
                "source_ref": "synthetic-source",
                "config_ref": "synthetic-config",
                "descriptor_digest": _digest(b"descriptor"),
                "execution_plan_digest": _digest(b"operation"),
            },
            "controller": {
                "lease_id": f"lease-{index}",
                "fingerprint": ssh_public_fingerprint(key.public_key()),
                "certificate_digest": _digest(cert),
                "ca_fingerprint": ssh_public_fingerprint(ca.public_key()),
                "principal": "dotmac-gate0-controller",
                "certificate_ttl_ceiling_seconds": 600,
            },
            "prerequisite_evidence_refs": [_digest(b"synthetic-prerequisite")],
            "authorization_binding": "control_parsed_full_envelope_v1",
        }

    def seed(index):
        key = Ed25519PrivateKey.generate()
        now = int(datetime.now(UTC).timestamp())
        cert = (
            SSHCertificateBuilder()
            .public_key(key.public_key())
            .type(SSHCertificateType.USER)
            .key_id(b"gate0:1397614140:2:1")
            .valid_principals([b"dotmac-gate0-controller"])
            .valid_after(now - 1)
            .valid_before(now + 120)
            .sign(ca)
            .public_bytes()
        )
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
            window = make_window(target, index, key, cert)
            desired = control.set_desired_state(
                db,
                control.SetDesiredStateCommand(
                    command_id=uuid4().hex,
                    target_id=target.id,
                    desired=control.DesiredDeployment(
                        release_ref="synthetic-issuer-operation",
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
                    _digest(b"descriptor"),
                    _digest(b"operation"),
                    "gate0.synthetic",
                    1,
                    expected_desired_revision=desired.desired_revision,
                ),
            )
            frozen = FrozenIssuerWindow.from_plan(control.get_plan(db, plan.id))
            assert (
                frozen.document == window
                and frozen.digest != plan.execution_plan_digest
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
        controllers[plan.id], certificates[plan.id] = key, cert
        reader = OwnerWindowReader(
            runtime=platform,
            rehearsal_target_id=target.id,
            issuer_identity=fixture_signer.rehearsal_issuer_identity,
            authorization_verifier=fixture_signer,
            expires_at=expiry,
            database_io_qualified=True,
        )
        readers[plan.id] = reader
        owner_admissions[plan.id] = OwnerWorkloadAdmission(
            reader=reader, transport=BoundedJSONTransport(GITHUB_ISSUER)
        )
        captured = reader.read("issue", plan.id)
        repeated = reader.read("issue", plan.id)
        assert captured.expectation.window_freshness is not None
        assert (
            repeated.expectation.window_freshness
            is captured.expectation.window_freshness
        )
        assert captured.expectation.window_freshness.origin == reader._origin
        assert captured.expectation.window_freshness.deadline <= reader._deadline
        expectations[plan.id] = captured.expectation
        # Mutating current desired state cannot mutate the approved frozen window.
        with platform.platform_session() as db:
            current = control.get_target(db, target.id)
            changed = {**window, "window_id": "unapproved-replacement"}
            control.set_desired_state(
                db,
                control.SetDesiredStateCommand(
                    command_id=uuid4().hex,
                    target_id=target.id,
                    desired=control.DesiredDeployment(
                        release_ref="synthetic-replacement",
                        spec={"gate0_window_v1": changed},
                        images=[],
                    ),
                    expected_version=current.record_version,
                ),
            )
            reread = control.get_plan(db, plan.id)
            assert reread.plan_digest == plan.plan_digest
            assert (
                FrozenIssuerWindow.from_plan(reread).canonical_bytes
                == frozen.canonical_bytes
            )
        return plan.id, request.request_id

    def admission(phase, plan_id):
        return owner_admissions[plan_id].admit(
            workload_token(plan_id),
            phase,
            plan_id,
            documents.get(plan_id) if phase == "consume" else None,
        )

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
        require_frozen_window=True,
    )
    import socket
    from concurrent.futures import ThreadPoolExecutor
    from time import monotonic

    from vendor_cp.deployment.gate0_collection import FramedCaseCollector, OutcomeKind
    from vendor_cp.deployment.gate0_composition import PhaseResult
    from vendor_cp.deployment.gate0_framing import FramedChannel, canonical
    from vendor_cp.deployment.gate0_observation import (
        SignedSessionObservation,
        bundle_document,
        decode,
        encode,
        observation_message,
    )
    from vendor_cp.deployment.gate0_services import (
        IssuerStartup,
        IssuerWorker,
        ServiceOwnerRefused,
    )

    sockets = None
    pool = None

    def actual_bundle(expected):
        started = datetime.now(UTC)
        produced = resolve(expected)
        ended = datetime.now(UTC)
        message = observation_message(
            proof=produced,
            operation=expected.operation,
            window_record_digest=expected.window_digest,
            invocation_id=uuid4().hex * 2,
            observed_from=started,
            observed_until=ended,
        )
        return bundle_document(
            produced, SignedSessionObservation(message, attester.sign(message))
        )

    def phase_result(outcome):
        data = json.loads(outcome.result_bytes)
        return PhaseResult(
            data["evidence_digest"],
            data["authorization_id"],
            data["lease_id"],
            None
            if data["authorization_document"] is None
            else decode(data["authorization_document"], 128 * 1024),
            data["single_use_reference"],
            None
            if data["issuer_receipt"] is None
            else decode(data["issuer_receipt"], 8192),
        )

    try:
        canary, _ = seed("snapshot-canary")
        with platform.platform_session() as db:
            original_plan = control.get_plan(db, canary)
            current_target = control.get_target(db, original_plan.target_id)
            with pytest.raises(control.PlanRefusedError):
                propose_issuer_plan(
                    db,
                    ProposeIssuerPlan(
                        uuid4().hex,
                        current_target.id,
                        _digest(b"descriptor"),
                        _digest(b"operation"),
                        "gate0.synthetic",
                        1,
                        expected_desired_revision=original_plan.desired_revision,
                    ),
                )
            replacement = propose_issuer_plan(
                db,
                ProposeIssuerPlan(
                    uuid4().hex,
                    current_target.id,
                    _digest(b"descriptor"),
                    _digest(b"operation"),
                    "gate0.synthetic",
                    1,
                    expected_desired_revision=current_target.desired_revision,
                ),
            )
            replacement_view = control.get_plan(db, replacement.id)
            assert replacement_view.plan_digest != original_plan.plan_digest
            assert (
                replacement_view.execution_plan_digest
                == original_plan.execution_plan_digest
            )
            assert (
                FrozenIssuerWindow.from_plan(replacement_view).document["window_id"]
                == "unapproved-replacement"
            )
            assert (
                FrozenIssuerWindow.from_plan(original_plan).document["window_id"]
                == "fixture-window-snapshot-canary"
            )
        first, first_request = seed("a")
        assert (
            readers[first].read("issue", first).window.document["case_kind"]
            == "consume_replay"
        )
        # The actual worker performs the one process-wide security install.
        # Custody/actors here remain explicitly synthetic, while PostgreSQL,
        # held approval, signature verification and framed owner codec are real.
        worker = IssuerWorker(
            IssuerStartup(
                owner_admissions[first],
                verifier,
                fixture_signer,
                fixture_signer,
                timedelta(seconds=30),
                "synthetic-management-actor",
                True,
                sessions=platform.platform_session_factory,
            )
        )
        with pytest.raises(RuntimeError):
            control.install_rehearsal_issuer_security(
                signer=fixture_signer,
                authorization_verifier=fixture_signer,
                harness_verifier=verifier,
                authorization_ttl=timedelta(seconds=30),
            )
        sockets = socket.socketpair()
        deadline = min(verifier._deadline, monotonic() + 60)
        client_channel = FramedChannel(
            sockets[0].fileno(), sockets[0].fileno(), deadline=deadline
        )
        owner_channel = FramedChannel(
            sockets[1].fileno(), sockets[1].fileno(), deadline=deadline
        )
        framed = FramedCaseCollector(client_channel)
        pool = ThreadPoolExecutor(max_workers=1)
        serving = pool.submit(worker.run, owner_channel)
        issue_bundle = actual_bundle(readers[first].read("issue", first).expectation)
        issued_outcome = framed._exchange(
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "issue",
                "plan_id": str(first),
                "command_id": uuid4().hex,
                "proof": issue_bundle,
                "workload_token": workload_token(first),
            }
        )
        assert issued_outcome.kind is OutcomeKind.ISSUE_COMMITTED
        assert issued_outcome.bundle_digest == _digest(canonical(issue_bundle))
        issued = phase_result(issued_outcome)
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
        documents[first] = issued.authorization_document
        consume = (
            readers[first]
            .read("consume", first, issued.authorization_document)
            .expectation
        )
        assert consume.operation.authorization_digest == binding.digest
        assert consume.operation.authorization_issued_at == binding.issued_at
        substituted = json.loads(issued.authorization_document)
        substituted["signature"] = "forged-synthetic-signature"
        with pytest.raises(ProviderRefused):
            readers[first].read("consume", first, json.dumps(substituted).encode())
        substituted = json.loads(issued.authorization_document)
        substituted["statement"]["target_ref"] = "other-target"
        with pytest.raises(ProviderRefused):
            readers[first].read("consume", first, json.dumps(substituted).encode())
        # Matching attacker bytes/digest do not match the actual frozen plan.
        changed_window = json.loads(expectations[first].frozen_window_bytes)
        changed_window["window_id"] = "substituted-window"
        from vendor_cp.deployment.gate0_framing import canonical

        changed_bytes = canonical(changed_window)
        with pytest.raises(ValueError):
            driver._preflight(
                replace(
                    expectations[first],
                    frozen_window_bytes=changed_bytes,
                    window_digest=_digest(changed_bytes),
                ),
                None,
            )
        consume_bundle = actual_bundle(
            readers[first]
            .read("consume", first, issued.authorization_document)
            .expectation
        )
        consume_submission = {
            "schema": "Gate0IssuerSubmission.v1",
            "operation": "consume",
            "plan_id": str(first),
            "authorization": encode(issued.authorization_document),
            "proof": consume_bundle,
            "workload_token": workload_token(first),
        }
        consumed_outcome = framed._exchange(consume_submission)
        assert consumed_outcome.kind is OutcomeKind.CONSUME_COMMITTED
        assert consumed_outcome.bundle_digest == _digest(canonical(consume_bundle))
        consumed = phase_result(consumed_outcome)
        assert consumed.authorization_id == issued.authorization_id
        assert consumed.single_use_reference
        assert issued.issuer_receipt is not None
        receipt = json.loads(issued.issuer_receipt)
        assert receipt["control_ref"] == issued.authorization_id
        standing = driver.standing(
            issued.authorization_document, consumed.evidence_digest
        )
        assert (
            standing.standing is control.RehearsalIssuerAuthorizationStanding.CONSUMED
        )
        assert (
            standing.refusal
            is control.RehearsalIssuerAuthorizationRefusalCode.ALREADY_CONSUMED
        )
        # Identical retained proof and authorization reach actual pinned a17
        # through the real framed worker. Generic/earlier harness failures do
        # not satisfy this exact owner refusal characterization.
        consume_submission["workload_token"] = workload_token(first)
        replay_outcome = framed._exchange(consume_submission)
        assert replay_outcome.kind is OutcomeKind.OWNER_REFUSED
        assert replay_outcome.owner_namespace == "control.issuance"
        assert (
            replay_outcome.owner_code
            == control.RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH.value
        )
        assert replay_outcome.proof_digest == consumed.evidence_digest
        assert replay_outcome.bundle_digest == consumed_outcome.bundle_digest
        with pytest.raises(ServiceOwnerRefused):
            serving.result(timeout=5)
        with pytest.raises(ValueError):
            framed._exchange(consume_submission)
        assert (
            driver.standing(
                issued.authorization_document, consumed.evidence_digest
            ).standing
            is control.RehearsalIssuerAuthorizationStanding.CONSUMED
        )
        second, second_request = seed("b")
        assert (
            readers[second].read("issue", second).window.document["case_kind"]
            == "withdrawal_later_use"
        )
        second_issued = driver.issue(RehearsalIssuerCommand(uuid4().hex, second))
        documents[second] = second_issued.authorization_document
        ns3_approved_at_start = readers[second].read("issue", second)
        before_withdrawal = readers[second].read(
            "consume", second, second_issued.authorization_document
        )
        assert (
            before_withdrawal.expectation.operation.authorization_digest
            == authorization_binding(second_issued.authorization_document).digest
        )

        def withdraw_between_preflight_and_mutation(expected):
            proof = resolve(expected)
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
            return proof

        driver._resolver = withdraw_between_preflight_and_mutation
        with pytest.raises(approvals.ApprovalNotHeld):
            driver.consume(second, second_issued.authorization_document)
        driver._resolver = resolve
        # NS3 honestly retains only approved-at-start possession scope. It can
        # derive a cryptographically valid envelope after withdrawal; IDP3's
        # fresh owner read and actual mutation hold independently refuse it.
        snapshot_consume = derive_consume_expectation(
            ns3_approved_at_start,
            second_issued.authorization_document,
            fixture_signer.rehearsal_issuer_identity,
            fixture_signer,
        )
        assert snapshot_consume.operation.phase == "consume"
        with pytest.raises(ProviderRefused):
            readers[second].read("issue", second)
        with pytest.raises(ProviderRefused):
            readers[second].read(
                "consume", second, second_issued.authorization_document
            )
        composition = RelayComposition(
            dispatcher.platform_session_factory,
            platform.platform_session_factory,
            PlatformEventConsumers(
                contracts=ContractEventConsumer(), approvals=ApprovalEventRouter()
            ),
        )
        claimed = 0
        for _ in range(16):
            report = drain_once(
                worker_id="gate0-composition-fixture", composition=composition
            )
            claimed += report.claimed
            if report.claimed == 0:
                break
        assert claimed >= 1
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
        from vendor_cp.deployment.gate0_window import AuthenticatedApprovalWithdrawal

        with pytest.raises(AuthenticatedApprovalWithdrawal) as withdrawn_use:
            driver.consume(second, second_issued.authorization_document)
        assert withdrawn_use.value.denial.request_id == second_request
        assert withdrawn_use.value.denial.plan_id == second
        assert withdrawn_use.value.denial.phase == "consume"
        with pytest.raises(ValueError):
            driver.standing(
                second_issued.authorization_document, second_issued.evidence_digest
            )
        assert verifier._retained_count == 4
        with platform.platform_session() as db:
            assert db.scalar(text("SELECT count(*) FROM mod_deploy.rollouts")) == 0
        print("synthetic-composition-lifecycle-complete")
    finally:
        if sockets is not None:
            for connection in sockets:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        if pool is not None:
            pool.shutdown(wait=True)
        platform.platform_engine.dispose()
        platform.engine.dispose()
        dispatcher.platform_engine.dispose()
        dispatcher.engine.dispose()


if __name__ == "__main__":
    if os.environ.get("GATE0_SYNTHETIC_COMPOSITION_WORKER") != "1":
        raise SystemExit(2)
    _worker(json.loads(sys.stdin.buffer.read()))
