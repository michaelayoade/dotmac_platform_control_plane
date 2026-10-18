"""Historical signed source fixtures; no protected producer or E acceptance.

These tests are source qualification for hosted CI. They do not open live Gate0
windows, instantiate fresh runtime verifiers, or supply an acceptance oracle.
"""

from copy import deepcopy
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment.gate0_attester import (
    ProducedAttestation,
    ssh_public_fingerprint,
)
from vendor_cp.deployment.gate0_e_finalization import EPublicTrust, ESourcePins
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_observation import (
    SignedSessionObservation,
    bundle_document,
    digest,
    encode,
    observation_message,
)
from vendor_cp.deployment.gate0_runtime import (
    AdmittedOperation,
    AttestationContext,
    CompanionAttestation,
    companion_message,
)
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow


def build_signed_history(window_document, index=0):  # noqa: F811
    """Real owner+companion+observation signatures over original schema bytes.

    SSHSIG fixture is intentionally supplied separately by the test vector below;
    no live proof producer or backdated runtime clock is used in construction.
    """
    now = datetime(2025, 1, 1, tzinfo=UTC) + timedelta(seconds=index * 130)
    controller, ca, signer = (Ed25519PrivateKey.generate() for _ in range(3))
    public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    cert = (
        SSHCertificateBuilder()
        .public_key(controller.public_key())
        .type(SSHCertificateType.USER)
        .key_id(f"gate0:{window_document['github']['repository_id']}:2:1".encode())
        .valid_principals([b"dotmac-gate0-controller"])
        .valid_after(int(now.timestamp()) - 1)
        .valid_before(int(now.timestamp()) + 120)
        .sign(ca)
        .public_bytes()
    )
    document = deepcopy(window_document)
    document["window_id"] = f"historical-window-{index}"
    document["case_kind"] = "consume_replay" if index == 0 else "withdrawal_later_use"
    document["controller"]["lease_id"] = f"historical-lease-{index}"
    document["not_before"] = now.isoformat().replace("+00:00", "Z")
    document["expires_at"] = (
        (now + timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
    )
    document["controller"].update(
        fingerprint=ssh_public_fingerprint(controller.public_key()),
        certificate_digest=digest(cert),
        ca_fingerprint=ssh_public_fingerprint(ca.public_key()),
    )
    window = FrozenIssuerWindow.parse(canonical(document))
    op = AdmittedOperation(
        document["github"]["repository_id"],
        "2",
        "1",
        document["window_id"],
        "issue",
        None,
        None,
        document["controller"]["lease_id"],
        document["controller"]["fingerprint"],
        document["target"]["ref"],
        f"00000000-0000-0000-0000-{index + 1:012d}",
        digest(f"plan-{index}".encode()),
        document["purpose"],
        "deploy",
        document["plan_inputs"]["execution_plan_digest"],
        digest(cert),
        document["controller"]["ca_fingerprint"],
    )
    trust = EPublicTrust(
        "test-attester",
        public,
        canonical(
            dict(
                version=2,
                trusted_key_ids={"test-attester": digest(public)},
                revoked_key_ids=[],
            )
        ),
        2,
        "test:original-record",
        digest(b"qualified-test-source"),
    )

    def make(sshsig: bytes, *, operation=op, issued_seconds=1):
        op = operation
        challenge = canonical(
            dict(
                schema="Gate0PossessionChallenge.v1",
                instance_id="1" * 64,
                challenge_id="2" * 64,
                nonce="3" * 64,
                context=asdict(op),
                expires_at=(now + timedelta(seconds=20)).isoformat(),
            )
        )
        owner = canonical(
            dict(
                schema="dotmac.deployment_control.rehearsal_harness_evidence",
                version=1,
                lease_id=op.lease_id,
                controller_fingerprint=op.controller_fingerprint,
                target_ref=op.target_ref,
                environment="rehearsal",
                issued_at=(now + timedelta(seconds=issued_seconds))
                .isoformat()
                .replace("+00:00", "Z"),
                valid_until=(now + timedelta(seconds=25))
                .isoformat()
                .replace("+00:00", "Z"),
            )
        )
        transcript = canonical(
            dict(
                schema="Gate0PublicProofTranscript.v1",
                certificate=encode(cert),
                challenge=encode(challenge),
                sshsig=encode(sshsig),
            )
        )
        context = AttestationContext(
            **asdict(op),
            challenge_digest=digest(challenge),
            proof_transcript_digest=digest(transcript),
        )
        companion = companion_message(context, owner)
        proof = ProducedAttestation(
            canonical(
                dict(
                    canonical_bytes=encode(owner),
                    signature=dict(
                        key_id=trust.key_id,
                        algorithm="ed25519",
                        signature=encode(signer.sign(owner)),
                    ),
                )
            ),
            CompanionAttestation(companion, signer.sign(companion)),
            context,
            transcript,
        )
        message = observation_message(
            proof=proof,
            operation=op,
            window_record_digest=window.digest,
            invocation_id=f"{index * 2 + (1 if op.phase == 'issue' else 2):064x}",
            observed_from=now + timedelta(seconds=issued_seconds - 1),
            observed_until=now + timedelta(seconds=issued_seconds + 1),
        )
        return canonical(
            bundle_document(
                proof, SignedSessionObservation(message, signer.sign(message))
            )
        ), challenge

    return dict(
        now=now,
        window=window,
        operation=op,
        trust=trust,
        make=make,
        controller=controller,
    )


@pytest.fixture
def signed_history(window_document):  # noqa: F811
    return build_signed_history(window_document)


def test_snapshot_is_original_and_revoked_wins(signed_history):
    trust = signed_history["trust"]
    assert trust.trust_state().version == 2
    record = strict_object(trust.record)
    record["revoked_key_ids"] = [trust.key_id]
    with pytest.raises((ValueError, RuntimeError)):
        replace(trust, record=canonical(record))
    with pytest.raises((ValueError, RuntimeError)):
        replace(trust, minimum_version=3)
    with pytest.raises((ValueError, RuntimeError)):
        replace(trust, public_key=bytes(32))


def test_signed_record_cannot_override_independent_source_pins():
    pins = ESourcePins(
        "a" * 40, *([digest(b"source")] * 4), "b" * 40, digest(b"workflow")
    )
    with pytest.raises((ValueError, RuntimeError)):
        replace(pins, cp_revision="main")
    with pytest.raises((ValueError, RuntimeError)):
        replace(pins, workflow_digest="accepted")


@pytest.mark.parametrize(
    "tamper",
    [
        None,
        "owner",
        "companion",
        "observation",
        "context",
        "purpose",
        "expired-challenge",
        "wrong-window",
    ],
)
def test_historical_signed_bundle_and_one_field_tampering(
    signed_history, tmp_path, tamper
):
    """A genuine SSHSIG uses only an ephemeral synthetic test controller key."""
    import subprocess

    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    from vendor_cp.deployment.gate0_runtime import verify_retained_bundle

    f = signed_history
    raw, challenge = f["make"](b"placeholder")
    key = tmp_path / "synthetic-controller"
    key.write_bytes(
        f["controller"].private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
        )
    )
    key.chmod(0o600)
    signed = subprocess.run(  # noqa: S603 -- fixed synthetic hosted-CI protocol
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(key),
            "-n",
            "dotmac-gate0-possession-v1",
        ],
        input=challenge,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=2,
        check=True,
    ).stdout
    raw, _ = f["make"](signed)
    doc = strict_object(raw)
    expected, window = f["operation"], f["window"]
    if tamper in ("owner", "companion", "observation"):
        field = {
            "owner": "control_document",
            "companion": "companion",
            "observation": "observation",
        }[tamper]
        from vendor_cp.deployment.gate0_observation import decode

        original = decode(doc[field], 128 * 1024)
        doc[field] = encode(original[:-1] + bytes([original[-1] ^ 1]))
    elif tamper == "context":
        doc["context"]["lease_id"] = "different-lease"
    elif tamper == "purpose":
        doc["context"]["plan_purpose"] = "foundation"
    elif tamper == "expired-challenge":
        from vendor_cp.deployment.gate0_observation import decode

        transcript = strict_object(decode(doc["transcript"], 128 * 1024))
        changed = strict_object(decode(transcript["challenge"], 8192))
        changed["expires_at"] = (f["now"] - timedelta(seconds=1)).isoformat()
        transcript["challenge"] = encode(canonical(changed))
        doc["transcript"] = encode(canonical(transcript))
    elif tamper == "wrong-window":
        changed = window.document
        changed["window_id"] = "foreign-window"
        window = FrozenIssuerWindow.parse(canonical(changed))

    def verify():
        return verify_retained_bundle(
            canonical(doc),
            expected=expected,
            frozen_window=window,
            key_id=f["trust"].key_id,
            public_key=f["trust"].public_key,
            trust_state=f["trust"].trust_state(),
        )

    if tamper is None:
        verified = verify()
        assert verified.observed_until == f["now"] + timedelta(seconds=2)
        assert not hasattr(verified, "require_open")
    else:
        with pytest.raises((ValueError, RuntimeError)):
            verify()


def build_outcome_history(signed_history, *, actual_sshsig=False, tmp_path=None):
    """Typed original case, genuine signed authorization and nine schema outcomes.

    This fixture isolates the request/outcome join; full public possession
    cryptography is exercised by the bundle test above, not bypassed in production.
    """
    import dotmac_deployment_control as control

    from vendor_cp.approvals.adapter import ApprovalHoldRefusal
    from vendor_cp.deployment.gate0_collection import (
        IssuerOutcome,
        OutcomeKind,
        request_identity,
    )
    from vendor_cp.deployment.gate0_composition import authorization_binding
    from vendor_cp.deployment.gate0_e_finalization import ERetainedCase
    from vendor_cp.deployment.gate0_observation import decode, parse_bundle
    from vendor_cp.deployment.gate0_runner_handoff import RootHostBinding

    f = signed_history
    window, op = f["window"], f["operation"]
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    issuer = EPublicTrust(
        "test-issuer",
        public,
        canonical(
            dict(
                version=2,
                trusted_key_ids={"test-issuer": digest(public)},
                revoked_key_ids=[],
            )
        ),
        2,
        "test:issuer-record",
        digest(b"qualified-issuer"),
    )

    def role(trust):
        return dict(
            key_id=trust.key_id,
            public_key_b64=encode(trust.public_key),
            source_revision="a" * 40,
            image_digest=digest(b"image"),
            profile_digest=digest(b"profile"),
        )

    packet = canonical(
        dict(
            schema="Gate0RunIdentity.v1",
            run_id=op.run_id,
            run_attempt=op.run_attempt,
            case_kind=window.document["case_kind"],
            not_before=window.document["not_before"],
            expires_at=window.document["expires_at"],
            capture=dict(
                window_digest=window.digest,
                plan_id=op.plan_id,
                plan_digest=op.plan_digest,
                target_id=window.document["target"]["id"],
                approval_request_id=(
                    f"00000000-0000-0000-0000-{10 + int(op.plan_id[-12:]):012d}"
                ),
            ),
            roles=dict(issuer=role(issuer), attester=role(f["trust"])),
            controller_ca_fingerprint=op.ca_fingerprint,
            management_key_fingerprint=op.controller_fingerprint,
        )
    )
    roots = tuple(
        RootHostBinding(
            canonical(
                dict(
                    host_role=host_role,
                    case_kind=window.document["case_kind"],
                    launch_packet_digest=digest(packet),
                    local_packet_digest=digest(
                        window.digest.encode() + host_role.encode()
                    ),
                    window_digest=window.digest,
                    machine_id_digest=digest(b"machine" + host_role.encode()),
                    network_measurement_digest=digest(b"network"),
                    not_before=window.document["not_before"],
                    expires_at=window.document["expires_at"],
                )
            )
        )
        for host_role in ("issuer", "attester")
    )
    case = ERetainedCase(
        packet,
        window.canonical_bytes,
        "test-command-" + window.document["window_id"],
        roots,
        issuer,
        f["trust"],
    )
    d = control.A6ProvenanceKind.DERIVED
    statement = control.RehearsalIssuerAuthorizationStatementV1(
        authorization_id="test-authorization-" + window.document["window_id"],
        immutable_reference=op.plan_id,
        target_id=window.document["target"]["id"],
        target_ref=op.target_ref,
        target_provenance=d,
        desired_state_digest=op.plan_digest,
        desired_state_provenance=d,
        profile_digest=window.document["plan_inputs"]["descriptor_digest"],
        profile_provenance=d,
        authorized_image_digests=(digest(b"authorized-image"),),
        authorized_images_provenance=d,
        execution_plan_digest=op.execution_plan_digest,
        execution_plan_provenance=d,
        controller_fingerprint=op.controller_fingerprint,
        key_id=issuer.key_id,
        algorithm="ed25519",
        public_key_fingerprint=digest(public),
        lease_id=op.lease_id,
        single_use_reference="test-once-" + window.document["window_id"],
        environment="rehearsal",
        not_before=f["now"],
        issued_at=f["now"] + timedelta(seconds=2),
        expires_at=f["now"] + timedelta(seconds=100),
        control_version="0.1.0a17",
    )
    auth = canonical(
        control.RehearsalIssuerAuthorizationV1(
            statement, encode(key.sign(statement.canonical_bytes()))
        ).as_mapping()
    )
    binding = authorization_binding(auth)
    consume_op = replace(
        op,
        phase="consume",
        authorization_digest=binding.digest,
        authorization_issued_at=binding.issued_at,
    )
    bundles = (
        f["make"](b"outcome-only-possession", issued_seconds=1)[0],
        f["make"](b"outcome-only-possession", operation=consume_op, issued_seconds=3)[
            0
        ],
    )
    documents = tuple(strict_object(v) for v in bundles)
    pairs = tuple(
        (
            digest(
                decode(
                    strict_object(parse_bundle(doc)[0].control_document)[
                        "canonical_bytes"
                    ],
                    8192,
                )
            ),
            digest(raw),
        )
        for doc, raw in zip(documents, bundles, strict=True)
    )
    base = dict(schema="Gate0IssuerSubmission.v1")
    issue = base | dict(
        operation="issue",
        plan_id=op.plan_id,
        command_id=case.command_id,
        proof=documents[0],
    )
    consume = base | dict(
        operation="consume",
        plan_id=op.plan_id,
        authorization=encode(auth),
        proof=documents[1],
    )

    def standing(pair):
        return base | dict(
            operation="standing", authorization=encode(auth), evidence_digest=pair[0]
        )

    result = dict(
        evidence_digest=pairs[0][0],
        authorization_id=statement.authorization_id,
        lease_id=op.lease_id,
        authorization_document=encode(auth),
        single_use_reference=None,
        issuer_receipt=encode(
            canonical(
                dict(
                    id=f"00000000-0000-0000-0000-{20 + int(op.plan_id[-12:]):012d}",
                    verb="issue_authorization",
                    command_id=case.command_id,
                    request_fingerprint=digest(b"fixture-issuer-owner-request"),
                    recorded_at=(f["now"] + timedelta(seconds=2.5)).isoformat(),
                    plan_id=op.plan_id,
                    approval_request_id=case.packet["capture"]["approval_request_id"],
                    control_ref=statement.authorization_id,
                )
            )
        ),
    )

    def outcomes(replay):
        kinds = (
            (
                OutcomeKind.ISSUE_COMMITTED,
                OutcomeKind.STANDING,
                OutcomeKind.CONSUME_COMMITTED,
                OutcomeKind.STANDING,
                OutcomeKind.OWNER_REFUSED,
            )
            if replay
            else (
                OutcomeKind.ISSUE_COMMITTED,
                OutcomeKind.STANDING,
                OutcomeKind.STANDING,
                OutcomeKind.OWNER_REFUSED,
            )
        )
        requests = (
            (issue, standing(pairs[0]), consume, standing(pairs[1]), consume)
            if replay
            else (issue, standing(pairs[0]), standing(pairs[0]), consume)
        )
        values = []
        for i, (kind, request) in enumerate(zip(kinds, requests, strict=True)):
            pair = pairs[0 if i < (2 if replay else 3) else 1]
            namespace = code = None
            if kind is OutcomeKind.ISSUE_COMMITTED:
                body = result
            elif kind is OutcomeKind.CONSUME_COMMITTED:
                body = result | dict(
                    evidence_digest=pair[0],
                    authorization_document=None,
                    issuer_receipt=None,
                    single_use_reference=statement.single_use_reference,
                )
            elif kind is OutcomeKind.STANDING:
                body = dict(
                    standing=(
                        control.RehearsalIssuerAuthorizationStanding.CONSUMED
                        if replay and i == 3
                        else control.RehearsalIssuerAuthorizationStanding.VALID
                    ).value,
                    refusal=None,
                )
            else:
                body = {}
                namespace = "control.issuance" if replay else "approvals"
                code = (
                    control.RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH.value
                    if replay
                    else ApprovalHoldRefusal.WITHDRAWN.value
                )
                if not replay:
                    pair = (None, None)
            values.append(
                IssuerOutcome(
                    i + 1,
                    request["operation"],
                    request_identity(request),
                    window.digest,
                    *pair,
                    kind,
                    namespace,
                    code,
                    canonical(body),
                ).document()
            )
        return values

    if actual_sshsig:
        import subprocess

        from cryptography.hazmat.primitives.serialization import (
            NoEncryption,
            PrivateFormat,
        )

        path = tmp_path / ("controller-" + window.document["window_id"])
        path.write_bytes(
            f["controller"].private_bytes(
                Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
            )
        )
        path.chmod(0o600)
        real_bundles = []
        for phase_op, seconds in ((op, 1), (consume_op, 3)):
            _, challenge = f["make"](
                b"placeholder", operation=phase_op, issued_seconds=seconds
            )
            signature = subprocess.run(  # noqa: S603 -- fixed synthetic test fixture
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(path),
                    "-n",
                    "dotmac-gate0-possession-v1",
                ],
                input=challenge,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=True,
            ).stdout
            real_bundles.append(
                f["make"](signature, operation=phase_op, issued_seconds=seconds)[0]
            )
        bundles = tuple(real_bundles)
        documents = tuple(strict_object(v) for v in bundles)
        pairs = tuple(
            (
                digest(
                    decode(
                        strict_object(parse_bundle(doc)[0].control_document)[
                            "canonical_bytes"
                        ],
                        8192,
                    )
                ),
                digest(raw),
            )
            for doc, raw in zip(documents, bundles, strict=True)
        )
        issue["proof"], consume["proof"] = documents
    return dict(
        case=case,
        bundles=bundles,
        pairs=pairs,
        outcomes=outcomes,
        authorization=auth,
        issuer_key=key,
    )


@pytest.fixture
def outcome_history(signed_history):
    return build_outcome_history(signed_history)


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "request",
        "third-standing",
        "partial-null",
        "wrong-refusal",
        "replay-change",
    ],
)
def test_nine_owner_outcomes_exact_request_proof_and_refusal_joins(
    outcome_history, replay, fault
):
    from vendor_cp.deployment.gate0_e_finalization import (
        RetainedEvidenceRefused,
        _outcomes,
    )

    case, bundles, pairs, make = (
        outcome_history[k] for k in ("case", "bundles", "pairs", "outcomes")
    )
    documents = make(replay)
    if fault == "request":
        documents[0]["request_digest"] = digest(b"foreign-command")
    elif fault == "third-standing":
        # B's third standing uses issue; A's fourth outcome uses consume.
        target = 3 if replay else 2
        pair = pairs[0 if replay else 1]
        documents[target]["proof_digest"], documents[target]["bundle_digest"] = pair
    elif fault == "partial-null":
        documents[-1]["proof_digest"] = None
        documents[-1]["bundle_digest"] = pairs[1][1]
    elif fault == "wrong-refusal":
        documents[-1]["owner_code"] = "anything-refused"
    elif fault == "replay-change":
        documents[-1]["request_digest"] = digest(b"replacement-proof-or-authorization")
    if fault is None:
        assert len(_outcomes(case, documents, bundles, replay=replay)) == (
            5 if replay else 4
        )
        if not replay:
            documents[-1]["proof_digest"], documents[-1]["bundle_digest"] = pairs[1]
            assert len(_outcomes(case, documents, bundles, replay=False)) == 4
    else:
        with pytest.raises((ValueError, RetainedEvidenceRefused)):
            _outcomes(case, documents, bundles, replay=replay)


def retained_root_bytes(case, bundles, outcomes, campaign):
    """Actual root schemas, finite rosters and joins; no fabricated live handles."""
    from vendor_cp.deployment.gate0_launch import FiniteGate0Supervisor
    from vendor_cp.deployment.gate0_observation import DOMAIN, parse_bundle
    from vendor_cp.deployment.gate0_runner_handoff import encode_root_event
    from vendor_cp.deployment.gate0_services import IssuerProcessResult

    start, end = case.start, case.end
    readback = dict(
        schema="Gate0CaptureInstalled.v1",
        launch_packet_digest=digest(case.shared_packet),
        capture=case.packet["capture"]
        | dict(capture_digest=digest(b"synthetic-capture")),
        effective_end=end.isoformat(),
    )
    capture = dict(readback=readback, readback_digest=digest(canonical(readback)))
    phases, finals, sessions = {}, {}, {}
    for phase, raw in zip(("issue", "consume"), bundles, strict=True):
        _, observation = parse_bundle(strict_object(raw))
        observed = strict_object(observation.canonical_bytes[len(DOMAIN) :])
        sessions[phase] = dict(
            bundle_digest=digest(raw),
            invocation_id=observed["invocation_id"],
            client_pid=601 if phase == "issue" else 602,
            client_returncode=0,
            completed_at=102.0 if phase == "issue" else 104.0,
        )
    transcript = IssuerProcessResult(3, outcomes).transcript_digest
    for index, (host, root) in enumerate(zip(("IDP3", "NS3"), case.roots, strict=True)):
        terms = root.terms
        issuer = index == 0
        phase_names = (
            ("issuer_listening",)
            if issuer
            else ("management_listening", "attester_listening_after_capture")
        )
        phases[host] = []
        for number, phase in enumerate(phase_names):
            phases[host].append(
                canonical(
                    dict(
                        **terms,
                        schema="Gate0RootLaunchPhase.v1",
                        supervisor_pid=700 + index,
                        supervisor_start=str(800 + index),
                        started_at=start.isoformat(),
                        monotonic_origin=100.0,
                        deadline=220.0,
                        emitted_at=(
                            start + timedelta(seconds=0.1 + number * 0.1)
                        ).isoformat(),
                        emitted_elapsed_seconds=0.1 + number * 0.1,
                        phase=phase,
                        listener=dict(
                            role="issuer"
                            if issuer
                            else "management"
                            if number == 0
                            else "attester",
                            interface="wgtest",
                            local_address="10.1.1.2",
                            local_port=2222,
                            remote_address="10.1.1.3",
                        ),
                        management_capture=capture
                        if phase == "attester_listening_after_capture"
                        else None,
                    )
                )
            )
        daemons = ("issuer",) if issuer else ("management", "issue", "consume")
        boundaries = (
            ("preflight", "issuer", "capture_sender")
            if issuer
            else ("preflight", "management", "issue", "consume")
        )
        terminal_records = {}
        for slot in ("issuer",) if issuer else ("issue", "consume"):
            worker = (
                dict(
                    schema="Gate0IssuerTerminal.v1",
                    launch_packet_digest=digest(case.shared_packet),
                    local_packet_digest=root.terms["local_packet_digest"],
                    case_kind=case.window.document["case_kind"],
                    window_digest=case.window.digest,
                    worker_declared_exit_code=3,
                    transcript_digest=transcript,
                    terminal_outcome=outcomes[-1].document(),
                )
                if issuer
                else dict(
                    schema="Gate0SlotTerminal.v1",
                    launch_packet_digest=digest(case.shared_packet),
                    slot=slot,
                    outcome="success",
                    bundle_digest=sessions[slot]["bundle_digest"],
                    invocation_id=sessions[slot]["invocation_id"],
                )
            )
            terminal_records[slot] = dict(
                worker_terminal_digest=digest(canonical(worker)), worker_terminal=worker
            )
        final = dict(
            **{k: v for k, v in terms.items() if k != "not_before"},
            schema="Gate0LaunchCleanup.v1",
            supervisor_pid=700 + index,
            supervisor_start=str(800 + index),
            started_at=start.isoformat(),
            cleanup_completed_at=(start + timedelta(seconds=15)).isoformat(),
            outcome="complete",
            reason="completed_mechanics",
            delivery_status="unconfirmed",
            terminals=terminal_records,
            phase_completed_at={
                p: (start + timedelta(seconds=10)).isoformat()
                for p in (("issuer", "capture_sender") if issuer else daemons)
            },
            daemon_observations={
                name: dict(
                    schema="Gate0DaemonObservation.v1",
                    boundary=name,
                    pid=1000 + index * 10 + n,
                    process_start=str(2000 + index * 10 + n),
                    daemon_returncode=255,
                    termination="exited",
                    completed_at=(start + timedelta(seconds=10)).isoformat(),
                    completed_elapsed_seconds=10.0,
                    phase_deadline_elapsed_seconds=100.0,
                )
                for n, name in enumerate(daemons)
            },
            boundaries=[
                dict(
                    boundary=name,
                    cgroup_device=1,
                    cgroup_inode=3000 + index * 10 + n,
                    kill_issued=True,
                    populated=0,
                    guardian_pid=4000 + index * 10 + n,
                    guardian_start=str(5000 + index * 10 + n),
                    guardian_wait_status=0,
                )
                for n, name in enumerate(boundaries)
            ],
            removed=list(FiniteGate0Supervisor._transient_paths()),
            expected_removed=list(FiniteGate0Supervisor._transient_paths()),
        )
        final["capture_delivery" if issuer else "management_capture"] = capture
        finals[host] = canonical(final)
    envelopes = [
        encode_root_event(campaign, "NS3", phases["NS3"][0]),
        encode_root_event(campaign, "IDP3", phases["IDP3"][0]),
        encode_root_event(campaign, "NS3", phases["NS3"][1]),
    ]
    for host in ("IDP3", "NS3"):
        envelopes.append(encode_root_event(campaign, host, finals[host]))
        envelopes.append(
            canonical(
                dict(
                    schema="Gate0RootHandoffTerminal.v1",
                    campaign_digest=campaign,
                    host=host,
                    root_final_digest=digest(finals[host]),
                    stdout_eof=True,
                    management_returncode=0,
                )
            )
        )
    join = canonical(
        dict(
            campaign_digest=campaign,
            case_kind=case.window.document["case_kind"],
            root_final_digests=[digest(finals[h]) for h in ("IDP3", "NS3")],
            issuer_transcript_digest=transcript,
            issuer_client_pid=600,
            issuer_client_returncode=3,
            issue=sessions["issue"],
            consume=sessions["consume"],
            capture=capture,
        )
    )
    return tuple(envelopes), join


@pytest.fixture
def complete_retained_collection(window_document, tmp_path):  # noqa: F811
    """A complete private byte fixture, never an operational campaign or oracle."""
    from uuid import UUID

    from vendor_cp.deployment.gate0_collection import IssuerOutcome
    from vendor_cp.deployment.gate0_e_finalization import ESelection
    from vendor_cp.deployment.gate0_runner_projection import RetainedProjectionCase

    histories = [
        build_outcome_history(
            build_signed_history(window_document, i),
            actual_sshsig=True,
            tmp_path=tmp_path,
        )
        for i in (0, 1)
    ]
    cases = tuple(h["case"] for h in histories)
    source = ESourcePins(
        "a" * 40,
        *([digest(b"qualified-source")] * 4),
        "b" * 40,
        digest(b"qualified-workflow"),
    )
    selection = ESelection(
        digest(b"policy"),
        digest(b"campaign"),
        source,
        cases,
        "human-reference",
        "rehearsal-issuer-protected",
    )
    approvals = []
    outcomes = []
    roots = []
    joins = []
    for i, history in enumerate(histories):
        case = history["case"]
        window = case.window.document
        binding = RetainedProjectionCase(case.shared_packet, case.frozen_window).binding
        decided = (case.start - timedelta(seconds=1)).isoformat()
        approval = canonical(
            dict(
                schema="Gate0CollectionApproval.v1",
                binding=binding,
                frozen_window_b64=encode(case.frozen_window),
                descriptor_digest=window["plan_inputs"]["descriptor_digest"],
                authorized_image_digests=[digest(b"authorized-image")],
                observed_at=(case.start + timedelta(seconds=0.1)).isoformat(),
                approval=dict(
                    request_id=binding["approval_request_id"],
                    subject_type="rehearsal_issuer_plan.v1",
                    subject_id="|".join(
                        (
                            "v1",
                            binding["plan_id"],
                            window["purpose"],
                            "deploy",
                            window["plan_inputs"]["execution_plan_digest"],
                        )
                    ),
                    content_digest=binding["plan_digest"],
                    policy_code=window["approval_policy"]["code"],
                    policy_version=1,
                    state="approved",
                    decided_at=decided,
                    decisions=[
                        dict(
                            id=str(UUID(int=30 + i)),
                            actor_id=str(UUID(int=40)),
                            action="approve",
                            decided_at=decided,
                        )
                    ],
                ),
            )
        )
        approvals.append(approval)
        actual = tuple(IssuerOutcome.parse(d) for d in history["outcomes"](i == 0))
        outcomes.append(actual)
        roster, join = retained_root_bytes(
            case, history["bundles"], actual, selection.campaign_digest
        )
        roots.extend(roster)
        joins.append(join)
    b = cases[1]
    binding = RetainedProjectionCase(b.shared_packet, b.frozen_window).binding
    event = str(UUID(int=50))
    a = strict_object(approvals[1])["approval"]
    withdrawal = canonical(
        dict(
            schema="Gate0CollectionWithdrawal.v1",
            binding=binding,
            state="applied",
            observed_at=(b.start + timedelta(seconds=7)).isoformat(),
            withdrawal=dict(
                request_id=binding["approval_request_id"],
                withdrawal_id=event,
                actor_id=str(UUID(int=40)),
                authority_ref="human-owner",
                approved_at=a["decided_at"],
                effective_at=(b.start + timedelta(seconds=6)).isoformat(),
                external_ref=selection.withdrawal_reference,
            ),
            relay=dict(
                event_id=event,
                payload_digest=digest(b"actual-relay-payload"),
                event_type="approval.withdrawn",
                request_id=binding["approval_request_id"],
                subject_type=a["subject_type"],
                subject_id=a["subject_id"],
                plan_id=binding["plan_id"],
                withdrawal_ref=event,
                disposition="applied",
                authorizations_revoked=[
                    strict_object(outcomes[1][0].result_bytes)["authorization_id"]
                ],
            ),
        )
    )
    evidence = dict(
        schema="Gate0CollectedEvidence.v1",
        case_a=[o.document() for o in outcomes[0]],
        case_b=[o.document() for o in outcomes[1]],
        exact_bundles=[encode(raw) for h in histories for raw in h["bundles"]],
        withdrawal_evidence=strict_object(withdrawal),
        approval_evidence=[strict_object(raw) for raw in approvals],
        producer_acceptance="pending",
        prerequisite_acceptance="pending",
        cleanup_acceptance="pending_root_integration",
        publication_acceptance="pending_owner_policy",
        readiness_accepted=False,
    )
    document = dict(
        collection_complete=True,
        readiness_accepted=False,
        evidence=evidence,
        root_records=[encode(v) for v in roots],
        joins=[encode(v) for v in joins],
        approval_projection_raw=[encode(v) for v in approvals],
        withdrawal_projection_raw=[encode(withdrawal)],
        original_selections=[c.document() for c in cases],
        public_trust=[
            t.document() for c in cases for t in (c.issuer_trust, c.attester_trust)
        ],
    )
    return canonical(document), selection


def test_complete_retained_collection_positive_and_cross_layer_tamper(
    complete_retained_collection, monkeypatch
):
    from vendor_cp.deployment import gate0_runtime
    from vendor_cp.deployment.gate0_e_finalization import (
        RetainedEvidenceRefused,
        verify_retained_collection,
    )
    from vendor_cp.deployment.gate0_observation import decode

    raw, selection = complete_retained_collection

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "historical verification must not construct a live clock capability"
        )

    monkeypatch.setattr(gate0_runtime, "BoundedHarnessVerifier", forbidden)
    monkeypatch.setattr(gate0_runtime, "ProtectedHarnessVerifier", forbidden)
    verified = verify_retained_collection(raw, selection)
    assert verified.collection_bytes is raw
    assert verified.result == "retained_bytes_verified"
    assert verified.readiness_accepted is False
    assert len(verified.bundle_digests) == 4 and len(verified.root_record_digests) == 14
    document = strict_object(raw)
    join = strict_object(decode(document["joins"][1], 196608))
    join["consume"]["bundle_digest"] = verified.bundle_digests[0]
    document["joins"][1] = encode(canonical(join))
    with pytest.raises(RetainedEvidenceRefused):
        verify_retained_collection(canonical(document), selection)


def test_coherent_unsigned_authorization_id_rebind_cannot_replace_signed_owner_id(
    complete_retained_collection,
):
    """Rehash all dependent JSON while keeping the actual signed envelope intact."""
    from vendor_cp.deployment.gate0_collection import IssuerOutcome
    from vendor_cp.deployment.gate0_e_finalization import (
        RetainedEvidenceRefused,
        verify_retained_collection,
    )
    from vendor_cp.deployment.gate0_observation import decode
    from vendor_cp.deployment.gate0_services import IssuerProcessResult

    raw, selection = complete_retained_collection
    document = strict_object(raw)
    foreign = "coherently-rebound-unsigned-authorization"
    outcome = document["evidence"]["case_b"][0]
    original_signed_envelope = outcome["result"]["authorization_document"]
    outcome["result"]["authorization_id"] = foreign
    receipt = strict_object(decode(outcome["result"]["issuer_receipt"], 8192))
    receipt["control_ref"] = foreign
    outcome["result"]["issuer_receipt"] = encode(canonical(receipt))
    actual = tuple(IssuerOutcome.parse(d) for d in document["evidence"]["case_b"])
    transcript = IssuerProcessResult(3, actual).transcript_digest
    envelope = strict_object(decode(document["root_records"][10], 270336))
    final = strict_object(decode(envelope["root_b64"], 196608))
    terminal = final["terminals"]["issuer"]["worker_terminal"]
    terminal["transcript_digest"] = transcript
    final["terminals"]["issuer"]["worker_terminal_digest"] = digest(canonical(terminal))
    final_bytes = canonical(final)
    envelope["root_b64"] = encode(final_bytes)
    document["root_records"][10] = encode(canonical(envelope))
    management = strict_object(decode(document["root_records"][11], 4096))
    management["root_final_digest"] = digest(final_bytes)
    document["root_records"][11] = encode(canonical(management))
    join = strict_object(decode(document["joins"][1], 196608))
    join["root_final_digests"][0] = digest(final_bytes)
    join["issuer_transcript_digest"] = transcript
    document["joins"][1] = encode(canonical(join))
    withdrawal = strict_object(
        decode(document["withdrawal_projection_raw"][-1], 196608)
    )
    withdrawal["relay"]["authorizations_revoked"] = [foreign]
    document["withdrawal_projection_raw"][-1] = encode(canonical(withdrawal))
    document["evidence"]["withdrawal_evidence"] = withdrawal
    assert outcome["result"]["authorization_document"] == original_signed_envelope
    with pytest.raises(RetainedEvidenceRefused):
        verify_retained_collection(canonical(document), selection)
