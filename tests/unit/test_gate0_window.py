"""Adopted window format, entirely synthetic hosted-only vectors."""

import base64
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment.gate0_workload_admission import _FIXED_CLAIMS


@pytest.fixture
def window_document():
    now = datetime.now(UTC).replace(microsecond=0)
    fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode().rstrip("=")
    return {
        "schema": "Gate0IssuerWindow.v1",
        "case_kind": "consume_replay",
        "window_id": "synthetic-window",
        "not_before": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=120)).isoformat().replace("+00:00", "Z"),
        "purpose": "rehearsal_issuer_operation",
        "allowed_phases": ["issue", "consume"],
        "github": dict(
            _FIXED_CLAIMS,
            run_id="2",
            run_attempt="1",
            sub="synthetic-exact-subject",
            workflow_sha="a" * 40,
            environment_node_id="synthetic-environment-node",
        ),
        "target": {
            "id": str(UUID(int=2)),
            "ref": "synthetic-target",
            "environment": "rehearsal",
            "operation": "deploy",
        },
        "approval_policy": {"code": "synthetic-policy", "version": 1},
        "plan_inputs": {
            "source_ref": "synthetic-source",
            "config_ref": "synthetic-config",
            "descriptor_digest": "sha256:" + "1" * 64,
            "execution_plan_digest": "sha256:" + "2" * 64,
        },
        "controller": {
            "lease_id": "synthetic-lease",
            "fingerprint": fingerprint,
            "certificate_digest": "sha256:" + "3" * 64,
            "ca_fingerprint": fingerprint,
            "principal": "dotmac-gate0-controller",
            "certificate_ttl_ceiling_seconds": 600,
        },
        "prerequisite_evidence_refs": ["sha256:" + "4" * 64],
        "authorization_binding": "control_parsed_full_envelope_v1",
    }


def test_closed_canonical_window_is_distinct_from_execution_digest(window_document):
    parsed = FrozenIssuerWindow.parse(canonical(window_document))
    assert parsed.canonical_bytes == canonical(window_document)
    assert parsed.digest != window_document["plan_inputs"]["execution_plan_digest"]
    mutated = parsed.document
    mutated["window_id"] = "other"
    assert parsed.document["window_id"] == "synthetic-window"


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "phase",
        "future-authority",
        "policy-float",
        "url",
        "principal",
        "wrong-owner",
    ],
)
def test_window_refuses_unknown_cyclic_and_unbound_values(window_document, change):
    value = deepcopy(window_document)
    if change == "extra":
        value["approved"] = True
    elif change == "phase":
        value["allowed_phases"] = ["issue", "rollout"]
    elif change == "future-authority":
        value["authorization_digest"] = "sha256:" + "5" * 64
    elif change == "policy-float":
        value["approval_policy"]["version"] = 1.0
    elif change == "url":
        value["github"]["jku"] = "https://example.invalid"
    elif change == "principal":
        value["controller"]["principal"] = "root"
    else:
        value["github"]["repository_owner_id"] = "1"
    with pytest.raises(ProviderRefused):
        FrozenIssuerWindow.parse(canonical(value))


def test_noncanonical_and_duplicate_window_refused(window_document):
    import json

    with pytest.raises(ProviderRefused):
        FrozenIssuerWindow.parse(json.dumps(window_document, indent=2).encode())
    with pytest.raises(ProviderRefused):
        FrozenIssuerWindow.parse(b'{"schema":"Gate0IssuerWindow.v1","schema":"other"}')


def test_unconfigured_owner_reader_and_static_issuer_promotion_refuse():
    from types import SimpleNamespace

    from vendor_cp.deployment.gate0_services import issuer_run
    from vendor_cp.deployment.gate0_window import OwnerWindowReader
    from vendor_cp.deployment.gate0_workload_admission import (
        OwnerWorkloadAdmission,
        WorkloadAdmission,
    )

    with pytest.raises(ProviderRefused):
        OwnerWindowReader()
    with pytest.raises(ProviderRefused):
        OwnerWorkloadAdmission(reader=object())
    assert (
        issuer_run(
            SimpleNamespace(admission=WorkloadAdmission(), require_frozen_window=True)
        )
        == 3
    )


def test_mandatory_frozen_binding_cannot_be_omitted(window_document, monkeypatch):
    from types import SimpleNamespace

    from vendor_cp.deployment.gate0_composition import (
        AdmissionExpectation,
        CompositionRefused,
        Gate0Composition,
    )
    from vendor_cp.deployment.gate0_runtime import AdmittedOperation
    from vendor_cp.deployment.gate0_window import FrozenIssuerWindow

    document = window_document
    window = FrozenIssuerWindow.parse(canonical(document))
    target = SimpleNamespace(
        id=UUID(document["target"]["id"]),
        target_ref=document["target"]["ref"],
        environment="rehearsal",
    )
    plan = SimpleNamespace(
        id=UUID(int=1),
        target_id=target.id,
        purpose="rehearsal_issuer_operation",
        operation="deploy",
        plan_digest="sha256:" + "5" * 64,
        descriptor_digest=document["plan_inputs"]["descriptor_digest"],
        execution_plan_digest=document["plan_inputs"]["execution_plan_digest"],
        approval_policy_code="synthetic-policy",
        approval_policy_version=1,
        requires_approval=True,
        approval_decision_ref=str(UUID(int=3)),
        snapshot={
            "spec": {"gate0_window_v1": document},
            "plan_purpose": "rehearsal_issuer_operation",
            "target_ref": target.target_ref,
            "environment": "rehearsal",
        },
    )
    from time import monotonic

    from vendor_cp.deployment.gate0_composition import WindowFreshness

    origin = monotonic()
    expected = window.expectation(
        plan, target, "issue", freshness=WindowFreshness(origin, origin + 120)
    )
    assert type(expected.operation) is AdmittedOperation
    with pytest.raises(CompositionRefused):
        AdmissionExpectation(
            expected.operation,
            expected.target_id,
            expected.environment,
            expected.approval_request_id,
            expected.approval_policy_code,
            1,
            expected.frozen_window_bytes,
            None,
        )
    driver = Gate0Composition(
        sessions=lambda: None,
        admission=None,
        proof_resolver=None,
        verifier=None,
        require_frozen_window=True,
    )
    from dataclasses import replace

    import dotmac_deployment_control as control

    monkeypatch.setattr(control, "get_plan", lambda db, selected: plan)
    monkeypatch.setattr(control, "get_target", lambda db, selected: target)
    driver._check_plan(object(), expected)
    with pytest.raises(CompositionRefused):
        driver._check_plan(object(), replace(expected, window_freshness=None))
    omitted = replace(expected, frozen_window_bytes=None, window_digest=None)
    with pytest.raises(CompositionRefused):
        driver._check_plan(object(), omitted)


@pytest.fixture
def signed_binding(window_document):
    import hashlib
    import time
    from types import SimpleNamespace

    import dotmac_deployment_control as control
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from vendor_cp.deployment.gate0_role_custody import PublicIssuerVerifier
    from vendor_cp.deployment.gate0_window import ApprovedWindowBinding
    from vendor_cp.deployment.rehearsal_issuer_trust_state import (
        RehearsalIssuerTrustState,
    )

    document = window_document
    window = FrozenIssuerWindow.parse(canonical(document))
    target = SimpleNamespace(
        id=UUID(document["target"]["id"]),
        target_ref=document["target"]["ref"],
        environment="rehearsal",
    )
    plan = SimpleNamespace(
        id=UUID(int=1),
        target_id=target.id,
        purpose="rehearsal_issuer_operation",
        operation="deploy",
        plan_digest="sha256:" + "5" * 64,
        descriptor_digest=document["plan_inputs"]["descriptor_digest"],
        execution_plan_digest=document["plan_inputs"]["execution_plan_digest"],
        approval_policy_code="synthetic-policy",
        approval_policy_version=1,
        requires_approval=True,
        approval_decision_ref=str(UUID(int=3)),
        snapshot={
            "spec": {"gate0_window_v1": document},
            "plan_purpose": "rehearsal_issuer_operation",
            "target_ref": target.target_ref,
            "environment": "rehearsal",
        },
    )
    from time import monotonic

    from vendor_cp.deployment.gate0_composition import WindowFreshness

    origin = monotonic()
    expected = window.expectation(
        plan, target, "issue", freshness=WindowFreshness(origin, origin + 120)
    )
    binding = ApprovedWindowBinding(expected, window, plan.descriptor_digest, ())
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = "sha256:" + hashlib.sha256(public).hexdigest()
    identity = control.RehearsalIssuerAuthorizationSignerIdentity(
        "synthetic-issuer", "ed25519", fingerprint
    )
    now, origin = datetime.now(UTC), time.monotonic()
    trust = RehearsalIssuerTrustState.start(
        minimum_version=1,
        read_record=lambda: {
            "version": 1,
            "trusted_key_ids": {identity.key_id: fingerprint},
            "revoked_key_ids": [],
        },
    )
    verifier = PublicIssuerVerifier(
        identity.key_id,
        public,
        trust,
        origin + 120,
        now + timedelta(seconds=120),
        now,
        origin,
    )
    derived = control.A6ProvenanceKind.DERIVED
    op = expected.operation
    statement = control.RehearsalIssuerAuthorizationStatementV1(
        authorization_id="synthetic-authorization",
        immutable_reference=op.plan_id,
        target_id=str(expected.target_id),
        target_ref=op.target_ref,
        target_provenance=derived,
        desired_state_digest=op.plan_digest,
        desired_state_provenance=derived,
        profile_digest=plan.descriptor_digest,
        profile_provenance=derived,
        authorized_image_digests=(),
        authorized_images_provenance=derived,
        execution_plan_digest=op.execution_plan_digest,
        execution_plan_provenance=derived,
        controller_fingerprint=op.controller_fingerprint,
        key_id=identity.key_id,
        algorithm="ed25519",
        public_key_fingerprint=fingerprint,
        lease_id=op.lease_id,
        single_use_reference="synthetic-once",
        environment="rehearsal",
        not_before=now,
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        control_version="0.1.0a17",
    )
    authorization = control.RehearsalIssuerAuthorizationV1(
        statement, base64.b64encode(key.sign(statement.canonical_bytes())).decode()
    )
    return binding, identity, verifier, canonical(authorization.as_mapping()), key


def test_ns3_snapshot_actual_signature_consume_derivation_and_jwt(
    signed_binding, monkeypatch
):
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    from vendor_cp.deployment.gate0_composition import authorization_binding
    from vendor_cp.deployment.gate0_role_custody import BoundedJSONTransport
    from vendor_cp.deployment.gate0_workload_admission import (
        GITHUB_ISSUER,
        ApprovedAtStartAdmission,
    )

    binding, identity, verifier, authorization, _ = signed_binding
    jwt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def url64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    numbers = jwt_key.public_key().public_numbers()
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

    def response(transport, path, **kwargs):
        assert (
            transport.origin == GITHUB_ISSUER
            and path == "/.well-known/jwks"
            and kwargs["token"] is None
        )
        return jwks

    monkeypatch.setattr(BoundedJSONTransport, "request", response)
    now = datetime.now(UTC)
    stamp = int(now.timestamp())
    claims = dict(
        binding.window.document["github"],
        iat=stamp,
        nbf=stamp,
        exp=stamp + 60,
        jti="synthetic-jti",
    )
    body = (
        url64(
            json.dumps(
                {"alg": "RS256", "kid": "synthetic-github", "typ": "JWT"}
            ).encode()
        )
        + "."
        + url64(json.dumps(claims).encode())
    ).encode()
    token = (
        body.decode()
        + "."
        + url64(jwt_key.sign(body, padding.PKCS1v15(), hashes.SHA256()))
    )
    admission = ApprovedAtStartAdmission(
        binding=binding,
        issuer_identity=identity,
        authorization_verifier=verifier,
        transport=BoundedJSONTransport(GITHUB_ISSUER),
        expires_at=now + timedelta(seconds=90),
    )
    admitted = admission.admit(token, "issue", UUID(int=1))
    assert admitted.operation == binding.expectation.operation
    assert admitted.frozen_window_bytes == binding.expectation.frozen_window_bytes
    assert admitted.window_freshness is not None
    assert admitted.window_freshness is not binding.expectation.window_freshness
    consume = admission.admit(token, "consume", UUID(int=1), authorization)
    assert consume.window_freshness is admitted.window_freshness
    actual = authorization_binding(authorization)
    assert consume.operation.authorization_digest == actual.digest
    assert consume.operation.authorization_issued_at == actual.issued_at
    assert admission.window_record_digest(consume) == binding.window.digest
    forged = json.loads(authorization)
    forged["signature"] = "forged-synthetic-signature"
    with pytest.raises(ProviderRefused):
        admission.admit(token, "consume", UUID(int=1), canonical(forged))


@pytest.fixture
def mutation_case(signed_binding, monkeypatch):
    from types import SimpleNamespace

    import dotmac_deployment_control as control

    from vendor_cp.deployment.gate0_composition import (
        Gate0Composition,
    )

    binding, _, _, _, _ = signed_binding
    expected = binding.expectation
    document = binding.window.document
    target = SimpleNamespace(
        id=expected.target_id,
        target_ref=expected.operation.target_ref,
        environment="rehearsal",
    )
    plan = SimpleNamespace(
        id=UUID(expected.operation.plan_id),
        target_id=target.id,
        purpose=expected.operation.plan_purpose,
        operation=expected.operation.operation,
        plan_digest=expected.operation.plan_digest,
        execution_plan_digest=expected.operation.execution_plan_digest,
        requires_approval=True,
        approval_decision_ref=str(expected.approval_request_id),
        approval_policy_code=expected.approval_policy_code,
        approval_policy_version=expected.approval_policy_version,
        descriptor_digest=binding.descriptor_digest,
        snapshot={
            "spec": {"gate0_window_v1": document},
            "plan_purpose": expected.operation.plan_purpose,
            "target_ref": target.target_ref,
            "environment": "rehearsal",
        },
    )
    events = []
    db = SimpleNamespace(
        commit=lambda: events.append("commit"),
        rollback=lambda: events.append("rollback"),
        close=lambda: events.append("close"),
    )
    monkeypatch.setattr(control, "get_plan", lambda db, selected: plan)
    monkeypatch.setattr(control, "get_target", lambda db, selected: target)
    driver = Gate0Composition(
        sessions=lambda: db,
        admission=None,
        proof_resolver=None,
        verifier=SimpleNamespace(_require_open=lambda: None),
        require_frozen_window=True,
    )
    driver._preflight(expected, None)
    events.clear()
    return driver, plan, expected, events, document


def test_mutation_rechecks_frozen_window_before_transition(mutation_case):
    from vendor_cp.deployment.gate0_composition import CompositionRefused

    driver, plan, expected, events, document = mutation_case
    plan.snapshot["spec"]["gate0_window_v1"] = dict(
        document, window_id="changed-after-preflight"
    )
    with pytest.raises(CompositionRefused):
        driver._mutate(
            expected,
            None,
            lambda db: pytest.fail("changed frozen window reached owner mutation"),
        )
    assert events == ["rollback", "close"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("immutable_reference", str(UUID(int=99))),
        ("lease_id", "different-lease"),
        ("target_ref", "different-target"),
        ("desired_state_digest", "sha256:" + "8" * 64),
        ("profile_digest", "sha256:" + "9" * 64),
        ("execution_plan_digest", "sha256:" + "a" * 64),
        ("authorized_image_digests", ("sha256:" + "b" * 64,)),
    ],
)
def test_genuinely_signed_wrong_consume_terms_refuse(signed_binding, field, value):
    import json
    from dataclasses import replace

    import dotmac_deployment_control as control

    from vendor_cp.deployment.gate0_window import derive_consume_expectation

    binding, identity, verifier, document, key = signed_binding
    original = control.RehearsalIssuerAuthorizationV1.parse(json.loads(document))
    statement = replace(original.statement, **{field: value})
    signature = base64.b64encode(key.sign(statement.canonical_bytes())).decode()
    assert verifier.verify_rehearsal_issuer_authorization(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_fingerprint=statement.public_key_fingerprint,
        canonical_bytes=statement.canonical_bytes(),
        signature=signature,
    )
    wrong = control.RehearsalIssuerAuthorizationV1(statement, signature)
    with pytest.raises(control.RehearsalIssuerAuthorizationRefusedError):
        derive_consume_expectation(
            binding, canonical(wrong.as_mapping()), identity, verifier
        )


def test_window_expiry_after_transition_rolls_back_before_commit(
    mutation_case, monkeypatch
):
    from vendor_cp.deployment.gate0_composition import PhaseResult

    driver, _, expected, events, document = mutation_case
    wall = [datetime.now(UTC)]

    class Clock:
        fromisoformat = staticmethod(datetime.fromisoformat)

        @staticmethod
        def now(tz):
            return wall[0]

    monkeypatch.setattr("vendor_cp.deployment.gate0_window.datetime", Clock)

    def transition(db):
        events.append("transition")
        wall[0] = datetime.fromisoformat(
            document["expires_at"].replace("Z", "+00:00")
        ) + timedelta(seconds=1)
        return PhaseResult(
            "sha256:" + "c" * 64, "synthetic-authorization", "synthetic-lease"
        )

    with pytest.raises(ProviderRefused):
        driver._mutate(expected, None, transition)
    assert events == ["transition", "rollback", "close"]


@pytest.mark.parametrize("after_transition", [False, True])
def test_original_window_monotonic_bound_survives_admission(
    mutation_case, monkeypatch, after_transition
):
    from dataclasses import replace

    from vendor_cp.deployment.gate0_composition import (
        CompositionRefused,
        PhaseResult,
        WindowFreshness,
    )

    driver, _, expected, events, document = mutation_case
    # Wall time remains inside the frozen window; the global verifier remains
    # open. Only the original process-local window deadline expires.
    wall = datetime.fromisoformat(
        document["not_before"].replace("Z", "+00:00")
    ) + timedelta(seconds=2)
    elapsed = [110.0 if after_transition else 161.0]
    expected = replace(expected, window_freshness=WindowFreshness(100.0, 160.0))

    class Clock:
        fromisoformat = staticmethod(datetime.fromisoformat)

        @staticmethod
        def now(tz):
            return wall

    monkeypatch.setattr("vendor_cp.deployment.gate0_window.datetime", Clock)
    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_composition.monotonic", lambda: elapsed[0]
    )

    def global_open():
        assert 100.0 <= elapsed[0] < 400.0  # Original 300-second service lifetime.

    from types import SimpleNamespace

    driver._verifier = SimpleNamespace(_require_open=global_open)
    global_open()

    def transition(db):
        events.append("transition")
        elapsed[0] = 161.0
        return PhaseResult(
            "sha256:" + "c" * 64, "synthetic-authorization", "synthetic-lease"
        )

    with pytest.raises(CompositionRefused):
        driver._mutate(expected, None, transition)
    assert events == (["transition"] if after_transition else []) + [
        "rollback",
        "close",
    ]


def test_original_window_monotonic_bound_allows_live_transition(
    mutation_case, monkeypatch
):
    from dataclasses import replace

    from vendor_cp.deployment.gate0_composition import PhaseResult, WindowFreshness

    driver, _, expected, events, _ = mutation_case
    expected = replace(expected, window_freshness=WindowFreshness(100.0, 160.0))
    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_composition.monotonic", lambda: 110.0
    )
    result = PhaseResult(
        "sha256:" + "c" * 64, "synthetic-authorization", "synthetic-lease"
    )
    assert driver._mutate(expected, None, lambda db: result) is result
    assert events == ["commit", "close"]


def test_detached_admission_and_proof_preserve_original_freshness(signed_binding):
    from types import SimpleNamespace

    from vendor_cp.deployment.gate0_composition import Gate0Composition

    binding, _, _, _, _ = signed_binding
    original = binding.expectation
    seen = []

    def resolve(expected):
        seen.append(expected)
        return object()

    driver = Gate0Composition(
        sessions=lambda: pytest.fail(
            "admission/proof must not open a mutation session"
        ),
        admission=lambda phase, plan: original,
        proof_resolver=resolve,
        verifier=SimpleNamespace(
            _require_open=lambda: None,
            _register=lambda proof, operation: "synthetic-proof",
        ),
        require_frozen_window=True,
    )
    admitted = driver._admit("issue", UUID(original.operation.plan_id))
    assert admitted is not original
    assert admitted.window_freshness is original.window_freshness
    assert driver._proof(admitted) == "synthetic-proof"
    assert seen[0] is not admitted
    assert seen[0].window_freshness is original.window_freshness


@pytest.mark.parametrize(
    "invalid",
    ["future-wall", "future-monotonic", "expired", "too-long", "nonfinite", "naive"],
)
def test_original_reader_clock_origin_is_local_bounded_and_not_renewable(invalid):
    import math
    import time

    from vendor_cp.deployment.gate0_window import WindowClockOrigin

    now, origin = datetime.now(UTC), time.monotonic()
    started, mapped, deadline = now, origin, origin + 120
    if invalid == "future-wall":
        started += timedelta(seconds=1)
    elif invalid == "future-monotonic":
        mapped += 10
    elif invalid == "expired":
        deadline = origin - 1
    elif invalid == "too-long":
        deadline = origin + 301
    elif invalid == "nonfinite":
        deadline = math.inf
    else:
        started = now.replace(tzinfo=None)
    with pytest.raises(ProviderRefused):
        WindowClockOrigin(started, mapped, deadline)


def test_owner_reader_uses_original_launch_mapping_before_first_read(monkeypatch):
    import time

    from dotmac_kernel.session_runtime import DatabaseRuntime

    from vendor_cp.deployment.gate0_window import OwnerWindowReader, WindowClockOrigin

    # No engine or connection is created. This type-only synthetic fixture
    # verifies initialization; real owner reads remain in the migration suite.
    runtime = object.__new__(DatabaseRuntime)
    now, origin = datetime.now(UTC), time.monotonic()
    local = WindowClockOrigin(now - timedelta(seconds=30), origin - 30, origin + 90)
    reader = OwnerWindowReader(
        runtime=runtime,
        rehearsal_target_id=UUID(int=2),
        issuer_identity=object(),
        authorization_verifier=object(),
        expires_at=now + timedelta(seconds=60),
        database_io_qualified=True,
        clock_origin=local,
    )
    assert reader._started == local.started_at
    assert reader._origin == local.monotonic_origin
    assert reader._deadline == min(local.deadline, local.monotonic_origin + 90)
    assert reader._freshness == {}
    with pytest.raises(ProviderRefused):
        OwnerWindowReader(
            runtime=runtime,
            rehearsal_target_id=UUID(int=2),
            issuer_identity=object(),
            authorization_verifier=object(),
            expires_at=now + timedelta(seconds=280),
            database_io_qualified=True,
            clock_origin=local,
        )  # Original launch duration, not remaining duration, exceeds 300.


@pytest.mark.parametrize("change", ["none", "token", "run", "expiry"])
def test_withdrawal_only_survives_authenticated_exact_original_window(
    signed_binding, monkeypatch, change
):
    from types import SimpleNamespace

    from vendor_cp.deployment.gate0_window import (
        AuthenticatedApprovalWithdrawal,
        OwnerWindowWithdrawal,
    )
    from vendor_cp.deployment.gate0_workload_admission import OwnerWorkloadAdmission

    binding, *_ = signed_binding
    expected = binding.expectation
    denial = OwnerWindowWithdrawal(
        window=binding.window,
        plan_id=UUID(expected.operation.plan_id),
        request_id=expected.approval_request_id,
        content_digest=expected.operation.plan_digest,
        phase="consume",
        freshness=expected.window_freshness,
    )
    events = []

    def read(*args):
        events.append("read")
        raise denial

    admission = object.__new__(OwnerWorkloadAdmission)
    admission._attempts = 0
    admission._transport = object()
    admission._reader = SimpleNamespace(read=read)
    admission._origin = expected.window_freshness.origin
    admission._started_at = datetime.now(UTC)
    admission._deadline = expected.window_freshness.deadline
    monkeypatch.setattr(admission, "_open", lambda: None)
    claims = dict(binding.window.document["github"])
    now = int(datetime.now(UTC).timestamp())
    claims.update(iat=now, nbf=now, exp=now + 30)
    if change == "run":
        claims["run_id"] = "999"
    if change == "expiry":
        claims["exp"] = now - 1

    def verified(token):
        events.append("jwt")
        if change == "token":
            raise ProviderRefused()
        return claims

    monkeypatch.setattr(admission, "_claims", verified)
    if change == "none":
        with pytest.raises(AuthenticatedApprovalWithdrawal) as caught:
            admission.admit("synthetic", "consume", denial.plan_id, b"synthetic")
        assert caught.value.denial is denial
        assert events == ["jwt", "read"]
    else:
        with pytest.raises(ProviderRefused):
            admission.admit("synthetic", "consume", denial.plan_id, b"synthetic")
        assert admission._transport is None
        assert events == (["jwt"] if change == "token" else ["jwt", "read"])


@pytest.mark.parametrize("cleanup", ["none", "rollback", "close"])
def test_owner_withdrawal_read_requires_confirmed_database_cleanup(
    mutation_case, monkeypatch, cleanup
):
    import time
    from types import SimpleNamespace

    import vendor_cp.approvals.adapter as approvals
    import vendor_cp.deployment.approval_barrier as barrier
    from vendor_cp.deployment.gate0_window import (
        OwnerWindowReader,
        OwnerWindowWithdrawal,
    )
    from vendor_cp.deployment.protected_rehearsal_issuer import (
        SUBJECT_TYPE,
        issuer_approval_subject,
    )

    _, plan, expected, _, document = mutation_case
    events = []

    class SyntheticOwnerDenial(Exception):
        code = approvals.ApprovalHoldRefusal.WITHDRAWN

    def withdrawn(*args, **kwargs):
        raise SyntheticOwnerDenial("sensitive-owner-detail")

    monkeypatch.setattr(approvals, "ApprovalNotHeld", SyntheticOwnerDenial)
    monkeypatch.setattr(barrier, "held_transition", withdrawn)
    monkeypatch.setattr(
        approvals,
        "request_identity_evidence",
        lambda db, selected: SimpleNamespace(
            subject_type=SUBJECT_TYPE,
            subject_id=issuer_approval_subject(plan),
            content_digest=plan.plan_digest,
            policy_code=plan.approval_policy_code,
            policy_version=plan.approval_policy_version,
        ),
    )

    def finish(name):
        events.append(name)
        if cleanup == name:
            raise RuntimeError("sensitive-cleanup-detail")

    db = SimpleNamespace(
        get_bind=lambda: SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
        execute=lambda *args: None,
        rollback=lambda: finish("rollback"),
        close=lambda: finish("close"),
    )
    reader = object.__new__(OwnerWindowReader)
    reader._runtime = SimpleNamespace(platform_session_factory=lambda: db)
    reader._target_id = expected.target_id
    reader._origin = time.monotonic()
    reader._started = datetime.now(UTC)
    reader._expires = datetime.fromisoformat(
        document["expires_at"].replace("Z", "+00:00")
    )
    reader._deadline = reader._origin + 120
    reader._freshness = {}
    if cleanup == "none":
        with pytest.raises(OwnerWindowWithdrawal) as caught:
            reader.read("consume", UUID(expected.operation.plan_id), b"synthetic")
        assert caught.value.request_id == expected.approval_request_id
        assert caught.value.content_digest == plan.plan_digest
    else:
        with pytest.raises(ProviderRefused) as caught:
            reader.read("consume", UUID(expected.operation.plan_id), b"synthetic")
        assert type(caught.value) is ProviderRefused
        assert "sensitive" not in str(caught.value)
    assert events == ["rollback", "close"]


def test_actual_worker_frames_one_typed_terminal_and_cannot_rearm(
    signed_binding, monkeypatch
):
    import socket
    import time
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace

    from vendor_cp.deployment import gate0_services as services
    from vendor_cp.deployment.gate0_collection import IssuerOutcome, OutcomeKind
    from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused
    from vendor_cp.deployment.gate0_observation import encode
    from vendor_cp.deployment.gate0_window import (
        AuthenticatedApprovalWithdrawal,
        OwnerWindowWithdrawal,
    )

    binding, *_ = signed_binding
    expected = binding.expectation
    denial = OwnerWindowWithdrawal(
        window=binding.window,
        plan_id=UUID(expected.operation.plan_id),
        request_id=expected.approval_request_id,
        content_digest=expected.operation.plan_digest,
        phase="consume",
        freshness=expected.window_freshness,
    )

    def consume(*args):
        raise AuthenticatedApprovalWithdrawal(denial)

    monkeypatch.setattr(
        services,
        "assemble_gate0_composition",
        lambda **kwargs: SimpleNamespace(consume=consume),
    )
    worker = services.IssuerWorker(
        SimpleNamespace(
            database_qualified=True,
            actor_ref="synthetic",
            sessions=lambda: None,
            require_frozen_window=False,
            custody=None,
            admission=None,
            verifier=SimpleNamespace(_require_open=lambda: None),
            signer=None,
            authorization_verifier=None,
            authorization_ttl=None,
        )
    )
    left, right = socket.socketpair()
    try:
        deadline = time.monotonic() + 5
        client = FramedChannel(left.fileno(), left.fileno(), deadline=deadline)
        server = FramedChannel(right.fileno(), right.fileno(), deadline=deadline)
        request = {
            "schema": "Gate0IssuerSubmission.v1",
            "operation": "consume",
            "plan_id": expected.operation.plan_id,
            "authorization": encode(b"synthetic"),
            "proof": {},
            "workload_token": "sensitive-synthetic-token",
        }
        with ThreadPoolExecutor(max_workers=1) as pool:
            serving = pool.submit(worker.run, server)
            client.send(request)
            client.send(request)  # Never read after the first terminal refusal.
            outcome = IssuerOutcome.parse(client.receive())
            assert outcome.kind is OutcomeKind.OWNER_REFUSED
            assert outcome.ordinal == 1 and outcome.owner_namespace == "approvals"
            assert len(worker.outcomes) == 1
            with pytest.raises(services.ServiceOwnerRefused):
                serving.result(timeout=5)
        with pytest.raises(ServiceRefused):
            worker.run(server)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("case_kind", ["consume_replay", "withdrawal_later_use"])
def test_closed_case_kind_is_bound_to_canonical_owner_window(
    window_document, case_kind
):
    value = dict(window_document, case_kind=case_kind)
    parsed = FrozenIssuerWindow.parse(canonical(value))
    assert parsed.document["case_kind"] == case_kind
    other = dict(
        value,
        case_kind="withdrawal_later_use"
        if case_kind == "consume_replay"
        else "consume_replay",
    )
    assert FrozenIssuerWindow.parse(canonical(other)).digest != parsed.digest


@pytest.mark.parametrize(
    "case_kind",
    [
        None,
        True,
        1,
        [],
        {},
        "A",
        "consume",
        " consume_replay",
        "consume_replay ",
        "WITHDRAWAL_LATER_USE",
    ],
)
def test_case_kind_refuses_unknown_values_and_type_coercion(window_document, case_kind):
    with pytest.raises(ProviderRefused):
        FrozenIssuerWindow.parse(canonical(dict(window_document, case_kind=case_kind)))


def test_case_kind_is_required_in_closed_window(window_document):
    value = dict(window_document)
    del value["case_kind"]
    with pytest.raises(ProviderRefused):
        FrozenIssuerWindow.parse(canonical(value))


def test_changing_only_case_kind_invalidates_held_window_before_mutation(mutation_case):
    from vendor_cp.deployment.gate0_composition import CompositionRefused

    driver, plan, expected, events, document = mutation_case
    plan.snapshot["spec"]["gate0_window_v1"] = dict(
        document, case_kind="withdrawal_later_use"
    )
    with pytest.raises(CompositionRefused):
        driver._mutate(
            expected,
            None,
            lambda db: pytest.fail("changed case reached owner mutation"),
        )
    assert events == ["rollback", "close"]
