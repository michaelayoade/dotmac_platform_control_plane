"""Synthetic provider cases, executed only by hosted CI."""

# Everything below is explicitly synthetic authority and role material. These
# fakes cannot be selected from the installed production command.
import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment.gate0_composition import AdmissionExpectation
from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    ProviderRefused,
    RoleCustody,
    RolePaths,
    strict_json,
)
from vendor_cp.deployment.gate0_runtime import AdmittedOperation
from vendor_cp.deployment.gate0_workload_admission import (
    _FIXED_CLAIMS,
    GITHUB_ISSUER,
    ProposedApprovedWindow,
    WorkloadAdmission,
)

_SYNTHETIC_TRANSPORTS = {}


@pytest.fixture(autouse=True)
def synthetic_http_only(monkeypatch):
    original = BoundedJSONTransport.request
    _SYNTHETIC_TRANSPORTS.clear()

    def request(transport, path, **kwargs):
        fake = _SYNTHETIC_TRANSPORTS.get(transport.origin)
        if fake is not None:
            return fake.request(path, **kwargs)
        return original(transport, path, **kwargs)

    monkeypatch.setattr(BoundedJSONTransport, "request", request)
    yield
    _SYNTHETIC_TRANSPORTS.clear()


def test_no_live_admission_default():
    with pytest.raises(ProviderRefused):
        WorkloadAdmission().admit("synthetic", "issue", None)


def test_duplicate_json_refused():
    with pytest.raises(ProviderRefused):
        strict_json(b'{"token":"synthetic","token":"other"}')


@pytest.mark.parametrize(
    "role", ["runner", "platform-cp-rehearsal-issuer", "../attester"]
)
def test_no_wrong_role_seed_paths(role):
    with pytest.raises(ProviderRefused):
        RolePaths.for_role(role)


def test_distinct_role_seed_paths():
    issuer = RolePaths.for_role("issuer")
    attester = RolePaths.for_role("attester")
    assert issuer.seed != attester.seed
    assert issuer.approle != attester.approle
    assert issuer.seed.endswith("rehearsal-issuer/signing-key")
    assert attester.seed.endswith("rehearsal-attester/signing-key")


def test_no_missing_transport_or_decoder():
    with pytest.raises(ProviderRefused):
        RoleCustody(
            role="issuer",
            role_id="synthetic",
            key_id="synthetic",
            public_key=b"x" * 32,
            minimum_versions={"issuer": 1, "attester": 1},
        )


def test_unconfigured_cannot_be_activated_by_payload():
    provider = WorkloadAdmission()
    with pytest.raises(ProviderRefused):
        provider.admit('{"approved":true}', "consume", None)


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class SyntheticBao:
    def __init__(self, role, seed):
        self.role = role
        self.seed = seed
        self.paths = []
        self.mutate = lambda path, result: result
        self.public = (
            ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    def request(self, path, **kwargs):
        self.paths.append(path)
        if path == "/v1/sys/wrapping/lookup":
            result = {
                "data": {
                    "creation_path": (
                        f"auth/approle/role/platform-cp-rehearsal-{self.role}"
                        "/secret-id"
                    ),
                    "creation_time": datetime.now(UTC).isoformat(),
                    "creation_ttl": 60,
                }
            }
        elif path == "/v1/sys/wrapping/unwrap":
            result = {
                "data": {
                    "secret_id": "synthetic-id",
                    "secret_id_num_uses": 1,
                    "secret_id_ttl": 60,
                }
            }
        elif path == "/v1/auth/approle/login":
            assert kwargs["document"] == {
                "role_id": "synthetic-role-id",
                "secret_id": "synthetic-id",
            }
            result = {
                "auth": {
                    "client_token": "synthetic-bao-token",
                    "lease_duration": 120,
                    "renewable": False,
                }
            }
        elif path == "/v1/auth/token/lookup-self":
            result = {"data": {"renewable": False, "num_uses": 31, "ttl": 119}}
        elif path.endswith("/signing-key"):
            assert path == "/v1/" + RolePaths.for_role(self.role).seed
            result = {
                "data": {
                    "data": {
                        "key_id": "synthetic-key",
                        "private_key_b64url": encoded(self.seed),
                    }
                }
            }
        elif path.endswith("/trust-state"):
            result = {
                "data": {
                    "data": {
                        "version": 7,
                        "trusted_key_ids": {
                            "synthetic-key": "sha256:"
                            + hashlib.sha256(self.public).hexdigest()
                        },
                        "revoked_key_ids": [],
                    }
                }
            }
        else:
            raise AssertionError("unexpected endpoint")
        return self.mutate(path, result)


def custody(fake):
    _SYNTHETIC_TRANSPORTS["https://synthetic-bao.invalid"] = fake
    return RoleCustody(
        role=fake.role,
        role_id="synthetic-role-id",
        key_id="synthetic-key",
        public_key=fake.public,
        minimum_versions={"issuer": 7, "attester": 7},
        transport=BoundedJSONTransport("https://synthetic-bao.invalid"),
        seed_format="a4-provisional-private-key-b64url",
        expires_at=datetime.now(UTC) + timedelta(seconds=120),
    )


@pytest.mark.parametrize("role", ["issuer", "attester"])
def test_role_bootstrap_positive_and_close(role):
    fake = SyntheticBao(role, bytes(range(32)))
    provider = custody(fake)
    material = provider.bootstrap("synthetic-wrap")
    assert len([p for p in fake.paths if p.endswith("/signing-key")]) == 1
    if role == "issuer":
        signed = material.issuer_signer.sign_rehearsal_issuer_authorization(
            b"synthetic-owner-canonical"
        )
        assert material.issuer_verifier.verify_rehearsal_issuer_authorization(
            key_id=signed.key_id,
            algorithm="ed25519",
            purpose="deployment_rehearsal_issuer",
            public_key_fingerprint="sha256:" + hashlib.sha256(fake.public).hexdigest(),
            canonical_bytes=b"synthetic-owner-canonical",
            signature=signed.signature,
        )
        with pytest.raises(ProviderRefused):
            material.attester_sign(b"synthetic")
    else:
        signature = material.attester_sign(b"synthetic-generated-proof")
        ed25519.Ed25519PublicKey.from_public_bytes(fake.public).verify(
            signature, b"synthetic-generated-proof"
        )
        with pytest.raises(ProviderRefused):
            _ = material.issuer_signer
    with pytest.raises(ProviderRefused):
        provider.bootstrap("synthetic-second-wrap")
    provider.close()
    with pytest.raises(ProviderRefused):
        material.key._sign(b"synthetic")


@pytest.mark.parametrize(
    ("suffix", "section", "field", "value"),
    [
        (
            "wrapping/lookup",
            "data",
            "creation_path",
            "auth/approle/role/platform-cp-rehearsal-attester/secret-id",
        ),
        ("wrapping/lookup", "data", "creation_ttl", 301),
        ("wrapping/lookup", "data", "creation_time", "2000-01-01T00:00:00Z"),
        ("wrapping/unwrap", "data", "secret_id_num_uses", 0),
        ("wrapping/unwrap", "data", "secret_id_num_uses", 2),
        ("wrapping/unwrap", "data", "secret_id_ttl", 301),
        ("approle/login", "auth", "renewable", True),
        ("approle/login", "auth", "lease_duration", 301),
        ("lookup-self", "data", "num_uses", 0),
        ("lookup-self", "data", "num_uses", 33),
        ("lookup-self", "data", "ttl", 301),
    ],
)
def test_custody_refuses_bad_wrapping_or_token_metadata(suffix, section, field, value):
    fake = SyntheticBao("issuer", bytes(range(32)))

    def mutate(path, result):
        if path.endswith(suffix):
            result[section][field] = value
        return result

    fake.mutate = mutate
    provider = custody(fake)
    with pytest.raises(ProviderRefused):
        provider.bootstrap("synthetic-wrap")
    assert not any(p.endswith("signing-key") for p in fake.paths)
    with pytest.raises(ProviderRefused):
        provider.bootstrap("synthetic-retry")


def test_trust_floor_and_refresh_failure_close_signer():
    fake = SyntheticBao("attester", bytes(range(32)))
    provider = custody(fake)
    material = provider.bootstrap("synthetic-wrap")

    def rollback(path, result):
        if path.endswith("trust-state"):
            result["data"]["data"]["version"] = 6
        return result

    fake.mutate = rollback
    with pytest.raises(ProviderRefused):
        provider.refresh()
    with pytest.raises(ProviderRefused):
        material.attester_sign(b"synthetic")


def test_request_budget_deadline_and_seed_pin(monkeypatch):
    fake = SyntheticBao("attester", bytes(range(32)))
    provider = custody(fake)
    material = provider.bootstrap("synthetic-wrap")
    provider._uses = 32
    with pytest.raises(ProviderRefused):
        provider.refresh()
    assert not material.attester_trust.available
    fake = SyntheticBao("attester", bytes(range(32)))
    provider = custody(fake)
    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_role_custody.time.monotonic",
        lambda: provider.deadline + 1,
    )
    with pytest.raises(ProviderRefused):
        provider.bootstrap("synthetic-wrap")
    assert fake.paths == []


class SyntheticJWKS:
    origin = GITHUB_ISSUER

    def __init__(self, key):
        nums = key.public_key().public_numbers()
        self.document = {
            "keys": [
                {
                    "kid": "synthetic-rsa",
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "n": encoded(
                        nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
                    ),
                    "e": encoded(nums.e.to_bytes(3, "big")),
                }
            ]
        }
        self.calls = 0

    def request(self, path, **kwargs):
        assert path == "/.well-known/jwks"
        assert kwargs["token"] is None
        self.calls += 1
        return self.document


@pytest.fixture
def jwt_case():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # This is not a live GitHub bearer or an actual approved window.
    now = datetime.now(UTC).replace(microsecond=0)
    ssh_fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode().rstrip("=")
    op = AdmittedOperation(
        repository_id="1397614140",
        run_id="22",
        run_attempt="2",
        window_id="synthetic-window",
        phase="issue",
        authorization_digest=None,
        authorization_issued_at=None,
        lease_id="synthetic-lease",
        controller_fingerprint=ssh_fingerprint,
        target_ref="synthetic-target",
        plan_id=str(UUID(int=1)),
        plan_digest="sha256:" + "1" * 64,
        plan_purpose="rehearsal_issuer_operation",
        operation="deploy",
        execution_plan_digest="sha256:" + "2" * 64,
        certificate_digest="sha256:" + "3" * 64,
        ca_fingerprint=ssh_fingerprint,
    )
    expected = AdmissionExpectation(
        op, UUID(int=2), "rehearsal", UUID(int=3), "synthetic-policy", 1
    )
    window = ProposedApprovedWindow(
        expected,
        "synthetic-exact-subject",
        "a" * 40,
        now - timedelta(seconds=2),
        now + timedelta(seconds=120),
        "sha256:" + "4" * 64,
    )
    transport = SyntheticJWKS(key)
    _SYNTHETIC_TRANSPORTS[GITHUB_ISSUER] = transport
    admission = WorkloadAdmission(
        windows=(window,),
        transport=BoundedJSONTransport(GITHUB_ISSUER),
        expires_at=now + timedelta(seconds=120),
    )
    claims = dict(
        _FIXED_CLAIMS,
        run_id="22",
        run_attempt="2",
        sub=window.subject,
        workflow_sha=window.workflow_sha,
        iat=int(now.timestamp()),
        nbf=int(now.timestamp()),
        exp=int((now + timedelta(seconds=60)).timestamp()),
        jti="synthetic-jti",
    )

    def token(changes=None, header_changes=None):
        header = dict(alg="RS256", kid="synthetic-rsa", typ="JWT")
        header.update(header_changes or {})
        body = dict(claims, **(changes or {}))
        signing = (
            encoded(json.dumps(header).encode())
            + "."
            + encoded(json.dumps(body).encode())
        ).encode()
        return (
            signing.decode()
            + "."
            + encoded(key.sign(signing, padding.PKCS1v15(), hashes.SHA256()))
        )

    return admission, window, transport, token


def test_valid_synthetic_jwt_and_window_and_no_cache(jwt_case):
    admission, window, transport, token = jwt_case
    assert admission.admit(token(), "issue", UUID(int=1)) == window.expectation
    assert (
        admission.window_record_digest(window.expectation)
        == window.authority_record_digest
    )
    transport.document = {"keys": []}
    with pytest.raises(ProviderRefused):
        admission.admit(token(), "issue", UUID(int=1))
    assert transport.calls == 2


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("repository_id", "1"),
        ("repository_owner_id", "1"),
        ("repository", "other/repo"),
        ("run_id", "23"),
        ("run_attempt", "1"),
        ("run_attempt", 2),
        ("environment", "other"),
        ("workflow_ref", "other"),
        ("workflow_sha", "b" * 40),
        ("event_name", "pull_request_target"),
        ("ref", "refs/heads/other"),
        ("sub", "other"),
        ("iss", "https://example.invalid"),
        ("aud", "other"),
        ("exp", 1),
        ("iat", True),
        ("job_workflow_ref", "synthetic-reusable"),
    ],
)
def test_wrong_jwt_claims_refused(jwt_case, claim, value):
    admission, _, _, token = jwt_case
    with pytest.raises(ProviderRefused):
        admission.admit(token({claim: value}), "issue", UUID(int=1))


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none"},
        {"alg": "HS256"},
        {"jku": "https://example.invalid/keys"},
        {"x5u": "https://example.invalid/keys"},
        {"crit": ["synthetic"]},
        {"kid": "unknown"},
    ],
)
def test_algorithm_and_token_key_url_refused(jwt_case, header):
    admission, _, _, token = jwt_case
    with pytest.raises(ProviderRefused):
        admission.admit(token(header_changes=header), "issue", UUID(int=1))


def test_window_substitution_phase_plan_and_original_deadline(jwt_case, monkeypatch):
    admission, window, _, token = jwt_case
    with pytest.raises(ProviderRefused):
        admission.admit(token(), "consume", UUID(int=1))
    with pytest.raises(ProviderRefused):
        admission.admit(token(), "issue", UUID(int=99))
    substituted = replace(
        window.expectation,
        operation=replace(window.expectation.operation, window_id="other"),
    )
    with pytest.raises(ProviderRefused):
        admission.window_record_digest(substituted)
    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_workload_admission.time.monotonic",
        lambda: admission._deadline + 1,
    )
    with pytest.raises(ProviderRefused):
        admission.admit(token(), "issue", UUID(int=1))


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.invalid",
        "https://user:pass@example.invalid",
        "https://example.invalid/?redirect=1",
        "file:///tmp/synthetic",
    ],
)
def test_transport_rejects_unencrypted_credentials_and_urls(origin):
    with pytest.raises(ProviderRefused):
        BoundedJSONTransport(origin)


def test_http_deadline_cancels_child_without_external_io(monkeypatch):
    """Exercise parent cancellation mechanically with synthetic process/pipe."""

    class Pipe:
        def close(self):
            pass

        def poll(self, timeout):
            assert 0 < timeout <= 5
            return False

    class Process:
        pid = None
        killed = False

        def start(self):
            self.pid = 1

        def is_alive(self):
            return not self.killed

        def kill(self):
            self.killed = True

        def join(self, timeout):
            assert timeout <= 0.2

    process = Process()

    class Context:
        def Pipe(self, duplex):
            assert duplex is False
            return Pipe(), Pipe()

        def Process(self, **kwargs):
            assert kwargs["daemon"] is True
            return process

    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_role_custody.multiprocessing.get_context",
        lambda _: Context(),
    )
    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_role_custody.time.monotonic", lambda: 1.0
    )
    transport = BoundedJSONTransport("https://synthetic.invalid")
    with pytest.raises(ProviderRefused):
        transport.request(
            "/v1/sys/wrapping/lookup",
            method="POST",
            token="synthetic-secret",
            document={},
            deadline=2.0,
        )
    assert process.killed


def test_admission_attempt_budget_refuses_before_jwks(jwt_case):
    admission, _, transport, token = jwt_case
    admission._attempts = 16
    with pytest.raises(ProviderRefused):
        admission.admit(token(), "issue", UUID(int=1))
    assert transport.calls == 0


def test_changed_seed_public_pin_refuses_without_signer():
    fake = SyntheticBao("issuer", bytes(range(32)))
    provider = custody(fake)

    def altered_seed(path, result):
        if path.endswith("signing-key"):
            result["data"]["data"]["private_key_b64url"] = encoded(b"z" * 32)
        return result

    fake.mutate = altered_seed
    with pytest.raises(ProviderRefused):
        provider.bootstrap("synthetic-wrap")
    assert provider._material is None


def test_jwks_rejects_duplicate_key_ids(jwt_case):
    admission, _, transport, token = jwt_case
    transport.document["keys"] *= 2
    with pytest.raises(ProviderRefused):
        admission.admit(token(), "issue", UUID(int=1))


def test_cached_record_cannot_extend_original_deadline(jwt_case, monkeypatch):
    admission, window, _, token = jwt_case
    assert admission.admit(token(), "issue", UUID(int=1)) == window.expectation
    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_workload_admission.time.monotonic",
        lambda: admission._deadline + 1,
    )
    with pytest.raises(ProviderRefused):
        admission.window_record_digest(window.expectation)


@pytest.mark.parametrize("partial", [b"\x00\x00", b"\x00\x00\x00\x20abc"])
def test_partial_ipc_header_or_payload_obeys_deadline(monkeypatch, partial):
    """Readable bytes never imply completion; no external HTTP or real child."""
    import multiprocessing
    import os
    import time

    real_context = multiprocessing.get_context("spawn")
    parent, child = real_context.Pipe(duplex=False)

    class StalledChild:
        pid = None
        held_fd = None
        killed = False

        def start(self):
            self.pid = 1
            self.held_fd = os.dup(child.fileno())
            os.write(self.held_fd, partial)

        def is_alive(self):
            return not self.killed

        def kill(self):
            self.killed = True
            os.close(self.held_fd)

        def join(self, timeout):
            assert timeout <= 0.2

    process = StalledChild()

    class Context:
        def Pipe(self, duplex):
            assert duplex is False
            return parent, child

        def Process(self, **kwargs):
            return process

    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_role_custody.multiprocessing.get_context",
        lambda _: Context(),
    )
    started = time.monotonic()
    transport = BoundedJSONTransport("https://synthetic.invalid", timeout=0.05)
    with pytest.raises(ProviderRefused):
        transport.request(
            "/v1/sys/wrapping/lookup",
            method="POST",
            token="synthetic",
            document={},
            deadline=started + 0.05,
        )
    assert process.killed
    assert time.monotonic() - started < 1
    assert parent.closed and child.closed


@pytest.fixture
def combined_worker(jwt_case, monkeypatch):
    """Real worker/composition/admission; synthetic DB/owner effects and proofs.

    This tests their combined bridge, not a real Approvals hold or DB lifecycle.
    The installed owner parser and public return types are used unchanged.
    """
    from dataclasses import asdict
    from types import SimpleNamespace

    import dotmac_deployment_control as control

    from vendor_cp.deployment import gate0_composition as composition
    from vendor_cp.deployment import gate0_services as services
    from vendor_cp.deployment.gate0_framing import canonical
    from vendor_cp.deployment.gate0_runtime import AttestationContext

    original, issue_window, transport, token = jwt_case
    issue = issue_window.expectation
    wall = datetime.now(UTC)
    derived = control.A6ProvenanceKind.DERIVED
    statement = control.RehearsalIssuerAuthorizationStatementV1(
        authorization_id="synthetic-authorization",
        immutable_reference=issue.operation.plan_id,
        target_id=str(issue.target_id),
        target_ref=issue.operation.target_ref,
        target_provenance=derived,
        desired_state_digest=issue.operation.plan_digest,
        desired_state_provenance=derived,
        profile_digest="sha256:" + "5" * 64,
        profile_provenance=derived,
        authorized_image_digests=(),
        authorized_images_provenance=derived,
        execution_plan_digest=issue.operation.execution_plan_digest,
        execution_plan_provenance=derived,
        controller_fingerprint=issue.operation.controller_fingerprint,
        key_id="synthetic-issuer",
        algorithm="ed25519",
        public_key_fingerprint="sha256:" + "6" * 64,
        lease_id=issue.operation.lease_id,
        single_use_reference="synthetic-once",
        environment="rehearsal",
        not_before=wall,
        issued_at=wall,
        expires_at=wall + timedelta(seconds=60),
        control_version="0.1.0a17",
    )
    envelope = control.RehearsalIssuerAuthorizationV1(statement, "synthetic-signature")
    document = canonical(envelope.as_mapping())
    binding = composition.authorization_binding(document)
    consume = replace(
        issue,
        operation=replace(
            issue.operation,
            phase="consume",
            authorization_digest=binding.digest,
            authorization_issued_at=binding.issued_at,
        ),
    )
    consume_window = replace(issue_window, expectation=consume)
    admission = WorkloadAdmission(
        windows=(issue_window, consume_window),
        transport=BoundedJSONTransport(GITHUB_ISSUER),
        expires_at=original._expires,
    )
    entries, installs, effects, sessions = {}, [], [], []

    class Registry:
        def _require_open(self):
            pass

        def _register(self, proof, operation):
            evidence = "sha256:" + ("a" if operation.phase == "issue" else "b") * 64
            entries[evidence] = SimpleNamespace(
                context=AttestationContext(
                    **asdict(operation),
                    challenge_digest="sha256:" + "c" * 64,
                    proof_transcript_digest="sha256:" + "d" * 64,
                ),
                owner_envelope=b"{}",
                owner_bytes=canonical(
                    {"issued_at": (wall + timedelta(seconds=1)).isoformat()}
                ),
            )
            return evidence

        def _evidence(self, digest):
            return entries[digest]

    registry = Registry()
    # Exact synthetic current plan; the real composition compares every field.
    plan = SimpleNamespace(
        id=UUID(issue.operation.plan_id),
        target_id=issue.target_id,
        purpose=issue.operation.plan_purpose,
        operation=issue.operation.operation,
        plan_digest=issue.operation.plan_digest,
        execution_plan_digest=issue.operation.execution_plan_digest,
        descriptor_digest=statement.profile_digest,
        requires_approval=True,
        approval_decision_ref=str(issue.approval_request_id),
        approval_policy_code=issue.approval_policy_code,
        approval_policy_version=issue.approval_policy_version,
    )
    target = SimpleNamespace(
        id=issue.target_id,
        target_ref=issue.operation.target_ref,
        environment="rehearsal",
    )

    class DB:
        def commit(self):
            effects.append("commit")

        def rollback(self):
            effects.append("rollback")

        def close(self):
            pass

    def session():
        db = DB()
        sessions.append(db)
        return db

    def issued(db, invocation):
        effects.append("issue")
        return envelope

    def consumed(db, **kwargs):
        assert kwargs["authorization_document"] == envelope.as_mapping()
        effects.append("consume")
        return control.RehearsalIssuerConsumptionStaged(
            statement.authorization_id,
            statement.single_use_reference,
            statement.lease_id,
        )

    def standing(db, **kwargs):
        assert kwargs["authorization_document"] == envelope.as_mapping()
        effects.append("standing")
        return SimpleNamespace(
            standing=SimpleNamespace(value="synthetic-standing"), refusal=None
        )

    monkeypatch.setattr(
        control, "get_plan", lambda db, selected: plan if selected == plan.id else None
    )
    monkeypatch.setattr(
        control,
        "get_target",
        lambda db, selected: target if selected == target.id else None,
    )
    monkeypatch.setattr(
        control,
        "install_rehearsal_issuer_security",
        lambda **kwargs: installs.append(kwargs),
    )
    monkeypatch.setattr(control, "rehearsal_issuer_standing_for", standing)
    monkeypatch.setattr(composition, "issue_authorization", issued)
    monkeypatch.setattr(composition, "consume_authorization", consumed)
    monkeypatch.setattr(
        services.IssuerWorker,
        "_proof",
        lambda self, expected: SimpleNamespace(
            synthetic_phase=expected.operation.phase
        ),
    )
    # The real composition registers the synthetic proof through its resolver.
    startup = services.IssuerStartup(
        admission,
        registry,
        object(),
        object(),
        timedelta(seconds=30),
        "synthetic-actor",
        True,
        require_frozen_window=False,  # Explicit unbound synthetic bridge case.
        sessions=session,
    )
    registry._expires = wall + timedelta(seconds=120)
    registry._now = lambda: wall
    worker = services.IssuerWorker(startup)

    class Channel:
        def __init__(self, requests):
            self.requests, self.output = iter(requests), []

        def receive(self, allow_eof=False):
            return next(self.requests, None)

        def send(self, result):
            self.output.append(result)

    def request(phase):
        common = {
            "schema": "Gate0IssuerSubmission.v1",
            "operation": phase,
            "workload_token": token(),
        }
        if phase == "issue":
            return dict(
                common,
                plan_id=issue.operation.plan_id,
                command_id="synthetic-command",
                proof={},
            )
        if phase == "standing":
            return dict(
                common,
                authorization=services.encode(document),
                evidence_digest="sha256:" + "a" * 64,
            )
        return dict(
            common,
            plan_id=issue.operation.plan_id,
            authorization=services.encode(document),
            proof={},
        )

    return SimpleNamespace(
        worker=worker,
        admission=admission,
        request=request,
        channel=Channel,
        effects=effects,
        installs=installs,
        entries=entries,
        transport=transport,
        document=document,
        plan=plan,
    )


def test_combined_issue_standing_consume_retains_install_and_phase_binding(
    combined_worker,
):
    case = combined_worker
    channel = case.channel([case.request(p) for p in ("issue", "standing", "consume")])
    case.worker.run(channel)
    assert [item["operation"] for item in channel.output] == [
        "issue",
        "standing",
        "consume",
    ]
    assert case.effects == ["issue", "commit", "standing", "consume", "commit"]
    assert len(case.installs) == 1 and len(case.entries) == 2
    assert case.transport.calls == 3
    assert all(item["readiness_accepted"] is False for item in channel.output)


@pytest.mark.parametrize(
    "substitution", ["standing-envelope", "consume-envelope", "plan", "jwks"]
)
def test_combined_lifecycle_substitutions_refuse(combined_worker, substitution):
    from vendor_cp.deployment.gate0_framing import canonical
    from vendor_cp.deployment.gate0_observation import encode

    case = combined_worker
    case.worker.run(case.channel([case.request("issue")]))
    request = case.request(
        "standing" if substitution == "standing-envelope" else "consume"
    )
    if substitution.endswith("envelope"):
        changed = json.loads(case.document)
        changed["statement"]["target_ref"] = "substituted-target"
        request["authorization"] = encode(canonical(changed))
    elif substitution == "plan":
        case.plan.plan_digest = "sha256:" + "9" * 64
    else:
        case.transport.document = {"keys": []}
    with pytest.raises(ValueError):
        case.worker.run(case.channel([request]))
    assert case.effects == ["issue", "commit"]
    assert len(case.installs) == 1


def test_nonblocking_ipc_frame_positive_and_length_refusals():
    import multiprocessing
    import os
    import struct
    import time

    from vendor_cp.deployment.gate0_role_custody import _receive_message

    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    try:
        child.send_bytes(b'{"synthetic":true}')
        assert _receive_message(parent, time.monotonic() + 1) == b'{"synthetic":true}'
    finally:
        parent.close()
        child.close()
    for length in (-1, 0, 131073):
        parent, child = context.Pipe(duplex=False)
        try:
            os.write(child.fileno(), struct.pack("!i", length))
            with pytest.raises(ProviderRefused):
                _receive_message(parent, time.monotonic() + 1)
        finally:
            parent.close()
            child.close()


def test_child_fallback_broken_pipe_emits_no_exception_details(monkeypatch, capsys):
    from vendor_cp.deployment.gate0_role_custody import _http_child

    def rejected(*args, **kwargs):
        raise OSError("synthetic-sensitive-error-marker")

    class BrokenConnection:
        def send_bytes(self, raw):
            raise BrokenPipeError("synthetic-pipe")

        def close(self):
            raise OSError("synthetic-close")

    monkeypatch.setattr(
        "vendor_cp.deployment.gate0_role_custody.urllib.request.Request", rejected
    )
    _http_child(
        BrokenConnection(),
        "https://synthetic.invalid",
        "GET",
        "synthetic-token",
        None,
        1,
        1024,
    )
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
