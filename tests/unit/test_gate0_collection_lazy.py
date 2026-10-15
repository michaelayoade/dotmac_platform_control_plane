"""Focused lazy-core tests; mocked owned boundaries do not qualify a campaign."""

import socket
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    SSHCertificateBuilder,
    SSHCertificateType,
    load_ssh_public_identity,
)
from test_gate0_collection_api import case  # noqa: F401
from test_gate0_runner_projection import approval_bytes
from test_gate0_runner_projection import (
    runner_cases as projection_runner_cases,  # noqa: F401
)
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment.gate0_attester import ssh_public_fingerprint
from vendor_cp.deployment.gate0_collection import (
    FixedEvidenceCollector,
    FramedCaseCollector,
    digest,
)
from vendor_cp.deployment.gate0_framing import (
    FramedChannel,
    ServiceRefused,
    canonical,
    strict_object,
)
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_projection import (
    RunnerProjectionCase,
    WithdrawalProjection,
    decode_approval,
)
from vendor_cp.deployment.gate0_runner_ssh import (
    OwnedAttesterSession,
    OwnedIssuerSession,
)
from vendor_cp.deployment.gate0_runtime import (
    BoundedHarnessVerifier,
    ProofRegistrationRefused,
)
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment.rehearsal_issuer_trust_state import RehearsalIssuerTrustState


@pytest.fixture
def controller_certificates():
    ca = Ed25519PrivateKey.generate()
    stamp = int(datetime.now(UTC).timestamp())
    return tuple(
        SSHCertificateBuilder()
        .public_key(Ed25519PrivateKey.generate().public_key())
        .type(SSHCertificateType.USER)
        .key_id(f"synthetic-lazy-{ordinal}".encode())
        .valid_principals([b"dotmac-gate0-controller"])
        .valid_after(stamp - 1)
        .valid_before(stamp + 600)
        .sign(ca)
        for ordinal in range(2)
    )


@pytest.fixture
def runner_cases(projection_runner_cases, controller_certificates):  # noqa: F811
    selected_cases = []
    for selected, certificate in zip(
        projection_runner_cases, controller_certificates, strict=True
    ):
        document = strict_object(selected.frozen_window)
        document["controller"].update(
            certificate_digest=digest(certificate.public_bytes()),
            fingerprint=ssh_public_fingerprint(certificate.public_key()),
            ca_fingerprint=ssh_public_fingerprint(certificate.signature_key()),
        )
        window = FrozenIssuerWindow.parse(canonical(document))
        packet = strict_object(selected.shared_packet)
        packet["controller_ca_fingerprint"] = document["controller"]["ca_fingerprint"]
        packet["management_key_fingerprint"] = document["controller"]["fingerprint"]
        packet["capture"]["window_digest"] = window.digest
        selected_cases.append(
            RunnerProjectionCase(
                canonical(packet),
                window.canonical_bytes,
                selected.wall_origin,
                selected.monotonic_origin,
            )
        )
    return tuple(selected_cases)


@pytest.fixture
def lazy(runner_cases):  # noqa: F811
    return FixedEvidenceCollector.for_installed(
        cases=runner_cases,
        command_a="synthetic-command-A",
        command_b="synthetic-command-B",
        withdrawal_ref="synthetic-human-reference",
    )


@pytest.fixture
def owned_boundary(tmp_path, controller_certificates):
    """Real framing, isolated owned-session objects; no SSH process is spawned."""
    sockets = []

    def make(selected):
        left, right = socket.socketpair()
        sockets.extend((left, right))
        issuer = object.__new__(OwnedIssuerSession)
        issuer.channel = FramedChannel(
            left.fileno(), left.fileno(), deadline=selected.deadline
        )
        issuer.collector = FramedCaseCollector(issuer.channel)
        issuer._completion = None
        certificate = next(
            item
            for item in controller_certificates
            if digest(item.public_bytes())
            == selected.window.document["controller"]["certificate_digest"]
        )
        # Model ordinary ssh-keygen file representation, not installed custody.
        certificate_file = tmp_path / (selected.window.document["case_kind"] + ".pub")
        certificate_file.write_bytes(certificate.public_bytes() + b"\n")
        certificate_file.chmod(0o600)
        certificate_raw = certificate_file.read_bytes()
        issuer.certificate = load_ssh_public_identity(certificate_raw.rstrip(b"\n"))
        assert isinstance(issuer.certificate, SSHCertificate)
        issuer.installation = SimpleNamespace(
            deadline=selected.deadline,
            expires_at=datetime.fromisoformat(
                selected.window.document["expires_at"].replace("Z", "+00:00")
            ),
            certificate=SimpleNamespace(
                sha256=digest(certificate_raw).removeprefix("sha256:")
            ),
            require_open=selected.require_open,
        )
        public = bytes(32)  # Existing synthetic packet's public attester key.
        trust = RehearsalIssuerTrustState.start(
            minimum_version=1,
            read_record=lambda: {
                "version": 1,
                "trusted_key_ids": {"synthetic": digest(public)},
                "revoked_key_ids": [],
            },
        )
        verifier = BoundedHarnessVerifier(
            key_id="synthetic",
            public_key=public,
            trust_state=trust,
            expires_at=datetime.fromisoformat(
                selected.window.document["expires_at"].replace("Z", "+00:00")
            ),
            deadline=selected.deadline,
        )
        return issuer, verifier

    yield make
    for item in sockets:
        item.close()


def test_inert_campaign_constructs_no_freshness_or_verifier(
    monkeypatch,
    runner_cases,  # noqa: F811
):
    from vendor_cp.deployment import gate0_runner_projection as projection

    a, b = runner_cases
    future = strict_object(b.frozen_window)
    future["not_before"] = (
        (datetime.now(UTC) + timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
    )
    future["expires_at"] = (
        (datetime.now(UTC) + timedelta(seconds=180)).isoformat().replace("+00:00", "Z")
    )
    window = FrozenIssuerWindow.parse(canonical(future))
    packet = strict_object(b.shared_packet)
    packet["not_before"], packet["expires_at"] = (
        future["not_before"],
        future["expires_at"],
    )
    packet["capture"]["window_digest"] = window.digest
    future_b = RunnerProjectionCase(
        canonical(packet), window.canonical_bytes, b.wall_origin, b.monotonic_origin
    )
    monkeypatch.setattr(
        projection, "WindowFreshness", lambda *a: pytest.fail("activated freshness")
    )
    collector = FixedEvidenceCollector.for_installed(
        cases=(a, future_b),
        command_a="A",
        command_b="B",
        withdrawal_ref="human-reference",
    )
    assert collector._bindings == collector._approvals == collector._verifiers == {}
    assert collector._issuers == {} and collector._bundles == []
    assert not hasattr(collector, "_b")
    assert not hasattr(collector, "_verifier")


def test_installed_db_helpers_refuse_before_acquiring_a_session(lazy):
    def sessions():
        pytest.fail("installed A9 must not access the CP database")

    with pytest.raises(ServiceRefused):
        lazy.read_approval(case="a", sessions=sessions)
    with pytest.raises(ServiceRefused):
        lazy.observe_b_withdrawal(sessions=sessions, external_ref="human-reference")


def test_a_binding_matches_canonical_certificate_despite_normal_file_newline(
    case,  # noqa: F811
    runner_cases,  # noqa: F811
    lazy,
    owned_boundary,  # noqa: F811
):
    selected = runner_cases[0]
    approval = decode_approval(approval_bytes(case, selected), selected)
    issuer, verifier = owned_boundary(selected)
    assert digest(issuer.certificate.public_bytes()) == (
        approval.binding.expectation.operation.certificate_digest
    )
    assert "sha256:" + issuer.installation.certificate.sha256 != (
        approval.binding.expectation.operation.certificate_digest
    )
    lazy.bind_case_a(approval, issuer, verifier, object(), object())
    assert lazy._a is issuer.collector
    assert lazy._approvals["a"] is approval.raw
    assert lazy._verifiers == {"a": verifier}
    assert not hasattr(lazy, "_b")
    with pytest.raises(ServiceRefused):
        lazy.bind_case_a(approval, issuer, verifier, object(), object())


@pytest.mark.parametrize(
    "changed",
    [
        "foreign-approval",
        "second-collector",
        "late-verifier",
        "wrong-actual-certificate",
    ],
)
def test_binding_refuses_projection_channel_and_original_deadline_substitution(
    case,  # noqa: F811
    runner_cases,  # noqa: F811
    lazy,
    owned_boundary,
    changed,  # noqa: F811
):
    selected = runner_cases[0]
    approval = decode_approval(approval_bytes(case, selected), selected)
    issuer, verifier = owned_boundary(selected)
    if changed == "foreign-approval":
        other = runner_cases[1]
        approval = decode_approval(approval_bytes(case, other), other)
    elif changed == "second-collector":
        other, _ = owned_boundary(selected)
        issuer.collector = other.collector
    elif changed == "wrong-actual-certificate":
        other, _ = owned_boundary(runner_cases[1])
        issuer.certificate = other.certificate
    else:
        verifier._deadline = selected.deadline + 0.001
    with pytest.raises((ServiceRefused, ProviderRefused, ProofRegistrationRefused)):
        lazy.bind_case_a(approval, issuer, verifier, object(), object())
    assert lazy._bindings == {} and lazy._issuers == {}


def test_owner_replay_completion_alone_cannot_activate_b(lazy, monkeypatch):
    from vendor_cp.deployment import gate0_runner_projection as projection

    lazy._a_done = True
    monkeypatch.setattr(
        projection, "decode_approval", lambda *a: pytest.fail("B approval decoded")
    )
    with pytest.raises(ServiceRefused):
        lazy.bind_case_b(object(), object(), object(), object(), object())
    assert lazy._binding_attempts == set() and not hasattr(lazy, "_b")


@pytest.mark.parametrize("ack_state", ["sent", "failed", "late"])
def test_only_owned_join_return_after_ack_enables_b(
    case,  # noqa: F811
    runner_cases,  # noqa: F811
    lazy,
    owned_boundary,
    monkeypatch,
    ack_state,
):
    from vendor_cp.deployment.gate0_runner_collector_handoff import (
        OwnedCollectorHandoff,
    )

    a, b = runner_cases
    approval_a = decode_approval(approval_bytes(case, a), a)
    issuer_a, verifier_a = owned_boundary(a)
    lazy.bind_case_a(approval_a, issuer_a, verifier_a, object(), object())
    # Isolate the core's join transition; proof/SSH/root semantics have owners.
    lazy._a_done = True
    lazy._a_expected = approval_a.binding.expectation
    lazy._bundles = [b"synthetic-issued-bundle", b"synthetic-consumed-bundle"]
    sessions = [object.__new__(OwnedAttesterSession) for _ in range(2)]
    for session, bundle in zip(sessions, lazy._bundles, strict=True):
        session._bundle = bundle
    root = object.__new__(OwnedCollectorHandoff)
    events = []
    joined = canonical({"private_synthetic_join": "not root qualification"})

    def complete(self, issuer, issue, consume, *, issue_expected, consume_expected):
        assert self is root and issuer is issuer_a
        assert (issue, consume) == tuple(sessions)
        assert issue_expected is approval_a.binding.expectation
        assert consume_expected is lazy._a_expected
        assert lazy._a_join is None and not hasattr(lazy, "_b")
        events.append("owned-join")
        if ack_state == "failed":
            raise ServiceRefused()
        events.append("sent-ack")
        if ack_state == "late":
            from vendor_cp.deployment import gate0_runner_projection as projection

            monkeypatch.setattr(projection.time, "monotonic", lambda: a.deadline)
        return joined

    monkeypatch.setattr(OwnedCollectorHandoff, "complete_case_a", complete)
    if ack_state != "sent":
        with pytest.raises((ServiceRefused, ProviderRefused)):
            lazy.complete_case_a(root, *sessions)
        assert lazy._a_join is None
        with pytest.raises(ServiceRefused):
            lazy.bind_case_b(object(), object(), object(), object(), object())
        assert events == (
            ["owned-join"] if ack_state == "failed" else ["owned-join", "sent-ack"]
        )
    else:
        assert lazy.complete_case_a(root, *sessions) is joined
        assert events == ["owned-join", "sent-ack"]
        approval_b = decode_approval(approval_bytes(case, b), b)
        issuer_b, verifier_b = owned_boundary(b)
        lazy.bind_case_b(approval_b, issuer_b, verifier_b, object(), object())
        assert lazy._b is issuer_b.collector
        assert lazy._verifiers == {"a": verifier_a, "b": verifier_b}
        assert lazy._approvals == {"a": approval_a.raw, "b": approval_b.raw}
    with pytest.raises(ServiceRefused):
        lazy.complete_case_a(root, *sessions)


@pytest.mark.parametrize("budget", ["fifth", "aggregate"])
def test_campaign_bundle_budget_refuses_before_any_registration(lazy, budget):
    if budget == "fifth":
        lazy._bundles = [b"retained"] * 4
        raw = b"{}"
    else:
        lazy._bundles = [b"x" * (128 * 1024)] * 3
        raw = b"x" * (128 * 1024 + 1)
    with pytest.raises(ServiceRefused):
        lazy._proof(raw, SimpleNamespace(window_digest=digest(b"window")))
    assert not hasattr(lazy, "_verifier")


def test_pending_b_projection_retains_no_revocation_and_caps_reads(
    case,  # noqa: F811
    runner_cases,  # noqa: F811
    lazy,  # noqa: F811
):
    b = runner_cases[1]
    approval = decode_approval(approval_bytes(case, b), b)
    # Exercise the real semantic DTO decoder without transport or a DB seam.
    lazy._a_join = canonical({"synthetic_unit_join": True})
    lazy._b_expected = approval.binding.expectation
    lazy._b_consume = b"synthetic-retained-consume"
    lazy._b_issue = SimpleNamespace(
        result_bytes=canonical({"authorization_id": "synthetic-authorization"})
    )
    lazy._projections["b"] = approval
    raw = canonical(
        {
            "schema": "Gate0CollectionWithdrawal.v1",
            "binding": b.binding,
            "state": "pending_withdrawal",
            "withdrawal": None,
            "relay": None,
            "observed_at": datetime.now(approval.approved_at.tzinfo).isoformat(),
        }
    )
    pending = WithdrawalProjection(raw, "pending_withdrawal", None)
    for _ in range(16):
        assert lazy.observe_b_projection(pending) is False
        assert lazy._b_revocation is None
    with pytest.raises(ServiceRefused):
        lazy.observe_b_projection(pending)
    assert strict_object(raw)["state"] == "pending_withdrawal"


@pytest.mark.parametrize("swap", [None, "reference", "authorization", "plan", "state"])
def test_applied_b_projection_rejoins_fixed_reference_actual_authorization_and_plan(
    case,  # noqa: F811
    runner_cases,  # noqa: F811
    lazy,
    swap,  # noqa: F811
):
    b = runner_cases[1]
    approval = decode_approval(approval_bytes(case, b), b)
    lazy._a_join = canonical({"synthetic_unit_join": True})
    lazy._b_expected = approval.binding.expectation
    lazy._b_consume = b"synthetic-retained-consume"
    lazy._b_issue = SimpleNamespace(
        result_bytes=canonical({"authorization_id": "actual-B-authorization"})
    )
    lazy._projections["b"] = approval
    original = strict_object(approval.raw)["approval"]
    event = str(UUID(int=90))
    document = {
        "schema": "Gate0CollectionWithdrawal.v1",
        "binding": b.binding,
        "state": "applied",
        "observed_at": datetime.now(approval.approved_at.tzinfo).isoformat(),
        "withdrawal": {
            "request_id": b.binding["approval_request_id"],
            "withdrawal_id": event,
            "actor_id": str(UUID(int=91)),
            "authority_ref": "synthetic-human-authority",
            "approved_at": approval.approved_at.isoformat(),
            "effective_at": approval.approved_at.isoformat(),
            "external_ref": "synthetic-human-reference",
        },
        "relay": {
            "event_id": event,
            "payload_digest": digest(b"synthetic-relay-payload"),
            "event_type": "approval.withdrawn",
            "request_id": b.binding["approval_request_id"],
            "subject_type": original["subject_type"],
            "subject_id": original["subject_id"],
            "plan_id": b.binding["plan_id"],
            "withdrawal_ref": event,
            "disposition": "applied",
            "authorizations_revoked": ["actual-B-authorization"],
        },
    }
    changed = deepcopy(document)
    if swap == "reference":
        changed["withdrawal"]["external_ref"] = "another-human-reference"
    elif swap == "authorization":
        changed["relay"]["authorizations_revoked"] = ["other-authorization"]
    elif swap == "plan":
        changed["relay"]["plan_id"] = str(UUID(int=92))
    raw = canonical(changed)
    projection = WithdrawalProjection(
        raw, "pending_relay" if swap == "state" else "applied", event
    )
    if swap is None:
        assert lazy.observe_b_projection(projection) is True
        assert lazy._b_revocation is raw
    else:
        with pytest.raises((ServiceRefused, ProviderRefused)):
            lazy.observe_b_projection(projection)
        assert lazy._b_revocation is None
