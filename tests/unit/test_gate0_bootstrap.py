"""Pure installation validation must precede any secret or database access."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from test_gate0_attester import proof_setup as _proof_setup
from test_gate0_management_delivery import captured as _captured
from test_gate0_runtime_providers import synthetic_http_only as _synthetic_http_only

from vendor_cp.deployment.gate0_bootstrap import InstallationIdentity, PublicKeyPin
from vendor_cp.deployment.gate0_role_custody import ProviderRefused

proof_setup = _proof_setup
captured = _captured
synthetic_http_only = _synthetic_http_only


def test_closed_public_key_pin_and_identity() -> None:
    pin = PublicKeyPin("synthetic", bytes(range(32)))
    pin.validate()
    now = datetime.now(UTC)
    identity = InstallationIdentity(
        "sha256:" + "1" * 64,
        "a" * 40,
        "sha256:" + "2" * 64,
        "sha256:" + "3" * 64,
        now - timedelta(seconds=1),
        now + timedelta(seconds=90),
    )
    identity.validate()
    for changed in (
        replace(pin, public_key=b""),
        replace(pin, key_id=""),
        replace(pin, public_key=bytearray(32)),
    ):
        with pytest.raises(ProviderRefused):
            changed.validate()
    for changed in (
        replace(identity, expires_at=now + timedelta(seconds=301)),
        replace(identity, not_before=now + timedelta(seconds=1)),
        replace(identity, source_revision="main"),
        replace(identity, packet_digest="unqualified"),
    ):
        with pytest.raises(ProviderRefused):
            changed.validate()


def synthetic_attester():
    from uuid import UUID

    from vendor_cp.deployment.gate0_bootstrap import (
        ActualAttesterInstallation,
        CustodyInstallation,
    )
    from vendor_cp.deployment.gate0_management_delivery import CaptureSelection
    from vendor_cp.deployment.gate0_role_custody import WireGuardBaoEndpoint

    now = datetime.now(UTC)
    digest = "sha256:" + "1" * 64
    identity = InstallationIdentity(
        digest,
        "a" * 40,
        digest,
        digest,
        now - timedelta(seconds=1),
        now + timedelta(seconds=90),
    )
    endpoint = WireGuardBaoEndpoint(
        "attester",
        "10.1.0.1",
        8200,
        "10.1.0.2",
        "wg0",
        1,
        1,
        1,
        digest,
        "10.1.0.1/32",
        digest,
        digest,
        digest,
    )
    custody = CustodyInstallation(
        "synthetic-role",
        PublicKeyPin("synthetic-attester", bytes(range(32))),
        1,
        1,
        endpoint,
    )
    return ActualAttesterInstallation(
        identity,
        custody,
        PublicKeyPin("synthetic-issuer", bytes(range(32))),
        bytes(range(32)),
        CaptureSelection(digest, UUID(int=1), digest, UUID(int=2), UUID(int=3)),
        "issue",
        "issue",
        1001,
    )


def test_protected_attester_document_closed_roundtrip(monkeypatch):
    from copy import deepcopy

    import vendor_cp.deployment.gate0_bootstrap as module

    installation = synthetic_attester()
    document = installation.document()
    monkeypatch.setattr(module, "_installed_document", lambda context: document)
    assert module.load_attester_installation(None) == installation
    for mutate in (
        lambda doc: doc.update(authenticated=True),
        lambda doc: doc.update(ca_public_key=doc["ca_public_key_b64"]),
        lambda doc: doc.update(ca_public_key=doc.pop("ca_public_key_b64")),
        lambda doc: doc["custody"].update(profile="unlimited"),
        lambda doc: doc["custody"]["endpoint"].update(url="https://caller.invalid"),
        lambda doc: doc.update(phase="standing"),
        lambda doc: doc.update(worker_uid=True),
        lambda doc: doc["identity"].update(deadline=123),
        lambda doc: doc["capture"].update(capture_digest="sha256:" + "1" * 64),
    ):
        bad = deepcopy(document)
        mutate(bad)
        monkeypatch.setattr(module, "_installed_document", lambda context, bad=bad: bad)
        with pytest.raises((ValueError, TypeError)):
            module.load_attester_installation(None)


def test_invalid_installation_refuses_before_secret_capture_or_database(monkeypatch):
    import vendor_cp.deployment.gate0_bootstrap as module

    called = []
    monkeypatch.setattr(
        module, "_installation", lambda *args: called.append("installation")
    )
    monkeypatch.setattr(module, "_custody", lambda *args: called.append("secret"))
    monkeypatch.setattr(
        module, "qualify_authority_database", lambda *args: called.append("db")
    )
    bad = replace(synthetic_attester(), worker_uid=0)
    with pytest.raises(ProviderRefused), module.prepare_installed_attester(None, bad):
        raise AssertionError("invalid input yielded")
    assert called == []


def test_context_construction_never_accepts_json_qualification():
    from vendor_cp.deployment.gate0_launch import InstalledLaunchContext

    with pytest.raises(ProviderRefused):
        InstalledLaunchContext(role="issuer", qualified=True)


def synthetic_issuer():
    from uuid import UUID

    from vendor_cp.deployment.gate0_bootstrap import ActualIssuerInstallation
    from vendor_cp.deployment.gate0_database import DatabaseExpectation
    from vendor_cp.deployment.gate0_management_delivery import (
        ManagementDeliveryInstallation,
    )

    attester = synthetic_attester()
    identity = attester.identity
    digest = identity.packet_digest
    selection = attester.capture
    management = ManagementDeliveryInstallation(
        digest,
        identity.not_before,
        identity.expires_at,
        "10.1.0.1",
        "10.1.0.2",
        22,
        1002,
        "synthetic",
        "SHA256:" + "A" * 43,
        "ssh-ed25519",
        "SHA256:" + "B" * 43,
        digest,
        digest,
        digest,
        selection,
    )
    database = DatabaseExpectation(
        "synthetic",
        "platform_api",
        "10.1.0.3",
        5432,
        True,
        ("public",),
        ("synthetic_head",),
        ("synthetic_head",),
        identity.source_revision,
        identity.source_revision,
        1000,
        500,
    )
    custody = replace(
        attester.custody,
        key=attester.issuer_key,
        endpoint=replace(attester.custody.endpoint, role="issuer"),
    )
    return ActualIssuerInstallation(
        identity,
        custody,
        database,
        attester.capture.target_id,
        UUID(int=1),
        attester.custody.key,
        60,
        "synthetic-admin",
        management,
    )


@pytest.mark.parametrize("role", ["issuer", "attester"])
@pytest.mark.parametrize(
    "mismatch",
    [
        "source",
        "image",
        "own-key-id",
        "own-key-bytes",
        "peer-key-id",
        "peer-key-bytes",
        "profile",
    ],
)
def test_shared_role_mismatch_refuses_before_database_capture_or_custody(
    role, mismatch, monkeypatch
):
    import base64
    import hashlib
    from uuid import UUID

    import vendor_cp.deployment.gate0_bootstrap as bootstrap
    import vendor_cp.deployment.gate0_launch as launch
    from vendor_cp.deployment.gate0_framing import canonical

    installation = synthetic_issuer() if role == "issuer" else synthetic_attester()
    peer = installation.attester_key if role == "issuer" else installation.issuer_key
    profile = canonical({"source_revision": installation.identity.source_revision})
    role_terms = {
        "key_id": installation.custody.key.key_id,
        "public_key_b64": base64.b64encode(installation.custody.key.public_key).decode(
            "ascii"
        ),
        "source_revision": installation.identity.source_revision,
        "image_digest": installation.identity.image_digest,
        "profile_digest": "sha256:" + hashlib.sha256(profile).hexdigest(),
    }
    peer_terms = dict(
        role_terms,
        key_id=peer.key_id,
        public_key_b64=base64.b64encode(peer.public_key).decode("ascii"),
    )
    terms = {role: role_terms, "attester" if role == "issuer" else "issuer": peer_terms}
    if mismatch == "source":
        role_terms["source_revision"] = "b" * 40
    elif mismatch == "image":
        role_terms["image_digest"] = "sha256:" + "b" * 64
    elif mismatch == "own-key-id":
        role_terms["key_id"] = "other-own-key"
    elif mismatch == "own-key-bytes":
        role_terms["public_key_b64"] = base64.b64encode(bytes(32)).decode("ascii")
    elif mismatch == "peer-key-id":
        peer_terms["key_id"] = "other-peer-key"
    elif mismatch == "peer-key-bytes":
        peer_terms["public_key_b64"] = base64.b64encode(bytes(32)).decode("ascii")
    elif mismatch == "profile":
        profile = canonical(
            {
                "source_revision": installation.identity.source_revision,
                "changed-build-profile": True,
            }
        )
    selection = {
        "window_digest": "sha256:" + "a" * 64,
        "plan_id": str(UUID(int=1)),
        "plan_digest": "sha256:" + "b" * 64,
        "target_id": str(UUID(int=2)),
        "approval_request_id": str(UUID(int=3)),
    }
    fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode("ascii").rstrip("=")
    run_document = {
        "schema": "Gate0RunIdentity.v1",
        "run_id": "2",
        "run_attempt": "1",
        "case_kind": "consume_replay",
        "not_before": installation.identity.not_before.isoformat(),
        "expires_at": installation.identity.expires_at.isoformat(),
        "capture": selection,
        "roles": terms,
        "controller_ca_fingerprint": fingerprint,
        "management_key_fingerprint": fingerprint,
    }
    run = canonical(run_document)
    shared = "sha256:" + hashlib.sha256(run).hexdigest()
    installation = replace(
        installation,
        identity=replace(installation.identity, packet_digest=shared),
        custody=replace(
            installation.custody,
            endpoint=replace(
                installation.custody.endpoint, launch_packet_digest=shared
            ),
        ),
    )
    if role == "issuer":
        installation = replace(
            installation,
            management_delivery=replace(
                installation.management_delivery, launch_packet_digest=shared
            ),
        )
    context = object.__new__(launch.InstalledLaunchContext)
    for field, value in {
        "role": role,
        "packet_digest": shared,
        "expires_at": installation.identity.expires_at,
        "local_packet_digest": "sha256:" + "c" * 64,
    }.items():
        object.__setattr__(context, field, value)
    # Only native file/process provenance is synthetic. The actual shared-run
    # parser, actual role-term comparator and both preparation paths execute.
    monkeypatch.setattr(bootstrap, "_installation", lambda *args: None)
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_capture_selection", lambda *args: None
    )
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_installation", lambda *args: None
    )
    monkeypatch.setattr(
        launch,
        "_read",
        lambda path, *args: run if path.name == "run-packet.json" else profile,
    )
    touched = []
    monkeypatch.setattr(
        bootstrap,
        "qualify_authority_database",
        lambda *args: touched.append("database"),
    )
    monkeypatch.setattr(bootstrap, "_custody", lambda *args: touched.append("custody"))
    monkeypatch.setattr(
        launch.InstalledLaunchContext,
        "capture_coordinates",
        lambda *args: touched.append("capture"),
    )
    prepare = (
        bootstrap.prepare_installed_issuer
        if role == "issuer"
        else bootstrap.prepare_installed_attester
    )
    with pytest.raises(ProviderRefused), prepare(context, installation):
        raise AssertionError("mismatched shared run yielded")
    assert touched == []


def test_shared_role_terms_accept_both_hosts_with_distinct_local_packets(monkeypatch):
    import base64
    import hashlib
    from uuid import UUID

    import vendor_cp.deployment.gate0_launch as launch
    from vendor_cp.deployment.gate0_framing import canonical

    issuer, attester = synthetic_issuer(), synthetic_attester()
    profile = canonical({"source_revision": issuer.identity.source_revision})
    roles = {}
    for role, installation in (("issuer", issuer), ("attester", attester)):
        roles[role] = {
            "key_id": installation.custody.key.key_id,
            "public_key_b64": base64.b64encode(
                installation.custody.key.public_key
            ).decode("ascii"),
            "source_revision": installation.identity.source_revision,
            "image_digest": installation.identity.image_digest,
            "profile_digest": "sha256:" + hashlib.sha256(profile).hexdigest(),
        }
    selection = {
        "window_digest": "sha256:" + "a" * 64,
        "plan_id": str(UUID(int=1)),
        "plan_digest": "sha256:" + "b" * 64,
        "target_id": str(UUID(int=2)),
        "approval_request_id": str(UUID(int=3)),
    }
    fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode("ascii").rstrip("=")
    run = canonical(
        {
            "schema": "Gate0RunIdentity.v1",
            "run_id": "2",
            "run_attempt": "1",
            "case_kind": "consume_replay",
            "not_before": issuer.identity.not_before.isoformat(),
            "expires_at": issuer.identity.expires_at.isoformat(),
            "capture": selection,
            "roles": roles,
            "controller_ca_fingerprint": fingerprint,
            "management_key_fingerprint": fingerprint,
        }
    )
    shared = "sha256:" + hashlib.sha256(run).hexdigest()
    monkeypatch.setattr(
        launch,
        "_read",
        lambda path, *args: run if path.name == "run-packet.json" else profile,
    )
    checked = []

    # Native local provenance is deliberately synthetic; each actual common
    # comparator still sees one shared run and its actual parsed public terms.
    def installed(context, role, digest, end):
        assert digest == shared
        checked.append((role, context.local_packet_digest))

    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_installation", installed
    )
    for role, installation, peer, local in (
        ("issuer", issuer, issuer.attester_key, "c"),
        ("attester", attester, attester.issuer_key, "d"),
    ):
        context = object.__new__(launch.InstalledLaunchContext)
        for field, value in {
            "role": role,
            "packet_digest": shared,
            "expires_at": issuer.identity.expires_at,
            "local_packet_digest": "sha256:" + local * 64,
        }.items():
            object.__setattr__(context, field, value)
        context.require_run_role_terms(
            role=role,
            source_revision=installation.identity.source_revision,
            image_digest=installation.identity.image_digest,
            own_key_id=installation.custody.key.key_id,
            own_public_key=installation.custody.key.public_key,
            peer_key_id=peer.key_id,
            peer_public_key=peer.public_key,
        )
    assert checked == [
        ("issuer", "sha256:" + "c" * 64),
        ("attester", "sha256:" + "d" * 64),
    ]


def test_issuer_selection_mismatch_refuses_before_database_or_custody(monkeypatch):
    from types import SimpleNamespace
    from uuid import UUID

    import vendor_cp.deployment.gate0_bootstrap as bootstrap
    import vendor_cp.deployment.gate0_launch as launch
    from vendor_cp.deployment.gate0_management_delivery import selection_document

    installation = synthetic_issuer()
    context = object.__new__(launch.InstalledLaunchContext)
    for key, value in {
        "packet_digest": installation.identity.packet_digest,
        "expires_at": installation.identity.expires_at,
    }.items():
        object.__setattr__(context, key, value)
    selection = selection_document(installation.management_delivery.capture)
    wrong = dict(selection, plan_id=str(UUID(int=99)))
    end = installation.identity.expires_at.isoformat()
    monkeypatch.setattr(bootstrap, "_installation", lambda *args: None)
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_open", lambda self: None
    )
    monkeypatch.setattr(
        launch,
        "_load_local_packet",
        lambda: {
            "shared_run_digest": context.packet_digest,
            "capture": wrong,
            "run_end": end,
        },
    )
    monkeypatch.setattr(
        launch.RunIdentity,
        "from_installed",
        lambda: SimpleNamespace(
            digest=context.packet_digest, canonical_bytes=b"synthetic-common"
        ),
    )
    monkeypatch.setattr(
        launch, "_run_document", lambda raw: {"capture": wrong, "expires_at": end}
    )
    touched = []
    monkeypatch.setattr(
        bootstrap,
        "qualify_authority_database",
        lambda *args: touched.append("database"),
    )
    monkeypatch.setattr(bootstrap, "_custody", lambda *args: touched.append("custody"))
    with (
        pytest.raises(ProviderRefused),
        bootstrap.prepare_installed_issuer(context, installation),
    ):
        raise AssertionError("foreign selection yielded")
    assert touched == []


def test_installed_raw_ca_composes_with_actual_session_and_producer(
    tmp_path, monkeypatch, proof_setup, captured, synthetic_http_only
):
    import os
    import time
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from test_gate0_runtime_providers import (
        _SYNTHETIC_TRANSPORTS,
        SyntheticBao,
    )
    from test_gate0_session_observation import SyntheticExchange

    import vendor_cp.deployment.gate0_bootstrap as bootstrap
    from vendor_cp.deployment.gate0_management_delivery import CaptureSelection
    from vendor_cp.deployment.gate0_role_custody import (
        BoundedJSONTransport,
        CustodyProfile,
        RoleCustody,
    )
    from vendor_cp.deployment.gate0_workload_admission import ApprovedAtStartAdmission

    setup = proof_setup
    _, _, capture, _ = captured
    coordinates = capture.coordinates
    fake = SyntheticBao("attester", bytes(range(32)))
    installation = synthetic_attester()
    started_at, monotonic_origin = datetime.now(UTC), time.monotonic()
    launch_deadline = (
        monotonic_origin
        + (installation.identity.expires_at - started_at).total_seconds()
    )
    _SYNTHETIC_TRANSPORTS["https://synthetic-bao.invalid"] = fake
    provider = RoleCustody(
        role="attester",
        role_id="synthetic-role-id",
        key_id="synthetic-key",
        public_key=fake.public,
        minimum_versions={"issuer": 7, "attester": 7},
        transport=BoundedJSONTransport("https://synthetic-bao.invalid"),
        seed_format="a4-provisional-private-key-b64url",
        expires_at=installation.identity.expires_at,
        profile=CustodyProfile.ATTESTER_FINITE_V1,
        launch_deadline=launch_deadline,
    )
    material = provider.bootstrap("synthetic-wrap")
    raw_ca = setup["ca"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    installation = replace(
        installation,
        ca_public_key=raw_ca,
        issuer_key=PublicKeyPin("synthetic-key", fake.public),
        custody=replace(
            installation.custody, key=PublicKeyPin("synthetic-key", fake.public)
        ),
        capture=CaptureSelection(
            coordinates.window_digest,
            coordinates.plan_id,
            coordinates.plan_digest,
            coordinates.target_id,
            coordinates.approval_request_id,
        ),
    )
    capture_path = tmp_path / "capture.json"
    capture_path.write_bytes(capture.encoded)
    context = SimpleNamespace(
        slot_id="issue",
        worker_uid=installation.worker_uid,
        required_phase="issue",
        started_at=started_at,
        monotonic_origin=monotonic_origin,
        deadline=launch_deadline,
        require_run_role_terms=lambda **kwargs: None,
        capture_coordinates=lambda: coordinates,
        require_capture_slot=lambda *args: None,
        open_authenticated_capture=lambda *args: os.open(capture_path, os.O_RDONLY),
        open_auth_info_directory=lambda: os.open(tmp_path, os.O_RDONLY),
        require_open=lambda: None,
    )
    # Native provenance/custody acquisition and workload admission are independent
    # boundaries. Keep the actual capture decoder, installed adapter, assembly,
    # bounded RoleCustody material, AttesterSession and AttesterProofProducer.
    monkeypatch.setattr(bootstrap, "_installation", lambda *args: None)
    monkeypatch.setattr(bootstrap, "_custody", lambda *args: (provider, material))
    monkeypatch.setattr(
        ApprovedAtStartAdmission,
        "admit",
        lambda *args: SimpleNamespace(
            operation=setup["operation"], authentication_freshness=None
        ),
    )
    monkeypatch.setattr(
        ApprovedAtStartAdmission,
        "window_record_digest",
        lambda *args: coordinates.window_digest,
    )
    assert len(installation.ca_public_key) == 32
    before = installation.document()
    exchange = SyntheticExchange(setup)
    with bootstrap.prepare_installed_attester(context, installation) as prepared:
        session = replace(prepared.session, now=lambda: setup["now"])
        assert session.ca_public_key.startswith(b"ssh-ed25519 ")
        session.run(exchange, setup["cert"])
        assert session.completion is not None
        assert len(exchange.output) == 2
        assert provider.profile is CustodyProfile.ATTESTER_FINITE_V1
        assert provider.deadline <= launch_deadline
        assert provider._phases == 2  # Actual challenge and complete refreshes.
        assert provider._token_attempts == provider.profile.token_limit == 8
        assert provider._http_attempts == provider.profile.http_limit == 11
    assert installation.document() == before
    assert len([path for path in fake.paths if path.endswith("/signing-key")]) == 1
    with pytest.raises(ProviderRefused):
        material.attester_sign(b"closed-synthetic-provider")
