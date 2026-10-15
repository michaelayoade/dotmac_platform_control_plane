"""Pure installation validation must precede any secret or database access."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vendor_cp.deployment.gate0_bootstrap import InstallationIdentity, PublicKeyPin
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


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
        "a_issue",
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
    selections = (
        attester.capture,
        replace(attester.capture, plan_id=UUID(int=4), approval_request_id=UUID(int=5)),
    )
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
        selections,
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
        (UUID(int=1), UUID(int=4)),
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
        "run_id": "synthetic-bootstrap-binding",
        "not_before": installation.identity.not_before.isoformat(),
        "expires_at": installation.identity.expires_at.isoformat(),
        "captures": {"a": selection, "b": dict(selection, plan_id=str(UUID(int=4)))},
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
            "run_id": "synthetic-two-hosts",
            "not_before": issuer.identity.not_before.isoformat(),
            "expires_at": issuer.identity.expires_at.isoformat(),
            "captures": {
                "a": selection,
                "b": dict(selection, plan_id=str(UUID(int=4))),
            },
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
