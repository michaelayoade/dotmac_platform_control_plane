"""Offline git/crypto proofs; DB projection is explicitly replaced, never SQLite."""

import hashlib
import subprocess
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from conformance_data import TestSigner, applied, desired

from vendor_cp.deploy_agent import contracts as c
from vendor_cp.deploy_agent.ledger import GitLedger
from vendor_cp.deploy_agent.service import DeployAgentService

ACTOR = UUID("00000000-0000-4000-8000-000000000010")


@pytest.fixture
def owner(tmp_path, monkeypatch):
    def git(*args):
        subprocess.run(  # noqa: S603 - fixed local git fixture
            ["/usr/bin/git", "-C", str(tmp_path), *args],
            check=True,
            capture_output=True,
        )

    git("init", "-b", "main")
    git("config", "user.name", "Offline test")
    git("config", "user.email", "offline@example.invalid")
    git("commit", "--allow-empty", "-m", "test root")
    projected = []

    def projection(_db, ledger):
        projected[:] = ledger.events()

    monkeypatch.setattr("vendor_cp.deploy_agent.service.rebuild", projection)
    ledger = GitLedger(tmp_path, remote=None)

    class FixtureReader:
        def verify(self, doc):
            assert all(
                doc[key] == desired()[key]
                for key in (
                    "image_digest",
                    "source_revision",
                    "source_tree",
                    "product_manifest_digest",
                    "build_run_id",
                    "evidence_run_id",
                )
            )

    service = DeployAgentService(
        ledger,
        TestSigner(),
        clock=lambda: datetime(2026, 10, 21, 10, tzinfo=UTC),
        candidate_reader=FixtureReader(),
    )
    return service, projected


def activate(owner, key=None):
    service, _ = owner
    host = key or TestSigner("test-host", seed=2)
    service.register(
        None,
        {
            "key_id": host.key_id,
            "deployment_ref": host.deployment_ref,
            "public_key_b64": host.public_key_b64,
        },
        actor_admin_id=ACTOR,
    )
    challenge = service.challenge(None, host.key_id, actor_admin_id=ACTOR)
    envelope = c.answer_challenge(challenge, host, desired()["from_image_digest"])
    fingerprint = "sha256:" + hashlib.sha256(c.unb64(host.public_key_b64)).hexdigest()
    service.activate(
        None,
        {"envelope": envelope, "approved_public_key_fingerprint": fingerprint},
        actor_admin_id=ACTOR,
    )
    return host


def issue(owner):
    service, _ = owner
    generated = {
        "schema",
        "nonce",
        "issued_at",
        "expires_at",
        "signer_key_id",
        "plan_digest",
    }
    unsigned = {key: value for key, value in desired().items() if key not in generated}
    request = {
        "command_id": "test-command",
        "desired": unsigned,
        "approved_plan_digest": desired()["plan_digest"],
    }
    envelope = service.issue(None, request, actor_admin_id=ACTOR)
    return (
        request,
        envelope,
        c.verify(c.DESIRED, envelope, service.signer.public_key_b64),
    )


def test_commit_before_serve_and_report_replay(owner):
    service, projection = owner
    host = activate(owner)
    request, envelope, doc = issue(owner)
    assert service.latest("dotmac_sub", "staging", "dotmac-sub-staging") == envelope
    assert service.issue(None, request, actor_admin_id=ACTOR) == envelope
    assert any(path.startswith("desired/") for path, _ in projection)
    report = c.seal(c.APPLIED, applied(doc), host)
    assert service.ingest(None, report) == {"verdict": "accepted"}
    assert service.ingest(None, report) == {"verdict": "idempotent_replay"}
    assert service.drift()["drift"] is False
    assert c.canonical_json(report) in [
        raw for _, raw in service.ledger.records("applied/")
    ]


def test_command_reuse_and_missing_baseline(owner):
    service, _ = owner
    with pytest.raises(c.ContractError, match="baseline_missing"):
        issue(owner)
    activate(owner)
    request, _, _ = issue(owner)
    request["desired"]["source_revision"] = "9" * 40
    with pytest.raises(c.ContractError, match="command_reused"):
        service.issue(None, request, actor_admin_id=ACTOR)


def test_key_swap_possession_binding_and_revocation(owner):
    service, _ = owner
    host = activate(owner)
    with pytest.raises(c.ContractError, match="key_reused"):
        service.register(
            None,
            {
                "key_id": "other-id",
                "deployment_ref": host.deployment_ref,
                "public_key_b64": host.public_key_b64,
            },
            actor_admin_id=ACTOR,
        )
    _, _, doc = issue(owner)
    service.register(
        None, {"operation": "revoke", "key_id": host.key_id}, actor_admin_id=ACTOR
    )
    with pytest.raises(c.ContractError, match="host_key_inactive"):
        service.ingest(None, c.seal(c.APPLIED, applied(doc), host))


def test_ingest_conflicts_and_unknown_desired_are_quarantined(owner):
    service, _ = owner
    host = activate(owner)
    unknown = c.seal(c.APPLIED, applied(), host)
    assert service.ingest(None, unknown)["verdict"] == "quarantined:desired_unknown"
    _, _, doc = issue(owner)
    payload = applied(doc)
    assert (
        service.ingest(None, c.seal(c.APPLIED, payload, host))["verdict"] == "accepted"
    )
    payload["deploy_receipt"]["receipt_line"] = "different bytes"
    assert (
        service.ingest(None, c.seal(c.APPLIED, payload, host))["verdict"]
        == "quarantined:report_reused"
    )
    payload["report_id"] = str(uuid4())
    assert (
        service.ingest(None, c.seal(c.APPLIED, payload, host))["verdict"]
        == "quarantined:nonce_replay"
    )


def test_observed_mismatch_never_advances_baseline(owner):
    service, _ = owner
    host = activate(owner)
    _, _, doc = issue(owner)
    payload = applied(doc)
    payload["observed"]["running_image"] = (
        "ghcr.io/michaelayoade/dotmac_sub@sha256:" + "9" * 64
    )
    verdict = service.ingest(None, c.seal(c.APPLIED, payload, host))
    assert verdict["verdict"] == "quarantined:observed_mismatch"
    assert service._baseline(host.deployment_ref) == desired()["from_image_digest"]


def test_ledger_refuses_dirty_tree_and_rewrite(owner):
    service, _ = owner
    with service.ledger.transaction():
        service.ledger.append("commands/first.json", {"test": True})
    with (
        service.ledger.transaction(),
        pytest.raises(c.ContractError, match="ledger_conflict"),
    ):
        service.ledger.append("commands/first.json", {"test": False})
    (service.ledger.root / "untracked").write_text("dirty")
    with (
        pytest.raises(c.ContractError, match="ledger_dirty"),
        service.ledger.transaction(),
    ):
        pass


def test_delayed_older_report_cannot_regress_latest_desired(owner):
    service, _ = owner
    host = activate(owner)
    request, _, first = issue(owner)
    request["command_id"] = "test-command-two"
    request["desired"]["image_digest"] = "sha256:" + "9" * 64
    request["approved_plan_digest"] = c.plan_digest({**first, **request["desired"]})

    class SecondCandidateReader:
        def verify(self, doc):
            assert doc["image_digest"] == "sha256:" + "9" * 64

    service.candidate_reader = SecondCandidateReader()
    second_envelope = service.issue(None, request, actor_admin_id=ACTOR)
    second = c.verify(c.DESIRED, second_envelope, service.signer.public_key_b64)
    report2 = applied(second)
    report2["report_id"] = str(uuid4())
    assert (
        service.ingest(None, c.seal(c.APPLIED, report2, host))["verdict"] == "accepted"
    )
    report1 = applied(first)
    assert (
        service.ingest(None, c.seal(c.APPLIED, report1, host))["verdict"] == "accepted"
    )
    assert service.drift()["applied"]["desired"]["nonce"] == second["nonce"]
    assert service.drift()["drift"] is False
    assert service._baseline(host.deployment_ref) == second["image_digest"]


def test_command_replay_is_bound_to_authenticated_principal(owner):
    service, _ = owner
    activate(owner)
    request, _, _ = issue(owner)
    with pytest.raises(c.ContractError, match="command_reused"):
        service.issue(
            None, request, actor_admin_id=UUID("00000000-0000-4000-8000-000000000011")
        )


def test_rebuild_refuses_signed_dishonest_success(owner):
    service, _ = owner
    host = activate(owner)
    _, _, doc = issue(owner)
    payload = applied(doc)
    payload["observed"]["running_image"] = "wrong"
    envelope = c.seal(c.APPLIED, payload, host)
    with service.ledger.transaction():
        service.ledger.append(
            f"applied/{host.deployment_ref}/{payload['report_id']}.json", envelope
        )
    with pytest.raises(c.ContractError, match="observed_mismatch"):
        service.validate_history()


def test_rebuild_refuses_key_identity_rebinding(owner):
    service, _ = owner
    host = activate(owner)
    key = dict(service._keys()[host.key_id])
    key["deployment_ref"] = "foreign/staging/host"
    with service.ledger.transaction():
        service.ledger.append("keys/test-host/rebinding.json", key)
    with pytest.raises(c.ContractError, match="ledger_identity"):
        service.validate_history()
