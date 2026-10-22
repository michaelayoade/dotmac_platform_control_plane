"""Offline crypto/Git evidence admission; never PostgreSQL or live proof acceptance."""

import copy
import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from conformance_data import TestSigner, applied, desired
from dotmac_kernel.config import settings
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_service import ACTOR, activate
from test_service import owner as shared_owner

from vendor_cp.deploy_agent import contracts as c
from vendor_cp.deploy_agent import gate_admission as a
from vendor_cp.deploy_agent import gate_evidence as g
from vendor_cp.deploy_agent import router as api

owner = shared_owner
D = "sha256:" + "1" * 64


def observation(doc, *, before=False, count=1):
    report = applied(doc)
    report["health"]["background"]["containers"]["celery-worker"] = "running"
    if before:
        for field in ("running_image", "pinned_image"):
            report["observed"][field] = (
                doc["image_reference"] + "@" + doc["from_image_digest"]
            )
    return {
        "observed_at": "2026-10-21T10:01:00Z" if before else "2026-10-21T10:02:00Z",
        "observed": report["observed"],
        "health": report["health"],
        "executor_count": count,
    }


@pytest.fixture
def admitted(owner):
    service, _ = owner
    host = activate(owner)
    references = []
    for number, reason in enumerate(("bad_signature", "rollback_digest", None), 1):
        doc = desired()
        doc["issued_at"] = "2026-10-21T10:01:00Z"
        doc["nonce"] = c.b64(bytes([number]) * 24)
        envelope = c.seal(c.DESIRED, doc, service.signer)
        service._record(
            None, {f"desired/{service.deployment_ref}/{doc['nonce']}.json": envelope}
        )
        report = applied(doc)
        report["report_id"] = str(uuid4())
        report["health"]["background"]["containers"]["celery-worker"] = "running"
        if reason:
            report.update(disposition="refused", reason=reason)
            report["observed"] = observation(doc, before=True)["observed"]
        signed = c.seal(c.APPLIED, report, host)
        assert service.ingest(None, signed) == {"verdict": "accepted"}
        references.append((doc, envelope, report, signed))
    commit = service.ledger.git("rev-parse", "HEAD").decode().strip()
    doc, envelope, report, signed = references[-1]
    path = f"applied/{service.deployment_ref}/{report['report_id']}.json"
    transition = {
        "source_preparation_sha256": D,
        "nonce": doc["nonce"],
        "desired_sha256": c.digest(envelope),
        "report_id": report["report_id"],
        "report_sha256": c.digest(signed),
        "receipt_sha256": c.digest(
            {
                "deployment_ref": service.deployment_ref,
                "report_id": report["report_id"],
                "path": path,
                "fingerprint": c.digest(signed),
            }
        ),
        "ledger_commit": commit,
        "before": observation(doc, before=True, count=0),
        "after": observation(doc),
        "signatures_verified": True,
        "runners_stopped": True,
    }
    refusals = []
    for index, code in (
        (0, "bad_signature"),
        (2, "nonce_replay"),
        (1, "rollback_digest"),
    ):
        item, original, terminal, receipt = references[index]
        submitted = copy.deepcopy(original)
        if code == "bad_signature":
            signature = bytearray(c.unb64(submitted["signature_b64"]))
            signature[0] ^= 1
            submitted["signature_b64"] = c.b64(signature)
        same = observation(item, before=code != "nonce_replay")
        refusals.append(
            {
                "case": code,
                "submitted_sha256": c.digest(submitted),
                "nonce": item["nonce"],
                "report_id": terminal["report_id"],
                "report_sha256": c.digest(receipt),
                "classification": "accepted",
                "expected_code": code,
                "observed_code": code,
                "journal_start": "cursor1",
                "journal_end": "cursor2",
                "normal_poll_journal_start": "normal1",
                "normal_poll_journal_end": "normal2",
                "cleanup_observed_at": "2026-10-21T10:03:00Z",
                "ledger_commit": commit,
                "before": same,
                "after": copy.deepcopy(same),
            }
        )
    oidc = {
        "main_run_id": 10,
        "negative_run_id": 11,
        "main_sha256": D,
        "negative_sha256": D,
        "main_accepted": True,
        "negative_refused": True,
    }
    egress = {
        "hostname": "registry.example.invalid",
        "started_at": "2026-10-21T10:00:00Z",
        "finished_at": "2026-10-21T10:10:00Z",
        "transition_report_id": report["report_id"],
        "transition_report_sha256": c.digest(signed),
        "probe_rule_handle": 1,
        "probe_source_port": 12345,
        "probe_rule_removed": True,
        "before": [
            {
                "family": "A",
                "address": "192.0.2.1",
                "ttl": 60,
                "kernel_timeout_ms": 60000,
                "kernel_expires_ms": 59000,
            },
            {
                "family": "AAAA",
                "address": "2001:db8::1",
                "ttl": 60,
                "kernel_timeout_ms": 60000,
                "kernel_expires_ms": 59000,
            },
        ],
        "after": [
            {
                "family": "A",
                "address": "192.0.2.2",
                "ttl": 60,
                "kernel_timeout_ms": 60000,
                "kernel_expires_ms": 59000,
            },
            {
                "family": "AAAA",
                "address": "2001:db8::2",
                "ttl": 60,
                "kernel_timeout_ms": 60000,
                "kernel_expires_ms": 59000,
            },
        ],
        "elapsed_seconds": 600,
        "old_expiry_observed_at": "2026-10-21T10:01:02Z",
        "kernel_rules_sha256": D,
        "terminal_drop": True,
        "counter_before": 0,
        "counter_after": 1,
        "disallowed_address": "198.51.100.1",
        "disallowed_port": 443,
        "fresh_connection_failed": True,
        "allowed_deployment_succeeded": True,
    }
    restore = {
        "source_identity": "staging",
        "test_host_identity": "restore-test",
        "bundle_sha256": D,
        "capture_sha256": D,
        "capture_started_at": "2026-10-21T09:30:00Z",
        "capture_finished_at": "2026-10-21T09:40:00Z",
        "source_inventory_sha256": D,
        "restored_inventory_sha256": D,
        "no_ddl_enforced": True,
        "source_parity": True,
        "scratch_absent": True,
    }
    proofs = [
        {
            "proof": number,
            "outcome": "pass",
            "failure_code": "none",
            "cleanup": "pass",
            "oidc": oidc if number == 1 else None,
            "refusals": refusals if number == 2 else [],
            "transition": copy.deepcopy(transition) if number in (3, 4) else None,
            "egress": egress if number == 4 else None,
            "restore": restore if number == 5 else None,
        }
        for number in range(1, 6)
    ]
    request = {
        "command_id": str(uuid4()),
        "run_id": str(uuid4()),
        "phase": "initial",
        "prior_run_id": None,
        "source_revision": "d" * 40,
        "source_tree": "e" * 40,
        "tool_revision": "f" * 40,
        "deployment_ref": service.deployment_ref,
        "host_key_id": host.key_id,
        "action_refs": ["campaign-approved"],
        "deadline": "2026-10-21T14:00:00Z",
        "proofs": proofs,
    }
    scope = {
        "context": {
            key: value
            for key, value in request.items()
            if key not in ("command_id", "proofs")
        },
        "actor_admin_ids": [str(ACTOR)],
        "host_public_key_sha256": g.raw_digest(c.unb64(host.public_key_b64)),
        "candidates": [c.plan_document(item[0]) for item in references],
        "restore_source_identity": "staging",
        "restore_test_host_identity": "restore-test",
        "oidc_main_run_id": 10,
        "oidc_negative_run_id": 11,
        "oidc_main_sha256": D,
        "oidc_negative_sha256": D,
        "restore_bundle_sha256": D,
        "restore_capture_sha256": D,
        "restore_inventory_sha256": D,
        "observation_not_before": "2026-10-21T09:00:00Z",
        "prior_evidence_sha256": None,
        "source_preparation_sha256": D,
        "egress_hostname": "registry.example.invalid",
        "egress_disallowed_address": "198.51.100.1",
        "egress_disallowed_port": 443,
    }
    service.gate_scope = a.scope_bytes(scope)
    return service, request, scope


def test_gate_published_replay_keeps_original_commit_and_actor(admitted):
    service, request, _ = admitted
    receipt = a.admit(service, None, request, actor_admin_id=ACTOR)
    assert receipt["evidence"] == request and receipt["evidence_sha256"] == c.digest(
        request
    )
    record = c.read_json(service.ledger.read(a.command_path(request)))
    assert record["actor_admin_id"] == str(ACTOR)
    service._record(None, {"commands/unrelated.json": {"actor_admin_id": str(ACTOR)}})
    service.clock = lambda: datetime(2026, 10, 22, tzinfo=UTC)
    assert a.admit(service, None, request, actor_admin_id=ACTOR) == receipt
    changed = copy.deepcopy(request)
    changed["proofs"][0]["oidc"]["main_sha256"] = "sha256:" + "2" * 64
    with pytest.raises(c.ContractError, match="command_reused"):
        a.admit(service, None, changed, actor_admin_id=ACTOR)
    changed = copy.deepcopy(request)
    changed["command_id"] = str(uuid4())
    with pytest.raises(c.ContractError, match="run_reused"):
        a.admit(service, None, changed, actor_admin_id=ACTOR)


def test_gate_negative_bindings_do_not_publish(admitted):
    service, request, _ = admitted
    mutations = [
        (lambda r: r.update(actor_admin_id=str(ACTOR)), "schema_violation"),
        (lambda r: r.update(source_tree="0" * 40), "campaign_scope"),
        (
            lambda r: r["proofs"][1]["refusals"][0].update(report_sha256=D),
            "evidence_substitution",
        ),
        (
            lambda r: r["proofs"][1]["refusals"][0].update(submitted_sha256=D),
            "submitted_mismatch",
        ),
        (
            lambda r: r["proofs"][2]["transition"].update(receipt_sha256=D),
            "receipt_mismatch",
        ),
        (
            lambda r: r["proofs"][1]["refusals"][0].update(
                classification="quarantined"
            ),
            "evidence_missing",
        ),
        (lambda r: r["proofs"].pop(), "proof_set"),
        (lambda r: r["proofs"][3]["egress"].update(counter_after=0), "proof_failed"),
        (
            lambda r: r["proofs"][4]["restore"].update(scratch_absent=False),
            "proof_failed",
        ),
    ]
    for mutate, code in mutations:
        changed = copy.deepcopy(request)
        mutate(changed)
        with pytest.raises(c.ContractError, match=code):
            a.admit(service, None, changed, actor_admin_id=ACTOR)
        assert service.ledger.read(a.evidence_path(request)) is None
    with pytest.raises(c.ContractError, match="campaign_actor"):
        a.admit(service, None, request, actor_admin_id=uuid4())


def test_gate_http_has_one_kernel_admin_owner_and_no_payload_actor(
    admitted, monkeypatch
):
    service, request, _ = admitted
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.get_platform_db] = lambda: None
    monkeypatch.setattr(api, "service", lambda: service)
    client = TestClient(app, base_url=f"http://{settings.platform_root_domain}")
    assert client.post("/platform/deploy/gate-evidence", json=request).status_code in (
        401,
        403,
    )
    app.dependency_overrides[api.require_platform_admin] = lambda: SimpleNamespace(
        id=ACTOR
    )
    bad = {**request, "actor_admin_id": str(ACTOR)}
    assert client.post("/platform/deploy/gate-evidence", json=bad).status_code == 409
    assert (
        client.post("/platform/deploy/gate-evidence", json=request).status_code == 200
    )


def test_gate_push_failure_and_append_only_history_hold(admitted, tmp_path_factory):
    service, request, _ = admitted
    remote = tmp_path_factory.mktemp("gate-remote.git")
    subprocess.run(  # noqa: S603 - fixed local Git fixture executable
        ["/usr/bin/git", "-C", str(remote), "init", "--bare", "-b", "main"],
        check=True,
        capture_output=True,
    )
    service.ledger.git("remote", "add", "origin", str(remote))
    service.ledger.git("push", "--set-upstream", "origin", "main")
    service.ledger.remote = "origin"
    hook = remote / "hooks/pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o700)
    with pytest.raises(c.ContractError, match="ledger_unavailable"):
        a.admit(service, None, request, actor_admin_id=ACTOR)
    with pytest.raises(c.ContractError, match="ledger_conflict"):
        a.admit(service, None, request, actor_admin_id=ACTOR)
    service.ledger.remote = None
    path = service.ledger.root / a.evidence_path(request)
    path.write_text("{}")
    service.ledger.git("add", "--", a.evidence_path(request))
    service.ledger.git("commit", "-m", "fixture illegal mutation")
    with pytest.raises(c.ContractError, match="ledger_rewritten"):
        with service.ledger.transaction():
            pass


def test_gate_enrollment_candidates_and_immutable_scope(admitted, tmp_path_factory):
    service, request, scope = admitted
    frozen = a.scope_bytes(scope)
    scope["context"]["tool_revision"] = "0" * 40
    assert c.read_json(frozen)["context"]["tool_revision"] == "f" * 40
    config_dir = tmp_path_factory.mktemp("gate-scope")
    path = config_dir / "scope.json"
    path.write_bytes(frozen)
    with pytest.raises(c.ContractError, match="campaign_permissions"):
        a.load_scope(str(path))
    link = config_dir / "scope-link.json"
    link.symlink_to(path)
    with pytest.raises(c.ContractError, match="campaign_permissions"):
        a.load_scope(str(link))
    for field in ("host_public_key_sha256", "candidates"):
        changed = c.read_json(frozen)
        if field == "candidates":
            for plan in changed[field]:
                plan["image_digest"] = D
        else:
            changed[field] = D
        service.gate_scope = a.scope_bytes(changed)
        with pytest.raises(c.ContractError, match="candidate_scope|host_key_mismatch"):
            a.admit(service, None, request, actor_admin_id=ACTOR)
    service.gate_scope = frozen
    service.register(
        None,
        {"operation": "revoke", "key_id": request["host_key_id"]},
        actor_admin_id=ACTOR,
    )
    with pytest.raises(c.ContractError, match="host_key_inactive"):
        a.admit(service, None, request, actor_admin_id=ACTOR)


def test_gate_history_verifies_quarantined_signature(admitted):
    service, request, _ = admitted
    ref = request["proofs"][2]["transition"]
    raw = service.ledger.read(
        f"applied/{service.deployment_ref}/{ref['report_id']}.json"
    )
    envelope = c.read_json(raw)
    signature = bytearray(c.unb64(envelope["signature_b64"]))
    signature[0] ^= 1
    envelope["signature_b64"] = c.b64(signature)
    with service.ledger.transaction():
        service.ledger.append(
            f"quarantine/{c.digest(envelope)[7:]}.json",
            {"code": "nonce_replay", "envelope": envelope},
        )
    with pytest.raises(c.ContractError, match="bad_signature"):
        a.admit(service, None, request, actor_admin_id=ACTOR)


def test_gate_terminal_fail_is_durable_without_fabricating_unperformed_proofs(admitted):
    service, request, _ = admitted
    failed = copy.deepcopy(request)
    proof = failed["proofs"][1]
    proof.update(
        outcome="fail", failure_code="evidence_missing", cleanup="fail", refusals=[]
    )
    failed["proofs"] = [proof]
    wrong_stage = copy.deepcopy(failed)
    wrong_stage["proofs"][0]["failure_code"] = "cleanup_failed"
    with pytest.raises(c.ContractError, match="schema_violation"):
        a.admit(service, None, wrong_stage, actor_admin_id=ACTOR)
    smuggled = copy.deepcopy(failed)
    smuggled["proofs"][0]["refusals"] = [
        copy.deepcopy(request["proofs"][1]["refusals"][0])
    ]
    smuggled["proofs"][0]["refusals"][0]["report_sha256"] = D
    with pytest.raises(c.ContractError, match="evidence_substitution"):
        a.admit(service, None, smuggled, actor_admin_id=ACTOR)
    receipt = a.admit(service, None, failed, actor_admin_id=ACTOR)
    assert receipt["published"] and receipt["verdict"] == "FAIL"
    assert receipt["evidence"]["proofs"] == [proof]
    assert a.admit(service, None, failed, actor_admin_id=ACTOR) == receipt
    with pytest.raises(c.ContractError, match="command_reused"):
        a.admit(service, None, request, actor_admin_id=ACTOR)


def test_signed_history_cannot_be_relabelled_as_a_new_campaign(admitted):
    service, request, scope = admitted

    def next_day(value):
        if isinstance(value, dict):
            return {key: next_day(item) for key, item in value.items()}
        if isinstance(value, list):
            return [next_day(item) for item in value]
        return (
            value.replace("2026-10-21T", "2026-10-22T")
            if isinstance(value, str)
            else value
        )

    moved = next_day(request)
    moved_scope = next_day(scope)
    service.gate_scope = a.scope_bytes(moved_scope)
    service.clock = lambda: datetime(2026, 10, 22, 10, tzinfo=UTC)
    with pytest.raises(c.ContractError, match="signed_observation_interval"):
        a.admit(service, None, moved, actor_admin_id=ACTOR)
    assert service.ledger.read(a.evidence_path(moved)) is None
    # Replay deliberately uses the old original terminal receipt, with a fresh
    # daemon/journal/host observation; no new signed report is fabricated.
    service.gate_scope = a.scope_bytes(scope)
    replay = copy.deepcopy(request["proofs"][1])
    replay["outcome"] = "fail"
    replay["failure_code"] = "observation_mismatch"
    replay["refusals"] = [next_day(replay["refusals"][1])]
    key = a.enrolled_key(service, moved)
    a.verify_refusals(service, moved, replay, key, moved_scope)
    transition = request["proofs"][2]["transition"]
    report, doc, _, _ = a.report_reference(service, request, transition, key, scope)
    for field in ("issued_at", "observed_at"):
        changed_doc, changed_report = copy.deepcopy(doc), copy.deepcopy(report)
        (changed_doc if field == "issued_at" else changed_report)[field] = (
            "2026-10-20T10:01:00Z"
        )
        with pytest.raises(c.ContractError, match="signed_observation_interval"):
            a.signed_interval(changed_report, changed_doc, transition, scope)


def test_dns_rotation_requires_actual_old_a_and_aaaa_absence(admitted):
    service, request, _ = admitted
    egress = request["proofs"][3]["egress"]
    original_after = copy.deepcopy(egress["after"])
    egress["after"].extend(copy.deepcopy(egress["before"]))
    with pytest.raises(c.ContractError, match="dns_evidence"):
        a.admit(service, None, request, actor_admin_id=ACTOR)
    alias = copy.deepcopy(egress["before"][1])
    alias["address"] = "2001:0db8:0000:0000:0000:0000:0000:0001"
    egress["after"] = original_after + [alias]
    with pytest.raises(c.ContractError, match="dns_evidence"):
        a.admit(service, None, request, actor_admin_id=ACTOR)
    assert service.ledger.read(a.evidence_path(request)) is None


def test_ledger_refuses_symlink_ancestor_before_any_outside_write(
    owner, tmp_path_factory
):
    service, _ = owner
    outside = tmp_path_factory.mktemp("gate-outside")
    (service.ledger.root / "gate0").symlink_to(outside, target_is_directory=True)
    service.ledger.git("add", "gate0")
    service.ledger.git("commit", "-m", "fixture tracked ancestor symlink")
    with pytest.raises(c.ContractError, match="ledger_path"):
        with service.ledger.transaction():
            service.ledger.append(
                "gate0/2026-10-22/run/evidence.json", {"public": "fixture"}
            )
    assert list(outside.iterdir()) == []


def test_authenticated_restore_failure_preserves_truthful_unobserved_fields(
    admitted, monkeypatch
):
    service, request, _ = admitted
    restore = request["proofs"][4]["restore"]
    restore.update(
        restored_inventory_sha256=None, source_parity=None, scratch_absent=None
    )
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.get_platform_db] = lambda: None
    app.dependency_overrides[api.require_platform_admin] = lambda: SimpleNamespace(
        id=ACTOR
    )
    monkeypatch.setattr(api, "service", lambda: service)
    client = TestClient(app, base_url=f"http://{settings.platform_root_domain}")
    assert (
        client.post("/platform/deploy/gate-evidence", json=request).status_code == 409
    )
    request["proofs"][4].update(
        outcome="fail", failure_code="cleanup_failed", cleanup="fail"
    )
    response = client.post("/platform/deploy/gate-evidence", json=request)
    assert response.status_code == 200
    receipt = response.json()
    assert receipt["verdict"] == "FAIL"
    assert receipt["evidence"]["proofs"][4]["restore"] == restore
    assert client.post("/platform/deploy/gate-evidence", json=request).json() == receipt


def morning_campaign(
    admitted,
    *,
    revision="1" * 40,
    tree="2" * 40,
    digest="sha256:" + "3" * 64,
    baseline=None,
):
    """Issue and ingest fresh signed B evidence after a published initial A run."""
    service, initial, initial_scope = admitted
    assert a.admit(service, None, initial, actor_admin_id=ACTOR)["verdict"] == "PASS"
    prior = copy.deepcopy(initial)
    previous = prior["proofs"][2]["transition"]
    previous_report_raw = service.ledger.read(
        f"applied/{service.deployment_ref}/{previous['report_id']}.json"
    )
    previous_report = c.verify(
        c.APPLIED,
        c.read_json(previous_report_raw),
        TestSigner("test-host", seed=2).public_key_b64,
    )
    old_image = previous_report["observed"]["running_image"]
    from_digest = baseline or old_image.rsplit("@", 1)[1]
    service.clock = lambda: datetime(2026, 10, 22, 10, 10, tzinfo=UTC)
    host = TestSigner("test-host", seed=2)
    refs = []
    plans = []
    for reason in ("bad_signature", "rollback_digest", None):
        doc = desired()
        doc.update(
            nonce=c.b64(uuid4().bytes),
            source_revision=revision,
            source_tree=tree,
            image_digest=digest,
            from_image_digest=from_digest,
            issued_at="2026-10-22T10:01:00Z",
            expires_at="2026-10-22T14:00:00Z",
        )
        doc["plan_digest"] = c.plan_digest(doc)
        signed = c.seal(c.DESIRED, doc, service.signer)
        service._record(
            None, {f"desired/{service.deployment_ref}/{doc['nonce']}.json": signed}
        )
        report = applied(doc)
        report.update(report_id=str(uuid4()), observed_at="2026-10-22T10:01:00Z")
        report["health"] = copy.deepcopy(previous_report["health"])
        for field in ("live", "ready"):
            report["health"][field]["checked_at"] = "2026-10-22T10:01:00Z"
        before = {
            "observed_at": "2026-10-22T10:01:00Z",
            "observed": copy.deepcopy(previous_report["observed"]),
            "health": copy.deepcopy(report["health"]),
            "executor_count": 1,
        }
        if baseline:
            for field in ("running_image", "pinned_image"):
                before["observed"][field] = doc["image_reference"] + "@" + baseline
        if reason:
            report.update(
                disposition="refused",
                reason=reason,
                observed=copy.deepcopy(before["observed"]),
            )
        envelope = c.seal(c.APPLIED, report, host)
        assert service.ingest(None, envelope) == {"verdict": "accepted"}
        path = f"applied/{service.deployment_ref}/{report['report_id']}.json"
        refs.append((doc, signed, report, envelope, before, path))
        plans.append(c.plan_document(doc))
    commit = service.ledger.git("rev-parse", "HEAD").decode().strip()
    doc, signed, report, envelope, before, path = refs[-1]
    after = {
        "observed_at": "2026-10-22T10:02:00Z",
        "observed": report["observed"],
        "health": report["health"],
        "executor_count": 2,
    }
    transition = {
        "nonce": doc["nonce"],
        "desired_sha256": c.digest(signed),
        "source_preparation_sha256": D,
        "report_id": report["report_id"],
        "report_sha256": c.digest(envelope),
        "receipt_sha256": c.digest(
            {
                "deployment_ref": service.deployment_ref,
                "report_id": report["report_id"],
                "path": path,
                "fingerprint": c.digest(envelope),
            }
        ),
        "ledger_commit": commit,
        "before": before,
        "after": after,
        "signatures_verified": True,
        "runners_stopped": True,
    }
    request = copy.deepcopy(prior)
    request.update(
        command_id=str(uuid4()),
        run_id=str(uuid4()),
        phase="next_morning",
        prior_run_id=prior["run_id"],
        source_revision=revision,
        source_tree=tree,
        deadline="2026-10-22T14:00:00Z",
        proofs=copy.deepcopy(prior["proofs"][1:4]),
    )
    refusal_refs = []
    for item, original, terminal, sealed, observed_before, _ in refs[:2]:
        code = terminal["reason"]
        submitted = copy.deepcopy(original)
        if code == "bad_signature":
            signature = bytearray(c.unb64(submitted["signature_b64"]))
            signature[0] ^= 1
            submitted["signature_b64"] = c.b64(signature)
        template = copy.deepcopy(
            next(r for r in prior["proofs"][1]["refusals"] if r["case"] == code)
        )
        template.update(
            submitted_sha256=c.digest(submitted),
            nonce=item["nonce"],
            report_id=terminal["report_id"],
            report_sha256=c.digest(sealed),
            ledger_commit=commit,
            before=observed_before,
            after=copy.deepcopy(observed_before),
            cleanup_observed_at="2026-10-22T10:03:00Z",
        )
        refusal_refs.append(template)
    replay = copy.deepcopy(prior["proofs"][1]["refusals"][1])
    replay.update(
        nonce=doc["nonce"],
        report_id=report["report_id"],
        report_sha256=c.digest(envelope),
        submitted_sha256=c.digest(signed),
        before=copy.deepcopy(after),
        after=copy.deepcopy(after),
        cleanup_observed_at="2026-10-22T10:03:00Z",
        ledger_commit=commit,
    )
    refusal_refs.append(replay)
    request["proofs"][0]["refusals"] = refusal_refs
    for proof in request["proofs"][1:]:
        proof["transition"] = copy.deepcopy(transition)
    egress = request["proofs"][2]["egress"]
    egress.update(
        started_at="2026-10-22T10:00:00Z",
        finished_at="2026-10-22T10:10:00Z",
        old_expiry_observed_at="2026-10-22T10:01:02Z",
        transition_report_id=report["report_id"],
        transition_report_sha256=c.digest(envelope),
    )
    scope = copy.deepcopy(initial_scope)
    scope.update(
        context={
            key: value
            for key, value in request.items()
            if key not in ("command_id", "proofs")
        },
        observation_not_before="2026-10-22T09:00:00Z",
        prior_evidence_sha256=c.digest(prior),
        candidates=scope["candidates"] + plans,
    )
    service.gate_scope = a.scope_bytes(scope)
    return service, request, scope, prior


def test_two_day_admission_binds_real_fresh_target_and_prior(admitted):
    service, request, scope, prior = morning_campaign(admitted)
    variants = []
    changed = copy.deepcopy(request)
    changed["tool_revision"] = "9" * 40
    variants.append((changed, "prior_run_mismatch"))
    changed = copy.deepcopy(request)
    changed["prior_run_id"] = str(uuid4())
    variants.append((changed, "prior_run_missing"))
    changed = copy.deepcopy(request)
    changed["host_key_id"] = "another-host"
    variants.append((changed, "host_key_inactive"))
    changed = copy.deepcopy(request)
    changed["source_revision"] = prior["source_revision"]
    variants.append((changed, "source_target_mismatch"))
    changed = copy.deepcopy(request)
    changed["source_tree"] = prior["source_tree"]
    changed["proofs"][1].update(outcome="fail", failure_code="observation_mismatch")
    variants.append((changed, "source_target_mismatch"))
    for changed, code in variants:
        bound = copy.deepcopy(scope)
        bound["context"] = {
            k: v for k, v in changed.items() if k not in ("command_id", "proofs")
        }
        service.gate_scope = a.scope_bytes(bound)
        with pytest.raises(c.ContractError, match=code):
            a.admit(service, None, changed, actor_admin_id=ACTOR)
    changed = copy.deepcopy(request)
    for proof in changed["proofs"][1:]:
        proof["transition"]["nonce"] = prior["proofs"][2]["transition"]["nonce"]
    service.gate_scope = a.scope_bytes(scope)
    with pytest.raises(c.ContractError, match="evidence_substitution"):
        a.admit(service, None, changed, actor_admin_id=ACTOR)
    bad_scope = copy.deepcopy(scope)
    bad_scope["prior_evidence_sha256"] = D
    service.gate_scope = a.scope_bytes(bad_scope)
    with pytest.raises(c.ContractError, match="prior_run_missing"):
        a.admit(service, None, request, actor_admin_id=ACTOR)
    service.gate_scope = a.scope_bytes(scope)
    old_replay_request = copy.deepcopy(request)
    current_replay = next(
        r
        for r in old_replay_request["proofs"][0]["refusals"]
        if r["case"] == "nonce_replay"
    )
    prior_replay = next(
        r for r in prior["proofs"][1]["refusals"] if r["case"] == "nonce_replay"
    )
    for key in ("nonce", "report_id", "report_sha256", "submitted_sha256"):
        current_replay[key] = prior_replay[key]
    with pytest.raises(c.ContractError, match="replay_expired"):
        a.admit(service, None, old_replay_request, actor_admin_id=ACTOR)
    receipt = a.admit(service, None, request, actor_admin_id=ACTOR)
    assert receipt["verdict"] == "PASS"
    assert request["source_revision"] != prior["source_revision"]
    assert request["source_tree"] != prior["source_tree"]
    assert a.admit(service, None, request, actor_admin_id=ACTOR) == receipt


@pytest.mark.parametrize(
    ("revision", "tree", "digest", "baseline", "code"),
    [
        ("d" * 40, "e" * 40, "sha256:" + "3" * 64, None, "source_reused"),
        ("1" * 40, "e" * 40, "sha256:" + "3" * 64, None, "source_reused"),
        (
            "1" * 40,
            "2" * 40,
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
            "target_reused",
        ),
        (
            "1" * 40,
            "2" * 40,
            "sha256:" + "3" * 64,
            "sha256:" + "b" * 64,
            "image_discontinuity",
        ),
    ],
)
def test_next_morning_refuses_noop_tree_reuse_and_discontinuity(
    admitted, revision, tree, digest, baseline, code
):
    service, request, _, _ = morning_campaign(
        admitted, revision=revision, tree=tree, digest=digest, baseline=baseline
    )
    with pytest.raises(c.ContractError, match=code):
        a.admit(service, None, request, actor_admin_id=ACTOR)
    assert service.ledger.read(a.evidence_path(request)) is None


def test_transition_source_substitution_refuses_pass_and_fail(admitted):
    service, request, scope = admitted
    for outcome in ("pass", "fail"):
        changed = copy.deepcopy(request)
        changed.update(source_revision="1" * 40, source_tree="2" * 40)
        if outcome == "fail":
            changed["proofs"][2].update(
                outcome="fail", failure_code="observation_mismatch"
            )
            changed["proofs"] = [changed["proofs"][2]]
        bound = copy.deepcopy(scope)
        bound["context"] = {
            key: value
            for key, value in changed.items()
            if key not in ("command_id", "proofs")
        }
        service.gate_scope = a.scope_bytes(bound)
        with pytest.raises(c.ContractError, match="source_target_mismatch"):
            a.admit(service, None, changed, actor_admin_id=ACTOR)
        assert service.ledger.read(a.evidence_path(changed)) is None


def test_next_morning_partial_fail_does_not_invent_transition(admitted):
    service, initial, scope = admitted
    a.admit(service, None, initial, actor_admin_id=ACTOR)
    request = copy.deepcopy(initial)
    request.update(
        command_id=str(uuid4()),
        run_id=str(uuid4()),
        phase="next_morning",
        prior_run_id=initial["run_id"],
        source_revision="1" * 40,
        source_tree="2" * 40,
        deadline="2026-10-22T14:00:00Z",
    )
    proof = copy.deepcopy(initial["proofs"][2])
    proof.update(
        outcome="fail", failure_code="transport_failed", cleanup="fail", transition=None
    )
    request["proofs"] = [proof]
    scope.update(
        context={
            key: value
            for key, value in request.items()
            if key not in ("command_id", "proofs")
        },
        observation_not_before="2026-10-22T09:00:00Z",
        prior_evidence_sha256=c.digest(initial),
    )
    service.gate_scope = a.scope_bytes(scope)
    service.clock = lambda: datetime(2026, 10, 22, 10, tzinfo=UTC)
    receipt = a.admit(service, None, request, actor_admin_id=ACTOR)
    assert receipt["verdict"] == "FAIL"
    assert receipt["evidence"]["proofs"] == [proof]


def test_same_run_replay_rejects_foreign_join_and_expiry(admitted):
    service, request, scope = admitted
    original = next(
        r for r in request["proofs"][1]["refusals"] if r["case"] == "nonce_replay"
    )
    for key, value in (
        ("nonce", c.b64(uuid4().bytes)),
        ("report_id", str(uuid4())),
        ("report_sha256", D),
    ):
        changed = copy.deepcopy(request)
        replay = next(
            r for r in changed["proofs"][1]["refusals"] if r["case"] == "nonce_replay"
        )
        replay[key] = value
        with pytest.raises(
            c.ContractError, match="evidence_substitution|evidence_missing"
        ):
            a.admit(service, None, changed, actor_admin_id=ACTOR)
    for start, finish in (("14:00:00", "14:00:01"), ("13:59:59", "14:00:00")):
        changed = copy.deepcopy(request)
        changed["deadline"] = "2026-10-21T15:00:00Z"
        replay = next(
            r for r in changed["proofs"][1]["refusals"] if r["case"] == "nonce_replay"
        )
        replay["before"]["observed_at"] = "2026-10-21T" + start + "Z"
        replay["after"]["observed_at"] = "2026-10-21T" + finish + "Z"
        replay["cleanup_observed_at"] = "2026-10-21T14:00:02Z"
        bound = copy.deepcopy(scope)
        bound["context"]["deadline"] = changed["deadline"]
        service.gate_scope = a.scope_bytes(bound)
        with pytest.raises(c.ContractError, match="replay_expired"):
            a.admit(service, None, changed, actor_admin_id=ACTOR)
    service.gate_scope = a.scope_bytes(scope)
    too_early = copy.deepcopy(request)
    replay = next(
        r for r in too_early["proofs"][1]["refusals"] if r["case"] == "nonce_replay"
    )
    replay["before"]["observed_at"] = "2026-10-21T10:01:30Z"
    replay["after"]["observed_at"] = "2026-10-21T10:01:31Z"
    with pytest.raises(c.ContractError, match="replay_order"):
        a.admit(service, None, too_early, actor_admin_id=ACTOR)
    # All cryptographic references can be valid yet belong to another command.
    doc = desired()
    doc.update(
        nonce=c.b64(uuid4().bytes),
        image_digest="sha256:" + "9" * 64,
        from_image_digest=doc["image_digest"],
        issued_at="2026-10-21T10:01:00Z",
    )
    doc["plan_digest"] = c.plan_digest(doc)
    desired_envelope = c.seal(c.DESIRED, doc, service.signer)
    service._record(
        None,
        {f"desired/{service.deployment_ref}/{doc['nonce']}.json": desired_envelope},
    )
    report = applied(doc)
    report["report_id"] = str(uuid4())
    report["health"]["background"]["containers"]["celery-worker"] = "running"
    sealed = c.seal(c.APPLIED, report, TestSigner("test-host", seed=2))
    assert service.ingest(None, sealed) == {"verdict": "accepted"}
    scope["candidates"].append(c.plan_document(doc))
    service.gate_scope = a.scope_bytes(scope)
    original.update(
        nonce=doc["nonce"],
        report_id=report["report_id"],
        report_sha256=c.digest(sealed),
        submitted_sha256=c.digest(desired_envelope),
        ledger_commit=service.ledger.git("rev-parse", "HEAD").decode().strip(),
    )
    with pytest.raises(c.ContractError, match="replay_transition_mismatch"):
        a.admit(service, None, request, actor_admin_id=ACTOR)
    assert service.ledger.read(a.evidence_path(request)) is None
