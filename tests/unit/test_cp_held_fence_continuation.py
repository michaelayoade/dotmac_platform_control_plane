"""Root-pinned continuation evidence and source-only host composition."""

from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_cp_transition_host import config
from test_transition_operator import request

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import cp_transition_host as host_module
from vendor_cp.deployment import transition_fence as fence
from vendor_cp.deployment import transition_operator as op


@pytest.fixture
def continuation(tmp_path, monkeypatch):
    # Filesystem custody has separate owner tests; this is source composition.
    monkeypatch.setattr(cp, "_protected", lambda *args, **kwargs: None)
    prior = request()
    proof = fence.FenceProof(
        database=prior["database"],
        fence_id="c" * 64,
        prior_acl="original",
        prior_grants=frozenset(
            {
                ("", "CONNECT", False, "app_admin"),
                ("app_user", "CONNECT", True, "app_admin"),
                ("app_admin", "CONNECT", False, "app_admin"),
            }
        ),
        fenced_roles=("app_user",),
        member_roles=(),
        absent_roles=tuple(role for role in fence.WRITER_ROLES if role != "app_user"),
        terminated_count=0,
        fenced_at=datetime.now(UTC),
    )
    store = cp.ArtifactStore(tmp_path)
    reservation = canonical_json(
        {
            "schema": "dotmac.cp_transition_attempt/2",
            "verification_digest": "sha256:" + "d" * 64,
            "request_digest": cp.request_digest(prior),
            "host_nonce": proof.fence_id,
            "authorization_run_id": prior["authorization_run_id"],
            "authorization_run_attempt": prior["authorization_run_attempt"],
        }
    )
    store._create(store._name(cp.request_digest(prior), "reservation"), reservation)
    failure = store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "request_digest": cp.request_digest(prior),
                "host_nonce": proof.fence_id,
                "kind": "failure",
                "result": {
                    "external_status": 503,
                    "writer_sessions": 0,
                    "reconnect_denial": "database_acl",
                },
            }
        )
    )
    proof_digest = store.put(proof.canonical_bytes())
    context = canonical_json(
        {
            "schema": "dotmac.cp_transition_held_fence_context/1",
            "prior_artifact_directory": str(tmp_path),
            "request": prior,
            "reservation_digest": cp.raw_digest(reservation),
            "failure_digest": failure,
            "failed_stage": "source-restore-comparison",
        }
    )
    pins = {
        "path": "/protected/context.json",
        "digest": cp.raw_digest(context),
        "proof_digest": proof_digest,
        "fence_id": proof.fence_id,
    }
    installation = SimpleNamespace(
        store=store,
        held_fence_context=pins,
        policy=SimpleNamespace(
            identity=SimpleNamespace(
                **{
                    key: prior[key]
                    for key in (
                        "host",
                        "database",
                        "cluster_system_identifier",
                        "database_oid",
                    )
                }
            )
        ),
    )
    monkeypatch.setattr(cp, "_read_protected", lambda path: context)
    current = deepcopy(prior)
    current["authorization_run_id"] += 1
    return installation, prior, current, proof


def test_root_pins_load_original_acl_for_distinct_new_attempt(continuation):
    installation, prior, current, proof = continuation
    loaded = op._load_held_fence(installation, current)
    assert loaded.request == prior
    assert loaded.proof == proof
    loaded.bind(current, "e" * 64)
    with pytest.raises(ContractError, match="nonce_reused"):
        loaded.bind(current, proof.fence_id)


@pytest.mark.parametrize("pin", ["digest", "proof_digest", "fence_id"])
def test_corrupt_or_stale_independent_pins_refuse(continuation, pin):
    installation, _, current, _ = continuation
    installation.held_fence_context[pin] = (
        "0" * 64 if pin == "fence_id" else "sha256:" + "0" * 64
    )
    with pytest.raises((ContractError, FileNotFoundError, fence.FenceRefused)):
        op._load_held_fence(installation, current)


@pytest.mark.parametrize(
    "field", ["source", "host", "database_oid", "cluster_system_identifier", "database"]
)
def test_new_identity_or_source_mismatch_refuses_before_host(continuation, field):
    installation, _, current, _ = continuation
    current[field] = (
        {**current[field], "revision": "e" * 40}
        if field == "source"
        else 999
        if field == "database_oid"
        else "different"
    )
    with pytest.raises(ContractError, match="source_mismatch"):
        op._load_held_fence(installation, current)


def test_old_request_or_authorization_cannot_be_reused(continuation):
    installation, prior, current, _ = continuation
    with pytest.raises(ContractError, match="request_reused"):
        op._load_held_fence(installation, prior)
    current["authorization_run_id"] = prior["authorization_run_id"]
    current["expires_at"] = "2099-01-01T00:00:00Z"
    with pytest.raises(ContractError, match="authorization_reused"):
        op._load_held_fence(installation, current)


class ReadOnlyConnection:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def execute(self, statement, parameters):
        assert str(statement).startswith("SELECT ")
        self.calls.append(str(statement))
        return SimpleNamespace(all=lambda: self.rows, __iter__=lambda: iter(self.rows))


def test_missing_context_refuses_fresh_capture_of_held_acl(tmp_path):
    host = host_module.ExistingCpTransitionHost(
        config(tmp_path), store=cp.ArtifactStore(tmp_path), recovery={}
    )
    connection = ReadOnlyConnection([("app_user",)])
    with pytest.raises(ContractError, match="held_fence_context_required"):
        host._check_fence_baseline(connection, request())


@pytest.mark.parametrize("drift", ["membership", "acl"])
def test_live_drift_refuses_before_fence_mutation(
    continuation, tmp_path, monkeypatch, drift
):
    installation, _, current, _ = continuation
    loaded = op._load_held_fence(installation, current)
    host = host_module.ExistingCpTransitionHost(
        config(tmp_path), store=installation.store, recovery={}, held_fence=loaded
    )
    host._request = current
    host._nonce = "e" * 64
    connection = SimpleNamespace(
        execute=lambda *args: [("intruder", "CONNECT", False, "app_admin")]
    )
    monkeypatch.setattr(host, "_connect", lambda *args: nullcontext(connection))
    monkeypatch.setattr(host, "_identity", lambda *args: None)
    monkeypatch.setattr(fence, "fence_is_holding", lambda *args: drift != "membership")
    monkeypatch.setattr(
        fence, "fence_writers", lambda *args, **kwargs: pytest.fail("mutation")
    )
    with pytest.raises(ContractError, match="held_fence_"):
        host.fence_and_negative_reconnect(current, "e" * 64)


def test_new_host_rebinds_prior_original_acl_without_unfencing(
    continuation, tmp_path, monkeypatch
):
    installation, _, current, original = continuation
    # Simulate a process boundary: public parser rebuilds the held proof from
    # retained evidence; the new owner does not inherit the failed host object.
    loaded = op._load_held_fence(installation, current)
    host = host_module.ExistingCpTransitionHost(
        config(tmp_path), store=installation.store, recovery={}, held_fence=loaded
    )
    host._request = current
    host._nonce = "e" * 64
    monkeypatch.setattr(host, "_connect", lambda *args: nullcontext(object()))
    monkeypatch.setattr(host, "_identity", lambda *args: None)
    monkeypatch.setattr(host, "_check_fence_baseline", lambda *args: None)
    monkeypatch.setattr(host, "_strict", lambda *args: host.proof)
    calls = []

    def rebind(connection, *, prior, expected_prior_fence_id, fence_id, **kwargs):
        assert prior == original
        assert expected_prior_fence_id == original.fence_id
        calls.append(fence_id)
        return replace(prior, fence_id=fence_id)

    monkeypatch.setattr(fence, "fence_writers", rebind)
    host.fence_and_negative_reconnect(current, host._nonce)
    assert calls == ["e" * 64]
    assert host.proof.prior_grants == original.prior_grants
    assert host.proof.fence_id != original.fence_id


@pytest.mark.parametrize(
    "kind",
    [
        "recovery-restored",
        "fence-source-rechecked",
        "migrate",
        "migrated-target-heads",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "full-ready",
        "pre-routing-verified",
        "routing-restored",
    ],
)
def test_post_restore_checkpoint_refuses_failed_prefix(continuation, kind):
    installation, prior, current, proof = continuation
    installation.store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "kind": kind,
                "request_digest": cp.request_digest(prior),
                "host_nonce": proof.fence_id,
                "result": {},
            }
        )
    )
    with pytest.raises(ContractError, match="prefix_after_restore"):
        op._load_held_fence(installation, current)


def test_unrelated_history_and_raw_descriptors_are_not_failed_prefix(continuation):
    installation, prior, current, proof = continuation
    installation.store.put(b'product="dotmac_vendor_control_plane"\n')
    installation.store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "kind": "migrate",
                "request_digest": cp.request_digest(prior),
                "host_nonce": "0" * 64,
                "result": {},
            }
        )
    )
    assert op._load_held_fence(installation, current).proof == proof


@pytest.mark.parametrize("phase", ["pre-routing", "complete"])
@pytest.mark.parametrize("same_attempt", [False, True])
def test_receipts_contradict_only_the_matching_failed_attempt(
    continuation, phase, same_attempt
):
    installation, prior, current, proof = continuation
    installation.store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_migration_transition_receipt/1",
                "phase": phase,
                "request": prior,
                "request_digest": cp.request_digest(prior),
                "host_nonce": proof.fence_id if same_attempt else "0" * 64,
                "genesis_digest": None,
                "previous_receipt_digest": None,
                "evidence": {},
            }
        ),
        kind="receipt",
    )
    if same_attempt:
        with pytest.raises(ContractError, match="prefix_after_restore"):
            op._load_held_fence(installation, current)
    else:
        assert op._load_held_fence(installation, current).proof == proof


@pytest.mark.parametrize("method", ["maintenance", "fail_closed"])
def test_missing_context_never_mutates_through_maintenance_or_containment(
    tmp_path, monkeypatch, method
):
    current = request()
    host = host_module.ExistingCpTransitionHost(
        config(tmp_path), store=cp.ArtifactStore(tmp_path), recovery={}
    )
    host._request, host._nonce = current, "e" * 64
    connection = ReadOnlyConnection([("app_user",)])
    monkeypatch.setattr(host, "_connect", lambda *args: nullcontext(connection))
    monkeypatch.setattr(host, "_identity", lambda *args: None)
    monkeypatch.setattr(host, "_maintenance", lambda: pytest.fail("mutation"))
    arguments = {"acl_may_be_restored": False} if method == "fail_closed" else {}
    with pytest.raises(ContractError, match="held_fence_context_required"):
        getattr(host, method)(current, host._nonce, **arguments)


def test_old_evidence_is_loaded_with_an_empty_new_artifact_store(
    continuation, tmp_path
):
    installation, _, current, proof = continuation
    next_store = tmp_path / "new-attempt"
    next_store.mkdir(mode=0o700)
    installation.store = cp.ArtifactStore(next_store)
    assert op._load_held_fence(installation, current).proof == proof
    assert list(next_store.iterdir()) == []


@pytest.mark.parametrize("field", ["reservation_digest", "failure_digest"])
def test_root_context_cannot_substitute_unbound_attempt_records(
    continuation, monkeypatch, field
):
    installation, _, current, _ = continuation
    context = cp.read_json(cp._read_protected(Path("/protected/context.json")))
    context[field] = installation.store.put(canonical_json({"wrong": "record"}))
    raw = canonical_json(context)
    installation.held_fence_context["digest"] = cp.raw_digest(raw)
    monkeypatch.setattr(cp, "_read_protected", lambda path: raw)
    with pytest.raises(ContractError, match="held_fence_"):
        op._load_held_fence(installation, current)
