"""Protected context composition and exact protocol dispatch; hosted CI only."""

# ruff: noqa: F811 - fixtures are composed from the existing owner suites
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_cp_adjudicated_post_acl_recovery import AdjudicatedHost
from test_cp_committed_continuation import committed, fresh_store  # noqa: F401
from test_cp_failed_candidate_recovery import failed  # noqa: F401
from test_cp_post_acl_recovery import sign
from test_cp_transition import request, store, trust  # noqa: F401
from test_failed_candidate_operator import protected_failed, protected_v2  # noqa: F401
from test_post_acl_operator import protected_post_acl  # noqa: F401
from test_transition_operator import document, load  # noqa: F401

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, digest
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_operator as op


@pytest.fixture
def protected_adjudicated(protected_post_acl, monkeypatch):
    p = protected_post_acl
    present = deepcopy(p.loaded.measurement)
    next(
        row for row in present["relations"] if row[:2] == ["public", "relay_heartbeats"]
    )[5] += 1
    adjudication = {
        "schema": "dotmac.cp_heartbeat_drift_adjudication/1",
        "acknowledgement": "HISTORICAL_INTERVAL_NOT_ATTRIBUTED",
        "historical_measurement_digest": digest(p.loaded.measurement),
        "present_measurement_digest": digest(present),
        "permitted_difference": {
            "schema": "public",
            "relation": "relay_heartbeats",
            "relation_identity_digest": digest(["public", "relay_heartbeats"]),
            "counter": "n_tup_upd",
            "direction": "increase",
        },
        "current_heartbeat": {"row_count": 1, "rowset_digest": "sha256:" + "9" * 64},
        "evidence": {
            "qualification_assessment_digest": "sha256:" + "1" * 64,
            "comparison_digest": "sha256:" + "2" * 64,
            "decoder_result_digest": "sha256:" + "3" * 64,
        },
        "unavailable_assurance": {
            "actor_attribution_proven": False,
            "backup_to_retained_baseline_linkage": False,
            "business_row_equality_proven": False,
            "harmlessness_proven": False,
            "intermediate_writes_excluded": False,
            "null_claim_proves_idle_interval": False,
        },
    }
    path = Path("/opt/current/adjudicated-context.json")
    value = {
        "schema": "dotmac.cp_adjudicated_post_acl_recovery_context/1",
        "historical_context": dict(p.active.post_acl_recovery_context),
        "adjudication": adjudication,
        "present_measurement": present,
    }
    p.reads[path] = canonical_json(value)
    active = replace(
        p.active,
        post_acl_recovery_context=None,
        adjudicated_post_acl_recovery_context={
            "path": str(path),
            "digest": digest(value),
        },
    )
    original_load = op.load_installation
    monkeypatch.setattr(
        op,
        "load_installation",
        lambda selected: active
        if selected == p.config_path
        else original_load(selected),
    )
    context = op._load_adjudicated_post_acl_recovery_context(active)
    successor = deepcopy(p.successor)
    successor.update(
        schema="dotmac.cp_adjudicated_post_acl_request/1",
        adjudication=adjudication,
        basis=cp.adjudicated_post_acl_basis(context),
    )
    successor["plan_digest"] = cp.transition_plan_digest(successor)
    p.reads[p.request_path] = canonical_json(successor)
    return SimpleNamespace(
        base=p,
        active=active,
        path=path,
        document=value,
        context=context,
        successor=successor,
    )


def test_protected_loader_preserves_historical_bytes_and_present_boundary(
    protected_adjudicated,
):
    p = protected_adjudicated
    before = dict(p.base.reads)
    loaded = op._load_adjudicated_post_acl_recovery_context(p.active)
    assert type(loaded) is cp.AdjudicatedPostAclRecoveryContext
    assert type(loaded.historical) is cp.PostAclRecoveryContext
    assert loaded.context_digest == cp.raw_digest(p.base.reads[p.path])
    assert loaded.historical.context_digest == p.base.loaded.context_digest
    assert loaded.historical.measurement == p.base.loaded.measurement
    assert loaded.present_measurement != loaded.historical.measurement
    assert loaded.historical.prior_store.root == p.base.loaded.prior_store.root
    assert p.base.reads == before


@pytest.mark.parametrize(
    "fault", ["raw-pin", "historical-pin", "unknown", "acknowledgement", "assurance"]
)
def test_protected_loader_refuses_crossed_or_nonclosed_context(
    protected_adjudicated, fault
):
    p = protected_adjudicated
    value = deepcopy(p.document)
    if fault == "historical-pin":
        value["historical_context"]["digest"] = "sha256:" + "f" * 64
    elif fault == "unknown":
        value["unknown"] = True
    elif fault == "acknowledgement":
        del value["adjudication"]["acknowledgement"]
    elif fault == "assurance":
        value["adjudication"]["unavailable_assurance"]["harmlessness_proven"] = True
    p.base.reads[p.path] = canonical_json(value)
    pins = {"path": str(p.path), "digest": digest(value)}
    if fault == "raw-pin":
        pins["digest"] = "sha256:" + "f" * 64
    with pytest.raises(ContractError):
        op._load_adjudicated_post_acl_recovery_context(
            replace(p.active, adjudicated_post_acl_recovery_context=pins)
        )


def test_only_dedicated_executor_receives_exact_context_and_shared_registry(
    protected_adjudicated, monkeypatch
):
    p = protected_adjudicated
    monkeypatch.setattr(op, "_load_recovery", lambda installed, **kwargs: {})
    calls = {}

    def host(config, **kwargs):
        calls["host"] = kwargs
        return SimpleNamespace()

    def execute(raw, **kwargs):
        assert cp.read_json(raw) == p.successor
        calls["execute"] = kwargs
        return "sha256:" + "d" * 64

    def forbidden(*args, **kwargs):
        pytest.fail("crossed protocol executor")

    from vendor_cp.deployment import cp_transition_host

    monkeypatch.setattr(cp_transition_host, "ExistingCpTransitionHost", host)
    monkeypatch.setattr(cp, "execute_adjudicated_post_acl_recovery", execute)
    for name in (
        "execute_transition",
        "execute_post_acl_recovery",
        "execute_committed_continuation",
        "execute_failed_candidate_recovery",
    ):
        monkeypatch.setattr(cp, name, forbidden)
    assert (
        op.run_transition(
            config_file=p.base.config_path, request_file=p.base.request_path
        )
        == "sha256:" + "d" * 64
    )
    loaded = calls["execute"]["context"]
    assert calls["host"]["post_acl_recovery_context"] is loaded
    registry = calls["execute"]["post_acl_contexts"]
    assert registry[loaded.context_digest] is loaded
    assert registry[loaded.historical.context_digest] is loaded.historical
    assert calls["host"]["post_acl_contexts"] is registry
    assert (
        loaded.historical.original.context_digest
        in calls["execute"]["committed_contexts"]
    )
    assert (
        loaded.historical.predecessor.context_digest
        in calls["execute"]["failed_candidate_contexts"]
    )


@pytest.mark.parametrize(
    "other",
    [
        "post_acl_recovery_context",
        "failed_candidate_context",
        "committed_migration_context",
        "held_fence_context",
    ],
)
def test_active_installation_cannot_select_two_context_protocols(load, other):
    value = document()
    value["operator_revision"] = "f" * 40
    pins = {"path": "/opt/current/context.json", "digest": "sha256:" + "a" * 64}
    value["adjudicated_post_acl_recovery_context"] = pins
    value[other] = pins
    with pytest.raises(ContractError):
        load(value)


def test_adjudicated_registry_digest_cannot_alias_historical(protected_adjudicated):
    p = protected_adjudicated
    crossed = replace(p.context, context_digest=p.context.historical.context_digest)
    with pytest.raises(ContractError, match="duplicate_adjudicated_post_acl_context"):
        op._register_adjudicated_post_acl_context({}, {}, {}, {}, crossed)


@pytest.fixture
def completed_adjudicated(protected_adjudicated, trust):
    """Retain a real completed receipt from the dedicated executor and owners."""
    p = protected_adjudicated
    sign(p.successor, trust, p.base.request_path)
    host = AdjudicatedHost(p.context, p.active.store)
    result = cp.execute_adjudicated_post_acl_recovery(
        canonical_json(p.successor),
        request_path=p.base.request_path,
        bundle_path=None,
        verifier=trust[0],
        host=host,
        store=p.active.store,
        recovery={},
        context=p.context,
        clock=lambda: p.base.now,
    )
    path = Path("/opt/current/adjudicated-historical-index.json")
    entry = {
        "schema": "dotmac.cp_adjudicated_post_acl_historical_recovery_context/1",
        "receipt_digest": result,
        "adjudicated_post_acl_recovery_context": dict(
            p.active.adjudicated_post_acl_recovery_context
        ),
    }
    p.base.reads[path] = canonical_json(entry)
    future = replace(
        p.active,
        adjudicated_post_acl_recovery_context=None,
        historical_context_files=(path,),
    )
    return SimpleNamespace(
        protected=p, installation=future, entry=entry, path=path, receipt_digest=result
    )


def test_completed_historical_receipt_reloads_with_both_context_identities(
    completed_adjudicated,
):
    p = completed_adjudicated
    contexts, failed_contexts, post_contexts = {}, {}, {}
    recovery = op._load_recovery(
        p.installation,
        committed_contexts=contexts,
        failed_candidate_contexts=failed_contexts,
        post_acl_contexts=post_contexts,
    )
    context = post_contexts[p.protected.context.context_digest]
    assert type(context) is cp.AdjudicatedPostAclRecoveryContext
    assert post_contexts[context.historical.context_digest] is context.historical
    assert context.historical.context_digest != context.context_digest
    raw = p.installation.store.read(p.receipt_digest, kind="receipt")
    receipt = cp.read_json(raw)
    assert receipt["historical_context_digest"] == context.historical.context_digest
    assert receipt["adjudicated_context_digest"] == context.context_digest
    cp.verify_adjudicated_post_acl_receipt(
        raw,
        store=p.installation.store,
        request=receipt["request"],
        host_nonce=receipt["host_nonce"],
        recovery=recovery,
        context=context,
        post_acl_contexts=post_contexts,
        committed_contexts=contexts,
        failed_candidate_contexts=failed_contexts,
        routing_gate=True,
    )


@pytest.mark.parametrize(
    "field", ["historical_context_digest", "adjudicated_context_digest"]
)
def test_completed_historical_receipt_rejects_crossed_context_identity(
    completed_adjudicated, field
):
    p = completed_adjudicated
    receipt = cp.read_json(p.installation.store.read(p.receipt_digest, kind="receipt"))
    receipt[field] = (
        p.protected.context.context_digest
        if field == "historical_context_digest"
        else p.protected.context.historical.context_digest
    )
    crossed = p.installation.store.put(canonical_json(receipt), kind="receipt")
    p.protected.base.reads[p.path] = canonical_json(
        {**p.entry, "receipt_digest": crossed}
    )
    with pytest.raises(
        ContractError, match="historical_adjudicated_post_acl_receipt_mismatch"
    ):
        op._load_recovery(p.installation)


def test_completed_adjudicated_receipt_dispatches_as_previous_ordinary_transition(
    completed_adjudicated, monkeypatch
):
    p = completed_adjudicated
    base = p.protected.base
    future = request()
    # The ancestry fixture advances beyond the original request's expiry.
    # This is a new request, so give it a fresh window at that fixed clock.
    future["expires_at"] = (
        (base.now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    )
    future["source"] = deepcopy(p.protected.successor["target"])
    future["target"]["image_digest"] = "sha256:" + "e" * 64
    future["previous_receipt_digest"] = p.receipt_digest
    future["plan_digest"] = cp.transition_plan_digest(future)
    base.reads[base.request_path] = canonical_json(future)
    assert (
        cp.load_request(
            canonical_json(future),
            identity=p.installation.policy.identity,
            now=base.now,
        )
        == future
    )
    original_load = op.load_installation
    monkeypatch.setattr(
        op,
        "load_installation",
        lambda path: p.installation
        if path == base.config_path
        else original_load(path),
    )
    calls = {}

    def execute(raw, **kwargs):
        assert cp.read_json(raw) == future
        calls.update(kwargs)
        # This is the same predecessor gate the actual ordinary executor uses.
        cp.verify_predecessor(
            future,
            store=kwargs["store"],
            recovery=kwargs["recovery"],
            post_acl_contexts=kwargs["post_acl_contexts"],
            committed_contexts=kwargs["committed_contexts"],
            failed_candidate_contexts=kwargs["failed_candidate_contexts"],
        )
        return "sha256:" + "e" * 64

    from vendor_cp.deployment import cp_transition_host

    monkeypatch.setattr(
        cp_transition_host,
        "ExistingCpTransitionHost",
        lambda *args, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(cp, "execute_transition", execute)
    assert (
        op.run_transition(config_file=base.config_path, request_file=base.request_path)
        == "sha256:" + "e" * 64
    )
    assert (
        type(calls["post_acl_contexts"][p.protected.context.context_digest])
        is cp.AdjudicatedPostAclRecoveryContext
    )
