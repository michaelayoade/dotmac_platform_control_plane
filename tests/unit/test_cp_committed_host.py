"""Read-only committed-frontier admission and existing suffix composition."""

from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_cp_transition_host import config

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition_host as module
from vendor_cp.deployment.cp_transition import ArtifactStore, raw_digest


@pytest.fixture
def committed(tmp_path, monkeypatch):
    catalogue = b"complete catalogue"
    measurement = {
        "track_counts": True,
        "stats_reset": "reset",
        "server_start": "started",
        "relations": [["public", "records", 1, 2, 3, 4, 5]],
        "sequences": [["public", "sequence", 6]],
        "catalogue_digest": raw_digest(catalogue),
    }
    proof = SimpleNamespace(
        fence_id="old-nonce",
        prior_grants=(("", "CONNECT", False, "owner"),),
        digest=lambda: "current-proof",
    )
    original = SimpleNamespace(
        prior_grants=proof.prior_grants, digest=lambda: "original"
    )
    target_raw = b"target descriptor"
    old = {
        "host": "host",
        "database": "cp",
        "database_oid": 42,
        "cluster_system_identifier": "123",
        "source": {"heads": ["source-six"]},
        "target": {
            "heads": [f"target-{i}" for i in range(7)],
            "raw_descriptor_digest": raw_digest(target_raw),
        },
    }
    context = SimpleNamespace(
        request=old,
        proof=proof,
        original_proof=original,
        context_digest="context",
        measurement=measurement,
    )
    request = {
        **deepcopy(old),
        "schema": "dotmac.cp_committed_migration_request/1",
        "operator_revision": "f" * 40,
        "basis": {
            "context_digest": "context",
            "current_fence_digest": "current-proof",
            "current_fence_id": "old-nonce",
            "original_fence_digest": "original",
            "frontier_measurement_digest": raw_digest(canonical_json(measurement)),
        },
    }
    host = module.ExistingCpTransitionHost(
        replace(config(tmp_path), operator_revision="f" * 40),
        store=ArtifactStore(tmp_path),
        recovery={},
        committed_context=context,
    )
    actions = []
    connection = SimpleNamespace(
        execute=lambda *a, **k: SimpleNamespace(all=lambda: [])
    )
    monkeypatch.setattr(host, "_connect", lambda *a, **k: nullcontext(connection))
    monkeypatch.setattr(host, "_identity", lambda *a: actions.append("identity"))
    monkeypatch.setattr(host, "_check_fence_baseline", lambda *a: actions.append("acl"))
    monkeypatch.setattr(host, "_http", lambda *a, **k: actions.append("503"))
    monkeypatch.setattr(host, "_inspect_installation", lambda *a: None)
    monkeypatch.setattr(host, "_strict", lambda *a: actions.append("strict"))
    monkeypatch.setattr(module, "_read_protected", lambda *a: target_raw)
    monkeypatch.setattr(
        module, "read_current_migration_heads", lambda *a: old["target"]["heads"]
    )
    monkeypatch.setattr(
        module.candidate_roles,
        "require_planned_target_only_connect",
        lambda *a, **k: actions.append("forecast"),
    )

    def measure(*a):
        result = deepcopy(measurement)
        result.pop("catalogue_digest")
        result["catalogue_bytes"] = catalogue
        return result

    monkeypatch.setattr(module, "measure_candidate_quiescence", measure)
    monkeypatch.setattr(host, "_source_image_identity", lambda *a: "incumbent")
    monkeypatch.setattr(
        host,
        "_writers",
        lambda: [
            {
                "Image": "incumbent",
                "State": {"Running": False},
                "HostConfig": {"RestartPolicy": {"Name": "no"}},
            }
        ],
    )
    monkeypatch.setattr(host, "_docker", lambda *a, **k: "")
    monkeypatch.setattr(
        host, "_source_matches", lambda *a: pytest.fail("source reobserved")
    )
    monkeypatch.setattr(host, "_run", lambda *a, **k: pytest.fail("mutation attempted"))
    return host, request, context, actions


def test_current_seven_heads_admitted_without_source_observation(committed):
    host, request, context, actions = committed
    assert module.read_json(host.inspect_committed(request, context)) == {
        "source": request["source"],
        "target": request["target"],
    }
    assert host._request is request
    assert actions == ["503", "identity", "acl", "forecast", "strict"]


@pytest.mark.parametrize(
    "field",
    [
        "track_counts",
        "stats_reset",
        "server_start",
        "relations",
        "sequences",
        "catalogue_digest",
    ],
)
def test_every_measurement_field_is_bound(committed, field):
    host, request, context, _ = committed
    context.measurement = {**context.measurement, field: "drift"}
    with pytest.raises(ContractError, match="committed_measurement_drift"):
        host.inspect_committed(request, context)
    assert host._request is None


def test_signed_measurement_digest_is_independently_required(committed):
    host, request, context, _ = committed
    request["basis"]["frontier_measurement_digest"] = "wrong"
    with pytest.raises(ContractError, match="committed_measurement_drift"):
        host.inspect_committed(request, context)


def test_operator_revision_is_independent_from_application_revision(committed):
    host, request, context, actions = committed
    request["operator_revision"] = "a" * 40
    with pytest.raises(ContractError, match="operator_revision_mismatch"):
        host.inspect_committed(request, context)
    assert actions == []


def test_other_database_connect_refuses_before_image_or_fence_operations(
    committed, monkeypatch
):
    host, request, context, actions = committed

    def forecast(*a, **k):
        raise module.candidate_roles.CandidateRoleRefused("another database")

    monkeypatch.setattr(
        module.candidate_roles, "require_planned_target_only_connect", forecast
    )
    monkeypatch.setattr(
        host, "_source_image_identity", lambda *a: pytest.fail("image inspected")
    )
    monkeypatch.setattr(
        module.transition_fence,
        "fence_writers",
        lambda *a, **k: pytest.fail("fence changed"),
    )
    with pytest.raises(module.candidate_roles.CandidateRoleRefused):
        host.inspect_committed(request, context)
    assert actions == ["503", "identity", "acl"]


@pytest.mark.parametrize(
    "drift", ["heads", "running", "restart", "candidate", "lineage"]
)
def test_current_state_drift_refuses(committed, monkeypatch, drift):
    host, request, context, _ = committed
    if drift == "heads":
        monkeypatch.setattr(
            module, "read_current_migration_heads", lambda *a: ["source-six"]
        )
    elif drift in {"running", "restart"}:
        monkeypatch.setattr(
            host,
            "_writers",
            lambda: [
                {
                    "Image": "incumbent",
                    "State": {"Running": drift == "running"},
                    "HostConfig": {
                        "RestartPolicy": {
                            "Name": "always" if drift == "restart" else "no"
                        }
                    },
                }
            ],
        )
    elif drift == "candidate":
        monkeypatch.setattr(host, "_docker", lambda *a: "candidate-id")
    else:
        context.original_proof.prior_grants = ()
    with pytest.raises(ContractError):
        host.inspect_committed(request, context)
    assert host._request is None


def test_rebind_uses_public_owner_with_pinned_prior_and_fresh_nonce(
    committed, monkeypatch
):
    host, request, context, actions = committed
    host.inspect_committed(request, context)
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    rebound = SimpleNamespace(to_document=lambda: {"rebound": True})

    def fence(connection, **kwargs):
        assert kwargs["prior"] is context.proof
        assert kwargs["expected_prior_fence_id"] == "old-nonce"
        assert kwargs["fence_id"] == "fresh-nonce"
        actions.append("rebind")
        return rebound

    monkeypatch.setattr(module.transition_fence, "fence_writers", fence)
    monkeypatch.setattr(host.store, "put", lambda *a: "retained")
    evidence = module.read_json(host.rebind_committed(request, "fresh-nonce", context))
    assert evidence["kind"] == "committed-rebound"
    assert actions.index("forecast") < actions.index("rebind")
    assert host.proof is rebound


def test_rebind_rechecks_measurement_immediately_before_mutation(
    committed, monkeypatch
):
    host, request, context, _ = committed
    host.inspect_committed(request, context)
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    original = module.measure_candidate_quiescence
    reads = []

    def measure(connection):
        result = original(connection)
        reads.append(True)
        if len(reads) == 2:
            result["server_start"] = "restarted"
        return result

    monkeypatch.setattr(module, "measure_candidate_quiescence", measure)
    monkeypatch.setattr(
        module.transition_fence,
        "fence_writers",
        lambda *a, **k: pytest.fail("mutated after drift"),
    )
    with pytest.raises(ContractError, match="committed_measurement_drift"):
        host.rebind_committed(request, "fresh-nonce", context)
    assert len(reads) == 2


def test_held_and_committed_contexts_are_mutually_exclusive(committed):
    host, _, context, _ = committed
    with pytest.raises(ContractError, match="continuation_contexts_mutually_exclusive"):
        module.ExistingCpTransitionHost(
            host.config,
            store=host.store,
            recovery={},
            held_fence=SimpleNamespace(proof=context.proof),
            committed_context=context,
        )


def test_candidate_uses_historical_recovery_accessor_without_rekeying(
    committed, monkeypatch
):
    host, request, context, _ = committed
    old_key = module.request_digest(context.request)
    historical = {old_key: object()}
    accessed = []

    def recovery_context():
        accessed.append(True)
        return historical

    context.recovery_context = recovery_context
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    monkeypatch.setattr(host, "_strict", lambda *a: context.proof)
    monkeypatch.setattr(host, "target_heads", lambda *a: b"heads")
    monkeypatch.setattr(host, "_quiescence_snapshot", lambda *a: b"snapshot")
    monkeypatch.setattr(host, "_retain", lambda *a: "retained")

    def before_candidate_mutation(*a):
        raise RuntimeError("recovery admitted")

    monkeypatch.setattr(
        host, "_materialize_candidate_environment", before_candidate_mutation
    )
    with pytest.raises(RuntimeError, match="recovery admitted"):
        host.candidate_ready(request, "fresh-nonce")
    assert accessed == [True]
    assert list(historical) == [old_key]
    assert host.recovery == {}
    assert module.request_digest(request) not in historical


def test_candidate_failure_reuses_cleanup_and_preserves_committed_heads_and_lineage(
    committed, monkeypatch
):
    host, request, context, actions = committed
    heads = deepcopy(request["target"]["heads"])
    grants = context.proof.prior_grants
    host._candidate_created = True
    host.candidate_phase = module.CandidateReadinessPhase.PASSWORD_INSTALL
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    monkeypatch.setattr(host, "_maintenance", lambda: actions.append("maintenance"))

    def cleanup(*a):
        actions.append("owned-candidate-cleanup")
        host._candidate_created = False
        host._candidate_started = False

    monkeypatch.setattr(host, "close_candidate_and_refence", cleanup)

    def refence(connection, **kwargs):
        assert kwargs["prior"].prior_grants == grants
        assert kwargs["expected_prior_fence_id"] == "old-nonce"
        actions.append("refence")
        return context.proof

    monkeypatch.setattr(module.transition_fence, "fence_writers", refence)
    result = module.read_json(
        host.fail_closed(request, "fresh-nonce", acl_may_be_restored=False)
    )
    assert result["kind"] == "failure"
    assert request["target"]["heads"] == heads
    assert host.proof.prior_grants == grants
    assert not host._candidate_created and not host._candidate_started
    assert actions.index("owned-candidate-cleanup") < actions.index("refence")
    assert host.candidate_phase is module.CandidateReadinessPhase.PASSWORD_INSTALL


def test_routing_verification_receives_both_runtime_contexts(committed, monkeypatch):
    host, request, context, _ = committed
    receipt = b"distinct committed receipt"
    checksum = raw_digest(receipt)
    host._request = request
    host._nonce = "fresh-nonce"
    calls = []

    def verify(raw, **kwargs):
        assert raw == receipt
        assert kwargs["context"] is context
        assert kwargs["request"] is request
        assert kwargs["host_nonce"] == "fresh-nonce"
        assert kwargs["routing_gate"] is True
        calls.append("both-contexts")

    monkeypatch.setattr(module, "verify_any_receipt", verify)
    monkeypatch.setattr(host.store, "read", lambda *a, **k: receipt)
    monkeypatch.setattr(host, "_full_runtime", lambda *a: calls.append("runtime"))
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    host.verify_pre_routing(receipt)
    assert host._routing_receipt == checksum
    assert calls == ["both-contexts", "runtime"]


def test_renamed_candidate_is_refused_by_compose_project_label(committed, monkeypatch):
    host, request, context, _ = committed
    monkeypatch.setattr(
        host,
        "_docker",
        lambda *argv: "renamed-id"
        if argv[-1] == "label=com.docker.compose.project"
        else "",
    )
    monkeypatch.setattr(
        host,
        "_container",
        lambda *a: {
            "Config": {"Labels": {"com.docker.compose.project": "vcp-d16-old"}}
        },
    )
    with pytest.raises(ContractError, match="committed_candidate_containers_present"):
        host.inspect_committed(request, context)


@pytest.mark.parametrize("subject", ["roles", "sessions"])
def test_candidate_database_resources_refuse_read_only(committed, monkeypatch, subject):
    host, request, context, _ = committed

    def execute(query):
        planted = "pg_roles" if subject == "roles" else "pg_stat_activity"
        return SimpleNamespace(
            all=lambda: [("candidate",)] if planted in str(query) else []
        )

    monkeypatch.setattr(
        host, "_connect", lambda *a, **k: nullcontext(SimpleNamespace(execute=execute))
    )
    with pytest.raises(ContractError, match=f"committed_candidate_{subject}_present"):
        host.inspect_committed(request, context)


def test_v1_routing_propagates_historical_continuation_registry(committed, monkeypatch):
    old_host, _, context, _ = committed
    registry = {context.context_digest: context}
    host = module.ExistingCpTransitionHost(
        old_host.config, store=old_host.store, recovery={}, committed_contexts=registry
    )
    request = {**context.request, "schema": "dotmac.cp_transition_request/1"}
    host._request = request
    host._nonce = "later-v1-nonce"
    receipt = b"v1 following continuation"

    def verify(raw, **kwargs):
        assert kwargs["request"] is request
        assert kwargs["context"] is None
        assert kwargs["committed_contexts"] == registry
        assert kwargs["committed_contexts"][context.context_digest] is context

    monkeypatch.setattr(module, "verify_any_receipt", verify)
    monkeypatch.setattr(host.store, "read", lambda *a, **k: receipt)
    monkeypatch.setattr(host, "_full_runtime", lambda *a: None)
    monkeypatch.setattr(host, "_bound", lambda *a: None)
    host.verify_pre_routing(receipt)
    assert host._routing_receipt == raw_digest(receipt)


def test_current_continuation_context_cannot_conflict_with_registry(committed):
    host, _, context, _ = committed
    with pytest.raises(ContractError, match="committed_context_registry_conflict"):
        module.ExistingCpTransitionHost(
            host.config,
            store=host.store,
            recovery={},
            committed_context=context,
            committed_contexts={context.context_digest: object()},
        )
    assert host._committed_contexts == {context.context_digest: context}
