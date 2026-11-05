"""Finite adjudication preserves history and requires an exact present boundary.

Synthetic protected-verifier fixtures exercise source contracts, never authority
for a host or acceptance of a real historical interval.
"""

# ruff: noqa: F811 - imported pytest fixtures intentionally retain owner names
from __future__ import annotations

import copy
import shutil
from dataclasses import replace
from datetime import timedelta

import pytest
from test_cp_committed_continuation import committed, fresh_store  # noqa: F401
from test_cp_failed_candidate_recovery import failed, failed_v1  # noqa: F401
from test_cp_post_acl_recovery import (
    PostAclHost,
    post_acl,  # noqa: F401
    run_post_acl,
    sign,
)
from test_cp_transition import request, store, trust  # noqa: F401

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, digest
from vendor_cp.deployment import cp_transition as cp


def adjudication_for(historical, present):
    return {
        "schema": "dotmac.cp_heartbeat_drift_adjudication/1",
        "acknowledgement": "HISTORICAL_INTERVAL_NOT_ATTRIBUTED",
        "historical_measurement_digest": digest(historical),
        "present_measurement_digest": digest(present),
        "permitted_difference": {
            "schema": "public",
            "relation": "relay_heartbeats",
            "relation_identity_digest": digest(["public", "relay_heartbeats"]),
            "counter": "n_tup_upd",
            "direction": "increase",
        },
        "current_heartbeat": {"row_count": 1, "rowset_digest": digest({"rowset": 1})},
        "evidence": {
            "qualification_assessment_digest": digest({"qualified": "end-state-only"}),
            "comparison_digest": digest({"comparison": "supporting"}),
            "decoder_result_digest": digest({"decoder": "synthetic"}),
        },
        "unavailable_assurance": {
            key: False for key in cp.UnavailableHistoricalAssuranceV1.__annotations__
        },
    }


@pytest.fixture
def adjudicated(post_acl, trust):
    historical, value, now, verifier, path = post_acl
    present = copy.deepcopy(historical.measurement)
    heartbeat = next(
        row for row in present["relations"] if row[:2] == ["public", "relay_heartbeats"]
    )
    heartbeat[5] += 3  # A counter increase is never asserted to be one write.
    ruling = adjudication_for(historical.measurement, present)
    context = cp.AdjudicatedPostAclRecoveryContext(
        historical=historical,
        adjudication=ruling,
        present_measurement=present,
        context_digest=digest(
            {
                "schema": "dotmac.cp_adjudicated_post_acl_recovery_context/1",
                "historical_context": {
                    "path": "/synthetic/history.json",
                    "digest": historical.context_digest,
                },
                "adjudication": ruling,
                "present_measurement": present,
            }
        ),
    )
    value = copy.deepcopy(value)
    value.update(
        schema="dotmac.cp_adjudicated_post_acl_request/1",
        basis=cp.adjudicated_post_acl_basis(context),
        adjudication=ruling,
    )
    value["plan_digest"] = cp.transition_plan_digest(value)
    sign(value, trust, path)
    return context, value, now, verifier, path


class AdjudicatedHost(PostAclHost):
    def inspect_adjudicated_post_acl_recovery(self, request, context):
        self.request = request
        self.events.append("inspect-present")
        return canonical_json(
            {
                "source": request["source"],
                "target": request["target"],
                "measurement": context.present_measurement,
                "heartbeat_rowset_digest": context.adjudication["current_heartbeat"][
                    "rowset_digest"
                ],
                "heartbeat_row_count": 1,
            }
        )

    def stop_and_drain_writers(self, request, nonce):
        self.request, self.nonce = request, nonce
        self.context.historical.prior_store.read(
            cp.post_acl_recovery_frontier_key(self.context.historical),
            kind="reservation",
        )
        return self.envelope(
            "writers-stopped", {"running_writers": [], "restart_enabled": []}
        )

    def rebind_adjudicated_post_acl_recovery(self, request, nonce, context):
        return self.envelope(
            "adjudicated-post-acl-rebound",
            {
                "prior_fence_id": context.historical.proof.fence_id,
                "fence_id": nonce,
                "original_fence_digest": context.historical.original_proof.digest(),
                "current_fence_digest": context.historical.proof.digest(),
                "historical_measurement_digest": digest(context.historical.measurement),
                "present_measurement_digest": digest(context.present_measurement),
                "adjudication_digest": digest(context.adjudication),
                "measurement": context.present_measurement,
                "heartbeat_rowset_digest": context.adjudication["current_heartbeat"][
                    "rowset_digest"
                ],
                "heartbeat_row_count": 1,
            },
        )

    def close_candidate_and_refence(self, request, nonce):
        measured = self.context.present_measurement
        self.store.put(
            self.context.historical.prior_store.read(measured["catalogue_digest"])
        )
        snapshot = self.store.put(
            canonical_json(
                {
                    "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
                    "request_digest": cp.request_digest(request),
                    "host_nonce": nonce,
                    "measurement": measured,
                }
            )
        )
        quiescence = self.store.put(
            canonical_json(
                {
                    "schema": "dotmac.cp_candidate_quiescence/1",
                    "request_digest": cp.request_digest(request),
                    "host_nonce": nonce,
                    "before_digest": snapshot,
                    "after_digest": snapshot,
                }
            )
        )
        return self.envelope(
            "candidate-removed-fenced",
            {
                "candidate_sessions": 0,
                "candidate_roles": [],
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
                "quiescence_digest": quiescence,
            },
        )

    def verify_pre_routing(self, raw):
        cp.verify_any_receipt(
            raw,
            store=self.store,
            request=self.request,
            host_nonce=self.nonce,
            recovery={},
            routing_gate=True,
            post_acl_contexts={self.context.context_digest: self.context},
        )
        return self.envelope(
            "pre-routing-verified", {"receipt_digest": cp.raw_digest(raw)}
        )


def run(
    adjudicated, *, name="adjudicated-success", fail=None, host_type=AdjudicatedHost
):
    context, value, now, verifier, path = adjudicated
    fresh = fresh_store(context.historical.original, name)
    host = host_type(context, fresh, fail=fail)
    result = cp.execute_adjudicated_post_acl_recovery(
        canonical_json(value),
        request_path=path,
        bundle_path=None,
        verifier=verifier,
        host=host,
        store=fresh,
        recovery={},
        context=context,
        clock=lambda: now,
    )
    return fresh, host, result


def test_exact_present_success_keeps_historical_measurement_and_unavailable_assurance(
    adjudicated,
):
    context, value, *_ = adjudicated
    before = canonical_json(context.historical.measurement)
    inventory = {
        p.name: p.read_bytes() for p in context.historical.prior_store.root.iterdir()
    }
    cp.verify_adjudicated_post_acl_frontier(context, value)
    fresh, host, result = run(adjudicated)
    receipt = cp.verify_any_receipt(
        fresh.read(result, kind="receipt"),
        store=fresh,
        request=value,
        host_nonce=host.nonce,
        recovery={},
        routing_gate=True,
        post_acl_contexts={context.context_digest: context},
    )
    assert receipt["phase"] == "complete"
    assert receipt["historical_context_digest"] == context.historical.context_digest
    assert receipt["adjudicated_context_digest"] == context.context_digest
    assert (
        receipt["historical_measurement_digest"]
        != receipt["present_measurement_digest"]
    )
    assert all(flag is False for flag in receipt["unavailable_assurance"].values())
    assert canonical_json(context.historical.measurement) == before
    assert all(
        (context.historical.prior_store.root / name).read_bytes() == raw
        for name, raw in inventory.items()
    )
    assert (
        len(list(context.historical.prior_store.root.iterdir())) == len(inventory) + 1
    )
    assert host.events.count("inspect-present") == 2
    assert host.events.index("writers-stopped") < host.events.index(
        "adjudicated-post-acl-rebound"
    )
    assert host.events.index("pre-routing-verified") < host.events.index(
        "routing-restored"
    )


@pytest.mark.parametrize(
    "field", list(cp.UnavailableHistoricalAssuranceV1.__annotations__)
)
def test_unavailable_assurance_cannot_be_promoted_to_proof(adjudicated, field):
    context, value, now, verifier, _ = adjudicated
    crossed = copy.deepcopy(value)
    crossed["adjudication"]["unavailable_assurance"][field] = True
    crossed["plan_digest"] = cp.transition_plan_digest(crossed)
    with pytest.raises(ContractError):
        cp.validate_adjudicated_post_acl_request(
            crossed, identity=verifier.policy.identity, now=now
        )
    with pytest.raises(ContractError):
        cp.verify_adjudicated_post_acl_frontier(
            replace(context, adjudication=crossed["adjudication"]), crossed
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-ack",
        "wrong-ack",
        "extra",
        "relation",
        "counter",
        "direction",
        "row-count",
        "rowset",
        "historical",
        "present",
        "supporting",
    ],
)
def test_closed_adjudication_and_crossed_bindings_refuse(adjudicated, mutation):
    context, value, now, verifier, _ = adjudicated
    crossed = copy.deepcopy(value)
    ruling = crossed["adjudication"]
    if mutation == "missing-ack":
        del ruling["acknowledgement"]
    elif mutation == "wrong-ack":
        ruling["acknowledgement"] = "HARMLESS"
    elif mutation == "extra":
        ruling["warning_waiver"] = True
    elif mutation in {"relation", "counter", "direction"}:
        ruling["permitted_difference"][mutation] = "different"
    elif mutation == "row-count":
        ruling["current_heartbeat"]["row_count"] = 2
    elif mutation == "rowset":
        ruling["current_heartbeat"]["rowset_digest"] = digest({"crossed": mutation})
    elif mutation in {"historical", "present"}:
        ruling[mutation + "_measurement_digest"] = digest({"crossed": mutation})
    else:
        ruling["evidence"]["comparison_digest"] = digest({"crossed": mutation})
    crossed["plan_digest"] = cp.transition_plan_digest(crossed)
    with pytest.raises(ContractError):
        cp.verify_adjudicated_post_acl_frontier(context, crossed)
    if mutation != "supporting":
        with pytest.raises(ContractError):
            cp.validate_adjudicated_post_acl_request(
                crossed, identity=verifier.policy.identity, now=now
            )


@pytest.mark.parametrize(
    "mutation",
    [
        "reset",
        "restart",
        "catalogue",
        "sequence",
        "storage",
        "identity",
        "insert",
        "delete",
        "other-update",
        "duplicate",
        "missing",
        "extra-relation",
        "bool-counter",
        "negative-counter",
        "decrease",
        "same",
    ],
)
def test_complete_measurement_difference_has_one_exact_increased_cell(
    adjudicated, mutation
):
    context, *_ = adjudicated
    present = copy.deepcopy(context.present_measurement)
    if mutation == "reset":
        present["stats_reset"] = "2026-11-05T00:00:00Z"
    elif mutation == "restart":
        present["server_start"] = "2026-11-05T00:00:00Z"
    elif mutation == "catalogue":
        present["catalogue_digest"] = digest({"different": "catalogue"})
    elif mutation == "sequence":
        present["sequences"] = [["public", "new_sequence", 1]]
    elif mutation in {
        "storage",
        "identity",
        "insert",
        "delete",
        "bool-counter",
        "negative-counter",
        "decrease",
        "same",
    }:
        row = present["relations"][1]
        field = {"storage": 3, "identity": 2, "insert": 4, "delete": 6}.get(mutation, 5)
        row[field] = (
            False
            if mutation == "bool-counter"
            else -1
            if mutation in {"negative-counter", "decrease"}
            else 0
            if mutation == "same"
            else 99
        )
    elif mutation == "other-update":
        present["relations"][0][5] += 1
    elif mutation == "duplicate":
        present["relations"].append(copy.deepcopy(present["relations"][1]))
    elif mutation == "missing":
        present["relations"].pop(0)
    else:
        present["relations"].append(["public", "z_new_relation", 3, 3, 0, 0, 0])
    ruling = adjudication_for(context.historical.measurement, present)
    with pytest.raises(ContractError):
        cp.validate_heartbeat_drift_adjudication(
            ruling,
            historical_measurement=context.historical.measurement,
            present_measurement=present,
        )


@pytest.mark.parametrize("when", ["before-claim", "after-stop", "rebound"])
@pytest.mark.parametrize("dimension", ["measurement", "rowset", "row-count"])
def test_present_movement_refuses_before_candidate(adjudicated, when, dimension):
    instances = []

    class MovingHost(AdjudicatedHost):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)
            self.inspections = 0

        def move(self, document):
            if dimension == "measurement":
                document["measurement"]["relations"][1][5] += 1
            elif dimension == "rowset":
                document["heartbeat_rowset_digest"] = digest({"later": "rowset"})
            else:
                document["heartbeat_row_count"] = 0
            return document

        def inspect_adjudicated_post_acl_recovery(self, request, context):
            document = cp.read_json(
                super().inspect_adjudicated_post_acl_recovery(request, context)
            )
            self.inspections += 1
            if (when == "before-claim" and self.inspections == 1) or (
                when == "after-stop" and self.inspections == 2
            ):
                self.move(document)
            return canonical_json(document)

        def rebind_adjudicated_post_acl_recovery(self, request, nonce, context):
            document = cp.read_json(
                super().rebind_adjudicated_post_acl_recovery(request, nonce, context)
            )
            if when == "rebound":
                self.move(document["result"])
            return canonical_json(document)

    context, *_ = adjudicated
    with pytest.raises(ContractError):
        run(adjudicated, host_type=MovingHost)
    host = instances[0]
    assert "candidate-ready" not in host.events
    assert ("failure" in host.events) == (when != "before-claim")
    if when == "after-stop":
        assert "adjudicated-post-acl-rebound" not in host.events
    claim = context.historical.prior_store.root / context.historical.prior_store._name(
        cp.post_acl_recovery_frontier_key(context.historical), "reservation"
    )
    assert claim.exists() == (when != "before-claim")


@pytest.mark.parametrize(
    "failure",
    [
        "writers-stopped",
        "adjudicated-post-acl-rebound",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "full-ready",
        "pre-routing-verified",
        "routing-restored",
    ],
)
def test_failure_consumes_single_shared_attempt_and_compensates(adjudicated, failure):
    context, value, *_ = adjudicated
    with pytest.raises(RuntimeError, match=failure):
        run(adjudicated, fail=failure)
    context.historical.prior_store.read(
        cp.post_acl_recovery_frontier_key(context.historical), kind="reservation"
    )
    with pytest.raises(ContractError):
        cp.verify_adjudicated_post_acl_frontier(context, value)


@pytest.mark.parametrize("protocol_first", ["strict", "adjudicated"])
def test_once_only_domain_is_shared_across_protocols(
    adjudicated, post_acl, protocol_first, trust
):
    context, value, *_ = adjudicated
    if protocol_first == "strict":
        _, strict, _, _, path = post_acl
        sign(strict, trust, path)
        run_post_acl(post_acl)
        with pytest.raises(ContractError):
            cp.verify_adjudicated_post_acl_frontier(context, value)
    else:
        run(adjudicated)
        historical, strict, *_ = post_acl
        with pytest.raises(ContractError):
            cp.verify_post_acl_recovery_frontier(historical, strict)


def test_context_store_and_fresh_authorization_cannot_create_another_attempt(
    adjudicated, trust
):
    context, value, now, verifier, path = adjudicated
    run(adjudicated)
    sibling = replace(context, context_digest=digest({"different": "context"}))
    sibling_request = copy.deepcopy(value)
    sibling_request.update(
        authorization_run_id=902, basis=cp.adjudicated_post_acl_basis(sibling)
    )
    sibling_request["plan_digest"] = cp.transition_plan_digest(sibling_request)
    sign(sibling_request, trust, path)
    with pytest.raises(ContractError):
        run((sibling, sibling_request, now, verifier, path), name="second-intent")
    clone_root = (
        context.historical.prior_store.root.parent.parent
        / "cloned-adjudication"
        / "artifact-store"
    )
    shutil.copytree(context.historical.prior_store.root, clone_root)
    cloned = replace(
        context,
        historical=replace(
            context.historical, prior_store=cp.ArtifactStore(clone_root)
        ),
    )
    with pytest.raises(ContractError, match="post_acl_canonical_store_mismatch"):
        cloned.historical.prior_store.reserve_adjudicated_post_acl_frontier(
            cloned,
            value,
            host_nonce="f" * 64,
            fresh_reservation_digest=digest({"fresh": 1}),
        )


def test_expired_authorization_and_strict_schema_substitution_refuse(adjudicated):
    context, value, now, verifier, _ = adjudicated
    with pytest.raises(ContractError, match="expired"):
        cp.validate_adjudicated_post_acl_request(
            value, identity=verifier.policy.identity, now=now + timedelta(days=2)
        )
    with pytest.raises(ContractError):
        cp.validate_post_acl_recovery_request(
            value, identity=verifier.policy.identity, now=now
        )
    with pytest.raises(ContractError):
        cp.verify_post_acl_recovery_frontier(context, value)


@pytest.mark.parametrize(
    "field",
    [
        "historical_context_digest",
        "adjudicated_context_digest",
        "historical_measurement_digest",
        "present_measurement_digest",
        "current_heartbeat_rowset_digest",
        "adjudication_digest",
        "unavailable_assurance",
        "adjudicated-post-acl-rebound",
        "inspection",
    ],
)
def test_receipt_does_not_cross_or_erase_prospective_boundary(adjudicated, field):
    context, value, *_ = adjudicated
    fresh, host, result = run(adjudicated)
    document = cp.read_json(fresh.read(result, kind="receipt"))
    if field in document["evidence"]:
        del document["evidence"][field]
    elif field == "unavailable_assurance":
        document[field]["harmlessness_proven"] = True
    else:
        document[field] = digest({"crossed": field})
    with pytest.raises(ContractError):
        cp.verify_adjudicated_post_acl_receipt(
            canonical_json(document),
            store=fresh,
            request=value,
            host_nonce=host.nonce,
            recovery={},
            context=context,
            routing_gate=True,
        )


def test_receipt_registry_rejects_crossed_context_types(adjudicated):
    context, value, *_ = adjudicated
    fresh, host, result = run(adjudicated)
    with pytest.raises(ContractError, match="adjudication_context_missing"):
        cp.verify_any_receipt(
            fresh.read(result, kind="receipt"),
            store=fresh,
            request=value,
            host_nonce=host.nonce,
            recovery={},
            post_acl_contexts={context.context_digest: context.historical},
        )


def test_strict_path_still_refuses_this_reviewed_present_drift(
    adjudicated, post_acl, trust
):
    adjudicated_context, *_ = adjudicated
    historical, strict, _, _, path = post_acl
    sign(strict, trust, path)
    hosts = []

    class StrictPresentHost(PostAclHost):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            hosts.append(self)

        def inspect_post_acl_recovery(self, request, context):
            observed = cp.read_json(super().inspect_post_acl_recovery(request, context))
            observed["measurement"] = adjudicated_context.present_measurement
            return canonical_json(observed)

    with pytest.raises(ContractError, match="post_acl_measurement_mismatch"):
        run_post_acl(post_acl, host_type=StrictPresentHost)
    assert hosts[0].events == ["inspect"]
    assert not (
        historical.prior_store.root
        / historical.prior_store._name(
            cp.post_acl_recovery_frontier_key(historical), "reservation"
        )
    ).exists()


@pytest.mark.parametrize(
    "record",
    [
        "ancestor-claim",
        "latest-authorization",
        "latest-cleanup",
        "latest-pre-receipt",
        "latest-fence",
        "latest-snapshot",
    ],
)
def test_adjudication_cannot_omit_or_replace_retained_history(adjudicated, record):
    context, value, *_ = adjudicated
    historical = context.historical
    if record == "ancestor-claim":
        owner = historical.predecessor.prior_store
        checksum, kind = (
            cp.failed_candidate_frontier_key(historical.predecessor),
            "reservation",
        )
    elif record == "latest-authorization":
        owner = historical.prior_store
        checksum, kind = (
            cp.raw_digest(historical.historical_authorization.verification_bytes),
            "evidence",
        )
    elif record == "latest-cleanup":
        owner = historical.prior_store
        checksum, kind = historical.evidence["candidate-removed-fenced"], "evidence"
    elif record == "latest-pre-receipt":
        owner = historical.prior_store
        checksum, kind = historical.pre_routing_receipt_digest, "receipt"
    elif record == "latest-fence":
        owner = historical.prior_store
        checksum, kind = historical.proof.digest(), "evidence"
    else:
        owner = historical.prior_store
        checksum, kind = (
            cp.read_json(owner.read(historical.quiescence_digest))["after_digest"],
            "evidence",
        )
    (owner.root / owner._name(checksum, kind)).unlink()
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_adjudicated_post_acl_frontier(context, value)


@pytest.mark.parametrize(
    "boundary",
    [
        "claim-create",
        "claim-readback",
        "owned-frontier",
        "inspection-retain",
        "authorization-retain",
    ],
)
def test_prehost_failures_never_run_compensation_or_suffix(
    adjudicated, monkeypatch, boundary
):
    context, value, now, verifier, path = adjudicated
    fresh = fresh_store(context.historical.original, "prehost-" + boundary)
    host = AdjudicatedHost(context, fresh)
    if boundary in {"claim-create", "claim-readback"}:
        real = cp.ArtifactStore.reserve_adjudicated_post_acl_frontier

        def fail_claim(self, *args, **kwargs):
            if boundary == "claim-readback":
                real(self, *args, **kwargs)
            raise RuntimeError(boundary)

        monkeypatch.setattr(
            cp.ArtifactStore, "reserve_adjudicated_post_acl_frontier", fail_claim
        )
    elif boundary == "owned-frontier":
        real = cp.verify_adjudicated_post_acl_frontier

        def fail_owned(*args, **kwargs):
            real(*args, **kwargs)
            if kwargs.get("owned_successor_claim") is not None:
                raise RuntimeError(boundary)

        monkeypatch.setattr(cp, "verify_adjudicated_post_acl_frontier", fail_owned)
    else:
        real = cp.ArtifactStore.put
        failed_kind = boundary.removesuffix("-retain")

        def fail_put(self, raw, **kwargs):
            if self is fresh and f'"kind":"{failed_kind}"'.encode() in raw:
                raise RuntimeError(boundary)
            return real(self, raw, **kwargs)

        monkeypatch.setattr(cp.ArtifactStore, "put", fail_put)
    with pytest.raises(RuntimeError, match=boundary):
        cp.execute_adjudicated_post_acl_recovery(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=fresh,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert host.events == ["inspect-present"]


def test_complete_adjudicated_receipt_can_anchor_next_ordinary_transition(adjudicated):
    context, value, *_ = adjudicated
    fresh, _, result = run(adjudicated)
    future = request()
    future["source"] = value["target"]
    future["previous_receipt_digest"] = result
    cp.verify_predecessor(
        future,
        store=fresh,
        recovery={},
        post_acl_contexts={context.context_digest: context},
    )
    with pytest.raises(ContractError, match="adjudication_context_missing"):
        cp.verify_predecessor(future, store=fresh, recovery={})


def test_strict_receipt_registry_cannot_consume_adjudicated_context(
    adjudicated, post_acl, trust
):
    context, *_ = adjudicated
    historical, strict, _, _, path = post_acl
    sign(strict, trust, path)
    fresh, host, result = run_post_acl(post_acl)
    with pytest.raises(ContractError, match="post_acl_context_missing"):
        cp.verify_any_receipt(
            fresh.read(result, kind="receipt"),
            store=fresh,
            request=strict,
            host_nonce=host.nonce,
            recovery={},
            post_acl_contexts={historical.context_digest: context},
        )


def test_cleanup_cannot_return_to_historical_snapshot_before_acl(adjudicated):
    hosts = []

    class HistoricalCleanupHost(AdjudicatedHost):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            hosts.append(self)

        def close_candidate_and_refence(self, request, nonce):
            snapshot = self.store.put(
                canonical_json(
                    {
                        "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
                        "request_digest": cp.request_digest(request),
                        "host_nonce": nonce,
                        "measurement": self.context.historical.measurement,
                    }
                )
            )
            self.store.put(
                self.context.historical.prior_store.read(
                    self.context.historical.measurement["catalogue_digest"]
                )
            )
            proof = self.store.put(
                canonical_json(
                    {
                        "schema": "dotmac.cp_candidate_quiescence/1",
                        "request_digest": cp.request_digest(request),
                        "host_nonce": nonce,
                        "before_digest": snapshot,
                        "after_digest": snapshot,
                    }
                )
            )
            return self.envelope(
                "candidate-removed-fenced",
                {
                    "candidate_sessions": 0,
                    "candidate_roles": [],
                    "writer_sessions": 0,
                    "reconnect_denial": "database_acl",
                    "quiescence_digest": proof,
                },
            )

    with pytest.raises(ContractError, match="post_acl_measurement_mismatch"):
        run(adjudicated, host_type=HistoricalCleanupHost)
    assert "candidate-ready" in hosts[0].events
    assert "acl-restored" not in hosts[0].events
    assert "failure" in hosts[0].events


def test_new_context_generation_is_closed_and_cannot_alias_historical_context(
    adjudicated,
):
    context, value, *_ = adjudicated

    class DerivedContext(cp.AdjudicatedPostAclRecoveryContext):
        pass

    derived = DerivedContext(
        context.historical,
        context.adjudication,
        context.present_measurement,
        context.context_digest,
    )
    with pytest.raises(ContractError, match="unsupported_recovery_generation"):
        cp.verify_adjudicated_post_acl_frontier(derived, value)
    aliased = replace(context, context_digest=context.historical.context_digest)
    aliased_request = copy.deepcopy(value)
    aliased_request["basis"] = cp.adjudicated_post_acl_basis(aliased)
    aliased_request["plan_digest"] = cp.transition_plan_digest(aliased_request)
    with pytest.raises(ContractError, match="adjudication_context_mismatch"):
        cp.verify_adjudicated_post_acl_frontier(aliased, aliased_request)
