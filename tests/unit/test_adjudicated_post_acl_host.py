"""Hosted-only host checks over the strict owner's transport fixture."""

# ruff: noqa: F811 - imported pytest owner fixture
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from test_cp_post_acl_host import post_acl  # noqa: F401

from vendor_cp.deploy_agent.contracts import (
    ContractError,
    canonical_json,
    digest,
    read_json,
)
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import cp_transition_host as module


@pytest.fixture
def adjudicated(post_acl, monkeypatch):
    state = post_acl
    historical = state.context
    present = deepcopy(state.measurement)
    present["relations"][0][5] += 1
    rowset = "sha256:" + "9" * 64
    adjudication = {
        "schema": "dotmac.cp_heartbeat_drift_adjudication/1",
        "acknowledgement": "HISTORICAL_INTERVAL_NOT_ATTRIBUTED",
        "permitted_difference": {
            "schema": "public",
            "relation": "relay_heartbeats",
            "relation_identity_digest": digest(["public", "relay_heartbeats"]),
            "counter": "n_tup_upd",
            "direction": "increase",
        },
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
        "historical_measurement_digest": cp.raw_digest(
            canonical_json(state.measurement)
        ),
        "present_measurement_digest": cp.raw_digest(canonical_json(present)),
        "current_heartbeat": {"row_count": 1, "rowset_digest": rowset},
    }
    context = cp.AdjudicatedPostAclRecoveryContext(
        historical, adjudication, present, "sha256:" + "8" * 64
    )
    request = deepcopy(state.request)
    request.update(
        schema="dotmac.cp_adjudicated_post_acl_request/1",
        adjudication=adjudication,
        basis={
            "context_digest": context.context_digest,
            "historical_basis": request["basis"],
            "adjudication_digest": cp.raw_digest(canonical_json(adjudication)),
            "present_measurement_digest": cp.raw_digest(canonical_json(present)),
            "current_heartbeat_rowset_digest": rowset,
        },
    )
    state.strict_request = state.request
    state.historical = historical
    state.context = context
    state.request = request
    state.measurement = deepcopy(present)
    state.rowset, state.row_count = rowset, 1
    state.host._post_acl_recovery_context = context
    state.host._post_acl_contexts[context.context_digest] = context
    monkeypatch.setattr(
        module,
        "measure_complete_heartbeat_rowset",
        lambda connection: (state.rowset, state.row_count),
    )
    return state


def test_exact_present_boundary_admitted_without_changing_historical(adjudicated):
    s = adjudicated
    old = deepcopy(s.historical.measurement)
    observed = read_json(
        s.host.inspect_adjudicated_post_acl_recovery(s.request, s.context)
    )
    assert observed == {
        "source": s.request["source"],
        "target": s.request["target"],
        "measurement": s.measurement,
        "heartbeat_rowset_digest": s.rowset,
        "heartbeat_row_count": 1,
    }
    assert s.historical.measurement == old
    assert old != s.measurement
    assert not s.retained and "stop" not in s.events
    assert all(call[0] == "ps" for call in s.docker_calls)


def test_same_live_drift_still_refuses_strict_measurement(adjudicated):
    s = adjudicated
    with pytest.raises(ContractError, match="post_acl_measurement_mismatch"):
        s.host._post_acl_measurement(None, s.strict_request, s.historical)


@pytest.mark.parametrize(
    "fault", ["rowset", "zero", "two", "extra-counter", "catalogue"]
)
def test_unreviewed_present_boundary_refuses_before_stop(adjudicated, fault):
    s = adjudicated
    if fault == "rowset":
        s.rowset = "sha256:" + "a" * 64
    elif fault in {"zero", "two"}:
        s.row_count = 0 if fault == "zero" else 2
    elif fault == "extra-counter":
        s.measurement["relations"][1][5] += 1
    else:
        s.catalogue += b"changed"
    with pytest.raises(ContractError):
        s.host.inspect_adjudicated_post_acl_recovery(s.request, s.context)
    assert not s.retained and "stop" not in s.events
    assert s.host._request is None


@pytest.mark.parametrize("fault", ["rowset", "counter", "restart"])
def test_post_stop_movement_refuses_before_fence_or_candidate(adjudicated, fault):
    s = adjudicated
    s.host.inspect_adjudicated_post_acl_recovery(s.request, s.context)
    s.core_claimed = True
    s.host.stop_and_drain_writers(s.request, s.nonce)
    if fault == "rowset":
        s.rowset = "sha256:" + "a" * 64
    elif fault == "counter":
        s.measurement["relations"][0][5] += 1
    else:
        s.measurement["server_start"] = "changed"
    with pytest.raises(ContractError):
        s.host.rebind_adjudicated_post_acl_recovery(s.request, s.nonce, s.context)
    assert not s.retained
    assert not s.host._post_acl_writers_stopped


def test_rebind_retains_both_boundaries_and_actual_rowset(adjudicated, monkeypatch):
    s = adjudicated
    s.host.inspect_adjudicated_post_acl_recovery(s.request, s.context)
    s.core_claimed = True
    s.host.stop_and_drain_writers(s.request, s.nonce)
    proof = SimpleNamespace(**vars(s.historical.proof))
    proof.fence_id = s.nonce
    proof.to_document = lambda: {"fence_id": s.nonce}
    calls = []

    def fence(connection, **kwargs):
        calls.append(kwargs)
        return proof

    monkeypatch.setattr(module.transition_fence, "fence_writers", fence)
    observed = read_json(
        s.host.rebind_adjudicated_post_acl_recovery(s.request, s.nonce, s.context)
    )
    assert observed["kind"] == "adjudicated-post-acl-rebound"
    assert observed["result"] == {
        "prior_fence_id": s.historical.host_nonce,
        "fence_id": s.nonce,
        "original_fence_digest": s.request["basis"]["historical_basis"][
            "original_fence_digest"
        ],
        "current_fence_digest": s.request["basis"]["historical_basis"][
            "current_fence_digest"
        ],
        "historical_measurement_digest": s.context.adjudication[
            "historical_measurement_digest"
        ],
        "present_measurement_digest": s.request["basis"]["present_measurement_digest"],
        "adjudication_digest": s.request["basis"]["adjudication_digest"],
        "measurement": s.measurement,
        "heartbeat_rowset_digest": s.rowset,
        "heartbeat_row_count": 1,
    }
    assert calls[0]["prior"] is s.historical.proof
    assert calls[0]["expected_prior_fence_id"] == s.historical.host_nonce
    assert s.retained == [canonical_json(proof.to_document())]


def test_context_protocol_cannot_be_crossed(adjudicated):
    s = adjudicated
    with pytest.raises(ContractError, match="post_acl_context_mismatch"):
        s.host.inspect_post_acl_recovery(s.strict_request, s.historical)
    with pytest.raises(ContractError, match="adjudicated_post_acl_context_mismatch"):
        s.host.inspect_adjudicated_post_acl_recovery(s.request, replace(s.context))


def snapshot(rows):
    return SimpleNamespace(execute=lambda statement: SimpleNamespace(all=lambda: rows))


def test_snapshot_normalizes_utc_microseconds_python_unicode_and_json_escaping():
    utc = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    offset = utc.astimezone(timezone(timedelta(hours=3)))
    rows = [["é", offset, utc, None], ["a", utc, offset, utc]]
    expected = [
        [
            "a",
            "2026-01-02T03:04:05.000000Z",
            "2026-01-02T03:04:05.000000Z",
            "2026-01-02T03:04:05.000000Z",
        ],
        ["é", "2026-01-02T03:04:05.000000Z", "2026-01-02T03:04:05.000000Z", None],
    ]
    assert module.measure_complete_heartbeat_rowset(snapshot(rows)) == (
        cp.raw_digest(canonical_json(expected)),
        2,
    )


@pytest.mark.parametrize(
    "fault", ["overflow", "duplicate", "naive", "null", "worker", "shape"]
)
def test_snapshot_refuses_incomplete_or_malformed_rows(fault):
    at = datetime(2026, 1, 2, tzinfo=UTC)
    rows = [["worker", at, at, None]]
    if fault == "overflow":
        rows = [[str(i), at, at, None] for i in range(1025)]
    elif fault == "duplicate":
        rows += rows
    elif fault == "naive":
        rows[0][1] = at.replace(tzinfo=None)
    elif fault == "null":
        rows[0][2] = None
    elif fault == "worker":
        rows[0][0] = "bad\x00worker"
    else:
        rows[0].append(None)
    with pytest.raises(ContractError):
        module.measure_complete_heartbeat_rowset(snapshot(rows))
