"""Protected authoring binds adjudicated intent without granting live authority."""

from __future__ import annotations

from datetime import timedelta

import pytest
from test_post_acl_transition_request import plan as strict_plan
from test_transition_request import NOW, REVISION, context

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_request as producer


def redigest(value):
    value["basis"]["adjudication_digest"] = cp.digest(value["adjudication"])
    value["plan_digest"] = cp.digest(
        {
            "schema": value["schema"],
            **{key: value[key] for key in cp.ADJUDICATED_POST_ACL_PLAN_FIELDS},
        }
    )


def plan():
    value = strict_plan()
    historical = value["basis"]
    present = "sha256:" + "a" * 64
    heartbeat = "sha256:" + "b" * 64
    value["schema"] = "dotmac.cp_adjudicated_post_acl_plan/1"
    value["adjudication"] = {
        "schema": "dotmac.cp_heartbeat_drift_adjudication/1",
        "acknowledgement": "HISTORICAL_INTERVAL_NOT_ATTRIBUTED",
        "historical_measurement_digest": historical["frontier_measurement_digest"],
        "present_measurement_digest": present,
        "permitted_difference": {
            "schema": "public",
            "relation": "relay_heartbeats",
            "relation_identity_digest": cp.digest(["public", "relay_heartbeats"]),
            "counter": "n_tup_upd",
            "direction": "increase",
        },
        "current_heartbeat": {"row_count": 1, "rowset_digest": heartbeat},
        "evidence": {
            "qualification_assessment_digest": "sha256:" + "c" * 64,
            "comparison_digest": "sha256:" + "d" * 64,
            "decoder_result_digest": "sha256:" + "e" * 64,
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
    value["basis"] = {
        "context_digest": "sha256:" + "9" * 64,
        "historical_basis": historical,
        "adjudication_digest": "sha256:" + "f" * 64,
        "present_measurement_digest": present,
        "current_heartbeat_rowset_digest": heartbeat,
    }
    redigest(value)
    return value


def author(value, runner=None):
    return producer.author_request(
        canonical_json(value),
        context=context() if runner is None else runner,
        expected_revision=REVISION,
        now=NOW,
    )


def test_distinct_request_binds_adjudication_and_runner_owned_identity():
    value = plan()
    request = author(value)
    assert request["schema"] == "dotmac.cp_adjudicated_post_acl_request/1"
    assert request["basis"] == value["basis"]
    assert request["adjudication"] == value["adjudication"]
    assert request["plan_digest"] == cp.transition_plan_digest(request)
    assert request["authorization_run_id"] == 123
    assert request["authorization_run_attempt"] == 2
    assert request["trusted_actor"] == producer.REPOSITORY_OWNER
    assert cp.timestamp(request["expires_at"]) == NOW + timedelta(hours=23)
    assert not any(request["adjudication"]["unavailable_assurance"].values())


@pytest.mark.parametrize(
    "field",
    [
        "authorization_run_id",
        "authorization_run_attempt",
        "trusted_actor",
        "expires_at",
    ],
)
def test_plan_cannot_supply_protected_runner_fields(field):
    value = plan()
    value[field] = "operator controlled"
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize(
    "field",
    [
        "actor_attribution_proven",
        "backup_to_retained_baseline_linkage",
        "business_row_equality_proven",
        "harmlessness_proven",
        "intermediate_writes_excluded",
        "null_claim_proves_idle_interval",
    ],
)
def test_plan_cannot_turn_policy_acknowledgment_into_forensic_proof(field):
    value = plan()
    value["adjudication"]["unavailable_assurance"][field] = True
    redigest(value)
    with pytest.raises(ContractError):
        author(value)


def test_missing_acknowledgment_refuses_even_with_consistent_hashes():
    value = plan()
    del value["adjudication"]["acknowledgement"]
    redigest(value)
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize(
    "field", ["present_measurement_digest", "historical_measurement_digest"]
)
def test_crossed_adjudication_measurements_refuse_even_with_a_new_plan_digest(field):
    value = plan()
    value["adjudication"][field] = "sha256:" + "7" * 64
    redigest(value)
    with pytest.raises(ContractError):
        author(value)


def test_current_rowset_is_bound_independently_of_full_measurement():
    value = plan()
    value["adjudication"]["current_heartbeat"]["rowset_digest"] = "sha256:" + "8" * 64
    redigest(value)
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize(
    "schema",
    ["dotmac.cp_post_acl_recovery_plan/1", "dotmac.cp_failed_candidate_plan/2"],
)
def test_new_policy_cannot_be_relabelled_as_a_strict_plan(schema):
    value = plan()
    value["schema"] = schema
    redigest(value)
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_ACTOR", "other"),
        ("GITHUB_TRIGGERING_ACTOR", "other"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_REF_PROTECTED", "false"),
        ("GITHUB_SHA", "a" * 40),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
    ],
)
def test_new_protocol_keeps_protected_workflow_context_checks(key, value):
    runner = context()
    runner[key] = value
    with pytest.raises(ContractError):
        author(plan(), runner)


def test_warning_waiver_is_not_an_adjudication_field():
    value = plan()
    value["adjudication"]["waive_warnings"] = True
    redigest(value)
    with pytest.raises(ContractError):
        author(value)
