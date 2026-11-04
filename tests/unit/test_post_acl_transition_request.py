"""Post-ACL intent is a separate canonical domain with runner-owned identity."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest
from test_transition_request import NOW, REVISION, context, failed_candidate_plan

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_request as producer


def plan():
    value = failed_candidate_plan()
    value["schema"] = "dotmac.cp_post_acl_recovery_plan/1"
    value["basis"].update(
        predecessor_context_digest="sha256:" + "1" * 64,
        predecessor_frontier_claim_digest="sha256:" + "2" * 64,
        pre_routing_receipt_digest="sha256:" + "3" * 64,
        acl_restored_digest="sha256:" + "4" * 64,
    )
    projection = {key: value[key] for key in cp.COMMITTED_PLAN_FIELDS}
    value["plan_digest"] = cp.digest({"schema": value["schema"], **projection})
    return value


def author(value, runner=None):
    return producer.author_request(
        canonical_json(value),
        context=runner or context(),
        expected_revision=REVISION,
        now=NOW,
    )


def test_separate_plan_domain_and_runner_owned_bindings():
    value = plan()
    request = author(value)
    assert request["schema"] == "dotmac.cp_post_acl_recovery_request/1"
    assert request["basis"] == value["basis"]
    assert request["plan_digest"] == cp.transition_plan_digest(request)
    assert request["authorization_run_id"] == 123
    assert request["authorization_run_attempt"] == 2
    assert request["trusted_actor"] == producer.REPOSITORY_OWNER
    assert cp.timestamp(request["expires_at"]) == NOW + timedelta(hours=23)
    request["schema"] = "dotmac.cp_failed_candidate_request/2"
    assert request["plan_digest"] != cp.transition_plan_digest(request)


@pytest.mark.parametrize(
    "field",
    [
        "authorization_run_id",
        "authorization_run_attempt",
        "trusted_actor",
        "expires_at",
        "unknown",
    ],
)
def test_plan_cannot_supply_runner_fields(field):
    value = plan()
    value[field] = "operator controlled"
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize("field", list(cp.PostAclRecoveryBasisV1.__annotations__))
def test_plan_canonical_projection_binds_every_basis_field(field):
    value = plan()
    value["basis"][field] = (
        "f" * 64
        if field.endswith("_nonce") or field.endswith("_id")
        else "sha256:" + "f" * 64
    )
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_ACTOR", "attacker"),
        ("GITHUB_TRIGGERING_ACTOR", "attacker"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "0"),
        ("GITHUB_REF_PROTECTED", "false"),
        ("GITHUB_SHA", "a" * 40),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
    ],
)
def test_protected_runner_context_is_required(key, value):
    runner = context()
    runner[key] = value
    with pytest.raises(ContractError):
        author(plan(), runner)


@pytest.mark.parametrize(
    "field",
    ["pre_routing_receipt_digest", "acl_restored_digest", "predecessor_context_digest"],
)
def test_missing_evidence_bindings_cannot_fall_back_to_old_family(field):
    value = plan()
    del value["basis"][field]
    with pytest.raises(ContractError):
        author(value)


def test_closed_request_loader_and_identity_expiry():
    value = author(plan())
    identity = cp.CpTransitionIdentity(
        value["host"],
        value["database"],
        value["cluster_system_identifier"],
        value["database_oid"],
    )
    assert (
        cp.load_post_acl_recovery_request(
            canonical_json(value), identity=identity, now=NOW
        )
        == value
    )
    for mutated in (
        {**value, "unknown": True},
        {**value, "database_oid": value["database_oid"] + 1},
        {**value, "expires_at": NOW.isoformat()},
    ):
        with pytest.raises(ContractError):
            cp.validate_post_acl_recovery_request(mutated, identity=identity, now=NOW)
    old = copy.deepcopy(value)
    old["schema"] = "dotmac.cp_failed_candidate_request/2"
    with pytest.raises(ContractError):
        cp.load_post_acl_recovery_request(
            canonical_json(old), identity=identity, now=NOW
        )
