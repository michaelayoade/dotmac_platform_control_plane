import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conformance_data import TestSigner, applied, desired

from vendor_cp.deploy_agent import contracts as c


def test_committed_vectors_and_plan_digest():
    vector = json.loads(
        (Path(__file__).parent / "vectors" / "conformance.json").read_bytes()
    )
    for kind, signer in (
        (c.DESIRED, TestSigner()),
        (c.APPLIED, TestSigner("test-host", seed=2)),
        (c.POSSESSION, TestSigner("test-host", seed=2)),
    ):
        item = vector[kind]
        assert c.seal(kind, item["payload"], signer) == item["envelope"]
        assert (
            c.verify(kind, item["envelope"], signer.public_key_b64) == item["payload"]
        )
    assert c.plan_digest(vector[c.DESIRED]["payload"]) == vector["plan_digest"]


@pytest.mark.parametrize(
    "mutation",
    ["unknown", "missing", "bool_run", "tag", "bad_config", "plan", "mode", "approval"],
)
def test_desired_closed_schema(mutation):
    doc = desired()
    if mutation == "unknown":
        doc["extra"] = True
    if mutation == "missing":
        del doc["source_tree"]
    if mutation == "bool_run":
        doc["build_run_id"] = True
    if mutation == "tag":
        doc["image_digest"] = "latest"
    if mutation == "bad_config":
        doc["config_files"][".env"] = "sha256:" + "c" * 64
    if mutation == "plan":
        doc["from_image_digest"] = "sha256:" + "9" * 64
    if mutation == "mode":
        doc["migration_policy"] = {"mode": "none_hotfix"}
    if mutation == "approval":
        doc["approvals"][0]["environment"] = "production"
    with pytest.raises(c.ContractError):
        c.validate_desired(doc)


def test_exact_byte_signature_key_swap_and_identity_guard():
    signer = TestSigner()
    envelope = c.seal(c.DESIRED, desired(), signer)
    for altered in (
        {**envelope, "key_id": "other"},
        {**envelope, "payload_b64": c.b64(c.unb64(envelope["payload_b64"]) + b" ")},
    ):
        with pytest.raises(c.ContractError, match="bad_signature"):
            c.verify(c.DESIRED, altered, signer.public_key_b64)
    challenge = {
        "schema": c.CHALLENGE,
        "key_id": signer.key_id,
        "deployment_ref": "foreign/staging/host",
        "nonce": c.b64(b"n" * 24),
        "expires_at": "2026-10-21T11:00:00Z",
    }
    signer.sign = lambda _: pytest.fail("identity guard must run before signing")
    with pytest.raises(c.ContractError, match="host_mismatch"):
        c.answer_challenge(challenge, signer, "sha256:" + "a" * 64)


def test_expiry_and_host_and_json_duplicates():
    with pytest.raises(c.ContractError, match="expired"):
        c.validate_desired(desired(), now=datetime(2026, 10, 21, 15, tzinfo=UTC))
    identity = {
        key: desired()[key]
        for key in ("product", "environment", "host", "image_reference")
    }
    identity["host"] = "other"
    with pytest.raises(c.ContractError, match="host_mismatch"):
        c.validate_desired(desired(), identity=identity)
    with pytest.raises(c.ContractError):
        c.read_json(b'{"a":1,"a":2}')
    with pytest.raises(c.ContractError):
        c.read_json(b'{"a":NaN}')


def test_applied_reason_rule_and_nested_fields():
    for mutate in (
        lambda doc: doc.update(reason="unknown"),
        lambda doc: doc["health"]["live"].update(secret=True),
        lambda doc: doc["observed"].update(extra=True),
    ):
        doc = copy.deepcopy(applied())
        mutate(doc)
        with pytest.raises(c.ContractError):
            c.validate_applied(doc)


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-21Z",
        "20261021Z",
        "2026-10-21T10:00:00",
        "2026-10-21T10:00:00+00:00",
        "2026-02-30T10:00:00Z",
    ],
)
def test_timestamp_rejects_non_rfc3339_utc(value):
    with pytest.raises(c.ContractError, match="schema_violation"):
        c.timestamp(value)


@pytest.mark.parametrize("actor", ["", "a" * 2049])
def test_desired_rejects_unbounded_approval_actor(actor):
    doc = desired()
    doc["approvals"][0]["actor"] = actor
    with pytest.raises(c.ContractError, match="schema_violation"):
        c.validate_desired(doc)


def test_maximum_domain_text_preserves_large_wire_payload():
    doc = desired()
    doc["approvals"][0]["actor"] = "a" * 2048
    envelope = c.seal(c.DESIRED, doc, TestSigner())
    assert len(envelope["payload_b64"]) > 2048
    assert c.verify(c.DESIRED, envelope, TestSigner().public_key_b64) == doc


def test_desired_rejects_duplicate_migration_heads_after_plan_rebinding():
    doc = desired()
    doc["migration_policy"]["expected_heads"] = ["head1", "head1"]
    doc["plan_digest"] = c.plan_digest(doc)
    with pytest.raises(c.ContractError, match="schema_violation"):
        c.validate_desired(doc)


@pytest.mark.parametrize(
    "reference",
    [
        "host",
        "product/host",
        "product/staging/host/extra",
        "product/staging/",
        "product/staging/invalid host",
        "product/staging/../host",
    ],
)
def test_applied_deployment_reference_has_three_identifier_components(reference):
    doc = applied()
    doc["deployment_ref"] = reference
    with pytest.raises(c.ContractError, match="schema_violation"):
        c.validate_applied(doc)


@pytest.mark.parametrize(
    "field",
    [
        "running_image",
        "running_revision_label",
        "pinned_image",
        "pinned_git_sha",
        "body_status",
        "receipt_line",
        "url",
        "container",
        "version",
    ],
)
@pytest.mark.parametrize("value", ["", "a" * 2049])
def test_applied_restores_original_domain_string_bounds(field, value):
    doc = applied()
    if field in doc["observed"]:
        doc["observed"][field] = value
    elif field == "body_status":
        doc["health"]["ready"][field] = value
    elif field == "receipt_line":
        doc["deploy_receipt"][field] = value
    elif field == "url":
        doc["health"]["live"][field] = value
    elif field == "container":
        doc["health"]["background"]["containers"]["app"] = value
    else:
        doc["agent"][field] = value
    with pytest.raises(c.ContractError, match="schema_violation"):
        c.validate_applied(doc)


def test_nullable_domain_observations_remain_allowed():
    doc = applied()
    for field in (
        "running_image",
        "running_revision_label",
        "pinned_image",
        "pinned_git_sha",
    ):
        doc["observed"][field] = None
    doc["health"]["ready"]["body_status"] = None
    doc["deploy_receipt"]["receipt_line"] = None
    assert c.validate_applied(doc) == doc


@pytest.mark.parametrize("reference", ["", "a" * 2049])
def test_challenge_deployment_reference_retains_text_bounds(reference):
    challenge = {
        "schema": c.CHALLENGE,
        "key_id": "test-host",
        "deployment_ref": reference,
        "nonce": c.b64(b"n" * 24),
        "expires_at": "2026-10-21T11:00:00Z",
    }
    with pytest.raises(c.ContractError, match="schema_violation"):
        c.validate_challenge(challenge)
