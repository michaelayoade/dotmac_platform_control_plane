"""Producer/consumer bindings and operator-controlled dispatch adversaries."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, read_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_request as producer

NOW = datetime(2026, 10, 24, tzinfo=UTC)
REVISION = "f" * 40


def context() -> dict[str, str]:
    return {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": producer.REPOSITORY,
        "GITHUB_REPOSITORY_ID": producer.REPOSITORY_ID,
        "GITHUB_REPOSITORY_OWNER_ID": producer.REPOSITORY_OWNER_ID,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_SHA": REVISION,
        "GITHUB_WORKFLOW_SHA": REVISION,
        "GITHUB_WORKFLOW_REF": (
            f"{producer.REPOSITORY}/{producer.WORKFLOW_PATH}@refs/heads/main"
        ),
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_ACTOR": producer.REPOSITORY_OWNER,
        "GITHUB_ACTOR_ID": producer.REPOSITORY_OWNER_ID,
        "GITHUB_TRIGGERING_ACTOR": producer.REPOSITORY_OWNER,
    }


def plan() -> dict[str, object]:
    value = {
        "product": "dotmac_vendor_control_plane",
        "environment": "production",
        "host": "cp-production",
        "database": "platform",
        "cluster_system_identifier": "123456",
        "database_oid": 16384,
        "source": {
            "image_digest": "sha256:" + "a" * 64,
            "revision": "a" * 40,
            "raw_descriptor_digest": "sha256:" + "c" * 64,
            "heads": ["a", "b"],
        },
        "target": {
            "image_digest": "sha256:" + "b" * 64,
            "revision": "b" * 40,
            "raw_descriptor_digest": "sha256:" + "d" * 64,
            "heads": ["c"],
        },
        "previous_receipt_digest": None,
    }
    return {**value, "plan_digest": cp.digest(value)}


def author(value=None, trusted=None):
    return producer.author_request(
        canonical_json(plan() if value is None else value),
        context=context() if trusted is None else trusted,
        expected_revision=REVISION,
        now=NOW,
    )


def test_exact_consumer_roundtrip_and_predicate(tmp_path: Path) -> None:
    request = author()
    assert request["authorization_run_id"] == 123
    assert request["authorization_run_attempt"] == 2
    assert request["trusted_actor"] == producer.REPOSITORY_OWNER
    assert cp.timestamp(request["expires_at"]) == NOW + timedelta(hours=23)
    assert request["target"]["revision"] != REVISION
    output = tmp_path / "authorization"
    metadata = producer.write_authorization(request, output)
    raw = (output / "request.json").read_bytes()
    assert metadata["subject_digest"] == cp.raw_digest(raw)
    assert metadata["predicate_type"] == producer.PREDICATE_TYPE
    assert read_json((output / "predicate.json").read_bytes()) == {
        "request_digest": cp.request_digest(request),
        "trusted_actor": request["trusted_actor"],
        "environment": "production",
    }
    identity = cp.CpTransitionIdentity("cp-production", "platform", "123456", 16384)
    assert cp.load_request(raw, identity=identity, now=NOW) == request
    with pytest.raises(FileExistsError):
        producer.write_authorization(request, output)


@pytest.mark.parametrize("field", list(context()))
def test_untrusted_workflow_context_refused(field: str) -> None:
    trusted = context()
    trusted[field] = "invalid"
    with pytest.raises(ContractError):
        author(trusted=trusted)


@pytest.mark.parametrize(
    "field",
    [
        "authorization_run_id",
        "authorization_run_attempt",
        "trusted_actor",
        "expires_at",
        "host_nonce",
        "build_run_id",
        "schema",
        "unknown",
    ],
)
def test_operator_cannot_author_identity_expiry_or_extra_fields(field: str) -> None:
    value = plan()
    value[field] = "injected"
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("host", "other-host"),
        ("database", "other-db"),
        ("database_oid", 123),
        ("cluster_system_identifier", "987654"),
        ("previous_receipt_digest", "sha256:" + "f" * 64),
        ("plan_digest", "sha256:" + "f" * 64),
    ],
)
def test_plan_digest_covers_every_binding(field: str, replacement: object) -> None:
    value = plan()
    value[field] = replacement
    with pytest.raises(ContractError):
        author(value)


@pytest.mark.parametrize("side", ["source", "target"])
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("revision", "e" * 40),
        ("image_digest", "sha256:" + "e" * 64),
        ("raw_descriptor_digest", "sha256:" + "e" * 64),
        ("heads", ["other"]),
        ("unknown", "injected"),
    ],
)
def test_plan_digest_covers_both_sides(side, field, replacement) -> None:
    value = copy.deepcopy(plan())
    value[side][field] = replacement
    with pytest.raises(ContractError):
        author(value)


def test_duplicate_json_and_ambiguous_heads_refused() -> None:
    raw = canonical_json(plan()).replace(
        b'"database_oid":16384', b'"database_oid":16384,"database_oid":1'
    )
    with pytest.raises(ContractError):
        producer.author_request(
            raw, context=context(), expected_revision=REVISION, now=NOW
        )
    value = plan()
    value["source"]["heads"] = ["b", "a"]
    value["plan_digest"] = cp.digest({key: value[key] for key in cp.PLAN_FIELDS})
    with pytest.raises(ContractError):
        author(value)


def test_rerun_identity_is_distinct_and_no_host_nonce() -> None:
    first = author()
    trusted = context()
    trusted["GITHUB_RUN_ATTEMPT"] = "3"
    second = author(trusted=trusted)
    assert cp.request_digest(first) != cp.request_digest(second)
    assert first["plan_digest"] == second["plan_digest"]
    assert "host_nonce" not in first


def test_cli_authors_request_and_safe_computed_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(canonical_json(plan()))
    output_path = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    for key, value in context().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "transition_request",
            "--plan",
            str(plan_path),
            "--output",
            str(tmp_path / "request"),
            "--expected-revision",
            REVISION,
        ],
    )
    producer.main()
    raw = (tmp_path / "request" / "request.json").read_bytes()
    assert output_path.read_text() == (
        f"subject_digest={cp.raw_digest(raw)}\n"
        f"predicate_type={producer.PREDICATE_TYPE}\n"
    )
    assert read_json(raw)["authorization_run_attempt"] == 2


@pytest.mark.parametrize("attempt", ["1", "2", "3"])
def test_owner_dispatch_and_owner_rerun_use_exact_owner_identity(attempt):
    trusted = context()
    trusted["GITHUB_RUN_ATTEMPT"] = attempt
    value = author(trusted=trusted)
    assert value["trusted_actor"] == producer.REPOSITORY_OWNER
    assert value["authorization_run_attempt"] == int(attempt)


@pytest.mark.parametrize(
    ("field", "foreign"),
    [
        ("GITHUB_ACTOR", "another-valid-actor"),
        ("GITHUB_ACTOR_ID", "32591930"),
        ("GITHUB_TRIGGERING_ACTOR", "another-valid-actor"),
    ],
)
def test_foreign_dispatch_actor_id_or_rerun_cannot_author_request(field, foreign):
    trusted = context()
    trusted[field] = foreign
    with pytest.raises(ContractError):
        author(trusted=trusted)


def test_actual_producer_cli_runs_with_database_and_kernel_imports_blocked(tmp_path):
    """Exercise the workflow's real producer with only portable public imports."""
    import json
    import os
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(canonical_json(plan()))
    output = tmp_path / "authorization"
    github_output = tmp_path / "github-output"
    program = r"""
import importlib.abc
import runpy
import sys

class PublicProducerBoundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.partition('.')[0] in {'sqlalchemy', 'psycopg', 'dotmac_kernel'}:
            raise ImportError(
                'database or private kernel dependency reached public producer'
            )
        return None

sys.meta_path.insert(0, PublicProducerBoundary())
sys.path.insert(0, sys.argv.pop(1))
sys.argv[0] = 'transition_request'
runpy.run_module(
    'vendor_cp.deployment.transition_request', run_name='__main__', alter_sys=True
)
"""
    result = subprocess.run(  # noqa: S603 -- actual reviewed producer, isolated fixture context
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(root / "src"),
            "--plan",
            str(plan_path),
            "--expected-revision",
            REVISION,
            "--output",
            str(output),
        ],
        env={**context(), "GITHUB_OUTPUT": str(github_output), "PATH": os.defpath},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    authored = json.loads((output / "request.json").read_bytes())
    assert authored["trusted_actor"] == producer.REPOSITORY_OWNER
    assert authored["authorization_run_attempt"] == 2
    predicate = json.loads((output / "predicate.json").read_bytes())
    assert set(predicate) == {"request_digest", "trusted_actor", "environment"}
    assert predicate["request_digest"] == cp.request_digest(authored)
    assert github_output.read_text().splitlines() == [
        "subject_digest=" + cp.raw_digest((output / "request.json").read_bytes()),
        "predicate_type=" + producer.PREDICATE_TYPE,
    ]


def test_authorization_workflow_keeps_manual_gate_and_repeats_owner_guards():
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github/workflows/authorize-cp-transition.yml"
    ).read_text()
    assert "environment: production" in workflow
    for guard in (
        "github.actor == github.repository_owner",
        "github.actor_id == github.repository_owner_id",
        "github.triggering_actor == github.repository_owner",
    ):
        assert guard in workflow
    assert "names = {'cryptography', 'cffi', 'pycparser'}" in workflow


def test_committed_plan_is_closed_and_operator_revision_is_independent(tmp_path):
    value = plan()
    value["operator_revision"] = "e" * 40
    value["basis"] = {
        "context_digest": "sha256:" + "1" * 64,
        "prior_request_digest": "sha256:" + "2" * 64,
        "prior_host_nonce": "3" * 64,
        "prior_reservation_digest": "sha256:" + "4" * 64,
        "prior_authorization_digest": "sha256:" + "5" * 64,
        "original_fence_digest": "sha256:" + "6" * 64,
        "current_fence_digest": "sha256:" + "7" * 64,
        "current_fence_id": "8" * 64,
        "frontier_measurement_digest": "sha256:" + "9" * 64,
    }
    # Canonical plan fields, including both new fields, are signed.
    value["plan_digest"] = cp.digest(
        {
            "schema": "dotmac.cp_committed_migration_plan/1",
            **{key: value[key] for key in cp.COMMITTED_PLAN_FIELDS},
        }
    )
    authored = author(value)
    assert authored["schema"] == "dotmac.cp_committed_migration_request/1"
    assert authored["operator_revision"] != REVISION
    identity = cp.CpTransitionIdentity("cp-production", "platform", "123456", 16384)
    cp.load_committed_request(canonical_json(authored), identity=identity, now=NOW)
    with pytest.raises(ContractError):
        cp.load_request(canonical_json(authored), identity=identity, now=NOW)
    producer.write_authorization(authored, tmp_path / "committed")
    value["basis"]["unknown"] = "unsafe"
    with pytest.raises(ContractError):
        author(value)


def test_old_plan_digest_accepts_closed_plan_without_schema_unchanged():
    value = plan()
    expected = cp.digest({key: value[key] for key in cp.PLAN_FIELDS})
    assert cp.transition_plan_digest(value) == expected
    assert (
        cp.transition_plan_digest({**value, "schema": "dotmac.cp_transition_request/1"})
        == expected
    )


def test_committed_plan_digest_binds_fixed_variant_discriminator():
    value = {
        **plan(),
        "schema": "dotmac.cp_committed_migration_request/1",
        "operator_revision": "e" * 40,
        "basis": {"frontier": "pinned"},
    }
    payload = {key: value[key] for key in cp.COMMITTED_PLAN_FIELDS}
    actual = cp.transition_plan_digest(value)
    assert actual == cp.digest(
        {"schema": "dotmac.cp_committed_migration_plan/1", **payload}
    )
    assert actual != cp.digest(payload)
    assert actual != cp.digest({"schema": "dotmac.cp_transition_plan/1", **payload})
    assert actual != cp.digest({key: value[key] for key in cp.PLAN_FIELDS})
