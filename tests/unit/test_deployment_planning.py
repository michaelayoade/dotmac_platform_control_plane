"""Stack 2: exact artifacts, deterministic plans and expiring approval."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from dotmac_kernel import ConflictError
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from dotmac_kernel.testing import create_test_engine, isolated_session
from dotmac_release_catalog import (
    ArtifactAttestation,
    ArtifactKind,
    ArtifactOrigin,
    AttestationKind,
    ReleaseArtifact,
    attest_artifact,
    publish_artifact,
)
from sqlalchemy import select
from sqlalchemy.orm import Session
from tests.capability_contract_registry import (
    build_capability_composition_registry,
    build_capability_contract_registry,
    build_composition_selections,
    build_desired_operation_documents,
)

import vendor_cp.offers.models  # noqa: F401
from vendor_cp.accounts.models import VendorAccount
from vendor_cp.approvals import adapter as approvals
from vendor_cp.fleet import service as fleet
from vendor_cp.fleet.feature import feature as fleet_feature
from vendor_cp.fleet.models import Deployment, DeploymentDesiredStateVersion
from vendor_cp.managed_profiles import service as profiles
from vendor_cp.managed_profiles.feature import feature as profiles_feature
from vendor_cp.planning import service
from vendor_cp.planning.feature import feature as planning_feature
from vendor_cp.planning.models import (
    DeploymentBundleManifestVersion,
    DeploymentPlan,
    IntegratorCommandDispatch,
    IntegratorExecutionReceipt,
)

HASH = "sha256:" + "a" * 64
NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
CAPABILITY_REGISTRY = build_capability_contract_registry()
COMPOSITION_REGISTRY = build_capability_composition_registry()


@pytest.fixture(scope="module", autouse=True)
def _declared_audit_actions() -> Iterator[None]:
    import dotmac_kernel.audit_actions as registry_module

    try:
        previous = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous = None
    install_audit_actions(
        AuditActionRegistry.from_manifests(
            (fleet_feature, profiles_feature, planning_feature)
        )
    )
    try:
        yield
    finally:
        if previous is None:
            registry_module._active_registry = None
        else:
            install_audit_actions(previous)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _configuration(
    ref: str = "config:internal/identity@v1",
) -> fleet.ConfigurationSnapshotInput:
    return fleet.ConfigurationSnapshotInput(
        snapshot_ref=ref,
        schema_version=1,
        values=(
            fleet.ConfigurationValue(
                "identity.dns", "customer_domain", "internal.example"
            ),
            fleet.ConfigurationValue(
                "identity.realm", "identity_endpoint", "https://id.internal.example"
            ),
            fleet.ConfigurationValue(
                "identity.realm",
                "identity_admin_secret_ref",
                "secret:internal/identity-admin@v1",
            ),
            fleet.ConfigurationValue(
                "identity.realm",
                "identity_policy_ref",
                "reference:identity/managed@v1",
            ),
            fleet.ConfigurationValue(
                "identity.realm",
                "identity_backup_policy_ref",
                "reference:backup/identity@v1",
            ),
        ),
    )


def _intent(db: Session) -> tuple[Deployment, DeploymentDesiredStateVersion]:
    account = VendorAccount(external_ref="internal-platform", display_name="Internal")
    db.add(account)
    db.flush()
    target = fleet.create_deployment_target(
        db,
        fleet.CreateDeploymentTargetCommand(
            command_id="target:internal-platform",
            account_id=account.id,
            target_ref="internal-identity",
            customer_ref=None,
            display_name="Internal identity",
            region_code="ng-abuja",
        ),
    )
    profiles.publish_profile_version(
        db,
        profiles.PublishProfileVersionCommand(
            commercial_product_code="managed-sso",
            profile_code="standard",
            version=1,
            schema_version=1,
            update_authority="customer_approved",
        ),
        capability_registry=CAPABILITY_REGISTRY,
        composition_registry=COMPOSITION_REGISTRY,
    )
    result = fleet.record_deployment_intent(
        db,
        fleet.CreateDeploymentIntentCommand(
            command_id="intent:internal-identity",
            account_id=account.id,
            target_id=target.id,
            deployment_ref="internal-identity",
            commercial_product_code="managed-sso",
            profile_code="standard",
            profile_version=1,
            selected_optional_components=(),
            configuration_snapshot=_configuration(),
            desired_operation_inputs=tuple(
                fleet.CapabilityOperationInput(
                    instance_ref, component_code, capability_id, document
                )
                for instance_ref, component_code, capability_id, document in (
                    build_desired_operation_documents("managed-sso")
                )
            ),
            composition_selections=build_composition_selections("managed-sso"),
            internal_source_code="dotmac.internal.identity",
        ),
    )
    deployment = db.get(Deployment, result.deployment.id)
    desired = db.get(DeploymentDesiredStateVersion, result.desired_state.id)
    assert deployment is not None and desired is not None
    return deployment, desired


def _attested_artifact(
    db: Session, *, product_manifest: bool = True, fill: str = "1"
) -> tuple[ReleaseArtifact, dict[AttestationKind, ArtifactAttestation]]:
    digest = "sha256:" + fill * 64
    artifact = publish_artifact(
        db,
        product_code="dotmac-identity" if product_manifest else "upstream-identity",
        version="1.0.0",
        artifact_kind=ArtifactKind.CONTAINER_IMAGE,
        origin=(
            ArtifactOrigin.DOTMAC_PRODUCT
            if product_manifest
            else ArtifactOrigin.UPSTREAM_THIRD_PARTY
        ),
        digest=digest,
        artifact_ref=f"registry.example/identity@{digest}",
        source_revision="b" * 40,
    )
    kinds = [
        AttestationKind.PROVENANCE,
        AttestationKind.SBOM,
        AttestationKind.SIGNATURE,
    ]
    if product_manifest:
        kinds.append(AttestationKind.PRODUCT_MANIFEST)
    else:
        kinds.extend(
            (
                AttestationKind.VULNERABILITY_POLICY_RESULT,
                AttestationKind.COMPATIBILITY_RESULT,
            )
        )
    attestations = {
        kind: attest_artifact(
            db,
            artifact_id=artifact.id,
            attestation_kind=kind,
            uri=f"evidence://{kind.value}/{fill}",
            digest="sha256:" + chr(ord(fill) + 1) * 64,
        )
        for kind in kinds
    }
    return artifact, attestations


def _selection(
    artifact: ReleaseArtifact,
    attestations: dict[AttestationKind, ArtifactAttestation],
) -> service.ComponentArtifactSelection:
    def selected(kind: AttestationKind) -> service.AttestationSelection:
        row = attestations[kind]
        return service.AttestationSelection(attestation_id=row.id, digest=row.digest)

    return service.ComponentArtifactSelection(
        component_code="identity",
        artifact_id=artifact.id,
        artifact_digest=artifact.digest,
        artifact_reference=artifact.artifact_ref,
        provenance=selected(AttestationKind.PROVENANCE),
        sbom=selected(AttestationKind.SBOM),
        signature=selected(AttestationKind.SIGNATURE),
        product_manifest=(
            selected(AttestationKind.PRODUCT_MANIFEST)
            if AttestationKind.PRODUCT_MANIFEST in attestations
            else None
        ),
        vulnerability_policy_result=(
            selected(AttestationKind.VULNERABILITY_POLICY_RESULT)
            if AttestationKind.VULNERABILITY_POLICY_RESULT in attestations
            else None
        ),
        compatibility_result=(
            selected(AttestationKind.COMPATIBILITY_RESULT)
            if AttestationKind.COMPATIBILITY_RESULT in attestations
            else None
        ),
    )


def _bundle(db: Session) -> service.BundleManifestView:
    artifact, attestations = _attested_artifact(db)
    return service.publish_bundle_manifest_version(
        db,
        service.PublishBundleManifestCommand(
            command_id="bundle:identity:1",
            commercial_product_code="managed-sso",
            profile_code="standard",
            profile_version=1,
            bundle_code="identity-stable",
            version=1,
            components=(_selection(artifact, attestations),),
        ),
    )


def _bindings(
    desired: DeploymentDesiredStateVersion,
    *,
    changed_configuration: bool = False,
    reverse: bool = False,
) -> tuple[service.IntegratorBindingSelection, ...]:
    result = [
        service.IntegratorBindingSelection(
            capability_instance_ref=str(item["capability_instance_ref"]),
            capability_id=str(item["capability_id"]),
            capability_schema_version=int(item["schema_version"]),
            installation_id=uuid4(),
            installation_ref=f"installation:{uuid4()}",
            binding_ref=uuid4(),
            connector_key=f"connector.{item['capability_id']}",
            connector_version="1.0.0",
            connector_manifest_digest="sha256:" + "c" * 64,
            connector_artifact_digest="sha256:" + "d" * 64,
            connector_configuration_revision_id=uuid4(),
            connector_configuration_digest=(
                "sha256:" + ("f" if changed_configuration and index == 0 else "e") * 64
            ),
            execution_policy_digest="sha256:" + "9" * 64,
        )
        for index, item in enumerate(desired.selected_capabilities)
    ]
    # Binding identity is a material input. Reordering tests must retain exact
    # identities, so callers reverse this already-built tuple rather than
    # rebuilding it.
    if reverse:
        result.reverse()
    return tuple(result)


def _plan(
    db: Session,
    deployment: Deployment,
    desired: DeploymentDesiredStateVersion,
    bundle: service.BundleManifestView,
    bindings: tuple[service.IntegratorBindingSelection, ...],
    *,
    command_id: str,
) -> service.DeploymentPlanView:
    return service.create_deployment_plan(
        db,
        service.CreateDeploymentPlanCommand(
            command_id=command_id,
            deployment_id=deployment.id,
            desired_state_version_id=desired.id,
            bundle_manifest_version_id=bundle.id,
            allocation_id=None,
            binding_selections=bindings,
            lifecycle_policy=service.VersionedPolicyRef("managed.lifecycle", 1),
        ),
    )


def test_bundle_derives_dotmac_class_from_catalogue_and_is_immutable(
    db: Session,
) -> None:
    _deployment, _desired = _intent(db)
    bundle = _bundle(db)
    row = db.get(DeploymentBundleManifestVersion, bundle.id)
    assert row is not None
    assert row.document["components"][0]["source_class"] == "dotmac_product"
    row.document = {"changed": True}
    with pytest.raises(ConflictError, match="immutable"):
        db.flush()


def test_upstream_admission_uses_catalogue_origin_and_distinct_exact_claims(
    db: Session,
) -> None:
    _intent(db)
    artifact, attestations = _attested_artifact(db, product_manifest=False, fill="3")
    bundle = service.publish_bundle_manifest_version(
        db,
        service.PublishBundleManifestCommand(
            command_id="bundle:upstream:1",
            commercial_product_code="managed-sso",
            profile_code="standard",
            profile_version=1,
            bundle_code="upstream-identity",
            version=1,
            components=(_selection(artifact, attestations),),
        ),
    )
    row = db.get(DeploymentBundleManifestVersion, bundle.id)
    assert row is not None
    component = row.document["components"][0]
    assert component["source_class"] == "upstream_third_party"
    assert "product_manifest" not in component["evidence"]
    assert {
        component["evidence"][kind]["id"]
        for kind in ("vulnerability_policy_result", "compatibility_result")
    } == {
        str(attestations[AttestationKind.VULNERABILITY_POLICY_RESULT].id),
        str(attestations[AttestationKind.COMPATIBILITY_RESULT].id),
    }


def test_bundle_request_has_no_source_class_or_raw_admission_reference() -> None:
    fields = set(service.ComponentArtifactSelection.__dataclass_fields__)
    assert "source_class" not in fields
    assert not ({"vulnerability_ref", "compatibility_ref"} & fields)


def test_plan_is_deterministic_under_reordering_and_revert_cannot_revive_grant(
    db: Session,
) -> None:
    deployment, desired = _intent(db)
    bundle = _bundle(db)
    original_bindings = _bindings(desired)
    first = _plan(
        db, deployment, desired, bundle, original_bindings, command_id="plan:first"
    )
    first_row = db.get(DeploymentPlan, first.id)
    assert first_row is not None
    for template in first_row.document["command_templates"]:
        for step in template["steps"]:
            assert step["input"] == {}
            assert "configuration" not in step["input"]
            assert "desired_state_hash" not in step["input"]
    with pytest.raises(ConflictError, match="equivalent deployment plan"):
        _plan(
            db,
            deployment,
            desired,
            bundle,
            tuple(reversed(original_bindings)),
            command_id="plan:duplicate-current",
        )
    changed = list(original_bindings)
    first_binding = changed[0]
    changed[0] = replace(
        first_binding,
        connector_configuration_digest="sha256:" + "f" * 64,
    )
    second = _plan(
        db, deployment, desired, bundle, tuple(changed), command_id="plan:changed"
    )
    reverted = _plan(
        db,
        deployment,
        desired,
        bundle,
        tuple(reversed(original_bindings)),
        command_id="plan:reverted",
    )
    assert first.plan_hash != second.plan_hash
    # saved_plan_id is part of every approved command template. Reverting
    # content creates a new immutable plan identity and therefore cannot revive
    # an earlier approval by recreating its hash.
    assert reverted.plan_hash != first.plan_hash
    assert reverted.id != first.id
    assert deployment.current_plan_id == reverted.id
    with pytest.raises(ConflictError, match="no longer current"):
        service.request_plan_approval(
            db,
            service.RequestPlanApprovalCommand(
                command_id="approval:stale",
                plan_id=first.id,
                policy_code="deployment-change",
                policy_version=1,
                expires_at=NOW + timedelta(minutes=10),
                requested_by=uuid4(),
                plan_validation_receipt_ids=(),
            ),
            now=NOW,
        )


class _Signer:
    key_id = "vendor-command-2026-01"
    purpose = service.COMMAND_SIGNING_PURPOSE
    public_key_b64 = "command-public-key"

    def sign(self, payload: bytes) -> bytes:
        return hashlib.sha512(payload).digest()


class _NoPrerequisites:
    def require_succeeded(
        self,
        *,
        deployment_ref: str,
        plan_hash: str,
        capability_binding_id: UUID,
    ) -> service.PrerequisiteReceiptPin:
        raise service.PrerequisiteReceiptUnavailableError(
            "prerequisite command has not completed"
        )


class _ReceiptVerifier:
    def verify(self, *, key_id: str, payload: bytes, signature_b64url: str) -> None:
        assert key_id == "integrator-receipt-2026-01"
        assert payload
        assert signature_b64url == "test-signature"


def _plan_validation_receipts(
    db: Session,
    *,
    plan: service.DeploymentPlanView,
    signer: _Signer,
    policy: service.CommandKeySeparationPolicy,
) -> tuple[UUID, ...]:
    envelopes = service.build_plan_commands(
        db,
        service.BuildPlanCommands(
            command_id_prefix=f"plan-validation-{plan.id}",
            plan_id=plan.id,
            audience="dotmac-integrator:abuja",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        ),
        signer=signer,
        key_separation=policy,
        now=NOW,
    )
    ids: list[UUID] = []
    for envelope in envelopes:
        body = envelope.document["body"]
        request_digest = envelope.document["body_sha256"]
        module_hash = (
            "sha256:"
            + hashlib.sha256(f"module:{envelope.command_id}".encode()).hexdigest()
        )
        receipt = {
            "receipt_contract_version": "integrator.provisioning-receipt.v1",
            "command_contract_version": "integrator.provisioning-command.v1",
            "operation": "plan",
            "command_id": envelope.command_id,
            "nonce": envelope.command_id,
            "issuer_account_ref": "vendor-control-plane",
            "deployment_ref": body["deployment_ref"],
            "capability_instance_ref": body["capability_instance_ref"],
            "request_body_sha256": request_digest,
            "plan_hash": body["plan_hash"],
            "approval_digest": None,
            "artifact_digest": None,
            "config_digest": body["config_digest"],
            "outcome": "planned",
            "operation_id": None,
            "replayed": False,
            "latest_module_receipt_sequence": None,
            "latest_module_receipt_hash": None,
            "module_plan_receipt_hash": module_hash,
            "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
            "evidence": {
                "step_count": len(body["steps"]),
                "module_plan_receipt": {
                    "capability_instance_ref": body["capability_instance_ref"],
                    "command_id": envelope.command_id,
                    "command_fingerprint": "sha256:" + "1" * 64,
                    "request_body_digest": request_digest,
                    "result_digest": "sha256:" + "2" * 64,
                    "receipt_hash": module_hash,
                },
            },
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode()
            ).hexdigest()
        )
        view = service.ingest_integrator_receipt(
            db,
            service.IngestIntegratorReceiptCommand(
                signed_receipt={
                    "key_id": "integrator-receipt-2026-01",
                    "receipt_sha256": digest,
                    "signature": "test-signature",
                    "receipt": receipt,
                }
            ),
            verifier=_ReceiptVerifier(),
        )
        ids.append(view.id)
    return tuple(ids)


def _approved_plan(
    db: Session,
) -> tuple[
    Deployment,
    DeploymentDesiredStateVersion,
    service.DeploymentPlanView,
    service.ApprovalGrantView,
]:
    deployment, desired = _intent(db)
    bundle = _bundle(db)
    plan = _plan(
        db,
        deployment,
        desired,
        bundle,
        _bindings(desired),
        command_id="plan:approved",
    )
    signer = _Signer()
    key_policy = service.CommandKeySeparationPolicy(
        command_key_id=signer.key_id,
        forbidden_key_ids=frozenset({"licence-primary", "session-jwt"}),
        forbidden_public_keys_b64=frozenset({"licence-public-key"}),
    )
    validation_receipt_ids = _plan_validation_receipts(
        db, plan=plan, signer=signer, policy=key_policy
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id="policy:deployment-change:1",
            policy_code="deployment-change",
            version=1,
            quorum=1,
            allow_self_approval=True,
        ),
    )
    admin_id = uuid4()
    request = service.request_plan_approval(
        db,
        service.RequestPlanApprovalCommand(
            command_id="approval:request:approved",
            plan_id=plan.id,
            policy_code="deployment-change",
            policy_version=1,
            expires_at=NOW + timedelta(minutes=10),
            requested_by=admin_id,
            plan_validation_receipt_ids=validation_receipt_ids,
        ),
        now=NOW,
    )
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id="approval:decision:approved",
            request_id=request.approval_request_id,
            approver_id=admin_id,
            content_hash=plan.plan_hash.removeprefix("sha256:"),
        ),
    )
    grant = service.record_plan_approval_grant(
        db,
        service.RecordPlanApprovalGrantCommand(
            command_id="approval:grant:approved",
            plan_id=plan.id,
            approval_request_binding_id=request.id,
            actor_admin_id=admin_id,
        ),
        now=NOW,
    )
    return deployment, desired, plan, grant


def _command_policy() -> service.CommandKeySeparationPolicy:
    return service.CommandKeySeparationPolicy(
        command_key_id=_Signer.key_id,
        forbidden_key_ids=frozenset(),
        forbidden_public_keys_b64=frozenset(),
    )


def _apply_execution_receipts(
    db: Session,
    *,
    plan: service.DeploymentPlanView,
    grant: service.ApprovalGrantView,
) -> tuple[service.IntegratorReceiptView, ...]:
    envelopes = service.build_approved_apply_commands(
        db,
        service.BuildApprovedApplyCommands(
            command_id_prefix=f"apply-{plan.id}",
            plan_id=plan.id,
            approval_grant_id=grant.id,
            audience="dotmac-integrator:abuja",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        ),
        signer=_Signer(),
        key_separation=_command_policy(),
        prerequisite_receipts=_NoPrerequisites(),
        now=NOW,
    )
    result: list[service.IntegratorReceiptView] = []
    for envelope in envelopes:
        body = envelope.document["body"]
        operation_id = uuid4()
        first_hash = "sha256:" + "7" * 64
        terminal_hash = "sha256:" + "8" * 64
        step = body["steps"][0]
        module_receipts = [
            {
                "sequence": 1,
                "receipt_kind": "command_accepted",
                "capability_instance_ref": body["capability_instance_ref"],
                "step_key": None,
                "provider_operation_ref": None,
                "previous_receipt_hash": None,
                "receipt_hash": first_hash,
                "plan_hash": plan.plan_hash,
                "connector_key": body["connector_key"],
                "connector_version": body["connector_version"],
                "manifest_digest": body["connector_manifest_digest"],
                "artifact_digest": body["artifact_digest"],
                "config_digest": body["config_digest"],
                "approval_digest": grant.grant_digest,
                "evidence": {"step_key": "untrusted.free-form.decoy"},
            },
            {
                "sequence": 2,
                "receipt_kind": "step_succeeded",
                "capability_instance_ref": body["capability_instance_ref"],
                "step_key": step["step_key"],
                "provider_operation_ref": "provider-operation:identity-001",
                "previous_receipt_hash": first_hash,
                "receipt_hash": terminal_hash,
                "plan_hash": plan.plan_hash,
                "connector_key": body["connector_key"],
                "connector_version": body["connector_version"],
                "manifest_digest": body["connector_manifest_digest"],
                "artifact_digest": body["artifact_digest"],
                "config_digest": body["config_digest"],
                "approval_digest": grant.grant_digest,
                "evidence": {
                    "step_key": "untrusted.free-form.decoy",
                    "provider_operation_ref": "untrusted-free-form-ref",
                },
            },
        ]
        receipt = {
            "receipt_contract_version": "integrator.provisioning-receipt.v1",
            "command_contract_version": "integrator.provisioning-command.v1",
            "operation": "apply",
            "command_id": envelope.command_id,
            "nonce": envelope.command_id,
            "issuer_account_ref": "vendor-control-plane",
            "deployment_ref": body["deployment_ref"],
            "capability_instance_ref": body["capability_instance_ref"],
            "request_body_sha256": envelope.document["body_sha256"],
            "plan_hash": plan.plan_hash,
            "approval_digest": grant.grant_digest,
            "artifact_digest": body["artifact_digest"],
            "config_digest": body["config_digest"],
            "outcome": "succeeded",
            "operation_id": str(operation_id),
            "replayed": False,
            "latest_module_receipt_sequence": 2,
            "latest_module_receipt_hash": terminal_hash,
            "module_plan_receipt_hash": None,
            "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
            "evidence": {"module_receipts": module_receipts},
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                service.canonical_provisioning_document_bytes(receipt)
            ).hexdigest()
        )
        result.append(
            service.ingest_integrator_receipt(
                db,
                service.IngestIntegratorReceiptCommand(
                    signed_receipt={
                        "key_id": "integrator-receipt-2026-01",
                        "receipt_sha256": digest,
                        "signature": "test-signature",
                        "receipt": receipt,
                    }
                ),
                verifier=_ReceiptVerifier(),
            )
        )
    return tuple(result)


def test_apply_envelopes_match_integrator_contract_and_key_is_separate(
    db: Session,
) -> None:
    _deployment, _desired, plan, grant = _approved_plan(db)
    signer = _Signer()
    policy = service.CommandKeySeparationPolicy(
        command_key_id=signer.key_id,
        forbidden_key_ids=frozenset({"licence-primary", "session-jwt"}),
        forbidden_public_keys_b64=frozenset({"licence-public-key"}),
    )
    envelopes = service.build_approved_apply_commands(
        db,
        service.BuildApprovedApplyCommands(
            command_id_prefix="apply-approved-plan",
            plan_id=plan.id,
            approval_grant_id=grant.id,
            audience="dotmac-integrator:abuja",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        ),
        signer=signer,
        key_separation=policy,
        prerequisite_receipts=_NoPrerequisites(),
        now=NOW,
    )
    assert envelopes
    fixture_body = json.loads(
        (
            Path(__file__).parents[2]
            / "docs/fixtures/provisioning_apply_command_v1.json"
        ).read_text(encoding="utf-8")
    )["body"]
    for envelope in envelopes:
        document = envelope.document
        assert document["contract_version"] == "integrator.provisioning-command.v1"
        assert document["nonce"] == document["command_id"]
        body = document["body"]
        assert set(body) == set(fixture_body)
        assert set(body["approval"]) == set(fixture_body["approval"])
        assert body["plan_hash"] == plan.plan_hash
        assert body["expected_plan_hash"] == plan.plan_hash
        assert body["approval"]["approved_plan_hash"] == plan.plan_hash
        assert (
            body["approval"]["approved_command_template_digest"]
            == body["approved_command_template_digest"]
        )
        assert body["prerequisite_capability_binding_ids"] == []
        assert body["prerequisite_receipt_pins"] == []
        assert body["artifact_digest"].startswith("sha256:")
        assert UUID(body["capability_binding_id"])
        assert body["capability_id"].endswith(".v1")
        assert all(
            step["endpoint_code"] == envelope.capability_id for step in body["steps"]
        )

    with pytest.raises(ConflictError, match="reuses licence or session"):
        service.build_approved_apply_commands(
            db,
            service.BuildApprovedApplyCommands(
                command_id_prefix="apply-reused-key",
                plan_id=plan.id,
                approval_grant_id=grant.id,
                audience="dotmac-integrator:abuja",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=2),
            ),
            signer=signer,
            key_separation=service.CommandKeySeparationPolicy(
                command_key_id=signer.key_id,
                forbidden_key_ids=frozenset({signer.key_id}),
                forbidden_public_keys_b64=frozenset(),
            ),
            prerequisite_receipts=_NoPrerequisites(),
            now=NOW,
        )


def test_receipt_ingress_is_idempotent_and_refuses_cross_deployment_payload(
    db: Session,
) -> None:
    _deployment, _desired, plan, _grant = _approved_plan(db)
    replayed_commands = service.build_plan_commands(
        db,
        service.BuildPlanCommands(
            command_id_prefix=f"plan-validation-{plan.id}",
            plan_id=plan.id,
            audience="dotmac-integrator:abuja",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        ),
        signer=_Signer(),
        key_separation=_command_policy(),
        now=NOW,
    )
    assert replayed_commands
    assert len(db.scalars(select(IntegratorCommandDispatch)).all()) == len(
        replayed_commands
    )
    row = db.scalar(
        select(IntegratorExecutionReceipt).where(
            IntegratorExecutionReceipt.operation == "plan"
        )
    )
    assert row is not None
    exact = json.loads(json.dumps(row.document))
    replay = service.ingest_integrator_receipt(
        db,
        service.IngestIntegratorReceiptCommand(signed_receipt=exact),
        verifier=_ReceiptVerifier(),
    )
    assert replay.id == row.id

    crossed = json.loads(json.dumps(exact))
    crossed["receipt"]["deployment_ref"] = "another-deployment"
    crossed["receipt_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            service.canonical_provisioning_document_bytes(crossed["receipt"])
        ).hexdigest()
    )
    with pytest.raises(ConflictError, match="crosses deployment"):
        service.ingest_integrator_receipt(
            db,
            service.IngestIntegratorReceiptCommand(signed_receipt=crossed),
            verifier=_ReceiptVerifier(),
        )


def test_observe_and_cancel_are_derived_from_verified_typed_step_pins(
    db: Session,
) -> None:
    _deployment, _desired, plan, grant = _approved_plan(db)
    receipts = _apply_execution_receipts(db, plan=plan, grant=grant)
    assert receipts

    observes = service.build_observe_commands(
        db,
        service.BuildObserveCommands(
            command_id_prefix="observe-approved-plan",
            plan_id=plan.id,
            approval_grant_id=grant.id,
            audience="dotmac-integrator:abuja",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        ),
        signer=_Signer(),
        key_separation=_command_policy(),
        now=NOW,
    )
    assert observes
    for envelope in observes:
        body = envelope.document["body"]
        assert set(body) == {
            "deployment_ref",
            "capability_instance_ref",
            "operation_id",
            "step_key",
            "provider_operation_ref",
            "plan_hash",
            "approval_digest",
            "artifact_digest",
            "config_digest",
        }
        assert body["step_key"] != "untrusted.free-form.decoy"
        assert body["provider_operation_ref"] == "provider-operation:identity-001"
        assert body["approval_digest"] == grant.grant_digest

    cancellations = service.build_cancel_commands(
        db,
        service.BuildCancelCommands(
            command_id_prefix="cancel-approved-plan",
            plan_id=plan.id,
            approval_grant_id=grant.id,
            audience="dotmac-integrator:abuja",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
            reason="Vendor rollback after failed acceptance evidence",
        ),
        signer=_Signer(),
        key_separation=_command_policy(),
        now=NOW,
    )
    assert cancellations
    assert all(
        envelope.document["body"]["reason"]
        == "Vendor rollback after failed acceptance evidence"
        for envelope in cancellations
    )

    after_expiry = NOW + timedelta(minutes=11)
    post_expiry_observes = service.build_observe_commands(
        db,
        service.BuildObserveCommands(
            command_id_prefix="observe-after-approval-expiry",
            plan_id=plan.id,
            approval_grant_id=grant.id,
            audience="dotmac-integrator:abuja",
            issued_at=after_expiry,
            expires_at=after_expiry + timedelta(minutes=2),
        ),
        signer=_Signer(),
        key_separation=_command_policy(),
        now=after_expiry,
    )
    assert post_expiry_observes


def test_receipt_ingress_refuses_detached_step_pin_and_artifact(
    db: Session,
) -> None:
    _deployment, _desired, plan, grant = _approved_plan(db)
    _apply_execution_receipts(db, plan=plan, grant=grant)
    row = db.scalar(
        select(IntegratorExecutionReceipt).where(
            IntegratorExecutionReceipt.operation == "apply"
        )
    )
    assert row is not None

    detached = json.loads(json.dumps(row.document))
    detached["receipt"]["evidence"]["module_receipts"][1]["provider_operation_ref"] = (
        None
    )
    detached["receipt_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            service.canonical_provisioning_document_bytes(detached["receipt"])
        ).hexdigest()
    )
    with pytest.raises(ConflictError, match="step/provider pin pair"):
        service.ingest_integrator_receipt(
            db,
            service.IngestIntegratorReceiptCommand(signed_receipt=detached),
            verifier=_ReceiptVerifier(),
        )

    changed_artifact = json.loads(json.dumps(row.document))
    changed_artifact["receipt"]["artifact_digest"] = "sha256:" + "0" * 64
    changed_artifact["receipt_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            service.canonical_provisioning_document_bytes(changed_artifact["receipt"])
        ).hexdigest()
    )
    with pytest.raises(ConflictError, match="artifact"):
        service.ingest_integrator_receipt(
            db,
            service.IngestIntegratorReceiptCommand(signed_receipt=changed_artifact),
            verifier=_ReceiptVerifier(),
        )


def test_desired_revision_clears_current_plan_and_invalidates_approval(
    db: Session,
) -> None:
    deployment, _desired, plan, grant = _approved_plan(db)
    revised = fleet.revise_deployment_desired_state(
        db,
        fleet.ReviseDeploymentDesiredStateCommand(
            command_id="desired:revision:2",
            deployment_id=deployment.id,
            expected_current_revision=1,
            profile_code="standard",
            profile_version=1,
            selected_optional_components=(),
            configuration_snapshot=_configuration("config:internal/identity@v2"),
            desired_operation_inputs=tuple(
                fleet.CapabilityOperationInput(
                    instance_ref, component_code, capability_id, document
                )
                for instance_ref, component_code, capability_id, document in (
                    build_desired_operation_documents("managed-sso")
                )
            ),
            composition_selections=build_composition_selections("managed-sso"),
        ),
    )
    assert revised.revision == 2
    assert deployment.current_plan_id is None
    with pytest.raises(ConflictError, match="no longer current"):
        service.build_approved_apply_commands(
            db,
            service.BuildApprovedApplyCommands(
                command_id_prefix="apply-stale-plan",
                plan_id=plan.id,
                approval_grant_id=grant.id,
                audience="dotmac-integrator:abuja",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=2),
            ),
            signer=_Signer(),
            key_separation=service.CommandKeySeparationPolicy(
                command_key_id=_Signer.key_id,
                forbidden_key_ids=frozenset(),
                forbidden_public_keys_b64=frozenset(),
            ),
            prerequisite_receipts=_NoPrerequisites(),
            now=NOW,
        )


def test_cross_binding_edges_become_static_templates_then_exact_receipt_pins() -> None:
    identity_binding = UUID("0f615bf7-3067-432f-b93e-e8bcde410d0a")
    application_binding = UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33")

    def binding(
        capability_instance_ref: str,
        capability_id: str,
        binding_ref: UUID,
        artifact: str,
        config: str,
    ) -> dict[str, object]:
        capability_code = capability_id.removesuffix(".v1")
        return {
            "capability_instance_ref": capability_instance_ref,
            "capability_id": capability_id,
            "capability_contract": {
                "owner_code": "test-owner",
                "capability_code": capability_code,
                "schema_version": 1,
                "content_hash": "sha256:" + "5" * 64,
                "contract_attestation_id": str(uuid4()),
                "operations": [
                    {
                        "operation_code": "apply",
                        "input_schema_ref": f"schema:test/{capability_code}/input@v1",
                        "input_schema_digest": "sha256:" + "6" * 64,
                        "output_schema_ref": f"schema:test/{capability_code}/output@v1",
                        "output_schema_digest": "sha256:" + "7" * 64,
                    }
                ],
            },
            "installation_id": str(uuid4()),
            "installation_ref": "installation:test",
            "binding_ref": str(binding_ref),
            "connector_key": "connector.test",
            "connector_version": "1.0.0",
            "connector_manifest_digest": "sha256:" + "8" * 64,
            "connector_configuration_revision_id": str(uuid4()),
            "execution_policy_digest": "sha256:" + "9" * 64,
            "connector_artifact_digest": artifact,
            "connector_configuration_digest": config,
        }

    bindings = [
        binding(
            "identity.realm",
            "identity.realm.lifecycle.v1",
            identity_binding,
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
        ),
        binding(
            "collaboration.application",
            "collaboration.application.lifecycle.v1",
            application_binding,
            "sha256:" + "3" * 64,
            "sha256:" + "4" * 64,
        ),
    ]
    identity_step = "step.identity.realm.apply"
    application_step = "step.collaboration.application.apply"
    steps = [
        {
            "step_id": identity_step,
            "step_kind": "apply_operation",
            "capability_instance_ref": "identity.realm",
            "capability_id": "identity.realm.lifecycle.v1",
            "endpoint_code": "identity.realm.lifecycle.v1",
            "component_codes": ["identity"],
            "depends_on": [],
            "input": {"desired_ref": "identity"},
        },
        {
            "step_id": application_step,
            "step_kind": "apply_operation",
            "capability_instance_ref": "collaboration.application",
            "capability_id": "collaboration.application.lifecycle.v1",
            "endpoint_code": "collaboration.application.lifecycle.v1",
            "component_codes": ["collaboration"],
            "depends_on": [identity_step],
            "input": {"desired_ref": "collaboration"},
        },
    ]
    templates = service._build_command_templates(
        deployment_ref="deployment-1",
        saved_plan_id=uuid4(),
        desired=SimpleNamespace(
            id=uuid4(),
            revision=1,
            desired_state_hash="sha256:" + "a" * 64,
            configuration_snapshot_ref="configuration:test@v1",
            configuration_schema_version=1,
            configuration_hash="sha256:" + "b" * 64,
            selected_composition_edges=[
                {
                    "source_capability_instance_ref": "identity.realm",
                    "source_capability_id": "identity.realm.lifecycle.v1",
                    "source_pointer": "/public_value",
                    "source_schema_ref": (
                        "schema:test/identity.realm.lifecycle/output@v1"
                    ),
                    "source_schema_digest": "sha256:" + "7" * 64,
                    "target_capability_instance_ref": "collaboration.application",
                    "target_capability_id": ("collaboration.application.lifecycle.v1"),
                    "target_pointer": "/upstream_value",
                    "target_schema_ref": (
                        "schema:test/collaboration.application.lifecycle/input@v1"
                    ),
                    "target_schema_digest": "sha256:" + "6" * 64,
                    "required": True,
                }
            ],
        ),
        profile=SimpleNamespace(
            id=uuid4(),
            profile_code="standard",
            version=1,
            schema_version=1,
            content_hash="sha256:" + "c" * 64,
            document={},
        ),
        bundle=SimpleNamespace(
            document={
                "components": [
                    {
                        "component_code": "identity",
                        "artifact": {"digest": "sha256:" + "d" * 64},
                    },
                    {
                        "component_code": "collaboration",
                        "artifact": {"digest": "sha256:" + "e" * 64},
                    },
                ]
            }
        ),
        binding_documents=bindings,
        steps=steps,
    )
    by_capability = {item["capability_id"]: item for item in templates}
    dependent = by_capability["collaboration.application.lifecycle.v1"]
    assert dependent["steps"][0]["depends_on"] == []
    assert dependent["prerequisite_capability_binding_ids"] == [str(identity_binding)]
    assert dependent["prerequisite_evidence_bindings"] == [
        {
            "source_capability_binding_id": str(identity_binding),
            "source_step_key": identity_step,
            "source_schema_ref": "schema:test/identity.realm.lifecycle/output@v1",
            "source_schema_digest": "sha256:" + "7" * 64,
            "source_pointer": "/public_value",
            "target_step_key": application_step,
            "target_schema_ref": (
                "schema:test/collaboration.application.lifecycle/input@v1"
            ),
            "target_schema_digest": "sha256:" + "6" * 64,
            "target_pointer": "/upstream_value",
            "required": True,
        }
    ]
    material = {
        key: value
        for key, value in dependent.items()
        if key != "approved_command_template_digest"
    }
    assert dependent["approved_command_template_digest"] == (
        "sha256:"
        + hashlib.sha256(
            service.canonical_provisioning_document_bytes(material)
        ).hexdigest()
    )

    class _ReceiptProjection:
        def require_succeeded(
            self,
            *,
            deployment_ref: str,
            plan_hash: str,
            capability_binding_id: UUID,
        ) -> service.PrerequisiteReceiptPin:
            return service.PrerequisiteReceiptPin(
                deployment_ref=deployment_ref,
                plan_hash=plan_hash,
                capability_binding_id=capability_binding_id,
                operation_id=UUID("b6451c6f-6f6a-44a7-9464-85ea18088cf7"),
                terminal_receipt_sequence=3,
                terminal_receipt_digest="sha256:" + "5" * 64,
                required_terminal_status="succeeded",
            )

    pins = service._resolve_prerequisite_receipt_pins(
        resolver=_ReceiptProjection(),
        deployment_ref="deployment-1",
        plan_hash="sha256:" + "6" * 64,
        prerequisite_binding_ids=[str(identity_binding)],
    )
    assert pins == [
        {
            "capability_binding_id": str(identity_binding),
            "operation_id": "b6451c6f-6f6a-44a7-9464-85ea18088cf7",
            "required_terminal_status": "succeeded",
            "terminal_receipt_digest": "sha256:" + "5" * 64,
            "terminal_receipt_sequence": 3,
        }
    ]


def test_expired_grant_and_naive_command_time_are_refused(db: Session) -> None:
    _deployment, _desired, plan, grant = _approved_plan(db)
    separation = service.CommandKeySeparationPolicy(
        command_key_id=_Signer.key_id,
        forbidden_key_ids=frozenset(),
        forbidden_public_keys_b64=frozenset(),
    )
    with pytest.raises(ConflictError, match="timezone"):
        service.build_approved_apply_commands(
            db,
            service.BuildApprovedApplyCommands(
                command_id_prefix="apply-naive",
                plan_id=plan.id,
                approval_grant_id=grant.id,
                audience="dotmac-integrator:abuja",
                issued_at=datetime(2026, 8, 17, 12, 0),
                expires_at=NOW + timedelta(minutes=2),
            ),
            signer=_Signer(),
            key_separation=separation,
            prerequisite_receipts=_NoPrerequisites(),
            now=NOW,
        )
    after_expiry = NOW + timedelta(minutes=11)
    with pytest.raises(ConflictError, match="grant has expired"):
        service.build_approved_apply_commands(
            db,
            service.BuildApprovedApplyCommands(
                command_id_prefix="apply-expired",
                plan_id=plan.id,
                approval_grant_id=grant.id,
                audience="dotmac-integrator:abuja",
                issued_at=after_expiry,
                expires_at=after_expiry + timedelta(minutes=2),
            ),
            signer=_Signer(),
            key_separation=separation,
            prerequisite_receipts=_NoPrerequisites(),
            now=after_expiry,
        )


def test_integrator_golden_fixture_uses_identical_canonical_json() -> None:
    fixture = json.loads(
        (
            Path(__file__).parents[2]
            / "docs/fixtures/provisioning_apply_command_v1.json"
        ).read_text(encoding="utf-8")
    )
    canonical_body = service.canonical_provisioning_document_bytes(
        fixture["body"]
    ).decode()
    template = json.loads(fixture["canonical_approved_command_template"])
    canonical_template = service.canonical_provisioning_document_bytes(
        template
    ).decode()
    canonical_header = service.canonical_provisioning_document_bytes(
        fixture["unsigned_header"]
    ).decode()
    assert canonical_body == fixture["canonical_body"]
    assert canonical_template == fixture["canonical_approved_command_template"]
    assert (
        "sha256:" + hashlib.sha256(canonical_template.encode()).hexdigest()
        == fixture["approved_command_template_digest"]
    )
    assert (
        "sha256:" + hashlib.sha256(canonical_body.encode()).hexdigest()
        == fixture["body_sha256"]
    )
    assert canonical_header == fixture["canonical_signature_input"]


def test_integrator_plan_golden_fixture_uses_identical_canonical_json() -> None:
    fixture = json.loads(
        (
            Path(__file__).parents[2]
            / "docs/fixtures/provisioning_plan_command_v1.json"
        ).read_text(encoding="utf-8")
    )
    canonical_body = service.canonical_provisioning_document_bytes(
        fixture["body"]
    ).decode()
    canonical_header = service.canonical_provisioning_document_bytes(
        fixture["unsigned_header"]
    ).decode()
    assert canonical_body == fixture["canonical_body"]
    assert (
        "sha256:" + hashlib.sha256(canonical_body.encode()).hexdigest()
        == fixture["body_sha256"]
    )
    assert canonical_header == fixture["canonical_signature_input"]
