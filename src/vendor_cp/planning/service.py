"""Owner of deterministic deployment plans and exact approval bindings.

Every operation is local database work.  Connector selection arrives as typed,
content-addressed input from Integrator; Vendor records it but never discovers a
plugin, dereferences a secret, performs provider I/O or executes a plan.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast, runtime_checkable
from uuid import NAMESPACE_URL, UUID, uuid5

from dotmac_kernel import (
    CapabilityContractError,
    CapabilitySchemaDocument,
    ConflictError,
    NotFoundError,
    write_platform_audit_event,
)
from dotmac_kernel.messaging import enqueue_platform_event, process_once_platform
from dotmac_release_catalog import (
    ArtifactAttestation,
    AttestationKind,
    Digest,
    ReleaseArtifact,
    pinned_reference,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter as allocations
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts.models import Contract, ContractStatus
from vendor_cp.fleet.models import Deployment, DeploymentDesiredStateVersion
from vendor_cp.managed_profiles import service as profiles
from vendor_cp.managed_profiles.instance_refs import is_capability_instance_ref
from vendor_cp.managed_profiles.models import ManagedServiceProfileVersion
from vendor_cp.managed_profiles.operation_inputs import (
    DesiredOperationInputError,
    validate_desired_operation_input,
)
from vendor_cp.planning.models import (
    DeploymentBundleManifestVersion,
    DeploymentPlan,
    DeploymentPlanApprovalGrant,
    DeploymentPlanApprovalRequest,
    IntegratorCommandDispatch,
    IntegratorExecutionReceipt,
)

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE = re.compile(r"^[a-z0-9](?:[a-z0-9._:-]{0,198}[a-z0-9])?$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,319}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CREATE_BUNDLE = "vendor.planning.publish_bundle"
_CREATE_PLAN = "vendor.planning.create_plan"
_REQUEST_APPROVAL = "vendor.planning.request_approval"
_RECORD_GRANT = "vendor.planning.record_grant"
COMMAND_SIGNING_PURPOSE = "vendor.deployment-command.v1"


@dataclass(frozen=True, slots=True)
class AttestationSelection:
    attestation_id: UUID
    digest: str


@dataclass(frozen=True, slots=True)
class ComponentArtifactSelection:
    component_code: str
    artifact_id: UUID
    artifact_digest: str
    artifact_reference: str
    provenance: AttestationSelection
    sbom: AttestationSelection
    signature: AttestationSelection
    product_manifest: AttestationSelection | None = None
    vulnerability_policy_result: AttestationSelection | None = None
    compatibility_result: AttestationSelection | None = None


@dataclass(frozen=True, slots=True)
class PublishBundleManifestCommand:
    command_id: str
    commercial_product_code: str
    profile_code: str
    profile_version: int
    bundle_code: str
    version: int
    components: tuple[ComponentArtifactSelection, ...]
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class BundleManifestView:
    id: UUID
    profile_version_id: UUID
    bundle_code: str
    version: int
    profile_content_hash: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class IntegratorBindingSelection:
    capability_instance_ref: str
    capability_id: str
    capability_schema_version: int
    installation_id: UUID
    installation_ref: str
    binding_ref: UUID
    connector_key: str
    connector_version: str
    connector_manifest_digest: str
    connector_artifact_digest: str
    connector_configuration_revision_id: UUID
    connector_configuration_digest: str
    execution_policy_digest: str


@dataclass(frozen=True, slots=True)
class VersionedPolicyRef:
    policy_code: str
    version: int


@dataclass(frozen=True, slots=True)
class CreateDeploymentPlanCommand:
    command_id: str
    deployment_id: UUID
    desired_state_version_id: UUID
    bundle_manifest_version_id: UUID
    allocation_id: UUID | None
    binding_selections: tuple[IntegratorBindingSelection, ...]
    lifecycle_policy: VersionedPolicyRef
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class DeploymentPlanView:
    id: UUID
    deployment_id: UUID
    revision: int
    desired_state_version_id: UUID
    bundle_manifest_version_id: UUID
    allocation_id: UUID | None
    plan_hash: str


@dataclass(frozen=True, slots=True)
class RequestPlanApprovalCommand:
    command_id: str
    plan_id: UUID
    policy_code: str
    policy_version: int
    expires_at: datetime
    requested_by: UUID
    plan_validation_receipt_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class RecordPlanApprovalGrantCommand:
    command_id: str
    plan_id: UUID
    approval_request_binding_id: UUID
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ApprovalRequestBindingView:
    id: UUID
    plan_id: UUID
    approval_request_id: UUID
    expires_at: datetime
    request_binding_hash: str


@dataclass(frozen=True, slots=True)
class ApprovalGrantView:
    id: UUID
    plan_id: UUID
    approval_request_binding_id: UUID
    approval_request_id: UUID
    expires_at: datetime
    grant_digest: str


@runtime_checkable
class DeploymentCommandSigningKey(Protocol):
    """Held deployment-command key; it exposes no private material."""

    @property
    def key_id(self) -> str: ...

    @property
    def purpose(self) -> str: ...

    @property
    def public_key_b64(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class PrerequisiteReceiptPin:
    """Verified local projection of one immutable Integrator terminal receipt."""

    deployment_ref: str
    plan_hash: str
    capability_binding_id: UUID
    operation_id: UUID
    terminal_receipt_sequence: int
    terminal_receipt_digest: str
    required_terminal_status: str


class PrerequisiteReceiptUnavailableError(ConflictError):
    """An approved dependent command is not dispatchable in the current wave."""


@runtime_checkable
class PrerequisiteReceiptResolver(Protocol):
    """Read verified, already-ingested Integrator evidence; performs no I/O."""

    def require_succeeded(
        self,
        *,
        deployment_ref: str,
        plan_hash: str,
        capability_binding_id: UUID,
    ) -> PrerequisiteReceiptPin: ...


@dataclass(frozen=True, slots=True)
class CommandKeySeparationPolicy:
    command_key_id: str
    forbidden_key_ids: frozenset[str]
    forbidden_public_keys_b64: frozenset[str]
    max_lifetime_seconds: int = 300


@dataclass(frozen=True, slots=True)
class BuildApprovedApplyCommands:
    command_id_prefix: str
    plan_id: UUID
    approval_grant_id: UUID
    audience: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class BuildPlanCommands:
    command_id_prefix: str
    plan_id: UUID
    audience: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class BuildObserveCommands:
    command_id_prefix: str
    plan_id: UUID
    approval_grant_id: UUID
    audience: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class BuildCancelCommands(BuildObserveCommands):
    """A Vendor compensation decision; reason is never connector-authored."""

    reason: str


@runtime_checkable
class IntegratorReceiptSignatureVerifier(Protocol):
    """Held Integrator receipt keys; verifies bytes without exposing material."""

    def verify(self, *, key_id: str, payload: bytes, signature_b64url: str) -> None: ...


@dataclass(frozen=True, slots=True)
class IngestIntegratorReceiptCommand:
    signed_receipt: Mapping[str, object]
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class IntegratorReceiptView:
    id: UUID
    dispatch_id: UUID
    plan_id: UUID
    capability_instance_ref: str
    capability_binding_id: UUID
    operation: str
    receipt_digest: str
    outcome: str
    operation_id: UUID | None
    latest_module_receipt_sequence: int | None
    latest_module_receipt_hash: str | None
    module_plan_receipt_hash: str | None


@dataclass(frozen=True, slots=True)
class SignedProvisioningCommandEnvelope:
    content_type: str
    key_id: str
    algorithm: str
    capability_id: str
    command_id: str
    document: dict[str, object]


def publish_bundle_manifest_version(
    db: Session, command: PublishBundleManifestCommand
) -> BundleManifestView:
    """Publish exact local-catalogue evidence for a reusable component bundle."""

    _require_code(command.bundle_code, "bundle code")
    if command.version < 1:
        raise ConflictError("bundle version must be positive")
    profile = profiles.get_profile_version(
        db,
        commercial_product_code=command.commercial_product_code,
        profile_code=command.profile_code,
        version=command.profile_version,
    )
    if profile is None:
        raise NotFoundError("no exact managed profile version exists for bundle")
    component_by_code = {item.component_code: item for item in command.components}
    if len(component_by_code) != len(command.components):
        raise ConflictError("bundle contains a duplicate component")
    profile_components = {item.component_code: item for item in profile.components}
    unknown = set(component_by_code) - set(profile_components)
    if unknown:
        raise ConflictError("bundle contains a component outside its exact profile")
    required = {item.component_code for item in profile.components if item.required}
    if missing := required - set(component_by_code):
        raise ConflictError(
            "bundle omits required profile component: " + ", ".join(sorted(missing))
        )
    for component_code in component_by_code:
        missing_dependencies = set(profile_components[component_code].depends_on) - set(
            component_by_code
        )
        if missing_dependencies:
            raise ConflictError(
                f"bundle component {component_code!r} omits dependency: "
                + ", ".join(sorted(missing_dependencies))
            )

    component_documents = [
        _artifact_document(db, component_by_code[code])
        for code in sorted(component_by_code)
    ]
    document: dict[str, object] = {
        "content_schema": "vendor.deployment-bundle-manifest@v1",
        "commercial_product_code": profile.commercial_product_code,
        "profile": {
            "id": str(profile.id),
            "profile_code": profile.profile_code,
            "version": profile.version,
            "content_hash": profile.content_hash,
        },
        "bundle_code": command.bundle_code,
        "version": command.version,
        "components": component_documents,
    }
    content_hash = _content_hash(document)

    def handler(session: Session) -> dict[str, object]:
        row = DeploymentBundleManifestVersion(
            profile_version_id=profile.id,
            bundle_code=command.bundle_code,
            version=command.version,
            profile_content_hash=profile.content_hash,
            content_hash=content_hash,
            document=document,
        )
        _insert_immutable(
            session,
            row,
            message="bundle version or content was published concurrently",
        )
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.deployment_bundle.published",
            entity_type="deployment_bundle_manifest_version",
            entity_id=str(row.id),
            details={
                "profile_version_id": str(profile.id),
                "bundle_code": command.bundle_code,
                "version": command.version,
                "content_hash": content_hash,
            },
        )
        return {"bundle_id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CREATE_BUNDLE,
        handler=handler,
    )
    row = db.get(
        DeploymentBundleManifestVersion,
        UUID(str(outcome.result["bundle_id"])),
    )
    if row is None:
        raise ConflictError("recorded bundle manifest disappeared")
    return _bundle_view(row)


def create_deployment_plan(
    db: Session, command: CreateDeploymentPlanCommand
) -> DeploymentPlanView:
    """Freeze a deterministic plan; no operation in this function executes it."""

    _validate_policy(command.lifecycle_policy, label="lifecycle policy")

    def handler(session: Session) -> dict[str, object]:
        deployment = session.scalar(
            select(Deployment)
            .where(Deployment.id == command.deployment_id)
            .with_for_update()
        )
        if deployment is None:
            raise NotFoundError(f"deployment {command.deployment_id} not found")
        desired = session.get(
            DeploymentDesiredStateVersion, command.desired_state_version_id
        )
        if (
            desired is None
            or desired.deployment_id != deployment.id
            or desired.revision != deployment.current_desired_state_revision
        ):
            raise ConflictError(
                "plan must bind the deployment's exact current desired state"
            )
        bundle = session.get(
            DeploymentBundleManifestVersion, command.bundle_manifest_version_id
        )
        if bundle is None:
            raise NotFoundError("bundle manifest version not found")
        if (
            bundle.profile_version_id != desired.profile_version_id
            or bundle.profile_content_hash != desired.profile_content_hash
        ):
            raise ConflictError(
                "bundle does not bind the desired state's exact profile"
            )
        profile_row = session.get(
            ManagedServiceProfileVersion, desired.profile_version_id
        )
        if (
            profile_row is None
            or profile_row.content_hash != desired.profile_content_hash
        ):
            raise ConflictError("desired state's exact managed profile is unavailable")
        bundle_components = {
            str(item["component_code"])
            for item in _document_list(bundle.document, "components")
        }
        missing_artifacts = set(desired.selected_components) - bundle_components
        if missing_artifacts:
            raise ConflictError(
                "bundle lacks selected component artifact: "
                + ", ".join(sorted(missing_artifacts))
            )

        bindings = _binding_documents(
            desired=desired, selections=command.binding_selections
        )
        allocation_document = _allocation_document(
            session,
            deployment=deployment,
            allocation_id=command.allocation_id,
        )
        steps = _build_steps(
            desired=desired,
            profile_document=profile_row.document,
            binding_documents=bindings,
            lifecycle_policy=command.lifecycle_policy,
        )
        plan_inputs: dict[str, object] = {
            "deployment_id": str(deployment.id),
            "desired_state_version_id": str(desired.id),
            "desired_state_hash": desired.desired_state_hash,
            "bundle_manifest_version_id": str(bundle.id),
            "bundle_hash": bundle.content_hash,
            "allocation": allocation_document,
            "binding_selections": bindings,
            "lifecycle_policy": {
                "policy_code": command.lifecycle_policy.policy_code,
                "version": command.lifecycle_policy.version,
            },
            "steps": steps,
        }
        plan_input_hash = _content_hash(plan_inputs)
        revision = deployment.latest_plan_revision + 1
        plan_identity: dict[str, object] = {
            **plan_inputs,
            "revision": revision,
        }
        plan_id = uuid5(NAMESPACE_URL, _content_hash(plan_identity))
        command_templates = _build_command_templates(
            deployment_ref=deployment.deployment_ref,
            saved_plan_id=plan_id,
            desired=desired,
            profile=profile_row,
            bundle=bundle,
            binding_documents=bindings,
            steps=steps,
        )
        document: dict[str, object] = {
            "content_schema": "vendor.deployment-plan@v1",
            "deployment": {
                "id": str(deployment.id),
                "deployment_ref": deployment.deployment_ref,
                "account_id": str(deployment.account_id),
                "target_id": str(deployment.target_id),
                "commercial_product_code": deployment.commercial_product_code,
                "contract_id": (
                    str(deployment.contract_id)
                    if deployment.contract_id is not None
                    else None
                ),
                "internal_source_code": deployment.internal_source_code,
            },
            "desired_state": {
                "id": str(desired.id),
                "revision": desired.revision,
                "content_hash": desired.desired_state_hash,
                "configuration_hash": desired.configuration_hash,
                "configuration_snapshot_ref": desired.configuration_snapshot_ref,
                "configuration_schema_version": desired.configuration_schema_version,
                "update_authority": desired.update_authority,
                "verification_checks": desired.selected_verification_checks,
            },
            "profile": {
                "id": str(desired.profile_version_id),
                "profile_code": desired.profile_code,
                "version": desired.profile_version,
                "schema_version": profile_row.schema_version,
                "content_hash": desired.profile_content_hash,
            },
            "bundle": {
                "id": str(bundle.id),
                "content_hash": bundle.content_hash,
                "components": [
                    item
                    for item in _document_list(bundle.document, "components")
                    if str(item["component_code"]) in set(desired.selected_components)
                ],
            },
            "allocation": allocation_document,
            "binding_selections": bindings,
            "lifecycle_policy": {
                "policy_code": command.lifecycle_policy.policy_code,
                "version": command.lifecycle_policy.version,
            },
            "steps": steps,
            "command_templates": command_templates,
            "plan_input_hash": plan_input_hash,
        }
        plan_hash = _content_hash(document)
        if deployment.current_plan_id is not None:
            current = session.get(DeploymentPlan, deployment.current_plan_id)
            if current is None:
                raise ConflictError("deployment current-plan pointer is broken")
            if current.document.get("plan_input_hash") == plan_input_hash:
                raise ConflictError("an equivalent deployment plan is already current")
        row = DeploymentPlan(
            id=plan_id,
            deployment_id=deployment.id,
            revision=revision,
            predecessor_plan_id=deployment.current_plan_id,
            desired_state_version_id=desired.id,
            bundle_manifest_version_id=bundle.id,
            allocation_id=command.allocation_id,
            plan_hash=plan_hash,
            document=document,
        )
        _insert_immutable(
            session,
            row,
            message="deployment plan revision was created concurrently",
        )
        deployment.current_plan_id = row.id
        deployment.latest_plan_revision = revision
        deployment.status = "plan_ready"
        session.flush()
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.deployment_plan.created",
            entity_type="deployment_plan",
            entity_id=str(row.id),
            details={
                "deployment_id": str(deployment.id),
                "revision": revision,
                "desired_state_hash": desired.desired_state_hash,
                "bundle_hash": bundle.content_hash,
                "plan_hash": plan_hash,
            },
        )
        enqueue_platform_event(
            session,
            event_type="deployment.plan_created",
            payload={
                "deployment_id": str(deployment.id),
                "plan_id": str(row.id),
                "plan_hash": plan_hash,
                "revision": revision,
            },
            correlation_id=str(deployment.id),
        )
        return {"plan_id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CREATE_PLAN,
        handler=handler,
    )
    row = db.get(DeploymentPlan, UUID(str(outcome.result["plan_id"])))
    if row is None:
        raise ConflictError("recorded deployment plan disappeared")
    return _plan_view(row)


def request_plan_approval(
    db: Session,
    command: RequestPlanApprovalCommand,
    *,
    now: datetime | None = None,
) -> ApprovalRequestBindingView:
    """Open the sole approval authority against one exact current plan hash."""

    effective_now = _require_aware_input(now or datetime.now(UTC), label="current time")
    expires_at = _require_aware_input(command.expires_at, label="approval expiry")
    if expires_at <= effective_now:
        raise ConflictError("approval request expiry must be in the future")
    _require_code(command.policy_code, "approval policy code")
    if command.policy_version < 1:
        raise ConflictError("approval policy version must be positive")

    def handler(session: Session) -> dict[str, object]:
        plan, _deployment = _require_current_plan(session, command.plan_id)
        validations = _require_complete_plan_validations(
            session,
            plan=plan,
            receipt_ids=command.plan_validation_receipt_ids,
        )
        authority = approvals.open_request(
            session,
            approvals.OpenRequestCommand(
                command_id=f"{command.command_id}:authority",
                policy_code=command.policy_code,
                policy_version=command.policy_version,
                subject_type="deployment_plan",
                subject_id=str(plan.id),
                content_hash=_bare_hash(plan.plan_hash),
                requested_by=command.requested_by,
            ),
        )
        document: dict[str, object] = {
            "content_schema": "vendor.deployment-plan-approval-request@v1",
            "plan_id": str(plan.id),
            "plan_hash": plan.plan_hash,
            "approval_request_id": str(authority.request_id),
            "policy_code": command.policy_code,
            "policy_version": command.policy_version,
            "expires_at": _time_text(expires_at),
            "plan_validations": validations,
        }
        row = DeploymentPlanApprovalRequest(
            plan_id=plan.id,
            approval_request_id=authority.request_id,
            policy_code=command.policy_code,
            policy_version=command.policy_version,
            expires_at=expires_at,
            request_binding_hash=_content_hash(document),
            document=document,
        )
        _insert_immutable(
            session,
            row,
            message="plan approval request was bound concurrently",
        )
        write_platform_audit_event(
            session,
            actor_admin_id=command.requested_by,
            action="vendor.deployment_plan.approval_requested",
            entity_type="deployment_plan",
            entity_id=str(plan.id),
            details={
                "approval_request_id": str(authority.request_id),
                "plan_hash": plan.plan_hash,
                "expires_at": _time_text(expires_at),
            },
        )
        return {"binding_id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_REQUEST_APPROVAL,
        handler=handler,
    )
    row = db.get(
        DeploymentPlanApprovalRequest,
        UUID(str(outcome.result["binding_id"])),
    )
    if row is None:
        raise ConflictError("recorded plan approval request disappeared")
    return _request_view(row)


def record_plan_approval_grant(
    db: Session,
    command: RecordPlanApprovalGrantCommand,
    *,
    now: datetime | None = None,
) -> ApprovalGrantView:
    """Record authority satisfaction without becoming a second vote counter."""

    effective_now = _require_aware_input(now or datetime.now(UTC), label="current time")

    def handler(session: Session) -> dict[str, object]:
        plan, _deployment = _require_current_plan(session, command.plan_id)
        request = session.get(
            DeploymentPlanApprovalRequest, command.approval_request_binding_id
        )
        if request is None or request.plan_id != plan.id:
            raise ConflictError("approval request binding does not belong to plan")
        expires_at = _aware(request.expires_at, label="approval expiry")
        if expires_at <= effective_now:
            raise ConflictError("plan approval request has expired")
        evaluation = approvals.evaluate_request(
            session, request_id=request.approval_request_id
        )
        if not evaluation.satisfied:
            raise ConflictError("approval authority has not approved the exact plan")
        document: dict[str, object] = {
            "content_schema": "vendor.deployment-plan-approval-grant@v1",
            "plan_id": str(plan.id),
            "plan_hash": plan.plan_hash,
            "approval_request_binding_id": str(request.id),
            "approval_request_id": str(request.approval_request_id),
            "request_binding_hash": request.request_binding_hash,
            "expires_at": _time_text(expires_at),
            "plan_validations": request.document["plan_validations"],
        }
        row = DeploymentPlanApprovalGrant(
            plan_id=plan.id,
            approval_request_binding_id=request.id,
            approval_request_id=request.approval_request_id,
            expires_at=expires_at,
            grant_digest=_content_hash(document),
            document=document,
        )
        _insert_immutable(
            session,
            row,
            message="plan approval grant was recorded concurrently",
        )
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.deployment_plan.approval_granted",
            entity_type="deployment_plan",
            entity_id=str(plan.id),
            details={
                "approval_request_id": str(request.approval_request_id),
                "plan_hash": plan.plan_hash,
                "grant_digest": row.grant_digest,
                "expires_at": _time_text(expires_at),
            },
        )
        return {"grant_id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_RECORD_GRANT,
        handler=handler,
    )
    row = db.get(
        DeploymentPlanApprovalGrant,
        UUID(str(outcome.result["grant_id"])),
    )
    if row is None:
        raise ConflictError("recorded plan approval grant disappeared")
    return _grant_view(row)


def build_plan_commands(
    db: Session,
    command: BuildPlanCommands,
    *,
    signer: DeploymentCommandSigningKey,
    key_separation: CommandKeySeparationPolicy,
    now: datetime | None = None,
) -> tuple[SignedProvisioningCommandEnvelope, ...]:
    """Sign and record one minimal Integrator PLAN command per binding."""

    effective_now = _require_aware_input(now or datetime.now(UTC), label="current time")
    issued_at, expires_at = _require_envelope_inputs(
        command_id_prefix=command.command_id_prefix,
        audience=command.audience,
        issued_at=command.issued_at,
        expires_at=command.expires_at,
        now=effective_now,
    )
    _require_separate_command_key(signer, key_separation)
    _require_command_lifetime(issued_at, expires_at, key_separation)
    plan, deployment = _require_current_plan(db, command.plan_id)
    envelopes: list[SignedProvisioningCommandEnvelope] = []
    for template in _document_list(plan.document, "command_templates"):
        instance_ref = str(template["capability_instance_ref"])
        capability_id = str(template["capability_id"])
        binding_id = UUID(str(template["capability_binding_id"]))
        body: dict[str, object] = {
            "deployment_ref": deployment.deployment_ref,
            "capability_instance_ref": instance_ref,
            "capability_id": capability_id,
            "capability_binding_id": str(binding_id),
            "plan_hash": plan.plan_hash,
            "config_digest": template["config_digest"],
            "steps": _document_list(template, "steps"),
        }
        command_id = f"{command.command_id_prefix}:{instance_ref}"
        envelope = _signed_envelope(
            signer=signer,
            audience=command.audience,
            command_id=command_id,
            issued_at=issued_at,
            expires_at=expires_at,
            capability_id=capability_id,
            body=body,
        )
        _record_dispatch(
            db,
            plan=plan,
            deployment=deployment,
            binding_id=binding_id,
            operation="plan",
            envelope=envelope,
        )
        envelopes.append(envelope)
    return tuple(envelopes)


def build_approved_apply_commands(
    db: Session,
    command: BuildApprovedApplyCommands,
    *,
    signer: DeploymentCommandSigningKey,
    key_separation: CommandKeySeparationPolicy,
    prerequisite_receipts: PrerequisiteReceiptResolver,
    now: datetime | None = None,
) -> tuple[SignedProvisioningCommandEnvelope, ...]:
    """Sign one exact Integrator APPLY command per planned capability binding."""

    effective_now = _require_aware_input(now or datetime.now(UTC), label="current time")
    issued_at, expires_at = _require_envelope_inputs(
        command_id_prefix=command.command_id_prefix,
        audience=command.audience,
        issued_at=command.issued_at,
        expires_at=command.expires_at,
        now=effective_now,
    )
    _require_separate_command_key(signer, key_separation)
    _require_command_lifetime(issued_at, expires_at, key_separation)
    plan, _deployment = _require_current_plan(db, command.plan_id)
    grant = _require_usable_grant(
        db,
        plan=plan,
        grant_id=command.approval_grant_id,
        now=effective_now,
    )
    deployment = db.get(Deployment, plan.deployment_id)
    if deployment is None:
        raise ConflictError("approved plan deployment disappeared")
    templates = _document_list(plan.document, "command_templates")
    envelopes: list[SignedProvisioningCommandEnvelope] = []
    for template in templates:
        instance_ref = str(template["capability_instance_ref"])
        capability_id = str(template["capability_id"])
        binding_ref = str(template["capability_binding_id"])
        try:
            binding_id = UUID(binding_ref)
        except ValueError as exc:
            raise ConflictError(
                "planned Integrator binding reference must be a UUID"
            ) from exc
        if _binding_has_succeeded_receipt(
            db,
            plan_id=plan.id,
            capability_binding_id=binding_id,
            operation="apply",
        ):
            continue
        body_steps = _document_list(template, "steps")
        if not body_steps:
            raise ConflictError(
                "planned capability binding has no versioned endpoint step"
            )
        template_material = {
            key: value
            for key, value in template.items()
            if key not in {"approved_command_template_digest"}
        }
        template_digest = str(template.get("approved_command_template_digest"))
        if _content_hash(template_material) != template_digest:
            raise ConflictError("approved command template digest no longer matches")
        prerequisite_binding_ids = _string_list(
            template, "prerequisite_capability_binding_ids"
        )
        try:
            receipt_pins = _resolve_prerequisite_receipt_pins(
                resolver=prerequisite_receipts,
                deployment_ref=deployment.deployment_ref,
                plan_hash=plan.plan_hash,
                prerequisite_binding_ids=prerequisite_binding_ids,
            )
        except PrerequisiteReceiptUnavailableError:
            continue
        validation = _plan_validation_for_binding(
            request_document=grant.document,
            binding_id=binding_id,
        )
        command_id = f"{command.command_id_prefix}:{instance_ref}"
        body: dict[str, object] = {
            **template_material,
            "capability_id": capability_id,
            "capability_binding_id": binding_ref,
            "plan_hash": plan.plan_hash,
            "config_digest": template["config_digest"],
            "steps": body_steps,
            "deployment_ref": deployment.deployment_ref,
            "artifact_digest": template["artifact_digest"],
            "expected_plan_hash": plan.plan_hash,
            "approved_command_template_digest": template_digest,
            "approval_request_id": str(grant.approval_request_id),
            "approval_request_binding_hash": grant.document["request_binding_hash"],
            "plan_command_id": validation["plan_command_id"],
            "plan_validation_receipt_id": validation["receipt_id"],
            "plan_validation_receipt_digest": validation["receipt_digest"],
            "plan_validation_request_body_digest": validation["request_body_digest"],
            "module_plan_receipt_hash": validation["module_plan_receipt_hash"],
            "prerequisite_capability_binding_ids": prerequisite_binding_ids,
            "prerequisite_receipt_pins": receipt_pins,
            "approval": {
                "grant_ref": str(grant.id),
                "approval_request_id": str(grant.approval_request_id),
                "approval_request_binding_hash": grant.document["request_binding_hash"],
                "saved_plan_id": str(plan.id),
                "approved_plan_hash": plan.plan_hash,
                "approved_command_template_digest": template_digest,
                "digest": grant.grant_digest,
                "plan_command_id": validation["plan_command_id"],
                "plan_validation_receipt_id": validation["receipt_id"],
                "plan_validation_receipt_digest": validation["receipt_digest"],
                "plan_validation_request_body_digest": validation[
                    "request_body_digest"
                ],
                "module_plan_receipt_hash": validation["module_plan_receipt_hash"],
                "expires_at": _time_text(grant.expires_at),
                "verified_at": _time_text(grant.created_at),
            },
        }
        envelope = _signed_envelope(
            signer=signer,
            audience=command.audience,
            command_id=command_id,
            issued_at=issued_at,
            expires_at=expires_at,
            capability_id=capability_id,
            body=body,
        )
        _record_dispatch(
            db,
            plan=plan,
            deployment=deployment,
            binding_id=binding_id,
            operation="apply",
            envelope=envelope,
        )
        envelopes.append(envelope)
    return tuple(envelopes)


def build_observe_commands(
    db: Session,
    command: BuildObserveCommands,
    *,
    signer: DeploymentCommandSigningKey,
    key_separation: CommandKeySeparationPolicy,
    now: datetime | None = None,
) -> tuple[SignedProvisioningCommandEnvelope, ...]:
    """Sign observations for every approved, owner-declared verification slice."""

    return _build_lifecycle_commands(
        db,
        command=command,
        signer=signer,
        key_separation=key_separation,
        operation="observe",
        reason=None,
        now=now,
    )


def build_cancel_commands(
    db: Session,
    command: BuildCancelCommands,
    *,
    signer: DeploymentCommandSigningKey,
    key_separation: CommandKeySeparationPolicy,
    now: datetime | None = None,
) -> tuple[SignedProvisioningCommandEnvelope, ...]:
    """Sign Vendor's compensation decision from verified provider-step pins."""

    reason = command.reason
    if not reason or reason.strip() != reason or len(reason) > 500:
        raise ConflictError(
            "cancellation reason must be 1-500 non-whitespace-bound characters"
        )
    return _build_lifecycle_commands(
        db,
        command=command,
        signer=signer,
        key_separation=key_separation,
        operation="cancel",
        reason=reason,
        now=now,
    )


def _build_lifecycle_commands(
    db: Session,
    *,
    command: BuildObserveCommands,
    signer: DeploymentCommandSigningKey,
    key_separation: CommandKeySeparationPolicy,
    operation: str,
    reason: str | None,
    now: datetime | None,
) -> tuple[SignedProvisioningCommandEnvelope, ...]:
    effective_now = _require_aware_input(now or datetime.now(UTC), label="current time")
    issued_at, expires_at = _require_envelope_inputs(
        command_id_prefix=command.command_id_prefix,
        audience=command.audience,
        issued_at=command.issued_at,
        expires_at=command.expires_at,
        now=effective_now,
    )
    _require_separate_command_key(signer, key_separation)
    _require_command_lifetime(issued_at, expires_at, key_separation)
    plan, deployment = _require_current_plan(db, command.plan_id)
    grant = _require_bound_grant(
        db,
        plan=plan,
        grant_id=command.approval_grant_id,
    )
    verification_bindings = _verification_binding_ids(plan)
    templates = {
        UUID(str(item["capability_binding_id"])): item
        for item in _document_list(plan.document, "command_templates")
    }
    selected_bindings = (
        verification_bindings if operation == "observe" else set(templates)
    )
    envelopes: list[SignedProvisioningCommandEnvelope] = []
    for binding_id in sorted(selected_bindings, key=str):
        template = templates.get(binding_id)
        if template is None:
            raise ConflictError("verification step names no planned capability binding")
        try:
            receipt = _latest_execution_receipt(
                db,
                plan=plan,
                deployment=deployment,
                binding_id=binding_id,
                grant=grant,
                template=template,
            )
        except PrerequisiteReceiptUnavailableError:
            continue
        capability_id = str(template["capability_id"])
        instance_ref = str(template["capability_instance_ref"])
        for pin in _typed_step_pins(receipt):
            step_key = str(pin["step_key"])
            body: dict[str, object] = {
                "deployment_ref": deployment.deployment_ref,
                "capability_instance_ref": instance_ref,
                "operation_id": str(receipt.operation_id),
                "step_key": step_key,
                "provider_operation_ref": pin["provider_operation_ref"],
                "plan_hash": plan.plan_hash,
                "approval_digest": grant.grant_digest,
                "artifact_digest": template["artifact_digest"],
                "config_digest": template["config_digest"],
            }
            if reason is not None:
                body["reason"] = reason
            command_id = (
                f"{command.command_id_prefix}:{operation}:{instance_ref}:{step_key}"
            )
            envelope = _signed_envelope(
                signer=signer,
                audience=command.audience,
                command_id=command_id,
                issued_at=issued_at,
                expires_at=expires_at,
                capability_id=capability_id,
                body=body,
            )
            _record_dispatch(
                db,
                plan=plan,
                deployment=deployment,
                binding_id=binding_id,
                operation=operation,
                envelope=envelope,
            )
            envelopes.append(envelope)
    return tuple(envelopes)


def ingest_integrator_receipt(
    db: Session,
    command: IngestIntegratorReceiptCommand,
    *,
    verifier: IntegratorReceiptSignatureVerifier,
) -> IntegratorReceiptView:
    """Verify and append one receipt for a command Vendor actually signed."""

    signed = _strict_object(
        command.signed_receipt,
        keys={"key_id", "receipt_sha256", "signature", "receipt"},
        label="signed Integrator receipt",
    )
    key_id = _required_string(signed, "key_id")
    digest = _required_string(signed, "receipt_sha256")
    signature = _required_string(signed, "signature")
    _require_hash(digest)
    receipt = _strict_object(
        signed.get("receipt"),
        keys={
            "receipt_contract_version",
            "command_contract_version",
            "operation",
            "command_id",
            "nonce",
            "issuer_account_ref",
            "deployment_ref",
            "capability_instance_ref",
            "request_body_sha256",
            "plan_hash",
            "approval_digest",
            "artifact_digest",
            "config_digest",
            "outcome",
            "operation_id",
            "replayed",
            "latest_module_receipt_sequence",
            "latest_module_receipt_hash",
            "module_plan_receipt_hash",
            "occurred_at",
            "evidence",
        },
        label="Integrator receipt payload",
    )
    if _content_hash(receipt) != digest:
        raise ConflictError("Integrator receipt digest does not match its payload")
    verifier.verify(
        key_id=key_id,
        payload=_canonical({"key_id": key_id, "receipt_sha256": digest}),
        signature_b64url=signature,
    )
    if receipt["receipt_contract_version"] != "integrator.provisioning-receipt.v1":
        raise ConflictError("Integrator receipt contract version is unsupported")
    if receipt["command_contract_version"] != "integrator.provisioning-command.v1":
        raise ConflictError("Integrator command contract version is unsupported")
    command_id = _required_string(receipt, "command_id")
    if receipt.get("nonce") != command_id:
        raise ConflictError("Integrator receipt nonce does not match command identity")
    dispatch = db.scalar(
        select(IntegratorCommandDispatch).where(
            IntegratorCommandDispatch.command_id == command_id
        )
    )
    if dispatch is None:
        raise ConflictError("Integrator receipt names no Vendor-signed command")
    operation = _required_string(receipt, "operation")
    request_digest = _required_string(receipt, "request_body_sha256")
    if (
        operation != dispatch.operation
        or request_digest != dispatch.request_body_digest
    ):
        raise ConflictError("Integrator receipt does not match the signed command")
    plan = db.get(DeploymentPlan, dispatch.plan_id)
    deployment = db.get(Deployment, dispatch.deployment_id)
    if plan is None or deployment is None or plan.deployment_id != deployment.id:
        raise ConflictError("Integrator receipt dispatch ownership is broken")
    if (
        receipt.get("deployment_ref") != deployment.deployment_ref
        or receipt.get("plan_hash") != plan.plan_hash
    ):
        raise ConflictError("Integrator receipt crosses deployment or plan identity")
    body = _document_object(dispatch.document, "body")
    capability_instance_ref = _required_string(receipt, "capability_instance_ref")
    if (
        not is_capability_instance_ref(capability_instance_ref)
        or capability_instance_ref != dispatch.capability_instance_ref
        or capability_instance_ref != body.get("capability_instance_ref")
    ):
        raise ConflictError("Integrator receipt changes capability instance identity")
    if receipt.get("config_digest") != body.get("config_digest"):
        raise ConflictError("Integrator receipt changes connector configuration")
    expected_approval: object = None
    expected_artifact: object = None
    if operation == "apply":
        expected_approval = _document_object(body, "approval").get("digest")
        expected_artifact = body.get("artifact_digest")
    elif operation in {"observe", "cancel"}:
        expected_approval = body.get("approval_digest")
        expected_artifact = body.get("artifact_digest")
    if receipt.get("approval_digest") != expected_approval:
        raise ConflictError("Integrator receipt changes the approved grant")
    if receipt.get("artifact_digest") != expected_artifact:
        raise ConflictError("Integrator receipt changes connector artifact evidence")
    operation_id = _optional_uuid(receipt.get("operation_id"), "operation id")
    latest_sequence = _optional_positive_int(
        receipt.get("latest_module_receipt_sequence"), "module receipt sequence"
    )
    latest_hash = _optional_hash(
        receipt.get("latest_module_receipt_hash"), "module receipt hash"
    )
    module_plan_hash = _optional_hash(
        receipt.get("module_plan_receipt_hash"), "module PLAN receipt hash"
    )
    outcome = _required_string(receipt, "outcome")
    _validate_module_projection(
        receipt=receipt,
        operation=operation,
        command_id=command_id,
        request_digest=request_digest,
        outcome=outcome,
        operation_id=operation_id,
        latest_sequence=latest_sequence,
        latest_hash=latest_hash,
        module_plan_hash=module_plan_hash,
    )
    if operation != "plan":
        _validate_execution_projection_against_plan(
            receipt=receipt,
            plan=plan,
            binding_id=dispatch.capability_binding_id,
        )
    occurred_at = _parse_time(receipt.get("occurred_at"), "receipt occurrence")

    existing = db.scalar(
        select(IntegratorExecutionReceipt).where(
            IntegratorExecutionReceipt.receipt_digest == digest
        )
    )
    if existing is not None:
        return _require_exact_receipt_replay(existing, dispatch=dispatch, signed=signed)
    row = IntegratorExecutionReceipt(
        dispatch_id=dispatch.id,
        plan_id=plan.id,
        deployment_id=deployment.id,
        capability_instance_ref=capability_instance_ref,
        capability_binding_id=dispatch.capability_binding_id,
        operation=operation,
        command_id=command_id,
        request_body_digest=request_digest,
        receipt_digest=digest,
        outcome=outcome,
        operation_id=operation_id,
        latest_module_receipt_sequence=latest_sequence,
        latest_module_receipt_hash=latest_hash,
        module_plan_receipt_hash=module_plan_hash,
        occurred_at=occurred_at,
        document=dict(signed),
    )
    try:
        _insert_immutable(
            db, row, message="Integrator receipt was ingested concurrently"
        )
    except ConflictError:
        concurrent = db.scalar(
            select(IntegratorExecutionReceipt).where(
                IntegratorExecutionReceipt.receipt_digest == digest
            )
        )
        if concurrent is not None:
            return _require_exact_receipt_replay(
                concurrent, dispatch=dispatch, signed=signed
            )
        raise
    write_platform_audit_event(
        db,
        actor_admin_id=command.actor_admin_id,
        action="vendor.integrator_receipt.ingested",
        entity_type="integrator_execution_receipt",
        entity_id=str(row.id),
        details={
            "plan_id": str(plan.id),
            "capability_instance_ref": capability_instance_ref,
            "capability_binding_id": str(dispatch.capability_binding_id),
            "operation": operation,
            "outcome": outcome,
            "receipt_digest": digest,
        },
    )
    return _receipt_view(row)


class VerifiedReceiptResolver:
    """Resolve prerequisite pins solely from Vendor's verified projection."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def require_succeeded(
        self,
        *,
        deployment_ref: str,
        plan_hash: str,
        capability_binding_id: UUID,
    ) -> PrerequisiteReceiptPin:
        rows = self._db.scalars(
            select(IntegratorExecutionReceipt)
            .join(
                DeploymentPlan,
                DeploymentPlan.id == IntegratorExecutionReceipt.plan_id,
            )
            .join(
                Deployment,
                Deployment.id == IntegratorExecutionReceipt.deployment_id,
            )
            .where(
                Deployment.deployment_ref == deployment_ref,
                DeploymentPlan.plan_hash == plan_hash,
                IntegratorExecutionReceipt.capability_binding_id
                == capability_binding_id,
                IntegratorExecutionReceipt.operation.in_(("apply", "observe")),
                IntegratorExecutionReceipt.operation_id.is_not(None),
                IntegratorExecutionReceipt.latest_module_receipt_sequence.is_not(None),
                IntegratorExecutionReceipt.latest_module_receipt_hash.is_not(None),
            )
        ).all()
        if not rows:
            raise PrerequisiteReceiptUnavailableError(
                "no verified prerequisite receipt was ingested"
            )
        row = max(
            rows,
            key=lambda value: (
                value.latest_module_receipt_sequence or 0,
                value.occurred_at,
            ),
        )
        if (
            row.outcome != "succeeded"
            or row.operation_id is None
            or row.latest_module_receipt_sequence is None
            or row.latest_module_receipt_hash is None
        ):
            raise PrerequisiteReceiptUnavailableError(
                "latest verified prerequisite is not succeeded"
            )
        return PrerequisiteReceiptPin(
            deployment_ref=deployment_ref,
            plan_hash=plan_hash,
            capability_binding_id=capability_binding_id,
            operation_id=row.operation_id,
            terminal_receipt_sequence=row.latest_module_receipt_sequence,
            terminal_receipt_digest=row.latest_module_receipt_hash,
            required_terminal_status="succeeded",
        )


def _verification_binding_ids(plan: DeploymentPlan) -> set[UUID]:
    result: set[UUID] = set()
    for step in _document_list(plan.document, "steps"):
        if step.get("step_kind") != "verify":
            continue
        bindings = _string_list(step, "bindings")
        if len(bindings) != 1:
            raise ConflictError("verification step must name exactly one binding")
        try:
            result.add(UUID(bindings[0]))
        except ValueError as exc:
            raise ConflictError("verification step binding is not a UUID") from exc
    return result


def _latest_execution_receipt(
    db: Session,
    *,
    plan: DeploymentPlan,
    deployment: Deployment,
    binding_id: UUID,
    grant: DeploymentPlanApprovalGrant,
    template: Mapping[str, object],
) -> IntegratorExecutionReceipt:
    rows = db.scalars(
        select(IntegratorExecutionReceipt).where(
            IntegratorExecutionReceipt.plan_id == plan.id,
            IntegratorExecutionReceipt.deployment_id == deployment.id,
            IntegratorExecutionReceipt.capability_binding_id == binding_id,
            IntegratorExecutionReceipt.operation.in_(("apply", "observe")),
            IntegratorExecutionReceipt.operation_id.is_not(None),
            IntegratorExecutionReceipt.latest_module_receipt_sequence.is_not(None),
            IntegratorExecutionReceipt.latest_module_receipt_hash.is_not(None),
        )
    ).all()
    if not rows:
        raise PrerequisiteReceiptUnavailableError(
            "no verified execution receipt exists for lifecycle work"
        )
    row = max(
        rows,
        key=lambda value: (
            value.latest_module_receipt_sequence or 0,
            value.occurred_at,
            str(value.id),
        ),
    )
    receipt = _document_object(row.document, "receipt")
    if (
        receipt.get("deployment_ref") != deployment.deployment_ref
        or receipt.get("plan_hash") != plan.plan_hash
        or receipt.get("approval_digest") != grant.grant_digest
        or receipt.get("artifact_digest") != template.get("artifact_digest")
        or receipt.get("config_digest") != template.get("config_digest")
    ):
        raise ConflictError("verified execution receipt does not match approved pins")
    return row


def _typed_step_pins(row: IntegratorExecutionReceipt) -> list[dict[str, str]]:
    if row.operation_id is None:
        raise ConflictError("execution receipt has no operation identity")
    receipt = _document_object(row.document, "receipt")
    evidence = _document_object(receipt, "evidence")
    chain = _document_list(evidence, "module_receipts")
    by_step: dict[str, str] = {}
    for item in chain:
        step_key = item.get("step_key")
        provider_ref = item.get("provider_operation_ref")
        if step_key is None and provider_ref is None:
            continue
        if not isinstance(step_key, str) or not isinstance(provider_ref, str):
            raise ConflictError("module receipt has a detached step/provider pin pair")
        by_step[step_key] = provider_ref
    if not by_step:
        raise ConflictError("execution receipt has no typed provider-step result")
    return [
        {"step_key": step_key, "provider_operation_ref": by_step[step_key]}
        for step_key in sorted(by_step)
    ]


def _artifact_document(
    db: Session, selection: ComponentArtifactSelection
) -> dict[str, object]:
    _require_code(selection.component_code, "component code")
    artifact = db.get(ReleaseArtifact, selection.artifact_id)
    if artifact is None:
        raise NotFoundError(f"release artifact {selection.artifact_id} not found")
    try:
        expected_digest = Digest.parse(selection.artifact_digest)
        pinned_reference(selection.artifact_reference, expected=expected_digest)
    except ValueError as exc:
        raise ConflictError("component artifact identity is not digest-pinned") from exc
    if (
        artifact.digest != selection.artifact_digest
        or artifact.artifact_ref != selection.artifact_reference
    ):
        raise ConflictError(
            "component artifact selection disagrees with Release Catalog"
        )
    common = {
        "provenance": _attestation_document(
            db, artifact.id, AttestationKind.PROVENANCE, selection.provenance
        ),
        "sbom": _attestation_document(
            db, artifact.id, AttestationKind.SBOM, selection.sbom
        ),
        "signature": _attestation_document(
            db, artifact.id, AttestationKind.SIGNATURE, selection.signature
        ),
    }
    # Source class is immutable Release Catalog evidence, never a label accepted
    # from this request.  a4 has no such field and therefore fails closed until
    # the a5 origin/admission contract is published and pinned by this assembly.
    source_class = getattr(artifact, "origin_class", None)
    if source_class not in {"dotmac_product", "upstream_third_party"}:
        raise ConflictError(
            "Release Catalog origin/admission evidence is unavailable or invalid"
        )
    vulnerability_kind = _optional_attestation_kind("vulnerability_policy_result")
    compatibility_kind = _optional_attestation_kind("compatibility_result")
    evidence: dict[str, object]
    if source_class == "dotmac_product":
        if selection.product_manifest is None:
            raise ConflictError(
                "Dotmac product artifact requires selected product-manifest evidence"
            )
        if (
            selection.vulnerability_policy_result is not None
            or selection.compatibility_result is not None
        ):
            raise ConflictError(
                "Dotmac product artifact cannot select upstream admission evidence"
            )
        evidence = {
            **common,
            "product_manifest": _attestation_document(
                db,
                artifact.id,
                AttestationKind.PRODUCT_MANIFEST,
                selection.product_manifest,
            ),
        }
    else:
        if selection.product_manifest is not None:
            raise ConflictError(
                "upstream artifact must not fabricate a Dotmac product manifest"
            )
        if (
            selection.vulnerability_policy_result is None
            or selection.compatibility_result is None
            or vulnerability_kind is None
            or compatibility_kind is None
        ):
            raise ConflictError(
                "upstream artifact lacks catalogue-backed admission evidence"
            )
        evidence = {
            **common,
            "vulnerability_policy_result": _attestation_document(
                db,
                artifact.id,
                vulnerability_kind,
                selection.vulnerability_policy_result,
            ),
            "compatibility_result": _attestation_document(
                db, artifact.id, compatibility_kind, selection.compatibility_result
            ),
        }
    return {
        "component_code": selection.component_code,
        "source_class": source_class,
        "artifact": {
            "id": str(artifact.id),
            "product_code": artifact.product_code,
            "version": artifact.version,
            "kind": artifact.artifact_kind,
            "digest": artifact.digest,
            "reference": artifact.artifact_ref,
            "source_revision": artifact.source_revision,
        },
        "evidence": evidence,
    }


def _attestation_document(
    db: Session,
    artifact_id: UUID,
    kind: AttestationKind,
    selection: AttestationSelection,
) -> dict[str, object]:
    _require_hash(selection.digest)
    row = db.get(ArtifactAttestation, selection.attestation_id)
    if (
        row is None
        or row.artifact_id != artifact_id
        or row.attestation_kind != kind.value
        or row.digest != selection.digest
    ):
        raise ConflictError(
            f"artifact {kind.value} evidence does not match Release Catalog"
        )
    return {
        "id": str(row.id),
        "kind": row.attestation_kind,
        "digest": row.digest,
        "uri": row.uri,
    }


def _optional_attestation_kind(value: str) -> AttestationKind | None:
    try:
        return AttestationKind(value)
    except ValueError:
        return None


def _binding_documents(
    *,
    desired: DeploymentDesiredStateVersion,
    selections: tuple[IntegratorBindingSelection, ...],
) -> list[dict[str, object]]:
    by_instance = {item.capability_instance_ref: item for item in selections}
    if len(by_instance) != len(selections):
        raise ConflictError("Integrator selected a capability instance twice")
    required = {
        str(item["capability_instance_ref"]): item
        for item in desired.selected_capabilities
    }
    if set(by_instance) != set(required):
        raise ConflictError(
            "Integrator binding selection does not exactly cover required instances"
        )
    documents: list[dict[str, object]] = []
    binding_refs: set[UUID] = set()
    for instance_ref in sorted(by_instance):
        item = by_instance[instance_ref]
        contract = required[instance_ref]
        if item.capability_id != contract.get("capability_id"):
            raise ConflictError(
                f"binding instance {instance_ref!r} selects the wrong capability"
            )
        if not is_capability_instance_ref(instance_ref):
            raise ConflictError("capability instance reference is not canonical")
        if item.binding_ref in binding_refs:
            raise ConflictError(
                "Integrator reused a binding across capability instances"
            )
        binding_refs.add(item.binding_ref)
        if item.capability_schema_version != int(contract["schema_version"]):
            raise ConflictError(
                f"binding capability schema disagrees for {instance_ref!r}"
            )
        for value, label in (
            (item.installation_ref, "installation reference"),
            (item.connector_key, "connector key"),
        ):
            _require_code(value, label)
        for digest in (
            item.connector_manifest_digest,
            item.connector_artifact_digest,
            item.connector_configuration_digest,
            item.execution_policy_digest,
        ):
            _require_hash(digest)
        if (
            not item.connector_version
            or item.connector_version.strip() != item.connector_version
        ):
            raise ConflictError("connector version must be non-blank and trimmed")
        documents.append(
            {
                "capability_instance_ref": instance_ref,
                "capability_id": item.capability_id,
                "capability_contract": {
                    "owner_code": contract["owner_code"],
                    "capability_code": contract["capability_code"],
                    "schema_version": contract["schema_version"],
                    "contract_ref": contract["contract_ref"],
                    "content_hash": contract["content_hash"],
                    "contract_attestation_id": contract["contract_attestation_id"],
                    "contract_attestation_digest": contract[
                        "contract_attestation_digest"
                    ],
                    "operations": contract["operations"],
                    "schemas": contract["schemas"],
                },
                "installation_id": str(item.installation_id),
                "installation_ref": item.installation_ref,
                "binding_ref": str(item.binding_ref),
                "connector_key": item.connector_key,
                "connector_version": item.connector_version,
                "connector_manifest_digest": item.connector_manifest_digest,
                "connector_artifact_digest": item.connector_artifact_digest,
                "connector_configuration_revision_id": str(
                    item.connector_configuration_revision_id
                ),
                "connector_configuration_digest": item.connector_configuration_digest,
                "execution_policy_digest": item.execution_policy_digest,
            }
        )
    return documents


def _allocation_document(
    db: Session, *, deployment: Deployment, allocation_id: UUID | None
) -> dict[str, object]:
    if deployment.contract_id is None:
        if allocation_id is not None or deployment.internal_source_code is None:
            raise ConflictError(
                "internal deployment cannot bind a commercial allocation"
            )
        return {
            "source_kind": "internal",
            "source_code": deployment.internal_source_code,
        }
    if allocation_id is None:
        raise ConflictError("commercial deployment plan requires an exact allocation")
    contract = db.get(Contract, deployment.contract_id)
    view = allocations.read_allocation(db, allocation_id)
    if contract is None or view is None:
        raise NotFoundError("commercial contract or allocation not found")
    if contract.status != ContractStatus.ACTIVE.value:
        raise ConflictError("commercial deployment contract is no longer active")
    if (
        view.contract_id != contract.id
        or view.product_code != deployment.commercial_product_code
        or view.content_hash != contract.content_hash
        or view.status != allocations.STAGED_STATUS
    ):
        raise ConflictError(
            "allocation does not match the deployment's exact active contract"
        )
    return {
        "source_kind": "commercial_allocation",
        "allocation_id": str(view.id),
        "contract_id": str(view.contract_id),
        "product_code": view.product_code,
        "customer_ref": view.customer_ref,
        "contract_content_hash": view.content_hash,
        "status": view.status,
        "entries": [
            {"capability_code": entry.capability_code, "quantity": entry.quantity}
            for entry in sorted(view.entries, key=lambda entry: entry.capability_code)
        ],
    }


def _build_steps(
    *,
    desired: DeploymentDesiredStateVersion,
    profile_document: dict[str, object],
    binding_documents: list[dict[str, object]],
    lifecycle_policy: VersionedPolicyRef,
) -> list[dict[str, object]]:
    binding_by_instance = {
        str(item["capability_instance_ref"]): item for item in binding_documents
    }
    instance_components: dict[str, set[str]] = {
        code: set() for code in binding_by_instance
    }
    for capability in desired.selected_capabilities:
        instance_ref = str(capability["capability_instance_ref"])
        component_code = str(capability["component_code"])
        if instance_ref not in instance_components:
            raise ConflictError("desired capability instance lacks an exact binding")
        instance_components[instance_ref].add(component_code)
    operation_inputs = _desired_operation_inputs(desired=desired)
    operation_ids = {
        (
            str(item["capability_instance_ref"]),
            str(item["operation_code"]),
        ): f"step.{item['capability_instance_ref']}.{item['operation_code']}"
        for item in desired.selected_operations
        if item.get("operation_code") == "apply"
    }
    steps: list[dict[str, object]] = []
    prerequisite_instances: dict[str, set[str]] = {}
    for mapping in desired.selected_composition_edges:
        if not isinstance(mapping, dict):
            raise ConflictError("desired composition binding snapshot is malformed")
        source = mapping.get("source_capability_instance_ref")
        target = mapping.get("target_capability_instance_ref")
        if not isinstance(source, str) or not isinstance(target, str):
            raise ConflictError("desired composition binding identity is malformed")
        prerequisite_instances.setdefault(target, set()).add(source)
    for (instance_ref, _operation_code), step_id in sorted(operation_ids.items()):
        binding = binding_by_instance[instance_ref]
        capability_id = str(binding["capability_id"])
        dependencies = {
            operation_ids[(source, "apply")]
            for source in prerequisite_instances.get(instance_ref, set())
            if (source, "apply") in operation_ids
        }
        material: dict[str, object] = {
            "step_id": step_id,
            "step_kind": "apply_operation",
            "capability_instance_ref": instance_ref,
            "capability_id": capability_id,
            "endpoint_code": capability_id,
            "command_schema": "integrator.provisioning-step.v1",
            "component_codes": sorted(instance_components[instance_ref]),
            "depends_on": sorted(dependencies - {step_id}),
            "input": operation_inputs[instance_ref],
            "retry_class": "idempotent_reconcile",
            "compensation_contract": "connector.capability.cancel@v1",
            "lifecycle_policy": {
                "policy_code": lifecycle_policy.policy_code,
                "version": lifecycle_policy.version,
            },
        }
        steps.append({**material, "operation_key": _content_hash(material)})
    for check in sorted(
        desired.selected_verification_checks,
        key=lambda item: (
            str(item["stage"]),
            str(item["check_code"]),
            str(item["capability_instance_ref"]),
            str(item["capability_id"]),
        ),
    ):
        check_instance_ref = str(check["capability_instance_ref"])
        verification_dependencies = [
            step_id
            for (instance_ref, _operation), step_id in operation_ids.items()
            if instance_ref == check_instance_ref
        ]
        material = {
            "step_id": (
                f"check.{check['stage']}.{check_instance_ref}.{check['check_code']}"
            ),
            "step_kind": "verify",
            "verification": check,
            "command_schema": "dotmac.managed-component.verify@v1",
            "depends_on": sorted(verification_dependencies),
            "bindings": [str(binding_by_instance[check_instance_ref]["binding_ref"])],
            "retry_class": "observation",
            "compensation_contract": "none",
        }
        steps.append({**material, "operation_key": _content_hash(material)})
    return steps


def _build_command_templates(
    *,
    deployment_ref: str,
    saved_plan_id: UUID,
    desired: DeploymentDesiredStateVersion,
    profile: ManagedServiceProfileVersion,
    bundle: DeploymentBundleManifestVersion,
    binding_documents: list[dict[str, object]],
    steps: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Freeze static per-binding commands without predicting later receipts."""

    apply_steps = [step for step in steps if step.get("step_kind") == "apply_operation"]
    step_binding = {
        str(step["step_id"]): str(step["capability_instance_ref"])
        for step in apply_steps
    }
    binding_by_instance = {
        str(binding["capability_instance_ref"]): binding
        for binding in binding_documents
    }
    evidence_mappings = desired.selected_composition_edges
    templates: list[dict[str, object]] = []
    for instance_ref in sorted(binding_by_instance):
        binding = binding_by_instance[instance_ref]
        capability_id = str(binding["capability_id"])
        local = [
            step
            for step in apply_steps
            if step.get("capability_instance_ref") == instance_ref
        ]
        if not local:
            raise ConflictError(
                f"capability {capability_id!r} has no owner-declared apply endpoint"
            )
        local_ids = {str(step["step_id"]) for step in local}
        prerequisite_instances: set[str] = set()
        wire_steps: list[dict[str, object]] = []
        for step in local:
            dependencies = set(cast(list[str], step["depends_on"]))
            for dependency in dependencies - local_ids:
                prerequisite = step_binding.get(dependency)
                if prerequisite is None:
                    raise ConflictError("plan step dependency is outside the apply DAG")
                prerequisite_instances.add(prerequisite)
            wire_steps.append(
                {
                    "step_key": str(step["step_id"]),
                    "endpoint_code": str(step["endpoint_code"]),
                    "depends_on": sorted(dependencies & local_ids),
                    "input": step["input"],
                }
            )
        prerequisite_evidence_bindings = _plan_evidence_bindings(
            target_capability_instance_ref=instance_ref,
            mappings=evidence_mappings,
            binding_by_instance=binding_by_instance,
            apply_steps=apply_steps,
        )
        prerequisite_instances.update(
            str(item["source_capability_instance_ref"])
            for item in evidence_mappings
            if str(item.get("target_capability_instance_ref")) == instance_ref
        )
        prerequisite_binding_ids = sorted(
            str(binding_by_instance[required]["binding_ref"])
            for required in prerequisite_instances
        )
        contract = _document_object(binding, "capability_contract")
        component_codes = cast(list[str], local[0]["component_codes"])
        artifact_by_component = {
            str(item["component_code"]): _document_object(item, "artifact")["digest"]
            for item in _document_list(bundle.document, "components")
        }
        component_digests = {
            str(artifact_by_component[code]) for code in component_codes
        }
        component_artifact_digest = (
            next(iter(component_digests)) if len(component_digests) == 1 else None
        )
        material: dict[str, object] = {
            "deployment_ref": deployment_ref,
            "saved_plan_id": str(saved_plan_id),
            "desired_state_version_id": str(desired.id),
            "desired_state_revision": desired.revision,
            "desired_state_hash": desired.desired_state_hash,
            "profile_version_id": str(profile.id),
            "profile_code": profile.profile_code,
            "profile_version": profile.version,
            "profile_schema_version": profile.schema_version,
            "profile_content_hash": profile.content_hash,
            "command_schema_version": "integrator.provisioning-command.v1",
            "configuration_snapshot_ref": desired.configuration_snapshot_ref,
            "configuration_schema_version": desired.configuration_schema_version,
            "configuration_hash": desired.configuration_hash,
            "capability_instance_ref": instance_ref,
            "capability_id": capability_id,
            "capability_binding_id": binding["binding_ref"],
            "binding_ref": binding["binding_ref"],
            "installation_id": binding["installation_id"],
            "installation_ref": binding["installation_ref"],
            "capability_owner_code": contract["owner_code"],
            "capability_code": contract["capability_code"],
            "capability_schema_version": contract["schema_version"],
            "capability_contract_attestation_id": contract["contract_attestation_id"],
            "capability_contract_digest": contract["content_hash"],
            "capability_operations": contract["operations"],
            "connector_key": binding["connector_key"],
            "connector_version": binding["connector_version"],
            "connector_manifest_digest": binding["connector_manifest_digest"],
            "connector_configuration_revision_id": binding[
                "connector_configuration_revision_id"
            ],
            "execution_policy_digest": binding["execution_policy_digest"],
            "artifact_digest": binding["connector_artifact_digest"],
            "component_artifact_digest": component_artifact_digest,
            "config_digest": binding["connector_configuration_digest"],
            "steps": sorted(wire_steps, key=lambda step: str(step["step_key"])),
            "prerequisite_capability_binding_ids": prerequisite_binding_ids,
            "prerequisite_evidence_bindings": prerequisite_evidence_bindings,
        }
        templates.append(
            {
                **material,
                "approved_command_template_digest": _content_hash(material),
            }
        )
    return templates


def _plan_evidence_bindings(
    *,
    target_capability_instance_ref: str,
    mappings: list[dict[str, object]],
    binding_by_instance: dict[str, dict[str, object]],
    apply_steps: list[dict[str, object]],
) -> list[dict[str, object]]:
    steps_by_operation = {
        (
            str(step["capability_instance_ref"]),
            str(step["endpoint_code"]),
        ): str(step["step_id"])
        for step in apply_steps
    }
    result: list[dict[str, object]] = []
    for mapping in mappings:
        if (
            str(mapping.get("target_capability_instance_ref"))
            != target_capability_instance_ref
        ):
            continue
        source_instance_ref = str(mapping["source_capability_instance_ref"])
        source_capability_id = str(mapping["source_capability_id"])
        target_capability_id = str(mapping["target_capability_id"])
        source_binding = binding_by_instance.get(source_instance_ref)
        target_binding = binding_by_instance.get(target_capability_instance_ref)
        if source_binding is None or target_binding is None:
            raise ConflictError("approved evidence mapping names an unbound capability")
        source_step = steps_by_operation.get(
            (source_instance_ref, source_capability_id)
        )
        target_step = steps_by_operation.get(
            (target_capability_instance_ref, target_capability_id)
        )
        if source_step is None or target_step is None:
            raise ConflictError(
                "approved evidence mapping names an unplanned operation"
            )
        result.append(
            {
                "source_capability_binding_id": source_binding["binding_ref"],
                "source_step_key": source_step,
                "source_schema_ref": mapping["source_schema_ref"],
                "source_schema_digest": mapping["source_schema_digest"],
                "source_pointer": mapping["source_pointer"],
                "target_step_key": target_step,
                "target_schema_ref": mapping["target_schema_ref"],
                "target_schema_digest": mapping["target_schema_digest"],
                "target_pointer": mapping["target_pointer"],
                "required": mapping["required"],
            }
        )
    canonical = sorted(
        result,
        key=lambda item: (
            str(item["source_capability_binding_id"]),
            str(item["source_step_key"]),
            str(item["source_pointer"]),
            str(item["target_step_key"]),
            str(item["target_pointer"]),
        ),
    )
    locator_keys = tuple(
        (
            str(item["source_capability_binding_id"]),
            str(item["source_step_key"]),
            str(item["source_pointer"]),
            str(item["target_step_key"]),
            str(item["target_pointer"]),
        )
        for item in canonical
    )
    if len(set(locator_keys)) != len(locator_keys):
        raise ConflictError("approved prerequisite evidence mapping is duplicated")
    target_locations = tuple(
        (str(item["target_step_key"]), str(item["target_pointer"]))
        for item in canonical
    )
    if len(set(target_locations)) != len(target_locations):
        raise ConflictError(
            "approved prerequisite evidence mappings compete for one target input"
        )
    return canonical


def _desired_operation_inputs(
    *,
    desired: DeploymentDesiredStateVersion,
) -> dict[str, dict[str, object]]:
    raw_inputs = desired.desired_operation_inputs
    if not isinstance(raw_inputs, dict) or not all(
        isinstance(key, str) and isinstance(value, Mapping)
        for key, value in raw_inputs.items()
    ):
        raise ConflictError("desired operation input snapshot is malformed")
    schemas: dict[str, CapabilitySchemaDocument] = {}
    capability_ids: dict[str, str] = {}
    for capability in desired.selected_capabilities:
        if not isinstance(capability, dict):
            raise ConflictError("desired capability snapshot is malformed")
        instance_ref = capability.get("capability_instance_ref")
        capability_id = capability.get("capability_id")
        operations = capability.get("operations")
        schema_evidence = capability.get("schemas")
        if (
            not isinstance(instance_ref, str)
            or not isinstance(capability_id, str)
            or not isinstance(operations, list)
            or not isinstance(schema_evidence, list)
        ):
            raise ConflictError("desired capability operation evidence is malformed")
        apply = tuple(
            item
            for item in operations
            if isinstance(item, dict) and item.get("operation_code") == "apply"
        )
        if len(apply) != 1:
            raise ConflictError(
                f"capability {capability_id!r} lacks one exact APPLY operation"
            )
        schema_ref = apply[0].get("input_schema_ref")
        schema_digest = apply[0].get("input_schema_digest")
        matches = tuple(
            item
            for item in schema_evidence
            if isinstance(item, dict)
            and item.get("schema_ref") == schema_ref
            and item.get("schema_digest") == schema_digest
        )
        if len(matches) != 1 or not isinstance(matches[0].get("document"), dict):
            raise ConflictError("desired APPLY operation lacks exact held schema")
        try:
            schema = CapabilitySchemaDocument.from_mapping(
                cast(dict[str, object], matches[0]["document"])
            )
        except CapabilityContractError as exc:
            raise ConflictError("desired APPLY schema document is invalid") from exc
        if schema.schema_ref != schema_ref or schema.digest != schema_digest:
            raise ConflictError("desired APPLY schema evidence pins do not match")
        schemas[instance_ref] = schema
        capability_ids[instance_ref] = capability_id
    if set(raw_inputs) != set(schemas):
        raise ConflictError(
            "desired operation input snapshot does not exactly cover APPLY capabilities"
        )
    pointers: dict[str, list[str]] = {}
    for mapping in desired.selected_composition_edges:
        if not isinstance(mapping, dict):
            raise ConflictError("desired composition binding snapshot is malformed")
        target_instance = mapping.get("target_capability_instance_ref")
        target_pointer = mapping.get("target_pointer")
        if (
            isinstance(target_instance, str)
            and target_instance in schemas
            and isinstance(target_pointer, str)
        ):
            pointers.setdefault(target_instance, []).append(target_pointer)
    validated: dict[str, dict[str, object]] = {}
    for instance_ref in sorted(schemas):
        raw = raw_inputs[instance_ref]
        if (
            not isinstance(raw, Mapping)
            or raw.get("capability_id") != capability_ids[instance_ref]
            or not isinstance(raw.get("document"), Mapping)
        ):
            raise ConflictError("saved desired APPLY instance identity is invalid")
        try:
            validated[instance_ref] = validate_desired_operation_input(
                cast(Mapping[str, object], raw["document"]),
                schema=schemas[instance_ref],
                composition_target_pointers=pointers.get(instance_ref, ()),
            )
        except DesiredOperationInputError as exc:
            raise ConflictError(
                f"saved desired APPLY input for {instance_ref!r} is invalid: {exc}"
            ) from exc
    return validated


def _profile_components(
    document: dict[str, object],
) -> dict[str, dict[str, object]]:
    value = document.get("components")
    if not isinstance(value, list):
        raise ConflictError("managed profile has no immutable component graph")
    result: dict[str, dict[str, object]] = {}
    for item in value:
        if not isinstance(item, dict) or not isinstance(
            item.get("component_code"), str
        ):
            raise ConflictError("managed profile component graph is malformed")
        code = str(item["component_code"])
        if code in result:
            raise ConflictError("managed profile component graph contains a duplicate")
        result[code] = item
    return result


def _require_current_plan(
    db: Session, plan_id: UUID
) -> tuple[DeploymentPlan, Deployment]:
    plan = db.get(DeploymentPlan, plan_id)
    if plan is None:
        raise NotFoundError(f"deployment plan {plan_id} not found")
    deployment = db.scalar(
        select(Deployment).where(Deployment.id == plan.deployment_id).with_for_update()
    )
    if deployment is None or deployment.current_plan_id != plan.id:
        raise ConflictError("deployment plan is no longer current")
    desired = db.get(DeploymentDesiredStateVersion, plan.desired_state_version_id)
    if (
        desired is None
        or desired.deployment_id != deployment.id
        or desired.revision != deployment.current_desired_state_revision
    ):
        raise ConflictError("deployment plan no longer binds current desired state")
    if _content_hash(plan.document) != plan.plan_hash:
        raise ConflictError("deployment plan document no longer matches its hash")
    if _document_object(plan.document, "allocation") != _allocation_document(
        db, deployment=deployment, allocation_id=plan.allocation_id
    ):
        raise ConflictError("deployment commercial source changed after planning")
    return plan, deployment


def _require_usable_grant(
    db: Session, *, plan: DeploymentPlan, grant_id: UUID, now: datetime
) -> DeploymentPlanApprovalGrant:
    grant = _require_bound_grant(db, plan=plan, grant_id=grant_id)
    request = db.get(DeploymentPlanApprovalRequest, grant.approval_request_binding_id)
    if request is None:
        raise ConflictError("approval grant request identity is inconsistent")
    if _aware(grant.expires_at, label="approval expiry") <= now:
        raise ConflictError("approval grant has expired")
    evaluation = approvals.evaluate_request(db, request_id=request.approval_request_id)
    if not evaluation.satisfied:
        raise ConflictError("approval authority no longer reports the plan approved")
    return grant


def _require_bound_grant(
    db: Session, *, plan: DeploymentPlan, grant_id: UUID
) -> DeploymentPlanApprovalGrant:
    """Verify immutable approval evidence without authorising another APPLY.

    Expiry and the live vote state gate new APPLY effects. OBSERVE reports an
    existing operation and CANCEL compensates one, so blocking either after
    expiry would make safety and evidence disappear precisely when needed.
    """

    grant = db.get(DeploymentPlanApprovalGrant, grant_id)
    if grant is None or grant.plan_id != plan.id:
        raise ConflictError("approval grant does not bind the exact plan")
    request = db.get(DeploymentPlanApprovalRequest, grant.approval_request_binding_id)
    if (
        request is None
        or request.plan_id != plan.id
        or request.approval_request_id != grant.approval_request_id
    ):
        raise ConflictError("approval grant request identity is inconsistent")
    if request.request_binding_hash != _content_hash(request.document):
        raise ConflictError("approval request binding no longer matches its hash")
    expected_document: dict[str, object] = {
        "content_schema": "vendor.deployment-plan-approval-grant@v1",
        "plan_id": str(plan.id),
        "plan_hash": plan.plan_hash,
        "approval_request_binding_id": str(request.id),
        "approval_request_id": str(request.approval_request_id),
        "request_binding_hash": request.request_binding_hash,
        "expires_at": _time_text(grant.expires_at),
        "plan_validations": request.document["plan_validations"],
    }
    if grant.grant_digest != _content_hash(expected_document):
        raise ConflictError("approval grant digest does not match exact plan evidence")
    return grant


def _require_complete_plan_validations(
    db: Session,
    *,
    plan: DeploymentPlan,
    receipt_ids: tuple[UUID, ...],
) -> list[dict[str, object]]:
    if len(set(receipt_ids)) != len(receipt_ids):
        raise ConflictError("PLAN validation receipt identities must be unique")
    expected_bindings = {
        UUID(str(template["capability_binding_id"]))
        for template in _document_list(plan.document, "command_templates")
    }
    rows = tuple(
        row
        for receipt_id in receipt_ids
        if (row := db.get(IntegratorExecutionReceipt, receipt_id)) is not None
    )
    if len(rows) != len(receipt_ids):
        raise ConflictError("a PLAN validation receipt was not ingested")
    by_binding = {row.capability_binding_id: row for row in rows}
    if len(by_binding) != len(rows) or set(by_binding) != expected_bindings:
        raise ConflictError(
            "PLAN validations do not exactly cover every planned capability binding"
        )
    documents: list[dict[str, object]] = []
    for binding_id in sorted(by_binding, key=str):
        row = by_binding[binding_id]
        if (
            row.plan_id != plan.id
            or row.operation != "plan"
            or row.outcome != "planned"
            or row.module_plan_receipt_hash is None
            or row.operation_id is not None
        ):
            raise ConflictError("approval requires successful exact PLAN validation")
        documents.append(
            {
                "capability_binding_id": str(binding_id),
                "receipt_id": str(row.id),
                "receipt_digest": row.receipt_digest,
                "plan_command_id": row.command_id,
                "request_body_digest": row.request_body_digest,
                "module_plan_receipt_hash": row.module_plan_receipt_hash,
            }
        )
    return documents


def _plan_validation_for_binding(
    *, request_document: Mapping[str, object], binding_id: UUID
) -> dict[str, object]:
    raw = request_document.get("plan_validations")
    if not isinstance(raw, list):
        raise ConflictError("approval grant has no PLAN validation set")
    matches = [
        item
        for item in raw
        if isinstance(item, dict)
        and item.get("capability_binding_id") == str(binding_id)
    ]
    if len(matches) != 1:
        raise ConflictError("approval grant does not bind this PLAN validation")
    return matches[0]


def _require_separate_command_key(
    signer: DeploymentCommandSigningKey, policy: CommandKeySeparationPolicy
) -> None:
    if signer.purpose != COMMAND_SIGNING_PURPOSE:
        raise ConflictError("signing key is not held for deployment commands")
    if signer.key_id != policy.command_key_id:
        raise ConflictError("deployment command signer does not match custody policy")
    if (
        signer.key_id in policy.forbidden_key_ids
        or signer.public_key_b64 in policy.forbidden_public_keys_b64
    ):
        raise ConflictError(
            "deployment command key reuses licence or session signing identity"
        )


def _require_command_lifetime(
    issued_at: datetime,
    expires_at: datetime,
    policy: CommandKeySeparationPolicy,
) -> None:
    if policy.max_lifetime_seconds < 1:
        raise ConflictError("deployment command lifetime policy is invalid")
    if (expires_at - issued_at).total_seconds() > policy.max_lifetime_seconds:
        raise ConflictError("deployment command lifetime exceeds custody policy")


def _require_envelope_inputs(
    *,
    command_id_prefix: str,
    audience: str,
    issued_at: datetime,
    expires_at: datetime,
    now: datetime,
) -> tuple[datetime, datetime]:
    issued = _require_aware_input(issued_at, label="command issue time")
    expires = _require_aware_input(expires_at, label="command expiry")
    if issued > now or expires <= now or expires <= issued:
        raise ConflictError("command envelope times are not currently usable")
    if not command_id_prefix or command_id_prefix.strip() != command_id_prefix:
        raise ConflictError("command id prefix must be non-blank and trimmed")
    if not audience or audience.strip() != audience or len(audience) > 240:
        raise ConflictError("command audience must be non-blank and trimmed")
    return issued, expires


def _signed_envelope(
    *,
    signer: DeploymentCommandSigningKey,
    audience: str,
    command_id: str,
    issued_at: datetime,
    expires_at: datetime,
    capability_id: str,
    body: dict[str, object],
) -> SignedProvisioningCommandEnvelope:
    if not 8 <= len(command_id) <= 240:
        raise ConflictError("command id must contain 8-240 characters")
    if _KEY_ID.fullmatch(signer.key_id) is None:
        raise ConflictError("deployment command key id is not canonical")
    header: dict[str, object] = {
        "contract_version": "integrator.provisioning-command.v1",
        "key_id": signer.key_id,
        "audience": audience,
        "issued_at": _time_text(issued_at),
        "expires_at": _time_text(expires_at),
        "command_id": command_id,
        "nonce": command_id,
        "body_sha256": _content_hash(body),
    }
    signature = signer.sign(_canonical(header))
    if len(signature) != 64:
        raise ConflictError("deployment command signer did not return Ed25519 output")
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return SignedProvisioningCommandEnvelope(
        content_type=(
            "application/vnd.dotmac.integrator.provisioning-command+json;version=1"
        ),
        key_id=signer.key_id,
        algorithm="Ed25519",
        capability_id=capability_id,
        command_id=command_id,
        document={**header, "signature": signature_b64, "body": body},
    )


def _record_dispatch(
    db: Session,
    *,
    plan: DeploymentPlan,
    deployment: Deployment,
    binding_id: UUID,
    operation: str,
    envelope: SignedProvisioningCommandEnvelope,
) -> None:
    body = _document_object(envelope.document, "body")
    capability_instance_ref = _required_string(body, "capability_instance_ref")
    if not is_capability_instance_ref(capability_instance_ref):
        raise ConflictError("command capability instance reference is not canonical")
    expected_body_digest = _content_hash(body)
    expected_envelope_digest = _content_hash(envelope.document)
    existing = db.scalar(
        select(IntegratorCommandDispatch).where(
            IntegratorCommandDispatch.command_id == envelope.command_id
        )
    )
    if existing is not None:
        _require_exact_dispatch_replay(
            existing,
            plan=plan,
            deployment=deployment,
            binding_id=binding_id,
            operation=operation,
            request_body_digest=expected_body_digest,
            envelope_digest=expected_envelope_digest,
            document=envelope.document,
        )
        return
    row = IntegratorCommandDispatch(
        plan_id=plan.id,
        deployment_id=deployment.id,
        capability_instance_ref=capability_instance_ref,
        capability_binding_id=binding_id,
        operation=operation,
        command_id=envelope.command_id,
        request_body_digest=expected_body_digest,
        envelope_digest=expected_envelope_digest,
        document=envelope.document,
    )
    try:
        _insert_immutable(
            db,
            row,
            message="Integrator command identity was dispatched with different content",
        )
    except ConflictError:
        concurrent = db.scalar(
            select(IntegratorCommandDispatch).where(
                IntegratorCommandDispatch.command_id == envelope.command_id
            )
        )
        if concurrent is None:
            raise
        _require_exact_dispatch_replay(
            concurrent,
            plan=plan,
            deployment=deployment,
            binding_id=binding_id,
            operation=operation,
            request_body_digest=expected_body_digest,
            envelope_digest=expected_envelope_digest,
            document=envelope.document,
        )
        return
    write_platform_audit_event(
        db,
        actor_admin_id=None,
        action="vendor.integrator_command.dispatched",
        entity_type="integrator_command_dispatch",
        entity_id=str(row.id),
        details={
            "plan_id": str(plan.id),
            "capability_instance_ref": capability_instance_ref,
            "capability_binding_id": str(binding_id),
            "operation": operation,
            "request_body_digest": row.request_body_digest,
        },
    )


def _require_exact_dispatch_replay(
    row: IntegratorCommandDispatch,
    *,
    plan: DeploymentPlan,
    deployment: Deployment,
    binding_id: UUID,
    operation: str,
    request_body_digest: str,
    envelope_digest: str,
    document: Mapping[str, object],
) -> None:
    if (
        row.plan_id != plan.id
        or row.deployment_id != deployment.id
        or row.capability_instance_ref
        != _document_object(dict(document), "body").get("capability_instance_ref")
        or row.capability_binding_id != binding_id
        or row.operation != operation
        or row.request_body_digest != request_body_digest
        or row.envelope_digest != envelope_digest
        or _canonical(row.document) != _canonical(document)
    ):
        raise ConflictError(
            "Integrator command identity was dispatched with different content"
        )


def _require_exact_receipt_replay(
    row: IntegratorExecutionReceipt,
    *,
    dispatch: IntegratorCommandDispatch,
    signed: Mapping[str, object],
) -> IntegratorReceiptView:
    if (
        row.dispatch_id != dispatch.id
        or row.plan_id != dispatch.plan_id
        or row.deployment_id != dispatch.deployment_id
        or row.capability_instance_ref != dispatch.capability_instance_ref
        or row.capability_binding_id != dispatch.capability_binding_id
        or _canonical(row.document) != _canonical(signed)
    ):
        raise ConflictError(
            "Integrator receipt digest was reused for different evidence"
        )
    return _receipt_view(row)


def _document_list(document: dict[str, object], key: str) -> list[dict[str, object]]:
    value = document.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ConflictError(f"immutable document has invalid {key!r}")
    return value


def _document_object(document: dict[str, object], key: str) -> dict[str, object]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise ConflictError(f"immutable document has invalid {key!r}")
    return value


def _string_list(document: dict[str, object], key: str) -> list[str]:
    value = document.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConflictError(f"immutable document has invalid {key!r}")
    return value


def _resolve_prerequisite_receipt_pins(
    *,
    resolver: PrerequisiteReceiptResolver,
    deployment_ref: str,
    plan_hash: str,
    prerequisite_binding_ids: list[str],
) -> list[dict[str, object]]:
    canonical_ids: list[str] = []
    for raw in prerequisite_binding_ids:
        try:
            canonical = str(UUID(raw))
        except ValueError as exc:
            raise ConflictError(
                "approved prerequisite binding identity is not a UUID"
            ) from exc
        if canonical != raw:
            raise ConflictError("approved prerequisite binding UUID is not canonical")
        canonical_ids.append(canonical)
    if canonical_ids != sorted(set(canonical_ids)):
        raise ConflictError(
            "approved prerequisite binding identities must be unique and sorted"
        )
    pins: list[dict[str, object]] = []
    for binding_id in canonical_ids:
        expected_id = UUID(binding_id)
        pin = resolver.require_succeeded(
            deployment_ref=deployment_ref,
            plan_hash=plan_hash,
            capability_binding_id=expected_id,
        )
        if (
            pin.deployment_ref != deployment_ref
            or pin.plan_hash != plan_hash
            or pin.capability_binding_id != expected_id
            or pin.terminal_receipt_sequence < 1
            or pin.required_terminal_status != "succeeded"
        ):
            raise ConflictError(
                "ingested prerequisite receipt does not satisfy the approved edge"
            )
        _require_hash(pin.terminal_receipt_digest)
        pins.append(
            {
                "capability_binding_id": str(pin.capability_binding_id),
                "operation_id": str(pin.operation_id),
                "terminal_receipt_sequence": pin.terminal_receipt_sequence,
                "terminal_receipt_digest": pin.terminal_receipt_digest,
                "required_terminal_status": pin.required_terminal_status,
            }
        )
    operation_ids = [str(pin["operation_id"]) for pin in pins]
    if len(set(operation_ids)) != len(operation_ids):
        raise ConflictError("ingested prerequisite receipts reuse an operation id")
    return sorted(pins, key=lambda pin: str(pin["operation_id"]))


def _binding_has_succeeded_receipt(
    db: Session,
    *,
    plan_id: UUID,
    capability_binding_id: UUID,
    operation: str,
) -> bool:
    return (
        db.scalar(
            select(IntegratorExecutionReceipt.id)
            .where(
                IntegratorExecutionReceipt.plan_id == plan_id,
                IntegratorExecutionReceipt.capability_binding_id
                == capability_binding_id,
                IntegratorExecutionReceipt.operation == operation,
                IntegratorExecutionReceipt.outcome == "succeeded",
            )
            .limit(1)
        )
        is not None
    )


def _strict_object(value: object, *, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ConflictError(f"{label} must be an object")
    result = dict(value)
    if set(result) != keys:
        raise ConflictError(f"{label} has an unsupported shape")
    return result


def _required_string(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ConflictError(f"Integrator receipt {key!r} must be a non-blank string")
    return value


def _optional_uuid(value: object, label: str) -> UUID | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConflictError(f"{label} must be a canonical UUID")
    try:
        result = UUID(value)
    except ValueError as exc:
        raise ConflictError(f"{label} must be a canonical UUID") from exc
    if str(result) != value:
        raise ConflictError(f"{label} must be a canonical UUID")
    return result


def _optional_positive_int(value: object, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConflictError(f"{label} must be a positive integer")
    return value


def _optional_hash(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise ConflictError(f"{label} must be a canonical sha256 digest")
    return value


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ConflictError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConflictError(f"{label} must be an RFC3339 timestamp") from exc
    return _require_aware_input(parsed, label=label)


def _validate_module_projection(
    *,
    receipt: Mapping[str, object],
    operation: str,
    command_id: str,
    request_digest: str,
    outcome: str,
    operation_id: UUID | None,
    latest_sequence: int | None,
    latest_hash: str | None,
    module_plan_hash: str | None,
) -> None:
    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ConflictError("Integrator receipt evidence must be an object")
    if operation == "plan":
        projection = evidence.get("module_plan_receipt")
        if (
            outcome != "planned"
            or operation_id is not None
            or latest_sequence is not None
            or latest_hash is not None
            or module_plan_hash is None
            or not isinstance(projection, Mapping)
            or projection.get("capability_instance_ref")
            != receipt.get("capability_instance_ref")
            or projection.get("command_id") != command_id
            or projection.get("request_body_digest") != request_digest
            or projection.get("receipt_hash") != module_plan_hash
        ):
            raise ConflictError("PLAN receipt is detached from module validation")
        return
    if operation not in {"apply", "observe", "cancel"}:
        raise ConflictError("Integrator receipt operation is unsupported")
    if (
        operation_id is None
        or latest_sequence is None
        or latest_hash is None
        or module_plan_hash is not None
    ):
        raise ConflictError("execution receipt lacks its module operation projection")
    chain = evidence.get("module_receipts")
    if not isinstance(chain, list) or not chain:
        raise ConflictError("execution receipt has no module receipt chain")
    previous: str | None = None
    for index, raw in enumerate(chain, start=1):
        if not isinstance(raw, Mapping):
            raise ConflictError("module receipt chain is malformed")
        item = _strict_object(
            raw,
            keys={
                "sequence",
                "receipt_kind",
                "capability_instance_ref",
                "step_key",
                "provider_operation_ref",
                "previous_receipt_hash",
                "receipt_hash",
                "plan_hash",
                "connector_key",
                "connector_version",
                "manifest_digest",
                "artifact_digest",
                "config_digest",
                "approval_digest",
                "evidence",
            },
            label="module receipt projection",
        )
        current_hash = item.get("receipt_hash")
        if (
            item.get("sequence") != index
            or item.get("previous_receipt_hash") != previous
            or not isinstance(current_hash, str)
            or _HASH.fullmatch(current_hash) is None
        ):
            raise ConflictError("module receipt chain is not continuous")
        if (
            item.get("plan_hash") != receipt.get("plan_hash")
            or item.get("capability_instance_ref")
            != receipt.get("capability_instance_ref")
            or item.get("artifact_digest") != receipt.get("artifact_digest")
            or item.get("config_digest") != receipt.get("config_digest")
            or item.get("approval_digest") != receipt.get("approval_digest")
        ):
            raise ConflictError("module receipt chain changes exact execution pins")
        for digest, label in (
            (item.get("manifest_digest"), "module connector manifest digest"),
            (item.get("artifact_digest"), "module connector artifact digest"),
            (item.get("config_digest"), "module connector configuration digest"),
            (item.get("approval_digest"), "module approval digest"),
        ):
            _require_optional_canonical_hash(digest, label)
        _required_string(item, "receipt_kind")
        _required_string(item, "connector_key")
        _required_string(item, "connector_version")
        step_key = item.get("step_key")
        provider_ref = item.get("provider_operation_ref")
        if (step_key is None) != (provider_ref is None):
            raise ConflictError("module receipt has a detached step/provider pin pair")
        if step_key is not None:
            if not isinstance(step_key, str) or _CODE.fullmatch(step_key) is None:
                raise ConflictError("module receipt step key is not canonical")
            if (
                not isinstance(provider_ref, str)
                or _REFERENCE.fullmatch(provider_ref) is None
            ):
                raise ConflictError(
                    "module receipt provider operation reference is not canonical"
                )
        if not isinstance(item.get("evidence"), Mapping):
            raise ConflictError("module receipt evidence must be an object")
        previous = current_hash
    if len(chain) != latest_sequence or previous != latest_hash:
        raise ConflictError("module receipt terminal pin differs from its chain")


def _validate_execution_projection_against_plan(
    *,
    receipt: Mapping[str, object],
    plan: DeploymentPlan,
    binding_id: UUID,
) -> None:
    matches = [
        item
        for item in _document_list(plan.document, "command_templates")
        if item.get("capability_binding_id") == str(binding_id)
    ]
    if len(matches) != 1:
        raise ConflictError("execution receipt binding has no exact planned template")
    template = matches[0]
    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ConflictError("Integrator receipt evidence must be an object")
    chain = evidence.get("module_receipts")
    if not isinstance(chain, list):
        raise ConflictError("execution receipt has no module receipt chain")
    for raw in chain:
        if not isinstance(raw, Mapping) or (
            raw.get("connector_key") != template.get("connector_key")
            or raw.get("connector_version") != template.get("connector_version")
            or raw.get("manifest_digest") != template.get("connector_manifest_digest")
            or raw.get("artifact_digest") != template.get("artifact_digest")
            or raw.get("config_digest") != template.get("config_digest")
        ):
            raise ConflictError(
                "module receipt chain differs from the planned connector pins"
            )


def _require_optional_canonical_hash(value: object, label: str) -> None:
    if value is not None and (
        not isinstance(value, str) or _HASH.fullmatch(value) is None
    ):
        raise ConflictError(f"{label} must be a canonical sha256 digest")


def _receipt_view(row: IntegratorExecutionReceipt) -> IntegratorReceiptView:
    return IntegratorReceiptView(
        id=row.id,
        dispatch_id=row.dispatch_id,
        plan_id=row.plan_id,
        capability_instance_ref=row.capability_instance_ref,
        capability_binding_id=row.capability_binding_id,
        operation=row.operation,
        receipt_digest=row.receipt_digest,
        outcome=row.outcome,
        operation_id=row.operation_id,
        latest_module_receipt_sequence=row.latest_module_receipt_sequence,
        latest_module_receipt_hash=row.latest_module_receipt_hash,
        module_plan_receipt_hash=row.module_plan_receipt_hash,
    )


def _insert_immutable(db: Session, row: object, *, message: str) -> None:
    from dotmac_kernel.db import conflict_savepoint

    try:
        with conflict_savepoint(db):
            db.add(row)
            db.flush()
    except IntegrityError as exc:
        raise ConflictError(message) from exc


def _validate_policy(policy: VersionedPolicyRef, *, label: str) -> None:
    _require_code(policy.policy_code, f"{label} code")
    if policy.version < 1:
        raise ConflictError(f"{label} version must be positive")


def _require_code(value: str, label: str) -> None:
    if _CODE.fullmatch(value) is None:
        raise ConflictError(f"{label} must be a canonical code")


def _require_hash(value: str) -> None:
    if _HASH.fullmatch(value) is None:
        raise ConflictError(
            "evidence digest must be sha256 plus 64 lowercase hex digits"
        )


def _bare_hash(value: str) -> str:
    _require_hash(value)
    return value.removeprefix("sha256:")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def canonical_provisioning_document_bytes(value: object) -> bytes:
    """The shared Integrator v1 canonical JSON contract (golden-fixture locked)."""

    return _canonical(value)


def _content_hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        # SQLite drops timezone metadata. Stored UTC rows are restored as UTC;
        # callers still must supply aware values at public command boundaries.
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _require_aware_input(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ConflictError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _time_text(value: datetime) -> str:
    return _aware(value, label="timestamp").isoformat().replace("+00:00", "Z")


def _bundle_view(row: DeploymentBundleManifestVersion) -> BundleManifestView:
    return BundleManifestView(
        id=row.id,
        profile_version_id=row.profile_version_id,
        bundle_code=row.bundle_code,
        version=row.version,
        profile_content_hash=row.profile_content_hash,
        content_hash=row.content_hash,
    )


def _plan_view(row: DeploymentPlan) -> DeploymentPlanView:
    return DeploymentPlanView(
        id=row.id,
        deployment_id=row.deployment_id,
        revision=row.revision,
        desired_state_version_id=row.desired_state_version_id,
        bundle_manifest_version_id=row.bundle_manifest_version_id,
        allocation_id=row.allocation_id,
        plan_hash=row.plan_hash,
    )


def _request_view(row: DeploymentPlanApprovalRequest) -> ApprovalRequestBindingView:
    return ApprovalRequestBindingView(
        id=row.id,
        plan_id=row.plan_id,
        approval_request_id=row.approval_request_id,
        expires_at=row.expires_at,
        request_binding_hash=row.request_binding_hash,
    )


def _grant_view(row: DeploymentPlanApprovalGrant) -> ApprovalGrantView:
    return ApprovalGrantView(
        id=row.id,
        plan_id=row.plan_id,
        approval_request_binding_id=row.approval_request_binding_id,
        approval_request_id=row.approval_request_id,
        expires_at=row.expires_at,
        grant_digest=row.grant_digest,
    )


__all__ = [
    "COMMAND_SIGNING_PURPOSE",
    "ApprovalGrantView",
    "ApprovalRequestBindingView",
    "AttestationSelection",
    "BuildApprovedApplyCommands",
    "BuildCancelCommands",
    "BuildObserveCommands",
    "BuildPlanCommands",
    "BundleManifestView",
    "CommandKeySeparationPolicy",
    "ComponentArtifactSelection",
    "CreateDeploymentPlanCommand",
    "DeploymentCommandSigningKey",
    "DeploymentPlanView",
    "IntegratorBindingSelection",
    "IntegratorReceiptSignatureVerifier",
    "IntegratorReceiptView",
    "IngestIntegratorReceiptCommand",
    "PublishBundleManifestCommand",
    "PrerequisiteReceiptPin",
    "PrerequisiteReceiptResolver",
    "PrerequisiteReceiptUnavailableError",
    "VerifiedReceiptResolver",
    "RecordPlanApprovalGrantCommand",
    "RequestPlanApprovalCommand",
    "SignedProvisioningCommandEnvelope",
    "VersionedPolicyRef",
    "build_approved_apply_commands",
    "build_cancel_commands",
    "build_observe_commands",
    "build_plan_commands",
    "canonical_provisioning_document_bytes",
    "create_deployment_plan",
    "ingest_integrator_receipt",
    "publish_bundle_manifest_version",
    "record_plan_approval_grant",
    "request_plan_approval",
]
