"""Typed platform-admin HTTP contracts for planning and approvals."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.planning.service import (
    ApprovalGrantView,
    ApprovalRequestBindingView,
    BundleManifestView,
    DeploymentPlanView,
    IntegratorReceiptView,
    SignedProvisioningCommandEnvelope,
)

_CAPABILITY_INSTANCE_REF = r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$"


class AttestationSelectionRequest(BaseModel):
    attestation_id: UUID
    digest: str = Field(min_length=71, max_length=71)


class ComponentArtifactSelectionRequest(BaseModel):
    component_code: str = Field(min_length=1, max_length=120)
    artifact_id: UUID
    artifact_digest: str = Field(min_length=71, max_length=71)
    artifact_reference: str = Field(min_length=1, max_length=1000)
    provenance: AttestationSelectionRequest
    sbom: AttestationSelectionRequest
    signature: AttestationSelectionRequest
    product_manifest: AttestationSelectionRequest | None = None
    vulnerability_policy_result: AttestationSelectionRequest | None = None
    compatibility_result: AttestationSelectionRequest | None = None


class PublishBundleManifestRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    commercial_product_code: str = Field(min_length=1, max_length=120)
    profile_code: str = Field(min_length=1, max_length=120)
    profile_version: int = Field(gt=0)
    bundle_code: str = Field(min_length=1, max_length=120)
    version: int = Field(gt=0)
    components: tuple[ComponentArtifactSelectionRequest, ...]


class BundleManifestResponse(BaseModel):
    id: UUID
    profile_version_id: UUID
    bundle_code: str
    version: int
    profile_content_hash: str
    content_hash: str

    @classmethod
    def from_view(cls, view: BundleManifestView) -> BundleManifestResponse:
        return cls(**{name: getattr(view, name) for name in cls.model_fields})


class IntegratorBindingSelectionRequest(BaseModel):
    capability_instance_ref: str = Field(
        min_length=1, max_length=200, pattern=_CAPABILITY_INSTANCE_REF
    )
    capability_id: str = Field(
        min_length=4, max_length=200, pattern=r"^[a-z][a-z0-9_.:-]*\.v[1-9][0-9]*$"
    )
    capability_schema_version: int = Field(gt=0)
    installation_id: UUID
    installation_ref: str = Field(min_length=1, max_length=200)
    binding_ref: UUID
    connector_key: str = Field(min_length=1, max_length=200)
    connector_version: str = Field(min_length=1, max_length=120)
    connector_manifest_digest: str = Field(min_length=71, max_length=71)
    connector_artifact_digest: str = Field(min_length=71, max_length=71)
    connector_configuration_revision_id: UUID
    connector_configuration_digest: str = Field(min_length=71, max_length=71)
    execution_policy_digest: str = Field(min_length=71, max_length=71)


class VersionedPolicyRequest(BaseModel):
    policy_code: str = Field(min_length=1, max_length=120)
    version: int = Field(gt=0)


class CreateDeploymentPlanRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    desired_state_version_id: UUID
    bundle_manifest_version_id: UUID
    allocation_id: UUID | None = None
    binding_selections: tuple[IntegratorBindingSelectionRequest, ...]
    lifecycle_policy: VersionedPolicyRequest


class DeploymentPlanResponse(BaseModel):
    id: UUID
    deployment_id: UUID
    revision: int
    desired_state_version_id: UUID
    bundle_manifest_version_id: UUID
    allocation_id: UUID | None
    plan_hash: str

    @classmethod
    def from_view(cls, view: DeploymentPlanView) -> DeploymentPlanResponse:
        return cls(**{name: getattr(view, name) for name in cls.model_fields})


class RequestPlanApprovalRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    policy_code: str = Field(min_length=1, max_length=120)
    policy_version: int = Field(gt=0)
    expires_at: datetime
    plan_validation_receipt_ids: tuple[UUID, ...]


class ApprovalRequestBindingResponse(BaseModel):
    id: UUID
    plan_id: UUID
    approval_request_id: UUID
    expires_at: datetime
    request_binding_hash: str

    @classmethod
    def from_view(
        cls, view: ApprovalRequestBindingView
    ) -> ApprovalRequestBindingResponse:
        return cls(**{name: getattr(view, name) for name in cls.model_fields})


class RecordPlanApprovalGrantRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    approval_request_binding_id: UUID


class BuildProvisioningCommandsRequest(BaseModel):
    command_id_prefix: str = Field(min_length=1, max_length=120)
    issued_at: datetime
    expires_at: datetime


class BuildApprovedProvisioningCommandsRequest(BuildProvisioningCommandsRequest):
    approval_grant_id: UUID


class BuildCancelProvisioningCommandsRequest(BuildApprovedProvisioningCommandsRequest):
    reason: str = Field(min_length=1, max_length=500)


class SignedProvisioningCommandResponse(BaseModel):
    content_type: str
    key_id: str
    algorithm: str
    capability_id: str
    command_id: str
    document: dict[str, object]

    @classmethod
    def from_view(
        cls, view: SignedProvisioningCommandEnvelope
    ) -> SignedProvisioningCommandResponse:
        return cls(**{name: getattr(view, name) for name in cls.model_fields})


class IngestIntegratorReceiptRequest(BaseModel):
    signed_receipt: dict[str, object]


class IntegratorReceiptResponse(BaseModel):
    id: UUID
    dispatch_id: UUID
    plan_id: UUID
    capability_binding_id: UUID
    operation: str
    receipt_digest: str
    outcome: str
    operation_id: UUID | None
    latest_module_receipt_sequence: int | None
    latest_module_receipt_hash: str | None
    module_plan_receipt_hash: str | None

    @classmethod
    def from_view(cls, view: IntegratorReceiptView) -> IntegratorReceiptResponse:
        return cls(**{name: getattr(view, name) for name in cls.model_fields})


class ApprovalGrantResponse(BaseModel):
    id: UUID
    plan_id: UUID
    approval_request_binding_id: UUID
    approval_request_id: UUID
    expires_at: datetime
    grant_digest: str

    @classmethod
    def from_view(cls, view: ApprovalGrantView) -> ApprovalGrantResponse:
        return cls(**{name: getattr(view, name) for name in cls.model_fields})


__all__ = [
    "ApprovalGrantResponse",
    "ApprovalRequestBindingResponse",
    "BuildApprovedProvisioningCommandsRequest",
    "BuildCancelProvisioningCommandsRequest",
    "BuildProvisioningCommandsRequest",
    "CreateDeploymentPlanRequest",
    "DeploymentPlanResponse",
    "IngestIntegratorReceiptRequest",
    "IntegratorReceiptResponse",
    "PublishBundleManifestRequest",
    "RecordPlanApprovalGrantRequest",
    "RequestPlanApprovalRequest",
    "SignedProvisioningCommandResponse",
]
