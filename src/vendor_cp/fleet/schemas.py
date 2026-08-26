"""Typed HTTP contracts for account-owned fleet intent."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.fleet.service import (
    DeploymentDesiredStateView,
    DeploymentIntentResult,
    DeploymentTargetView,
    DeploymentView,
)


class CreateDeploymentTargetRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    target_ref: str = Field(min_length=1, max_length=200)
    customer_ref: str | None = Field(default=None, min_length=1, max_length=200)
    display_name: str = Field(min_length=1, max_length=200)
    region_code: str = Field(min_length=1, max_length=80)


class ConfigurationValueRequest(BaseModel):
    field_code: str = Field(min_length=1, max_length=120)
    value: str | tuple[str, ...]


class ConfigurationSnapshotRequest(BaseModel):
    snapshot_ref: str = Field(min_length=1, max_length=200)
    schema_version: int = Field(gt=0)
    values: tuple[ConfigurationValueRequest, ...]


class CreateDeploymentIntentRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    target_id: UUID
    deployment_ref: str = Field(min_length=1, max_length=200)
    commercial_product_code: str = Field(min_length=1, max_length=120)
    profile_code: str = Field(min_length=1, max_length=120)
    profile_version: int = Field(gt=0)
    selected_optional_components: tuple[str, ...] = ()
    configuration_snapshot: ConfigurationSnapshotRequest
    contract_id: UUID | None = None
    internal_source_code: str | None = Field(default=None, min_length=1, max_length=160)


class DeploymentTargetResponse(BaseModel):
    id: UUID
    account_id: UUID
    target_ref: str
    customer_ref: str | None
    display_name: str
    region_code: str

    @classmethod
    def from_view(cls, view: DeploymentTargetView) -> DeploymentTargetResponse:
        return cls(
            id=view.id,
            account_id=view.account_id,
            target_ref=view.target_ref,
            customer_ref=view.customer_ref,
            display_name=view.display_name,
            region_code=view.region_code,
        )


class DeploymentResponse(BaseModel):
    id: UUID
    account_id: UUID
    target_id: UUID
    deployment_ref: str
    commercial_product_code: str
    status: str
    contract_id: UUID | None
    internal_source_code: str | None
    current_desired_state_revision: int

    @classmethod
    def from_view(cls, view: DeploymentView) -> DeploymentResponse:
        return cls(
            id=view.id,
            account_id=view.account_id,
            target_id=view.target_id,
            deployment_ref=view.deployment_ref,
            commercial_product_code=view.commercial_product_code,
            status=view.status,
            contract_id=view.contract_id,
            internal_source_code=view.internal_source_code,
            current_desired_state_revision=view.current_desired_state_revision,
        )


class DesiredStateResponse(BaseModel):
    id: UUID
    deployment_id: UUID
    revision: int
    profile_version_id: UUID
    profile_content_hash: str
    configuration_hash: str
    desired_state_hash: str

    @classmethod
    def from_view(cls, view: DeploymentDesiredStateView) -> DesiredStateResponse:
        return cls(
            id=view.id,
            deployment_id=view.deployment_id,
            revision=view.revision,
            profile_version_id=view.profile_version_id,
            profile_content_hash=view.profile_content_hash,
            configuration_hash=view.configuration_hash,
            desired_state_hash=view.desired_state_hash,
        )


class DeploymentIntentResponse(BaseModel):
    deployment: DeploymentResponse
    desired_state: DesiredStateResponse
    was_duplicate: bool

    @classmethod
    def from_result(cls, result: DeploymentIntentResult) -> DeploymentIntentResponse:
        return cls(
            deployment=DeploymentResponse.from_view(result.deployment),
            desired_state=DesiredStateResponse.from_view(result.desired_state),
            was_duplicate=result.was_duplicate,
        )


__all__ = [
    "ConfigurationSnapshotRequest",
    "ConfigurationValueRequest",
    "CreateDeploymentIntentRequest",
    "CreateDeploymentTargetRequest",
    "DeploymentIntentResponse",
    "DeploymentTargetResponse",
]
