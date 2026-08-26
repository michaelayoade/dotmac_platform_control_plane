"""Thin platform-admin adapter for immutable planning records."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.planning import service
from vendor_cp.planning.command_signer import CommandSigner
from vendor_cp.planning.receipt_verifier import ReceiptVerifier
from vendor_cp.planning.schemas import (
    ApprovalGrantResponse,
    ApprovalRequestBindingResponse,
    BuildApprovedProvisioningCommandsRequest,
    BuildCancelProvisioningCommandsRequest,
    BuildProvisioningCommandsRequest,
    BundleManifestResponse,
    CreateDeploymentPlanRequest,
    DeploymentPlanResponse,
    IngestIntegratorReceiptRequest,
    IntegratorReceiptResponse,
    PublishBundleManifestRequest,
    RecordPlanApprovalGrantRequest,
    RequestPlanApprovalRequest,
    SignedProvisioningCommandResponse,
)

router = APIRouter(prefix="/platform/vendor", tags=["planning"])
Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post(
    "/deployment-bundles",
    response_model=BundleManifestResponse,
    status_code=status.HTTP_201_CREATED,
)
def publish_bundle(
    body: PublishBundleManifestRequest, admin: Admin, db: Db
) -> BundleManifestResponse:
    result = service.publish_bundle_manifest_version(
        db,
        service.PublishBundleManifestCommand(
            command_id=body.command_id,
            commercial_product_code=body.commercial_product_code,
            profile_code=body.profile_code,
            profile_version=body.profile_version,
            bundle_code=body.bundle_code,
            version=body.version,
            components=tuple(
                service.ComponentArtifactSelection(
                    component_code=item.component_code,
                    artifact_id=item.artifact_id,
                    artifact_digest=item.artifact_digest,
                    artifact_reference=item.artifact_reference,
                    provenance=service.AttestationSelection(
                        **item.provenance.model_dump()
                    ),
                    sbom=service.AttestationSelection(**item.sbom.model_dump()),
                    signature=service.AttestationSelection(
                        **item.signature.model_dump()
                    ),
                    product_manifest=(
                        service.AttestationSelection(
                            **item.product_manifest.model_dump()
                        )
                        if item.product_manifest is not None
                        else None
                    ),
                    vulnerability_policy_result=(
                        service.AttestationSelection(
                            **item.vulnerability_policy_result.model_dump()
                        )
                        if item.vulnerability_policy_result is not None
                        else None
                    ),
                    compatibility_result=(
                        service.AttestationSelection(
                            **item.compatibility_result.model_dump()
                        )
                        if item.compatibility_result is not None
                        else None
                    ),
                )
                for item in body.components
            ),
            actor_admin_id=admin.id,
        ),
    )
    return BundleManifestResponse.from_view(result)


@router.post(
    "/deployments/{deployment_id}/plans",
    response_model=DeploymentPlanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_plan(
    deployment_id: UUID,
    body: CreateDeploymentPlanRequest,
    admin: Admin,
    db: Db,
) -> DeploymentPlanResponse:
    result = service.create_deployment_plan(
        db,
        service.CreateDeploymentPlanCommand(
            command_id=body.command_id,
            deployment_id=deployment_id,
            desired_state_version_id=body.desired_state_version_id,
            bundle_manifest_version_id=body.bundle_manifest_version_id,
            allocation_id=body.allocation_id,
            binding_selections=tuple(
                service.IntegratorBindingSelection(**item.model_dump())
                for item in body.binding_selections
            ),
            lifecycle_policy=service.VersionedPolicyRef(
                policy_code=body.lifecycle_policy.policy_code,
                version=body.lifecycle_policy.version,
            ),
            actor_admin_id=admin.id,
        ),
    )
    return DeploymentPlanResponse.from_view(result)


@router.post(
    "/deployment-plans/{plan_id}/approval-requests",
    response_model=ApprovalRequestBindingResponse,
    status_code=status.HTTP_201_CREATED,
)
def request_approval(
    plan_id: UUID,
    body: RequestPlanApprovalRequest,
    admin: Admin,
    db: Db,
) -> ApprovalRequestBindingResponse:
    result = service.request_plan_approval(
        db,
        service.RequestPlanApprovalCommand(
            command_id=body.command_id,
            plan_id=plan_id,
            policy_code=body.policy_code,
            policy_version=body.policy_version,
            expires_at=body.expires_at,
            requested_by=admin.id,
            plan_validation_receipt_ids=body.plan_validation_receipt_ids,
        ),
    )
    return ApprovalRequestBindingResponse.from_view(result)


@router.post(
    "/deployment-plans/{plan_id}/approval-grants",
    response_model=ApprovalGrantResponse,
    status_code=status.HTTP_201_CREATED,
)
def record_grant(
    plan_id: UUID,
    body: RecordPlanApprovalGrantRequest,
    admin: Admin,
    db: Db,
) -> ApprovalGrantResponse:
    result = service.record_plan_approval_grant(
        db,
        service.RecordPlanApprovalGrantCommand(
            command_id=body.command_id,
            plan_id=plan_id,
            approval_request_binding_id=body.approval_request_binding_id,
            actor_admin_id=admin.id,
        ),
    )
    return ApprovalGrantResponse.from_view(result)


@router.post(
    "/integrator-receipts",
    response_model=IntegratorReceiptResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_receipt(
    body: IngestIntegratorReceiptRequest,
    admin: Admin,
    db: Db,
    verifier: ReceiptVerifier,
) -> IntegratorReceiptResponse:
    result = service.ingest_integrator_receipt(
        db,
        service.IngestIntegratorReceiptCommand(
            signed_receipt=body.signed_receipt,
            actor_admin_id=admin.id,
        ),
        verifier=verifier,
    )
    return IntegratorReceiptResponse.from_view(result)


@router.post(
    "/deployment-plans/{plan_id}/commands/plan",
    response_model=tuple[SignedProvisioningCommandResponse, ...],
)
def build_plan_command_envelopes(
    plan_id: UUID,
    body: BuildProvisioningCommandsRequest,
    _admin: Admin,
    db: Db,
    runtime: CommandSigner,
) -> tuple[SignedProvisioningCommandResponse, ...]:
    result = service.build_plan_commands(
        db,
        service.BuildPlanCommands(
            command_id_prefix=body.command_id_prefix,
            plan_id=plan_id,
            audience=runtime.audience,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
        ),
        signer=runtime.signer,
        key_separation=runtime.key_separation,
    )
    return tuple(SignedProvisioningCommandResponse.from_view(item) for item in result)


@router.post(
    "/deployment-plans/{plan_id}/commands/apply",
    response_model=tuple[SignedProvisioningCommandResponse, ...],
)
def build_apply_command_envelopes(
    plan_id: UUID,
    body: BuildApprovedProvisioningCommandsRequest,
    _admin: Admin,
    db: Db,
    runtime: CommandSigner,
) -> tuple[SignedProvisioningCommandResponse, ...]:
    result = service.build_approved_apply_commands(
        db,
        service.BuildApprovedApplyCommands(
            command_id_prefix=body.command_id_prefix,
            plan_id=plan_id,
            approval_grant_id=body.approval_grant_id,
            audience=runtime.audience,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
        ),
        signer=runtime.signer,
        key_separation=runtime.key_separation,
        prerequisite_receipts=service.VerifiedReceiptResolver(db),
    )
    return tuple(SignedProvisioningCommandResponse.from_view(item) for item in result)


@router.post(
    "/deployment-plans/{plan_id}/commands/observe",
    response_model=tuple[SignedProvisioningCommandResponse, ...],
)
def build_observe_command_envelopes(
    plan_id: UUID,
    body: BuildApprovedProvisioningCommandsRequest,
    _admin: Admin,
    db: Db,
    runtime: CommandSigner,
) -> tuple[SignedProvisioningCommandResponse, ...]:
    result = service.build_observe_commands(
        db,
        service.BuildObserveCommands(
            command_id_prefix=body.command_id_prefix,
            plan_id=plan_id,
            approval_grant_id=body.approval_grant_id,
            audience=runtime.audience,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
        ),
        signer=runtime.signer,
        key_separation=runtime.key_separation,
    )
    return tuple(SignedProvisioningCommandResponse.from_view(item) for item in result)


@router.post(
    "/deployment-plans/{plan_id}/commands/cancel",
    response_model=tuple[SignedProvisioningCommandResponse, ...],
)
def build_cancel_command_envelopes(
    plan_id: UUID,
    body: BuildCancelProvisioningCommandsRequest,
    _admin: Admin,
    db: Db,
    runtime: CommandSigner,
) -> tuple[SignedProvisioningCommandResponse, ...]:
    result = service.build_cancel_commands(
        db,
        service.BuildCancelCommands(
            command_id_prefix=body.command_id_prefix,
            plan_id=plan_id,
            approval_grant_id=body.approval_grant_id,
            audience=runtime.audience,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
            reason=body.reason,
        ),
        signer=runtime.signer,
        key_separation=runtime.key_separation,
    )
    return tuple(SignedProvisioningCommandResponse.from_view(item) for item in result)


__all__ = ["router"]
