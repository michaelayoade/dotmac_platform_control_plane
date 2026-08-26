"""Platform-admin adapter for account-owned fleet intent."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.fleet import service
from vendor_cp.fleet.schemas import (
    CreateDeploymentIntentRequest,
    CreateDeploymentTargetRequest,
    DeploymentIntentResponse,
    DeploymentTargetResponse,
)

router = APIRouter(prefix="/platform/vendor", tags=["fleet"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post(
    "/accounts/{account_id}/deployment-targets",
    response_model=DeploymentTargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    account_id: UUID,
    body: CreateDeploymentTargetRequest,
    admin: Admin,
    db: Db,
) -> DeploymentTargetResponse:
    view = service.create_deployment_target(
        db,
        service.CreateDeploymentTargetCommand(
            command_id=body.command_id,
            account_id=account_id,
            target_ref=body.target_ref,
            customer_ref=body.customer_ref,
            display_name=body.display_name,
            region_code=body.region_code,
            actor_admin_id=admin.id,
        ),
    )
    return DeploymentTargetResponse.from_view(view)


@router.post(
    "/accounts/{account_id}/deployments",
    response_model=DeploymentIntentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_deployment_intent(
    account_id: UUID,
    body: CreateDeploymentIntentRequest,
    admin: Admin,
    db: Db,
) -> DeploymentIntentResponse:
    result = service.record_deployment_intent(
        db,
        service.CreateDeploymentIntentCommand(
            command_id=body.command_id,
            account_id=account_id,
            target_id=body.target_id,
            deployment_ref=body.deployment_ref,
            commercial_product_code=body.commercial_product_code,
            profile_code=body.profile_code,
            profile_version=body.profile_version,
            selected_optional_components=body.selected_optional_components,
            configuration_snapshot=service.ConfigurationSnapshotInput(
                snapshot_ref=body.configuration_snapshot.snapshot_ref,
                schema_version=body.configuration_snapshot.schema_version,
                values=tuple(
                    service.ConfigurationValue(
                        field_code=value.field_code,
                        value=value.value,
                    )
                    for value in body.configuration_snapshot.values
                ),
            ),
            contract_id=body.contract_id,
            internal_source_code=body.internal_source_code,
            actor_admin_id=admin.id,
        ),
    )
    return DeploymentIntentResponse.from_result(result)


__all__ = ["router"]
