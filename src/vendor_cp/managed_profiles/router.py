"""Platform-admin adapter for reusable managed-profile publication."""

from __future__ import annotations

from typing import Annotated

from dotmac_kernel import NotFoundError, PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.managed_profiles import service
from vendor_cp.managed_profiles.capability_contracts import (
    CapabilityContractRegistry,
    CataloguedCapabilityContractRegistry,
    DirectoryCapabilityContractDocumentReader,
)
from vendor_cp.managed_profiles.composition_contracts import (
    CapabilityCompositionRegistry,
    CataloguedCapabilityCompositionRegistry,
)
from vendor_cp.managed_profiles.schemas import (
    ManagedProfileVersionResponse,
    PublishProfileVersionRequest,
)

router = APIRouter(
    prefix="/platform/vendor/managed-profiles", tags=["managed-profiles"]
)

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


def _catalogued_capability_registry(db: Db) -> CapabilityContractRegistry:
    """Resolve exact held owner evidence on the request's platform session."""

    from vendor_cp.config import vendor_settings

    return CataloguedCapabilityContractRegistry.from_catalogue(
        db,
        pins=dict(vendor_settings.product_release_pins),
        document_reader=DirectoryCapabilityContractDocumentReader(
            vendor_settings.product_manifest_directory
        ),
    )


CapabilityRegistry = Annotated[
    CapabilityContractRegistry, Depends(_catalogued_capability_registry)
]


def _catalogued_composition_registry(
    db: Db, capability_registry: CapabilityRegistry
) -> CapabilityCompositionRegistry:
    """Resolve held canonical compositions or fail closed on an old catalogue."""

    from vendor_cp.config import vendor_settings

    return CataloguedCapabilityCompositionRegistry.from_catalogue(
        db,
        pins=dict(vendor_settings.product_release_pins),
        document_reader=DirectoryCapabilityContractDocumentReader(
            vendor_settings.product_manifest_directory
        ),
        capability_registry=capability_registry,
    )


CompositionRegistry = Annotated[
    CapabilityCompositionRegistry, Depends(_catalogued_composition_registry)
]


@router.post(
    "",
    response_model=ManagedProfileVersionResponse,
    status_code=status.HTTP_201_CREATED,
)
def publish_profile(
    body: PublishProfileVersionRequest,
    admin: Admin,
    db: Db,
    capability_registry: CapabilityRegistry,
    composition_registry: CompositionRegistry,
) -> ManagedProfileVersionResponse:
    view = service.publish_profile_version(
        db,
        service.PublishProfileVersionCommand(
            commercial_product_code=body.commercial_product_code,
            profile_code=body.profile_code,
            version=body.version,
            schema_version=body.schema_version,
            update_authority=body.update_authority,
            compatible_predecessors=tuple(
                service.CompatiblePredecessor(
                    commercial_product_code=item.commercial_product_code,
                    content_hash=item.content_hash,
                )
                for item in body.compatible_predecessors
            ),
            actor_admin_id=admin.id,
        ),
        capability_registry=capability_registry,
        composition_registry=composition_registry,
    )
    return ManagedProfileVersionResponse.from_view(view)


@router.get(
    "/{commercial_product_code}/{profile_code}/{version}",
    response_model=ManagedProfileVersionResponse,
)
def get_profile(
    commercial_product_code: str,
    profile_code: str,
    version: int,
    _admin: Admin,
    db: Db,
) -> ManagedProfileVersionResponse:
    view = service.get_profile_version(
        db,
        commercial_product_code=commercial_product_code,
        profile_code=profile_code,
        version=version,
    )
    if view is None:
        raise NotFoundError("managed profile version not found")
    return ManagedProfileVersionResponse.from_view(view)


__all__ = ["router"]
