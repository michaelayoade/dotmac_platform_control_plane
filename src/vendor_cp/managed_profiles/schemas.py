"""Typed HTTP contracts for reusable managed-service profile schemas."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.managed_profiles.service import ManagedServiceProfileVersionView


class CompatiblePredecessorRequest(BaseModel):
    commercial_product_code: str = Field(min_length=1, max_length=120)
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class PublishProfileVersionRequest(BaseModel):
    commercial_product_code: str = Field(min_length=1, max_length=120)
    profile_code: str = Field(min_length=1, max_length=120)
    version: int = Field(gt=0)
    schema_version: int = Field(gt=0)
    update_authority: str = Field(min_length=1, max_length=30)
    compatible_predecessors: tuple[CompatiblePredecessorRequest, ...] = ()


class ManagedProfileVersionResponse(BaseModel):
    id: UUID
    commercial_product_code: str
    profile_code: str
    version: int
    schema_version: int
    content_hash: str
    update_authority: str
    allowed_optional_components: tuple[str, ...]
    component_codes: tuple[str, ...]

    @classmethod
    def from_view(
        cls, view: ManagedServiceProfileVersionView
    ) -> ManagedProfileVersionResponse:
        return cls(
            id=view.id,
            commercial_product_code=view.commercial_product_code,
            profile_code=view.profile_code,
            version=view.version,
            schema_version=view.schema_version,
            content_hash=view.content_hash,
            update_authority=view.update_authority,
            allowed_optional_components=view.allowed_optional_components,
            component_codes=view.component_codes,
        )


__all__ = [
    "CompatiblePredecessorRequest",
    "ManagedProfileVersionResponse",
    "PublishProfileVersionRequest",
]
