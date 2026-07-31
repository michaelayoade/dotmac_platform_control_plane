"""Typed request/response models for the tenant-scoped accounts API (option C)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.accounts.service import AccountView


class CreateAccountRequest(BaseModel):
    """Create a vendor account. `command_id` is the client idempotency key; the
    `tenant_id` is NOT in the body — it comes from the authenticated tenant
    context (a tenant-scoped resource is created in the caller's tenant)."""

    command_id: str = Field(min_length=1, max_length=200)
    external_ref: str = Field(min_length=1, max_length=200)
    display_name: str = Field(min_length=1, max_length=200)


class AccountResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    external_ref: str
    display_name: str
    status: str

    @classmethod
    def from_view(cls, view: AccountView) -> AccountResponse:
        return cls(
            id=view.id,
            tenant_id=view.tenant_id,
            external_ref=view.external_ref,
            display_name=view.display_name,
            status=view.status,
        )


__all__ = ["CreateAccountRequest", "AccountResponse"]
