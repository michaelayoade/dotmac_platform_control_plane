"""Typed request/response models for the accounts JSON API (no bare dicts)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.accounts.service import AccountView


class CreateAccountRequest(BaseModel):
    """Create a vendor account. `command_id` is the client-supplied idempotency
    key — retrying with the same key returns the original account, not a second
    one."""

    command_id: str = Field(min_length=1, max_length=200)
    external_ref: str = Field(min_length=1, max_length=200)
    display_name: str = Field(min_length=1, max_length=200)


class AccountResponse(BaseModel):
    """A vendor account as returned by the API."""

    id: UUID
    external_ref: str
    display_name: str
    status: str

    @classmethod
    def from_view(cls, view: AccountView) -> AccountResponse:
        return cls(
            id=view.id,
            external_ref=view.external_ref,
            display_name=view.display_name,
            status=view.status,
        )


__all__ = ["CreateAccountRequest", "AccountResponse"]
