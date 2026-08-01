"""Licence API schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.licensing.service import LicenceIssuanceView


class IssueLicenceRequest(BaseModel):
    """Issue the next version for a staged allocation. Validity and binding come
    from the contract/commercial policy — the route never guesses them."""

    allocation_id: UUID
    product: str
    edition: str | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    grace_days: int = Field(default=0, ge=0)
    deployment_id: str | None = None
    constraints: dict[str, object] = Field(default_factory=dict)


class LicenceIssuanceResponse(BaseModel):
    id: UUID
    licence_id: UUID
    allocation_id: UUID
    version: int
    digest: str
    key_id: str
    status: str
    envelope: dict[str, object]

    @classmethod
    def of(cls, view: LicenceIssuanceView) -> LicenceIssuanceResponse:
        return cls(
            id=view.id,
            licence_id=view.licence_id,
            allocation_id=view.allocation_id,
            version=view.version,
            digest=view.digest,
            key_id=view.key_id,
            status=view.status,
            envelope=dict(view.envelope),
        )


class SigningKeyResponse(BaseModel):
    """PUBLIC verification material — what a deployment's keyring is built
    from. There is no endpoint that exposes private material, by construction."""

    key_id: str
    public_key_b64: str
    status: str


__all__ = [
    "IssueLicenceRequest",
    "LicenceIssuanceResponse",
    "SigningKeyResponse",
]
