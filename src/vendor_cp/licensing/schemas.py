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


class StageDeliveryRequest(BaseModel):
    """Stage an issued version for a REGISTERED delivery target. `target_ref`
    is resolved against the registry — an arbitrary destination is refused."""

    issuance_id: UUID
    target_ref: str


class DeliveryResponse(BaseModel):
    id: UUID
    issuance_id: UUID
    target_ref: str
    state: str
    activating_ack_id: UUID | None = None


class AcknowledgementRequest(BaseModel):
    """An inbound acknowledgement in the kernel's cross-plane vocabulary. Every
    field is a CLAIM until matched against what the vendor actually issued."""

    licence_id: str
    licence_version: int
    digest: str
    status: str
    reason: str | None = None
    deployment_id: str | None = None


class AckOutcomeResponse(BaseModel):
    """The vendor's verdict — deliberately distinct from the receiver's claim.
    `quarantined` marks an ack that could not be tied to something we issued."""

    ack_id: UUID
    disposition: str
    activated: bool
    quarantined: bool
    delivery_id: UUID | None = None


class RevokeLicenceRequest(BaseModel):
    """Revoking is a decision: a named reason is mandatory."""

    licence_id: UUID
    reason: str = Field(min_length=1, max_length=200)


class RevocationEntryResponse(BaseModel):
    """Confirmation that a lineage is revoked. It reaches deployments only when
    the next snapshot is published AND imported — this is a decision, not
    delivery."""

    licence_id: UUID
    reason: str


class RevocationListResponse(BaseModel):
    """A published snapshot. `revoked_licence_ids` is the FULL cumulative set —
    deployments import the whole artifact, never a delta."""

    id: UUID
    list_version: int
    digest: str
    key_id: str
    entry_count: int
    envelope: dict[str, object]
    revoked_licence_ids: list[str]


class RegisterTargetRequest(BaseModel):
    """Register or synchronise a delivery target. `connection_ref` is an opaque
    handle a transport interprets — never a destination URL from the caller."""

    target_ref: str = Field(min_length=1, max_length=200)
    customer_ref: str = Field(min_length=1, max_length=200)
    connection_ref: str | None = Field(default=None, max_length=200)
    status: str = Field(default="active")


class DeliveryTargetResponse(BaseModel):
    id: UUID
    target_ref: str
    customer_ref: str
    connection_ref: str | None = None
    status: str


class MapLegacyDeliveryRequest(BaseModel):
    """Attach a destination to a delivery staged before the registry existed."""

    target_ref: str = Field(min_length=1, max_length=200)


class DispatchRequest(BaseModel):
    """Run one replay pass. Bounded by `limit` so an operator (or a job) cannot
    accidentally sweep the whole backlog in a single transaction."""

    limit: int = Field(default=100, ge=1, le=1000)
    max_attempts: int = Field(default=10, ge=1, le=100)


class DispatchReportResponse(BaseModel):
    attempted: int
    sent: int
    failed: int
    parked_terminal: int
    parked_exhausted: int


class PipelineHealthResponse(BaseModel):
    """The alertable signals, kept as SEPARATE observations. The two
    `*_measurable` flags are False until deployments report the keyring and
    revocation-list versions they have APPLIED — a dashboard should show "not
    measurable" rather than a zero that reads green during an outage."""

    never_attempted: int
    attempted_never_sent: int
    sent_unacknowledged: int
    oldest_unacknowledged_age_seconds: int | None = None
    parked_total: int
    rejected_by_reason: dict[str, int]
    unknown_digest_acks: int
    unknown_licence_acks: int
    deployment_mismatch_acks: int
    unverified_identity_acks: int
    critical_acks: int
    latest_revocation_list_version: int | None = None
    keyring_uptake_lag_measurable: bool
    revocation_application_lag_measurable: bool


__all__ = [
    "IssueLicenceRequest",
    "LicenceIssuanceResponse",
    "SigningKeyResponse",
    "StageDeliveryRequest",
    "DeliveryResponse",
    "AcknowledgementRequest",
    "AckOutcomeResponse",
    "RevokeLicenceRequest",
    "RevocationEntryResponse",
    "RevocationListResponse",
    "PipelineHealthResponse",
    "RegisterTargetRequest",
    "DeliveryTargetResponse",
    "MapLegacyDeliveryRequest",
    "DispatchRequest",
    "DispatchReportResponse",
]
