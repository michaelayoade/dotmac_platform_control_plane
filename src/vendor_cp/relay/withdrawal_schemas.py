"""Typed HTTP values for resolving an `approval.withdrawn` `security_conflict`."""

from __future__ import annotations

from pydantic import BaseModel, Field

from vendor_cp.relay.withdrawal_outcomes import (
    RecordedConflictResolution,
    WithdrawalResolution,
)


class ResolveWithdrawalConflictRequest(BaseModel):
    resolution: WithdrawalResolution
    reason: str = Field(min_length=1, max_length=2000)
    redrive_ref: str | None = Field(default=None, max_length=200)


class ConflictResolutionResponse(BaseModel):
    id: str
    outcome_id: str
    resolution: str
    actor_ref: str
    reason: str
    redrive_ref: str | None
    recorded_at: str

    @classmethod
    def of(cls, value: RecordedConflictResolution) -> ConflictResolutionResponse:
        return cls(
            id=str(value.id),
            outcome_id=str(value.outcome_id),
            resolution=value.resolution.value,
            actor_ref=value.actor_ref,
            reason=value.reason,
            redrive_ref=value.redrive_ref,
            recorded_at=value.recorded_at.isoformat(),
        )


__all__ = ["ConflictResolutionResponse", "ResolveWithdrawalConflictRequest"]
