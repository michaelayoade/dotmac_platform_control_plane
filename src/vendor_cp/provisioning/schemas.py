"""Typed request/response models for the provisioning-lab API (no bare dicts).

Map the kernel's frozen provisioning results (`PlanResult`/`ApplyResult`/
`ObserveResult`/`CompensationResult`) to JSON. The status vocabularies
(`ProvisioningStatus`, `StepStatus`) are `(str, Enum)`; responses carry their
string value.
"""

from __future__ import annotations

from dotmac_kernel.providers.provisioning import (
    ApplyResult,
    CompensationResult,
    ObserveResult,
    PlanResult,
    ProvisioningStep,
)
from pydantic import BaseModel, ConfigDict, Field


class StepSchema(BaseModel):
    step_id: str
    status: str
    detail: str

    @classmethod
    def of(cls, step: ProvisioningStep) -> StepSchema:
        return cls(step_id=step.step_id, status=step.status.value, detail=step.detail)


class PlanRequest(BaseModel):
    intent_id: str = Field(min_length=1, max_length=200)
    spec: dict[str, object] = Field(default_factory=dict)


class ApplyRequest(BaseModel):
    intent_id: str = Field(min_length=1, max_length=200)
    spec: dict[str, object] = Field(default_factory=dict)
    # An existing operation to RESUME (idempotent re-apply); omit to start a new one.
    operation_id: str | None = None


class CompensationRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    reason: str = Field(min_length=1, max_length=500)


class PlanResponse(BaseModel):
    intent_id: str
    plan_hash: str
    steps: list[StepSchema]

    @classmethod
    def of(cls, r: PlanResult) -> PlanResponse:
        return cls(
            intent_id=r.intent_id,
            plan_hash=r.plan_hash,
            steps=[StepSchema.of(s) for s in r.steps],
        )


class ApplyResponse(BaseModel):
    intent_id: str
    operation_id: str
    plan_hash: str
    status: str
    steps: list[StepSchema]

    @classmethod
    def of(cls, r: ApplyResult) -> ApplyResponse:
        return cls(
            intent_id=r.intent_id,
            operation_id=r.operation_id,
            plan_hash=r.plan_hash,
            status=r.status.value,
            steps=[StepSchema.of(s) for s in r.steps],
        )


class ObserveResponse(BaseModel):
    intent_id: str
    operation_id: str
    status: str
    plan_hash: str | None
    steps: list[StepSchema]

    @classmethod
    def of(cls, r: ObserveResult) -> ObserveResponse:
        return cls(
            intent_id=r.intent_id,
            operation_id=r.operation_id,
            status=r.status.value,
            plan_hash=r.plan_hash,
            steps=[StepSchema.of(s) for s in r.steps],
        )


class CompensationResponse(BaseModel):
    operation_id: str
    disposition: str
    snapshot: ObserveResponse
    reason_code: str | None

    @classmethod
    def of(cls, r: CompensationResult) -> CompensationResponse:
        return cls(
            operation_id=r.operation_id,
            disposition=r.disposition.value,
            snapshot=ObserveResponse.of(r.snapshot),
            reason_code=r.reason_code,
        )


__all__ = [
    "StepSchema",
    "PlanRequest",
    "ApplyRequest",
    "CompensationRequest",
    "PlanResponse",
    "ApplyResponse",
    "ObserveResponse",
    "CompensationResponse",
]
