"""Vendor-owned, side-effect-free provider for the provisioning laboratory.

This is shipped runtime behaviour, not a test helper. It implements the
kernel's public ``ProvisioningProvider`` contract while deliberately touching no
infrastructure: the laboratory exists to exercise plan/apply/observe/cancel
semantics before a real runner or provider is admitted by design.
"""

from __future__ import annotations

import hashlib
import json

from dotmac_kernel.providers.provisioning import (
    ApplyResult,
    CompensationDisposition,
    CompensationResult,
    ObserveResult,
    PlanResult,
    ProvisioningPlanError,
    ProvisioningRequest,
    ProvisioningStatus,
    ProvisioningStep,
    StepStatus,
)


class LaboratoryProvisioningProvider:
    """Deterministic in-memory simulation owned by the Vendor laboratory."""

    def __init__(
        self,
        *,
        steps: tuple[str, ...] = ("resource-a", "resource-b"),
        fail_plan: bool = False,
        fail_apply: bool = False,
        partial_first_apply: bool = False,
    ) -> None:
        if not steps:
            raise ValueError("the laboratory provider needs at least one step")
        self._step_ids = steps
        self._fail_plan = fail_plan
        self._fail_apply = fail_apply
        self._partial_first_apply = partial_first_apply
        self._operations: dict[str, ApplyResult] = {}

    @staticmethod
    def _plan_hash(request: ProvisioningRequest) -> str:
        canonical = json.dumps(
            {"intent_id": request.intent_id, "spec": dict(request.spec)},
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = hashlib.sha256(canonical.encode(), usedforsecurity=False)
        return digest.hexdigest()[:16]

    def _steps(self, status: StepStatus) -> tuple[ProvisioningStep, ...]:
        return tuple(
            ProvisioningStep(step_id=step_id, status=status)
            for step_id in self._step_ids
        )

    def plan(self, request: ProvisioningRequest) -> PlanResult:
        if self._fail_plan:
            raise ProvisioningPlanError(
                f"laboratory plan failure for {request.intent_id!r}"
            )
        return PlanResult(
            intent_id=request.intent_id,
            plan_hash=self._plan_hash(request),
            steps=self._steps(StepStatus.PENDING),
        )

    def apply(self, request: ProvisioningRequest) -> ApplyResult:
        plan_hash = self._plan_hash(request)
        operation_id = request.operation_id or f"{request.intent_id}:{plan_hash}"
        previous = self._operations.get(operation_id)
        if previous is not None and previous.is_terminal:
            return previous

        if self._fail_apply:
            status = ProvisioningStatus.FAILED
            steps = self._steps(StepStatus.FAILED)
        elif self._partial_first_apply and previous is None:
            status = ProvisioningStatus.PARTIAL
            steps = (
                ProvisioningStep(self._step_ids[0], StepStatus.SUCCEEDED),
                *(
                    ProvisioningStep(step_id, StepStatus.PENDING)
                    for step_id in self._step_ids[1:]
                ),
            )
        else:
            status = ProvisioningStatus.SUCCEEDED
            steps = self._steps(StepStatus.SUCCEEDED)

        result = ApplyResult(
            intent_id=request.intent_id,
            operation_id=operation_id,
            plan_hash=plan_hash,
            status=status,
            steps=steps,
        )
        self._operations[operation_id] = result
        return result

    def observe(self, operation_id: str) -> ObserveResult:
        result = self._operations.get(operation_id)
        if result is None:
            return ObserveResult(
                intent_id="",
                operation_id=operation_id,
                status=ProvisioningStatus.PENDING,
            )
        return ObserveResult(
            intent_id=result.intent_id,
            operation_id=operation_id,
            status=result.status,
            steps=result.steps,
            plan_hash=result.plan_hash,
        )

    def cancel(self, operation_id: str) -> ObserveResult:
        result = self._operations.get(operation_id)
        steps = tuple(
            ProvisioningStep(
                step.step_id,
                step.status if step.is_settled else StepStatus.CANCELLED,
            )
            for step in (result.steps if result is not None else ())
        )
        if result is not None:
            self._operations[operation_id] = ApplyResult(
                intent_id=result.intent_id,
                operation_id=operation_id,
                plan_hash=result.plan_hash,
                status=ProvisioningStatus.CANCELLED,
                steps=steps,
            )
        return ObserveResult(
            intent_id=result.intent_id if result is not None else "",
            operation_id=operation_id,
            status=ProvisioningStatus.CANCELLED,
            steps=steps,
            plan_hash=result.plan_hash if result is not None else None,
        )

    def compensate(self, operation_id: str, reason: str) -> CompensationResult:
        """Reverse a settled operation, in the only place it exists.

        A first version of this returned `NOT_SUPPORTED` on the reasoning that a
        laboratory touching no infrastructure has nothing to undo. That was
        wrong, and the kernel's conformance suite is right to reject it: this
        provider DOES hold state — the operation record every `observe` reads —
        and that record is the whole of the effect it ever produced. Reversing
        it is a faithful compensation rather than a courtesy `SUCCEEDED`.

        The distinction that matters is against `cancel`, which stops work in
        flight and leaves a CANCELLED operation behind. This runs after
        settlement and drives every step it can still reach to CANCELLED,
        including the ones that had SUCCEEDED — undoing a converged step is
        precisely what compensation means and what cancellation does not.

        Idempotent by `operation_id`: compensating an already-compensated
        operation recomputes the same terminal record. An unknown id
        compensates nothing and says so with an empty snapshot rather than
        inventing an operation to reverse.
        """
        result = self._operations.get(operation_id)
        if result is not None:
            self._operations[operation_id] = ApplyResult(
                intent_id=result.intent_id,
                operation_id=operation_id,
                plan_hash=result.plan_hash,
                status=ProvisioningStatus.CANCELLED,
                steps=tuple(
                    ProvisioningStep(step.step_id, StepStatus.CANCELLED)
                    for step in result.steps
                ),
            )
        return CompensationResult(
            operation_id=operation_id,
            disposition=CompensationDisposition.SUCCEEDED,
            snapshot=self.observe(operation_id),
            reason_code=None,
        )


__all__ = ["LaboratoryProvisioningProvider"]
