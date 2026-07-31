"""Contracts JSON API — a thin, platform-admin-only adapter around ContractService.

Each mutating route maps to one named lifecycle command; `ContractService` owns the
guards, the atomic state+audit+outbox-event commit, and the transitions.
`ConflictError` (bad transition / unmet guard) → 409; `NotFoundError` → 404.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.contracts import service
from vendor_cp.contracts.schemas import (
    ContractResponse,
    CreateDraftRequest,
    SubmitRequest,
    TransitionRequest,
)
from vendor_cp.offers.catalog import offered_capability_catalogue

router = APIRouter(prefix="/platform/vendor/contracts", tags=["contracts"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post("", response_model=ContractResponse, status_code=status.HTTP_201_CREATED)
def create_draft(body: CreateDraftRequest, admin: Admin, db: Db) -> ContractResponse:
    view = service.create_draft(
        db,
        service.CreateDraftCommand(
            command_id=body.command_id,
            customer_ref=body.customer_ref,
            legal_entity=body.legal_entity,
            currency_code=body.currency,
            term_start=body.term_start,
            term_end=body.term_end,
            activation_rule=body.activation_rule,
            lines=tuple(
                service.LineInput(
                    offer_code=li.offer_code,
                    offer_version=li.offer_version,
                    capability_code=li.capability_code,
                    quantity=li.quantity,
                )
                for li in body.lines
            ),
            actor_admin_id=admin.id,
        ),
    )
    return ContractResponse.of(view)


@router.post("/{contract_id}/submit", response_model=ContractResponse)
def submit(
    contract_id: UUID, body: SubmitRequest, admin: Admin, db: Db
) -> ContractResponse:
    view = service.submit(
        db,
        service.SubmitCommand(
            command_id=body.command_id,
            contract_id=contract_id,
            approval_policy_code=body.approval_policy_code,
            approval_policy_version=body.approval_policy_version,
            submitter_id=body.submitter_id,
            actor_admin_id=admin.id,
        ),
        catalogue=offered_capability_catalogue(),
    )
    return ContractResponse.of(view)


def _cmd(
    contract_id: UUID, body: TransitionRequest, admin: PlatformAdmin
) -> service.TransitionCommand:
    return service.TransitionCommand(
        command_id=body.command_id,
        contract_id=contract_id,
        reason=body.reason,
        activation_evidence=body.activation_evidence,
        effective_date=body.effective_date,
        impact_acknowledged=body.impact_acknowledged,
        actor_admin_id=admin.id,
    )


@router.post("/{contract_id}/approve", response_model=ContractResponse)
def approve(
    contract_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return ContractResponse.of(service.approve(db, _cmd(contract_id, body, admin)))


@router.post("/{contract_id}/reject", response_model=ContractResponse)
def reject(
    contract_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return ContractResponse.of(service.reject(db, _cmd(contract_id, body, admin)))


@router.post("/{contract_id}/activate", response_model=ContractResponse)
def activate(
    contract_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return ContractResponse.of(service.activate(db, _cmd(contract_id, body, admin)))


@router.post("/{contract_id}/suspend", response_model=ContractResponse)
def suspend(
    contract_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return ContractResponse.of(service.suspend(db, _cmd(contract_id, body, admin)))


@router.post("/{contract_id}/reinstate", response_model=ContractResponse)
def reinstate(
    contract_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return ContractResponse.of(service.reinstate(db, _cmd(contract_id, body, admin)))


@router.post("/{contract_id}/terminate", response_model=ContractResponse)
def terminate(
    contract_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return ContractResponse.of(service.terminate(db, _cmd(contract_id, body, admin)))


@router.post("/{contract_id}/cancel", response_model=ContractResponse)
def cancel(
    contract_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return ContractResponse.of(service.cancel(db, _cmd(contract_id, body, admin)))


@router.get("/{contract_id}", response_model=ContractResponse)
def get_contract(contract_id: UUID, _admin: Admin, db: Db) -> ContractResponse:
    from dotmac_kernel import NotFoundError

    view = service.get(db, contract_id)
    if view is None:
        raise NotFoundError(f"contract {contract_id} not found")
    return ContractResponse.of(view)


__all__ = ["router"]
