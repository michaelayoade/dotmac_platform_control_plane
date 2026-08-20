"""Thin platform-admin HTTP adapter for Commercial Agreements."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from dotmac_kernel import NotFoundError, PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.contracts import adapter
from vendor_cp.contracts.schemas import (
    ActivateRequest,
    ApprovalRequest,
    ContractResponse,
    CreateDraftRequest,
    ProposeRequest,
    TerminateRequest,
    TransitionRequest,
)
from vendor_cp.offers.catalog import configured_product_capability_catalogues

router = APIRouter(prefix="/platform/vendor/contracts", tags=["contracts"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post("", response_model=ContractResponse, status_code=status.HTTP_201_CREATED)
def create_draft(body: CreateDraftRequest, admin: Admin, db: Db) -> ContractResponse:
    try:
        value = adapter.create_draft(
            db,
            adapter.CreateDraftCommand(
                command_id=body.command_id,
                reference=body.reference,
                product_code=body.product_code,
                counterparty_ref=body.counterparty_ref,
                agreement_type=body.agreement_type,
                term_start=body.term_start,
                term_end=body.term_end,
                lines=tuple(
                    adapter.LineInput(
                        offer_code=line.offer_code,
                        offer_version=line.offer_version,
                        capability_code=line.capability_code,
                        quantity=line.quantity,
                    )
                    for line in body.lines
                ),
                actor_admin_id=admin.id,
            ),
            catalogues=configured_product_capability_catalogues(db),
        )
    except adapter.AgreementError as exc:
        raise adapter.agreement_domain_error(exc) from exc
    return ContractResponse.of(value)


@router.post("/{agreement_id}/propose", response_model=ContractResponse)
def propose(
    agreement_id: UUID, body: ProposeRequest, admin: Admin, db: Db
) -> ContractResponse:
    try:
        value = adapter.propose(
            db,
            adapter.ProposeCommand(
                command_id=body.command_id,
                agreement_id=agreement_id,
                approval_policy_code=body.approval_policy_code,
                approval_policy_version=body.approval_policy_version,
                requested_by=body.requested_by,
                expected_version=body.expected_version,
                actor_admin_id=admin.id,
            ),
            catalogues=configured_product_capability_catalogues(db),
        )
    except adapter.AgreementError as exc:
        raise adapter.agreement_domain_error(exc) from exc
    return ContractResponse.of(value)


@router.post("/{agreement_id}/approve", response_model=ContractResponse)
def approve(
    agreement_id: UUID, body: ApprovalRequest, admin: Admin, db: Db
) -> ContractResponse:
    try:
        value = adapter.approve(
            db,
            adapter.ApprovalCommand(
                command_id=body.command_id,
                agreement_id=agreement_id,
                approval_request_id=body.approval_request_id,
                expected_version=body.expected_version,
                actor_admin_id=admin.id,
            ),
        )
    except adapter.AgreementError as exc:
        raise adapter.agreement_domain_error(exc) from exc
    return ContractResponse.of(value)


@router.post("/{agreement_id}/activate", response_model=ContractResponse)
def activate(
    agreement_id: UUID, body: ActivateRequest, admin: Admin, db: Db
) -> ContractResponse:
    try:
        value = adapter.activate(
            db,
            adapter.ActivateCommand(
                command_id=body.command_id,
                agreement_id=agreement_id,
                approval_request_id=body.approval_request_id,
                activation_rule=body.activation_rule,
                activation_reference=body.activation_reference,
                activation_satisfied_at=body.activation_satisfied_at,
                expected_version=body.expected_version,
                actor_admin_id=admin.id,
            ),
        )
    except adapter.AgreementError as exc:
        raise adapter.agreement_domain_error(exc) from exc
    return ContractResponse.of(value)


def _transition_command(
    agreement_id: UUID, body: TransitionRequest, admin: PlatformAdmin
) -> adapter.TransitionCommand:
    return adapter.TransitionCommand(
        command_id=body.command_id,
        agreement_id=agreement_id,
        expected_status=body.expected_status,
        expected_version=body.expected_version,
        reason=body.reason,
        actor_admin_id=admin.id,
    )


def _apply_transition(
    operation: Callable[[Session, adapter.TransitionCommand], adapter.ContractView],
    db: Session,
    command: adapter.TransitionCommand,
) -> ContractResponse:
    try:
        value = operation(db, command)
    except adapter.AgreementError as exc:
        raise adapter.agreement_domain_error(exc) from exc
    return ContractResponse.of(value)


@router.post("/{agreement_id}/reject", response_model=ContractResponse)
def reject(
    agreement_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return _apply_transition(
        adapter.reject, db, _transition_command(agreement_id, body, admin)
    )


@router.post("/{agreement_id}/suspend", response_model=ContractResponse)
def suspend(
    agreement_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return _apply_transition(
        adapter.suspend, db, _transition_command(agreement_id, body, admin)
    )


@router.post("/{agreement_id}/reinstate", response_model=ContractResponse)
def reinstate(
    agreement_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return _apply_transition(
        adapter.reinstate, db, _transition_command(agreement_id, body, admin)
    )


@router.post("/{agreement_id}/cancel", response_model=ContractResponse)
def cancel(
    agreement_id: UUID, body: TransitionRequest, admin: Admin, db: Db
) -> ContractResponse:
    return _apply_transition(
        adapter.cancel, db, _transition_command(agreement_id, body, admin)
    )


@router.post("/{agreement_id}/terminate", response_model=ContractResponse)
def terminate(
    agreement_id: UUID, body: TerminateRequest, admin: Admin, db: Db
) -> ContractResponse:
    try:
        value = adapter.terminate(
            db,
            adapter.TerminateCommand(
                command_id=body.command_id,
                agreement_id=agreement_id,
                effective_date=body.effective_date,
                impact_acknowledged=body.impact_acknowledged,
                reason=body.reason,
                expected_status=body.expected_status,
                expected_version=body.expected_version,
                actor_admin_id=admin.id,
            ),
        )
    except adapter.AgreementError as exc:
        raise adapter.agreement_domain_error(exc) from exc
    return ContractResponse.of(value)


@router.get("/{agreement_id}", response_model=ContractResponse)
def get_contract(agreement_id: UUID, _admin: Admin, db: Db) -> ContractResponse:
    value = adapter.get(db, agreement_id)
    if value is None:
        raise NotFoundError(f"agreement {agreement_id} not found")
    return ContractResponse.of(value)


__all__ = ["router"]
