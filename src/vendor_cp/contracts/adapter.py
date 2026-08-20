"""The one typed seam from Vendor into Commercial Agreements.

The published module owns agreement shape, lifecycle, history, audit and facts.
This adapter owns only assembly translations: Vendor offers become opaque line
references and frozen terms, Vendor's product catalogue satisfies the module
port, and the Approvals authority is converted into content-bound evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from uuid import UUID

from dotmac_commercial_agreements import (
    AGREEMENT_ACTIVATED_V1,
    ActivationEvidence,
    AgreementError,
    AgreementPeriod,
    AgreementStatus,
    AgreementView,
    ApprovalEvidence,
    CommercialTerms,
    EvidenceRefusedError,
    ExpectedStateError,
    TransitionRefusedError,
    UndeclaredCapabilityError,
    UnknownProductError,
)
from dotmac_commercial_agreements import (
    ActivateCommand as ModuleActivateCommand,
)
from dotmac_commercial_agreements import (
    ApproveCommand as ModuleApproveCommand,
)
from dotmac_commercial_agreements import (
    DraftCommand as ModuleDraftCommand,
)
from dotmac_commercial_agreements import (
    LineInput as ModuleLineInput,
)
from dotmac_commercial_agreements import (
    ProposeCommand as ModuleProposeCommand,
)
from dotmac_commercial_agreements import (
    TerminateCommand as ModuleTerminateCommand,
)
from dotmac_commercial_agreements import (
    TransitionCommand as ModuleTransitionCommand,
)
from dotmac_commercial_agreements import (
    activate as module_activate,
)
from dotmac_commercial_agreements import (
    approve as module_approve,
)
from dotmac_commercial_agreements import (
    cancel as module_cancel,
)
from dotmac_commercial_agreements import (
    get as module_get,
)
from dotmac_commercial_agreements import (
    open_draft as module_open_draft,
)
from dotmac_commercial_agreements import (
    propose as module_propose,
)
from dotmac_commercial_agreements import (
    reinstate as module_reinstate,
)
from dotmac_commercial_agreements import (
    reject as module_reject,
)
from dotmac_commercial_agreements import (
    suspend as module_suspend,
)
from dotmac_commercial_agreements import (
    terminate as module_terminate,
)
from dotmac_entitlement_allocation import (
    UndeclaredCapabilityError as AllocationUndeclaredCapabilityError,
)
from dotmac_entitlement_allocation import (
    UnknownProductError as AllocationUnknownProductError,
)
from dotmac_kernel import BadRequestError, ConflictError, DomainError, NotFoundError
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts_authority import APPROVAL_SUBJECT_TYPE
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.service import get_offer_version

ACTIVATED_EVENT_TYPE = AGREEMENT_ACTIVATED_V1


def agreement_domain_error(error: AgreementError) -> DomainError:
    """Translate the module's refusal vocabulary at Vendor's HTTP boundary."""
    if isinstance(error, UnknownProductError):
        return NotFoundError(str(error))
    if isinstance(
        error,
        EvidenceRefusedError | ExpectedStateError | TransitionRefusedError,
    ):
        return ConflictError(str(error))
    return BadRequestError(str(error))


@dataclass(frozen=True, slots=True)
class LineInput:
    offer_code: str
    offer_version: int
    capability_code: str
    quantity: int = 1


@dataclass(frozen=True, slots=True)
class CreateDraftCommand:
    command_id: str
    reference: str
    product_code: str
    counterparty_ref: str
    agreement_type: str
    term_start: date
    term_end: date
    lines: tuple[LineInput, ...]
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ProposeCommand:
    command_id: str
    agreement_id: UUID
    approval_policy_code: str
    approval_policy_version: int
    requested_by: UUID
    expected_version: int | None = None
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ApprovalCommand:
    command_id: str
    agreement_id: UUID
    approval_request_id: UUID
    expected_version: int | None = None
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ActivateCommand:
    command_id: str
    agreement_id: UUID
    approval_request_id: UUID
    activation_rule: str
    activation_reference: str
    activation_satisfied_at: datetime
    expected_version: int | None = None
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class TransitionCommand:
    command_id: str
    agreement_id: UUID
    expected_status: str | None = None
    expected_version: int | None = None
    reason: str | None = None
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class TerminateCommand:
    command_id: str
    agreement_id: UUID
    effective_date: date
    impact_acknowledged: bool
    reason: str
    expected_status: str | None = None
    expected_version: int | None = None
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class LineView:
    product_code: str
    capability_code: str
    quantity: int
    unit_amount: str
    unit_currency_code: str
    offer_ref: str | None
    release_ref: str | None


@dataclass(frozen=True, slots=True)
class ContractView:
    id: UUID
    reference: str
    agreement_family_id: UUID
    agreement_version: int
    product_code: str
    counterparty_ref: str
    agreement_type: str
    status: str
    content_hash: str | None
    record_version: int
    activation_rule: str | None
    approval_request_id: UUID | None = None
    lines: tuple[LineView, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ActiveAgreementSnapshot:
    agreement_id: UUID
    product_code: str
    counterparty_ref: str
    content_hash: str
    capabilities: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class _AgreementCatalogue:
    source: ProductCapabilityCatalogues

    def require_declared(self, product_code: str, codes: tuple[str, ...]) -> None:
        for code in codes:
            try:
                self.source.require_declared(
                    product_code=product_code,
                    capability_code=code,
                )
            except AllocationUnknownProductError as exc:
                raise UnknownProductError(product_code) from exc
            except AllocationUndeclaredCapabilityError as exc:
                raise UndeclaredCapabilityError(product_code, exc.codes) from exc


def _single_product(view: AgreementView) -> str:
    products = {line.product_code for line in view.lines}
    if len(products) != 1:
        raise ConflictError(
            f"Vendor agreements must name exactly one product; found {sorted(products)}"
        )
    return next(iter(products))


def _view(
    value: AgreementView, *, approval_request_id: UUID | None = None
) -> ContractView:
    return ContractView(
        id=value.id,
        reference=value.reference,
        agreement_family_id=value.agreement_family_id,
        agreement_version=value.agreement_version,
        product_code=_single_product(value),
        counterparty_ref=value.counterparty_ref,
        agreement_type=value.agreement_type,
        status=str(value.status),
        content_hash=value.content_hash,
        record_version=value.record_version,
        activation_rule=value.activation_rule,
        approval_request_id=approval_request_id,
        lines=tuple(
            LineView(
                product_code=line.product_code,
                capability_code=line.capability_code,
                quantity=line.quantity,
                unit_amount=line.unit_amount,
                unit_currency_code=line.unit_currency_code,
                offer_ref=line.offer_ref,
                release_ref=line.release_ref,
            )
            for line in value.lines
        ),
    )


def _module_lines(
    db: Session, command: CreateDraftCommand
) -> tuple[ModuleLineInput, ...]:
    lines: list[ModuleLineInput] = []
    for requested in command.lines:
        offer = get_offer_version(
            db,
            product_code=command.product_code,
            offer_code=requested.offer_code,
            version=requested.offer_version,
        )
        if offer is None:
            raise NotFoundError(
                f"offer version {command.product_code!r}/{requested.offer_code!r} "
                f"v{requested.offer_version} not found"
            )
        if requested.capability_code not in offer.capability_codes:
            raise BadRequestError(
                f"capability {requested.capability_code!r} is not granted by offer "
                f"{requested.offer_code!r} v{requested.offer_version}"
            )
        lines.append(
            ModuleLineInput(
                product_code=command.product_code,
                capability_code=requested.capability_code,
                quantity=requested.quantity,
                terms=CommercialTerms(
                    unit_amount=str(offer.price.amount),
                    currency_code=offer.price.currency.code,
                ),
                offer_ref=str(offer.id),
            )
        )
    return tuple(lines)


def create_draft(
    db: Session,
    command: CreateDraftCommand,
    *,
    catalogues: ProductCapabilityCatalogues,
) -> ContractView:
    value = module_open_draft(
        db,
        ModuleDraftCommand(
            command_id=command.command_id,
            reference=command.reference,
            counterparty_ref=command.counterparty_ref,
            agreement_type=command.agreement_type,
            period=AgreementPeriod(command.term_start, command.term_end),
            lines=_module_lines(db, command),
            actor_admin_id=command.actor_admin_id,
        ),
        catalogue=_AgreementCatalogue(catalogues),
    )
    return _view(value)


def propose(
    db: Session,
    command: ProposeCommand,
    *,
    catalogues: ProductCapabilityCatalogues,
) -> ContractView:
    value = module_propose(
        db,
        ModuleProposeCommand(
            command_id=command.command_id,
            agreement_id=command.agreement_id,
            approval_policy_code=command.approval_policy_code,
            approval_policy_version=command.approval_policy_version,
            expected_version=command.expected_version,
            actor_admin_id=command.actor_admin_id,
        ),
        catalogue=_AgreementCatalogue(catalogues),
    )
    if value.content_hash is None:
        raise ConflictError(
            f"agreement {value.id} was proposed without a frozen content hash"
        )
    request = approvals.open_request(
        db,
        approvals.OpenRequestCommand(
            command_id=f"{command.command_id}:approval-request",
            policy_code=command.approval_policy_code,
            policy_version=command.approval_policy_version,
            subject_type=APPROVAL_SUBJECT_TYPE,
            subject_id=str(value.id),
            content_hash=value.content_hash,
            requested_by=command.requested_by,
        ),
    )
    return _view(value, approval_request_id=request.request_id)


def _approval_evidence(
    db: Session, *, agreement_id: UUID, request_id: UUID, content_hash: str
) -> ApprovalEvidence:
    evidence = approvals.approved_request_evidence(
        db,
        request_id=request_id,
        subject_type=APPROVAL_SUBJECT_TYPE,
        subject_id=str(agreement_id),
        content_hash=content_hash,
    )
    return ApprovalEvidence(
        policy_code=evidence.policy_code,
        policy_version=evidence.policy_version,
        decision_ref=str(evidence.request_id),
        content_digest=evidence.content_hash,
        decided_at=evidence.decided_at,
        approver_refs=evidence.approver_refs,
    )


def _required(db: Session, agreement_id: UUID) -> AgreementView:
    value = module_get(db, agreement_id)
    if value is None:
        raise NotFoundError(f"agreement {agreement_id} not found")
    return value


def approve(db: Session, command: ApprovalCommand) -> ContractView:
    current = _required(db, command.agreement_id)
    if current.content_hash is None:
        raise ConflictError(f"agreement {current.id} has no frozen content hash")
    value = module_approve(
        db,
        ModuleApproveCommand(
            command_id=command.command_id,
            agreement_id=command.agreement_id,
            evidence=_approval_evidence(
                db,
                agreement_id=command.agreement_id,
                request_id=command.approval_request_id,
                content_hash=current.content_hash,
            ),
            expected_version=command.expected_version,
            actor_admin_id=command.actor_admin_id,
        ),
    )
    return _view(value, approval_request_id=command.approval_request_id)


def activate(db: Session, command: ActivateCommand) -> ContractView:
    current = _required(db, command.agreement_id)
    if current.content_hash is None:
        raise ConflictError(f"agreement {current.id} has no frozen content hash")
    approval = _approval_evidence(
        db,
        agreement_id=command.agreement_id,
        request_id=command.approval_request_id,
        content_hash=current.content_hash,
    )
    value = module_activate(
        db,
        ModuleActivateCommand(
            command_id=command.command_id,
            agreement_id=command.agreement_id,
            approval_evidence=approval,
            activation_evidence=ActivationEvidence(
                rule=command.activation_rule,
                reference=command.activation_reference,
                satisfied_at=command.activation_satisfied_at,
            ),
            expected_version=command.expected_version,
            actor_admin_id=command.actor_admin_id,
        ),
    )
    return _view(value, approval_request_id=command.approval_request_id)


def _transition(command: TransitionCommand) -> ModuleTransitionCommand:
    return ModuleTransitionCommand(
        command_id=command.command_id,
        agreement_id=command.agreement_id,
        expected_status=command.expected_status,
        expected_version=command.expected_version,
        reason=command.reason,
        actor_admin_id=command.actor_admin_id,
    )


def reject(db: Session, command: TransitionCommand) -> ContractView:
    return _view(module_reject(db, _transition(command)))


def suspend(db: Session, command: TransitionCommand) -> ContractView:
    return _view(module_suspend(db, _transition(command)))


def reinstate(db: Session, command: TransitionCommand) -> ContractView:
    return _view(module_reinstate(db, _transition(command)))


def cancel(db: Session, command: TransitionCommand) -> ContractView:
    return _view(module_cancel(db, _transition(command)))


def terminate(db: Session, command: TerminateCommand) -> ContractView:
    return _view(
        module_terminate(
            db,
            ModuleTerminateCommand(
                command_id=command.command_id,
                agreement_id=command.agreement_id,
                effective_date=command.effective_date,
                impact_acknowledged=command.impact_acknowledged,
                reason=command.reason,
                expected_status=command.expected_status,
                expected_version=command.expected_version,
                actor_admin_id=command.actor_admin_id,
            ),
        )
    )


def get(db: Session, agreement_id: UUID) -> ContractView | None:
    value = module_get(db, agreement_id)
    return None if value is None else _view(value)


def active_snapshot(
    db: Session, agreement_id: UUID, *, expected_content_hash: str
) -> ActiveAgreementSnapshot:
    value = _required(db, agreement_id)
    if value.status != AgreementStatus.ACTIVE.value:
        raise NotFoundError(
            f"agreement {agreement_id} is {value.status!r}, not active — "
            "nothing to allocate"
        )
    if value.content_hash != expected_content_hash:
        raise NotFoundError(
            "activation event content_hash does not match the agreement's "
            "current accepted snapshot — stale event, skipping"
        )
    return ActiveAgreementSnapshot(
        agreement_id=value.id,
        product_code=_single_product(value),
        counterparty_ref=value.counterparty_ref,
        content_hash=expected_content_hash,
        capabilities=tuple(
            (line.capability_code, line.quantity) for line in value.lines
        ),
    )


__all__ = [
    "ACTIVATED_EVENT_TYPE",
    "AgreementError",
    "ActivateCommand",
    "ActiveAgreementSnapshot",
    "ApprovalCommand",
    "ContractView",
    "CreateDraftCommand",
    "LineInput",
    "LineView",
    "ProposeCommand",
    "TerminateCommand",
    "TransitionCommand",
    "activate",
    "active_snapshot",
    "agreement_domain_error",
    "approve",
    "cancel",
    "create_draft",
    "get",
    "propose",
    "reinstate",
    "reject",
    "suspend",
    "terminate",
]
