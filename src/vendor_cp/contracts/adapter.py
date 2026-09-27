"""The one typed seam from Vendor into Commercial Agreements.

The published module owns agreement shape, lifecycle, history, audit and facts.
This adapter owns only assembly translations: Vendor offers become opaque line
references and frozen terms, Vendor's product catalogue satisfies the module
port, and the Approvals authority is converted into content-bound evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import TYPE_CHECKING, Final
from uuid import UUID

from dotmac_commercial_agreements import (
    AGREEMENT_ACTIVATED_V1,
    AGREEMENT_APPROVED_V1,
    AGREEMENT_REINSTATED_V1,
    DEFAULT_AGREEMENT_PAGE_SIZE,
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
    history as module_history,
)
from dotmac_commercial_agreements import (
    list_agreements as module_list_agreements,
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
from vendor_cp.approvals_authority import translate_digest
from vendor_cp.contracts.terms import (
    TermEndNotRepresentable,
    end_exclusive_from_inclusive,
)
from vendor_cp.contracts_authority import APPROVAL_SUBJECT_TYPE
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.service import get_offer_version

if TYPE_CHECKING:
    from vendor_cp.approvals.adapter import HeldPlatformApproval

ACTIVATED_EVENT_TYPE = AGREEMENT_ACTIVATED_V1

#: Explicit adapter-owned aliases for assembly readers. Code outside this
#: adapter never imports the authority package directly (ADR-0008).
AGREEMENT_PAGE_SIZE: Final[int] = DEFAULT_AGREEMENT_PAGE_SIZE
AGREEMENT_STATUS_NAMES: Final[dict[str, str]] = {
    status.value: status.name for status in AgreementStatus
}
SUPERSEDED_AGREEMENT_STATUS: Final[str] = AgreementStatus.SUPERSEDED.name


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
    line_no: int
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
    term_start: date
    term_end_exclusive: date
    status: str
    content_hash: str | None
    record_version: int
    activation_rule: str | None
    superseded_by_id: UUID | None = None
    approval_request_id: UUID | None = None
    lines: tuple[LineView, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ContractPage:
    """One bounded page from the agreement owner's complete estate reader.

    ``next_after`` is opaque to Vendor. Callers pass it back unchanged; the
    Commercial Agreements owner defines and validates the UUID keyset.
    """

    items: tuple[ContractView, ...]
    next_after: UUID | None


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
    try:
        term_end_exclusive = end_exclusive_from_inclusive(value.expiry_date)
    except TermEndNotRepresentable as exc:
        raise ConflictError(
            "the agreement expiry cannot be represented by Vendor's "
            "end-exclusive commercial contract"
        ) from exc
    return ContractView(
        id=value.id,
        reference=value.reference,
        agreement_family_id=value.agreement_family_id,
        agreement_version=value.agreement_version,
        product_code=_single_product(value),
        counterparty_ref=value.counterparty_ref,
        agreement_type=value.agreement_type,
        term_start=value.effective_date,
        term_end_exclusive=term_end_exclusive,
        status=str(value.status),
        content_hash=value.content_hash,
        record_version=value.record_version,
        activation_rule=value.activation_rule,
        superseded_by_id=value.superseded_by_id,
        approval_request_id=approval_request_id,
        lines=tuple(
            LineView(
                line_no=line.line_no,
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


def _required(db: Session, agreement_id: UUID) -> AgreementView:
    value = module_get(db, agreement_id)
    if value is None:
        raise NotFoundError(f"agreement {agreement_id} not found")
    return value


def _held_evidence(
    held: HeldPlatformApproval, *, content_digest: str
) -> ApprovalEvidence:
    """Content-bound evidence built from a barrier-held decision.

    `content_digest` is the bare form Commercial Agreements stores (its own
    frozen `content_hash`), never the approvals module's `sha256:`-prefixed
    form the barrier's own lock arguments use.
    """
    return ApprovalEvidence(
        policy_code=held.policy_code,
        policy_version=held.policy_version,
        decision_ref=str(held.request_id),
        content_digest=content_digest,
        decided_at=held.decided_at,
        approver_refs=tuple(str(approver_id) for approver_id in held.approver_ids),
    )


def _replayed_view(
    db: Session,
    current: AgreementView,
    *,
    command_id: str,
    event_type: str,
    approval_request_id: UUID | None,
) -> ContractView | None:
    """`command_id` already produced `event_type` for this agreement — return
    the current (already-committed) view without holding anything or calling
    into the module again.

    CA's own at-most-once ledger is what makes this a REPLAY rather than a
    second effect: `current` was read fresh by `_required` above, so it
    already reflects whatever `event_type` committed. Without this check, a
    retry of an already-committed command after a LATER withdrawal would be
    refused by the barrier for a transition that already succeeded — the
    barrier protects the transition from a concurrent withdrawal, not a
    retry of one that already happened. A `command_id` reused for a
    DIFFERENT `event_type` is not a replay: this returns `None` and the
    normal path runs, so CA's own ledger (not the barrier) refuses it.
    """
    for record in module_history(db, current.id):
        if record.command_id == command_id and record.event_type == event_type:
            return _view(current, approval_request_id=approval_request_id)
    return None


def _parsed_decision_ref(value: str | None) -> UUID | None:
    """`current.approval_decision_ref` as a `UUID`, or `None` if it is unset
    or not one. Used only to label a REPLAY's returned view — a genuine
    replay's decision ref was already validated the first time this command
    ran, so a parse failure here (should one somehow occur) degrades to an
    unlabelled view rather than blocking the replay."""
    if value is None:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def _not_held_conflict(
    request_id: UUID, exc: approvals.ApprovalNotHeld
) -> ConflictError:
    """`ApprovalNotHeld` is `dotmac_approvals`' own error, not a kernel
    `DomainError` — uncaught, it would surface as a 500 rather than the 409 a
    withdrawn, unapproved or mismatched approval request actually is. Naming
    the refusal's `.code` keeps the message specific (e.g. "...: withdrawn")
    without leaking anything beyond the closed `ApprovalHoldRefusal`
    vocabulary the barrier itself already refuses with.

    `ApprovalBarrierUnavailable`, the barrier's OTHER refusal, is deliberately
    never caught anywhere in this module: it means the session cannot hold a
    lock at all, a deployment defect rather than something the caller did, so
    it propagates unchanged rather than becoming a 409.
    """
    return ConflictError(f"approval request {request_id} is not held: {exc.code.value}")


def approve(db: Session, command: ApprovalCommand) -> ContractView:
    from vendor_cp.deployment.approval_barrier import held_transition

    current = _required(db, command.agreement_id)
    replayed = _replayed_view(
        db,
        current,
        command_id=command.command_id,
        event_type=AGREEMENT_APPROVED_V1,
        approval_request_id=command.approval_request_id,
    )
    if replayed is not None:
        return replayed
    if current.content_hash is None:
        raise ConflictError(f"agreement {current.id} has no frozen content hash")
    content_hash = current.content_hash

    def transition(held: HeldPlatformApproval) -> AgreementView:
        return module_approve(
            db,
            ModuleApproveCommand(
                command_id=command.command_id,
                agreement_id=command.agreement_id,
                evidence=_held_evidence(held, content_digest=content_hash),
                expected_version=command.expected_version,
                actor_admin_id=command.actor_admin_id,
            ),
        )

    try:
        value = held_transition(
            db,
            request_id=command.approval_request_id,
            subject_type=APPROVAL_SUBJECT_TYPE,
            subject_id=str(current.id),
            content_digest=translate_digest(content_hash),
            transition=transition,
        )
    except approvals.ApprovalNotHeld as exc:
        raise _not_held_conflict(command.approval_request_id, exc) from exc
    return _view(value, approval_request_id=command.approval_request_id)


def activate(db: Session, command: ActivateCommand) -> ContractView:
    from vendor_cp.deployment.approval_barrier import held_transition

    current = _required(db, command.agreement_id)
    replayed = _replayed_view(
        db,
        current,
        command_id=command.command_id,
        event_type=AGREEMENT_ACTIVATED_V1,
        approval_request_id=_parsed_decision_ref(current.approval_decision_ref),
    )
    if replayed is not None:
        return replayed
    if current.content_hash is None:
        raise ConflictError(f"agreement {current.id} has no frozen content hash")
    content_hash = current.content_hash
    if current.approval_decision_ref is None:
        raise ConflictError(
            f"agreement {current.id} has no recorded approval decision to "
            "activate from"
        )
    try:
        request_id = UUID(current.approval_decision_ref)
    except ValueError as exc:
        raise ConflictError(
            f"agreement {current.id} approval_decision_ref "
            f"{current.approval_decision_ref!r} is not a UUID"
        ) from exc
    if command.approval_request_id != request_id:
        raise ConflictError(
            f"agreement {current.id} activation names approval request "
            f"{command.approval_request_id}, but the agreement's recorded "
            f"decision is {request_id}"
        )

    def transition(held: HeldPlatformApproval) -> AgreementView:
        return module_activate(
            db,
            ModuleActivateCommand(
                command_id=command.command_id,
                agreement_id=command.agreement_id,
                approval_evidence=_held_evidence(held, content_digest=content_hash),
                activation_evidence=ActivationEvidence(
                    rule=command.activation_rule,
                    reference=command.activation_reference,
                    satisfied_at=command.activation_satisfied_at,
                ),
                expected_version=command.expected_version,
                actor_admin_id=command.actor_admin_id,
            ),
        )

    try:
        value = held_transition(
            db,
            request_id=request_id,
            subject_type=APPROVAL_SUBJECT_TYPE,
            subject_id=str(current.id),
            content_digest=translate_digest(content_hash),
            transition=transition,
        )
    except approvals.ApprovalNotHeld as exc:
        raise _not_held_conflict(request_id, exc) from exc
    return _view(value, approval_request_id=request_id)


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
    """Hold the agreement's own recorded decision through the transition.

    CA's own guard only fires once the relay has recorded standing, so a
    reinstate that raced a not-yet-relayed withdrawal would otherwise be
    unprotected. The request comes from the agreement row's
    `approval_decision_ref` — never from the caller, since `TransitionCommand`
    carries no approval reference at all.
    """
    from vendor_cp.deployment.approval_barrier import held_transition

    current = _required(db, command.agreement_id)
    replayed = _replayed_view(
        db,
        current,
        command_id=command.command_id,
        event_type=AGREEMENT_REINSTATED_V1,
        approval_request_id=None,
    )
    if replayed is not None:
        return replayed
    if current.content_hash is None:
        raise ConflictError(f"agreement {current.id} has no frozen content hash")
    if current.approval_decision_ref is None:
        raise ConflictError(
            f"agreement {current.id} has no recorded approval decision to "
            "reinstate from"
        )
    try:
        request_id = UUID(current.approval_decision_ref)
    except ValueError as exc:
        raise ConflictError(
            f"agreement {current.id} approval_decision_ref "
            f"{current.approval_decision_ref!r} is not a UUID"
        ) from exc

    def transition(_held: HeldPlatformApproval) -> AgreementView:
        return module_reinstate(db, _transition(command))

    try:
        value = held_transition(
            db,
            request_id=request_id,
            subject_type=APPROVAL_SUBJECT_TYPE,
            subject_id=str(current.id),
            content_digest=translate_digest(current.content_hash),
            transition=transition,
        )
    except approvals.ApprovalNotHeld as exc:
        raise _not_held_conflict(request_id, exc) from exc
    return _view(value)


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


def list_agreements(
    db: Session,
    *,
    after: UUID | None = None,
    limit: int = DEFAULT_AGREEMENT_PAGE_SIZE,
) -> ContractPage:
    """Translate one owner-bounded agreement page into Vendor values.

    Pagination, ordering, cursor validation and materialization stay with the
    Commercial Agreements owner. This adapter only applies Vendor's existing
    typed projection, including its one inclusive-to-exclusive term boundary.
    """
    page = module_list_agreements(db, after=after, limit=limit)
    return ContractPage(
        items=tuple(_view(value) for value in page.items),
        next_after=page.next_after,
    )


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
    "ContractPage",
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
    "list_agreements",
    "propose",
    "reinstate",
    "reject",
    "suspend",
    "terminate",
]
