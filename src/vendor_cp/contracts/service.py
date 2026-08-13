"""`ContractService` — the one owner of commercial-contract shape + lifecycle.

Platform-level, built on the kernel's platform-scoped primitives. Every state
transition is a named, guarded command that commits THREE things in ONE
transaction (never audit-only): the state change, a `write_platform_audit_event`
record, and an `enqueue_platform_event` outbox event (kernel 0.1.0a6). A decision
and its emitted consequence can never diverge; the platform relay delivers the
event and `AllocationService` consumes `contract.activated` via
`process_once_platform`.

ContractService only changes contract state and enqueues events — it never
synchronously mutates allocation / entitlement / deployment state, and it NEVER
writes a product data plane's WS2 grants. See `docs/design/contract-service.md`.

Transaction-authority contract: receives a `Session` and only add/flush; the route
owns commit. Typed commands/outcomes throughout (no bare dicts, no float money).

Scope of this slice: the forward + operational lifecycle
(draft → submit → approve/reject → activate → suspend/reinstate/terminate/expire,
plus cancel). Amendment/supersession (a new immutable version → predecessor
`superseded`) is a separable follow-up; `superseded_by_id` is reserved for it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from uuid import UUID

from dotmac_kernel import (
    ConflictError,
    NotFoundError,
    write_platform_audit_event,
)
from dotmac_kernel.messaging import enqueue_platform_event, process_once_platform
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.approvals import service as approvals
from vendor_cp.contracts.models import Contract, ContractLine, ContractStatus
from vendor_cp.offers.catalog import ProductCapabilityCatalogueReader
from vendor_cp.offers.models import OfferVersion

_CMD_CREATE = "vendor.contract.create_draft"
_CMD_SUBMIT = "vendor.contract.submit"
_CMD_APPROVE = "vendor.contract.approve"
_CMD_REJECT = "vendor.contract.reject"
_CMD_ACTIVATE = "vendor.contract.activate"
_CMD_SUSPEND = "vendor.contract.suspend"
_CMD_REINSTATE = "vendor.contract.reinstate"
_CMD_TERMINATE = "vendor.contract.terminate"
_CMD_EXPIRE = "vendor.contract.expire"
_CMD_CANCEL = "vendor.contract.cancel"

_SUBJECT = "contract"  # approval subject_type


# ── typed inputs ─────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class LineInput:
    """A requested contract line: pins an offer by `(offer_code, version)` and
    names the capability it entitles (validated at submit)."""

    offer_code: str
    offer_version: int
    capability_code: str
    quantity: int = 1


@dataclass(frozen=True, slots=True)
class CreateDraftCommand:
    command_id: str
    product_code: str
    customer_ref: str
    legal_entity: str
    currency_code: str
    term_start: date
    term_end: date
    lines: tuple[LineInput, ...]
    activation_rule: str = "manual_confirmation"
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class SubmitCommand:
    command_id: str
    contract_id: UUID
    approval_policy_code: str
    approval_policy_version: int
    submitter_id: UUID
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class TransitionCommand:
    """A simple lifecycle transition carrying its idempotency key + audit actor,
    an optional reason, and (where the guard needs it) evidence."""

    command_id: str
    contract_id: UUID
    reason: str | None = None
    actor_admin_id: UUID | None = None
    # activate: the satisfied activation rule's evidence (rule-driven, not "a form
    # was submitted"); terminate: the acknowledged impact preview + effective date.
    activation_evidence: str | None = None
    effective_date: date | None = None
    impact_acknowledged: bool = False


@dataclass(frozen=True, slots=True)
class ContractView:
    id: UUID
    product_code: str
    customer_ref: str
    status: str
    content_hash: str | None
    activation_rule: str
    lines: tuple[LineView, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class LineView:
    offer_code: str
    offer_version: int
    capability_code: str
    quantity: int
    unit_amount: str | None
    unit_currency_code: str | None


# ── read helpers ─────────────────────────────────────────────────────────────
def _load(session: Session, contract_id: UUID) -> Contract:
    row = session.get(Contract, contract_id)
    if row is None:
        raise NotFoundError(f"contract {contract_id} not found")
    _require_product(row)
    return row


def _view(row: Contract) -> ContractView:
    product_code = _require_product(row)
    return ContractView(
        id=row.id,
        product_code=product_code,
        customer_ref=row.customer_ref,
        status=row.status,
        content_hash=row.content_hash,
        activation_rule=row.activation_rule,
        lines=tuple(
            LineView(
                offer_code=ln.offer_code,
                offer_version=ln.offer_version,
                capability_code=ln.capability_code,
                quantity=ln.quantity,
                unit_amount=ln.unit_amount,
                unit_currency_code=ln.unit_currency_code,
            )
            for ln in row.lines
        ),
    )


def _content_hash(row: Contract) -> str:
    """Canonical digest of the frozen priced snapshot — approvals bind to it, so
    any change to terms/lines/prices invalidates prior approvals."""
    snapshot = {
        "product_code": _require_product(row),
        "customer_ref": row.customer_ref,
        "legal_entity": row.legal_entity,
        "currency_code": row.currency_code,
        "term_start": row.term_start.isoformat(),
        "term_end": row.term_end.isoformat(),
        "lines": sorted(
            (
                {
                    "offer_code": ln.offer_code,
                    "offer_version": ln.offer_version,
                    "capability_code": ln.capability_code,
                    "quantity": ln.quantity,
                    "unit_amount": ln.unit_amount,
                    "unit_currency_code": ln.unit_currency_code,
                }
                for ln in row.lines
            ),
            key=lambda d: (d["offer_code"], d["offer_version"], d["capability_code"]),
        ),
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _emit(
    session: Session,
    row: Contract,
    *,
    event_type: str,
    action: str,
    actor_admin_id: UUID | None,
    extra: Mapping[str, object] | None = None,
) -> None:
    """The atomic consequence of a transition: a platform audit record AND a
    platform outbox event, both in the caller's transaction."""
    details: dict[str, object] = {
        "product_code": _require_product(row),
        "customer_ref": row.customer_ref,
        "status": row.status,
        "content_hash": row.content_hash,
    }
    if extra:
        details.update(extra)
    write_platform_audit_event(
        session,
        actor_admin_id=actor_admin_id,
        action=action,
        entity_type=_SUBJECT,
        entity_id=str(row.id),
        details=details,
    )
    enqueue_platform_event(
        session,
        event_type=event_type,
        payload={"contract_id": str(row.id), **details},
        correlation_id=str(row.id),
    )


def _require_status(row: Contract, allowed: set[str]) -> None:
    if row.status not in allowed:
        raise ConflictError(
            f"contract {row.id} is {row.status!r}; "
            f"this transition requires one of {sorted(allowed)}"
        )


def _require_product(row: Contract) -> str:
    product_code = row.product_code
    if not product_code or product_code != product_code.strip():
        raise ConflictError(
            f"contract {row.id} has no product identity; backfill it from "
            "evidence before moving its lifecycle"
        )
    return product_code


# ── commands ─────────────────────────────────────────────────────────────────
def create_draft(db: Session, command: CreateDraftCommand) -> ContractView:
    """Create a `draft` contract with its (unpriced) lines. Pricing is frozen at
    submit. Each line must pin an existing offer version."""
    if not command.lines:
        raise ConflictError("a contract needs at least one line")
    if not command.product_code or command.product_code != command.product_code.strip():
        raise ConflictError("a contract needs a valid product identity")

    def handler(session: Session) -> Mapping[str, object]:
        row = Contract(
            product_code=command.product_code,
            customer_ref=command.customer_ref,
            legal_entity=command.legal_entity,
            currency_code=command.currency_code,
            term_start=command.term_start,
            term_end=command.term_end,
            activation_rule=command.activation_rule,
            status=ContractStatus.DRAFT.value,
        )
        session.add(row)
        session.flush()
        for li in command.lines:
            ov = _resolve_offer(
                session, command.product_code, li.offer_code, li.offer_version
            )
            session.add(
                ContractLine(
                    contract_id=row.id,
                    offer_version_id=ov.id,
                    offer_code=ov.offer_code,
                    offer_version=ov.version,
                    capability_code=li.capability_code,
                    quantity=li.quantity,
                )
            )
        session.flush()
        _emit(
            session,
            row,
            event_type="contract.drafted",
            action="vendor.contract.drafted",
            actor_admin_id=command.actor_admin_id,
        )
        return {"id": str(row.id)}

    outcome = process_once_platform(
        db, command_id=command.command_id, command_type=_CMD_CREATE, handler=handler
    )
    return _view(_load(db, UUID(str(outcome.result["id"]))))


def submit(
    db: Session,
    command: SubmitCommand,
    *,
    catalogues: ProductCapabilityCatalogueReader,
) -> ContractView:
    """`draft → pending_approval`. Freezes the priced snapshot (copies each pinned
    offer version's price onto its line), validates every line's capability code is
    declared (WS1) and granted by its pinned offer, records the approval policy +
    submitter, computes `content_hash`, and emits `contract.submitted`."""

    def handler(session: Session) -> Mapping[str, object]:
        row = _load(session, command.contract_id)
        _require_status(row, {ContractStatus.DRAFT.value})
        if not row.lines:
            raise ConflictError("a contract needs at least one line")
        product_code = _require_product(row)
        for ln in row.lines:
            catalogues.require_declared(
                product_code=product_code, capability_code=ln.capability_code
            )
            ov = session.get(OfferVersion, ln.offer_version_id)
            if ov is None:
                raise ConflictError(
                    f"line pins offer version {ln.offer_version_id} which no "
                    "longer exists"
                )
            if ov.product_code != product_code:
                raise ConflictError(
                    f"line pins offer {ov.id} for product {ov.product_code!r}; "
                    f"contract {row.id} belongs to {product_code!r}"
                )
            if ln.capability_code not in ov.capability_codes:
                raise ConflictError(
                    f"capability {ln.capability_code!r} is not granted by offer "
                    f"{ov.offer_code!r} v{ov.version}"
                )
            # Freeze the price snapshot (offer versions are immutable, so this
            # pins it beyond any later offer change).
            ln.unit_amount = ov.amount
            ln.unit_currency_code = ov.currency_code
        row.approval_policy_code = command.approval_policy_code
        row.approval_policy_version = command.approval_policy_version
        row.submitter_id = command.submitter_id
        row.status = ContractStatus.PENDING_APPROVAL.value
        session.flush()
        row.content_hash = _content_hash(row)
        _emit(
            session,
            row,
            event_type="contract.submitted",
            action="vendor.contract.submitted",
            actor_admin_id=command.actor_admin_id,
            extra={
                "approval_policy_code": command.approval_policy_code,
                "approval_policy_version": command.approval_policy_version,
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=_CMD_SUBMIT, handler=handler
    )
    return _view(_load(db, command.contract_id))


def approve(db: Session, command: TransitionCommand) -> ContractView:
    """`pending_approval → approved`. Commercial approval only — does NOT make the
    contract active. Guarded by `ApprovalPolicyService` satisfied at the recorded
    policy version, content-bound to `content_hash`, submitter excluded when the
    policy disallows self-approval."""

    def handler(session: Session) -> Mapping[str, object]:
        row = _load(session, command.contract_id)
        _require_status(row, {ContractStatus.PENDING_APPROVAL.value})
        decision = approvals.evaluate(
            session,
            policy_code=row.approval_policy_code or "",
            policy_version=row.approval_policy_version or 0,
            subject_type=_SUBJECT,
            subject_id=str(row.id),
            content_hash=row.content_hash or "",
            submitter_id=row.submitter_id,
        )
        if not decision.satisfied:
            raise ConflictError(
                f"approval policy not satisfied ({decision.reason}: "
                f"{decision.distinct_approvers}/{decision.quorum})"
            )
        row.status = ContractStatus.APPROVED.value
        _emit(
            session,
            row,
            event_type="contract.approved",
            action="vendor.contract.approved",
            actor_admin_id=command.actor_admin_id,
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=_CMD_APPROVE, handler=handler
    )
    return _view(_load(db, command.contract_id))


def reject(db: Session, command: TransitionCommand) -> ContractView:
    """`pending_approval → draft`. The frozen snapshot is cleared so the contract
    must be re-submitted (invalidating any approvals)."""

    def handler(session: Session) -> Mapping[str, object]:
        row = _load(session, command.contract_id)
        _require_status(row, {ContractStatus.PENDING_APPROVAL.value})
        row.status = ContractStatus.DRAFT.value
        row.content_hash = None
        row.approval_policy_code = None
        row.approval_policy_version = None
        row.last_reason = command.reason
        _emit(
            session,
            row,
            event_type="contract.rejected",
            action="vendor.contract.rejected",
            actor_admin_id=command.actor_admin_id,
            extra={"reason": command.reason},
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=_CMD_REJECT, handler=handler
    )
    return _view(_load(db, command.contract_id))


def activate(db: Session, command: TransitionCommand) -> ContractView:
    """`approved → active`. A SEPARATE, rule-driven command — the contracted
    activation rule must be satisfied (evidence required, not "a form was
    submitted"). Emits `contract.activated`; mutates NO allocation/entitlement
    state (AllocationService reacts to the event)."""

    def handler(session: Session) -> Mapping[str, object]:
        row = _load(session, command.contract_id)
        _require_status(row, {ContractStatus.APPROVED.value})
        if not (command.activation_evidence or "").strip():
            raise ConflictError(
                f"activation rule {row.activation_rule!r} requires evidence "
                "(countersignature/confirmation), not a bare request"
            )
        row.status = ContractStatus.ACTIVE.value
        row.activated_at = datetime.now(UTC)
        _emit(
            session,
            row,
            event_type="contract.activated",
            action="vendor.contract.activated",
            actor_admin_id=command.actor_admin_id,
            extra={"activation_rule": row.activation_rule},
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=_CMD_ACTIVATE, handler=handler
    )
    return _view(_load(db, command.contract_id))


def suspend(db: Session, command: TransitionCommand) -> ContractView:
    """`active → suspended`. Projects to allocation RESTRICTION only (never data
    deletion) — the projection is owned by Allocation/data-plane, not here."""
    return _simple_transition(
        db,
        command,
        _CMD_SUSPEND,
        allowed={ContractStatus.ACTIVE.value},
        to=ContractStatus.SUSPENDED,
        event_type="contract.suspended",
        action="vendor.contract.suspended",
    )


def reinstate(db: Session, command: TransitionCommand) -> ContractView:
    """`suspended → active`."""
    return _simple_transition(
        db,
        command,
        _CMD_REINSTATE,
        allowed={ContractStatus.SUSPENDED.value},
        to=ContractStatus.ACTIVE,
        event_type="contract.reinstated",
        action="vendor.contract.reinstated",
    )


def terminate(db: Session, command: TransitionCommand) -> ContractView:
    """`active → terminated`. Requires an acknowledged impact preview + effective
    date; projects to allocation restriction, never data deletion."""

    def handler(session: Session) -> Mapping[str, object]:
        row = _load(session, command.contract_id)
        _require_status(row, {ContractStatus.ACTIVE.value})
        if not command.impact_acknowledged or command.effective_date is None:
            raise ConflictError(
                "termination requires an acknowledged impact preview + effective date"
            )
        row.status = ContractStatus.TERMINATED.value
        row.last_reason = command.reason
        _emit(
            session,
            row,
            event_type="contract.terminated",
            action="vendor.contract.terminated",
            actor_admin_id=command.actor_admin_id,
            extra={
                "reason": command.reason,
                "effective_date": command.effective_date.isoformat(),
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=_CMD_TERMINATE, handler=handler
    )
    return _view(_load(db, command.contract_id))


def expire(db: Session, command: TransitionCommand, *, as_of: date) -> ContractView:
    """`active → expired` (clock-driven). Guarded on the term end having passed."""

    def handler(session: Session) -> Mapping[str, object]:
        row = _load(session, command.contract_id)
        _require_status(row, {ContractStatus.ACTIVE.value})
        if as_of <= row.term_end:
            raise ConflictError(
                f"contract term ends {row.term_end}; not expired as of {as_of}"
            )
        row.status = ContractStatus.EXPIRED.value
        _emit(
            session,
            row,
            event_type="contract.expired",
            action="vendor.contract.expired",
            actor_admin_id=command.actor_admin_id,
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=_CMD_EXPIRE, handler=handler
    )
    return _view(_load(db, command.contract_id))


def cancel(db: Session, command: TransitionCommand) -> ContractView:
    """`draft | pending_approval → cancelled` (no downstream allocation exists)."""
    return _simple_transition(
        db,
        command,
        _CMD_CANCEL,
        allowed={ContractStatus.DRAFT.value, ContractStatus.PENDING_APPROVAL.value},
        to=ContractStatus.CANCELLED,
        event_type="contract.cancelled",
        action="vendor.contract.cancelled",
        with_reason=True,
    )


def get(db: Session, contract_id: UUID) -> ContractView | None:
    row = db.get(Contract, contract_id)
    return _view(row) if row is not None else None


# ── internals ────────────────────────────────────────────────────────────────
def _resolve_offer(
    session: Session, product_code: str, offer_code: str, version: int
) -> OfferVersion:
    ov = session.execute(
        select(OfferVersion).where(
            OfferVersion.product_code == product_code,
            OfferVersion.offer_code == offer_code,
            OfferVersion.version == version,
        )
    ).scalar_one_or_none()
    if ov is None:
        raise NotFoundError(
            f"offer version {product_code!r}/{offer_code!r} v{version} not found"
        )
    return ov


def _simple_transition(
    db: Session,
    command: TransitionCommand,
    command_type: str,
    *,
    allowed: set[str],
    to: ContractStatus,
    event_type: str,
    action: str,
    with_reason: bool = False,
) -> ContractView:
    def handler(session: Session) -> Mapping[str, object]:
        row = _load(session, command.contract_id)
        _require_status(row, allowed)
        row.status = to.value
        if with_reason:
            row.last_reason = command.reason
        _emit(
            session,
            row,
            event_type=event_type,
            action=action,
            actor_admin_id=command.actor_admin_id,
            extra={"reason": command.reason} if with_reason else None,
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=command_type, handler=handler
    )
    return _view(_load(db, command.contract_id))


__all__ = [
    "LineInput",
    "CreateDraftCommand",
    "SubmitCommand",
    "TransitionCommand",
    "ContractView",
    "LineView",
    "create_draft",
    "submit",
    "approve",
    "reject",
    "activate",
    "suspend",
    "reinstate",
    "terminate",
    "expire",
    "cancel",
    "get",
]
