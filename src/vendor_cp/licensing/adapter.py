"""The one typed seam from Vendor into the Licensing issuer.

The released module owns licence lineage, immutable issuance, public key
registry, lifecycle, installation acknowledgements and revocation.  Vendor
supplies an active allocated grant, product-held signers, and the separately
owned delivery projection.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from dotmac_kernel import BadRequestError, ConflictError, NotFoundError
from dotmac_kernel.licensing import LicenceKeyRing
from dotmac_licensing import (
    AcknowledgeCommand as ModuleAcknowledgeCommand,
)
from dotmac_licensing import (
    AcknowledgementRefusedError,
    ExpectedStateError,
    InstallationReport,
    IssuanceView,
    LicenceIssuance,
    LicenceSigner,
    LicenceView,
    LicensableGrant,
    LicensedCapability,
    LicensingError,
    Revocation,
    RevocationList,
    RevocationSupersessionError,
    SigningKey,
    SigningKeyStatus,
    TransitionRefusedError,
)
from dotmac_licensing import (
    IssueCommand as ModuleIssueCommand,
)
from dotmac_licensing import (
    RevocationListView as ModuleRevocationListView,
)
from dotmac_licensing import (
    RevokeCommand as ModuleRevokeCommand,
)
from dotmac_licensing import (
    acknowledge as module_acknowledge,
)
from dotmac_licensing import (
    build_keyring as module_build_keyring,
)
from dotmac_licensing import (
    get_issuance as module_get_issuance,
)
from dotmac_licensing import (
    issue_licence as module_issue_licence,
)
from dotmac_licensing import (
    licence_view as module_licence_view,
)
from dotmac_licensing import (
    publish_revocation_list as module_publish_revocation_list,
)
from dotmac_licensing import (
    register_signing_key as module_register_signing_key,
)
from dotmac_licensing import (
    revoke_licence as module_revoke_licence,
)
from dotmac_licensing import (
    set_key_status as module_set_key_status,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter as allocations
from vendor_cp.contracts import adapter as agreements
from vendor_cp.licensing.signing_adapter import runtime_licence_signers

DEFAULT_ISSUER = "dotmac-vendor"


def licensing_domain_error(error: LicensingError) -> BadRequestError | ConflictError:
    if isinstance(
        error,
        ExpectedStateError | TransitionRefusedError | AcknowledgementRefusedError,
    ):
        return ConflictError(str(error))
    return BadRequestError(str(error))


@dataclass(frozen=True, slots=True)
class IssueLicenceCommand:
    allocation_id: UUID
    edition: str | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    grace_days: int = 0
    deployment_id: str | None = None
    constraints: Mapping[str, object] = field(default_factory=dict)
    issuer: str = DEFAULT_ISSUER
    actor_admin_id: UUID | None = None
    command_id: str | None = None


@dataclass(frozen=True, slots=True)
class LicenceIssuanceView:
    id: UUID
    licence_id: UUID
    allocation_id: UUID
    version: int
    digest: str
    key_id: str
    status: str
    envelope: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class DeliveryIssuanceView:
    id: UUID
    licence_id: UUID
    subject_ref: str
    version: int
    digest: str
    deployment_ref: str | None
    envelope: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class RevokeLicenceCommand:
    licence_id: UUID
    reason: str
    actor_admin_id: UUID | None = None
    command_id: str | None = None


@dataclass(frozen=True, slots=True)
class RevocationEntryView:
    id: UUID
    licence_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class RevocationListView:
    id: UUID
    list_version: int
    digest: str
    key_id: str
    entry_count: int
    envelope: Mapping[str, object]
    revoked_licence_ids: tuple[str, ...]


def _issue_view(value: IssuanceView) -> LicenceIssuanceView:
    try:
        allocation_id = UUID(value.allocation_ref)
    except ValueError as exc:  # imported estates are refused by v016
        raise RuntimeError(
            f"licensing issuance {value.id} has a non-Vendor allocation ref"
        ) from exc
    return LicenceIssuanceView(
        id=value.id,
        licence_id=value.licence_id,
        allocation_id=allocation_id,
        version=value.version,
        digest=value.digest,
        key_id=value.key_id,
        status=value.status,
        envelope=dict(value.envelope),
    )


def _signers(
    signer: LicenceSigner | None,
    overlap_signers: Sequence[LicenceSigner] | None,
) -> tuple[LicenceSigner, ...]:
    if signer is None:
        installed = runtime_licence_signers()
        return (
            installed if overlap_signers is None else (installed[0], *overlap_signers)
        )
    return (signer, *(overlap_signers or ()))


def issue_licence(
    db: Session,
    command: IssueLicenceCommand,
    *,
    signer: LicenceSigner | None = None,
    overlap_signers: Sequence[LicenceSigner] | None = None,
    now: datetime | None = None,
) -> LicenceIssuanceView:
    # Return the immutable module-owned fact before consulting today's source
    # state. An idempotent replay must still work after the allocation or
    # agreement has moved on.
    existing = db.execute(
        select(LicenceIssuance).where(
            LicenceIssuance.allocation_ref == str(command.allocation_id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _issue_view(
            module_get_issuance(db, existing.id) or _missing(existing.id)
        )

    allocation = allocations.read_allocation(db, command.allocation_id)
    if allocation is None:
        raise NotFoundError(f"allocation {command.allocation_id} not found")
    if allocation.status != str(allocations.STAGED_STATUS):
        raise BadRequestError(
            f"allocation {command.allocation_id} is {allocation.status!r}, "
            "not staged — nothing to issue"
        )
    if not allocation.entries:
        raise BadRequestError(
            f"allocation {command.allocation_id} has no entries — an empty "
            "licence would grant nothing"
        )

    agreement = agreements.active_snapshot(
        db,
        allocation.contract_id,
        expected_content_hash=allocation.content_hash,
    )
    product = allocations.allocation_product(db, command.allocation_id)
    if (
        agreement.product_code != product
        or allocation.product_code != product
        or agreement.counterparty_ref != allocation.customer_ref
    ):
        raise ConflictError(
            f"allocation {allocation.id} no longer matches its active agreement"
        )

    try:
        value = module_issue_licence(
            db,
            ModuleIssueCommand(
                command_id=(
                    command.command_id
                    or f"vendor:licence:issue:{command.allocation_id}"
                ),
                grant=LicensableGrant(
                    subject_ref=allocation.customer_ref,
                    product_code=product,
                    capabilities=tuple(
                        LicensedCapability(
                            entry.capability_code,
                            {"quantity": entry.quantity},
                        )
                        for entry in allocation.entries
                    ),
                    agreement_ref=str(allocation.contract_id),
                    allocation_ref=str(allocation.id),
                    valid_from=command.not_before,
                    valid_until=command.expires_at,
                    grace_days=command.grace_days,
                    edition=command.edition,
                    deployment_ref=command.deployment_id,
                    constraints=command.constraints,
                ),
                issuer=command.issuer,
                actor_ref=(
                    str(command.actor_admin_id)
                    if command.actor_admin_id is not None
                    else None
                ),
            ),
            signers=_signers(signer, overlap_signers),
            now=now,
        )
    except LicensingError as exc:
        raise licensing_domain_error(exc) from exc
    return _issue_view(value)


def _missing(issuance_id: UUID) -> IssuanceView:
    raise RuntimeError(f"licensing issuance {issuance_id} vanished during replay")


def list_issuances(db: Session, licence_id: UUID) -> list[LicenceIssuanceView]:
    lineage = module_licence_view(db, licence_id)
    return (
        [] if lineage is None else [_issue_view(value) for value in lineage.issuances]
    )


def latest_issuance(db: Session, licence_id: UUID) -> LicenceIssuanceView | None:
    values = list_issuances(db, licence_id)
    return max(values, key=lambda value: value.version) if values else None


def _delivery_view(
    issuance: IssuanceView, lineage: LicenceView
) -> DeliveryIssuanceView:
    return DeliveryIssuanceView(
        id=issuance.id,
        licence_id=issuance.licence_id,
        subject_ref=lineage.subject_ref,
        version=issuance.version,
        digest=issuance.digest,
        deployment_ref=issuance.deployment_ref,
        envelope=dict(issuance.envelope),
    )


def issuance_for_delivery(
    db: Session, issuance_id: UUID
) -> DeliveryIssuanceView | None:
    issuance = module_get_issuance(db, issuance_id)
    if issuance is None:
        return None
    lineage = module_licence_view(db, issuance.licence_id)
    if lineage is None:
        raise RuntimeError(f"issuance {issuance.id} has no licensing lineage")
    return _delivery_view(issuance, lineage)


def find_issuance(
    db: Session, *, licence_id: UUID, version: int
) -> DeliveryIssuanceView | None:
    lineage = module_licence_view(db, licence_id)
    if lineage is None:
        return None
    issuance = next(
        (value for value in lineage.issuances if value.version == version), None
    )
    return None if issuance is None else _delivery_view(issuance, lineage)


def register_signing_key(
    db: Session,
    *,
    key_id: str,
    public_key_b64: str,
    status: SigningKeyStatus = SigningKeyStatus.ACTIVE,
) -> SigningKey:
    return module_register_signing_key(
        db,
        key_id=key_id,
        public_key_b64=public_key_b64,
        status=status,
    )


def set_key_status(db: Session, *, key_id: str, status: SigningKeyStatus) -> None:
    try:
        module_set_key_status(db, key_id=key_id, status=status)
    except LicensingError as exc:
        raise licensing_domain_error(exc) from exc


def build_keyring(db: Session) -> LicenceKeyRing:
    return module_build_keyring(db)


def list_signing_keys(db: Session) -> tuple[SigningKey, ...]:
    return tuple(db.execute(select(SigningKey).order_by(SigningKey.key_id)).scalars())


def revoke_licence(db: Session, command: RevokeLicenceCommand) -> RevocationEntryView:
    if not command.reason.strip():
        raise BadRequestError("a revocation reason is required")
    if module_licence_view(db, command.licence_id) is None:
        raise NotFoundError(f"licence {command.licence_id} not found")
    try:
        module_revoke_licence(
            db,
            ModuleRevokeCommand(
                command_id=(
                    command.command_id or f"vendor:licence:revoke:{command.licence_id}"
                ),
                licence_id=command.licence_id,
                reason=command.reason,
                actor_ref=(
                    str(command.actor_admin_id)
                    if command.actor_admin_id is not None
                    else None
                ),
            ),
        )
    except LicensingError as exc:
        raise licensing_domain_error(exc) from exc
    row = db.execute(
        select(Revocation).where(Revocation.licence_id == command.licence_id)
    ).scalar_one()
    return RevocationEntryView(row.id, command.licence_id, row.reason)


def revoked_licence_ids(db: Session) -> tuple[str, ...]:
    rows = db.execute(select(Revocation.licence_id)).scalars()
    return tuple(sorted(str(value) for value in rows))


def _published_ids(envelope: Mapping[str, object]) -> tuple[str, ...]:
    payload_b64 = envelope.get("payload_b64")
    if not isinstance(payload_b64, str):
        return ()
    try:
        payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        document = json.loads(payload)
    except (ValueError, TypeError):
        return ()
    if not isinstance(document, dict):
        return ()
    values = document.get("revoked_licence_ids", [])
    return (
        tuple(sorted(str(value) for value in values))
        if isinstance(values, list)
        else ()
    )


def _revocation_view(value: ModuleRevocationListView) -> RevocationListView:
    return RevocationListView(
        id=value.id,
        list_version=value.list_version,
        digest=value.digest,
        key_id=value.key_id,
        entry_count=value.entry_count,
        envelope=dict(value.envelope),
        revoked_licence_ids=_published_ids(value.envelope),
    )


def latest_revocation_list(db: Session) -> RevocationListView | None:
    row = db.execute(
        select(RevocationList).order_by(RevocationList.list_version.desc()).limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    return RevocationListView(
        id=row.id,
        list_version=row.list_version,
        digest=row.digest,
        key_id=row.key_id,
        entry_count=row.entry_count,
        envelope=dict(row.envelope),
        revoked_licence_ids=_published_ids(row.envelope),
    )


def latest_list(db: Session) -> RevocationListView | None:
    """Compatibility spelling for the retained Vendor route/tests."""
    return latest_revocation_list(db)


def latest_revocation_list_version(db: Session) -> int | None:
    value = db.execute(select(func.max(RevocationList.list_version))).scalar()
    return int(value) if value is not None else None


def publish_revocation_list(
    db: Session,
    *,
    signer: LicenceSigner | None = None,
    overlap_signers: Sequence[LicenceSigner] | None = None,
    actor_admin_id: UUID | None = None,
    now: datetime | None = None,
    command_id: str | None = None,
) -> RevocationListView:
    try:
        value = module_publish_revocation_list(
            db,
            command_id=command_id or f"vendor:licence:publish:{uuid4()}",
            signers=_signers(signer, overlap_signers),
            actor_ref=str(actor_admin_id) if actor_admin_id is not None else None,
            now=now,
        )
    except LicensingError as exc:
        raise licensing_domain_error(exc) from exc
    return _revocation_view(value)


def acknowledge_installation(
    db: Session,
    *,
    issuance: DeliveryIssuanceView,
    outcome: str,
    reason: str | None,
    reported_at: datetime | None,
    authenticated_deployment_ref: str,
    actor_admin_id: UUID | None,
) -> IssuanceView:
    # The module's acknowledgement fact is unique on this same triple. A
    # stable command id makes a transport retry replay the first command rather
    # than emitting another audit/outbox consequence for the same report.
    reporter_digest = hashlib.sha256(authenticated_deployment_ref.encode()).hexdigest()[
        :16
    ]
    stable_command_id = f"vendor:licence:ack:{issuance.id}:{outcome}:{reporter_digest}"
    try:
        return module_acknowledge(
            db,
            ModuleAcknowledgeCommand(
                command_id=stable_command_id,
                report=InstallationReport(
                    licence_ref=str(issuance.licence_id),
                    licence_version=issuance.version,
                    digest=issuance.digest,
                    outcome=outcome,
                    reason=reason,
                    reported_at=reported_at or datetime.now(UTC),
                    authenticated_deployment_ref=authenticated_deployment_ref,
                ),
                actor_ref=str(actor_admin_id) if actor_admin_id is not None else None,
            ),
        )
    except LicensingError as exc:
        raise licensing_domain_error(exc) from exc


# Compatibility name for the source error vocabulary; callers should treat it
# as a refusal, not depend on its concrete shared-module class.
RevocationListRegressionError = RevocationSupersessionError

__all__ = [
    "DEFAULT_ISSUER",
    "DeliveryIssuanceView",
    "IssueLicenceCommand",
    "LicenceIssuanceView",
    "RevocationEntryView",
    "RevocationListRegressionError",
    "RevocationListView",
    "RevokeLicenceCommand",
    "SigningKeyStatus",
    "acknowledge_installation",
    "build_keyring",
    "find_issuance",
    "issuance_for_delivery",
    "issue_licence",
    "latest_issuance",
    "latest_revocation_list",
    "latest_revocation_list_version",
    "latest_list",
    "licensing_domain_error",
    "list_issuances",
    "list_signing_keys",
    "publish_revocation_list",
    "register_signing_key",
    "revoked_licence_ids",
    "revoke_licence",
    "set_key_status",
]
