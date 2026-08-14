"""`LicenceIssuanceService` — turns a staged allocation into a signed document.

The vendor half of WS8 (`docs/design/licence-service.md`). It owns the signed
document and nothing else:

- **Reads** an immutable staged `Allocation` (the one derivation owner is
  `AllocationService`); issuance never re-derives entitlement from contract
  lines.
- **Assigns lineage + version**: one `Licence` per `(customer_ref, product)`;
  `licence_version` is strictly monotonic within it (`max + 1`), which is
  exactly what the receiver's replay/rollback guard keys on.
- **Signs** the exact payload bytes through the `LicenceSignerProvider` seam and
  **freezes** them: payload digest, `key_id`, and envelope are stored immutably.
  A change is a NEW version, never an edit.
- **Proves compatibility**: every envelope is round-tripped through the PINNED
  kernel's `verify_licence` before the issuance is recorded. If the kernel would
  not accept it, we do not issue it — the vendor never re-implements or drifts
  from the verifier.

It does NOT deliver, does not track acknowledgements (the projection slice), and
NEVER writes a product data plane's `tenant_entitlement_grants` (ruling C4).

Transaction-authority contract: receives a `Session` and only add/flush. State
change + platform audit + platform outbox event commit in ONE transaction
(never audit-only), the same discipline as `ContractService`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from dotmac_kernel import BadRequestError, NotFoundError, write_platform_audit_event
from dotmac_kernel.licensing import (
    ENVELOPE_SCHEMA,
    LICENCE_SCHEMA,
    KeyStatus,
    LicenceError,
    LicenceKey,
    LicenceKeyRing,
    payload_digest,
    verify_licence,
)
from dotmac_kernel.messaging import enqueue_platform_event
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations.models import Allocation, AllocationStatus
from vendor_cp.licensing.models import (
    IssuanceStatus,
    Licence,
    LicenceIssuance,
    LicenceSigningKey,
    SigningKeyStatus,
)

# Imported at module level (not lazily inside `_is_revoked`) so the table is
# always registered on `Base.metadata` wherever this service is imported.
# Deferring it made a test file pass in a full run — where some other module
# happened to import it first — and fail when run alone. Models are safe to
# import here: only `revocation.py` (the service) would create a cycle.
from vendor_cp.licensing.revocation_models import LicenceRevocationEntry
from vendor_cp.licensing.signer import (
    LicenceSignerProvider,
    runtime_licence_signers,
)

DEFAULT_ISSUER = "dotmac-vendor"

_EVENT_ISSUED = "licence.issued"


@dataclass(frozen=True, slots=True)
class IssueLicenceCommand:
    """Issue the next licence version for a staged allocation.

    `deployment_id` binds the document to one deployment when the contract says
    so (the receiver mirrors it with `require_binding`); omitted means a
    deliberately portable licence. `expires_at`/`not_before` come from the
    contract term, `grace_days` from the versioned commercial policy — never an
    evaluator guess. `constraints` carries contracted operational semantics
    (e.g. HA/node counts) that no one in this path interprets.
    """

    allocation_id: UUID
    product: str
    edition: str | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    grace_days: int = 0
    deployment_id: str | None = None
    constraints: Mapping[str, object] = field(default_factory=dict)
    issuer: str = DEFAULT_ISSUER
    actor_admin_id: UUID | None = None


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


def _view(row: LicenceIssuance) -> LicenceIssuanceView:
    return LicenceIssuanceView(
        id=row.id,
        licence_id=row.licence_id,
        allocation_id=row.allocation_id,
        version=row.version,
        digest=row.digest,
        key_id=row.key_id,
        status=row.status,
        envelope=dict(row.envelope),
    )


# ── Key registry ────────────────────────────────────────────────────────────


def register_signing_key(
    db: Session,
    *,
    key_id: str,
    public_key_b64: str,
    status: SigningKeyStatus = SigningKeyStatus.ACTIVE,
) -> LicenceSigningKey:
    """Record a signing key's PUBLIC material (idempotent on `key_id`). This
    registry is what the distributed verification keyring is built from; it
    never holds private material."""
    existing = db.execute(
        select(LicenceSigningKey).where(LicenceSigningKey.key_id == key_id)
    ).scalar_one_or_none()
    if existing is not None:
        existing.public_key_b64 = public_key_b64
        existing.status = status.value
        db.flush()
        return existing
    row = LicenceSigningKey(
        key_id=key_id, public_key_b64=public_key_b64, status=status.value
    )
    db.add(row)
    db.flush()
    return row


def set_key_status(db: Session, *, key_id: str, status: SigningKeyStatus) -> None:
    """Rotate a key's state: `active` → `retired` (installed base keeps
    verifying) or → `revoked` (compromise; nothing it signed verifies, and
    affected lineages must be re-issued at a higher version)."""
    row = db.execute(
        select(LicenceSigningKey).where(LicenceSigningKey.key_id == key_id)
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"signing key {key_id!r} is not registered")
    row.status = status.value
    db.flush()


def build_keyring(db: Session) -> LicenceKeyRing:
    """The verification keyring as distributed to deployments — every
    registered key with its rotation status, public material only."""
    rows = db.execute(select(LicenceSigningKey)).scalars().all()
    return LicenceKeyRing(
        [
            LicenceKey(
                key_id=r.key_id,
                public_key_b64=r.public_key_b64,
                status=KeyStatus(r.status),
            )
            for r in rows
        ]
    )


# ── Issuance ────────────────────────────────────────────────────────────────


def _lineage(db: Session, *, customer_ref: str, product: str) -> Licence:
    """Resolve the lineage to issue into for a customer+product.

    Reuses the current generation unless it has been REVOKED — revocation is by
    `licence_id` and permanent, so continuing to issue into a revoked lineage
    would produce documents every deployment must refuse. In that case a new
    generation is minted: that is the contracted recovery path, and it is why
    `generation` exists at all.
    """
    current = db.execute(
        select(Licence)
        .where(Licence.customer_ref == customer_ref, Licence.product == product)
        .order_by(Licence.generation.desc())
        .limit(1)
    ).scalar_one_or_none()
    if current is not None and not _is_revoked(db, current.id):
        return current
    row = Licence(
        customer_ref=customer_ref,
        product=product,
        generation=(current.generation + 1) if current is not None else 1,
    )
    db.add(row)
    db.flush()
    return row


def _is_revoked(db: Session, licence_id: UUID) -> bool:
    """Reads the revocation FACT from its model, never the revocation service —
    the dependency runs one way (revocation → issuance)."""
    return (
        db.execute(
            select(LicenceRevocationEntry.id).where(
                LicenceRevocationEntry.licence_id == licence_id
            )
        ).scalar_one_or_none()
        is not None
    )


def _next_version(db: Session, licence_id: UUID) -> int:
    highest = db.execute(
        select(func.max(LicenceIssuance.version)).where(
            LicenceIssuance.licence_id == licence_id
        )
    ).scalar()
    return int(highest or 0) + 1


def _build_payload(
    command: IssueLicenceCommand,
    *,
    licence: Licence,
    version: int,
    allocation: Allocation,
    issued_at: datetime,
) -> bytes:
    """The `dotmac-licence/1` payload, serialized ONCE — these exact bytes are
    what gets signed, digested, and shipped."""
    subject: dict[str, object] = {"customer": licence.customer_ref}
    # Bound only when the contract says so — an absent key means a deliberately
    # portable licence, which is a different contractual choice from a null.
    if command.deployment_id is not None:
        subject["deployment_id"] = command.deployment_id
    document: dict[str, object] = {
        "schema": LICENCE_SCHEMA,
        "licence_id": str(licence.id),
        "licence_version": version,
        "issuer": command.issuer,
        "product": command.product,
        "edition": command.edition,
        "subject": subject,
        "capabilities": [
            {"code": e.capability_code, "limits": {"quantity": e.quantity}}
            for e in allocation.entries
        ],
        "issued_at": issued_at.isoformat(),
        "not_before": command.not_before.isoformat() if command.not_before else None,
        "expires_at": command.expires_at.isoformat() if command.expires_at else None,
        "grace_days": command.grace_days,
        "constraints": dict(command.constraints),
    }
    return json.dumps(document).encode()


def _envelope(
    payload: bytes, signers: Sequence[LicenceSignerProvider]
) -> dict[str, object]:
    """One envelope, one signature per signer. More than one signer is a
    ROTATION OVERLAP: deployments holding either keyring can verify the same
    document, which is what makes rotation non-breaking."""
    return {
        "schema": ENVELOPE_SCHEMA,
        "payload_b64": _b64url(payload),
        "signatures": [
            {
                "key_id": s.key_id,
                "algorithm": "ed25519",
                "signature_b64": _b64url(s.sign(payload)),
            }
            for s in signers
        ],
    }


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def issue_licence(
    db: Session,
    command: IssueLicenceCommand,
    *,
    signer: LicenceSignerProvider | None = None,
    overlap_signers: Sequence[LicenceSignerProvider] | None = None,
    now: datetime | None = None,
) -> LicenceIssuanceView:
    """Issue (sign + freeze) the next licence version for a staged allocation.

    Idempotent per allocation: an allocation already issued returns its existing
    immutable issuance rather than minting a second version. Fails closed if the
    pinned kernel verifier would not accept the envelope we just produced.
    """
    installed = runtime_licence_signers()
    signer = signer or installed[0]
    if overlap_signers is None:
        overlap_signers = installed[1:]
    signers = (signer, *overlap_signers)
    issued_at = now or datetime.now(UTC)

    existing = db.execute(
        select(LicenceIssuance).where(
            LicenceIssuance.allocation_id == command.allocation_id
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _view(existing)

    allocation = db.get(Allocation, command.allocation_id)
    if allocation is None:
        raise NotFoundError(f"allocation {command.allocation_id} not found")
    if allocation.status != AllocationStatus.STAGED.value:
        raise BadRequestError(
            f"allocation {command.allocation_id} is {allocation.status!r}, "
            "not staged — nothing to issue"
        )
    if not allocation.entries:
        raise BadRequestError(
            f"allocation {command.allocation_id} has no entries — an empty "
            "licence would grant nothing"
        )

    # Every signing key's PUBLIC half must be in the registry before we sign
    # with it, so the keyring we distribute can verify what we issue — during a
    # rotation overlap that means BOTH keys.
    for s in signers:
        register_signing_key(db, key_id=s.key_id, public_key_b64=s.public_key_b64)

    licence = _lineage(
        db, customer_ref=allocation.customer_ref, product=command.product
    )
    version = _next_version(db, licence.id)
    payload = _build_payload(
        command,
        licence=licence,
        version=version,
        allocation=allocation,
        issued_at=issued_at,
    )
    envelope = _envelope(payload, signers)
    digest = payload_digest(payload)

    # Round-trip through the PINNED kernel verifier before recording anything.
    # If the kernel would reject it, this is an issuance bug — fail loudly here
    # rather than shipping a document no deployment can apply.
    try:
        verified = verify_licence(
            envelope,
            keyring=build_keyring(db),
            now=issued_at,
            expected_deployment_id=command.deployment_id,
        )
    except LicenceError as exc:
        raise RuntimeError(
            f"issued envelope fails the pinned kernel verifier ({type(exc).__name__}: "
            f"{exc}) — refusing to record an unusable licence"
        ) from exc
    if verified.digest != digest:
        raise RuntimeError("verifier digest disagrees with the issued payload digest")

    issuance = LicenceIssuance(
        licence_id=licence.id,
        allocation_id=allocation.id,
        version=version,
        digest=digest,
        key_id=signer.key_id,
        envelope=envelope,
        status=IssuanceStatus.ISSUED.value,
    )
    db.add(issuance)
    db.flush()

    write_platform_audit_event(
        db,
        actor_admin_id=command.actor_admin_id,
        action="vendor.licence.issued",
        entity_type="licence_issuance",
        entity_id=str(issuance.id),
        details={
            "licence_id": str(licence.id),
            "licence_version": version,
            "digest": digest,
            "key_id": signer.key_id,
            "allocation_id": str(allocation.id),
            "product": command.product,
            "deployment_id": command.deployment_id,
            "capabilities": [e.capability_code for e in allocation.entries],
        },
    )
    enqueue_platform_event(
        db,
        event_type=_EVENT_ISSUED,
        payload={
            "licence_id": str(licence.id),
            "licence_version": version,
            "digest": digest,
            "issuance_id": str(issuance.id),
            "customer_ref": licence.customer_ref,
            "product": command.product,
        },
    )
    return _view(issuance)


def list_issuances(db: Session, licence_id: UUID) -> list[LicenceIssuanceView]:
    rows = db.execute(
        select(LicenceIssuance)
        .where(LicenceIssuance.licence_id == licence_id)
        .order_by(LicenceIssuance.version)
    ).scalars()
    return [_view(r) for r in rows]


def latest_issuance(db: Session, licence_id: UUID) -> LicenceIssuanceView | None:
    row = db.execute(
        select(LicenceIssuance)
        .where(LicenceIssuance.licence_id == licence_id)
        .order_by(LicenceIssuance.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    return _view(row) if row is not None else None


__all__ = [
    "DEFAULT_ISSUER",
    "IssueLicenceCommand",
    "LicenceIssuanceView",
    "register_signing_key",
    "set_key_status",
    "build_keyring",
    "issue_licence",
    "list_issuances",
    "latest_issuance",
]
