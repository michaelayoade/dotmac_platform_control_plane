"""Revocation — append-only entries and signed, cumulative list publication.

The vendor half of WS8 revocation (`docs/design/licence-service.md`). Two
operations, both owned here:

- `revoke_licence` appends an immutable entry (idempotent per lineage) with a
  named reason, audited and emitted as `licence.revoked`.
- `publish_revocation_list` signs a FULL snapshot of the revoked set at a
  strictly increasing `list_version`, round-trips it through the PINNED
  kernel's `verify_revocation_list` before recording it, and emits
  `licence.revocation_list_published`.

**The cumulative rule (ruled 2026-08-02):** every published snapshot must be a
SUPERSET of its predecessor. Monotonic versions alone do not stop
un-revocation — a higher version that quietly drops an earlier id would restore
access while looking perfectly ordered to a receiver, which validates ordering
but cannot know what it was not told. Publication therefore fails closed on any
omission, and recovery from a mistaken revocation is re-issuance under a NEW
lineage rather than silent removal.

Transaction-authority contract: receives a `Session` and only add/flush.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from dotmac_kernel import BadRequestError, NotFoundError, write_platform_audit_event
from dotmac_kernel.licensing import (
    REVOCATION_SCHEMA,
    LicenceError,
    payload_digest,
    verify_revocation_list,
)
from dotmac_kernel.messaging import enqueue_platform_event
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.licensing.models import Licence
from vendor_cp.licensing.revocation_models import (
    LicenceRevocationEntry,
    LicenceRevocationList,
)
from vendor_cp.licensing.service import build_keyring, register_signing_key
from vendor_cp.licensing.signer import LicenceSignerProvider, build_licence_signer

_EVENT_REVOKED = "licence.revoked"
_EVENT_LIST_PUBLISHED = "licence.revocation_list_published"


class RevocationListRegressionError(RuntimeError):
    """A candidate snapshot omits a previously revoked id. Refusing to publish
    is the whole point: an omission is silent un-revocation."""


@dataclass(frozen=True, slots=True)
class RevokeLicenceCommand:
    licence_id: UUID
    reason: str
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class RevocationListView:
    id: UUID
    list_version: int
    digest: str
    key_id: str
    entry_count: int
    envelope: dict[str, object]
    revoked_licence_ids: tuple[str, ...]


def revoked_licence_ids(db: Session) -> tuple[str, ...]:
    """The full revoked set as it stands now, sorted for determinism."""
    rows = db.execute(select(LicenceRevocationEntry.licence_id)).scalars().all()
    return tuple(sorted(str(licence_id) for licence_id in rows))


def latest_list(db: Session) -> LicenceRevocationList | None:
    return db.execute(
        select(LicenceRevocationList)
        .order_by(LicenceRevocationList.list_version.desc())
        .limit(1)
    ).scalar_one_or_none()


def revoke_licence(
    db: Session, command: RevokeLicenceCommand
) -> LicenceRevocationEntry:
    """Append an immutable revocation entry for a lineage. Idempotent: revoking
    an already-revoked licence returns the existing entry rather than a second
    fact. Revocation takes effect for deployments at the next list import."""
    licence = db.get(Licence, command.licence_id)
    if licence is None:
        raise NotFoundError(f"licence {command.licence_id} not found")
    if not command.reason.strip():
        raise BadRequestError("a revocation reason is required")

    existing = db.execute(
        select(LicenceRevocationEntry).where(
            LicenceRevocationEntry.licence_id == command.licence_id
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    entry = LicenceRevocationEntry(
        licence_id=licence.id,
        reason=command.reason,
        revoked_by_admin_id=command.actor_admin_id,
    )
    db.add(entry)
    db.flush()
    write_platform_audit_event(
        db,
        actor_admin_id=command.actor_admin_id,
        action="vendor.licence.revoked",
        entity_type="licence",
        entity_id=str(licence.id),
        details={
            "licence_id": str(licence.id),
            "customer_ref": licence.customer_ref,
            "product": licence.product,
            "reason": command.reason,
        },
    )
    enqueue_platform_event(
        db,
        event_type=_EVENT_REVOKED,
        payload={
            "licence_id": str(licence.id),
            "customer_ref": licence.customer_ref,
            "product": licence.product,
            "reason": command.reason,
        },
    )
    return entry


def _published_ids(envelope: dict[str, object]) -> tuple[str, ...]:
    """Read the ids back out of a published snapshot's signed payload."""
    import base64

    payload_b64 = envelope.get("payload_b64")
    if not isinstance(payload_b64, str):
        return ()
    payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    document = json.loads(payload)
    ids = document.get("revoked_licence_ids", [])
    return tuple(sorted(str(i) for i in ids)) if isinstance(ids, list) else ()


def publish_revocation_list(
    db: Session,
    *,
    signer: LicenceSignerProvider | None = None,
    actor_admin_id: UUID | None = None,
    now: datetime | None = None,
) -> RevocationListView:
    """Sign and record a FULL snapshot of the revoked set.

    Fails closed if the candidate set is not a superset of the last published
    one, or if the pinned kernel verifier would not accept the artifact.
    """
    signer = signer or build_licence_signer()
    issued_at = now or datetime.now(UTC)
    current = revoked_licence_ids(db)

    previous = latest_list(db)
    if previous is not None:
        missing = set(_published_ids(previous.envelope)) - set(current)
        if missing:
            raise RevocationListRegressionError(
                "refusing to publish a revocation list that omits previously "
                f"revoked licence id(s): {sorted(missing)} — an omission is "
                "silent un-revocation. Recovery from a mistaken revocation is "
                "re-issuance under a new lineage."
            )
    next_version = (
        int(
            db.execute(select(func.max(LicenceRevocationList.list_version))).scalar()
            or 0
        )
        + 1
    )

    payload = json.dumps(
        {
            "schema": REVOCATION_SCHEMA,
            "list_version": next_version,
            "issued_at": issued_at.isoformat(),
            "revoked_licence_ids": list(current),
        }
    ).encode()
    envelope = _sign_envelope(payload, signer)
    digest = payload_digest(payload)

    # The signing key's public half must be distributable before we publish.
    register_signing_key(db, key_id=signer.key_id, public_key_b64=signer.public_key_b64)
    try:
        verified = verify_revocation_list(
            envelope,
            keyring=build_keyring(db),
            applied_list_version=previous.list_version if previous else None,
        )
    except LicenceError as exc:
        raise RuntimeError(
            f"published revocation list fails the pinned kernel verifier "
            f"({type(exc).__name__}: {exc}) — refusing to record it"
        ) from exc
    if verified.revoked_licence_ids != frozenset(current):
        raise RuntimeError("verifier set disagrees with the published set")

    row = LicenceRevocationList(
        list_version=next_version,
        digest=digest,
        key_id=signer.key_id,
        entry_count=len(current),
        envelope=envelope,
    )
    db.add(row)
    db.flush()
    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action="vendor.licence.revocation_list_published",
        entity_type="licence_revocation_list",
        entity_id=str(row.id),
        details={
            "list_version": next_version,
            "digest": digest,
            "key_id": signer.key_id,
            "entry_count": len(current),
        },
    )
    enqueue_platform_event(
        db,
        event_type=_EVENT_LIST_PUBLISHED,
        payload={
            "list_version": next_version,
            "digest": digest,
            "entry_count": len(current),
        },
    )
    return RevocationListView(
        id=row.id,
        list_version=next_version,
        digest=digest,
        key_id=signer.key_id,
        entry_count=len(current),
        envelope=envelope,
        revoked_licence_ids=current,
    )


def _sign_envelope(payload: bytes, signer: LicenceSignerProvider) -> dict[str, object]:
    import base64

    from dotmac_kernel.licensing import ENVELOPE_SCHEMA

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    return {
        "schema": ENVELOPE_SCHEMA,
        "payload_b64": b64(payload),
        "signatures": [
            {
                "key_id": signer.key_id,
                "algorithm": "ed25519",
                "signature_b64": b64(signer.sign(payload)),
            }
        ],
    }


__all__ = [
    "RevocationListRegressionError",
    "RevokeLicenceCommand",
    "RevocationListView",
    "revoked_licence_ids",
    "latest_list",
    "revoke_licence",
    "publish_revocation_list",
]
