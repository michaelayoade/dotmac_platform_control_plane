"""The Lane 3 E10 operator command (CP-3): receipts, roots, destruction, revocation.

Pre-E11 design sections 1 and 2.5. Run by Michael, attended, on the CP host from
the pinned image over the OWNER DSN (`LANE3_E10_DATABASE_URL`), the same Touch-ID
gated session as the E6 ceremony. No runtime role holds any privilege on
`cp_lane3`, so nothing else can write what this command writes.

    python -m vendor_cp.deployment.lane3_e10 challenge --kind incarnation
    python -m vendor_cp.deployment.lane3_e10 target-setup --target-ref T ...
    python -m vendor_cp.deployment.lane3_e10 enrol-incarnation   < request.json
    python -m vendor_cp.deployment.lane3_e10 enrol-candidate-root < request.json
    python -m vendor_cp.deployment.lane3_e10 presentation-challenge --key-id K ...
    python -m vendor_cp.deployment.lane3_e10 enrol-presentation-credential ...
    python -m vendor_cp.deployment.lane3_e10 activate-presentation-credential ...
    python -m vendor_cp.deployment.lane3_e10 record-destruction  < request.json
    python -m vendor_cp.deployment.lane3_e10 revoke --receipt-ref R
    python -m vendor_cp.deployment.lane3_e10 show --receipt-ref R

It prints NAMES and DIGESTS only: ids, fingerprints, refs and sha256 values. It
never prints, reads or writes a private key, a token or a DSN, and a refusal is a
typed code, never database text.

## What it decides, and what it does not

* It is an adapter over Control (`enrol_root` / `rotate_root` / `revoke_root`,
  `bind_target_host`, `set_target_admission_policy`, the host-admission
  credential lifecycle). The trust registry is Control's; this command asks it
  and never writes `mod_deploy` itself.
* It writes ONLY `cp_lane3.e10_receipts` and `cp_lane3.e10_destructions`, in the
  same transaction as the Control call that backs them. Every instant is the
  database clock (`cp_lane3.store_now()`); the host's clock and this process's
  clock decide nothing.
* A key is accepted only if it is exactly 32 raw bytes, was generated and held
  inside OpenBao transit with every export/backup/derivation flag OFF (read back
  from transit and refused otherwise), and answers a proof of possession over a
  domain-separated message that can never parse as an envelope.
* The PoP nonce is CP-issued randomness (`challenge`) and is not persisted: a PoP
  replayed for the same key is moot because a fingerprint enrols once, globally
  (`uq_attestation_enrolments_fingerprint`), and a revoked one never again.

## One digest rule

`receipt_digest` is THE function: this command prints it at enrolment and
`lane3_record export` (CP-6) carries it, so the Gate 2 record's second channel and
the E9 verifier compare the same value. It is sha256 over the canonical bytes of
the receipt row exactly as exported (13 members, `recorded_at` as `...Z`).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from sqlalchemy import text

__all__ = [
    "ATTESTER_DOMAIN",
    "ensure_audit_registry",
    "CANDIDATE_DOMAIN",
    "CANDIDATE_POP_PREFIX",
    "E10Refused",
    "INCARNATION_POP_PREFIX",
    "RECEIPT_EXPORT_KEYS",
    "ControlRegistry",
    "RegistryEnrolment",
    "canonical",
    "candidate_pop_message",
    "enrol_candidate_root",
    "enrol_incarnation",
    "format_time",
    "HostFacts",
    "receipt_host_facts",
    "incarnation_pop_message",
    "main",
    "receipt_digest",
    "record_destruction",
    "revoke_incarnation",
    "root_document",
    "store_now",
]

ATTESTER_DOMAIN: Final = "host_attester"
CANDIDATE_DOMAIN: Final = "candidate_release_signer"
INSTALLED_PURPOSE: Final = "dotmac.foundation.installed-host.v2"
CANDIDATE_PURPOSE: Final = "dotmac.foundation.candidate-artifact.v2"
ALGORITHM: Final = "ed25519"
#: Domain-separated, and NOT JSON: a transit signature over this can never be
#: parsed as an attestation envelope (design E10.3 and 2.5).
INCARNATION_POP_PREFIX: Final = b"dotmac.lane3.incarnation-pop.v1\x00"
CANDIDATE_POP_PREFIX: Final = b"dotmac.lane3.candidate-pop.v1\x00"
NONCE_BYTES: Final = 32
AUTHORITY: Final = "lane3-e10-ceremony"
DESTRUCTION_ROUTE: Final = "transit_mount_disabled"
DSN_ENV: Final = "LANE3_E10_DATABASE_URL"
CANDIDATE_POINTER: Final = "bao://transit-a2-candidate/keys/candidate-release-v1"
CANDIDATE_ISSUER: Final = re.compile(
    r"urn:dotmac:foundation:candidate-release-ceremony:[a-z0-9][a-z0-9.-]{0,40}"
)

_HOST: Final = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_ALIAS: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
_VM_SLOT: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}/[1-9][0-9]{0,8}")
_MACHINE_ID: Final = re.compile(r"[0-9a-f]{32}")
_SSH_FINGERPRINT: Final = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_SHA256: Final = re.compile(r"sha256:[0-9a-f]{64}")
_MOUNT: Final = re.compile(
    r"transit-a2-hi-(?P<alias>[a-z0-9][a-z0-9._-]{0,62})-(?P<n>[1-9][0-9]{0,3})"
)
_TOKEN: Final = re.compile(r"[\x21-\x7e]{1,120}")
_KEY_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
_RECEIPT_REF: Final = re.compile(
    r"e10-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_SIGNATURE: Final = re.compile(r"vault:v1:([A-Za-z0-9+/]+={0,2})")
_MAX_INPUT: Final = 1024 * 1024

#: The receipt row exactly as exported (CP-6) and as digested. Closed.
RECEIPT_EXPORT_KEYS: Final = (
    "receipt_ref",
    "vm_alias",
    "host_id",
    "machine_id",
    "ssh_host_key_fingerprint",
    "vm_slot",
    "incarnation_public_key_b64url",
    "incarnation_fingerprint",
    "enrolment_uuid",
    "key_custody_pointer",
    "recorded_by",
    "recorded_at",
    "seq",
)
#: The nine-member receipt as it stands at step 3 (before the destruction stamp),
#: the shape `lane3_installed_attestation render` consumes.
STEP3_KEYS: Final = (
    "vm_alias",
    "host_id",
    "machine_id",
    "ssh_host_key_fingerprint",
    "incarnation_public_key_b64url",
    "incarnation_fingerprint",
    "enrolment_uuid",
    "receipt_ref",
    "vm_slot",
)
_FLAGS_OFF: Final = (
    "exportable",
    "allow_plaintext_backup",
    "derived",
    "deletion_allowed",
)


class E10Refused(Exception):
    """A typed refusal. The code names a thing; it never carries a value."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# ── pure helpers ─────────────────────────────────────────────────────────────


def canonical(document: Any) -> bytes:
    """Canonical bytes: sorted keys, compact, ASCII-escaped, one trailing newline.

    The export (CP-6) and the digest use this one function; Starter's
    `lane3_cp6_export._canonical` is byte for byte the same rule.
    """
    return (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def format_time(value: datetime) -> str:
    """A UTC instant as `YYYY-MM-DDTHH:MM:SS.ffffffZ` (microseconds always)."""
    if value.tzinfo is None:
        raise E10Refused("time-naive")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def receipt_digest(row: Mapping[str, Any]) -> str:
    """THE second-channel digest of one receipt row, as exported (13 members)."""
    if set(row) != set(RECEIPT_EXPORT_KEYS):
        raise E10Refused("receipt-row-malformed")
    return "sha256:" + hashlib.sha256(canonical(dict(row))).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _raw_b64url(value: object) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise E10Refused("public-key-invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise E10Refused("public-key-invalid") from None
    if len(raw) != 32 or _b64url(raw) != value:
        raise E10Refused("public-key-invalid")
    return raw


def fingerprint_of(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def incarnation_pop_message(host_id: str, nonce: bytes) -> bytes:
    return INCARNATION_POP_PREFIX + host_id.encode("ascii") + b"\x00" + nonce


def candidate_pop_message(subject: str, nonce: bytes) -> bytes:
    return CANDIDATE_POP_PREFIX + subject.encode("ascii") + b"\x00" + nonce


def parse_transit_key(document: Mapping[str, Any]) -> bytes:
    """The raw public key out of an OpenBao transit key read-back, or a refusal.

    Refuses unless the key is ed25519, has exactly one version, and every flag
    that could let the private half leave transit is OFF. Accepts the response
    with or without its `data` envelope.
    """
    data = document.get("data", document) if isinstance(document, Mapping) else None
    if not isinstance(data, Mapping):
        raise E10Refused("transit-key-malformed")
    if data.get("type") != "ed25519":
        raise E10Refused("transit-key-type")
    for flag in _FLAGS_OFF:
        if data.get(flag) is not False:
            raise E10Refused("transit-key-flag")
    keys = data.get("keys")
    if not isinstance(keys, Mapping) or set(keys) != {"1"}:
        raise E10Refused("transit-key-versions")
    entry = keys["1"]
    material = entry.get("public_key") if isinstance(entry, Mapping) else None
    if not isinstance(material, str):
        raise E10Refused("transit-key-malformed")
    try:
        raw = base64.b64decode(material, validate=True)
    except (binascii.Error, ValueError):
        raise E10Refused("public-key-invalid") from None
    if len(raw) != 32:
        raise E10Refused("public-key-invalid")
    return raw


def verify_pop(raw_public: bytes, signature: object, message: bytes) -> None:
    """Refuse unless `signature` (`vault:v1:<base64>`) verifies over `message`."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(signature, str) or not (m := _SIGNATURE.fullmatch(signature)):
        raise E10Refused("pop-malformed")
    try:
        raw_sig = base64.b64decode(m.group(1), validate=True)
        if len(raw_sig) != 64:
            raise ValueError("length")
        Ed25519PublicKey.from_public_bytes(raw_public).verify(raw_sig, message)
    except (InvalidSignature, ValueError, binascii.Error):
        raise E10Refused("pop-invalid") from None


def _nonce(value: object) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
    except (binascii.Error, ValueError):
        raise E10Refused("nonce-invalid") from None
    if len(raw) != NONCE_BYTES:
        raise E10Refused("nonce-invalid")
    return raw


# ── the registry seam ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RegistryEnrolment:
    enrolment_uuid: str
    fingerprint: str
    enrolled_at: datetime


class Registry(Protocol):
    """What this command needs of Control's attestation trust registry."""

    def enrol(
        self,
        db: Any,
        *,
        custody_domain: str,
        subject: str,
        public_key_b64url: str,
        pointer: str,
        issuer: str,
        attestation_key_id: str,
        evidence_purpose: str,
        not_after: datetime,
        enrolled_at: datetime,
    ) -> RegistryEnrolment:
        """`rotate_root` while the subject's prior root is CURRENT, else `enrol_root`
        (first enrolment, or recovery after `revoke_root`)."""
        ...

    def revoke(
        self, db: Any, *, fingerprint: str, reason: str, revoked_at: datetime
    ) -> None: ...


class ControlRegistry:
    """The real registry: Control a17's `attestation_trust_registry`."""

    def enrol(
        self,
        db: Any,
        *,
        custody_domain: str,
        subject: str,
        public_key_b64url: str,
        pointer: str,
        issuer: str,
        attestation_key_id: str,
        evidence_purpose: str,
        not_after: datetime,
        enrolled_at: datetime,
    ) -> RegistryEnrolment:
        from dotmac_deployment_control.attestation_trust_registry import (
            AttestationRefusedError,
            AttestationRootDescriptorTerms,
            AttestationRootRefusal,
            enrol_root,
            resolve_current_root,
            rotate_root,
        )

        terms = AttestationRootDescriptorTerms(
            issuer=issuer,
            attestation_key_id=attestation_key_id,
            evidence_purpose=evidence_purpose,
            not_after=not_after,
        )
        resolution = resolve_current_root(
            db, custody_domain=custody_domain, subject=subject
        )
        try:
            if resolution.root is not None:
                view = rotate_root(
                    db,
                    custody_domain=custody_domain,
                    subject=subject,
                    supersedes_fingerprint=resolution.root.public_key_fingerprint,
                    public_key_b64=public_key_b64url,
                    algorithm=ALGORITHM,
                    key_custody_pointer=pointer,
                    enrolment_authority=AUTHORITY,
                    descriptor=terms,
                    enrolled_at=enrolled_at,
                )
            elif resolution.refusal is AttestationRootRefusal.ABSENT:
                view = enrol_root(
                    db,
                    custody_domain=custody_domain,
                    subject=subject,
                    public_key_b64=public_key_b64url,
                    algorithm=ALGORITHM,
                    key_custody_pointer=pointer,
                    enrolment_authority=AUTHORITY,
                    descriptor=terms,
                    enrolled_at=enrolled_at,
                )
            else:
                # Disagreement or drift: a human decision, never a tie-break.
                raise E10Refused("registry-not-clean")
        except AttestationRefusedError as refusal:
            raise E10Refused(f"control-{refusal.code.value}") from None
        row = db.execute(
            text(
                "SELECT id::text FROM mod_deploy.attestation_enrolments "
                "WHERE public_key_fingerprint = :fp"
            ),
            {"fp": view.public_key_fingerprint},
        ).scalar_one()
        return RegistryEnrolment(
            enrolment_uuid=str(row),
            fingerprint=view.public_key_fingerprint,
            enrolled_at=view.enrolled_at,
        )

    def revoke(
        self, db: Any, *, fingerprint: str, reason: str, revoked_at: datetime
    ) -> None:
        from dotmac_deployment_control.attestation_trust_registry import (
            AttestationRefusedError,
            revoke_root,
        )

        try:
            revoke_root(
                db,
                fingerprint=fingerprint,
                revocation_authority=AUTHORITY,
                revocation_reason=reason,
                revoked_at=revoked_at,
            )
        except AttestationRefusedError as refusal:
            raise E10Refused(f"control-{refusal.code.value}") from None


# ── database reads ───────────────────────────────────────────────────────────


def store_now(db: Any) -> datetime:
    """The database clock. Everything this command stamps or judges is on it."""
    value = db.execute(text("SELECT cp_lane3.store_now()")).scalar_one()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise E10Refused("clock-unavailable")
    return value


def _receipt_row(db: Any, receipt_ref: str) -> dict[str, Any]:
    """The receipt row in its exported form (13 members), or a refusal."""
    if not _RECEIPT_REF.fullmatch(receipt_ref):
        raise E10Refused("receipt-ref-invalid")
    row = (
        db.execute(
            text(
                "SELECT receipt_ref, vm_alias, host_id, machine_id, "
                "ssh_host_key_fingerprint, vm_slot, incarnation_public_key_b64url, "
                "incarnation_fingerprint, enrolment_uuid::text AS enrolment_uuid, "
                "key_custody_pointer, recorded_by, recorded_at, seq "
                "FROM cp_lane3.e10_receipts WHERE receipt_ref = :ref"
            ),
            {"ref": receipt_ref},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise E10Refused("receipt-unknown")
    return exported_receipt(dict(row))


def exported_receipt(row: Mapping[str, Any]) -> dict[str, Any]:
    """A database row as the 13-member exported receipt (`recorded_at` as `Z`)."""
    value = {name: row[name] for name in RECEIPT_EXPORT_KEYS}
    value["recorded_at"] = format_time(value["recorded_at"])
    value["seq"] = int(value["seq"])
    return value


def step3_receipt(row: Mapping[str, Any]) -> dict[str, Any]:
    """The nine-member receipt as it stands at step 3 (design 2.2)."""
    return {name: row[name] for name in STEP3_KEYS}


def root_document(db: Any, *, enrolment_uuid: str) -> dict[str, Any]:
    """One enrolment as Foundation's trust-root shape (design 2.2 step 3, CP-3/CP-6).

    `revoked` is a boolean (true once ANY closure exists for the fingerprint:
    revoked, or superseded by a rotation), `not_before` is the enrolment instant,
    and `trust_root_version` is the enrolment UUID. Read straight from Control's
    own append-only tables; nothing here is a second registry.
    """
    row = (
        db.execute(
            text(
                "SELECT e.id::text AS enrolment_uuid, e.custody_domain, "
                "e.public_key_b64, e.public_key_fingerprint, e.algorithm, "
                "e.enrolled_at, d.issuer, d.attestation_key_id, d.evidence_purpose, "
                "d.not_after, f.closed_at "
                "FROM mod_deploy.attestation_enrolments e "
                "JOIN mod_deploy.attestation_root_descriptors d "
                "ON d.enrolment_id = e.id "
                "LEFT JOIN mod_deploy.attestation_fingerprint_closures f "
                "ON f.fingerprint = e.public_key_fingerprint "
                "WHERE e.id = CAST(:id AS uuid)"
            ),
            {"id": enrolment_uuid},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise E10Refused("root-unknown")
    raw = _raw_b64url(row["public_key_b64"])
    return {
        "public_key_fingerprint": row["public_key_fingerprint"],
        "public_key_base64": base64.b64encode(raw).decode("ascii"),
        "issuer": row["issuer"],
        "key_id": row["attestation_key_id"],
        "purpose": row["evidence_purpose"],
        "custody_domain": row["custody_domain"],
        "algorithm": row["algorithm"],
        "trust_root_version": row["enrolment_uuid"],
        "not_before": format_time(row["enrolled_at"]),
        "not_after": format_time(row["not_after"]),
        "revoked": row["closed_at"] is not None,
    }


# ── commands ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EnrolOutcome:
    receipt_ref: str
    enrolment_uuid: str
    fingerprint: str
    receipt_digest: str


def _text(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise E10Refused(code)
    return value


def _instant(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise E10Refused(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise E10Refused(code) from None
    return parsed.astimezone(UTC)


def enrol_incarnation(
    db: Any, registry: Registry, request: Mapping[str, Any]
) -> EnrolOutcome:
    """E10.5: PoP, then Control's root and the receipt row, in the caller's one
    transaction. The caller commits."""
    expected = {
        "host_id",
        "vm_alias",
        "vm_slot",
        "machine_id",
        "ssh_host_key_fingerprint",
        "mount",
        "transit_key",
        "pop_signature",
        "nonce",
        "issuer",
        "attestation_key_id",
        "not_after",
        "recorded_by",
    }
    if set(request) != expected:
        raise E10Refused("request-malformed")
    host_id = _text(request["host_id"], _HOST, "host-id-invalid")
    alias = _text(request["vm_alias"], _ALIAS, "vm-alias-invalid")
    slot = request["vm_slot"]
    if slot is not None:
        slot = _text(slot, _VM_SLOT, "vm-slot-invalid")
    machine_id = _text(request["machine_id"], _MACHINE_ID, "machine-id-invalid")
    ssh = _text(
        request["ssh_host_key_fingerprint"], _SSH_FINGERPRINT, "ssh-fingerprint-invalid"
    )
    mount = _MOUNT.fullmatch(str(request["mount"]))
    if mount is None or mount.group("alias") != alias:
        raise E10Refused("mount-invalid")
    recorded_by = _text(request["recorded_by"], _TOKEN, "recorded-by-invalid")
    issuer = _text(request["issuer"], _TOKEN, "issuer-invalid")
    key_id = _text(request["attestation_key_id"], _KEY_ID, "key-id-invalid")
    not_after = _instant(request["not_after"], "not-after-invalid")
    raw = parse_transit_key(request["transit_key"])
    verify_pop(
        raw,
        request["pop_signature"],
        incarnation_pop_message(host_id, _nonce(request["nonce"])),
    )
    public = _b64url(raw)
    pointer = f"bao://{mount.group(0)}/keys/incarnation"
    now = store_now(db)
    enrolment = registry.enrol(
        db,
        custody_domain=ATTESTER_DOMAIN,
        subject=host_id,
        public_key_b64url=public,
        pointer=pointer,
        issuer=issuer,
        attestation_key_id=key_id,
        evidence_purpose=INSTALLED_PURPOSE,
        not_after=not_after,
        enrolled_at=now,
    )
    if enrolment.fingerprint != fingerprint_of(raw):
        raise E10Refused("registry-fingerprint-disagrees")
    receipt_ref = f"e10-{uuid.uuid4()}"
    db.execute(
        text(
            "INSERT INTO cp_lane3.e10_receipts (receipt_ref, vm_alias, host_id, "
            "machine_id, ssh_host_key_fingerprint, vm_slot, "
            "incarnation_public_key_b64url, incarnation_fingerprint, "
            "enrolment_uuid, key_custody_pointer, recorded_by) VALUES (:ref, "
            ":alias, :host, :machine, :ssh, :slot, :key, :fp, "
            "CAST(:enrolment AS uuid), :pointer, :by)"
        ),
        {
            "ref": receipt_ref,
            "alias": alias,
            "host": host_id,
            "machine": machine_id,
            "ssh": ssh,
            "slot": slot,
            "key": public,
            "fp": enrolment.fingerprint,
            "enrolment": enrolment.enrolment_uuid,
            "pointer": pointer,
            "by": recorded_by,
        },
    )
    row = _receipt_row(db, receipt_ref)
    return EnrolOutcome(
        receipt_ref=receipt_ref,
        enrolment_uuid=enrolment.enrolment_uuid,
        fingerprint=enrolment.fingerprint,
        receipt_digest=receipt_digest(row),
    )


def enrol_candidate_root(
    db: Any, registry: Registry, request: Mapping[str, Any]
) -> RegistryEnrolment:
    """E8 (Q5-B): the candidate-release signer root, from a transit key with a
    truthful pointer, a PoP over the policy's candidate root subject, and the
    ceremony issuer. The caller commits."""
    expected = {
        "subject",
        "transit_key",
        "pop_signature",
        "nonce",
        "issuer",
        "attestation_key_id",
        "not_after",
    }
    if set(request) != expected:
        raise E10Refused("request-malformed")
    subject = _text(request["subject"], _TOKEN, "subject-invalid")
    issuer = _text(request["issuer"], CANDIDATE_ISSUER, "issuer-invalid")
    key_id = _text(request["attestation_key_id"], _KEY_ID, "key-id-invalid")
    not_after = _instant(request["not_after"], "not-after-invalid")
    raw = parse_transit_key(request["transit_key"])
    verify_pop(
        raw,
        request["pop_signature"],
        candidate_pop_message(subject, _nonce(request["nonce"])),
    )
    return registry.enrol(
        db,
        custody_domain=CANDIDATE_DOMAIN,
        subject=subject,
        public_key_b64url=_b64url(raw),
        pointer=CANDIDATE_POINTER,
        issuer=issuer,
        attestation_key_id=key_id,
        evidence_purpose=CANDIDATE_PURPOSE,
        not_after=not_after,
        enrolled_at=store_now(db),
    )


def record_destruction(db: Any, request: Mapping[str, Any]) -> datetime:
    """Step 8: stamp the destruction. `destroyed_at` is database time, written by
    a trigger, so no input can choose it. With an installed attestation I(D)
    (`dispatch_id` and its digest are then recorded), without one it is a
    destroy-only E11 incarnation. The caller commits. Returns `destroyed_at`.
    """
    if set(request) != {"receipt_ref", "evidence_digest", "recorded_by", "installed"}:
        raise E10Refused("request-malformed")
    receipt = _receipt_row(db, str(request["receipt_ref"]))
    evidence = _text(request["evidence_digest"], _SHA256, "evidence-digest-invalid")
    recorded_by = _text(request["recorded_by"], _TOKEN, "recorded-by-invalid")
    dispatch_id: str | None = None
    installed_digest: str | None = None
    installed = request["installed"]
    if installed is not None:
        dispatch_id, installed_digest = _verify_installed(db, receipt, installed)
    db.execute(
        text(
            "INSERT INTO cp_lane3.e10_destructions (receipt_ref, route, "
            "dispatch_id, installed_attestation_digest, evidence_digest, "
            "recorded_by) VALUES (:ref, :route, CAST(:dispatch AS uuid), :digest, "
            ":evidence, :by)"
        ),
        {
            "ref": receipt["receipt_ref"],
            "route": DESTRUCTION_ROUTE,
            "dispatch": dispatch_id,
            "digest": installed_digest,
            "evidence": evidence,
            "by": recorded_by,
        },
    )
    value = db.execute(
        text("SELECT destroyed_at FROM cp_lane3.e10_destructions WHERE receipt_ref=:r"),
        {"r": receipt["receipt_ref"]},
    ).scalar_one()
    if not isinstance(value, datetime):
        raise E10Refused("clock-unavailable")
    return value


def _verify_installed(
    db: Any, receipt: Mapping[str, Any], installed: object
) -> tuple[str, str]:
    """Verify I(D) against the enrolled key and Control's own dispatch record."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise E10Refused("cryptography-unavailable") from None
    # H1 (CP #266): the Foundation verifier is VENDORED byte for byte, pinned
    # PROVISIONAL-PENDING-E5 (`vendor_cp/vendored_foundation/PINS.json`), so step 8
    # runs from the image, which carries no `dotmac_deployment_foundation`.
    from vendor_cp.vendored_foundation.errors import SpecError
    from vendor_cp.vendored_foundation.trusted_host_source import (
        AttestationEnvelopeV2,
        attestation_envelope_digest,
    )

    try:
        envelope = AttestationEnvelopeV2.from_mapping(installed)
    except SpecError:
        raise E10Refused("installed-attestation-malformed") from None
    if (
        envelope.custody_domain != ATTESTER_DOMAIN
        or envelope.algorithm != ALGORITHM
        or envelope.public_key_fingerprint != receipt["incarnation_fingerprint"]
        or envelope.trust_root_version != receipt["enrolment_uuid"]
        or envelope.audience != receipt["host_id"]
    ):
        raise E10Refused("installed-attestation-not-this-incarnation")
    # The evidence must be the installed-host kind and still be in force (database
    # time): a different purpose, or a lapsed attestation, is not I(D).
    if envelope.purpose != INSTALLED_PURPOSE:
        raise E10Refused("installed-attestation-purpose")
    try:
        expires = datetime.fromisoformat(
            str(envelope.expires_at).replace("Z", "+00:00")
        )
    except ValueError:
        raise E10Refused("installed-attestation-malformed") from None
    if expires.tzinfo is None or expires <= store_now(db):
        raise E10Refused("installed-attestation-expired")
    try:
        dispatch_id = str(uuid.UUID(envelope.observation_id))
    except ValueError:
        raise E10Refused("installed-attestation-observation") from None
    if dispatch_id != envelope.observation_id:
        raise E10Refused("installed-attestation-observation")
    known = db.execute(
        text("SELECT 1 FROM mod_deploy.rollout_attempts WHERE id = CAST(:id AS uuid)"),
        {"id": dispatch_id},
    ).first()
    if known is None:
        raise E10Refused("dispatch-unknown")
    try:
        signature = base64.b64decode(envelope.signature, validate=True)
        if len(signature) != 64:
            raise ValueError("length")
        Ed25519PublicKey.from_public_bytes(
            _raw_b64url(receipt["incarnation_public_key_b64url"])
        ).verify(signature, envelope.signed_bytes())
    except (InvalidSignature, ValueError, binascii.Error):
        raise E10Refused("installed-attestation-signature") from None
    return dispatch_id, str(attestation_envelope_digest(envelope))


def revoke_incarnation(db: Any, registry: Registry, *, receipt_ref: str) -> str:
    """Step 15: revoke the incarnation's root (permanent) in Control. The caller
    commits. Returns the fingerprint revoked."""
    receipt = _receipt_row(db, receipt_ref)
    registry.revoke(
        db,
        fingerprint=receipt["incarnation_fingerprint"],
        reason=f"lane3 run complete: {receipt_ref}",
        revoked_at=store_now(db),
    )
    return str(receipt["incarnation_fingerprint"])


# ── Control adapters (target set-up, presentation credential) ───────────────


def _target_id(db: Any, target_ref: str) -> uuid.UUID:
    row = db.execute(
        text("SELECT id FROM mod_deploy.deployment_targets WHERE target_ref = :r"),
        {"r": target_ref},
    ).scalar_one_or_none()
    if row is None:
        raise E10Refused("target-unknown")
    return row if isinstance(row, uuid.UUID) else uuid.UUID(str(row))


def target_setup(
    db: Any,
    *,
    target_ref: str,
    host_id: str,
    candidate_root_subject: str,
    candidate_audience: str,
    installed_audience: str,
    expected_foundation_package: str,
) -> tuple[str, str]:
    """Bind the target to a host and set its admission policy, through Control.
    Refuses (never revises) if either already exists. The caller commits."""
    from dotmac_deployment_control import (
        BindTargetHostCommand,
        HostAdmissionStateRefusedError,
        SetTargetAdmissionPolicyCommand,
        bind_target_host,
        set_target_admission_policy,
    )

    _text(host_id, _HOST, "host-id-invalid")
    target = _target_id(db, target_ref)
    try:
        association = bind_target_host(
            db,
            BindTargetHostCommand(
                target_id=target, host_id=host_id, authority=AUTHORITY
            ),
        )
        policy = set_target_admission_policy(
            db,
            SetTargetAdmissionPolicyCommand(
                target_id=target,
                candidate_root_subject=candidate_root_subject,
                candidate_audience=candidate_audience,
                installed_audience=installed_audience,
                expected_foundation_package=expected_foundation_package,
                authority=AUTHORITY,
            ),
        )
    except HostAdmissionStateRefusedError as refusal:
        raise E10Refused(f"control-{refusal.code.value}") from None
    return str(association), str(policy)


def presentation_challenge(
    *, key_id: str, deployment_ref: str, challenge_id: str, now: datetime
) -> dict[str, str]:
    """A fresh Kernel possession challenge for the target's presentation key."""
    from dotmac_kernel.licensing import DeploymentPossessionChallenge

    challenge = DeploymentPossessionChallenge(
        challenge_id=challenge_id,
        key_id=key_id,
        deployment_ref=deployment_ref,
        nonce=os.urandom(NONCE_BYTES),
        expires_at=now + timedelta(minutes=10),
    )
    wire: dict[str, str] = challenge.to_wire()
    return wire


def enrol_presentation_credential(
    db: Any, *, target_ref: str, key_id: str, public_key_b64url: str, command_id: str
) -> str:
    from dotmac_deployment_control import (
        EnrolHostAdmissionCredentialCommand,
        TransitionRefusedError,
        enrol_host_admission_credential,
    )

    _raw_b64url(public_key_b64url)
    try:
        credential = enrol_host_admission_credential(
            db,
            EnrolHostAdmissionCredentialCommand(
                command_id=command_id,
                target_id=_target_id(db, target_ref),
                key_id=_text(key_id, _KEY_ID, "key-id-invalid"),
                algorithm=ALGORITHM,
                public_key_b64=public_key_b64url,
                enrollment_authority=AUTHORITY,
                actor_ref=AUTHORITY,
            ),
        )
    except TransitionRefusedError:
        raise E10Refused("control-credential-refused") from None
    return str(credential)


def activate_presentation_credential(
    db: Any,
    *,
    credential_id: str,
    challenge: Mapping[str, Any],
    response: Mapping[str, Any],
    command_id: str,
    now: datetime,
) -> None:
    """Possession is proven with the Kernel's `verify_possession`, then Control
    activates. The challenge is the vendor's own record: this command takes it
    from the file `presentation-challenge` printed."""
    from dotmac_deployment_control import (
        CredentialTransitionCommand,
        TransitionRefusedError,
        activate_credential,
    )
    from dotmac_kernel.licensing import (
        DeploymentVerificationKey,
        verify_possession,
    )

    row = (
        db.execute(
            text(
                "SELECT key_id, public_key_b64, status, purpose "
                "FROM mod_deploy.target_credentials WHERE id = CAST(:id AS uuid)"
            ),
            {"id": credential_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row["status"] != "pending":
        raise E10Refused("credential-not-pending")
    try:
        from dotmac_kernel.licensing import DeploymentPossessionChallenge

        parsed = DeploymentPossessionChallenge.from_wire(dict(challenge))
        verify_possession(
            parsed,
            dict(response),
            key=DeploymentVerificationKey(
                key_id=row["key_id"],
                public_key_b64=row["public_key_b64"],
                deployment_ref=parsed.deployment_ref,
            ),
            now=now,
        )
    except Exception:  # noqa: BLE001 - every failure is the same refusal
        raise E10Refused("possession-not-proven") from None
    try:
        activate_credential(
            db,
            CredentialTransitionCommand(
                command_id=command_id,
                credential_id=uuid.UUID(credential_id),
                actor_ref=AUTHORITY,
            ),
        )
    except TransitionRefusedError:
        raise E10Refused("control-credential-refused") from None


@dataclass(frozen=True, slots=True)
class HostFacts:
    """The three host facts an execution context carries, from ONE receipt row."""

    host_id: str
    host_incarnation: str
    host_enrolment_ref: str


def receipt_host_facts(db: Any, *, receipt_ref: str) -> HostFacts:
    """CP-7: the host facts for `materials_producer issue --e10-receipt-ref`.

    Read from the receipt row, never typed, so a typo cannot spend a single-use
    incarnation (B3 protection). Refuses unless the receipt's enrolment is
    Control's own row for this host and key AND is the host's CURRENT root. It
    does not demand a destruction: issuance (design 2.2 step 1) comes before
    the key is signed with and destroyed (steps 5-8).
    """
    receipt = _receipt_row(db, receipt_ref)
    agrees = db.execute(
        text(
            "SELECT 1 FROM mod_deploy.attestation_enrolments e "
            "JOIN mod_deploy.attestation_current_roots c "
            "ON c.custody_domain = e.custody_domain AND c.subject = e.subject "
            "AND c.current_fingerprint = e.public_key_fingerprint "
            "WHERE e.id = CAST(:id AS uuid) AND e.custody_domain = 'host_attester' "
            "AND e.subject = :host AND e.public_key_fingerprint = :fp "
            "AND e.key_custody_pointer = :pointer "
            # the view alone is not trusted: a fingerprint any closure names is closed
            "AND NOT EXISTS (SELECT 1 FROM "
            "mod_deploy.attestation_fingerprint_closures f "
            "WHERE f.fingerprint = e.public_key_fingerprint)"
        ),
        {
            "id": receipt["enrolment_uuid"],
            "host": receipt["host_id"],
            "fp": receipt["incarnation_fingerprint"],
            "pointer": receipt["key_custody_pointer"],
        },
    ).first()
    if agrees is None:
        raise E10Refused("receipt-not-current-root")
    return HostFacts(
        host_id=str(receipt["host_id"]),
        host_incarnation=str(receipt["incarnation_fingerprint"]),
        host_enrolment_ref=str(receipt["enrolment_uuid"]),
    )


def show(db: Any, *, receipt_ref: str) -> dict[str, Any]:
    """The receipt, its digest, its destruction and both roots' shapes. Read-only."""
    receipt = _receipt_row(db, receipt_ref)
    destruction = (
        db.execute(
            text(
                "SELECT destroyed_at FROM cp_lane3.e10_destructions "
                "WHERE receipt_ref = :r"
            ),
            {"r": receipt_ref},
        )
        .mappings()
        .one_or_none()
    )
    document: dict[str, Any] = {
        "receipt": receipt,
        "receipt_digest": receipt_digest(receipt),
        "receipt_step3": step3_receipt(receipt),
        "destroyed_at": None
        if destruction is None
        else format_time(destruction["destroyed_at"]),
        "installed_root": root_document(db, enrolment_uuid=receipt["enrolment_uuid"]),
    }
    return document


# ── the CLI ──────────────────────────────────────────────────────────────────


def owner_session(env: Mapping[str, str]) -> Any:
    dsn = env.get(DSN_ENV, "").strip()
    if not dsn:
        raise E10Refused("dsn-missing")
    libpq = [name for name in env if name.startswith("PG")]
    if libpq:
        raise E10Refused("libpq-environment")
    from dotmac_kernel.session_runtime import DatabaseRuntime

    runtime = DatabaseRuntime.from_urls(database_url=dsn, platform_database_url=dsn)
    return runtime.platform_session_factory()


def ensure_audit_registry() -> None:
    """Install the audit-action registry a Control credential command needs.

    Control's credential lifecycle writes an audit event, and the kernel refuses
    any write in a process that installed no registry (`create_app` installs one;
    a CLI builds no app). This delegates to the ONE process bootstrap
    (`vendor_cp.audit_bootstrap`, composed from `vendor_cp.composition`), which
    installs only when nothing is installed already: no second registry builder.
    """
    from vendor_cp.audit_bootstrap import ensure_process_audit_actions

    ensure_process_audit_actions()


def _stdin_json(stdin: Any) -> dict[str, Any]:
    data = stdin.read(_MAX_INPUT + 1)
    if not data or len(data) > _MAX_INPUT:
        raise E10Refused("input-size")
    try:
        document = json.loads(data)
    except ValueError:
        raise E10Refused("input-malformed") from None
    if not isinstance(document, dict):
        raise E10Refused("input-malformed")
    return document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="action", required=True)
    challenge = sub.add_parser("challenge")
    challenge.add_argument(
        "--kind", choices=("incarnation", "candidate"), required=True
    )
    setup = sub.add_parser("target-setup")
    for name in (
        "target-ref",
        "host-id",
        "candidate-root-subject",
        "candidate-audience",
        "installed-audience",
        "expected-foundation-package",
    ):
        setup.add_argument(f"--{name}", required=True)
    sub.add_parser("enrol-incarnation")
    sub.add_parser("enrol-candidate-root")
    pchal = sub.add_parser("presentation-challenge")
    pchal.add_argument("--key-id", required=True)
    pchal.add_argument("--deployment-ref", required=True)
    pchal.add_argument("--challenge-id", required=True)
    penrol = sub.add_parser("enrol-presentation-credential")
    penrol.add_argument("--target-ref", required=True)
    penrol.add_argument("--key-id", required=True)
    penrol.add_argument("--public-key-b64url", required=True)
    penrol.add_argument("--command-id", required=True)
    pact = sub.add_parser("activate-presentation-credential")
    pact.add_argument("--credential-id", required=True)
    pact.add_argument("--command-id", required=True)
    sub.add_parser("record-destruction")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--receipt-ref", required=True)
    revoke.add_argument("--credential-id")
    revoke.add_argument("--command-id")
    shown = sub.add_parser("show")
    shown.add_argument("--receipt-ref", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    stdin: Any = None,
    registry: Registry | None = None,
) -> int:
    """Names and digests only; typed refusals; exit 2 on any refusal."""
    args = _build_parser().parse_args(argv)
    env = os.environ if environ is None else environ
    source = sys.stdin if stdin is None else stdin
    chosen = registry or ControlRegistry()
    try:
        if args.action == "challenge":
            raw = os.urandom(NONCE_BYTES)
            print(f"kind={args.kind}")
            print(f"nonce={_b64url(raw)}")
            return 0
        db = owner_session(env)
        try:
            if args.action == "enrol-incarnation":
                outcome = enrol_incarnation(db, chosen, _stdin_json(source))
                db.commit()
                print(f"receipt_ref={outcome.receipt_ref}")
                print(f"enrolment_uuid={outcome.enrolment_uuid}")
                print(f"fingerprint={outcome.fingerprint}")
                print(f"receipt_digest={outcome.receipt_digest}")
            elif args.action == "enrol-candidate-root":
                enrolled = enrol_candidate_root(db, chosen, _stdin_json(source))
                db.commit()
                print(f"enrolment_uuid={enrolled.enrolment_uuid}")
                print(f"fingerprint={enrolled.fingerprint}")
            elif args.action == "target-setup":
                association, policy = target_setup(
                    db,
                    target_ref=args.target_ref,
                    host_id=args.host_id,
                    candidate_root_subject=args.candidate_root_subject,
                    candidate_audience=args.candidate_audience,
                    installed_audience=args.installed_audience,
                    expected_foundation_package=args.expected_foundation_package,
                )
                db.commit()
                print(f"association_id={association}")
                print(f"policy_id={policy}")
            elif args.action == "presentation-challenge":
                print(
                    json.dumps(
                        presentation_challenge(
                            key_id=args.key_id,
                            deployment_ref=args.deployment_ref,
                            challenge_id=args.challenge_id,
                            now=store_now(db),
                        ),
                        sort_keys=True,
                    )
                )
            elif args.action == "enrol-presentation-credential":
                ensure_audit_registry()
                credential = enrol_presentation_credential(
                    db,
                    target_ref=args.target_ref,
                    key_id=args.key_id,
                    public_key_b64url=args.public_key_b64url,
                    command_id=args.command_id,
                )
                db.commit()
                print(f"credential_id={credential}")
            elif args.action == "activate-presentation-credential":
                ensure_audit_registry()
                document = _stdin_json(source)
                if set(document) != {"challenge", "response"}:
                    raise E10Refused("request-malformed")
                activate_presentation_credential(
                    db,
                    credential_id=args.credential_id,
                    challenge=document["challenge"],
                    response=document["response"],
                    command_id=args.command_id,
                    now=store_now(db),
                )
                db.commit()
                print("credential_active=true")
            elif args.action == "record-destruction":
                destroyed = record_destruction(db, _stdin_json(source))
                db.commit()
                print(f"destroyed_at={format_time(destroyed)}")
            elif args.action == "revoke":
                fingerprint = revoke_incarnation(
                    db, chosen, receipt_ref=args.receipt_ref
                )
                if args.credential_id:
                    ensure_audit_registry()
                    _revoke_credential(db, args.credential_id, args.command_id)
                db.commit()
                print(f"revoked_fingerprint={fingerprint}")
            else:
                print(
                    json.dumps(show(db, receipt_ref=args.receipt_ref), sort_keys=True)
                )
        finally:
            db.close()
    except E10Refused as refusal:
        print(f"{args.action} refused: {refusal.code}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 - class name only, never the text
        # A database or owner error can carry statement text and parameters; the
        # operator gets the class, and the cause stays on the host.
        print(f"{args.action} failed: {type(error).__name__}", file=sys.stderr)
        return 4
    return 0


def _revoke_credential(db: Any, credential_id: str, command_id: str | None) -> None:
    from dotmac_deployment_control import CredentialTransitionCommand, revoke_credential

    if not command_id:
        raise E10Refused("command-id-required")
    revoke_credential(
        db,
        CredentialTransitionCommand(
            command_id=command_id,
            credential_id=uuid.UUID(credential_id),
            reason="lane3 run complete",
            actor_ref=AUTHORITY,
        ),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
