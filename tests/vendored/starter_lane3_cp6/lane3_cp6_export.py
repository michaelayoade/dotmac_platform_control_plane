"""The CP-6 `lane3_record export` document, parsed fail-closed. PROVISIONAL SCHEMA.

CP-6 (PRE-E11-DESIGN section 5) is the read-only export the ceremony owner
session runs on the CP side: the Control half (dispatch envelope, ledger row,
attempt) and the `cp_lane3` half (E10 receipt, destruction, lease, release,
candidate and installed root standings), as canonical JSON.

Only the SHAPE of that document is not yet pinned. Everything the E9 offline
orchestrator needs to know about that shape lives in THIS file and nowhere
else, so the final CP-6 schema pin (before the S8a merge) edits this one
module. Every place a guess was needed is marked `# CP-6 PIN:`. The
orchestrator consumes only the typed `Cp6Export` this module returns.

Nothing here trusts the export: it is data from the CP host, joined against
independent inputs by `lane3_offline_orchestrator`. This module verifies no
signature and judges no time.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from lane3_host_source_admission import Ed25519AttestationVerifier

__all__ = [
    "EXPORT_SCHEMA",
    "MAX_EXPORT_BYTES",
    "PRESENTATION_PURPOSE",
    "PresentationCredentialBlock",
    "Cp6Export",
    "Cp6ExportRefused",
    "DestructionBlock",
    "DispatchBlock",
    "LeaseBlock",
    "LedgerBlock",
    "ReceiptBlock",
    "ReleaseBlock",
    "RootBlock",
    "CONSUME_SCOPE",
    "CONSUME_STATUS",
    "DISPATCH_PURPOSE",
    "DispatchStatement",
    "PinnedIdentity",
    "dispatch_envelope_digest",
    "ledger_fingerprint",
    "ledger_key_for",
    "verify_dispatch",
    "parse_cp6_export",
    "raw_public_key",
    "receipt_digest",
]

# CP-6 PIN: the schema identifier.
#
# v2 (CP6-CREDENTIAL-BLOCK-SPEC section 2): the closed `control.presentation_credential`
# block. Starter is v2-only: a v1 document is refused on the schema string and on
# the closed `_CONTROL` key set, and a v1 parser refuses v2 the same way.
EXPORT_SCHEMA: Final = "lane3.cp6-export.v2"

# CP-6 PIN (Control a17 `HOST_ADMISSION_PRESENTATION_PURPOSE`): the purpose of the
# target credential that signs host-admission presentations.
PRESENTATION_PURPOSE: Final = "dotmac.control.host-admission-presentation.v1"
MAX_EXPORT_BYTES: Final = 262144

_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
_TIME: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z"
)
_TOKEN: Final = re.compile(r"[\x21-\x7e]{1,256}")


class Cp6ExportRefused(ValueError):
    """The export is malformed. A stable code; never any supplied text."""


def _refuse(code: str) -> None:
    raise Cp6ExportRefused(f"cp6-export-{code}")


# --- the schema: every definition the final CP-6 pin may change ---------------


# CP-6 PIN (Control a17 `dispatch_envelope.py`, `digests.py`): the dispatch
# envelope is `{statement, signature}`; the statement is signed over
# `canonical_json(statement)`; the envelope digest is `sha256:` + sha256 over
# `canonical_json({statement, signature})`; signatures and keys are unpadded
# base64url; a ledger row's fingerprint is bare hex.
DISPATCH_PURPOSE: Final = "deployment_dispatch"
CONSUME_SCOPE: Final = "deployment.consume_dispatch_challenge.v1"
CONSUME_STATUS: Final = "executed"
_STATEMENT_KEYS: Final = {
    "schema",
    "version",
    "purpose",
    "dispatch_id",
    "authorization_id",
    "authorization_plan_id",
    "authorization_control_version",
    "authorization_key_id",
    "authorization_public_key_fingerprint",
    "authorization_envelope_digest",
    "execution_sequence",
    "attempt_no",
    "rollout_ref",
    "target_id",
    "target_ref",
    "product_code",
    "environment",
    "operation",
    "release_ref",
    "authorized_images",
    "plan_digest",
    "descriptor_digest",
    "execution_plan_digest",
    "issued_at",
    "control_version",
    "key_id",
    "algorithm",
    "public_key_fingerprint",
}
_BARE_HEX: Final = re.compile(r"[0-9a-f]{64}")


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Control's `canonical_json`: sorted, compact, UTF-8, no trailing newline."""
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def ledger_key_for(dispatch_id: str) -> str:
    """The Control ledger key: the bare dispatch id (scope `CONSUME_SCOPE`)."""
    return dispatch_id


def dispatch_envelope_digest(statement: Mapping[str, Any], signature: str) -> str:
    """Control `DispatchEnvelopeDigestV1.over_bytes(envelope.canonical_bytes)`."""
    raw = canonical_json({"statement": statement, "signature": signature})
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def ledger_fingerprint(
    *,
    dispatch_envelope_digest: str,
    candidate_attestation_envelope_digest: str,
    installed_attestation_envelope_digest: str,
) -> str:
    """Control `compute_host_admission_consumption_fingerprint`: bare hex."""
    payload = {
        "schema": "dotmac.control.host-admission-consumption",
        "version": 1,
        "dispatch_envelope_digest": dispatch_envelope_digest,
        "candidate_attestation_envelope_digest": candidate_attestation_envelope_digest,
        "installed_attestation_envelope_digest": installed_attestation_envelope_digest,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _unb64url(value: Any, *, length: int | None = None) -> bytes:
    if type(value) is not str or not value or "=" in value:
        _refuse("field")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        _refuse("field")
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value or (
        length is not None and len(raw) != length
    ):
        _refuse("field")
    return raw


@dataclasses.dataclass(frozen=True, slots=True)
class PinnedIdentity:
    """A CP signing identity pinned independently of the export."""

    key_id: str
    algorithm: str
    public_key_b64url: str

    @property
    def raw(self) -> bytes:
        try:
            return raw_public_key(self.public_key_b64url)
        except Cp6ExportRefused:
            raise Cp6ExportRefused("cp6-export-pinned-identity-invalid") from None

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.raw).hexdigest()


@dataclasses.dataclass(frozen=True, slots=True)
class DispatchStatement:
    """The typed, signed dispatch statement (the fields the joins consume)."""

    dispatch_id: str
    execution_sequence: int
    attempt_no: int
    target_id: str
    target_ref: str
    execution_plan_digest: str
    descriptor_digest: str
    purpose: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str


def verify_dispatch(
    block: DispatchBlock, pinned: Sequence[PinnedIdentity]
) -> DispatchStatement:
    """Verify the dispatch envelope against pinned CP identities; type it.

    Refuses: wrong purpose, signer not pinned (key id, algorithm and the key
    fingerprint the statement itself names), a bad signature over the exact
    signed statement bytes, and an envelope digest the export mis-states.
    """
    statement = block.statement
    if statement["purpose"] != DISPATCH_PURPOSE:
        _refuse("dispatch-purpose")
    matches = [
        item
        for item in pinned
        if item.key_id == statement["key_id"]
        and item.algorithm == statement["algorithm"]
        and item.fingerprint == statement["public_key_fingerprint"]
    ]
    if not matches:
        _refuse("dispatch-signer-unpinned")
    raw_signature = _unb64url(block.signature, length=64)
    if not Ed25519AttestationVerifier().verify(
        public_key=matches[0].raw,
        algorithm=statement["algorithm"],
        message=canonical_json(statement),
        signature=base64.b64encode(raw_signature).decode("ascii"),
    ):
        _refuse("dispatch-signature-invalid")
    if block.envelope_digest != dispatch_envelope_digest(statement, block.signature):
        _refuse("dispatch-digest-mismatch")
    return DispatchStatement(
        dispatch_id=statement["dispatch_id"],
        execution_sequence=statement["execution_sequence"],
        attempt_no=statement["attempt_no"],
        target_id=statement["target_id"],
        target_ref=statement["target_ref"],
        execution_plan_digest=statement["execution_plan_digest"],
        descriptor_digest=statement["descriptor_digest"],
        purpose=statement["purpose"],
        key_id=statement["key_id"],
        algorithm=statement["algorithm"],
        public_key_fingerprint=statement["public_key_fingerprint"],
    )


def receipt_digest(document: Mapping[str, Any]) -> str:
    """The second-channel digest of the E10 receipt row (Gate 2 record).

    CP-6 PIN: THE one rule. CP's `enrol-incarnation` (which prints the digest)
    and `lane3_record export` (which carries it) must both call an equivalent
    of this function; the offline orchestrator recomputes it and refuses a
    differing exported value. Provisional: sha256 over `_canonical` of the row.
    """
    return "sha256:" + hashlib.sha256(_canonical(dict(document))).hexdigest()


def _canonical(document: Any) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


# CP-6 PIN: closed key sets of every block.
_TOP: Final = {"schema", "dispatch_id", "host_id", "control", "cp_lane3"}
_CONTROL: Final = {"dispatch", "ledger", "presentation_credential"}
_PRESENTATION: Final = {
    "target_id",
    "key_id",
    "algorithm",
    "purpose",
    "public_key_b64url",
    "public_key_fingerprint",
    "status",
    "activated_at",
    "retired_at",
    "revoked_at",
}
_CREDENTIAL_STATUSES: Final = {"pending", "active", "retired", "revoked"}
_DISPATCH: Final = {"statement", "signature", "envelope_digest"}
_LEDGER: Final = {
    "key",
    "scope",
    "status",
    "fingerprint",
    "created_at",
    "execution_sequence",
    "attempt_no",
}
_CP_LANE3: Final = {
    "e10_receipt",
    "e10_receipt_digest",
    "destruction",
    "lease",
    "release",
    "candidate_root",
    "installed_root",
}
_RECEIPT: Final = {
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
}
_DESTRUCTION: Final = {
    "receipt_ref",
    "destroyed_at",
    "route",
    "dispatch_id",
    "installed_attestation_digest",
    "evidence_digest",
    "recorded_by",
}
_LEASE: Final = {
    "lease_id",
    "host_id",
    "authorization_run",
    "e10_receipt_ref",
    "acquired_at",
    "expires_at",
}
_RELEASE: Final = {"lease_id", "released_at", "host_mutated"}
_ROOT: Final = {
    "enrolment_uuid",
    "custody_domain",
    "issuer",
    "key_id",
    "purpose",
    "algorithm",
    "public_key_b64url",
    "not_before",
    "not_after",
    "enrolled_at",
    "revoked_at",
}

# --- typed blocks -------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class DispatchBlock:
    #: The signed statement exactly as exported (unverified until `verify_dispatch`).
    statement: Mapping[str, Any]
    #: Unpadded base64url, as Control stores it.
    signature: str
    envelope_digest: str


@dataclasses.dataclass(frozen=True, slots=True)
class PresentationCredentialBlock:
    """Control's `target_credentials` row for the presentation key (public only)."""

    target_id: str
    key_id: str
    algorithm: str
    purpose: str
    public_key: bytes
    public_key_fingerprint: str
    status: str
    activated_at: datetime
    retired_at: datetime | None
    revoked_at: datetime | None


@dataclasses.dataclass(frozen=True, slots=True)
class LedgerBlock:
    key: str
    scope: str
    status: str
    #: Bare hex, as Control stores it: `ledger_fingerprint(...)`.
    fingerprint: str
    created_at: datetime
    execution_sequence: int
    attempt_no: int


@dataclasses.dataclass(frozen=True, slots=True)
class ReceiptBlock:
    #: The row exactly as exported; `receipt_digest` digests it.
    document: Mapping[str, Any]
    receipt_ref: str
    vm_alias: str
    host_id: str
    machine_id: str
    ssh_host_key_fingerprint: str
    vm_slot: str | None
    incarnation_public_key_b64url: str
    incarnation_fingerprint: str
    enrolment_uuid: str


@dataclasses.dataclass(frozen=True, slots=True)
class DestructionBlock:
    receipt_ref: str
    destroyed_at: datetime
    route: str
    dispatch_id: str | None
    installed_attestation_digest: str | None
    evidence_digest: str


@dataclasses.dataclass(frozen=True, slots=True)
class LeaseBlock:
    lease_id: str
    host_id: str
    authorization_run: str
    e10_receipt_ref: str
    acquired_at: datetime
    expires_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseBlock:
    lease_id: str
    released_at: datetime
    host_mutated: bool


@dataclasses.dataclass(frozen=True, slots=True)
class RootBlock:
    """A Control attestation-root standing. The key is the enrolled public key."""

    enrolment_uuid: str
    custody_domain: str
    issuer: str
    key_id: str
    purpose: str
    algorithm: str
    public_key: bytes
    not_before: str
    not_after: str
    enrolled_at: datetime
    revoked_at: datetime | None

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.public_key).hexdigest()

    @property
    def public_key_base64(self) -> str:
        return base64.b64encode(self.public_key).decode("ascii")


@dataclasses.dataclass(frozen=True, slots=True)
class Cp6Export:
    dispatch_id: str
    host_id: str
    dispatch: DispatchBlock
    ledger: LedgerBlock
    presentation_credential: PresentationCredentialBlock
    receipt: ReceiptBlock
    destruction: DestructionBlock
    lease: LeaseBlock
    release: ReleaseBlock | None
    #: The digest CP exported for the receipt row (checked by the orchestrator).
    e10_receipt_digest: str
    candidate_root: RootBlock
    installed_root: RootBlock
    #: sha256 of the exact export bytes, for the report.
    export_digest: str


# --- parsing ------------------------------------------------------------------


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _refuse("schema")
    return value


def _token(value: Any) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        _refuse("field")
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _refuse("field")
    return value


def _time(value: Any) -> datetime:
    """A UTC instant `...Z`, with up to microseconds (database time)."""
    if type(value) is not str or not _TIME.fullmatch(value):
        _refuse("time")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
    except ValueError:
        _refuse("time")
    raise AssertionError  # pragma: no cover


def _time_text(value: Any) -> str:
    _time(value)
    return value


def _positive(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        _refuse("field")
    return value


def _uuid(value: Any) -> str:
    """A canonical lower-case UUID, as Control mints dispatch and target ids."""
    if type(value) is not str:
        _refuse("field")
    try:
        if str(uuid.UUID(value)) != value:
            _refuse("field")
    except ValueError:
        _refuse("field")
    return value


def _statement(value: Any) -> dict[str, Any]:
    """A closed dispatch statement with the typed fields the joins consume."""
    block = _object(value, set(_STATEMENT_KEYS))
    for name in (
        "purpose",
        "target_ref",
        "key_id",
        "algorithm",
    ):
        _token(block[name])
    _uuid(block["dispatch_id"])
    _uuid(block["target_id"])
    _digest(block["execution_plan_digest"])
    _digest(block["public_key_fingerprint"])
    _positive(block["execution_sequence"])
    _positive(block["attempt_no"])
    return block


def raw_public_key(value: Any) -> bytes:
    """A canonical unpadded base64url 32-byte key, the form Control stores."""
    if type(value) is not str or not value or "=" in value:
        _refuse("key")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        _refuse("key")
    if (
        len(raw) != 32
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value
    ):
        _refuse("key")
    return raw


def _root(value: Any) -> RootBlock:
    block = _object(value, _ROOT)
    revoked = block["revoked_at"]
    return RootBlock(
        enrolment_uuid=_token(block["enrolment_uuid"]),
        custody_domain=_token(block["custody_domain"]),
        issuer=_token(block["issuer"]),
        key_id=_token(block["key_id"]),
        purpose=_token(block["purpose"]),
        algorithm=_token(block["algorithm"]),
        public_key=raw_public_key(block["public_key_b64url"]),
        not_before=_time_text(block["not_before"]),
        not_after=_time_text(block["not_after"]),
        enrolled_at=_time(block["enrolled_at"]),
        revoked_at=None if revoked is None else _time(revoked),
    )


def _presentation_credential(value: Any) -> PresentationCredentialBlock:
    block = _object(value, _PRESENTATION)
    raw = raw_public_key(block["public_key_b64url"])
    fingerprint = _digest(block["public_key_fingerprint"])
    if fingerprint != "sha256:" + hashlib.sha256(raw).hexdigest():
        _refuse("presentation-fingerprint")
    if type(block["status"]) is not str or (
        block["status"] not in _CREDENTIAL_STATUSES
    ):
        _refuse("field")
    retired, revoked = block["retired_at"], block["revoked_at"]
    return PresentationCredentialBlock(
        target_id=_uuid(block["target_id"]),
        key_id=_token(block["key_id"]),
        algorithm=_token(block["algorithm"]),
        purpose=_token(block["purpose"]),
        public_key=raw,
        public_key_fingerprint=fingerprint,
        status=block["status"],
        activated_at=_time(block["activated_at"]),
        retired_at=None if retired is None else _time(retired),
        revoked_at=None if revoked is None else _time(revoked),
    )


def _strict_json(payload: bytes) -> dict[str, Any]:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_EXPORT_BYTES:
        _refuse("size")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _refuse("duplicate-key")
            result[key] = value
        return result

    def noninteger(_value: str) -> Any:
        _refuse("number")

    try:
        document = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=pairs,
            parse_float=noninteger,
            parse_constant=noninteger,
        )
    except Cp6ExportRefused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        _refuse("encoding")
    if type(document) is not dict or _canonical(document) != payload:
        _refuse("noncanonical")
    return document


def parse_cp6_export(payload: bytes) -> Cp6Export:
    """Parse the canonical export bytes into typed blocks, or refuse."""
    document = _strict_json(payload)
    top = _object(document, _TOP)
    if top["schema"] != EXPORT_SCHEMA:
        _refuse("schema")
    control = _object(top["control"], _CONTROL)
    cp = _object(top["cp_lane3"], _CP_LANE3)

    raw_dispatch = _object(control["dispatch"], _DISPATCH)
    _unb64url(raw_dispatch["signature"], length=64)
    dispatch = DispatchBlock(
        statement=_statement(raw_dispatch["statement"]),
        signature=raw_dispatch["signature"],
        envelope_digest=_digest(raw_dispatch["envelope_digest"]),
    )
    raw_ledger = _object(control["ledger"], _LEDGER)
    fingerprint = raw_ledger["fingerprint"]
    if type(fingerprint) is not str or not _BARE_HEX.fullmatch(fingerprint):
        _refuse("field")
    ledger = LedgerBlock(
        key=_token(raw_ledger["key"]),
        scope=_token(raw_ledger["scope"]),
        status=_token(raw_ledger["status"]),
        fingerprint=fingerprint,
        created_at=_time(raw_ledger["created_at"]),
        execution_sequence=_positive(raw_ledger["execution_sequence"]),
        attempt_no=_positive(raw_ledger["attempt_no"]),
    )

    raw_receipt = _object(cp["e10_receipt"], _RECEIPT)
    slot = raw_receipt["vm_slot"]
    _token(raw_receipt["key_custody_pointer"])
    _token(raw_receipt["recorded_by"])
    _time(raw_receipt["recorded_at"])
    _positive(raw_receipt["seq"])
    receipt = ReceiptBlock(
        document=dict(raw_receipt),
        receipt_ref=_token(raw_receipt["receipt_ref"]),
        vm_alias=_token(raw_receipt["vm_alias"]),
        host_id=_token(raw_receipt["host_id"]),
        machine_id=_token(raw_receipt["machine_id"]),
        ssh_host_key_fingerprint=_token(raw_receipt["ssh_host_key_fingerprint"]),
        vm_slot=None if slot is None else _token(slot),
        incarnation_public_key_b64url=_token(
            raw_receipt["incarnation_public_key_b64url"]
        ),
        incarnation_fingerprint=_digest(raw_receipt["incarnation_fingerprint"]),
        enrolment_uuid=_token(raw_receipt["enrolment_uuid"]),
    )

    raw_destruction = _object(cp["destruction"], _DESTRUCTION)
    destroyed_dispatch = raw_destruction["dispatch_id"]
    installed = raw_destruction["installed_attestation_digest"]
    # The design: NULL together (a destroy-only E11 incarnation), else both.
    if (destroyed_dispatch is None) != (installed is None):
        _refuse("destruction")
    _token(raw_destruction["recorded_by"])
    destruction = DestructionBlock(
        receipt_ref=_token(raw_destruction["receipt_ref"]),
        destroyed_at=_time(raw_destruction["destroyed_at"]),
        route=_token(raw_destruction["route"]),
        dispatch_id=None if destroyed_dispatch is None else _token(destroyed_dispatch),
        installed_attestation_digest=None if installed is None else _digest(installed),
        evidence_digest=_digest(raw_destruction["evidence_digest"]),
    )

    raw_lease = _object(cp["lease"], _LEASE)
    lease = LeaseBlock(
        lease_id=_token(raw_lease["lease_id"]),
        host_id=_token(raw_lease["host_id"]),
        authorization_run=_token(raw_lease["authorization_run"]),
        e10_receipt_ref=_token(raw_lease["e10_receipt_ref"]),
        acquired_at=_time(raw_lease["acquired_at"]),
        expires_at=_time(raw_lease["expires_at"]),
    )

    release: ReleaseBlock | None = None
    if cp["release"] is not None:
        raw_release = _object(cp["release"], _RELEASE)
        if type(raw_release["host_mutated"]) is not bool:
            _refuse("field")
        release = ReleaseBlock(
            lease_id=_token(raw_release["lease_id"]),
            released_at=_time(raw_release["released_at"]),
            host_mutated=raw_release["host_mutated"],
        )

    return Cp6Export(
        dispatch_id=_uuid(top["dispatch_id"]),
        host_id=_token(top["host_id"]),
        dispatch=dispatch,
        ledger=ledger,
        presentation_credential=_presentation_credential(
            control["presentation_credential"]
        ),
        receipt=receipt,
        destruction=destruction,
        lease=lease,
        release=release,
        e10_receipt_digest=_digest(cp["e10_receipt_digest"]),
        candidate_root=_root(cp["candidate_root"]),
        installed_root=_root(cp["installed_root"]),
        export_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
    )
