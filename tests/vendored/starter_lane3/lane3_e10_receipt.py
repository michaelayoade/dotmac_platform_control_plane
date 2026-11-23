"""The per-VM E10 provisioning receipt, as a typed INPUT the launcher validates.

Michael's amended U3 (option B): `host_incarnation` is a dedicated Ed25519
incarnation key. E10 generates it, enrols it in Control, uses it to sign the
installed attestation and destroys its private half before the session launches.
The target's SSH Ed25519 host key is pinned SEPARATELY (with the VM alias as
`HostKeyAlias`). The per-VM E10 receipt is what links the two.

This module builds no receipt and verifies no signature. It names the fields the
launcher requires the receipt to carry, checks each is well-formed, and compares
them with the independent inputs the launcher was given. Every field is required
and none has a default. Whether a receipt reference names a real receipt is CP's
to verify; here it is only a non-empty token.

Two forms of "fingerprint" appear and are NOT interchangeable:

* the SSH host key's OpenSSH form, `SHA256:` + 43 base64 characters (a digest of
  the SSH wire blob), which is what `PinnedHostKey` carries;
* the incarnation key's CP form, `sha256:` + 64 lower-case hex (a digest of the
  RAW 32-byte public key), which is CP's `installed_signer_fingerprint` and so
  the plan's `host_incarnation`.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Final

__all__ = [
    "E10ReceiptRef",
    "ReceiptRefused",
    "require_enrolment_matches",
    "validate_incarnation_fingerprint",
]

_OPENSSH_FINGERPRINT: Final = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_INCARNATION_FINGERPRINT: Final = re.compile(r"sha256:[0-9a-f]{64}")
_ALIAS: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
_VM_SLOT: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}/[1-9][0-9]{0,8}")
_MACHINE_ID: Final = re.compile(r"[0-9a-f]{32}")
_TOKEN: Final = re.compile(r"[\x21-\x7e]{1,256}")


class ReceiptRefused(Exception):
    """The receipt input is malformed or disagrees with an independent input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_incarnation_fingerprint(value: object) -> str:
    """`sha256:<64 lower-case hex>`, CP's `installed_signer_fingerprint` form."""
    if not isinstance(value, str) or not _INCARNATION_FINGERPRINT.fullmatch(value):
        raise ReceiptRefused("host-incarnation-required")
    return value


def _raw_public_key(value: object) -> bytes:
    """A canonical unpadded base64url 32-byte key, in the form Control reads.

    Control's `PublicKeyFingerprintV1.from_public_key_b64` (Control `digests.py`,
    the host-attester enrolment's `public_key_b64`) refuses a padded key and
    requires the canonical unpadded base64url spelling, so that is the ONLY
    spelling accepted here. The same 32 bytes in padded or standard base64 are a
    different string and are refused.
    """
    if not isinstance(value, str) or not value or "=" in value:
        raise ReceiptRefused("incarnation-public-key-invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise ReceiptRefused("incarnation-public-key-invalid") from None
    if (
        len(raw) != 32
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value
    ):
        raise ReceiptRefused("incarnation-public-key-invalid")
    return raw


@dataclasses.dataclass(frozen=True, slots=True)
class E10ReceiptRef:
    """The fields the per-VM E10 receipt must carry. All required, no defaults."""

    vm_alias: str
    host_id: str
    machine_id: str
    ssh_host_key_fingerprint: str
    incarnation_public_key_b64url: str
    incarnation_fingerprint: str
    enrolment_uuid: str
    incarnation_key_destroyed_at: datetime
    receipt_ref: str
    #: Proxmox slot, `node/vmid`, or None. REQUIRED like every field (no default),
    #: but may be None: the receipt row carries it (E3 U7), nothing compares it yet.
    vm_slot: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.vm_alias, str) or not _ALIAS.fullmatch(self.vm_alias):
            raise ReceiptRefused("receipt-vm-alias-invalid")
        for name in ("host_id", "receipt_ref"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _TOKEN.fullmatch(value):
                raise ReceiptRefused(f"receipt-{name.replace('_', '-')}-invalid")
        if not isinstance(self.machine_id, str) or not _MACHINE_ID.fullmatch(
            self.machine_id
        ):
            raise ReceiptRefused("receipt-machine-id-invalid")
        if not isinstance(
            self.ssh_host_key_fingerprint, str
        ) or not _OPENSSH_FINGERPRINT.fullmatch(self.ssh_host_key_fingerprint):
            raise ReceiptRefused("receipt-ssh-fingerprint-invalid")
        if self.vm_slot is not None and (
            not isinstance(self.vm_slot, str) or not _VM_SLOT.fullmatch(self.vm_slot)
        ):
            raise ReceiptRefused("receipt-vm-slot-invalid")
        validate_incarnation_fingerprint(self.incarnation_fingerprint)
        derived = (
            "sha256:"
            + hashlib.sha256(
                _raw_public_key(self.incarnation_public_key_b64url)
            ).hexdigest()
        )
        if derived != self.incarnation_fingerprint:
            raise ReceiptRefused("incarnation-fingerprint-does-not-identify-the-key")
        try:
            canonical = str(uuid.UUID(str(self.enrolment_uuid)))
        except ValueError:
            raise ReceiptRefused("receipt-enrolment-uuid-invalid") from None
        if canonical != self.enrolment_uuid:
            raise ReceiptRefused("receipt-enrolment-uuid-invalid")
        destroyed = self.incarnation_key_destroyed_at
        if not isinstance(destroyed, datetime) or destroyed.tzinfo is None:
            raise ReceiptRefused("receipt-destruction-time-invalid")

    def require_matches(
        self,
        *,
        ssh_fingerprint: str,
        alias: str,
        expected_host_incarnation: str,
        host_id: str,
        machine_id: str,
        store_time: datetime,
    ) -> None:
        """Refuse unless the receipt agrees with every independent input.

        `ssh_fingerprint` and `alias` come from the pinned host key,
        `expected_host_incarnation` from its own typed input, `host_id` from the
        held lease, `machine_id` from the session plan (`expected_machine_id`) and
        `store_time` from the lease store. The incarnation private
        key must have been destroyed no later than the store's time.
        """
        validate_incarnation_fingerprint(expected_host_incarnation)
        if ssh_fingerprint != self.ssh_host_key_fingerprint:
            raise ReceiptRefused("receipt-ssh-fingerprint-mismatch")
        if alias != self.vm_alias:
            raise ReceiptRefused("receipt-alias-mismatch")
        if expected_host_incarnation != self.incarnation_fingerprint:
            raise ReceiptRefused("receipt-incarnation-mismatch")
        if host_id != self.host_id:
            raise ReceiptRefused("receipt-host-id-mismatch")
        if machine_id != self.machine_id:
            raise ReceiptRefused("receipt-machine-id-mismatch")
        if self.incarnation_key_destroyed_at > store_time:
            raise ReceiptRefused("incarnation-key-not-destroyed-before-launch")


MAX_CONTEXT_BYTES: Final = 1024 * 1024


def require_enrolment_matches(execution_context: bytes, receipt: E10ReceiptRef) -> None:
    """The receipt's enrolment UUID must be the staged context's `host_enrolment_ref`.

    `execution_context` is the exact `execution-context.json` the launcher stages
    (CP `materials_producer.CONTEXT_KEYS` carries `host_enrolment_ref`), so the
    enrolment the receipt says the incarnation key was enrolled under is the one
    the authorization is issued for.
    """
    if not isinstance(execution_context, bytes) or not (
        0 < len(execution_context) <= MAX_CONTEXT_BYTES
    ):
        raise ReceiptRefused("execution-context-unreadable")
    try:
        document = json.loads(execution_context)
    except ValueError:
        raise ReceiptRefused("execution-context-unreadable") from None
    if not isinstance(document, dict):
        raise ReceiptRefused("execution-context-unreadable")
    reference = document.get("host_enrolment_ref")
    if not isinstance(reference, str) or not reference:
        raise ReceiptRefused("execution-context-enrolment-missing")
    if reference != receipt.enrolment_uuid:
        raise ReceiptRefused("receipt-enrolment-mismatch")
