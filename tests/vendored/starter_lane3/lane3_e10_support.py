"""A valid E10 receipt input, for tests. Builds nothing but the typed input."""

from __future__ import annotations

import base64
import hashlib
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from lane3_e10_receipt import E10ReceiptRef  # noqa: E402

INCARNATION_RAW = bytes(range(32, 64))
INCARNATION_B64URL = base64.urlsafe_b64encode(INCARNATION_RAW).decode().rstrip("=")
INCARNATION_FINGERPRINT = "sha256:" + hashlib.sha256(INCARNATION_RAW).hexdigest()
OTHER_INCARNATION_FINGERPRINT = "sha256:" + "0" * 64
SSH_FINGERPRINT = "SHA256:" + "B" * 43
MACHINE_ID = "0123456789abcdef0123456789abcdef"
ENROLMENT_UUID = "6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11"
DESTROYED_AT = datetime(2026, 11, 17, 4, 0, 0, tzinfo=UTC)


def incarnation_for(raw: bytes) -> tuple[str, str]:
    """`(public key b64url, fingerprint)` for a 32-byte key, derived the CP way."""
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return encoded, "sha256:" + hashlib.sha256(raw).hexdigest()


def make_generation_receipt(
    host_id: str,
    generation: int,
    *,
    ordered_as: int | None = None,
    incarnation_of: int | None = None,
    **overrides: Any,
) -> E10ReceiptRef:
    """The `generation`-th receipt for a host: each is a DIFFERENT incarnation.

    Generation 1 is `make_receipt()`. Every later one has its own key (derived
    from the generation, never a neighbour's), enrolment and receipt ref, and a
    destruction time one hour later per generation, as a rebuilt VM's receipt
    does. `ordered_as` gives it another generation's position in that order
    (its destruction time); `incarnation_of` gives it another generation's key
    while its ref, enrolment and order stay its own.
    """
    position = generation if ordered_as is None else ordered_as
    key_of = generation if incarnation_of is None else incarnation_of
    if key_of == 1:
        key, fingerprint = INCARNATION_B64URL, INCARNATION_FINGERPRINT
    else:
        key, fingerprint = incarnation_for(hashlib.sha256(b"gen-%d" % key_of).digest())
    values: dict[str, Any] = {
        "host_id": host_id,
        "incarnation_public_key_b64url": key,
        "incarnation_fingerprint": fingerprint,
        "enrolment_uuid": (
            ENROLMENT_UUID if generation == 1 else str(uuid.UUID(int=generation))
        ),
        "incarnation_key_destroyed_at": DESTROYED_AT + timedelta(hours=position - 1),
        "receipt_ref": (
            "e10-receipt-0001" if generation == 1 else f"e10-receipt-{generation:04d}"
        ),
    }
    values.update(overrides)
    return make_receipt(**values)


def make_receipt(**overrides: Any) -> E10ReceiptRef:
    values: dict[str, Any] = {
        "vm_alias": "vm-alpha",
        "host_id": "host-a",
        "machine_id": MACHINE_ID,
        "ssh_host_key_fingerprint": SSH_FINGERPRINT,
        "incarnation_public_key_b64url": INCARNATION_B64URL,
        "incarnation_fingerprint": INCARNATION_FINGERPRINT,
        "enrolment_uuid": ENROLMENT_UUID,
        "incarnation_key_destroyed_at": DESTROYED_AT,
        "receipt_ref": "e10-receipt-0001",
        "vm_slot": None,
    }
    values.update(overrides)
    return E10ReceiptRef(**values)
