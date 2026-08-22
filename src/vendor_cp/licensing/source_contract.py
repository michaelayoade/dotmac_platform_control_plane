"""The versioned, digest-pinned licence-SOURCE contract (ADR-0010 § 3, gate 2a).

Vendor is the SOURCE of a licence artifact, not a destination for one. That
distinction decides the whole shape of this file, so it is stated first.

## What this is NOT, and why the difference is load-bearing

It is not a `ProductPortDescriptorV1`. That contract answers *"where does this
land?"* — it carries `delivery_path`, `mirror_path`, a `DestinationBinding` and a
destination-owned `LocalScope`, all of which are the DESTINATION application's
vocabulary. Reusing it here would make Vendor a routing destination for its own
outbound artifacts, which is false and would put a second answer to "where does
this land?" in the fleet.

The destination is the DEPLOYMENT. `dotmac-deployment-control` owns the stable
`target_ref`, the deployment publishes its own authenticated destination
descriptor, and the Integrator binds that descriptor to that `target_ref` before
any connector I/O (ADR-0010's 2026-08-22 amendment, gate 2b — a later change in
the Deployment and Integrator repositories, not this one).

So this file describes only what Vendor OFFERS: three read/write operations over
its own artifacts and acknowledgement lifecycle. It has no routing opinion, no
destination scope and no delivery path, and it must never grow one. If
acknowledgements ever need independent routing, Vendor becomes the destination
for that SEPARATE capability and gets its own destination descriptor then —
under the existing contract, not by widening this one.

## Why a digest at all

The Integrator pins this contract by digest and refuses drift. That is what makes
a silent change to Vendor's port shape a failed reconciliation rather than a
malformed request at delivery time. The digest is computed over the canonical
JSON of the declaration below, so it moves if and only if the declared surface
moves — adding a field, renaming an operation, changing a correlation
requirement. Prose changes here do not move it, and that is deliberate: a pin
that churned on a docstring edit would be re-pinned reflexively and stop meaning
anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Final

#: Not `dotmac.io/product-port-descriptor/v1`. A different question, a different
#: schema id, and deliberately not a version of that one.
CONTRACT_SCHEMA: Final[str] = "dotmac.io/licence-source-contract/v1"

CONTRACT_VERSION: Final[int] = 1

APPLICATION: Final[str] = "dotmac-vendor-control-plane"

#: The lifecycle owner behind the acknowledgement port. Named because the
#: acknowledgement is delegated to it rather than decided here.
LIFECYCLE_OWNER: Final[str] = "dotmac-licensing"

#: The four fields that correlate an intent to its acknowledgement, required on
#: BOTH. A mismatch on any of them fails closed — an acknowledgement that cannot
#: be tied to the exact artifact and destination it claims to complete is
#: evidence of a routing fault, not a completion.
CORRELATION_FIELDS: Final[tuple[str, ...]] = (
    "delivery_intent_id",
    "deployment_target_ref",
    "licence_version",
    "artifact_digest",
)


@dataclass(frozen=True, slots=True)
class SourceOperation:
    """One declared operation. Paths are Vendor's own; they route nothing."""

    name: str
    method: str
    path: str
    summary: str
    request_fields: tuple[str, ...]
    response_fields: tuple[str, ...]


#: Exactly three, as ADR-0010 § 3 specifies. Adding a fourth is a contract
#: change with a new digest, not an implementation detail.
OPERATIONS: Final[tuple[SourceOperation, ...]] = (
    SourceOperation(
        name="open_delivery_intent",
        method="POST",
        path="/platform/vendor/licences/source/intents",
        summary=(
            "Durably record that an exact licence artifact is to be delivered "
            "to one Deployment Control target. Returns the correlation fields "
            "and NOT the signed envelope."
        ),
        request_fields=("issuance_id", "deployment_target_id"),
        response_fields=(
            "delivery_intent_id",
            "deployment_target_ref",
            "licence_version",
            "artifact_digest",
            "issuance_id",
            "status",
        ),
    ),
    SourceOperation(
        name="read_exact_artifact",
        method="GET",
        path="/platform/vendor/licences/source/intents/{delivery_intent_id}/artifact",
        summary=(
            "Return the immutable signed envelope for this intent's artifact, "
            "for dispatch only. Never copied into an event, retry row or log."
        ),
        request_fields=("delivery_intent_id",),
        response_fields=("delivery_intent_id", "artifact_digest", "envelope"),
    ),
    SourceOperation(
        name="acknowledge_delivery_intent",
        method="POST",
        path=(
            "/platform/vendor/licences/source/intents/"
            "{delivery_intent_id}/acknowledgement"
        ),
        summary=(
            "Complete an already-correlated intent. Carries the "
            "transport-authenticated deployment identity and the durable "
            "Integrator receipt identity. Idempotent on the receipt."
        ),
        request_fields=(
            "deployment_target_ref",
            "licence_version",
            "artifact_digest",
            "integrator_receipt_ref",
            "authenticated_deployment_ref",
            "outcome",
            "reason",
            "reported_at",
        ),
        response_fields=(
            "delivery_intent_id",
            "status",
            "acknowledged_at",
            "integrator_receipt_ref",
        ),
    ),
)


def declaration() -> dict[str, Any]:
    """The pinned surface, as data. Digest input and response body alike."""
    return {
        "schema": CONTRACT_SCHEMA,
        "application": APPLICATION,
        "contract_version": CONTRACT_VERSION,
        "lifecycle_owner": LIFECYCLE_OWNER,
        "correlation_fields": list(CORRELATION_FIELDS),
        "operations": [asdict(operation) for operation in OPERATIONS],
    }


def contract_digest() -> str:
    """`sha256:<hex>` over the canonical declaration.

    Sorted keys and separators fixed, so two processes on the same declaration
    agree byte-for-byte. Anything a reader could not see in `declaration()` is
    not in the digest, which is what lets prose be edited without forcing every
    consumer to re-pin.
    """
    canonical = json.dumps(
        declaration(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


__all__ = [
    "APPLICATION",
    "CONTRACT_SCHEMA",
    "CONTRACT_VERSION",
    "CORRELATION_FIELDS",
    "LIFECYCLE_OWNER",
    "OPERATIONS",
    "SourceOperation",
    "contract_digest",
    "declaration",
]
