"""Inert retained-byte composition and encryption, never Gate 0 acceptance.

Supplied coordinates/source pins are expectations. Actual producer authentication,
prerequisite decisions, custody verification and publication belong elsewhere.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, cast

from vendor_cp.deployment.gate0_e_archive import (
    ARCHIVE_NAMES,
    MAX_CIPHERTEXT_BYTES,
    MAX_PRIVATE_BYTES,
    ArchiveRefused,
    EncryptedArchive,
    GpgArchiveProfile,
    package_private_collection,
)
from vendor_cp.deployment.gate0_e_finalization import (
    ESelection,
    RetainedEvidenceRefused,
    VerifiedCollection,
    verify_retained_collection,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object


class EPreparationRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_e_preparation_refused")


def _require(condition: bool) -> None:
    if not condition:
        raise EPreparationRefused()


def _bare_digest(value: object) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return cast(str, value)


def _digest(value: object) -> str:
    _require(type(value) is str and value.startswith("sha256:"))
    text = cast(str, value)
    _bare_digest(text[7:])
    return text


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _deadline(deadline: float) -> None:
    _require(type(deadline) in (float, int))
    _require(math.isfinite(deadline) and time.monotonic() < deadline)


@dataclass(frozen=True, slots=True)
class EProducerCoordinates:
    """Independent inert selection pins; no authenticated GitHub-facts claim."""

    repository_id: int
    owner_id: int
    workflow_id: int
    run_id: int
    attempt: int
    job_id: int
    source_revision: str

    def __post_init__(self) -> None:
        for value in (
            self.repository_id,
            self.owner_id,
            self.workflow_id,
            self.run_id,
            self.attempt,
            self.job_id,
        ):
            _require(type(value) is int and value > 0)
        _require(self.attempt == 1)
        _require(
            type(self.source_revision) is str
            and re.fullmatch(r"[0-9a-f]{40}", self.source_revision) is not None
        )

    def document(self) -> dict[str, object]:
        return {
            "repository_id": self.repository_id,
            "owner_id": self.owner_id,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "attempt": self.attempt,
            "job_id": self.job_id,
            "source_revision": self.source_revision,
        }


@dataclass(frozen=True, slots=True, repr=False)
class PreparedEncryptedEvidence:
    """Exact ciphertext and public projection from this preparation invocation."""

    ciphertext: bytes = field(repr=False)
    projection: bytes = field(repr=False)


def validate_encrypted_e_projection(raw: bytes) -> dict[str, object]:
    """Pure schema validation, not provenance, private verification or acceptance."""
    try:
        _require(type(raw) is bytes and 0 < len(raw) <= 65536)
        value = strict_object(raw, 65536)
        _require(
            set(value)
            == {
                "schema",
                "policy_digest",
                "campaign_digest",
                "source_bundle_digest",
                "collection_digest",
                "plaintext_archive_digest",
                "inner_manifest_digest",
                "ciphertext_digest",
                "ciphertext_bytes",
                "producer",
                "result",
            }
        )
        _require(value["schema"] == "Gate0EncryptedEvidenceProjection.v1")
        _require(value["result"] == "encrypted_evidence")
        for key in (
            "policy_digest",
            "campaign_digest",
            "source_bundle_digest",
            "collection_digest",
            "plaintext_archive_digest",
            "inner_manifest_digest",
            "ciphertext_digest",
        ):
            _digest(value[key])
        _require(
            type(value["ciphertext_bytes"]) is int
            and 0 < value["ciphertext_bytes"] <= MAX_CIPHERTEXT_BYTES
        )
        producer = value["producer"]
        _require(
            type(producer) is dict
            and set(producer)
            == {
                "repository_id",
                "owner_id",
                "workflow_id",
                "run_id",
                "attempt",
                "job_id",
                "source_revision",
            }
        )
        EProducerCoordinates(**cast(dict[str, Any], producer))
        return value
    except Exception:
        raise EPreparationRefused() from None


def _join_selection(selection: ESelection, producer: EProducerCoordinates) -> None:
    _require(type(selection) is ESelection and type(producer) is EProducerCoordinates)
    _require(producer.source_revision == selection.source.workflow_revision)
    for case in selection.cases:
        claims = case.window.document["github"]
        for key, value in (
            ("repository_id", producer.repository_id),
            ("repository_owner_id", producer.owner_id),
            ("run_id", producer.run_id),
            ("run_attempt", producer.attempt),
        ):
            _require(type(claims[key]) is str and claims[key] == str(value))
        _require(claims["workflow_sha"] == producer.source_revision)


def prepare_encrypted_e(
    raw_collection: bytes,
    selection: ESelection,
    producer: EProducerCoordinates,
    source_bundle_digest: str,
    prerequisite_bytes: bytes,
    profile: GpgArchiveProfile,
    *,
    deadline: float,
) -> PreparedEncryptedEvidence:
    """Verify exact retained collection, compose four payloads, encrypt once.

    The finite future monotonic deadline is passed unchanged to the concrete
    archive owner. No caller-made VerifiedCollection/EncryptedArchive is accepted.
    Prerequisite bytes remain opaque exact retained evidence, never acceptance.
    """
    try:
        _deadline(deadline)
        _require(
            type(raw_collection) is bytes and 0 < len(raw_collection) <= 8 * 1024 * 1024
        )
        _require(
            type(prerequisite_bytes) is bytes
            and 0 < len(prerequisite_bytes) <= MAX_PRIVATE_BYTES - 65536
        )
        _require(type(profile) is GpgArchiveProfile)
        _digest(source_bundle_digest)
        _join_selection(selection, producer)
        verified = verify_retained_collection(raw_collection, selection)
        _deadline(deadline)
        _require(type(verified) is VerifiedCollection)
        _require(verified.collection_bytes == raw_collection)
        _require(verified.collection_digest == "sha256:" + _sha(raw_collection))
        _require(verified.policy_digest == selection.policy_digest)
        _require(
            verified.result == "retained_bytes_verified"
            and verified.readiness_accepted is False
        )
        for values, count in (
            (verified.bundle_digests, 4),
            (verified.root_record_digests, 14),
            (verified.join_digests, 2),
        ):
            _require(type(values) is tuple and len(values) == count)
            for value in values:
                _digest(value)
        producer_bytes = canonical(
            {
                "schema": "Gate0EProducerSelection.v1",
                "producer": producer.document(),
                "source_bundle_digest": source_bundle_digest,
            }
        )
        receipt = canonical(
            {
                "schema": "Gate0ERetainedCollectionReceipt.v1",
                "policy_digest": verified.policy_digest,
                "collection_digest": verified.collection_digest,
                "bundle_digests": list(verified.bundle_digests),
                "root_record_digests": list(verified.root_record_digests),
                "join_digests": list(verified.join_digests),
                "result": "retained_bytes_verified",
            }
        )
        _require(len(producer_bytes) <= 65536 and len(receipt) <= 65536)
        payloads = {
            "collection.json": verified.collection_bytes,
            "producer.json": producer_bytes,
            "prerequisites.json": prerequisite_bytes,
            "receipt.json": receipt,
        }
        _require(set(payloads) == set(ARCHIVE_NAMES))
        manifest = canonical(
            {
                "schema": "Gate0EArchiveManifest.v1",
                "files": {
                    name: {
                        "length": len(payloads[name]),
                        "sha256": _sha(payloads[name]),
                    }
                    for name in ARCHIVE_NAMES
                },
            }
        )
        _require(
            len(manifest) <= 65536
            and sum(map(len, payloads.values())) + len(manifest)
            <= MAX_PRIVATE_BYTES - 65536
        )
        _deadline(deadline)
        encrypted = package_private_collection(
            manifest, payloads, profile, deadline=deadline
        )
        _deadline(deadline)
        _require(type(encrypted) is EncryptedArchive)
        _require(
            type(encrypted.ciphertext) is bytes
            and 0 < len(encrypted.ciphertext) <= MAX_CIPHERTEXT_BYTES
        )
        _require(
            _bare_digest(encrypted.ciphertext_sha256) == _sha(encrypted.ciphertext)
        )
        _require(_bare_digest(encrypted.inner_manifest_sha256) == _sha(manifest))
        _bare_digest(encrypted.plaintext_sha256)
        projection = canonical(
            {
                "schema": "Gate0EncryptedEvidenceProjection.v1",
                "policy_digest": selection.policy_digest,
                "campaign_digest": selection.campaign_digest,
                "source_bundle_digest": source_bundle_digest,
                "collection_digest": verified.collection_digest,
                "plaintext_archive_digest": "sha256:" + encrypted.plaintext_sha256,
                "inner_manifest_digest": "sha256:" + encrypted.inner_manifest_sha256,
                "ciphertext_digest": "sha256:" + encrypted.ciphertext_sha256,
                "ciphertext_bytes": len(encrypted.ciphertext),
                "producer": producer.document(),
                "result": "encrypted_evidence",
            }
        )
        validate_encrypted_e_projection(projection)
        _deadline(deadline)
        return PreparedEncryptedEvidence(encrypted.ciphertext, projection)
    except (RetainedEvidenceRefused, ArchiveRefused):
        raise
    except Exception:
        raise EPreparationRefused() from None
