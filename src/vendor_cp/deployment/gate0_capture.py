"""Portable approved-at-start values; decoding never authenticates management.

Only the concrete owner reader exports captures. No runtime, process clock,
secret, signing endpoint, transport or live loader is selected by this module.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from uuid import UUID

from vendor_cp.deployment.gate0_composition import AdmissionExpectation
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import (
    json_integer,
    json_record,
    json_string,
)
from vendor_cp.deployment.gate0_runtime import AdmittedOperation
from vendor_cp.deployment.gate0_window import (
    ApprovedWindowBinding,
    FrozenIssuerWindow,
    OwnerWindowReader,
)

MAX_CAPTURE_BYTES = 65536
MAX_CAPTURE_PLANS = 4
MAX_CAPTURE_IMAGES = 64
_SCHEMA = "Gate0ApprovedStartCapture.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = frozenset(
    "schema frozen_window_b64 window_digest plan_id plan_digest target_id "
    "environment approval_request_id approval_policy_code approval_policy_version "
    "descriptor_digest authorized_image_digests operation".split()
)
_OPERATION_FIELDS = frozenset(
    "repository_id run_id run_attempt window_id phase authorization_digest "
    "authorization_issued_at lease_id controller_fingerprint target_ref plan_id "
    "plan_digest plan_purpose operation execution_plan_digest certificate_digest "
    "ca_fingerprint".split()
)


class CaptureRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_capture_refused")


def _digest(value: object) -> str:
    value = json_string(value)
    if _DIGEST.fullmatch(value) is None:
        raise CaptureRefused()
    return value


def _uuid(value: object) -> UUID:
    text = json_string(value)
    result = UUID(text)
    if str(result) != text:
        raise CaptureRefused()
    return result


def capture_digest(encoded: bytes) -> str:
    """Hash bounded capture bytes; the codec separately checks canonical form."""
    if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_CAPTURE_BYTES:
        raise CaptureRefused()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CaptureCoordinates:
    """Required independent equality inputs; their shape is not authentication."""

    capture_digest: str
    window_digest: str
    plan_id: UUID
    plan_digest: str
    target_id: UUID
    approval_request_id: UUID

    def __post_init__(self) -> None:
        if any(
            type(value) is not UUID
            for value in (self.plan_id, self.target_id, self.approval_request_id)
        ) or any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (self.capture_digest, self.window_digest, self.plan_digest)
        ):
            raise CaptureRefused()


@dataclass(frozen=True, slots=True)
class PublicCapture:
    """Public bytes and equality coordinates; no portable grant or signature."""

    encoded: bytes
    coordinates: CaptureCoordinates


@dataclass(frozen=True, slots=True)
class UnauthenticatedCapture:
    """Validated value only. A trusted loader must authenticate its delivery.

    The binding intentionally has no WindowFreshness. NS3's existing admission
    maps the authenticated absolute end onto its own original startup clocks.
    """

    binding: ApprovedWindowBinding
    coordinates: CaptureCoordinates


def _operation_document(operation: AdmittedOperation) -> dict[str, object]:
    return {
        "repository_id": operation.repository_id,
        "run_id": operation.run_id,
        "run_attempt": operation.run_attempt,
        "window_id": operation.window_id,
        "phase": operation.phase,
        "authorization_digest": operation.authorization_digest,
        "authorization_issued_at": operation.authorization_issued_at,
        "lease_id": operation.lease_id,
        "controller_fingerprint": operation.controller_fingerprint,
        "target_ref": operation.target_ref,
        "plan_id": operation.plan_id,
        "plan_digest": operation.plan_digest,
        "plan_purpose": operation.plan_purpose,
        "operation": operation.operation,
        "execution_plan_digest": operation.execution_plan_digest,
        "certificate_digest": operation.certificate_digest,
        "ca_fingerprint": operation.ca_fingerprint,
    }


def _operation(value: object) -> AdmittedOperation:
    record = json_record(value)
    if (
        set(record) != _OPERATION_FIELDS
        or record["phase"] != "issue"
        or record["authorization_digest"] is not None
        or record["authorization_issued_at"] is not None
    ):
        raise CaptureRefused()
    return AdmittedOperation(
        repository_id=json_string(record["repository_id"]),
        run_id=json_string(record["run_id"]),
        run_attempt=json_string(record["run_attempt"]),
        window_id=json_string(record["window_id"]),
        phase="issue",
        authorization_digest=None,
        authorization_issued_at=None,
        lease_id=json_string(record["lease_id"]),
        controller_fingerprint=json_string(record["controller_fingerprint"]),
        target_ref=json_string(record["target_ref"]),
        plan_id=json_string(record["plan_id"]),
        plan_digest=json_string(record["plan_digest"]),
        plan_purpose=json_string(record["plan_purpose"]),
        operation=json_string(record["operation"]),
        execution_plan_digest=json_string(record["execution_plan_digest"]),
        certificate_digest=json_string(record["certificate_digest"]),
        ca_fingerprint=json_string(record["ca_fingerprint"]),
    )


def _images(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > MAX_CAPTURE_IMAGES:
        raise CaptureRefused()
    return tuple(_digest(item) for item in value)


def _coordinates(encoded: bytes, binding: ApprovedWindowBinding) -> CaptureCoordinates:
    expected = binding.expectation
    if expected.window_digest is None:
        raise CaptureRefused()
    return CaptureCoordinates(
        capture_digest(encoded),
        expected.window_digest,
        UUID(expected.operation.plan_id),
        expected.operation.plan_digest,
        expected.target_id,
        expected.approval_request_id,
    )


def _encode(binding: ApprovedWindowBinding) -> PublicCapture:
    # Private codec projection. The only export entrypoint obtains binding
    # through OwnerWindowReader itself; no caller-provided binding export API.
    if type(binding) is not ApprovedWindowBinding:
        raise CaptureRefused()
    ApprovedWindowBinding(
        binding.expectation,
        binding.window,
        binding.descriptor_digest,
        binding.authorized_image_digests,
    )
    expected = binding.expectation
    operation = _operation(_operation_document(expected.operation))
    images = _images(list(binding.authorized_image_digests))
    document = {
        "schema": _SCHEMA,
        "frozen_window_b64": base64.b64encode(binding.window.canonical_bytes).decode(
            "ascii"
        ),
        "window_digest": binding.window.digest,
        "plan_id": operation.plan_id,
        "plan_digest": operation.plan_digest,
        "target_id": str(expected.target_id),
        "environment": expected.environment,
        "approval_request_id": str(expected.approval_request_id),
        "approval_policy_code": expected.approval_policy_code,
        "approval_policy_version": expected.approval_policy_version,
        "descriptor_digest": binding.descriptor_digest,
        "authorized_image_digests": list(images),
        "operation": _operation_document(operation),
    }
    encoded = canonical(document)
    coordinates = _coordinates(encoded, binding)
    # One decoder owns closed fields and cross-field equality for both directions.
    # This internal roundtrip validates owner-derived data, never its delivery.
    decode_capture(encoded, expected=coordinates)
    return PublicCapture(encoded, coordinates)


def decode_capture(
    encoded: bytes, *, expected: CaptureCoordinates | None = None
) -> UnauthenticatedCapture:
    """Compare independently supplied coordinates, then return unauthenticated data.

    The expected digest must not be sourced from the submitted capture itself.
    Equality, parser success and this function's type do not establish delivery
    authenticity, human approval, current standing or unspent authority.
    """
    try:
        if (
            type(expected) is not CaptureCoordinates
            or capture_digest(encoded) != expected.capture_digest
            or not encoded.isascii()
        ):
            raise CaptureRefused()
        value = strict_object(encoded, MAX_CAPTURE_BYTES)
        if (
            set(value) != _FIELDS
            or value["schema"] != _SCHEMA
            or canonical(value) != encoded
        ):
            raise CaptureRefused()
        window_b64 = json_string(value["frozen_window_b64"])
        if not 0 < len(window_b64) <= 4 * ((32768 + 2) // 3):
            raise CaptureRefused()
        window_bytes = base64.b64decode(window_b64, validate=True)
        if base64.b64encode(window_bytes).decode("ascii") != window_b64:
            raise CaptureRefused()
        window = FrozenIssuerWindow.parse(window_bytes)
        operation = _operation(value["operation"])
        plan_id, plan_digest = _uuid(value["plan_id"]), _digest(value["plan_digest"])
        if str(plan_id) != operation.plan_id or plan_digest != operation.plan_digest:
            raise CaptureRefused()
        binding = ApprovedWindowBinding(
            AdmissionExpectation(
                operation,
                _uuid(value["target_id"]),
                json_string(value["environment"]),
                _uuid(value["approval_request_id"]),
                json_string(value["approval_policy_code"]),
                json_integer(value["approval_policy_version"]),
                window.canonical_bytes,
                _digest(value["window_digest"]),
            ),
            window,
            _digest(value["descriptor_digest"]),
            _images(value["authorized_image_digests"]),
        )
        coordinates = _coordinates(encoded, binding)
        if coordinates != expected:
            raise CaptureRefused()
        return UnauthenticatedCapture(binding, coordinates)
    except Exception:
        raise CaptureRefused() from None


def export_approved_start(
    reader: OwnerWindowReader, configured_plans: tuple[UUID, ...]
) -> tuple[PublicCapture, ...]:
    """Capture 1–4 selected plans through the existing actual held owner read.

    All selections validate before I/O. Each capture means approved at its own
    read, never a simultaneous batch hold/current-standing assertion. No partial
    result escapes on failure. Delivery and bounded descriptor writes belong to
    the future qualified management adapter, not a caller callback here.
    """
    try:
        if (
            type(reader) is not OwnerWindowReader
            or type(configured_plans) is not tuple
            or not 0 < len(configured_plans) <= MAX_CAPTURE_PLANS
            or any(type(plan) is not UUID for plan in configured_plans)
            or len(set(configured_plans)) != len(configured_plans)
        ):
            raise CaptureRefused()
        reader._open()
        captures: list[PublicCapture] = []
        bindings: list[ApprovedWindowBinding] = []
        for plan_id in configured_plans:
            binding = reader.read("issue", plan_id)
            freshness = binding.expectation.window_freshness
            if freshness is None or binding.expectation.operation.plan_id != str(
                plan_id
            ):
                raise CaptureRefused()
            freshness.require_open()
            captures.append(_encode(binding))
            bindings.append(binding)
        reader._open()
        for binding in bindings:
            freshness = binding.expectation.window_freshness
            if freshness is None:
                raise CaptureRefused()
            freshness.require_open()
        return tuple(captures)
    except Exception:
        raise CaptureRefused() from None
