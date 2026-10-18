"""Synthetic capture vectors; authentic management delivery is outside the codec."""

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import monotonic
from types import SimpleNamespace
from uuid import UUID

import pytest

from vendor_cp.deployment.gate0_capture import (
    CaptureCoordinates,
    CaptureRefused,
    UnauthenticatedCapture,
    capture_digest,
    decode_capture,
    export_approved_start,
)
from vendor_cp.deployment.gate0_composition import WindowFreshness
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_window import (
    ApprovedWindowBinding,
    FrozenIssuerWindow,
    OwnerWindowReader,
)
from vendor_cp.deployment.gate0_workload_admission import _FIXED_CLAIMS


@pytest.fixture
def captured(monkeypatch):
    now = datetime.now(UTC)
    fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode().rstrip("=")
    document = {
        "schema": "Gate0IssuerWindow.v1",
        "case_kind": "consume_replay",
        "window_id": "synthetic-capture-window",
        "not_before": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=120)).isoformat().replace("+00:00", "Z"),
        "purpose": "rehearsal_issuer_operation",
        "allowed_phases": ["issue", "consume"],
        "authorization_binding": "control_parsed_full_envelope_v1",
        "github": dict(
            _FIXED_CLAIMS,
            run_id="2",
            run_attempt="1",
            sub="synthetic-subject",
            workflow_sha="a" * 40,
            environment_node_id="synthetic-node",
        ),
        "target": {
            "id": str(UUID(int=2)),
            "ref": "synthetic-target",
            "environment": "rehearsal",
            "operation": "deploy",
        },
        "approval_policy": {"code": "synthetic-policy", "version": 1},
        "plan_inputs": {
            "source_ref": "synthetic-source",
            "config_ref": "synthetic-config",
            "descriptor_digest": "sha256:" + "1" * 64,
            "execution_plan_digest": "sha256:" + "2" * 64,
        },
        "controller": {
            "lease_id": "synthetic-lease",
            "fingerprint": fingerprint,
            "certificate_digest": "sha256:" + "3" * 64,
            "ca_fingerprint": fingerprint,
            "principal": "dotmac-gate0-controller",
            "certificate_ttl_ceiling_seconds": 600,
        },
        "prerequisite_evidence_refs": ["sha256:" + "4" * 64],
    }
    target = SimpleNamespace(
        id=UUID(int=2), target_ref="synthetic-target", environment="rehearsal"
    )
    plan = SimpleNamespace(
        id=UUID(int=1),
        target_id=target.id,
        purpose="rehearsal_issuer_operation",
        operation="deploy",
        plan_digest="sha256:" + "5" * 64,
        descriptor_digest=document["plan_inputs"]["descriptor_digest"],
        execution_plan_digest=document["plan_inputs"]["execution_plan_digest"],
        approval_policy_code="synthetic-policy",
        approval_policy_version=1,
        requires_approval=True,
        approval_decision_ref=str(UUID(int=3)),
        snapshot={
            "spec": {"gate0_window_v1": document},
            "plan_purpose": "rehearsal_issuer_operation",
            "target_ref": target.target_ref,
            "environment": "rehearsal",
        },
    )
    window = FrozenIssuerWindow.parse(canonical(document))
    origin = monotonic()
    expected = window.expectation(
        plan, target, "issue", freshness=WindowFreshness(origin, origin + 120)
    )
    binding = ApprovedWindowBinding(
        expected, window, plan.descriptor_digest, ("sha256:" + "6" * 64,)
    )
    calls = []

    # Exact concrete type, but explicit synthetic method patches isolate codec
    # behavior. Actual owner/hold/withdrawal is covered in the migration suite.
    reader = object.__new__(OwnerWindowReader)
    monkeypatch.setattr(OwnerWindowReader, "_open", lambda self: None)

    def read(self, phase, plan_id, authorization_document=None):
        calls.append((phase, plan_id, authorization_document))
        return binding

    monkeypatch.setattr(OwnerWindowReader, "read", read)
    packet = export_approved_start(reader, (plan.id,))[0]
    return reader, binding, packet, calls


def test_roundtrip_preserves_owner_terms_without_portable_freshness(captured):
    _, binding, packet, calls = captured
    decoded = decode_capture(packet.encoded, expected=packet.coordinates)
    assert type(decoded) is UnauthenticatedCapture
    assert decoded.binding == replace(
        binding, expectation=replace(binding.expectation, window_freshness=None)
    )
    assert decoded.binding.expectation.window_freshness is None
    assert decoded.coordinates == packet.coordinates
    assert calls == [("issue", UUID(int=1), None)]
    assert packet.coordinates.capture_digest == capture_digest(packet.encoded)
    document = json.loads(packet.encoded)
    assert canonical(document) == packet.encoded
    assert packet.encoded.isascii()
    assert not {
        "window_freshness",
        "origin",
        "deadline",
        "token",
        "runtime",
        "callback",
    } & set(document)
    assert (
        base64.b64decode(document["frozen_window_b64"])
        == binding.window.canonical_bytes
    )
    assert decoded.binding.authorized_image_digests == binding.authorized_image_digests


@pytest.mark.parametrize(
    "field,value",
    [
        ("capture_digest", "sha256:" + "a" * 64),
        ("window_digest", "sha256:" + "a" * 64),
        ("plan_digest", "sha256:" + "a" * 64),
        ("plan_id", UUID(int=99)),
        ("target_id", UUID(int=99)),
        ("approval_request_id", UUID(int=99)),
    ],
)
def test_whole_capture_and_each_independent_coordinate_must_match(
    captured, field, value
):
    _, _, packet, _ = captured
    with pytest.raises(CaptureRefused, match="^gate0_capture_refused$"):
        decode_capture(
            packet.encoded, expected=replace(packet.coordinates, **{field: value})
        )


def test_missing_independent_coordinates_never_self_authenticate(captured):
    _, _, packet, _ = captured
    with pytest.raises(CaptureRefused):
        decode_capture(packet.encoded)
    with pytest.raises(CaptureRefused):
        decode_capture(packet.encoded, expected=object())


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "schema",
        "clock",
        "runtime",
        "base64",
        "window-digest",
        "plan-id",
        "plan-digest",
        "target",
        "policy-code",
        "policy-bool",
        "descriptor",
        "images-shape",
        "image-digest",
        "images-bound",
        "operation-extra",
        "operation-type",
        "consume",
        "future-authorization",
        "window-extra",
    ],
)
def test_rehashed_malformed_or_internally_substituted_capture_refuses(captured, change):
    _, _, packet, _ = captured
    value = json.loads(packet.encoded)
    if change == "unknown":
        value["approved"] = True
    elif change == "schema":
        value["schema"] = "other"
    elif change == "clock":
        value["window_freshness"] = {"origin": 1, "deadline": 999}
    elif change == "runtime":
        value["runtime"] = "caller-provider"
    elif change == "base64":
        value["frozen_window_b64"] += "="
    elif change == "window-digest":
        value["window_digest"] = "sha256:" + "a" * 64
    elif change == "plan-id":
        value["operation"]["plan_id"] = str(UUID(int=99))
    elif change == "plan-digest":
        value["operation"]["plan_digest"] = "sha256:" + "a" * 64
    elif change == "target":
        value["target_id"] = str(UUID(int=99))
    elif change == "policy-code":
        value["approval_policy_code"] = "substitute"
    elif change == "policy-bool":
        value["approval_policy_version"] = True
    elif change == "descriptor":
        value["descriptor_digest"] = "sha256:" + "a" * 64
    elif change == "images-shape":
        value["authorized_image_digests"] = {}
    elif change == "image-digest":
        value["authorized_image_digests"] = [123]
    elif change == "images-bound":
        value["authorized_image_digests"] *= 65
    elif change == "operation-extra":
        value["operation"]["token"] = "sensitive-canary"
    elif change == "operation-type":
        value["operation"]["repository_id"] = 1397614140
    elif change == "consume":
        value["operation"]["phase"] = "consume"
    elif change == "future-authorization":
        value["operation"]["authorization_digest"] = "sha256:" + "a" * 64
    else:
        window = json.loads(base64.b64decode(value["frozen_window_b64"]))
        window["approved"] = True
        value["frozen_window_b64"] = base64.b64encode(canonical(window)).decode()
    raw = canonical(value)
    # Update the external whole hash deliberately: these assertions must reach
    # shape/duplicate/owner-binding checks, not pass only by hash mismatch.
    with pytest.raises(CaptureRefused, match="^gate0_capture_refused$"):
        decode_capture(
            raw,
            expected=replace(packet.coordinates, capture_digest=capture_digest(raw)),
        )


@pytest.mark.parametrize(
    "kind", ["whitespace", "duplicate", "nested-duplicate", "non-ascii", "oversize"]
)
def test_exact_bounded_canonical_ascii_transport(captured, kind):
    _, _, packet, _ = captured
    if kind == "whitespace":
        raw = packet.encoded + b"\n"
    elif kind == "duplicate":
        raw = packet.encoded.replace(
            b'{"approval_policy_code":',
            b'{"schema":"duplicate","approval_policy_code":',
            1,
        )
    elif kind == "nested-duplicate":
        raw = packet.encoded.replace(
            b'"phase":"issue"', b'"phase":"issue","phase":"issue"', 1
        )
    elif kind == "non-ascii":
        raw = packet.encoded.replace(b"synthetic-lease", "synthétique-lease".encode())
    else:
        raw = b" " * 65537
    with pytest.raises(CaptureRefused):
        decode_capture(
            raw,
            expected=replace(
                packet.coordinates,
                capture_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            ),
        )


@pytest.mark.parametrize(
    "selection",
    [
        (),
        (UUID(int=1),) * 2,
        tuple(UUID(int=i) for i in range(1, 6)),
        ("caller-id",),
        [UUID(int=1)],
    ],
)
def test_export_validates_complete_configured_selection_before_owner_read(
    captured, selection
):
    reader, _, _, calls = captured
    calls.clear()
    with pytest.raises(CaptureRefused):
        export_approved_start(reader, selection)
    assert calls == []


def test_export_rejects_generic_provider_callback_and_wrong_owner_plan(
    captured, monkeypatch
):
    reader, binding, _, calls = captured
    with pytest.raises(CaptureRefused):
        export_approved_start(lambda: binding, (UUID(int=1),))
    calls.clear()
    with pytest.raises(CaptureRefused):
        export_approved_start(reader, (UUID(int=99),))
    assert calls == [("issue", UUID(int=99), None)]


def test_export_original_freshness_is_checked_after_owner_read(captured, monkeypatch):
    reader, binding, _, _ = captured
    expired = replace(
        binding,
        expectation=replace(
            binding.expectation, window_freshness=WindowFreshness(1.0, 2.0)
        ),
    )
    monkeypatch.setattr(OwnerWindowReader, "read", lambda *args: expired)
    with pytest.raises(CaptureRefused):
        export_approved_start(reader, (UUID(int=1),))


def test_coordinates_types_are_closed(captured):
    _, _, packet, _ = captured
    with pytest.raises(CaptureRefused):
        replace(packet.coordinates, plan_id=str(UUID(int=1)))
    with pytest.raises(CaptureRefused):
        replace(packet.coordinates, capture_digest="not-a-digest")
    assert type(packet.coordinates) is CaptureCoordinates


def test_complete_four_plan_export_and_all_or_nothing_failure(captured, monkeypatch):
    reader, binding, _, calls = captured
    plans = tuple(UUID(int=i) for i in range(1, 5))
    calls.clear()

    def read(self, phase, plan_id):
        calls.append((phase, plan_id))
        return replace(
            binding,
            expectation=replace(
                binding.expectation,
                operation=replace(binding.expectation.operation, plan_id=str(plan_id)),
            ),
        )

    monkeypatch.setattr(OwnerWindowReader, "read", read)
    packets = export_approved_start(reader, plans)
    assert tuple(p.coordinates.plan_id for p in packets) == plans
    assert calls == [("issue", plan) for plan in plans]
    assert len({p.coordinates.capture_digest for p in packets}) == 4
    assert all(
        decode_capture(
            p.encoded, expected=p.coordinates
        ).binding.expectation.window_freshness
        is None
        for p in packets
    )
    calls.clear()

    def partial_failure(self, phase, plan_id):
        calls.append(plan_id)
        if plan_id == plans[1]:
            raise ValueError("synthetic-sensitive-owner-diagnostic")
        return binding

    monkeypatch.setattr(OwnerWindowReader, "read", partial_failure)
    with pytest.raises(CaptureRefused, match="^gate0_capture_refused$") as refused:
        export_approved_start(reader, plans)
    assert refused.value.__suppress_context__
    assert calls == list(plans[:2])


def test_valid_image_substitution_is_bound_by_whole_capture_digest(captured):
    _, _, packet, _ = captured
    value = json.loads(packet.encoded)
    value["authorized_image_digests"] = ["sha256:" + "a" * 64]
    with pytest.raises(CaptureRefused):
        decode_capture(canonical(value), expected=packet.coordinates)


@pytest.mark.parametrize("count", [0, 64])
def test_declared_empty_and_maximum_ordered_image_lists_roundtrip(
    captured, monkeypatch, count
):
    reader, binding, _, _ = captured
    images = tuple("sha256:" + f"{index:064x}" for index in range(count))
    changed = replace(binding, authorized_image_digests=images)
    monkeypatch.setattr(OwnerWindowReader, "read", lambda *args: changed)
    packet = export_approved_start(reader, (UUID(int=1),))[0]
    assert (
        decode_capture(
            packet.encoded, expected=packet.coordinates
        ).binding.authorized_image_digests
        == images
    )
