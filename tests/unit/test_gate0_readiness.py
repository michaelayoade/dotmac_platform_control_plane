"""Synthetic report fixtures; these never constitute protected E evidence."""

import hashlib
import json
from pathlib import Path

import pytest

from vendor_cp.deployment.gate0_readiness import (
    CASE_OUTCOMES,
    Gate0ReportRefused,
    ReportRefusal,
    inspect_case_report,
)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture
def synthetic_report():
    blobs = {name: f"synthetic:{name}".encode() for name in CASE_OUTCOMES}
    document = {
        "schema": "Gate0CaseReport.v1",
        "evidence_class": "synthetic_ci",
        "source_bundle_digest": digest(b"synthetic source bundle"),
        "repository_id": "1",
        "run_id": "2",
        "run_attempt": "1",
        "prerequisites": {
            name: {"state": "unknown", "evidence_digest": None}
            for name in ("B", "C1", "C2", "D")
        },
        "cases": [
            {"case": name, "outcome": outcome, "evidence_digest": digest(blobs[name])}
            for name, outcome in CASE_OUTCOMES.items()
        ],
        "completion": "complete",
    }
    return document, blobs


def inspect(document, blobs):
    return inspect_case_report(
        json.dumps(document).encode(),
        evidence=blobs,
        expected_source_bundle_digest=digest(b"synthetic source bundle"),
        expected_run=("1", "2", "1"),
    )


def test_synthetic_report_preserves_unknowns_and_cannot_be_readiness(synthetic_report):
    document, blobs = synthetic_report
    report = inspect(document, blobs)
    assert report.evidence_class == "synthetic_ci"
    assert report.unknown_prerequisites == ("B", "C1", "C2", "D")
    assert report.readiness_accepted is False


@pytest.mark.parametrize("change", ["omit", "duplicate", "extra", "wrong_outcome"])
def test_case_inventory_is_exact(synthetic_report, change):
    document, blobs = synthetic_report
    if change == "omit":
        document["cases"].pop()
    elif change == "duplicate":
        document["cases"].append(document["cases"][0])
    elif change == "extra":
        document["cases"].append({"case": "invented", "outcome": "refused"})
    else:
        document["cases"][0]["outcome"] = "refused"
    with pytest.raises(Gate0ReportRefused):
        inspect(document, blobs)


@pytest.mark.parametrize("name", ["candidate", "ExecutionGrant", "image_digest"])
def test_candidate_and_authority_fields_refuse(synthetic_report, name):
    document, blobs = synthetic_report
    document[name] = "synthetic"
    with pytest.raises(Gate0ReportRefused) as caught:
        inspect(document, blobs)
    assert caught.value.refusal == ReportRefusal.SHAPE


@pytest.mark.parametrize("where", ["root", "case", "prerequisite"])
def test_duplicate_json_keys_refuse_before_interpretation(synthetic_report, where):
    document, blobs = synthetic_report
    encoded = json.dumps(document)
    if where == "root":
        encoded = encoded.replace('"schema":', '"schema": "ignored", "schema":', 1)
    elif where == "case":
        encoded = encoded.replace('"outcome":', '"outcome": "ignored", "outcome":', 1)
    else:
        encoded = encoded.replace('"state":', '"state": "accepted", "state":', 1)
    with pytest.raises(Gate0ReportRefused) as caught:
        inspect_case_report(
            encoded.encode(),
            evidence=blobs,
            expected_source_bundle_digest=digest(b"synthetic source bundle"),
            expected_run=("1", "2", "1"),
        )
    assert caught.value.refusal == ReportRefusal.MALFORMED


@pytest.mark.parametrize("change", ["tamper", "missing", "extra"])
def test_all_case_bytes_must_match_exact_retained_evidence(synthetic_report, change):
    document, blobs = synthetic_report
    name = next(iter(blobs))
    if change == "tamper":
        blobs[name] += b"altered"
    elif change == "missing":
        del blobs[name]
    else:
        blobs["extra"] = b"extra"
    with pytest.raises(Gate0ReportRefused) as caught:
        inspect(document, blobs)
    assert caught.value.refusal == ReportRefusal.EVIDENCE


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_attempt", "2"),
        ("run_id", "3"),
        ("repository_id", "2"),
        ("source_bundle_digest", "sha256:" + "0" * 64),
    ],
)
def test_cross_attempt_run_repository_and_source_substitution_refuse(
    synthetic_report,
    field,
    value,
):
    document, blobs = synthetic_report
    document[field] = value
    with pytest.raises(Gate0ReportRefused) as caught:
        inspect(document, blobs)
    assert caught.value.refusal == ReportRefusal.BINDING


@pytest.mark.parametrize("completion", ["interrupted", "cancelled", "incomplete", True])
def test_incomplete_results_cannot_be_validated(synthetic_report, completion):
    document, blobs = synthetic_report
    document["completion"] = completion
    with pytest.raises(Gate0ReportRefused) as caught:
        inspect(document, blobs)
    assert caught.value.refusal == ReportRefusal.INCOMPLETE


def test_live_report_without_accepted_prerequisites_refuses(synthetic_report):
    document, blobs = synthetic_report
    document["evidence_class"] = "protected_live"
    with pytest.raises(Gate0ReportRefused) as caught:
        inspect(document, blobs)
    assert caught.value.refusal == ReportRefusal.PREREQUISITES


def test_accepted_prerequisite_requires_digest(synthetic_report):
    document, blobs = synthetic_report
    document["prerequisites"]["B"]["state"] = "accepted"
    with pytest.raises(Gate0ReportRefused):
        inspect(document, blobs)


def test_live_self_asserted_prerequisites_still_cannot_accept_readiness(
    synthetic_report,
):
    document, blobs = synthetic_report
    document["evidence_class"] = "protected_live"
    for prerequisite in document["prerequisites"].values():
        prerequisite.update(state="accepted", evidence_digest=digest(b"unverified"))
    report = inspect(document, blobs)
    assert report.readiness_accepted is False
    assert "receipt_producer_trust" in report.finalization_blockers
    assert "controller_possession_contract" in report.finalization_blockers


@pytest.mark.parametrize("data", [b"{}", b"null", b"[]", b"NaN", b"\xff", b"{" * 1000])
def test_malformed_and_deep_input_refuses(data):
    with pytest.raises(Gate0ReportRefused):
        inspect_case_report(
            data,
            evidence={},
            expected_source_bundle_digest=digest(b"x"),
            expected_run=("1", "2", "1"),
        )


def test_inventory_matches_source_and_does_not_assert_acceptance():
    inventory = json.loads(
        (Path(__file__).parents[2] / "docs/inventories/e-requirements.json").read_text()
    )
    assert {row["case"]: row["outcome"] for row in inventory["cases"]} == CASE_OUTCOMES
    assert all(row["state"] == "unknown" for row in inventory["prerequisites"].values())


# Public-key verification fixtures below use synthetic keys only in hosted CI.
# No fixture is serialized as a production readiness receipt.
def test_report_and_evidence_bounds_refuse(synthetic_report):
    document, blobs = synthetic_report
    with pytest.raises(Gate0ReportRefused):
        inspect_case_report(
            b" " * (128 * 1024 + 1),
            evidence=blobs,
            expected_source_bundle_digest=digest(b"x"),
            expected_run=("1", "2", "1"),
        )
    blobs[next(iter(blobs))] = b"x" * (8 * 1024 * 1024 + 1)
    with pytest.raises(Gate0ReportRefused):
        inspect(document, blobs)


@pytest.fixture
def attester_fixture():
    from datetime import UTC, datetime, timedelta

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from vendor_cp.deployment.gate0_runtime import (
        AttestationContext,
        CompanionAttestation,
        ProtectedHarnessVerifier,
        companion_message,
    )
    from vendor_cp.deployment.rehearsal_issuer_trust_state import (
        RehearsalIssuerTrustState,
    )

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    trust = RehearsalIssuerTrustState.start(
        minimum_version=2,
        read_record=lambda: {
            "version": 2,
            "trusted_key_ids": {"fixture-attester": digest(public)},
            "revoked_key_ids": [],
        },
    )
    now = datetime(2026, 10, 15, tzinfo=UTC)
    context = AttestationContext(
        repository_id="1",
        run_id="2",
        run_attempt="1",
        lease_id="lease-fixture",
        controller_fingerprint="SHA256:" + "A" * 43,
        target_ref="fixture-target",
        plan_id="00000000-0000-0000-0000-000000000001",
        plan_digest=digest(b"frozen plan"),
        plan_purpose="rehearsal_issuer_operation",
        operation="deploy",
        execution_plan_digest=digest(b"issuer operation"),
        certificate_digest=digest(b"synthetic certificate"),
        ca_fingerprint="SHA256:" + "A" * 43,
    )
    owner_document = {
        "schema": "dotmac.deployment_control.rehearsal_harness_evidence",
        "version": 1,
        "lease_id": context.lease_id,
        "controller_fingerprint": context.controller_fingerprint,
        "target_ref": context.target_ref,
        "environment": "rehearsal",
        "issued_at": now.isoformat(),
        "valid_until": (now + timedelta(seconds=60)).isoformat(),
    }
    canonical = json.dumps(
        owner_document, sort_keys=True, separators=(",", ":")
    ).encode()
    message = companion_message(context, canonical)
    companion = CompanionAttestation(message, key.sign(message))
    verifier = ProtectedHarnessVerifier(
        key_id="fixture-attester",
        public_key=public,
        trust_state=trust,
        context=context,
        read_companion=lambda _: companion,
        expires_at=now + timedelta(seconds=120),
        now=lambda: now,
    )
    arguments = dict(
        key_id="fixture-attester",
        algorithm="ed25519",
        purpose="deployment_rehearsal_harness_evidence",
        canonical_bytes=canonical,
        signature=key.sign(canonical),
    )
    return verifier, arguments, key, trust, context, companion


def test_protected_adapter_authenticates_exact_owner_bytes_and_companion(
    attester_fixture,
):
    verifier, arguments, *_ = attester_fixture
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("purpose", "deployment_rehearsal_issuer"),
        ("key_id", "issuer"),
        ("algorithm", "other"),
        ("signature", b"bad"),
    ],
)
def test_protected_adapter_refuses_wrong_identity_and_signature(
    attester_fixture, field, value
):
    verifier, arguments, *_ = attester_fixture
    arguments[field] = value
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("lease_id", "other"),
        ("controller_fingerprint", "SHA256:" + "B" * 43),
        ("target_ref", "other"),
        ("environment", "production"),
    ],
)
def test_valid_attester_signature_cannot_rebind_owner_context(
    attester_fixture, field, value
):
    verifier, arguments, key, *_ = attester_fixture
    document = json.loads(arguments["canonical_bytes"])
    document[field] = value
    arguments["canonical_bytes"] = json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode()
    arguments["signature"] = key.sign(arguments["canonical_bytes"])
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_failed_public_trust_refresh_closes_protected_adapter(attester_fixture):
    from vendor_cp.deployment.rehearsal_issuer_trust_state import TrustStateInstallError

    verifier, arguments, _, trust, *_ = attester_fixture
    with pytest.raises(TrustStateInstallError):
        trust.refresh(read_record=lambda: None)
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_companion_cross_attempt_plan_or_exact_bytes_substitution_refuses(
    attester_fixture,
):
    from dataclasses import replace

    from vendor_cp.deployment.gate0_runtime import (
        CompanionAttestation,
        companion_message,
    )

    verifier, arguments, key, _, context, _ = attester_fixture
    for changed in (
        replace(context, run_attempt="2"),
        replace(context, plan_digest=digest(b"other plan")),
    ):
        message = companion_message(changed, arguments["canonical_bytes"])
        changed_verifier = replace(
            verifier,
            read_companion=lambda _, message=message: CompanionAttestation(
                message, key.sign(message)
            ),
        )
        assert changed_verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_unconfigured_or_failed_transport_never_verifies(attester_fixture):
    verifier, arguments, *_ = attester_fixture
    from dataclasses import replace

    verifier = replace(verifier, read_companion=None)
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_protected_adapter_expiry_refuses(attester_fixture):
    from datetime import UTC, datetime

    verifier, arguments, *_ = attester_fixture
    from dataclasses import replace

    clock = iter(
        [datetime(2026, 10, 15, tzinfo=UTC), datetime(2026, 10, 16, tzinfo=UTC)]
    )
    verifier = replace(verifier, now=lambda: next(clock))
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_startup_refuses_unbounded_window(attester_fixture):
    from dataclasses import replace
    from datetime import timedelta

    verifier, *_ = attester_fixture
    with pytest.raises(ValueError):
        replace(verifier, expires_at=verifier.expires_at + timedelta(days=1))


def test_attester_revocation_closes_adapter(attester_fixture):
    verifier, arguments, _, trust, *_ = attester_fixture
    trust.refresh(
        read_record=lambda: {
            "version": 3,
            "trusted_key_ids": {},
            "revoked_key_ids": ["fixture-attester"],
        }
    )
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_companion_transport_failure_and_bad_signature_refuse(attester_fixture):
    from dataclasses import replace

    from vendor_cp.deployment.gate0_runtime import CompanionAttestation

    verifier, arguments, _, _, _, companion = attester_fixture

    def failed(_):
        raise RuntimeError("synthetic transport failure")

    assert (
        replace(verifier, read_companion=failed).verify_rehearsal_harness_evidence(
            **arguments
        )
        is False
    )
    bad = CompanionAttestation(companion.canonical_bytes, b"0" * 64)
    assert (
        replace(
            verifier, read_companion=lambda _: bad
        ).verify_rehearsal_harness_evidence(**arguments)
        is False
    )


def test_adapter_matches_published_control_verifier_port_and_constants(
    attester_fixture,
):
    import inspect

    from dotmac_deployment_control import RehearsalHarnessEvidenceVerifier
    from dotmac_deployment_control.rehearsal_harness_evidence import (
        REHEARSAL_HARNESS_EVIDENCE_PURPOSE,
        REHEARSAL_HARNESS_EVIDENCE_SCHEMA,
        REHEARSAL_HARNESS_EVIDENCE_VERSION,
    )

    from vendor_cp.deployment.gate0_runtime import ProtectedHarnessVerifier

    _, arguments, *_ = attester_fixture
    document = json.loads(arguments["canonical_bytes"])
    assert document["schema"] == REHEARSAL_HARNESS_EVIDENCE_SCHEMA
    assert document["version"] == REHEARSAL_HARNESS_EVIDENCE_VERSION
    assert arguments["purpose"] == REHEARSAL_HARNESS_EVIDENCE_PURPOSE

    def shape(method):
        return [
            (name, parameter.kind)
            for name, parameter in inspect.signature(method).parameters.items()
        ]

    assert shape(ProtectedHarnessVerifier.verify_rehearsal_harness_evidence) == shape(
        RehearsalHarnessEvidenceVerifier.verify_rehearsal_harness_evidence,
    )


def test_backward_wall_clock_before_startup_refuses(attester_fixture):
    from dataclasses import replace
    from datetime import timedelta

    verifier, arguments, *_ = attester_fixture
    startup = verifier.now()
    wall = [startup]
    verifier = replace(verifier, now=lambda: wall[0], monotonic_clock=lambda: 100.0)
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is True
    wall[0] = startup - timedelta(seconds=1)
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_monotonic_expiry_is_not_extended_by_backward_wall_clock(attester_fixture):
    from dataclasses import replace
    from datetime import timedelta

    verifier, arguments, *_ = attester_fixture
    startup = verifier.now()
    wall = [startup]
    monotonic = [100.0]
    verifier = replace(
        verifier, now=lambda: wall[0], monotonic_clock=lambda: monotonic[0]
    )
    wall[0] = startup + timedelta(seconds=100)
    monotonic[0] = 200.0
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is True
    # Still after startup and before wall expiry, but the fixed elapsed cap expires.
    wall[0] = startup + timedelta(seconds=10)
    monotonic[0] = 220.0
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False
    monotonic[0] = 221.0
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


@pytest.mark.parametrize("advance", ["wall", "monotonic", "backward_wall"])
def test_clock_change_during_lookup_cannot_pass(attester_fixture, advance):
    from dataclasses import replace
    from datetime import timedelta

    verifier, arguments, _, _, _, companion = attester_fixture
    startup = verifier.now()
    wall = [startup]
    monotonic = [100.0]

    def lookup(_):
        if advance == "wall":
            wall[0] = verifier.expires_at
        elif advance == "monotonic":
            monotonic[0] = 220.0
        else:
            wall[0] = startup - timedelta(seconds=1)
        return companion

    verifier = replace(
        verifier,
        now=lambda: wall[0],
        monotonic_clock=lambda: monotonic[0],
        read_companion=lookup,
    )
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), float("-inf"), -1.0, True, "100"]
)
def test_invalid_monotonic_startup_clock_refuses(attester_fixture, value):
    from dataclasses import replace

    verifier, *_ = attester_fixture
    with pytest.raises(ValueError):
        replace(verifier, monotonic_clock=lambda: value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, 99.0, True, "101"])
def test_invalid_monotonic_readback_refuses(attester_fixture, value):
    from dataclasses import replace

    verifier, arguments, *_ = attester_fixture
    monotonic = [100.0]
    verifier = replace(verifier, monotonic_clock=lambda: monotonic[0])
    monotonic[0] = value
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_clock_readback_failure_refuses(attester_fixture):
    from dataclasses import replace

    verifier, arguments, *_ = attester_fixture
    calls = [0]

    def broken_clock():
        calls[0] += 1
        if calls[0] > 1:
            raise RuntimeError("synthetic clock failure")
        return 100.0

    verifier = replace(verifier, monotonic_clock=broken_clock)
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


@pytest.mark.parametrize("clock_value", [None, "2026-10-15", True])
def test_invalid_wall_clock_startup_refuses(attester_fixture, clock_value):
    from dataclasses import replace

    verifier, *_ = attester_fixture
    with pytest.raises(ValueError):
        replace(verifier, now=lambda: clock_value)


def test_naive_wall_clock_readback_refuses(attester_fixture):
    from dataclasses import replace

    verifier, arguments, *_ = attester_fixture
    wall = [verifier.now()]
    verifier = replace(verifier, now=lambda: wall[0])
    wall[0] = wall[0].replace(tzinfo=None)
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False


def test_public_trust_refresh_does_not_reset_monotonic_cap(attester_fixture):
    from dataclasses import replace

    verifier, arguments, _, trust, *_ = attester_fixture
    monotonic = [100.0]
    verifier = replace(verifier, monotonic_clock=lambda: monotonic[0])
    trust.refresh(
        read_record=lambda: {
            "version": 3,
            "trusted_key_ids": {"fixture-attester": digest(verifier.public_key)},
            "revoked_key_ids": [],
        }
    )
    monotonic[0] = 220.0
    assert verifier.verify_rehearsal_harness_evidence(**arguments) is False
