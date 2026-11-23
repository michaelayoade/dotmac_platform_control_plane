"""CP-3 / CP-7 / CP-5: `lane3_e10` against REAL Control a17 on real PostgreSQL.

The enrolment, rotation, revocation and recovery run through Control's own
`attestation_trust_registry` (`enrol_root` / `rotate_root` / `revoke_root`); the
host binding and the host-admission credential through Control's services and the
Kernel's `verify_possession`. Nothing here stands in for Control.

Control a17 facts these tests pin: `enrol_root` / `rotate_root` take no PoP and no
nonce (the CP command verifies possession BEFORE calling Control, and a failed PoP
leaves no row anywhere), `rotate_root` works only while the prior root is current,
and `enrol_root` is the recovery path after `revoke_root`.

The installed-attestation (I(D)) tests need Foundation and are gated like the lease
suite: skipped in the ordinary step, a failure under `LANE3_REQUIRE_FOUNDATION=1`.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import sys
import uuid
from datetime import UTC, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.deployment import lane3_e10 as e10


def _support() -> Any:
    name = "lane3_cp_support"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "unit" / "lane3_cp_support.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = _support()
NONCE = bytes(range(32))
NOT_AFTER = "2031-01-01T00:00:00Z"


def _foundation_or_skip() -> None:
    try:
        import dotmac_deployment_foundation.trusted_host_source  # noqa: F401
    except ImportError:
        if os.environ.get("LANE3_REQUIRE_FOUNDATION") == "1":
            raise
        pytest.skip("Foundation is not importable; the dedicated Lane 3 step runs this")


@pytest.fixture
def case(lane3_cases: Any) -> Any:
    return lane3_cases.new()


@pytest.fixture
def db(case: Any) -> Any:
    with Session(case.admin) as session:
        yield session


def _key(seed: str) -> Any:
    return SUPPORT.TransitKey(hashlib.sha256(seed.encode()).digest())


def _request(host: str, n: int, key: Any, **override: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "host_id": host,
        "vm_alias": f"vm-{host}",
        "vm_slot": "node-a/102",
        "machine_id": hashlib.sha256(host.encode()).hexdigest()[:32],
        "ssh_host_key_fingerprint": "SHA256:" + "B" * 43,
        "mount": f"transit-a2-hi-vm-{host}-{n}",
        "transit_key": key.read_back(),
        "pop_signature": key.sign(e10.incarnation_pop_message(host, NONCE)),
        "nonce": base64.urlsafe_b64encode(NONCE).decode().rstrip("="),
        "issuer": "urn:dotmac:foundation:installed-host-ceremony:a2",
        "attestation_key_id": f"incarnation-{host}-{n}",
        "not_after": NOT_AFTER,
        "recorded_by": "operator",
    }
    request.update(override)
    return request


def _enrol(db: Session, host: str, n: int, seed: str | None = None) -> Any:
    outcome = e10.enrol_incarnation(
        db, e10.ControlRegistry(), _request(host, n, _key(seed or f"{host}-{n}"))
    )
    db.commit()
    return outcome


def _count(db: Session, sql: str) -> int:
    return int(db.execute(text(sql)).scalar_one())


# ── enrol, rotate, revoke, recover ──────────────────────────────────────────


def test_the_first_enrolment_writes_controls_root_and_the_receipt_together(
    db: Session,
) -> None:
    outcome = _enrol(db, "host-a", 1)
    receipt = e10._receipt_row(db, outcome.receipt_ref)
    enrolment = (
        db.execute(
            text(
                "SELECT e.custody_domain, e.subject, e.public_key_fingerprint, "
                "e.key_custody_pointer, e.algorithm, e.supersedes_fingerprint, d.issuer, "
                "d.evidence_purpose, d.not_after FROM mod_deploy.attestation_enrolments e "
                "JOIN mod_deploy.attestation_root_descriptors d ON d.enrolment_id = e.id "
                "WHERE e.id = CAST(:id AS uuid)"
            ),
            {"id": outcome.enrolment_uuid},
        )
        .mappings()
        .one()
    )
    assert enrolment["custody_domain"] == "host_attester"
    assert enrolment["subject"] == "host-a" == receipt["host_id"]
    assert enrolment["public_key_fingerprint"] == receipt["incarnation_fingerprint"]
    assert enrolment["public_key_fingerprint"] == outcome.fingerprint
    assert enrolment["key_custody_pointer"] == receipt["key_custody_pointer"]
    assert (
        enrolment["key_custody_pointer"]
        == "bao://transit-a2-hi-vm-host-a-1/keys/incarnation"
    )
    assert enrolment["algorithm"] == "ed25519"
    assert enrolment["supersedes_fingerprint"] is None
    assert enrolment["evidence_purpose"] == "dotmac.foundation.installed-host.v2"
    assert receipt["enrolment_uuid"] == outcome.enrolment_uuid
    assert receipt["vm_slot"] == "node-a/102"
    assert outcome.receipt_ref.startswith("e10-")


def test_the_printed_digest_is_the_one_rule_over_the_row_as_exported(
    db: Session,
) -> None:
    outcome = _enrol(db, "host-a", 1)
    row = e10._receipt_row(db, outcome.receipt_ref)
    assert outcome.receipt_digest == e10.receipt_digest(row)
    assert row["recorded_at"].endswith("Z") and "." in row["recorded_at"]
    shown = e10.show(db, receipt_ref=outcome.receipt_ref)
    assert shown["receipt_digest"] == outcome.receipt_digest
    assert shown["destroyed_at"] is None
    assert (
        set(shown["receipt_step3"]) == set(e10.STEP3_KEYS) and len(e10.STEP3_KEYS) == 9
    )


def test_a_second_incarnation_rotates_the_current_root_and_closes_the_first(
    db: Session,
) -> None:
    first = _enrol(db, "host-a", 1)
    second = _enrol(db, "host-a", 2)
    current = db.execute(
        text(
            "SELECT current_fingerprint FROM mod_deploy.attestation_current_roots "
            "WHERE custody_domain = 'host_attester' AND subject = 'host-a'"
        )
    ).scalar_one()
    assert current == second.fingerprint
    superseded = db.execute(
        text(
            "SELECT supersedes_fingerprint FROM mod_deploy.attestation_enrolments "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {"id": second.enrolment_uuid},
    ).scalar_one()
    assert superseded == first.fingerprint
    assert e10.root_document(db, enrolment_uuid=first.enrolment_uuid)["revoked"] is True
    assert (
        e10.root_document(db, enrolment_uuid=second.enrolment_uuid)["revoked"] is False
    )


def test_revoke_is_permanent_and_enrol_root_is_the_recovery_after_it(
    db: Session,
) -> None:
    first = _enrol(db, "host-a", 1)
    fingerprint = e10.revoke_incarnation(
        db, e10.ControlRegistry(), receipt_ref=first.receipt_ref
    )
    db.commit()
    assert fingerprint == first.fingerprint
    assert _count(db, "SELECT count(*) FROM mod_deploy.attestation_current_roots") == 0
    assert e10.root_document(db, enrolment_uuid=first.enrolment_uuid)["revoked"] is True
    # A second revoke of the same fingerprint is refused by Control, never repeated.
    with pytest.raises(e10.E10Refused) as refused:
        e10.revoke_incarnation(db, e10.ControlRegistry(), receipt_ref=first.receipt_ref)
    assert refused.value.code.startswith("control-attestation_fingerprint_revoked")
    db.rollback()
    # Recovery: with no current root the registry takes a fresh enrolment.
    recovered = _enrol(db, "host-a", 2)
    assert (
        e10.root_document(db, enrolment_uuid=recovered.enrolment_uuid)["revoked"]
        is False
    )
    current = db.execute(
        text("SELECT current_fingerprint FROM mod_deploy.attestation_current_roots")
    ).scalar_one()
    assert current == recovered.fingerprint


def test_a_fingerprint_enrols_once_globally_and_a_revoked_one_never_again(
    db: Session,
) -> None:
    first = _enrol(db, "host-a", 1, seed="shared")
    with pytest.raises(e10.E10Refused) as refused:
        e10.enrol_incarnation(
            db, e10.ControlRegistry(), _request("host-b", 1, _key("shared"))
        )
    assert refused.value.code == "control-attestation_fingerprint_already_enrolled"
    db.rollback()
    e10.revoke_incarnation(db, e10.ControlRegistry(), receipt_ref=first.receipt_ref)
    db.commit()
    with pytest.raises(e10.E10Refused):
        e10.enrol_incarnation(
            db, e10.ControlRegistry(), _request("host-a", 2, _key("shared"))
        )
    db.rollback()
    assert _count(db, "SELECT count(*) FROM cp_lane3.e10_receipts") == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r, k: {"pop_signature": k.sign(b"some other message")},
        lambda r, k: {
            "pop_signature": _key("another").sign(
                e10.incarnation_pop_message(r["host_id"], NONCE)
            )
        },
        lambda r, k: {"transit_key": k.read_back(exportable=True)},
        lambda r, k: {"transit_key": k.read_back(allow_plaintext_backup=True)},
    ],
)
def test_a_refused_request_leaves_nothing_in_control_or_in_the_receipts(
    db: Session, mutate: Any
) -> None:
    key = _key("host-a-1")
    request = _request("host-a", 1, key)
    request.update(mutate(request, key))
    with pytest.raises(e10.E10Refused):
        e10.enrol_incarnation(db, e10.ControlRegistry(), request)
    db.rollback()
    assert _count(db, "SELECT count(*) FROM mod_deploy.attestation_enrolments") == 0
    assert _count(db, "SELECT count(*) FROM cp_lane3.e10_receipts") == 0


def test_a_registry_that_disagrees_about_the_fingerprint_writes_no_receipt(
    db: Session,
) -> None:
    class _Lying(e10.ControlRegistry):
        def enrol(self, db: Any, **kw: Any) -> Any:
            real = super().enrol(db, **kw)
            return e10.RegistryEnrolment(
                real.enrolment_uuid, "sha256:" + "0" * 64, real.enrolled_at
            )

    with pytest.raises(e10.E10Refused) as refused:
        e10.enrol_incarnation(db, _Lying(), _request("host-a", 1, _key("host-a-1")))
    assert refused.value.code == "registry-fingerprint-disagrees"
    db.rollback()
    assert _count(db, "SELECT count(*) FROM cp_lane3.e10_receipts") == 0


def test_instants_are_the_database_clock_not_the_commands(
    case: Any, db: Session
) -> None:
    outcome = _enrol(db, "host-a", 1)
    enrolled = db.execute(
        text(
            "SELECT enrolled_at FROM mod_deploy.attestation_enrolments "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {"id": outcome.enrolment_uuid},
    ).scalar_one()
    assert enrolled == case.now()


# ── destruction ─────────────────────────────────────────────────────────────


def _destroy_only(db: Session, receipt_ref: str, **override: Any) -> Any:
    request = {
        "receipt_ref": receipt_ref,
        "evidence_digest": "sha256:" + hashlib.sha256(receipt_ref.encode()).hexdigest(),
        "recorded_by": "operator",
        "installed": None,
    }
    request.update(override)
    destroyed = e10.record_destruction(db, request)
    db.commit()
    return destroyed


def test_a_destroy_only_incarnation_is_stamped_with_database_time(
    case: Any, db: Session
) -> None:
    outcome = _enrol(db, "host-a", 1)
    destroyed = _destroy_only(db, outcome.receipt_ref)
    assert destroyed == case.now()
    row = db.execute(
        text(
            "SELECT dispatch_id, installed_attestation_digest, route FROM "
            "cp_lane3.e10_destructions WHERE receipt_ref = :r"
        ),
        {"r": outcome.receipt_ref},
    ).one()
    assert row == (None, None, "transit_mount_disabled")
    assert e10.show(db, receipt_ref=outcome.receipt_ref)[
        "destroyed_at"
    ] == e10.format_time(destroyed)


def test_a_receipt_is_destroyed_at_most_once(db: Session) -> None:
    outcome = _enrol(db, "host-a", 1)
    _destroy_only(db, outcome.receipt_ref)
    with pytest.raises(IntegrityError):
        _destroy_only(db, outcome.receipt_ref, evidence_digest="sha256:" + "9" * 64)
    db.rollback()


@pytest.mark.parametrize(
    ("override", "code"),
    [
        (
            {"receipt_ref": "e10-00000000-0000-0000-0000-000000000000"},
            "receipt-unknown",
        ),
        ({"receipt_ref": "not-a-ref"}, "receipt-ref-invalid"),
        ({"evidence_digest": "sha256:short"}, "evidence-digest-invalid"),
        ({"recorded_by": "two words"}, "recorded-by-invalid"),
    ],
)
def test_a_malformed_destruction_request_is_refused_before_any_write(
    db: Session, override: dict[str, Any], code: str
) -> None:
    outcome = _enrol(db, "host-a", 1)
    request = {
        "receipt_ref": outcome.receipt_ref,
        "evidence_digest": "sha256:" + "a" * 64,
        "recorded_by": "operator",
        "installed": None,
    }
    request.update(override)
    with pytest.raises(e10.E10Refused) as refused:
        e10.record_destruction(db, request)
    assert refused.value.code == code
    db.rollback()
    assert _count(db, "SELECT count(*) FROM cp_lane3.e10_destructions") == 0


def _installed(
    receipt: dict[str, Any], key: Any, dispatch_id: str, **override: Any
) -> dict[str, Any]:
    """A signed I(D) over the receipt's incarnation, built with the VENDORED classes
    (the same ones step 8 verifies with), so it needs no Foundation."""
    from vendor_cp.vendored_foundation.trusted_host_source import (
        ATTESTATION_SCHEMA,
        INSTALLED_OBSERVATION_PURPOSE,
        AttestationEnvelopeV2,
    )

    fields: dict[str, Any] = {
        "schema": ATTESTATION_SCHEMA,
        "purpose": INSTALLED_OBSERVATION_PURPOSE,
        "issuer": "urn:dotmac:foundation:installed-host-ceremony:a2",
        "key_id": "incarnation-1",
        "algorithm": "ed25519",
        "public_key_fingerprint": receipt["incarnation_fingerprint"],
        "custody_domain": "host_attester",
        "trust_root_version": receipt["enrolment_uuid"],
        "issued_at": "2026-11-19T10:00:00Z",
        "expires_at": "2031-01-01T00:00:00Z",
        "audience": receipt["host_id"],
        "observation_id": dispatch_id,
        "subject": {"host_identity": receipt["host_id"]},
        "signature": "AAAA",
    }
    fields.update(override)
    unsigned = AttestationEnvelopeV2(**fields)
    signature = key._key.sign(unsigned.signed_bytes())
    fields["signature"] = base64.b64encode(signature).decode("ascii")
    return fields


def _dispatch_row(db: Session, dispatch_id: str) -> None:
    from dotmac_deployment_control.models import RolloutAttempt

    db.execute(text("SET LOCAL session_replication_role = replica"))
    db.add(
        RolloutAttempt(
            id=uuid.UUID(dispatch_id),
            rollout_id=uuid.uuid4(),
            attempt_no=1,
            dispatch_envelope={"statement": {}, "signature": "x"},
        )
    )
    db.flush()
    db.execute(text("SET LOCAL session_replication_role = origin"))
    db.commit()


def test_an_installed_attestation_is_verified_then_its_dispatch_and_digest_recorded(
    db: Session,
) -> None:
    _foundation_or_skip()
    from dotmac_deployment_foundation.trusted_host_source import (
        AttestationEnvelopeV2,
        attestation_envelope_digest,
    )

    key = _key("host-a-1")
    outcome = _enrol(db, "host-a", 1, seed="host-a-1")
    receipt = e10._receipt_row(db, outcome.receipt_ref)
    dispatch_id = str(uuid.uuid4())
    _dispatch_row(db, dispatch_id)
    installed = _installed(receipt, key, dispatch_id)
    _destroy_only(db, outcome.receipt_ref, installed=installed)
    row = db.execute(
        text(
            "SELECT dispatch_id::text, installed_attestation_digest FROM "
            "cp_lane3.e10_destructions WHERE receipt_ref = :r"
        ),
        {"r": outcome.receipt_ref},
    ).one()
    assert row[0] == dispatch_id
    assert row[1] == str(
        attestation_envelope_digest(AttestationEnvelopeV2.from_mapping(installed))
    )


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"audience": "host-z"}, "installed-attestation-not-this-incarnation"),
        (
            {"custody_domain": "candidate_release_signer"},
            "installed-attestation-not-this-incarnation",
        ),
        (
            {"public_key_fingerprint": "sha256:" + "0" * 64},
            "installed-attestation-not-this-incarnation",
        ),
        (
            {"trust_root_version": str(uuid.uuid4())},
            "installed-attestation-not-this-incarnation",
        ),
        (
            {"purpose": "dotmac.foundation.candidate-artifact.v2"},
            "installed-attestation-purpose",
        ),
        (
            {
                "issued_at": "2020-01-01T00:00:00Z",
                "expires_at": "2020-01-02T00:00:00Z",
            },
            "installed-attestation-expired",
        ),
        ({"observation_id": "not-a-uuid"}, "installed-attestation-observation"),
        ({"observation_id": str(uuid.uuid4())}, "dispatch-unknown"),
        (
            {"signature": base64.b64encode(bytes(64)).decode()},
            "installed-attestation-signature",
        ),
    ],
)
def test_an_installed_attestation_that_is_not_this_incarnations_is_refused(
    db: Session, override: dict[str, Any], code: str
) -> None:
    _foundation_or_skip()
    key = _key("host-a-1")
    outcome = _enrol(db, "host-a", 1, seed="host-a-1")
    receipt = e10._receipt_row(db, outcome.receipt_ref)
    dispatch_id = str(uuid.uuid4())
    _dispatch_row(db, dispatch_id)
    signed = {k: v for k, v in override.items() if k != "signature"}
    installed = _installed(receipt, key, dispatch_id, **signed)
    if "signature" in override:
        installed["signature"] = override["signature"]
    with pytest.raises(e10.E10Refused) as refused:
        e10.record_destruction(
            db,
            {
                "receipt_ref": outcome.receipt_ref,
                "evidence_digest": "sha256:" + "b" * 64,
                "recorded_by": "operator",
                "installed": installed,
            },
        )
    assert refused.value.code == code
    db.rollback()
    assert _count(db, "SELECT count(*) FROM cp_lane3.e10_destructions") == 0


def test_h1_step_eight_runs_with_foundation_off_the_import_path(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H1 (ruled 2026-11-19): step 8 uses the vendored verifier, so with Foundation
    off the import path, as in the image, a valid installed attestation is still
    verified and recorded, and a forged one is still refused with nothing written."""
    outcome = _enrol(db, "host-a", 1, seed="host-a-1")
    receipt = e10._receipt_row(db, outcome.receipt_ref)
    dispatch_id = str(uuid.uuid4())
    _dispatch_row(db, dispatch_id)
    # `None` in `sys.modules` makes every import of the name raise ImportError,
    # whether or not the real package is installed in this environment.
    for name in (
        "dotmac_deployment_foundation",
        "dotmac_deployment_foundation.errors",
        "dotmac_deployment_foundation.trusted_host_source",
    ):
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(ImportError):
        import dotmac_deployment_foundation.errors  # noqa: F401
    forged = _installed(receipt, _key("someone-else"), dispatch_id)
    with pytest.raises(e10.E10Refused) as refused:
        _destroy_only(db, outcome.receipt_ref, installed=forged)
    assert refused.value.code == "installed-attestation-signature"
    db.rollback()
    assert _count(db, "SELECT count(*) FROM cp_lane3.e10_destructions") == 0
    installed = _installed(receipt, _key("host-a-1"), dispatch_id)
    assert _destroy_only(db, outcome.receipt_ref, installed=installed) is not None
    assert (
        _count(
            db,
            "SELECT count(*) FROM cp_lane3.e10_destructions "
            "WHERE installed_attestation_digest IS NOT NULL",
        )
        == 1
    )


def test_an_installed_attestation_signed_by_another_key_is_refused(db: Session) -> None:
    _foundation_or_skip()
    outcome = _enrol(db, "host-a", 1, seed="host-a-1")
    receipt = e10._receipt_row(db, outcome.receipt_ref)
    dispatch_id = str(uuid.uuid4())
    _dispatch_row(db, dispatch_id)
    installed = _installed(receipt, _key("someone-else"), dispatch_id)
    with pytest.raises(e10.E10Refused) as refused:
        e10.record_destruction(
            db,
            {
                "receipt_ref": outcome.receipt_ref,
                "evidence_digest": "sha256:" + "b" * 64,
                "recorded_by": "operator",
                "installed": installed,
            },
        )
    assert refused.value.code == "installed-attestation-signature"
    db.rollback()


# ── the roots, in Foundation's shape ────────────────────────────────────────


def test_the_installed_root_is_foundations_trust_root_shape(db: Session) -> None:
    _foundation_or_skip()
    from dotmac_deployment_foundation.trusted_host_source import AttestationTrustRootV2

    outcome = _enrol(db, "host-a", 1)
    document = e10.root_document(db, enrolment_uuid=outcome.enrolment_uuid)
    assert set(document) == {
        "public_key_fingerprint",
        "public_key_base64",
        "issuer",
        "key_id",
        "purpose",
        "custody_domain",
        "algorithm",
        "trust_root_version",
        "not_before",
        "not_after",
        "revoked",
    }
    root = AttestationTrustRootV2(**document)
    assert root.revoked is False and root.custody_domain == "host_attester"
    assert root.trust_root_version == outcome.enrolment_uuid
    row = db.execute(
        text(
            "SELECT enrolled_at FROM mod_deploy.attestation_enrolments WHERE id = CAST(:i AS uuid)"
        ),
        {"i": outcome.enrolment_uuid},
    ).scalar_one()
    assert document["not_before"] == e10.format_time(row)  # not_before = enrolled_at
    assert base64.b64decode(document["public_key_base64"], validate=True)
    assert (
        "="
        not in e10.show(db, receipt_ref=outcome.receipt_ref)["receipt"][
            "incarnation_public_key_b64url"
        ]
    )


# ── the candidate root (Q5-B) ───────────────────────────────────────────────

CANDIDATE_POINTER = "bao://transit-a2-candidate/keys/candidate-release-v1"


def _candidate_request(subject: str, key: Any, **override: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "subject": subject,
        "transit_key": key.read_back(),
        "pop_signature": key.sign(e10.candidate_pop_message(subject, NONCE)),
        "nonce": base64.urlsafe_b64encode(NONCE).decode().rstrip("="),
        "issuer": "urn:dotmac:foundation:candidate-release-ceremony:a2",
        "attestation_key_id": "candidate-release-v1",
        "not_after": NOT_AFTER,
    }
    request.update(override)
    return request


def test_the_candidate_root_has_the_truthful_pointer_and_the_ceremony_issuer(
    db: Session,
) -> None:
    key = _key("candidate")
    enrolled = e10.enrol_candidate_root(
        db, e10.ControlRegistry(), _candidate_request("candidate-subject", key)
    )
    db.commit()
    row = (
        db.execute(
            text(
                "SELECT e.custody_domain, e.subject, e.key_custody_pointer, d.issuer, "
                "d.evidence_purpose FROM mod_deploy.attestation_enrolments e JOIN "
                "mod_deploy.attestation_root_descriptors d ON d.enrolment_id = e.id "
                "WHERE e.id = CAST(:i AS uuid)"
            ),
            {"i": enrolled.enrolment_uuid},
        )
        .mappings()
        .one()
    )
    assert row["custody_domain"] == "candidate_release_signer"
    assert row["subject"] == "candidate-subject"
    assert row["key_custody_pointer"] == CANDIDATE_POINTER == e10.CANDIDATE_POINTER
    assert row["issuer"] == "urn:dotmac:foundation:candidate-release-ceremony:a2"
    assert row["evidence_purpose"] == "dotmac.foundation.candidate-artifact.v2"
    document = e10.root_document(db, enrolment_uuid=enrolled.enrolment_uuid)
    assert (
        document["revoked"] is False
        and document["custody_domain"] == "candidate_release_signer"
    )


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"issuer": "https://github.com/dotmac/workflow"}, "issuer-invalid"),
        (
            {"issuer": "urn:dotmac:foundation:installed-host-ceremony:a2"},
            "issuer-invalid",
        ),
        (
            {"pop_signature": "vault:v1:" + base64.b64encode(bytes(64)).decode()},
            "pop-invalid",
        ),
        (
            {"transit_key": _key("candidate").read_back(exportable=True)},
            "transit-key-flag",
        ),
    ],
)
def test_a_candidate_request_with_a_wrong_issuer_pop_or_key_is_refused(
    db: Session, override: dict[str, Any], code: str
) -> None:
    with pytest.raises(e10.E10Refused) as refused:
        e10.enrol_candidate_root(
            db,
            e10.ControlRegistry(),
            _candidate_request("candidate-subject", _key("candidate"), **override),
        )
    assert refused.value.code == code
    db.rollback()
    assert _count(db, "SELECT count(*) FROM mod_deploy.attestation_enrolments") == 0


def test_the_incarnation_pop_cannot_stand_in_for_the_candidate_pop(db: Session) -> None:
    key = _key("candidate")
    wrong = key.sign(e10.incarnation_pop_message("candidate-subject", NONCE))
    with pytest.raises(e10.E10Refused) as refused:
        e10.enrol_candidate_root(
            db,
            e10.ControlRegistry(),
            _candidate_request("candidate-subject", key, pop_signature=wrong),
        )
    assert refused.value.code == "pop-invalid"
    db.rollback()


# ── target set-up and the presentation credential ───────────────────────────


def _register_target(db: Session, ref: str = "tgt-a") -> None:
    from dotmac_deployment_control import RegisterTargetCommand, register_target

    register_target(
        db,
        RegisterTargetCommand(
            command_id=f"cmd-{ref}",
            target_ref=ref,
            subject_ref="subject",
            product_code="product",
            environment="test",
            actor_ref="operator",
        ),
    )
    db.commit()


def _setup(db: Session, **override: Any) -> tuple[str, str]:
    arguments: dict[str, Any] = {
        "target_ref": "tgt-a",
        "host_id": "host-a",
        "candidate_root_subject": "candidate-subject",
        "candidate_audience": "dotmac-deployment-foundation",
        "installed_audience": "host-a",
        "expected_foundation_package": "dotmac-deployment-foundation",
    }
    arguments.update(override)
    result = e10.target_setup(db, **arguments)
    db.commit()
    return result


def test_target_setup_binds_the_host_and_sets_the_policy_once(db: Session) -> None:
    _register_target(db)
    association, policy = _setup(db)
    assert uuid.UUID(association) and uuid.UUID(policy)
    row = db.execute(
        text(
            "SELECT a.host_id, p.candidate_root_subject, p.installed_audience "
            "FROM mod_deploy.target_current_hosts h JOIN mod_deploy.target_host_associations a "
            "ON a.id = h.association_id JOIN mod_deploy.target_current_admission_policies c "
            "ON c.target_id = h.target_id JOIN mod_deploy.target_admission_policies p "
            "ON p.id = c.policy_id"
        )
    ).one()
    assert row == ("host-a", "candidate-subject", "host-a")
    with pytest.raises(e10.E10Refused) as refused:
        _setup(db)
    assert refused.value.code == "control-target_host_association_already_bound"
    db.rollback()


def test_target_setup_refuses_an_unknown_target_and_a_malformed_host(
    db: Session,
) -> None:
    with pytest.raises(e10.E10Refused) as refused:
        _setup(db, target_ref="absent")
    assert refused.value.code == "target-unknown"
    _register_target(db)
    with pytest.raises(e10.E10Refused) as refused:
        _setup(db, host_id="Host_A")
    assert refused.value.code == "host-id-invalid"
    db.rollback()


class _Signer:
    def __init__(self, key: Any, key_id: str, deployment_ref: str) -> None:
        self._key = key
        self.key_id = key_id
        self.deployment_ref = deployment_ref

    def sign(self, data: bytes) -> bytes:
        return self._key._key.sign(data)  # type: ignore[no-any-return]


def _credential(db: Session) -> tuple[str, Any]:
    _register_target(db)
    key = _key("presentation")
    public = e10._b64url(key.raw_public)
    credential = e10.enrol_presentation_credential(
        db,
        target_ref="tgt-a",
        key_id="presentation-key-1",
        public_key_b64url=public,
        command_id="c-enrol",
    )
    db.commit()
    return credential, key


def _status(db: Session, credential: str) -> str:
    return str(
        db.execute(
            text(
                "SELECT status FROM mod_deploy.target_credentials WHERE id = CAST(:i AS uuid)"
            ),
            {"i": credential},
        ).scalar_one()
    )


def test_a_presentation_credential_is_pending_until_possession_is_proven(
    case: Any, db: Session
) -> None:
    from dotmac_kernel.licensing import (
        DeploymentPossessionChallenge,
        answer_possession_challenge,
    )

    credential, key = _credential(db)
    assert _status(db, credential) == "pending"
    challenge = e10.presentation_challenge(
        key_id="presentation-key-1",
        deployment_ref="host-a",
        challenge_id="chal-1",
        now=e10.store_now(db),
    )
    response = answer_possession_challenge(
        DeploymentPossessionChallenge.from_wire(challenge),
        signer=_Signer(key, "presentation-key-1", "host-a"),
    ).to_wire()
    e10.activate_presentation_credential(
        db,
        credential_id=credential,
        challenge=challenge,
        response=response,
        command_id="c-activate",
        now=e10.store_now(db),
    )
    db.commit()
    assert _status(db, credential) == "active"
    # A second activation is refused: only a pending credential can be activated.
    with pytest.raises(e10.E10Refused) as refused:
        e10.activate_presentation_credential(
            db,
            credential_id=credential,
            challenge=challenge,
            response=response,
            command_id="c-activate-2",
            now=e10.store_now(db),
        )
    assert refused.value.code == "credential-not-pending"
    db.rollback()


def test_a_response_signed_by_another_key_does_not_activate(db: Session) -> None:
    from dotmac_kernel.licensing import (
        DeploymentPossessionChallenge,
        answer_possession_challenge,
    )

    credential, _key_held = _credential(db)
    challenge = e10.presentation_challenge(
        key_id="presentation-key-1",
        deployment_ref="host-a",
        challenge_id="chal-2",
        now=e10.store_now(db),
    )
    response = answer_possession_challenge(
        DeploymentPossessionChallenge.from_wire(challenge),
        signer=_Signer(_key("an-impostor"), "presentation-key-1", "host-a"),
    ).to_wire()
    with pytest.raises(e10.E10Refused) as refused:
        e10.activate_presentation_credential(
            db,
            credential_id=credential,
            challenge=challenge,
            response=response,
            command_id="c-activate",
            now=e10.store_now(db),
        )
    assert refused.value.code == "possession-not-proven"
    db.rollback()
    assert _status(db, credential) == "pending"


def test_an_expired_challenge_does_not_activate(db: Session) -> None:
    from dotmac_kernel.licensing import (
        DeploymentPossessionChallenge,
        answer_possession_challenge,
    )

    credential, key = _credential(db)
    now = e10.store_now(db)
    challenge = e10.presentation_challenge(
        key_id="presentation-key-1",
        deployment_ref="host-a",
        challenge_id="chal-3",
        now=now,
    )
    response = answer_possession_challenge(
        DeploymentPossessionChallenge.from_wire(challenge),
        signer=_Signer(key, "presentation-key-1", "host-a"),
    ).to_wire()
    with pytest.raises(e10.E10Refused) as refused:
        e10.activate_presentation_credential(
            db,
            credential_id=credential,
            challenge=challenge,
            response=response,
            command_id="c-activate",
            now=now + timedelta(hours=1),
        )
    assert refused.value.code == "possession-not-proven"
    db.rollback()


# ── CP-7: the host facts from the receipt ───────────────────────────────────


def test_the_host_facts_are_read_from_the_receipt_and_must_be_the_current_root(
    db: Session,
) -> None:
    first = _enrol(db, "host-a", 1)
    facts = e10.receipt_host_facts(db, receipt_ref=first.receipt_ref)
    assert facts == e10.HostFacts("host-a", first.fingerprint, first.enrolment_uuid)
    _enrol(db, "host-a", 2)  # the first incarnation is no longer the current root
    with pytest.raises(e10.E10Refused) as refused:
        e10.receipt_host_facts(db, receipt_ref=first.receipt_ref)
    assert refused.value.code == "receipt-not-current-root"
    with pytest.raises(e10.E10Refused) as refused:
        e10.receipt_host_facts(
            db, receipt_ref="e10-00000000-0000-0000-0000-000000000000"
        )
    assert refused.value.code == "receipt-unknown"


def test_m2_a_closure_naming_the_fingerprint_makes_the_receipt_not_current(
    db: Session,
) -> None:
    """The view still lists the fingerprint, but a closure names it: closed."""
    first = _enrol(db, "host-a", 1)
    e10.receipt_host_facts(db, receipt_ref=first.receipt_ref)  # current: accepted
    db.execute(
        text(
            "INSERT INTO mod_deploy.attestation_fingerprint_closures "
            "(fingerprint, closure_kind, closed_at, closure_authority) "
            "VALUES (:f, 'revoked', now(), 'test')"
        ),
        {"f": first.fingerprint},
    )
    db.commit()
    still_listed = db.execute(
        text(
            "SELECT count(*) FROM mod_deploy.attestation_current_roots "
            "WHERE current_fingerprint = :f"
        ),
        {"f": first.fingerprint},
    ).scalar_one()
    assert still_listed == 1
    with pytest.raises(e10.E10Refused) as refused:
        e10.receipt_host_facts(db, receipt_ref=first.receipt_ref)
    assert refused.value.code == "receipt-not-current-root"


def test_the_ensure_audit_registry_helper_is_idempotent() -> None:
    e10.ensure_audit_registry()
    e10.ensure_audit_registry()


def test_an_attestation_expiring_exactly_now_is_expired_and_nothing_is_written(
    case: Any, db: Session
) -> None:
    """Fail closed at the boundary: `expires_at <= database time` is lapsed."""
    _foundation_or_skip()
    key = _key("host-a-1")
    outcome = _enrol(db, "host-a", 1, seed="host-a-1")
    receipt = e10._receipt_row(db, outcome.receipt_ref)
    dispatch_id = str(uuid.uuid4())
    _dispatch_row(db, dispatch_id)
    now = case.now().astimezone(UTC)
    installed = _installed(
        receipt,
        key,
        dispatch_id,
        issued_at=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    with pytest.raises(e10.E10Refused) as refused:
        e10.record_destruction(
            db,
            {
                "receipt_ref": outcome.receipt_ref,
                "evidence_digest": "sha256:" + "b" * 64,
                "recorded_by": "operator",
                "installed": installed,
            },
        )
    assert refused.value.code == "installed-attestation-expired"
    assert _count(db, "SELECT count(*) FROM cp_lane3.e10_destructions") == 0
    db.rollback()
