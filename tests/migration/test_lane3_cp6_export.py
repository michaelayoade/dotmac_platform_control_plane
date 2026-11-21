"""CP-6: `lane3_record export`, parsed by Starter's own `parse_cp6_export`.

The parser is Starter's (S8b-2 #1128 @3a39f3fc, schema v2; vendored verbatim and pinned by sha256 in
`tests/vendored/starter_lane3_cp6`): the E9 offline orchestrator's view of the
export. Everything here runs on REAL Control a17 types and PostgreSQL: a genuinely
signed `DispatchEnvelopeV1`, the registry's own enrolment rows, the
`platform_idempotency_records` ledger row, and `cp_lane3` rows written the way the
functions write them. Then the orchestrator's joins are re-run on the output:

* the dispatch signature verifies against an independently pinned CP identity;
* the dispatch digest is Control's `DispatchEnvelopeDigestV1` over
  `canonical_json({statement, signature})`;
* the receipt digest the export carries is the one `lane3_e10` printed at
  enrolment, and Starter's own `receipt_digest` computes the same value;
* the ledger fingerprint recomputed by Starter equals Control a17's
  `compute_host_admission_consumption_fingerprint`.

No Foundation is needed (the vendored parser needs only `cryptography`).
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import types
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text
from sqlalchemy.orm import Session

from vendor_cp.deployment import lane3_e10 as e10
from vendor_cp.deployment import lane3_record as record

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "vendored" / "starter_lane3_cp6"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _cp6() -> Any:
    """Starter's parser, with the one script it imports stood in by a faithful copy
    of `Ed25519AttestationVerifier` (it needs only `cryptography`)."""
    import hashlib as _h

    pins = json.loads((VENDORED / "PINS.json").read_text())
    for name, entry in pins["files"].items():
        assert _h.sha256((VENDORED / name).read_bytes()).hexdigest() == entry["sha256"]
    if "lane3_cp6_export" in sys.modules:
        return sys.modules["lane3_cp6_export"]
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    class Ed25519AttestationVerifier:
        def verify(
            self, *, public_key: bytes, algorithm: str, message: bytes, signature: str
        ) -> bool:
            if algorithm != "ed25519" or len(public_key) != 32:
                return False
            try:
                raw = base64.b64decode(signature, validate=True)
                Ed25519PublicKey.from_public_bytes(public_key).verify(raw, message)
            except (InvalidSignature, ValueError):
                return False
            return len(raw) == 64

    stub = types.ModuleType("lane3_host_source_admission")
    stub.Ed25519AttestationVerifier = Ed25519AttestationVerifier  # type: ignore[attr-defined]
    sys.modules["lane3_host_source_admission"] = stub
    return _load(VENDORED / "lane3_cp6_export.py", "lane3_cp6_export")


def _support() -> Any:
    name = "lane3_cp_support"
    if name in sys.modules:
        return sys.modules[name]
    return _load(ROOT / "unit" / "lane3_cp_support.py", name)


SUPPORT = _support()
CP6 = _cp6()
NONCE = bytes(range(32))
HOST = "host-a"
SCOPE = "deployment.consume_dispatch_challenge.v1"
CANDIDATE_DIGEST = "sha256:" + "c1" * 32
DISPATCH_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(7, 39)))
DISPATCH_PUBLIC = (
    base64.urlsafe_b64encode(
        DISPATCH_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    .decode()
    .rstrip("=")
)
CANDIDATE_SUBJECT = "candidate-subject"


@pytest.fixture
def case(lane3_cases: Any) -> Any:
    return lane3_cases.new()


@pytest.fixture
def db(case: Any) -> Any:
    with Session(case.admin) as session:
        yield session


class _Signer:
    """A possession-challenge signer for the presentation key."""

    def __init__(self, key: Any, key_id: str, deployment_ref: str) -> None:
        self._key = key
        self.key_id = key_id
        self.deployment_ref = deployment_ref

    def sign(self, data: bytes) -> bytes:
        return self._key._key.sign(data)  # type: ignore[no-any-return]


def _enrol_and_activate(db: Session, *, seed: str, key_id: str) -> tuple[str, Any]:
    """A presentation credential through the REAL owners: enrol, prove possession
    with the Kernel's own challenge, then Control activates."""
    from dotmac_kernel.licensing import (
        DeploymentPossessionChallenge,
        answer_possession_challenge,
    )

    key = SUPPORT.TransitKey(hashlib.sha256(seed.encode()).digest())
    credential = e10.enrol_presentation_credential(
        db,
        target_ref="tgt-a",
        key_id=key_id,
        public_key_b64url=e10._b64url(key.raw_public),
        command_id=f"c-enrol-{key_id}",
    )
    db.commit()
    now = e10.store_now(db)
    challenge = e10.presentation_challenge(
        key_id=key_id, deployment_ref=HOST, challenge_id=f"chal-{key_id}", now=now
    )
    response = answer_possession_challenge(
        DeploymentPossessionChallenge.from_wire(challenge),
        signer=_Signer(key, key_id, HOST),
    ).to_wire()
    e10.activate_presentation_credential(
        db,
        credential_id=credential,
        challenge=challenge,
        response=response,
        command_id=f"c-activate-{key_id}",
        now=now,
    )
    db.commit()
    return credential, key


class _World:
    """Everything one export joins, built through the real owners."""

    def __init__(
        self,
        db: Session,
        case: Any,
        *,
        released: bool = True,
        credential: bool = True,
    ) -> None:
        from dotmac_deployment_control import (
            DispatchEnvelopeV1,
            RegisterTargetCommand,
            register_target,
        )
        from dotmac_deployment_control.dispatch_envelope import DispatchStatementV1
        from dotmac_deployment_control.models import RolloutAttempt
        from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord

        self.db, self.case = db, case
        register_target(
            db,
            RegisterTargetCommand(
                command_id="cmd-t",
                target_ref="tgt-a",
                subject_ref="s",
                product_code="p",
                environment="test",
                actor_ref="operator",
            ),
        )
        db.commit()
        self.target_id = str(
            db.execute(
                text("SELECT id FROM mod_deploy.deployment_targets")
            ).scalar_one()
        )
        e10.target_setup(
            db,
            target_ref="tgt-a",
            host_id=HOST,
            candidate_root_subject=CANDIDATE_SUBJECT,
            candidate_audience="dotmac-deployment-foundation",
            installed_audience=HOST,
            expected_foundation_package="dotmac-deployment-foundation",
        )
        db.commit()
        # The candidate root and the installed incarnation, through the real command.
        ckey = SUPPORT.TransitKey(hashlib.sha256(b"candidate").digest())
        e10.enrol_candidate_root(
            db,
            e10.ControlRegistry(),
            {
                "subject": CANDIDATE_SUBJECT,
                "transit_key": ckey.read_back(),
                "pop_signature": ckey.sign(
                    e10.candidate_pop_message(CANDIDATE_SUBJECT, NONCE)
                ),
                "nonce": base64.urlsafe_b64encode(NONCE).decode().rstrip("="),
                "issuer": "urn:dotmac:foundation:candidate-release-ceremony:a2",
                "attestation_key_id": "candidate-release-v1",
                "not_after": "2031-01-01T00:00:00Z",
            },
        )
        ikey = SUPPORT.TransitKey(hashlib.sha256(b"incarnation").digest())
        self.enrolled = e10.enrol_incarnation(
            db,
            e10.ControlRegistry(),
            {
                "host_id": HOST,
                "vm_alias": "vm-a",
                "vm_slot": None,
                "machine_id": "0" * 32,
                "ssh_host_key_fingerprint": "SHA256:" + "B" * 43,
                "mount": "transit-a2-hi-vm-a-1",
                "transit_key": ikey.read_back(),
                "pop_signature": ikey.sign(e10.incarnation_pop_message(HOST, NONCE)),
                "nonce": base64.urlsafe_b64encode(NONCE).decode().rstrip("="),
                "issuer": "urn:dotmac:foundation:installed-host-ceremony:a2",
                "attestation_key_id": "incarnation-1",
                "not_after": "2031-01-01T00:00:00Z",
                "recorded_by": "operator",
            },
        )
        db.commit()
        # A genuinely signed dispatch, stored the way Control stores it.
        self.dispatch_id = str(uuid.uuid4())
        fingerprint = (
            "sha256:"
            + hashlib.sha256(
                DISPATCH_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).hexdigest()
        )
        statement = DispatchStatementV1(
            dispatch_id=self.dispatch_id,
            authorization_id=str(uuid.uuid4()),
            authorization_plan_id=str(uuid.uuid4()),
            authorization_control_version="0.1.0a17",
            authorization_key_id="auth-key",
            authorization_public_key_fingerprint=fingerprint,
            authorization_envelope_digest="sha256:" + "a" * 64,
            execution_sequence=3,
            attempt_no=2,
            rollout_ref="rollout-1",
            target_id=self.target_id,
            target_ref="tgt-a",
            product_code="p",
            environment="test",
            operation="deploy",
            release_ref="rel-1",
            authorized_images=(),
            plan_digest="sha256:" + "b" * 64,
            descriptor_digest="sha256:" + "d" * 64,
            execution_plan_digest="sha256:" + "e" * 64,
            issued_at=datetime(2026, 11, 19, 9, 0, 0, tzinfo=UTC),
            control_version="0.1.0a17",
            key_id="dispatch-key",
            algorithm="ed25519",
            public_key_fingerprint=fingerprint,
        )
        signature = (
            base64.urlsafe_b64encode(DISPATCH_KEY.sign(statement.canonical_bytes))
            .decode()
            .rstrip("=")
        )
        self.envelope = DispatchEnvelopeV1(statement=statement, signature=signature)
        db.execute(text("SET LOCAL session_replication_role = replica"))
        db.add(
            RolloutAttempt(
                id=uuid.UUID(self.dispatch_id),
                rollout_id=uuid.uuid4(),
                attempt_no=2,
                dispatch_envelope=json.loads(self.envelope.canonical_bytes),
            )
        )
        db.flush()
        db.execute(text("SET LOCAL session_replication_role = origin"))
        db.commit()
        # Destruction citing the dispatch, then the lease, its release and the ledger row.
        self.installed_digest = "sha256:" + "f0" * 32
        db.execute(
            text(
                "INSERT INTO cp_lane3.e10_destructions (receipt_ref, route, dispatch_id, "
                "installed_attestation_digest, evidence_digest, recorded_by) VALUES "
                "(:r, 'transit_mount_disabled', CAST(:d AS uuid), :i, :e, 'operator')"
            ),
            {
                "r": self.enrolled.receipt_ref,
                "d": self.dispatch_id,
                "i": self.installed_digest,
                "e": "sha256:" + "ee" * 32,
            },
        )
        case.advance(None, 120)
        self.lease_id = str(uuid.uuid4())
        acquired = case.now()
        db.execute(
            text("INSERT INTO cp_lane3.host_current_lease (host_id) VALUES (:h)"),
            {"h": HOST},
        )
        db.execute(
            text(
                "INSERT INTO cp_lane3.host_leases (lease_id, host_id, authorization_run, "
                "controller_identity, workload_principal, e10_receipt_ref, acquired_at, "
                "expires_at, ttl_seconds) VALUES (CAST(:l AS uuid), :h, 'run-1', :c, "
                "'repo:dotmac-tech/lane3:ref:refs/heads/main', :r, :a, :e, 600)"
            ),
            {
                "l": self.lease_id,
                "h": HOST,
                "c": "SHA256:" + "A" * 43,
                "r": self.enrolled.receipt_ref,
                "a": acquired,
                "e": acquired + timedelta(seconds=600),
            },
        )
        case.advance(None, 30)
        self.consumed_at = case.now()
        self.fingerprint = hashlib.sha256(b"fp").hexdigest()
        db.add(
            PlatformIdempotencyRecord(
                scope=SCOPE,
                key=self.dispatch_id,
                fingerprint=self.fingerprint,
                operation=SCOPE,
                status="executed",
                created_at=self.consumed_at,
                updated_at=self.consumed_at,
            )
        )
        case.advance(None, 30)
        if released:
            db.execute(
                text(
                    "INSERT INTO cp_lane3.host_lease_releases (lease_id, record_released_at, "
                    "host_mutated, release_bytes, release_digest) VALUES (CAST(:l AS uuid), "
                    ":a, true, CAST('{}' AS bytea), :d)"
                ),
                {"l": self.lease_id, "a": case.now(), "d": "sha256:" + "6" * 64},
            )
        db.execute(
            text(
                "UPDATE cp_lane3.host_current_lease SET lease_id = CAST(:l AS uuid) WHERE host_id = :h"
            ),
            {"l": self.lease_id, "h": HOST},
        )
        db.commit()
        self.credential_id: str | None = None
        if credential:
            self.add_credential("presentation-key-1", "first", -60, +60)

    def add_credential(
        self, key_id: str, seed: str, activated: float, revoked: float | None
    ) -> str:
        """Enrol, activate (possession proven) and, when `revoked` is given, revoke a
        presentation credential through Control; then place its window at the given
        offsets, in seconds, from the ledger instant. Control stamps its own clock;
        the window is pinned relative to the (frozen-clock) ledger row so the
        brackets under test are exact."""
        credential, key = _enrol_and_activate(self.db, seed=seed, key_id=key_id)
        if revoked is not None:
            e10._revoke_credential(self.db, credential, f"c-revoke-{key_id}")
            self.db.commit()
        self.set_window(credential, activated=activated, revoked=revoked)
        self.credential_id = self.credential_id or credential
        self.credential_key = key
        return credential

    def set_window(
        self,
        credential: str,
        *,
        activated: float,
        revoked: float | None,
        retired: float | None = None,
    ) -> None:
        def at(offset: float | None) -> datetime | None:
            return (
                None if offset is None else self.consumed_at + timedelta(seconds=offset)
            )

        self.db.execute(text("SET LOCAL session_replication_role = replica"))
        self.db.execute(
            text(
                "UPDATE mod_deploy.target_credentials SET activated_at = :a, "
                "retired_at = :t, revoked_at = :r WHERE id = CAST(:i AS uuid)"
            ),
            {"a": at(activated), "t": at(retired), "r": at(revoked), "i": credential},
        )
        self.db.execute(text("SET LOCAL session_replication_role = origin"))
        self.db.commit()

    def export(self) -> tuple[dict[str, Any], bytes]:
        document = record.build_export(
            self.db, dispatch_id=self.dispatch_id, host_id=HOST
        )
        return document, record.render(document)


def test_the_export_parses_with_starters_own_parser_and_every_join_holds(
    db: Session, case: Any
) -> None:
    from dotmac_deployment_control.digests import (
        compute_host_admission_consumption_fingerprint as c,
    )

    world = _World(db, case)
    document, payload = world.export()
    parsed = CP6.parse_cp6_export(payload)

    assert document["schema"] == CP6.EXPORT_SCHEMA == "lane3.cp6-export.v2"
    assert parsed.dispatch_id == world.dispatch_id and parsed.host_id == HOST
    # 1. the dispatch verifies against an INDEPENDENT pin, and the digest is Control's.
    pinned = CP6.PinnedIdentity("dispatch-key", "ed25519", DISPATCH_PUBLIC)
    statement = CP6.verify_dispatch(parsed.dispatch, [pinned])
    assert (statement.execution_sequence, statement.attempt_no) == (3, 2)
    assert parsed.dispatch.envelope_digest == CP6.dispatch_envelope_digest(
        parsed.dispatch.statement, parsed.dispatch.signature
    )
    from dotmac_deployment_control import DispatchEnvelopeDigestV1

    assert (
        parsed.dispatch.envelope_digest
        == DispatchEnvelopeDigestV1.over_bytes(world.envelope.canonical_bytes).canonical
    )
    assert "=" not in parsed.dispatch.signature  # unpadded base64url
    # 2. the ledger row: key = the bare dispatch id, executed, the consumption scope.
    assert (parsed.ledger.key, parsed.ledger.scope, parsed.ledger.status) == (
        world.dispatch_id,
        CP6.CONSUME_SCOPE,
        CP6.CONSUME_STATUS,
    )
    assert parsed.ledger.fingerprint == world.fingerprint
    assert parsed.ledger.created_at == world.consumed_at
    assert (parsed.ledger.execution_sequence, parsed.ledger.attempt_no) == (3, 2)
    # 3. Starter's recomputation of the consumption fingerprint IS Control a17's.
    inputs = dict(
        dispatch_envelope_digest=parsed.dispatch.envelope_digest,
        candidate_attestation_envelope_digest=CANDIDATE_DIGEST,
        installed_attestation_envelope_digest=world.installed_digest,
    )
    assert CP6.ledger_fingerprint(**inputs) == c(**inputs)
    # 4. the receipt digest: the export, the enrolment printout and Starter agree.
    assert parsed.e10_receipt_digest == world.enrolled.receipt_digest
    assert CP6.receipt_digest(parsed.receipt.document) == parsed.e10_receipt_digest
    assert e10.receipt_digest(parsed.receipt.document) == parsed.e10_receipt_digest


def test_the_receipt_lease_destruction_and_release_are_the_hosts_and_consistent(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    parsed = CP6.parse_cp6_export(world.export()[1])
    assert (
        parsed.receipt.receipt_ref
        == world.enrolled.receipt_ref
        == parsed.lease.e10_receipt_ref
    )
    assert parsed.destruction.receipt_ref == parsed.receipt.receipt_ref
    assert parsed.destruction.dispatch_id == world.dispatch_id
    assert parsed.destruction.installed_attestation_digest == world.installed_digest
    assert parsed.destruction.route == "transit_mount_disabled"
    assert parsed.lease.lease_id == world.lease_id and parsed.lease.host_id == HOST
    assert (
        parsed.lease.acquired_at <= parsed.ledger.created_at < parsed.lease.expires_at
    )
    assert parsed.release is not None and parsed.release.lease_id == world.lease_id
    assert parsed.release.host_mutated is True
    assert parsed.ledger.created_at <= parsed.release.released_at
    assert parsed.destruction.destroyed_at <= parsed.lease.acquired_at


def test_both_roots_carry_their_standing_and_the_installed_one_follows_the_receipt(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    parsed = CP6.parse_cp6_export(world.export()[1])
    installed, candidate = parsed.installed_root, parsed.candidate_root
    assert (
        installed.enrolment_uuid
        == world.enrolled.enrolment_uuid
        == parsed.receipt.enrolment_uuid
    )
    assert installed.fingerprint == parsed.receipt.incarnation_fingerprint
    assert (installed.custody_domain, installed.purpose) == (
        "host_attester",
        "dotmac.foundation.installed-host.v2",
    )
    assert (candidate.custody_domain, candidate.purpose) == (
        "candidate_release_signer",
        "dotmac.foundation.candidate-artifact.v2",
    )
    assert installed.revoked_at is None and candidate.revoked_at is None
    assert installed.not_before == e10.format_time(
        installed.enrolled_at
    )  # not_before = enrolled_at
    assert installed.enrolled_at <= parsed.destruction.destroyed_at
    # After the run's revoke, the SAME export shows the closure instant.
    e10.revoke_incarnation(
        db, e10.ControlRegistry(), receipt_ref=world.enrolled.receipt_ref
    )
    db.commit()
    again = CP6.parse_cp6_export(world.export()[1])
    assert again.installed_root.revoked_at is not None
    assert again.installed_root.revoked_at > again.ledger.created_at
    assert again.candidate_root.revoked_at is None


def test_an_unreleased_lease_exports_release_null(db: Session, case: Any) -> None:
    world = _World(db, case, released=False)
    document, payload = world.export()
    assert document["cp_lane3"]["release"] is None
    assert CP6.parse_cp6_export(payload).release is None


def test_the_export_is_canonical_bytes_and_deterministic(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    first, again = world.export()[1], world.export()[1]
    assert first == again
    assert first.endswith(b"\n") and first.isascii()
    assert first == e10.canonical(json.loads(first))
    assert len(first) <= record.MAX_EXPORT_BYTES == CP6.MAX_EXPORT_BYTES


def test_the_dispatch_block_is_exactly_the_a17_statement_and_a_tampered_one_is_caught(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    parsed = CP6.parse_cp6_export(world.export()[1])
    assert set(parsed.dispatch.statement) == CP6._STATEMENT_KEYS
    tampered = {**parsed.dispatch.statement, "operation": "something-else"}
    block = CP6.DispatchBlock(
        tampered, parsed.dispatch.signature, parsed.dispatch.envelope_digest
    )
    with pytest.raises(CP6.Cp6ExportRefused):
        CP6.verify_dispatch(
            block, [CP6.PinnedIdentity("dispatch-key", "ed25519", DISPATCH_PUBLIC)]
        )
    with pytest.raises(CP6.Cp6ExportRefused):
        CP6.verify_dispatch(
            parsed.dispatch,
            [CP6.PinnedIdentity("dispatch-key", "ed25519", e10._b64url(bytes(32)))],
        )


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("DELETE FROM public.platform_idempotency_records", "ledger-row-absent"),
        (
            "UPDATE public.platform_idempotency_records SET status = 'pending'",
            "ledger-row-not-consumed",
        ),
        (
            "UPDATE public.platform_idempotency_records SET fingerprint = 'abc'",
            "ledger-row-not-consumed",
        ),
    ],
)
def test_a_ledger_row_that_is_not_an_executed_consumption_is_refused(
    db: Session, case: Any, sql: str, code: str
) -> None:
    world = _World(db, case)
    db.execute(text(sql))
    with pytest.raises(e10.E10Refused) as refused:
        world.export()
    assert refused.value.code == code


def test_every_other_unfaithful_export_is_refused_with_a_code(
    db: Session, case: Any
) -> None:
    world = _World(db, case)

    def refused(dispatch: str, host: str) -> str:
        with pytest.raises(e10.E10Refused) as caught:
            record.build_export(db, dispatch_id=dispatch, host_id=host)
        return caught.value.code

    assert refused(world.dispatch_id, "host-z") == "receipt-is-for-another-host"
    assert refused(str(uuid.uuid4()), HOST) == "dispatch-unknown"
    assert refused(world.dispatch_id.upper(), HOST) == "dispatch-id-invalid"
    assert refused("not-a-uuid", HOST) == "dispatch-id-invalid"
    assert refused(world.dispatch_id, "Host_A") == "host-id-invalid"


def test_the_command_is_read_only_prints_the_digest_and_names_a_code_on_refusal(
    db: Session, case: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    world = _World(db, case)
    out = tmp_path / "export.json"
    code = record.main(
        [
            "export",
            "--dispatch-id",
            world.dispatch_id,
            "--host-id",
            HOST,
            "--out",
            str(out),
        ],
        environ={},
        session=db,
    )
    assert code == 0
    payload = out.read_bytes()
    assert (out.stat().st_mode & 0o777) == 0o600
    assert (
        capsys.readouterr().err.strip()
        == "export_digest=sha256:" + hashlib.sha256(payload).hexdigest()
    )
    # Create-only: a second write to the same path is refused, never overwritten.
    code = record.main(
        [
            "export",
            "--dispatch-id",
            world.dispatch_id,
            "--host-id",
            HOST,
            "--out",
            str(out),
        ],
        environ={},
        session=db,
    )
    assert code == 2 and "out-path-unwritable" in capsys.readouterr().err
    assert out.read_bytes() == payload
    code = record.main(
        ["export", "--dispatch-id", str(uuid.uuid4()), "--host-id", HOST],
        environ={},
        session=db,
    )
    assert code == 2 and "dispatch-unknown" in capsys.readouterr().err


def test_a_missing_dsn_refuses_and_never_echoes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = record.main(
        ["export", "--dispatch-id", str(uuid.uuid4()), "--host-id", HOST], environ={}
    )
    assert code == 2 and "dsn-missing" in capsys.readouterr().err


# ── M4: the candidate root is the one CURRENT at the ledger instant ─────────


def _rotate_candidate(db: Session, seed: bytes = b"candidate-2") -> None:
    ckey = SUPPORT.TransitKey(hashlib.sha256(seed).digest())
    e10.enrol_candidate_root(
        db,
        e10.ControlRegistry(),
        {
            "subject": CANDIDATE_SUBJECT,
            "transit_key": ckey.read_back(),
            "pop_signature": ckey.sign(
                e10.candidate_pop_message(CANDIDATE_SUBJECT, NONCE)
            ),
            "nonce": base64.urlsafe_b64encode(NONCE).decode().rstrip("="),
            "issuer": "urn:dotmac:foundation:candidate-release-ceremony:a2",
            "attestation_key_id": "candidate-release-v2",
            "not_after": "2031-01-01T00:00:00Z",
        },
    )
    db.commit()


def _candidate_uuids(db: Session) -> list[str]:
    return [
        row[0]
        for row in db.execute(
            text(
                "SELECT id::text FROM mod_deploy.attestation_enrolments WHERE "
                "custody_domain = 'candidate_release_signer' ORDER BY enrolled_at, id"
            )
        )
    ]


def test_a_candidate_rotation_after_the_ledger_row_does_not_change_the_export(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    (first,) = _candidate_uuids(db)
    _rotate_candidate(db)  # enrolled AFTER the dispatch was consumed
    assert len(_candidate_uuids(db)) == 2
    parsed = CP6.parse_cp6_export(world.export()[1])
    assert parsed.candidate_root.enrolment_uuid == first
    # the first root is closed now, by a closure LATER than the ledger instant
    assert parsed.candidate_root.revoked_at is not None
    assert parsed.candidate_root.revoked_at > parsed.ledger.created_at


def test_a_candidate_rotation_before_the_ledger_row_exports_the_newer_root(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    _rotate_candidate(db)
    first, second = _candidate_uuids(db)
    # Owner-only setup: move the rotation to BEFORE the ledger instant (the
    # evidence tables are append-only; `replica` steps over that guard here only).
    db.execute(text("SET LOCAL session_replication_role = replica"))
    db.execute(
        text(
            "UPDATE mod_deploy.attestation_enrolments SET enrolled_at = "
            ":t WHERE id = CAST(:i AS uuid)"
        ),
        {"t": world.consumed_at - timedelta(seconds=10), "i": second},
    )
    db.execute(
        text(
            "UPDATE mod_deploy.attestation_fingerprint_closures SET closed_at = :t "
            "WHERE fingerprint IN (SELECT public_key_fingerprint FROM "
            "mod_deploy.attestation_enrolments WHERE id = CAST(:i AS uuid))"
        ),
        {"t": world.consumed_at - timedelta(seconds=10), "i": first},
    )
    db.execute(text("SET LOCAL session_replication_role = origin"))
    db.commit()
    parsed = CP6.parse_cp6_export(world.export()[1])
    assert parsed.candidate_root.enrolment_uuid == second
    assert parsed.candidate_root.revoked_at is None


def test_no_candidate_root_current_at_the_ledger_instant_is_a_refusal(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    db.execute(text("SET LOCAL session_replication_role = replica"))
    db.execute(
        text(
            "UPDATE mod_deploy.attestation_enrolments SET enrolled_at = :t "
            "WHERE custody_domain = 'candidate_release_signer'"
        ),
        {"t": world.consumed_at + timedelta(hours=1)},
    )
    db.execute(text("SET LOCAL session_replication_role = origin"))
    db.commit()
    with pytest.raises(e10.E10Refused) as refused:
        world.export()
    assert refused.value.code == "candidate-root-absent"


def test_two_candidate_roots_current_at_the_ledger_instant_are_a_refusal(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    _rotate_candidate(db)
    first, second = _candidate_uuids(db)
    # Both enrolled before the ledger instant and the first never closed: two
    # "current" roots. The export refuses rather than choose.
    db.execute(text("SET LOCAL session_replication_role = replica"))
    db.execute(
        text(
            "UPDATE mod_deploy.attestation_enrolments SET enrolled_at = :t "
            "WHERE id = CAST(:i AS uuid)"
        ),
        {"t": world.consumed_at - timedelta(seconds=10), "i": second},
    )
    db.execute(
        text(
            "DELETE FROM mod_deploy.attestation_fingerprint_closures WHERE "
            "fingerprint IN (SELECT public_key_fingerprint FROM "
            "mod_deploy.attestation_enrolments WHERE id = CAST(:i AS uuid))"
        ),
        {"i": first},
    )
    db.execute(text("SET LOCAL session_replication_role = origin"))
    db.commit()
    with pytest.raises(e10.E10Refused) as refused:
        world.export()
    assert refused.value.code == "candidate-root-ambiguous"


def test_the_cp6_key_set_is_unchanged_by_the_candidate_selection(
    db: Session, case: Any
) -> None:
    """The vendored Starter parser (pinned at #1128 @3a39f3fc) accepts the export
    and its root blocks carry exactly the keys it expects."""
    world = _World(db, case)
    document = world.export()[0]
    block = document["cp_lane3"]["candidate_root"]
    assert set(block) == set(document["cp_lane3"]["installed_root"])
    assert set(block) == {
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
    CP6.parse_cp6_export(record.render(document))


# ── the presentation-credential block (CP6-CREDENTIAL-BLOCK-SPEC section 3) ─────────


def test_the_block_is_the_credential_active_at_consumption_and_revoked_after(
    db: Session, case: Any
) -> None:
    from dotmac_deployment_control import HOST_ADMISSION_PRESENTATION_PURPOSE

    world = _World(db, case)
    document, payload = world.export()
    parsed = CP6.parse_cp6_export(payload)
    block = parsed.presentation_credential
    assert set(document["control"]) == {"dispatch", "ledger", "presentation_credential"}
    assert block.target_id == world.target_id
    assert (block.key_id, block.algorithm) == ("presentation-key-1", "ed25519")
    assert (
        block.purpose == HOST_ADMISSION_PRESENTATION_PURPOSE == CP6.PRESENTATION_PURPOSE
    )
    assert block.public_key == world.credential_key.raw_public
    assert (
        block.public_key_fingerprint
        == "sha256:" + hashlib.sha256(block.public_key).hexdigest()
    )
    # C2: active AT consumption, revoked NOW (step 15 ran before the export).
    assert block.status == "revoked"
    assert block.activated_at <= parsed.ledger.created_at
    assert block.revoked_at is not None and parsed.ledger.created_at < block.revoked_at
    assert block.retired_at is None


def test_the_export_is_v2_only_and_the_block_is_required_and_consistent(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    document = json.loads(world.export()[1])
    v1 = {**document, "schema": "lane3.cp6-export.v1"}
    with pytest.raises(CP6.Cp6ExportRefused):
        CP6.parse_cp6_export(e10.canonical(v1))
    stripped = json.loads(json.dumps(document))
    del stripped["control"]["presentation_credential"]
    with pytest.raises(CP6.Cp6ExportRefused):
        CP6.parse_cp6_export(e10.canonical(stripped))
    forged = json.loads(json.dumps(document))
    forged["control"]["presentation_credential"]["public_key_fingerprint"] = (
        "sha256:" + "9" * 64
    )
    with pytest.raises(CP6.Cp6ExportRefused):
        CP6.parse_cp6_export(e10.canonical(forged))


def _refused(world: _World) -> str:
    with pytest.raises(e10.E10Refused) as caught:
        world.export()
    return str(caught.value.code)


def test_no_credential_is_a_refusal_never_a_pick(db: Session, case: Any) -> None:
    assert _refused(_World(db, case, credential=False)) == (
        "presentation-credential-absent"
    )


def test_two_credentials_active_at_consumption_are_a_refusal(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    world.add_credential("presentation-key-2", "second", -30, +90)
    assert _refused(world) == "presentation-credential-ambiguous"


def test_a_credential_activated_after_consumption_does_not_count(
    db: Session, case: Any
) -> None:
    world = _World(db, case, credential=False)
    world.add_credential("presentation-key-1", "first", +60, +120)
    assert _refused(world) == "presentation-credential-absent"


def test_a_credential_revoked_before_consumption_does_not_count(
    db: Session, case: Any
) -> None:
    world = _World(db, case, credential=False)
    world.add_credential("presentation-key-1", "first", -120, -60)
    assert _refused(world) == "presentation-credential-absent"


def test_a_credential_rotated_out_before_consumption_does_not_count(
    db: Session, case: Any
) -> None:
    """C3: the bracket includes `retired_at`, not `revoked_at` alone."""
    world = _World(db, case)
    assert world.credential_id is not None
    world.set_window(world.credential_id, activated=-120, retired=-60, revoked=+60)
    assert _refused(world) == "presentation-credential-absent"


def test_a_credential_active_at_the_ledger_instant_exactly_is_the_boundary(
    db: Session, case: Any
) -> None:
    """activated_at <= created counts; revoked_at = created does not (t < revoked)."""
    world = _World(db, case, credential=False)
    credential = world.add_credential("presentation-key-1", "first", 0, +60)
    assert world.export()[0]["control"]["presentation_credential"]["key_id"] == (
        "presentation-key-1"
    )
    world.set_window(credential, activated=-60, revoked=0)
    assert _refused(world) == "presentation-credential-absent"


def test_a_stored_fingerprint_that_is_not_the_keys_is_inconsistent(
    db: Session, case: Any
) -> None:
    world = _World(db, case)
    db.execute(text("SET LOCAL session_replication_role = replica"))
    db.execute(
        text("UPDATE mod_deploy.target_credentials SET public_key_fingerprint = :f"),
        {"f": "sha256:" + "8" * 64},
    )
    db.execute(text("SET LOCAL session_replication_role = origin"))
    assert _refused(world) == "presentation-credential-inconsistent"
