"""CP-side producer of the dispatch materials (R8). No key is ever held here."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vendor_cp.deployment import materials_producer as producer
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import PinnedVerificationIdentity


def _identity(
    key: Ed25519PrivateKey, purpose: str, key_id: str
) -> PinnedVerificationIdentity:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    text = producer._b64url(raw)
    return PinnedVerificationIdentity(
        key_id=key_id,
        algorithm="ed25519",
        purpose=purpose,
        public_key=raw,
        public_key_b64url=text,
        public_key_fingerprint="sha256:" + "ab" * 32,
    )


class _Keys:
    def __init__(self) -> None:
        self.auth, self.disp = (
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate(),
        )
        self.signed: list[str] = []

    def custody(self, **overrides: Any) -> producer.Custody:
        def auth_sign(message: bytes) -> bytes:
            self.signed.append("authorization")
            return self.auth.sign(message)

        def disp_sign(message: bytes) -> bytes:
            self.signed.append("dispatch")
            return self.disp.sign(message)

        values: dict[str, Any] = {
            "authorization_identity": _identity(
                self.auth, "deployment_authorization", "a-1"
            ),
            "dispatch_identity": _identity(self.disp, "deployment_dispatch", "d-1"),
            "authorization_sign": auth_sign,
            "dispatch_sign": disp_sign,
        }
        values.update(overrides)
        return producer.Custody(**values)


class _Envelope:
    def __init__(self, statement: Any, signature: str) -> None:
        self.statement, self.signature = statement, signature

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {"signature": self.signature, "statement": vars(self.statement)},
            sort_keys=True,
        ).encode()


def _fixture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {"commits": 0}
    plan_id = uuid4()
    control = ModuleType("dotmac_deployment_control")
    control.AuthorizationSignerIdentity = lambda *a: SimpleNamespace(
        kind="auth-identity", args=a
    )  # type: ignore[attr-defined]
    control.AuthorizationSignature = lambda *a: SimpleNamespace(
        kind="auth-signature", args=a
    )  # type: ignore[attr-defined]
    control.DispatchSignerIdentity = lambda *a: SimpleNamespace(
        kind="dispatch-identity", args=a
    )  # type: ignore[attr-defined]
    control.DispatchSignature = lambda *a: SimpleNamespace(
        kind="dispatch-signature", args=a
    )  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dotmac_deployment_control", control)

    approval = ModuleType("vendor_cp.deployment.foundation_execution_approval")

    def request_rollout(db: Any, **kwargs: Any) -> Any:
        seen["rollout"] = kwargs
        seen["authorization_signature"] = kwargs["signer"].sign(b"authorization-bytes")
        db.order.append("rollout")
        return SimpleNamespace(id=uuid4())

    def dispatch(db: Any, **kwargs: Any) -> Any:
        seen["dispatch"] = kwargs
        seen["dispatch_signature"] = kwargs["dispatch_signer"].sign_dispatch(
            b"dispatch-bytes"
        )
        db.order.append("dispatch")
        authorization = SimpleNamespace(
            plan_id=str(plan_id), approval_decision_ref=str(uuid4())
        )
        statement = SimpleNamespace(
            dispatch_id=str(uuid4()),
            authorization_plan_id=str(plan_id),
            product_code="sub_thin",
            environment="production",
            target_id=str(uuid4()),
            target_ref="target-1",
            operation="deploy",
            release_ref="release-1",
            rollout_ref="rollout-1",
            plan_digest="sha256:" + "11" * 32,
            execution_sequence=2,
            attempt_no=1,
        )
        return SimpleNamespace(
            authorization_envelope=_Envelope(authorization, "sig-a"),
            dispatch_envelope=_Envelope(statement, "sig-d"),
        )

    approval.request_foundation_rollout = request_rollout  # type: ignore[attr-defined]
    approval.dispatch_foundation_attempt = dispatch  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules, "vendor_cp.deployment.foundation_execution_approval", approval
    )
    seen["plan_id"] = plan_id
    return seen


class _Db:
    def __init__(self) -> None:
        self.order: list[str] = []

    def commit(self) -> None:
        self.order.append("commit")


def _request(plan_id: Any) -> producer.IssueDispatchRequest:
    return producer.IssueDispatchRequest(
        plan_id=plan_id,
        rollout_ref="rollout-1",
        rollout_command_id="cmd-r",
        dispatch_command_id="cmd-d",
        authorization_expires_at=datetime.now(UTC) + timedelta(hours=1),
        controller_ssh_fingerprint="SHA256:launchkey",
        host_id="host-1",
        host_incarnation="incarnation-1",
        host_enrolment_ref="6f1d1c1e-0000-4000-8000-000000000001",
    )


@pytest.fixture(autouse=True)
def _no_installed_custody(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(producer, "_CUSTODY", None)


def test_with_no_custody_nothing_is_issued_and_no_stage_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _fixture(monkeypatch)
    db = _Db()
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer.issue_dispatch_materials(db, _request(seen["plan_id"]))
    assert caught.value.code is TargetRefusal.CUSTODY_NOT_CONFIGURED
    assert db.order == [] and "rollout" not in seen


def test_custody_installs_once(monkeypatch: pytest.MonkeyPatch) -> None:
    keys = _Keys()
    producer.install_custody(keys.custody())
    with pytest.raises(FoundationBindingsUnavailable):
        producer.install_custody(keys.custody())


def test_a_pair_is_issued_through_the_approval_lifecycle_in_two_committed_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _fixture(monkeypatch)
    keys = _Keys()
    db = _Db()
    issued = producer.issue_dispatch_materials(
        db, _request(seen["plan_id"]), custody=keys.custody()
    )
    assert db.order == ["rollout", "commit", "dispatch", "commit"]
    assert keys.signed == ["authorization", "dispatch"]
    assert seen["rollout"]["command_id"] == "cmd-r"
    assert seen["dispatch"]["command_id"] == "cmd-d"
    # Control received real, verifying signatures from the custody callables.
    assert seen["authorization_signature"].kind == "auth-signature"
    assert seen["dispatch_signature"].kind == "dispatch-signature"
    assert tuple(issued.context_document) == producer.CONTEXT_KEYS
    ctx = issued.context_document
    assert ctx["control_plan_digest"] == "sha256:" + "11" * 32
    assert ctx["execution_sequence"] == 2 and ctx["attempt_no"] == 1
    assert (
        ctx["host_id"] == "host-1"
        and ctx["controller_ssh_fingerprint"] == "SHA256:launchkey"
    )
    assert issued.dispatch_document["attempt_id"] == issued.attempt_id
    assert set(issued.dispatch_document) == {
        "attempt_id",
        "authorization_envelope",
        "dispatch_envelope",
    }


def test_the_context_keys_are_exactly_what_the_target_observer_demands() -> None:
    # Twelve Control-owned facts (FoundationExecutionContextV1) plus four host
    # and controller facts (ExecutionContextV3's additions).
    assert producer.CONTEXT_KEYS == (
        "product_code",
        "environment",
        "target_id",
        "target_ref",
        "operation",
        "release_ref",
        "rollout_ref",
        "plan_id",
        "approval_decision_ref",
        "control_plan_digest",
        "execution_sequence",
        "attempt_no",
        "controller_ssh_fingerprint",
        "host_id",
        "host_incarnation",
        "host_enrolment_ref",
    )


@pytest.mark.parametrize("which", ["authorization_sign", "dispatch_sign"])
@pytest.mark.parametrize("fault", ["wrong_key", "empty", "raises", "not_bytes"])
def test_a_custody_that_signs_wrongly_cannot_get_a_pair_issued(
    monkeypatch: pytest.MonkeyPatch, which: str, fault: str
) -> None:
    seen = _fixture(monkeypatch)
    keys = _Keys()
    stranger = Ed25519PrivateKey.generate()

    def faulty(message: bytes) -> Any:
        if fault == "wrong_key":
            return stranger.sign(message)
        if fault == "empty":
            return b""
        if fault == "not_bytes":
            return "text"
        raise RuntimeError("SECRET-MARKER")

    custody = keys.custody(**{which: faulty})
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer.issue_dispatch_materials(
            _Db(), _request(seen["plan_id"]), custody=custody
        )
    assert caught.value.code is TargetRefusal.CUSTODY_NOT_CONFIGURED
    assert "SECRET-MARKER" not in str(caught.value) and caught.value.__cause__ is None


def test_blank_request_facts_refuse_before_any_signing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _fixture(monkeypatch)
    keys = _Keys()
    request = _request(seen["plan_id"])
    blank = dataclasses.replace(request, controller_ssh_fingerprint=" ")
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer.issue_dispatch_materials(_Db(), blank, custody=keys.custody())
    assert caught.value.code is TargetRefusal.MATERIALS_REFUSED
    assert keys.signed == []


def test_write_materials_is_create_only_0600_in_an_owner_only_directory(
    tmp_path: Path,
) -> None:
    issued = producer.IssuedMaterials("a-1", {"attempt_id": "a-1"}, {"host_id": "h"})
    target = tmp_path / "out"
    target.mkdir(mode=0o700)
    dispatch, context = producer.write_materials(target, issued)
    for path in (dispatch, context):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(context.read_text()) == {"host_id": "h"}
    with pytest.raises(FoundationBindingsUnavailable) as again:
        producer.write_materials(target, issued)
    assert again.value.code is TargetRefusal.MATERIALS_REFUSED
    assert dispatch.read_text() == '{"attempt_id":"a-1"}'


@pytest.mark.parametrize("mode", [0o750, 0o705, 0o777])
def test_write_materials_refuses_a_shared_directory(tmp_path: Path, mode: int) -> None:
    target = tmp_path / "shared"
    target.mkdir()
    target.chmod(mode)
    with pytest.raises(FoundationBindingsUnavailable):
        producer.write_materials(target, producer.IssuedMaterials("a", {}, {}))
    assert list(target.iterdir()) == []


def test_write_materials_refuses_a_missing_directory_and_a_symlinked_one(
    tmp_path: Path,
) -> None:
    issued = producer.IssuedMaterials("a", {}, {})
    with pytest.raises(FoundationBindingsUnavailable):
        producer.write_materials(tmp_path / "absent", issued)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(FoundationBindingsUnavailable):
        producer.write_materials(link, issued)


@pytest.mark.parametrize(
    "delta", [timedelta(hours=4, seconds=5), timedelta(0), timedelta(hours=-1)]
)
def test_the_authorization_expiry_is_capped_at_the_role_window(
    monkeypatch: pytest.MonkeyPatch, delta: timedelta
) -> None:
    seen = _fixture(monkeypatch)
    keys = _Keys()
    request = dataclasses.replace(
        _request(seen["plan_id"]),
        authorization_expires_at=datetime.now(UTC) + delta,
    )
    db = _Db()
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer.issue_dispatch_materials(db, request, custody=keys.custody())
    assert caught.value.code is TargetRefusal.MATERIALS_REFUSED
    assert db.order == [] and keys.signed == []
    naive = dataclasses.replace(request, authorization_expires_at=datetime(2030, 1, 1))
    with pytest.raises(FoundationBindingsUnavailable):
        producer.issue_dispatch_materials(db, naive, custody=keys.custody())


def _issue_argv(tmp_path: Path, **overrides: str) -> list[str]:
    values = {
        "--plan-id": str(uuid4()),
        "--rollout-ref": "r",
        "--rollout-command-id": "c1",
        "--dispatch-command-id": "c2",
        "--authorization-expires-at": (
            datetime.now(UTC) + timedelta(hours=1)
        ).isoformat(),
        "--controller-ssh-fingerprint": "f",
        "--host-id": "h",
        "--host-incarnation": "i",
        "--host-enrolment-ref": "6f1d1c1e-0000-4000-8000-000000000001",
        "--out-dir": str(tmp_path),
        "--custody": "transit",
        "--custody-config": str(tmp_path / "absent.json"),
    }
    values.update(overrides)
    return ["issue", *[part for item in values.items() for part in item]]


def test_issue_requires_the_transit_custody_flags_and_has_no_default_mode(
    tmp_path: Path,
) -> None:
    argv = _issue_argv(tmp_path)
    for flag in ("--custody", "--custody-config"):
        index = argv.index(flag)
        broken = argv[:index] + argv[index + 2 :]
        with pytest.raises(SystemExit):
            producer.main(broken, {})
    with pytest.raises(SystemExit):
        producer.main(_issue_argv(tmp_path, **{"--custody": "stdin"}), {})


def test_issue_refuses_before_the_database_without_a_valid_config_or_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    touched: list[str] = []
    monkeypatch.setattr(
        producer, "_controller_session", lambda env: touched.append("db") or None
    )
    assert producer.main(_issue_argv(tmp_path), {}) == 2
    assert "custody_not_configured" in capsys.readouterr().err
    assert touched == []


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (
            [
                "propose", "--command-id", "c", "--target-id", str(uuid4()),
                "--operation", "deploy", "--descriptor-digest", "d",
                "--execution-plan-digest", "e", "--approval-policy-code", "p",
                "--approval-policy-version", "1",
            ],
            "plan proposed:",
        ),
        (
            [
                "open-approval", "--command-id", "c",
                "--plan-id", str(uuid4()), "--requested-by", str(uuid4()),
            ],
            "approval opened:",
        ),
        (
            [
                "approve", "--command-id", "c",
                "--plan-id", str(uuid4()), "--approval-request-id", str(uuid4()),
            ],
            "plan approved:",
        ),
    ],
)  # fmt: skip
def test_the_plan_lifecycle_commands_print_ids_only_and_commit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    expected: str,
) -> None:
    calls: list[str] = []

    class _Session:
        def commit(self) -> None:
            calls.append("commit")

        def close(self) -> None:
            calls.append("close")

    approval = ModuleType("vendor_cp.deployment.foundation_execution_approval")
    approval.ProposeFoundationPlan = lambda **kw: SimpleNamespace(**kw)  # type: ignore[attr-defined]
    approval.propose_foundation_plan = lambda db, req: SimpleNamespace(id="plan-1")  # type: ignore[attr-defined]
    approval.open_foundation_approval = lambda db, **kw: SimpleNamespace(
        request_id="req-1"
    )  # type: ignore[attr-defined]
    approval.approve_foundation_plan = lambda db, **kw: SimpleNamespace(id="plan-1")  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules, "vendor_cp.deployment.foundation_execution_approval", approval
    )
    monkeypatch.setattr(producer, "_controller_session", lambda env: _Session())
    assert producer.main(argv, {"DATABASE_URL": "x", "PLATFORM_DATABASE_URL": "y"}) == 0
    out = capsys.readouterr().out
    assert expected in out and calls == ["commit", "close"]
    assert "SECRET" not in out


def test_a_lifecycle_command_refuses_on_a_bad_id_without_the_database(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = ModuleType("x")
    stub.approve_foundation_plan = lambda db, **kw: None  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules, "vendor_cp.deployment.foundation_execution_approval", stub
    )
    monkeypatch.setattr(
        producer, "_controller_session", lambda env: SimpleNamespace(close=lambda: None)
    )
    argv = [
        "approve",
        "--command-id",
        "c",
        "--plan-id",
        "not-a-uuid",
        "--approval-request-id",
        "x",
    ]
    assert producer.main(argv, {}) == 2
    assert "invalid request" in capsys.readouterr().err


def test_the_module_holds_no_key_material_and_generates_none() -> None:
    source = Path(producer.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "generate(",
        "private_bytes",
        "PRIVATE KEY",
        "load_pem_private_key",
        "Ed25519PrivateKey",
    ):
        assert forbidden not in source


@pytest.mark.parametrize(
    "ref",
    [
        "enrol-1",
        "",
        "6F1D1C1E-0000-4000-8000-000000000001",
        "6f1d1c1e00004000800000000000001",
    ],
)
def test_a_non_uuid_enrolment_ref_refuses_before_any_signing(
    monkeypatch: pytest.MonkeyPatch, ref: str
) -> None:
    seen = _fixture(monkeypatch)
    keys = _Keys()
    request = dataclasses.replace(_request(seen["plan_id"]), host_enrolment_ref=ref)
    db = _Db()
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer.issue_dispatch_materials(db, request, custody=keys.custody())
    assert caught.value.code is TargetRefusal.MATERIALS_REFUSED
    assert db.order == [] and keys.signed == []


# ── CP-7: the host facts come from the E10 receipt row, or from flags, never both ──


class _Args(SimpleNamespace):
    pass


def _args(**values: Any) -> Any:
    base: dict[str, Any] = {
        "e10_receipt_ref": None,
        "host_id": None,
        "host_incarnation": None,
        "host_enrolment_ref": None,
    }
    base.update(values)
    return _Args(**base)


_TYPED = {
    "host_id": "host-a",
    "host_incarnation": "sha256:" + "ab" * 32,
    "host_enrolment_ref": "6f1d1c1e-0000-4000-8000-000000000001",
}


def test_all_three_typed_flags_are_still_accepted() -> None:
    assert producer._host_facts(_args(**_TYPED), {}) == (
        "host-a",
        "sha256:" + "ab" * 32,
        "6f1d1c1e-0000-4000-8000-000000000001",
    )


@pytest.mark.parametrize("missing", sorted(_TYPED))
def test_a_partial_set_of_typed_flags_refuses(missing: str) -> None:
    typed = {k: v for k, v in _TYPED.items() if k != missing}
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer._host_facts(_args(**typed), {})
    assert caught.value.code is TargetRefusal.MATERIALS_REFUSED


def test_neither_a_receipt_nor_flags_refuses() -> None:
    with pytest.raises(FoundationBindingsUnavailable):
        producer._host_facts(_args(), {})


@pytest.mark.parametrize("flag", sorted(_TYPED))
def test_a_receipt_beside_any_typed_flag_refuses_before_the_database(
    monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    """A typed value that could disagree with the receipt is the typo that would
    spend a single-use host; the database is never opened."""
    from vendor_cp.deployment import lane3_e10

    monkeypatch.setattr(
        lane3_e10,
        "owner_session",
        lambda env: pytest.fail("the owner session was opened before the refusal"),
    )
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer._host_facts(_args(e10_receipt_ref="e10-x", **{flag: _TYPED[flag]}), {})
    assert caught.value.code is TargetRefusal.MATERIALS_REFUSED


def test_the_facts_are_read_from_the_receipt_over_the_owner_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vendor_cp.deployment import lane3_e10

    closed: list[bool] = []
    session = SimpleNamespace(close=lambda: closed.append(True))
    seen: dict[str, Any] = {}

    def fake_session(env: Any) -> Any:
        seen["env"] = dict(env)
        return session

    def fake_facts(db: Any, *, receipt_ref: str) -> Any:
        assert db is session
        seen["ref"] = receipt_ref
        return lane3_e10.HostFacts(
            "host-a", "sha256:" + "cd" * 32, _TYPED["host_enrolment_ref"]
        )

    monkeypatch.setattr(lane3_e10, "owner_session", fake_session)
    monkeypatch.setattr(lane3_e10, "receipt_host_facts", fake_facts)
    got = producer._host_facts(
        _args(e10_receipt_ref="e10-6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11"),
        {lane3_e10.DSN_ENV: "postgresql://owner@h/d"},
    )
    assert got == ("host-a", "sha256:" + "cd" * 32, _TYPED["host_enrolment_ref"])
    assert seen["ref"] == "e10-6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11"
    assert closed == [True]


def test_a_receipt_that_is_not_usable_is_a_typed_refusal_naming_the_code_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vendor_cp.deployment import lane3_e10

    monkeypatch.setattr(
        lane3_e10, "owner_session", lambda env: SimpleNamespace(close=lambda: None)
    )

    def refuse(db: Any, *, receipt_ref: str) -> Any:
        raise lane3_e10.E10Refused("receipt-not-current-root")

    monkeypatch.setattr(lane3_e10, "receipt_host_facts", refuse)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        producer._host_facts(_args(e10_receipt_ref="e10-x"), {})
    assert caught.value.code is TargetRefusal.MATERIALS_REFUSED
    assert "receipt-not-current-root" in str(caught.value)


def test_the_issue_parser_accepts_a_receipt_ref_and_no_typed_host_flags(
    tmp_path: Path,
) -> None:
    argv = _issue_argv(tmp_path)
    for flag in ("--host-id", "--host-incarnation", "--host-enrolment-ref"):
        index = argv.index(flag)
        argv = argv[:index] + argv[index + 2 :]
    argv += ["--e10-receipt-ref", "e10-6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11"]
    parsed = producer._build_parser().parse_args(argv)
    assert parsed.e10_receipt_ref == "e10-6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11"
    assert parsed.host_id is None


def _recovery_fixture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Offline orchestration doubles, not Control/native lock qualification."""
    seen = _fixture(monkeypatch)
    control = sys.modules["dotmac_deployment_control"]
    approval = sys.modules["vendor_cp.deployment.foundation_execution_approval"]
    original = _request(seen["plan_id"])
    now = datetime.now(UTC)
    envelope = SimpleNamespace(
        statement=SimpleNamespace(
            plan_id=str(original.plan_id),
            rollout_ref=original.rollout_ref,
            expires_at=original.authorization_expires_at,
            approval_decision_ref=str(uuid4()),
        ),
        canonical_bytes=b'{"original":"authorization"}',
    )

    @dataclasses.dataclass(frozen=True)
    class Expectation:
        plan_id: Any = original.plan_id
        rollout_id: Any = dataclasses.field(default_factory=uuid4)
        rollout_ref: str = original.rollout_ref
        rollout_command_id: str = original.rollout_command_id
        dispatch_command_id: str = original.dispatch_command_id
        original_authorization: Any = dataclasses.field(
            default_factory=lambda: envelope
        )

    expectation = Expectation()
    control.DispatchResumeExpectation = Expectation
    control.verify_authorization_envelope = lambda value, **kw: seen.update(
        verified=value
    )

    def validate(value: Any, **kw: Any) -> Any:
        seen["validated"] = kw
        if not kw["not_before"] <= kw["at"] < kw["deadline"]:
            raise ValueError("expired before forwarding")
        return SimpleNamespace(canonical_bytes=b"{}")

    control.validate_recovery_dispatch_statement = validate
    old_dispatch = approval.dispatch_foundation_attempt

    def replay(db: Any, **kw: Any) -> Any:
        seen["rollout"] = kw
        db.order.append("rollout")
        return SimpleNamespace(id=expectation.rollout_id)

    def dispatch(db: Any, **kw: Any) -> Any:
        original_signer = kw["dispatch_signer"]
        kw["dispatch_signer"] = SimpleNamespace(
            sign_dispatch=lambda unused: original_signer.sign_dispatch(b"{}")
        )
        result = old_dispatch(db, **kw)
        seen["dispatch"]["dispatch_signer"] = original_signer
        result.authorization_envelope = envelope
        return result

    approval.request_foundation_rollout = replay
    approval.dispatch_foundation_attempt = dispatch
    monkeypatch.setattr(producer, "version", lambda name: "test-installed-version")
    seen["request"] = producer.RecoverDispatchRequest(
        original,
        expectation,
        "recovery-session",
        now - timedelta(seconds=1),
        now + timedelta(minutes=4),
    )
    return seen


def test_recovery_replays_without_authorization_signing_and_shares_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _recovery_fixture(monkeypatch)
    keys, db = _Keys(), _Db()
    result = producer.recover_dispatch_materials(
        db, seen["request"], custody=keys.custody()
    )
    assert db.order == ["rollout", "commit", "dispatch", "commit"]
    assert keys.signed == ["dispatch"]
    assert seen["verified"] is seen["request"].expectation.original_authorization
    assert seen["rollout"]["resume_expectation"] is seen["request"].expectation
    assert seen["dispatch"]["resume_expectation"] is seen["request"].expectation
    assert seen["validated"]["at"].tzinfo is UTC
    assert result.dispatch_document["authorization_envelope"] == {
        "original": "authorization"
    }
    assert result.context_document["host_id"] == "host-1"
    with pytest.raises(FoundationBindingsUnavailable):
        seen["rollout"]["signer"].sign(b"replacement")
    with pytest.raises(FoundationBindingsUnavailable):
        seen["dispatch"]["dispatch_signer"].sign_dispatch(b"duplicate")
    assert keys.signed == ["dispatch"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("rollout_command_id", "changed"),
        ("dispatch_command_id", "changed"),
        ("rollout_ref", "changed"),
        ("plan_id", uuid4()),
        ("authorization_expires_at", datetime.now(UTC) + timedelta(hours=2)),
        ("rollout_command_id", " "),
        ("dispatch_command_id", 1),
        ("host_id", ""),
        ("host_enrolment_ref", "not-a-uuid"),
    ],
)
def test_recovery_changed_original_inputs_refuse_before_any_stage(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: Any,
) -> None:
    seen = _recovery_fixture(monkeypatch)
    req = seen["request"]
    req = dataclasses.replace(
        req,
        original_request=dataclasses.replace(req.original_request, **{field: value}),
    )
    keys, db = _Keys(), _Db()
    with pytest.raises(FoundationBindingsUnavailable):
        producer.recover_dispatch_materials(db, req, custody=keys.custody())
    assert db.order == [] and keys.signed == []


@pytest.mark.parametrize("change", ["expired", "future", "naive", "late", "session"])
def test_recovery_window_and_session_refuse_before_any_stage(
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    seen = _recovery_fixture(monkeypatch)
    req, now = seen["request"], datetime.now(UTC)
    values = {
        "expired": {"deadline": now - timedelta(seconds=1)},
        "future": {"not_before": now + timedelta(minutes=1)},
        "naive": {"deadline": now.replace(tzinfo=None)},
        "late": {"deadline": req.original_request.authorization_expires_at},
        "session": {"session_id": ""},
    }
    keys, db = _Keys(), _Db()
    with pytest.raises(FoundationBindingsUnavailable):
        producer.recover_dispatch_materials(
            db, dataclasses.replace(req, **values[change]), custody=keys.custody()
        )
    assert db.order == [] and keys.signed == []


def test_recovery_fresh_sign_time_expiry_refuses_after_replay_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _recovery_fixture(monkeypatch)
    real_datetime = datetime
    late = seen["request"].deadline

    class Clock:
        calls = 0

        @classmethod
        def now(cls, tz: Any) -> datetime:
            cls.calls += 1
            return real_datetime.now(tz) if cls.calls == 1 else late

    # Preserve datetime type checks while changing only the clock callable.
    class DateTime(real_datetime):
        now = Clock.now

    monkeypatch.setattr(producer, "datetime", DateTime)
    # The normal datetime bounds remain valid instances of the actual base type.
    # Expire from the validator, modelling a wait after entering dispatch.
    control = sys.modules["dotmac_deployment_control"]

    def expired(value: Any, **kw: Any) -> None:
        assert kw["at"] >= late
        raise ValueError("expired")

    control.validate_recovery_dispatch_statement = expired
    # Use DateTime bounds for the runtime guard.
    req = dataclasses.replace(
        seen["request"],
        not_before=DateTime.fromisoformat(seen["request"].not_before.isoformat()),
        deadline=DateTime.fromisoformat(late.isoformat()),
        original_request=dataclasses.replace(
            seen["request"].original_request,
            authorization_expires_at=DateTime.fromisoformat(
                seen["request"].original_request.authorization_expires_at.isoformat()
            ),
        ),
    )
    keys, db = _Keys(), _Db()
    with pytest.raises(ValueError, match="expired"):
        producer.recover_dispatch_materials(db, req, custody=keys.custody())
    assert db.order == ["rollout", "commit"] and keys.signed == []


def test_recovery_missing_replay_refuses_new_authorization(monkeypatch):
    seen = _recovery_fixture(monkeypatch)
    approval = sys.modules["vendor_cp.deployment.foundation_execution_approval"]

    def new_rollout(db, **kwargs):
        kwargs["signer"].sign(b"new authorization forbidden")

    approval.request_foundation_rollout = new_rollout
    keys, db = _Keys(), _Db()
    with pytest.raises(FoundationBindingsUnavailable):
        producer.recover_dispatch_materials(db, seen["request"], custody=keys.custody())
    assert keys.signed == [] and db.order == []


@pytest.mark.parametrize("failed_commit", [1, 2])
def test_recovery_commit_failure_propagates_without_extra_sign_or_output(
    monkeypatch, failed_commit
):
    seen = _recovery_fixture(monkeypatch)

    class Database(_Db):
        def commit(self):
            super().commit()
            if self.order.count("commit") == failed_commit:
                raise RuntimeError("modeled commit failure")

    keys, db = _Keys(), Database()
    with pytest.raises(RuntimeError, match="commit failure"):
        producer.recover_dispatch_materials(db, seen["request"], custody=keys.custody())
    assert keys.signed == ([] if failed_commit == 1 else ["dispatch"])
    assert db.order.count("commit") == failed_commit


def test_recovery_cli_uses_recovery_custody_and_existing_writer(monkeypatch, tmp_path):
    from vendor_cp import audit_bootstrap
    from vendor_cp.deployment import transit_custody

    seen = _recovery_fixture(monkeypatch)
    calls = []
    db = SimpleNamespace(close=lambda: calls.append("close"))
    custody = object()
    monkeypatch.setattr(audit_bootstrap, "ensure_process_audit_actions", lambda: None)
    monkeypatch.setattr(
        producer, "load_recovery_request", lambda path, **kw: seen["request"]
    )
    monkeypatch.setattr(transit_custody, "load_config", lambda path: "config")
    monkeypatch.setattr(transit_custody, "read_token", lambda stream: b"test-token")
    monkeypatch.setattr(
        transit_custody, "build_recovery_custody", lambda *a, **kw: custody
    )
    monkeypatch.setattr(
        transit_custody, "build_custody", lambda *a, **kw: pytest.fail("normal custody")
    )
    monkeypatch.setattr(producer, "_controller_session", lambda env: db)

    def recover(session, request, *, custody):
        assert session is db and request is seen["request"]
        calls.append("recover")
        return "materials"

    monkeypatch.setattr(producer, "recover_dispatch_materials", recover)
    monkeypatch.setattr(
        producer, "write_materials", lambda path, value: calls.append((path, value))
    )
    args = [
        "recover-dispatch",
        "--recovery-request-sha256",
        "ab" * 32,
        "--recovery-request",
        "public.json",
        "--custody",
        "transit",
        "--custody-config",
        "config.json",
        "--out-dir",
        str(tmp_path),
    ]
    assert producer.main(args, {}, stdin=object()) == 0
    assert calls == ["recover", "close", (str(tmp_path), "materials")]


def test_recovery_invalid_projection_stops_before_token_or_database(
    monkeypatch, tmp_path
):
    from vendor_cp import audit_bootstrap
    from vendor_cp.deployment import transit_custody

    monkeypatch.setattr(audit_bootstrap, "ensure_process_audit_actions", lambda: None)
    monkeypatch.setattr(
        transit_custody, "read_token", lambda *a: pytest.fail("token read")
    )
    monkeypatch.setattr(
        producer, "_controller_session", lambda *a: pytest.fail("DB opened")
    )
    path = tmp_path / "invalid.json"
    path.write_text('{"unknown":true}')
    args = [
        "recover-dispatch",
        "--recovery-request-sha256",
        "ab" * 32,
        "--recovery-request",
        str(path),
        "--custody",
        "transit",
        "--custody-config",
        "missing",
        "--out-dir",
        str(tmp_path),
    ]
    assert producer.main(args, {}) == 2


def test_recovery_refuses_legacy_control_api_before_token(monkeypatch, tmp_path):
    from vendor_cp.deployment import transit_custody

    seen = _fixture(monkeypatch)
    keys, db = _Keys(), _Db()
    request = producer.RecoverDispatchRequest(
        _request(seen["plan_id"]),
        object(),
        "session",
        datetime.now(UTC),
        datetime.now(UTC) + timedelta(minutes=1),
    )
    monkeypatch.setattr(
        transit_custody, "read_token", lambda *a: pytest.fail("token read")
    )
    with pytest.raises(FoundationBindingsUnavailable, match="API is unavailable"):
        producer.recover_dispatch_materials(db, request, custody=keys.custody())
    assert keys.signed == [] and db.order == []


@pytest.mark.parametrize("defect", ["duplicate", "oversized", "symlink", "fifo"])
def test_recovery_projection_file_ingress_is_bounded_and_strict(tmp_path, defect):
    path = tmp_path / "projection.json"
    if defect == "duplicate":
        path.write_text('{"session_id":"one","session_id":"two"}')
    elif defect == "oversized":
        path.write_bytes(b" " * (128 * 1024 + 1))
    elif defect == "symlink":
        target = tmp_path / "actual.json"
        target.write_text("{}")
        path.symlink_to(target)
    else:
        os.mkfifo(path)
    with pytest.raises(FoundationBindingsUnavailable):
        producer.load_recovery_request(str(path), expected_sha256="ab" * 32)


@pytest.mark.parametrize(
    "digest",
    [None, 1, "", "ab" * 31, "AB" * 32, "sha256:" + "ab" * 32, "ab" * 32 + "\n"],
)
def test_recovery_projection_digest_is_required_strict_before_file_open(
    monkeypatch, digest
):
    monkeypatch.setattr(
        producer.os, "open", lambda *a, **kw: pytest.fail("file opened")
    )
    with pytest.raises(FoundationBindingsUnavailable):
        producer.load_recovery_request("/fixture.json", expected_sha256=digest)


def test_recovery_projection_missing_digest_cannot_fall_back(tmp_path):
    with pytest.raises(TypeError):
        producer.load_recovery_request(str(tmp_path / "projection.json"))


@pytest.mark.parametrize("when", ["first-read", "eof"])
def test_recovery_projection_same_inode_mutation_refuses_before_parse(
    monkeypatch, tmp_path, when
):
    from vendor_cp.deployment import transit_custody

    path = tmp_path / "projection.json"
    raw = b"{}"
    path.write_bytes(raw)
    before = path.stat()
    real_read = producer.os.read
    mutated = False

    def read(fd, count):
        nonlocal mutated
        result = real_read(fd, count)
        if not mutated and (
            (when == "first-read" and result) or (when == "eof" and not result)
        ):
            path.write_bytes(b"[]")
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
            mutated = True
        return result

    monkeypatch.setattr(producer.os, "read", read)
    monkeypatch.setattr(
        transit_custody, "strict_json", lambda *a: pytest.fail("parsed mutable bytes")
    )
    with pytest.raises(FoundationBindingsUnavailable):
        producer.load_recovery_request(
            str(path), expected_sha256=hashlib.sha256(raw).hexdigest()
        )
    assert mutated and path.stat().st_ino == before.st_ino


@pytest.mark.parametrize(
    "defect", ["hardlink", "group-write", "parent-write", "parent-symlink"]
)
def test_recovery_projection_path_and_ownership_guards(tmp_path, monkeypatch, defect):
    from vendor_cp.deployment import transit_custody

    parent = tmp_path / "protected"
    parent.mkdir(mode=0o700)
    path = parent / "projection.json"
    path.write_bytes(b"{}")
    if defect == "hardlink":
        os.link(path, tmp_path / "other.json")
    elif defect == "group-write":
        path.chmod(0o620)
    elif defect == "parent-write":
        parent.chmod(0o720)
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(parent, target_is_directory=True)
        path = alias / path.name
    monkeypatch.setattr(
        transit_custody, "strict_json", lambda *a: pytest.fail("unsafe path parsed")
    )
    with pytest.raises(FoundationBindingsUnavailable):
        producer.load_recovery_request(
            str(path), expected_sha256=hashlib.sha256(b"{}").hexdigest()
        )


@pytest.mark.parametrize("digest", ["AB" * 32, "ab" * 32])
def test_recovery_cli_wrong_digest_stops_before_token_or_database(
    monkeypatch, tmp_path, digest
):
    from vendor_cp import audit_bootstrap
    from vendor_cp.deployment import transit_custody

    monkeypatch.setattr(audit_bootstrap, "ensure_process_audit_actions", lambda: None)
    monkeypatch.setattr(
        transit_custody, "read_token", lambda *a: pytest.fail("token read")
    )
    monkeypatch.setattr(
        producer, "_controller_session", lambda *a: pytest.fail("DB opened")
    )
    path = tmp_path / "projection.json"
    path.write_text("{}")
    args = [
        "recover-dispatch",
        "--recovery-request",
        str(path),
        "--recovery-request-sha256",
        digest,
        "--custody",
        "transit",
        "--custody-config",
        "missing",
        "--out-dir",
        str(tmp_path),
    ]
    assert producer.main(args, {}) == 2
