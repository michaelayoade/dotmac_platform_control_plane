"""CP-side producer of the dispatch materials (R8). No key is ever held here."""

from __future__ import annotations

import dataclasses
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
