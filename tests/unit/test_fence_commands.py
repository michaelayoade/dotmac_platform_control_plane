"""`vendor_cp.deployment.fence_commands`, without a database.

Three questions, no Postgres needed for any of them: does the broker protocol
accept exactly its own reply and nothing else; does every function refuse a
missing host-supplied value BEFORE it ever tries to connect; and, running a
whole CLI invocation end to end with the fence functions faked out, does
nothing but a protocol line or the final envelope ever reach stdout. The real
database behaviour — the SQL, the ACL — is `tests/migration/test_fence_commands.py`'s
job.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

from vendor_cp.cli import main
from vendor_cp.cli.runtime import translate
from vendor_cp.deployment import fence_commands
from vendor_cp.deployment.transition_fence import (
    FenceProof,
    FenceRefusalCode,
    FenceRefused,
)

# ── StdioBrokerTerminator ────────────────────────────────────────────────────


def test_the_terminator_accepts_the_exact_reply_and_writes_the_exact_request() -> None:
    stdin = io.StringIO("DOTMAC-FENCE-TERMINATED v1 abc\n")
    stdout = io.StringIO()
    terminator = fence_commands.StdioBrokerTerminator("abc", stdin=stdin, stdout=stdout)

    terminator()  # must not raise

    assert stdout.getvalue() == "DOTMAC-FENCE-TERMINATE v1 abc\n"


def test_the_terminator_refuses_a_reply_naming_a_different_fence_id() -> None:
    stdin = io.StringIO("DOTMAC-FENCE-TERMINATED v1 someone-elses-run\n")
    terminator = fence_commands.StdioBrokerTerminator(
        "abc", stdin=stdin, stdout=io.StringIO()
    )

    with pytest.raises(fence_commands.BrokerProtocolError):
        terminator()


def test_the_terminator_refuses_end_of_input() -> None:
    terminator = fence_commands.StdioBrokerTerminator(
        "abc", stdin=io.StringIO(""), stdout=io.StringIO()
    )

    with pytest.raises(fence_commands.BrokerProtocolError):
        terminator()


def test_the_terminator_refuses_a_reply_carrying_an_extra_token() -> None:
    stdin = io.StringIO("DOTMAC-FENCE-TERMINATED v1 abc extra-token\n")
    terminator = fence_commands.StdioBrokerTerminator(
        "abc", stdin=stdin, stdout=io.StringIO()
    )

    with pytest.raises(fence_commands.BrokerProtocolError):
        terminator()


# ── argument validation refuses before any connection ───────────────────────


def _explode() -> fence_commands.DatabaseRuntime:
    raise AssertionError(
        "owner_runtime() was called — argument validation should have "
        "refused before any connection was ever attempted"
    )


def test_close_fence_refuses_an_empty_database_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.close_fence(
            database="",
            fence_id="fence-1",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_close_fence_refuses_an_empty_fence_id_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.close_fence(
            database="db1",
            fence_id="",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_close_fence_refuses_a_prior_digest_given_without_a_prior_fence_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.close_fence(
            database="db1",
            fence_id="fence-1",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
            prior_expected_digest="sha256:" + "0" * 64,
        )


def test_close_fence_refuses_a_prior_document_without_a_prior_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.close_fence(
            database="db1",
            fence_id="fence-1",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
            prior_document={"schema": "TransitionFenceProof.v1"},
            expected_prior_fence_id="prior-run",
        )


def test_fence_holding_refuses_an_empty_database_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.fence_holding(
            database="",
            proof_document={},
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id="fence-1",
        )


def test_fence_holding_refuses_an_empty_expected_digest_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.fence_holding(
            database="db1",
            proof_document={},
            expected_digest="",
            expected_fence_id="fence-1",
        )


def test_fence_holding_refuses_an_empty_expected_fence_id_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.fence_holding(
            database="db1",
            proof_document={},
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id="",
        )


def test_fence_holding_refuses_a_malformed_fence_id_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.fence_holding(
            database="db1",
            proof_document={},
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id="not a valid fence id!",
        )


@pytest.mark.parametrize("bad_seconds", [0.0, -1.0, float("nan"), float("inf")])
def test_close_fence_refuses_a_non_positive_or_non_finite_session_wait(
    monkeypatch: pytest.MonkeyPatch, bad_seconds: float
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.close_fence(
            database="db1",
            fence_id="fence-1",
            session_wait_seconds=bad_seconds,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_close_fence_refuses_a_malformed_fence_id_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.close_fence(
            database="db1",
            fence_id="has a space",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_restore_fence_refuses_an_empty_database_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.restore_fence(
            database="",
            proof_document={},
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id="fence-1",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_restore_fence_refuses_an_empty_expected_digest_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.restore_fence(
            database="db1",
            proof_document={},
            expected_digest="",
            expected_fence_id="fence-1",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_restore_fence_refuses_an_empty_expected_fence_id_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.restore_fence(
            database="db1",
            proof_document={},
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id="",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_restore_fence_refuses_a_malformed_expected_fence_id_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.restore_fence(
            database="db1",
            proof_document={},
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id="not valid!",
            session_wait_seconds=1.0,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


@pytest.mark.parametrize("bad_seconds", [0.0, -1.0, float("nan"), float("inf")])
def test_restore_fence_refuses_a_non_positive_or_non_finite_session_wait(
    monkeypatch: pytest.MonkeyPatch, bad_seconds: float
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.restore_fence(
            database="db1",
            proof_document={},
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id="fence-1",
            session_wait_seconds=bad_seconds,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


# ── fence_holding binds the document to the caller's own coordinates ───────


def test_fence_holding_reports_false_before_connecting_on_a_database_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A structurally valid, digest-matching document naming a DIFFERENT
    database is `holding: False` — never evidence about the database the
    caller actually asked about — and this is caught before `owner_runtime()`
    is ever called."""
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)

    proof = FenceProof(
        database="other-db",
        fence_id="fence-1",
        prior_acl="",
        prior_grants=frozenset(),
        fenced_roles=(),
        member_roles=(),
        absent_roles=(),
        terminated_count=0,
        fenced_at=datetime.now(UTC),
    )
    document = proof.to_document()

    result = fence_commands.fence_holding(
        database="db1",
        proof_document=document,
        expected_digest=proof.digest(),
        expected_fence_id="fence-1",
    )
    assert result == {"holding": False}


def test_fence_holding_reports_false_before_connecting_on_a_fence_id_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)

    proof = FenceProof(
        database="db1",
        fence_id="fence-1",
        prior_acl="",
        prior_grants=frozenset(),
        fenced_roles=(),
        member_roles=(),
        absent_roles=(),
        terminated_count=0,
        fenced_at=datetime.now(UTC),
    )
    document = proof.to_document()

    result = fence_commands.fence_holding(
        database="db1",
        proof_document=document,
        expected_digest=proof.digest(),
        expected_fence_id="a-different-run",
    )
    assert result == {"holding": False}


# ── translate() gives FenceRefused/FenceCommandConfigError/BrokerProtocolError
#    their own identity, rather than collapsing to execution.failed ─────────


def test_translate_carries_fence_refused_as_its_own_code_and_before_acl() -> None:
    error = FenceRefused(
        FenceRefusalCode.WRITER_SESSIONS_SURVIVED,
        "2 writer backend(s) survived",
        before_acl="GRANT CONNECT ON DATABASE foo TO bar",
    )

    refusal = translate(error)

    assert refusal.code == "owner.fence_refused"
    assert "writer_sessions_survived" in refusal.message
    assert "GRANT CONNECT ON DATABASE foo TO bar" in refusal.message


def test_translate_carries_fence_refused_without_before_acl() -> None:
    error = FenceRefused(FenceRefusalCode.UNKNOWN_DATABASE, "no such database")

    refusal = translate(error)

    assert refusal.code == "owner.fence_refused"
    assert "before_acl" not in refusal.message


def test_translate_carries_fence_command_config_error_as_usage() -> None:
    refusal = translate(
        fence_commands.FenceCommandConfigError("database must be given")
    )

    assert refusal.code == "usage.fence_command_invalid"


def test_translate_carries_broker_protocol_error_as_unavailable_evidence() -> None:
    refusal = translate(fence_commands.BrokerProtocolError("wrong reply"))

    assert refusal.code == "evidence.fence_broker_unavailable"


# ── stdout discipline ─────────────────────────────────────────────────────


class _FakeConnectionContext:
    def __enter__(self) -> object:
        return object()

    def __exit__(self, *exc_info: object) -> None:
        return None


class _FakeEngine:
    def execution_options(self, **_kwargs: object) -> _FakeEngine:
        return self

    def connect(self) -> _FakeConnectionContext:
        return _FakeConnectionContext()


class _FakeRuntime:
    platform_engine = _FakeEngine()


class _FakeProof:
    #: `close_fence` reads its result's `fence_id` back from `proof.fence_id`
    #: — never from the `fence_id` argument it was called with — so this fake
    #: carries its own value, matched against below.
    fence_id = "fence-xyz"

    def to_document(self) -> dict[str, object]:
        return {"schema": "TransitionFenceProof.v1", "fake": True}

    def digest(self) -> str:
        return "sha256:" + "0" * 64


def test_a_close_run_writes_only_protocol_lines_and_the_final_envelope(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A fake connection and a fake `fence_writers` that calls the terminator
    once, exactly like a real drain would — nothing here touches a database."""

    def _fake_fence_writers(
        conn: object,
        *,
        database: str,
        fence_id: str,
        session_wait_seconds: float,
        prior: object,
        expected_prior_fence_id: str | None,
        terminator: fence_commands.Terminator,
    ) -> _FakeProof:
        terminator()
        return _FakeProof()

    monkeypatch.setattr(fence_commands, "owner_runtime", lambda: _FakeRuntime())
    monkeypatch.setattr(fence_commands, "fence_writers", _fake_fence_writers)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO("DOTMAC-FENCE-TERMINATED v1 fence-xyz\n")
    )

    exit_code = main(
        [
            "--format",
            "json",
            "admin",
            "transition-fence-close",
            "--database",
            "db1",
            "--fence-id",
            "fence-xyz",
            "--session-wait-seconds",
            "2",
        ]
    )

    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line]
    assert exit_code == 0
    # Exactly one protocol line, first, then nothing but the trailing JSON
    # envelope block `main()` ever prints — `--format json` is multi-line
    # (`indent=2`), so "the single final envelope" means one contiguous
    # trailing block, not one physical line.
    assert lines[0] == "DOTMAC-FENCE-TERMINATE v1 fence-xyz"
    assert all(not line.startswith("DOTMAC-FENCE-") for line in lines[1:])
    envelope = json.loads("\n".join(lines[1:]))
    assert envelope["command"] == "admin transition-fence-close"
    assert envelope["status"] == "ok"
    # The fence_id in both the data and the references comes back from the
    # PROOF (`_FakeProof.fence_id`), never echoed from `--fence-id` alone —
    # they happen to be equal here, but the READ PATH is what this proves.
    assert envelope["data"]["fence_id"] == "fence-xyz"
    assert envelope["references"]["fence_id"] == "fence-xyz"
