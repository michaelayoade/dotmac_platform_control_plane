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

import pytest

from vendor_cp.cli import main
from vendor_cp.deployment import fence_commands

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


def test_fence_holding_refuses_an_empty_expected_digest_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fence_commands, "owner_runtime", _explode)
    with pytest.raises(fence_commands.FenceCommandConfigError):
        fence_commands.fence_holding(proof_document={}, expected_digest="")


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
            "transition-fence",
            "close",
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
    assert envelope["command"] == "admin transition-fence close"
    assert envelope["status"] == "ok"
