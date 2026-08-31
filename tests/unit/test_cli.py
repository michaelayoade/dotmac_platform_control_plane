"""The CLI's own behaviour: verdicts, redaction, secret intake, delegation.

These exercise the parts that have no owner behind them — the transport. What a
command MEANS is tested where its owner lives; what this file checks is that the
answer comes out with the right number on it, that nothing secret comes out at
all, and that a secret can only get in through a held file or stdin.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from vendor_cp.cli import build_parser, main
from vendor_cp.cli.delegate import FOUNDATION_COMMAND, foundation_path
from vendor_cp.cli.exits import ExitCode, Refusal, refuse
from vendor_cp.cli.io import REDACTED, Result, read_secret, redact, render
from vendor_cp.cli.runtime import translate

# ── verdicts ────────────────────────────────────────────────────────────────


def test_a_refusal_takes_its_exit_code_from_the_declared_vocabulary() -> None:
    """A raiser names the code and nothing else, so it cannot pick a status that
    disagrees with the vocabulary."""
    assert refuse("owner.conflict", "x").exit_code is ExitCode.REFUSED
    assert refuse("evidence.not_found", "x").exit_code is ExitCode.UNAVAILABLE
    with pytest.raises(AssertionError):
        refuse("owner.invented_code", "x")


def test_an_unreadable_digest_and_a_refused_approval_are_different_verdicts() -> None:
    """`0.1.0a4` collapsed these and reported a formatting bug as tamper
    detection — a security refusal standing in for an encoding difference, which
    is the worst available failure mode because it looks like the system
    working. They exit on different numbers here."""

    class DigestEncodingError(ValueError): ...

    class ApprovalRefusedError(ValueError): ...

    assert translate(DigestEncodingError("unreadable")).exit_code is ExitCode.MISMATCH
    assert translate(ApprovalRefusedError("no")).exit_code is ExitCode.REFUSED


def test_translation_walks_the_mro_so_a_new_subclass_lands_correctly() -> None:
    """A module adding `PlanSupersededError(PlanRefusedError)` next release must
    be refused as a plan refusal, not silently become an execution failure."""

    class PlanRefusedError(ValueError): ...

    class PlanSupersededError(PlanRefusedError): ...

    assert translate(PlanSupersededError("gone")).exit_code is ExitCode.REFUSED


def test_an_unrecognised_error_is_an_execution_failure_not_a_refusal() -> None:
    assert translate(RuntimeError("boom")).exit_code is ExitCode.FAILED


def test_a_refusal_passed_through_translation_is_unchanged() -> None:
    original = refuse("owner.forbidden", "no")
    assert translate(original) is original


# ── output ──────────────────────────────────────────────────────────────────


def test_credential_named_fields_are_redacted_at_any_depth() -> None:
    payload = {
        "password": "hunter2",
        "nested": [{"jwtSecret": "s3cr3t", "key_id": "primary"}],
        "db_password": "p",
    }
    cleaned = redact(payload)
    assert cleaned == {
        "password": REDACTED,
        "nested": [{"jwtSecret": REDACTED, "key_id": "primary"}],
        "db_password": REDACTED,
    }
    assert "hunter2" not in json.dumps(cleaned)
    assert "s3cr3t" not in json.dumps(cleaned)


def test_evidence_shaped_names_survive_redaction() -> None:
    """A digest and a key IDENTIFIER are what an operator came for. Redacting
    them would push people to read raw values out of the database instead."""
    assert redact({"credential_id": "abc", "digest": "sha256:0"}) == {
        "credential_id": "abc",
        "digest": "sha256:0",
    }


def test_the_envelope_carries_the_code_and_the_status_in_both_formats() -> None:
    result = Result(
        command="deployment authorize",
        exit_code=ExitCode.REFUSED,
        refusal_code="owner.approval_refused",
        message="no",
    )
    envelope = json.loads(render(result, "json"))
    assert envelope["exit_code"] == 3
    assert envelope["status"] == "refused"
    assert envelope["refusal_code"] == "owner.approval_refused"
    table = render(result, "table")
    assert "owner.approval_refused" in table
    assert "exit_code" in table


# ── secrets ─────────────────────────────────────────────────────────────────


def test_a_secret_can_be_read_from_a_held_file(tmp_path: Path) -> None:
    held = tmp_path / "held"
    held.write_text("s3cret\n", encoding="utf-8")
    assert read_secret(from_file=str(held), from_stdin=False, prompt="p") == "s3cret"


def test_a_secret_can_be_read_from_stdin() -> None:
    stream = io.StringIO("s3cret\n")
    assert (
        read_secret(from_file=None, from_stdin=True, prompt="p", stdin=stream)
        == "s3cret"
    )


def test_naming_neither_source_refuses_rather_than_waiting_on_stdin() -> None:
    """Defaulting to stdin would make a forgotten flag hang a deploy forever."""
    with pytest.raises(Refusal) as caught:
        read_secret(from_file=None, from_stdin=False, prompt="p")
    assert caught.value.exit_code is ExitCode.USAGE


def test_naming_both_sources_refuses() -> None:
    with pytest.raises(Refusal) as caught:
        read_secret(from_file="x", from_stdin=True, prompt="p")
    assert caught.value.exit_code is ExitCode.USAGE


def test_an_empty_source_refuses_instead_of_supplying_an_empty_secret(
    tmp_path: Path,
) -> None:
    held = tmp_path / "held"
    held.write_text("\n", encoding="utf-8")
    with pytest.raises(Refusal):
        read_secret(from_file=str(held), from_stdin=False, prompt="p")


def test_an_unreadable_held_file_is_a_usage_fault_not_a_missing_artifact(
    tmp_path: Path,
) -> None:
    with pytest.raises(Refusal) as caught:
        read_secret(from_file=str(tmp_path / "absent"), from_stdin=False, prompt="p")
    assert caught.value.code == "usage.secret_unreadable"


# ── dispatch ────────────────────────────────────────────────────────────────


def test_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0


def test_an_unknown_group_exits_two() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["nonsense"])
    assert caught.value.code == int(ExitCode.USAGE)


def test_a_group_with_no_command_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["deployment"]) == int(ExitCode.USAGE)


def test_every_command_help_renders(capsys: pytest.CaptureFixture[str]) -> None:
    """Every documented command's help path, in one sweep.

    This is the acceptance step that a clean install repeats against the real
    wheel: if a handler's module cannot even be reached to build its parser, the
    surface is not what the owner table says it is.
    """
    from vendor_cp.cli.owners import OWNERS

    for owner in OWNERS:
        group, name = owner.command.split(" ", 1)
        with pytest.raises(SystemExit) as caught:
            main([group, name, "--help"])
        assert caught.value.code == 0, owner.command
    capsys.readouterr()


def test_the_foundation_passthrough_reports_an_absent_tool_as_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Absence of the delegate is `4`, not `3`.

    Nothing refused: the tool that would have decided was not there. An operator
    branching on the status needs that difference, because one of them is worth
    retrying after an install and the other never is.
    """
    monkeypatch.setenv("PATH", "")
    assert foundation_path() is None
    code = main(["--format", "json", "deployment", "foundation", "--", "render"])
    assert code == int(ExitCode.UNAVAILABLE)
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["refusal_code"] == "evidence.tool_absent"
    assert FOUNDATION_COMMAND in envelope["message"]


def test_the_passthrough_forwards_the_vector_untouched_past_one_separator() -> None:
    """Only a LEADING `--` is this parser's; everything after it is the
    delegate's, including a second `--`. Rewriting the vector would defeat the
    one thing this command exists to do."""
    parser = build_parser()
    args = parser.parse_args(
        ["deployment", "foundation", "--", "rollback", "--", "--execute"]
    )
    forwarded = list(args.argv)
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    assert forwarded == ["rollback", "--", "--execute"]


def test_the_parser_defaults_to_the_table_format() -> None:
    args = build_parser().parse_args(["diagnose", "owners"])
    assert args.output_format == "table"
    assert args.command == "diagnose owners"


def test_diagnose_owners_runs_without_a_database(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A diagnosis must not require the thing it may be diagnosing."""
    assert main(["--format", "json", "diagnose", "owners"]) == int(ExitCode.OK)
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["data"]["count"] > 0
