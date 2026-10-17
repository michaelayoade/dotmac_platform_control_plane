"""Focused controller boundaries; these mocks do not qualify a real campaign."""

import ast
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from vendor_cp.deployment import gate0_runner_controller as controller
from vendor_cp.deployment.gate0_runner_installation import InstalledRunnerCollection

SOURCE = Path(controller.__file__).read_text()
TREE = ast.parse(SOURCE)


def _a_boundary(tmp_path, *, failed_join=False, acknowledged=True):
    a, b = (
        SimpleNamespace(projection=Mock(), command_id="a", ssh=Mock()),
        SimpleNamespace(projection=Mock(), command_id="b", ssh=Mock()),
    )
    installed = InstalledRunnerCollection(
        "sha256:" + "1" * 64,
        os.getuid(),
        os.getuid() + 1,
        "https://cp.example",
        Mock(),
        b"{}",
        (a, b),
        "human-reference",
        str(tmp_path / "evidence"),
        str(tmp_path / "claimed"),
        b"{}",
    )
    subject = controller.InstalledCollectionController(installed)
    core, client, tokens, root = Mock(), Mock(), Mock(), Mock()
    expected = SimpleNamespace(operation=Mock())
    client.approval.return_value = SimpleNamespace(
        binding=SimpleNamespace(expectation=expected)
    )
    core.issue_a.return_value = b"authorization", expected
    root.case_a_complete = acknowledged
    if failed_join:
        core.complete_case_a.side_effect = RuntimeError("failed A join/ACK")
    issuer, issue, consume = Mock(), Mock(), Mock()
    subject._verifiers = Mock(return_value=(Mock(), Mock(), Mock()))
    with (
        patch.object(InstalledRunnerCollection, "require_actual_job"),
        patch.object(
            controller, "_private_parent", return_value=os.open(tmp_path, os.O_RDONLY)
        ),
        patch.object(controller, "_wait_original") as wait,
        patch.object(
            controller.FixedEvidenceCollector, "for_installed", return_value=core
        ),
        patch.object(controller, "RunnerProjectionClient", return_value=client),
        patch.object(controller, "OwnedCollectorHandoff", return_value=root),
        patch.object(
            controller.InstalledJobTokens, "from_installed", return_value=tokens
        ),
        patch.object(
            controller, "OwnedIssuerSession", return_value=issuer
        ) as issuer_owner,
        patch.object(controller, "OwnedAttesterSession", side_effect=(issue, consume)),
        patch.object(controller, "close_owned_sessions") as cleanup,
    ):
        with pytest.raises((RuntimeError, controller.ProviderRefused)):
            subject.run()
        client.approval.assert_called_once_with(a.projection, tokens.next.return_value)
        assert all(call.args == (a.projection,) for call in tokens.next.call_args_list)
        assert tokens.next.call_count == 8
        subject._verifiers.assert_called_once_with(a)
        issuer_owner.assert_called_once_with(a.ssh)
        wait.assert_called_once_with(a.projection)
        core.bind_case_b.assert_not_called()
        core.complete_case_a.assert_called_once_with(root, issue, consume)
        cleanup.assert_called_once_with(issuer, issue, consume)
        root.close.assert_called_once()
        assert tokens._credential == ""
        assert tokens._failed is True
        assert not (tmp_path / "evidence").exists()
        assert (tmp_path / "claimed").exists()
        with pytest.raises(controller.ProviderRefused):
            subject.run()


def test_failed_a_join_blocks_all_b_and_cleans_actual_sessions(tmp_path):
    _a_boundary(tmp_path, failed_join=True)


def test_missing_actual_ack_blocks_all_b(tmp_path):
    _a_boundary(tmp_path, acknowledged=False)


def test_exclusive_private_output_cannot_overwrite(tmp_path):
    directory = os.open(tmp_path, os.O_RDONLY)
    try:
        controller._exclusive(directory, "evidence", b"exact-evidence")
        with pytest.raises(FileExistsError):
            controller._exclusive(directory, "evidence", b"replacement")
        assert (tmp_path / "evidence").read_bytes() == b"exact-evidence"
        assert stat.S_IMODE((tmp_path / "evidence").stat().st_mode) == 0o600
    finally:
        os.close(directory)


def test_original_clock_and_concrete_owners_are_retained():
    assert "deadline=case.projection.deadline" in SOURCE
    assert "case.projection.wall_origin" in SOURCE
    assert "case.projection.monotonic_origin" in SOURCE
    assert "issuer_b.collector.outcomes[0].result_bytes" in SOURCE
    assert "authorization_ref=authorization_id" in SOURCE
    assert "range(16)" in SOURCE
    assert "root.complete_case_b(" in SOURCE
    assert "core.complete_case_a(root, issue_a, consume_a)" in SOURCE
    assert "FramedCaseCollector(" not in SOURCE
    assert "read_approval(" not in SOURCE
    assert "observe_b_withdrawal(" not in SOURCE
    assert '"readiness_accepted": False' in SOURCE


def test_no_public_output_precedes_final_owned_join():
    run = next(
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.FunctionDef) and node.name == "run"
    )
    calls = [node for node in ast.walk(run) if isinstance(node, ast.Call)]
    join = next(
        node.lineno
        for node in calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "complete_case_b"
    )
    mkdir = next(
        node.lineno
        for node in calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "mkdir"
    )
    assert join < mkdir
    assert "print(" not in SOURCE
    assert "logging" not in SOURCE


def test_wait_uses_original_start_and_deadline_without_reanchoring():
    case = Mock(
        start=12.0,
        deadline=20.0,
        window=SimpleNamespace(
            document={
                "not_before": "2026-10-15T12:00:02Z",
                "expires_at": "2026-10-15T12:00:10Z",
            }
        ),
    )
    with (
        patch.object(controller.time, "monotonic", side_effect=(10.0, 12.0)),
        patch.object(controller, "datetime", wraps=datetime) as wall,
        patch.object(controller.time, "sleep") as sleep,
    ):
        wall.now.side_effect = (
            datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC),
            datetime(2026, 10, 15, 12, 0, 2, tzinfo=UTC),
        )
        controller._wait_original(case)
        sleep.assert_called_once_with(0.25)
        case.require_open.assert_called_once_with()
        assert (case.start, case.deadline) == (12.0, 20.0)


@pytest.mark.parametrize(
    ("deadline", "elapsed", "reads", "expected"),
    (
        (150.0, 10.0, 1, 5.0),
        (70.0, 10.0, 9, 5.0),
        (55.0, 10.0, 6, 2.0),
        (55.0, 25.0, 6, 0.5),
    ),
)
def test_pending_human_wait_is_fixed_bounded_and_shrinks(
    deadline, elapsed, reads, expected
):
    case = Mock(deadline=deadline)
    with (
        patch.object(controller.time, "monotonic", return_value=elapsed),
        patch.object(controller.time, "sleep") as sleep,
    ):
        controller._wait_pending_withdrawal(case, reads)
        sleep.assert_called_once_with(expected)
        assert case.require_open.call_count == 2
        assert case.deadline == deadline


@pytest.mark.parametrize("elapsed", (30.0, 30.001, 44.0))
def test_pending_refuses_at_or_beyond_original_reserve_without_sleep(elapsed):
    case = Mock(deadline=55.0)
    with (
        patch.object(controller.time, "monotonic", return_value=elapsed),
        patch.object(controller.time, "sleep") as sleep,
    ):
        with pytest.raises(controller.ProviderRefused):
            controller._wait_pending_withdrawal(case, 1)
        sleep.assert_not_called()


def test_sixteenth_pending_read_has_no_extra_interval():
    case = Mock(deadline=300.0)
    with patch.object(controller.time, "sleep") as sleep:
        with pytest.raises(controller.ProviderRefused):
            controller._wait_pending_withdrawal(case, 16)
        sleep.assert_not_called()


def test_applied_withdrawal_breaks_before_pending_wait():
    run = next(
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.FunctionDef) and node.name == "run"
    )
    loop = next(
        node
        for node in ast.walk(run)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and node.target.id == "read_index"
    )
    applied = next(
        node
        for node in loop.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Call)
        and isinstance(node.test.func, ast.Attribute)
        and node.test.func.attr == "observe_b_projection"
    )
    pending_wait = next(
        node
        for node in loop.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_wait_pending_withdrawal"
    )
    assert isinstance(applied.body[-1], ast.Break)
    assert applied.lineno < pending_wait.lineno


def test_last_poll_two_existing_request_caps_preserve_strict_final_reserve():
    deadline = 100.0
    latest_start = deadline - controller._LATEST_POLL_START_MARGIN
    assert controller._POLL_REQUEST_SECONDS == 2 * 5
    assert controller._FINAL_RESERVE_SECONDS == 15
    assert deadline - (latest_start + controller._POLL_REQUEST_SECONDS) == 15
    # Equality is refused; any admitted start precedes this boundary.
    case = Mock(deadline=deadline)
    with (
        patch.object(controller.time, "monotonic", return_value=latest_start),
        patch.object(controller.time, "sleep") as sleep,
    ):
        with pytest.raises(controller.ProviderRefused):
            controller._wait_pending_withdrawal(case, 15)
        sleep.assert_not_called()
    assert "<= _FINAL_RESERVE_SECONDS" in SOURCE
    assert ">= b.projection.deadline - _LATEST_POLL_START_MARGIN" in SOURCE
