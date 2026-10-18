"""Installed adapters preserve fixed paths, binary stdout and secret suppression."""

import pytest

from vendor_cp.deployment import gate0_collection, gate0_runner_handoff
from vendor_cp.deployment.gate0_runner_controller import InstalledCollectionController
from vendor_cp.deployment.gate0_runner_installation import InstalledRunnerCollection


@pytest.mark.parametrize("failure_at", ["installation", "controller"])
def test_collection_entrypoint_never_exposes_private_failure(
    monkeypatch, capsys, failure_at
):
    def refused(*_args):
        raise ValueError("synthetic-private-diagnostic-must-not-escape")

    monkeypatch.setattr(
        InstalledRunnerCollection,
        "from_installed",
        refused if failure_at == "installation" else lambda: object(),
    )
    if failure_at == "controller":
        # This adapter test reaches run's failure boundary without qualifying or
        # starting any actual installation, socket, token or SSH child.
        monkeypatch.setattr(
            InstalledCollectionController, "__init__", lambda self, installed: None
        )
    monkeypatch.setattr(InstalledCollectionController, "run", refused)
    assert gate0_collection.run_installed_collection() == 3
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "GATE0_COLLECTION_UNAVAILABLE\n"


@pytest.mark.parametrize(
    "owner,entrypoint",
    [
        (gate0_runner_handoff.FixedLaunchHolder, "run_installed_handoff_holder"),
        (
            gate0_runner_handoff.InstalledHandoffReceiver,
            "run_installed_handoff_receiver",
        ),
    ],
)
def test_handoff_entrypoints_keep_binary_stdout_and_fail_closed(
    monkeypatch, capsys, owner, entrypoint
):
    def refused():
        raise ValueError("synthetic-private-diagnostic-must-not-escape")

    monkeypatch.setattr(owner, "from_installed", refused)
    assert getattr(gate0_runner_handoff, entrypoint)() == 3
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "GATE0_HANDOFF_REFUSED\n"
