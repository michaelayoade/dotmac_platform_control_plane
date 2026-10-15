"""Fixed installed launch adapters have no caller-selected operational inputs."""

import sys
from types import ModuleType

import pytest

from vendor_cp.cli import main
from vendor_cp.cli.owners import by_command

ENTRIES = (
    (
        "bootstrap-collector",
        "vendor_cp.deployment.gate0_runner_bootstrap",
        "run_installed_bootstrap",
    ),
    (
        "collect-e-credential",
        "vendor_cp.deployment.gate0_runner_credential",
        "run_installed_credential_collection",
    ),
)


@pytest.mark.parametrize("command,module_name,symbol", ENTRIES)
@pytest.mark.parametrize("status", [0, 3])
def test_cli_reaches_only_the_declared_argument_free_owner(
    monkeypatch, capsys, command, module_name, symbol, status
):
    calls = []

    def installed_owner():
        calls.append(symbol)
        print("synthetic-owner-stream")
        return status

    module = ModuleType(module_name)
    setattr(module, symbol, installed_owner)
    monkeypatch.setitem(sys.modules, module_name, module)
    declared = by_command()[f"gate0 {command}"]
    assert (declared.module, declared.symbol, declared.mutates) == (
        module_name,
        symbol,
        True,
    )
    assert main(["gate0", command]) == status
    assert calls == [symbol]
    output = capsys.readouterr()
    assert output.out == "synthetic-owner-stream\n"
    assert output.err == ""


@pytest.mark.parametrize("command,module_name,symbol", ENTRIES)
def test_bootstrap_cli_suppresses_private_owner_failure(
    monkeypatch, capsys, command, module_name, symbol
):
    def unavailable():
        raise ValueError("synthetic-private-diagnostic-must-not-escape")

    module = ModuleType(module_name)
    setattr(module, symbol, unavailable)
    monkeypatch.setitem(sys.modules, module_name, module)
    assert main(["gate0", command]) == 3
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "GATE0_BOOTSTRAP_UNAVAILABLE\n"


@pytest.mark.parametrize("command,module_name,symbol", ENTRIES)
@pytest.mark.parametrize(
    "option", ["--host", "--unit", "--deadline", "--credential-file"]
)
def test_bootstrap_cli_cannot_override_the_installed_inputs(
    monkeypatch, command, module_name, symbol, option
):
    calls = []
    module = ModuleType(module_name)
    setattr(module, symbol, lambda: calls.append(symbol))
    monkeypatch.setitem(sys.modules, module_name, module)
    with pytest.raises(SystemExit) as refused:
        main(["gate0", command, option, "synthetic-override"])
    assert refused.value.code == 2
    assert calls == []
