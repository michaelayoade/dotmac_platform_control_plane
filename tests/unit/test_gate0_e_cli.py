"""Finite E CLI delegates; synthetic owners do not qualify evidence or custody."""

import sys
from types import ModuleType

import pytest

from vendor_cp.cli import main
from vendor_cp.cli.owners import by_command

ENTRIES = (
    (
        "await-e-transfer",
        "vendor_cp.deployment.gate0_e_transfer",
        "run_installed_await_e_transfer",
    ),
    (
        "prepare-e-draft",
        "vendor_cp.deployment.gate0_e_publication",
        "run_installed_prepare_e_draft",
    ),
    (
        "publish-e",
        "vendor_cp.deployment.gate0_e_publication",
        "run_installed_publish_e",
    ),
    (
        "verify-e-published",
        "vendor_cp.deployment.gate0_e_final_readback",
        "run_installed_verify_e_published",
    ),
    ("finalize-e", "vendor_cp.deployment.gate0_e_writer", "run_installed_prepare_e"),
    (
        "verify-e-b-archive",
        "vendor_cp.deployment.gate0_e_b_holder",
        "run_installed_verify_e_b_archive",
    ),
)


@pytest.mark.parametrize("command,module_name,symbol", ENTRIES)
@pytest.mark.parametrize("status", [0, 3])
def test_e_cli_delegates_once_without_inputs_or_output_transformation(
    monkeypatch, capsys, command, module_name, symbol, status
):
    calls = []

    def selected_owner():
        calls.append(symbol)
        sys.stdout.write("synthetic-public-owner-result")
        return status

    module = ModuleType(module_name)
    setattr(module, symbol, selected_owner)
    monkeypatch.setitem(sys.modules, module_name, module)
    owner = by_command()[f"gate0 {command}"]
    assert (owner.module, owner.symbol, owner.mutates) == (
        module_name,
        symbol,
        command not in {"verify-e-published", "await-e-transfer"},
    )
    assert main(["gate0", command]) == status
    assert calls == [symbol]
    streams = capsys.readouterr()
    assert streams.out == "synthetic-public-owner-result"
    assert streams.err == ""


@pytest.mark.parametrize("command,module_name,symbol", ENTRIES)
def test_e_cli_does_not_expose_owner_exception(
    monkeypatch, capsys, command, module_name, symbol
):
    def failure():
        raise ValueError("synthetic-private-owner-detail")

    module = ModuleType(module_name)
    setattr(module, symbol, failure)
    monkeypatch.setitem(sys.modules, module_name, module)
    assert main(["gate0", command]) == 3
    streams = capsys.readouterr()
    assert streams.out == ""
    assert streams.err == "GATE0_E_UNAVAILABLE\n"


@pytest.mark.parametrize("command,module_name,symbol", ENTRIES)
@pytest.mark.parametrize(
    "flag",
    [
        "--path",
        "--host",
        "--credential-file",
        "--deadline",
        "--release-id",
        "--phase",
        "--client",
        "--slot",
    ],
)
def test_e_cli_refuses_installed_policy_overrides(
    monkeypatch, command, module_name, symbol, flag
):
    calls = []
    module = ModuleType(module_name)
    setattr(module, symbol, lambda: calls.append(symbol))
    monkeypatch.setitem(sys.modules, module_name, module)
    with pytest.raises(SystemExit) as refused:
        main(["gate0", command, flag, "synthetic-override"])
    assert refused.value.code == 2
    assert not calls


@pytest.mark.parametrize("status", [0, 3])
def test_public_jit_cli_is_one_argument_free_owner(monkeypatch, capsys, status):
    module_name = "vendor_cp.deployment.gate0_runner_lifecycle_courier"
    module = ModuleType(module_name)
    calls = []
    module.run_installed_public_jit_runner = lambda: calls.append(()) or status
    monkeypatch.setitem(sys.modules, module_name, module)
    owner = by_command()["gate0 public-jit-runner-credential"]
    assert (owner.module, owner.symbol, owner.mutates) == (
        module_name,
        "run_installed_public_jit_runner",
        True,
    )
    assert main(["gate0", "public-jit-runner-credential"]) == status
    assert calls == [()]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "extra",
    [
        ["unexpected"],
        ["--path", "/synthetic/profile"],
        ["--uid", "123"],
        ["--deadline", "60"],
        ["--credential-file", "/synthetic/secret"],
        ["--command", "other"],
        ["--mode", "publish"],
    ],
)
def test_public_jit_cli_rejects_all_extra_inputs(extra):
    with pytest.raises(SystemExit) as caught:
        main(["gate0", "public-jit-runner-credential", *extra])
    assert caught.value.code == 2


def test_public_jit_cli_sanitizes_unexpected_owner_failure(monkeypatch, capsys):
    module_name = "vendor_cp.deployment.gate0_runner_lifecycle_courier"
    module = ModuleType(module_name)

    def failure():
        raise ValueError("synthetic-private-launch-detail")

    module.run_installed_public_jit_runner = failure
    monkeypatch.setitem(sys.modules, module_name, module)
    assert main(["gate0", "public-jit-runner-credential"]) == 3
    assert capsys.readouterr() == ("", "")
