"""Configuration/local-file acceptance; no runtime, connectivity or custody proof."""

from __future__ import annotations

import base64
import builtins
import json
import logging
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

import pytest
from dotmac_kernel.config import settings

from vendor_cp.cli import main
from vendor_cp.config import VendorSettings
from vendor_cp.deployment import candidate_materials as materials


@pytest.fixture(autouse=True)
def configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use existing owners with synthetic development configuration."""
    monkeypatch.setattr(
        settings, "database_url", "postgresql+psycopg://x@localhost/test"
    )
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("VENDOR_PROVIDER_MODE", "fake")
    monkeypatch.setenv("VENDOR_LICENCE_SIGNING_MODE", "configured")
    for name in (
        "VENDOR_OFFERED_CAPABILITIES",
        "VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON",
        "VENDOR_LICENCE_OVERLAP_KEY_FILE",
        "VENDOR_LICENCE_OVERLAP_KEY_ID",
        "VENDOR_RELAY_DISPATCHER_DATABASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)


def signer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    # Synthetic raw Ed25519 test material, never a deployed credential.
    path = tmp_path / "signer"
    path.write_text(base64.urlsafe_b64encode(bytes(range(32))).decode())
    monkeypatch.setenv("VENDOR_LICENCE_SIGNING_KEY_FILE", str(path))
    monkeypatch.setenv("VENDOR_LICENCE_SIGNING_KEY_ID", "synthetic-primary")
    return path


def checks(result: materials.CandidateMaterialProbeResult) -> dict[str, str]:
    return {check.name: check.status for check in result.checks}


def test_app_ready_with_configured_primary_and_absent_optional_overlap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer(monkeypatch, tmp_path)
    result = materials.probe(role="app")
    assert result.status == "ready"
    assert result.exit_code == 0
    assert checks(result) == {
        "kernel_configuration": "ready",
        "vendor_configuration": "ready",
        "licence_signing": "ready",
        "licence_overlap_signing": "ready",
    }


@pytest.mark.parametrize("content", ["", "malformed", "AA"])
def test_invalid_primary_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str
) -> None:
    path = signer(monkeypatch, tmp_path)
    path.write_text(content)
    assert checks(materials.probe(role="app"))["licence_signing"] == "refused"


def test_missing_primary_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer(monkeypatch, tmp_path).unlink()
    result = materials.probe(role="app")
    assert result.status == "refused"
    assert result.exit_code == 3


@pytest.mark.parametrize("partial", ["file", "id"])
def test_partial_overlap_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, partial: str
) -> None:
    path = signer(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "VENDOR_LICENCE_OVERLAP_KEY_" + partial.upper(),
        str(path) if partial == "file" else "synthetic-overlap",
    )
    assert checks(materials.probe(role="app"))["licence_overlap_signing"] == "refused"


def test_valid_and_invalid_overlap_use_existing_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = signer(monkeypatch, tmp_path)
    monkeypatch.setenv("VENDOR_LICENCE_OVERLAP_KEY_FILE", str(path))
    monkeypatch.setenv("VENDOR_LICENCE_OVERLAP_KEY_ID", "synthetic-overlap")
    assert materials.probe(role="app").status == "ready"
    monkeypatch.setenv("VENDOR_LICENCE_OVERLAP_KEY_FILE", str(tmp_path / "absent"))
    assert checks(materials.probe(role="app"))["licence_overlap_signing"] == "refused"


def test_relay_requires_dispatcher_even_when_not_expected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VENDOR_RELAY_EXPECTED", "false")
    monkeypatch.setenv("VENDOR_LICENCE_SIGNING_MODE", "unknown")
    assert materials.probe(role="relay").status == "refused"
    monkeypatch.setenv(
        "VENDOR_RELAY_DISPATCHER_DATABASE_URL", "postgresql+psycopg://x@localhost/test"
    )
    result = materials.probe(role="relay")
    assert result.status == "ready"
    assert checks(result) == {
        "kernel_configuration": "ready",
        "relay_dispatcher": "ready",
    }


def test_kernel_owner_refusal_is_retained(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "database_url", "")
    assert checks(materials.probe(role="app"))["kernel_configuration"] == "refused"


def test_unexpected_kernel_validator_value_error_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from dotmac_kernel import config

    def failing(value: object) -> NoReturn:
        print("synthetic-sensitive-canary", file=sys.stderr)
        raise ValueError("synthetic-sensitive-canary")

    monkeypatch.setattr(config, "validate_settings", failing)
    monkeypatch.setenv("VENDOR_RELAY_DISPATCHER_DATABASE_URL", "synthetic-dispatcher")
    result = materials.probe(role="relay")
    assert result.status == "unavailable"
    assert result.exit_code == 4
    assert capsys.readouterr() == ("", "")


def test_vendor_mode_refused_only_for_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer(monkeypatch, tmp_path)
    monkeypatch.setenv("VENDOR_PROVIDER_MODE", "unknown")
    assert checks(materials.probe(role="app"))["vendor_configuration"] == "refused"


def test_refusal_wins_unavailable_and_diagnostics_are_discarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vendor_cp.licensing import signing_adapter

    signer(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "database_url", "")
    previous = logging.root.manager.disable

    def failing(**kwargs: object) -> NoReturn:
        print("synthetic-sensitive-canary")
        print("synthetic-sensitive-canary", file=sys.stderr)
        logging.error("synthetic-sensitive-canary")
        logging.log(100, "synthetic-sensitive-canary")
        raise RuntimeError("synthetic-sensitive-canary")

    monkeypatch.setattr(signing_adapter, "build_licence_signer", failing)
    result = materials.probe(role="app")
    assert result.status == "refused"
    assert checks(result)["licence_signing"] == "unavailable"
    assert capsys.readouterr() == ("", "")
    assert logging.root.manager.disable == previous
    assert "synthetic-sensitive-canary" not in result.json_document()


@pytest.mark.parametrize("dispatcher", [False, True])
def test_import_diagnostics_and_errors_never_escape(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    dispatcher: bool,
) -> None:
    if dispatcher:
        monkeypatch.setenv(
            "VENDOR_RELAY_DISPATCHER_DATABASE_URL", "synthetic-dispatcher"
        )
    original = builtins.__import__

    def importing(name: str, *args: object, **kwargs: object) -> object:
        if name == "dotmac_kernel.config":
            print("synthetic-sensitive-canary")
            print("synthetic-sensitive-canary", file=sys.stderr)
            logging.critical("synthetic-sensitive-canary")
            logging.log(100, "synthetic-sensitive-canary")
            raise ImportError("synthetic-sensitive-canary")
        return original(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", importing)
    result = materials.probe(role="relay")
    assert result.status == ("unavailable" if dispatcher else "refused")
    assert result.exit_code == (4 if dispatcher else 3)
    assert checks(result)["kernel_configuration"] == "unavailable"
    assert capsys.readouterr() == ("", "")


def test_cli_closed_wire_ignores_generic_format(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    signer(monkeypatch, tmp_path)
    assert main(["deployment", "candidate-material-probe", "--role", "app"]) == 0
    output = capsys.readouterr()
    assert not output.err
    wire = json.loads(output.out)
    assert set(wire) == {"schema", "status", "checks"}
    assert wire["schema"] == "CandidateMaterialProbeResult.v1"
    assert len(output.out.encode()) <= 16 * 1024
    names = [check["name"] for check in wire["checks"]]
    assert len(names) == len(set(names))
    assert all(name.isascii() and len(name) <= 64 for name in names)
    assert all(set(check) == {"name", "status"} for check in wire["checks"])


@pytest.mark.parametrize("error", [RuntimeError, SystemExit])
def test_cli_unexpected_handler_failure_is_closed_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: type[BaseException],
) -> None:
    from vendor_cp.cli import commands

    def failing(args: object) -> NoReturn:
        print("synthetic-sensitive-canary", file=sys.stderr)
        raise error("synthetic-sensitive-canary")

    monkeypatch.setattr(commands, "deployment_candidate_material_probe", failing)
    assert main(["deployment", "candidate-material-probe", "--role", "relay"]) == 4
    output = capsys.readouterr()
    assert not output.err
    assert json.loads(output.out) == {
        "schema": "CandidateMaterialProbeResult.v1",
        "status": "unavailable",
        "checks": [{"name": "probe_execution", "status": "unavailable"}],
    }


@pytest.mark.parametrize("argv", [[], ["--role", "other"]])
def test_explicit_supported_role_required(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["deployment", "candidate-material-probe", *argv])
    assert caught.value.code == 2


def test_legacy_command_keeps_generic_envelope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--format", "json", "diagnose", "owners"]) == 0
    wire = json.loads(capsys.readouterr().out)
    assert wire["command"] == "diagnose owners"
    assert "data" in wire and "schema" not in wire


def test_descriptor_role_and_material_coverage_matches_both_directions() -> None:
    root = Path(__file__).resolve().parents[2]
    descriptor = tomllib.loads((root / "deploy/product.toml").read_text())
    assert materials.ROLE_MATERIALS == {
        role["code"]: frozenset(role["materials"]) for role in descriptor["roles"]
    }


def test_compatibility_exports_preserve_exception_and_validator_identity() -> None:
    from vendor_cp.config import ProductionConfigurationError
    from vendor_cp.config_errors import ProductionConfigurationError as CanonicalError
    from vendor_cp.relay import config, runner

    assert ProductionConfigurationError is CanonicalError
    assert runner.RelayNotConfiguredError is config.RelayNotConfiguredError
    assert runner.require_dispatcher_dsn is config.require_dispatcher_dsn
    with pytest.raises(runner.RelayNotConfiguredError):
        runner.require_dispatcher_dsn(VendorSettings(provider_mode="fake"))


def test_probe_imports_and_execution_do_not_reach_runtime_owners(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer(monkeypatch, tmp_path)
    original = builtins.__import__
    forbidden = (
        "dotmac_kernel.db",
        "dotmac_kernel.session_runtime",
        "vendor_cp.assembly",
        "vendor_cp.relay.runner",
        "dotmac_deployment_foundation",
        "socket",
        "httpx",
    )

    def importing(name: str, *args: object, **kwargs: object) -> object:
        assert not name.startswith(forbidden)
        return original(name, *args, **kwargs)  # type: ignore[arg-type]

    # Signing adapter already imported by test bootstrap; disallow the actual
    # global installation entry point too, rather than relying on module names.
    from vendor_cp.licensing import signing_adapter

    def install_forbidden(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("probe installed process-global signers")

    monkeypatch.setattr(
        signing_adapter, "install_runtime_licence_signers", install_forbidden
    )
    monkeypatch.setattr(builtins, "__import__", importing)
    assert materials.probe(role="app").status == "ready"
    monkeypatch.setenv("VENDOR_RELAY_DISPATCHER_DATABASE_URL", "synthetic-dispatcher")
    assert materials.probe(role="relay").status == "ready"


def test_installed_entry_point_probe_and_import_time_refusal(tmp_path: Path) -> None:
    """Exercise entry-point metadata and cold imports, using synthetic env only."""
    script = (
        "from importlib.metadata import distribution; "
        "e=next(e for e in distribution('dotmac-platform-control-plane').entry_points "
        "if e.name=='dotmac-platform'); e.load()()"
    )
    # Exact distribution authority is shared with the existing CLI.
    from vendor_cp.identity import DISTRIBUTION

    script = script.replace("dotmac-platform-control-plane", DISTRIBUTION)
    env = {
        "PATH": os.defpath,
        "DATABASE_URL": "postgresql+psycopg://x@localhost/test",
        "PLATFORM_DATABASE_URL": "postgresql+psycopg://x@localhost/test",
        "VENDOR_RELAY_DISPATCHER_DATABASE_URL": "synthetic-dispatcher",
    }
    argv = [
        sys.executable,
        "-c",
        script,
        "deployment",
        "candidate-material-probe",
        "--role",
        "relay",
    ]
    result = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "ready"
    assert not result.stderr
    env["VENDOR_RELAY_EXPECTED"] = "synthetic-sensitive-canary"
    result = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 3
    assert json.loads(result.stdout)["status"] == "refused"
    assert "synthetic-sensitive-canary" not in result.stdout + result.stderr
    assert not result.stderr

    del env["VENDOR_RELAY_EXPECTED"]
    env["JWT_TTL_SECONDS"] = "synthetic-sensitive-canary"
    result = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 3
    wire = json.loads(result.stdout)
    assert wire["status"] == "refused"
    assert {c["name"]: c["status"] for c in wire["checks"]}[
        "kernel_configuration"
    ] == "refused"
    assert "synthetic-sensitive-canary" not in result.stdout + result.stderr
    assert not result.stderr
