"""Offline contracts for opt-in runtime wiring through the CP deploy owner.

These inspect YAML and execute only the shell argument composer with a fake
docker function. Strict Compose rendering remains a hosted CI obligation.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
KEY_PATH = "/run/secrets/dotmac/platform-cp/desired-state/primary.key"
LEDGER_PATH = "/var/lib/dotmac-deploy/ledger"
AUTH_PATH = "/run/secrets/dotmac/platform-cp/github"
SCOPE_PATH = "/etc/dotmac-deploy/gate-scope.json"
GIT_CONFIG_PATH = "/etc/dotmac-deploy/gitconfig"
REQUIRED_INPUTS = {
    "VENDOR_DESIRED_SIGNING_KEY_ID",
    "VENDOR_DEPLOY_CP_LEDGER_HOST_DIR",
    "VENDOR_DEPLOY_CP_GATE_SCOPE_HOST_FILE",
    "VENDOR_DEPLOY_CP_GITHUB_AUTH_HOST_DIR",
    "VENDOR_DEPLOY_CP_GIT_CONFIG_HOST_FILE",
}


def _yaml(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def test_overlay_only_supplies_app_environment_and_protected_binds() -> None:
    overlay = _yaml("docker-compose.keyless.yml")
    assert set(overlay) == {"services"}
    assert set(overlay["services"]) == {"app"}
    app = overlay["services"]["app"]
    assert set(app) == {"environment", "volumes"}
    env = app["environment"]
    assert env == {
        "VENDOR_DEPLOY_AGENT_ENABLED": "true",
        "VENDOR_DESIRED_SIGNING_KEY_ID": (
            "${VENDOR_DESIRED_SIGNING_KEY_ID:?"
            "Set the public desired-state signing key id}"
        ),
        "VENDOR_DESIRED_SIGNING_KEY_FILE": KEY_PATH,
        "VENDOR_DESIRED_SIGNING_KEY_POINTER": (
            "secret/dotmac/platform-cp/desired-state/signing-key"
        ),
        "VENDOR_DEPLOY_LEDGER_DIR": LEDGER_PATH,
        "VENDOR_DEPLOY_GH_EXECUTABLE": "/usr/local/bin/gh",
        "VENDOR_DEPLOY_GH_SHA256": (
            "sha256:a95a4e011d77e9cd0e9922c13fda2b95195c6be29dfa58207075fd983bbae744"
        ),
        "VENDOR_DEPLOY_GATE_SCOPE_FILE": SCOPE_PATH,
        "GH_CONFIG_DIR": AUTH_PATH,
        "GIT_CONFIG_GLOBAL": GIT_CONFIG_PATH,
        "GIT_TERMINAL_PROMPT": "0",
        "GH_PROMPT_DISABLED": "1",
    }
    mounts = app["volumes"]
    assert len(mounts) == 5
    assert {mount["target"] for mount in mounts} == {
        KEY_PATH,
        LEDGER_PATH,
        AUTH_PATH,
        SCOPE_PATH,
        GIT_CONFIG_PATH,
    }
    host_inputs = {
        LEDGER_PATH: "VENDOR_DEPLOY_CP_LEDGER_HOST_DIR",
        SCOPE_PATH: "VENDOR_DEPLOY_CP_GATE_SCOPE_HOST_FILE",
        AUTH_PATH: "VENDOR_DEPLOY_CP_GITHUB_AUTH_HOST_DIR",
        GIT_CONFIG_PATH: "VENDOR_DEPLOY_CP_GIT_CONFIG_HOST_FILE",
    }
    for mount in mounts:
        assert set(mount) == {"type", "source", "target", "read_only", "bind"}
        assert mount["type"] == "bind"
        assert mount["bind"] == {"create_host_path": False}
        assert mount["read_only"] is (mount["target"] != LEDGER_PATH)
        if mount["target"] == KEY_PATH:
            assert mount["source"] == KEY_PATH
        else:
            prefix = "${" + host_inputs[mount["target"]] + ":?"
            assert mount["source"].startswith(prefix)


def test_overlay_requires_every_public_input_without_empty_or_unset_fallback() -> None:
    source = (ROOT / "docker-compose.keyless.yml").read_text(encoding="utf-8")
    references = re.findall(r"\$\{([^}]+)\}", source)
    # Compose's :? form refuses both missing and empty inputs. A plain ? only
    # rejects missing values; a default would silently admit incomplete wiring.
    required = [re.fullmatch(r"([A-Z_]+):\?\S.*", value) for value in references]
    assert all(required)
    assert {match[1] for match in required if match} == REQUIRED_INPUTS
    assert len(references) == len(REQUIRED_INPUTS)


def test_github_binary_digest_obeys_runtime_prefixed_digest_contract() -> None:
    env = _yaml("docker-compose.keyless.yml")["services"]["app"]["environment"]
    digest = env["VENDOR_DEPLOY_GH_SHA256"]
    # GitHubCandidateEvidenceReader calls contracts.sha with its default prefix.
    # Independently enforce that format rather than only repeating a pin literal.
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    assert not re.fullmatch(r"sha256:[0-9a-f]{64}", digest.removeprefix("sha256:"))


def test_base_keeps_bootstrap_and_all_service_restrictions() -> None:
    base = _yaml("docker-compose.production.yml")["services"]
    for role in ("app", "relay", "ops"):
        service = base[role]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["env_file"] == "${VENDOR_CP_RUNTIME_ENV_FILE:-.env}"
        assert not any(
            key.startswith(("VENDOR_DEPLOY_", "VENDOR_DESIRED_", "GH_", "GIT_"))
            for key in service["environment"]
        )
    source = (ROOT / "scripts/deploy_production.sh").read_text(encoding="utf-8")
    assert "${EXPECTED_DEPLOYMENT_PROFILE-production-bootstrap}" in source
    assert '"VENDOR_DEPLOYMENT_PROFILE=$EXPECTED_DEPLOYMENT_PROFILE"' in source


@pytest.mark.parametrize("override", [None, "", "/public path/keyless.yml"])
def test_existing_compose_owner_adds_only_explicit_second_file(
    override: str | None,
) -> None:
    source = (ROOT / "scripts/deploy_production.sh").read_text(encoding="utf-8")
    declarations = re.findall(
        r"(?m)^readonly (?:COMPOSE_FILE|COMPOSE_OVERRIDE_FILE|ENV_FILE)=.*$", source
    )
    assert len(declarations) == 3
    function = re.search(r"(?ms)^compose\(\) \{\n.*?^\}", source)
    assert function is not None
    environment = {"PATH": os.defpath}
    if override is not None:
        environment["COMPOSE_OVERRIDE_FILE"] = override
        environment["COMPOSE_FILE"] = "/public path/base.yml"
        environment["ENV_FILE"] = "/public path/host.env"
    script = "\n".join(declarations) + "\n" + function[0] + "\n"
    script += 'docker() { printf "%s\\0" "$@"; }; compose run --rm ops diagnose\n'
    result = subprocess.run(  # noqa: S603 -- isolated argument composer, fake docker
        ["/bin/bash", "-eu", "-c", script],
        env=environment,
        capture_output=True,
        check=True,
    )
    expected = [
        "compose",
        "--env-file",
        environment.get("ENV_FILE", ".env"),
        "-f",
        environment.get("COMPOSE_FILE", "docker-compose.production.yml"),
    ]
    if override:
        expected += ["-f", override]
    expected += ["run", "--rm", "ops", "diagnose"]
    assert result.stdout.decode().split("\0") == [*expected, ""]
