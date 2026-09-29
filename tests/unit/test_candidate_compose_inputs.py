"""Pure refusals at the candidate app Compose input boundary."""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

import pytest

from vendor_cp.deployment import candidate_compose_inputs as inputs
from vendor_cp.deployment.candidate_compose_inputs import (
    ALLOWED_APP_ENV_KEYS,
    DOCKER_CLIENT_PATH,
    LICENCE_KEY_HOST_FILE,
    LOCAL_DOCKER_HOST,
    CandidateInputRefused,
    _read_literal_env,
    build_candidate_compose_launch,
)
from vendor_cp.deployment.candidate_roles import CandidateRoles

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "0123456789abcdef0123456789abcdef"
DIGEST = "sha256:" + "a" * 64
IMAGE = "ghcr.io/michaelayoade/dotmac_vendor_control_plane@" + DIGEST
DATABASE = "vendor_control_plane"


def _values() -> dict[str, str]:
    roles = CandidateRoles.for_run(database=DATABASE, run_id=RUN_ID)
    app_password = "a" + secrets.token_urlsafe(20) + "$literal"
    platform_password = "p" + secrets.token_urlsafe(20) + "$literal"
    return {
        "DATABASE_URL": (
            f"postgresql+psycopg://{roles.app}:{app_password}@db:5432/{DATABASE}"
        ),
        "PLATFORM_DATABASE_URL": (
            f"postgresql+psycopg://{roles.platform}:{platform_password}@db:5432/{DATABASE}"
        ),
        "APP_ENV": "production",
        "SERVER_NAME": "vendor-cp-prod",
        "ENVIRONMENT": "production",
        "VENDOR_DEPLOYMENT_PROFILE": "production-bootstrap",
        "PLATFORM_ROOT_DOMAIN": "vendor.dotmac.io",
        "TRUSTED_HOSTS": "vendor.dotmac.io",
        "TENANCY": "multi",
        "JWT_SECRET": secrets.token_urlsafe(32) + "$literal",
        "SESSION_HASH_SECRET": secrets.token_urlsafe(32),
        "CSRF_ENABLED": "true",
        "CSRF_SECRET": secrets.token_urlsafe(32),
        "RATE_LIMIT_ENABLED": "true",
        "VENDOR_PROVIDER_MODE": "fake",
        "VENDOR_PRODUCT_RELEASE_PINS_JSON": "{}",
        "VENDOR_PRODUCT_MANIFEST_DIRECTORY": "/run/dotmac/product-manifests",
        "VENDOR_LICENCE_SIGNING_MODE": "configured",
        "VENDOR_LICENCE_SIGNING_KEY_FILE": (
            "/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key"
        ),
        "VENDOR_LICENCE_SIGNING_KEY_ID": "vendor-prod-1",
        "VENDOR_LICENCE_DELIVERY_MODE": "logging",
        "VENDOR_RELAY_EXPECTED": "false",
    }


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    path.chmod(0o600)


@pytest.fixture
def candidate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    root = tmp_path / "candidate-runs"
    monkeypatch.setattr(inputs, "DEFAULT_RUN_ROOT", root)
    run_dir = root / RUN_ID
    run_dir.mkdir(parents=True, mode=0o700)
    run_dir.chmod(0o700)
    env_file = run_dir / "app.env"
    _write_env(env_file, _values())
    docker_config = run_dir / "docker-config"
    docker_config.mkdir(mode=0o700)
    docker_config.chmod(0o700)
    compose_file = tmp_path / "docker-compose.candidate.yml"
    compose_file.write_bytes((ROOT / "docker-compose.candidate.yml").read_bytes())
    compose_file.chmod(0o644)
    monkeypatch.setattr(inputs, "DEFAULT_COMPOSE_FILE", compose_file)
    return {
        "run_id": RUN_ID,
        "selected_image": IMAGE,
        "expected_digest": DIGEST,
        "candidate_port": 8111,
        "database": DATABASE,
        "env_file": env_file,
        "licence_key_host_file": LICENCE_KEY_HOST_FILE,
    }


def _build(candidate: dict[str, object]) -> object:
    return build_candidate_compose_launch(**candidate)  # type: ignore[arg-type]


def test_allowlist_is_grounded_in_the_production_app_template() -> None:
    template = (ROOT / ".env.production.example").read_text(encoding="utf-8")
    declared = set(re.findall(r"^([A-Z][A-Z0-9_]*)=", template, re.MULTILINE))
    assert ALLOWED_APP_ENV_KEYS - {"DATABASE_URL", "PLATFORM_DATABASE_URL"} <= declared
    assert not any(key.startswith("VENDOR_DB_") for key in ALLOWED_APP_ENV_KEYS)
    assert "MIGRATION_DATABASE_URL" not in ALLOWED_APP_ENV_KEYS
    assert "VENDOR_RELAY_DISPATCHER_DATABASE_URL" not in ALLOWED_APP_ENV_KEYS


def test_valid_launch_is_redacted_and_secret_dollar_is_literal(
    candidate: dict[str, object],
) -> None:
    launch = _build(candidate)
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    values = _read_literal_env(env_file)
    assert values["JWT_SECRET"].endswith("$literal")
    assert "$literal" in values["DATABASE_URL"]
    assert launch.argv[-1] == "candidate-app"  # type: ignore[attr-defined]
    assert "--no-deps" in launch.argv  # type: ignore[attr-defined]
    assert "--wait" in launch.argv  # type: ignore[attr-defined]
    assert launch.argv[launch.argv.index("--pull") + 1] == "never"  # type: ignore[attr-defined]
    assert launch.argv[launch.argv.index("-p") + 1] == (  # type: ignore[attr-defined]
        f"vcp-d16-{RUN_ID}"
    )
    assert "password" not in repr(launch).lower()
    for value in (
        values["JWT_SECRET"],
        values["DATABASE_URL"],
        values["PLATFORM_DATABASE_URL"],
    ):
        assert value not in repr(launch)
        assert value not in " ".join(launch.argv)  # type: ignore[attr-defined]
        assert value not in repr(launch.compose_env)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("selected_image", "ghcr.io/michaelayoade/dotmac_vendor_control_plane:latest"),
        ("selected_image", IMAGE[:-1] + "b"),
        ("expected_digest", "sha256:short"),
        ("run_id", "../candidate"),
        ("run_id", RUN_ID.upper()),
        ("candidate_port", 8100),
        ("candidate_port", 1023),
        ("candidate_port", 0),
        ("candidate_port", 65536),
    ],
)
def test_identity_image_and_port_refusals(
    candidate: dict[str, object], field: str, bad: object
) -> None:
    candidate[field] = bad
    with pytest.raises(CandidateInputRefused):
        _build(candidate)


def test_path_owner_mode_and_symlink_refusals(
    candidate: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    candidate["env_file"] = env_file.parent / ".." / "app.env"
    with pytest.raises(CandidateInputRefused, match="canonical"):
        _build(candidate)
    candidate["env_file"] = env_file
    env_file.chmod(0o644)
    with pytest.raises(CandidateInputRefused, match="mode"):
        _build(candidate)
    env_file.chmod(0o600)
    monkeypatch.setattr(inputs, "_invocation_uid", lambda: os.geteuid() + 1)
    with pytest.raises(CandidateInputRefused, match="owner"):
        _build(candidate)
    monkeypatch.setattr(inputs, "_invocation_uid", os.geteuid)
    link = tmp_path / "linked"
    link.symlink_to(env_file)
    candidate["env_file"] = link
    with pytest.raises(CandidateInputRefused):
        _build(candidate)
    candidate["env_file"] = env_file
    env_file.parent.chmod(0o755)
    with pytest.raises(CandidateInputRefused, match="mode"):
        _build(candidate)


def test_canonical_env_path_symlink_is_refused(candidate: dict[str, object]) -> None:
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    target = env_file.parent / "actual.env"
    env_file.rename(target)
    env_file.symlink_to(target)
    with pytest.raises(CandidateInputRefused, match="symlink"):
        _build(candidate)


def test_licence_mount_path_is_fixed_without_inspecting_key_custody(
    candidate: dict[str, object], tmp_path: Path
) -> None:
    candidate["licence_key_host_file"] = tmp_path / "other-key"
    with pytest.raises(CandidateInputRefused, match="licence key host path"):
        _build(candidate)
    candidate["licence_key_host_file"] = Path("relative.key")
    with pytest.raises(CandidateInputRefused, match="licence key host path"):
        _build(candidate)


def test_hostile_inherited_compose_interpolation_is_overridden(
    candidate: dict[str, object],
) -> None:
    launch = _build(candidate)
    hostile = {
        "VENDOR_CANDIDATE_APP_IMAGE": "untrusted:latest",
        "VENDOR_CANDIDATE_RUN_ID": "different-run",
        "VENDOR_CANDIDATE_APP_PORT": "8100",
        "VENDOR_LICENCE_SIGNING_KEY_HOST_FILE": "/run/untrusted-key",
        "PATH": "/untrusted/docker-client",
        "DOCKER_HOST": "tcp://hostile.invalid:2375",
        "DOCKER_CONTEXT": "hostile-context",
        "DOCKER_CONFIG": "/untrusted/docker-config",
        "COMPOSE_PROFILES": "relay",
        "COMPOSE_FILE": "/untrusted/compose.yml",
        "VENDOR_DB_ADMIN_PASSWORD": "untrusted-secret",
        "HTTPS_PROXY": "http://hostile.invalid",
    }
    env = launch.subprocess_env(hostile)  # type: ignore[attr-defined]
    assert set(dict(launch.compose_env)) == {  # type: ignore[attr-defined]
        "VENDOR_CANDIDATE_APP_IMAGE",
        "VENDOR_CANDIDATE_RUN_ID",
        "VENDOR_CANDIDATE_APP_PORT",
        "VENDOR_LICENCE_SIGNING_KEY_HOST_FILE",
    }
    assert env["VENDOR_CANDIDATE_APP_IMAGE"] == IMAGE
    assert env["VENDOR_CANDIDATE_RUN_ID"] == RUN_ID
    assert env["VENDOR_CANDIDATE_APP_PORT"] == "8111"
    assert env["VENDOR_LICENCE_SIGNING_KEY_HOST_FILE"] == str(LICENCE_KEY_HOST_FILE)
    assert env["PATH"] == DOCKER_CLIENT_PATH
    assert env["DOCKER_HOST"] == LOCAL_DOCKER_HOST
    assert env["DOCKER_CONFIG"] == str(
        inputs.DEFAULT_RUN_ROOT / RUN_ID / "docker-config"
    )
    assert set(env) == set(dict(launch.compose_env)) | {  # type: ignore[attr-defined]
        "PATH",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
    }
    assert hostile["VENDOR_CANDIDATE_APP_IMAGE"] == "untrusted:latest"


def test_docker_config_must_be_empty_owned_private_directory(
    candidate: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = inputs.DEFAULT_RUN_ROOT / RUN_ID / "docker-config"
    (config / "config.json").write_text('{"currentContext":"remote"}')
    with pytest.raises(CandidateInputRefused, match="not empty"):
        _build(candidate)
    (config / "config.json").unlink()
    config.chmod(0o755)
    with pytest.raises(CandidateInputRefused, match="mode"):
        _build(candidate)
    config.chmod(0o700)
    monkeypatch.setattr(inputs, "_invocation_uid", lambda: os.geteuid() + 1)
    with pytest.raises(CandidateInputRefused, match="owner"):
        _build(candidate)


def test_reviewed_compose_bytes_mode_and_symlink_are_required(
    candidate: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compose = inputs.DEFAULT_COMPOSE_FILE
    compose.write_bytes(compose.read_bytes() + b"# hostile change\n")
    with pytest.raises(CandidateInputRefused, match="bytes differ"):
        _build(candidate)
    compose.write_bytes((ROOT / "docker-compose.candidate.yml").read_bytes())
    compose.chmod(0o666)
    with pytest.raises(CandidateInputRefused, match="owner or mode"):
        _build(candidate)
    compose.chmod(0o644)
    linked = tmp_path / "linked-compose.yml"
    linked.symlink_to(compose)
    monkeypatch.setattr(inputs, "DEFAULT_COMPOSE_FILE", linked)
    with pytest.raises(CandidateInputRefused, match="symlink"):
        _build(candidate)


@pytest.mark.parametrize(
    "injected",
    [
        "MIGRATION_DATABASE_URL",
        "VENDOR_RELAY_DISPATCHER_DATABASE_URL",
        "VENDOR_DB_ADMIN_PASSWORD",
        "VENDOR_DB_DISPATCHER_PASSWORD",
        "UNREVIEWED_RUNTIME_SETTING",
    ],
)
def test_unknown_owner_and_dispatcher_keys_are_refused(
    candidate: dict[str, object], injected: str
) -> None:
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    with env_file.open("a", encoding="utf-8") as output:
        output.write(f"{injected}=untrusted\n")
    with pytest.raises(CandidateInputRefused, match="unknown key"):
        _build(candidate)


def test_duplicate_missing_and_shell_form_are_refused(
    candidate: dict[str, object],
) -> None:
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    values = _values()
    _write_env(env_file, values)
    with env_file.open("a", encoding="utf-8") as output:
        output.write("VENDOR_RELAY_EXPECTED=false\n")
    with pytest.raises(CandidateInputRefused, match="repeats"):
        _build(candidate)
    values.pop("VENDOR_RELAY_EXPECTED")
    _write_env(env_file, values)
    with pytest.raises(CandidateInputRefused, match="VENDOR_RELAY_EXPECTED"):
        _build(candidate)
    values["VENDOR_RELAY_EXPECTED"] = "false"
    values["JWT_SECRET"] = "$(echo unsafe)"
    _write_env(env_file, values)
    with pytest.raises(CandidateInputRefused, match="shell syntax"):
        _build(candidate)


def test_old_role_and_wrong_candidate_role_urls_are_refused(
    candidate: dict[str, object],
) -> None:
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    values = _values()
    values["DATABASE_URL"] = values["DATABASE_URL"].replace(
        CandidateRoles.for_run(database=DATABASE, run_id=RUN_ID).app, "app_user"
    )
    _write_env(env_file, values)
    with pytest.raises(CandidateInputRefused, match="DATABASE_URL"):
        _build(candidate)
    values = _values()
    values["PLATFORM_DATABASE_URL"] = values["PLATFORM_DATABASE_URL"].replace(
        CandidateRoles.for_run(database=DATABASE, run_id=RUN_ID).platform,
        "platform_outbox_dispatcher",
    )
    _write_env(env_file, values)
    with pytest.raises(CandidateInputRefused, match="PLATFORM_DATABASE_URL"):
        _build(candidate)
    values = _values()
    values["DATABASE_URL"] = values["DATABASE_URL"].replace(
        CandidateRoles.for_run(database=DATABASE, run_id=RUN_ID).app,
        "app_admin",
    )
    _write_env(env_file, values)
    with pytest.raises(CandidateInputRefused, match="DATABASE_URL"):
        _build(candidate)


def test_equal_candidate_passwords_are_refused_without_disclosure(
    candidate: dict[str, object],
) -> None:
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    values = _values()
    app_password = values["DATABASE_URL"].split(":", 2)[2].split("@", 1)[0]
    platform_role = CandidateRoles.for_run(database=DATABASE, run_id=RUN_ID).platform
    values["PLATFORM_DATABASE_URL"] = (
        f"postgresql+psycopg://{platform_role}:{app_password}@db:5432/{DATABASE}"
    )
    _write_env(env_file, values)
    with pytest.raises(CandidateInputRefused) as refusal:
        _build(candidate)
    assert app_password not in str(refusal.value)
    assert app_password not in repr(refusal.value)


@pytest.mark.parametrize(
    ("which", "replacement"),
    [
        ("DATABASE_URL", "@db:5432/vendor_control_plane"),
        ("PLATFORM_DATABASE_URL", "@other-host:5432/vendor_control_plane"),
        ("DATABASE_URL", "@db:5432/other_database"),
    ],
)
def test_candidate_url_must_have_password_host_and_database(
    candidate: dict[str, object], which: str, replacement: str
) -> None:
    env_file = candidate["env_file"]
    assert isinstance(env_file, Path)
    values = _values()
    if which == "DATABASE_URL" and replacement.startswith("@db"):
        values[which] = (
            values[which].split(":", 2)[0]
            + "://"
            + (
                CandidateRoles.for_run(database=DATABASE, run_id=RUN_ID).app
                + replacement
            )
        )
    else:
        values[which] = re.sub(r"@[^/]+/[^/]+$", replacement, values[which])
    _write_env(env_file, values)
    with pytest.raises(CandidateInputRefused, match=which):
        _build(candidate)
