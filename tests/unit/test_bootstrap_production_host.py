"""Canaries for the one-time Vendor production-host bootstrap contract."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "scripts/bootstrap_production_host.sh"
BASH = "/bin/bash"


def _fake_certbot(tmp_path: Path, *, account_exists: bool) -> Path:
    binary = tmp_path / "certbot"
    status = "0" if account_exists else "1"
    binary.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "${1:-}" == show_account ]]; then\n'
        f"  exit {status}\n"
        "fi\n"
        "printf '%s\\n' \"$@\"\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary


def _resolve(
    tmp_path: Path,
    *,
    account_exists: bool,
    email: str = "",
) -> subprocess.CompletedProcess[str]:
    _fake_certbot(tmp_path, account_exists=account_exists)
    command = (
        f"source {shlex.quote(os.fspath(BOOTSTRAP))}; "
        "resolve_certbot_registration; "
        "issue_production_certificate"
    )
    env = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "CERTBOT_EMAIL": email,
    }
    return subprocess.run(  # noqa: S603 -- fixed shell and quoted test paths
        [BASH, "-c", command],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _validate_env(path: Path) -> subprocess.CompletedProcess[str]:
    command = (
        f"source {shlex.quote(os.fspath(BOOTSTRAP))}; "
        f"validate_materialized_env {shlex.quote(os.fspath(path))}"
    )
    return subprocess.run(  # noqa: S603 -- fixed shell and quoted test paths
        [BASH, "-c", command],
        check=False,
        capture_output=True,
        text=True,
    )


def test_registered_certbot_account_needs_no_duplicate_email(tmp_path: Path) -> None:
    result = _resolve(tmp_path, account_exists=True)

    assert result.returncode == 0, result.stderr
    assert "--email\n" not in result.stdout
    assert result.stdout.endswith("--domain\nvendor.dotmac.io\n")


def test_explicit_certbot_email_is_preserved_for_a_new_account(tmp_path: Path) -> None:
    result = _resolve(
        tmp_path,
        account_exists=False,
        email="operator@example.net",
    )

    assert result.returncode == 0, result.stderr
    assert "--email\noperator@example.net\n" in result.stdout
    assert result.stdout.endswith("--domain\nvendor.dotmac.io\n")


def test_missing_certbot_account_and_email_fails_closed(tmp_path: Path) -> None:
    result = _resolve(tmp_path, account_exists=False)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "CERTBOT_EMAIL is required when no Certbot account exists" in result.stderr


def test_materialized_environment_requires_every_held_value(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "VENDOR_DB_ADMIN_PASSWORD=admin\n"
        "VENDOR_DB_APP_USER_PASSWORD=app\n"
        "VENDOR_DB_PLATFORM_API_PASSWORD=platform\n"
        "JWT_SECRET=jwt\n"
        "SESSION_HASH_SECRET=session\n"
        "VENDOR_LICENCE_SIGNING_KEY_ID=vendor-prod-1\n",
        encoding="utf-8",
    )

    result = _validate_env(env_file)

    assert result.returncode == 0, result.stderr


def test_empty_or_duplicate_held_value_refuses_the_marker(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "VENDOR_DB_ADMIN_PASSWORD=admin\n"
        "VENDOR_DB_APP_USER_PASSWORD=\n"
        "VENDOR_DB_PLATFORM_API_PASSWORD=platform\n"
        "JWT_SECRET=jwt\n"
        "SESSION_HASH_SECRET=session\n"
        "VENDOR_LICENCE_SIGNING_KEY_ID=vendor-prod-1\n"
        "JWT_SECRET=duplicate\n",
        encoding="utf-8",
    )

    result = _validate_env(env_file)

    assert result.returncode != 0
    assert (
        "host environment declaration is missing, empty, or duplicated" in result.stderr
    )


def test_host_identity_is_written_only_after_the_full_contract() -> None:
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")

    marker = bootstrap.index('mv "$HOST_ID_TMP" /etc/dotmac-host-id')
    assert bootstrap.index("certbot certonly") < marker
    assert bootstrap.index('openssl x509 -checkhost "$PRODUCTION_DOMAIN"') < marker
    assert bootstrap.index('[[ ! -f "$DEPLOY_DIR/.env" ]]') < marker
    assert bootstrap.index('validate_materialized_env "$DEPLOY_DIR/.env"') < marker
    assert (
        bootstrap.index("systemctl reload nginx", bootstrap.index("certbot certonly"))
        < marker
    )
    stale_shape = "printf '%s\\n' \"$EXPECTED_HOST_ID\" > /etc/dotmac-host-id"
    assert stale_shape not in bootstrap


def test_bootstrap_never_registers_without_a_contact() -> None:
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")

    assert "--register-unsafely-without-email" not in bootstrap
    assert "certbot show_account --non-interactive" in bootstrap
