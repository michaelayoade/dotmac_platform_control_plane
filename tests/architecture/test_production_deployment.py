"""Production deployment is immutable, isolated, and fail-closed.

These are shape guards for the deployment boundary rather than a substitute for
the live first-deploy rehearsal.  They prevent the cheap regressions that would
turn the production host back into a build machine, expose PostgreSQL, mount
source code, or start the application before its backup and composed migrations.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_runtime_image_uses_a_build_secret_and_runs_unprivileged() -> None:
    dockerfile = _text("Dockerfile")

    assert dockerfile.startswith("# syntax=docker/dockerfile:")
    assert dockerfile.count("python:3.12-slim@sha256:") == 2
    assert "--require-hashes --only-binary=:all:" in dockerfile
    assert ".github/bootstrap/poetry-requirements.txt" in dockerfile
    assert "--mount=type=secret,id=forgejo_token" in dockerfile
    assert "POETRY_HTTP_BASIC_FORGEJO_PASSWORD" in dockerfile
    assert not re.search(
        r"^(?:ARG|ENV) .*FORGEJO.*(?:TOKEN|PASSWORD)", dockerfile, re.M
    )
    assert "poetry install --only main --no-root" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert 'CMD ["uvicorn", "vendor_cp.main:app"' in dockerfile

    cmd = dockerfile.split("CMD ", 1)[1]
    assert "migrate" not in cmd.lower()
    assert "alembic" not in cmd.lower()


def test_production_compose_pulls_only_and_keeps_state_private() -> None:
    compose = _text("docker-compose.production.yml")

    assert "build:" not in compose
    assert "image: ${VENDOR_APP_IMAGE:?" in compose
    assert '"127.0.0.1:${VENDOR_APP_PORT:-8100}:8000"' in compose
    assert "vendor_postgres_data:/var/lib/postgresql/data" in compose
    assert "vendor_product_manifests:/run/dotmac/product-manifests:ro" in compose
    assert "vendor_product_manifests:/run/dotmac/product-manifests:rw" in compose
    assert "${VENDOR_LICENCE_SIGNING_KEY_HOST_FILE:?" in compose
    assert (
        ":/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key:ro"
        in compose
    )
    assert 'profiles: ["ops"]' in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "vendor_backend:\n    internal: true" in compose
    assert 'com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"' in compose

    db_block = compose.split("  db:\n", 1)[1].split("  app:\n", 1)[0]
    assert "ports:" not in db_block


def test_database_initialization_never_embeds_passwords() -> None:
    initializer = _text("deploy/postgres/init-roles.sh")

    assert "\\getenv app_user_password VENDOR_DB_APP_USER_PASSWORD" in initializer
    assert (
        "\\getenv platform_api_password VENDOR_DB_PLATFORM_API_PASSWORD" in initializer
    )
    assert "PASSWORD :'app_user_password'" in initializer
    assert "PASSWORD :'platform_api_password'" in initializer
    assert "set -x" not in initializer


def test_platform_admin_bootstrap_uses_kernel_transaction_authority() -> None:
    bootstrap = _text("scripts/create_platform_admin.py")

    assert "platform_session" in bootstrap
    assert "getpass.getpass" in bootstrap
    assert "create_engine" not in bootstrap
    assert "sessionmaker" not in bootstrap
    assert "--password" not in bootstrap


def test_deploy_backs_up_and_runs_the_composed_migration_owner_before_app() -> None:
    deploy = _text("scripts/deploy_production.sh")

    assert "docker compose" in deploy
    assert "docker compose build" not in deploy
    assert "scripts/migrate.py" in deploy
    assert "alembic upgrade" not in deploy
    assert "ghcr.io/michaelayoade/dotmac_vendor_control_plane@${DIGEST}" in deploy
    assert "APP_ENV=production" in deploy
    assert "SERVER_NAME=vendor-cp-prod" in deploy

    backup = deploy.index("pg_dump")
    migrate = deploy.index("scripts/migrate.py")
    replace = deploy.index("up -d app")
    assert backup < migrate < replace


def test_production_environment_has_no_secret_defaults() -> None:
    example = _text(".env.production.example")

    required_empty = {
        "VENDOR_DB_ADMIN_PASSWORD",
        "VENDOR_DB_APP_USER_PASSWORD",
        "VENDOR_DB_PLATFORM_API_PASSWORD",
        "JWT_SECRET",
        "SESSION_HASH_SECRET",
    }
    values = dict(
        line.split("=", 1)
        for line in example.splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    assert required_empty <= values.keys()
    assert all(values[key] == "" for key in required_empty)
    assert values["ENVIRONMENT"] == "production"
    assert values["PLATFORM_ROOT_DOMAIN"] == "vendor.dotmac.io"
    assert values["VENDOR_LICENCE_SIGNING_MODE"] == "configured"
    assert values["VENDOR_PRODUCT_RELEASE_PINS_JSON"] == "{}"


def test_image_workflow_builds_on_github_hosted_runner_and_publishes_a_digest() -> None:
    workflow = _text(".github/workflows/production-image.yml")

    assert "runs-on: ubuntu-latest" in workflow
    assert "self-hosted" not in workflow
    assert "docker build" in workflow
    assert "docker push" in workflow
    assert "id=forgejo_token,env=FORGEJO_READ_TOKEN" in workflow
    assert "${{ steps.publish.outputs.digest }}" in workflow
    assert ":latest" not in workflow


def test_every_test_job_runs_on_a_github_hosted_runner() -> None:
    workflow = _text(".github/workflows/ci.yml")

    assert "self-hosted" not in workflow
    assert workflow.count("runs-on: ubuntu-latest") == 3
    assert "DOCKER_BUILDKIT=1 docker build" in workflow
    assert "from vendor_cp.main import app" in workflow


def test_deploy_workflow_requires_the_named_target_and_an_immutable_digest() -> None:
    workflow = _text(".github/workflows/production-deploy.yml")

    assert "runs-on: ubuntu-latest" in workflow
    assert "self-hosted" not in workflow
    assert "environment: production" in workflow
    assert '"$TARGET_SERVER_NAME" != "vendor-cp-prod"' in workflow
    assert "sha256:[0-9a-f]{64}" in workflow
    assert "VENDOR_PRODUCTION_KNOWN_HOSTS" in workflow
    assert "VENDOR_PRODUCTION_SSH_KEY" in workflow


def test_nginx_contract_routes_only_to_the_loopback_vendor_app() -> None:
    nginx = _text("deploy/nginx/vendor.dotmac.io.conf")

    assert "server_name vendor.dotmac.io;" in nginx
    assert "proxy_pass http://127.0.0.1:8100;" in nginx
    assert (
        "ssl_certificate /etc/letsencrypt/live/vendor.dotmac.io/fullchain.pem;" in nginx
    )
    assert (
        "ssl_certificate_key /etc/letsencrypt/live/vendor.dotmac.io/privkey.pem;"
        in nginx
    )


def test_host_bootstrap_requires_held_key_material_and_an_explicit_email() -> None:
    bootstrap = _text("scripts/bootstrap_production_host.sh")

    assert "CERTBOT_EMAIL" in bootstrap
    assert "vendor-cp-prod" in bootstrap
    assert (
        "/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key"
        in bootstrap
    )
    assert "secret/dotmac/licensing/signing-key" in bootstrap
    assert "certbot certonly" in bootstrap
