"""Render the standalone D16 candidate Compose file without starting services."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from vendor_cp.deployment import candidate_compose_inputs as inputs

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.candidate.yml"
RUN_ID = "0123456789abcdef0123456789abcdef"
IMAGE = "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "a" * 64
RUN_DIR_PREFIX = "/opt/dotmac/vendor-control-plane/candidate-runs/"
REVIEWED_COMPOSE_SHA256 = (
    "d452382e11296a2c41bd9f171921ab8e1f0e7dea0eaa41b72f331801c828fee1"
)


def test_compose_bytes_are_pinned_and_public_builder_has_no_path_override(
    tmp_path: Path,
) -> None:
    source = COMPOSE.read_bytes()
    assert hashlib.sha256(source).hexdigest() == REVIEWED_COMPOSE_SHA256
    assert inputs.COMPOSE_SHA256 == REVIEWED_COMPOSE_SHA256
    assert not {"compose_file", "run_root", "invocation_uid"} & set(
        inspect.signature(inputs.build_candidate_compose_launch).parameters
    )
    changed = tmp_path / "changed-compose.yml"
    changed.write_bytes(source + b"# altered after review\n")
    changed.chmod(0o644)
    with pytest.raises(inputs.CandidateInputRefused, match="bytes differ"):
        inputs._require_reviewed_compose(changed, uid=os.geteuid())
    hostile_path = tmp_path / "hostile-link.yml"
    hostile_path.symlink_to(COMPOSE)
    with pytest.raises(inputs.CandidateInputRefused, match="symlink"):
        inputs._require_reviewed_compose(hostile_path, uid=os.geteuid())


def test_candidate_compose_declares_only_isolated_app_and_absolute_file() -> None:
    source = COMPOSE.read_text(encoding="utf-8")
    assert "docker-compose.production.yml" in source
    assert source.count("image: ${VENDOR_CANDIDATE_APP_IMAGE:?") == 1
    assert source.count(f"{RUN_DIR_PREFIX}${{VENDOR_CANDIDATE_RUN_ID:?") == 1
    assert "/app.env" in source and "/relay.env" not in source
    assert "  candidate-app:\n" in source
    assert "  candidate-relay:\n" not in source
    assert "  relay:\n" not in source
    assert "command:" not in source
    assert "dotmac-platform" not in source
    assert 'VENDOR_RELAY_EXPECTED: "false"' in source
    assert "env_file: .env" not in source
    assert "format: raw" in source
    assert "VENDOR_DB_APP_USER_PASSWORD" not in source
    assert "VENDOR_DB_PLATFORM_API_PASSWORD" not in source
    assert "VENDOR_DB_DISPATCHER_PASSWORD" not in source
    assert "MIGRATION_DATABASE_URL" not in source
    assert "VENDOR_RELAY_DISPATCHER_DATABASE_URL" not in source
    assert "external: true" in source
    assert "dotmac_vendor_control_plane_vendor_backend" in source
    assert "dotmac_vendor_control_plane_vendor_product_manifests" in source


def test_compose_render_exposes_only_candidate_app_with_relay_disabled(
    tmp_path: Path,
) -> None:
    if shutil.which("docker") is None:
        pytest.fail("Docker Compose is required to verify candidate isolation")
    run_dir = tmp_path / "candidate-runs" / RUN_ID
    run_dir.mkdir(parents=True)
    app_file = run_dir / "app.env"
    app_file.write_text(
        "DATABASE_URL=postgresql+psycopg://candidate_app@db:5432/test\n"
        "PLATFORM_DATABASE_URL=postgresql+psycopg://candidate_platform@db:5432/test\n"
        "JWT_SECRET=synthetic$NOT_A_COMPOSE_VARIABLE\n"
        "VENDOR_RELAY_EXPECTED=false\n",
        encoding="utf-8",
    )
    # The original file fixes the host path under /opt. Replace that one
    # absolute prefix in a disposable copy so Compose can stat synthetic files.
    source = COMPOSE.read_text(encoding="utf-8")
    assert source.count(RUN_DIR_PREFIX) == 1
    local = tmp_path / "compose.yml"
    local.write_text(
        source.replace(RUN_DIR_PREFIX, str(tmp_path / "candidate-runs") + "/"),
        encoding="utf-8",
    )
    env = dict(os.environ)
    env.update(
        VENDOR_CANDIDATE_APP_IMAGE=IMAGE,
        VENDOR_CANDIDATE_RUN_ID=RUN_ID,
        VENDOR_CANDIDATE_APP_PORT="8111",
        VENDOR_LICENCE_SIGNING_KEY_HOST_FILE=str(tmp_path / "held-key"),
    )
    result = subprocess.run(  # noqa: S603 -- fixed read-only Compose render
        ["docker", "compose", "-f", str(local), "config", "--format", "json"],  # noqa: S607
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=True,
    )
    rendered = json.loads(result.stdout)
    services = rendered["services"]
    assert set(services) == {"candidate-app"}
    app = services["candidate-app"]
    assert app["image"] == IMAGE
    assert app["environment"]["DATABASE_URL"].startswith(
        "postgresql+psycopg://candidate_app@"
    )
    assert app["environment"]["PLATFORM_DATABASE_URL"].startswith(
        "postgresql+psycopg://candidate_platform@"
    )
    assert "VENDOR_RELAY_DISPATCHER_DATABASE_URL" not in app["environment"]
    assert set(app["environment"]) == {
        "DATABASE_URL",
        "PLATFORM_DATABASE_URL",
        "JWT_SECRET",
        "VENDOR_RELAY_EXPECTED",
    }
    # Compose's rendered config escapes a preserved literal dollar as '$$'.
    # Without env_file format: raw the unknown name would be interpolated away.
    assert app["environment"]["JWT_SECRET"] == "synthetic$$NOT_A_COMPOSE_VARIABLE"
    assert app["environment"]["VENDOR_RELAY_EXPECTED"] == "false"
    assert not any(key.startswith("VENDOR_DB_") for key in app["environment"])
    assert "MIGRATION_DATABASE_URL" not in app["environment"]
    assert app["ports"] == [
        {
            "mode": "ingress",
            "target": 8000,
            "published": "8111",
            "protocol": "tcp",
            "host_ip": "127.0.0.1",
        }
    ]
    assert app.get("command") is None
    assert app.get("entrypoint") is None
    assert app["restart"] == "no"
    assert app["networks"] == {"vendor_backend": None}
    assert rendered["networks"]["vendor_backend"]["external"] is True
    assert rendered["volumes"]["vendor_product_manifests"]["external"] is True
