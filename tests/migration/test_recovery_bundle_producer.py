"""`build_bundle()` really produces a Foundation-valid manifest.

`recovery/bundle.py` has carried zero test coverage anywhere in this repo:
it is wired into the `recovery bundle` CLI command (`cli/commands.py`,
untested itself, and NOT called by `scripts/deploy_production.sh`), but
nothing had ever proven that a REAL captured catalogue, mapped through
`build_bundle()`, produces a manifest `dotmac_deployment_foundation.recovery
.load_manifest()` actually accepts. That is what this file proves — against
a genuinely migrated scratch database, not a hand-built capture fixture,
because the property under test is whether this assembly's mapping agrees
with the facility's own reader, and a synthetic capture could silently drift
from what `capture_sql()` really emits.

Requires the test Postgres cluster from `make test-db-up`, AND a real
`dotmac-deployment-foundation` install; skips (or fails under
`REQUIRE_POSTGRES_TESTS=1`) when `TEST_DATABASE_URL` is unset — see
`tests/migration/conftest.py`. The required CI postgres job runs these cases a
second time against the exact Foundation source commit, then refuses skips or
missing cases. A local run without Foundation may still skip deliberately.

Foundation itself is brought in through a `try/except ImportError` around
the actual import, converted to `pytest.skip(..., allow_module_level=True)`
on catch — not a bare module-level `from dotmac_deployment_foundation...
import ...`, and not `pytest.importorskip` on the package name alone
either: `importorskip("dotmac_deployment_foundation")` only proves the TOP
package imports, not that the specific names this file needs
(`REQUIRED_COMPONENTS`, `load_manifest`) exist in whatever version is
installed — a present-but-older Foundation checkout missing one of them
raises a plain `ImportError` at the real `from ...recovery import (...)`
line, which `importorskip` on the package alone would not have caught. A
bare module-level import that fails (of either kind) breaks COLLECTION for
this entire file — worse than a clean skip, since depending on the
`postgres` CI job's configuration that can error the whole test session
rather than report these specific tests as not-yet-provable. This
repository's own `pyproject.toml` mypy override and `poetry.lock` both
confirm `dotmac-deployment-foundation` is not a declared dependency
anywhere in this assembly, including the `postgres` CI job (`poetry
install` only) — so the ordinary migration invocation may still skip, but
the separate D16 conformance step executes the same cases from exact source
and refuses skips. That source-only CI tool is not a CP production dependency
or deploy wiring.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text

from vendor_cp.cli.commands import recovery_bundle
from vendor_cp.deployment.image_heads import composed_effective_heads
from vendor_cp.migrations import (
    BINDINGS_ENV_VAR,
    MODULE_PLANES_ENV_VAR,
    make_alembic_config,
)
from vendor_cp.recovery.bundle import build_bundle
from vendor_cp.recovery.capture import capture_sql

try:
    from dotmac_deployment_foundation.recovery import (  # noqa: E402
        REQUIRED_COMPONENTS,
        load_manifest,
    )
except ImportError as _foundation_error:
    pytest.skip(
        "dotmac-deployment-foundation is not yet a declared CP dependency "
        "(an open decision), or the installed checkout is missing a name "
        f"this file needs — this file proves nothing about build_bundle() "
        f"until it is installed and compatible: {_foundation_error}",
        allow_module_level=True,
    )

_PRODUCT_TOML = Path(__file__).resolve().parents[2] / "deploy" / "product.toml"
_OFFLINE_DSN = "postgresql+psycopg://image-heads@127.0.0.1:5432/none"


def _dbname(url: str) -> str:
    return url.rpartition("/")[2]


def _product_from_descriptor() -> str:
    """The real `product` value this assembly declares, not a guess.

    `ProductDeploymentSpec.load(...)` (the production accessor,
    `deployment/candidate.py`) itself requires Foundation to be installed —
    the same dependency this whole test already requires — but reading the
    one field this test needs directly out of the checked-in TOML avoids a
    second, redundant Foundation-availability dependency for a single
    string.
    """
    with _PRODUCT_TOML.open("rb") as handle:
        descriptor = tomllib.load(handle)
    return str(descriptor["product"])


def _run_migration(admin_url: str, app_user_url: str, platform_api_url: str) -> None:
    dotmac_platform = shutil.which("dotmac-platform")
    assert dotmac_platform is not None, (
        "the dotmac-platform console script is not on PATH; this suite must "
        "run inside the project's installed virtualenv"
    )
    env = {
        "PATH": os.environ.get("PATH", ""),
        "DATABASE_URL": app_user_url,
        "PLATFORM_DATABASE_URL": platform_api_url,
        "MIGRATION_DATABASE_URL": admin_url,
    }
    result = subprocess.run(  # noqa: S603 -- fixed console-script argv, no shell
        [dotmac_platform, "admin", "migrate"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"`dotmac-platform admin migrate` failed (exit {result.returncode}):\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )


def _offline_effective_heads(monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    """Same pattern as `test_fenced_migration.py`'s own helper: computed
    OFFLINE, so this never needs the scratch database's own URL or leaks
    environment state past this test."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.delenv(BINDINGS_ENV_VAR, raising=False)
    monkeypatch.delenv(MODULE_PLANES_ENV_VAR, raising=False)
    config = make_alembic_config(_OFFLINE_DSN)
    return composed_effective_heads(config)


def _postgres_major(admin_url: str) -> int:
    engine = create_engine(admin_url)
    try:
        with engine.connect() as conn:
            server_version_num = int(
                conn.execute(
                    text("SELECT current_setting('server_version_num')")
                ).scalar_one()
            )
    finally:
        engine.dispose()
    return server_version_num // 10000


def _capture_catalogue(admin_url: str) -> dict[str, Any]:
    psql = shutil.which("psql")
    assert psql is not None, "psql is required for the packaged capture script"
    # capture_sql() is a psql script, not driver SQL: it includes \set and is
    # explicitly documented to be fed to psql. -X excludes local psqlrc state.
    libpq_url = admin_url.replace("postgresql+psycopg://", "postgresql://", 1)
    result = subprocess.run(  # noqa: S603 -- fixed psql argv, no shell
        [psql, "-X", "-tA", "-v", "ON_ERROR_STOP=1", "--dbname", libpq_url],
        input=capture_sql(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert (
        result.returncode == 0
    ), f"psql catalogue capture failed (exit {result.returncode}): {result.stderr}"
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, dict)
    return parsed


def test_build_bundle_produces_a_foundation_valid_manifest(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = _dbname(scratch_db)
    engine = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            conn.execute(text(f'ALTER DATABASE "{db}" OWNER TO app_admin'))
    finally:
        engine.dispose()

    admin_url = url_for(postgres_url, db, user="app_admin")
    app_user_url = url_for(postgres_url, db, user="app_user")
    platform_api_url = url_for(postgres_url, db, user="platform_api")

    _run_migration(admin_url, app_user_url, platform_api_url)

    capture = _capture_catalogue(admin_url)
    postgres_major = _postgres_major(admin_url)

    product = _product_from_descriptor()
    outcome = build_bundle(
        capture,
        dump_digest="sha256:" + "0" * 64,
        product=product,
        environment="test",
        postgres_major=postgres_major,
        source_revision="test-recovery-bundle-producer-scratch",
        captured_at_epoch=int(time.time()),
    )

    manifest = load_manifest(outcome.manifest_json)
    assert manifest.product == product

    expected_heads = set(_offline_effective_heads(monkeypatch))
    assert expected_heads, (
        "composed_effective_heads returned no heads; the equality check "
        "below would otherwise pass vacuously"
    )
    assert set(manifest.migration_heads) == expected_heads

    captured_role_names = {str(r["name"]) for r in capture["roles"]}
    for expected_role in ("app_admin", "app_user", "platform_api"):
        assert expected_role in captured_role_names, (
            f"the scratch cluster's own capture never named {expected_role!r} "
            "as a role — this is a finding about the migration/role setup, "
            "not something to paper over"
        )
    assert manifest.role_closure, "role_closure must not be empty"
    for expected_role in ("app_admin", "app_user", "platform_api"):
        assert expected_role in manifest.role_closure, (
            f"{expected_role!r} is a captured role but the derived closure "
            "does not require it"
        )

    for component in REQUIRED_COMPONENTS:
        manifest.component_digest(component)  # raises if absent; let it

    captured_superusers = {
        str(role["name"]) for role in capture["roles"] if role["superuser"]
    }
    assert "postgres" in captured_superusers
    assert set(outcome.excluded_superusers) == captured_superusers
    assert not captured_superusers.intersection(
        {"app_admin", "app_user", "platform_api"}
    ), "an application role was captured as SUPERUSER and excluded from the bundle"


def test_recovery_bundle_cli_handler_round_trips_through_load_manifest(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    tmp_path: Path,
) -> None:
    """Exercises `cli.commands.recovery_bundle` in-process, end to end — the
    handler behind `dotmac-platform recovery bundle`, itself never
    previously tested."""
    db = _dbname(scratch_db)
    engine = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            conn.execute(text(f'ALTER DATABASE "{db}" OWNER TO app_admin'))
    finally:
        engine.dispose()

    admin_url = url_for(postgres_url, db, user="app_admin")
    app_user_url = url_for(postgres_url, db, user="app_user")
    platform_api_url = url_for(postgres_url, db, user="platform_api")

    _run_migration(admin_url, app_user_url, platform_api_url)
    capture = _capture_catalogue(admin_url)
    postgres_major = _postgres_major(admin_url)

    capture_path = tmp_path / "capture.json"
    capture_path.write_text(json.dumps(capture), encoding="utf-8")
    out_path = tmp_path / "manifest.json"

    product = _product_from_descriptor()
    args = argparse.Namespace(
        capture=str(capture_path),
        dump_digest="sha256:" + "1" * 64,
        product=product,
        environment="test",
        postgres_major=postgres_major,
        source_revision="test-recovery-bundle-cli-scratch",
        captured_at=int(time.time()),
        out=str(out_path),
    )

    result = recovery_bundle(args)
    assert result.references["manifest_digest"]

    written = out_path.read_text(encoding="utf-8")
    manifest = load_manifest(written)
    assert manifest.product == product
