"""Transition evidence, proved against real git history and a real migration.

Two tests. The first (C1) is the single most important one in this suite:
it proves `read_descriptor_at_revision` reads the descriptor's bytes AS
THEY WERE at a git revision, never the file currently sitting in the
working tree — the exact bug class `deploy_production.sh`'s
`DESCRIPTOR_SHA256` line is latent for, since it has no git checkout of its
own and only ever reads the live file. The second (C2) proves
`capture_genesis_baseline`/`capture_target_state` compose correctly around
a real fenced migration, using the identical fence/migrate pattern
`test_fenced_migration.py` already established.

Requires the test Postgres cluster (roles + kernel schema) from
`make test-db-up`; skips (or fails under `REQUIRE_POSTGRES_TESTS=1`) when
`TEST_DATABASE_URL` is unset — see `tests/migration/conftest.py`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment.image_heads import composed_effective_heads
from vendor_cp.deployment.transition_evidence import (
    capture_genesis_baseline,
    capture_target_state,
    raw_bytes_digest,
    read_descriptor_at_revision,
)
from vendor_cp.deployment.transition_fence import (
    fence_is_holding,
    fence_writers,
    restore_writers,
)
from vendor_cp.migrations import (
    BINDINGS_ENV_VAR,
    MODULE_PLANES_ENV_VAR,
    make_alembic_config,
)

SESSION_WAIT_SECONDS = 3.0

FENCE_ID = "transition-evidence-test"

#: `make_alembic_config`'s own offline placeholder — no database is dialled.
#: Matches `test_fenced_migration.py`'s identical `OFFLINE_DSN` use, so the
#: composed expected head set is always computed without needing its own
#: database connection or environment mutation.
OFFLINE_DSN = "postgresql+psycopg://image-heads@127.0.0.1:5432/none"


def _git_executable() -> str:
    executable = shutil.which("git")
    assert executable is not None, (
        "git is not on PATH — every other CP test that touches git assumes "
        "it, so this is a report-worthy environment gap, not a fixture bug"
    )
    return executable


def _git(repo_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv list, resolved executable
        [
            _git_executable(),
            "-C",
            str(repo_root),
            "-c",
            "user.email=transition-evidence-tests@example.invalid",
            "-c",
            "user.name=Transition Evidence Tests",
            *arguments,
        ],
        capture_output=True,
        text=True,
        check=True,
    )


@contextmanager
def _connect(url: str, *, autocommit: bool = False) -> Iterator[Connection]:
    engine = create_engine(url, isolation_level="AUTOCOMMIT" if autocommit else None)
    try:
        with engine.connect() as conn:
            conn.execute(text("SET lock_timeout = '5s'"))
            yield conn
    finally:
        engine.dispose()


def _dbname(url: str) -> str:
    return url.rpartition("/")[2]


def _offline_effective_heads(monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    """`composed_effective_heads` over the OFFLINE config — never the scratch
    database's URL. Identical pattern to
    `test_fenced_migration.py::_offline_effective_heads`: pre-registering
    every variable `make_alembic_config` mutates with `monkeypatch` restores
    them to whatever this test process held before the call, so nothing
    leaks past this test once `scratch_db` has dropped the database these
    variables could otherwise still be naming.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.delenv(BINDINGS_ENV_VAR, raising=False)
    monkeypatch.delenv(MODULE_PLANES_ENV_VAR, raising=False)
    config = make_alembic_config(OFFLINE_DSN)
    return composed_effective_heads(config)


def test_the_genesis_descriptor_comes_from_git_history_not_the_working_tree(
    tmp_path: Path,
) -> None:
    """The critical test: `read_descriptor_at_revision` must return the OLD
    descriptor's exact bytes, even though the working tree now holds a
    DIFFERENT descriptor at the same path. A real, isolated temp git
    repository (never this CP repo's own history) proves it.
    """
    (tmp_path / "deploy").mkdir()
    descriptor_path = tmp_path / "deploy" / "product.toml"

    _git(tmp_path, "init", "--quiet")

    old_text = 'product = "old-value"\n'
    descriptor_path.write_text(old_text, encoding="utf-8")
    _git(tmp_path, "add", "deploy/product.toml")
    _git(tmp_path, "commit", "--quiet", "-m", "genesis descriptor")
    old_revision = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    assert (
        len(old_revision) == 40
    ), f"git rev-parse HEAD did not return a 40-character SHA: {old_revision!r}"

    # The working tree now moves on to a NEW descriptor — a normal,
    # independent descriptor-promotion commit, exactly the scenario
    # deploy_production.sh's own working-tree read cannot distinguish from
    # "this is still the descriptor that was deployed".
    new_text = 'product = "new-value"\n'
    descriptor_path.write_text(new_text, encoding="utf-8")
    _git(tmp_path, "add", "deploy/product.toml")
    _git(tmp_path, "commit", "--quiet", "-m", "promote descriptor")

    # Sanity: the working tree really does hold the NEW content right now.
    assert descriptor_path.read_text(encoding="utf-8") == new_text

    returned_text = read_descriptor_at_revision(
        repo_root=tmp_path, source_revision=old_revision
    )

    assert returned_text == old_text, (
        "read_descriptor_at_revision must return the descriptor's bytes AS "
        "THEY WERE at old_revision, not the working tree's current content"
    )
    assert returned_text != new_text

    # Non-vacuity control: the two texts are genuinely different values, so
    # the digest comparison below is not accidentally comparing identical
    # bytes to itself.
    assert raw_bytes_digest(old_text) != raw_bytes_digest(new_text)
    assert raw_bytes_digest(returned_text) == raw_bytes_digest(old_text)
    assert raw_bytes_digest(returned_text) != raw_bytes_digest(
        descriptor_path.read_text(encoding="utf-8")
    )


def test_genesis_baseline_and_target_state_around_a_real_fenced_migration(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`capture_genesis_baseline` (empty heads, pre-migration) and
    `capture_target_state` (the real composed heads, post-migration),
    captured around a real `dotmac-platform admin migrate` run, while the
    scratch database stays fenced the entire time — the invariant Michael
    named: "retain the independently measured genesis baseline while
    fenced, then capture target heads after migration".
    """
    repo_root = Path(__file__).resolve().parents[2]
    rev_parse = subprocess.run(  # noqa: S603 - argv list, resolved executable
        [_git_executable(), "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rev_parse.returncode == 0 and rev_parse.stdout.strip(), (
        f"{repo_root} did not resolve as a git repository via `git rev-parse "
        f"HEAD` (exit {rev_parse.returncode}): {rev_parse.stderr}"
    )
    current_revision = rev_parse.stdout.strip()
    assert (
        len(current_revision) == 40
    ), f"git rev-parse HEAD did not return a 40-character SHA: {current_revision!r}"

    descriptor_path = repo_root / "deploy" / "product.toml"
    assert descriptor_path.is_file(), (
        f"{descriptor_path} does not exist in this checkout; C2 cannot "
        "capture a real target descriptor without it"
    )

    db = _dbname(scratch_db)

    # Make the scratch database production-shaped, exactly as
    # test_fenced_migration.py does: `scratch_db` only hands `public`'s
    # SCHEMA to `app_admin`; the DATABASE itself is still superuser-owned.
    with _connect(postgres_url, autocommit=True) as conn:
        conn.execute(text(f'ALTER DATABASE "{db}" OWNER TO app_admin'))

    admin_url = url_for(postgres_url, db, user="app_admin")
    app_user_url = url_for(postgres_url, db, user="app_user")
    platform_api_url = url_for(postgres_url, db, user="platform_api")

    with _connect(admin_url, autocommit=True) as conn:
        proof = fence_writers(
            conn,
            database=db,
            fence_id=FENCE_ID,
            session_wait_seconds=SESSION_WAIT_SECONDS,
        )
    with _connect(admin_url) as conn:
        assert fence_is_holding(conn, proof) is True

    # Non-vacuity control: the fence genuinely blocks a new writer
    # connection, matching test_fenced_migration.py's own control.
    with pytest.raises(OperationalError, match="permission denied"):
        with _connect(app_user_url):
            pass

    with _connect(admin_url) as conn:
        genesis = capture_genesis_baseline(
            conn, repo_root=repo_root, source_revision=current_revision
        )
    assert genesis.migration_heads == (), (
        "a fresh scratch database has no alembic_version rows yet; a "
        "non-empty genesis head set here would mean this test is not "
        "actually measuring a pre-migration database"
    )
    assert genesis.raw_bytes_descriptor_digest.startswith("sha256:")
    hex_part = genesis.raw_bytes_descriptor_digest.removeprefix("sha256:")
    assert len(hex_part) == 64

    dotmac_platform = shutil.which("dotmac-platform")
    assert dotmac_platform is not None, (
        "the dotmac-platform console script is not on PATH; this suite "
        "must run inside the project's installed virtualenv — the same "
        "one CI's `poetry run dotmac-platform admin migrate` step uses"
    )

    env = {
        "PATH": os.environ.get("PATH", ""),
        "DATABASE_URL": app_user_url,
        "PLATFORM_DATABASE_URL": platform_api_url,
        "MIGRATION_DATABASE_URL": admin_url,
    }
    result = subprocess.run(  # noqa: S603 - fixed console-script argv, no shell
        [dotmac_platform, "admin", "migrate"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        "`dotmac-platform admin migrate` failed under the fence "
        f"(exit {result.returncode}):\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )

    # Still fenced: no writer reconnected during the capture-then-migrate
    # sequence.
    with _connect(admin_url) as conn:
        assert fence_is_holding(conn, proof) is True

    with _connect(admin_url) as conn:
        target = capture_target_state(conn, descriptor_path=descriptor_path)

    expected_heads = set(_offline_effective_heads(monkeypatch))
    assert expected_heads, (
        "composed_effective_heads returned no heads; the equality check "
        "below would otherwise pass vacuously against an empty database"
    )
    assert set(target.migration_heads) == expected_heads

    # The whole point: before and after are genuinely different.
    assert genesis.migration_heads != target.migration_heads

    with _connect(admin_url, autocommit=True) as conn:
        restore_writers(
            conn,
            proof,
            database=db,
            expected_fence_id=FENCE_ID,
            session_wait_seconds=SESSION_WAIT_SECONDS,
        )

    # PUBLIC/writer CONNECT is back: a new connection as `app_user` succeeds.
    with _connect(app_user_url) as conn:
        assert conn.execute(text("SELECT 1")).scalar_one() == 1
