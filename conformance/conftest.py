"""Configuration guard for the database-backed conformance suite.

`conformance/` is deliberately excluded from this repository's `testpaths`
(`pyproject.toml` pins `testpaths = ["tests"]`) and from CI's default
`poetry run pytest -q` invocation, which never descends into this directory.
The required D16 CI step invokes its single conformance file explicitly.
`pytest conformance/` therefore only ever runs when someone invokes it
explicitly and deliberately, per `conformance/README.md`.

A database-backed run that then silently skipped every test because
`CONFORMANCE_DATABASE_URL` was unset would still exit zero -- "0 passed, N
skipped" looks like a pass to anyone, or anything, reading the exit code
alone, and this suite is the acceptance gate for a real cross-repository
security boundary. The separately invoked D16 source-verifier test needs an
exact Foundation checkout but no database. Only that single-file invocation
is exempt from the database precondition; a whole-directory or mixed run
still fails before collection. Each test's own required inputs remain hard
errors, never skips.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def pytest_configure(config: pytest.Config) -> None:
    d16_file = (
        Path(__file__).parent / "test_d16_source_verifier_real_foundation.py"
    ).resolve()
    requested = [Path(arg.split("::", 1)[0]).resolve() for arg in config.args]
    if requested == [d16_file]:
        return
    if not os.environ.get("CONFORMANCE_DATABASE_URL"):
        raise pytest.UsageError(
            "CONFORMANCE_DATABASE_URL is unset. Database-backed conformance "
            "requires a real, migrated PostgreSQL mod_deploy schema; only an "
            "explicit single-file D16 source-verifier run is database-free. "
            "A missing configuration is a usage error, not a skip."
        )
