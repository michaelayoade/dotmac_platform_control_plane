"""Configuration guard for the host-admission conformance suite.

`conformance/` is deliberately excluded from this repository's `testpaths`
(`pyproject.toml` pins `testpaths = ["tests"]`) and from CI (`poetry run
pytest -q` takes no path argument, so it never descends into this directory
at all -- this `conftest.py` is never even loaded during a normal CI run).
`pytest conformance/` therefore only ever runs when someone invokes it
explicitly and deliberately, per `conformance/README.md`.

A run that then silently skipped every test because
`CONFORMANCE_DATABASE_URL` was unset would still exit zero -- "0 passed, N
skipped" looks like a pass to anyone, or anything, reading the exit code
alone, and this suite is the acceptance gate for a real cross-repository
security boundary. So a missing configuration here is a HARD USAGE ERROR,
not a skip: `pytest_configure` raises before collection even starts, so the
run aborts loudly and non-zero, and never reports a misleadingly-green
"all skipped" result.
"""

from __future__ import annotations

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    if not os.environ.get("CONFORMANCE_DATABASE_URL"):
        raise pytest.UsageError(
            "CONFORMANCE_DATABASE_URL is unset. conformance/ is an explicit, "
            "deliberately-excluded suite (see conformance/README.md) that "
            "requires a real, migrated PostgreSQL mod_deploy schema -- it is "
            "never invoked implicitly, so a missing configuration here is a "
            "usage error to fix, not a precondition to skip past."
        )
