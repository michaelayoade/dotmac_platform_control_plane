"""Postgres-suite gate.

`pytest -rs` only PRINTS skips; it does not fail on them. Under required CI a
suite that can pass by skipping is not a gate at all — which is precisely how
these tests stayed silently unrun while the pipeline reported green.

Exposed as a FIXTURE rather than an importable helper: `tests.migration` is a
package, so cross-module imports here are import-path-fragile, and a gate that
breaks collection is no better than one that skips.

`REQUIRE_POSTGRES_TESTS=1` (set by the CI job) turns a missing
`TEST_DATABASE_URL` into a FAILURE. Locally the variable is unset, so the suite
still skips politely for anyone without a database.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session")
def postgres_url() -> str:
    """The single place that decides skip-vs-fail for the Postgres suites."""
    url = os.getenv("TEST_MIGRATION_DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if url:
        return url
    message = (
        "TEST_DATABASE_URL is not set — the Postgres migration and replay "
        "concurrency suites cannot run."
    )
    if os.getenv("REQUIRE_POSTGRES_TESTS") == "1":
        pytest.fail(
            f"{message} REQUIRE_POSTGRES_TESTS=1, so this is a FAILURE: under "
            "required CI these tests must never pass by skipping.",
            pytrace=False,
        )
    pytest.skip(message)
