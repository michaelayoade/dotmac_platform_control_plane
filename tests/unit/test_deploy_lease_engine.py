"""The lease store's own database runtime (architect review of PR 269, ruling 6).

No database. The DSN is a NAMED setting; it must name the dedicated lease role, so
the application DSN (`platform_api`, shared by the app, relay and ops containers) is
refused before anything is built. No refusal carries a value.
"""

from __future__ import annotations

import pytest

from vendor_cp.deployment.deploy_lease_engine import (
    LEASE_DSN_ENV,
    LEASE_ROLE,
    LeaseDsnRefused,
    lease_runtime,
)

_GOOD = f"postgresql+psycopg://{LEASE_ROLE}:x@db:5432/vendor"


def test_the_setting_is_named_and_the_role_is_the_dedicated_one() -> None:
    assert LEASE_DSN_ENV == "VENDOR_TARGET_LEASE_DATABASE_URL"
    assert LEASE_ROLE == "platform_target_lease"


@pytest.mark.parametrize(
    "env",
    [
        {},
        {LEASE_DSN_ENV: ""},
        {LEASE_DSN_ENV: "not a url"},
        {LEASE_DSN_ENV: "mysql://platform_target_lease:x@db/v"},
        # the application role's DSN is never a lease DSN
        {LEASE_DSN_ENV: "postgresql+psycopg://platform_api:x@db:5432/vendor"},
        {LEASE_DSN_ENV: _GOOD + "?options=-c%20role%3Dplatform_api"},
        {LEASE_DSN_ENV: _GOOD + "?role=platform_api"},
        {LEASE_DSN_ENV: _GOOD, "PGPASSWORD": "x"},
        {LEASE_DSN_ENV: _GOOD, "PGSERVICE": "x"},
    ],
)
def test_a_lease_dsn_that_is_not_the_lease_roles_is_refused_without_its_value(
    env: dict[str, str],
) -> None:
    with pytest.raises(LeaseDsnRefused) as refused:
        lease_runtime(env)
    assert "x@db" not in str(refused.value) and "platform_api:x" not in str(
        refused.value
    )
