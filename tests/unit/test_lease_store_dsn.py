"""`lease_dsn` (CP-2, design 3.6): TCP, verify-full, channel binding, nothing else."""

from __future__ import annotations

import pytest

from vendor_cp.deployment.lease_store import (
    LEASE_DSN_ENV,
    LeaseDsnRefused,
    lease_dsn,
)

GOOD = (
    "postgresql+psycopg://lease_run_a1@db.lane3.test:55432/vendor_cp"
    "?hostaddr=127.0.0.1&sslmode=verify-full&sslrootcert=/run/lane3/ca.pem"
    "&channel_binding=require&connect_timeout=5"
)


def _env(dsn: str | None = GOOD, **extra: str) -> dict[str, str]:
    environment = dict(extra)
    if dsn is not None:
        environment[LEASE_DSN_ENV] = dsn
    return environment


def test_the_conforming_dsn_is_returned_unchanged() -> None:
    assert lease_dsn(_env()) == GOOD


def test_a_missing_dsn_refuses_naming_the_variable_only() -> None:
    with pytest.raises(LeaseDsnRefused, match=LEASE_DSN_ENV):
        lease_dsn(_env(None))


@pytest.mark.parametrize(
    "mutation",
    [
        ("sslmode=verify-full", "sslmode=require"),
        ("sslmode=verify-full", "sslmode=verify-ca"),
        ("&channel_binding=require", ""),
        ("channel_binding=require", "channel_binding=prefer"),
        ("sslrootcert=/run/lane3/ca.pem", "sslrootcert=ca.pem"),
        ("&sslrootcert=/run/lane3/ca.pem", ""),
        ("connect_timeout=5", "connect_timeout=30"),
        ("&connect_timeout=5", ""),
        ("&connect_timeout=5", "&connect_timeout=5&passfile=/tmp/pw"),
        ("&connect_timeout=5", "&connect_timeout=5&options=-c%20role%3Dx"),
        ("&connect_timeout=5", "&connect_timeout=5&service=s"),
    ],
)
def test_a_non_conforming_dsn_refuses(mutation: tuple[str, str]) -> None:
    old, new = mutation
    assert old in GOOD
    with pytest.raises(LeaseDsnRefused):
        lease_dsn(_env(GOOD.replace(old, new)))


def test_a_unix_socket_dsn_refuses_because_it_carries_no_tls() -> None:
    socket = (
        "postgresql+psycopg://lease_run_a1@/vendor_cp?host=/var/run/postgresql"
        "&sslmode=verify-full&sslrootcert=/ca.pem&channel_binding=require"
        "&connect_timeout=5"
    )
    with pytest.raises(LeaseDsnRefused):
        lease_dsn(_env(socket))


@pytest.mark.parametrize("name", ["PGPASSWORD", "PGSSLMODE", "PGHOST", "PGSERVICE"])
def test_libpq_environment_variables_refuse_by_name_only(name: str) -> None:
    with pytest.raises(LeaseDsnRefused) as caught:
        lease_dsn(_env(**{name: "secret-value"}))
    assert "secret-value" not in str(caught.value)
    assert name in str(caught.value)


@pytest.mark.parametrize(
    "dsn", ["not a url", "mysql://u@h/d", "postgresql+psycopg://@h/d"]
)
def test_a_malformed_dsn_refuses_without_echoing_it(dsn: str) -> None:
    with pytest.raises(LeaseDsnRefused) as caught:
        lease_dsn(_env(dsn))
    assert dsn not in str(caught.value)
