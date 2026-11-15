"""The role SQL is rendered as text, ordered, validated and never executed."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from vendor_cp.deployment import consumption_role_check as check
from vendor_cp.deployment import consumption_role_spec as spec
from vendor_cp.deployment import consumption_scope as scope
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

_NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "role", ["Run", "1run", "ru", "run-x", "run x", "r;DROP", "x" * 64, ""]
)
def test_unsafe_role_names_refuse(role: str) -> None:
    for call in (spec.creation_sql, spec.revocation_sql, spec.verification_sql):
        with pytest.raises(ValueError):
            call(role)


def test_valid_until_is_capped_at_four_hours_and_must_be_aware_and_future() -> None:
    ok = spec.creation_sql(
        "run_consume", valid_until=_NOW + timedelta(hours=4), now=_NOW
    )
    assert "VALID UNTIL '2026-11-15 16:00:00+00'" in ok[0]
    for bad in (
        _NOW + timedelta(hours=4, seconds=1),
        _NOW,
        _NOW - timedelta(minutes=1),
        datetime(2026, 11, 15, 13, 0),
        "tomorrow",
    ):
        with pytest.raises(ValueError):
            spec.creation_sql("run_consume", valid_until=bad, now=_NOW)  # type: ignore[arg-type]


def test_a_quote_in_the_password_placeholder_refuses() -> None:
    with pytest.raises(ValueError):
        spec.creation_sql("run_consume", password="x'; DROP")


def test_creation_carries_the_four_limits_in_the_statements() -> None:
    sql = spec.creation_sql("run_consume")
    joined = "\n".join(sql)
    assert "CONNECTION LIMIT 4" in sql[0]
    assert "statement_timeout" in joined and "lock_timeout" in joined
    assert "idle_in_transaction_session_timeout" in joined
    assert "log_statement = 'all'" in joined
    assert f"UPDATE ({scope.LOCK_COLUMN})" in joined
    assert "GRANT INSERT ON public.platform_idempotency_records" in joined
    assert spec.PASSWORD_PLACEHOLDER in sql[0]


def test_revocation_is_ordered_and_closes_each_gap() -> None:
    sql = spec.revocation_sql("run_consume")
    assert sql[0].startswith('ALTER ROLE "run_consume" NOLOGIN CONNECTION LIMIT 0')
    assert "pg_terminate_backend" in sql[1]
    assert sql[2] == 'DROP OWNED BY "run_consume"'
    assert sql[3] == 'DROP ROLE "run_consume"'
    verify = spec.verification_sql("run_consume")
    assert "roles_remaining" in verify and "sessions_remaining" in verify
    assert "'run_consume'" in verify


def test_the_cli_prints_text_and_executes_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert spec.main(["create", "--role", "run_consume"]) == 0
    out = capsys.readouterr().out
    assert out.count(";") >= 9 and "CREATE ROLE" in out
    assert spec.main(["revoke", "--role", "run_consume"]) == 0
    assert "DROP OWNED BY" in capsys.readouterr().out
    assert spec.main(["verify"]) == 0
    assert spec.main(["create", "--role", "Bad Name"]) == 2
    assert "refused" in capsys.readouterr().err


def test_the_spec_module_cannot_reach_a_database() -> None:
    tree = ast.parse(Path(spec.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {
        "sqlalchemy",
        "psycopg",
        "subprocess",
        "socket",
        "dotmac_kernel",
    }


# ── the standalone read-only check ──────────────────────────────────────────

_TLS = "sslmode=verify-full&sslrootcert=/etc/dotmac/ca.pem"
_DSN = f"postgresql+psycopg://run_consume:SECRET-MARKER@db.example.test/cp?{_TLS}"


def _patch_proof(monkeypatch: pytest.MonkeyPatch, *, refuse: bool = False) -> list[Any]:
    seen: list[Any] = []
    monkeypatch.setattr(
        check,
        "consumption_sessions",
        lambda dsn: seen.append(("dsn", dsn)) or (lambda: None),
    )

    def prove(_factory: Any, *, role: str | None = None) -> None:
        seen.append(("role", role))
        if refuse:
            raise FoundationBindingsUnavailable(
                "x", code=TargetRefusal.CONSUMPTION_ROLE_OVERBROAD
            )

    monkeypatch.setattr(check, "prove_scoped_role", prove)
    return seen


def test_check_proves_the_credentials_own_role(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = _patch_proof(monkeypatch)
    assert check.main([], {scope.CONSUMPTION_DSN_ENV: _DSN}) == 0
    assert ("role", None) in seen and "passed" in capsys.readouterr().out


def test_check_proves_a_named_role_over_an_admin_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_proof(monkeypatch)
    assert (
        check.main(
            ["--role", "run_consume"], {check.ADMIN_DSN_ENV: "postgresql://a@h/d"}
        )
        == 0
    )
    assert ("role", "run_consume") in seen


def test_check_refuses_by_code_and_never_echoes_the_dsn(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_proof(monkeypatch, refuse=True)
    assert check.main([], {scope.CONSUMPTION_DSN_ENV: _DSN}) == 2
    err = capsys.readouterr().err
    assert "consumption_role_overbroad" in err and "SECRET-MARKER" not in err
    # static refusals come first: no TLS, general DSN, PG* variables, no admin DSN
    assert check.main([], {scope.CONSUMPTION_DSN_ENV: "postgresql://u:p@h/d"}) == 2
    assert check.main([], {scope.CONSUMPTION_DSN_ENV: _DSN, "PGHOST": "x"}) == 2
    assert check.main(["--role", "run_consume"], {}) == 2
