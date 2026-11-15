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
    assert "VALID UNTIL '2026-11-15 16:00:00+00'" in "\n".join(ok)
    for bad in (
        _NOW + timedelta(hours=4, seconds=1),
        _NOW,
        _NOW - timedelta(minutes=1),
        datetime(2026, 11, 15, 13, 0),
        "tomorrow",
    ):
        with pytest.raises(ValueError):
            spec.creation_sql("run_consume", valid_until=bad, now=_NOW)  # type: ignore[arg-type]


_DISPATCH = "3f2b8c1e-1111-4222-8333-444455556666"


@pytest.mark.parametrize(
    "verifier",
    [
        "plaintext-password",
        "x'; DROP ROLE y; --",
        "SCRAM-SHA-256$4096:abc",
        "SCRAM-SHA-512$4096:YWJj$YWJj:YWJj",
        "",
    ],
)
def test_a_plaintext_or_malformed_password_refuses(verifier: str) -> None:
    with pytest.raises(ValueError):
        spec.creation_sql("run_consume", scram_verifier=verifier)


def test_creation_takes_a_scram_verifier_and_no_plaintext_password_anywhere() -> None:
    verifier = spec.scram_verifier("pw-never-in-sql", salt=b"0123456789abcdef")
    sql = "\n".join(spec.creation_sql("run_consume", scram_verifier=verifier))
    assert f"PASSWORD '{verifier}'" in sql and "pw-never-in-sql" not in sql
    assert spec.VERIFIER_PLACEHOLDER in "\n".join(spec.creation_sql("run_consume"))


def test_the_scram_verifier_is_the_rfc5802_construction() -> None:
    import base64
    import hashlib
    import hmac

    salt = b"0123456789abcdef"
    verifier = spec.scram_verifier("secret", salt=salt)
    head, rest = verifier.split("$", 1)
    iterations, parts = rest.split(":", 1)
    assert head == "SCRAM-SHA-256" and iterations == "4096"
    _salt64, keys = parts.split("$")
    stored64, server64 = keys.split(":")
    salted = hashlib.pbkdf2_hmac("sha256", b"secret", salt, 4096)
    client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    assert base64.b64decode(stored64) == hashlib.sha256(client).digest()
    assert (
        base64.b64decode(server64)
        == hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    )
    assert base64.b64decode(_salt64) == salt
    assert spec.scram_verifier("secret") != spec.scram_verifier("secret")  # random salt
    for bad in (("", 4096), ("x", 100)):
        with pytest.raises(ValueError):
            spec.scram_verifier(bad[0], iterations=bad[1])


def test_creation_is_one_transaction_that_keeps_the_verifier_out_of_the_log() -> None:
    sql = spec.creation_sql("run_consume", dispatch_id=_DISPATCH)
    assert sql[0] == "BEGIN" and sql[-1] == "COMMIT"
    assert sql[1] == "SET LOCAL log_statement = 'none'"
    assert sql.index("SET LOCAL log_statement = 'none'") < next(
        i for i, s in enumerate(sql) if s.startswith("CREATE ROLE")
    )
    assert any("temp_file_limit = '256MB'" in s for s in sql)


def test_the_run_policies_bind_scope_dispatch_and_database_time() -> None:
    sql = spec.creation_sql("run_consume", dispatch_id=_DISPATCH)
    insert = next(s for s in sql if s.startswith('CREATE POLICY "run_consume_insert"'))
    select = next(s for s in sql if s.startswith('CREATE POLICY "run_consume_select"'))
    assert 'AS RESTRICTIVE FOR INSERT TO "run_consume"' in insert
    assert 'AS RESTRICTIVE FOR SELECT TO "run_consume"' in select
    for text_ in (insert, select):
        assert (
            "deployment.consume_dispatch_challenge.v1" in text_ and _DISPATCH in text_
        )
    assert "created_at = now()" in insert and "updated_at = now()" in insert
    assert "status = 'executed'" in insert and "expires_at IS NULL" in insert
    assert "FOR ALL" not in insert + select and "PUBLIC" not in insert + select


@pytest.mark.parametrize(
    "dispatch",
    [
        "",
        "not-a-uuid",
        _DISPATCH.upper(),
        _DISPATCH + "'; --",
        "3f2b8c1e11114222833344445555666",
    ],
)
def test_the_dispatch_id_must_be_a_canonical_uuid(dispatch: str) -> None:
    with pytest.raises(ValueError):
        spec.creation_sql("run_consume", dispatch_id=dispatch)


def test_the_guard_is_unrestricted_for_others_and_refuses_teardown_with_policies() -> (
    None
):
    enable = "\n".join(spec.guard_enable_sql())
    assert "ENABLE ROW LEVEL SECURITY" in enable and "FORCE" not in enable
    assert "AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)" in enable
    assert "lock_timeout = '3s'" in enable
    disable = spec.guard_disable_sql()
    joined = "\n".join(disable)
    assert "permissive = 'RESTRICTIVE'" in joined and "RAISE EXCEPTION" in joined
    assert joined.index("RAISE EXCEPTION") < joined.index("DROP POLICY")
    assert joined.index("DROP POLICY") < joined.index("DISABLE ROW LEVEL SECURITY")


def test_creation_carries_the_four_limits_in_the_statements() -> None:
    sql = spec.creation_sql("run_consume")
    joined = "\n".join(sql)
    assert "CONNECTION LIMIT 4" in next(s for s in sql if s.startswith("CREATE ROLE"))
    assert "statement_timeout" in joined and "lock_timeout" in joined
    assert "idle_in_transaction_session_timeout" in joined
    assert "log_statement = 'all'" in joined
    assert f"UPDATE ({scope.LOCK_COLUMN})" in joined
    assert "GRANT INSERT ON public.platform_idempotency_records" in joined


def test_revocation_is_ordered_and_closes_each_gap() -> None:
    sql = spec.revocation_sql("run_consume")
    assert sql[0].startswith('ALTER ROLE "run_consume" NOLOGIN CONNECTION LIMIT 0')
    assert "pg_terminate_backend" in sql[1]
    assert sql[2].startswith('DROP POLICY IF EXISTS "run_consume_insert" ON ')
    assert sql[3].startswith('DROP POLICY IF EXISTS "run_consume_select"')
    assert sql[4] == 'DROP OWNED BY "run_consume"'
    assert sql[5] == 'DROP ROLE "run_consume"'
    verify = spec.verification_sql("run_consume")
    assert "roles_remaining" in verify and "sessions_remaining" in verify
    assert "policies_remaining" in verify
    assert "'run_consume'" in verify


def test_the_cli_prints_text_and_executes_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert spec.main(["create", "--role", "run_consume"]) == 0
    out = capsys.readouterr().out
    assert out.count(";") >= 15 and "CREATE ROLE" in out
    assert spec.main(["revoke", "--role", "run_consume"]) == 0
    assert "DROP OWNED BY" in capsys.readouterr().out
    assert spec.main(["verify"]) == 0
    assert (
        spec.main(["guard-enable"]) == 0
        and "ENABLE ROW LEVEL" in capsys.readouterr().out
    )
    assert spec.main(["guard-disable"]) == 0 and "RAISE" in capsys.readouterr().out
    assert spec.main(["create", "--role", "run_consume", "--dispatch-id", "bad"]) == 2
    assert (
        spec.main(["create", "--role", "run_consume", "--scram-verifier", "plain"]) == 2
    )
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

    def prove(_factory: Any, *, dispatch_id: str, role: str | None = None) -> None:
        seen.append(("role", role))
        seen.append(("dispatch", dispatch_id))
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
    assert (
        check.main(["--dispatch-id", _DISPATCH], {scope.CONSUMPTION_DSN_ENV: _DSN}) == 0
    )
    assert ("role", None) in seen and "passed" in capsys.readouterr().out


def test_check_proves_a_named_role_over_an_admin_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_proof(monkeypatch)
    assert (
        check.main(
            ["--role", "run_consume", "--dispatch-id", _DISPATCH],
            {check.ADMIN_DSN_ENV: "postgresql://a@h/d"},
        )
        == 0
    )
    assert ("role", "run_consume") in seen and ("dispatch", _DISPATCH) in seen


def test_check_refuses_by_code_and_never_echoes_the_dsn(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_proof(monkeypatch, refuse=True)
    assert (
        check.main(["--dispatch-id", _DISPATCH], {scope.CONSUMPTION_DSN_ENV: _DSN}) == 2
    )
    err = capsys.readouterr().err
    assert "consumption_role_overbroad" in err and "SECRET-MARKER" not in err
    # static refusals come first: no TLS, general DSN, PG* variables, no admin DSN
    arg = ["--dispatch-id", _DISPATCH]
    assert check.main(arg, {scope.CONSUMPTION_DSN_ENV: "postgresql://u:p@h/d"}) == 2
    assert check.main(arg, {scope.CONSUMPTION_DSN_ENV: _DSN, "PGHOST": "x"}) == 2
    assert check.main(["--role", "run_consume", *arg], {}) == 2
    with pytest.raises(SystemExit):
        check.main([], {scope.CONSUMPTION_DSN_ENV: _DSN})  # --dispatch-id is required
