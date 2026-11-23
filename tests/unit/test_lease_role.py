"""The per-run LEASE role: rendered text, the proof over a scripted catalogue, the
watchdog's lease kind, and the consumption role's zero reach into `cp_lane3`.

The rendered statements are what the real-PostgreSQL job runs
(`tests/migration/test_lane3_store_privileges.py`), so the specification is
exactly what is proven there.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from vendor_cp.deployment import consumption_role_spec as consumption_spec
from vendor_cp.deployment import consumption_scope as scope
from vendor_cp.deployment import consumption_watchdog as watchdog
from vendor_cp.deployment import lease_role_check as check
from vendor_cp.deployment import lease_role_spec as spec

_NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
_VERIFIER = spec.scram_verifier("p" * 24, salt=bytes(range(16)), iterations=4096)
_HOST = "host-a"
_RUN = "github-actions:dotmac-tech/lane3:9001:1"
_ROLE = "l3_run_a1"


def _sql(**override: Any) -> tuple[str, ...]:
    arguments: dict[str, Any] = {
        "host_id": _HOST,
        "authorization_run": _RUN,
        "scram_verifier_value": _VERIFIER,
        "valid_until": _NOW + timedelta(hours=3),
        "now": _NOW,
    }
    arguments.update(override)
    return spec.executable_creation_sql(_ROLE, **arguments)


# ── the rendered creation transaction ───────────────────────────────────────


def test_the_creation_transaction_is_ordered_and_bracketed() -> None:
    statements = _sql()
    assert statements[0] == "BEGIN"
    assert statements[-1] == "COMMIT"
    assert statements[1] == "SET LOCAL log_statement = 'none'"
    assert statements[3].startswith(f'CREATE ROLE "{_ROLE}" LOGIN PASSWORD')


def test_the_role_is_least_privilege_with_every_limit_the_proof_demands() -> None:
    text = "\n".join(_sql())
    for needle in (
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOREPLICATION",
        "NOBYPASSRLS",
        "NOINHERIT",
        "CONNECTION LIMIT 2",
        "VALID UNTIL '2026-11-19 15:00:00+00'",
        "SET statement_timeout = '30s'",
        "SET lock_timeout = '5s'",
        "SET idle_in_transaction_session_timeout = '30s'",
        "SET temp_file_limit = '256MB'",
        "SET log_statement = 'all'",
    ):
        assert needle in text, needle


def test_the_only_grants_are_schema_usage_and_the_lease_functions() -> None:
    grants = [s for s in _sql() if s.startswith("GRANT")]
    assert len(grants) == 2
    assert grants[0] == f'GRANT USAGE ON SCHEMA cp_lane3 TO "{_ROLE}"'
    assert grants[1].startswith("GRANT EXECUTE ON FUNCTION ")
    for signature in spec.LEASE_FUNCTIONS:
        assert f"cp_lane3.{signature}" in grants[1]
    # No table, sequence, column, ALL, PUBLIC or GRANT OPTION anywhere.
    text = "\n".join(_sql())
    for forbidden in (
        "ON TABLE",
        "ON ALL",
        "ON SEQUENCE",
        "WITH GRANT OPTION",
        "TO PUBLIC",
        "GRANT SELECT",
        "GRANT INSERT",
        "GRANT UPDATE",
        "mod_deploy",
        "platform_idempotency_records",
    ):
        assert forbidden not in text, forbidden


def test_the_binding_names_one_host_and_one_run_until_the_roles_own_deadline() -> None:
    inserts = [s for s in _sql() if s.startswith("INSERT INTO cp_lane3.run_bindings")]
    assert len(inserts) == 1
    assert f"'{_ROLE}'" in inserts[0]
    assert f"'{_HOST}'" in inserts[0]
    assert f"'{_RUN}'" in inserts[0]
    assert "'2026-11-19 15:00:00+00'" in inserts[0]
    assert inserts[0].endswith("'lane3-ceremony')")


def test_the_rendered_password_is_only_ever_a_scram_verifier() -> None:
    text = "\n".join(_sql())
    assert _VERIFIER in text
    assert "p" * 24 not in text


@pytest.mark.parametrize(
    "role", ["Run", "1run", "ru", "run-x", "run x", "r;DROP", "x" * 64, ""]
)
def test_unsafe_role_names_refuse(role: str) -> None:
    with pytest.raises(ValueError):
        spec.revocation_sql(role)
    with pytest.raises(ValueError):
        spec.verification_sql(role)


@pytest.mark.parametrize(
    "override",
    [
        {"host_id": "Host_A"},
        {"host_id": "host'a"},
        {"host_id": "-host"},
        {"authorization_run": "run'; DROP TABLE x; --"},
        {"authorization_run": "has space"},
        {"authorization_run": ""},
        {"scram_verifier_value": "plaintext-password"},
        {"scram_verifier_value": "x'; DROP ROLE y; --"},
        {"valid_until": _NOW + timedelta(hours=4, seconds=1)},
        {"valid_until": _NOW},
        {"valid_until": datetime(2026, 11, 19, 13, 0)},
    ],
)
def test_unsafe_or_out_of_bound_values_refuse(override: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _sql(**override)


def test_the_template_placeholder_never_executes() -> None:
    with pytest.raises(ValueError):
        spec.executable_creation_sql(
            spec.ROLE_PLACEHOLDER,
            host_id=_HOST,
            authorization_run=_RUN,
            scram_verifier_value=_VERIFIER,
            valid_until=_NOW + timedelta(hours=1),
            now=_NOW,
        )


def test_revocation_is_ordered_and_reads_back_three_zero_counts() -> None:
    steps = spec.revocation_sql(_ROLE)
    assert steps[0] == f'ALTER ROLE "{_ROLE}" NOLOGIN CONNECTION LIMIT 0'
    assert "pg_terminate_backend" in steps[1]
    assert steps[-2] == f'DROP OWNED BY "{_ROLE}"'
    assert steps[-1] == f'DROP ROLE "{_ROLE}"'
    verification = spec.verification_sql(_ROLE)
    for name in ("roles_remaining", "sessions_remaining", "grants_remaining"):
        assert name in verification


# ── pg_hba (Q1-B) ───────────────────────────────────────────────────────────


def test_the_hba_block_admits_only_the_cp_side_tunnel_source() -> None:
    block = spec.pg_hba_block(_ROLE, database="vendor_cp", cp_bridge_addr="192.0.2.7")
    assert block == (
        f"hostssl vendor_cp {_ROLE} 192.0.2.7/32 scram-sha-256",
        f"host    all {_ROLE} all reject",
        f"local   all {_ROLE} reject",
    )
    assert block[0].startswith("hostssl ")
    assert not any(line.startswith("host ") and "reject" not in line for line in block)


@pytest.mark.parametrize(
    "address",
    ["", "launcher.example", "192.0.2.0/24", "0.0.0.0", "224.0.0.1", "::"],  # noqa: S104
)
def test_the_hba_source_must_be_one_literal_host_address(address: str) -> None:
    with pytest.raises(ValueError):
        spec.pg_hba_block(_ROLE, database="vendor_cp", cp_bridge_addr=address)


def test_an_ipv6_source_renders_a_slash_128() -> None:
    block = spec.pg_hba_block(_ROLE, database="d", cp_bridge_addr="2001:db8::7")
    assert block[0] == f"hostssl d {_ROLE} 2001:db8::7/128 scram-sha-256"


def test_the_cli_prints_text_and_executes_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        spec.main(
            [
                "pg-hba",
                "--role",
                _ROLE,
                "--database",
                "d",
                "--cp-bridge-addr",
                "192.0.2.7",
            ]
        )
        == 0
    )
    assert "hostssl d" in capsys.readouterr().out
    assert spec.main(["revoke", "--role", "BAD ROLE"]) == 2


# ── the consumption role holds NOTHING in the lease schema ──────────────────


def test_the_consumption_role_spec_never_names_the_lease_schema() -> None:
    """Design 3.5: an architecture assertion on the rendered text, so a later edit
    that granted the target anything in `cp_lane3` fails here, not in production."""
    rendered: list[str] = [
        *consumption_spec.creation_sql(consumption_spec.ROLE_PLACEHOLDER),
        *consumption_spec.revocation_sql("run_consume"),
        *consumption_spec.guard_enable_sql(),
        *consumption_spec.guard_disable_sql(),
        consumption_spec.verification_sql("run_consume"),
    ]
    assert rendered
    assert not any("cp_lane3" in statement for statement in rendered)
    assert "cp_lane3" not in {s for pair in scope.READ_ONLY_TABLES for s in pair}
    for table_set in (scope.READ_ONLY_TABLES, scope.LOCK_TABLES, scope.LEDGER_TABLES):
        assert all(schema != "cp_lane3" for schema, _ in table_set)


# ── the proof, over a scripted catalogue ────────────────────────────────────

_GOOD_CONFIG = [
    "statement_timeout=30s",
    "lock_timeout=5s",
    "idle_in_transaction_session_timeout=30s",
    "temp_file_limit=256MB",
    "log_statement=all",
]
_GOOD_ROLE = (False,) * 6 + (True, 2, "t", 3600.0, _GOOD_CONFIG)


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def one_or_none(self) -> Any:
        return self._value

    def scalar(self) -> Any:
        return self._value

    def all(self) -> Any:
        return self._value

    def one(self) -> Any:
        return self._value


class _Catalogue:
    """Answers each catalogue question by identity of its SQL text."""

    def __init__(self, **answers: Any) -> None:
        self.answers: dict[str, Any] = {
            scope._ROLE_SQL: _GOOD_ROLE,
            scope._MEMBERSHIP_SQL: 0,
            scope._DATABASE_CREATE_SQL: False,
            scope._CREATE_SCHEMAS_SQL: 0,
            scope._OWNED_SQL: 0,
            scope._TABLES_SQL: [],
            scope._COLUMNS_SQL: [],
            scope._SEQUENCES_SQL: [],
            check._SCHEMA_USAGE_SQL: [("cp_lane3",), ("public",)],
            check._LEASE_EXECUTE_SQL: [
                (_catalogue_spelling(signature),) for signature in spec.LEASE_FUNCTIONS
            ],
            check._DEFINERS_OUTSIDE_SQL: 0,
            check._CONNECT_SQL: True,
            check._BINDING_SQL: 1,
            check._OTHER_BINDINGS_SQL: 0,
        }
        names = {
            "ROLE": scope._ROLE_SQL,
            "MEMBERSHIP": scope._MEMBERSHIP_SQL,
            "DATABASE_CREATE": scope._DATABASE_CREATE_SQL,
            "CREATE_SCHEMAS": scope._CREATE_SCHEMAS_SQL,
            "OWNED": scope._OWNED_SQL,
            "TABLES": scope._TABLES_SQL,
            "COLUMNS": scope._COLUMNS_SQL,
            "SEQUENCES": scope._SEQUENCES_SQL,
            "SCHEMA_USAGE": check._SCHEMA_USAGE_SQL,
            "LEASE_EXECUTE": check._LEASE_EXECUTE_SQL,
            "DEFINERS_OUTSIDE": check._DEFINERS_OUTSIDE_SQL,
            "CONNECT": check._CONNECT_SQL,
            "BINDING": check._BINDING_SQL,
            "OTHER_BINDINGS": check._OTHER_BINDINGS_SQL,
        }
        for key, value in answers.items():
            self.answers[names[key]] = value
        self.rolled_back = False
        self.closed = False

    def execute(self, statement: Any, params: Any = None) -> _Result:
        return _Result(self.answers[str(statement)])

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def _catalogue_spelling(signature: str) -> str:
    return signature.replace("timestamptz", "timestamp with time zone")


def _code(catalogue: _Catalogue) -> str:
    with pytest.raises(check.LeaseRoleRefused) as refused:
        check.prove_lease_role(
            lambda: catalogue, role=_ROLE, host_id=_HOST, authorization_run=_RUN
        )
    assert catalogue.rolled_back and catalogue.closed
    return refused.value.code


def test_the_lease_role_exactly_as_rendered_is_proven() -> None:
    catalogue = _Catalogue()
    check.prove_lease_role(
        lambda: catalogue, role=_ROLE, host_id=_HOST, authorization_run=_RUN
    )
    assert catalogue.rolled_back and catalogue.closed


@pytest.mark.parametrize("position", range(6))
def test_a_role_attribute_refuses(position: int) -> None:
    row = list(_GOOD_ROLE)
    row[position] = True
    assert _code(_Catalogue(ROLE=tuple(row))).startswith("lease-role-")


def test_a_connection_limit_above_two_refuses() -> None:
    row = list(_GOOD_ROLE)
    row[7] = 3
    assert _code(_Catalogue(ROLE=tuple(row))) == "lease-role-connection-limit"


def test_a_missing_or_loose_limit_refuses() -> None:
    for broken in (
        [c for c in _GOOD_CONFIG if not c.startswith("log_statement")],
        [c for c in _GOOD_CONFIG if not c.startswith("temp_file_limit")],
        [
            c.replace("30s", "120s") if c.startswith("statement") else c
            for c in _GOOD_CONFIG
        ],
    ):
        row = list(_GOOD_ROLE)
        row[10] = broken
        assert _code(_Catalogue(ROLE=tuple(row))).startswith("lease-role-")


def test_an_expiry_beyond_four_hours_refuses() -> None:
    row = list(_GOOD_ROLE)
    row[9] = 4 * 3600.0 + 1
    assert _code(_Catalogue(ROLE=tuple(row))) == "lease-role-expiry-bound"


def test_any_membership_refuses() -> None:
    assert _code(_Catalogue(MEMBERSHIP=1)) == "lease-role-membership"


def test_any_table_privilege_anywhere_refuses_even_a_select() -> None:
    rows = [("public", "unrelated", True, False, False, False, False, False, False)]
    assert _code(_Catalogue(TABLES=rows)) == "lease-role-table-privilege"
    # ...and a table privilege inside cp_lane3 is no more welcome: the functions
    # are the only door.
    rows = [("cp_lane3", "host_leases", False, False, False, False, False, False, True)]
    assert _code(_Catalogue(TABLES=rows)) == "lease-role-table-privilege"


def test_a_null_privilege_answer_counts_as_held() -> None:
    rows = [("public", "t", None, False, False, False, False, False, False)]
    assert _code(_Catalogue(TABLES=rows)) == "lease-role-table-privilege"


def test_any_column_or_sequence_privilege_refuses() -> None:
    column = [("cp_lane3", "host_leases", "lease_bytes", True, False, False, False)]
    assert _code(_Catalogue(COLUMNS=column)) == "lease-role-column-privilege"
    sequence = [("cp_lane3", "e10_receipts_seq_seq", True, False, False)]
    assert _code(_Catalogue(SEQUENCES=sequence)) == "lease-role-sequence-privilege"


def test_usage_on_any_other_schema_refuses() -> None:
    usage = [("cp_lane3",), ("public",), ("mod_deploy",)]
    assert _code(_Catalogue(SCHEMA_USAGE=usage)) == "lease-role-other-schema-usage"


def test_no_usage_on_the_lease_schema_refuses() -> None:
    assert _code(_Catalogue(SCHEMA_USAGE=[("public",)])) == "lease-role-no-schema-usage"


def test_the_executable_function_set_is_compared_exactly() -> None:
    full = [(_catalogue_spelling(s),) for s in spec.LEASE_FUNCTIONS]
    assert _code(_Catalogue(LEASE_EXECUTE=full[:-1])) == "lease-role-function-set"
    extra = [*full, ("store_now()",)]
    assert _code(_Catalogue(LEASE_EXECUTE=extra)) == "lease-role-function-set"


def test_an_executable_definer_function_elsewhere_refuses() -> None:
    assert _code(_Catalogue(DEFINERS_OUTSIDE=1)) == "lease-role-other-definer"


@pytest.mark.parametrize("answer", [False, None])
def test_a_role_that_cannot_connect_refuses_and_null_counts_as_not_connecting(
    answer: object,
) -> None:
    assert _code(_Catalogue(CONNECT=answer)) == "lease-role-cannot-connect"


def test_the_connect_check_asks_about_the_current_database_for_this_role() -> None:
    assert "has_database_privilege(:role, current_database(), 'CONNECT')" in (
        check._CONNECT_SQL
    )


def test_the_role_must_be_bound_to_this_host_and_run_and_no_other() -> None:
    assert _code(_Catalogue(BINDING=0)) == "lease-role-not-bound"
    assert _code(_Catalogue(OTHER_BINDINGS=1)) == "lease-role-bound-elsewhere"


def test_an_unreadable_or_invisible_role_is_unprovable_not_assumed_fine() -> None:
    assert _code(_Catalogue(ROLE=None)) == "lease-role-unverifiable"

    class _Broken(_Catalogue):
        def execute(self, statement: Any, params: Any = None) -> _Result:
            raise RuntimeError("password=hunter2")

    broken = _Broken()
    with pytest.raises(check.LeaseRoleRefused) as refused:
        check.prove_lease_role(
            lambda: broken, role=_ROLE, host_id=_HOST, authorization_run=_RUN
        )
    assert refused.value.code == "lease-role-unverifiable"
    assert "hunter2" not in str(refused.value)


def test_the_function_set_the_check_compares_is_the_one_the_spec_grants() -> None:
    granted = {s for s in spec.LEASE_FUNCTIONS}
    assert check._normalise("acquire(text, text)") == "acquire(text, text)"
    assert len(granted) == len(spec.LEASE_FUNCTIONS) == 8


def test_the_cli_refuses_without_a_dsn_and_never_echoes_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = check.main(
        ["--role", _ROLE, "--host-id", _HOST, "--authorization-run", _RUN],
        environ={},
    )
    assert code == 2
    assert check.ADMIN_DSN_ENV in capsys.readouterr().err


# ── the watchdog guards the lease role too ──────────────────────────────────


class _Conn:
    def __init__(self, executed: list[str]) -> None:
        self.executed = executed

    def exec_driver_sql(self, statement: str) -> Any:
        if statement.startswith("SET lock_timeout"):
            return _Result(None)
        self.executed.append(statement)
        return _Result((0, 0, 0))


class _Session:
    def __init__(self, executed: list[str]) -> None:
        self._conn = _Conn(executed)

    def connection(self) -> _Conn:
        return self._conn

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


def test_the_watchdog_revokes_a_lease_role_with_the_lease_statements() -> None:
    executed: list[str] = []
    counts = watchdog.revoke(lambda: _Session(executed), _ROLE, "lease")
    assert counts == (0, 0, 0)
    revocation, verification = spec.revocation_sql(_ROLE), spec.verification_sql(_ROLE)
    assert executed == [*revocation, verification]
    assert not any("DROP POLICY" in statement for statement in executed)


def test_the_default_watchdog_kind_is_still_the_consumption_role() -> None:
    executed: list[str] = []
    watchdog.revoke(lambda: _Session(executed), "run_consume")
    assert any("DROP POLICY" in statement for statement in executed)


def test_an_unknown_role_kind_refuses() -> None:
    with pytest.raises(ValueError):
        watchdog.revoke(lambda: _Session([]), _ROLE, "target")
    assert watchdog.KINDS == ("consumption", "lease")
