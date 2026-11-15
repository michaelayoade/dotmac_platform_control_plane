"""Scoped dispatch-consumption credential: static refusals and catalogue proof.

The proof's SQL runs for real in `conformance/test_host_admission_conformance.py`
(real PostgreSQL, real Control). Here a fake session answers each catalogue
question by identity of its SQL text, so every refusal branch is exercised.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from vendor_cp.deployment import consumption_role_spec as spec
from vendor_cp.deployment import consumption_scope as scope
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

_TLS = "sslmode=verify-full&sslrootcert=/etc/dotmac/ca.pem"
_SCOPED = (
    f"postgresql+psycopg://run_consume:pw-SECRET-MARKER@db.example.test:5432/cp?{_TLS}"
)


def _refusal(env: dict[str, str]) -> FoundationBindingsUnavailable:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        scope.scoped_consumption_dsn(env)
    assert "SECRET-MARKER" not in str(caught.value)
    assert "db.example.test" not in str(caught.value)
    return caught.value


def test_scoped_dsn_is_accepted_and_returned_unchanged() -> None:
    assert scope.scoped_consumption_dsn({scope.CONSUMPTION_DSN_ENV: _SCOPED}) == _SCOPED


def test_missing_scoped_dsn_is_a_typed_refusal_naming_the_variable() -> None:
    refused = _refusal({})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_MISSING
    assert scope.CONSUMPTION_DSN_ENV in str(refused)


@pytest.mark.parametrize("general", scope.GENERAL_DSN_ENVS)
def test_a_general_dsn_on_the_host_refuses_even_beside_a_scoped_one(
    general: str,
) -> None:
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: _SCOPED, general: _SCOPED})
    assert refused.code is TargetRefusal.GENERAL_DSN_PRESENT
    assert general in str(refused)


def test_an_owner_dsn_supplied_as_the_consumption_dsn_refuses() -> None:
    owner = f"postgresql+psycopg://vendor_cp_owner:pw@db.example.test/cp?{_TLS}"
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: owner})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED


@pytest.mark.parametrize(
    "role", ["postgres", "cp_admin", "vendor_cp_owner", "migrator", "root", "app"]
)
def test_privileged_looking_role_names_refuse(role: str) -> None:
    dsn = f"postgresql+psycopg://{role}:pw@db.example.test/cp?{_TLS}"
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: dsn})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED


@pytest.mark.parametrize("option", ["options", "role", "service", "passfile"])
def test_connection_options_that_change_role_or_load_credentials_refuse(
    option: str,
) -> None:
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: f"{_SCOPED}&{option}=x"})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED


@pytest.mark.parametrize(
    "query",
    [
        "",
        "sslmode=require&sslrootcert=/etc/dotmac/ca.pem",
        "sslmode=verify-ca&sslrootcert=/etc/dotmac/ca.pem",
        "sslmode=disable",
        "sslmode=verify-full",
        "sslmode=verify-full&sslrootcert=relative/ca.pem",
    ],
)
def test_tls_with_verification_and_a_pinned_ca_is_required(query: str) -> None:
    dsn = "postgresql+psycopg://run_consume:pw@db.example.test/cp"
    if query:
        dsn += "?" + query
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: dsn})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED


@pytest.mark.parametrize(
    "name",
    [
        "PGHOST",
        "PGUSER",
        "PGPASSWORD",
        "PGSERVICE",
        "PGOPTIONS",
        "PGSSLMODE",
        "PGPASSFILE",
        "PGSSLROOTCERT",
    ],
)
def test_libpq_environment_variables_refuse_by_name_only(name: str) -> None:
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: _SCOPED, name: "SECRET-MARKER"})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED
    assert name in str(refused)


@pytest.mark.parametrize(
    "dsn",
    [
        "not a url",
        "mysql://u:p@db.example.test/cp",
        f"postgresql+psycopg://db.example.test/cp?{_TLS}",
        f"postgresql+psycopg://u:p@db.example.test?{_TLS}",
        f"postgresql+psycopg://u:p@/cp?{_TLS}",
    ],
)
def test_malformed_scoped_dsn_refuses_without_echoing_it(dsn: str) -> None:
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: dsn})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_MALFORMED


# ── catalogue proof ─────────────────────────────────────────────────────────

_GOOD_CONFIG = [
    "statement_timeout=30s",
    "lock_timeout=5s",
    "idle_in_transaction_session_timeout=30s",
    "temp_file_limit=256MB",
    "log_statement=all",
]
_DISPATCH = "3f2b8c1e-1111-4222-8333-444455556666"
_SCOPE = f"'{scope.LEDGER_SCOPE}'"
_GOOD_POLICIES = [
    ("dotmac_ledger_unrestricted", "PERMISSIVE", ["public"], "ALL", "true", "true"),
    (
        "run_consume_insert",
        "RESTRICTIVE",
        ["run_consume"],
        "INSERT",
        None,
        f"((scope)::text = {_SCOPE}::text) AND ((\"key\")::text = '{_DISPATCH}'::text) "
        "AND (created_at = now()) AND (updated_at = now())",
    ),
    (
        "run_consume_select",
        "RESTRICTIVE",
        ["run_consume"],
        "SELECT",
        f"((scope)::text = {_SCOPE}::text) AND ((\"key\")::text = '{_DISPATCH}'::text)",
        None,
    ),
]
_GOOD_ROLE = (False,) * 6 + (True, 4, "t", 3600.0, _GOOD_CONFIG)


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def one_or_none(self) -> Any:
        return self._value

    def scalar(self) -> Any:
        return self._value

    def all(self) -> Any:
        return self._value


class _CatalogueSession:
    """Answers each catalogue question by identity of its SQL text."""

    def __init__(self, **answers: Any) -> None:
        self.answers = {
            scope._CURRENT_SQL: ("run_consume", "run_consume"),
            scope._ROLE_SQL: _GOOD_ROLE,
            scope._MEMBERSHIP_SQL: 0,
            scope._DATABASE_CREATE_SQL: False,
            scope._CREATE_SCHEMAS_SQL: 0,
            scope._OWNED_SQL: 0,
            scope._TABLES_SQL: [],
            scope._COLUMNS_SQL: [],
            scope._SEQUENCES_SQL: [],
            scope._FUNCTIONS_SQL: 0,
            scope._RLS_SQL: (True, False),
            scope._POLICIES_SQL: list(_GOOD_POLICIES),
        }
        self.answers.update({getattr(scope, f"_{k}"): v for k, v in answers.items()})
        self.params: list[Any] = []
        self.closed = False
        self.rolled_back = False

    def execute(self, statement: Any, params: Any = None) -> _Result:
        self.params.append(params)
        return _Result(self.answers[str(statement)])

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def _table(
    schema: str, name: str, *, select=False, insert=False, update=False, never=None
):  # noqa: ANN001, ANN202
    flags = never or (False, False, False, False)
    return (schema, name, select, insert, update, *flags)


def _column(
    schema: str,
    name: str,
    column: str,
    *,
    select=False,
    insert=False,
    update=False,
    references=False,
):  # noqa: ANN001, ANN202
    return (schema, name, column, select, insert, update, references)


def _proven(session: _CatalogueSession, **kwargs: Any) -> None:
    kwargs.setdefault("dispatch_id", _DISPATCH)
    scope.prove_scoped_role(lambda: session, **kwargs)  # type: ignore[arg-type,return-value]
    assert session.rolled_back and session.closed


def _code(session: _CatalogueSession, **kwargs: Any) -> TargetRefusal:
    kwargs.setdefault("dispatch_id", _DISPATCH)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        scope.prove_scoped_role(lambda: session, **kwargs)  # type: ignore[arg-type,return-value]
    assert session.rolled_back and session.closed
    return caught.value.code


_OVER = TargetRefusal.CONSUMPTION_ROLE_OVERBROAD

_LOCK = sorted(scope.LOCK_TABLES)[0]
_READ = sorted(scope.READ_ONLY_TABLES)[0]
_LEDGER = sorted(scope.LEDGER_TABLES)[0]


def _contract_tables() -> list[tuple]:
    rows = [_table(s, n, select=True) for s, n in sorted(scope.READ_ONLY_TABLES)]
    rows += [_table(s, n, select=True) for s, n in sorted(scope.LOCK_TABLES)]
    rows += [
        _table(s, n, select=True, insert=True) for s, n in sorted(scope.LEDGER_TABLES)
    ]
    rows.append(_table("public", "unrelated"))
    return rows


def _contract_columns() -> list[tuple]:
    return [
        _column(s, n, scope.LOCK_COLUMN, select=True, update=True)
        for s, n in sorted(scope.LOCK_TABLES)
    ]


def test_a_role_exactly_as_the_contract_is_proven() -> None:
    session = _CatalogueSession(
        TABLES_SQL=_contract_tables(), COLUMNS_SQL=_contract_columns()
    )
    _proven(session)
    assert all(p == {"role": "run_consume"} for p in session.params[1:])


def test_a_named_role_is_proven_from_any_connection() -> None:
    session = _CatalogueSession(CURRENT_SQL=("admin_reader", "admin_reader"))
    _proven(session, role="run_consume")
    assert all(p == {"role": "run_consume"} for p in session.params[1:])


def test_a_switched_session_role_refuses() -> None:
    assert _code(_CatalogueSession(CURRENT_SQL=("run_consume", "other"))) is _OVER


@pytest.mark.parametrize("attribute", range(6))
def test_a_role_attribute_refuses_including_inherit(attribute: int) -> None:
    flags = [False] * 6
    flags[attribute] = True
    role = (*flags, *_GOOD_ROLE[6:])
    assert _code(_CatalogueSession(ROLE_SQL=role)) is _OVER


def test_a_role_that_cannot_log_in_is_not_the_credential() -> None:
    role = (*_GOOD_ROLE[:6], False, *_GOOD_ROLE[7:])
    assert _code(_CatalogueSession(ROLE_SQL=role)) is _OVER


@pytest.mark.parametrize("memberships", [1, 3])
def test_any_role_membership_refuses_whatever_inherit_says(memberships: int) -> None:
    assert _code(_CatalogueSession(MEMBERSHIP_SQL=memberships)) is _OVER


@pytest.mark.parametrize("ttl", [None, 0.0, -5.0, 4 * 3600.0 + 1, 12 * 3600.0])
def test_a_missing_or_unbounded_expiry_refuses_beyond_four_hours(
    ttl: float | None,
) -> None:
    valid_until = None if ttl is None else "t"
    role = (*_GOOD_ROLE[:8], valid_until, ttl, _GOOD_CONFIG)
    assert _code(_CatalogueSession(ROLE_SQL=role)) is _OVER


def test_four_hours_exactly_is_accepted() -> None:
    role = (*_GOOD_ROLE[:8], "t", 4 * 3600.0, _GOOD_CONFIG)
    _proven(_CatalogueSession(ROLE_SQL=role))


@pytest.mark.parametrize("limit", [-1, 0, 5, 100, None])
def test_the_connection_limit_must_be_bounded(limit: object) -> None:
    role = (*_GOOD_ROLE[:7], limit, *_GOOD_ROLE[8:])
    assert _code(_CatalogueSession(ROLE_SQL=role)) is _OVER


@pytest.mark.parametrize(
    "config",
    [
        None,
        [],
        [c for c in _GOOD_CONFIG if not c.startswith("log_statement")],
        [c for c in _GOOD_CONFIG if not c.startswith("temp_file_limit")],
        [
            "temp_file_limit=257MB" if c.startswith("temp_file") else c
            for c in _GOOD_CONFIG
        ],
        [
            "temp_file_limit=-1" if c.startswith("temp_file") else c
            for c in _GOOD_CONFIG
        ],
        ["log_statement=ddl" if c.startswith("log_") else c for c in _GOOD_CONFIG],
        [c for c in _GOOD_CONFIG if not c.startswith("statement_timeout")],
        ["statement_timeout=0", *_GOOD_CONFIG[1:]],
        ["statement_timeout=61s", *_GOOD_CONFIG[1:]],
        [_GOOD_CONFIG[0], "lock_timeout=11s", *_GOOD_CONFIG[2:]],
        [
            *_GOOD_CONFIG[:2],
            "idle_in_transaction_session_timeout=2min",
            _GOOD_CONFIG[3],
        ],
        ["statement_timeout=abc", *_GOOD_CONFIG[1:]],
    ],
)
def test_missing_or_loose_timeouts_and_logging_refuse(config: Any) -> None:
    role = (*_GOOD_ROLE[:9], 3600.0, config)
    assert _code(_CatalogueSession(ROLE_SQL=role)) is _OVER


def test_tighter_limits_and_other_duration_spellings_are_accepted() -> None:
    config = [
        "statement_timeout=45000",
        "lock_timeout=1500ms",
        "idle_in_transaction_session_timeout=1min",
        "temp_file_limit=100000",
        "log_statement=all",
    ]
    _proven(_CatalogueSession(ROLE_SQL=(*_GOOD_ROLE[:10], config)))


def test_database_create_refuses() -> None:
    assert _code(_CatalogueSession(DATABASE_CREATE_SQL=True)) is _OVER


def test_create_in_a_schema_refuses() -> None:
    assert _code(_CatalogueSession(CREATE_SCHEMAS_SQL=1)) is _OVER


def test_owning_an_object_refuses() -> None:
    assert _code(_CatalogueSession(OWNED_SQL=2)) is _OVER


def test_an_executable_security_definer_function_refuses() -> None:
    assert _code(_CatalogueSession(FUNCTIONS_SQL=1)) is _OVER


@pytest.mark.parametrize(
    "held", [(True, False, False), (False, True, False), (False, False, True)]
)
def test_any_sequence_privilege_refuses(held: tuple[bool, bool, bool]) -> None:
    row = ("public", "some_seq", *held)
    assert _code(_CatalogueSession(SEQUENCES_SQL=[row])) is _OVER


@pytest.mark.parametrize("position", range(4))
def test_never_granted_privileges_refuse_on_any_table(position: int) -> None:
    never = [False] * 4
    never[position] = True
    rows = [_table(*_READ, select=True, never=tuple(never))]
    assert _code(_CatalogueSession(TABLES_SQL=rows)) is _OVER


@pytest.mark.parametrize(
    "row",
    [
        _table("public", "customers", select=True),
        _table(*_READ, select=True, insert=True),
        _table(*_READ, select=True, update=True),
        _table(*_LOCK, select=True, update=True),
        _table(*_LEDGER, select=True, insert=True, update=True),
        _table(*_LEDGER, select=True, never=(1,) * 4),
        # Same table name in a different schema is a different table.
        ("public", _READ[1], True, False, False, False, False, False, False),
        ("other", _LEDGER[1], True, True, False, False, False, False, False),
    ],
)
def test_privileges_beyond_the_contract_refuse_schema_qualified(row: tuple) -> None:
    assert _code(_CatalogueSession(TABLES_SQL=[row])) is _OVER


@pytest.mark.parametrize(
    "row",
    [
        _column("public", "customers", "email", select=True),
        _column(*_READ, "x", update=True),
        _column(*_READ, "x", insert=True),
        _column(*_READ, "x", references=True),
        _column(*_LOCK, "public_key_b64", update=True),
        _column(*_LEDGER, "result", update=True),
        _column("other", _LEDGER[1], "x", insert=True),
    ],
)
def test_column_level_grants_beyond_the_contract_refuse(row: tuple) -> None:
    assert _code(_CatalogueSession(COLUMNS_SQL=[row])) is _OVER


def test_a_lock_table_may_update_updated_at_and_only_that() -> None:
    both = [
        _column(*_LOCK, scope.LOCK_COLUMN, update=True),
        _column(*_LOCK, "status", update=True),
    ]
    assert _code(_CatalogueSession(COLUMNS_SQL=both)) is _OVER
    _proven(
        _CatalogueSession(COLUMNS_SQL=[_column(*_LOCK, scope.LOCK_COLUMN, update=True)])
    )


def test_a_null_privilege_answer_counts_as_held() -> None:
    rows = [("mod_deploy", "customers", None, False, False, False, False, False, False)]
    assert _code(_CatalogueSession(TABLES_SQL=rows)) is _OVER


def test_an_unreadable_or_invisible_role_is_unprovable_not_assumed_fine() -> None:
    class _Broken(_CatalogueSession):
        def execute(self, statement: Any, params: Any = None) -> _Result:
            raise RuntimeError("SECRET-MARKER")

    assert _code(_Broken()) is TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE
    assert (
        _code(_CatalogueSession(ROLE_SQL=None))
        is TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE
    )


def test_refusal_does_not_chain_the_database_error() -> None:
    class _Broken(_CatalogueSession):
        def execute(self, statement: Any, params: Any = None) -> _Result:
            raise RuntimeError("SECRET-MARKER")

    with pytest.raises(FoundationBindingsUnavailable) as caught:
        scope.prove_scoped_role(lambda: _Broken(), dispatch_id=_DISPATCH)  # type: ignore[arg-type,return-value]
    assert caught.value.__cause__ is None
    assert "SECRET-MARKER" not in str(caught.value)


# ── the documented, rendered and enforced grants are one thing ──────────────

_DOC = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "design"
    / "scoped-consumption-role.md"
)


def test_the_grants_document_names_exactly_the_enforced_tables() -> None:
    doc = _DOC.read_text(encoding="utf-8")
    enforced = scope.READ_ONLY_TABLES | scope.LOCK_TABLES | scope.LEDGER_TABLES
    for schema, table in enforced:
        assert f"`{table}`" in doc, table
        assert f"{schema}.{table}" in doc, table
    assert not scope.READ_ONLY_TABLES & scope.LOCK_TABLES
    assert not (scope.READ_ONLY_TABLES | scope.LOCK_TABLES) & scope.LEDGER_TABLES
    assert "TODO(before D3)" in doc


def test_the_document_embeds_the_rendered_sql_verbatim() -> None:
    doc = _DOC.read_text(encoding="utf-8")
    statements = (
        *spec.creation_sql(spec.ROLE_PLACEHOLDER),
        *spec.revocation_sql(spec.ROLE_PLACEHOLDER),
        *spec.guard_enable_sql(),
        *spec.guard_disable_sql(),
        spec.verification_sql(spec.ROLE_PLACEHOLDER),
    )
    for statement in statements:
        assert statement in doc, statement
    assert "4 hours" in doc and str(scope.CONNECTION_LIMIT) in doc


def test_the_rendered_sql_grants_exactly_the_contract_and_nothing_wider() -> None:
    sql = "\n".join(spec.creation_sql("run_consume"))
    assert "CONNECTION LIMIT 4" in sql
    assert "NOINHERIT" in sql and "NOSUPERUSER" in sql and "NOCREATEROLE" in sql
    assert f"statement_timeout = '{scope.STATEMENT_TIMEOUT}'" in sql
    assert "log_statement = 'all'" in sql
    for schema, table in scope.LOCK_TABLES:
        assert f"{schema}.{table}" in sql
    assert f"GRANT UPDATE ({scope.LOCK_COLUMN}) ON" in sql
    assert "GRANT INSERT ON public.platform_idempotency_records" in sql
    # No table-level UPDATE/DELETE/TRUNCATE/ALL anywhere, no admin option.
    for forbidden in (
        "GRANT UPDATE ON",
        "DELETE",
        "TRUNCATE",
        "ALL PRIVILEGES",
        "ADMIN OPTION",
        "GRANT ALL",
    ):
        assert forbidden not in sql


# ── ledger row level security (the per-run guard) ───────────────────────────


def _policies(**changes: Any) -> list[tuple]:
    rows = [list(row) for row in _GOOD_POLICIES]
    for index, value in changes.items():
        row_index, column = index.split("_", 1)
        rows[int(row_index)][int(column)] = value
    return [tuple(row) for row in rows]


@pytest.mark.parametrize("rls", [None, (False, False), (True, True), (None, False)])
def test_rls_must_be_enabled_without_force(rls: Any) -> None:
    assert _code(_CatalogueSession(RLS_SQL=rls)) is _OVER


@pytest.mark.parametrize(
    "policies",
    [
        [],
        _GOOD_POLICIES[1:],
        [_GOOD_POLICIES[0], _GOOD_POLICIES[1]],
        [_GOOD_POLICIES[0], _GOOD_POLICIES[2]],
        [
            *_GOOD_POLICIES,
            ("extra_public", "PERMISSIVE", ["public"], "ALL", "true", "true"),
        ],
        _policies(**{"0_1": "RESTRICTIVE"}),
        _policies(**{"0_4": "(scope IS NOT NULL)"}),
        _policies(**{"0_5": "false"}),
        _policies(**{"0_3": "SELECT"}),
        _policies(**{"1_1": "PERMISSIVE"}),
        _policies(**{"1_2": ["run_consume", "other_role"]}),
        _policies(**{"2_1": "PERMISSIVE"}),
        [
            *_GOOD_POLICIES,
            ("another", "PERMISSIVE", ["run_consume"], "UPDATE", "true", "true"),
        ],
        _policies(**{"2_2": "nonsense"}),
    ],
)
def test_the_ledger_policies_must_be_exactly_the_contract(
    policies: list[tuple],
) -> None:
    assert _code(_CatalogueSession(POLICIES_SQL=policies)) is _OVER


def test_policies_are_bound_to_the_scope_and_the_dispatch_being_consumed() -> None:
    other = "99999999-9999-4999-8999-999999999999"
    assert _code(_CatalogueSession(), dispatch_id=other) is _OVER
    wrong_scope = _policies(
        **{
            "2_4": "(scope = 'something.else') AND "
            f"((\"key\")::text = '{_DISPATCH}'::text)"
        }
    )
    assert _code(_CatalogueSession(POLICIES_SQL=wrong_scope)) is _OVER
    backdatable = _policies(
        **{
            "1_5": f"((scope)::text = {_SCOPE}::text) AND "
            f"((\"key\")::text = '{_DISPATCH}'::text)"
        }
    )
    assert _code(_CatalogueSession(POLICIES_SQL=backdatable)) is _OVER


def test_other_roles_restrictive_policies_do_not_disturb_this_roles_proof() -> None:
    others = [
        ("o_insert", "RESTRICTIVE", ["other_run"], "INSERT", None, "(false)"),
        ("o_select", "RESTRICTIVE", ["other_run"], "SELECT", "(false)", None),
    ]
    _proven(_CatalogueSession(POLICIES_SQL=[*_GOOD_POLICIES, *others]))


def test_array_literal_roles_are_understood_and_a_non_uuid_dispatch_is_unprovable() -> (
    None
):
    as_text = [
        (n, k, "{" + ",".join(r) + "}", c, q, w) for n, k, r, c, q, w in _GOOD_POLICIES
    ]
    _proven(_CatalogueSession(POLICIES_SQL=as_text))
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        scope.prove_scoped_role(lambda: _CatalogueSession(), dispatch_id="not-a-uuid")
    assert caught.value.code is TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE
