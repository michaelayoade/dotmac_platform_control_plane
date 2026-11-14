"""Scoped dispatch-consumption credential: static refusals and catalogue proof."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from vendor_cp.deployment import consumption_scope as scope
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

_SCOPED = "postgresql+psycopg://run_consume:pw-SECRET-MARKER@db.example.test:5432/cp"


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
    owner = "postgresql+psycopg://vendor_cp_owner:pw@db.example.test/cp"
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: owner})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED


@pytest.mark.parametrize(
    "role", ["postgres", "cp_admin", "vendor_cp_owner", "migrator", "root", "app"]
)
def test_privileged_looking_role_names_refuse(role: str) -> None:
    dsn = f"postgresql+psycopg://{role}:pw@db.example.test/cp"
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: dsn})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED


@pytest.mark.parametrize("option", ["options", "role", "service", "passfile"])
def test_connection_options_that_change_role_or_load_credentials_refuse(
    option: str,
) -> None:
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: f"{_SCOPED}?{option}=x"})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED


@pytest.mark.parametrize(
    "dsn",
    [
        "not a url",
        "mysql://u:p@db.example.test/cp",
        "postgresql+psycopg://db.example.test/cp",
        "postgresql+psycopg://u:p@db.example.test",
        "postgresql+psycopg://u:p@/cp",
    ],
)
def test_malformed_scoped_dsn_refuses_without_echoing_it(dsn: str) -> None:
    refused = _refusal({scope.CONSUMPTION_DSN_ENV: dsn})
    assert refused.code is TargetRefusal.CONSUMPTION_DSN_MALFORMED


# ── catalogue proof ─────────────────────────────────────────────────────────


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
            scope._ROLE_SQL: (False, False, False, False, False, "t", 3600.0),
            scope._CREATE_SCHEMAS_SQL: 0,
            scope._OWNED_SQL: 0,
            scope._PRIVILEGES_SQL: [],
        }
        self.answers.update({getattr(scope, f"_{k}"): v for k, v in answers.items()})
        self.closed = False
        self.rolled_back = False

    def execute(self, statement: Any) -> _Result:
        return _Result(self.answers[str(statement)])

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def _row(name: str, *, select=False, insert=False, update=False, never=None) -> tuple:
    flags = never or (False, False, False, False)
    return ("mod_deploy", name, select, insert, update, *flags)


def _prove(session: _CatalogueSession) -> None:
    scope.prove_scoped_role(lambda: session)  # type: ignore[arg-type,return-value]
    assert session.rolled_back and session.closed


def _refused_code(session: _CatalogueSession) -> TargetRefusal:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        scope.prove_scoped_role(lambda: session)  # type: ignore[arg-type,return-value]
    assert session.rolled_back and session.closed
    return caught.value.code


def test_a_narrow_role_is_proven() -> None:
    _prove(
        _CatalogueSession(
            PRIVILEGES_SQL=[
                _row("target_current_hosts", select=True),
                _row("rollouts", select=True, update=True),
                _row(
                    "platform_idempotency_records",
                    select=True,
                    insert=True,
                    update=True,
                ),
                _row("unrelated_table"),
            ]
        )
    )


@pytest.mark.parametrize("attribute", range(5))
def test_a_role_attribute_refuses(attribute: int) -> None:
    flags = [False] * 5
    flags[attribute] = True
    session = _CatalogueSession(ROLE_SQL=(*flags, "t", 3600.0))
    assert _refused_code(session) is TargetRefusal.CONSUMPTION_ROLE_OVERBROAD


@pytest.mark.parametrize("ttl", [None, 0.0, -5.0, 13 * 3600.0])
def test_a_missing_or_unbounded_expiry_refuses(ttl: float | None) -> None:
    valid_until = None if ttl is None else "t"
    session = _CatalogueSession(
        ROLE_SQL=(False, False, False, False, False, valid_until, ttl)
    )
    assert _refused_code(session) is TargetRefusal.CONSUMPTION_ROLE_OVERBROAD


def test_create_in_a_schema_refuses() -> None:
    assert (
        _refused_code(_CatalogueSession(CREATE_SCHEMAS_SQL=1))
        is TargetRefusal.CONSUMPTION_ROLE_OVERBROAD
    )


def test_owning_a_relation_refuses() -> None:
    assert (
        _refused_code(_CatalogueSession(OWNED_SQL=2))
        is TargetRefusal.CONSUMPTION_ROLE_OVERBROAD
    )


@pytest.mark.parametrize("position", range(4))
def test_never_granted_privileges_refuse_on_any_table(position: int) -> None:
    never = [False] * 4
    never[position] = True
    session = _CatalogueSession(
        PRIVILEGES_SQL=[_row("rollouts", select=True, never=tuple(never))]
    )
    assert _refused_code(session) is TargetRefusal.CONSUMPTION_ROLE_OVERBROAD


@pytest.mark.parametrize(
    "row",
    [
        _row("customers", select=True),
        _row("target_current_hosts", select=True, insert=True),
        _row("target_current_hosts", select=True, update=True),
        _row("rollouts", select=True, insert=True),
        _row("platform_idempotency_records", select=True, insert=True, never=(1,) * 4),
    ],
)
def test_privileges_beyond_the_contract_refuse(row: tuple) -> None:
    session = _CatalogueSession(PRIVILEGES_SQL=[row])
    assert _refused_code(session) is TargetRefusal.CONSUMPTION_ROLE_OVERBROAD


def test_an_unreadable_or_invisible_role_is_unprovable_not_assumed_fine() -> None:
    class _Broken(_CatalogueSession):
        def execute(self, statement: Any) -> _Result:
            raise RuntimeError("SECRET-MARKER")

    assert _refused_code(_Broken()) is TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE
    assert (
        _refused_code(_CatalogueSession(ROLE_SQL=None))
        is TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE
    )


def test_refusal_does_not_chain_the_database_error() -> None:
    class _Broken(_CatalogueSession):
        def execute(self, statement: Any) -> _Result:
            raise RuntimeError("SECRET-MARKER")

    with pytest.raises(FoundationBindingsUnavailable) as caught:
        scope.prove_scoped_role(lambda: _Broken())  # type: ignore[arg-type,return-value]
    assert caught.value.__cause__ is None
    assert "SECRET-MARKER" not in str(caught.value)


# ── the documented grants are the enforced grants ───────────────────────────


def test_the_grants_document_names_exactly_the_enforced_tables() -> None:
    doc = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "design"
        / "scoped-consumption-role.md"
    ).read_text(encoding="utf-8")
    enforced = scope.READ_ONLY_TABLES | scope.LOCK_ONLY_TABLES | scope.WRITE_TABLES
    for table in enforced:
        assert f"`{table}`" in doc, table
        assert f".{table}" in doc, table
    # No table appears in two privilege classes.
    assert not scope.READ_ONLY_TABLES & scope.LOCK_ONLY_TABLES
    assert not (scope.READ_ONLY_TABLES | scope.LOCK_ONLY_TABLES) & scope.WRITE_TABLES
    assert "NOT executed" in doc.replace("NOT EXECUTED", "NOT executed")
    assert "CREATE ROLE" in doc and "DROP ROLE" in doc
    assert "TODO(before D3)" in doc
