"""Hosted source vectors: fixed accessor identity, lazy refusal and SQL cleanup."""

from __future__ import annotations

import ast
import importlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vendor_cp.deployment.gate0_database import (
    DatabaseExpectation,
    DatabaseQualification,
    qualify_authority_database,
)
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


def expectation() -> DatabaseExpectation:
    return DatabaseExpectation(
        database="authority",
        role="platform_api",
        server_address="192.0.2.1",
        server_port=5432,
        tls=True,
        schemas=("public", "mod_deploy"),
        image_heads=("kernel_100", "v030"),
        descriptor_heads=("v030", "kernel_100"),
        source_revision="a" * 40,
        expected_source_revision="a" * 40,
        statement_timeout_ms=1000,
        lock_timeout_ms=500,
    )


def measured_session(*, identity=None, role=None, schemas=None, heads=None):
    session = Mock()
    responses = [
        Mock(),
        Mock(),
        Mock(
            one=Mock(
                return_value=identity
                or (
                    "authority",
                    "platform_api",
                    "192.0.2.1",
                    5432,
                    True,
                )
            )
        ),
        Mock(one=Mock(return_value=role or (False, False, False, False, False, True))),
        Mock(scalars=Mock(return_value=schemas or ("public", "mod_deploy"))),
        Mock(scalars=Mock(return_value=heads or ("v030", "kernel_100"))),
    ]
    session.execute.side_effect = responses
    return session


def install_runtime(monkeypatch, session):
    from vendor_cp.relay import runner

    runtime = SimpleNamespace(platform_session_factory=Mock(return_value=session))
    accessor = Mock(return_value=runtime)
    monkeypatch.setattr(runner, "authority_database_runtime", accessor)
    return runtime, accessor


def test_success_retains_runtime_and_rolls_back_read_only_measurement(monkeypatch):
    session = measured_session()
    runtime, accessor = install_runtime(monkeypatch, session)
    qualified = qualify_authority_database(expectation())
    assert qualified.runtime is runtime
    qualified.require_runtime(runtime)
    with pytest.raises(ProviderRefused):
        qualified.require_runtime(object())
    accessor.assert_called_once_with()
    runtime.platform_session_factory.assert_called_once_with()
    statements = [str(call.args[0]) for call in session.execute.call_args_list]
    assert statements[0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
    assert "set_config('statement_timeout'" in statements[1]
    assert "host(inet_server_addr())" in statements[2]
    assert "inet_server_addr()::text" not in statements[2]
    assert all(s.startswith("SELECT") for s in statements[1:])
    assert session.execute.call_args_list[1].args[1] == {
        "statement": "1000",
        "lock": "500",
    }
    session.commit.assert_not_called()
    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


@pytest.mark.parametrize(
    "changes",
    [
        {"database": ""},
        {"role": "bad;role"},
        {"server_address": "hostname"},
        {"server_address": "192.0.2.1/32"},
        {"server_address": "2001:db8::1/128"},
        {"server_port": True},
        {"tls": 1},
        {"schemas": ()},
        {"schemas": ("public", "pg_catalog")},
        {"image_heads": ()},
        {"descriptor_heads": ("wrong",)},
        {"expected_source_revision": "b" * 40},
        {"statement_timeout_ms": 0},
        {"statement_timeout_ms": 2001},
        {"lock_timeout_ms": 1001},
    ],
)
def test_missing_or_malformed_bounds_refuse_before_runtime(monkeypatch, changes):
    runtime, accessor = install_runtime(monkeypatch, measured_session())
    with pytest.raises(ProviderRefused):
        qualify_authority_database(replace(expectation(), **changes))
    accessor.assert_not_called()
    runtime.platform_session_factory.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"identity": ("wrong", "platform_api", "192.0.2.1", 5432, True)},
        {"identity": ("authority", "wrong", "192.0.2.1", 5432, True)},
        {"identity": ("authority", "platform_api", "192.0.2.2", 5432, True)},
        {"identity": ("authority", "platform_api", "192.0.2.1", 5432, False)},
        {"role": (True, False, False, False, False, True)},
        {"schemas": ("public",)},
        {"schemas": ("public", "mod_deploy", "extra")},
        {"heads": ("wrong",)},
        {"heads": ("v030", "kernel_100", "extra")},
    ],
)
def test_measured_mismatch_refuses_and_closes(monkeypatch, changes):
    session = measured_session(**changes)
    install_runtime(monkeypatch, session)
    with pytest.raises(ProviderRefused):
        qualify_authority_database(expectation())
    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()
    session.commit.assert_not_called()


def test_sql_error_is_sanitized_and_session_closed(monkeypatch):
    session = measured_session()
    session.execute.side_effect = RuntimeError("synthetic-sensitive-database-detail")
    install_runtime(monkeypatch, session)
    with pytest.raises(ProviderRefused) as refusal:
        qualify_authority_database(expectation())
    assert "synthetic-sensitive" not in str(refusal.value)
    assert refusal.value.__suppress_context__
    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_public_boolean_and_unmeasured_result_are_not_qualification():
    with pytest.raises(ProviderRefused):
        qualify_authority_database({"database_qualified": True})
    with pytest.raises(ProviderRefused):
        DatabaseQualification(object(), expectation())


def test_invalid_expectation_never_imports_runtime_accessor(monkeypatch):
    import builtins

    original = builtins.__import__
    attempted = []

    def no_runtime_import(name, *args, **kwargs):
        if name == "vendor_cp.relay.runner":
            attempted.append(name)
            raise AssertionError("invalid inputs reached runtime import")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_runtime_import)
    with pytest.raises(ProviderRefused):
        qualify_authority_database(replace(expectation(), statement_timeout_ms=0))
    assert attempted == []


def test_session_acquisition_failure_is_sanitized_without_retry(monkeypatch):
    runtime, accessor = install_runtime(monkeypatch, measured_session())
    runtime.platform_session_factory.side_effect = RuntimeError("sensitive-detail")
    with pytest.raises(ProviderRefused) as refusal:
        qualify_authority_database(expectation())
    assert "sensitive-detail" not in str(refusal.value)
    assert refusal.value.__suppress_context__
    accessor.assert_called_once_with()
    runtime.platform_session_factory.assert_called_once_with()


def test_accessor_returns_actual_configured_singleton_without_dispatcher(monkeypatch):
    from vendor_cp.relay import runner

    configured = importlib.import_module("dotmac_kernel.db").runtime
    monkeypatch.setattr(runner, "dispatcher_runtime", Mock(side_effect=AssertionError))
    monkeypatch.setattr(configured.engine, "connect", Mock(side_effect=AssertionError))
    monkeypatch.setattr(
        configured.platform_engine, "connect", Mock(side_effect=AssertionError)
    )
    monkeypatch.setattr(
        type(configured),
        "platform_session_factory",
        property(
            lambda self: (_ for _ in ()).throw(
                AssertionError("session factory accessed")
            )
        ),
    )
    assert runner.authority_database_runtime() is configured
    assert runner.authority_database_runtime() is configured


def test_composed_keeps_accessor_delivery_and_separate_dispatcher(monkeypatch):
    from vendor_cp.config import vendor_settings
    from vendor_cp.relay import runner

    delivery = object()
    dispatcher = object()
    monkeypatch.setattr(
        runner,
        "authority_database_runtime",
        Mock(return_value=SimpleNamespace(platform_session_factory=delivery)),
    )
    construct = Mock(return_value=SimpleNamespace(platform_session_factory=dispatcher))
    monkeypatch.setattr(runner, "dispatcher_runtime", construct)
    result = runner.composed(
        replace(vendor_settings, relay_dispatcher_database_url="synthetic")
    )
    assert result.delivery_sessions is delivery
    assert result.dispatcher_sessions is dispatcher
    construct.assert_called_once_with("synthetic")


def test_configured_import_remains_in_existing_relay_accessor_only():
    root = Path(__file__).resolve().parents[2] / "src/vendor_cp"
    relay = ast.parse((root / "relay/runner.py").read_text())
    accessor = next(
        n
        for n in relay.body
        if isinstance(n, ast.FunctionDef) and n.name == "authority_database_runtime"
    )
    configured_imports = [
        n
        for n in ast.walk(relay)
        if isinstance(n, ast.ImportFrom) and n.module == "dotmac_kernel.db"
    ]
    assert len(configured_imports) == 1
    assert configured_imports[0] in list(ast.walk(accessor))
    assert [a.name for a in configured_imports[0].names] == ["runtime"]
    qualifier = ast.parse((root / "deployment/gate0_database.py").read_text())
    assert not any(
        isinstance(n, ast.ImportFrom) and n.module == "dotmac_kernel.db"
        for n in ast.walk(qualifier)
    )
