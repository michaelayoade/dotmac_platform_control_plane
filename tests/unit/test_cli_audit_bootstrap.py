"""Fresh-process proofs: the service fixture must not bootstrap operator tests."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest


def _fresh(
    code: str, *, database: str = "configured"
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if database != "configured":
        for name in ("DATABASE_URL", "PLATFORM_DATABASE_URL"):
            env.pop(name, None)
            if database == "poisoned":
                env[name] = "not-a-database-url"
        env["VENDOR_PROVIDER_MODE"] = "invalid-safe-path-canary"
    code = textwrap.dedent(code)
    compile(code, "<fresh-cli-bootstrap>", "exec")
    result = subprocess.run(  # noqa: S603 -- fixed interpreter, authored test code
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result


_REGISTER = repr(
    [
        "deployment",
        "register-target",
        "--command-id",
        "audit-bootstrap-canary",
        "--target-ref",
        "canary",
        "--subject-ref",
        "canary",
        "--product-code",
        "canary",
        "--environment",
        "test",
    ]
)


def test_cli_installs_all_composed_actions_before_opening_session() -> None:
    _fresh(
        f"""
        from contextlib import contextmanager
        from dotmac_kernel.audit_actions import (
            AuditActionsNotInstalledError, UndeclaredAuditActionError,
            active_audit_actions,
        )
        try:
            active_audit_actions()
        except AuditActionsNotInstalledError:
            pass
        else:
            raise AssertionError('fixture leaked into fresh process')

        from vendor_cp import composition
        from vendor_cp.cli import commands, main
        from vendor_cp.cli.io import Result
        from vendor_cp.cli.runtime import platform_db
        from dotmac_kernel import db as kernel_db
        from dotmac_kernel.audit import write_platform_audit_event

        class Session:
            def __init__(self):
                self.events = []
            def add(self, event):
                self.events.append(event)
            def flush(self):
                pass

        @contextmanager
        def session():
            expected = {{action for manifest in composition.COMPOSED_DECLARATIONS
                        for action in manifest.audit_actions}}
            registry = active_audit_actions()
            assert registry.actions() == expected
            yield Session()
        kernel_db.platform_session = session

        def mutate(args):
            with platform_db() as db:
                registry = active_audit_actions()
                control = next(manifest for manifest in composition.STATEFUL_MODULES
                               if manifest.name == 'deployment_control')
                action = next(iter(control.audit_actions))
                assert registry.owner(action) == control.name
                write_platform_audit_event(db, actor_admin_id=None, action=action,
                                           entity_type='bootstrap_canary')
                assert len(db.events) == 1
                try:
                    write_platform_audit_event(
                        db, actor_admin_id=None, action='canary.undeclared',
                        entity_type='bootstrap_canary')
                except UndeclaredAuditActionError:
                    pass
                else:
                    raise AssertionError('unknown audit action was accepted')
                assert len(db.events) == 1
            return Result(command=args.command)

        commands.deployment_register_target = mutate
        assert main({_REGISTER}) == 0
        """
    )


@pytest.mark.parametrize("failure", ["install", "import"])
def test_bootstrap_failure_is_sanitized_before_session_side_effects(
    failure: str,
) -> None:
    result = _fresh(
        f"""
        import builtins
        import sys
        from vendor_cp.cli import commands, main
        from vendor_cp.cli.runtime import platform_db
        called = []
        def broken():
            raise RuntimeError('synthetic-bootstrap-secret-canary')
        if {failure!r} == 'install':
            from vendor_cp import composition
            composition.install_process_audit_actions = broken
        else:
            original_import = builtins.__import__
            def import_module(name, *args, **kwargs):
                if name == 'vendor_cp.composition':
                    broken()
                return original_import(name, *args, **kwargs)
            builtins.__import__ = import_module
        def mutate(args):
            with platform_db():
                called.append('owner')
        commands.deployment_register_target = mutate
        assert main(['--format', 'json'] + {_REGISTER}) == 5
        assert called == []
        assert 'dotmac_kernel.db' not in sys.modules
        """,
        database="absent",
    )
    assert '"refusal_code": "execution.failed"' in result.stdout
    assert "the process audit vocabulary could not be installed" in result.stdout
    assert "synthetic-bootstrap-secret-canary" not in result.stdout + result.stderr
    assert result.stderr == ""


@pytest.mark.parametrize(
    "argv",
    [
        ["--help"],
        ["deployment", "register-target", "--help"],
        ["diagnose", "version"],
        ["diagnose", "owners"],
    ],
)
def test_safe_cli_paths_need_no_database_or_runtime_configuration(
    argv: list[str],
) -> None:
    _fresh(
        f"""
        import sys
        from vendor_cp.cli import main
        try:
            status = main({argv!r})
        except SystemExit as result:
            status = result.code
        assert status == 0
        assert 'vendor_cp.assembly' not in sys.modules
        assert 'vendor_cp.main' not in sys.modules
        assert 'dotmac_kernel.db' not in sys.modules
        """,
        database="absent",
    )


@pytest.mark.parametrize("database", ["absent", "poisoned"])
def test_producer_bootstrap_uses_no_os_database_or_vendor_runtime(
    database: str,
) -> None:
    _fresh(
        """
        import os
        import sys
        from dotmac_kernel.audit_actions import active_audit_actions
        from vendor_cp.deployment import materials_producer as producer
        argv = ['propose', '--command-id', 'canary', '--target-id',
                '00000000-0000-0000-0000-000000000001', '--operation', 'deploy',
                '--descriptor-digest', 'd', '--execution-plan-digest', 'e',
                '--approval-policy-code', 'p', '--approval-policy-version', '1']
        explicit = {'DATABASE_URL': 'explicit-input', 'PLATFORM_DATABASE_URL': 'input'}
        before = dict(os.environ)
        called = []
        def session(env):
            from vendor_cp import composition
            expected = {action for manifest in composition.COMPOSED_DECLARATIONS
                        for action in manifest.audit_actions}
            assert active_audit_actions().actions() == expected
            assert env is explicit
            called.append('session')
            raise ValueError('stop before real database')
        producer._controller_session = session
        assert producer.main(argv, explicit) == 2
        assert called == ['session']
        assert dict(os.environ) == before
        assert 'vendor_cp.assembly' not in sys.modules
        assert 'vendor_cp.config' not in sys.modules
        assert 'dotmac_kernel.db' not in sys.modules
        assert not any(name.startswith('vendor_cp.') and
                       (name.endswith('.router') or name.endswith('.web'))
                       for name in sys.modules)
        """,
        database=database,
    )


def test_producer_bootstrap_failure_precedes_custody_and_session() -> None:
    result = _fresh(
        """
        import sys
        from vendor_cp import composition
        from vendor_cp.deployment import materials_producer as producer
        def broken():
            raise RuntimeError('synthetic-producer-secret-canary')
        composition.install_process_audit_actions = broken
        def session(env):
            raise AssertionError('session must not be opened')
        producer._controller_session = session
        # Missing custody inputs would fail argument parsing; a nonexistent
        # custody config must remain unread when bootstrap itself refuses.
        argv = ['issue', '--plan-id', 'p', '--rollout-ref', 'r',
                '--rollout-command-id', 'c', '--dispatch-command-id', 'd',
                '--authorization-expires-at', 'invalid',
                '--controller-ssh-fingerprint', 'f', '--host-id', 'h',
                '--host-incarnation', 'i', '--host-enrolment-ref', 'e',
                '--out-dir', '/nonexistent', '--custody', 'transit',
                '--custody-config', '/nonexistent/bootstrap-canary']
        assert producer.main(argv, {}) == 2
        assert 'vendor_cp.deployment.transit_custody' not in sys.modules
        assert 'dotmac_kernel.db' not in sys.modules
        """,
        database="absent",
    )
    assert "synthetic-producer-secret-canary" not in result.stdout + result.stderr
    assert "materials_refused" in result.stderr


@pytest.mark.parametrize("name", ["issuer-run", "attester-session"])
def test_gate0_protocol_dispatch_does_not_import_audit_bootstrap(name: str) -> None:
    result = _fresh(
        f"""
        import sys
        from types import ModuleType
        from vendor_cp.cli import main
        service = ModuleType('vendor_cp.deployment.gate0_services')
        def protocol():
            sys.stdout.buffer.write(b'protocol-canary')
            return 3
        service.issuer_run = protocol
        service.attester_session = protocol
        sys.modules[service.__name__] = service
        assert main(['gate0', {name!r}]) == 3
        assert 'vendor_cp.composition' not in sys.modules
        """,
        database="absent",
    )
    assert result.stdout == "protocol-canary"


def test_database_free_mutation_does_not_bootstrap_database_or_audit() -> None:
    _fresh(
        """
        import sys
        from vendor_cp.cli import main
        from vendor_cp import github_app_credentials as owner
        called = []
        def renew():
            called.append('renew')
            return {'renewed': True}
        owner.renew_host_credentials = renew
        assert main(['admin', 'github-auth-renew']) == 0
        assert called == ['renew']
        assert 'dotmac_kernel.db' not in sys.modules
        assert 'vendor_cp.composition' not in sys.modules
        """,
        database="absent",
    )


def test_migration_only_url_reaches_existing_migration_owner_without_audit_boot() -> (
    None
):
    _fresh(
        """
        import os
        import sys
        from alembic import command
        from vendor_cp.cli import main
        from vendor_cp import migrations
        url = 'postgresql+psycopg://canary:canary@127.0.0.1:1/canary'
        os.environ['MIGRATION_DATABASE_URL'] = url
        calls = []
        def deploy_config(value):
            assert value == url
            return 'canary-config'
        def upgrade(config, target):
            calls.append((config, target))
            assert os.environ['DATABASE_URL'] == url
        migrations.deploy_config = deploy_config
        command.upgrade = upgrade
        assert main(['admin', 'migrate']) == 0
        assert calls == [('canary-config', migrations.COMPOSED_TARGET)]
        assert 'dotmac_kernel.db' not in sys.modules
        assert 'vendor_cp.composition' not in sys.modules
        """,
        database="absent",
    )


@pytest.mark.parametrize("registry_kind", ["empty", "partial"])
def test_leaf_caller_registry_is_preserved_without_importing_cp_composition(
    registry_kind: str,
) -> None:
    _fresh(
        f"""
        import builtins
        import sys
        import dotmac_deployment_control as control
        from dotmac_kernel import AuditActionRegistry, install_audit_actions
        from dotmac_kernel.audit_actions import (
            UndeclaredAuditActionError, active_audit_actions,
        )
        from vendor_cp.audit_bootstrap import ensure_process_audit_actions
        from vendor_cp.deployment import materials_producer as producer
        registry = AuditActionRegistry.from_manifests(
            [] if {registry_kind!r} == 'empty' else [control.module])
        install_audit_actions(registry)
        original_import = builtins.__import__
        def import_module(name, *args, **kwargs):
            if name == 'vendor_cp.composition':
                raise AssertionError('leaf caller must not load full CP composition')
            return original_import(name, *args, **kwargs)
        builtins.__import__ = import_module
        ensure_process_audit_actions()
        assert active_audit_actions() is registry
        action = next(iter(control.module.audit_actions))
        if {registry_kind!r} == 'empty':
            try:
                active_audit_actions().require(action)
            except UndeclaredAuditActionError:
                pass
            else:
                raise AssertionError('empty registry was widened')
        else:
            active_audit_actions().require(action)
        try:
            active_audit_actions().require('canary.undeclared')
        except UndeclaredAuditActionError:
            pass
        else:
            raise AssertionError('unknown audit action was accepted')
        calls = []
        def session(env):
            assert active_audit_actions() is registry
            calls.append('session')
            raise ValueError('stop before database')
        producer._controller_session = session
        argv = ['propose', '--command-id', 'canary', '--target-id',
                '00000000-0000-0000-0000-000000000001', '--operation', 'deploy',
                '--descriptor-digest', 'd', '--execution-plan-digest', 'e',
                '--approval-policy-code', 'p', '--approval-policy-version', '1']
        assert producer.main(argv, {{}}) == 2
        assert calls == ['session']
        assert active_audit_actions() is registry
        assert 'vendor_cp.composition' not in sys.modules
        assert 'dotmac_kernel.db' not in sys.modules
        """,
        database="absent",
    )


def test_unrelated_registry_error_propagates_without_composition_fallback() -> None:
    _fresh(
        """
        import builtins
        import sys
        from vendor_cp import audit_bootstrap
        failure = LookupError('synthetic-unrelated-registry-error')
        def broken():
            raise failure
        audit_bootstrap.active_audit_actions = broken
        original_import = builtins.__import__
        def import_module(name, *args, **kwargs):
            if name == 'vendor_cp.composition':
                raise AssertionError('unrelated error triggered composition fallback')
            return original_import(name, *args, **kwargs)
        builtins.__import__ = import_module
        try:
            audit_bootstrap.ensure_process_audit_actions()
        except LookupError as error:
            assert error is failure
        else:
            raise AssertionError('unrelated registry error was swallowed')
        assert 'vendor_cp.composition' not in sys.modules
        """,
        database="absent",
    )
