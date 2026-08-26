"""Two-session canaries for Fleet's real natural-key write paths.

SQLite cannot arbitrate concurrent uniqueness.  These tests migrate an isolated
Postgres database, drive the production services from two platform sessions,
and prove the losing transaction receives `ConflictError` while its outer
transaction remains usable after `conflict_savepoint` rolls back only the
failed insert.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator

import pytest
from alembic import command
from dotmac_kernel import ConflictError
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from vendor_cp.accounts.models import VendorAccount
from vendor_cp.fleet import service
from vendor_cp.fleet.feature import feature
from vendor_cp.fleet.models import (
    Deployment,
    DeploymentDesiredStateVersion,
    DeploymentTarget,
)
from vendor_cp.managed_profiles import service as profiles
from vendor_cp.managed_profiles.feature import feature as managed_profiles_feature
from vendor_cp.migrations import make_alembic_config


@pytest.fixture(scope="module", autouse=True)
def _declared_audit_actions() -> Iterator[None]:
    """Mirror `create_app` wiring for service-level Postgres races."""

    import dotmac_kernel.audit_actions as registry_module

    try:
        previous = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous = None
    install_audit_actions(
        AuditActionRegistry.from_manifests((feature, managed_profiles_feature))
    )
    try:
        yield
    finally:
        if previous is None:
            registry_module._active_registry = None
        else:
            install_audit_actions(previous)


def _upgrade(url: str) -> None:
    command.upgrade(make_alembic_config(url), "heads")


def _platform_engine(scratch_db: str, url_for: Callable[..., str]) -> Engine:
    dbname = scratch_db.rsplit("/", 1)[1]
    return create_engine(url_for(scratch_db, dbname, user="platform_api"))


def _account(db: Session, ref: str) -> VendorAccount:
    row = VendorAccount(external_ref=ref, display_name=ref)
    db.add(row)
    db.flush()
    return row


def _race(
    engine: Engine,
    *,
    insert_table: str,
    operations: tuple[Callable[[Session], object], Callable[[Session], object]],
) -> tuple[list[object], list[BaseException], list[bool]]:
    barrier = threading.Barrier(2, timeout=30)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    results: list[object] = []
    failures: list[BaseException] = []
    transaction_usable: list[bool] = []

    def rendezvous(
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalized = " ".join(statement.lower().split())
        if normalized.startswith(f"insert into {insert_table}"):
            try:
                barrier.wait()
            except BaseException:
                barrier.abort()
                raise

    event.listen(engine, "before_cursor_execute", rendezvous)

    def run(operation: Callable[[Session], object]) -> None:
        db = factory()
        try:
            db.execute(text("SET LOCAL lock_timeout = '15s'"))
            db.execute(text("SET LOCAL statement_timeout = '30s'"))
            results.append(operation(db))
            db.commit()
        except BaseException as exc:
            failures.append(exc)
            try:
                transaction_usable.append(db.scalar(text("SELECT 1")) == 1)
            except BaseException:
                transaction_usable.append(False)
            db.rollback()
        finally:
            db.close()

    threads = [
        threading.Thread(target=run, args=(operation,), daemon=True)
        for operation in operations
    ]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=90)
        assert all(not thread.is_alive() for thread in threads), "fleet race deadlocked"
    finally:
        event.remove(engine, "before_cursor_execute", rendezvous)

    return results, failures, transaction_usable


def test_target_natural_key_races_are_typed_and_keep_outer_transaction(
    scratch_db: str, url_for: Callable[..., str]
) -> None:
    _upgrade(scratch_db)
    engine = _platform_engine(scratch_db, url_for)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    suffix = uuid.uuid4().hex[:10]
    try:
        with factory() as db:
            first_account = _account(db, f"first-{suffix}")
            second_account = _account(db, f"second-{suffix}")
            first_id = first_account.id
            second_id = second_account.id
            db.commit()

        def same_account_ref(
            command_id: str, customer_ref: str
        ) -> Callable[[Session], object]:
            return lambda db: service.create_deployment_target(
                db,
                service.CreateDeploymentTargetCommand(
                    command_id=command_id,
                    account_id=first_id,
                    target_ref=f"same-ref-{suffix}",
                    customer_ref=customer_ref,
                    display_name="same natural key",
                    region_code="ng-abuja",
                ),
            )

        results, failures, usable = _race(
            engine,
            insert_table="deployment_targets",
            operations=(
                same_account_ref(f"target-ref-a-{suffix}", f"customer-ref-a-{suffix}"),
                same_account_ref(f"target-ref-b-{suffix}", f"customer-ref-b-{suffix}"),
            ),
        )
        assert len(results) == 1
        assert len(failures) == 1 and isinstance(failures[0], ConflictError)
        assert usable == [True]

        def same_customer(
            account_id: object, command_id: str, target_ref: str
        ) -> Callable[[Session], object]:
            return lambda db: service.create_deployment_target(
                db,
                service.CreateDeploymentTargetCommand(
                    command_id=command_id,
                    account_id=account_id,
                    target_ref=target_ref,
                    customer_ref=f"global-customer-{suffix}",
                    display_name="global commercial owner",
                    region_code="ng-abuja",
                ),
            )

        results, failures, usable = _race(
            engine,
            insert_table="deployment_targets",
            operations=(
                same_customer(first_id, f"customer-a-{suffix}", f"a-{suffix}"),
                same_customer(second_id, f"customer-b-{suffix}", f"b-{suffix}"),
            ),
        )
        assert len(results) == 1
        assert len(failures) == 1 and isinstance(failures[0], ConflictError)
        assert usable == [True]

        with factory() as db:
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(DeploymentTarget)
                    .where(DeploymentTarget.customer_ref == f"global-customer-{suffix}")
                )
                == 1
            )
    finally:
        engine.dispose()


def test_deployment_natural_key_races_create_one_immutable_snapshot(
    scratch_db: str, url_for: Callable[..., str]
) -> None:
    _upgrade(scratch_db)
    engine = _platform_engine(scratch_db, url_for)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    suffix = uuid.uuid4().hex[:10]
    try:
        with factory() as db:
            account = _account(db, f"deployment-{suffix}")
            target = service.create_deployment_target(
                db,
                service.CreateDeploymentTargetCommand(
                    command_id=f"setup-target-{suffix}",
                    account_id=account.id,
                    target_ref=f"target-{suffix}",
                    customer_ref=None,
                    display_name="concurrent deployment target",
                    region_code="ng-abuja",
                ),
            )
            profiles.publish_profile_version(
                db,
                profiles.PublishProfileVersionCommand(
                    commercial_product_code="managed-collaboration",
                    profile_code=f"collaboration-{suffix}",
                    version=1,
                    schema_version=1,
                    update_authority="customer_approved",
                ),
            )
            account_id = account.id
            target_id = target.id
            db.commit()

        values = (
            service.ConfigurationValue("customer_domain", "customer.example"),
            service.ConfigurationValue(
                "identity_endpoint", "https://id.customer.example"
            ),
            service.ConfigurationValue(
                "identity_admin_secret_ref", "secret:customer/identity@v1"
            ),
            service.ConfigurationValue(
                "identity_policy_ref", "reference:identity/managed@v1"
            ),
            service.ConfigurationValue(
                "identity_backup_policy_ref", "reference:backup/identity@v1"
            ),
            service.ConfigurationValue(
                "collaboration_endpoint", "https://cloud.customer.example"
            ),
            service.ConfigurationValue(
                "collaboration_admin_secret_ref",
                "secret:customer/collaboration@v1",
            ),
            service.ConfigurationValue(
                "collaboration_backup_policy_ref",
                "reference:backup/collaboration@v1",
            ),
        )

        def operation(
            command_id: str, deployment_ref: str
        ) -> Callable[[Session], object]:
            return lambda db: service.record_deployment_intent(
                db,
                service.CreateDeploymentIntentCommand(
                    command_id=command_id,
                    account_id=account_id,
                    target_id=target_id,
                    deployment_ref=deployment_ref,
                    commercial_product_code="managed-collaboration",
                    profile_code=f"collaboration-{suffix}",
                    profile_version=1,
                    selected_optional_components=(),
                    configuration_snapshot=service.ConfigurationSnapshotInput(
                        snapshot_ref=f"config:{deployment_ref}@v1",
                        schema_version=1,
                        values=values,
                    ),
                    internal_source_code="dotmac.canary.seabone",
                ),
            )

        results, failures, usable = _race(
            engine,
            insert_table="deployments",
            operations=(
                operation(f"deployment-a-{suffix}", f"deployment-a-{suffix}"),
                operation(f"deployment-b-{suffix}", f"deployment-b-{suffix}"),
            ),
        )
        assert len(results) == 1
        assert len(failures) == 1 and isinstance(failures[0], ConflictError)
        assert usable == [True]

        with factory() as db:
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(Deployment)
                    .where(Deployment.target_id == target_id)
                )
                == 1
            )
            assert (
                db.scalar(
                    select(func.count()).select_from(DeploymentDesiredStateVersion)
                )
                == 1
            )
    finally:
        engine.dispose()
