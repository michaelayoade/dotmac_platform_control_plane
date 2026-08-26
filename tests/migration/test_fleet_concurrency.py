"""Two-session canaries for Fleet's real natural-key write paths.

SQLite cannot arbitrate concurrent uniqueness.  These tests migrate an isolated
Postgres database, drive the production services from two platform sessions,
and prove the losing transaction receives `ConflictError` while its outer
transaction remains usable after `conflict_savepoint` rolls back only the
failed insert. Exact signed-receipt replay is the deliberate complement: both
callers converge on one immutable row without weakening collision refusal.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from dotmac_kernel import ConflictError
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from dotmac_release_catalog import (
    ArtifactKind,
    ArtifactOrigin,
    AttestationKind,
    attest_artifact,
    publish_artifact,
)
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from tests.capability_contract_registry import (
    build_capability_composition_registry,
    build_capability_contract_registry,
    build_composition_selections,
    build_desired_operation_documents,
)

from vendor_cp.accounts.models import VendorAccount
from vendor_cp.fleet import service
from vendor_cp.fleet.feature import feature
from vendor_cp.fleet.models import (
    Deployment,
    DeploymentCapabilityInstance,
    DeploymentDesiredStateVersion,
    DeploymentTarget,
)
from vendor_cp.managed_profiles import service as profiles
from vendor_cp.managed_profiles.feature import feature as managed_profiles_feature
from vendor_cp.migrations import make_alembic_config
from vendor_cp.planning import service as planning
from vendor_cp.planning.feature import feature as planning_feature
from vendor_cp.planning.models import (
    DeploymentBundleManifestVersion,
    DeploymentPlan,
    IntegratorExecutionReceipt,
)

CAPABILITY_REGISTRY = build_capability_contract_registry()
COMPOSITION_REGISTRY = build_capability_composition_registry()


@pytest.fixture(scope="module", autouse=True)
def _declared_audit_actions() -> Iterator[None]:
    """Mirror `create_app` wiring for service-level Postgres races."""

    import dotmac_kernel.audit_actions as registry_module

    try:
        previous = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous = None
    install_audit_actions(
        AuditActionRegistry.from_manifests(
            (feature, managed_profiles_feature, planning_feature)
        )
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


def _race_before_deployment_lock(
    engine: Engine,
    *,
    operations: tuple[Callable[[Session], object], Callable[[Session], object]],
) -> tuple[list[object], list[BaseException], list[bool]]:
    """Release both real planners immediately before SELECT FOR UPDATE."""

    barrier = threading.Barrier(2, timeout=30)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    results: list[object] = []
    failures: list[BaseException] = []
    usable: list[bool] = []

    def rendezvous(
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalized = " ".join(statement.lower().split())
        if " from deployments " in normalized and normalized.endswith("for update"):
            barrier.wait()

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
                usable.append(db.scalar(text("SELECT 1")) == 1)
            except BaseException:
                usable.append(False)
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
        assert all(
            not thread.is_alive() for thread in threads
        ), "deployment plan race deadlocked"
    finally:
        event.remove(engine, "before_cursor_execute", rendezvous)
    return results, failures, usable


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
                capability_registry=CAPABILITY_REGISTRY,
                composition_registry=COMPOSITION_REGISTRY,
            )
            account_id = account.id
            target_id = target.id
            db.commit()

        values = (
            service.ConfigurationValue(
                "identity.dns", "customer_domain", "customer.example"
            ),
            service.ConfigurationValue(
                "collaboration.dns", "customer_domain", "customer.example"
            ),
            service.ConfigurationValue(
                "identity.realm", "identity_endpoint", "https://id.customer.example"
            ),
            service.ConfigurationValue(
                "identity.realm",
                "identity_admin_secret_ref",
                "secret:customer/identity@v1",
            ),
            service.ConfigurationValue(
                "identity.realm",
                "identity_policy_ref",
                "reference:identity/managed@v1",
            ),
            service.ConfigurationValue(
                "identity.realm",
                "identity_backup_policy_ref",
                "reference:backup/identity@v1",
            ),
            service.ConfigurationValue(
                "collaboration.application",
                "collaboration_endpoint",
                "https://cloud.customer.example",
            ),
            service.ConfigurationValue(
                "collaboration.application",
                "collaboration_admin_secret_ref",
                "secret:customer/collaboration@v1",
            ),
            service.ConfigurationValue(
                "collaboration.application",
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
                    desired_operation_inputs=tuple(
                        service.CapabilityOperationInput(
                            instance_ref, component_code, capability_id, document
                        )
                        for instance_ref, component_code, capability_id, document in (
                            build_desired_operation_documents("managed-collaboration")
                        )
                    ),
                    composition_selections=build_composition_selections(
                        "managed-collaboration"
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
            desired = db.scalar(select(DeploymentDesiredStateVersion))
            assert desired is not None
            assert db.scalar(
                select(func.count())
                .select_from(DeploymentCapabilityInstance)
                .where(
                    DeploymentCapabilityInstance.deployment_id == desired.deployment_id
                )
            ) == len(desired.selected_capabilities)
    finally:
        engine.dispose()


def test_bundle_and_plan_natural_key_races_are_typed_and_serialized(
    scratch_db: str, url_for: Callable[..., str]
) -> None:
    _upgrade(scratch_db)
    engine = _platform_engine(scratch_db, url_for)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    suffix = uuid.uuid4().hex[:10]
    try:
        with factory() as db:
            account = _account(db, f"planning-{suffix}")
            target = service.create_deployment_target(
                db,
                service.CreateDeploymentTargetCommand(
                    command_id=f"planning-target-{suffix}",
                    account_id=account.id,
                    target_ref=f"planning-{suffix}",
                    customer_ref=None,
                    display_name="planning concurrency",
                    region_code="ng-abuja",
                ),
            )
            profile = profiles.publish_profile_version(
                db,
                profiles.PublishProfileVersionCommand(
                    commercial_product_code="managed-sso",
                    profile_code=f"planning-{suffix}",
                    version=1,
                    schema_version=1,
                    update_authority="customer_approved",
                ),
                capability_registry=CAPABILITY_REGISTRY,
                composition_registry=COMPOSITION_REGISTRY,
            )
            intent = service.record_deployment_intent(
                db,
                service.CreateDeploymentIntentCommand(
                    command_id=f"planning-intent-{suffix}",
                    account_id=account.id,
                    target_id=target.id,
                    deployment_ref=f"planning-{suffix}",
                    commercial_product_code="managed-sso",
                    profile_code=f"planning-{suffix}",
                    profile_version=1,
                    selected_optional_components=(),
                    configuration_snapshot=service.ConfigurationSnapshotInput(
                        snapshot_ref=f"config:planning-{suffix}@v1",
                        schema_version=1,
                        values=(
                            service.ConfigurationValue(
                                "identity.dns",
                                "customer_domain",
                                "planning.example",
                            ),
                            service.ConfigurationValue(
                                "identity.realm",
                                "identity_endpoint",
                                "https://id.planning.example",
                            ),
                            service.ConfigurationValue(
                                "identity.realm",
                                "identity_admin_secret_ref",
                                "secret:planning/identity@v1",
                            ),
                            service.ConfigurationValue(
                                "identity.realm",
                                "identity_policy_ref",
                                "reference:planning/identity@v1",
                            ),
                            service.ConfigurationValue(
                                "identity.realm",
                                "identity_backup_policy_ref",
                                "reference:planning/backup@v1",
                            ),
                        ),
                    ),
                    desired_operation_inputs=tuple(
                        service.CapabilityOperationInput(
                            instance_ref, component_code, capability_id, document
                        )
                        for instance_ref, component_code, capability_id, document in (
                            build_desired_operation_documents("managed-sso")
                        )
                    ),
                    composition_selections=build_composition_selections("managed-sso"),
                    internal_source_code="dotmac.canary.seabone",
                ),
            )
            artifact_digest = "sha256:" + "1" * 64
            artifact = publish_artifact(
                db,
                product_code=f"dotmac-identity-{suffix}",
                version="1.0.0",
                artifact_kind=ArtifactKind.CONTAINER_IMAGE,
                origin=ArtifactOrigin.DOTMAC_PRODUCT,
                digest=artifact_digest,
                artifact_ref=f"registry.example/identity@{artifact_digest}",
                source_revision="2" * 40,
            )
            evidence = {
                kind: attest_artifact(
                    db,
                    artifact_id=artifact.id,
                    attestation_kind=kind,
                    uri=f"evidence://{suffix}/{kind.value}",
                    digest="sha256:" + fill * 64,
                )
                for kind, fill in (
                    (AttestationKind.PROVENANCE, "3"),
                    (AttestationKind.SBOM, "4"),
                    (AttestationKind.SIGNATURE, "5"),
                    (AttestationKind.PRODUCT_MANIFEST, "6"),
                )
            }
            deployment_id = intent.deployment.id
            desired_id = intent.desired_state.id
            profile_id = profile.id
            selection = planning.ComponentArtifactSelection(
                component_code="identity",
                artifact_id=artifact.id,
                artifact_digest=artifact.digest,
                artifact_reference=artifact.artifact_ref,
                provenance=planning.AttestationSelection(
                    evidence[AttestationKind.PROVENANCE].id,
                    evidence[AttestationKind.PROVENANCE].digest,
                ),
                sbom=planning.AttestationSelection(
                    evidence[AttestationKind.SBOM].id,
                    evidence[AttestationKind.SBOM].digest,
                ),
                signature=planning.AttestationSelection(
                    evidence[AttestationKind.SIGNATURE].id,
                    evidence[AttestationKind.SIGNATURE].digest,
                ),
                product_manifest=planning.AttestationSelection(
                    evidence[AttestationKind.PRODUCT_MANIFEST].id,
                    evidence[AttestationKind.PRODUCT_MANIFEST].digest,
                ),
            )
            db.commit()

        def publish(command_id: str) -> Callable[[Session], object]:
            return lambda db: planning.publish_bundle_manifest_version(
                db,
                planning.PublishBundleManifestCommand(
                    command_id=command_id,
                    commercial_product_code="managed-sso",
                    profile_code=f"planning-{suffix}",
                    profile_version=1,
                    bundle_code=f"bundle-{suffix}",
                    version=1,
                    components=(selection,),
                ),
            )

        results, failures, usable = _race(
            engine,
            insert_table="deployment_bundle_manifest_versions",
            operations=(
                publish(f"bundle-a-{suffix}"),
                publish(f"bundle-b-{suffix}"),
            ),
        )
        assert len(results) == 1
        assert len(failures) == 1 and isinstance(failures[0], ConflictError)
        assert usable == [True]

        with factory() as db:
            bundle = db.scalar(
                select(DeploymentBundleManifestVersion).where(
                    DeploymentBundleManifestVersion.profile_version_id == profile_id
                )
            )
            desired = db.get(DeploymentDesiredStateVersion, desired_id)
            assert bundle is not None and desired is not None
            bindings = tuple(
                planning.IntegratorBindingSelection(
                    capability_instance_ref=str(item["capability_instance_ref"]),
                    capability_id=str(item["capability_id"]),
                    capability_schema_version=int(item["schema_version"]),
                    installation_id=uuid.uuid4(),
                    installation_ref=f"installation:{uuid.uuid4()}",
                    binding_ref=uuid.uuid4(),
                    connector_key=f"connector.{item['capability_id']}",
                    connector_version="1.0.0",
                    connector_manifest_digest="sha256:" + "7" * 64,
                    connector_artifact_digest="sha256:" + "8" * 64,
                    connector_configuration_revision_id=uuid.uuid4(),
                    connector_configuration_digest="sha256:" + "9" * 64,
                    execution_policy_digest="sha256:" + "a" * 64,
                )
                for item in desired.selected_capabilities
            )
            bundle_id = bundle.id

        def plan(command_id: str) -> Callable[[Session], object]:
            return lambda db: planning.create_deployment_plan(
                db,
                planning.CreateDeploymentPlanCommand(
                    command_id=command_id,
                    deployment_id=deployment_id,
                    desired_state_version_id=desired_id,
                    bundle_manifest_version_id=bundle_id,
                    allocation_id=None,
                    binding_selections=bindings,
                    lifecycle_policy=planning.VersionedPolicyRef(
                        "managed.lifecycle", 1
                    ),
                ),
            )

        results, failures, usable = _race_before_deployment_lock(
            engine,
            operations=(plan(f"plan-a-{suffix}"), plan(f"plan-b-{suffix}")),
        )
        assert len(results) == 1
        assert len(failures) == 1 and isinstance(failures[0], ConflictError)
        assert usable == [True]
        with factory() as db:
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(DeploymentPlan)
                    .where(DeploymentPlan.deployment_id == deployment_id)
                )
                == 1
            )

        class _Signer:
            key_id = f"vendor-command-{suffix}"
            purpose = planning.COMMAND_SIGNING_PURPOSE
            public_key_b64 = f"public-key-{suffix}"

            def sign(self, payload: bytes) -> bytes:
                return hashlib.sha512(payload).digest()

        class _Verifier:
            def verify(
                self, *, key_id: str, payload: bytes, signature_b64url: str
            ) -> None:
                assert key_id == f"integrator-receipt-{suffix}"
                assert payload and signature_b64url == "test-signature"

        now = datetime.now(UTC)
        with factory() as db:
            saved_plan = db.scalar(
                select(DeploymentPlan).where(
                    DeploymentPlan.deployment_id == deployment_id
                )
            )
            assert saved_plan is not None
            envelopes = planning.build_plan_commands(
                db,
                planning.BuildPlanCommands(
                    command_id_prefix=f"plan-validation-{suffix}",
                    plan_id=saved_plan.id,
                    audience="dotmac-integrator:seabone",
                    issued_at=now,
                    expires_at=now + timedelta(minutes=2),
                ),
                signer=_Signer(),
                key_separation=planning.CommandKeySeparationPolicy(
                    command_key_id=_Signer.key_id,
                    forbidden_key_ids=frozenset(),
                    forbidden_public_keys_b64=frozenset(),
                ),
                now=now,
            )
            assert envelopes
            envelope = envelopes[0]
            body = envelope.document["body"]
            module_hash = "sha256:" + "b" * 64
            receipt = {
                "receipt_contract_version": "integrator.provisioning-receipt.v1",
                "command_contract_version": "integrator.provisioning-command.v1",
                "operation": "plan",
                "command_id": envelope.command_id,
                "nonce": envelope.command_id,
                "issuer_account_ref": "vendor-control-plane",
                "deployment_ref": body["deployment_ref"],
                "capability_instance_ref": body["capability_instance_ref"],
                "request_body_sha256": envelope.document["body_sha256"],
                "plan_hash": body["plan_hash"],
                "approval_digest": None,
                "artifact_digest": None,
                "config_digest": body["config_digest"],
                "outcome": "planned",
                "operation_id": None,
                "replayed": False,
                "latest_module_receipt_sequence": None,
                "latest_module_receipt_hash": None,
                "module_plan_receipt_hash": module_hash,
                "occurred_at": now.isoformat().replace("+00:00", "Z"),
                "evidence": {
                    "module_plan_receipt": {
                        "capability_instance_ref": body["capability_instance_ref"],
                        "command_id": envelope.command_id,
                        "command_fingerprint": "sha256:" + "c" * 64,
                        "request_body_digest": envelope.document["body_sha256"],
                        "result_digest": "sha256:" + "d" * 64,
                        "receipt_hash": module_hash,
                    }
                },
            }
            digest = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(
                        receipt,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode()
                ).hexdigest()
            )
            signed_receipt = {
                "key_id": f"integrator-receipt-{suffix}",
                "receipt_sha256": digest,
                "signature": "test-signature",
                "receipt": receipt,
            }
            db.commit()

        def ingest(db: Session) -> object:
            return planning.ingest_integrator_receipt(
                db,
                planning.IngestIntegratorReceiptCommand(signed_receipt=signed_receipt),
                verifier=_Verifier(),
            )

        results, failures, usable = _race(
            engine,
            insert_table="integrator_execution_receipts",
            operations=(ingest, ingest),
        )
        assert len(results) == 2 and not failures and not usable
        assert len({result.id for result in results}) == 1
        with factory() as db:
            count = db.scalar(
                select(func.count()).select_from(IntegratorExecutionReceipt)
            )
            assert count == 1
    finally:
        engine.dispose()
