"""Fleet owns customer selection and immutable deployment configuration."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from uuid import UUID

import pytest
from dotmac_kernel import ConflictError, PlatformAuditEvent
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from tests.capability_contract_registry import (
    build_capability_composition_registry,
    build_capability_contract_registry,
    build_composition_selections,
    build_desired_operation_documents,
)

import vendor_cp.offers.models  # noqa: F401  # registers ContractLine's FK target
from vendor_cp.accounts.models import VendorAccount
from vendor_cp.contracts.models import Contract, ContractStatus
from vendor_cp.fleet import service
from vendor_cp.fleet.feature import feature
from vendor_cp.fleet.models import (
    DeploymentCapabilityInstance,
    DeploymentDesiredStateVersion,
)
from vendor_cp.managed_profiles import service as profiles
from vendor_cp.managed_profiles.feature import feature as managed_profiles_feature
from vendor_cp.managed_profiles.models import ManagedServiceProfileVersion

CAPABILITY_REGISTRY = build_capability_contract_registry()
COMPOSITION_REGISTRY = build_capability_composition_registry()


@pytest.fixture(scope="module", autouse=True)
def _declared_audit_actions() -> Iterator[None]:
    """Install Fleet's declarations when the service is tested without an app."""

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


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as db:
            yield db
    finally:
        engine.dispose()


def _account(db: Session, *, ref: str = "acct-nhia") -> VendorAccount:
    row = VendorAccount(external_ref=ref, display_name=ref)
    db.add(row)
    db.flush()
    return row


def _publish_profile(
    db: Session,
    *,
    product: str = "managed-collaboration",
    profile_code: str = "standard",
) -> profiles.ManagedServiceProfileVersionView:
    return profiles.publish_profile_version(
        db,
        profiles.PublishProfileVersionCommand(
            commercial_product_code=product,
            profile_code=profile_code,
            version=1,
            schema_version=1,
            update_authority="customer_approved",
        ),
        capability_registry=CAPABILITY_REGISTRY,
        composition_registry=COMPOSITION_REGISTRY,
    )


def _target(
    db: Session,
    account: VendorAccount,
    *,
    target_ref: str = "nhia-production",
    customer_ref: str | None = "customer-nhia",
) -> service.DeploymentTargetView:
    return service.create_deployment_target(
        db,
        service.CreateDeploymentTargetCommand(
            command_id=f"target:{account.external_ref}:{target_ref}",
            account_id=account.id,
            target_ref=target_ref,
            customer_ref=customer_ref,
            display_name=target_ref,
            region_code="ng-abuja",
        ),
    )


def _active_contract(
    db: Session,
    *,
    customer_ref: str = "customer-nhia",
    product: str = "managed-collaboration",
) -> Contract:
    row = Contract(
        product_code=product,
        customer_ref=customer_ref,
        legal_entity="National Health Insurance Authority",
        currency_code="NGN",
        term_start=date.today(),
        term_end=date.today() + timedelta(days=365),
        status=ContractStatus.ACTIVE.value,
        activation_rule="manual_confirmation",
        content_hash="a" * 64,
        activated_at=datetime.now(UTC),
    )
    db.add(row)
    db.flush()
    return row


def _values(*, workspace: bool = False) -> tuple[service.ConfigurationValue, ...]:
    values: dict[str, str | tuple[str, ...]] = {
        "customer_domain": "customer.example",
        "identity_endpoint": "https://id.customer.example",
        "identity_admin_secret_ref": "secret:customer/identity-admin@v1",
        "identity_policy_ref": "reference:identity/managed@v1",
        "identity_backup_policy_ref": "reference:backup/identity-daily@v1",
        "business_endpoint": "https://erp.customer.example",
        "business_admin_secret_ref": "secret:customer/business-admin@v2",
        "business_backup_policy_ref": "reference:backup/business-daily@v1",
        "email_endpoint": "https://mail.customer.example",
        "email_admin_secret_ref": "secret:customer/email-admin@v3",
        "email_domains": ("customer.example", "subsidiary.example"),
        "email_backup_policy_ref": "reference:backup/email-daily@v1",
        "collaboration_endpoint": "https://cloud.customer.example",
        "collaboration_admin_secret_ref": ("secret:customer/collaboration-admin@v1"),
        "collaboration_backup_policy_ref": ("reference:backup/collaboration-daily@v1"),
        "academy_endpoint": "https://academy.customer.example",
        "academy_admin_secret_ref": "secret:customer/academy-admin@v1",
        "academy_backup_policy_ref": "reference:backup/academy-daily@v1",
    }
    if workspace:
        values.update(
            {
                "workspace_endpoint": "https://workspace.customer.example",
                "workspace_admin_secret_ref": ("secret:customer/workspace-admin@v1"),
            }
        )
    component_prefixes = ("identity", "business", "email", "collaboration", "academy")
    if workspace:
        component_prefixes += ("workspace",)
    result: list[service.ConfigurationValue] = []
    for code, value in values.items():
        if code == "customer_domain":
            result.extend(
                service.ConfigurationValue(f"{prefix}.dns", code, value)
                for prefix in component_prefixes
            )
            continue
        prefix = code.split("_", 1)[0]
        instance_ref = (
            f"{prefix}.application" if prefix != "identity" else "identity.realm"
        )
        result.append(service.ConfigurationValue(instance_ref, code, value))
    return tuple(result)


def _collaboration_values() -> tuple[service.ConfigurationValue, ...]:
    selected = {
        "customer_domain",
        "identity_endpoint",
        "identity_admin_secret_ref",
        "identity_policy_ref",
        "identity_backup_policy_ref",
        "collaboration_endpoint",
        "collaboration_admin_secret_ref",
        "collaboration_backup_policy_ref",
    }
    return tuple(
        value
        for value in _values()
        if value.field_code in selected
        and value.capability_instance_ref.split(".", 1)[0]
        in {"identity", "collaboration"}
    )


def _snapshot(
    values: tuple[service.ConfigurationValue, ...],
    *,
    ref: str = "config:nhia/collaboration@v1",
    schema_version: int = 1,
) -> service.ConfigurationSnapshotInput:
    return service.ConfigurationSnapshotInput(
        snapshot_ref=ref,
        schema_version=schema_version,
        values=values,
    )


def _intent(
    *,
    account_id: UUID,
    target_id: UUID,
    product: str = "managed-collaboration",
    profile_code: str = "standard",
    deployment_ref: str = "nhia-collaboration",
    selected_optional: tuple[str, ...] = (),
    configuration_snapshot: service.ConfigurationSnapshotInput | None = None,
    contract_id: UUID | None = None,
    internal_source_code: str | None = None,
) -> service.CreateDeploymentIntentCommand:
    return service.CreateDeploymentIntentCommand(
        command_id=f"deployment:{deployment_ref}",
        account_id=account_id,
        target_id=target_id,
        deployment_ref=deployment_ref,
        commercial_product_code=product,
        profile_code=profile_code,
        profile_version=1,
        selected_optional_components=selected_optional,
        configuration_snapshot=(
            configuration_snapshot or _snapshot(_collaboration_values())
        ),
        desired_operation_inputs=tuple(
            service.CapabilityOperationInput(
                instance_ref, component_code, capability_id, document
            )
            for instance_ref, component_code, capability_id, document in (
                build_desired_operation_documents(
                    product,
                    selected_optional_components=(
                        selected_optional if product == "managed-suite" else ()
                    ),
                )
            )
        ),
        composition_selections=build_composition_selections(
            product,
            selected_optional_components=(
                selected_optional if product == "managed-suite" else ()
            ),
        ),
        contract_id=contract_id,
        internal_source_code=internal_source_code,
    )


def test_target_has_account_owner_and_global_commercial_customer_owner(
    session: Session,
) -> None:
    first = _account(session, ref="acct-one")
    second = _account(session, ref="acct-two")
    target = _target(session, first)
    assert target.account_id == first.id
    assert target.customer_ref == "customer-nhia"

    with pytest.raises(ConflictError, match="target"):
        _target(
            session,
            second,
            target_ref="second-production",
            customer_ref="customer-nhia",
        )

    internal = _target(
        session,
        second,
        target_ref="internal-lab",
        customer_ref=None,
    )
    assert internal.customer_ref is None


def test_contract_backed_intent_freezes_exact_selected_snapshot(
    session: Session,
) -> None:
    account = _account(session)
    target = _target(session, account)
    profile = _publish_profile(session)
    contract = _active_contract(session)

    result = service.record_deployment_intent(
        session,
        _intent(
            account_id=account.id,
            target_id=target.id,
            contract_id=contract.id,
        ),
    )
    desired = session.get(DeploymentDesiredStateVersion, result.desired_state.id)
    assert desired is not None
    assert desired.profile_version_id == profile.id
    assert desired.profile_content_hash == profile.content_hash
    assert desired.selected_components == ["collaboration", "identity"]
    stable_instances = set(
        session.execute(
            select(DeploymentCapabilityInstance.capability_instance_ref).where(
                DeploymentCapabilityInstance.deployment_id == result.deployment.id
            )
        ).scalars()
    )
    assert stable_instances == {
        str(item["capability_instance_ref"]) for item in desired.selected_capabilities
    }
    assert {item["capability_id"] for item in desired.selected_capabilities} >= {
        "collaboration.application.lifecycle.v1",
        "identity.realm.lifecycle.v1",
        "dns.authoritative.v1",
        "host.deployment-bundle.lifecycle.v1",
        "host.backup-restore.lifecycle.v1",
    }
    assert {
        (item["capability_id"], item["operation_code"])
        for item in desired.selected_operations
    } >= {
        ("collaboration.application.lifecycle.v1", "apply"),
        ("identity.realm.lifecycle.v1", "apply"),
        ("dns.authoritative.v1", "plan"),
        ("dns.authoritative.v1", "apply"),
        ("dns.authoritative.v1", "observe"),
    }
    assert desired.configuration_snapshot_ref == "config:nhia/collaboration@v1"
    assert desired.configuration_schema_version == 1
    assert desired.configuration_snapshot["identity.realm"][
        "identity_admin_secret_ref"
    ] == ("secret:customer/identity-admin@v1")
    assert desired.configuration_hash.startswith("sha256:")
    assert desired.desired_state_hash.startswith("sha256:")
    assert (
        session.scalar(
            select(func.count())
            .select_from(PlatformAuditEvent)
            .where(PlatformAuditEvent.action == "vendor.deployment.intent_recorded")
        )
        == 1
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(PlatformOutboxEvent)
            .where(PlatformOutboxEvent.event_type == "deployment.intent_recorded")
        )
        == 1
    )


def test_suite_optional_workspace_is_per_deployment_not_per_profile(
    session: Session,
) -> None:
    account = _account(session)
    profile = _publish_profile(
        session, product="managed-suite", profile_code="suite-standard"
    )
    without_target = _target(
        session, account, target_ref="suite-without", customer_ref=None
    )
    with_target = _target(session, account, target_ref="suite-with", customer_ref=None)

    with pytest.raises(ConflictError, match="unselected component"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=without_target.id,
                product="managed-suite",
                profile_code="suite-standard",
                deployment_ref="suite-extra-config",
                configuration_snapshot=_snapshot(
                    _values(workspace=True), ref="config:nhia/suite-extra@v1"
                ),
                internal_source_code="dotmac.pilot.seabone",
            ),
        )

    without = service.record_deployment_intent(
        session,
        _intent(
            account_id=account.id,
            target_id=without_target.id,
            product="managed-suite",
            profile_code="suite-standard",
            deployment_ref="suite-without",
            configuration_snapshot=_snapshot(
                _values(), ref="config:nhia/suite-without@v1"
            ),
            internal_source_code="dotmac.pilot.seabone",
        ),
    )
    with_workspace = service.record_deployment_intent(
        session,
        _intent(
            account_id=account.id,
            target_id=with_target.id,
            product="managed-suite",
            profile_code="suite-standard",
            deployment_ref="suite-with",
            selected_optional=("workspace",),
            configuration_snapshot=_snapshot(
                _values(workspace=True), ref="config:nhia/suite-with@v1"
            ),
            internal_source_code="dotmac.pilot.seabone",
        ),
    )
    without_row = session.get(DeploymentDesiredStateVersion, without.desired_state.id)
    with_row = session.get(
        DeploymentDesiredStateVersion, with_workspace.desired_state.id
    )
    assert without_row is not None and with_row is not None
    assert without_row.profile_version_id == with_row.profile_version_id == profile.id
    assert "workspace" not in without_row.selected_components
    assert "workspace_endpoint" not in without_row.configuration_snapshot
    assert "workspace" in with_row.selected_components
    assert (
        "workspace_endpoint" in with_row.configuration_snapshot["workspace.application"]
    )
    assert {
        item["target_capability_instance_ref"]
        for item in with_row.selected_composition_edges
        if item["binding_code"] == "realm-to-oidc-clients"
    } == {
        "academy.oidc-client",
        "business.oidc-client",
        "collaboration.oidc-client",
        "email.oidc-client",
        "workspace.oidc-client",
    }
    assert without_row.desired_state_hash != with_row.desired_state_hash


def test_email_capability_instances_are_explicit_and_owner_coverage_is_exact(
    session: Session,
) -> None:
    account = _account(session)
    target = _target(session, account, customer_ref=None)
    profile = _publish_profile(session, product="managed-email")
    baseline_documents = build_desired_operation_documents("managed-email")
    documents = (
        *baseline_documents,
        (
            "email.domain-primary",
            "email",
            "email.lifecycle.v1",
            {"resource_kind": "domain"},
        ),
        (
            "email.mailbox-admin",
            "email",
            "email.lifecycle.v1",
            {"resource_kind": "mailbox"},
        ),
    )
    selections = build_composition_selections(
        "managed-email", desired_operation_documents=documents
    )
    baseline_values = tuple(
        value
        for value in _values()
        if value.capability_instance_ref.startswith(("identity.", "email."))
    )
    email_values = tuple(
        value
        for value in baseline_values
        if value.capability_instance_ref == "email.application"
    )
    values = (
        *baseline_values,
        *(
            service.ConfigurationValue(
                instance_ref,
                value.field_code,
                value.value,
            )
            for instance_ref in ("email.domain-primary", "email.mailbox-admin")
            for value in email_values
        ),
    )
    operation_inputs = tuple(
        service.CapabilityOperationInput(
            instance_ref, component_code, capability_id, document
        )
        for instance_ref, component_code, capability_id, document in documents
    )

    with pytest.raises(ConflictError, match="each_target_exactly_one"):
        service._validate_and_select_profile(
            profile,
            selected_optional_components=(),
            configuration_snapshot=_snapshot(
                values, ref="config:nhia/email-missing-edge@v1"
            ),
            desired_operation_inputs=operation_inputs,
            composition_selections=tuple(
                selection
                for selection in selections
                if not (
                    selection.binding_code == "email-application-to-mailbox"
                    and selection.target_capability_instance_ref
                    == "email.mailbox-admin"
                )
            ),
        )

    result = service.record_deployment_intent(
        session,
        service.CreateDeploymentIntentCommand(
            command_id="deployment:managed-email-multiple-instances",
            account_id=account.id,
            target_id=target.id,
            deployment_ref="managed-email-multiple-instances",
            commercial_product_code="managed-email",
            profile_code="standard",
            profile_version=1,
            selected_optional_components=(),
            configuration_snapshot=_snapshot(
                values, ref="config:nhia/email-multiple@v1"
            ),
            desired_operation_inputs=operation_inputs,
            composition_selections=selections,
            internal_source_code="dotmac.pilot.seabone",
        ),
    )
    desired = session.get(DeploymentDesiredStateVersion, result.desired_state.id)
    assert desired is not None
    assert {
        item["capability_instance_ref"]
        for item in desired.selected_capabilities
        if item["capability_id"] == "email.lifecycle.v1"
    } == {"email.application", "email.domain-primary", "email.mailbox-admin"}
    assert {
        (
            item["binding_code"],
            item["source_capability_instance_ref"],
            item["target_capability_instance_ref"],
        )
        for item in desired.selected_composition_edges
        if str(item["binding_code"]).startswith("email-application-to-")
    } == {
        (
            "email-application-to-domain",
            "email.application",
            "email.domain-primary",
        ),
        (
            "email-application-to-mailbox",
            "email.application",
            "email.mailbox-admin",
        ),
    }


def test_config_change_changes_desired_state_hash(session: Session) -> None:
    account = _account(session)
    _publish_profile(session)
    first_target = _target(session, account, target_ref="first", customer_ref=None)
    second_target = _target(session, account, target_ref="second", customer_ref=None)
    first = service.record_deployment_intent(
        session,
        _intent(
            account_id=account.id,
            target_id=first_target.id,
            deployment_ref="first",
            internal_source_code="dotmac.pilot.seabone",
        ),
    )
    changed = tuple(
        service.ConfigurationValue(
            capability_instance_ref=value.capability_instance_ref,
            field_code=value.field_code,
            value=(
                "reference:identity/strict@v2"
                if value.field_code == "identity_policy_ref"
                else value.value
            ),
        )
        for value in _collaboration_values()
    )
    second = service.record_deployment_intent(
        session,
        _intent(
            account_id=account.id,
            target_id=second_target.id,
            deployment_ref="second",
            configuration_snapshot=_snapshot(
                changed, ref="config:nhia/collaboration@v2"
            ),
            internal_source_code="dotmac.pilot.seabone",
        ),
    )
    assert (
        first.desired_state.desired_state_hash
        != second.desired_state.desired_state_hash
    )


def test_cross_account_contract_cannot_authorize_another_accounts_target(
    session: Session,
) -> None:
    owner = _account(session, ref="owner")
    other = _account(session, ref="other")
    _target(session, owner, target_ref="owned", customer_ref="customer-owned")
    other_target = _target(
        session, other, target_ref="other", customer_ref="customer-other"
    )
    _publish_profile(session)
    contract = _active_contract(session, customer_ref="customer-owned")

    with pytest.raises(ConflictError, match="customer reference"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=other.id,
                target_id=other_target.id,
                contract_id=contract.id,
            ),
        )


def test_billable_intent_requires_active_matching_product(session: Session) -> None:
    account = _account(session)
    target = _target(session, account)
    _publish_profile(session)
    wrong_product = _active_contract(session, product="managed-email")
    with pytest.raises(ConflictError, match="product"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=target.id,
                contract_id=wrong_product.id,
            ),
        )

    inactive = _active_contract(session, customer_ref="customer-nhia")
    inactive.status = ContractStatus.SUSPENDED.value
    session.flush()
    with pytest.raises(ConflictError, match="active"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=target.id,
                deployment_ref="inactive",
                contract_id=inactive.id,
            ),
        )


def test_named_internal_source_allows_target_without_customer_ref(
    session: Session,
) -> None:
    account = _account(session)
    target = _target(session, account, customer_ref=None)
    _publish_profile(session)
    result = service.record_deployment_intent(
        session,
        _intent(
            account_id=account.id,
            target_id=target.id,
            internal_source_code="dotmac.pilot.seabone",
        ),
    )
    assert result.deployment.contract_id is None
    assert result.deployment.internal_source_code == "dotmac.pilot.seabone"


def test_optional_selection_and_dependency_fail_closed(session: Session) -> None:
    account = _account(session)
    target = _target(session, account, customer_ref=None)
    _publish_profile(session)
    with pytest.raises(ConflictError, match="allowed optional"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=target.id,
                selected_optional=("workspace",),
                internal_source_code="dotmac.pilot.seabone",
            ),
        )

    built = profiles.build_profile_version(
        profiles.PublishProfileVersionCommand(
            commercial_product_code="managed-suite",
            profile_code="broken-closure",
            version=1,
            schema_version=1,
            update_authority="customer_approved",
        ),
        capability_registry=CAPABILITY_REGISTRY,
        composition_registry=COMPOSITION_REGISTRY,
    )
    document = copy.deepcopy(built.document)
    components = document["components"]
    assert isinstance(components, list)
    for component in components:
        assert isinstance(component, dict)
        if component["component_code"] == "workspace":
            component["depends_on"] = ["unavailable"]
    row = ManagedServiceProfileVersion(
        commercial_product_code="managed-suite",
        profile_code="broken-closure",
        version=1,
        schema_version=1,
        content_hash=_content_hash(document),
        document=document,
    )
    session.add(row)
    session.flush()
    broken_target = _target(session, account, target_ref="broken", customer_ref=None)
    with pytest.raises(ConflictError, match="unavailable dependency"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=broken_target.id,
                product="managed-suite",
                profile_code="broken-closure",
                deployment_ref="broken",
                selected_optional=("workspace",),
                configuration_snapshot=_snapshot(
                    _values(workspace=True), ref="config:nhia/broken@v1"
                ),
                internal_source_code="dotmac.pilot.seabone",
            ),
        )


def test_snapshot_schema_selected_fields_and_secret_refs_fail_closed(
    session: Session,
) -> None:
    account = _account(session)
    target = _target(session, account, customer_ref=None)
    _publish_profile(session)

    with pytest.raises(ConflictError, match="schema version"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=target.id,
                configuration_snapshot=_snapshot(
                    _collaboration_values(), schema_version=2
                ),
                internal_source_code="dotmac.pilot.seabone",
            ),
        )

    raw_secret = tuple(
        service.ConfigurationValue(
            capability_instance_ref=value.capability_instance_ref,
            field_code=value.field_code,
            value=(
                "actual-password"
                if value.field_code == "identity_admin_secret_ref"
                else value.value
            ),
        )
        for value in _collaboration_values()
    )
    with pytest.raises(ConflictError, match="secret reference"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=target.id,
                deployment_ref="raw-secret",
                configuration_snapshot=_snapshot(
                    raw_secret, ref="config:nhia/raw-secret@v1"
                ),
                internal_source_code="dotmac.pilot.seabone",
            ),
        )

    workspace_value = service.ConfigurationValue(
        "workspace.application",
        "workspace_endpoint",
        "https://workspace.customer.example",
    )
    with pytest.raises(ConflictError, match="profile schema"):
        service.record_deployment_intent(
            session,
            _intent(
                account_id=account.id,
                target_id=target.id,
                deployment_ref="unselected-config",
                configuration_snapshot=_snapshot(
                    (*_collaboration_values(), workspace_value),
                    ref="config:nhia/unselected@v1",
                ),
                internal_source_code="dotmac.pilot.seabone",
            ),
        )


def test_desired_state_is_immutable_and_has_no_integrator_binding_fields(
    session: Session,
) -> None:
    account = _account(session)
    target = _target(session, account, customer_ref=None)
    _publish_profile(session)
    result = service.record_deployment_intent(
        session,
        _intent(
            account_id=account.id,
            target_id=target.id,
            internal_source_code="dotmac.pilot.seabone",
        ),
    )
    desired = session.get(DeploymentDesiredStateVersion, result.desired_state.id)
    assert desired is not None
    desired.configuration_hash = "sha256:" + "0" * 64
    with pytest.raises(ConflictError, match="immutable"):
        session.flush()

    columns = set(DeploymentDesiredStateVersion.__table__.columns.keys())
    assert not any("binding" in column for column in columns)
    assert not any("installation" in column for column in columns)
    command_fields = set(service.CreateDeploymentIntentCommand.__dataclass_fields__)
    assert not any("binding" in field for field in command_fields)
    assert not any("installation" in field for field in command_fields)


def _content_hash(document: object) -> str:
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
