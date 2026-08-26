"""Contract tests for reusable managed-service profile schemas."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest
from dotmac_kernel import (
    BadRequestError,
    CapabilityCheck,
    CapabilityCheckStage,
    CapabilityConfigField,
    CapabilityConfigValueFormat,
    CapabilityConfigValueType,
    CapabilityEvidenceType,
    ConflictError,
    NotFoundError,
    PlatformAdmin,
    PlatformAuditEvent,
)
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import select
from sqlalchemy.orm import Session
from tests.capability_contract_registry import (
    InMemoryCapabilityContractRegistry,
    build_capability_composition_registry,
    build_capability_contract_registry,
)

from vendor_cp.managed_profiles import catalogues, service
from vendor_cp.managed_profiles.composition_contracts import (
    CapabilityCompositionEvidenceError,
    UnavailableCapabilityCompositionRegistry,
)
from vendor_cp.managed_profiles.feature import feature
from vendor_cp.managed_profiles.instance_refs import is_capability_instance_ref
from vendor_cp.managed_profiles.models import ManagedServiceProfileVersion

REGISTRY = build_capability_contract_registry()
COMPOSITION_REGISTRY = build_capability_composition_registry()


@pytest.fixture(scope="module", autouse=True)
def _declared_audit_actions() -> Iterator[None]:
    """Install this feature's declaration for service-only unit tests.

    `create_app` owns this installation in production.  These focused tests do
    not build an app, so they install the same manifest-derived registry and
    restore the exact prior process state afterwards.
    """

    import dotmac_kernel.audit_actions as registry_module

    try:
        previous = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous = None
    install_audit_actions(AuditActionRegistry.from_manifests((feature,)))
    try:
        yield
    finally:
        if previous is None:
            registry_module._active_registry = None
        else:
            install_audit_actions(previous)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _suite_command(**overrides: object) -> service.PublishProfileVersionCommand:
    values: dict[str, object] = {
        "commercial_product_code": "managed-suite",
        "profile_code": "managed-suite-standard",
        "version": 1,
        "schema_version": 1,
        "update_authority": "customer_approved",
        "compatible_predecessors": (),
    }
    values.update(overrides)
    return service.PublishProfileVersionCommand(**values)  # type: ignore[arg-type]


def _build(
    command: service.PublishProfileVersionCommand,
) -> service.BuiltProfileVersion:
    return service.build_profile_version(
        command,
        capability_registry=REGISTRY,
        composition_registry=COMPOSITION_REGISTRY,
    )


def _publish(
    db: Session, command: service.PublishProfileVersionCommand
) -> service.ManagedServiceProfileVersionView:
    return service.publish_profile_version(
        db,
        command,
        capability_registry=REGISTRY,
        composition_registry=COMPOSITION_REGISTRY,
    )


def test_vendor_catalogues_compose_but_do_not_own_capability_semantics() -> None:
    assert set(catalogues.PRODUCT_CATALOGUE) == {
        "managed-email",
        "managed-collaboration",
        "managed-business",
        "managed-sso",
        "managed-suite",
        "managed-academy",
    }
    assert set(catalogues.COMPONENT_CATALOGUE) == {
        "identity",
        "email",
        "collaboration",
        "business",
        "academy",
        "workspace",
    }
    assert not hasattr(catalogues, "CAPABILITY_CATALOGUE")
    assert {
        evidence.snapshot.owner_code for evidence in REGISTRY.snapshots.values()
    } >= {
        "dotmac-domains",
        "dotmac-erp",
        "mail-service-owner",
    }
    assert "dns.authoritative.v1" in REGISTRY.snapshots
    assert {
        operation.operation_code
        for operation in REGISTRY.require("dns.authoritative.v1").snapshot.operations
    } == {"plan", "apply", "observe", "cancel"}
    assert not hasattr(catalogues, "CONFIGURATION_FIELD_CATALOGUE")
    assert not hasattr(catalogues, "VERIFICATION_CHECK_CATALOGUE")


def test_capability_instance_reference_uses_the_frozen_wire_grammar() -> None:
    assert is_capability_instance_ref("email.oidc-client")
    assert is_capability_instance_ref("workspace.application")
    for invalid in (
        "",
        "Email.oidc-client",
        "email_oidc",
        "email..oidc",
        "email.-oidc",
        "email.oidc-",
        "email oidc",
        "émail.oidc",
        "a" * 201,
    ):
        assert not is_capability_instance_ref(invalid)


def test_five_relying_parties_are_distinct_instances_of_one_owner_contract() -> None:
    built = _build(_suite_command())
    oidc_clients = {
        capability.capability_instance_ref: capability.capability_id
        for component in built.components
        for capability in component.capabilities
        if capability.capability_id == "identity.oidc-client.lifecycle.v1"
    }

    assert oidc_clients == {
        "academy.oidc-client": "identity.oidc-client.lifecycle.v1",
        "business.oidc-client": "identity.oidc-client.lifecycle.v1",
        "collaboration.oidc-client": "identity.oidc-client.lifecycle.v1",
        "email.oidc-client": "identity.oidc-client.lifecycle.v1",
        "workspace.oidc-client": "identity.oidc-client.lifecycle.v1",
    }
    realm_to_clients = [
        item
        for item in built.prerequisite_evidence_bindings
        if item.target_capability_id == "identity.oidc-client.lifecycle.v1"
    ]
    assert len(realm_to_clients) == 1
    assert realm_to_clients[0].coverage == "each_target_exactly_one"


def test_profile_publish_command_cannot_accept_customer_selection_or_values() -> None:
    fields = set(service.PublishProfileVersionCommand.__dataclass_fields__)
    assert "selected_optional_components" not in fields
    assert "configuration" not in fields
    assert "configuration_snapshot" not in fields


def test_profile_hash_binds_exact_product_owned_capability_contract_evidence() -> None:
    baseline = _build(_suite_command())
    original = REGISTRY.require("dns.authoritative.v1")
    injected_field = CapabilityConfigField(
        "owner_injected_field",
        CapabilityConfigValueType.STRING,
        CapabilityConfigValueFormat.STABLE_CODE,
    )
    injected_check = CapabilityCheck(
        "owner.injected.check",
        CapabilityCheckStage.EVIDENCE,
        CapabilityEvidenceType.DOCUMENT,
    )
    changed_snapshot = replace(
        original.snapshot,
        config_fields=tuple(
            sorted(
                (*original.snapshot.config_fields, injected_field),
                key=lambda item: item.field_code,
            )
        ),
        checks=tuple(
            sorted(
                (*original.snapshot.checks, injected_check),
                key=lambda item: (item.stage.value, item.check_code),
            )
        ),
    )
    changed = replace(
        original,
        contract_attestation_digest=changed_snapshot.digest,
        contract_ref=f"file:///held/{changed_snapshot.digest[7:]}.json",
        snapshot=changed_snapshot,
    )
    snapshots = dict(REGISTRY.snapshots)
    snapshots[changed.capability_id] = changed
    rebuilt = service.build_profile_version(
        _suite_command(),
        capability_registry=InMemoryCapabilityContractRegistry(snapshots),
        composition_registry=COMPOSITION_REGISTRY,
    )

    assert rebuilt.content_hash != baseline.content_hash
    dns_contracts = {
        capability.capability_id: capability
        for component in rebuilt.components
        for capability in component.capabilities
    }
    assert dns_contracts["dns.authoritative.v1"].owner_code == "dotmac-domains"
    assert dns_contracts["dns.authoritative.v1"].content_hash == (
        changed_snapshot.digest
    )
    assert injected_field.field_code in {
        field.field_code for field in rebuilt.configuration_fields
    }
    assert injected_check.check_code in {
        check.check_code for check in rebuilt.verification_checks
    }


def test_profile_publication_fails_when_an_owner_contract_is_absent() -> None:
    snapshots = dict(REGISTRY.snapshots)
    del snapshots["identity.realm.lifecycle.v1"]
    with pytest.raises(ConflictError, match="no product owner published"):
        service.build_profile_version(
            _suite_command(),
            capability_registry=InMemoryCapabilityContractRegistry(snapshots),
            composition_registry=COMPOSITION_REGISTRY,
        )


def test_profile_snapshots_held_schemas_and_admitted_composition_mappings() -> None:
    built = _build(_suite_command())
    identity = next(
        capability
        for component in built.components
        for capability in component.capabilities
        if capability.capability_id == "identity.realm.lifecycle.v1"
    )

    assert len(identity.schemas) == 8
    assert all(
        schema.document.digest == schema.schema_digest for schema in identity.schemas
    )
    assert len(built.prerequisite_evidence_bindings) == 10
    email = next(
        item
        for item in built.prerequisite_evidence_bindings
        if item.target_capability_id == "email.lifecycle.v1"
    )
    assert email.source_schema_ref.endswith("/apply/output@v1")
    assert email.target_schema_ref.endswith("/apply/input@v1")
    assert email.source_pointer == "/public_value"
    assert email.target_pointer == "/upstream_value"
    target = next(
        capability
        for component in built.components
        for capability in component.capabilities
        if capability.capability_id == email.target_capability_id
    )
    target_schema = next(
        schema
        for schema in target.schemas
        if schema.schema_ref == email.target_schema_ref
    )
    assert (
        "x-dotmac-data-classification"
        not in target_schema.document.require_instance_pointer(email.target_pointer)
    )


def test_dependent_profile_fails_closed_without_admitted_composition_evidence() -> None:
    with pytest.raises(CapabilityCompositionEvidenceError, match="attestation"):
        service.build_profile_version(
            _suite_command(commercial_product_code="managed-email"),
            capability_registry=REGISTRY,
            composition_registry=UnavailableCapabilityCompositionRegistry(),
        )

    with pytest.raises(CapabilityCompositionEvidenceError, match="attestation"):
        service.build_profile_version(
            _suite_command(commercial_product_code="managed-sso"),
            capability_registry=REGISTRY,
            composition_registry=UnavailableCapabilityCompositionRegistry(),
        )


def test_profile_is_full_reusable_allowed_graph_not_customer_desired_state() -> None:
    built = _build(_suite_command())

    assert built.allowed_optional_components == ("workspace",)
    required = {
        component.component_code for component in built.components if component.required
    }
    optional = {
        component.component_code
        for component in built.components
        if not component.required
    }
    assert required == {
        "academy",
        "business",
        "collaboration",
        "email",
        "identity",
    }
    assert optional == {"workspace"}
    assert "configuration" not in built.document
    assert built.document["allowed_optional_components"] == ["workspace"]
    assert built.document["content_schema"] == ("vendor.managed-service-profile@v1")
    assert {field.field_code for field in built.configuration_fields} >= {
        "customer_domain",
        "workspace_endpoint",
    }


def test_non_suite_profile_contains_own_component_and_dependency_closure() -> None:
    built = _build(
        service.PublishProfileVersionCommand(
            commercial_product_code="managed-email",
            profile_code="managed-email-standard",
            version=1,
            schema_version=1,
            update_authority="customer_approved",
        )
    )
    assert built.allowed_optional_components == ()
    assert built.component_codes == ("email", "identity")
    assert all(component.required for component in built.components)


def test_publish_creates_content_addressed_immutable_schema(db: Session) -> None:
    first = _publish(db, _suite_command())
    assert first.content_hash.startswith("sha256:")
    assert first.allowed_optional_components == ("workspace",)

    row = db.get(ManagedServiceProfileVersion, first.id)
    assert row is not None
    row.document = {"tampered": True}
    with pytest.raises(ConflictError, match="immutable"):
        db.flush()


def test_profile_publication_is_audited_with_only_safe_contract_identity(
    db: Session,
) -> None:
    admin = PlatformAdmin(
        email="profile-publisher@dotmac.io", password_hash="x", is_active=True
    )
    db.add(admin)
    db.flush()
    published = _publish(db, _suite_command(actor_admin_id=admin.id))

    event = db.execute(
        select(PlatformAuditEvent).where(
            PlatformAuditEvent.action == "vendor.managed_profile.published"
        )
    ).scalar_one()
    assert event.entity_id == str(published.id)
    assert event.actor_admin_id == admin.id
    assert event.details == {
        "commercial_product_code": "managed-suite",
        "profile_code": "managed-suite-standard",
        "version": 1,
        "content_hash": published.content_hash,
    }
    assert feature.audit_actions == ("vendor.managed_profile.published",)


def test_same_profile_version_cannot_be_republished(db: Session) -> None:
    _publish(db, _suite_command())
    with pytest.raises(ConflictError, match="already exists"):
        _publish(
            db,
            _suite_command(update_authority="offline"),
        )


def test_content_hash_changes_for_every_profile_owned_input() -> None:
    baseline = _build(_suite_command()).content_hash
    assert (
        _build(_suite_command(update_authority="vendor_automatic")).content_hash
        != baseline
    )
    assert _build(_suite_command(schema_version=2)).content_hash != baseline


def test_compatible_predecessor_requires_exact_persisted_product_and_hash(
    db: Session,
) -> None:
    first = _publish(db, _suite_command())
    exact = service.CompatiblePredecessor(
        commercial_product_code=first.commercial_product_code,
        content_hash=first.content_hash,
    )
    second = _publish(
        db,
        _suite_command(
            version=2,
            update_authority="vendor_automatic",
            compatible_predecessors=(exact,),
        ),
    )
    assert second.compatible_predecessors == (exact,)

    with pytest.raises(NotFoundError, match="exact predecessor"):
        _publish(
            db,
            _suite_command(
                profile_code="bad-predecessor-product",
                version=2,
                compatible_predecessors=(
                    service.CompatiblePredecessor(
                        commercial_product_code="managed-email",
                        content_hash=first.content_hash,
                    ),
                ),
            ),
        )
    with pytest.raises(NotFoundError, match="exact predecessor"):
        _publish(
            db,
            _suite_command(
                profile_code="bad-predecessor-hash",
                version=2,
                compatible_predecessors=(
                    service.CompatiblePredecessor(
                        commercial_product_code="managed-suite",
                        content_hash="sha256:" + "0" * 64,
                    ),
                ),
            ),
        )


def test_update_authority_is_closed() -> None:
    for authority in ("vendor_automatic", "customer_approved", "offline"):
        assert (
            _build(_suite_command(update_authority=authority)).update_authority
            == authority
        )
    with pytest.raises(BadRequestError, match="update authority"):
        _build(_suite_command(update_authority="automatic"))


def test_representative_suite_schema_covers_identity_and_all_managed_products() -> None:
    built = _build(_suite_command())
    checks = {check.check_code for check in built.verification_checks}
    assert {
        "identity.realm.ready",
        "business.application.ready",
        "email.ready",
        "collaboration.application.ready",
        "academy.application.ready",
        "workspace.application.ready",
    } <= checks
